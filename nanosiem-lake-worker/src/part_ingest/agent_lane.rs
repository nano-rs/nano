// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4721: the agent catalog (master export + fresh serving epochs) is the
//! lowest-priority work on a lake cell. Agents never compete with analysts:
//!
//! * CPU-heavy steps (staging a cold part file: sha256 + spool write, and the
//!   parquet footer check) run on ONE process-wide `agent-lane` thread at
//!   `SCHED_IDLE` (nice 19 if the kernel refuses it). That bounds agent-lane
//!   CPU to one idle-class core and never takes a Tokio worker the ingest
//!   loop needs. The thread also asks for IO class IDLE, but on a cell that
//!   is close to a no-op: the reads are network GETs, the spool writes are
//!   buffered (page-cache writeback ignores the writer's IO priority), and
//!   the Cinder volumes run `none`/`mq-deadline`. The byte bound below is
//!   what actually limits agent IO.
//! * Network reads stay on the shared runtime (pooled connections are shared
//!   with ingest and must not be driven by an idle-class thread).
//! * [`IngestPressure`] is set from the ingest loop's health update: ingest
//!   lag inside the top quarter of its alert bound, past it, or the cell's
//!   CPU throttled / R2 strained (the catch-up headroom signal, see
//!   [`agent_pressure`]). While it holds, a serving-epoch batch yields before
//!   it starts and one export prepare yields before its first cold file, each
//!   at most [`MAX_YIELD`]; past that, cold bytes are read at most
//!   [`PRESSURED_BYTES_PER_SEC`] (checked every chunk), so under sustained
//!   lag the catalog still converges at a bounded trickle instead of
//!   bursting a whole file at line rate once a minute.
//!
//! The yields and the pace fit the commit attempt timeout (which budgets
//! [`PRESSURED_BYTES_PER_SEC`] per byte plus a 120 s base), so erasure
//! completion and custody are delayed, never starved, and their semantics do
//! not change.
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Mutex, OnceLock,
    },
    time::Duration,
};

/// How often a yielding step re-reads the lag signal.
pub(crate) const PRESSURE_POLL: Duration = Duration::from_secs(1);
/// Longest single yield. Past it one unit of work (a prepare or a batch)
/// runs even under lag, so the agent catalog cannot be starved forever.
pub(crate) const MAX_YIELD: Duration = Duration::from_secs(60);
/// Cold-read rate while ingest is under pressure: the commit attempt
/// timeout's own floor rate, so a paced batch still fits its attempt.
pub(crate) const PRESSURED_BYTES_PER_SEC: u64 = super::iceberg_export::ATTEMPT_PREPARE_BYTES_PER_SEC;

/// The agent lane's pressure signal for one health update: ingest lag past
/// [`super::prevalence::CATCH_UP_LAG_HOLD_SHARE`] of its alert bound (the lag
/// alert itself is too late: a demo tenant showed 120-250 s before anything backed
/// off), or the cell's CPU throttled / R2 strained.
pub(crate) fn agent_pressure(lag_ms: i64, lag_bound_ms: i64) -> bool {
    pressured(super::merge_quota::catch_up_headroom(lag_ms, lag_bound_ms))
}

fn pressured(headroom: super::prevalence::CatchUpHeadroom) -> bool {
    headroom != super::prevalence::CatchUpHeadroom::Room
}

/// Per-tenant "ingest is lagging" signal. Owned by the tenant's catalog; the
/// ingest loop writes it on every health update.
#[derive(Debug, Default)]
pub struct IngestPressure {
    lagging: AtomicBool,
    /// Total milliseconds agent-lane work spent yielding (telemetry/tests).
    yielded_ms: AtomicU64,
}

impl IngestPressure {
    /// `lagging`: the ingest lag is above its alert threshold.
    pub fn set(&self, lagging: bool) {
        self.lagging.store(lagging, Ordering::Relaxed);
    }

    pub fn lagging(&self) -> bool {
        self.lagging.load(Ordering::Relaxed)
    }

    pub fn yielded_ms(&self) -> u64 {
        self.yielded_ms.load(Ordering::Relaxed)
    }

    /// Wait while ingest is lagging, up to [`MAX_YIELD`]. Returns how long
    /// it waited (zero when ingest is healthy).
    pub async fn yield_while_lagging(&self, what: &'static str) -> Duration {
        self.yield_while_lagging_up_to(what, MAX_YIELD).await
    }

    /// [`Self::yield_while_lagging`] bounded by `cap` (a caller's remaining
    /// yield budget; zero never waits).
    pub async fn yield_while_lagging_up_to(&self, what: &'static str, cap: Duration) -> Duration {
        if cap.is_zero() || !self.lagging() {
            return Duration::ZERO;
        }
        let started = tokio::time::Instant::now();
        while self.lagging() && started.elapsed() < cap {
            tokio::time::sleep(PRESSURE_POLL.min(cap.saturating_sub(started.elapsed()))).await;
        }
        let waited = started.elapsed();
        self.yielded_ms
            .fetch_add(waited.as_millis() as u64, Ordering::Relaxed);
        tracing::info!(what, waited_ms = waited.as_millis() as u64, still_lagging = self.lagging(),
            "agent catalog yielded to ingest lag");
        waited
    }

    /// After a chunk of `bytes` that started at `started`: while ingest is
    /// under pressure, wait until the chunk took at least its share of
    /// [`PRESSURED_BYTES_PER_SEC`]. A healthy cell never waits.
    pub async fn pace(&self, bytes: u64, started: tokio::time::Instant) {
        if !self.lagging() {
            return;
        }
        let share = Duration::from_secs_f64(bytes as f64 / PRESSURED_BYTES_PER_SEC as f64);
        let due = started + share;
        if due > tokio::time::Instant::now() {
            let waited = due - tokio::time::Instant::now();
            tokio::time::sleep_until(due).await;
            self.yielded_ms.fetch_add(waited.as_millis() as u64, Ordering::Relaxed);
        }
    }
}

type Job = Box<dyn FnOnce() + Send + 'static>;

/// The scheduling class the agent-lane thread actually got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LanePriority {
    /// `SCHED_IDLE` and IO class IDLE.
    Idle,
    /// The kernel refused `SCHED_IDLE`: nice 19 (IO class IDLE if allowed).
    Nice19,
}

static LANE: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();
static PRIORITY: OnceLock<LanePriority> = OnceLock::new();

/// Lower the calling thread to the lowest CPU and IO priority. Only ever
/// called on the dedicated agent-lane thread, never a runtime worker.
fn lower_to_idle() -> LanePriority {
    // SAFETY: Linux scheduling syscalls on this thread's own id (0 / gettid).
    unsafe {
        let param = libc::sched_param { sched_priority: 0 };
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        // IOPRIO_WHO_PROCESS = 1 (a tid), IOPRIO_CLASS_IDLE = 3.
        if libc::syscall(libc::SYS_ioprio_set, 1, tid, 3 << 13) != 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "agent lane: IO priority class IDLE refused");
        }
        if libc::sched_setscheduler(0, libc::SCHED_IDLE, &param) == 0 {
            return LanePriority::Idle;
        }
        tracing::warn!(error = %std::io::Error::last_os_error(), "agent lane: SCHED_IDLE refused; nice 19");
        libc::setpriority(libc::PRIO_PROCESS, tid, 19);
        LanePriority::Nice19
    }
}

fn lane() -> std::io::Result<mpsc::Sender<Job>> {
    if let Some(sender) = LANE.get() {
        return Ok(sender.lock().expect("agent lane sender").clone());
    }
    let (tx, rx) = mpsc::channel::<Job>();
    let (ready_tx, ready_rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("agent-lane".into())
        .spawn(move || {
            let _ = ready_tx.send(lower_to_idle());
            // Concurrency 1: one job at a time, in submission order. A
            // panicking job fails only its caller (its result sender drops);
            // the process-wide lane survives for every later job.
            while let Ok(job) = rx.recv() {
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
                    tracing::error!("agent lane job panicked");
                }
            }
        })?;
    let priority = ready_rx
        .recv()
        .map_err(|_| std::io::Error::other("agent lane thread exited"))?;
    // Racing first callers: the loser's thread exits when its sender drops.
    let _ = PRIORITY.set(priority);
    let _ = LANE.set(Mutex::new(tx));
    Ok(LANE.get().expect("agent lane set").lock().expect("agent lane sender").clone())
}

/// The priority the agent-lane thread runs at (starting it if needed).
#[cfg(test)]
pub(crate) fn priority() -> LanePriority {
    lane().expect("agent lane");
    *PRIORITY.get().expect("agent lane priority")
}

/// Run blocking agent-catalog work on the idle-class agent-lane thread.
/// Cancelling the caller does not cancel a job already queued; it finishes
/// and its result is dropped.
pub async fn run<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> anyhow::Result<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let dispatch = tracing::dispatcher::get_default(|dispatch| dispatch.clone());
    lane()?
        .send(Box::new(move || {
            let out = tracing::dispatcher::with_default(&dispatch, work);
            let _ = tx.send(out);
        }))
        .map_err(|_| anyhow::anyhow!("agent lane thread is gone"))?;
    rx.await.map_err(|_| anyhow::anyhow!("agent lane job panicked"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lane thread really runs at SCHED_IDLE + IO class IDLE, one job
    /// at a time, off the calling (runtime) thread.
    #[tokio::test]
    async fn lane_runs_jobs_at_idle_cpu_and_io_priority_off_the_runtime() {
        assert_eq!(priority(), LanePriority::Idle, "SCHED_IDLE is allowed for an unprivileged thread");
        let caller = std::thread::current().id();
        let (policy, ioprio, name, thread) = run(|| unsafe {
            let tid = libc::syscall(libc::SYS_gettid);
            (
                libc::sched_getscheduler(0),
                libc::syscall(libc::SYS_ioprio_get, 1, tid) >> 13,
                std::thread::current().name().map(str::to_owned),
                std::thread::current().id(),
            )
        })
        .await
        .unwrap();
        assert_eq!(policy, libc::SCHED_IDLE);
        assert_eq!(ioprio, 3, "IO class IDLE");
        assert_eq!(name.as_deref(), Some("agent-lane"));
        assert_ne!(thread, caller);
        // Concurrency 1: jobs never overlap.
        let busy = std::sync::Arc::new(AtomicBool::new(false));
        let jobs = (0..8).map(|_| {
            let busy = busy.clone();
            run(move || {
                assert!(!busy.swap(true, Ordering::SeqCst), "two agent-lane jobs overlapped");
                std::thread::sleep(Duration::from_millis(5));
                busy.store(false, Ordering::SeqCst);
            })
        });
        for job in futures::future::join_all(jobs).await {
            job.unwrap();
        }
    }

    /// A panicking job fails its caller only; the process-wide lane keeps
    /// serving every later job.
    #[tokio::test]
    async fn a_panicking_job_does_not_kill_the_lane() {
        let error = run(|| -> u8 { panic!("job panics") }).await.unwrap_err();
        assert!(format!("{error:#}").contains("panicked"), "{error:#}");
        assert_eq!(run(|| 7u8).await.unwrap(), 7);
    }

    /// The signal backs off before the lag alert: inside the top quarter of
    /// the bound, past it, or on cell strain; never on a healthy cell.
    #[test]
    fn agent_pressure_starts_before_the_lag_alert() {
        use super::super::merge_quota::catch_up_headroom_given as headroom;
        assert!(!pressured(headroom(30_000, 120_000, false)));
        assert!(pressured(headroom(100_000, 120_000, false)), "inside the alert bound, near it");
        assert!(pressured(headroom(121_000, 120_000, false)));
        assert!(pressured(headroom(0, 120_000, true)), "CPU throttling / R2 strain");
        assert!(agent_pressure(121_000, 120_000));
    }

    /// Under pressure every chunk takes at least its share of the bounded
    /// rate; a healthy cell is never paced.
    #[tokio::test(start_paused = true)]
    async fn pace_bounds_bytes_per_second_only_under_pressure() {
        let pressure = IngestPressure::default();
        let started = tokio::time::Instant::now();
        pressure.pace(4 * 1024 * 1024, started).await;
        assert_eq!(started.elapsed(), Duration::ZERO);
        pressure.set(true);
        let started = tokio::time::Instant::now();
        for _ in 0..4 {
            let chunk = tokio::time::Instant::now();
            pressure.pace(PRESSURED_BYTES_PER_SEC / 2, chunk).await;
        }
        assert!(started.elapsed() >= Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(started.elapsed() < Duration::from_secs(2) + PRESSURE_POLL);
        assert_eq!(pressure.yield_while_lagging_up_to("t", Duration::ZERO).await, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn yield_waits_while_lagging_and_is_bounded() {
        let pressure = IngestPressure::default();
        assert_eq!(pressure.yield_while_lagging("t").await, Duration::ZERO);
        pressure.set(true);
        assert_eq!(pressure.yield_while_lagging("t").await, MAX_YIELD, "bounded under sustained lag");
        let pressure = std::sync::Arc::new(pressure);
        let clear = pressure.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            clear.set(false);
        });
        let waited = pressure.yield_while_lagging("t").await;
        assert!(waited >= Duration::from_secs(5) && waited <= Duration::from_secs(5) + PRESSURE_POLL, "{waited:?}");
    }
}
