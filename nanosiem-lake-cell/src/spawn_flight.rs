//! NAN-4128: bounded, cancellation-proof role spawns.
//!
//! A wake used to run the whole spawn (warm process, tenant tree, jail,
//! bootstrap-token mint, readiness) inside the HTTP request future while it
//! held the tenant's per-role spawn lock. Two failure modes came from that:
//!
//! * **Cancellation livelock.** A caller that gives up first (a 10 s probe
//!   against a detect spawn that needs longer) drops the request future. The
//!   half-assigned child is killed (`kill_on_drop`) and nothing is logged, not
//!   "tenant process started" and not "spawn failed". The next wake starts
//!   from scratch and is cancelled again, so the role never comes up
//!   (cell-uk-1, 2026-10-19).
//! * **Silent lock waits.** The lock wait had no bound and no log, so a
//!   wedged holder made every later wake hang with no trace.
//!
//! [`SpawnFlight`] runs one detached attempt per tenant role under an overall
//! deadline. Callers join it and wait a bounded time, and they never own it,
//! so a caller that leaves cannot abort it. [`RoleLock`] records who holds
//! the lock and at which step, and it logs waits that run long.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A waiter logs every this long while it waits on a role lock.
pub const LOCK_WAIT_LOG_EVERY: Duration = Duration::from_secs(5);

/// What a role-lock holder (or a spawn attempt) is doing right now.
#[derive(Debug)]
pub struct Progress {
    /// `spawn` or `exit_cleanup`.
    pub label: &'static str,
    pub started: Instant,
    step: Mutex<&'static str>,
}

impl Progress {
    pub fn new(label: &'static str) -> Arc<Self> {
        Arc::new(Self { label, started: Instant::now(), step: Mutex::new("start") })
    }

    pub fn set(&self, step: &'static str) {
        *self.step.lock().unwrap() = step;
    }

    pub fn step(&self) -> &'static str {
        *self.step.lock().unwrap()
    }
}

/// A tenant role's spawn lock that knows its holder.
#[derive(Default)]
pub struct RoleLock {
    mutex: tokio::sync::Mutex<()>,
    holder: Mutex<Option<Arc<Progress>>>,
    /// Count of "waiting on role lock" lines logged (status and tests).
    pub waits_logged: AtomicU64,
}

pub struct RoleGuard<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    lock: &'a RoleLock,
}

impl Drop for RoleGuard<'_> {
    fn drop(&mut self) {
        *self.lock.holder.lock().unwrap() = None;
    }
}

impl RoleLock {
    /// Non-blocking probe (reaper, keeper, handover `writing`). It does not
    /// record a holder, and the guard is dropped right after the check.
    pub fn try_lock(&self) -> Result<tokio::sync::MutexGuard<'_, ()>, tokio::sync::TryLockError> {
        self.mutex.try_lock()
    }

    /// The current holder's label, step and age, if anyone holds the lock.
    pub fn holder(&self) -> Option<(&'static str, &'static str, Duration)> {
        self.holder.lock().unwrap().as_ref().map(|p| (p.label, p.step(), p.started.elapsed()))
    }

    /// Take the lock as `who`, logging every `log_every` while waiting
    /// (naming the holder, its step and its age). The caller bounds the
    /// total wait (the spawn attempt runs under a deadline).
    pub async fn lock_logged(&self, who: &Arc<Progress>, tenant: &str, role: &str, log_every: Duration) -> RoleGuard<'_> {
        let waited = Instant::now();
        let guard = loop {
            match tokio::time::timeout(log_every, self.mutex.lock()).await {
                Ok(g) => break g,
                Err(_) => {
                    self.waits_logged.fetch_add(1, Ordering::Relaxed);
                    let (holder, holder_step, holder_secs) = self
                        .holder()
                        .map_or(("unknown", "unknown", 0), |(l, s, d)| (l, s, d.as_secs()));
                    tracing::warn!(tenant, role, waiter = who.label, waiter_step = who.step(),
                        waited_secs = waited.elapsed().as_secs(), holder, holder_step, holder_secs,
                        "waiting on tenant role spawn lock");
                }
            }
        };
        *self.holder.lock().unwrap() = Some(who.clone());
        RoleGuard { _guard: guard, lock: self }
    }
}

/// Why a joined spawn attempt produced no process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlightError<E> {
    /// The attempt itself failed.
    Failed(E),
    /// The attempt hit its overall deadline at `step`. It was dropped, which
    /// kills its half-started child and releases the role lock.
    TimedOut { step: &'static str, secs: u64 },
    /// This caller stopped waiting. The attempt is still running at `step`.
    StillRunning { step: &'static str, secs: u64 },
}

type Outcome<T, E> = Option<Result<T, FlightError<E>>>;

struct InFlight<T, E> {
    progress: Arc<Progress>,
    rx: tokio::sync::watch::Receiver<Outcome<T, E>>,
}

/// One detached spawn attempt at a time for one tenant role.
pub struct SpawnFlight<T, E> {
    /// Shared with the detached attempt, which retires itself when done (so
    /// a finished attempt never pins its process or error).
    current: Arc<Mutex<Option<Arc<InFlight<T, E>>>>>,
}

impl<T, E> Default for SpawnFlight<T, E> {
    fn default() -> Self {
        Self { current: Arc::new(Mutex::new(None)) }
    }
}

impl<T, E> SpawnFlight<T, E>
where
    T: Clone + Send + Sync + 'static,
    E: Clone + Send + Sync + 'static,
{
    /// Is an attempt running now? Returns its step and age.
    pub fn in_flight(&self) -> Option<(&'static str, Duration)> {
        self.current.lock().unwrap().as_ref().map(|f| (f.progress.step(), f.progress.started.elapsed()))
    }

    /// Join the running attempt, or start one with `start`. The attempt runs
    /// detached under `deadline`. This caller waits at most `wait`.
    pub async fn run<F, Fut>(&self, deadline: Duration, wait: Duration, start: F) -> Result<T, FlightError<E>>
    where
        F: FnOnce(Arc<Progress>) -> Fut,
        Fut: Future<Output = Result<T, E>> + Send + 'static,
    {
        let flight = {
            let mut cur = self.current.lock().unwrap();
            match cur.as_ref() {
                // A finished attempt is never joined: its outcome is stale.
                Some(f) if f.rx.borrow().is_none() => f.clone(),
                _ => {
                    let progress = Progress::new("spawn");
                    let (tx, rx) = tokio::sync::watch::channel(None);
                    let f = Arc::new(InFlight { progress: progress.clone(), rx });
                    *cur = Some(f.clone());
                    let fut = start(progress.clone());
                    let current = self.current.clone();
                    let mine = Arc::downgrade(&f);
                    tokio::spawn(async move {
                        let out = match tokio::time::timeout(deadline, fut).await {
                            Ok(Ok(v)) => Ok(v),
                            Ok(Err(e)) => Err(FlightError::Failed(e)),
                            Err(_) => Err(FlightError::TimedOut { step: progress.step(), secs: deadline.as_secs() }),
                        };
                        // Joined callers keep their receivers; the value stays
                        // readable after the sender is gone.
                        let _ = tx.send(Some(out));
                        let mut cur = current.lock().unwrap();
                        if cur.as_ref().is_some_and(|c| mine.upgrade().is_some_and(|m| Arc::ptr_eq(c, &m))) {
                            *cur = None;
                        }
                    });
                    f
                }
            }
        };
        let mut rx = flight.rx.clone();
        let res = tokio::time::timeout(wait, async {
            match rx.wait_for(|o| o.is_some()).await {
                Ok(o) => o.clone().expect("checked is_some"),
                // The task ended without publishing (runtime shutdown).
                Err(_) => Err(FlightError::TimedOut { step: flight.progress.step(), secs: deadline.as_secs() }),
            }
        })
        .await;
        // Retire a finished attempt so the next caller starts fresh.
        {
            let mut cur = self.current.lock().unwrap();
            if cur.as_ref().is_some_and(|c| Arc::ptr_eq(c, &flight) && c.rx.borrow().is_some()) {
                *cur = None;
            }
        }
        match res {
            Ok(r) => r,
            Err(_) => Err(FlightError::StillRunning {
                step: flight.progress.step(),
                secs: flight.progress.started.elapsed().as_secs(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const MS: fn(u64) -> Duration = Duration::from_millis;

    /// A spawn that never completes: the caller gets an error within the
    /// bound, the attempt is dropped (lock released), and a later wake
    /// proceeds.
    #[tokio::test]
    async fn a_hung_spawn_times_out_releases_the_lock_and_a_later_wake_proceeds() {
        let lock = Arc::new(RoleLock::default());
        let flight: SpawnFlight<u32, String> = SpawnFlight::default();
        let t0 = Instant::now();
        let l = lock.clone();
        let r = flight
            .run(MS(150), MS(400), move |p| async move {
                let _g = l.lock_logged(&p, "t1", "detect", MS(1000)).await;
                p.set("mint");
                std::future::pending::<()>().await;
                Ok(1)
            })
            .await;
        assert_eq!(r, Err(FlightError::TimedOut { step: "mint", secs: 0 }));
        assert!(t0.elapsed() < MS(1000), "bounded: {:?}", t0.elapsed());
        // The dropped attempt released its lock.
        tokio::time::sleep(MS(20)).await;
        assert!(lock.try_lock().is_ok(), "lock released after the timeout");
        assert!(lock.holder().is_none());
        let l = lock.clone();
        let r = flight
            .run(MS(500), MS(500), move |p| async move {
                let _g = l.lock_logged(&p, "t1", "detect", MS(1000)).await;
                Ok(7)
            })
            .await;
        assert_eq!(r, Ok(7));
    }

    /// A caller that stops waiting does not cancel the attempt: it finishes
    /// in the background, and the caller gets a clear "still running" error.
    #[tokio::test]
    async fn a_caller_that_leaves_does_not_cancel_the_spawn() {
        let flight: Arc<SpawnFlight<u32, String>> = Arc::new(SpawnFlight::default());
        let done = Arc::new(AtomicUsize::new(0));
        let d = done.clone();
        let r = flight
            .run(MS(2000), MS(50), move |p| async move {
                p.set("ready");
                tokio::time::sleep(MS(200)).await;
                d.fetch_add(1, Ordering::SeqCst);
                Ok(3)
            })
            .await;
        assert!(matches!(r, Err(FlightError::StillRunning { step: "ready", .. })), "{r:?}");
        // A second caller joins the same attempt; it does not start another.
        let starts = Arc::new(AtomicUsize::new(0));
        let s = starts.clone();
        let r = flight
            .run(MS(2000), MS(2000), move |_| async move {
                s.fetch_add(1, Ordering::SeqCst);
                Ok(99)
            })
            .await;
        assert_eq!(r, Ok(3));
        assert_eq!(starts.load(Ordering::SeqCst), 0, "joined, not restarted");
        assert_eq!(done.load(Ordering::SeqCst), 1);
        // Even a caller that is dropped mid-wait leaves the attempt running.
        let d = done.clone();
        let f2 = flight.clone();
        let h = tokio::spawn(async move {
            f2.run(MS(2000), MS(2000), move |_| async move {
                tokio::time::sleep(MS(100)).await;
                d.fetch_add(1, Ordering::SeqCst);
                Ok(4)
            })
            .await
        });
        tokio::time::sleep(MS(20)).await;
        h.abort();
        tokio::time::sleep(MS(200)).await;
        assert_eq!(done.load(Ordering::SeqCst), 2, "the aborted caller's attempt still completed");
    }

    /// A finished failure is not replayed to the next caller.
    #[tokio::test]
    async fn a_finished_attempt_is_never_joined() {
        let flight: SpawnFlight<u32, String> = SpawnFlight::default();
        let r = flight.run(MS(500), MS(500), |_| async { Err("boom".to_string()) }).await;
        assert_eq!(r, Err(FlightError::Failed("boom".into())));
        let r = flight.run(MS(500), MS(500), |_| async { Ok(5) }).await;
        assert_eq!(r, Ok(5));
    }

    /// A lock wait logs (and counts), naming the holder and its step.
    #[tokio::test]
    async fn a_long_lock_wait_logs_the_holder() {
        let lock = Arc::new(RoleLock::default());
        let holder = Progress::new("exit_cleanup");
        holder.set("kill_leftovers");
        let g = lock.lock_logged(&holder, "t1", "detect", MS(1000)).await;
        assert_eq!(lock.holder().map(|(l, s, _)| (l, s)), Some(("exit_cleanup", "kill_leftovers")));
        let l = lock.clone();
        let waiter = tokio::spawn(async move {
            let p = Progress::new("spawn");
            p.set("role_lock");
            let _g = l.lock_logged(&p, "t1", "detect", MS(30)).await;
        });
        tokio::time::sleep(MS(120)).await;
        assert!(lock.waits_logged.load(Ordering::Relaxed) >= 2, "waits logged: {}", lock.waits_logged.load(Ordering::Relaxed));
        drop(g);
        tokio::time::timeout(MS(500), waiter).await.expect("waiter got the lock").unwrap();
    }

    /// Tenant isolation: one tenant's hung detect spawn never blocks another
    /// tenant's detect wake (each tenant role has its own lock and flight).
    #[tokio::test]
    async fn a_hung_tenant_does_not_block_another_tenant() {
        struct Slot { lock: Arc<RoleLock>, flight: SpawnFlight<u32, String> }
        let a = Slot { lock: Arc::new(RoleLock::default()), flight: SpawnFlight::default() };
        let b = Slot { lock: Arc::new(RoleLock::default()), flight: SpawnFlight::default() };
        let la = a.lock.clone();
        let hung = a.flight.run(MS(5000), MS(50), move |p| async move {
            let _g = la.lock_logged(&p, "a", "detect", MS(1000)).await;
            std::future::pending::<()>().await;
            Ok(0)
        });
        assert!(matches!(hung.await, Err(FlightError::StillRunning { .. })));
        assert!(a.lock.try_lock().is_err(), "tenant a's spawn still holds its lock");
        let lb = b.lock.clone();
        let t0 = Instant::now();
        let r = b.flight.run(MS(500), MS(500), move |p| async move {
            let _g = lb.lock_logged(&p, "b", "detect", MS(1000)).await;
            Ok(2)
        }).await;
        assert_eq!(r, Ok(2));
        assert!(t0.elapsed() < MS(200));
        assert_eq!(b.lock.waits_logged.load(Ordering::Relaxed), 0);
    }
}
