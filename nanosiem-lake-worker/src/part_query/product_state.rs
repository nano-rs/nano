// SPDX-License-Identifier: AGPL-3.0-or-later
//! Single-flight, bounded product-state work. Requests only enqueue cache misses.
use super::{
    engine::{AdmissionSlot, PartQueryEngine},
    partials, risk,
};
use crate::parts::part_log::PartRef;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};

pub(super) const WARMING: &str = "product_state_warming";
tokio::task_local! { pub(super) static BUILD: (); }
static PENDING: Mutex<VecDeque<(PathBuf, Work)>> = Mutex::new(VecDeque::new());

#[derive(Clone, PartialEq, Eq)]
pub(super) enum Work {
    Window(i64, i64),
    History(Vec<PartRef>),
    Detail(String, i64, i64),
    Risk(i64, i64),
    Prevalence(Vec<PartRef>),
}

pub(super) fn building() -> bool {
    BUILD.try_with(|_| ()).is_ok()
}

/// NAN-3168: native threads one product-state statement may use. chDB runs
/// a statement's pipeline on its own global pool, so neither the nice-19
/// publisher thread nor its cgroup weight reaches the threads doing the
/// work; only the statement's own thread budget bounds it. One thread keeps
/// a cycle on at most ~1 core beside interactive search.
pub const THREADS_ENV: &str = "NANO_LAKE_PRODUCT_STATE_THREADS";
pub const DEFAULT_THREADS: u64 = 1;
const MAX_THREADS: u64 = 64;

/// The configured product-state statement thread budget (1..=64).
pub fn build_threads() -> u64 {
    parse_threads(std::env::var(THREADS_ENV).ok().as_deref())
}

fn parse_threads(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|threads| *threads > 0)
        .map_or(DEFAULT_THREADS, |threads| threads.min(MAX_THREADS))
}

/// NAN-3279: input bytes one fold step of a maintained prevalence state may
/// read. A fold over more state bytes than this runs as several statements,
/// each over a disjoint hash range of the entity key (so each is a fraction
/// of the whole fold, its own admission slot and its own `max_execution_time`).
/// Measured on chDB 26.7 at one thread: ~13 ms per input MiB (fast core),
/// so the default step stays a few seconds even on a contended node.
pub const STEP_BYTES_ENV: &str = "NANO_LAKE_PRODUCT_STATE_STEP_BYTES";
pub const DEFAULT_STEP_BYTES: u64 = 128 << 20;
/// NAN-3279: the event hours one leaf state (a statement over raw prevalence
/// partials) covers: aligned groups of this many hours within a day (a
/// divisor of 24), so a leaf statement reads at most that many hours of
/// partials and a sliding window edge rebuilds one group, not a whole day.
pub const LEAF_HOURS_ENV: &str = "NANO_LAKE_PRODUCT_STATE_LEAF_HOURS";
pub const DEFAULT_LEAF_HOURS: i64 = 4;
#[cfg(test)]
static STEP_BYTES_OVERRIDE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The configured fold step budget (bytes of state input per statement).
pub fn step_bytes() -> u64 {
    #[cfg(test)]
    {
        let forced = STEP_BYTES_OVERRIDE.load(std::sync::atomic::Ordering::Relaxed);
        if forced > 0 {
            return forced;
        }
    }
    parse_step_bytes(std::env::var(STEP_BYTES_ENV).ok().as_deref())
}

/// Tests: force the fold step budget for this process (0: back to the env).
#[cfg(test)]
pub(super) fn force_step_bytes(bytes: u64) {
    STEP_BYTES_OVERRIDE.store(bytes, std::sync::atomic::Ordering::Relaxed);
}

fn parse_step_bytes(value: Option<&str>) -> u64 {
    value
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(DEFAULT_STEP_BYTES)
}

/// The configured leaf width in event hours (a divisor of 24).
pub fn leaf_hours() -> i64 {
    parse_leaf_hours(std::env::var(LEAF_HOURS_ENV).ok().as_deref())
}

fn parse_leaf_hours(value: Option<&str>) -> i64 {
    value
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|hours| *hours > 0 && 24 % *hours == 0)
        .unwrap_or(DEFAULT_LEAF_HOURS)
}

/// The `max_threads` a statement gets: the product budget (never above the
/// interactive one) under build authority, else `query_threads` unchanged.
pub(super) fn statement_threads(query_threads: u64) -> u64 {
    if building() {
        build_threads().min(query_threads.max(1))
    } else {
        query_threads
    }
}

/// The thread settings of one statement (no leading `SETTINGS`). Under build
/// authority Parquet decoding is bounded too: `max_parsing_threads` defaults
/// to every core regardless of `max_threads`.
pub(super) fn thread_settings(query_threads: u64) -> String {
    let threads = statement_threads(query_threads);
    if building() {
        format!("max_threads={threads}, max_parsing_threads={threads}")
    } else {
        format!("max_threads={threads}")
    }
}

/// NAN-3168 evidence for one build: wall time and process CPU (all threads:
/// chDB's pool is not attributable per statement; in-process mode includes
/// concurrent search CPU, so it is an upper bound there).
pub(super) struct BuildMeter {
    wall: std::time::Instant,
    cpu_ms: Option<f64>,
}

pub(super) const CPU_SCOPE: &str = "process";

impl BuildMeter {
    pub(super) fn start() -> Self {
        Self {
            wall: std::time::Instant::now(),
            cpu_ms: crate::query_timing::process_cpu_ms(),
        }
    }

    pub(super) fn wall_ms(&self) -> u64 {
        self.wall.elapsed().as_millis() as u64
    }

    pub(super) fn cpu_ms(&self) -> u64 {
        match (self.cpu_ms, crate::query_timing::process_cpu_ms()) {
            (Some(started), Some(now)) => (now - started).max(0.0) as u64,
            _ => 0,
        }
    }
}

pub(super) fn enqueue(state: &Path, work: Work) {
    let mut pending = PENDING.lock().expect("product state queue");
    if pending.iter().filter(|(path, _)| path == state).count() < 64
        && !pending
            .iter()
            .any(|(path, item)| path == state && item == &work)
    {
        pending.push_back((state.to_path_buf(), work));
    }
}

/// File `work` with whoever builds product state for this process: the
/// in-process queue keyed by `state` (engines without published state:
/// detect, tests), or the demand inbox of the publisher (product[T]'s, or
/// query's own in-process one) (NAN-3148). Never builds.
pub(super) fn request_at(engine: &PartQueryEngine, state: &Path, work: Work) {
    match engine.product_state() {
        Some(published) if published.mode() != super::product_publish::Mode::Publisher => {
            super::product_publish::demand(published.dir(), &work);
        }
        _ => enqueue(state, work),
    }
}

/// Where product state files under `state` live for this process: product[T]'s
/// dir when one is configured (NAN-3148), else `state` itself.
pub(super) fn dir_for<'a>(engine: &'a PartQueryEngine, state: &'a Path) -> &'a Path {
    match engine.product_state() {
        Some(published) => published.dir(),
        None => state,
    }
}

/// Tests: the in-process build oracle (no worker drains this queue).
#[cfg(test)]
pub(super) fn take(state: &Path) -> Option<Work> {
    let mut pending = PENDING.lock().expect("product state queue");
    let index = pending.iter().position(|(path, _)| path == state)?;
    pending.remove(index).map(|(_, work)| work)
}

/// How often a waiting build statement retries the idle slot.
const IDLE_POLL: Duration = Duration::from_millis(100);

/// NAN-3858: the longest a background build statement (window, history,
/// fold step, risk ledger) defers to a running detail demand at one
/// statement boundary. A demand's slices then run back to back; once a
/// background statement has waited this long it runs next, so a window
/// build makes at least one statement of progress per this much demand
/// work, and a demand behind a long build is never starved either.
pub(super) const MAX_DEFERRAL: Duration = Duration::from_secs(60);

/// NAN-3858: who gets the product process's idle slot next. A detail demand
/// is interactive (a person expanded a row and polls for it); window
/// statements are background. Both still take the slot only when no user
/// work runs ([`PartQueryEngine::try_admit_idle`]).
#[derive(Default)]
pub(super) struct Priority {
    /// Detail demand builds in flight (between their slices too).
    demands: std::sync::atomic::AtomicUsize,
    /// A background statement has deferred [`MAX_DEFERRAL`] and runs next:
    /// demand slices hold off until it has the slot.
    overdue: std::sync::atomic::AtomicUsize,
}

static PRIORITY: Priority = Priority {
    demands: std::sync::atomic::AtomicUsize::new(0),
    overdue: std::sync::atomic::AtomicUsize::new(0),
};

/// Marks a detail demand build in flight for its lifetime.
pub(super) struct DemandActive<'a>(&'a Priority);

impl Drop for DemandActive<'_> {
    fn drop(&mut self) {
        self.0.demands.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Clears an overdue mark however the waiting statement ends.
struct Overdue<'a>(Option<&'a Priority>);

impl Overdue<'_> {
    fn clear(&mut self) {
        if let Some(priority) = self.0.take() {
            priority.overdue.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for Overdue<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Priority {
    pub(super) fn demand(&self) -> DemandActive<'_> {
        self.demands.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        DemandActive(self)
    }

    fn demand_running(&self) -> bool {
        self.demands.load(std::sync::atomic::Ordering::SeqCst) > 0
    }

    /// A background statement's slot: deferred while a demand runs, for at
    /// most `max_deferral` (then it runs next, ahead of the demand).
    pub(super) async fn background<S>(&self, max_deferral: Duration, mut admit: impl FnMut() -> Option<S>) -> S {
        let started = tokio::time::Instant::now();
        let mut overdue = Overdue(None);
        loop {
            let deferring = self.demand_running() && started.elapsed() < max_deferral;
            if !deferring {
                if overdue.0.is_none() && self.demand_running() {
                    self.overdue.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    overdue.0 = Some(self);
                }
                if let Some(slot) = admit() {
                    overdue.clear();
                    return slot;
                }
            }
            tokio::time::sleep(IDLE_POLL).await;
        }
    }

    /// A demand slice's slot: ahead of background statements unless one is
    /// overdue. The wait is never charged to the demand's budget.
    pub(super) async fn demand_slot<S>(&self, mut admit: impl FnMut() -> Option<S>) -> S {
        loop {
            if self.overdue.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                if let Some(slot) = admit() {
                    return slot;
                }
            }
            tokio::time::sleep(IDLE_POLL).await;
        }
    }
}

/// Mark a detail demand build in flight in this process (NAN-3858).
pub(super) fn demand_active() -> DemandActive<'static> {
    PRIORITY.demand()
}

/// Yield between immutable parts/statements. Never queue behind user work;
/// defer (boundedly) to a running detail demand (NAN-3858).
pub(super) async fn idle(engine: &PartQueryEngine) -> AdmissionSlot {
    PRIORITY.background(MAX_DEFERRAL, || engine.try_admit_idle()).await
}

/// One detail demand slice's idle slot (NAN-3858): ahead of background
/// statements unless one has deferred [`MAX_DEFERRAL`].
pub(super) async fn idle_for_demand(engine: &PartQueryEngine) -> AdmissionSlot {
    PRIORITY.demand_slot(|| engine.try_admit_idle()).await
}

#[cfg(test)]
pub(super) async fn prepare(
    engine: &PartQueryEngine,
    state: &Path,
    work: Work,
) -> anyhow::Result<()> {
    engine
        .pinned_if_needed(BUILD.scope((), async {
            match work {
                Work::History(parts) => {
                    partials::maintained_history(engine, &parts).await?;
                }
                Work::Window(from, to) => {
                    partials::maintained_window(engine, from, to).await?;
                }
                Work::Detail(request, from, to) => {
                    let request = serde_json::from_str(&request)?;
                    partials::maintained_detail_bounds(engine, &request, from, to).await?;
                }
                Work::Risk(from, to) => {
                    risk::ledger(engine, state, from, to).await?;
                }
                Work::Prevalence(parts) => {
                    partials::maintained_prevalence(engine, &parts).await?;
                }
            }
            Ok(())
        }))
        .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn build_authority_is_task_local() {
        assert!(!building());
        BUILD
            .scope((), async {
                assert!(building());
                assert!(!tokio::spawn(async { building() }).await.unwrap());
            })
            .await;
        assert!(!building());
    }
    #[tokio::test]
    async fn build_statements_are_bounded_to_the_product_thread_budget() {
        assert_eq!(parse_threads(None), DEFAULT_THREADS);
        assert_eq!(parse_threads(Some("0")), DEFAULT_THREADS);
        assert_eq!(parse_threads(Some("junk")), DEFAULT_THREADS);
        assert_eq!(parse_threads(Some(" 2 ")), 2);
        assert_eq!(parse_threads(Some("999")), MAX_THREADS);
        // Outside build authority: the interactive budget, untouched.
        assert_eq!(statement_threads(8), 8);
        assert_eq!(thread_settings(8), "max_threads=8");
        BUILD
            .scope((), async {
                let budget = build_threads();
                assert_eq!(statement_threads(8), budget.min(8));
                assert_eq!(
                    statement_threads(0),
                    1,
                    "never zero (chDB: auto = every core)"
                );
                assert_eq!(
                    thread_settings(8),
                    format!("max_threads={0}, max_parsing_threads={0}", budget.min(8))
                );
            })
            .await;
    }
    #[test]
    fn fold_step_and_leaf_knobs_parse_with_safe_defaults() {
        assert_eq!(parse_step_bytes(None), DEFAULT_STEP_BYTES);
        assert_eq!(parse_step_bytes(Some("0")), DEFAULT_STEP_BYTES);
        assert_eq!(parse_step_bytes(Some("junk")), DEFAULT_STEP_BYTES);
        assert_eq!(parse_step_bytes(Some(" 1048576 ")), 1 << 20);
        assert_eq!(parse_leaf_hours(None), DEFAULT_LEAF_HOURS);
        assert_eq!(parse_leaf_hours(Some("6")), 6);
        assert_eq!(parse_leaf_hours(Some("24")), 24);
        assert_eq!(
            parse_leaf_hours(Some("5")),
            DEFAULT_LEAF_HOURS,
            "not a divisor of a day"
        );
        assert_eq!(parse_leaf_hours(Some("0")), DEFAULT_LEAF_HOURS);
        assert_eq!(parse_leaf_hours(Some("-4")), DEFAULT_LEAF_HOURS);
    }
    /// NAN-3858 convergence model: the real [`Priority`] gate over a
    /// one-permit idle slot, in paused time. A window build of `statements`
    /// statements of `statement` each is running when `demands` detail
    /// demands arrive back to back, each needing `scan` of slice work in
    /// `slice` statements. Returns (each demand's completion after it was
    /// filed, the window build's end, the longest gap between two window
    /// statement starts while a demand ran).
    async fn model(statement: Duration, statements: usize, demands: usize, scan: Duration, slice: Duration)
        -> (Vec<Duration>, Duration, Duration) {
        use std::sync::Arc;
        use tokio::time::Instant;
        let priority = Arc::new(Priority::default());
        let slot = Arc::new(tokio::sync::Semaphore::new(1));
        let admit = |slot: &Arc<tokio::sync::Semaphore>| slot.clone().try_acquire_owned().ok();
        let t0 = Instant::now();
        let starts = Arc::new(Mutex::new(Vec::new()));
        let window = {
            let (priority, slot, starts) = (priority.clone(), slot.clone(), starts.clone());
            tokio::spawn(async move {
                for _ in 0..statements {
                    let _held = priority.background(MAX_DEFERRAL, || admit(&slot)).await;
                    starts.lock().unwrap().push(t0.elapsed());
                    tokio::time::sleep(statement).await;
                }
                t0.elapsed()
            })
        };
        // Filed mid-statement: the worst case for the first slot wait.
        tokio::time::sleep(statement / 2).await;
        let mut done = Vec::new();
        let mut busy = Vec::new();
        for _ in 0..demands {
            let filed = Instant::now();
            let _active = priority.demand();
            let mut left = scan;
            while !left.is_zero() {
                let _held = priority.demand_slot(|| admit(&slot)).await;
                let step = left.min(slice);
                tokio::time::sleep(step).await;
                left -= step;
            }
            done.push(filed.elapsed());
            busy.push((filed - t0, t0.elapsed()));
        }
        let window_end = window.await.unwrap();
        let starts = starts.lock().unwrap().clone();
        let (from, to) = (busy[0].0, busy.last().unwrap().1);
        let mut inside = starts.iter().copied().filter(|at| *at >= from && *at <= to).collect::<Vec<_>>();
        inside.insert(0, from);
        inside.push(to.min(window_end));
        let gap = inside.windows(2).map(|pair| pair[1].saturating_sub(pair[0])).max().unwrap_or_default();
        (done, window_end, gap)
    }

    /// NAN-3858: backlog x statement cost converges. tenant-a numbers: a 1h
    /// window statement ~30 s, fold steps up to ~28 s, window/explorer
    /// statements at their 120 s cap; a 24h common-IP detail ~5 min of scan
    /// in 5 s slices. Every demand completes within
    ///   statement (first wait) + scan + ceil(scan / MAX_DEFERRAL) x statement,
    /// the window build still runs a statement at least every
    /// MAX_DEFERRAL + slice + statement, and it ends within its own work plus
    /// the demands' work (it is delayed, never starved).
    #[tokio::test(start_paused = true)]
    async fn nan3858_detail_demands_converge_behind_long_window_statements() {
        let slice = Duration::from_secs(5);
        let scan = Duration::from_secs(300);
        let poll = IDLE_POLL * 4;
        for statement in [Duration::from_secs(30), Duration::from_secs(28), Duration::from_secs(120)] {
            for demands in [1_usize, 3] {
                let statements = 60;
                let (done, window_end, gap) = model(statement, statements, demands, scan, slice).await;
                let yields = scan.as_secs().div_ceil(MAX_DEFERRAL.as_secs()) as u32;
                let bound = statement + scan + statement * (yields + 1) + poll * (scan.as_secs() as u32);
                for (index, took) in done.iter().enumerate() {
                    // Later demands of the backlog also wait out earlier ones.
                    let backlog = bound * (index as u32 + 1);
                    assert!(*took <= backlog, "statement={statement:?} demand {index}: {took:?} > {backlog:?}");
                }
                assert!(done[0] <= bound, "statement={statement:?}: first demand {:?} > {bound:?}", done[0]);
                let progress = MAX_DEFERRAL + slice + statement + poll;
                assert!(gap <= progress, "statement={statement:?} demands={demands}: window gap {gap:?} > {progress:?}");
                let window_bound = statement * statements as u32 + scan * demands as u32 + poll * (statements as u32 + scan.as_secs() as u32 * demands as u32);
                assert!(window_end <= window_bound, "statement={statement:?}: window {window_end:?} > {window_bound:?}");
                println!("NAN3858 model statement={}s demands={demands} first_done={}s last_done={}s window_end={}s max_window_gap={}s",
                    statement.as_secs(), done[0].as_secs(), done.last().unwrap().as_secs(), window_end.as_secs(), gap.as_secs());
            }
        }
    }

    /// The old behaviour this replaces: a 10 s wall budget that included the
    /// slot wait could not even start behind any statement longer than it.
    #[tokio::test(start_paused = true)]
    async fn nan3858_a_wall_budget_with_the_slot_wait_never_converges() {
        use std::sync::Arc;
        let slot = Arc::new(tokio::sync::Semaphore::new(1));
        let held = slot.clone().try_acquire_owned().unwrap();
        let release = tokio::spawn(async move { tokio::time::sleep(Duration::from_secs(29)).await; drop(held); });
        let priority = Priority::default();
        let waited = tokio::time::timeout(Duration::from_secs(10), priority.demand_slot(|| slot.clone().try_acquire_owned().ok())).await;
        assert!(waited.is_err(), "a 10 s budget spent entirely behind one 29 s window statement (tenant-a 18:50:38-18:51:08)");
        release.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn without_a_demand_background_statements_never_defer() {
        let priority = Priority::default();
        let started = tokio::time::Instant::now();
        let slot = priority.background(MAX_DEFERRAL, || Some(())).await;
        assert_eq!(slot, ());
        assert!(started.elapsed() < IDLE_POLL);
        // A demand that ended (guard dropped) leaves nothing behind.
        drop(priority.demand());
        priority.background(MAX_DEFERRAL, || Some(())).await;
        assert!(started.elapsed() < IDLE_POLL);
        assert_eq!(priority.overdue.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn queue_is_bounded_deduplicated_and_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        for i in 0..100 {
            enqueue(dir.path(), Work::Risk(i, i + 1));
        }
        enqueue(dir.path(), Work::Risk(0, 1));
        assert!(take(other.path()).is_none());
        let mut count = 0;
        while take(dir.path()).is_some() {
            count += 1;
        }
        assert_eq!(count, 64);
    }
}

/// The timer is polled beside the build, so cancellation drops it as well.
pub(super) async fn with_progress<T>(build: impl std::future::Future<Output = T>) -> T {
    with_progress_every(build, Duration::from_secs(30)).await
}

async fn with_progress_every<T>(
    build: impl std::future::Future<Output = T>,
    period: Duration,
) -> T {
    let started = std::time::Instant::now();
    tracing::info!(wall_ms = 0_u64, "product state building");
    // Native product pipelines have large debug futures; keep them off the
    // executor stack, including the progress wrapper itself.
    let mut build = Box::pin(build);
    let mut progress = tokio::time::interval(period);
    progress.tick().await;
    loop {
        tokio::select! {
            result = &mut build => return result,
            _ = progress.tick() => tracing::info!(wall_ms = started.elapsed().as_millis() as u64, "product state building"),
        }
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;
    use tracing::instrument::WithSubscriber;
    #[derive(Clone)]
    struct Capture(std::sync::Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[tokio::test]
    async fn building_progress_logs_duration_and_stops_with_build() {
        let capture = Capture(Default::default());
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        with_progress_every(
            tokio::time::sleep(Duration::from_millis(25)),
            Duration::from_millis(5),
        )
        .with_subscriber(subscriber)
        .await;
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("INFO"));
        assert!(text.matches("product state building").count() >= 2);
        assert!(text.contains("wall_ms="));
    }
}
