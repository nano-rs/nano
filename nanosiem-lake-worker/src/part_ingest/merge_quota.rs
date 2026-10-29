// SPDX-License-Identifier: AGPL-3.0-or-later
//! Process-wide compaction admission and independent CPU-work/I/O pacing.
//! Only merges use this budget; ingest and query never acquire it. Count
//! backfill rewrites always pace, adaptively to the cell's headroom (NAN-3772).
use crate::parts::levels::Level;
use anyhow::{ensure, Context, Result};
use std::cell::RefCell;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

static ADMISSION: Mutex<[usize; 2]> = Mutex::new([0, 0]);
static READY: Condvar = Condvar::new();
static PARALLEL_CPU_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
thread_local! {
    static BUDGET: RefCell<Option<Pace>> = const { RefCell::new(None) };
    static COUNT_BACKFILL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Count rewrites are explicitly requested within the writer feature gate.
// Their safety budget is always on, independent of compaction experiments.
//
// NAN-3772: the budget charges each input row once per rewrite and the
// rewrite thread's measured CPU, both at a share of one core that adapts to
// the cell's headroom (`observe_backfill_headroom`). The NAN-3737 budget
// charged every decoded input, intermediate, spool and index-scan batch at
// its Arrow *capacity*: an IPC- or Parquet-decoded batch shares one body
// buffer across its columns, so a 673-row batch was charged 5.5 GB and one
// 1.57M-row tenant-a hour was still pacing after 90 minutes.
/// Input rows per second a rewrite may decode at full share (one core).
const BACKFILL_ROWS_PER_SECOND_AT_FULL_SHARE: u64 = 160_000;
/// CPU share of ALL running count rewrites together, in permille of one
/// core: the bounds of the adaptive backfill pace. NAN-3795: an idle cell
/// lends the backfill up to four cores (tenant-a measured ~1 ms of rewrite work
/// per row live, so one core is ~38 h for a 7 d window); the same headroom
/// signals take it back (halving) the moment ingest lag, CPU or R2 strain
/// shows pressure.
pub const BACKFILL_SHARE_MIN_PERMILLE: u64 = 100;
pub const BACKFILL_SHARE_MAX_PERMILLE: u64 = 4_000;
pub const BACKFILL_SHARE_ONE_CORE_PERMILLE: u64 = 1_000;
/// A second concurrent rewrite starts only once the cell has proven this much
/// sustained headroom (the share climbed to two cores).
pub const BACKFILL_SECOND_REWRITE_PERMILLE: u64 = 2_000;
/// Count rewrites that may run at once (each paces at its split of the share).
pub const BACKFILL_MAX_REWRITES: usize = 2;
const BACKFILL_SHARE_START_PERMILLE: u64 = 250;
const BACKFILL_SHARE_STEP_PERMILLE: u64 = 100;
/// Ingest lag (oldest pending notice) at which backfill backs off, and below
/// which it may speed up. Freshness must stay under 60 s end to end, and
/// the edge pipeline itself accounts for ~20 s of that.
const BACKFILL_LAG_BACKOFF_MS: i64 = 30_000;
const BACKFILL_LAG_IDLE_MS: i64 = 15_000;
/// Share of CFS periods throttled, and share of the cgroup CPU quota used.
const BACKFILL_THROTTLED_BACKOFF: f64 = 0.10;
const BACKFILL_THROTTLED_IDLE: f64 = 0.02;
const BACKFILL_UTILIZATION_BACKOFF: f64 = 0.85;
const BACKFILL_UTILIZATION_IDLE: f64 = 0.65;
/// Share of strained R2 attempts at which backfill backs off / may speed up.
const BACKFILL_R2_STRAIN_BACKOFF: f64 = 0.05;
const BACKFILL_R2_STRAIN_IDLE: f64 = 0.01;
static TRANSFER_FAILURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Minimum spacing between two headroom samples.
const HEADROOM_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
static BACKFILL_SHARE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(BACKFILL_SHARE_START_PERMILLE);
static BACKFILL_ROWS_DONE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BACKFILL_ROWS_TOTAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static BACKFILL_LANE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(BACKFILL_MAX_REWRITES);
/// Count rewrites currently holding a backfill pace (they split the share).
static ACTIVE_REWRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many count rewrites the scheduler may START now: none while the
/// tenant is searching, two only while the adaptive share says the cell has
/// had two cores to spare.
pub fn backfill_rewrite_slots() -> usize {
    if backfill_yielding() {
        0
    } else if backfill_share_permille() >= BACKFILL_SECOND_REWRITE_PERMILLE {
        BACKFILL_MAX_REWRITES
    } else {
        1
    }
}

/// This rewrite's split of the backfill share; the floor while searching.
fn per_rewrite_share_permille() -> u64 {
    if backfill_yielding() {
        return BACKFILL_SHARE_MIN_PERMILLE;
    }
    backfill_share_permille() / ACTIVE_REWRITES.load(std::sync::atomic::Ordering::Relaxed).max(1)
}

/// NAN-3795 (r49b k6 B: 1d p95 +50% beside a running backfill): searches
/// come first. The cell supervisor relays "this tenant's searches are in
/// flight" to ingest (`WakeReason::Query`, every 2 s while they run). For
/// [`SEARCH_QUIET`] after the last relay the backfill yields: no new probe,
/// download or rewrite starts, a running rewrite paces at the floor share
/// (0.1 core, digests included), and the adaptive share halves per sample.
/// CPU share alone missed this: k6 used 3-6 of the tenant's 15.8 ceiling
/// cores, far below the 85% backoff, while rewrites published recent hours
/// under the searches' caches.
pub const SEARCH_QUIET: Duration = Duration::from_secs(10);
/// Milliseconds after [`search_epoch`] of the last relayed search, plus one
/// (0: none seen by this process).
static SEARCH_SEEN_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn search_epoch() -> Instant {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

/// The supervisor relayed a running search on this tenant.
pub fn note_search_activity() {
    let ms = search_epoch().elapsed().as_millis() as u64 + 1;
    SEARCH_SEEN_MS.fetch_max(ms, std::sync::atomic::Ordering::Relaxed);
}

/// Did a search run on this tenant within [`SEARCH_QUIET`]?
pub fn search_active() -> bool {
    #[cfg(test)]
    {
        // Process-wide state would leak between parallel tests.
        SEARCH_FOR_TEST.with(|searching| searching.get())
    }
    #[cfg(not(test))]
    {
        searched_within_quiet(SEARCH_SEEN_MS.load(std::sync::atomic::Ordering::Relaxed), search_epoch().elapsed().as_millis() as u64 + 1)
    }
}

/// `seen`/`now`: [`SEARCH_SEEN_MS`] encoding (0 = never).
fn searched_within_quiet(seen: u64, now: u64) -> bool {
    seen > 0 && now < seen.saturating_add(SEARCH_QUIET.as_millis() as u64)
}

#[cfg(test)]
thread_local! {
    static SEARCH_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static INGEST_BEHIND_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// NAN-3811 (tenant-a 2026-10-14): the backfill also yields to the tenant's own
/// ingest maintenance. While the prevalence state is behind the part log or
/// an L0 merge is overdue past their alert thresholds (`prevalence_behind`,
/// `l0_merge_overdue` warn), no rewrite starts, a running one paces at the
/// floor, and the share halves per sample. On tenant-a a full-hour rewrite kept
/// pacing at 100-300 permille through 2.5 h of stalled prevalence (merges
/// wait for prevalence, so L0 merges fell from ~50/h to 7/h); the old
/// signals (ingest lag, CPU, R2 strain) never saw it.
static INGEST_BEHIND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The alert thresholds the backfill yields at (see [`INGEST_BEHIND`]).
pub const BACKFILL_PREVALENCE_BEHIND_BACKOFF_MS: u64 =
    (nanosiem_lake_cell::signals::PREVALENCE_BEHIND_WARN_SECS * 1_000.0) as u64;
pub const BACKFILL_L0_MERGE_OVERDUE_BACKOFF_MS: i64 =
    (nanosiem_lake_cell::signals::L0_MERGE_OVERDUE_WARN_SECS * 1_000.0) as i64;

/// Prevalence or L0 merges are past their alert thresholds.
pub fn ingest_maintenance_behind(prevalence_behind_ms: u64, l0_merge_overdue_ms: i64) -> bool {
    prevalence_behind_ms >= BACKFILL_PREVALENCE_BEHIND_BACKOFF_MS
        || l0_merge_overdue_ms >= BACKFILL_L0_MERGE_OVERDUE_BACKOFF_MS
}

/// The last headroom sample found ingest maintenance behind.
pub fn ingest_behind() -> bool {
    #[cfg(test)]
    {
        INGEST_BEHIND_FOR_TEST.with(|behind| behind.get())
    }
    #[cfg(not(test))]
    {
        INGEST_BEHIND.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
pub fn set_ingest_behind_for_test(behind: bool) {
    INGEST_BEHIND_FOR_TEST.with(|cell| cell.set(behind));
}

/// The backfill steps aside: a search is running, or ingest maintenance is
/// behind (NAN-3811).
pub fn backfill_yielding() -> bool {
    search_active() || ingest_behind()
}
#[cfg(test)]
pub fn set_searching_for_test(searching: bool) {
    SEARCH_FOR_TEST.with(|cell| cell.set(searching));
}

pub(super) async fn reserve_count_backfill() -> Result<tokio::sync::SemaphorePermit<'static>> {
    BACKFILL_LANE
        .acquire()
        .await
        .context("count backfill lane closed")
}

/// Called only on the blocking compute thread, never on the writer tick.
/// The scope resets even on failure or panic; ordinary merges stay unchanged.
pub(super) fn with_count_backfill<T>(enabled: bool, work: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            COUNT_BACKFILL.set(self.0);
        }
    }
    let _reset = Reset(COUNT_BACKFILL.replace(enabled));
    work()
}

/// One pressure sample of the cell, taken on the ingest tick.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Headroom {
    /// Age of the oldest pending edge notice (`IngestHealth::lag_ms`).
    pub lag_ms: i64,
    /// Highest share of the CPU quota used over the last interval, across
    /// this role's cgroup and its tenant parent; `None` without a quota.
    pub utilization: Option<f64>,
    /// Highest share of CFS periods throttled over the same interval.
    pub throttled: Option<f64>,
    /// Share of this process's R2 wire attempts that failed, were refused
    /// (429/5xx) or were slow over the interval (`r2_ops::strain_counters`).
    pub r2_strain: Option<f64>,
    /// Compaction transfers that failed or timed out over the interval.
    pub transfer_failures: u64,
    /// The tenant searched within [`SEARCH_QUIET`] (NAN-3795).
    pub searching: bool,
    /// NAN-3811: how long the prevalence state has been behind the part log
    /// (`IngestHealth::prevalence_behind_ms`, 0 when stamping at the head).
    pub prevalence_behind_ms: u64,
    /// NAN-3811: how long the most overdue L0 has waited past its merge
    /// deadline (`IngestHealth::l0_merge_overdue_ms`).
    pub l0_merge_overdue_ms: i64,
}

/// AIMD: halve under pressure, add a step while the cell is idle, hold in
/// between. Never below the floor, so a busy cell still converges.
pub fn next_backfill_share(current: u64, headroom: &Headroom) -> u64 {
    let pressured = headroom.lag_ms > BACKFILL_LAG_BACKOFF_MS
        || headroom.throttled.is_some_and(|t| t > BACKFILL_THROTTLED_BACKOFF)
        || headroom.utilization.is_some_and(|u| u > BACKFILL_UTILIZATION_BACKOFF)
        || headroom.r2_strain.is_some_and(|s| s > BACKFILL_R2_STRAIN_BACKOFF)
        || headroom.transfer_failures > 0
        || headroom.searching
        || ingest_maintenance_behind(headroom.prevalence_behind_ms, headroom.l0_merge_overdue_ms);
    // Grow only while prevalence is at the head and no L0 is overdue at all.
    let idle = headroom.lag_ms <= BACKFILL_LAG_IDLE_MS
        && headroom.prevalence_behind_ms == 0
        && headroom.l0_merge_overdue_ms <= 0
        && headroom.throttled.is_none_or(|t| t < BACKFILL_THROTTLED_IDLE)
        && headroom.utilization.is_none_or(|u| u < BACKFILL_UTILIZATION_IDLE)
        && headroom.r2_strain.is_none_or(|s| s < BACKFILL_R2_STRAIN_IDLE);
    let next = if pressured {
        current / 2
    } else if idle {
        // Additive below a core, then +25% per sample: 1 -> 4 cores in ~35 s
        // of sustained idle, while any pressure sample still halves it.
        current.saturating_add(BACKFILL_SHARE_STEP_PERMILLE.max(current / 4))
    } else {
        current
    };
    next.clamp(BACKFILL_SHARE_MIN_PERMILLE, BACKFILL_SHARE_MAX_PERMILLE)
}

/// The share of one core a count rewrite currently paces at (permille).
pub fn backfill_share_permille() -> u64 {
    BACKFILL_SHARE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Serializes tests that set the process-global [`BACKFILL_SHARE`]; parallel
/// test threads otherwise race on it (train 5b: two merge_quota tests flaked).
#[cfg(test)]
pub static BACKFILL_SHARE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub fn lock_backfill_share_for_test() -> std::sync::MutexGuard<'static, ()> {
    BACKFILL_SHARE_TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
pub fn set_backfill_share_for_test(permille: u64) {
    BACKFILL_SHARE.store(permille, std::sync::atomic::Ordering::Relaxed);
}

/// Input rows the running count rewrite has decoded, of its total.
pub fn backfill_progress() -> Option<(u64, u64)> {
    let total = BACKFILL_ROWS_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    (total > 0).then(|| (BACKFILL_ROWS_DONE.load(std::sync::atomic::Ordering::Relaxed).min(total), total))
}

/// Ingest tick: fold lag, prevalence and L0-merge debt (NAN-3811) and the
/// cgroup CPU counters into the backfill share. Cheap (two small cgroup
/// reads at most every 5 s), never blocks.
pub fn observe_backfill_headroom(lag_ms: i64, prevalence_behind_ms: u64, l0_merge_overdue_ms: i64) {
    type Sample = (Instant, Vec<CpuCounters>, (u64, u64), u64);
    static LAST: Mutex<Option<Sample>> = Mutex::new(None);
    let Ok(mut last) = LAST.lock() else { return };
    if last.as_ref().is_some_and(|(at, ..)| at.elapsed() < HEADROOM_SAMPLE_INTERVAL) {
        return;
    }
    let now = Instant::now();
    let counters = CpuCounters::read_own_and_parent();
    let wire = crate::r2_ops::strain_counters();
    let failures = TRANSFER_FAILURES.load(std::sync::atomic::Ordering::Relaxed);
    let (utilization, throttled, r2_strain, transfer_failures) = match last.as_ref() {
        Some((at, previous, previous_wire, previous_failures)) => {
            let (utilization, throttled) = cpu_pressure(previous, &counters, now.duration_since(*at));
            (utilization, throttled, r2_strain(*previous_wire, wire), failures.saturating_sub(*previous_failures))
        }
        None => (None, None, None, 0),
    };
    *last = Some((now, counters, wire, failures));
    let behind = ingest_maintenance_behind(prevalence_behind_ms, l0_merge_overdue_ms);
    if INGEST_BEHIND.swap(behind, std::sync::atomic::Ordering::Relaxed) != behind {
        tracing::info!(behind, prevalence_behind_ms, l0_merge_overdue_ms,
            "count backfill {} ingest maintenance (prevalence / L0 merges)", if behind { "yields to" } else { "resumes beside" });
    }
    let headroom = Headroom { lag_ms, utilization, throttled, r2_strain, transfer_failures, searching: search_active(),
        prevalence_behind_ms, l0_merge_overdue_ms };
    let current = backfill_share_permille();
    let next = next_backfill_share(current, &headroom);
    if next != current {
        BACKFILL_SHARE.store(next, std::sync::atomic::Ordering::Relaxed);
        tracing::info!(share_permille = next, previous_permille = current, lag_ms, utilization, throttled, r2_strain,
            transfer_failures, searching = headroom.searching, prevalence_behind_ms, l0_merge_overdue_ms,
            "count backfill pace adjusted to cell headroom");
    }
}

/// NAN-4460 / NAN-4464: the cell's room for a larger prevalence catch-up
/// batch. Pressured when ingest lag is past its bound (`lag_bound_ms`, the
/// ingest stall alert), or this role or its tenant slot is CPU-throttled, or
/// this process's R2 attempts are strained (the count backfill's throttle
/// and strain thresholds). Lag within [`super::prevalence::CATCH_UP_LAG_HOLD_SHARE`]
/// of the bound holds the scale.
///
/// NAN-4464 (a large hosted tenant, 2026-10-23): this used the count backfill's 30 s
/// lag backoff. A healthy cell's lag is the age of its oldest pending notice,
/// which already spans a flush interval (~30 s on the large tenant), so the large tenant sat at 72-98 s
/// with ingest keeping up (4-10 notices pending). Pressure held on every
/// batch, and the scale never left 1.
///
/// The backfill's own pressure test does not apply here. Its
/// `ingest_maintenance_behind` term is always true during a catch-up, and
/// quota utilization is not starvation: a larger batch costs less CPU and
/// fewer bytes per entry it drains, because its reads sweep the state once
/// either way. Cheap: two small cgroup reads at most every 5 s.
pub fn catch_up_headroom(lag_ms: i64, lag_bound_ms: i64) -> super::prevalence::CatchUpHeadroom {
    catch_up_headroom_given(lag_ms, lag_bound_ms, catch_up_cell_strained())
}

/// [`catch_up_headroom`] for a given cell strain (CPU throttling or R2 strain).
pub fn catch_up_headroom_given(lag_ms: i64, lag_bound_ms: i64, strained: bool) -> super::prevalence::CatchUpHeadroom {
    use super::prevalence::{CatchUpHeadroom, CATCH_UP_LAG_HOLD_SHARE};
    if lag_ms > lag_bound_ms || strained {
        CatchUpHeadroom::Pressured
    } else if lag_ms as f64 > lag_bound_ms as f64 * CATCH_UP_LAG_HOLD_SHARE {
        CatchUpHeadroom::Hold
    } else {
        CatchUpHeadroom::Room
    }
}

fn catch_up_cell_strained() -> bool {
    type Sample = (Instant, Vec<CpuCounters>, (u64, u64), bool);
    static LAST: Mutex<Option<Sample>> = Mutex::new(None);
    let Ok(mut last) = LAST.lock() else { return false };
    if let Some((at, _, _, strained)) = last.as_ref() {
        if at.elapsed() < HEADROOM_SAMPLE_INTERVAL {
            return *strained;
        }
    }
    let now = Instant::now();
    let counters = CpuCounters::read_own_and_parent();
    let wire = crate::r2_ops::strain_counters();
    let strained = last.as_ref().is_some_and(|(at, previous, previous_wire, _)| {
        let (_, throttled) = cpu_pressure(previous, &counters, now.duration_since(*at));
        throttled.is_some_and(|t| t > BACKFILL_THROTTLED_BACKOFF)
            || r2_strain(*previous_wire, wire).is_some_and(|s| s > BACKFILL_R2_STRAIN_BACKOFF)
    });
    *last = Some((now, counters, wire, strained));
    strained
}

/// Strained share of R2 wire attempts between two cumulative samples. A
/// single slow or failed request among many is noise, not pressure.
pub fn r2_strain(previous: (u64, u64), now: (u64, u64)) -> Option<f64> {
    let attempts = now.0.saturating_sub(previous.0);
    let strained = now.1.saturating_sub(previous.1);
    (attempts > 0).then(|| if strained < 2 { 0.0 } else { strained as f64 / attempts as f64 })
}

/// Cumulative counters of one cgroup v2 directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuCounters {
    pub usage_usec: u64,
    pub nr_periods: u64,
    pub nr_throttled: u64,
    /// `cpu.max` as (quota, period) microseconds; `None` when unlimited.
    pub quota: Option<(u64, u64)>,
}

impl CpuCounters {
    pub fn parse(stat: &str, max: Option<&str>) -> Option<Self> {
        let field = |name: &str| stat.lines().find_map(|line| line.strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(' ')).and_then(|v| v.trim().parse::<u64>().ok()));
        let quota = max.and_then(|max| {
            let mut parts = max.split_whitespace();
            let quota = parts.next()?.parse::<u64>().ok()?;
            let period = parts.next().and_then(|p| p.parse::<u64>().ok()).unwrap_or(100_000);
            (quota > 0 && period > 0).then_some((quota, period))
        });
        Some(Self { usage_usec: field("usage_usec")?, nr_periods: field("nr_periods").unwrap_or(0),
            nr_throttled: field("nr_throttled").unwrap_or(0), quota })
    }

    /// This role's leaf cgroup and its parent (the tenant slot, whose
    /// ceiling also covers the query role); either may be unreadable.
    fn read_own_and_parent() -> Vec<Self> {
        let read = |path: &std::path::Path| std::fs::read_to_string(path).ok();
        let Some(own) = read(std::path::Path::new("/proc/self/cgroup"))
            .and_then(|s| s.lines().find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_owned())))
            .map(|path| std::path::Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'))) else { return Vec::new() };
        let parent = own.parent().filter(|p| p.starts_with("/sys/fs/cgroup") && *p != std::path::Path::new("/sys/fs/cgroup"))
            .map(std::path::Path::to_path_buf);
        [Some(own), parent].into_iter().flatten()
            .filter_map(|dir| Self::parse(&read(&dir.join("cpu.stat"))?, read(&dir.join("cpu.max")).as_deref()))
            .collect()
    }
}

/// Highest quota utilization and throttled-period share over `elapsed`
/// across matching cgroups (`previous` and `now` in the same order).
pub fn cpu_pressure(previous: &[CpuCounters], now: &[CpuCounters], elapsed: Duration) -> (Option<f64>, Option<f64>) {
    let (mut utilization, mut throttled) = (None::<f64>, None::<f64>);
    let wall_usec = elapsed.as_micros() as f64;
    for (before, after) in previous.iter().zip(now) {
        if let (Some((quota, period)), true) = (after.quota, wall_usec > 0.0) {
            let used = after.usage_usec.saturating_sub(before.usage_usec) as f64;
            let share = used / (wall_usec * quota as f64 / period as f64);
            utilization = Some(utilization.map_or(share, |u| u.max(share)));
        }
        let periods = after.nr_periods.saturating_sub(before.nr_periods);
        if periods > 0 {
            let share = after.nr_throttled.saturating_sub(before.nr_throttled) as f64 / periods as f64;
            throttled = Some(throttled.map_or(share, |t| t.max(share)));
        }
    }
    (utilization, throttled)
}

const LIMIT_ENVS: [&str; 5] = [
    "NANO_LAKE_COMPACTION_ROWS_PER_SECOND",
    "NANO_LAKE_COMPACTION_BYTES_PER_SECOND",
    "NANO_LAKE_COMPACTION_CPU_PERCENT",
    "NANO_LAKE_COMPACTION_REMOTE_BYTES_PER_SECOND",
    "NANO_LAKE_COMPACTION_REMOTE_REQUESTS_PER_SECOND",
];

/// Pacing is an experiment, not an implicit change to production throughput.
/// Existing explicit quota overrides still opt in; `0` provides a rollback.
fn pacing_enabled() -> Result<bool> {
    pacing_enabled_from(
        std::env::var("NANO_LAKE_COMPACTION_PACING").ok().as_deref(),
        LIMIT_ENVS
            .iter()
            .any(|name| std::env::var_os(name).is_some()),
    )
}

fn pacing_enabled_from(value: Option<&str>, explicit_limit: bool) -> Result<bool> {
    match value {
        Some("1") => Ok(true),
        Some("0") => Ok(false),
        None => Ok(explicit_limit),
        Some(_) => anyhow::bail!("NANO_LAKE_COMPACTION_PACING must be 0 or 1"),
    }
}

enum Pace {
    /// Opt-in compaction pacing experiment (explicit env limits).
    Explicit(Budget),
    /// Count-backfill rewrite pacing (always on for count rewrites).
    Backfill(BackfillPace),
}

struct Budget {
    start: Instant,
    rows: u64,
    bytes: u64,
    rows_per_sec: u64,
    bytes_per_sec: u64,
    cpu_percent: u64,
    cpu_start: u64,
    parallel_start: u64,
    slots: u64,
}
impl Budget {
    /// Explicit elapsed time makes rate and CPU bounds deterministic in tests.
    fn delay(&self, elapsed: Duration, cpu_ns: u64) -> Duration {
        let work = required_duration(
            self.rows.saturating_mul(self.slots),
            self.bytes.saturating_mul(self.slots),
            self.rows_per_sec,
            self.bytes_per_sec,
        );
        let cpu = Duration::from_secs_f64(
            cpu_ns as f64 / 1e9 * 100.0 * self.slots as f64 / self.cpu_percent as f64,
        );
        work.max(cpu).saturating_sub(elapsed)
    }
}

/// Wall time owed by one count rewrite. Rows and CPU accrue independently,
/// each at the share in force when it was spent, so a share change applies
/// to the work that follows instead of re-pricing the whole rewrite.
struct BackfillPace {
    start: Instant,
    /// Rows of the rewrite's inputs: decoded rows past this are a later
    /// pass (intermediate, spool, restore) over rows already charged.
    row_cap: u64,
    rows: u64,
    owed_rows: Duration,
    owed_cpu: Duration,
    cpu_seen_ns: u64,
    cpu_start: u64,
    parallel_start: u64,
    /// Total pacing sleep of this rewrite (r49b: tells a paced rewrite from
    /// a compute-bound one in the completion line).
    slept: Duration,
    /// Rows this rewrite added to the process-wide progress total.
    reported_total: u64,
}
impl BackfillPace {
    fn new(cpu_start: u64, parallel_start: u64) -> Self {
        Self { start: Instant::now(), row_cap: u64::MAX, rows: 0, owed_rows: Duration::ZERO, owed_cpu: Duration::ZERO,
            cpu_seen_ns: 0, cpu_start, parallel_start, slept: Duration::ZERO, reported_total: 0 }
    }

    /// Charge `input_rows` decoded rows and the CPU spent so far (`cpu_ns`,
    /// cumulative for this rewrite) at `share_permille`; the remaining delay.
    /// `strict` (a search is running): this charge's own CPU is paced too,
    /// without spending slack banked earlier while the rewrite waited on I/O.
    fn charge(&mut self, input_rows: u64, cpu_ns: u64, share_permille: u64, elapsed: Duration, strict: bool) -> Duration {
        let share = share_permille.clamp(BACKFILL_SHARE_MIN_PERMILLE, BACKFILL_SHARE_MAX_PERMILLE) as f64 / BACKFILL_SHARE_ONE_CORE_PERMILLE as f64;
        let rows = input_rows.min(self.row_cap.saturating_sub(self.rows));
        self.rows += rows;
        self.owed_rows += Duration::from_secs_f64(rows as f64 / (BACKFILL_ROWS_PER_SECOND_AT_FULL_SHARE as f64 * share));
        let cpu = cpu_ns.saturating_sub(self.cpu_seen_ns);
        self.cpu_seen_ns = self.cpu_seen_ns.max(cpu_ns);
        self.owed_cpu += Duration::from_secs_f64(cpu as f64 / 1e9 / share);
        let cumulative = self.owed_rows.max(self.owed_cpu).saturating_sub(elapsed);
        if strict {
            return cumulative.max(Duration::from_secs_f64(cpu as f64 / 1e9 * (1.0 / share - 1.0).max(0.0)));
        }
        cumulative
    }
}

pub struct Permit {
    /// The admission lane this permit holds; `None` for a count rewrite,
    /// which the backfill lane bounds instead (NAN-3795: rewrites never
    /// occupy a history slot a sealed-hour merge needs).
    lane: Option<usize>,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}
fn limit(name: &str, default: u64) -> Result<u64> {
    let value = std::env::var(name)
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .with_context(|| format!("invalid {name}"))?
        .unwrap_or(default);
    ensure!(value > 0, "{name} must be positive");
    Ok(value)
}
#[cfg(test)]
pub fn acquire() -> Result<Permit> {
    acquire_for(Level::Hour)
}
pub fn acquire_for(level: Level) -> Result<Permit> {
    let lane = usize::from(level != Level::Minute);
    if COUNT_BACKFILL.get() {
        ACTIVE_REWRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        BUDGET.with(|budget| {
            *budget.borrow_mut() = Some(Pace::Backfill(BackfillPace::new(
                thread_cpu_ns(),
                PARALLEL_CPU_NS.load(std::sync::atomic::Ordering::Relaxed),
            )));
        });
        return Ok(Permit { lane: None, _thread_bound: std::marker::PhantomData });
    }
    let cap = super::merge_lanes::capacity(level);
    let mut counts = ADMISSION
        .lock()
        .map_err(|_| anyhow::anyhow!("compaction admission poisoned"))?;
    while counts[lane] >= cap {
        counts = READY
            .wait(counts)
            .map_err(|_| anyhow::anyhow!("compaction admission poisoned"))?;
    }
    counts[lane] += 1;
    drop(counts);
    let permit = Permit {
        lane: Some(lane),
        _thread_bound: std::marker::PhantomData,
    };
    if !pacing_enabled()? {
        return Ok(permit);
    }
    let slots = (super::merge_lanes::capacity(Level::Minute)
        + super::merge_lanes::capacity(Level::Hour)) as u64;
    let rows_per_sec = limit("NANO_LAKE_COMPACTION_ROWS_PER_SECOND", 20_000)?;
    let bytes_per_sec = limit("NANO_LAKE_COMPACTION_BYTES_PER_SECOND", 32 * 1024 * 1024)?;
    let cpu_percent = limit("NANO_LAKE_COMPACTION_CPU_PERCENT", 25)?;
    ensure!(
        cpu_percent <= 100,
        "compaction CPU percent must be at most 100"
    );
    // Split explicit process quotas conservatively across every possible job.
    BUDGET.with(|budget| {
        *budget.borrow_mut() = Some(Pace::Explicit(Budget {
            start: Instant::now(),
            rows: 0,
            bytes: 0,
            rows_per_sec,
            bytes_per_sec,
            cpu_percent,
            slots,
            cpu_start: thread_cpu_ns(),
            parallel_start: PARALLEL_CPU_NS.load(std::sync::atomic::Ordering::Relaxed),
        }))
    });
    Ok(permit)
}

/// Name the input rows of the merge holding this thread's permit. A count
/// rewrite charges each of them once, whatever passes re-read them.
pub fn set_rewrite_rows(rows: u64) {
    BUDGET.with(|budget| {
        if let Some(Pace::Backfill(pace)) = budget.borrow_mut().as_mut() {
            // Sums over every running rewrite (NAN-3795: up to two).
            BACKFILL_ROWS_TOTAL.fetch_add(rows.saturating_sub(pace.reported_total), std::sync::atomic::Ordering::Relaxed);
            pace.row_cap = rows;
            pace.reported_total = rows;
        }
    });
}

/// Logical bytes of a batch: the slices its arrays reference, not the
/// capacity of the buffers behind them. IPC and Parquet decoders back every
/// column of a batch with one shared allocation, so
/// `RecordBatch::get_array_memory_size` counts that allocation once per
/// buffer (NAN-3772: 5.5 GB for a 673-row batch).
pub fn batch_bytes(batch: &arrow_array::RecordBatch) -> u64 {
    use arrow_array::Array;
    batch.columns().iter()
        .map(|column| column.to_data().get_slice_memory_size().unwrap_or_else(|_| column.get_array_memory_size()) as u64)
        .sum()
}

/// Charge a batch of merge input as the k-way merge decodes it: the one
/// site a count rewrite counts rows at (once per input row).
pub fn charge_input(rows: u64, bytes: u64) {
    charge_rows(rows, bytes, true)
}

/// Charge any other pass (spill, sort, spool, index scan): explicit pacing
/// counts it, a count rewrite only accrues the CPU it spent.
pub fn charge(rows: u64, bytes: u64) {
    charge_rows(rows, bytes, false)
}

fn charge_rows(rows: u64, bytes: u64, input: bool) {
    let delay = BUDGET.with(|budget| {
        let mut budget = budget.borrow_mut();
        match budget.as_mut() {
            None => Duration::ZERO,
            Some(Pace::Explicit(budget)) => {
                budget.rows = budget.rows.saturating_add(rows);
                budget.bytes = budget.bytes.saturating_add(bytes);
                let cpu_ns = cpu_since(budget.cpu_start, budget.parallel_start);
                budget.delay(budget.start.elapsed(), cpu_ns)
            }
            Some(Pace::Backfill(pace)) => {
                let cpu_ns = cpu_since(pace.cpu_start, pace.parallel_start);
                let before = pace.rows;
                let delay = pace.charge(if input { rows } else { 0 }, cpu_ns, per_rewrite_share_permille(), pace.start.elapsed(), backfill_yielding());
                BACKFILL_ROWS_DONE.fetch_add(pace.rows - before, std::sync::atomic::Ordering::Relaxed);
                pace.slept += delay;
                delay
            }
        }
    });
    if !delay.is_zero() {
        if delay >= Duration::from_secs(10) {
            tracing::warn!(
                wait_seconds = delay.as_secs_f64(),
                rows,
                bytes,
                "compaction quota pacing wait"
            );
        }
        std::thread::sleep(delay);
    }
}

fn cpu_since(cpu_start: u64, parallel_start: u64) -> u64 {
    thread_cpu_ns().saturating_sub(cpu_start).saturating_add(
        PARALLEL_CPU_NS
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_sub(parallel_start),
    )
}
/// Thread CPU excludes sleeps, I/O waits and other tenant/query threads.
pub fn thread_cpu_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: writable timespec and the current thread's POSIX CPU clock.
    if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) } != 0 {
        return 0;
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}
pub fn active_on_this_thread() -> bool {
    BUDGET.with(|budget| budget.borrow().is_some())
}
pub fn charge_parallel_cpu(ns: u64) {
    PARALLEL_CPU_NS.fetch_add(ns, std::sync::atomic::Ordering::Relaxed);
}
fn required_duration(rows: u64, bytes: u64, rows_per_sec: u64, bytes_per_sec: u64) -> Duration {
    Duration::from_secs_f64(
        (rows as f64 / rows_per_sec as f64).max(bytes as f64 / bytes_per_sec as f64),
    )
}
impl Drop for Permit {
    fn drop(&mut self) {
        BUDGET.with(|budget| match budget.borrow_mut().take() {
            Some(Pace::Backfill(pace)) => {
                // One line per count rewrite: where its wall time went. The
                // parallel term is process-wide digest CPU since the start.
                let own = thread_cpu_ns().saturating_sub(pace.cpu_start);
                let parallel = PARALLEL_CPU_NS.load(std::sync::atomic::Ordering::Relaxed).saturating_sub(pace.parallel_start);
                let wall = pace.start.elapsed();
                tracing::info!(rows = pace.rows, wall_s = wall.as_secs_f64(), thread_cpu_s = own as f64 / 1e9,
                    parallel_cpu_s = parallel as f64 / 1e9, paced_sleep_s = pace.slept.as_secs_f64(),
                    us_per_row = if pace.rows > 0 { wall.as_secs_f64() * 1e6 / pace.rows as f64 } else { 0.0 },
                    share_permille = backfill_share_permille(),
                    concurrent = ACTIVE_REWRITES.load(std::sync::atomic::Ordering::Relaxed), "count backfill rewrite cost");
                BACKFILL_ROWS_DONE.fetch_sub(pace.rows.min(BACKFILL_ROWS_DONE.load(std::sync::atomic::Ordering::Relaxed)), std::sync::atomic::Ordering::Relaxed);
                BACKFILL_ROWS_TOTAL.fetch_sub(pace.reported_total.min(BACKFILL_ROWS_TOTAL.load(std::sync::atomic::Ordering::Relaxed)), std::sync::atomic::Ordering::Relaxed);
                ACTIVE_REWRITES.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        });
        if let Some(lane) = self.lane {
            ADMISSION.lock().expect("compaction admission poisoned")[lane] -= 1;
            READY.notify_all();
        }
    }
}
/// Independent process-wide remote transfer lane. Only compaction calls this;
/// ordinary ingestion and interactive readers never wait on it. Reserve signed
/// object lengths before transfers, rather than charging a large GET afterward.
///
/// NAN-3187: one permit per history lane (`merge_lanes::capacity(Hour)`,
/// default 2), so two concurrent hour merges download side by side instead
/// of strictly in turn. An explicit pacing quota stays process-wide: each
/// permit holder paces at its share of the configured rate.
fn remote_lane() -> &'static tokio::sync::Semaphore {
    static REMOTE: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    REMOTE.get_or_init(|| tokio::sync::Semaphore::new(remote_permits()))
}

fn remote_permits() -> usize {
    super::merge_lanes::capacity(Level::Hour)
}

pub async fn reserve_remote(bytes: u64) -> Result<tokio::sync::SemaphorePermit<'static>> {
    let paced = pacing_enabled()?;
    let waiting = Instant::now();
    let lock = remote_lane().acquire();
    tokio::pin!(lock);
    let guard = loop {
        tokio::select! {
            guard = &mut lock => break guard.context("compaction remote lane closed")?,
            _ = tokio::time::sleep(Duration::from_secs(10)) =>
                tracing::warn!(wait_seconds = waiting.elapsed().as_secs_f64(), bytes, "compaction remote lane waiting"),
        }
    };
    if !paced {
        return Ok(guard);
    }
    let permits = remote_permits() as u64;
    let bytes_per_sec = limit(
        "NANO_LAKE_COMPACTION_REMOTE_BYTES_PER_SECOND",
        32 * 1024 * 1024,
    )?;
    let requests_per_sec = limit("NANO_LAKE_COMPACTION_REMOTE_REQUESTS_PER_SECOND", 4)?;
    let duration = required_duration(
        1,
        bytes,
        (requests_per_sec / permits).max(1),
        (bytes_per_sec / permits).max(1),
    );
    if duration >= Duration::from_secs(10) {
        tracing::warn!(
            wait_seconds = duration.as_secs_f64(),
            bytes,
            "compaction remote quota pacing wait"
        );
    }
    tokio::time::sleep(duration).await;
    Ok(guard)
}

/// Occupy the whole remote lane (tests: a stalled store).
#[cfg(test)]
pub async fn hold_remote_lane() -> tokio::sync::SemaphorePermit<'static> {
    remote_lane()
        .acquire_many(remote_permits() as u32)
        .await
        .expect("remote lane open")
}

/// The wall-clock bound of one transfer of `bytes` once it owns the lane.
fn transfer_deadline(bytes: u64) -> Duration {
    Duration::from_secs(120 + bytes / (4 * 1024 * 1024))
}
/// A streaming download fails only after this long without a byte landing.
const TRANSFER_IDLE: Duration = Duration::from_secs(120);
const TRANSFER_PROGRESS_POLL: Duration = Duration::from_secs(5);

/// Bound a transfer while it owns the shared lane. Cancellation or failure
/// drops the guard, so a stalled store cannot starve every subsequent merge.
///
/// NAN-3772: the clock starts once the lane is held. Queueing behind other
/// merges' transfers (8 uploads of one publish share 2 permits) and any
/// explicit pacing sleep are not a stall of this transfer; counting them
/// timed out a healthy minute merge on tenant-a (2026-10-13 17:02Z).
pub async fn remote_transfer<T>(
    compacting: bool,
    bytes: u64,
    transfer: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if !compacting {
        return transfer.await;
    }
    let _permit = reserve_remote(bytes).await?;
    note_failure(transfer_with_deadline(transfer_deadline(bytes), transfer).await)
}

fn note_failure<T>(result: Result<T>) -> Result<T> {
    if result.is_err() {
        TRANSFER_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    result
}

/// [`remote_transfer`] for a download streaming into `target`: it times out
/// only when the file stops growing for [`TRANSFER_IDLE`] (or, as a backstop,
/// after 8x the size-based deadline), so a slow but progressing transfer of
/// a large backfill input is never cut off at an unthrottled merge's budget.
pub async fn remote_download<T>(
    compacting: bool,
    bytes: u64,
    target: &std::path::Path,
    transfer: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if !compacting {
        return transfer.await;
    }
    let _permit = reserve_remote(bytes).await?;
    let target = target.to_path_buf();
    note_failure(transfer_with_progress(TRANSFER_IDLE, transfer_deadline(bytes) * 8,
        move || std::fs::metadata(&target).map_or(0, |m| m.len()), transfer).await)
}

async fn transfer_with_deadline<T>(
    timeout: Duration,
    transfer: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, transfer)
        .await
        .context("compaction remote transfer timed out; lane released")?
}

async fn transfer_with_progress<T>(
    idle: Duration,
    cap: Duration,
    progress: impl Fn() -> u64,
    transfer: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::pin!(transfer);
    let started = tokio::time::Instant::now();
    let (mut seen, mut moved) = (progress(), started);
    let mut poll = tokio::time::interval_at(started + TRANSFER_PROGRESS_POLL.min(idle), TRANSFER_PROGRESS_POLL.min(idle));
    loop {
        tokio::select! {
            result = &mut transfer => return result,
            now = poll.tick() => {
                let current = progress();
                if current != seen {
                    (seen, moved) = (current, now);
                }
                if now.duration_since(moved) >= idle || now.duration_since(started) >= cap {
                    return Err(anyhow::anyhow!("no progress for {:?} after {seen} bytes ({:?} elapsed)",
                        now.duration_since(moved), now.duration_since(started)))
                        .context("compaction remote transfer timed out; lane released");
                }
            }
        }
    }
}

/// NAN-4755: share of the ingest role's `memory.max` at which a running
/// merge gives up (with [`MemoryPressure`]) instead of letting the kernel
/// OOM-kill the whole process. The scheduler then reruns it smaller
/// ([`super::merge_attempts`]).
pub const MEMORY_GUARD_SHARE: f64 = 0.85;
/// A merge thread reads its cgroup again after this long, or after
/// [`MEMORY_GUARD_BYTES`] of decoded batches, whichever comes first: a
/// burst of reader opens allocates tens of MiB within milliseconds, which a
/// time-only interval misses.
const MEMORY_GUARD_INTERVAL: Duration = Duration::from_millis(25);
const MEMORY_GUARD_BYTES: u64 = 4 * 1024 * 1024;
/// The guard stops a merge when the memory in use plus this many times
/// the batch just charged would cross [`MEMORY_GUARD_SHARE`]: each batch is
/// copied once more per family and once more by its encoder before it is
/// released, so the next step needs about twice its size. A check after
/// the fact would let one large batch take the process past the limit.
const MEMORY_GUARD_LOOKAHEAD: u64 = 2;

/// A merge stopped by the memory guard: the process's unreclaimable memory
/// reached [`MEMORY_GUARD_SHARE`] of its cgroup limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPressure {
    pub used_bytes: u64,
    pub limit_bytes: u64,
    /// NAN-4796: bytes in use when the merge's guard was armed (0 when
    /// unknown): what the process held before this merge grew.
    pub start_used_bytes: u64,
}

impl MemoryPressure {
    /// NAN-4796: is the stop the merge's own? It is when the merge started
    /// with the normal room: the process below [`MERGE_START_SHARE`] (the
    /// history start gate), so the 15 % up to the guard is what the merge
    /// used. Running it smaller (or splitting its fan-in) then helps. A
    /// merge that started past that share (a minute merge beside a full
    /// buffer, or a race with admission) was stopped by memory held
    /// elsewhere: shrinking it cannot make it fit, so it waits briefly at
    /// its shape instead of walking the ladder toward "left unmerged" (FP
    /// cell-us-1: a smallest-shape 6-input chunk stopped at the same
    /// ~1.18 GB as the 164-input hour).
    pub fn charged_to_merge(&self) -> bool {
        (self.start_used_bytes as f64) < self.limit_bytes as f64 * MERGE_START_SHARE
    }
}

impl std::fmt::Display for MemoryPressure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "merge stopped under memory pressure: {} of {} bytes in use (guard at {:.0}%; {} in use at merge start)",
            self.used_bytes, self.limit_bytes, MEMORY_GUARD_SHARE * 100.0, self.start_used_bytes)
    }
}

/// NAN-4796: the error is a guard stop that running the merge smaller
/// would help ([`MemoryPressure::charged_to_merge`]).
pub fn memory_pressure_of(error: &anyhow::Error) -> Option<MemoryPressure> {
    error.chain().find_map(|cause| cause.downcast_ref::<MemoryPressure>().copied())
}

impl std::error::Error for MemoryPressure {}

/// Did the memory guard end this merge?
pub fn is_memory_pressure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<MemoryPressure>().is_some())
}

thread_local! {
    /// `Some` while this thread runs a guarded merge: the last cgroup read.
    static MEMORY_GUARD: std::cell::Cell<Option<Option<Instant>>> = const { std::cell::Cell::new(None) };
    /// Batch bytes charged on this thread since its last cgroup read.
    static MEMORY_GUARD_PENDING: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// NAN-4796: bytes in use when the outermost guard scope was armed.
    static MEMORY_GUARD_START: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Guards the merge running on this thread until dropped.
pub struct MemoryGuardScope {
    previous: Option<Option<Instant>>,
    _thread_bound: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Arm the memory guard on this thread (the merge compute thread).
pub fn memory_guard_scope() -> MemoryGuardScope {
    let previous = MEMORY_GUARD.replace(Some(None));
    if previous.is_none() {
        // The merge's starting point: what it grows from (NAN-4796).
        MEMORY_GUARD_START.set(memory_probe().map_or(0, |(used, _)| used));
    }
    MemoryGuardScope { previous, _thread_bound: std::marker::PhantomData }
}

impl Drop for MemoryGuardScope {
    fn drop(&mut self) {
        MEMORY_GUARD.set(self.previous);
        if self.previous.is_none() {
            MEMORY_GUARD_START.set(0);
        }
    }
}

/// [`charge`], then the memory guard.
pub fn charge_checked(rows: u64, bytes: u64) -> Result<()> {
    charge(rows, bytes);
    memory_guard_after(bytes)
}

/// [`charge_input`], then the memory guard.
pub fn charge_input_checked(rows: u64, bytes: u64) -> Result<()> {
    charge_input(rows, bytes);
    memory_guard_after(bytes)
}

/// NAN-4755: fail the merge on this thread with [`MemoryPressure`] once the
/// process's unreclaimable memory reaches [`MEMORY_GUARD_SHARE`] of its
/// cgroup `memory.max`. A no-op off a guarded merge thread (admission and
/// flush code share these readers) and where no limit is known.
pub fn memory_guard() -> Result<()> {
    memory_guard_after(0)
}

/// [`memory_guard`] after `bytes` more were decoded or buffered on this
/// thread.
pub fn memory_guard_bytes(bytes: u64) -> Result<()> {
    memory_guard_after(bytes)
}

fn memory_guard_after(bytes: u64) -> Result<()> {
    let pending = MEMORY_GUARD_PENDING.get().saturating_add(bytes);
    let due = MEMORY_GUARD.with(|guard| match guard.get() {
        None => false,
        Some(Some(last)) if last.elapsed() < MEMORY_GUARD_INTERVAL && pending < MEMORY_GUARD_BYTES => false,
        Some(_) => {
            guard.set(Some(Some(Instant::now())));
            true
        }
    });
    MEMORY_GUARD_PENDING.set(if due { 0 } else { pending });
    if !due {
        return Ok(());
    }
    let Some((used_bytes, limit_bytes)) = memory_probe() else { return Ok(()) };
    if memory_guard_stops(used_bytes, limit_bytes, bytes) {
        return Err(MemoryPressure { used_bytes, limit_bytes, start_used_bytes: MEMORY_GUARD_START.get() }.into());
    }
    Ok(())
}

/// Would `batch_bytes` more, at [`MEMORY_GUARD_LOOKAHEAD`], take `used` of
/// `limit` past [`MEMORY_GUARD_SHARE`]?
fn memory_guard_stops(used: u64, limit: u64, batch_bytes: u64) -> bool {
    used.saturating_add(batch_bytes.saturating_mul(MEMORY_GUARD_LOOKAHEAD)) as f64 >= limit as f64 * MEMORY_GUARD_SHARE
}

/// NAN-4755: share of the ingest role's `memory.max` below which a history
/// merge may START. Catch-up admission and flushes share the role with the
/// merges; above this the room is theirs, and the merge waits for a later
/// tick instead of starting into the memory admission is using (FP
/// cell-us-1: the stall hour's merge fit alone, and died beside the
/// catch-up's 128-object flushes).
pub const MERGE_START_SHARE: f64 = 0.70;

/// May a history merge start now? True without a known limit (lab).
pub fn history_merge_may_start() -> bool {
    match memory_probe() {
        Some((used, limit)) => (used as f64) < limit as f64 * MERGE_START_SHARE,
        None => true,
    }
}

/// This process's cgroup `memory.max`, if known.
pub fn memory_limit() -> Option<u64> {
    memory_probe().map(|(_, limit)| limit)
}

/// (unreclaimable bytes in use, `memory.max`) of this process's cgroup.
fn memory_probe() -> Option<(u64, u64)> {
    #[cfg(test)]
    if let Some(probe) = MEMORY_PROBE_FOR_TEST.get() {
        return probe();
    }
    super::merge_lanes::cgroup_memory()
}


#[cfg(test)]
thread_local! {
    /// Tests: a memory probe for merges started from this thread (carried
    /// onto the merge compute thread by `merge_lanes::compute`).
    pub(crate) static MEMORY_PROBE_FOR_TEST: std::cell::Cell<Option<fn() -> Option<(u64, u64)>>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_memory_guard_stops_before_a_batch_would_cross_the_share() {
        // 85% of 100: 80 in use with no batch is fine.
        assert!(!memory_guard_stops(80, 100, 0));
        assert!(memory_guard_stops(85, 100, 0));
        // A 5-byte batch needs ~10 more: 80 + 10 crosses 85.
        assert!(memory_guard_stops(80, 100, 5));
        assert!(!memory_guard_stops(70, 100, 5));
    }

    #[test]
    fn the_memory_guard_only_acts_inside_a_guarded_merge() {
        fn full() -> Option<(u64, u64)> { Some((99, 100)) }
        MEMORY_PROBE_FOR_TEST.set(Some(full));
        assert!(memory_guard().is_ok(), "unguarded threads (admission, flush) are never stopped");
        {
            let _scope = memory_guard_scope();
            let error = memory_guard().unwrap_err();
            assert!(is_memory_pressure(&error.context("merge pass")), "the stop survives added context");
        }
        assert!(memory_guard().is_ok(), "the scope ended");
        MEMORY_PROBE_FOR_TEST.set(None);
    }

    /// NAN-4796: a stop is the merge's only when it grew into its own room.
    #[test]
    fn a_stop_is_charged_to_the_merge_only_when_it_used_its_room() {
        let stop = |start, used| MemoryPressure { used_bytes: used, limit_bytes: 1_000, start_used_bytes: start };
        // Started with the normal room (below the 70 % start share): its own.
        assert!(stop(100, 850).charged_to_merge());
        assert!(stop(699, 850).charged_to_merge());
        // Started at 70 % or past it: memory held elsewhere left no room.
        assert!(!stop(700, 850).charged_to_merge());
        assert!(!stop(900, 950).charged_to_merge());
        let error = anyhow::Error::from(stop(800, 810)).context("merge pass");
        assert_eq!(memory_pressure_of(&error), Some(stop(800, 810)));
        assert!(memory_pressure_of(&anyhow::anyhow!("io")).is_none());
    }


    #[test]
    fn the_guard_scope_records_where_the_merge_started() {
        fn at_600() -> Option<(u64, u64)> { Some((600, 1_000)) }
        fn at_900() -> Option<(u64, u64)> { Some((900, 1_000)) }
        MEMORY_PROBE_FOR_TEST.set(Some(at_600));
        let outer = memory_guard_scope();
        MEMORY_PROBE_FOR_TEST.set(Some(at_900));
        {
            // A nested scope (the write path) keeps the merge's start.
            let _inner = memory_guard_scope();
            let stop = memory_pressure_of(&memory_guard().unwrap_err()).unwrap();
            assert_eq!((stop.start_used_bytes, stop.used_bytes), (600, 900));
            assert!(stop.charged_to_merge());
        }
        drop(outer);
        assert_eq!(MEMORY_GUARD_START.get(), 0);
        MEMORY_PROBE_FOR_TEST.set(None);
    }

    #[test]
    fn every_history_merge_waits_at_the_start_share() {
        fn below() -> Option<(u64, u64)> { Some((69, 100)) }
        fn at() -> Option<(u64, u64)> { Some((70, 100)) }
        MEMORY_PROBE_FOR_TEST.set(Some(below));
        assert!(history_merge_may_start());
        MEMORY_PROBE_FOR_TEST.set(Some(at));
        assert!(!history_merge_may_start());
        MEMORY_PROBE_FOR_TEST.set(None);
    }
    fn pace_rows() -> Option<(u64, u64)> {
        BUDGET.with(|budget| match budget.borrow().as_ref() {
            Some(Pace::Backfill(pace)) => Some((pace.rows, pace.row_cap)),
            _ => None,
        })
    }
    #[test]
    fn count_backfill_always_has_its_budget_and_resets_scope() {
        assert!(!pacing_enabled_from(None, false).unwrap());
        with_count_backfill(true, || {
            let permit = acquire().unwrap();
            assert!(active_on_this_thread());
            // NAN-3795: a rewrite never holds a history admission slot.
            assert!(permit.lane.is_none());
            set_rewrite_rows(1_000);
            assert_eq!(pace_rows(), Some((0, 1_000)));
            charge_input(400, 0);
            charge_input(900, 0);
            assert_eq!(pace_rows(), Some((1_000, 1_000)), "capped at the rewrite's input rows");
            drop(permit);
            assert!(!active_on_this_thread());
        });
        assert!(!COUNT_BACKFILL.get());
        let _permit = acquire().unwrap();
        assert_eq!(_permit.lane, Some(1), "ordinary hour compaction holds a history slot");
        assert!(
            !active_on_this_thread(),
            "ordinary compaction stays unpaced"
        );
        let _ = std::panic::catch_unwind(|| with_count_backfill(true, || panic!("injected")));
        assert!(!COUNT_BACKFILL.get());
    }

    /// NAN-3772: every pass of one rewrite (time-order restore, k-way merge
    /// over intermediates, family spool, host sort, index scans) re-reads the
    /// same rows. Only the first decode of each input row is charged.
    #[test]
    fn backfill_charges_each_input_row_once_per_rewrite() {
        let share = 250;
        let mut once = BackfillPace::new(0, 0);
        once.row_cap = 1_000_000;
        once.charge(1_000_000, 0, share, Duration::ZERO, false);
        let mut passes = BackfillPace::new(0, 0);
        passes.row_cap = 1_000_000;
        for _ in 0..4 {
            // Pass over the input, then over an intermediate of it.
            passes.charge(1_000_000, 0, share, Duration::ZERO, false);
        }
        assert_eq!(passes.rows, 1_000_000);
        assert_eq!(passes.owed_rows, once.owed_rows);
        // 1M rows at 25% of the full-share row rate: 25 s, not 100 s.
        assert_eq!(once.owed_rows, Duration::from_secs(25));
        // Non-input passes charge no rows at all: a 5.5 GB memory-size
        // batch (the r48 log line) no longer costs 329 s.
        with_count_backfill(true, || {
            let _permit = acquire().unwrap();
            set_rewrite_rows(673);
            let started = Instant::now();
            charge(673, 5_526_216_504);
            charge(673, 5_526_216_504);
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(pace_rows(), Some((0, 673)));
        });
    }

    #[test]
    fn decoded_batch_bytes_count_each_buffer_once() {
        use arrow_array::{ArrayRef, Int64Array, RecordBatch, StringArray};
        let columns = (0..64).map(|column| {
            if column % 2 == 0 {
                std::sync::Arc::new(Int64Array::from_iter_values(0..4_096)) as ArrayRef
            } else {
                std::sync::Arc::new(StringArray::from_iter_values((0..4_096).map(|row| format!("value-{row}")))) as ArrayRef
            }
        }).collect::<Vec<_>>();
        let fields = columns.iter().enumerate()
            .map(|(i, c)| arrow_schema::Field::new(format!("c{i}"), c.data_type().clone(), false)).collect::<Vec<_>>();
        let batch = RecordBatch::try_new(std::sync::Arc::new(arrow_schema::Schema::new(fields)), columns).unwrap();
        let mut ipc = Vec::new();
        let mut writer = arrow_ipc::writer::StreamWriter::try_new(&mut ipc, &batch.schema()).unwrap();
        writer.write(&batch).unwrap();
        writer.finish().unwrap();
        drop(writer);
        let decoded = arrow_ipc::reader::StreamReader::try_new(std::io::Cursor::new(ipc), None).unwrap()
            .next().unwrap().unwrap();
        let logical = batch_bytes(&batch);
        let decoded_logical = batch_bytes(&decoded);
        assert!(decoded_logical <= logical * 2, "{decoded_logical} vs {logical}");
        // The capacity measure the NAN-3737 budget charged: one shared body
        // counted per buffer.
        assert!(decoded.get_array_memory_size() as u64 > 20 * logical,
            "{} vs {logical}", decoded.get_array_memory_size());
        // A small slice of it is charged for its own rows.
        assert!(batch_bytes(&decoded.slice(0, 64)) < logical / 32);
    }

    #[test]
    fn backfill_share_backs_off_under_ingest_pressure_and_speeds_up_when_idle() {
        let idle = Headroom { lag_ms: 5_000, utilization: Some(0.2), throttled: Some(0.0), r2_strain: Some(0.0), transfer_failures: 0, searching: false, prevalence_behind_ms: 0, l0_merge_overdue_ms: 0 };
        let mut share = BACKFILL_SHARE_START_PERMILLE;
        for _ in 0..20 {
            share = next_backfill_share(share, &idle);
        }
        assert_eq!(share, BACKFILL_SHARE_MAX_PERMILLE, "an idle cell lends the backfill up to four cores");
        let lagging = Headroom { lag_ms: 45_000, ..idle };
        share = next_backfill_share(share, &lagging);
        assert_eq!(share, 2_000, "one pressure sample halves it");
        let throttled = Headroom { throttled: Some(0.3), ..idle };
        assert_eq!(next_backfill_share(share, &throttled), 1_000);
        let busy = Headroom { utilization: Some(0.95), ..idle };
        assert_eq!(next_backfill_share(share, &busy), 1_000);
        // Above a core it grows by a quarter per idle sample.
        assert_eq!(next_backfill_share(2_000, &idle), 2_500);
        assert_eq!(next_backfill_share(3_900, &idle), BACKFILL_SHARE_MAX_PERMILLE);
        for _ in 0..20 {
            share = next_backfill_share(share, &lagging);
        }
        assert_eq!(share, BACKFILL_SHARE_MIN_PERMILLE, "never zero: a busy cell still converges");
        // Between the thresholds the share holds.
        let between = Headroom { lag_ms: 20_000, ..idle };
        assert_eq!(next_backfill_share(400, &between), 400);
        // Unknown CPU (no cgroup) decides on lag alone.
        assert_eq!(next_backfill_share(400, &Headroom { lag_ms: 0, utilization: None, throttled: None, r2_strain: None, transfer_failures: 0, searching: false, prevalence_behind_ms: 0, l0_merge_overdue_ms: 0 }), 500);
        // R2 strain (the 2026-10-13 prevalence-store timeouts) and failed
        // compaction transfers back off too, even with idle CPU and lag.
        let strained = Headroom { r2_strain: Some(0.2), ..idle };
        assert_eq!(next_backfill_share(400, &strained), 200);
        let failing = Headroom { transfer_failures: 1, ..idle };
        assert_eq!(next_backfill_share(400, &failing), 200);
        assert_eq!(r2_strain((100, 0), (200, 1)), Some(0.0), "one slow request is noise");
        assert_eq!(r2_strain((100, 0), (200, 10)), Some(0.1));
        assert_eq!(r2_strain((100, 0), (100, 0)), None);

        // The same CPU owes more wall time at a lower share: the rewrite
        // sleeps longer while ingest is pressed.
        let mut fast = BackfillPace::new(0, 0);
        let mut slow = BackfillPace::new(0, 0);
        let second = 1_000_000_000;
        assert_eq!(fast.charge(0, second, BACKFILL_SHARE_ONE_CORE_PERMILLE, Duration::ZERO, false), Duration::from_secs(1));
        assert_eq!(slow.charge(0, second, BACKFILL_SHARE_MIN_PERMILLE, Duration::ZERO, false), Duration::from_secs(10));
        // A share change prices only the work after it.
        assert_eq!(slow.charge(0, 2 * second, BACKFILL_SHARE_ONE_CORE_PERMILLE, Duration::from_secs(10), false), Duration::from_secs(1));
        // Two cores: one CPU-second owes half a second of wall.
        let mut wide = BackfillPace::new(0, 0);
        assert_eq!(wide.charge(0, second, 2_000, Duration::ZERO, false), Duration::from_millis(500));
    }

    #[test]
    fn cgroup_cpu_counters_give_utilization_and_throttling() {
        let before = CpuCounters::parse("usage_usec 1000000\nuser_usec 1\nnr_periods 100\nnr_throttled 0\n", Some("200000 100000")).unwrap();
        let after = CpuCounters::parse("usage_usec 9000000\nnr_periods 150\nnr_throttled 20\n", Some("200000 100000")).unwrap();
        assert_eq!(after.quota, Some((200_000, 100_000)));
        let (utilization, throttled) = cpu_pressure(&[before], &[after], Duration::from_secs(5));
        // 8 CPU-seconds over 5 s of a 2-core quota.
        assert!((utilization.unwrap() - 0.8).abs() < 1e-9);
        assert!((throttled.unwrap() - 0.4).abs() < 1e-9);
        let unlimited = CpuCounters::parse("usage_usec 5\n", Some("max 100000")).unwrap();
        assert_eq!(unlimited.quota, None);
        assert_eq!(cpu_pressure(&[unlimited], &[unlimited], Duration::from_secs(5)), (None, None));
        assert!(CpuCounters::parse("nr_periods 1\n", None).is_none());
    }

    #[tokio::test]
    async fn count_backfill_lane_is_process_wide_and_released_on_cancel() {
        let first = reserve_count_backfill().await.unwrap();
        // NAN-3795: two rewrites at most.
        let second = reserve_count_backfill().await.unwrap();
        assert!(BACKFILL_LANE.try_acquire().is_err());
        let waiting = tokio::spawn(async { reserve_count_backfill().await.unwrap() });
        waiting.abort();
        let _ = waiting.await;
        drop(first);
        let next = reserve_count_backfill().await.unwrap();
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let task = tokio::spawn(super::super::merge_lanes::compute(move || {
            let _permit = next;
            started.send(()).unwrap();
            blocked.recv().unwrap();
        }));
        running.await.unwrap();
        task.abort();
        let _ = task.await;
        assert!(
            BACKFILL_LANE.try_acquire().is_err(),
            "cancel cannot release a running compute's slot"
        );
        release.send(()).unwrap();
        let _next = tokio::time::timeout(Duration::from_secs(1), reserve_count_backfill())
            .await
            .unwrap()
            .unwrap();
        drop(second);
    }

    #[test]
    fn a_second_rewrite_needs_two_cores_of_headroom() {
        let _share = lock_backfill_share_for_test();
        set_backfill_share_for_test(BACKFILL_SECOND_REWRITE_PERMILLE - 1);
        assert_eq!(backfill_rewrite_slots(), 1);
        set_backfill_share_for_test(BACKFILL_SECOND_REWRITE_PERMILLE);
        assert_eq!(backfill_rewrite_slots(), BACKFILL_MAX_REWRITES);
        set_backfill_share_for_test(BACKFILL_SHARE_START_PERMILLE);
    }

    /// NAN-3795 (r49b k6 B): searches come first. While the supervisor
    /// relays a running search no rewrite starts, a running one paces at
    /// the floor without spending banked slack, and the share halves.
    #[test]
    fn backfill_yields_to_interactive_search() {
        let _share = lock_backfill_share_for_test();
        set_backfill_share_for_test(BACKFILL_SHARE_MAX_PERMILLE);
        assert_eq!(backfill_rewrite_slots(), BACKFILL_MAX_REWRITES);
        set_searching_for_test(true);
        assert_eq!(backfill_rewrite_slots(), 0, "no rewrite starts while searching");
        assert_eq!(per_rewrite_share_permille(), BACKFILL_SHARE_MIN_PERMILLE);
        let idle = Headroom { lag_ms: 0, utilization: Some(0.1), throttled: Some(0.0), r2_strain: Some(0.0), transfer_failures: 0, searching: true, prevalence_behind_ms: 0, l0_merge_overdue_ms: 0 };
        assert_eq!(next_backfill_share(4_000, &idle), 2_000, "a search sample is pressure even on an idle CPU");
        // Strict pacing: 1 s of CPU at 0.1 core owes 9 s more, even after
        // 60 s of I/O wait banked as slack.
        let second = 1_000_000_000;
        let mut pace = BackfillPace::new(0, 0);
        assert_eq!(pace.charge(0, second, BACKFILL_SHARE_MIN_PERMILLE, Duration::from_secs(60), true), Duration::from_secs(9));
        let mut lax = BackfillPace::new(0, 0);
        assert_eq!(lax.charge(0, second, BACKFILL_SHARE_MIN_PERMILLE, Duration::from_secs(60), false), Duration::ZERO);
        set_searching_for_test(false);
        assert_eq!(backfill_rewrite_slots(), BACKFILL_MAX_REWRITES);
        set_backfill_share_for_test(BACKFILL_SHARE_START_PERMILLE);
        // The relay window itself.
        assert!(!searched_within_quiet(0, 5));
        assert!(searched_within_quiet(1_000, 1_000 + SEARCH_QUIET.as_millis() as u64 - 1));
        assert!(!searched_within_quiet(1_000, 1_000 + SEARCH_QUIET.as_millis() as u64));
    }

    /// NAN-3811 (tenant-a 2026-10-14): the backfill yields when prevalence is
    /// behind or an L0 merge is overdue past their alert thresholds, even
    /// with idle CPU, no lag and no search.
    #[test]
    fn backfill_yields_when_prevalence_is_behind_or_l0_merges_are_overdue() {
        let _share = lock_backfill_share_for_test();
        let idle = Headroom { lag_ms: 0, utilization: Some(0.1), throttled: Some(0.0), r2_strain: Some(0.0),
            transfer_failures: 0, searching: false, prevalence_behind_ms: 0, l0_merge_overdue_ms: 0 };
        assert_eq!(next_backfill_share(400, &idle), 500, "healthy ingest: the share grows");
        // The alert thresholds themselves (prevalence_behind warns at 10 min,
        // l0_merge_overdue at 15 min), not a new knob.
        assert_eq!(BACKFILL_PREVALENCE_BEHIND_BACKOFF_MS, 600_000);
        assert_eq!(BACKFILL_L0_MERGE_OVERDUE_BACKOFF_MS, 900_000);
        // tenant-a at 11:35Z: prevalence 7,759 s behind, L0 1,017 s overdue.
        let prevalence = Headroom { prevalence_behind_ms: 7_759_000, ..idle };
        assert_eq!(next_backfill_share(4_000, &prevalence), 2_000, "prevalence behind halves it");
        let l0 = Headroom { l0_merge_overdue_ms: 1_016_954, ..idle };
        assert_eq!(next_backfill_share(4_000, &l0), 2_000, "an overdue L0 merge halves it");
        assert!(ingest_maintenance_behind(600_000, 0));
        assert!(ingest_maintenance_behind(0, 900_000));
        assert!(!ingest_maintenance_behind(599_999, 899_999));
        // Below the thresholds but not at the head: hold, never grow.
        let catching_up = Headroom { prevalence_behind_ms: 77_000, ..idle };
        assert_eq!(next_backfill_share(400, &catching_up), 400);
        let merge_due = Headroom { l0_merge_overdue_ms: 60_000, ..idle };
        assert_eq!(next_backfill_share(400, &merge_due), 400);

        // While behind no rewrite starts and a running one paces at the floor.
        set_backfill_share_for_test(BACKFILL_SHARE_MAX_PERMILLE);
        assert_eq!(backfill_rewrite_slots(), BACKFILL_MAX_REWRITES);
        set_ingest_behind_for_test(true);
        assert!(backfill_yielding());
        assert_eq!(backfill_rewrite_slots(), 0, "no rewrite starts while ingest maintenance is behind");
        assert_eq!(per_rewrite_share_permille(), BACKFILL_SHARE_MIN_PERMILLE);
        set_ingest_behind_for_test(false);
        assert_eq!(backfill_rewrite_slots(), BACKFILL_MAX_REWRITES);
        set_backfill_share_for_test(BACKFILL_SHARE_START_PERMILLE);
    }

    #[test]
    fn pacing_requires_explicit_opt_in_and_can_be_rolled_back() {
        assert!(!pacing_enabled_from(None, false).unwrap());
        assert!(pacing_enabled_from(None, true).unwrap());
        assert!(pacing_enabled_from(Some("1"), false).unwrap());
        assert!(!pacing_enabled_from(Some("0"), true).unwrap());
        assert!(pacing_enabled_from(Some("true"), false).is_err());
    }
    #[tokio::test]
    async fn default_remote_admission_does_not_sleep() {
        assert!(std::env::var("NANO_LAKE_COMPACTION_PACING").is_err());
        let _permit = tokio::time::timeout(Duration::from_millis(100), reserve_remote(1024 * 1024))
            .await
            .expect("default compaction must not add per-object sleeps")
            .unwrap();
    }
    #[test]
    fn default_compute_admission_has_no_pacing_budget() {
        let _permit = acquire().unwrap();
        assert!(!active_on_this_thread());
        charge(1_000_000, 1_000_000_000);
    }
    #[tokio::test]
    async fn failed_timed_out_and_cancelled_transfers_release_the_lane() {
        let failed: Result<()> =
            remote_transfer(true, 0, async { anyhow::bail!("injected failure") }).await;
        assert!(failed.is_err());
        let stalled: Result<()> =
            transfer_with_deadline(Duration::from_millis(10), std::future::pending()).await;
        assert!(stalled.unwrap_err().to_string().contains("timed out"));
        let (started, waiting) = tokio::sync::oneshot::channel();
        let pending = tokio::spawn(remote_transfer::<()>(true, 0, async move {
            started.send(()).unwrap();
            std::future::pending().await
        }));
        waiting.await.unwrap();
        pending.abort();
        let _ = pending.await;
        // NAN-3772: waiting for the lane is not part of the deadline. The
        // transfer queues while the lane is held and runs once released.
        let held = hold_remote_lane().await;
        let queued = tokio::spawn(remote_transfer(true, 0, async { Ok(()) }));
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!queued.is_finished(), "still queued behind the held lane");
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), queued)
            .await
            .expect("lane was not released")
            .unwrap()
            .unwrap();
    }

    /// NAN-3772: a transfer queued behind other merges for longer than its
    /// whole deadline still runs (and succeeds) once it holds the lane.
    #[tokio::test(start_paused = true)]
    async fn lane_wait_does_not_consume_the_transfer_deadline() {
        let held = hold_remote_lane().await;
        let queued = tokio::spawn(remote_transfer(true, 0, async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok(7)
        }));
        tokio::time::sleep(transfer_deadline(0) * 3).await;
        drop(held);
        assert_eq!(queued.await.unwrap().unwrap(), 7);
    }

    /// NAN-3772: a long download keeps going while bytes land, and fails
    /// once it stops making progress.
    #[tokio::test(start_paused = true)]
    async fn progressing_transfer_outlives_its_size_deadline_but_a_stall_times_out() {
        let landed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let writer = landed.clone();
        let progressing = transfer_with_progress(TRANSFER_IDLE, Duration::from_secs(3_600),
            { let landed = landed.clone(); move || landed.load(std::sync::atomic::Ordering::Relaxed) },
            async move {
                // 10 minutes, a chunk every 30 s: far past a 120 s deadline.
                for _ in 0..20 {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    writer.fetch_add(1 << 20, std::sync::atomic::Ordering::Relaxed);
                }
                Ok(())
            });
        let started = tokio::time::Instant::now();
        progressing.await.unwrap();
        assert!(started.elapsed() >= Duration::from_secs(600));

        let stalled_at = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let writer = stalled_at.clone();
        let started = tokio::time::Instant::now();
        let stalled: Result<()> = transfer_with_progress(TRANSFER_IDLE, Duration::from_secs(3_600),
            { let landed = stalled_at.clone(); move || landed.load(std::sync::atomic::Ordering::Relaxed) },
            async move {
                for _ in 0..3 {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    writer.fetch_add(1 << 20, std::sync::atomic::Ordering::Relaxed);
                }
                std::future::pending().await
            }).await;
        let error = format!("{:#}", stalled.unwrap_err());
        assert!(error.contains("timed out"), "{error}");
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_secs(90) + TRANSFER_IDLE && elapsed <= Duration::from_secs(90) + TRANSFER_IDLE + TRANSFER_PROGRESS_POLL,
            "stall detected one idle window after the last byte: {elapsed:?}");

        // The backstop still ends a transfer that trickles forever.
        let trickle = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let writer = trickle.clone();
        let capped: Result<()> = transfer_with_progress(TRANSFER_IDLE, Duration::from_secs(600),
            { let landed = trickle.clone(); move || landed.load(std::sync::atomic::Ordering::Relaxed) },
            async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    writer.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }).await;
        assert!(capped.is_err());
    }

    /// NAN-3187: two history merges transfer side by side.
    #[tokio::test]
    async fn remote_lane_admits_one_transfer_per_history_lane() {
        if remote_permits() < 2 {
            return; // an explicit NANO_LAKE_MERGE_HISTORY_CONCURRENCY=1
        }
        let first = reserve_remote(0).await.unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), reserve_remote(0))
            .await
            .expect("a second history merge's transfer waited behind the first");
        drop((first, second));
    }
    #[test]
    fn cpu_work_and_io_limits_are_independent() {
        assert_eq!(required_duration(100, 1, 10, 1000), Duration::from_secs(10));
        assert_eq!(
            required_duration(1, 10000, 10, 1000),
            Duration::from_secs(10)
        );
        assert_eq!(
            required_duration(100, 10000, 10, 1000),
            Duration::from_secs(10)
        );
    }

    /// NAN-3772 fixture estimate: the wall time of the tenant-a seven-day window
    /// (213 sealed hour parts, ~154M rows) at the adaptive pace, from the
    /// measured local rewrite cost (`writer::tests::count_rewrite_cost`,
    /// release, 160k real tenant-a rows of 2026-10-12: 61-63 µs CPU per input row,
    /// all passes included; wall equal to CPU at full share).
    #[test]
    fn seven_day_b12_backfill_estimate() {
        let (parts, rows) = (213_u64, 154_000_000_u64);
        let cpu_ns_per_row = 62_000_u64;
        let estimate = |share: u64| {
            let mut wall = Duration::ZERO;
            for _ in 0..parts {
                let mut pace = BackfillPace::new(0, 0);
                pace.row_cap = rows / parts;
                let cpu = pace.row_cap * cpu_ns_per_row;
                // A rewrite takes at least its CPU; the pace adds the rest.
                let delay = pace.charge(pace.row_cap, cpu, share, Duration::from_nanos(cpu), false);
                wall += Duration::from_nanos(cpu) + delay;
            }
            wall
        };
        let hours = |d: Duration| d.as_secs_f64() / 3600.0;
        let (idle, half, old_cap, floor) = (estimate(BACKFILL_SHARE_ONE_CORE_PERMILLE), estimate(500), estimate(250), estimate(BACKFILL_SHARE_MIN_PERMILLE));
        eprintln!("213 parts / 154M rows: idle {:.1} h, half {:.1} h, 25% {:.1} h, floor {:.1} h",
            hours(idle), hours(half), hours(old_cap), hours(floor));
        assert!((2.5..=2.8).contains(&hours(idle)), "{idle:?}");
        assert!((5.1..=5.5).contains(&hours(half)), "{half:?}");
        // A fixed 25% cap alone (even with once-per-row charging) is ~10 h.
        assert!(hours(old_cap) > 10.0);
        assert!(floor > old_cap);
    }
}
