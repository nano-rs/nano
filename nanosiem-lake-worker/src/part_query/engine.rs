// SPDX-License-Identifier: AGPL-3.0-or-later

//! `query[T]`: the per-tenant chDB query engine over parts (NAN-2869).
//!
//! The engine keeps the reader's query semantics by construction. A request
//! is compiled by the same `lake_query_compile` binary, and the compiled SQL
//! is bound by the same `planner` functions the generation reader uses. The
//! only thing that changes is the source those functions are handed: a
//! manifest of verified, locally leased part files selected from the part
//! log, instead of a generation plus a hot tail.
//!
//! Selection (per query):
//! 1. time: live parts whose `[min_time_us, max_time_us]` intersects the
//!    compiled window (from the `PartRef`, no fetch);
//! 2. tokens: for `token` keyword hints, each part's `tokens.nti` is leased
//!    (small) and row groups that cannot hold every token are dropped; a part
//!    with no surviving group is never fetched;
//! 3. entities: the surviving parts' `data.parquet` is leased and the
//!    row-group statistics and blooms decide entity hints;
//! 4. the surviving row groups become planner `CandidateBlock`s (exactly the
//!    `_path`/`_row_number` fence the reader's sidecars produce), or no
//!    candidates at all when nothing was pruned.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

use super::fetch::{FileSet, LocalParts, PartFetcher, PartFile};
use super::log_view::{Advance, PartLogView};
use super::keyword_count;
use super::progressive;
use super::membership::{self, Membership};
use super::prune;
use crate::executor::NativeExecutor;
use crate::native::NativeQueryOutput;
use crate::parts::part_log::{ObjectStore, PartRef};
use crate::planner::{
    self, CandidateBlock, CandidateHint, CompiledQuery, FetchLogPlanRequest, ManifestObject, NativeQueryPlan,
    ObjectStoreCredentials, SnapshotCache, SnapshotCacheObject, SourceCursorFence, SourceManifest, SourceTimeFence,
    TenantQueryConfig,
};

/// Task-local discovery is scoped to one engine and one request, never shared
/// between tenants or inherited by background tasks.
struct PinnedDiscovery {
    engine: usize,
    parts: Vec<PartRef>,
    schema: Arc<arrow_schema::Schema>,
    head: Option<(u64, String)>,
    fingerprint: Option<String>,
    live_parts: usize,
}

impl PinnedDiscovery {
    fn snapshot_for(&self, engine: usize, from_us: i64, to_us: i64) -> Option<(Vec<PartRef>, Arc<arrow_schema::Schema>, Option<u64>, usize)> {
        (self.engine == engine).then(|| (
            self.parts.iter().filter(|part| part.overlaps(from_us, to_us)).cloned().collect(),
            self.schema.clone(), self.head.as_ref().map(|(seq, _)| *seq), self.live_parts,
        ))
    }
}

tokio::task_local! {
    static DISCOVERY: PinnedDiscovery;
    // Typed view companion SQL must stay on the executing job's writer lane.
    // Bind to this engine so nested work for another tenant cannot inherit it.
    static JOB_STATEMENTS: usize;
}

pub const MAX_QUERY_TEXT_BYTES: usize = 262_144;
pub const MAX_RESULT_LIMIT: usize = 1_000_000;
const MAX_RESULT_SENTINEL: usize = MAX_RESULT_LIMIT + 1;
/// The planner's candidate fence bound (`candidate_source`).
const MAX_CANDIDATE_BLOCKS: usize = 4_096;
/// Most v2 block runs one selection may fence. Each run is one OR-ed
/// `_row_number` fence plus a `time` range; past ~100 per hour of data the
/// predicate costs more than the page skipping saves (NAN-3032 prototype:
/// 97 runs 0.070 s vs 0.137 s by row group; 350 runs 0.182 s vs 0.138 s).
const FINE_RUN_BUDGET: usize = 128;
/// NAN-3171: one row's decode, in OR-ed fence-term evaluations. A statement
/// costs ~`rows × (FINE_TERMS_PER_ROW_DECODE + terms)`: every row the fence
/// lets through is decoded once and checked against every term. NAN-3032's
/// hour-of-data probe bounds it to (11, 195): 97 runs (~0.1 M rows) beat
/// whole groups (~1 M rows), 350 runs (~0.36 M rows) lost to them. The
/// NAN-3171 native fixture (narrow ~150 B rows) puts it near 16: 178 runs
/// over 0.18 M rows ran 2.7x the unfenced 0.85 M-row scan (model: 2.6x).
/// Wider live rows decode slower, so 16 errs toward whole groups.
const FINE_TERMS_PER_ROW_DECODE: u64 = 16;
/// NAN-3179: the set-membership fence's per-row cost, in OR-term
/// evaluations, whatever the block count (one `transform` + one hash probe;
/// measured at ~0.4 of a row's decode on the native fixture, i.e. under
/// one OR term). Only the OR fence (`NANO_LAKE_FENCE_SET=0`) costs a term
/// per block.
const SET_FENCE_TERMS: u64 = 1;

/// NAN-3171: whether a selection fences its v2 block runs rather than its
/// whole kept row groups. Up to [`FINE_RUN_BUDGET`] runs always (NAN-3032);
/// past it, when the runs' estimated scan cost is below the row groups'.
/// [`FINE_RUN_BUDGET`] was measured on one hour of data, but a selection
/// spans the whole window: a rare token over a day has a run or two in each
/// of ~100 groups, and refusing all of them made chDB decode every kept
/// group (~65x the rows) to find ~160 events. `NANO_LAKE_FINE_RUN_COST=0`
/// restores the fixed budget.
fn use_fine_runs(fine_runs: usize, fine: (u64, usize), coarse: (u64, usize)) -> bool {
    if fine_runs == 0 || fine.1 > MAX_CANDIDATE_BLOCKS {
        return false;
    }
    if fine_runs <= FINE_RUN_BUDGET {
        return true;
    }
    if !crate::perf_overrides::probe_flag("fine_run_cost", !std::env::var("NANO_LAKE_FINE_RUN_COST").is_ok_and(|value| value == "0")) {
        return false;
    }
    fine_beats_coarse(fine, coarse, crate::planner::fence_set_enabled())
}

/// NAN-4211: whether the fine selection's rendered row fence and time guard
/// fit one statement. Exact runs over many one-row-group files (the window
/// entity index on a busy host over 7d: ~3,000 runs in ~2,500 files) fence
/// every file, where the coarse selection reads those files whole with no
/// fence; past the budget the statement outgrew chDB's `max_query_size` and
/// the query failed. Declining keeps the coarse selection (same rows).
fn fine_fence_fits(fine_selection: &[CandidateBlock], objects: &[ManifestObject]) -> bool {
    let rows = objects.iter().map(|object| (object.event_object_key.as_str(), object.rows)).collect::<BTreeMap<_, _>>();
    planner::candidate_fence_sql_bytes(fine_selection, &|key| rows.get(key).copied()) <= planner::MAX_FENCE_SQL_BYTES
}

/// `rows × (decode + fence)` for each selection; a selection without terms
/// is read unfenced. The set fence costs [`SET_FENCE_TERMS`] per row, the OR
/// fence one term per block (NAN-3179).
fn fine_beats_coarse(fine: (u64, usize), coarse: (u64, usize), set_fence: bool) -> bool {
    let fence = |terms: usize| match (terms, set_fence) {
        (0, _) => 0,
        (_, true) => SET_FENCE_TERMS,
        (terms, false) => terms as u64,
    };
    let cost = |(rows, terms): (u64, usize)| u128::from(rows) * u128::from(FINE_TERMS_PER_ROW_DECODE + fence(terms));
    cost(fine) < cost(coarse)
}

#[derive(Debug, thiserror::Error)]
pub enum PartQueryError {
    #[error("invalid request: {0}")]
    Invalid(String),
    /// NAN-3644: the reader's OOM safety net (see
    /// `ReaderObjectCache::interactive_cold_ceiling`), never the old 2 GiB
    /// cold-data refusal: a cold read under the ceiling queues and runs.
    #[error("This search would read ~{gb:.1} GB of uncached data in one pass, more than the ~{ceiling:.1} GB this reader can stage at once", gb = *needed_bytes as f64 / 1_000_000_000.0, ceiling = *ceiling_bytes as f64 / 1_000_000_000.0)]
    ColdScanTooLarge { needed_bytes: u64, ceiling_bytes: u64, background_bytes: u64 },
    #[error("query exceeds its scan budget: {0}")]
    Budget(String),
    /// chDB rejected the statement itself (type or evaluation error): a
    /// deterministic query failure, never a retryable outage.
    #[error("query execution failed: {0}")]
    QueryFailed(String),
    #[error("part data is temporarily unavailable: {0}")]
    Unavailable(String),
    /// The process's memory budget refused this one statement (chDB's
    /// per-statement or total cap, or a result too large to decode). The
    /// process is unaffected; retry later or as a durable search job.
    #[error("query memory budget exceeded: {0}")]
    MemoryBudget(String),
    /// Every native-work slot stayed busy past the admission deadline.
    #[error("query concurrency budget exceeded: {0}")]
    ConcurrencyBudget(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// NAN-4316: the tenant's part log has no `genesis` yet. A new tenant's
    /// ingest writes it when it first opens the log, so a query process
    /// started at birth sees this for a few seconds: retryable, not a fault.
    #[error("tenant part log has no schema yet")]
    NoSchemaYet,
}

impl PartQueryError {
    pub fn status(&self) -> u16 {
        match self {
            Self::Invalid(_) => 400,
            Self::Budget(_) => 413,
            Self::ColdScanTooLarge { .. } => 422,
            Self::QueryFailed(_) => 422,
            Self::Unavailable(_) | Self::MemoryBudget(_) | Self::NoSchemaYet => 503,
            Self::ConcurrencyBudget(_) => 429,
            Self::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_request",
            Self::Budget(_) => "scan_budget_exhausted",
            Self::ColdScanTooLarge { .. } => "cold_scan_too_large",
            Self::QueryFailed(_) => "query_execution_failed",
            Self::Unavailable(_) => "part_data_unavailable",
            // One retryable signal for both budgets: the search service
            // escalates it to a durable job.
            Self::MemoryBudget(_) | Self::ConcurrencyBudget(_) => QUERY_BUDGET_EXHAUSTED,
            Self::Internal(_) => "internal",
            Self::NoSchemaYet => "no_schema",
        }
    }
}

/// NAN-4290: the durable job lanes of one query process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobLane {
    /// One job at a time on the read-write lane, at the large lane's memory
    /// (NAN-3077): every job may run here.
    General,
    /// One small job at a time on its own read-write connection: a 1 h
    /// listing never waits for a 30 d aggregate on the general lane.
    Small,
}

/// One admitted request's native-work slot. Every release returns freed
/// heap to the kernel (see [`super::memory_budget::release_freed_heap`]):
/// under a steady queue some slot is always busy, so trimming only when
/// all slots were idle never ran and RSS ratcheted.
pub struct AdmissionSlot {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// The engine's admission slots when this one was granted.
    slots: usize,
    /// NAN-3077: a class gate held beside the slot (the companion gate).
    gate: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for AdmissionSlot {
    fn drop(&mut self) {
        // One slot (detect[T], small query roles): trim while still holding
        // it. A released permit goes straight to a queued waiter, so under a
        // constant backlog (claims queued behind the lane) the "last slot"
        // check below never sees an idle engine and freed heap ratchets up
        // (NAN-3047: ~0.5 GiB of retained arenas at claim concurrency 4).
        if self.slots == 1 {
            super::memory_budget::release_freed_heap();
            drop(self.permit.take());
            return;
        }
        drop(self.permit.take());
        super::memory_budget::release_freed_heap();
    }
}

/// The `reason` of a request refused by the memory or concurrency budget.
pub const QUERY_BUDGET_EXHAUSTED: &str = "query_budget_exhausted";

/// NAN-3077 admission classes (gen1's reader served every route on the same
/// lanes too, but its companions and point lookups never queued behind a
/// 300 s statement; see `query_timing::measure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestClass {
    /// A single event by uid (event detail): its own lane and permits, never
    /// queued behind a scan.
    Point,
    /// A request's rows query, user aggregates, typed interactive routes.
    Primary,
    /// A search's histogram / rollup companion (`-hist` request ids): at
    /// most `slots - 1` at once, so a primary always finds a slot free of
    /// companions.
    Companion,
    /// NAN-4174: a primary over a wide window (more than
    /// [`WIDE_WINDOW_HOURS`]): at most `slots - SHORT_RESERVED_SLOTS` at
    /// once, so short-window primaries always find a slot.
    Wide,
}

impl RequestClass {
    /// The class of a `/v1/query` or `/v1/aggregate/count` request.
    pub fn of(request_id: &str, fetch_log: bool) -> Self {
        if fetch_log {
            Self::Point
        } else if request_id.contains("-hist") {
            Self::Companion
        } else {
            Self::Primary
        }
    }

    /// [`Self::of`] for a request over `[start, end]`: a primary over a
    /// wide window is [`Self::Wide`].
    pub fn of_window(request_id: &str, fetch_log: bool, start: &str, end: &str) -> Self {
        match Self::of(request_id, fetch_log) {
            Self::Primary if wide_window(start, end) => Self::Wide,
            class => class,
        }
    }
}

/// Concurrent point lookups admitted (they share one dedicated lane).
pub const POINT_PERMITS: usize = 4;

/// Bound on the identity coverage memo (parts in a 30-day lookback are a
/// few thousand at 300 eps).
const MAX_IDENTITY_COVERAGE_MEMO: usize = 65_536;

/// Companion-gate permits for `slots` admission slots: one fewer, so a
/// primary is never shut out by companions (one slot: companions and
/// primaries simply share it).
pub(crate) fn companion_permits(slots: usize) -> usize {
    slots.saturating_sub(1).max(1)
}

/// NAN-4174: admission slots kept for short-window primaries: a wide
/// primary (window over [`WIDE_WINDOW_HOURS`]) never takes the last ones, so
/// a 1 h / 24 h or single-source search never waits behind 7 d aggregates
/// for a slot (a Chronicle-style simple/complex split).
pub const SHORT_RESERVED_SLOTS: usize = 2;
/// NAN-4174: a primary over more hours than this is wide.
pub const WIDE_WINDOW_HOURS: i64 = 24;

/// Wide-gate permits for `slots` admission slots (at least one).
pub(crate) fn wide_permits(slots: usize) -> usize {
    slots.saturating_sub(SHORT_RESERVED_SLOTS).max(1)
}

/// NAN-4174: whether a `[start, end]` (RFC 3339) request window is wide.
/// An unparsable window is not: the request fails later, never here.
pub fn wide_window(start: &str, end: &str) -> bool {
    match (chrono::DateTime::parse_from_rfc3339(start), chrono::DateTime::parse_from_rfc3339(end)) {
        (Ok(start), Ok(end)) => (end - start).num_hours() > WIDE_WINDOW_HOURS,
        _ => false,
    }
}

/// NAN-4164: add a token-cache work delta to a request's phases.
pub(super) fn record_token_work(p: &mut crate::query_timing::Phases, work: super::token_cache::TokenCacheStats) {
    p.token_probes += work.probes;
    p.token_probe_excluded += work.probe_excluded;
    p.token_probe_ms += work.probe_ns as f64 / 1e6;
    p.token_decodes += work.decodes;
    p.token_decode_bytes += work.decode_bytes;
    p.token_read_ms += work.read_ns as f64 / 1e6;
    p.token_decode_ms += work.decode_ns as f64 / 1e6;
}

/// A permit only when all `slots` are free (NAN-3077 background work).
pub(crate) fn idle_permit(admission: &Arc<tokio::sync::Semaphore>, slots: usize) -> Option<tokio::sync::OwnedSemaphorePermit> {
    if admission.available_permits() < slots {
        return None;
    }
    admission.clone().try_acquire_owned().ok()
}

/// Evidence parsing never owns query admission: one file can finish after
/// a search arrives, but it cannot hold or queue for that search's slot.
fn evidence_prewarm_idle(admission: &Arc<tokio::sync::Semaphore>, slots: usize) -> bool {
    !admission.is_closed() && admission.available_permits() >= slots
}

fn evidence_lanes_idle(admission: &Arc<tokio::sync::Semaphore>, slots: usize,
    point: &Arc<tokio::sync::Semaphore>, job: &Arc<tokio::sync::Semaphore>) -> bool {
    evidence_prewarm_idle(admission, slots)
        && evidence_prewarm_idle(point, POINT_PERMITS)
        && evidence_prewarm_idle(job, 1)
}

/// Only called on the disposable evidence thread, never a runtime worker.
fn lower_evidence_priority() -> std::io::Result<()> {
    // SAFETY: Linux priority syscalls applied to this thread's own id.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        if libc::setpriority(libc::PRIO_PROCESS, tid, crate::part_query::product_publish::ROLE_NICE) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // IOPRIO_WHO_PROCESS = 1; IOPRIO_CLASS_IDLE = 3.
        if libc::syscall(libc::SYS_ioprio_set, 1, tid, 3 << 13) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn evidence_quiet_period_over(elapsed: Duration) -> bool {
    elapsed >= Duration::from_secs(60)
}

/// NAN-3720: how often background work waiting for an idle engine checks again.
pub(crate) const BACKGROUND_IDLE_POLL: Duration = Duration::from_millis(100);
/// NAN-3720: how long one background step waits for an idle engine before
/// its pass stops and leaves the rest to the next pass.
pub(crate) const BACKGROUND_IDLE_WAIT: Duration = Duration::from_secs(30);

/// NAN-3720: a slot for background native work that never competes with a
/// request for one. It is granted only while every slot is free
/// ([`idle_permit`]) and it never joins the semaphore's FIFO queue: a queued
/// background waiter would be served before a request that arrived after
/// it, so an interactive search waited behind a whole background batch (an
/// incremental prewarm after every merge commit). It polls
/// every `poll` and gives up (`None`) after `wait` or once admission closes.
pub(crate) async fn wait_idle_permit(
    admission: &Arc<tokio::sync::Semaphore>,
    slots: usize,
    poll: Duration,
    wait: Duration,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        if let Some(permit) = idle_permit(admission, slots) {
            return Some(permit);
        }
        if admission.is_closed() || tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(poll).await;
    }
}

/// How long a request waits for a native-work slot before a 429.
pub const ADMISSION_DEADLINE: Duration = Duration::from_secs(20);
/// detect[T]'s deadline: scheduled rules queue behind each other (claim
/// concurrency 4 over one or two lanes) instead of failing their window; a
/// 429 still only delays the rule (the gate re-plans an uncommitted window).
/// Wait + run stay inside the scheduler's 130 s cell client timeout.
pub const DETECT_ADMISSION_DEADLINE: Duration = Duration::from_secs(60);

pub type QueryResult<T> = std::result::Result<T, PartQueryError>;

/// The read schema at the view's head; [`PartQueryError::NoSchemaYet`] while
/// the log has no `genesis` (NAN-4316), any other failure `Internal`.
fn read_schema(view: &mut PartLogView) -> QueryResult<Arc<arrow_schema::Schema>> {
    if view.schema_fingerprint().is_none() {
        return Err(PartQueryError::NoSchemaYet);
    }
    view.read_schema().map_err(internal)
}

pub(super) fn internal(error: impl std::fmt::Display) -> PartQueryError {
    internal_text(error.to_string())
}

/// `Internal`, unless the text is a refused storage credential: that is
/// being refreshed (NAN-3017), so it is a retryable 503, never a 500.
pub(crate) fn internal_text(text: String) -> PartQueryError {
    if super::credentials::text_is_credential_stale(&text) {
        PartQueryError::Unavailable(text)
    } else if crate::reader_object_cache::text_is_saturation(&text) {
        // NAN-4138: a saturated reader cache that reached here through a
        // stringly error path is transient (503, retryable), not a 500.
        PartQueryError::Unavailable(text)
    } else if super::memory_budget::is_budget_refusal(&text) {
        // A budget refusal that reached here through a stringly error path.
        PartQueryError::MemoryBudget(text)
    } else {
        PartQueryError::Internal(text)
    }
}

fn map_plan_error(error: planner::QueryPlanError) -> PartQueryError {
    match error {
        planner::QueryPlanError::BudgetRejected { .. } => PartQueryError::Budget(error.to_string()),
        planner::QueryPlanError::InvalidCompilerOutput(_) => PartQueryError::Invalid(error.to_string()),
        other => PartQueryError::Internal(other.to_string()),
    }
}

pub(super) fn map_executor_error(error: crate::executor::ExecutorError) -> PartQueryError {
    use crate::executor::ExecutorError;
    match error {
        ExecutorError::EstimateExceeded { .. } => PartQueryError::Budget(error.to_string()),
        ExecutorError::LaneWaitTimeout | ExecutorError::AdmissionTimeout => PartQueryError::Unavailable(error.to_string()),
        ExecutorError::ResultTooLarge { .. } | ExecutorError::MemoryExhausted { .. } => PartQueryError::MemoryBudget(error.to_string()),
        ExecutorError::Query(_) => {
            let message = error.to_string();
            if memory_exhausted(&error) {
                PartQueryError::MemoryBudget(message)
            } else if message.contains("TIMEOUT_EXCEEDED") || message.contains("TOO_MANY_BYTES") {
                PartQueryError::Budget(message)
            } else {
                PartQueryError::QueryFailed(message)
            }
        }
        other => PartQueryError::Internal(other.to_string()),
    }
}

/// Marker of a part file or record that is gone from the store.
pub const VANISHED: &str = "part object vanished";

pub(super) fn map_fetch_error(error: anyhow::Error) -> PartQueryError {
    let text = format!("{error:#}");
    if super::credentials::text_is_credential_stale(&text) {
        return PartQueryError::Unavailable(text);
    }
    if text.contains(VANISHED) || text.contains("is missing") || text.contains("NotFound") {
        return PartQueryError::Unavailable(format!("{VANISHED}: {text}"));
    }
    if let Some(cache) = error.downcast_ref::<crate::reader_object_cache::ReaderCacheError>() {
        return match cache {
            crate::reader_object_cache::ReaderCacheError::ScanTooLarge { required_bytes, ceiling_bytes, background_bytes } =>
                PartQueryError::ColdScanTooLarge { needed_bytes: *required_bytes, ceiling_bytes: *ceiling_bytes, background_bytes: *background_bytes },
            other if other.retryable() => PartQueryError::Unavailable(other.to_string()),
            other => internal_text(other.to_string()),
        };
    }
    internal_text(format!("{error:#}"))
}

/// Per-tenant engine limits. Same meaning as the reader's
/// `TenantQueryConfig` limits.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    pub tenant_id: String,
    pub bucket: String,
    pub compiler: PathBuf,
    pub max_query_bytes: u64,
    pub max_memory_bytes: u64,
    pub max_execution_seconds: u64,
    pub threads: u64,
}

/// The nPL request, wire-compatible with the reader's `broad_npl` route.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BroadNplRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub dataset: String,
    pub query: String,
    pub start: String,
    pub end: String,
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    pub table_view: bool,
    #[serde(default)]
    pub use_cache: bool,
    #[serde(default)]
    pub cursor_time: Option<String>,
    #[serde(default)]
    pub cursor_event_uid: Option<String>,
    #[serde(default)]
    pub anchor_us: Option<i64>,
    #[serde(default)]
    pub decay: Option<crate::risk::RiskDecay>,
    #[serde(default)]
    pub clear_boundaries: BTreeMap<String, i64>,
    #[serde(default)]
    pub minimum_clear_revision: Option<i64>,
    /// Watchlist weights for `dataset=risk` (NAN-3228).
    #[serde(default)]
    pub watch_weights: std::collections::BTreeMap<String, f64>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: BTreeSet<String>,
}

/// The reader's `fetch_log` route.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FetchLogRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub id: String,
    #[serde(default)]
    pub start: Option<String>,
    #[serde(default)]
    pub end: Option<String>,
    #[serde(default)]
    pub log_source: Option<String>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    pub deny_source_types: BTreeSet<String>,
}

#[derive(Serialize)]
struct CompilerRequest<'a> {
    stats_page: bool,
    stats_page_offset: usize,
    query: &'a str,
    dataset: &'a str,
    start: &'a str,
    end: &'a str,
    limit: usize,
    table_view: bool,
    event_contract: &'static str,
    snapshot_field_types: BTreeMap<String, String>,
    /// NAN-3154: paths every part of the window attests lowercased at rest
    /// (signed provenance, admission v2); the compiler compares them RAW so
    /// chDB's Parquet statistics/bloom push-down can prune. Omitted when empty
    /// so an older pinned compiler (`deny_unknown_fields`) still accepts it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    lowercased_fields: Vec<String>,
}

/// What pruning did for one query (returned as planner evidence).
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct SelectionEvidence {
    pub log_seq: Option<u64>,
    pub live_parts: usize,
    pub time_parts: usize,
    pub time_files: usize,
    pub source_family_pruned_files: usize,
    pub membership_pruned_parts: usize,
    pub token_pruned_files: usize,
    pub uid_pruned_files: usize,
    pub entity_sidecar_pruned_files: usize,
    /// NAN-3165: files whose data was already local, so entity evidence came
    /// from the data file's own Parquet blooms instead of decoding the
    /// locator / bloom sidecars.
    pub resident_infile_files: usize,
    /// NAN-4190: files answered by the window entity index, and those it
    /// proved hold no matching row (pruned before any sidecar or footer).
    pub entity_index_files: usize,
    pub entity_index_pruned_files: usize,
    /// NAN-3165: leased data files dropped because no row group survived
    /// their own evidence (in-file blooms, membership, tokens).
    pub infile_pruned_files: usize,
    /// NAN-3165: thread CPU (µs) of this selection's synchronous Rust work
    /// (sidecar decode, token/bloom/footer pruning).
    pub select_cpu_us: u64,
    pub fetched_files: usize,
    pub row_groups: usize,
    pub kept_row_groups: usize,
    pub candidate_blocks: Option<usize>,
    /// NAN-3032: row runs chosen from v2 block indexes (0 = row groups only).
    pub fine_runs: usize,
    /// Rows those runs cover, against the rows of the row groups they replace.
    pub fine_rows: u64,
    pub fine_replaced_rows: u64,
    /// NAN-3171: v2 block runs offered but declined for whole row groups
    /// (over budget and not cheaper; see [`use_fine_runs`]).
    pub fine_declined_runs: usize,
    /// Row groups answered from v3 token counts (never scanned), and the
    /// matching rows they hold.
    pub count_groups: usize,
    pub count_rows: u64,
    pub cache_hits: usize,
    pub cache_misses: usize,
    pub cache_fetched_bytes: u64,
    /// NAN-3133: data files served as sparse column-range files, and the
    /// data stage's ranged vs whole-file fetched bytes and fallbacks.
    #[serde(flatten)]
    pub range: super::range_fetch::FetchEvidence,
}

/// NAN-3172: adds one part selection's funnel to the request's phase record.
fn record_selection_funnel(evidence: &SelectionEvidence) {
    crate::query_timing::record(|p| {
        let f = &mut p.funnel;
        f.selections += 1;
        f.time_parts += evidence.time_parts;
        f.time_files += evidence.time_files;
        f.source_family_pruned_files += evidence.source_family_pruned_files;
        f.membership_pruned_parts += evidence.membership_pruned_parts;
        f.token_pruned_files += evidence.token_pruned_files;
        f.uid_pruned_files += evidence.uid_pruned_files;
        f.entity_sidecar_pruned_files += evidence.entity_sidecar_pruned_files;
        f.infile_pruned_files += evidence.infile_pruned_files;
        f.resident_infile_files += evidence.resident_infile_files;
        f.entity_index_files += evidence.entity_index_files;
        f.entity_index_pruned_files += evidence.entity_index_pruned_files;
        f.fetched_files += evidence.fetched_files;
        f.row_groups += evidence.row_groups;
        f.kept_row_groups += evidence.kept_row_groups;
        f.candidate_blocks += evidence.candidate_blocks.unwrap_or(0);
        f.fine_runs += evidence.fine_runs;
        f.fine_declined_runs += evidence.fine_declined_runs;
        f.count_groups += evidence.count_groups;
    });
}

/// NAN-3172: counts of keyword and entity hints (alternatives included).
fn hint_counts(hints: &[CandidateHint]) -> (usize, usize) {
    hints.iter().fold((0, 0), |(keywords, entities), hint| match hint {
        CandidateHint::Keyword { .. } => (keywords + 1, entities),
        CandidateHint::Entity { .. } => (keywords, entities + 1),
        CandidateHint::SourceFamily { .. } | CandidateHint::Class { .. } => (keywords, entities),
        CandidateHint::Any { alternatives } => {
            let (k, e) = hint_counts(alternatives);
            (keywords + k, entities + e)
        }
    })
}

/// NAN-3165: resident data files take entity evidence from their in-file
/// Parquet blooms rather than the locator/bloom sidecars (default on;
/// `NANO_LAKE_RESIDENT_INFILE_BLOOMS=0` restores sidecar pruning for them).
fn resident_infile_blooms() -> bool {
    crate::perf_overrides::probe_flag("resident_infile_blooms",
        std::env::var("NANO_LAKE_RESIDENT_INFILE_BLOOMS").map_or(true, |value| value != "0"))
}

/// NAN-3165: whether payload statements after `locate` read only the files
/// whose times hold a located instant (default on; `=0` reads the chunk's
/// whole selection, as before).
fn payload_at_instants() -> bool {
    crate::perf_overrides::probe_flag("payload_at_instants",
        std::env::var("NANO_LAKE_PAYLOAD_AT_INSTANTS").map_or(true, |value| value != "0"))
}

/// NAN-3169: whether a density estimate that fills the page in a newer
/// first chunk overrides the whole-window read of a selective preselect
/// (default on; `NANO_LAKE_DENSITY_OVER_SELECTIVE=0` reads the window whole).
fn density_over_selective() -> bool {
    crate::perf_overrides::probe_flag("density_over_selective",
        std::env::var("NANO_LAKE_DENSITY_OVER_SELECTIVE").map_or(true, |value| value != "0"))
}

/// NAN-4157: the inputs of the progressive walk's whole-window preselect.
#[derive(Debug, Clone, Copy, Default)]
struct WindowPreselect {
    /// The one-shot multi-path hash window (read whole anyway).
    whole_hash_window: bool,
    /// The density estimate found the value too dense for blooms.
    dense: bool,
    /// The density estimate fills the page inside a newer first chunk.
    density_fills_first_chunk: bool,
    /// [`density_over_selective`].
    density_over_selective: bool,
    /// A keyword token keeps few row groups of the window.
    token_preselect: bool,
    /// An entity pivot (host, IP, user, process, hash).
    uses_entities: bool,
}

/// NAN-4157: whether the progressive walk selects the whole window once
/// before its first chunk. The preselect only pays off when it may be read
/// whole (a few row groups); when the density estimate fills the page in a
/// newer first chunk and overrides a selective read, it would just lease
/// every surviving file of the window to cut chunks from.
fn window_preselect(inputs: WindowPreselect) -> bool {
    let candidate = !inputs.whole_hash_window && !inputs.dense && (inputs.token_preselect || inputs.uses_entities);
    candidate && !(inputs.density_fills_first_chunk && inputs.density_over_selective)
}

/// The verified local source of one query. Holding it holds the leases.
pub struct Selection {
    pub parts: Vec<PartRef>,
    pub manifest: SourceManifest,
    pub tenant: TenantQueryConfig,
    pub candidates: Option<Vec<CandidateBlock>>,
    pub field_types: BTreeMap<String, String>,
    pub evidence: SelectionEvidence,
    /// NAN-3155: each selected data file's verified `[min, max]` event time
    /// (µs), by object key, so a sub-window can be cut from this selection
    /// without selecting again ([`Selection::narrowed`]).
    pub object_times: BTreeMap<String, (i64, i64)>,
    _leases: Vec<LocalParts>,
}

impl Selection {
    /// NAN-3155: the part of this selection that can hold a row in
    /// `[from_us, to_us]`: files whose verified time bounds touch the window
    /// and, under a row-group fence, the blocks whose statistics touch it
    /// (blocks without statistics are kept). Every pruning decision of the
    /// whole-window selection (blooms, tokens, membership, uid) stays in
    /// force; the window itself is enforced by the statement's time fence,
    /// so this only drops reads that cannot contribute. It holds no leases:
    /// `self` must outlive it.
    pub fn narrowed(&self, from_us: i64, to_us: i64) -> QueryResult<Selection> {
        let touches = |(min, max): (i64, i64)| min <= to_us && max >= from_us;
        self.retained(|key| self.object_times.get(key).is_none_or(|times| touches(*times)),
            |block| block.time_range_us.is_none_or(touches))
    }

    /// NAN-3165: the part of this selection that can hold a row at one of
    /// the located instants `times` (canonical exact-fence times): files
    /// whose verified `[min, max]` event time contains one, and, under a
    /// row-group fence, the blocks whose time statistics contain one (files
    /// and blocks without times are kept). The payload statement fences on
    /// exactly these instants, so this drops only reads that cannot
    /// contribute. `None` when nothing is dropped or a time does not parse.
    /// Holds no leases: `self` must outlive it.
    pub fn at_instants(&self, times: &[String]) -> QueryResult<Option<Selection>> {
        let mut instants = BTreeSet::new();
        for time in times {
            // `planner::exact_fence_time` form: UTC `%Y-%m-%d %H:%M:%S%.6f`.
            let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(time, "%Y-%m-%d %H:%M:%S%.f") else { return Ok(None) };
            let us = parsed.and_utc().timestamp_micros();
            instants.insert(us);
        }
        let holds = |(min, max): (i64, i64)| min <= max && instants.range(min..=max).next().is_some();
        let keep_object = |key: &str| self.object_times.get(key).is_none_or(|times| holds(*times));
        let dropped_objects = self.manifest.objects.iter().any(|object| !keep_object(&object.event_object_key));
        let dropped_blocks = self.candidates.as_ref().is_some_and(|blocks| blocks.iter().any(|block| block.time_range_us.is_some_and(|t| !holds(t))));
        if !dropped_objects && !dropped_blocks {
            return Ok(None);
        }
        let narrowed = self.retained(keep_object, |block| block.time_range_us.is_none_or(holds))?;
        Ok((!narrowed.manifest.objects.is_empty()).then_some(narrowed))
    }

    /// NAN-3155: only the files at these local paths (a payload pass reads
    /// the files that hold its rows, and only those are owner-probed).
    pub fn only_paths(&self, paths: &BTreeSet<String>) -> QueryResult<Selection> {
        let keys = self.tenant.snapshot_cache.as_ref()
            .map(|cache| cache.objects.iter()
                .filter(|(_, object)| paths.contains(object.path.to_string_lossy().as_ref()))
                .map(|(key, _)| key.clone()).collect::<BTreeSet<_>>())
            .unwrap_or_default();
        self.retained(|key| keys.contains(key), |_| true)
    }

    fn retained(&self, keep_object: impl Fn(&str) -> bool, keep_block: impl Fn(&CandidateBlock) -> bool) -> QueryResult<Selection> {
        let candidates = self.candidates.as_ref().map(|blocks| blocks.iter()
            .filter(|block| keep_object(&block.event_object_key) && keep_block(block))
            .cloned()
            .collect::<Vec<_>>());
        let keep = |key: &str| keep_object(key)
            && candidates.as_ref().is_none_or(|blocks| blocks.iter().any(|block| block.event_object_key == key));
        let objects = self.manifest.objects.iter().filter(|object| keep(&object.event_object_key)).cloned().collect::<Vec<_>>();
        let keys = objects.iter().map(|object| object.event_object_key.clone()).collect::<BTreeSet<_>>();
        let mut tenant = self.tenant.clone();
        if let Some(cache) = tenant.snapshot_cache.as_mut().filter(|cache| !cache.bootstrap) {
            cache.objects.retain(|key, _| keys.contains(key));
            if !cache.objects.is_empty() {
                let mut paths = cache.objects.values().map(|object| object.path.to_string_lossy().into_owned()).collect::<Vec<_>>();
                cache.source_spec = planner::local_path_spec(&mut paths).map_err(map_plan_error)?;
            }
            cache.bytes = cache.objects.values().map(|object| object.bytes).sum();
        }
        let mut manifest = SourceManifest::from_objects(self.manifest.tenant_id.clone(), objects);
        if manifest.objects.is_empty() {
            manifest = SourceManifest::empty_with_bootstrap_paths(self.manifest.tenant_id.clone(),
                self.field_types.keys().cloned());
        }
        Ok(Selection {
            parts: self.parts.clone(),
            manifest,
            tenant,
            candidates: candidates.filter(|blocks| !blocks.is_empty()),
            field_types: self.field_types.clone(),
            evidence: SelectionEvidence {
                fetched_files: keys.len(),
                candidate_blocks: None,
                // Cut from `self` without selecting again: no new work.
                select_cpu_us: 0,
                ..self.evidence.clone()
            },
            object_times: self.object_times.iter().filter(|(key, _)| keys.contains(*key)).map(|(k, v)| (k.clone(), *v)).collect(),
            _leases: Vec::new(),
        })
    }
}

pub struct PartQueryEngine {
    settings: EngineSettings,
    store: Arc<dyn ObjectStore>,
    view: tokio::sync::Mutex<PartLogView>,
    fetcher: PartFetcher,
    executor: NativeExecutor,
    /// One read-write lane for job spools and risk materialization.
    writer: Option<NativeExecutor>,
    /// Every catch-up's new-data footprint `(head seq, advance)`, whoever
    /// triggered it, until the detection gate drains it. Without this, a
    /// catch-up done inside a query would hide new data from the gate and a
    /// due detection could be skipped.
    advances: std::sync::Mutex<Vec<(u64, Advance)>>,
    /// The process's own state dir (`None`: no persistent state).
    state_dir: Option<PathBuf>,
    /// A part prewarm is running.
    prewarming: std::sync::atomic::AtomicBool,
    evidence_prewarm: std::sync::Mutex<Value>,
    evidence_ready_at: std::sync::OnceLock<Instant>,
    /// NAN-3403: digests an earlier prewarm pass already leased and proved.
    prewarmed: super::prewarm_pacing::PrewarmLedger,
    // NAN-3392: shared with the blocking-pool evidence probes.
    file_metadata: Arc<prune::FileMetadataCache>,
    token_cache: Arc<super::token_cache::TokenCache>,
    /// NAN-4292: verified uid sidecar layouts for event-id lookups.
    uid_layouts: Arc<super::uid_probe::UidLayouts>,
    /// NAN-3392: per-(file, hint) footer/bloom evidence across queries.
    evidence_cache: Arc<super::select_evidence::EvidenceCache>,
    entity_cache: super::entity_cache::EntityCache,
    pub(super) entity_count_memo: super::entity_count::Memo,
    locator_cache: std::sync::Mutex<VecDeque<(LocatorKey, LocatorHits)>>,
    fragments: super::fragment_cache::FragmentCache,
    /// Whole-part membership answers, see [`MembershipMemo`].
    membership_memo: std::sync::Mutex<MembershipMemo>,
    /// NAN-3077: identity-observation coverage per part (`Some(events)`
    /// when its entity-range partial carries a coverage row, `None` when it
    /// carries none). A part's partial is immutable, so the answer is too;
    /// see [`super::identity::index_sources`].
    identity_coverage: std::sync::Mutex<std::collections::HashMap<crate::parts::format::PartId, Option<i64>>>,
    /// NAN-3399: this process's merged identity observation index.
    identity_merged: super::identity_merged::MergedSlot,
    /// NAN-4190: this process's window entity index.
    entity_index: super::entity_index::Slot,
    /// NAN-3093: per-part count-rollup answers (see [`super::rollup_rows`]).
    rollup_rows: super::rollup_rows::RollupRowsMemo,
    prevalence_rows: super::prevalence_rows::PrevalenceRowsMemo,
    /// When the view last completed a catch-up (see [`CATCH_UP_COALESCE`]).
    caught_up_at: std::sync::Mutex<Option<Instant>>,
    /// NAN-3392: a background refresher keeps the view caught up (see
    /// [`request_may_skip_catch_up`]).
    background_log_refresh: std::sync::atomic::AtomicBool,
    /// NAN-3077: the point-lookup lane and its permits (see [`RequestClass`]).
    point: Option<NativeExecutor>,
    /// NAN-3077: the large lane and its memory. `executor` is then the
    /// pool of small lanes (see `memory_budget`), and a statement that needs
    /// more than a small lane runs here (NAN-3393: two at half its memory,
    /// or one at all of it; see [`super::lanes`]).
    large: Option<super::lanes::LargeLane>,
    /// NAN-3393: statements that needed a bigger lane than they started on.
    lane_memo: super::lanes::LaneMemo,
    point_admission: Arc<tokio::sync::Semaphore>,
    /// NAN-3077: companions hold one of these beside their slot.
    companion_gate: Arc<tokio::sync::Semaphore>,
    /// NAN-4174: wide-window primaries hold one of these beside their slot.
    wide_gate: Arc<tokio::sync::Semaphore>,
    /// NAN-3077: durable jobs (one at a time, on the read-write lane).
    job_admission: Arc<tokio::sync::Semaphore>,
    /// NAN-4290: the small-job lane: its own read-write connection and one
    /// permit (see [`JobLane::Small`]). `None`: every job takes the general lane.
    small_job_writer: Option<NativeExecutor>,
    small_job_admission: Arc<tokio::sync::Semaphore>,
    /// Native-work slots (see [`super::memory_budget`]): one per read lane.
    pub(super) admission: Arc<tokio::sync::Semaphore>,
    /// NAN-3148: published product state (product[T] publishes, query[T]
    /// with a product role only reads). Unset: the legacy in-process build.
    product: std::sync::OnceLock<super::product_publish::Published>,
}

#[derive(PartialEq, Eq)]
struct LocatorKey {
    selection_identity: String,
    sql: String,
    limit: usize,
    start: String,
    end: String,
    end_inclusive: bool,
    cursor: Option<(String, String)>,
}

const MAX_LOCATOR_RESULTS: usize = 256;
const MAX_LOCATOR_CACHE_BYTES: usize = 16 * 1024 * 1024;

fn locator_selection_identity(manifest: &SourceManifest, candidates: Option<&[CandidateBlock]>) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    let mut objects: Vec<_> = manifest.objects.iter().collect();
    objects.sort_by(|left, right| left.event_object_key.cmp(&right.event_object_key));
    for object in objects {
        for field in [&object.event_object_key, &object.event_object_version] {
            digest.update((field.len() as u64).to_le_bytes());
            digest.update(field.as_bytes());
        }
    }
    // Candidate fences are part of the proof: membership/source scopes may
    // choose different groups from the same immutable files.
    digest.update(format!("{candidates:?}").as_bytes());
    hex::encode(digest.finalize())
}

fn locator_entry_bytes(key: &LocatorKey, hits: &LocatorHits) -> usize {
    key.selection_identity.len() + key.sql.len() + key.start.len() + key.end.len()
        + key.cursor.as_ref().map_or(0, |(time, uid)| time.len() + uid.len())
        + hits.times.iter().map(|time| time.len() + std::mem::size_of::<String>()).sum::<usize>()
}

/// Membership answers kept (one per part per distinct constraint set).
const MAX_MEMBERSHIP_MEMO: usize = 16_384;
const MAX_MEMBERSHIP_BYTES: usize = 32 * 1024 * 1024;

/// `(constraint statement, part)` → the part's matching rollup buckets over
/// its whole time range (empty: provably no match). A part and its rollup
/// partial are immutable, so the answer never changes (NAN-2996). Without it
/// every search re-ran one chDB statement over every rollup in its window
/// (~0.3 s for a live hour); now only parts new since the last identical
/// search are evaluated.
#[derive(Default)]
struct MembershipMemo {
    answers: std::collections::HashMap<(Arc<str>, crate::parts::format::PartId), Arc<BTreeSet<i64>>>,
    order: VecDeque<(Arc<str>, crate::parts::format::PartId)>,
    bytes: usize,
}

impl MembershipMemo {
    fn get(&self, key: &Arc<str>, part: &crate::parts::format::PartId) -> Option<Arc<BTreeSet<i64>>> {
        self.answers.get(&(key.clone(), part.clone())).cloned()
    }

    /// Intersection of available parent answers. A missing parent supplies no
    /// evidence; an empty answer excludes the part. Never an exact child memo.
    fn candidate_buckets(&self, keys: &[Arc<str>], part: &crate::parts::format::PartId) -> Option<BTreeSet<i64>> {
        let mut result: Option<BTreeSet<i64>> = None;
        for key in keys {
            if let Some(buckets) = self.get(key, part) {
                result = Some(match result {
                    None => (*buckets).clone(),
                    Some(previous) => previous.intersection(&buckets).copied().collect(),
                });
                if result.as_ref().is_some_and(BTreeSet::is_empty) {
                    break;
                }
            }
        }
        result
    }

    fn insert(&mut self, key: Arc<str>, part: crate::parts::format::PartId, buckets: BTreeSet<i64>) {
        let entry = (key, part);
        let size = Self::entry_bytes(&entry, &buckets);
        if let Some(previous) = self.answers.remove(&entry) {
            self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&entry, &previous));
            self.order.retain(|old| old != &entry);
        }
        // Oversized answers are evaluated normally, but never retained.
        if size > MAX_MEMBERSHIP_BYTES { return; }
        self.bytes += size;
        self.answers.insert(entry.clone(), Arc::new(buckets));
        self.order.push_back(entry);
        while self.order.len() > MAX_MEMBERSHIP_MEMO || self.bytes > MAX_MEMBERSHIP_BYTES {
            if let Some(evicted) = self.order.pop_front() {
                if let Some(previous) = self.answers.remove(&evicted) {
                    self.bytes = self.bytes.saturating_sub(Self::entry_bytes(&evicted, &previous));
                }
            }
        }
    }

    fn entry_bytes(entry: &(Arc<str>, crate::parts::format::PartId), buckets: &BTreeSet<i64>) -> usize {
        // Conservative BTree node/allocator allowance, including both keys.
        256 + entry.0.len() * 2 + entry.1.as_str().len() * 2 + buckets.len() * 32
    }
}
/// A selection reuses a part-log catch-up completed this recently instead of
/// issuing its own (NAN-2996). Each catch-up is at least one object-store GET
/// (an R2 404 for `head + 1` when nothing is new), taken under the view lock
/// that every query shares. The request handler already catches up before
/// the engine runs, yet membership, the progressive start and every
/// progressive chunk each caught up again: a 7-chunk page paid ~9 serialized
/// GETs. `refresh` (notify, detection and prewarm path) always catches up;
/// in-query re-reads coalesce, and so does the request handler while the
/// NAN-3392 background refresher runs (`refresh_for_request`), so
/// visibility moves by at most this.
const CATCH_UP_COALESCE: Duration = Duration::from_secs(1);

/// Active cadence of the background part-log refresher. Empty passes back
/// off to 60 seconds; arrivals still refresh through supervisor notifications
/// and requests catch up inline once the one-second freshness bound expires.
pub const BACKGROUND_REFRESH_PERIOD: Duration = Duration::from_millis(500);

/// NAN-3392: may a request use the view as is instead of catching up?
/// Only while a background refresher runs, and only when the last completed
/// catch-up *started* less than [`CATCH_UP_COALESCE`] ago. That catch-up
/// applied every entry appended before its start, so the request sees every
/// part committed more than `CATCH_UP_COALESCE` (1 s) before it started:
/// the staleness bound is < 1 s. Without the refresher (tests, detect,
/// product), or when it stalls or fails, the request catches up inline as
/// before. A local ingest notify (`wake`) still catches up at once.
fn request_may_skip_catch_up(background: bool, caught_up_at: Option<Instant>, now: Instant) -> bool {
    background && caught_up_at.is_some_and(|at| now.saturating_duration_since(at) < CATCH_UP_COALESCE)
}

/// Poll while `target` is alive, doubling the delay after an unchanged
/// head. A changed head or failure returns to `period`. The strong target
/// reference is held only during a tick, never during the idle sleep.
pub(super) async fn run_periodic<T, F, Fut>(target: std::sync::Weak<T>, period: Duration, mut tick: F)
where
    F: FnMut(Arc<T>) -> Fut,
    Fut: std::future::Future<Output = std::result::Result<bool, PartQueryError>>,
{
    let mut delay = period;
    loop {
        let Some(target) = target.upgrade() else { return };
        delay = match tick(target).await {
            Ok(changed) => background_refresh_delay(period, delay, changed),
            Err(error) => {
                tracing::warn!(%error, "background part-log catch-up failed; requests catch up inline");
                period
            }
        };
        tokio::time::sleep(delay).await;
    }
}

/// Only the background backstop waits. Arrival notifications and stale
/// requests still catch up immediately, with the existing 1-second bound.
fn background_refresh_delay(base: Duration, previous: Duration, changed: bool) -> Duration {
    if changed { base } else {
        previous.max(base).saturating_mul(2).min(Duration::from_secs(60).max(base))
    }
}

/// File name of the owner-denial proof memo earlier releases persisted in
/// the state dir; removed on start (NAN-4168: no read-time enrichment masks).
const LEGACY_OWNER_PROOFS_MEMO: &str = "owner-proofs.v2.json";

/// Data files per prewarm batch.
const PREWARM_BATCH_FILES: usize = 16;

/// Remote (R2-only) data files of parts this close to the newest data are
/// fetched into the reader cache by the arrival prewarm (NAN-2996). Live
/// parts are R2-only, so without it the first search over each new part paid
/// its GET (observed 1.7-2.5 s for 0.6-3.5 MB) on the query path. The lab
/// (#4629) never saw this: its parts were cell-local.
const PREWARM_REMOTE_DATA_US: i64 = 2 * 3_600_000_000;

/// Cold bytes per prewarm batch, well under the cache's per-call budget.
const PREWARM_BATCH_BYTES: u64 = 256 * 1024 * 1024;

/// Split newest-first prewarm candidates into batches of one kind (local or
/// remote) bounded by [`PREWARM_BATCH_FILES`] and [`PREWARM_BATCH_BYTES`].
fn prewarm_batches<T>(candidates: Vec<(T, u64, bool)>) -> Vec<(Vec<T>, bool)> {
    let mut batches: Vec<(Vec<T>, bool)> = Vec::new();
    let mut bytes = 0_u64;
    for (file, size, local) in candidates {
        let fits = batches.last().is_some_and(|(batch, kind)| {
            *kind == local && batch.len() < PREWARM_BATCH_FILES && bytes.saturating_add(size) <= PREWARM_BATCH_BYTES
        });
        if !fits {
            batches.push((Vec::new(), local));
            bytes = 0;
        }
        bytes = bytes.saturating_add(size);
        batches.last_mut().expect("pushed").0.push(file);
    }
    batches
}

impl PartQueryEngine {
    pub fn new(
        settings: EngineSettings,
        store: Arc<dyn ObjectStore>,
        view: PartLogView,
        fetcher: PartFetcher,
        executor: NativeExecutor,
    ) -> Result<Self> {
        if view.tenant_id() != settings.tenant_id {
            anyhow::bail!("part log view belongs to another tenant");
        }
        let slots = executor.connection_count().max(1);
        let fragments = super::fragment_cache::FragmentCache::new(settings.max_memory_bytes);
        Ok(Self { settings, fragments, store, view: tokio::sync::Mutex::new(view), fetcher, executor, writer: None, advances: Default::default(), state_dir: None, prewarming: Default::default(), evidence_prewarm: Default::default(), evidence_ready_at: Default::default(), prewarmed: Default::default(), file_metadata: Default::default(), token_cache: Default::default(), uid_layouts: Default::default(), evidence_cache: Default::default(), entity_cache: Default::default(), entity_count_memo: Default::default(), locator_cache: Default::default(), membership_memo: Default::default(), identity_coverage: Default::default(), identity_merged: Default::default(), entity_index: Default::default(), rollup_rows: Default::default(), prevalence_rows: Default::default(), caught_up_at: Default::default(), background_log_refresh: Default::default(),
            point: None, large: None, lane_memo: Default::default(), point_admission: Arc::new(tokio::sync::Semaphore::new(POINT_PERMITS)),
            companion_gate: Arc::new(tokio::sync::Semaphore::new(companion_permits(slots))),
            wide_gate: Arc::new(tokio::sync::Semaphore::new(wide_permits(slots))),
            job_admission: Arc::new(tokio::sync::Semaphore::new(1)),
            small_job_writer: None, small_job_admission: Arc::new(tokio::sync::Semaphore::new(1)),
            admission: Arc::new(tokio::sync::Semaphore::new(slots)), product: Default::default() })
    }

    /// Admit one request to native work, waiting at most `deadline` for a
    /// slot; the permit is held until the response is built.
    pub async fn admit(&self, deadline: Duration) -> QueryResult<AdmissionSlot> {
        match tokio::time::timeout(deadline, self.admission.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(AdmissionSlot { permit: Some(permit), slots: self.admission_slots(), gate: None }),
            Ok(Err(_)) => Err(PartQueryError::Unavailable("query admission is closed".into())),
            Err(_) => Err(PartQueryError::ConcurrencyBudget(format!(
                "all {} query slots stayed busy for {} s; retry later or run it as a search job",
                self.admission_slots(), deadline.as_secs()
            ))),
        }
    }

    /// Admit one request of `class` (NAN-3077). A point lookup takes a
    /// point permit (and runs on the point lane); a companion first takes a
    /// companion-gate permit, then an ordinary slot; a primary takes a slot.
    pub async fn admit_class(&self, class: RequestClass, deadline: Duration) -> QueryResult<AdmissionSlot> {
        match class {
            RequestClass::Point if self.point.is_some() => {
                match tokio::time::timeout(deadline, self.point_admission.clone().acquire_owned()).await {
                    Ok(Ok(permit)) => Ok(AdmissionSlot { permit: Some(permit), slots: POINT_PERMITS, gate: None }),
                    Ok(Err(_)) => Err(PartQueryError::Unavailable("query admission is closed".into())),
                    Err(_) => Err(PartQueryError::ConcurrencyBudget(format!(
                        "all {POINT_PERMITS} event-detail slots stayed busy for {} s; retry shortly",
                        deadline.as_secs()
                    ))),
                }
            }
            RequestClass::Point | RequestClass::Primary => self.admit(deadline).await,
            RequestClass::Wide => {
                let started = Instant::now();
                let gate = match tokio::time::timeout(deadline, self.wide_gate.clone().acquire_owned()).await {
                    Ok(Ok(gate)) => gate,
                    Ok(Err(_)) => return Err(PartQueryError::Unavailable("query admission is closed".into())),
                    Err(_) => {
                        return Err(PartQueryError::ConcurrencyBudget(format!(
                            "long-window searches stayed at their limit for {} s; retry later or run it as a search job",
                            deadline.as_secs()
                        )))
                    }
                };
                let mut slot = self.admit(deadline.saturating_sub(started.elapsed())).await?;
                slot.gate = Some(gate);
                Ok(slot)
            }
            RequestClass::Companion => {
                let started = Instant::now();
                let gate = match tokio::time::timeout(deadline, self.companion_gate.clone().acquire_owned()).await {
                    Ok(Ok(gate)) => gate,
                    Ok(Err(_)) => return Err(PartQueryError::Unavailable("query admission is closed".into())),
                    Err(_) => {
                        return Err(PartQueryError::ConcurrencyBudget(format!(
                            "search companions stayed at their limit for {} s; retry later",
                            deadline.as_secs()
                        )))
                    }
                };
                let mut slot = self.admit(deadline.saturating_sub(started.elapsed())).await?;
                slot.gate = Some(gate);
                Ok(slot)
            }
        }
    }

    /// Trusted SQL (typed partial routes) through [`Self::run`].
    pub async fn run_sql(&self, sql: String, params: Vec<(String, String)>) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
        let plan = NativeQueryPlan {
            query_sha256: String::new(),
            sql,
            params,
            budget: planner::QueryBudget { candidate_objects: 0, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
            native_event_rows: false,
            temporary_aliases: BTreeSet::new(),
            schema_defaults: Vec::new(), reader: Default::default(),
        };
        self.run(plan).await
    }

    /// A durable job's statement cap (NAN-3077): the large lane's when size
    /// classes are on (the default cap is then a small lane's), else the
    /// engine's.
    pub fn job_memory_bytes(&self) -> u64 {
        self.large.as_ref().map_or(self.settings.max_memory_bytes, super::lanes::LargeLane::bytes)
    }

    /// Admit one durable job (NAN-3077): jobs have their own permit (one at a
    /// time, like gen1's separate runner) and run on the read-write lane, so
    /// a job never holds an interactive slot.
    pub async fn admit_job(&self, deadline: Duration) -> QueryResult<AdmissionSlot> {
        match tokio::time::timeout(deadline, self.job_admission.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(AdmissionSlot { permit: Some(permit), slots: 1, gate: None }),
            Ok(Err(_)) => Err(PartQueryError::Unavailable("query admission is closed".into())),
            Err(_) => Err(PartQueryError::ConcurrencyBudget(format!(
                "a search job is already running; retry after {} s",
                deadline.as_secs()
            ))),
        }
    }

    /// NAN-4290: admit one durable job to a lane. A `small` job (see
    /// [`nanosiem_core::search::small_job_lane`]) takes the small-job lane,
    /// or the general lane when only that one is free; any other job takes
    /// the general lane ([`Self::admit_job`]). A small-lane job also holds an
    /// interactive admission slot: its statements run at one interactive
    /// lane's memory ([`Self::job_lane_memory_bytes`]), inside the memory and
    /// CPU (thread budget) the interactive lanes are carved from, so the
    /// tenant's query budget is unchanged.
    pub async fn admit_job_lane(&self, small: bool, deadline: Duration) -> QueryResult<(JobLane, AdmissionSlot)> {
        if !small || self.small_job_writer.is_none() {
            return Ok((JobLane::General, self.admit_job(deadline).await?));
        }
        let started = Instant::now();
        let gate = match self.small_job_admission.clone().try_acquire_owned() {
            Ok(gate) => gate,
            Err(_) => {
                if let Ok(permit) = self.job_admission.clone().try_acquire_owned() {
                    return Ok((JobLane::General, AdmissionSlot { permit: Some(permit), slots: 1, gate: None }));
                }
                match tokio::time::timeout(deadline, self.small_job_admission.clone().acquire_owned()).await {
                    Ok(Ok(gate)) => gate,
                    Ok(Err(_)) => return Err(PartQueryError::Unavailable("query admission is closed".into())),
                    Err(_) => return Err(PartQueryError::ConcurrencyBudget(format!(
                        "both search job lanes stayed busy for {} s; retry after it",
                        deadline.as_secs()
                    ))),
                }
            }
        };
        let mut slot = self.admit(deadline.saturating_sub(started.elapsed())).await?;
        slot.gate = Some(gate);
        Ok((JobLane::Small, slot))
    }

    /// NAN-4290: attach the small-job lane's read-write connection.
    pub fn with_small_job_writer(mut self, writer: NativeExecutor) -> Self {
        self.small_job_writer = Some(writer);
        self
    }

    /// The read-write connection a job admitted to `lane` executes on.
    pub fn job_writer(&self, lane: JobLane) -> Option<&NativeExecutor> {
        match lane {
            JobLane::General => self.writer.as_ref(),
            JobLane::Small => self.small_job_writer.as_ref(),
        }
    }

    /// A job statement's memory cap on `lane`: the general lane's is
    /// [`Self::job_memory_bytes`], the small lane's one interactive lane's.
    pub fn job_lane_memory_bytes(&self, lane: JobLane) -> u64 {
        match lane {
            JobLane::General => self.job_memory_bytes(),
            JobLane::Small => self.settings.max_memory_bytes,
        }
    }

    /// Attach the large lane (NAN-3077 size classes) with its memory
    /// (`large_bytes`, split across its connections, see
    /// [`super::lanes::LargeLane`]).
    pub fn with_large(self, large: NativeExecutor, large_bytes: u64) -> Self {
        self.with_large_lane(super::lanes::LargeLane::new(large, large_bytes))
    }

    /// [`Self::with_large`] with the lane already built (its routing may be
    /// `NANO_LAKE_LANE_ROUTING_V2=0`'s, see [`super::lanes::LargeLane::with_routing`]).
    pub fn with_large_lane(mut self, large: super::lanes::LargeLane) -> Self {
        if self.large.is_none() {
            // One more admitted request: the large lane's. A second large
            // connection (NAN-3393) serves the statements of requests already
            // admitted; it adds no request, so the Rust-side result headroom
            // (`QueryMemoryBudget::result_bytes`) is unchanged.
            self.admission.add_permits(1);
            self.companion_gate.add_permits(1);
            self.wide_gate.add_permits(1);
        }
        self.large = Some(large);
        self
    }

    pub(super) async fn with_job_statements<T>(&self, work: impl std::future::Future<Output = T>) -> T {
        JOB_STATEMENTS.scope(self as *const Self as usize, Box::pin(work)).await
    }

    /// Run one statement on the interactive lanes (NAN-3077, NAN-3393): a
    /// small lane, or the large lane when its estimated scan exceeds
    /// [`LARGE_SCAN_BYTES`], it ran out of a small lane's memory, or it did
    /// so before (see [`super::lanes::run_sized`]). Inside an
    /// interactive request it runs cancellably, so a request dropped by its
    /// caller (gateway timeout, closed tab) frees its lane at once.
    pub async fn run(&self, plan: NativeQueryPlan) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
        if JOB_STATEMENTS.try_with(|engine| *engine == self as *const Self as usize).unwrap_or(false) {
            if let Some(writer) = &self.writer {
                let cap = self.job_memory_bytes();
                let plan = with_memory_cap(plan, cap);
                return match run_on(writer, plan.clone()).await {
                    // NAN-3650: a durable job's statement gets the same last
                    // rung as an interactive one before it fails the job.
                    Err(error) if super::memory_budget::is_memory_limit_error(&error.to_string()) => {
                        tracing::info!(error = %error, cap_bytes = cap, "job statement exceeded its memory; retrying degraded");
                        let mut degraded = plan;
                        degraded.sql = super::lanes::degraded_sql(&degraded.sql);
                        match run_on(writer, degraded).await {
                            Err(error) if super::memory_budget::is_memory_limit_error(&error.to_string()) =>
                                Err(crate::executor::ExecutorError::MemoryExhausted { cap_bytes: cap, class: "job_degraded", detail: error.to_string() }),
                            Ok(output) => {
                                tracing::info!(cap_bytes = cap, finished_on = "job_degraded", "job statement finished on the degraded rung");
                                Ok(output)
                            }
                            other => other,
                        }
                    }
                    other => other,
                };
            }
        }
        super::lanes::run_sized(&self.executor, self.large.as_ref(), &self.lane_memo, plan).await
    }

    /// Attach the dedicated point-lookup lane (see [`RequestClass::Point`]).
    pub fn with_point(mut self, point: NativeExecutor) -> Self {
        self.point = Some(point);
        self
    }

    /// The lane a point lookup executes on.
    fn point_executor(&self) -> &NativeExecutor {
        self.point.as_ref().unwrap_or(&self.executor)
    }

    /// A slot for background work (NAN-3077), granted only while every slot
    /// is free: never queued, so it never delays an interactive or detect
    /// request, and `None` whenever anything else is running.
    pub fn try_admit_idle(&self) -> Option<AdmissionSlot> {
        let slots = self.admission_slots();
        idle_permit(&self.admission, slots).map(|permit| AdmissionSlot { permit: Some(permit), slots, gate: None })
    }

    /// Whether a durable job holds its permit (NAN-3399: background work on
    /// the read-write lane never starts while one runs).
    pub(crate) fn job_running(&self) -> bool {
        self.job_admission.available_permits() == 0
    }

    /// NAN-3399: the merged identity observation index slot.
    pub(crate) fn identity_merged(&self) -> &super::identity_merged::MergedSlot {
        &self.identity_merged
    }

    /// NAN-4190: the window entity index slot.
    pub(crate) fn entity_index(&self) -> &super::entity_index::Slot {
        &self.entity_index
    }

    /// Memoized identity coverage of `part` (see `identity_coverage`).
    pub(crate) fn identity_coverage(&self, part: &crate::parts::format::PartId) -> Option<Option<i64>> {
        self.identity_coverage.lock().expect("identity coverage").get(part).copied()
    }

    pub(crate) fn remember_identity_coverage(&self, answers: impl IntoIterator<Item = (crate::parts::format::PartId, Option<i64>)>) {
        let mut memo = self.identity_coverage.lock().expect("identity coverage");
        for (part, covered) in answers {
            if memo.len() >= MAX_IDENTITY_COVERAGE_MEMO && !memo.contains_key(&part) {
                // Parts only ever leave the window; a full memo is rebuilt.
                memo.clear();
            }
            memo.insert(part, covered);
        }
    }

    /// Admission slots (the budget's concurrency).
    pub fn admission_slots(&self) -> usize {
        self.executor.connection_count().max(1) + usize::from(self.large.is_some())
    }

    /// Use `dir` (the process's own state dir) for persistent state. The
    /// owner-denial proof memo of earlier releases is removed (NAN-4168).
    pub fn with_state_dir(mut self, dir: &std::path::Path) -> Self {
        let _ = std::fs::remove_file(dir.join(LEGACY_OWNER_PROOFS_MEMO));
        self.state_dir = Some(dir.to_path_buf());
        self
    }

    /// NAN-4174: keep the lane memo (see [`super::lanes::LaneMemo`]) in
    /// `dir`: the persistent hot volume when query[T] has one (it survives a
    /// pod roll), else the state dir (it survives idle exit).
    pub fn with_lane_memo_dir(self, dir: &std::path::Path) -> Self {
        self.lane_memo.persist_at(dir.join(super::lanes::LANE_MEMO_FILE));
        self
    }

    /// Reuse the query process's local identity derivation directory. Engines
    /// without persistent state use signed part partials only.
    pub(super) fn identity_state_dir(&self) -> &std::path::Path {
        self.state_dir.as_deref().unwrap_or_else(|| std::path::Path::new("/dev/null"))
    }

    /// NAN-3148: how this process relates to published product state (set
    /// once, before serving). Unset: build in-process (legacy).
    pub fn set_product_state(&self, published: super::product_publish::Published) -> anyhow::Result<()> {
        self.product.set(published).map_err(|_| anyhow::anyhow!("product state mode is already set"))
    }

    pub(super) fn product_state(&self) -> Option<&super::product_publish::Published> {
        self.product.get()
    }

    /// Where product state files live: product[T]'s published directory
    /// when one is configured, else this process's identity state dir.
    pub(super) fn product_dir(&self) -> &std::path::Path {
        match self.product.get() {
            Some(published) => published.dir(),
            None => self.identity_state_dir(),
        }
    }

    /// Attach the read-write lane (jobs, risk materialization).
    pub fn with_writer(mut self, writer: NativeExecutor) -> Self {
        self.writer = Some(writer);
        self
    }

    pub fn writer(&self) -> Option<&NativeExecutor> {
        self.writer.as_ref()
    }

    pub fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    pub fn executor(&self) -> &NativeExecutor {
        &self.executor
    }

    /// Per-part states from leased signed prevalence summaries.
    pub(super) fn prevalence_rows(&self) -> &super::prevalence_rows::PrevalenceRowsMemo {
        &self.prevalence_rows
    }

    /// Per-part count-rollup answers (NAN-3093).
    pub fn rollup_rows(&self) -> &super::rollup_rows::RollupRowsMemo {
        &self.rollup_rows
    }

    pub fn fetcher(&self) -> &PartFetcher {
        &self.fetcher
    }

    pub(super) fn token_cache_arc(&self) -> Arc<super::token_cache::TokenCache> {
        self.token_cache.clone()
    }

    pub(super) fn token_cache(&self) -> &super::token_cache::TokenCache {
        &self.token_cache
    }

    /// The tenant limits without a source (trusted typed routes such as the
    /// rollup planner read only threads/time/bytes/memory from it).
    pub fn limits_tenant(&self) -> TenantQueryConfig {
        TenantQueryConfig {
            tenant_id: self.settings.tenant_id.clone(),
            source: format!("s3://{}/{}", self.settings.bucket, super::fetch::parts_key_prefix(&self.settings.tenant_id).unwrap_or_default()),
            iceberg_metadata_file_path: "lake-parts-v1".to_string(),
            max_query_bytes: self.settings.max_query_bytes,
            max_memory_bytes: self.settings.max_memory_bytes,
            max_execution_seconds: self.settings.max_execution_seconds,
            threads: self.settings.threads,
            credentials: ObjectStoreCredentials::DefaultChain,
            snapshot_cache: None,
        }
    }

    /// Catch the view up with the log (called on notify and before queries).
    pub async fn refresh(&self) -> QueryResult<()> {
        let mut view = self.view.lock().await;
        self.catch_up_locked(&mut view).await
    }

    /// NAN-3392: the request path's catch-up: skipped while the background
    /// refresher keeps the view younger than [`CATCH_UP_COALESCE`] (see
    /// [`request_may_skip_catch_up`] for the exact staleness bound).
    pub async fn refresh_for_request(&self) -> QueryResult<()> {
        let at = *self.caught_up_at.lock().expect("catch-up clock");
        if request_may_skip_catch_up(self.background_log_refresh.load(std::sync::atomic::Ordering::Relaxed), at, Instant::now()) {
            return Ok(());
        }
        self.refresh().await
    }

    /// NAN-3392: a background refresher now keeps the view caught up.
    pub fn enable_background_log_refresh(&self) {
        self.background_log_refresh.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn catch_up_locked(&self, view: &mut PartLogView) -> QueryResult<()> {
        let _timer = crate::query_timing::timer(crate::query_timing::Phase::LogRefresh);
        let started = Instant::now();
        let advance = view.catch_up(self.store.as_ref()).await.map_err(|error| internal_text(format!("{error:#}")))?;
        let live = (!advance.is_empty()).then(|| view.live().parts().map(|part| part.part_id.clone()).collect());
        if !advance.is_empty() {
            let head = view.head().map_or(0, |(seq, _)| seq);
            self.advances.lock().expect("advance sink").push((head, advance));
        }
        if let Some(live) = &live { self.fragments.retain_live(live); }
        if let Err(error) = self.fetcher.retire_removed(live.as_ref()).await {
            tracing::warn!(%error, "superseded reader cache eviction deferred");
        }
        // The start instant: anything appended after it may not be applied.
        *self.caught_up_at.lock().expect("catch-up clock") = Some(started);
        Ok(())
    }

    /// Drain every catch-up footprint recorded since the last call.
    pub fn take_advances(&self) -> Vec<(u64, Advance)> {
        std::mem::take(&mut *self.advances.lock().expect("advance sink"))
    }

    /// `(seq, sha256)` of the verified head.
    pub async fn head(&self) -> Option<(u64, String)> {
        if let Ok(Some(head)) = DISCOVERY.try_with(|pin| {
            (pin.engine == self as *const Self as usize).then(|| pin.head.clone())
        }) { return head; }
        self.latest_head().await
    }

    /// Live head for cache admission after a potentially refreshed retry.
    pub async fn latest_head(&self) -> Option<(u64, String)> {
        self.view.lock().await.head()
    }

    pub async fn head_and_schema_fingerprint(&self) -> (Option<(u64, String)>, Option<String>) {
        if let Ok(Some(identity)) = DISCOVERY.try_with(|pin| {
            (pin.engine == self as *const Self as usize).then(|| (pin.head.clone(), pin.fingerprint.clone()))
        }) { return identity; }
        let view = self.view.lock().await;
        (view.head(), view.schema_fingerprint().map(str::to_owned))
    }

    /// Totals over the verified live part set (NAN-3020 storage facts).
    pub async fn live_totals(&self) -> crate::parts::part_log::LivePartTotals {
        self.view.lock().await.live().totals()
    }

    /// NAN-3662: rows refused at admission per source lane, 5-minute
    /// buckets (by refusal time) in `[start_ms, end_ms)`, and the time from
    /// which the window is complete (`None` while older entries are still
    /// being read). The first call after a checkpoint start reads the older
    /// `reject` entries in the background ([`super::log_view::backfill_refusals`]).
    pub async fn refusals(&self, start_ms: i64, end_ms: i64, now_ms: i64) -> (Vec<crate::parts::refusal_tally::RefusalRow>, Option<i64>) {
        let window = {
            let mut view = self.view.lock().await;
            if let Some(from) = view.take_refusal_history() {
                let store = Arc::clone(&self.store);
                let window = view.refusals();
                let tenant_id = view.tenant_id().to_string();
                let horizon_ms = now_ms.saturating_sub(super::log_view::REFUSAL_RETAIN_MS);
                tokio::spawn(async move {
                    let read = super::log_view::backfill_refusals(
                        store.as_ref(), &tenant_id, from, horizon_ms, super::log_view::MAX_REFUSAL_BACKFILL_ENTRIES, &window,
                    );
                    if let Err(error) = read.await {
                        tracing::warn!(tenant_id, error = %format!("{error:#}"), "refusal backfill stopped early; older refusals are not counted");
                    }
                });
            }
            view.refusals()
        };
        let window = window.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        (window.rows(start_ms, end_ms), window.complete_since_ms())
    }

    /// Live parts overlapping a window plus the read schema, at the head.
    pub async fn snapshot(&self, from_us: i64, to_us: i64) -> QueryResult<(Vec<PartRef>, Arc<arrow_schema::Schema>, Option<u64>, usize)> {
        if let Ok(Some(snapshot)) = DISCOVERY.try_with(|pin| {
            pin.snapshot_for(self as *const Self as usize, from_us, to_us)
        }) { return Ok(snapshot); }
        let mut view = self.view.lock().await;
        let fresh = self.caught_up_at.lock().expect("catch-up clock").is_some_and(|at| at.elapsed() < CATCH_UP_COALESCE);
        if !fresh {
            self.catch_up_locked(&mut view).await?;
        }
        let schema = read_schema(&mut view)?;
        Ok((view.parts_overlapping(from_us, to_us), schema, view.head().map(|(seq, _)| seq), view.live().parts().count()))
    }

    /// Preserve an enclosing discovery pin when a typed lookup is nested.
    pub(super) async fn pinned_if_needed<F: std::future::Future>(&self, work: F) -> QueryResult<F::Output> {
        // NAN-3141: hold `work` once, on the heap (see `Self::pinned`).
        let work = Box::pin(work);
        if DISCOVERY.try_with(|pin| pin.engine == self as *const Self as usize).unwrap_or(false) {
            return Ok(work.await);
        }
        self.pinned(work).await
    }

    /// Run discovery against one verified view; retries can explicitly repin.
    pub async fn pinned<F: std::future::Future>(&self, work: F) -> QueryResult<F::Output> {
        // NAN-3141: box `work` before the first await. Held by value across
        // `catch_up_locked` and then again inside `DISCOVERY.scope`, it was
        // laid out ~3x in this future; nested wrappers multiplied that into
        // a multi-MiB request future whose poll frame overflowed the 2 MiB
        // worker stack.
        let work = Box::pin(work);
        let mut view = self.view.lock().await;
        let fresh = self.caught_up_at.lock().expect("catch-up clock").is_some_and(|at| at.elapsed() < CATCH_UP_COALESCE);
        if !fresh { self.catch_up_locked(&mut view).await?; }
        let pin = PinnedDiscovery {
            engine: self as *const Self as usize,
            parts: view.parts_overlapping(i64::MIN, i64::MAX),
            schema: read_schema(&mut view)?,
            head: view.head(),
            fingerprint: view.schema_fingerprint().map(str::to_owned),
            live_parts: view.live().parts().count(),
        };
        drop(view);
        Ok(DISCOVERY.scope(pin, work).await)
    }

    /// The typed leaves of the read schema (the compiler's
    /// `snapshot_field_types`, as the reader derives them from its manifest).
    pub async fn field_types(&self) -> QueryResult<BTreeMap<String, String>> {
        if let Ok(Some(types)) = DISCOVERY.try_with(|pin| {
            (pin.engine == self as *const Self as usize).then(|| crate::generation::schema_leaf_types(&pin.schema))
        }) { return Ok(types); }
        let mut view = self.view.lock().await;
        let schema = read_schema(&mut view)?;
        Ok(crate::generation::schema_leaf_types(&schema))
    }

    /// Select, prune and lease the part files of `[from_us, to_us]` for
    /// `hints`. Every data file of a part is one planner object (contract r2:
    /// files are complete Parquet files holding consecutive rows).
    pub async fn select(&self, from_us: i64, to_us: i64, hints: &[CandidateHint]) -> QueryResult<Selection> {
        self.select_with(from_us, to_us, hints, None).await
    }

    /// [`Self::select`] with value-membership pruning from rollup partials.
    pub async fn select_with(
        &self,
        from_us: i64,
        to_us: i64,
        hints: &[CandidateHint],
        membership: Option<&Membership>,
    ) -> QueryResult<Selection> {
        self.select_counting(from_us, to_us, hints, membership, None).await
    }

    /// [`Self::select_with`] that also answers a single-keyword histogram
    /// from v3 token counts where it can: every row group counted into
    /// `tally` is fenced out of the selection, so the selection holds only
    /// the rows left to scan (see [`keyword_count`]).
    pub async fn select_counting(
        &self,
        from_us: i64,
        to_us: i64,
        hints: &[CandidateHint],
        membership: Option<&Membership>,
        counting: Option<(&keyword_count::CountPlan, &mut keyword_count::Tally)>,
    ) -> QueryResult<Selection> {
        self.select_part(from_us, to_us, hints, membership, counting, None).await
    }

    pub(super) async fn select_part(
        &self,
        from_us: i64,
        to_us: i64,
        hints: &[CandidateHint],
        membership: Option<&Membership>,
        counting: Option<(&keyword_count::CountPlan, &mut keyword_count::Tally)>,
        part_id: Option<&crate::parts::format::PartId>,
    ) -> QueryResult<Selection> {
        let only = part_id.map(|id| std::iter::once(id.clone()).collect::<BTreeSet<_>>());
        let selection = self.select_part_inner(from_us, to_us, hints, membership, counting, only.as_ref()).await?;
        record_selection_funnel(&selection.evidence);
        Ok(selection)
    }

    /// NAN-3644: [`Self::select_with`] restricted to the parts in `parts`
    /// (one batch of a batched cold read).
    pub(super) async fn select_parts(
        &self,
        from_us: i64,
        to_us: i64,
        hints: &[CandidateHint],
        membership: Option<&Membership>,
        parts: &BTreeSet<crate::parts::format::PartId>,
    ) -> QueryResult<Selection> {
        let selection = self.select_part_inner(from_us, to_us, hints, membership, None, Some(parts)).await?;
        record_selection_funnel(&selection.evidence);
        Ok(selection)
    }

    async fn select_part_inner(
        &self,
        from_us: i64,
        to_us: i64,
        hints: &[CandidateHint],
        membership: Option<&Membership>,
        mut counting: Option<(&keyword_count::CountPlan, &mut keyword_count::Tally)>,
        only: Option<&BTreeSet<crate::parts::format::PartId>>,
    ) -> QueryResult<Selection> {
        let (mut parts, schema, log_seq, live_parts) = self.snapshot(from_us, to_us).await?;
        // NAN-3715: an SQL probe may switch individual prune stages off to
        // measure what each one saves (process values everywhere else).
        use crate::perf_overrides::probe_flag;
        let (prune_family, prune_uid, prune_sidecars, prune_tokens, prune_blooms, allow_fine_runs) = (
            probe_flag("prune_source_family", true), probe_flag("prune_uid", true), probe_flag("prune_entity_sidecars", true),
            probe_flag("prune_tokens", true), probe_flag("prune_blooms", true), probe_flag("fine_runs", true));
        if let Some(only) = only {
            parts.retain(|part| only.contains(&part.part_id));
        }
        let mut evidence = SelectionEvidence { log_seq, live_parts, time_parts: parts.len(), ..Default::default() };
        let mut leases = Vec::new();
        if let Ok(Some(context)) = super::fragment_cache::CONTEXT.try_with(Clone::clone) {
            parts.retain(|part| !self.fragments.negative(&context.key(&self.settings.tenant_id, part, from_us, to_us)));
        }

        // File-level time pruning from the verified records (each data file
        // carries its own time bounds), before anything large is fetched.
        let records = self.fetcher.records(&parts).await.map_err(map_fetch_error)?;
        let uid_lookup = prune_uid && hints.iter().any(|hint| matches!(hint, CandidateHint::Entity { source_path, .. } if source_path == crate::parts::format::UID_PATH));
        let mut uid_masks = BTreeMap::new();
        let mut entity_masks = BTreeMap::new();
        let mut entity_wanted = Vec::new();
        let entity_lookup = prune_sidecars && prune::uses_entity_sidecars(hints);
        let exact_entity_lookup = prune_sidecars && crate::parts::entity_locators::uses_locators(hints);
        let mut uid_wanted = Vec::new();
        let mut candidates_files: Vec<(PartRef, usize)> = Vec::new();
        // NAN-3165: only the hinted fields of a sidecar are decoded (and,
        // NAN-3694, a bloom sidecar's folded keys for them).
        let entity_fields = crate::parts::entity_locators::hinted_fields(hints);
        let bloom_fields = prune::entity_bloom_fields(hints);
        let mut select_cpu_ms = 0.0_f64;
        let mut sidecar_files: Vec<(PartRef, usize, PartFile)> = Vec::new();
        for (part, record) in parts.iter().zip(&records) {
            let allowed = match membership.map(|membership| membership.part(&part.part_id)) {
                None => Some(None),
                Some(None) => None,
                Some(Some(buckets)) => Some(buckets),
            };
            let Some(buckets) = allowed else {
                evidence.membership_pruned_parts += 1;
                continue;
            };
            for (index, data) in record.files.data.iter().enumerate() {
                // NAN-3188: class pruning counts with the source family:
                // both decide a whole file from its signed family label.
                if prune_family && !prune::file_family_may_match(
                    data.log_sources.as_deref(),
                    data.class_id,
                    hints,
                ) {
                    evidence.source_family_pruned_files += 1;
                    continue;
                }
                if data.min_time_us <= to_us
                    && data.max_time_us >= from_us
                    && buckets.is_none_or(|buckets| Membership::touches(buckets, data.min_time_us.max(from_us), data.max_time_us.min(to_us)))
                {
                    if exact_entity_lookup && data.entity_locators.is_some() {
                        sidecar_files.push((part.clone(), index, PartFile::EntityLocators(index)));
                    } else if entity_lookup && data.entity_blooms.is_some() {
                        sidecar_files.push((part.clone(), index, PartFile::Entities(index)));
                    }
                    if uid_lookup && data.uid_blooms.is_some() {
                        uid_wanted.push((part.clone(), PartFile::Uids(index)));
                    }
                    candidates_files.push((part.clone(), index));
                }
            }
        }
        evidence.time_files = candidates_files.len();
        // NAN-3392: select sub-phase walls (sidecar / token / footer-bloom).
        let sidecar_started = Instant::now();
        // NAN-4190: the window entity index answers the entity hints of the
        // files it covers (exact group masks and row runs with exact times)
        // before any sidecar or footer is read; uncovered files keep the
        // per-file evidence path below.
        let mut index_fine: BTreeMap<(String, usize), prune::FineBlocks> = BTreeMap::new();
        let mut index_answered: BTreeSet<(String, usize)> = BTreeSet::new();
        let mut index_hints: Option<Arc<[CandidateHint]>> = None;
        if let Some(index) = prune_sidecars.then(|| self.entity_index.for_query()).flatten().filter(|index| index.answers(hints)) {
            let record_of = parts.iter().zip(&records).map(|(part, record)| (part.part_id.clone(), record)).collect::<BTreeMap<_, _>>();
            let files = candidates_files.iter().map(|(part, index)| {
                let data = &record_of[&part.part_id].files.data[*index];
                (super::entity_index::SourceKey { part: part.part_id.clone(), index: *index, sha256: data.sha256.clone() }, data.row_groups as usize, data.rows)
            }).collect::<Vec<_>>();
            let (lookup_index, lookup_hints) = (index.clone(), hints.to_vec());
            let (mut found, cpu) = super::select_evidence::blocking_map(vec![()], move |()| lookup_index.evidence(&lookup_hints, &files)).await;
            select_cpu_ms += cpu;
            // A failed task or an unreadable index file keeps every file on the per-file path.
            if let Some(Some(Some(found))) = found.pop() {
                let (mut covered, mut pruned) = (BTreeSet::new(), BTreeSet::new());
                let mut kept = Vec::with_capacity(candidates_files.len());
                for ((part, file), answer) in std::mem::take(&mut candidates_files).into_iter().zip(found) {
                    let Some(answer) = answer else {
                        kept.push((part, file));
                        continue;
                    };
                    evidence.entity_index_files += 1;
                    covered.insert((part.part_id.clone(), file));
                    if !answer.mask.iter().any(|keep| *keep) {
                        evidence.entity_index_pruned_files += 1;
                        pruned.insert((part.part_id.clone(), file));
                        continue;
                    }
                    let key = (part.part_id.to_string(), file);
                    if answer.answered {
                        index_answered.insert(key.clone());
                    }
                    if answer.fine.iter().any(Option::is_some) {
                        index_fine.insert(key.clone(), answer.fine);
                    }
                    entity_masks.insert(key, answer.mask);
                    kept.push((part, file));
                }
                candidates_files = kept;
                sidecar_files.retain(|(part, file, _)| !covered.contains(&(part.part_id.clone(), *file)));
                uid_wanted.retain(|(part, file)| !matches!(file, PartFile::Uids(file) if pruned.contains(&(part.part_id.clone(), *file))));
                super::entity_index::fit_run_budget(&mut index_fine, MAX_CANDIDATE_BLOCKS * 3 / 4);
                index_hints = Some(index.strip_answered(if prune_blooms { hints } else { &[] }).into());
            }
        }
        // NAN-3165: a data file already local answers entity evidence from
        // its own Parquet blooms in the data stage (a pread of the hinted
        // field's filter per row group), so its sidecars are not leased or
        // decoded. Sidecars only save fetching data that is not local.
        // NAN-3694: except when a hint has only folded evidence (a long
        // mixed-case value): the in-file raw blooms cannot answer it.
        if !sidecar_files.is_empty() && resident_infile_blooms() && !prune::needs_folded_blooms(hints) {
            let wanted = sidecar_files.iter().map(|(part, index, _)| (part.clone(), *index)).collect::<Vec<_>>();
            let resident = self.fetcher.resident_data_files(&wanted).await;
            sidecar_files.retain(|(part, index, _)| !resident.contains(&(part.part_id.clone(), *index)));
            evidence.resident_infile_files = resident.len();
        }
        entity_wanted.extend(sidecar_files.into_iter().map(|(part, _, file)| (part, file)));
        if uid_lookup {
            let uids = self.fetcher.ensure_files(&uid_wanted).await.map_err(map_fetch_error)?;
            // NAN-4292: one positioned read per group against a cached
            // layout (not a full JSON + hex decode through the metadata
            // cache), fanned out like the token probes.
            let items = candidates_files.iter().map(|(part, index)| {
                let groups = uids.records[&part.part_id].files.data[*index].row_groups as usize;
                let local = uids.path(&part.part_id, PartFile::Uids(*index)).map(|local| (local.path.clone(), local.sha256.clone()));
                (local, groups)
            }).collect::<Vec<_>>();
            let (layouts, uid_hints) = (self.uid_layouts.clone(), Arc::<[CandidateHint]>::from(hints));
            let (masks, cpu) = super::select_evidence::blocking_map_with(items, super::select_evidence::token_probe_concurrency(), move |(local, groups)| {
                local.and_then(|(path, sha256)| layouts.mask(&path, &sha256, groups, &uid_hints))
            }).await;
            select_cpu_ms += cpu;
            let mut masks = masks.into_iter();
            candidates_files.retain(|(part, index)| {
                // A failed blocking task or unknown file keeps every group.
                let Some(mask) = masks.next().flatten().flatten() else { return true };
                if !mask.iter().any(|keep| *keep) {
                    evidence.uid_pruned_files += 1;
                    return false;
                }
                uid_masks.insert((part.part_id.to_string(), *index), mask);
                true
            });
            record_lease(&mut evidence, &uids);
            leases.push(uids);
        }

        if !entity_wanted.is_empty() {
            let entities = self.fetcher.ensure_files(&entity_wanted).await.map_err(map_fetch_error)?;
            // NAN-3156: a locator that dropped a hint's (dense) field, or
            // one that does not decode, no longer shadows the file's bloom
            // sidecar: both prune, and their group masks AND together.
            let mut bloom_fallback = Vec::new();
            let cpu = crate::query_timing::select_cpu(Some(&mut select_cpu_ms));
            candidates_files.retain(|(part, index)| {
                if let Some(local) = entities.path(&part.part_id, PartFile::EntityLocators(*index)) {
                    let data = &entities.records[&part.part_id].files.data[*index];
                    let with_blooms = entity_lookup && data.entity_blooms.is_some();
                    let locator = self.entity_cache.get_fields(&local.path, &local.sha256, data.row_groups as usize, data.rows, &entity_fields);
                    let Some(locator) = locator else {
                        if with_blooms { bloom_fallback.push((part.clone(), PartFile::Entities(*index))); }
                        return true;
                    };
                    let mask = locator.group_mask(hints);
                    if !mask.iter().any(|keep| *keep) {
                        evidence.entity_sidecar_pruned_files += 1;
                        return false;
                    }
                    if with_blooms && !locator.covers(hints) {
                        bloom_fallback.push((part.clone(), PartFile::Entities(*index)));
                    }
                    entity_masks.insert((part.part_id.to_string(), *index), mask);
                    return true;
                }
                let Some(local) = entities.path(&part.part_id, PartFile::Entities(*index)) else { return true };
                let blooms = self.fetcher.metadata_bytes(local)
                    .and_then(|bytes| prune::decode_entity_blooms(&bytes, &bloom_fields));
                let record = &entities.records[&part.part_id];
                let Some(mask) = prune::entity_summary_mask(blooms.as_ref(), record.files.data[*index].row_groups as usize, hints) else { return true };
                if !mask.iter().any(|keep| *keep) {
                    evidence.entity_sidecar_pruned_files += 1;
                    return false;
                }
                entity_masks.insert((part.part_id.to_string(), *index), mask);
                true
            });
            drop(cpu);
            record_lease(&mut evidence, &entities);
            leases.push(entities);
            if !bloom_fallback.is_empty() {
                let blooms = self.fetcher.ensure_files(&bloom_fallback).await.map_err(map_fetch_error)?;
                let cpu = crate::query_timing::select_cpu(Some(&mut select_cpu_ms));
                candidates_files.retain(|(part, index)| {
                    let Some(local) = blooms.path(&part.part_id, PartFile::Entities(*index)) else { return true };
                    let decoded = self.fetcher.metadata_bytes(local)
                        .and_then(|bytes| prune::decode_entity_blooms(&bytes, &bloom_fields));
                    let groups = blooms.records[&part.part_id].files.data[*index].row_groups as usize;
                    let key = (part.part_id.to_string(), *index);
                    let Some(mask) = prune::and(entity_masks.remove(&key), prune::entity_summary_mask(decoded.as_ref(), groups, hints)) else { return true };
                    if !mask.iter().any(|keep| *keep) {
                        evidence.entity_sidecar_pruned_files += 1;
                        return false;
                    }
                    entity_masks.insert(key, mask);
                    true
                });
                drop(cpu);
                record_lease(&mut evidence, &blooms);
                leases.push(blooms);
            }
        }

        let sidecar_ms = sidecar_started.elapsed().as_secs_f64() * 1000.0;
        let token_started = Instant::now();
        // Token stage: decided from the small per-file index before any data
        // fetch; a file with no surviving row group is never fetched.
        let mut token_masks: BTreeMap<(String, usize), Vec<bool>> = BTreeMap::new();
        let mut fine_blocks: BTreeMap<(String, usize), prune::FineBlocks> = BTreeMap::new();
        // NAN-3392: a combined hint's token index is decoded only when the
        // footer stage misses the evidence cache, never per query.
        let mut combined_token_files: BTreeMap<(String, usize), super::select_evidence::TokenFile> = BTreeMap::new();
        let combine_hints = prune_blooms && prune::needs_combined(hints);
        let shared_hints: Arc<[CandidateHint]> = Arc::from(hints);
        // The footer stage without hints still reads the row ranges and
        // group times every plan needs; it just proves nothing empty.
        let footer_hints: Arc<[CandidateHint]> = if prune_blooms { shared_hints.clone() } else { Arc::from(Vec::new()) };
        let mut survivors = candidates_files.clone();
        if prune_tokens && prune::uses_tokens(hints) && !candidates_files.is_empty() {
            let wanted = candidates_files.iter().map(|(part, index)| (part.clone(), PartFile::Tokens(*index))).collect::<Vec<_>>();
            let tokens = self.fetcher.ensure_files(&wanted).await.map_err(map_fetch_error)?;
            let lease_ms = token_started.elapsed().as_secs_f64() * 1000.0;
            let token_stats = self.token_cache.stats();
            survivors.clear();
            let record_of = parts.iter().zip(&records).map(|(part, record)| (part.part_id.clone(), record.clone())).collect::<BTreeMap<_, _>>();
            // NAN-3392: first-time token evidence (read + decode) runs on
            // the blocking pool, `PROBE_CONCURRENCY` files at a time, not
            // inline on a runtime worker. Counting selections tally into
            // `&mut` state and keep the sequential path below.
            let mut fanned_out = None;
            if counting.is_none() {
                let items = candidates_files.iter().map(|(part, index)| {
                    let groups = record_of[&part.part_id].files.data[*index].row_groups as usize;
                    let local = tokens.path(&part.part_id, PartFile::Tokens(*index)).map(|local| (local.path.clone(), local.sha256.clone()));
                    (local, groups)
                }).collect::<Vec<_>>();
                let (cache, hints) = (self.token_cache.clone(), shared_hints.clone());
                // NAN-4164: I/O-bound, so a deeper fan-out than footers.
                let (results, cpu) = super::select_evidence::blocking_map_with(items, super::select_evidence::token_probe_concurrency(), move |(local, groups)| {
                    // Leased files: the fetcher verified them against the
                    // signed record, so the trailer is not re-hashed.
                    local.map_or((None, None), |(path, sha256)| cache.evidence(&path, &sha256, groups, &hints))
                }).await;
                select_cpu_ms += cpu;
                fanned_out = Some(results.into_iter());
            }
            // NAN-4311: a counting selection tallies sequentially, but reads
            // and decodes its token files on the blocking pool first, one
            // chunk at a time (a day of a common token is hundreds of whole
            // files, far over the decoded cache; a chunk bounds what is held).
            let chunk_files = if counting.is_some() { super::select_evidence::token_probe_concurrency().max(1) } else { candidates_files.len().max(1) };
            for chunk in candidates_files.chunks(chunk_files) {
                let mut decoded_for_counting = None;
                if counting.is_some() {
                    let items = chunk.iter().map(|(part, index)| {
                        tokens.path(&part.part_id, PartFile::Tokens(*index)).map(|local| (local.path.clone(), local.sha256.clone()))
                    }).collect::<Vec<_>>();
                    let cache = self.token_cache.clone();
                    let (results, cpu) = super::select_evidence::blocking_map_with(items, super::select_evidence::token_probe_concurrency(), move |local| {
                        local.and_then(|(path, sha256)| cache.get(&path, &sha256))
                    }).await;
                    select_cpu_ms += cpu;
                    decoded_for_counting = Some(results.into_iter().map(Option::flatten));
                }
                let cpu = crate::query_timing::select_cpu(Some(&mut select_cpu_ms));
                for (part, index) in chunk {
                    let token_file = tokens.path(&part.part_id, PartFile::Tokens(*index));
                    let groups = record_of[&part.part_id].files.data[*index].row_groups as usize;
                    let (mask, fine) = match counting.as_mut() {
                        // A failed blocking task keeps every group (unknown).
                        None => fanned_out.as_mut().and_then(Iterator::next).flatten().unwrap_or((None, None)),
                        Some((plan, tally)) => match decoded_for_counting.as_mut().and_then(Iterator::next).flatten() {
                            None => (None, None),
                            Some(decoded) => {
                                let (mut mask, mut fine) = prune::token_evidence_of(&decoded, groups, hints);
                                // NAN-4311: the file's one signed source family, if any.
                                let source = record_of[&part.part_id].files.data[*index].log_sources.as_deref()
                                    .and_then(|sources| match sources { [source] => Some(source.as_str()), _ => None });
                                if let Some(mask) = mask.as_mut().filter(|mask| mask.len() == decoded.len()) {
                                    for (group, tokens) in decoded.iter().enumerate() {
                                        // Exact counts replace the group's scan; an
                                        // unreadable table just leaves it scanned.
                                        let counted = tally.count_group(&format!("{}/{index}", part.part_id), source, plan, tokens).unwrap_or_else(|error| {
                                            tracing::warn!(part = %part.part_id, file = index, group, error = %error, "token counts unreadable; scanning the group");
                                            false
                                        });
                                        if counted {
                                            mask[group] = false;
                                            if let Some(runs) = fine.as_mut().and_then(|fine| fine.get_mut(group)) {
                                                *runs = Some(Vec::new());
                                            }
                                        }
                                    }
                                }
                                (mask, fine)
                            }
                        },
                    };
                    match mask {
                        Some(mask) if !mask.iter().any(|keep| *keep) => evidence.token_pruned_files += 1,
                        Some(mask) => {
                            token_masks.insert((part.part_id.to_string(), *index), mask);
                            if let Some(fine) = fine {
                                fine_blocks.insert((part.part_id.to_string(), *index), fine);
                            }
                            if combine_hints {
                                if let Some(local) = token_file {
                                    combined_token_files.insert((part.part_id.to_string(), *index), super::select_evidence::TokenFile { path: local.path.clone(), sha256: local.sha256.clone() });
                                }
                            }
                            survivors.push((part.clone(), *index));
                        }
                        None => {
                            if combine_hints {
                                if let Some(local) = token_file {
                                    combined_token_files.insert((part.part_id.to_string(), *index), super::select_evidence::TokenFile { path: local.path.clone(), sha256: local.sha256.clone() });
                                }
                            }
                            survivors.push((part.clone(), *index));
                        }
                    }
                }
                drop(cpu);
            }
            record_lease(&mut evidence, &tokens);
            leases.push(tokens);
            let work = self.token_cache.stats() - token_stats;
            let total_ms = token_started.elapsed().as_secs_f64() * 1000.0;
            crate::query_timing::record(|p| {
                p.select_token_lease_ms += lease_ms;
                p.select_token_evidence_ms += total_ms - lease_ms;
                record_token_work(p, work);
            });
        }
        let token_ms = token_started.elapsed().as_secs_f64() * 1000.0;
        crate::query_timing::record(|p| {
            p.select_sidecar_ms += sidecar_ms;
            p.select_token_ms += token_ms;
        });
        evidence.select_cpu_us = (select_cpu_ms * 1000.0) as u64;

        let schema_read = crate::iceberg::clickhouse_read_schema(&schema).map_err(internal)?;
        let field_types = crate::generation::schema_leaf_types(&schema);
        let available: Arc<[String]> = field_types.keys().cloned().collect::<Vec<_>>().into();
        let tenant_base = |snapshot_cache: SnapshotCache| TenantQueryConfig {
            snapshot_cache: Some(snapshot_cache),
            ..self.limits_tenant()
        };

        if let Some((_, tally)) = &counting {
            evidence.count_groups = tally.groups();
            evidence.count_rows = tally.rows();
        }
        if survivors.is_empty() {
            // Nothing can match: the typed empty relation of the read schema,
            // exactly the reader's zero-snapshot bootstrap source.
            let tenant = tenant_base(SnapshotCache {
                source_spec: String::new(),
                objects: BTreeMap::new(),
                bytes: 0,
                read_schema: Some(schema_read),
                bootstrap: true,
            });
            return Ok(Selection {
                parts: Vec::new(),
                // NAN-3081: the empty relation's columns are the read
                // schema's, not missing ones.
                manifest: SourceManifest::empty_with_bootstrap_paths(self.settings.tenant_id.clone(), available.iter().cloned()),
                tenant,
                candidates: None,
                field_types,
                evidence,
                object_times: BTreeMap::new(),
                _leases: leases,
            });
        }

        let wanted = survivors.iter().map(|(part, index)| (part.clone(), PartFile::Data(*index))).collect::<Vec<_>>();
        // NAN-3133: an entity pivot prunes row groups with in-file blooms,
        // which no signed range covers: it keeps whole files (and that
        // pruning). A rerun scope reads whole files under its budget.
        let scope = super::range_fetch::current();
        let pivot = scope.as_ref().is_some_and(|scope| !scope.whole_only()) && prune::uses_entities(hints);
        // Pivots still draw on the request's cold budget and debit.
        let data = match &scope {
            Some(scope) => self.fetcher.ensure_ranged(&wanted, scope, pivot).await,
            None => self.fetcher.ensure_files(&wanted).await,
        }.map_err(map_fetch_error)?;
        record_lease(&mut evidence, &data);
        match (&scope, &data.ranged) {
            (Some(scope), Some(ranged)) => {
                evidence.range.absorb(&ranged.evidence);
                if ranged.evidence.range_files > 0 {
                    scope.mark_sparse_used();
                }
            }
            _ => evidence.range.fetched(0, 0, data.lease.as_ref().map_or(0, |lease| lease.fetched_bytes())),
        }
        evidence.fetched_files = survivors.len();
        let mut objects = Vec::with_capacity(survivors.len());
        let mut object_times = BTreeMap::new();
        let mut cache_objects = BTreeMap::new();
        let mut paths = Vec::with_capacity(survivors.len());
        let mut blocks = Vec::new();
        // NAN-3032: the same selection with v2 block runs in place of whole
        // row groups where an index proved them sparse; used when it stays
        // within FINE_RUN_BUDGET.
        let mut fine_selection = Vec::new();
        let (mut fine_runs, mut fine_rows, mut fine_replaced_rows) = (0_usize, 0_u64, 0_u64);
        let mut pruned_any = false;
        let mut total_bytes = 0_u64;
        let mut selected_parts: Vec<PartRef> = Vec::new();
        let mut unfenced_leaf_bytes: Vec<(usize, BTreeMap<String, u64>)> = Vec::new();
        // NAN-3392: every survivor's footer/bloom evidence, from the
        // per-(file, hint) evidence cache where known; first-time evidence
        // reads blooms (and decodes a combined token index) on the blocking
        // pool, `PROBE_CONCURRENCY` files at a time.
        let bloom_started = Instant::now();
        let evidence_caches = super::select_evidence::Caches {
            metadata: self.file_metadata.clone(),
            evidence: self.evidence_cache.clone(),
            tokens: self.token_cache.clone(),
        };
        let cache_footer = survivors.len() <= prune::MAX_OPEN_FOOTERS;
        // NAN-4190: a file whose indexed hints the window entity index
        // answered exactly reads no bloom for them.
        let probe_hints = |part: &PartRef, index: usize| index_answered.contains(&(part.part_id.to_string(), index)).then(|| index_hints.clone()).flatten();
        let probe_of = |part: &PartRef, local: &super::fetch::LocalFile, tokens: Option<super::select_evidence::TokenFile>, hints: Option<Arc<[CandidateHint]>>| super::select_evidence::Probe {
            path: local.path.clone(),
            // A sparse file's footer summary is keyed apart from the whole
            // file's: its rewritten footer carries no bloom references.
            file_key: summary_key(local),
            tokens,
            buckets: membership.and_then(|membership| membership.part(&part.part_id).flatten()).cloned(),
            hints,
        };
        let probes = survivors.iter().map(|(part, index)| {
            let tokens = combined_token_files.get(&(part.part_id.to_string(), *index)).cloned();
            data.path(&part.part_id, PartFile::Data(*index)).map(|local| probe_of(part, local, tokens, probe_hints(part, *index)))
        }).collect::<Vec<_>>();
        let (probed, cpu) = super::select_evidence::probe_all(&evidence_caches, probes, footer_hints.clone(), combine_hints, cache_footer).await;
        select_cpu_ms += cpu;
        let mut probe_stats = super::select_evidence::ProbeStats::default();
        let mut probed = probed.into_iter();
        for (part, index) in &survivors {
            let record = data
                .records
                .get(&part.part_id)
                .ok_or_else(|| internal(format!("part {} record was not leased", part.part_id)))?;
            let digest = &record.files.data[*index];
            let mut local = data
                .path(&part.part_id, PartFile::Data(*index))
                .ok_or_else(|| internal(format!("part {} data file {index} was not leased", part.part_id)))?.clone();
            let key = self.fetcher.file_uri(part, record, PartFile::Data(*index)).map_err(internal)?;
            let key_for_mask = (part.part_id.to_string(), *index);
            let token_mask = token_masks.remove(&key_for_mask);
            let (mut footer, stats, mut file_summary) = probed.next().unwrap_or_default();
            probe_stats.absorb(stats);
            if footer.is_none() {
                // Re-resolve the same signed object once, retaining the new
                // lease through execution. Never substitute a different part.
                let retry = self.fetcher.ensure_files(&[(part.clone(), PartFile::Data(*index))]).await.map_err(map_fetch_error)?;
                record_lease(&mut evidence, &retry);
                local = retry.path(&part.part_id, PartFile::Data(*index))
                    .ok_or_else(|| internal("retry data file was not leased"))?.clone();
                let tokens = combined_token_files.get(&key_for_mask).cloned();
                let (mut again, cpu) = super::select_evidence::probe_all(&evidence_caches, vec![Some(probe_of(part, &local, tokens, probe_hints(part, *index)))], footer_hints.clone(), combine_hints, cache_footer).await;
                select_cpu_ms += cpu;
                let (retried, stats, summary) = again.pop().unwrap_or_default();
                probe_stats.absorb(stats);
                footer = retried;
                file_summary = summary;
                leases.push(retry);
            }
            let (combined_mask, membership_mask, ranges, group_times) = footer
                .ok_or_else(|| internal(format!("part {} data file {index} footer is unreadable after re-resolution", part.part_id)))?;
            let mask = prune::and(prune::and(prune::and(token_mask, combined_mask), membership_mask), prune::and(uid_masks.remove(&key_for_mask), entity_masks.remove(&key_for_mask)));
            if ranges.len() != digest.row_groups as usize || ranges.last().map(|(_, end)| *end) != Some(digest.rows) {
                return Err(internal(format!("part {} data file {index} row groups disagree with its record", part.part_id)));
            }
            evidence.row_groups += ranges.len();
            // NAN-3165: a file every row group of which is proven empty
            // (in-file blooms, membership, tokens) is not handed to the
            // statement at all; otherwise its footer is still opened by every
            // statement over this selection. Counting selections keep it:
            // their unfenced fallback forgets every survivor's counts.
            if counting.is_none() && mask.as_ref().is_some_and(|mask| mask.len() == ranges.len() && !mask.iter().any(|keep| *keep)) {
                evidence.infile_pruned_files += 1;
                continue;
            }
            // Runs are group-relative; an index whose groups disagree with
            // the verified footer is ignored (row groups only).
            let fine = super::entity_index::and_fine(fine_blocks.remove(&key_for_mask), index_fine.remove(&key_for_mask)).filter(|fine| {
                fine.len() == ranges.len()
                    && fine.iter().zip(&ranges).all(|(runs, (start, end))| {
                        runs.as_ref().is_none_or(|runs| runs.iter().all(|(s, e, _)| s < e && *e <= end - start))
                    })
            });
            if let Some(fine) = &fine {
                for (group, runs) in fine.iter().enumerate() {
                    let Some(runs) = runs else { continue };
                    if mask.as_ref().is_some_and(|mask| mask.len() == ranges.len() && !mask[group]) {
                        continue;
                    }
                    let (start, end) = ranges[group];
                    fine_replaced_rows += end - start;
                    for (run_start, run_end, time) in runs {
                        fine_runs += 1;
                        fine_rows += run_end - run_start;
                        fine_selection.push(CandidateBlock {
                            event_object_key: key.clone(),
                            event_object_bytes: local.bytes,
                            row_start: start + run_start,
                            row_end: start + run_end,
                            max_time_ms: None,
                            time_range_us: Some(*time),
                        });
                    }
                }
            }
            let kept = match &mask {
                Some(mask) if mask.len() == ranges.len() => {
                    pruned_any |= mask.iter().any(|keep| !keep);
                    evidence.kept_row_groups += mask.iter().filter(|keep| **keep).count();
                    prune::kept_ranges_with_time(mask, &ranges, group_times.as_deref())
                }
                _ => {
                    evidence.kept_row_groups += ranges.len();
                    let whole = group_times
                        .as_deref()
                        .filter(|times| times.len() == ranges.len())
                        .and_then(|times| Some((times.iter().map(|t| t.0).min()?, times.iter().map(|t| t.1).max()?)));
                    vec![(0, digest.rows, whole)]
                }
            };
            for (start, end, time_range_us) in kept {
                blocks.push(CandidateBlock {
                    event_object_key: key.clone(),
                    event_object_bytes: local.bytes,
                    row_start: start,
                    row_end: end,
                    max_time_ms: None,
                    time_range_us,
                });
                // Groups without sparse runs are read whole in the fine
                // selection too (split so they never overlap a run).
                if let Some(fine) = &fine {
                    for (group, (group_start, group_end)) in ranges.iter().enumerate() {
                        if fine[group].is_none() && *group_start >= start && *group_end <= end {
                            fine_selection.push(CandidateBlock {
                                event_object_key: key.clone(),
                                event_object_bytes: local.bytes,
                                row_start: *group_start,
                                row_end: *group_end,
                                max_time_ms: None,
                                time_range_us: group_times
                                    .as_deref()
                                    .filter(|times| times.len() == ranges.len())
                                    .map(|times| times[group]),
                            });
                        }
                    }
                } else {
                    fine_selection.push(blocks.last().expect("pushed").clone());
                }
            }
            total_bytes = total_bytes.checked_add(local.bytes).ok_or_else(|| internal("part byte total overflowed"))?;
            paths.push(local.path.to_str().ok_or_else(|| internal("cache path is not UTF-8"))?.to_string());
            cache_objects.insert(
                key.clone(),
                SnapshotCacheObject { version_id: local.sha256.clone(), bytes: local.bytes, path: local.path.clone() },
            );
            if super::debug::enabled() {
                super::debug::file(&key, part.level.code(), local.bytes);
            }
            // NAN-3155: the leaves' bytes in the row groups this selection
            // keeps (the scan estimate used to be the whole file). NAN-3159:
            // unkept groups are skipped only through the time guard (exact
            // group stats), and a selection that is not handed to the scan
            // (no fence) reads every group: keep that charge aside.
            let (column_compressed_bytes, whole_leaves) = file_summary.clone()
                .or_else(|| self.file_metadata.summary(&local.path, &summary_key(&local)))
                .map(|summary| summary.kept_and_whole_leaf_bytes(mask.as_deref().filter(|_| group_times.is_some())))
                .unwrap_or_default();
            if let Some(whole) = whole_leaves {
                unfenced_leaf_bytes.push((objects.len(), whole));
            }
            object_times.insert(key.clone(), (digest.min_time_us, digest.max_time_us));
            objects.push(ManifestObject {
                event_object_key: key,
                event_object_version: local.sha256.clone(),
                event_object_bytes: local.bytes,
                rows: digest.rows,
                available_paths: available.clone(),
                field_types: field_types.clone(),
                column_compressed_bytes,
            });
            if selected_parts.last().is_none_or(|last| last.part_id != part.part_id) {
                selected_parts.push(part.clone());
            }
        }
        // The coarse alternative: kept row groups under a fence, or (nothing
        // pruned, or too many blocks) whole files with no fence term.
        let scan_rows = |blocks: &[CandidateBlock]| blocks.iter().map(|block| block.row_end - block.row_start).sum::<u64>();
        let coarse_terms = if pruned_any && blocks.len() <= MAX_CANDIDATE_BLOCKS { blocks.len() } else { 0 };
        let use_fine = allow_fine_runs
            && use_fine_runs(fine_runs, (scan_rows(&fine_selection), fine_selection.len()), (scan_rows(&blocks), coarse_terms))
            && fine_fence_fits(&fine_selection, &objects);
        if fine_runs > 0 && !use_fine {
            evidence.fine_declined_runs = fine_runs;
        }
        let candidates = if use_fine {
            evidence.fine_runs = fine_runs;
            evidence.fine_rows = fine_rows;
            evidence.fine_replaced_rows = fine_replaced_rows;
            Some(fine_selection)
        } else {
            pruned_any.then_some(blocks).filter(|blocks| blocks.len() <= MAX_CANDIDATE_BLOCKS)
        };
        evidence.candidate_blocks = candidates.as_ref().map(Vec::len);
        if candidates.is_none() {
            // Whole surviving files are scanned: charge every row group.
            for (object, whole) in unfenced_leaf_bytes {
                objects[object].column_compressed_bytes = whole;
            }
        }
        if let Some((_, tally)) = counting.as_mut() {
            // Without a fence the scan reads whole surviving files, counted
            // groups included: those files' counts are dropped (never added
            // twice). Fully counted files were never selected.
            if candidates.is_none() {
                for (part, index) in &survivors {
                    tally.forget(&format!("{}/{index}", part.part_id));
                }
            }
            evidence.count_groups = tally.groups();
            evidence.count_rows = tally.rows();
        }
        leases.push(data);
        let bloom_ms = bloom_started.elapsed().as_secs_f64() * 1000.0;
        crate::query_timing::record(|p| {
            p.select_bloom_ms += bloom_ms;
            p.evidence_cache_hits += probe_stats.hits;
            p.evidence_cache_misses += probe_stats.misses;
        });
        evidence.select_cpu_us = (select_cpu_ms * 1000.0) as u64;
        if objects.is_empty() {
            // Every leased file was proven empty: the typed empty relation,
            // as when no file survives the sidecar stages.
            let tenant = tenant_base(SnapshotCache {
                source_spec: String::new(),
                objects: BTreeMap::new(),
                bytes: 0,
                read_schema: Some(schema_read),
                bootstrap: true,
            });
            return Ok(Selection {
                parts: Vec::new(),
                manifest: SourceManifest::empty_with_bootstrap_paths(self.settings.tenant_id.clone(), available.iter().cloned()),
                tenant,
                candidates: None,
                field_types,
                evidence,
                object_times: BTreeMap::new(),
                _leases: leases,
            });
        }
        let source_spec = planner::local_path_spec(&mut paths).map_err(map_plan_error)?;
        let tenant = tenant_base(SnapshotCache {
            source_spec,
            objects: cache_objects,
            bytes: total_bytes,
            read_schema: Some(schema_read),
            bootstrap: false,
        });
        Ok(Selection {
            parts: selected_parts,
            manifest: SourceManifest::from_objects(self.settings.tenant_id.clone(), objects),
            tenant,
            candidates,
            field_types,
            evidence,
            object_times,
            _leases: leases,
        })
    }

    pub(super) async fn hot_live_parts(&self) -> Vec<PartRef> {
        self.view.lock().await.live().parts().cloned().collect()
    }

    /// Verify and cache new part files ahead of queries (on part arrival and
    /// at start), so no interactive query pays the first-sight fetch. Best
    /// effort: errors are logged.
    ///
    /// Required cell-local files retain their verification fence. Optional
    /// remote sidecars/data are warmed newest-first within a total byte budget.
    /// One prewarm runs at a time.
    pub async fn prewarm_parts(&self, recent_hours: u64) -> QueryResult<usize> {
        self.prewarm_parts_with(recent_hours, false).await
    }

    /// [`Self::prewarm_parts`] as background work (NAN-3720): the
    /// incremental pass after arrivals and merges, which no readiness waits
    /// on. Its optional native statements (source summaries) start only while
    /// the engine is idle.
    pub async fn prewarm_parts_in_background(&self, recent_hours: u64) -> QueryResult<usize> {
        // NAN-4164: token-index layouts the before-warm pass left (its
        // deadline) or that arrived since; idle engine only.
        self.warm_token_indexes_in_background().await;
        self.prewarm_selection_evidence().await?;
        self.prewarm_parts_with(recent_hours, true).await
    }

    pub fn selection_evidence_status(&self) -> Value {
        let (entries, bytes) = self.file_metadata.bloom_stats();
        let (metadata_entries, metadata_bytes) = self.file_metadata.summary_stats();
        json!({"entries": entries, "bytes": bytes,
            "metadata_entries": metadata_entries, "metadata_bytes": metadata_bytes,
            "max_bytes": prune::MAX_PARSED_BLOOM_BYTES,
            "mask_entries": self.evidence_cache.len(), "mask_bytes": self.evidence_cache.bytes(),
            "prewarm": self.evidence_prewarm.lock().unwrap_or_else(|e| e.into_inner()).clone()})
    }

    pub fn evidence_prewarm_yielded(&self) -> bool {
        self.evidence_prewarm.lock().unwrap_or_else(|e| e.into_inner())["state"] == "yielded"
    }

    /// Optional seven-day evidence work, independent of prewarm progress
    /// and file-residency ledgers. Searches always resolve their own misses.
    pub(crate) async fn prewarm_selection_evidence(&self) -> QueryResult<()> {
        // Observe readiness conservatively: the first pass after the hot gate
        // opens starts the quiet period, never an earlier engine-open time.
        if !self.fetcher.hot_window_gate().is_none_or(|gate| gate.warm())
            || !evidence_quiet_period_over(self.evidence_ready_at.get_or_init(Instant::now).elapsed())
        {
            *self.evidence_prewarm.lock().unwrap_or_else(|e| e.into_inner()) = json!({"state": "yielded", "reason": "startup quiet period"});
            return Ok(());
        }
        const WINDOW_US: i64 = 7 * 24 * 3_600_000_000;
        let now = chrono::Utc::now().timestamp_micros();
        let (mut parts, _, _, _) = self.snapshot(now.saturating_sub(WINDOW_US), now).await?;
        parts.sort_by_key(|part| std::cmp::Reverse((part.max_time_us, part.part_id.clone())));
        let records = self.fetcher.records(&parts).await.map_err(map_fetch_error)?;
        let live = records.iter().flat_map(|record| record.files.data.iter().map(|data| data.sha256.as_str())).collect();
        self.file_metadata.retain_blooms(&live);
        let ordered = records.iter().flat_map(|record| record.files.data.iter().map(|data| data.sha256.as_str())).collect::<Vec<_>>();
        self.file_metadata.order_blooms_oldest_first(&ordered);
        let mut remaining = prune::MAX_PARSED_BLOOM_BYTES;
        let total = records.iter().map(|record| record.files.data.len()).sum::<usize>();
        let mut completed = 0usize;
        let mut skipped = 0usize;
        let progress = |state: &str, completed: usize, skipped: usize| {
            *self.evidence_prewarm.lock().unwrap_or_else(|e| e.into_inner()) = json!({
                "state": state, "window_days": 7, "total_files": total,
                "completed_files": completed, "skipped_files": skipped,
                "updated_at": chrono::Utc::now().to_rfc3339()});
        };
        progress("running", completed, skipped);
        for record in &records {
            if let Some(partial) = record.files.partials.iter().find(|p| p.kind == crate::parts::provenance::PartialKind::EntityRanges) {
                if !self.entity_count_memo.coverage.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&partial.sha256)
                    || !self.fetcher.count_footer_cached(&partial.sha256) {
                    if !self.evidence_idle() {
                        progress("yielded", completed, skipped);
                        return Ok(());
                    }
                    let warm = self.fetcher.count_footer_warmer(partial.sha256.clone());
                    let admission = self.admission.clone();
                    let point = self.point_admission.clone();
                    let job = self.job_admission.clone();
                    let slots = self.admission_slots();
                    let (done, result) = tokio::sync::oneshot::channel();
                    std::thread::Builder::new().name("count-prewarm".into()).spawn(move || {
                        let hint = if lower_evidence_priority().is_ok() && evidence_lanes_idle(&admission, slots, &point, &job) {
                            warm()
                        } else { None };
                        let _ = done.send(hint);
                    }).map_err(|error| PartQueryError::Unavailable(format!("count evidence thread: {error}")))?;
                    if let Ok(Some(hint)) = result.await {
                        let mut memo = self.entity_count_memo.coverage.lock().unwrap_or_else(|e| e.into_inner());
                        if memo.len() >= 16_384 { memo.clear(); }
                        memo.insert(partial.sha256.clone(), hint);
                    }
                    tokio::task::yield_now().await;
                }
            }
            for data in &record.files.data {
                if let Some(bytes) = self.file_metadata.resident_bloom_bytes(&data.sha256) {
                    if bytes <= remaining { remaining -= bytes; completed += 1; }
                    else { skipped += 1; }
                    continue;
                }
                // Never queue behind a search or fetch remote data solely for
                // evidence. A later pass resumes after a query/hydrator leases it.
                if !self.evidence_idle() {
                    progress("yielded", completed, skipped);
                    return Ok(());
                }
                // Read immutable local files directly. In particular, never
                // enter ensure_files: its reader-cache download/verification
                // path could put a query behind background footer work.
                // Only use digest-verified reader objects, never an unproved
                // producer path. Missing/evicted files remain query-time work.
                let Some(path) = self.fetcher.cache().verified_background_path(&data.sha256) else {
                    skipped += 1;
                    continue;
                };
                let metadata = self.file_metadata.clone();
                let digest = data.sha256.clone();
                let admission = self.admission.clone();
                let point = self.point_admission.clone();
                let job = self.job_admission.clone();
                let slots = self.admission_slots();
                let (done, result) = tokio::sync::oneshot::channel();
                std::thread::Builder::new().name("evidence-prewarm".into()).spawn(move || {
                    // Dedicated thread: never lower a shared Tokio worker's
                    // priority. Match the existing background product role.
                    if let Err(error) = lower_evidence_priority() {
                        tracing::warn!(%error, "evidence prewarm priority unavailable; skipping file");
                        let _ = done.send((Some(false), remaining));
                        return;
                    }
                    // Check at the actual parse boundary, after scheduling.
                    let idle = evidence_lanes_idle(&admission, slots, &point, &job);
                    let warmed = idle.then(|| metadata.prewarm_with_budget(&path, &digest, &mut remaining));
                    let _ = done.send((warmed, remaining));
                }).map_err(|error| PartQueryError::Unavailable(format!("evidence thread: {error}")))?;
                let (warmed, left) = result.await.unwrap_or((Some(false), remaining));
                let Some(warmed) = warmed else {
                    progress("yielded", completed, skipped);
                    return Ok(());
                };
                remaining = left;
                if warmed { completed += 1; } else { skipped += 1; }
                progress("running", completed, skipped);
                tokio::task::yield_now().await;
            }
        }
        progress("complete", completed, skipped);
        Ok(())
    }

    pub(super) fn evidence_idle(&self) -> bool {
        evidence_lanes_idle(&self.admission, self.admission_slots(), &self.point_admission, &self.job_admission)
    }

    /// A background step's native-work slot (`None`: searches kept the
    /// engine busy for [`BACKGROUND_IDLE_WAIT`]).
    async fn background_slot(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        wait_idle_permit(&self.admission, self.admission_slots(), BACKGROUND_IDLE_POLL, BACKGROUND_IDLE_WAIT).await
    }

    async fn prewarm_parts_with(&self, recent_hours: u64, background: bool) -> QueryResult<usize> {
        if self.prewarming.swap(true, std::sync::atomic::Ordering::SeqCst) {
            return Err(PartQueryError::Unavailable("part prewarm is already running".to_string()));
        }
        struct Reset<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for Reset<'_> {
            fn drop(&mut self) { self.0.store(false, std::sync::atomic::Ordering::SeqCst); }
        }
        let _reset = Reset(&self.prewarming);
        let result = async {
            let (parts, _, _, _) = match self.snapshot(i64::MIN, i64::MAX).await {
                // NAN-4316: a tenant born moments ago (no ingest genesis
                // yet) has nothing to warm; its parts are fetched as they come.
                Err(PartQueryError::NoSchemaYet) => {
                    tracing::debug!("part log has no schema yet (new tenant); nothing to prewarm");
                    return Ok(0);
                }
                other => other?,
            };
            let newest = parts.iter().map(|part| part.max_time_us).max().unwrap_or(0);
            let from_us = newest.saturating_sub(i64::try_from(recent_hours).unwrap_or(i64::MAX).saturating_mul(3_600_000_000));
            let mut newest_first = parts.clone();
            newest_first.sort_by_key(|part| std::cmp::Reverse((part.max_time_us, part.part_id.clone())));
            let (recent_parts, older_parts): (Vec<_>, Vec<_>) = newest_first.iter().cloned()
                .partition(|part| part.max_time_us >= from_us);
            // Optional cache residency is bounded across the entire pass,
            // newest first. Verification remains mandatory when a query leases
            // any skipped object; readiness does not promise whole-set residency.
            let records = self.fetcher.records(&parts).await.map_err(map_fetch_error)?;
            // In hot-window mode the hydrator owns background residency.
            // Keep mandatory local verification, but leave remote data and all
            // sidecars to queries so prewarm cannot bypass the event window.
            let mut remaining = if self.fetcher.hot_settings.is_some() {
                0
            } else {
                self.fetcher.cache().prewarm_max_bytes()
            };
            // NAN-3403: a pass touches only what no earlier pass finished
            // (kill switch: NANO_LAKE_PREWARM_THROTTLE=0 re-walks everything).
            let throttle = super::prewarm_pacing::throttle_enabled();
            if throttle {
                let live = records.iter().flat_map(|record| record.files.all().into_iter().map(|(_, digest, _)| digest))
                    .collect::<std::collections::HashSet<_>>();
                self.prewarmed.retain_live(&live);
            }
            let needs = |sha256: &str| !throttle || self.prewarmed.needs(sha256);
            let mut skipped = 0_usize;
            let mut by_id = records.iter().zip(&parts).map(|(record, part)| (&part.part_id, record)).collect::<std::collections::BTreeMap<_, _>>();
            for part in recent_parts.iter().chain(&older_parts) {
                let record = by_id.remove(&part.part_id).expect("snapshot record");
                let sidecars = (0..record.files.data.len()).map(PartFile::Tokens)
                    .chain(record.files.partials.iter().map(|partial| PartFile::Partial(partial.kind)));
                for file in sidecars {
                    let Some((_, digest, bytes)) = super::fetch::file_digest(record, file) else { continue };
                    if !needs(digest) { skipped += 1; continue }
                    if !take_prewarm_budget(&mut remaining, bytes) { continue }
                    match self.fetcher.ensure_files(&[(part.clone(), file)]).await {
                        Ok(_) => {
                            if throttle { self.prewarmed.record([digest]); }
                            if matches!(file, PartFile::Partial(crate::parts::provenance::PartialKind::Rollup))
                                && part.max_time_us >= from_us {
                                // Optional: only on an idle engine in the background.
                                let slot = if background {
                                    idle_permit(&self.admission, self.admission_slots())
                                } else {
                                    self.admission.clone().try_acquire_owned().ok()
                                };
                                if let Some(_slot) = slot {
                                    if let Err(error) = super::partials::prewarm_source_summaries(self, std::slice::from_ref(part)).await {
                                        tracing::warn!(%error, "source summaries not prewarmed; query will read rollups");
                                    }
                                }
                            }
                        },
                        Err(error) if error.downcast_ref::<crate::reader_object_cache::ReaderCacheError>()
                            .is_some_and(|error| error.retryable()) => {
                            tracing::warn!(%error, "optional sidecar prewarm unavailable; queries fetch it");
                        }
                        Err(error) => return Err(map_fetch_error(error)),
                    }
                }
            }
            let remote_from_us = newest.saturating_sub(PREWARM_REMOTE_DATA_US);
            // Newest part first: what interactive searches touch first.
            let mut candidates = Vec::new();
            let mut ordered = records.iter().zip(&parts).collect::<Vec<_>>();
            ordered.sort_by_key(|(_, part)| std::cmp::Reverse((part.max_time_us, part.part_id.clone())));
            let remote_budget = PREWARM_BATCH_BYTES.min(remaining);
            let mut remote_bytes = 0_u64;
            for (record, part) in ordered {
                if let Some(settings) = &self.fetcher.hot_settings {
                    let now = chrono::Utc::now().timestamp_micros();
                    let cutoff = now.saturating_sub(i64::try_from(settings.hours)
                        .unwrap_or(i64::MAX).saturating_mul(3_600_000_000));
                    if !part.overlaps(cutoff, now) { continue; }
                }
                for index in 0..record.files.data.len() {
                    if !needs(&record.files.data[index].sha256) { skipped += 1; continue }
                    let local = self.fetcher.local_file_path(part, record, PartFile::Data(index)).is_some();
                    let bytes = record.files.data[index].bytes;
                    let remote = part.max_time_us >= remote_from_us && remote_bytes.saturating_add(bytes) <= remote_budget;
                    if local || remote {
                        if !local { remote_bytes += bytes; }
                        candidates.push(((part.clone(), PartFile::Data(index)), record.files.data[index].bytes, local));
                    }
                }
            }
            let wanted = candidates.len();
            for (batch, local) in &prewarm_batches(candidates) {
                match self.fetcher.ensure_files(batch).await {
                    Ok(leased) => if throttle { self.prewarmed.record(leased.files.iter().map(|file| file.sha256.as_str())) },
                    Err(error) if !local => tracing::warn!(error = %format!("{error:#}"), "recent remote part data prewarm failed; queries fetch it"),
                    Err(error) => return Err(map_fetch_error(error)),
                }
            }
            tracing::info!(recent_parts = recent_parts.len(), all_parts = parts.len(), skipped_files = skipped, "part sidecars prewarmed");
            Ok::<usize, PartQueryError>(wanted)
        }
        .await;
        match &result {
            Ok(files) => tracing::info!(files, recent_hours, "part files prewarmed"),
            Err(error) => tracing::warn!(error = %error, "part prewarm failed"),
        }
        result
    }

    /// Value-membership over the parts of `[from_us, to_us]` for `query`'s
    /// equality predicates (`None` when none apply).
    pub async fn membership(&self, query: &str, field_types: &BTreeMap<String, String>, from_us: i64, to_us: i64) -> QueryResult<Option<Membership>> {
        self.membership_with(query, field_types, from_us, to_us, false).await
    }

    /// [`Self::membership`]; with `memo_only`, parts whose answer is not
    /// memoized are kept (unknown) instead of computed (NAN-3077). A
    /// newest-first page reads only the newest chunks, and at 300 eps some
    /// fresh L0 always lacks an answer, so computing cost one chDB rollup read
    /// (~0.6 s) on every page for pruning the walk rarely needs. The
    /// aggregate companions of the same base still compute and memoize.
    pub async fn membership_with(
        &self,
        query: &str,
        field_types: &BTreeMap<String, String>,
        from_us: i64,
        to_us: i64,
        memo_only: bool,
    ) -> QueryResult<Option<Membership>> {
        use crate::parts::provenance::PartialKind;
        let constraints = membership::constraints(query, field_types);
        if constraints.is_empty() || !crate::perf_overrides::probe_flag("prune_membership", true) {
            return Ok(None);
        }
        let (parts, _, _, _) = self.snapshot(from_us, to_us).await?;
        let mut result = Membership { evaluated: parts.iter().map(|part| part.part_id.clone()).collect(), ..Membership::default() };
        if parts.is_empty() {
            return Ok(Some(result));
        }
        // Answers are per whole part (window-independent) so they can be
        // memoized; the window is applied when they are read back.
        let key: Arc<str> = membership::statement(&constraints, 0, i64::MAX).into();
        let parent_keys = if memo_only { membership::parent_keys(&constraints) } else { Vec::new() };
        let first_bucket = from_us.div_euclid(crate::rollup::COUNT_ROLLUP_BUCKET_US) * crate::rollup::COUNT_ROLLUP_BUCKET_US;
        let add = |result: &mut Membership, part: &crate::parts::format::PartId, buckets: &BTreeSet<i64>| {
            let within = buckets.range(first_bucket..=to_us).copied().collect::<BTreeSet<_>>();
            if !within.is_empty() {
                result.buckets.insert(part.clone(), within);
            }
        };
        #[cfg(feature = "part-lab")]
        let resident_only = std::env::var("BENCH_BASELINE_PARENT_OVERHEAD").as_deref() != Ok("1");
        #[cfg(not(feature = "part-lab"))]
        let resident_only = true;
        if memo_only && resident_only {
            // Optional pruning must not fetch/verify provenance for the whole
            // window before a bounded page. A resident answer was computed
            // from verified immutable rollups; a miss remains unknown. The
            // eventual selected data files still pass every integrity fence.
            let memo = self.membership_memo.lock().expect("membership memo");
            for part in &parts {
                if let Some(buckets) = memo.get(&key, &part.part_id) {
                    add(&mut result, &part.part_id, &buckets);
                } else if let Some(buckets) = memo.candidate_buckets(&parent_keys, &part.part_id) {
                    add(&mut result, &part.part_id, &buckets);
                } else {
                    result.unknown.insert(part.part_id.clone());
                }
            }
            return Ok(Some(result));
        }
        let records = self.fetcher.records(&parts).await.map_err(map_fetch_error)?;
        let mut pending = Vec::new();
        {
            let memo = self.membership_memo.lock().expect("membership memo");
            for (part, record) in parts.iter().zip(&records) {
                if !record.files.partials.iter().any(|partial| partial.kind == PartialKind::Rollup) {
                    result.unknown.insert(part.part_id.clone());
                } else if let Some(buckets) = memo.get(&key, &part.part_id) {
                    add(&mut result, &part.part_id, &buckets);
                } else if let Some(buckets) = memo.candidate_buckets(&parent_keys, &part.part_id) {
                    // A cached parent is a safe superset of this child. Do not
                    // memoize it under the child's exact statement key.
                    add(&mut result, &part.part_id, &buckets);
                } else {
                    pending.push(part.clone());
                }
            }
        }
        if pending.is_empty() {
            return Ok(Some(result));
        }
        if memo_only {
            result.unknown.extend(pending.iter().map(|part| part.part_id.clone()));
            return Ok(Some(result));
        }
        let local = self
            .fetcher
            .ensure(&pending, &[FileSet::Partial(PartialKind::Rollup)])
            .await
            .map_err(map_fetch_error)?;
        let mut by_path = BTreeMap::new();
        for file in local.of(FileSet::Partial(PartialKind::Rollup)) {
            by_path.insert(file.path.to_string_lossy().to_string(), file.part_id.clone());
        }
        for part in &pending {
            if !by_path.values().any(|id| id == &part.part_id) {
                result.unknown.insert(part.part_id.clone());
            }
        }
        if by_path.is_empty() {
            return Ok(Some(result));
        }
        let mut paths = by_path.keys().cloned().collect::<Vec<_>>();
        let spec = planner::local_path_spec(&mut paths).map_err(map_plan_error)?;
        let sql = format!(
            "{} SETTINGS max_threads={}, max_execution_time={}, max_memory_usage={}, use_query_cache=0",
            key,
            self.settings.threads,
            crate::query_timing::execution_seconds(self.settings.max_execution_seconds),
            self.settings.max_memory_bytes
        );
        let mut answers: BTreeMap<crate::parts::format::PartId, BTreeSet<i64>> =
            by_path.values().map(|id| (id.clone(), BTreeSet::new())).collect();
        for row in self.execute_sql(sql, vec![("membership_rollups".to_string(), spec)]).await? {
            let path = row["path"].as_str().unwrap_or_default();
            let bucket = row["bucket"].as_i64().or_else(|| row["bucket"].as_str().and_then(|s| s.parse().ok()));
            if let (Some(id), Some(bucket)) = (by_path.get(path), bucket) {
                answers.entry(id.clone()).or_default().insert(bucket);
            }
        }
        drop(local);
        let mut memo = self.membership_memo.lock().expect("membership memo");
        for (part, buckets) in answers {
            add(&mut result, &part, &buckets);
            memo.insert(key.clone(), part, buckets);
        }
        Ok(Some(result))
    }

    /// Compile nPL through the pinned compiler (the reader's `run_compiler`).
    pub async fn compile(&self, request: &BroadNplRequest, field_types: BTreeMap<String, String>) -> QueryResult<CompiledQuery> {
        self.compile_with_stats_page(request, field_types, false).await
    }

    async fn compile_with_stats_page(&self, request: &BroadNplRequest, field_types: BTreeMap<String, String>, stats_page: bool) -> QueryResult<CompiledQuery> {
        let limit = request.offset.saturating_add(request.limit).saturating_add(1).min(MAX_RESULT_SENTINEL);
        let scoped_query = if request.dataset == "logs" {
            nanosiem_core::search::query_processing::enforce_source_scope_with_field(
                &request.query,
                &request.deny_source_types,
                "metadata.log_source",
            )
            .map_err(|error| PartQueryError::Invalid(error.to_string()))?
        } else {
            request.query.clone()
        };
        let (lowercased_fields, host_conjuncts) = if request.dataset == "logs" {
            (
                self.attested_lowercase_paths(request, &field_types).await,
                super::host_hint::dotless_host_conjuncts(&request.query, &field_types),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let mut compiled = run_compiler(
            &self.settings.compiler,
            &CompilerRequest {
                stats_page,
                stats_page_offset: request.offset,
                query: &scoped_query,
                dataset: &request.dataset,
                start: &request.start,
                end: &request.end,
                limit,
                table_view: request.table_view,
                event_contract: "ocsf-1.9",
                snapshot_field_types: if request.dataset == "logs" { field_types } else { BTreeMap::new() },
                lowercased_fields,
            },
            self.settings.max_execution_seconds,
        )
        .await?;
        if compiled.dataset != request.dataset || compiled.limit != limit || compiled.table_view != request.table_view {
            return Err(internal("compiler substituted a request binding"));
        }
        // NAN-3154: dotless hostnames get the hint the compiler cannot prove.
        if !host_conjuncts.is_empty() {
            let (from_us, to_us) = compiled_window_us(&compiled)?;
            // A bounded newest-first page reads the memo only (no partial
            // fetches before its first rows, the membership rule).
            let fetch = !compiled.newest_first_event_rows;
            compiled.candidate_hints.extend(super::host_hint::resolve(self, &host_conjuncts, from_us, to_us, fetch).await);
        }
        Ok(compiled)
    }

    /// NAN-3154: the provenance-attested lowercase paths (contract 3.4,
    /// `ProvenanceRecord::lowercased_at_rest`) common to EVERY part of the
    /// request window, restricted to the ones the query names and that are
    /// string leaves of the snapshot. Readers may compare raw only on a path
    /// every verified record attests; a legacy or adopted part (empty set)
    /// empties the intersection. Any failure answers "none" — `lower()` is
    /// always correct, just slower. The window's part set is the one the
    /// caller's discovery pin serves, so selection reads the same parts.
    async fn attested_lowercase_paths(&self, request: &BroadNplRequest, field_types: &BTreeMap<String, String>) -> Vec<String> {
        let named = attestable_paths_named(&request.query, field_types);
        if named.is_empty() {
            return Vec::new();
        }
        let (Ok(from_us), Ok(to_us)) = (rfc3339_us(&request.start), rfc3339_us(&request.end)) else { return Vec::new() };
        let Ok((parts, ..)) = self.snapshot(from_us, to_us).await else { return Vec::new() };
        if parts.is_empty() {
            return Vec::new();
        }
        let Ok(records) = self.fetcher.records(&parts).await else { return Vec::new() };
        common_lowercase_paths(named, records.iter().map(|record| record.lowercased_at_rest.as_slice()))
    }

    /// The reader's `broad_npl` route over parts (dataset `logs`).
    ///
    /// A merge can supersede a part between this process's log read and the
    /// part's fetch; its files are deleted after a grace period. The cache
    /// keeps verified copies, so only that window matters: on a vanished part
    /// the log is re-read and the query retried once (P0 design change 4).
    pub async fn broad_npl(&self, request: &BroadNplRequest) -> QueryResult<Value> {
        validate_broad_npl(request, &self.settings.tenant_id)?;
        let already_pinned = DISCOVERY.try_with(|pin| pin.engine == self as *const Self as usize).unwrap_or(false);
        let answer = if already_pinned { self.broad_npl_once(request).await }
            else { self.pinned(self.broad_npl_once(request)).await? };
        match answer {
            Err(PartQueryError::Unavailable(reason)) if reason.contains(VANISHED) => {
                tracing::info!(reason = %reason, "a part vanished under the query; retrying on the refreshed log");
                self.refresh().await?;
                self.pinned(self.broad_npl_once(request)).await?
            }
            other => other,
        }
    }

    async fn broad_npl_once(&self, request: &BroadNplRequest) -> QueryResult<Value> {
        let started = Instant::now();
        validate_broad_npl(request, &self.settings.tenant_id)?;
        if request.dataset != "logs" {
            return Err(PartQueryError::Invalid("the part engine serves dataset logs; risk goes to /v1/risk".to_string()));
        }
        let work = async {
            let started = Instant::now();
            let field_types = self.field_types().await?;
            let compiled = self.compile_with_stats_page(request, field_types.clone(), true).await?;
            let compile_s = started.elapsed().as_secs_f64();
            let cursor = request.cursor_time.as_deref().zip(request.cursor_event_uid.as_deref());
            let (from_us, to_us) = compiled_window_us(&compiled)?;
            if let Some(run) = super::entity_count::run(self, request, &compiled).await? {
                return Ok::<_, PartQueryError>((compiled, run));
            }
            if let Some(run) = super::cloud_facets::run(self, request, &compiled, from_us, to_us).await? {
                return Ok::<_, PartQueryError>((compiled, run));
            }
            // NAN-3133: a request whose shape names its columns may read
            // sparse column-range files. Any native failure of a request that
            // read one reruns it once on whole files (the existing path).
            let scope = super::range_fetch::scope_for(&compiled, &field_types);
            let attempt = super::range_fetch::with_scope(scope.clone(),
                Box::pin(self.run_compiled(request, &compiled, &field_types, cursor, compile_s))).await;
            let run = match (attempt, &scope) {
                (Err(error), Some(scope)) if scope.sparse_used() && reruns_whole(&error) => {
                    super::range_fetch::record_fallback(super::range_fetch::Fallback::NativeError, 1);
                    tracing::warn!(error = %error, "search read a hole of a sparse column-range file; rerunning on whole files");
                    // The rerun draws on what the ranged attempt left of its
                    // cold budget; if it fails, the caller sees the original.
                    let rerun = Arc::new(scope.rerun());
                    match super::range_fetch::with_scope(Some(rerun),
                        Box::pin(self.run_compiled(request, &compiled, &field_types, cursor, compile_s))).await {
                        Ok(mut run) => {
                            run.planner["range_fetch_rerun"] = json!(super::range_fetch::Fallback::NativeError.as_str());
                            run
                        }
                        Err(rerun_error) => {
                            tracing::warn!(error = %rerun_error, "whole-file rerun failed; returning the ranged attempt's error");
                            return Err(error);
                        }
                    }
                }
                (other, _) => other?,
            };
            Ok((compiled, run))
        };
        let (compiled, mut run) = work.await?;
        let continuation = run.continuation.take();
        let mut decoded = run.rows;
        let group_total = stats_page_total(compiled.stats_page, request.offset, &mut decoded)?;
        let page_offset = if compiled.stats_page { 0 } else { request.offset };
        let mut rows = page_decoded(decoded, &run.temporary_aliases, page_offset, request.limit);
        // NAN-3270: a byte-cut page has more whatever its row count.
        rows.1 |= continuation.is_some();
        let wall_seconds = started.elapsed().as_secs_f64();
        let (plan_budget, plan_defaults, mut evidence) = (run.budget, run.schema_defaults, run.planner);
        if let Some(phases) = crate::query_timing::current() {
            let p = phases.lock().unwrap_or_else(|e| e.into_inner());
            evidence["entity_count_fallback_reasons"] = json!(p.entity_count_fallback_reasons);
            evidence["worker_phases_ms"] = json!({
                "native_init_ms": p.native_init_ms, "native_fetch_ms": p.native_fetch_ms,
                "native_session_reused": p.native_session_reused,
                "native_bind_ms": p.native_bind_ms, "native_init_abi_ms": p.native_init_abi_ms,
                "native_first_fetch_ms": p.native_first_fetch_ms,
                "native_statements": p.native_statements, "native_fetch_calls": p.native_fetch_calls,
                "native_total_ms": p.chdb_ms, "sql_prepare_ms": p.sql_prepare_ms,
                "lane_wait_ms": p.lane_wait_ms, "file_prepare_ms": p.file_prepare_ms,
                "file_verify_ms": p.file_verify_ms,
                "footer_read_ms": p.footer_read_ms, "decode_ms": p.decode_ms,
                "log_refresh_ms": p.log_refresh_ms,
                "select_cpu_ms": p.select_cpu_ms,
                "select_sidecar_ms": p.select_sidecar_ms, "select_token_ms": p.select_token_ms,
                "select_token_lease_ms": p.select_token_lease_ms, "select_token_evidence_ms": p.select_token_evidence_ms,
                "density_token_ms": p.density_token_ms,
                "token_probes": p.token_probes, "token_probe_excluded": p.token_probe_excluded, "token_probe_ms": p.token_probe_ms,
                "token_decodes": p.token_decodes, "token_decode_bytes": p.token_decode_bytes,
                "token_read_ms": p.token_read_ms, "token_decode_ms": p.token_decode_ms,
                "select_bloom_ms": p.select_bloom_ms,
                "entity_count_index_ms": p.entity_count_index_ms, "entity_count_native_ms": p.entity_count_native_ms,
                "entity_count_index_parts": p.entity_count_index_parts, "entity_count_native_parts": p.entity_count_native_parts,
                "entity_count_index_hours": p.entity_count_index_hours, "entity_count_native_hours": p.entity_count_native_hours,
                "evidence_cache_hits": p.evidence_cache_hits, "evidence_cache_misses": p.evidence_cache_misses,
            });
        }
        let output_elapsed = run.engine_seconds;
        let (storage_rows, storage_bytes) = (run.storage_rows, run.storage_bytes);
        Ok(json!({
            "ok": true,
            "schema_version": 1,
            "request_id": request.request_id,
            "tenant_id": request.tenant_id,
            "route": "broad_npl",
            "source_mode": "parts",
            "log_head": self.head_json().await,
            "wall_seconds": wall_seconds,
            "query_sha256": compiled.query_sha256,
            "schema_defaults": plan_defaults,
            "budget": plan_budget,
            "planner": evidence,
            "result": {
                "result_rows": rows.0.len(),
                "rows": rows.0,
                "page_offset": request.offset,
                "page_limit": request.limit,
                "page_has_more": rows.1,
                // NAN-3270: the page stopped at its byte budget; continue it
                // from this cursor (offset 0) for the rows still wanted.
                "page_byte_cut": continuation.is_some(),
                "continuation": continuation.as_ref().map(|next| json!({
                    "cursor_time": next.cursor_time, "cursor_event_uid": next.cursor_event_uid})),
                "group_total": group_total,
                // Rows are raw events newest first, so a caller may continue
                // with the (time, metadata.uid) cursor of the last row.
                "newest_first_event_rows": compiled.newest_first_event_rows,
                "engine_seconds": output_elapsed,
                "storage_rows": storage_rows,
                "storage_bytes": storage_bytes,
                "wall_seconds": wall_seconds,
                "query_result_cache_hit": false,
            }
        }))
    }

    /// Everything of [`Self::broad_npl_once`] after compilation: membership,
    /// then progressive, fragment-aggregate or one-shot execution.
    async fn run_compiled(
        &self, request: &BroadNplRequest, compiled: &CompiledQuery, field_types: &BTreeMap<String, String>,
        cursor: Option<(&str, &str)>, compile_s: f64,
    ) -> QueryResult<Run> {
        let mut phases = vec![("compile", compile_s)];
        let mut clock = Instant::now();
        let mut lap = |name: &'static str, phases: &mut Vec<(&str, f64)>| {
            phases.push((name, clock.elapsed().as_secs_f64()));
            clock = Instant::now();
        };
        let (from_us, to_us) = compiled_window_us(compiled)?;
        let progressive = progressive::eligible(&request.dataset, compiled.newest_first_event_rows, request.offset, request.limit);
        let (keyword_hints, entity_hints) = hint_counts(&compiled.candidate_hints);
        crate::query_timing::record(|p| {
            p.funnel.keyword_hints = keyword_hints;
            p.funnel.entity_hints = entity_hints;
            p.funnel.uses_entities = prune::uses_entities(&compiled.candidate_hints);
            p.funnel.token_seed_applies = super::token_seed::applies(&compiled.candidate_hints);
            p.funnel.progressive = progressive;
        });
        // Indexable predicates do not replace membership evidence for the
        // other conjuncts. Consult the memo even for indexed searches;
        // unknown parts stay eligible and no rollup scan runs on this path.
        let membership = self.membership_with(&request.query, field_types, from_us, to_us, progressive).await?;
        lap("membership", &mut phases);
        if progressive {
            let context = (super::fragment_cache::enabled() && super::result_cache::cacheable(request))
                .then(|| planner::page_locator(compiled)).flatten()
                .map(|locator| super::fragment_cache::Context::new(&locator, cursor));
            let mut run = super::fragment_cache::CONTEXT.scope(context,
                self.progressive(compiled, cursor, membership.as_ref(), if compiled.stats_page { 0 } else { request.offset })).await?;
            run.planner["result_cache"] = serde_json::to_value(self.fragments.counters()).map_err(internal)?;
            super::debug::result_cache(serde_json::to_value(self.fragments.counters()).map_err(internal)?);
            run.planner["compile_s"] = json!(phases[0].1);
            run.planner["membership_s"] = json!(phases[1].1);
            return Ok(run);
        }
        if cursor.is_none() && super::fragment_cache::enabled() && super::result_cache::cacheable(request) {
            if let Some(run) = Box::pin(self.fragment_aggregate(compiled, from_us, to_us, membership.as_ref())).await? {
                crate::query_timing::record(|p| p.funnel.fragment_aggregate = true);
                return Ok(run);
            }
        }
        // A single-keyword histogram is answered from v3 token counts
        // where they cover whole row groups; the rest is scanned.
        let count_plan = if cursor.is_none() && keyword_count::enabled() { keyword_count::plan(compiled, compiled_bound_us(compiled)?) } else { None };
        let mut tally = keyword_count::Tally::default();
        crate::query_timing::record(|p| p.funnel.counting = count_plan.is_some());
        let selection = match self
            .select_counting(from_us, to_us, &compiled.candidate_hints, membership.as_ref(), count_plan.as_ref().map(|plan| (plan, &mut tally)))
            .await
        {
            Ok(selection) => selection,
            // NAN-3644: over the cold ceiling, read the window in batches
            // (the keyword tally is only an optimization of the same answer).
            Err(PartQueryError::ColdScanTooLarge { needed_bytes, .. }) if cursor.is_none() && super::cold_batches::not_batchable(compiled).is_none() => {
                return Box::pin(self.run_cold_batched(compiled, (from_us, to_us), membership.as_ref(), needed_bytes)).await;
            }
            Err(error @ PartQueryError::ColdScanTooLarge { .. }) => {
                tracing::info!(reason = super::cold_batches::not_batchable(compiled).unwrap_or("a cursor page"),
                    "cold read over the ceiling cannot run in batches");
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        lap("select", &mut phases);
        // NAN-3155: a filtered/sorted/limited row page reads its predicate and
        // order leaves first, then only the result rows' full width.
        let two_pass = count_plan.is_none().then(|| super::two_pass::plan(compiled)).flatten();
        crate::query_timing::record(|p| p.funnel.two_pass = two_pass.is_some());
        if let Some(two) = two_pass {
            if let Some(two_run) = Box::pin(self.run_two_pass(&selection, &two, None, cursor)).await? {
                lap("execute", &mut phases);
                return Ok(Run {
                    rows: two_run.rows,
                    engine_seconds: two_run.engine_seconds,
                    storage_rows: two_run.storage_rows,
                    storage_bytes: two_run.storage_bytes,
                    temporary_aliases: two_run.temporary_aliases,
                    schema_defaults: two_run.schema_defaults,
                    budget: serde_json::to_value(&two_run.budget).map_err(internal)?,
                    continuation: None,
                    planner: {
                        let mut planner = serde_json::to_value(&selection.evidence).map_err(internal)?;
                        planner["two_pass"] = json!({"statements": two_run.statements, "narrow_rows": two_run.narrow_rows});
                        planner["phases_s"] = json!(phases.iter().map(|(name, seconds)| json!({"phase": name, "s": seconds})).collect::<Vec<_>>());
                        planner
                    },
                });
            }
        }
        let mut plan = plan_logs(&selection, compiled, cursor)?;
        let (mut rows, mut engine_seconds, mut storage_rows, mut storage_bytes) = if count_plan.is_some() && selection.manifest.objects.is_empty() {
            // Everything was counted: nothing is left to scan.
            (Vec::new(), 0.0, 0, 0)
        } else {
            let output = self.execute(plan.clone()).await?;
            (decode_rows(&output.data)?, output.elapsed.as_secs_f64(), output.storage_rows_read, output.storage_bytes_read)
        };
        let mut selection = selection;
        if let Some(count_plan) = &count_plan {
            match keyword_count::merge(count_plan, rows, &tally).map_err(|error| internal(format!("{error:#}")))? {
                keyword_count::Merged::Rows(merged) => rows = merged,
                keyword_count::Merged::Rescan => {
                    // NAN-4311: the scan's page cut groups the merge needs
                    // (more sources than the page): the plain statement
                    // over the whole selection, without the counts.
                    tracing::info!("keyword count groups overflowed the page; rescanning without the counts");
                    crate::query_timing::record(|p| p.funnel.counting = false);
                    selection = match self.select_with(from_us, to_us, &compiled.candidate_hints, membership.as_ref()).await {
                        Ok(selection) => selection,
                        // As above: over the cold ceiling, read in batches.
                        Err(PartQueryError::ColdScanTooLarge { needed_bytes, .. }) if super::cold_batches::not_batchable(compiled).is_none() => {
                            return Box::pin(self.run_cold_batched(compiled, (from_us, to_us), membership.as_ref(), needed_bytes)).await;
                        }
                        Err(error) => return Err(error),
                    };
                    plan = plan_logs(&selection, compiled, cursor)?;
                    let output = self.execute(plan.clone()).await?;
                    rows = decode_rows(&output.data)?;
                    engine_seconds += output.elapsed.as_secs_f64();
                    storage_rows += output.storage_rows_read;
                    storage_bytes += output.storage_bytes_read;
                }
            }
        }
        lap("execute", &mut phases);
        Ok(Run {
            rows,
            engine_seconds,
            storage_rows,
            storage_bytes,
            temporary_aliases: plan.temporary_aliases.clone(),
            schema_defaults: plan.schema_defaults.clone(),
            budget: serde_json::to_value(&plan.budget).map_err(internal)?,
            continuation: None,
            planner: {
                let mut planner = serde_json::to_value(&selection.evidence).map_err(internal)?;
                planner["phases_s"] = json!(phases.iter().map(|(name, seconds)| json!({"phase": name, "s": seconds})).collect::<Vec<_>>());
                planner
            },
        })
    }

    /// The reader's `fetch_log` route over parts.
    pub async fn fetch_log(&self, request: &FetchLogRequest) -> QueryResult<Value> {
        if request.tenant_id != self.settings.tenant_id {
            return Err(PartQueryError::Invalid("request tenant is not this process's tenant".to_string()));
        }
        let (from_us, to_us) = match (&request.start, &request.end) {
            (Some(start), Some(end)) => (rfc3339_us(start)?, rfc3339_us(end)?),
            (None, None) => (i64::MIN, i64::MAX),
            _ => return Err(PartQueryError::Invalid("fetch_log needs both start and end".to_string())),
        };
        // The event id is a `metadata.uid` equality: every part carries a
        // uid bloom; the SQL equality rechecks every candidate.
        let mut hints = vec![CandidateHint::Entity { source_path: "metadata.uid".to_string(), value: request.id.clone() }];
        if let Some(source) = &request.log_source {
            hints.push(CandidateHint::SourceFamily { value: source.clone() });
        }
        let started = Instant::now();
        let work = async {
            let (parts, _, _, _) = self.snapshot(from_us, to_us).await?;
            let mut evidence = SelectionEvidence { time_parts: parts.len(), ..Default::default() };
            let mut storage_rows = 0;
            let mut storage_bytes = 0;
            let mut rows = Vec::new();
            for part in parts {
                let selection = self.select_part(from_us, to_us, &hints, None, None, Some(&part.part_id)).await?;
                evidence.log_seq = selection.evidence.log_seq;
                evidence.live_parts = selection.evidence.live_parts;
                evidence.time_files += selection.evidence.time_files;
                evidence.source_family_pruned_files += selection.evidence.source_family_pruned_files;
                evidence.uid_pruned_files += selection.evidence.uid_pruned_files;
                evidence.entity_sidecar_pruned_files += selection.evidence.entity_sidecar_pruned_files;
                evidence.fetched_files += selection.evidence.fetched_files;
                evidence.row_groups += selection.evidence.row_groups;
                evidence.kept_row_groups += selection.evidence.kept_row_groups;
                evidence.cache_hits += selection.evidence.cache_hits;
                evidence.cache_misses += selection.evidence.cache_misses;
                evidence.cache_fetched_bytes += selection.evidence.cache_fetched_bytes;
                if selection.manifest.objects.is_empty() {
                    continue;
                }
                let plan = planner::plan_fetch_log_with_tail(
                    &selection.tenant,
                    &selection.manifest,
                    None,
                    selection.candidates.as_deref(),
                    &FetchLogPlanRequest {
                        event_id: &request.id,
                        start: request.start.as_deref(),
                        end: request.end.as_deref(),
                        log_source: request.log_source.as_deref(),
                        deny_source_types: &request.deny_source_types,
                    },
                )
                .map_err(map_plan_error)?;
                let output = run_on(self.point_executor(), plan.clone()).await.map_err(map_executor_error)?;
                storage_rows += output.storage_rows_read;
                storage_bytes += output.storage_bytes_read;
                rows = page_rows(&output.data, &plan, 0, 1)?.0;
                if !rows.is_empty() {
                    break;
                }
            }
            Ok::<_, PartQueryError>((rows, evidence, storage_rows, storage_bytes))
        };
        let (rows, planner, storage_rows, storage_bytes) = work.await?;
        Ok(json!({
            "ok": true,
            "schema_version": 1,
            "request_id": request.request_id,
            "tenant_id": request.tenant_id,
            "route": "fetch_log",
            "source_mode": "parts",
            "wall_seconds": started.elapsed().as_secs_f64(),
            "planner": planner,
            "result": { "result_rows": rows.len(), "rows": rows, "storage_rows": storage_rows, "storage_bytes": storage_bytes }
        }))
    }

    /// The reader's `field_names` route: `unmapped.*` leaves of the schema.
    pub async fn field_names(&self, request_id: &str) -> QueryResult<Value> {
        let fields = self
            .field_types()
            .await?
            .into_keys()
            .filter(|field| field.starts_with("unmapped.") && field.len() <= 1_024)
            .map(|field| json!({ "field": field }))
            .collect::<Vec<_>>();
        Ok(json!({
            "ok": true,
            "schema_version": 1,
            "request_id": request_id,
            "tenant_id": self.settings.tenant_id,
            "route": "field_names",
            "source_mode": "parts",
            "result": { "result_rows": fields.len(), "rows": fields, "page_offset": 0, "page_limit": 10000, "page_has_more": false }
        }))
    }

    /// Execute a bound plan on the engine's read-only lanes.
    pub async fn execute(&self, plan: NativeQueryPlan) -> QueryResult<NativeQueryOutput> {
        self.run(plan).await.map_err(map_executor_error)
    }

    /// NAN-3644: one materialized write statement (an `INSERT INTO
    /// FUNCTION file` spool) on the read-write lane under the job memory
    /// cap. Writes have no streamed form, and read lanes are read-only.
    pub(super) async fn execute_spool(&self, plan: NativeQueryPlan) -> QueryResult<NativeQueryOutput> {
        let writer = self.writer.as_ref().ok_or_else(|| PartQueryError::Unavailable("no read-write lane for a spool".to_string()))?;
        writer.execute(with_memory_cap(plan, self.job_memory_bytes())).await.map_err(map_executor_error)
    }

    /// NAN-3644: one materialized statement on a read lane, outside the
    /// sized router (which streams). For metadata statements such as
    /// `DESCRIBE`, which read no data and have no streamed form.
    pub(super) async fn execute_materialized(&self, plan: NativeQueryPlan) -> QueryResult<NativeQueryOutput> {
        self.executor.execute(plan).await.map_err(map_executor_error)
    }

    /// Execute trusted SQL (typed partial routes) on the read-only lanes.
    pub async fn execute_sql(&self, sql: String, params: Vec<(String, String)>) -> QueryResult<Vec<Value>> {
        let output = self.run_sql(sql, params).await.map_err(map_executor_error)?;
        decode_rows(&output.data)
    }

    /// The reader's `explain_npl` route: compile only.
    pub async fn explain_npl(&self, request: &BroadNplRequest) -> QueryResult<Value> {
        validate_broad_npl(request, &self.settings.tenant_id)?;
        let field_types = self.field_types().await?;
        let compiled = self.compile(request, field_types).await?;
        Ok(json!({
            "ok": true,
            "request_id": request.request_id,
            "tenant_id": request.tenant_id,
            "route": "explain_npl",
            "source_mode": "parts",
            "log_head": self.head_json().await,
            "result": {
                "sql": format!("-- Canonical OCSF 1.9 lake compiler plan\n-- {} is bound by query[T] to the verified part set.\n{}", compiled.source_placeholder, compiled.sql),
                "source_placeholder": compiled.source_placeholder,
                "query_sha256": compiled.query_sha256,
                "required_columns": compiled.required_columns.iter().map(|column| json!({"name": column.name, "field_type": column.field_type})).collect::<Vec<_>>(),
                "candidate_hint_count": compiled.candidate_hints.len(),
                "newest_first_event_rows": compiled.newest_first_event_rows,
            }
        }))
    }

    /// `{seq, sha256}` of the verified log head (the response binding).
    pub async fn head_json(&self) -> Value {
        self.head().await.map_or(Value::Null, |(seq, sha256)| json!({"seq": seq, "sha256": sha256}))
    }
}

/// The rows and facts of one executed `broad_npl`.
pub struct Run {
    pub rows: Vec<Value>,
    pub engine_seconds: f64,
    pub storage_rows: u64,
    pub storage_bytes: u64,
    pub temporary_aliases: BTreeSet<String>,
    pub schema_defaults: Vec<String>,
    pub budget: Value,
    pub planner: Value,
    /// NAN-3270: a progressive page cut short by its byte budget continues
    /// after this row (`page_has_more` is then true whatever the row count).
    pub continuation: Option<Continuation>,
}

/// NAN-3270: the `(time, metadata.uid)` cursor a byte-cut page continues
/// from: the last row it returned, in the request's cursor form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Continuation {
    /// RFC3339, microseconds, UTC.
    pub cursor_time: String,
    pub cursor_event_uid: String,
}

impl Continuation {
    /// The cursor of `row`, when it names a usable one.
    pub fn after(row: &Value) -> Option<Self> {
        let time = row_field(row, "time").and_then(Value::as_str).and_then(progressive::row_time_us)?;
        let uid = row_field(row, "metadata.uid").and_then(Value::as_str)?;
        let usable = !uid.is_empty() && uid.len() <= 2_048 && !uid.chars().any(char::is_control);
        let time = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(time)?;
        usable.then(|| Self {
            cursor_time: time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            cursor_event_uid: uid.to_string(),
        })
    }
}

/// How a streamed page read ([`PartQueryEngine::broad_npl_pages`]) ended.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PagedOutcome {
    /// Rows handed to the caller.
    pub delivered: usize,
    /// Pages handed to the caller (the first rides in the envelope).
    pub pages: usize,
    /// More rows matched than the request's limit.
    pub has_more: bool,
    /// The caller stopped taking pages.
    pub stopped: bool,
    /// Result statements executed for the whole read: 1, or 0 when no part
    /// can hold a row. Never grows with the page count (NAN-3060).
    pub result_statements: u32,
    pub engine_seconds: f64,
    pub storage_rows: u64,
    pub storage_bytes: u64,
    /// The rows are raw events newest first (a streamed read needs that; the
    /// caller runs the ordinary request otherwise).
    pub newest_first_event_rows: bool,
}

/// One streamed read's line to the caller: the envelope (with the first
/// page's rows) once, then each further page.
pub enum PagedLine {
    Envelope(Value),
    Page(Vec<Value>),
}

/// NAN-3060: the streamed statement with its top-N found on `time` alone
/// first, in the same statement:
///
/// ```sql
/// WITH __nano_rows AS (<rows>)
/// SELECT * FROM __nano_rows
/// WHERE time >= (SELECT min(__nano_t) FROM
///     (SELECT time AS __nano_t FROM __nano_rows ORDER BY time DESC LIMIT n))
/// ORDER BY time DESC, <uid> DESC LIMIT n SETTINGS …
/// ```
///
/// Parts hold rows oldest first, so a plain full-width `ORDER BY time DESC
/// LIMIT n` can drop nothing early and its sort buffers every row of the
/// window (a 20k read of a 300-eps hour peaked at ~2 GiB RSS and was refused
/// by the query budget). The threshold scan reads only `time` and the
/// predicate columns; the full-width read then keeps rows at or after the
/// n-th newest instant (PREWHERE on `time`), so the sort holds about n rows:
/// ~0.55 GiB and 0.2 s instead of ~2.2 GiB and 1.8 s on that hour, with
/// byte-identical output (every top-n row is at or after the threshold, and
/// ties at it are kept for the final order). `None` (run as is) unless the
/// statement ends in the event order the stream relies on.
pub fn threshold_first(sql: &str) -> Option<String> {
    let at = sql.rfind(" SETTINGS ")?;
    let (body, settings) = (&sql[..at], sql[at..].trim_start());
    let order_at = body.rfind(" ORDER BY time DESC, ")?;
    let (rows, order) = (&body[..order_at], &body[order_at..]);
    let rest = order.strip_prefix(" ORDER BY time DESC, ")?;
    let (tiebreak, limit) = rest.split_once(" DESC LIMIT ")?;
    let limit = limit.trim();
    if !limit.bytes().all(|byte| byte.is_ascii_digit()) || limit.is_empty()
        || !tiebreak.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'"' | b'.' | b'`'))
        || settings.contains(')')
    {
        return None;
    }
    Some(format!(
        "WITH __nano_rows AS ({rows}) SELECT * FROM __nano_rows \
         WHERE time >= (SELECT min(__nano_t) FROM (SELECT time AS __nano_t FROM __nano_rows ORDER BY time DESC LIMIT {limit})) \
         ORDER BY time DESC, {tiebreak} DESC LIMIT {limit} {settings}"
    ))
}

/// Rows per streamed block chDB is asked for: a page's worth, so one block
/// never approaches the result budget however wide the rows are.
fn stream_block_rows(page_rows: usize) -> usize {
    page_rows.clamp(64, 8_192)
}

impl PartQueryEngine {
    /// NAN-3060: a raw-event read of `request.limit` rows delivered to
    /// `emit` in `page_rows` pages from ONE execution of the query.
    ///
    /// The paged cursor protocol (NAN-3046) re-planned and re-ran the whole
    /// statement for every 2000-row page (a 20k read = 10 full scans of the
    /// window). Here the statement (`… ORDER BY time DESC, uid DESC LIMIT
    /// limit+1`) runs once on one lane and its output is read block by block
    /// through chDB's streaming ABI; at most one page plus one block is held
    /// in this process, and chDB holds only its top-N sort state (inside the
    /// per-statement memory cap). A caller that stops (`emit` returns false)
    /// cancels the statement. `request` must be a first page (no cursor, no
    /// offset). A result that is not raw events newest first is announced by
    /// an envelope with `newest_first_event_rows: false` and no rows.
    pub async fn broad_npl_pages<F, Fut>(&self, request: &BroadNplRequest, page_rows: usize, mut emit: F) -> QueryResult<PagedOutcome>
    where
        F: FnMut(PagedLine) -> Fut + Send,
        Fut: std::future::Future<Output = bool> + Send,
    {
        let mut emitted = false;
        let first = self.pinned(self.broad_npl_pages_once(request, page_rows, &mut emit, &mut emitted)).await?;
        match first {
            // A merge superseded a part before anything reached the caller.
            Err(PartQueryError::Unavailable(reason)) if reason.contains(VANISHED) && !emitted => {
                tracing::info!(reason = %reason, "a part vanished under a streamed read; retrying on the refreshed log");
                self.refresh().await?;
                self.pinned(self.broad_npl_pages_once(request, page_rows, &mut emit, &mut emitted)).await?
            }
            other => other,
        }
    }

    async fn broad_npl_pages_once<F, Fut>(&self, request: &BroadNplRequest, page_rows: usize, emit: &mut F, emitted: &mut bool) -> QueryResult<PagedOutcome>
    where
        F: FnMut(PagedLine) -> Fut + Send,
        Fut: std::future::Future<Output = bool> + Send,
    {
        let started = Instant::now();
        validate_broad_npl(request, &self.settings.tenant_id)?;
        if request.dataset != "logs" || request.offset != 0 || request.cursor_time.is_some() || page_rows == 0 {
            return Err(PartQueryError::Invalid("a streamed read is a first page of dataset logs with a positive page size".to_string()));
        }
        let work = async {
            let field_types = self.field_types().await?;
            let compiled = self.compile(request, field_types.clone()).await?;
            let envelope = |rows: Vec<Value>, newest_first: bool, planner: Value, budget: Value, defaults: Value, head: Value| json!({
                "ok": true,
                "schema_version": 1,
                "request_id": request.request_id,
                "tenant_id": request.tenant_id,
                "route": "broad_npl",
                "source_mode": "parts",
                "log_head": head,
                "wall_seconds": started.elapsed().as_secs_f64(),
                "query_sha256": compiled.query_sha256,
                "schema_defaults": defaults,
                "budget": budget,
                "planner": planner,
                "stream": {"page_rows": page_rows},
                "result": {
                    "result_rows": rows.len(),
                    "rows": rows,
                    "page_offset": 0,
                    "page_limit": request.limit,
                    "page_has_more": false,
                    "newest_first_event_rows": newest_first,
                    "query_result_cache_hit": false,
                }
            });
            let mut outcome = PagedOutcome { newest_first_event_rows: compiled.newest_first_event_rows, ..Default::default() };
            if !compiled.newest_first_event_rows {
                *emitted = true;
                emit(PagedLine::Envelope(envelope(Vec::new(), false, Value::Null, Value::Null, Value::Null, self.head_json().await))).await;
                return Ok(outcome);
            }
            let (from_us, to_us) = compiled_window_us(&compiled)?;
            let membership = self.membership(&request.query, &field_types, from_us, to_us).await?;
            let selection = self.select_with(from_us, to_us, &compiled.candidate_hints, membership.as_ref()).await?;
            let mut plan = plan_logs(&selection, &compiled, None)?;
            if let Some(sql) = threshold_first(&plan.sql) {
                plan.sql = sql;
            }
            plan.sql = crate::executor::with_setting(&plan.sql, &format!("max_block_size={}", stream_block_rows(page_rows)));
            let aliases = plan.temporary_aliases.clone();
            let budget = serde_json::to_value(&plan.budget).map_err(internal)?;
            let defaults = serde_json::to_value(&plan.schema_defaults).map_err(internal)?;
            let mut planner = serde_json::to_value(&selection.evidence).map_err(internal)?;
            planner["kind"] = json!("streamed_pages");
            let total = request.limit;
            let mut pending: VecDeque<Value> = VecDeque::new();
            let mut matched = 0_usize;
            if !selection.manifest.objects.is_empty() {
                // NAN-3150: a PREWHERE defect fails the statement before its
                // first block; rerun it once without move-to-prewhere then.
                let mut retry = Some(without_prewhere(plan.clone()));
                let mut stream = match self.executor.execute_streaming(plan.clone()).await {
                    Err(error) if prewhere_defect(&error.to_string(), &plan.sql) => {
                        tracing::warn!(error = %error, "native PREWHERE lost a shared filter expression; rerunning without move-to-prewhere");
                        self.executor.execute_streaming(retry.take().expect("one retry")).await.map_err(map_executor_error)?
                    }
                    other => other.map_err(map_executor_error)?,
                };
                outcome.result_statements = 1;
                let mut carry: Vec<u8> = Vec::new();
                loop {
                    let block = match stream.next().await {
                        Some(Err(error)) if prewhere_defect(&error.to_string(), &plan.sql) && retry.is_some() => {
                            tracing::warn!(error = %error, "native PREWHERE lost a shared filter expression; rerunning without move-to-prewhere");
                            stream = self.executor.execute_streaming(retry.take().expect("one retry")).await.map_err(map_executor_error)?;
                            continue;
                        }
                        Some(block) => block.map_err(map_executor_error)?,
                        None => break,
                    };
                    // Rows reached the caller's pages: never restart past here.
                    retry = None;
                    outcome.engine_seconds += block.elapsed.as_secs_f64();
                    outcome.storage_rows = outcome.storage_rows.saturating_add(block.storage_rows_read);
                    outcome.storage_bytes = outcome.storage_bytes.saturating_add(block.storage_bytes_read);
                    // JSONEachRow blocks end on a row boundary; a split row
                    // is carried to the next block all the same.
                    carry.extend_from_slice(&block.data);
                    let whole = carry.iter().rposition(|byte| *byte == b'\n').map_or(0, |at| at + 1);
                    let tail = carry.split_off(whole);
                    for mut row in decode_rows(&carry)? {
                        if let Some(object) = row.as_object_mut() {
                            for alias in &aliases {
                                object.remove(alias);
                            }
                        }
                        matched += 1;
                        if matched <= total {
                            pending.push_back(row);
                        }
                    }
                    carry = tail;
                    while pending.len() >= page_rows {
                        let page: Vec<Value> = pending.drain(..page_rows).collect();
                        if !deliver(self, emit, emitted, &mut outcome, page, &envelope, &planner, &budget, &defaults).await? {
                            // Dropping the stream cancels the statement.
                            return Ok(outcome);
                        }
                    }
                }
                if !carry.iter().all(u8::is_ascii_whitespace) {
                    for row in decode_rows(&carry)? {
                        matched += 1;
                        if matched <= total {
                            let mut row = row;
                            if let Some(object) = row.as_object_mut() {
                                for alias in &aliases {
                                    object.remove(alias);
                                }
                            }
                            pending.push_back(row);
                        }
                    }
                }
            }
            outcome.has_more = matched > total;
            if !pending.is_empty() || !*emitted {
                let page: Vec<Value> = pending.drain(..).collect();
                deliver(self, emit, emitted, &mut outcome, page, &envelope, &planner, &budget, &defaults).await?;
            }
            Ok::<_, PartQueryError>(outcome)
        };
        work.await
    }
}

/// Hand one page to the caller of a streamed read: the envelope first,
/// plain pages after.
#[allow(clippy::too_many_arguments)]
async fn deliver<F, Fut, E>(
    engine: &PartQueryEngine,
    emit: &mut F,
    emitted: &mut bool,
    outcome: &mut PagedOutcome,
    page: Vec<Value>,
    envelope: &E,
    planner: &Value,
    budget: &Value,
    defaults: &Value,
) -> QueryResult<bool>
where
    F: FnMut(PagedLine) -> Fut + Send,
    Fut: std::future::Future<Output = bool> + Send,
    E: Fn(Vec<Value>, bool, Value, Value, Value, Value) -> Value,
{
    let rows = page.len();
    let line = if *emitted {
        PagedLine::Page(page)
    } else {
        *emitted = true;
        PagedLine::Envelope(envelope(page, true, planner.clone(), budget.clone(), defaults.clone(), engine.head_json().await))
    };
    let keep_going = emit(line).await;
    outcome.delivered += rows;
    outcome.pages += 1;
    if !keep_going {
        outcome.stopped = true;
    }
    Ok(keep_going)
}

/// Consume compiler-owned group cardinality before pagination, including an
/// empty offset page. Ordinary user aliases cannot opt into this protocol.
fn stats_page_total(stats_page: bool, offset: usize, rows: &mut Vec<Value>) -> QueryResult<Option<u64>> {
    if !stats_page {
        return Ok(None);
    }
    let mut total = None;
    for row in rows.iter_mut() {
        let raw = row.as_object_mut().and_then(|row| row.remove("__nano_stats_total"))
            .ok_or_else(|| internal("group page omitted exact cardinality"))?;
        let count = raw.as_u64().or_else(|| raw.as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| internal("group page returned invalid cardinality"))?;
        if total.is_some_and(|previous| previous != count) {
            return Err(internal("group page returned inconsistent cardinality"));
        }
        total = Some(count);
    }
    let mut invalid_ordinal = false;
    rows.retain_mut(|row| {
        let ordinal = row.as_object_mut().and_then(|row| row.remove("__nano_stats_ordinal"))
            .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())));
        match ordinal {
            Some(ordinal) if ordinal > 0 => ordinal > offset as u64,
            _ => { invalid_ordinal = true; false }
        }
    });
    if invalid_ordinal {
        return Err(internal("group page returned invalid ordinal"));
    }
    Ok(Some(total.unwrap_or(0)))
}

/// Strip planner aliases, apply offset/limit, report the sentinel row.
pub fn page_decoded(mut rows: Vec<Value>, aliases: &BTreeSet<String>, offset: usize, limit: usize) -> (Vec<Value>, bool) {
    for row in &mut rows {
        if let Some(object) = row.as_object_mut() {
            for alias in aliases {
                object.remove(alias);
            }
        }
    }
    let has_more = rows.len() > offset.saturating_add(limit);
    (rows.into_iter().skip(offset).take(limit).collect(), has_more)
}

/// NAN-3265: what follows a progressive chunk read.
#[derive(Debug, PartialEq)]
enum ChunkFollow {
    /// The chunk is exhausted: re-tile the older remainder.
    Done,
    /// Its capped statement came back full: read the rest of the chunk
    /// after the last kept row.
    Continue(progressive::Chunk),
    /// Full, but the last row names no usable cursor: drop this read and
    /// reread the chunk with the whole remaining page as its limit.
    Reread(progressive::Chunk),
}

fn row_field<'a>(row: &'a Value, path: &str) -> Option<&'a Value> {
    row.get(path).or_else(|| path.split('.').try_fold(row, |value, part| value.get(part)))
}

/// `got` rows came back from a chunk statement limited to `statement_rows`
/// while `remaining` rows were still wanted. Only a full statement below
/// the remaining page can have left rows of the chunk unread.
fn chunk_follow(
    chunk: &progressive::Chunk, rows: &[Value], got: usize, statement_rows: usize, remaining: usize, window_start_us: i64,
) -> ChunkFollow {
    if got < statement_rows || statement_rows >= remaining {
        return ChunkFollow::Done;
    }
    let cursor = rows.last().and_then(|row| {
        let time = row_field(row, "time").and_then(Value::as_str)?;
        let uid = row_field(row, "metadata.uid").and_then(Value::as_str)?;
        Some((time, uid))
    });
    match cursor.and_then(|(time, uid)| progressive::continuation(chunk, time, uid)) {
        // The planner admits a cursor strictly inside the query window.
        Some(next) if next.end_us > window_start_us => ChunkFollow::Continue(next),
        _ => {
            let mut again = chunk.clone();
            again.uncapped = true;
            ChunkFollow::Reread(again)
        }
    }
}

/// Over the memory or result budget (splittable in the progressive path).
fn memory_exhausted(error: &crate::executor::ExecutorError) -> bool {
    matches!(error, crate::executor::ExecutorError::ResultTooLarge { .. })
        || super::memory_budget::is_budget_refusal(&error.to_string())
}

/// Estimated scan above which a statement starts on the large lane.
pub const LARGE_SCAN_BYTES: u64 = 4 * 1024 * 1024 * 1024;

// Total scan bytes are not peak resident memory: Parquet reads projected
// blocks incrementally. Do not serialize ordinary scans on the large lane
// using an assumed whole-scan decode multiplier. The native statement cap
// remains authoritative, with a large-lane retry on a real memory refusal.
pub(super) fn needs_large_lane(scan_bytes: u64) -> bool {
    scan_bytes > LARGE_SCAN_BYTES
}
fn take_prewarm_budget(remaining: &mut u64, bytes: u64) -> bool {
    if bytes > *remaining { return false }
    *remaining -= bytes;
    true
}

/// Run `plan` on `lanes`: inside an interactive request (a `query_timing`
/// scope) through the streaming ABI when the runtime has it, whose statement
/// is cancelled when the stream is dropped (NAN-3077: a dropped request no
/// longer keeps its lane until the SQL deadline); otherwise as before.
async fn run_on(lanes: &NativeExecutor, plan: NativeQueryPlan) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
    run_on_as(lanes, plan, None).await
}

/// [`run_on`] for a statement routed by [`super::lanes::run_sized`].
pub(super) async fn run_on_routed(
    lanes: &NativeExecutor, plan: NativeQueryPlan, route: super::lanes::Route,
) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
    run_on_as(lanes, plan, Some(route)).await
}

async fn run_on_as(
    lanes: &NativeExecutor, plan: NativeQueryPlan, route: Option<super::lanes::Route>,
) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
    // NAN-3715: an SQL probe's chDB settings, on every statement it runs
    // (tighten-only for limits; nothing outside a probe).
    let plan = super::sql_probe::with_probe_settings(plan);
    match run_on_once(lanes, plan.clone(), route).await {
        Err(error) if prewhere_defect(&error.to_string(), &plan.sql) => {
            tracing::warn!(error = %error, "native PREWHERE lost a shared filter expression; rerunning without move-to-prewhere");
            run_on_once(lanes, without_prewhere(plan), route).await
        }
        other => other,
    }
}

/// NAN-3150: chDB 26.7's File/Parquet PREWHERE drops a filter subexpression
/// that one OR conjunct shares with another conjunct, whenever the statement
/// also reads non-filter columns: `(lower(message) LIKE '%x%' OR class_uid =
/// 3) AND lower(message) != 'zz'` over `SELECT *` dies with `Code: 10. Not
/// found column lower(message) in block (NOT_FOUND_COLUMN_IN_BLOCK)`. The
/// lean-gate k6 shape `metadata.log_source=aws_cloudtrail OR <hash>` hits it
/// through the caller's source scope (`... AND lower(<log_source>) !=
/// 'audit'`). The same predicate is correct with automatic move-to-prewhere
/// off (no explicit PREWHERE is ever emitted), so the one failed statement is
/// rerun that way; every other statement keeps PREWHERE. Rows are identical:
/// PREWHERE only reorders reads.
fn prewhere_defect(error: &str, sql: &str) -> bool {
    (error.contains("NOT_FOUND_COLUMN_IN_BLOCK") || (error.contains("Code: 10.") && error.contains("Not found column")))
        && !sql.contains("optimize_move_to_prewhere=0")
}

fn without_prewhere(mut plan: NativeQueryPlan) -> NativeQueryPlan {
    plan.sql = crate::executor::with_setting(&plan.sql, "optimize_move_to_prewhere=0");
    plan
}

async fn run_on_once(
    lanes: &NativeExecutor, plan: NativeQueryPlan, route: Option<super::lanes::Route>,
) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
    if !super::debug::enabled() { return run_on_inner(lanes, plan).await; }
    let (sql, _) = crate::executor::execution_sql(plan.sql.clone(), crate::query_timing::current().as_ref());
    let sql = crate::executor::with_read_only_setting(&sql);
    let settings_clause = crate::executor::statement_settings(&sql).unwrap_or("readonly=2");
    let settings_sql = format!("SELECT name, value FROM system.settings WHERE name IN ('max_threads', 'max_memory_usage', 'max_execution_time', 'max_bytes_before_external_sort', 'max_bytes_before_external_group_by', 'input_format_parquet_filter_push_down', 'input_format_parquet_use_native_reader', 'input_format_parquet_use_offset_index', 'use_query_cache', 'use_uncompressed_cache', 'use_page_cache_for_disks_without_file_cache', 'input_format_parquet_use_metadata_cache', 'schema_inference_use_cache_for_file') UNION ALL SELECT concat('server.', name) AS name, value FROM system.server_settings WHERE name IN ('max_server_memory_usage', 'memory_worker_use_cgroup', 'memory_worker_dynamic_hard_limit', 'page_cache_max_size', 'mark_cache_size', 'uncompressed_cache_size', 'parquet_metadata_cache_size') SETTINGS {settings_clause}");
    let settings_plan = NativeQueryPlan { sql: settings_sql, params: Vec::new(), ..plan.clone() };
    let settings = match lanes.execute(settings_plan).await {
        Ok(output) => json!({"effective": decode_rows(&output.data).unwrap_or_default(), "configured_lane_server_memory_bytes": lanes.server_memory_limit_bytes()}),
        Err(_) => json!({"unavailable":true}),
    };
    let started = Instant::now();
    let (output, times) = crate::executor::capture_statement_times(run_on_inner(lanes, plan)).await;
    // NAN-3393: each attempt's own native time, so a statement that failed
    // on a small lane before its large-lane rerun shows what it cost.
    let mut timing = json!({
        "statement_ms": started.elapsed().as_secs_f64() * 1000.0,
        "native_init_ms": times.init_ms, "native_fetch_ms": times.fetch_ms,
        "native_first_fetch_ms": times.first_fetch_ms, "native_ms": times.native_ms,
    });
    if let Some(route) = route {
        timing["lane_class"] = json!(route.class.label());
        timing["bounded_reader"] = json!(route.bounded);
        timing["gate_wait_ms"] = json!(route.gate_wait_ms);
    }
    if let Err(error) = &output {
        timing["error"] = json!(if super::memory_budget::is_memory_limit_error(&error.to_string()) { "memory_limit" } else { "error" });
    }
    super::debug::statement(&sql, settings, match lanes.lane_name() { "parts" => "small", "parts-large" => "large", name => name }, times.lane_wait_ms, output.as_ref().ok().map(|output| (output.storage_rows_read, output.storage_bytes_read)), timing);
    output
}

async fn run_on_inner(lanes: &NativeExecutor, plan: NativeQueryPlan) -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
    if crate::query_timing::current().is_none() || !lanes.supports_streaming() {
        return lanes.execute(plan).await;
    }
    let limit = lanes.result_limit_bytes();
    let mut stream = lanes.execute_streaming(plan).await?;
    let mut output = NativeQueryOutput { data: Vec::new(), elapsed: Duration::ZERO, storage_rows_read: 0, storage_bytes_read: 0 };
    while let Some(block) = stream.next().await {
        let block = block?;
        output.data.extend_from_slice(&block.data);
        output.elapsed += block.elapsed;
        output.storage_rows_read = output.storage_rows_read.saturating_add(block.storage_rows_read);
        output.storage_bytes_read = output.storage_bytes_read.saturating_add(block.storage_bytes_read);
        if let Some(limit_bytes) = limit.filter(|limit| output.data.len() as u64 > *limit) {
            return Err(crate::executor::ExecutorError::ResultTooLarge { bytes: output.data.len() as u64, limit_bytes });
        }
    }
    Ok(output)
}

/// `plan` with its statement memory cap (and the spill thresholds derived
/// from it) set to `bytes`.
pub(crate) fn with_memory_cap(mut plan: NativeQueryPlan, bytes: u64) -> NativeQueryPlan {
    plan.sql = memory_cap_sql(&plan.sql, bytes);
    plan
}

fn memory_cap_sql(sql: &str, bytes: u64) -> String {
    static SETTINGS: std::sync::OnceLock<[regex::Regex; 4]> = std::sync::OnceLock::new();
    let [memory, sort, group_by, disk] = SETTINGS.get_or_init(|| {
        [
            regex::Regex::new(r"max_memory_usage\s*=\s*\d+").expect("static regex"),
            regex::Regex::new(r"max_bytes_before_external_sort\s*=\s*\d+").expect("static regex"),
            regex::Regex::new(r"max_bytes_before_external_group_by\s*=\s*\d+").expect("static regex"),
            regex::Regex::new(r"max_temporary_data_on_disk_size_for_query\s*=\s*\d+").expect("static regex"),
        ]
    });
    let (spill_at, spill_disk) = crate::planner::external_processing_limits(bytes);
    let sql = memory.replace_all(sql, format!("max_memory_usage={bytes}"));
    // Retarget the lane ceiling without widening the full-payload sort bound.
    // Only the planner's payload bundle carries this Parquet watermark; narrow
    // pages and analytical statements retain their existing lane thresholds.
    let payload = crate::executor::statement_settings(sql.as_ref())
        .is_some_and(|settings| settings.contains("input_format_parquet_memory_high_watermark="));
    let sort_at = if payload { spill_at.min(67_108_864) } else { spill_at };
    let sql = sort.replace_all(&sql, format!("max_bytes_before_external_sort={sort_at}"));
    let sql = group_by.replace_all(&sql, format!("max_bytes_before_external_group_by={spill_at}"));
    disk.replace_all(&sql, format!("max_temporary_data_on_disk_size_for_query={spill_disk}")).into_owned()
}

impl PartQueryEngine {
    /// Newest-first progressive execution over parts (see [`progressive`]).
    /// `skip` is the page offset: its rows are walked but not held (NAN-3270).
    pub async fn progressive(&self, compiled: &CompiledQuery, cursor: Option<(&str, &str)>, membership: Option<&Membership>, skip: usize) -> QueryResult<Run> {
        let cache_before = self.fetcher.cache().stats();
        let mut decode_s = 0.0_f64;
        let start = chrono::DateTime::parse_from_rfc3339(&compiled.start)
            .map_err(|_| PartQueryError::Invalid("query start is not RFC3339".to_string()))?
            .with_timezone(&chrono::Utc);
        let requested_end = chrono::DateTime::parse_from_rfc3339(cursor.map_or(compiled.end.as_str(), |(time, _)| time))
            .map_err(|_| PartQueryError::Invalid("query end is not RFC3339".to_string()))?
            .with_timezone(&chrono::Utc);
        // Start the walk at the newest data that exists (the reader clips to
        // its source upper bound the same way); chunking never changes rows.
        let (parts, _, _, _) = self.snapshot(start.timestamp_micros(), requested_end.timestamp_micros()).await?;
        let newest_us = parts.iter().map(|part| part.max_time_us.saturating_add(1)).max();
        let execution_end = match newest_us.and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_micros) {
            Some(newest) if newest > start && newest < requested_end => newest,
            _ => requested_end,
        };
        let limit = planner::newest_first_row_cap(&compiled.sql).map_or(compiled.limit, |cap| cap.min(compiled.limit));
        // Multi-path hash probes commonly need most of the day before finding
        // a page. One narrow locator over that day avoids reopening the same
        // Parquet files for every geometrically growing chunk. The exact-time
        // full read and existing budget bisection still enforce result parity.
        let hash_paths = compiled.projected_scan_columns.iter()
            .filter(|path| path.ends_with("hashes.value"))
            .count();
        // A source-family disjunct (for example `source=audit OR hash=...`)
        // leaves the whole day broad; only an independent hash-only OR hint
        // can make the one-shot locator cheap.
        let selective_hash_hint = compiled.candidate_hints.iter().any(|hint| match hint {
            planner::CandidateHint::Any { alternatives } =>
                alternatives.iter().any(|alternative| matches!(alternative,
                    planner::CandidateHint::Entity { source_path, .. } if source_path.ends_with("hashes.value")))
                && alternatives.iter().all(|alternative| match alternative {
                    planner::CandidateHint::Entity { source_path, .. } => source_path.ends_with("hashes.value"),
                    planner::CandidateHint::Keyword { value, .. } => value.len() >= 32,
                    _ => false,
                }),
            _ => false,
        });
        let whole_hash_window = hash_paths >= 2
            && selective_hash_hint
            && (execution_end - start).num_seconds() <= 86_400
            && planner::page_locator(compiled).is_some();
        let mut pending = if whole_hash_window {
            std::collections::VecDeque::from([progressive::whole_window_chunk(start, execution_end)])
        } else {
            std::collections::VecDeque::from(progressive::seed_chunks(start, execution_end))
        };
        // NAN-3077: an entity pivot (host, IP, user, process, hash) selects
        // once over the whole window; when stats and blooms leave only a few
        // row groups, those are read in one fenced chunk instead of walking
        // widening chunks, each re-selecting, locating and executing.
        let mut preselected: Option<(i64, i64, Selection)> = None;
        let mut whole_window_preselected = false;
        let mut preselect = Value::Null;
        let mut select_cpu_us = 0_u64;
        // NAN-3155: a non-selective preselect is not discarded: every chunk
        // is cut from it ([`Selection::narrowed`]) instead of re-running the
        // blooms, footers and fetches per chunk.
        let mut window_selection: Option<Selection> = None;
        let mut narrowed_chunks = 0_usize;
        // NAN-3158: size the newest chunk from the entity-ranges counts, and
        // skip the whole-window preselect for a value too dense for blooms.
        let mut density = Value::Null;
        let mut skip_preselect = false;
        // NAN-3169: the estimate reached the page's target inside a newer
        // first chunk, so a selective preselect is still cut into that chunk
        // rather than read whole.
        let mut density_fills_first_chunk = false;
        if !whole_hash_window && prune::uses_entities(&compiled.candidate_hints) && super::density::enabled() {
            let (from_us, to_us) = (start.timestamp_micros(), execution_end.timestamp_micros());
            let target = (progressive::step_target(0, limit) as u64).saturating_mul(super::density::DENSITY_MARGIN);
            let started = Instant::now();
            match Box::pin(super::density::estimate(self, &compiled.candidate_hints, from_us, to_us, target)).await {
                Ok(Some(estimate)) => {
                    skip_preselect = estimate.dense();
                    if let Some(first_start_us) = estimate.first_start_us {
                        pending = progressive::density_seed(start, execution_end, first_start_us).into();
                        density_fills_first_chunk = estimate.events >= target as f64 && pending.len() > 1;
                    }
                    crate::query_timing::record(|p| {
                        p.funnel.density_seed = true;
                        p.funnel.seed_consulted = estimate.consulted_parts;
                        p.funnel.seed_complete = Some(estimate.complete);
                        p.funnel.seed_estimated_events = Some(estimate.events);
                    });
                    density = json!({"s": started.elapsed().as_secs_f64(), "dense": skip_preselect, "estimate": estimate});
                }
                Ok(None) => {}
                // Only a seed: the walk below is correct without it.
                Err(error) => tracing::warn!(reason = error.reason(), "entity density unavailable; default progressive seeds"),
            }
        }
        // NAN-3170: a keyword-only walk (a bareword) seeds its newest chunk
        // from the token indexes' candidate blocks, and a token that keeps a
        // few row groups of the whole window takes the preselect below.
        let mut token_preselect = false;
        if !whole_hash_window && super::token_seed::applies(&compiled.candidate_hints) && super::density::enabled() {
            let (from_us, to_us) = (start.timestamp_micros(), execution_end.timestamp_micros());
            let target = (progressive::step_target(0, limit) as u64).saturating_mul(super::density::DENSITY_MARGIN);
            let started = Instant::now();
            match Box::pin(super::token_seed::estimate(self, &compiled.candidate_hints, from_us, to_us, target)).await {
                Ok(Some(estimate)) => {
                    token_preselect = estimate.selective();
                    // A token whose page (with its margin) fits in the newest
                    // few minutes keeps the default seeds: the default walk
                    // fills it in a chunk or two, without the margin's wider read.
                    let default_first_us = to_us - super::token_seed::DEFAULT_SEED_SPAN_US;
                    if let Some(first_start_us) = estimate.first_start_us.filter(|first| *first < default_first_us) {
                        pending = progressive::density_seed(start, execution_end, first_start_us).into();
                    }
                    crate::query_timing::record(|p| {
                        p.funnel.token_seed = true;
                        p.funnel.seed_consulted = estimate.consulted_files;
                        p.funnel.seed_complete = Some(estimate.complete);
                        p.funnel.seed_estimated_events = Some(estimate.events);
                    });
                    density = json!({"s": started.elapsed().as_secs_f64(), "token": estimate});
                }
                Ok(None) => {}
                // Only a seed: the walk below is correct without it.
                Err(error) => tracing::warn!(reason = error.reason(), "token density unavailable; default progressive seeds"),
            }
        }
        // NAN-4157: when the density estimate fills the page inside a newer
        // first chunk, the preselect can never be read whole (see
        // `read_whole` below), so it would only cut chunks out of a lease
        // of every surviving file in the window. Cold, that lease is the
        // whole window's token indexes and data files (168 h hash pivot: 355
        // files / 9.3 GB) before chunk 1 runs. Each chunk selects its own
        // files instead.
        let preselect_window = window_preselect(WindowPreselect {
            whole_hash_window,
            dense: skip_preselect,
            density_fills_first_chunk,
            density_over_selective: density_over_selective(),
            token_preselect,
            uses_entities: prune::uses_entities(&compiled.candidate_hints),
        });
        if !preselect_window && density_fills_first_chunk && !skip_preselect && !whole_hash_window {
            preselect = json!({"skipped": "density_first_chunk"});
        }
        if preselect_window {
            let (from_us, to_us) = (start.timestamp_micros(), execution_end.timestamp_micros());
            let preselect_started = Instant::now();
            // NAN-3644: a window over the cold ceiling walks its chunks
            // instead (each chunk leases only its own files).
            match self.select_with(from_us, to_us, &compiled.candidate_hints, membership).await {
                Err(PartQueryError::ColdScanTooLarge { .. }) => {
                    preselect = json!({"s": preselect_started.elapsed().as_secs_f64(), "skipped": "cold_ceiling"});
                }
                Err(error) => return Err(error),
                Ok(selection) => {
                    preselect = json!({"s": preselect_started.elapsed().as_secs_f64(), "evidence": serde_json::to_value(&selection.evidence).map_err(internal)?});
                    // NAN-3169: "few row groups" is not "few rows". A busy host kept
                    // in 24 of 400 groups (one source family's, 262,144 rows each)
                    // read ~6 M rows over the whole day for a 50-row page. When the
                    // density estimate fills the page in a newer first chunk, every
                    // chunk is cut from this selection instead (one selection, and
                    // the first chunk's narrow + payload statements, as before).
                    let read_whole = progressive::selective_window(selection.evidence.kept_row_groups, selection.evidence.row_groups)
                        && !(density_fills_first_chunk && density_over_selective());
                    if read_whole {
                        pending = std::collections::VecDeque::from([progressive::whole_window_chunk(start, execution_end)]);
                        preselected = Some((from_us, to_us, selection));
                        whole_window_preselected = true;
                    } else {
                        select_cpu_us += selection.evidence.select_cpu_us;
                        window_selection = Some(selection);
                    }
                }
            }
        }
        // Locate-then-fetch (the reader's narrow locator, per chunk): read only
        // the predicate/order columns to find the chunk's page instants, then
        // read full-width rows at exactly those instants. A rare value spread
        // over hours otherwise decodes every projected column of every row.
        let locator = planner::page_locator(compiled);
        // NAN-3155: staged row shapes (`| sort -time | head N`) have no
        // single-select locator; each chunk runs as narrow + payload passes.
        let two_pass = if locator.is_none() { super::two_pass::plan(compiled) } else { None };
        let mut two_pass_chunks = 0_usize;
        let mut two_pass_statements = 0_usize;
        let mut locator_fallbacks = 0_usize;
        let mut locator_cache_hits = 0_usize;
        let mut located_chunks = 0_usize;
        let mut locator_statements = 0_usize;
        let mut run = Run {
            rows: Vec::with_capacity(limit.min(4_096)),
            engine_seconds: 0.0,
            storage_rows: 0,
            storage_bytes: 0,
            temporary_aliases: BTreeSet::new(),
            schema_defaults: Vec::new(),
            budget: Value::Null,
            planner: Value::Null,
            continuation: None,
        };
        let (mut attempts, mut executed, mut splits, mut fetched_files, mut source_family_pruned_files) =
            (0_usize, 0_usize, 0_usize, 0_usize, 0_usize);
        let (mut select_s, mut locate_s, mut plan_s, mut execute_s) = (0.0_f64, 0.0_f64, 0.0_f64, 0.0_f64);
        let mut payload_files = 0_usize;
        let mut payload_narrowed_files = 0_usize;
        // Files in the full-width statements' source (what chDB opens).
        let mut payload_source_files = 0_usize;
        let mut payload_candidate_blocks = 0_usize;
        // After each walked chunk the older remainder is re-tiled from the
        // density seen so far (see [`progressive::reseed`]).
        let (window_start_us, walk_end_us) = (start.timestamp_micros(), execution_end.timestamp_micros());
        let reseed = |chunk: &progressive::Chunk, rows: usize, pending: &mut std::collections::VecDeque<progressive::Chunk>| {
            *pending = progressive::reseed(window_start_us, chunk.start_us, walk_end_us - chunk.start_us, rows, progressive::step_target(rows, limit)).into();
        };
        let mut decoded_bytes = 0_u64;
        let mut range_fetch = super::range_fetch::FetchEvidence::default();
        let row_capped = progressive::row_capped(limit);
        let (mut continuations, mut uncapped_rereads) = (0_usize, 0_usize);
        // NAN-3270: the page is bounded by the bytes it holds as well as by
        // rows; past its budget the walk stops with a continuation instead
        // of refusing the whole page.
        let mut bytes = progressive::ByteBudget::new(self.executor.result_limit_bytes(), skip);
        let (mut byte_cut, mut byte_limited_statements) = (false, 0_usize);
        while let Some(chunk) = pending.pop_front() {
            attempts += 1;
            if attempts > progressive::MAX_PLAN_ATTEMPTS {
                return Err(PartQueryError::Budget("progressive paging exceeded its plan attempts".to_string()));
            }
            let chunk_to = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
            // NAN-3265: a page deeper than one cap reads each chunk under a
            // statement limit of at most CHUNK_ROW_CAP rows (its locator and
            // two-pass plans follow the capped statement), from the chunk's
            // own continuation cursor when it has one.
            let kept_before = run.rows.len();
            let remaining = limit - kept_before;
            let row_step = progressive::chunk_row_limit(limit, kept_before, chunk.uncapped);
            // NAN-3270: and to the rows the page's byte budget has room for
            // at the width seen so far (an uncapped reread keeps its rows:
            // the admission below still cuts it by bytes).
            let step_rows = match if chunk.uncapped { progressive::ByteStep::Rows(row_step) } else { bytes.step(kept_before, row_step) } {
                progressive::ByteStep::Rows(rows) => rows,
                progressive::ByteStep::Cut => {
                    byte_cut = true;
                    break;
                }
            };
            byte_limited_statements += usize::from(step_rows < row_step);
            let capped_query = (row_capped || step_rows < remaining)
                .then(|| planner::with_newest_first_row_cap(compiled, step_rows))
                .flatten();
            let capped_plans = capped_query.as_ref().map(|query| {
                let locator = planner::page_locator(query);
                let two_pass = if locator.is_none() { super::two_pass::plan(query) } else { None };
                (locator, two_pass)
            });
            let (query, chunk_locator, chunk_two_pass) = match (&capped_query, &capped_plans) {
                (Some(query), Some((locator, two_pass))) => (query, locator.as_ref(), two_pass.as_ref()),
                _ => (compiled, locator.as_ref(), two_pass.as_ref()),
            };
            let statement_rows = planner::newest_first_row_cap(&query.sql).unwrap_or(usize::MAX);
            let chunk_cursor = chunk.after.as_ref().map(|(time, uid)| (time.as_str(), uid.as_str())).or(cursor);
            let phase_start = Instant::now();
            let selection = match preselected.take().filter(|(from, to, _)| *from == chunk.start_us && *to == chunk_to) {
                Some((_, _, selection)) => selection,
                None => match &window_selection {
                    Some(window) => {
                        narrowed_chunks += 1;
                        window.narrowed(chunk.start_us, chunk_to)?
                    }
                    None => match self.select_with(chunk.start_us, chunk_to, &compiled.candidate_hints, membership).await {
                        Ok(selection) => selection,
                        // NAN-3644: a chunk over the cold ceiling is read as
                        // two narrower chunks, newest first, like one over
                        // its memory budget (the page may stop early).
                        Err(error @ PartQueryError::ColdScanTooLarge { .. }) => {
                            let Some((newer, older)) = progressive::split(&chunk) else { return Err(error) };
                            pending.push_front(older);
                            pending.push_front(newer);
                            splits += 1;
                            continue;
                        }
                        Err(error) => return Err(error),
                    },
                },
            };
            source_family_pruned_files += selection.evidence.source_family_pruned_files;
            range_fetch.absorb(&selection.evidence.range);
            select_s += phase_start.elapsed().as_secs_f64();
            select_cpu_us += selection.evidence.select_cpu_us;
            if selection.manifest.objects.is_empty() {
                // No verified part can hold a row in this chunk.
                reseed(&chunk, run.rows.len(), &mut pending);
                continue;
            }
            fetched_files += selection.evidence.fetched_files;
            let phase_start = Instant::now();
            let exact_times = match chunk_locator {
                Some(locator) => {
                    let fence = SourceTimeFence { start: &chunk.start, end: &chunk.end, end_inclusive: chunk.end_inclusive, exact_times: None };
                    // A capped statement's locator differs from the page's,
                    // so it bypasses the per-part locator cache (keyed on
                    // the page's locator and cursor).
                    let located = if capped_query.is_some() {
                        self.locate_chunk(&selection, locator, fence, chunk_cursor).await
                    } else {
                        self.locate(&selection, locator, fence, chunk_cursor).await
                    };
                    match located {
                        Ok(Some(located)) => {
                            run.engine_seconds += located.engine_seconds;
                            run.storage_rows = run.storage_rows.saturating_add(located.storage_rows);
                            run.storage_bytes = run.storage_bytes.saturating_add(located.storage_bytes);
                            located_chunks += 1;
                            locator_statements += located.statements;
                            locator_cache_hits += usize::from(located.cache_hit);
                            if located.times.is_empty() {
                                locate_s += phase_start.elapsed().as_secs_f64();
                                // Exact: no row of this chunk satisfies the predicate.
                                reseed(&chunk, run.rows.len(), &mut pending);
                                continue;
                            }
                            Some(located.times)
                        }
                        // Unlocatable (too many instants, budget, memory): the
                        // full-width chunk read below is always correct.
                        Ok(None) => {
                            locator_fallbacks += 1;
                            tracing::info!("locator exceeded its budget; reading the chunk full-width");
                            None
                        },
                        Err(PartQueryError::Unavailable(reason)) => return Err(PartQueryError::Unavailable(reason)),
                        Err(error) => {
                            locator_fallbacks += 1;
                            tracing::warn!(reason = error.reason(), "locator failed; reading the chunk full-width");
                            None
                        }
                    }
                }
                None => None,
            };
            locate_s += phase_start.elapsed().as_secs_f64();
            // NAN-3165: the payload statement opens only the files (and row
            // groups) whose verified times hold a located instant, not every
            // candidate of the chunk (~265 footers on a 24 h hot pivot).
            let at_instants = match exact_times.as_deref() {
                Some(times) if payload_at_instants() => selection.at_instants(times)?,
                _ => None,
            };
            if let Some(narrowed) = &at_instants {
                payload_narrowed_files += selection.manifest.objects.len().saturating_sub(narrowed.manifest.objects.len());
            }
            let selection = at_instants.as_ref().unwrap_or(&selection);
            let fence = SourceTimeFence { start: &chunk.start, end: &chunk.end, end_inclusive: chunk.end_inclusive, exact_times: exact_times.as_deref() };
            if let Some(two) = chunk_two_pass {
                let phase_start = Instant::now();
                if let Some(two_run) = Box::pin(self.run_two_pass(&selection, two, Some(fence), chunk_cursor)).await? {
                    execute_s += phase_start.elapsed().as_secs_f64();
                    decoded_bytes = decoded_bytes.saturating_add(two_run.payload_bytes);
                    let mut rows = two_run.rows;
                    // The payload's mean width per row (its rows are decoded
                    // already; the narrow pass carries no payload).
                    let mean = two_run.payload_bytes.div_ceil(rows.len().max(1) as u64);
                    let before_admit = bytes.clone();
                    let sizes = vec![mean; rows.len()];
                    let admitted = bytes.admit(kept_before, &mut rows, &sizes);
                    run.temporary_aliases.extend(two_run.temporary_aliases);
                    if run.schema_defaults.is_empty() {
                        run.schema_defaults = two_run.schema_defaults;
                        run.budget = serde_json::to_value(&two_run.budget).map_err(internal)?;
                    }
                    run.engine_seconds += two_run.engine_seconds;
                    run.storage_rows = run.storage_rows.saturating_add(two_run.storage_rows);
                    run.storage_bytes = run.storage_bytes.saturating_add(two_run.storage_bytes);
                    run.rows.extend(rows);
                    two_pass_chunks += 1;
                    two_pass_statements += two_run.statements;
                    executed += 1;
                    payload_files += selection.manifest.objects.len();
                    payload_candidate_blocks += selection.candidates.as_ref().map_or(0, Vec::len);
                    if run.rows.len() >= limit {
                        run.rows.truncate(limit);
                        break;
                    }
                    if admitted.cut {
                        byte_cut = true;
                        break;
                    }
                    match chunk_follow(&chunk, &run.rows, run.rows.len() - kept_before, statement_rows, remaining, window_start_us) {
                        ChunkFollow::Done => reseed(&chunk, run.rows.len(), &mut pending),
                        ChunkFollow::Continue(next) => {
                            continuations += 1;
                            pending.push_front(next);
                        }
                        ChunkFollow::Reread(again) => {
                            uncapped_rereads += 1;
                            run.rows.truncate(kept_before);
                            decoded_bytes = decoded_bytes.saturating_sub(two_run.payload_bytes);
                            bytes = before_admit;
                            pending.push_front(again);
                        }
                    }
                    continue;
                }
            }
            let phase_start = Instant::now();
            let planned = match chunk_cursor {
                Some((time, event_uid)) => planner::plan_broad_log_query_with_candidates_tail_time_and_cursor(
                    &selection.tenant,
                    &selection.manifest,
                    query,
                    selection.candidates.as_deref(),
                    None,
                    Some(fence),
                    SourceCursorFence { time, event_uid },
                ),
                None => planner::plan_broad_log_query_with_candidates_tail_and_time(
                    &selection.tenant,
                    &selection.manifest,
                    query,
                    selection.candidates.as_deref(),
                    None,
                    Some(fence),
                ),
            };
            let plan = match planned {
                Ok(plan) => plan,
                Err(planner::QueryPlanError::BudgetRejected { .. }) => {
                    let (newer, older) = progressive::split(&chunk).ok_or_else(|| PartQueryError::Budget("progressive chunk cannot be split further".to_string()))?;
                    pending.push_front(older);
                    pending.push_front(newer);
                    splits += 1;
                    continue;
                }
                Err(error) => return Err(map_plan_error(error)),
            };
            plan_s += phase_start.elapsed().as_secs_f64();
            run.temporary_aliases.extend(plan.temporary_aliases.iter().cloned());
            if run.schema_defaults.is_empty() {
                run.schema_defaults = plan.schema_defaults.clone();
                run.budget = serde_json::to_value(&plan.budget).map_err(internal)?;
            }
            let phase_start = Instant::now();
            let planned_files = plan.budget.candidate_objects;
            let output = match self.run(plan).await {
                Ok(output) => output,
                // Over the memory or result budget: retry as two narrower
                // windows, down to one that cannot split (a clean refusal).
                Err(error) if memory_exhausted(&error) => {
                    let Some((newer, older)) = progressive::split(&chunk) else {
                        return Err(map_executor_error(error));
                    };
                    pending.push_front(older);
                    pending.push_front(newer);
                    splits += 1;
                    continue;
                }
                Err(crate::executor::ExecutorError::LaneWaitTimeout) => {
                    return Err(PartQueryError::Unavailable("all query lanes are busy".to_string()))
                }
                Err(error) => return Err(map_executor_error(error)),
            };
            execute_s += phase_start.elapsed().as_secs_f64();
            decoded_bytes = decoded_bytes.saturating_add(output.data.len() as u64);
            run.engine_seconds += output.elapsed.as_secs_f64();
            run.storage_rows = run.storage_rows.saturating_add(output.storage_rows_read);
            run.storage_bytes = run.storage_bytes.saturating_add(output.storage_bytes_read);
            let decode_started = Instant::now();
            // The rows kept across chunks share the one byte budget.
            let before_admit = bytes.clone();
            let admitted = {
                let _timer = crate::query_timing::timer(crate::query_timing::Phase::Decode);
                let mut rows = decode_rows(&output.data)?;
                let mut sizes = progressive::line_sizes(&output.data);
                if sizes.len() != rows.len() {
                    sizes = vec![(output.data.len() as u64).div_ceil(rows.len().max(1) as u64); rows.len()];
                }
                let admitted = bytes.admit(kept_before, &mut rows, &sizes);
                run.rows.extend(rows);
                admitted
            };
            decode_s += decode_started.elapsed().as_secs_f64();
            executed += 1;
            payload_files += planned_files;
            payload_source_files += selection.manifest.objects.len();
            payload_candidate_blocks += selection.candidates.as_ref().map_or(0, Vec::len);
            if run.rows.len() >= limit {
                run.rows.truncate(limit);
                break;
            }
            if admitted.cut {
                byte_cut = true;
                break;
            }
            match chunk_follow(&chunk, &run.rows, run.rows.len() - kept_before, statement_rows, remaining, window_start_us) {
                ChunkFollow::Done => reseed(&chunk, run.rows.len(), &mut pending),
                ChunkFollow::Continue(next) => {
                    continuations += 1;
                    pending.push_front(next);
                }
                ChunkFollow::Reread(again) => {
                    uncapped_rereads += 1;
                    run.rows.truncate(kept_before);
                    decoded_bytes = decoded_bytes.saturating_sub(output.data.len() as u64);
                    bytes = before_admit;
                    pending.push_front(again);
                }
            }
        }
        if byte_cut {
            // NAN-3270: the page continues after its last row. A last row
            // naming no cursor cannot be continued: refuse as before.
            let Some(next) = run.rows.last().and_then(Continuation::after) else {
                return Err(PartQueryError::MemoryBudget(format!(
                    "the page's rows exceed its {}-byte result budget and its last row carries no (time, metadata.uid) cursor; narrow the query or add | head",
                    self.executor.result_limit_bytes().unwrap_or_default())));
            };
            run.continuation = Some(next);
        }
        let cache_after = self.fetcher.cache().stats();
        crate::query_timing::record(|p| {
            p.funnel.progressive = true;
            p.funnel.two_pass |= two_pass.is_some();
            p.funnel.whole_window_preselected = whole_window_preselected;
            p.funnel.chunks_executed += executed;
            p.funnel.payload_source_files += payload_source_files;
            p.funnel.payload_narrowed_files += payload_narrowed_files;
        });
        run.planner = json!({
            "kind": "progressive_newest_first",
            "fetch_s": cache_after.fetch_ns.saturating_sub(cache_before.fetch_ns) as f64 / 1e9,
            "verify_s": cache_after.verify_ns.saturating_sub(cache_before.verify_ns) as f64 / 1e9,
            "cache_timing_scope": "process_cache_delta_sum_per_file",
            "cache_hits": cache_after.hits.saturating_sub(cache_before.hits),
            "cache_misses": cache_after.misses.saturating_sub(cache_before.misses),
            "decode_s": decode_s,
            "decode_scope": "result_json; parquet_decode_in_native_elapsed",
            "whole_window_preselected": whole_window_preselected,
            "preselect_narrowed_chunks": narrowed_chunks,
            "preselect": preselect,
            "density": density,
            "locator_fallbacks": locator_fallbacks,
            "locator_cache_hits": locator_cache_hits,
            "successful_native_statements": locator_statements + executed + two_pass_statements - two_pass_chunks,
            "two_pass_chunks": two_pass_chunks,
            "chunks_executed": executed,
            "payload_files": payload_files,
            "payload_narrowed_files": payload_narrowed_files,
            "payload_source_files": payload_source_files,
            "select_cpu_s": select_cpu_us as f64 / 1e6,
            "payload_candidate_blocks": payload_candidate_blocks,
            "chunks_split": splits,
            "plan_attempts": attempts,
            "pending_chunks_skipped_after_limit": pending.len(),
            "fetched_files": fetched_files,
            "source_family_pruned_files": source_family_pruned_files,
            "range_files": range_fetch.range_files,
            "resident_files": range_fetch.resident_files,
            "range_fetched_bytes": range_fetch.range_fetched_bytes,
            "whole_fetched_bytes": range_fetch.whole_fetched_bytes,
            "range_fallbacks": range_fetch.range_fallbacks,
            "located_chunks": located_chunks,
            "select_s": select_s,
            "locate_s": locate_s,
            "plan_s": plan_s,
            "execute_s": execute_s,
            "exact_recheck": true,
        });
        run.planner["row_capped"] = json!(row_capped);
        run.planner["chunk_row_cap"] = json!(progressive::CHUNK_ROW_CAP);
        run.planner["chunk_continuations"] = json!(continuations);
        run.planner["uncapped_rereads"] = json!(uncapped_rereads);
        run.planner["byte_cut"] = json!(byte_cut);
        run.planner["held_bytes"] = json!(bytes.held_bytes());
        run.planner["decoded_bytes"] = json!(decoded_bytes);
        run.planner["byte_limited_statements"] = json!(byte_limited_statements);
        Ok(run)
    }
}

impl PartQueryEngine {
    async fn fragment_aggregate(&self, compiled: &CompiledQuery, from: i64, to: i64, membership: Option<&Membership>) -> QueryResult<Option<Run>> {
        let Some(shape) = super::fragment_aggregate::shape(compiled) else { return Ok(None) };
        // Keep Rust-side partial decoding bounded. Larger shapes use the
        // existing streaming/native aggregation and its memory accounting.
        if compiled.limit > 4096 { return Ok(None); }
        let (parts, _, _, _) = self.snapshot(from, to).await?;
        // Preserve native empty-relation validation, schemas and metadata.
        if parts.is_empty() || parts.len() > 4096 { return Ok(None); }
        let context = super::fragment_cache::Context::for_statement(shape.kind, compiled, None);
        let mut run = Run { rows: Vec::new(), engine_seconds: 0.0, storage_rows: 0, storage_bytes: 0,
            temporary_aliases: BTreeSet::new(), schema_defaults: Vec::new(), budget: json!({}), planner: json!({}), continuation: None };
        let mut partials = Vec::new();
        let mut decoded_bytes = 0;
        let mut selected_bytes = 0_u64;
        let mut statements = 0;
        let mut range_fetch = super::range_fetch::FetchEvidence::default();
        // NAN-4164: a single-keyword count or histogram answers each part's
        // whole-window row groups from its v3 token counts (as the unpartial
        // path does); only the rest of the part is scanned. Without this the
        // result cache bypassed the counts and every part of a common token
        // (`sysmon | stats count`, the search histogram) was scanned.
        let count_plan = if keyword_count::enabled() { keyword_count::plan(compiled, compiled_bound_us(compiled)?) } else { None };
        let (mut counted_groups, mut counted_rows, mut counted_parts) = (0_usize, 0_u64, 0_usize);
        crate::query_timing::record(|p| p.funnel.counting = count_plan.is_some());
        for part in &parts {
            let key = context.key(&self.settings.tenant_id, part, from, to);
            let bytes = if let Some(bytes) = self.fragments.get_partial(&key) { bytes } else {
                let mut tally = keyword_count::Tally::default();
                let selection = self.select_part(from, to, &compiled.candidate_hints, membership, count_plan.as_ref().map(|plan| (plan, &mut tally)), Some(&part.part_id)).await?;
                range_fetch.absorb(&selection.evidence.range);
                selected_bytes = selected_bytes.saturating_add(selection.manifest.objects.iter().map(|object| object.event_object_bytes).sum::<u64>());
                if selected_bytes > self.settings.max_query_bytes { return Ok(None); }
                let plan = plan_logs(&selection, compiled, None)?;
                let rows = if count_plan.is_some() && selection.manifest.objects.is_empty() {
                    // Every group was counted (or none can match): no scan.
                    Vec::new()
                } else {
                    let output = self.execute(plan.clone()).await?;
                    run.engine_seconds += output.elapsed.as_secs_f64();
                    run.storage_rows += output.storage_rows_read;
                    run.storage_bytes += output.storage_bytes_read;
                    statements += 1;
                    decode_rows(&output.data)?
                };
                let rows = match &count_plan {
                    Some(count_plan) => {
                        counted_groups += tally.groups();
                        counted_rows += tally.rows();
                        counted_parts += usize::from(tally.groups() > 0);
                        match keyword_count::merge(count_plan, rows, &tally).map_err(|error| internal(format!("{error:#}")))? {
                            keyword_count::Merged::Rows(rows) => rows,
                            // Only the grouped plan rescans, and its shape
                            // is never a fragment aggregate: the plain path.
                            keyword_count::Merged::Rescan => return Ok(None),
                        }
                    }
                    None => rows,
                };
                let partial = json!({"rows":rows,"schema_defaults":plan.schema_defaults,"budget":plan.budget});
                let bytes = serde_json::to_vec(&partial).map_err(internal)?.into_boxed_slice();
                self.fragments.insert_partial(key, part.part_id.clone(), bytes.clone());
                bytes
            };
            decoded_bytes += bytes.len();
            if decoded_bytes > 4 * 1024 * 1024 { return Ok(None); }
            let partial: Value = serde_json::from_slice(&bytes).map_err(internal)?;
            run.schema_defaults.extend(serde_json::from_value::<Vec<String>>(partial["schema_defaults"].clone()).map_err(internal)?);
            run.schema_defaults.sort();
            run.schema_defaults.dedup();
            run.budget = partial["budget"].clone();
            partials.push(serde_json::from_value(partial["rows"].clone()).map_err(internal)?);
        }
        run.rows = shape.merge(partials).map_err(internal)?;
        let counters = serde_json::to_value(self.fragments.counters()).map_err(internal)?;
        super::debug::result_cache(counters.clone());
        run.planner = json!({"kind":shape.kind,"result_cache":counters,"successful_native_statements":statements,
            "keyword_counts":{"applies":count_plan.is_some(),"groups":counted_groups,"rows":counted_rows,"parts":counted_parts},
            "partial_bytes":decoded_bytes,"parts":parts.len(),
            "range_files":range_fetch.range_files,"resident_files":range_fetch.resident_files,
            "range_fetched_bytes":range_fetch.range_fetched_bytes,"whole_fetched_bytes":range_fetch.whole_fetched_bytes,
            "range_fallbacks":range_fetch.range_fallbacks});
        Ok(Some(run))
    }

    /// Lab warm runs model moving ingest windows rather than static locator hits.
    #[cfg(any(test, feature = "part-lab"))]
    pub fn clear_locator_cache(&self) {
        self.locator_cache.lock().expect("locator cache").clear();
    }

    /// The narrow locator over one chunk: the instants of its newest page
    /// rows (at most the page size), canonical for an exact time fence.
    /// `None` when the chunk cannot be located cheaply (too many instants, or
    /// the plan does not fit), so the caller reads it full-width.
    async fn locate(
        &self,
        selection: &Selection,
        locator: &CompiledQuery,
        fence: SourceTimeFence<'_>,
        cursor: Option<(&str, &str)>,
    ) -> QueryResult<Option<Located>> {
        let context = super::fragment_cache::CONTEXT.try_with(Clone::clone).ok().flatten();
        // A selection narrowed from a window selection holds no leases of its
        // own (NAN-3155); it is located as one chunk, uncached per part.
        let Some(context) = context.filter(|_| !selection._leases.is_empty()) else { return self.locate_chunk(selection, locator, fence, cursor).await };
        if locator.limit > planner::MAX_EXACT_FENCE_TIMES { return Ok(None); }
        let from = rfc3339_us(fence.start)?;
        // NAN-4280: a fence inclusive at the window end still admits only
        // what the half-open compiled bound does, so the key's last instant
        // is the compiled last µs, never the end itself (two windows ending
        // 1µs apart would otherwise share a key over a part ending there).
        let to = (rfc3339_us(fence.end)? - i64::from(!fence.end_inclusive)).min(compiled_window_us(locator)?.1);
        let mut merged = Located { statements: 0, times: Vec::new(), cache_hit: true, engine_seconds: 0.0, storage_rows: 0, storage_bytes: 0 };
        let mut times = BTreeSet::new();
        for part in &selection.parts {
            let key = context.key(&self.settings.tenant_id, part, from, to);
            if let Some(cached) = self.fragments.get(&key) {
                times.extend(cached);
                continue;
            }
            let mut keys = BTreeSet::new();
            for lease in &selection._leases {
                if let Some(record) = lease.records.get(&part.part_id) {
                    for index in 0..record.files.data.len() {
                        keys.insert(self.fetcher.file_uri(part, record, PartFile::Data(index)).map_err(internal)?);
                    }
                }
            }
            let objects = selection.manifest.objects.iter().filter(|object| keys.contains(&object.event_object_key)).cloned().collect::<Vec<_>>();
            if objects.is_empty() { return Err(internal("part locator selection has no files")); }
            let mut tenant = selection.tenant.clone();
            let cache = tenant.snapshot_cache.as_mut().ok_or_else(|| internal("part locator requires leased files"))?;
            cache.objects.retain(|key, _| keys.contains(key));
            let mut paths = cache.objects.values().map(|object| object.path.to_string_lossy().into_owned()).collect::<Vec<_>>();
            cache.source_spec = planner::local_path_spec(&mut paths).map_err(map_plan_error)?;
            cache.bytes = cache.objects.values().map(|object| object.bytes).sum();
            let one = Selection {
                parts: vec![part.clone()],
                manifest: SourceManifest::from_objects(self.settings.tenant_id.clone(), objects),
                tenant,
                candidates: selection.candidates.as_ref().map(|blocks| blocks.iter().filter(|block| keys.contains(&block.event_object_key)).cloned().collect()),
                field_types: selection.field_types.clone(), evidence: Default::default(),
                object_times: selection.object_times.iter().filter(|(key, _)| keys.contains(*key)).map(|(k, v)| (k.clone(), *v)).collect(),
                _leases: Vec::new(),
            };
            let Some(located) = self.locate_chunk(&one, locator,
                SourceTimeFence { start: fence.start, end: fence.end, end_inclusive: fence.end_inclusive, exact_times: None }, cursor).await? else { return Ok(None) };
            self.fragments.insert(key, part.part_id.clone(), located.times.clone());
            times.extend(located.times);
            merged.cache_hit = false;
            merged.statements += located.statements;
            merged.engine_seconds += located.engine_seconds;
            merged.storage_rows += located.storage_rows;
            merged.storage_bytes += located.storage_bytes;
        }
        // Per-part top K includes every timestamp that can reach global top K.
        // Keep all ties; the payload query applies the UID tie sort and limit.
        merged.times = times.into_iter().rev().take(locator.limit).collect();
        Ok(Some(merged))
    }

    async fn locate_chunk(
        &self,
        selection: &Selection,
        locator: &CompiledQuery,
        fence: SourceTimeFence<'_>,
        cursor: Option<(&str, &str)>,
    ) -> QueryResult<Option<Located>> {
        if locator.limit > planner::MAX_EXACT_FENCE_TIMES {
            return Ok(None);
        }
        let key = LocatorKey {
            selection_identity: locator_selection_identity(&selection.manifest, selection.candidates.as_deref()),
            // Typed missing-column defaults can change with the read schema
            // even when the selected older files and SQL text do not.
            sql: format!("{}\n{:?}\n{:?}", locator.sql, locator.required_columns, locator.projected_scan_columns),
            limit: locator.limit,
            start: fence.start.to_owned(),
            end: fence.end.to_owned(),
            end_inclusive: fence.end_inclusive,
            cursor: cursor.map(|(time, uid)| (time.to_owned(), uid.to_owned())),
        };
        // NAN-3715: a probe neither reads nor writes the locator cache (its
        // timing must include the locate statement; its knobs may differ).
        let probe = crate::perf_overrides::in_probe();
        if let Some(times) = (!probe).then(|| self.locator_cache.lock().expect("locator cache").iter()
            .find(|(cached, _)| cached == &key).map(|(_, hits)| hits.clone())).flatten() {
            return Ok(Some(Located { statements: 0, times: times.times, cache_hit: true, engine_seconds: 0.0, storage_rows: 0, storage_bytes: 0 }));
        }
        let planned = match cursor {
            Some((time, event_uid)) => planner::plan_broad_log_query_with_candidates_tail_time_and_cursor(
                &selection.tenant,
                &selection.manifest,
                locator,
                selection.candidates.as_deref(),
                None,
                Some(fence),
                SourceCursorFence { time, event_uid },
            ),
            None => planner::plan_broad_log_query_with_candidates_tail_and_time(
                &selection.tenant,
                &selection.manifest,
                locator,
                selection.candidates.as_deref(),
                None,
                Some(fence),
            ),
        };
        let plan = match planned {
            Ok(plan) => plan,
            Err(planner::QueryPlanError::BudgetRejected { .. }) => return Ok(None),
            Err(error) => return Err(map_plan_error(error)),
        };
        let output = match self.run(plan).await {
            Ok(output) => output,
            Err(error) if memory_exhausted(&error) => return Ok(None),
            Err(crate::executor::ExecutorError::LaneWaitTimeout) => {
                return Err(PartQueryError::Unavailable("all query lanes are busy".to_string()))
            }
            Err(error) => return Err(map_executor_error(error)),
        };
        let mut times = BTreeSet::new();
        for row in decode_rows(&output.data)? {
            let raw = row
                .get("__nano_locator_time")
                .and_then(Value::as_str)
                .ok_or_else(|| internal("locator omitted event time"))?;
            let time = planner::exact_fence_time(raw).ok_or_else(|| internal("locator returned an invalid event time"))?;
            times.insert(time);
        }
        let times = times.into_iter().collect::<Vec<_>>();
        if !probe {
            let mut cache = self.locator_cache.lock().expect("locator cache");
            cache.push_back((key, LocatorHits { times: times.clone() }));
            while cache.len() > MAX_LOCATOR_RESULTS || cache.iter().map(|(key, hits)| locator_entry_bytes(key, hits)).sum::<usize>() > MAX_LOCATOR_CACHE_BYTES {
                cache.pop_front();
            }
        }
        Ok(Some(Located {
            statements: 1,
            times,
            cache_hit: false,
            engine_seconds: output.elapsed.as_secs_f64(),
            storage_rows: output.storage_rows_read,
            storage_bytes: output.storage_bytes_read,
        }))
    }
}

/// NAN-3155: one two-pass execution's rows (final order, identity columns
/// stripped) and native work.
pub(crate) struct TwoPassRun {
    pub rows: Vec<Value>,
    pub statements: usize,
    pub narrow_rows: usize,
    pub engine_seconds: f64,
    pub storage_rows: u64,
    pub storage_bytes: u64,
    pub budget: Option<planner::QueryBudget>,
    pub temporary_aliases: BTreeSet<String>,
    pub schema_defaults: Vec<String>,
    pub payload_bytes: u64,
}

impl PartQueryEngine {
    /// Bind `compiled` to `selection` under the optional chunk fence and
    /// cursor (the same planner entry points the one-pass paths use).
    fn plan_fenced(
        selection: &Selection, compiled: &CompiledQuery, fence: Option<SourceTimeFence<'_>>, cursor: Option<(&str, &str)>,
    ) -> std::result::Result<NativeQueryPlan, planner::QueryPlanError> {
        match (fence, cursor) {
            (None, cursor) => match cursor {
                Some((time, event_uid)) => planner::plan_broad_log_query_with_candidates_tail_time_and_cursor(
                    &selection.tenant, &selection.manifest, compiled, selection.candidates.as_deref(), None, None,
                    SourceCursorFence { time, event_uid }),
                None => planner::plan_broad_log_query_with_candidates_and_tail(
                    &selection.tenant, &selection.manifest, compiled, selection.candidates.as_deref(), None),
            },
            (Some(fence), Some((time, event_uid))) => planner::plan_broad_log_query_with_candidates_tail_time_and_cursor(
                &selection.tenant, &selection.manifest, compiled, selection.candidates.as_deref(), None, Some(fence),
                SourceCursorFence { time, event_uid }),
            (Some(fence), None) => planner::plan_broad_log_query_with_candidates_tail_and_time(
                &selection.tenant, &selection.manifest, compiled, selection.candidates.as_deref(), None, Some(fence)),
        }
    }

    /// NAN-3155: run a row query as a narrow identity pass plus a payload
    /// fetch of exactly those rows (see [`super::two_pass`]). `Ok(None)`:
    /// the caller runs the one-pass statement (a pass did not fit its
    /// budget, or the passes disagreed). Rows come back in the narrow pass's
    /// order, which is the statement's own final order.
    pub(crate) async fn run_two_pass(
        &self,
        selection: &Selection,
        two: &super::two_pass::TwoPass,
        fence: Option<SourceTimeFence<'_>>,
        cursor: Option<(&str, &str)>,
    ) -> QueryResult<Option<TwoPassRun>> {
        use super::two_pass::{self, RowId};
        let narrow = if cursor.is_some() { &two.narrow_cursor } else { &two.narrow };
        let planned = Self::plan_fenced(selection, narrow, fence, cursor);
        let plan = match planned {
            Ok(plan) => plan,
            Err(planner::QueryPlanError::BudgetRejected { .. }) => return Ok(None),
            Err(error) => return Err(map_plan_error(error)),
        };
        let mut run = TwoPassRun {
            rows: Vec::new(), statements: 0, narrow_rows: 0, engine_seconds: 0.0, storage_rows: 0, storage_bytes: 0,
            budget: Some(plan.budget.clone()), temporary_aliases: BTreeSet::new(), schema_defaults: Vec::new(), payload_bytes: 0,
        };
        let output = match self.run(plan).await {
            Ok(output) => output,
            Err(error) if memory_exhausted(&error) => return Ok(None),
            Err(crate::executor::ExecutorError::LaneWaitTimeout) =>
                return Err(PartQueryError::Unavailable("all query lanes are busy".to_string())),
            Err(error) => return Err(map_executor_error(error)),
        };
        run.statements += 1;
        run.engine_seconds += output.elapsed.as_secs_f64();
        run.storage_rows += output.storage_rows_read;
        run.storage_bytes += output.storage_bytes_read;
        let integer = |value: &Value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok()));
        let mut ids = Vec::new();
        let mut times = Vec::new();
        for row in decode_rows(&output.data)? {
            let path = row.get(two_pass::NARROW_PATH).and_then(Value::as_str).ok_or_else(|| internal("narrow pass omitted the row path"))?;
            let number = row.get(two_pass::NARROW_ROW).and_then(integer).ok_or_else(|| internal("narrow pass omitted the row number"))?;
            let time = row.get(two_pass::NARROW_TIME).and_then(Value::as_str).and_then(planner::exact_fence_time)
                .ok_or_else(|| internal("narrow pass returned an invalid event time"))?;
            ids.push(RowId { path: path.to_string(), row: number });
            times.push(time);
        }
        run.narrow_rows = ids.len();
        if ids.is_empty() {
            return Ok(Some(run));
        }
        if ids.len() > two_pass::MAX_TWO_PASS_ROWS {
            // A boundary instant shared by too many rows (WITH TIES).
            return Ok(None);
        }
        let known = ids.iter().cloned().collect::<BTreeSet<_>>();
        if known.len() != ids.len() {
            tracing::warn!("narrow pass returned a row twice; running the one-pass statement");
            return Ok(None);
        }
        // Payload statements: the identities, plus an exact-instant fence
        // (Parquet statistics then skip every row group without a result
        // row). Past the fence's size bound, rows are fetched in batches of
        // whole instants and merged in the event order.
        let mut by_time: BTreeMap<&str, Vec<RowId>> = BTreeMap::new();
        for (id, time) in ids.iter().zip(&times) {
            by_time.entry(time.as_str()).or_default().push(id.clone());
        }
        let batches = by_time.into_iter().collect::<Vec<_>>();
        let batches = batches.chunks(two_pass::MAX_PAYLOAD_ROWS).collect::<Vec<_>>();
        if batches.len() > 1 && !two.event_order {
            return Ok(None);
        }
        let (start, end, end_inclusive) = match fence {
            Some(fence) => (fence.start.to_string(), fence.end.to_string(), fence.end_inclusive),
            None => (two.payload.start.clone(), two.payload.end.clone(), true),
        };
        // The payload reads only the files holding its rows.
        let payload_selection = selection.only_paths(&ids.iter().map(|id| id.path.clone()).collect())?;
        if payload_selection.manifest.objects.is_empty() {
            return Ok(None);
        }
        let selection = &payload_selection;
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        for batch in &batches {
            let batch_times = batch.iter().map(|(time, _)| time.to_string()).collect::<Vec<_>>();
            let batch_ids = batch.iter().flat_map(|(_, ids)| ids.iter().cloned()).collect::<Vec<_>>();
            let payload_fence = SourceTimeFence { start: &start, end: &end, end_inclusive, exact_times: Some(&batch_times) };
            let planned = Self::plan_fenced(selection, &two.payload, Some(payload_fence), cursor);
            let mut plan = match planned {
                Ok(plan) => plan,
                Err(planner::QueryPlanError::BudgetRejected { .. }) => return Ok(None),
                Err(error) => return Err(map_plan_error(error)),
            };
            plan.params.push((two_pass::ROW_IDS_PARAM.to_string(), two_pass::ids_param(&batch_ids)));
            run.temporary_aliases.extend(plan.temporary_aliases.iter().cloned());
            run.schema_defaults = plan.schema_defaults.clone();
            let output = match self.run(plan).await {
                Ok(output) => output,
                Err(error) if memory_exhausted(&error) => return Ok(None),
                Err(crate::executor::ExecutorError::LaneWaitTimeout) =>
                    return Err(PartQueryError::Unavailable("all query lanes are busy".to_string())),
                Err(error) => return Err(map_executor_error(error)),
            };
            run.statements += 1;
            run.engine_seconds += output.elapsed.as_secs_f64();
            run.storage_rows += output.storage_rows_read;
            run.storage_bytes += output.storage_bytes_read;
            run.payload_bytes += output.data.len() as u64;
            for mut row in decode_rows(&output.data)? {
                let object = row.as_object_mut().ok_or_else(|| internal("payload row is not an object"))?;
                let path = object.remove(planner::ROW_PATH_COLUMN);
                let number = object.remove(planner::ROW_NUMBER_COLUMN);
                let id = path.as_ref().and_then(Value::as_str).zip(number.as_ref().and_then(integer))
                    .map(|(path, row)| RowId { path: path.to_string(), row });
                match id {
                    Some(id) if known.contains(&id) && seen.insert(id.clone()) => rows.push(row),
                    _ => {
                        tracing::warn!("payload pass returned a row the narrow pass did not; running the one-pass statement");
                        return Ok(None);
                    }
                }
            }
        }
        if batches.len() > 1 {
            // Each batch is in event order; so is their merge (time, then
            // uid, descending; ClickHouse sorts NULL last either way).
            let key = |row: &Value, field: &str| row.get(field).and_then(Value::as_str).map(str::to_string);
            rows.sort_by(|left, right| {
                let order = |a: Option<String>, b: Option<String>| match (a, b) {
                    (Some(a), Some(b)) => b.cmp(&a),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                };
                order(key(left, "time"), key(right, "time")).then_with(|| order(key(left, "metadata.uid"), key(right, "metadata.uid")))
            });
            rows.truncate(two.limit);
        }
        // The payload re-applies the final order and limit over the narrow
        // superset; it must return exactly min(limit, superset) rows.
        if rows.len() != ids.len().min(two.limit) {
            tracing::warn!(narrow = ids.len(), payload = rows.len(), "payload pass lost narrow-pass rows; running the one-pass statement");
            return Ok(None);
        }
        run.rows = rows;
        Ok(Some(run))
    }
}

/// One narrow read's result and actual native work. Cached results cost no
/// native scan; empty results still account for the work that proved absence.
#[derive(Clone)]
struct LocatorHits {
    times: Vec<String>,
}

struct Located {
    statements: usize,
    times: Vec<String>,
    cache_hit: bool,
    engine_seconds: f64,
    storage_rows: u64,
    storage_bytes: u64,
}

/// Bind compiled `logs` SQL to a selection, with the reader's planner.
pub fn plan_logs(
    selection: &Selection,
    compiled: &CompiledQuery,
    cursor: Option<(&str, &str)>,
) -> QueryResult<NativeQueryPlan> {
    match cursor {
        Some((time, event_uid)) => planner::plan_broad_log_query_with_candidates_tail_time_and_cursor(
            &selection.tenant,
            &selection.manifest,
            compiled,
            selection.candidates.as_deref(),
            None,
            None,
            SourceCursorFence { time, event_uid },
        ),
        None => planner::plan_broad_log_query_with_candidates_and_tail(
            &selection.tenant,
            &selection.manifest,
            compiled,
            selection.candidates.as_deref(),
            None,
        ),
    }
    .map_err(map_plan_error)
}

/// NAN-3133: errors after which a request that read a sparse file reruns on
/// whole files: only a Parquet decode failure, the way a read of a hole
/// surfaces ([`super::range_fetch::is_hole_read`]). Type, identifier,
/// budget, memory and availability errors are answered as they are.
fn reruns_whole(error: &PartQueryError) -> bool {
    match error {
        PartQueryError::QueryFailed(text) | PartQueryError::Internal(text) => super::range_fetch::is_hole_read(text),
        _ => false,
    }
}

/// The footer-summary cache key of a leased data file.
fn summary_key(local: &super::fetch::LocalFile) -> String {
    if local.sparse { format!("{}#ranged", local.sha256) } else { local.sha256.clone() }
}

fn record_lease(evidence: &mut SelectionEvidence, local: &LocalParts) {
    if let Some(lease) = &local.lease {
        evidence.cache_hits += lease.hits();
        evidence.cache_misses += lease.misses();
        evidence.cache_fetched_bytes += lease.fetched_bytes();
    }
}

/// Decode JSONEachRow, strip planner aliases, apply offset/limit and report
/// whether the sentinel row proved more rows (the reader's page contract).
pub fn page_rows(data: &[u8], plan: &NativeQueryPlan, offset: usize, limit: usize) -> QueryResult<(Vec<Value>, bool)> {
    let mut rows = decode_rows(data)?;
    for row in &mut rows {
        if let Some(object) = row.as_object_mut() {
            for alias in &plan.temporary_aliases {
                object.remove(alias);
            }
        }
    }
    let has_more = rows.len() > offset.saturating_add(limit);
    Ok((rows.into_iter().skip(offset).take(limit).collect(), has_more))
}

pub fn decode_rows(data: &[u8]) -> QueryResult<Vec<Value>> {
    data.split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|error| internal(format!("native result JSON is invalid: {error}"))))
        .collect()
}

pub fn rfc3339_us(value: &str) -> QueryResult<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|time| time.timestamp_micros())
        .map_err(|_| PartQueryError::Invalid(format!("{value} is not an RFC3339 timestamp")))
}

/// The compiled query's event-time window as INCLUSIVE µs `(first, last)`.
///
/// NAN-4280: the compiled bound is half-open (`time >= start AND time <
/// end`), so the last instant it admits is `end - 1µs`. Every consumer
/// (part selection, membership, fragment-cache keys, coverage checks) works
/// in inclusive µs; the conversion happens here, once.
pub fn compiled_window_us(compiled: &CompiledQuery) -> QueryResult<(i64, i64)> {
    let (first, end) = (rfc3339_us(&compiled.start)?, rfc3339_us(&compiled.end)?);
    Ok((first, end.saturating_sub(1)))
}

/// The compiled bound's own literals, `[start, end)` µs, for the fast-path
/// recognizers that match them against the SQL text.
pub fn compiled_bound_us(compiled: &CompiledQuery) -> QueryResult<(i64, i64)> {
    Ok((rfc3339_us(&compiled.start)?, rfc3339_us(&compiled.end)?))
}

pub(super) fn validate_broad_npl(request: &BroadNplRequest, tenant_id: &str) -> QueryResult<()> {
    if request.tenant_id != tenant_id {
        return Err(PartQueryError::Invalid("request tenant is not this process's tenant".to_string()));
    }
    if !matches!(request.dataset.as_str(), "logs" | "risk")
        || request.query.is_empty()
        || request.query.len() > MAX_QUERY_TEXT_BYTES
        || request.limit == 0
        || request.limit > MAX_RESULT_LIMIT
        || request.offset > MAX_RESULT_LIMIT
        || request.offset.saturating_add(request.limit) > MAX_RESULT_LIMIT
        || request.cursor_time.is_some() != request.cursor_event_uid.is_some()
        || request.cursor_time.is_some() && (request.dataset != "logs" || request.offset != 0)
        || request
            .cursor_event_uid
            .as_ref()
            .is_some_and(|uid| uid.is_empty() || uid.len() > 2_048 || uid.chars().any(char::is_control))
        || request.deny_source_types.iter().any(|source| source.is_empty() || source.len() > 512)
    {
        return Err(PartQueryError::Invalid(
            "broad nPL request violates its dataset, query, page, or source-scope bound".to_string(),
        ));
    }
    Ok(())
}

/// Attestable lowercase paths (`parts::provenance::LOWERCASED_AT_REST`) that
/// the query text names and the snapshot types as string leaves (the
/// compiler refuses any other path).
fn attestable_paths_named(query: &str, field_types: &BTreeMap<String, String>) -> BTreeSet<String> {
    crate::parts::provenance::LOWERCASED_AT_REST
        .iter()
        .filter(|path| query.contains(**path) && field_types.get(**path).map(String::as_str) == Some("string"))
        .map(|path| (*path).to_string())
        .collect()
}

/// `named` intersected with every record's attested set (no records: none).
fn common_lowercase_paths<'a>(named: BTreeSet<String>, records: impl IntoIterator<Item = &'a [String]>) -> Vec<String> {
    let mut common = named;
    let mut any = false;
    for attested in records {
        any = true;
        common.retain(|path| attested.contains(path));
    }
    if any { common.into_iter().collect() } else { Vec::new() }
}

async fn run_compiler(path: &std::path::Path, request: &CompilerRequest<'_>, timeout_seconds: u64) -> QueryResult<CompiledQuery> {
    let input = serde_json::to_vec(request).map_err(internal)?;
    // H02: retain the GNU compiler's bytes as the identity pin, while native
    // execution goes through its static, package-bound bundled-loader shim.
    let launch = nanosiem_lake_cell::worker_launch::compiler_launch_path(path)
        .map_err(|_| internal("native compiler launch denied"))?;
    let mut child = tokio::process::Command::new(launch)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| internal(format!("compiler start failed: {error}")))?;
    child
        .stdin
        .take()
        .context("compiler stdin is unavailable")
        .map_err(internal)?
        .write_all(&input)
        .await
        .map_err(|error| internal(format!("compiler input write failed: {error}")))?;
    let output = tokio::time::timeout(Duration::from_secs(timeout_seconds.max(1)), child.wait_with_output())
        .await
        .map_err(|_| internal("compiler timed out"))?
        .map_err(|error| internal(format!("compiler wait failed: {error}")))?;
    if !output.status.success() {
        return Err(PartQueryError::Invalid(String::from_utf8_lossy(&output.stderr).trim().to_string()));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| internal(format!("compiler output failed: {error}")))
}

#[cfg(test)]
#[path = "compiler_spawn_bench.rs"]
mod compiler_spawn_bench;

#[cfg(test)]
mod nan4157_window_preselect_tests {
    use super::*;

    fn pivot() -> WindowPreselect {
        WindowPreselect { uses_entities: true, density_over_selective: true, ..Default::default() }
    }

    /// NAN-4157: a 168 h hash pivot whose density estimate fills the page
    /// in the newest chunk never leases the whole window before chunk 1.
    #[test]
    fn density_filled_first_chunk_skips_the_whole_window_preselect() {
        assert!(!window_preselect(WindowPreselect { density_fills_first_chunk: true, ..pivot() }));
        assert!(!window_preselect(WindowPreselect { density_fills_first_chunk: true, token_preselect: true, ..pivot() }));
    }

    #[test]
    fn other_pivots_keep_their_preselect_decision() {
        // A sparse pivot (page not filled in chunk 1) may still be read whole.
        assert!(window_preselect(pivot()));
        // The NAN-3169 override off: a selective preselect may be read whole.
        assert!(window_preselect(WindowPreselect { density_fills_first_chunk: true, density_over_selective: false, ..pivot() }));
        // A token-selective keyword walk.
        assert!(window_preselect(WindowPreselect { token_preselect: true, uses_entities: false, ..pivot() }));
        // Dense values and the one-shot hash window never preselect.
        assert!(!window_preselect(WindowPreselect { dense: true, ..pivot() }));
        assert!(!window_preselect(WindowPreselect { whole_hash_window: true, ..pivot() }));
        // No index hint: nothing to preselect with.
        assert!(!window_preselect(WindowPreselect { uses_entities: false, ..pivot() }));
    }
}

/// NAN-3720: interactive searches win over background native work. A slot
/// model with the engine's admission semaphore and virtual time, so the
/// latency bound is exact rather than a flaky wall-clock measurement.
#[cfg(test)]
mod nan3720_background_yield_tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use tokio::time::{sleep, Instant};

    const SLOTS: usize = 2;
    const SEARCH: Duration = Duration::from_secs(1);
    /// One batch of an incremental prewarm (statement time).
    const BATCH: Duration = Duration::from_secs(5);

    /// A search admitted like `PartQueryEngine::admit`, doing `work`: its
    /// latency is the admission wait plus its own work.
    async fn search(admission: Arc<Semaphore>, work: Duration) -> Duration {
        let started = Instant::now();
        let _slot = admission.acquire_owned().await.unwrap();
        sleep(work).await;
        started.elapsed()
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Background { None, Queued, Yielding }

    /// Both slots busy (searches ending at 1 s and 3 s), background batches
    /// asking for a slot at 50 ms, and a late search arriving at 100 ms: k6
    /// meeting an incremental prewarm after a merge commit. Returns the late
    /// search's latency and whether a background batch ran while a search
    /// held a slot.
    async fn scenario(mode: Background) -> (Duration, bool) {
        let admission = Arc::new(Semaphore::new(SLOTS));
        let a = tokio::spawn(search(admission.clone(), SEARCH));
        let b = tokio::spawn(search(admission.clone(), 3 * SEARCH));
        tokio::task::yield_now().await;
        let overlapped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let background = {
            let (admission, overlapped) = (admission.clone(), overlapped.clone());
            tokio::spawn(async move {
                sleep(Duration::from_millis(50)).await;
                for _ in 0..3 {
                    let _slot = match mode {
                        Background::None => return,
                        // Before NAN-3720: a slot like a request's, FIFO.
                        Background::Queued => admission.clone().acquire_owned().await.unwrap(),
                        Background::Yielding => match wait_idle_permit(&admission, SLOTS, BACKGROUND_IDLE_POLL, BACKGROUND_IDLE_WAIT).await {
                            Some(slot) => slot,
                            None => return,
                        },
                    };
                    if admission.available_permits() < SLOTS - 1 {
                        overlapped.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    sleep(BATCH).await;
                }
            })
        };
        sleep(Duration::from_millis(100)).await;
        let late = search(admission.clone(), SEARCH).await;
        a.await.unwrap();
        b.await.unwrap();
        background.await.unwrap();
        (late, overlapped.load(std::sync::atomic::Ordering::SeqCst))
    }

    #[tokio::test(start_paused = true)]
    async fn a_search_never_waits_behind_background_batches() {
        let (alone, _) = scenario(Background::None).await;
        assert!(alone >= Duration::from_millis(1_900) && alone <= Duration::from_millis(1_901), "{alone:?}");
        // Before: the late search waited out a whole background batch.
        let (queued, queued_overlap) = scenario(Background::Queued).await;
        assert!(queued >= alone + Duration::from_secs(2), "{queued:?} vs {alone:?}");
        assert!(queued_overlap);
        // Now: within 1% of its latency with no background work at all,
        // and no background batch ran while a search held a slot.
        let (yielded, overlap) = scenario(Background::Yielding).await;
        assert!(yielded <= alone.mul_f64(1.01), "{yielded:?} vs {alone:?}");
        assert!(!overlap, "background ran beside a search");
    }

    #[tokio::test(start_paused = true)]
    async fn background_runs_when_idle_and_gives_up_under_sustained_load() {
        let admission = Arc::new(Semaphore::new(SLOTS));
        // Idle engine: granted at once, and it holds a real slot.
        let slot = wait_idle_permit(&admission, SLOTS, BACKGROUND_IDLE_POLL, BACKGROUND_IDLE_WAIT).await.unwrap();
        assert_eq!(admission.available_permits(), SLOTS - 1);
        drop(slot);
        // A search running for longer than the wait: background gives up
        // (the pass stops; queries prove what it did not reach).
        let busy = admission.clone().acquire_owned().await.unwrap();
        let started = Instant::now();
        assert!(wait_idle_permit(&admission, SLOTS, BACKGROUND_IDLE_POLL, BACKGROUND_IDLE_WAIT).await.is_none());
        assert!(started.elapsed() >= BACKGROUND_IDLE_WAIT);
        // Freed mid-wait: granted within one poll of the search finishing.
        let waiter = tokio::spawn({
            let admission = admission.clone();
            async move {
                let started = Instant::now();
                wait_idle_permit(&admission, SLOTS, BACKGROUND_IDLE_POLL, BACKGROUND_IDLE_WAIT).await.map(|_| started.elapsed())
            }
        });
        sleep(Duration::from_secs(2)).await;
        drop(busy);
        let waited = waiter.await.unwrap().expect("granted once idle");
        assert!(waited <= Duration::from_secs(2) + BACKGROUND_IDLE_POLL, "{waited:?}");
        // Closed admission ends the wait.
        admission.close();
        assert!(wait_idle_permit(&admission, SLOTS, BACKGROUND_IDLE_POLL, BACKGROUND_IDLE_WAIT).await.is_none());
    }
}

#[cfg(test)]
mod nan3171_fine_run_tests {
    use super::*;

    #[test]
    fn fine_runs_over_the_budget_win_only_when_they_scan_less() {
        // Nothing offered, or more than the planner's fence bound.
        assert!(!use_fine_runs(0, (0, 0), (1 << 20, 1)));
        assert!(!use_fine_runs(10, (10_240, MAX_CANDIDATE_BLOCKS + 1), (1 << 20, 1)));
        // NAN-3032's budget is unchanged.
        assert!(use_fine_runs(FINE_RUN_BUDGET, (FINE_RUN_BUDGET as u64 * 1_024, FINE_RUN_BUDGET), (65_536, 1)));
        // Its winning one stays within the budget either way.
        assert!(use_fine_runs(97, (97 * 1_024, 97), (16 * 65_536, 1)));
        // The OR fence (NANO_LAKE_FENCE_SET=0) pays a term per block per row.
        // Live NAN-3171: ~164 single-block runs over a day against ~118
        // kept 8,192-row groups in ~61 ranges.
        assert!(fine_beats_coarse((164 * 1_024, 164), (118 * 8_192, 61), false));
        // NAN-3032's losing probe: 350 runs over one hour of whole groups.
        assert!(!fine_beats_coarse((350 * 1_024, 350), (16 * 65_536, 1), false));
        // NAN-3171's narrow-row fixture: 178 runs lost to 26 whole files
        // read with no fence (0.247 s vs 0.092 s execute).
        assert!(!fine_beats_coarse((178 * 1_024, 178), (26 * 32_768, 0), false));
    }

    /// NAN-3179: the set fence costs the same per row for any block count,
    /// so fewer rows win unless the saving is under the fence's own cost
    /// against an unfenced read.
    /// NAN-4211: exact runs spread over thousands of files are declined (the
    /// coarse selection reads them whole); a few files keep their fine runs.
    #[test]
    fn fine_fence_declined_when_it_would_outgrow_the_statement() {
        let t0 = 1_790_640_000_000_000_i64;
        let selection = |files: u64| {
            let key = |file: u64| format!("s3://bucket/table/data/2026/10/{file:05}-0123456789abcdef.parquet");
            let objects = (0..files)
                .map(|file| ManifestObject { event_object_key: key(file), event_object_version: "v".into(), event_object_bytes: 900,
                    rows: 100_000, available_paths: vec!["time".into()].into(), field_types: BTreeMap::new(),
                    column_compressed_bytes: BTreeMap::new() })
                .collect::<Vec<_>>();
            let blocks = (0..files)
                .flat_map(|file| (0..3_u64).map(move |run| (file, run)))
                .map(|(file, run)| CandidateBlock { event_object_key: key(file), event_object_bytes: 900,
                    row_start: run * 4_096, row_end: run * 4_096 + 1_024, max_time_ms: None,
                    time_range_us: Some((t0 + (file * 3 + run) as i64 * 60_000_000, t0 + (file * 3 + run) as i64 * 60_000_000 + 2_000_000)) })
                .collect::<Vec<_>>();
            (blocks, objects)
        };
        let (blocks, objects) = selection(40);
        assert!(fine_fence_fits(&blocks, &objects));
        let (blocks, objects) = selection(1_365);
        assert!(blocks.len() <= MAX_CANDIDATE_BLOCKS);
        assert!(!fine_fence_fits(&blocks, &objects));
    }

    #[test]
    fn set_fence_costs_runs_by_rows_not_terms() {
        assert!(fine_beats_coarse((164 * 1_024, 164), (118 * 8_192, 61), true));
        assert!(fine_beats_coarse((350 * 1_024, 350), (16 * 65_536, 1), true));
        assert!(fine_beats_coarse((178 * 1_024, 178), (26 * 32_768, 0), true));
        assert!(fine_beats_coarse((4_000 * 1_024, 4_000), (5_000 * 1_024, 600), true));
        // Fenced rows near the unfenced count lose to the unfenced read.
        assert!(!fine_beats_coarse((1_000_000, 900), (1_050_000, 0), true));
        // Equal rows, both fenced: no gain, keep the coarse selection.
        assert!(!fine_beats_coarse((65_536, 64), (65_536, 1), true));
    }
}

#[cfg(test)]
mod nan3154_lowercase_tests {
    use super::*;

    /// Raw equality only on a path the query names, the snapshot types as a
    /// string, and EVERY part's signed record attests (a legacy or adopted
    /// part's empty set empties the intersection).
    #[test]
    fn attested_paths_are_named_typed_and_common_to_every_part() {
        let types = BTreeMap::from([
            ("metadata.log_source".to_string(), "string".to_string()),
            ("src_endpoint.ip".to_string(), "string".to_string()),
            ("user.name".to_string(), "string".to_string()),
        ]);
        let named = attestable_paths_named(r#"metadata.log_source="X" user.name="bob" dst_endpoint.ip="1.2.3.4""#, &types);
        // user.name is never attested; dst_endpoint.ip is not a snapshot leaf.
        assert_eq!(named.iter().map(String::as_str).collect::<Vec<_>>(), vec!["metadata.log_source"]);
        let v2 = crate::parts::provenance::LOWERCASED_AT_REST.iter().map(|path| path.to_string()).collect::<Vec<_>>();
        assert_eq!(common_lowercase_paths(named.clone(), [v2.as_slice(), v2.as_slice()]), vec!["metadata.log_source"]);
        assert!(common_lowercase_paths(named.clone(), [v2.as_slice(), &[][..]]).is_empty(), "an adopted part");
        assert!(common_lowercase_paths(named, std::iter::empty::<&[String]>()).is_empty(), "no parts");
    }
}

#[cfg(test)]
mod admission_class_tests {
    use super::*;

    #[test]
    fn classes_follow_the_route_and_companion_ids() {
        assert_eq!(RequestClass::of("0192-aaaa", true), RequestClass::Point);
        assert_eq!(RequestClass::of("0192-aaaa-hist", false), RequestClass::Companion);
        assert_eq!(RequestClass::of("0192-aaaa-hist-rollup", false), RequestClass::Companion);
        assert_eq!(RequestClass::of("0192-aaaa", false), RequestClass::Primary);
        // NAN-4174: a primary over more than 24 h is wide; companions and
        // point lookups keep their class; a bad window is not wide.
        let (day, week) = (("2026-10-18T00:00:00Z", "2026-10-19T00:00:00Z"), ("2026-10-12T00:00:00Z", "2026-10-19T00:00:00Z"));
        assert_eq!(RequestClass::of_window("0192-aaaa", false, day.0, day.1), RequestClass::Primary);
        assert_eq!(RequestClass::of_window("0192-aaaa", false, week.0, week.1), RequestClass::Wide);
        assert_eq!(RequestClass::of_window("0192-aaaa-hist", false, week.0, week.1), RequestClass::Companion);
        assert_eq!(RequestClass::of_window("0192-aaaa", true, week.0, week.1), RequestClass::Point);
        assert_eq!(RequestClass::of_window("0192-aaaa", false, "x", week.1), RequestClass::Primary);
        assert_eq!((wide_permits(7), wide_permits(2), wide_permits(1)), (5, 1, 1));
        assert_eq!(companion_permits(1), 1);
        assert_eq!(companion_permits(2), 1);
        assert_eq!(companion_permits(4), 3);
    }

    #[tokio::test]
    async fn companions_never_take_the_last_slot_from_a_primary() {
        // Two slots: one companion runs, a second companion waits on the
        // gate, and a primary still gets the other slot at once.
        let slots = Arc::new(tokio::sync::Semaphore::new(2));
        let gate = Arc::new(tokio::sync::Semaphore::new(companion_permits(2)));
        let first_gate = gate.clone().try_acquire_owned().unwrap();
        let first_slot = slots.clone().try_acquire_owned().unwrap();
        assert!(gate.clone().try_acquire_owned().is_err(), "a second companion waits");
        let primary = slots.clone().try_acquire_owned();
        assert!(primary.is_ok(), "a primary is not shut out by companions");
        drop((first_gate, first_slot));
    }

    /// NAN-4174: on the 7-slot query role, five wide (7 d) searches running
    /// leave two slots that only short-window searches can take.
    #[tokio::test]
    async fn wide_searches_never_take_the_slots_kept_for_short_ones() {
        let slots = Arc::new(tokio::sync::Semaphore::new(7));
        let gate = Arc::new(tokio::sync::Semaphore::new(wide_permits(7)));
        let wide = (0..5).map(|_| (gate.clone().try_acquire_owned().unwrap(), slots.clone().try_acquire_owned().unwrap())).collect::<Vec<_>>();
        assert!(gate.clone().try_acquire_owned().is_err(), "a sixth wide search waits on the gate");
        let short = (0..2).map(|_| slots.clone().try_acquire_owned()).collect::<Vec<_>>();
        assert!(short.iter().all(Result::is_ok), "short searches still get a slot at once");
        drop((wide, short));
    }
}

#[cfg(test)]
mod membership_memo_tests {
    use super::*;
    use crate::parts::format::PartId;

    #[test]
    fn cached_parents_intersect_without_inventing_a_child_answer() {
        let mut memo = MembershipMemo::default();
        let part = PartId::new(1_790_000_000_000).unwrap();
        let (a, b, missing): (Arc<str>, Arc<str>, Arc<str>) = ("a".into(), "b".into(), "missing".into());
        assert_eq!(memo.candidate_buckets(&[missing.clone()], &part), None);
        memo.insert(a.clone(), part.clone(), [0, 300_000_000].into_iter().collect());
        memo.insert(b.clone(), part.clone(), [300_000_000, 600_000_000].into_iter().collect());
        assert_eq!(memo.candidate_buckets(&[a.clone(), missing.clone()], &part), Some([0, 300_000_000].into_iter().collect()));
        assert_eq!(memo.candidate_buckets(&[a.clone(), b.clone(), missing.clone()], &part), Some([300_000_000].into_iter().collect()));
        assert!(memo.get(&missing, &part).is_none());
        memo.insert(b.clone(), part.clone(), BTreeSet::new());
        assert_eq!(memo.candidate_buckets(&[a, b], &part), Some(BTreeSet::new()));
        assert_eq!(memo.candidate_buckets(&["a".into()], &PartId::new(1_790_000_000_001).unwrap()), None);
    }

    #[test]
    fn memo_byte_budget_handles_large_answers_and_replacement() {
        let mut memo = MembershipMemo::default();
        let part = PartId::new(1_790_000_000_000).unwrap();
        let key: Arc<str> = "large".into();
        memo.insert(key.clone(), part.clone(), (0..100_000).collect());
        assert!(memo.bytes > 3_000_000);
        memo.insert(key.clone(), part.clone(), BTreeSet::new());
        assert!(memo.bytes < 1024);
        for i in 0..20 { memo.insert(format!("large-{i}").into(), part.clone(), (0..100_000).collect()); }
        assert!(memo.bytes <= MAX_MEMBERSHIP_BYTES);
        assert!(memo.answers.len() < 20);
        let oversized: Arc<str> = "x".repeat(MAX_MEMBERSHIP_BYTES).into();
        memo.insert(oversized.clone(), part.clone(), BTreeSet::new());
        assert!(memo.get(&oversized, &part).is_none());
    }

    #[test]
    fn memo_answers_per_statement_and_part_and_stays_bounded() {
        let mut memo = MembershipMemo::default();
        let (a, b): (Arc<str>, Arc<str>) = ("stmt-a".into(), "stmt-b".into());
        let part = PartId::new(1_790_000_000_000).unwrap();
        memo.insert(a.clone(), part.clone(), [300_000_000_i64].into_iter().collect());
        // An empty answer (provably no match) is an answer, not a miss.
        memo.insert(b.clone(), part.clone(), BTreeSet::new());
        assert_eq!(memo.get(&a, &part).unwrap().len(), 1);
        assert!(memo.get(&b, &part).unwrap().is_empty());
        assert!(memo.get(&"stmt-c".into(), &part).is_none());
        for index in 0..(MAX_MEMBERSHIP_MEMO + 10) {
            memo.insert(format!("s{index}").into(), part.clone(), BTreeSet::new());
        }
        assert_eq!(memo.answers.len(), MAX_MEMBERSHIP_MEMO);
        assert_eq!(memo.order.len(), MAX_MEMBERSHIP_MEMO);
        assert!(memo.get(&a, &part).is_none(), "oldest answers are evicted first");
    }
}

#[cfg(test)]
mod prewarm_tests {
    use super::*;

    #[test]
    fn evidence_thread_lowers_cpu_and_io_priority() {
        std::thread::spawn(|| {
            lower_evidence_priority().unwrap();
            unsafe {
                let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
                assert_eq!(libc::getpriority(libc::PRIO_PROCESS, tid), crate::part_query::product_publish::ROLE_NICE);
                assert_eq!(libc::syscall(libc::SYS_ioprio_get, 1, tid) >> 13, 3);
            }
        }).join().unwrap();
    }

    #[tokio::test]
    async fn evidence_checks_every_query_lane_at_the_parse_boundary() {
        let primary = Arc::new(tokio::sync::Semaphore::new(2));
        let point = Arc::new(tokio::sync::Semaphore::new(POINT_PERMITS));
        let job = Arc::new(tokio::sync::Semaphore::new(1));
        for lane in [&primary, &point, &job] {
            let permit = lane.clone().acquire_owned().await.unwrap();
            let mut parses = 0;
            if evidence_lanes_idle(&primary, 2, &point, &job) { parses += 1; }
            assert_eq!(parses, 0, "a held query permit prevents a file parse");
            drop(permit);
            assert!(evidence_lanes_idle(&primary, 2, &point, &job));
        }
        point.close();
        assert!(!evidence_lanes_idle(&primary, 2, &point, &job));
    }

    #[test]
    fn evidence_startup_quiet_period() {
        assert!(!evidence_quiet_period_over(Duration::ZERO));
        assert!(!evidence_quiet_period_over(Duration::from_millis(59_999)));
        assert!(evidence_quiet_period_over(Duration::from_secs(60)));
    }

    #[tokio::test]
    async fn evidence_prewarm_yields_to_an_inflight_search_without_reserving_admission() {
        let admission = Arc::new(tokio::sync::Semaphore::new(2));
        let search = admission.clone().acquire_owned().await.unwrap();
        assert!(!evidence_prewarm_idle(&admission, 2));
        assert_eq!(admission.available_permits(), 1);
        drop(search);
        assert!(evidence_prewarm_idle(&admission, 2));
        assert_eq!(admission.available_permits(), 2, "parsing reserves no search slots");
        let cold_search = admission.clone().try_acquire_owned().unwrap();
        assert!(!evidence_prewarm_idle(&admission, 2));
        drop(cold_search);
    }

    #[test]
    fn optional_prewarm_stays_within_total_budget_and_skips_oversize() {
        let mut remaining = 512;
        assert!(!take_prewarm_budget(&mut remaining, 662));
        assert!(take_prewarm_budget(&mut remaining, 300));
        assert!(!take_prewarm_budget(&mut remaining, 300));
        assert!(take_prewarm_budget(&mut remaining, 212));
        assert_eq!(remaining, 0);
    }

    #[test]
    fn ordinary_scans_do_not_serialize_on_the_large_lane() {
        assert!(!needs_large_lane(17 * 1024 * 1024));
        assert!(!needs_large_lane(LARGE_SCAN_BYTES));
        assert!(needs_large_lane(LARGE_SCAN_BYTES + 1));
        assert!(needs_large_lane(u64::MAX));
    }

    #[test]
    fn prewarm_batches_split_by_kind_count_and_bytes() {
        let mib = 1024 * 1024;
        // Newest first: two remote, one local, then remote files that exceed
        // the byte bound together.
        let batches = prewarm_batches(vec![
            (1, mib, false),
            (2, mib, false),
            (3, mib, true),
            (4, 200 * mib, false),
            (5, 200 * mib, false),
        ]);
        assert_eq!(batches, vec![(vec![1, 2], false), (vec![3], true), (vec![4], false), (vec![5], false)]);
        let many = prewarm_batches((0..PREWARM_BATCH_FILES + 1).map(|i| (i, 1, false)).collect());
        assert_eq!(many.iter().map(|(batch, _)| batch.len()).collect::<Vec<_>>(), vec![PREWARM_BATCH_FILES, 1]);
        // A single file over the bound still gets its own batch.
        assert_eq!(prewarm_batches(vec![(9, PREWARM_BATCH_BYTES + 1, false)]), vec![(vec![9], false)]);
    }
}

#[cfg(test)]
mod prewhere_defect_tests {
    use super::*;

    #[test]
    fn only_a_lost_column_without_the_fallback_setting_reruns() {
        let error = "native chDB query failed: chDB query failed: Code: 10. DB::Exception: Not found column lower(__table5.__nano_path_0) in block. There are only columns: message, metadata, raw_data, ti";
        let sql = "SELECT * FROM t WHERE (lower(a) = 'x' OR b) AND lower(a) != 'audit' SETTINGS max_threads=2";
        assert!(prewhere_defect(error, sql));
        assert!(prewhere_defect("... While executing File. (NOT_FOUND_COLUMN_IN_BLOCK)", sql));
        assert!(!prewhere_defect("Code: 241. DB::Exception: Memory limit exceeded", sql));
        assert!(!prewhere_defect("Code: 47. Unknown expression identifier", sql));
        let plan = NativeQueryPlan {
            query_sha256: String::new(), sql: sql.into(), params: vec![],
            budget: planner::QueryBudget { candidate_objects: 0, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
            native_event_rows: false, temporary_aliases: BTreeSet::new(), schema_defaults: vec![], reader: Default::default(),
        };
        let rerun = without_prewhere(plan);
        assert_eq!(rerun.sql, format!("{sql}, optimize_move_to_prewhere=0"));
        // The rerun itself never reruns again.
        assert!(!prewhere_defect(error, &rerun.sql));
    }
}

#[cfg(test)]
mod budget_error_tests {
    use super::*;
    use crate::executor::ExecutorError;
    use crate::native::NativeChdbError;

    #[test]
    fn streamed_statement_finds_its_threshold_on_time_first() {
        let sql = "WITH stage_0 AS (SELECT * FROM (SELECT *, tupleElement(`metadata`, 'uid') AS __nano_path_1 FROM src) WHERE time >= 'a' AND time < 'b') \
                   SELECT * FROM stage_0 ORDER BY time DESC, __nano_path_1 DESC LIMIT 20001 SETTINGS max_threads=3, readonly=2";
        let rewritten = threshold_first(sql).unwrap();
        assert!(rewritten.starts_with("WITH __nano_rows AS (WITH stage_0 AS ("), "{rewritten}");
        assert!(rewritten.contains("SELECT * FROM stage_0) SELECT * FROM __nano_rows WHERE time >= (SELECT min(__nano_t) FROM (SELECT time AS __nano_t FROM __nano_rows ORDER BY time DESC LIMIT 20001))"), "{rewritten}");
        assert!(rewritten.ends_with("ORDER BY time DESC, __nano_path_1 DESC LIMIT 20001 SETTINGS max_threads=3, readonly=2"), "{rewritten}");
        // Anything that does not end in the event order runs unchanged.
        for other in [
            "SELECT * FROM t LIMIT 10 SETTINGS max_threads=1",
            "SELECT * FROM t ORDER BY time DESC LIMIT 10 SETTINGS max_threads=1",
            "SELECT * FROM t ORDER BY time DESC, uid DESC LIMIT 10",
            "SELECT * FROM t ORDER BY time DESC, lower(uid) DESC LIMIT 10 SETTINGS max_threads=1",
        ] {
            assert_eq!(threshold_first(other), None, "{other}");
        }
    }

    #[test]
    fn memory_and_result_refusals_are_retryable_budget_errors() {
        for error in [
            ExecutorError::Query(NativeChdbError::Query("Code: 241. DB::Exception: (total) memory limit exceeded: would use 2.78 GiB".into())),
            ExecutorError::Query(NativeChdbError::Query("Memory limit (for query) exceeded (MEMORY_LIMIT_EXCEEDED)".into())),
            ExecutorError::ResultTooLarge { bytes: 100, limit_bytes: 10 },
            ExecutorError::Query(NativeChdbError::Query("Code: 396. Limit for result exceeded, max bytes: 64.00 MiB (TOO_MANY_ROWS_OR_BYTES)".into())),
        ] {
            let mapped = map_executor_error(error);
            assert!(matches!(mapped, PartQueryError::MemoryBudget(_)), "{mapped:?}");
            assert_eq!((mapped.status(), mapped.reason()), (503, QUERY_BUDGET_EXHAUSTED));
            assert!(mapped.to_string().starts_with("query memory budget exceeded"));
        }
        let busy = PartQueryError::ConcurrencyBudget("busy".into());
        assert_eq!((busy.status(), busy.reason()), (429, QUERY_BUDGET_EXHAUSTED));
        // Other engine failures keep their meaning.
        let timeout = map_executor_error(ExecutorError::Query(NativeChdbError::Query("TIMEOUT_EXCEEDED".into())));
        assert_eq!(timeout.reason(), "scan_budget_exhausted");
        let syntax = map_executor_error(ExecutorError::Query(NativeChdbError::Query("Code: 62. Syntax error".into())));
        assert_eq!(syntax.status(), 422);
    }
}

#[cfg(test)]
mod pinned_discovery_tests {
    use super::*;
    fn pin(seq: u64) -> PinnedDiscovery {
        let part = PartRef {
            part_id: crate::parts::format::PartId::new(1_790_000_000_000).unwrap(),
            level: crate::parts::levels::Level::L0, event_hour: 0, event_day: None,
            rows: 2, min_time_us: 100, max_time_us: 200,
            schema_fingerprint: format!("schema-{seq}"), provenance_sha256: "signed-digest".into(),
            merkle_root: "signed-root".into(), sorted: true, data_bytes: 10, row_groups: 1, data_files: 1,
        };
        PinnedDiscovery { engine: 7, parts: vec![part], schema: Arc::new(arrow_schema::Schema::empty()),
            head: Some((seq, format!("head-{seq}"))), fingerprint: Some(format!("schema-{seq}")), live_parts: 1 }
    }
    #[tokio::test]
    async fn request_pin_survives_yields_and_new_heads_without_crossing_engines_or_tasks() {
        DISCOVERY.scope(pin(1), async {
            let before = DISCOVERY.with(|pin| pin.snapshot_for(7, 100, 200).unwrap());
            assert_eq!(before.2, Some(1));
            assert!(DISCOVERY.with(|pin| pin.snapshot_for(8, 100, 200)).is_none());
            assert!(DISCOVERY.with(|pin| pin.snapshot_for(7, 201, 300).unwrap().0).is_empty());
            tokio::task::yield_now().await;
            assert!(tokio::spawn(async { DISCOVERY.try_with(|_| ()).is_err() }).await.unwrap());
            // Explicit retry on a refreshed head; the outer request remains pinned.
            DISCOVERY.scope(pin(2), async {
                assert_eq!(DISCOVERY.with(|pin| pin.head.clone()).unwrap().0, 2);
            }).await;
            let after = DISCOVERY.with(|pin| pin.snapshot_for(7, 100, 200).unwrap());
            assert_eq!(before, after);
        }).await;
        assert!(DISCOVERY.try_with(|_| ()).is_err());
        DISCOVERY.scope(pin(3), async {
            assert_eq!(DISCOVERY.with(|pin| pin.head.clone()).unwrap().0, 3);
        }).await;
    }
}

#[cfg(test)]
mod locator_identity_tests {
    use super::*;

    #[test]
    fn immutable_files_and_candidate_fences_define_locator_identity() {
        let object = || ManifestObject { event_object_key: "s3://bucket/part".into(), event_object_version: "digest-a".into(),
            event_object_bytes: 100, rows: 10, available_paths: vec!["time".into()].into(),
            field_types: BTreeMap::new(), column_compressed_bytes: BTreeMap::new() };
        let manifest = SourceManifest::from_objects("tenant", vec![object()]);
        let before = locator_selection_identity(&manifest, None);
        let same = SourceManifest::from_objects("tenant", vec![object()]);
        assert_eq!(before, locator_selection_identity(&same, None));
        let mut replacement = object();
        replacement.event_object_version = "digest-b".into();
        assert_ne!(before, locator_selection_identity(&SourceManifest::from_objects("tenant", vec![replacement]), None));
        let block = CandidateBlock { event_object_key: "s3://bucket/part".into(), event_object_bytes: 100,
            row_start: 0, row_end: 1, max_time_ms: None, time_range_us: Some((1, 1)) };
        assert_ne!(before, locator_selection_identity(&manifest, Some(&[block.clone()])));
        let first = locator_selection_identity(&manifest, Some(&[block.clone()]));
        let mut other = block;
        other.row_start = 1; other.row_end = 2;
        assert_ne!(first, locator_selection_identity(&manifest, Some(&[other])));
    }
}

#[cfg(test)]
mod native_debug_tests {
    use super::*;
    use super::super::lanes::LargeLane;

    /// The lane router with a fresh memo (every call starts small).
    async fn run_sized(small: &NativeExecutor, large: Option<&LargeLane>, plan: NativeQueryPlan)
        -> Result<NativeQueryOutput, crate::executor::ExecutorError> {
        super::super::lanes::run_sized(small, large, &super::super::lanes::LaneMemo::default(), plan).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires digest-verified native library"]
    async fn source_summary_prewarm_memory_retry_keeps_same_lane_usable() {
        use crate::executor::ExecutorMode;
        use super::super::memory_budget::GIB;
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        let pool = |name| NativeExecutor::start_with_server_memory_limit(
            runtime.clone(), 1, name, ExecutorMode::ReadOnly, Some(3 * GIB),
        ).unwrap();
        let small = pool("prewarm-small");
        let large = super::super::lanes::LargeLane::new(pool("prewarm-large"), 3 * GIB / 2);
        // Mirror the per-part source histogram's path/bucket/value grouping
        // and audit exclusion. Synthetic high-cardinality values force the
        // small cap without requiring captured production sidecars.
        crate::query_timing::measure("source-summary-prewarm", async {
            for deny_audit in [false, true] {
                let filter = if deny_audit { "AND lower(source_type) != 'audit'" } else { "" };
                let sql = format!(
                    "SELECT sum(events) AS n FROM (SELECT part_path, bucket_start_us, value, toUInt64(sum(events)) AS events FROM (SELECT 'part-1' AS part_path, toInt64(0) AS bucket_start_us, toUInt16(1) AS field_id, 'sysmon' AS source_type, repeat(toString(cityHash64(number)), 16) AS value, toUInt64(1) AS events FROM numbers(1500000)) AS _nano_rollup WHERE field_id = 1 AND bucket_start_us >= 0 AND bucket_start_us < 60000000 {filter} GROUP BY part_path, bucket_start_us, value) SETTINGS max_memory_usage=268435456, max_threads=2, max_bytes_before_external_group_by=0"
                );
                let plan = contention_plan(&sql, 64 * 1024 * 1024, 256 * 1024 * 1024);
                let error = run_on(&small, plan.clone()).await.unwrap_err().to_string();
                assert!(error.contains("Code: 241"), "expected small-lane memory refusal: {error}");
                assert_eq!(small.status().connection_recycles, small.status().failed,
                    "failure must be delivered after failed-session cleanup");
                let output = run_sized(&small, Some(&large), plan).await.unwrap();
                assert_eq!(output.data, b"{\"n\":1500000}\n");
                let recycles = small.status().connection_recycles;
                for n in 40..46 {
                    let output = run_on(&small, contention_plan(&format!("SELECT {n} AS n"), 0, 256 * 1024 * 1024)).await.unwrap();
                    assert_eq!(output.data, format!("{{\"n\":{n}}}\n").as_bytes());
                }
                assert_eq!(small.status().connection_recycles, recycles,
                    "normal statements must reuse the recovered connection");
            }
            assert_eq!(small.status().failed, 4);
            assert_eq!(large.executor().status().completed, 2);
            Ok::<_, ()>(())
        }).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires digest-verified native library"]
    async fn small_lane_memory_failure_retry_and_subsequent_statement_succeed() {
        use crate::executor::ExecutorMode;
        use super::super::memory_budget::GIB;
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let pool = |count, name| NativeExecutor::start_with_server_memory_limit(
            runtime.clone(), count, name, ExecutorMode::ReadOnly, Some(3 * GIB),
        ).unwrap();
        let small = pool(6, "parts");
        let large = super::super::lanes::LargeLane::new(pool(1, "parts-large"), 3 * GIB / 2);
        // No spill: force Code 241 during aggregation, after stream init.
        let plan = contention_plan(
            "SELECT count() AS n FROM (SELECT repeat(toString(cityHash64(number)), 16) AS k FROM numbers(1500000) GROUP BY k) SETTINGS max_memory_usage=268435456, max_threads=2, max_bytes_before_external_group_by=0",
            64 * 1024 * 1024, 256 * 1024 * 1024,
        );
        for round in 0..12 {
            crate::query_timing::measure("memory-retry", async {
                let output = run_sized(&small, Some(&large), plan.clone()).await.unwrap();
                assert!(String::from_utf8_lossy(&output.data).contains("1500000"));
                // With no other admitted work, ties rotate across all six
                // lanes. Visiting a full cycle includes the failed lane's
                // replacement connection, not just a different healthy lane.
                for _ in 0..small.connection_count() {
                    let output = run_on(&small, contention_plan("SELECT 42 AS n", 0, 256 * 1024 * 1024)).await.unwrap();
                    assert!(String::from_utf8_lossy(&output.data).contains("42"));
                }
                Ok::<_, ()>(())
            }).await.unwrap();
            assert_eq!(small.status().failed, round + 1, "small statement must hit memory limit");
        }
        assert_eq!(large.executor().status().completed, 12);
        assert_eq!(small.status().connection_recycles, 12);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires digest-verified native library; 21-second contention cadence"]
    async fn ordinary_interactive_scans_bypass_busy_large_lane_under_detect_cadence() {
        use crate::executor::ExecutorMode;
        use super::super::memory_budget::{GIB, QueryMemoryBudget};
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        // A wide, uncompressed Parquet file exceeds the regressed 16 MiB
        // threshold; the interactive aggregate projects only its narrow column.
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("wide.parquet");
        {
            use arrow_array::{RecordBatch, StringArray, UInt64Array};
            use arrow_schema::{DataType, Field, Schema};
            let schema = Arc::new(Schema::new(vec![
                Field::new("number", DataType::UInt64, false),
                Field::new("payload", DataType::Utf8, false),
            ]));
            let batch = RecordBatch::try_new(schema.clone(), vec![
                Arc::new(UInt64Array::from_iter_values(0..10_000)),
                Arc::new(StringArray::from_iter_values((0..10_000).map(|i| format!("{i}:{}", "x".repeat(4096))))),
            ]).unwrap();
            let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&path).unwrap(), schema, None).unwrap();
            writer.write(&batch).unwrap();
            writer.close().unwrap();
        }
        let scan_bytes = std::fs::metadata(&path).unwrap().len();
        assert!(scan_bytes > 16 * 1024 * 1024);
        let (budget, classes) = QueryMemoryBudget::derive(3 * GIB, None).with_classes();
        let classes = classes.unwrap();
        let pool = |count, name| NativeExecutor::start_with_server_memory_limit(
            runtime.clone(), count, name, ExecutorMode::ReadOnly, Some(budget.server_bytes),
        ).unwrap();
        let small = pool(classes.small_lanes, "parts");
        let large = super::super::lanes::LargeLane::new(pool(1, "parts-large"), classes.large_bytes);
        // Production detect has its own process. A distinct pool in this
        // fixture also adds native CPU contention without sharing query lanes.
        let detect = pool(2, "detect");
        let background_large = large.clone();
        let background_small = small.clone();
        let background = tokio::spawn(async move {
            let mut cadence = tokio::time::interval(Duration::from_secs(3));
            for _ in 0..7 {
                cadence.tick().await;
                let plan = contention_plan("SELECT sleep(2.5)", LARGE_SCAN_BYTES + 1, classes.small_bytes);
                run_sized(&background_small, Some(&background_large), plan).await.unwrap();
            }
        });
        let detections = tokio::spawn(async move {
            let mut cadence = tokio::time::interval(Duration::from_secs(3));
            for _ in 0..7 {
                cadence.tick().await;
                detect.execute_sql("SELECT sleep(0.1) SETTINGS max_memory_usage=268435456".into(), vec![]).await.unwrap();
            }
            assert_eq!(detect.status().failed, 0);
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while large.executor().status().in_flight == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await.unwrap();
        let mut waits = Vec::new();
        let mut cadence = tokio::time::interval(Duration::from_millis(100));
        for i in 0..210 {
            cadence.tick().await;
            let mut plan = contention_plan("SELECT sum(number) AS total FROM file({fixture:String}, Parquet)", scan_bytes, classes.small_bytes);
            plan.params.push(("fixture".into(), path.to_str().unwrap().into()));
            let (output, wait) = crate::query_timing::measure("contention-interactive", async {
                Ok::<_, ()>(crate::executor::capture_lane_wait(run_sized(&small, Some(&large), plan)).await)
            }).await.unwrap();
            let output = output.unwrap();
            assert!(String::from_utf8_lossy(&output.data).contains("49995000"));
            assert!(output.storage_bytes_read < scan_bytes, "projection must avoid the wide payload");
            waits.push(wait);
            // Finding drain every 20 seconds, sharing the interactive pool.
            if i % 200 == 0 {
                run_sized(&small, Some(&large), contention_plan("SELECT count() FROM numbers(10000)", 64 * 1024 * 1024, classes.small_bytes)).await.unwrap();
            }
        }
        background.await.unwrap();
        detections.await.unwrap();
        waits.sort_by(f64::total_cmp);
        let p95 = waits[(waits.len() * 95 / 100).min(waits.len() - 1)];
        eprintln!("interactive lane wait p95={p95:.3} ms, max={:.3} ms", waits.last().unwrap());
        assert!(p95 < 50.0, "interactive lane wait p95={p95} ms");
        assert_eq!(small.status().failed, 0, "no small-lane MEMORY_LIMIT retries");
        assert_eq!(large.executor().status().failed, 0);
        assert_eq!(large.executor().status().completed, 7, "only deliberate heavy scans use large");
        assert_eq!(small.server_memory_limit_bytes(), Some(budget.server_bytes));
        assert_eq!(classes.small_lanes as u64 * classes.small_bytes + classes.large_bytes, budget.server_bytes);
    }

    fn contention_plan(sql: &str, scan_bytes: u64, memory_bytes: u64) -> NativeQueryPlan {
        NativeQueryPlan {
            query_sha256: String::new(),
            sql: format!("{sql} SETTINGS max_threads=1, max_memory_usage={memory_bytes}, max_execution_time=10"),
            params: vec![],
            budget: planner::QueryBudget { candidate_objects: 4, estimated_scan_bytes: scan_bytes, max_query_bytes: u64::MAX },
            native_event_rows: false, temporary_aliases: BTreeSet::new(), schema_defaults: vec![], reader: Default::default(),
        }
    }

    #[tokio::test]
    #[ignore = "requires digest-verified native library"]
    async fn native_debug_reports_settings_and_redacts_values_without_changing_rows() {
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        ).unwrap();
        std::mem::forget(runtime.clone());
        let lanes = NativeExecutor::start_named(runtime, 1, "parts").unwrap();
        let plan = NativeQueryPlan {
            query_sha256: String::new(),
            sql: "SELECT {private:String} AS value, 'private literal' AS literal SETTINGS max_threads=2, max_memory_usage=3000000000, max_execution_time=55, use_query_cache=0".into(),
            params: vec![("private".into(), "private parameter".into())],
            budget: planner::QueryBudget { candidate_objects: 0, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
            native_event_rows: false, temporary_aliases: BTreeSet::new(), schema_defaults: vec![], reader: Default::default(),
        };
        let reference = run_on(&lanes, plan.clone()).await.unwrap();
        let answer = super::super::debug::collect(async {
            super::super::debug::file("s3://bucket/h/data-00000.parquet", "h", 123);
            let output = run_on(&lanes, plan).await.unwrap();
            assert_eq!(output.data, reference.data);
            Ok::<_, ()>(json!({"planner":{}}))
        }).await.unwrap();
        let evidence = &answer["planner"]["native_debug"];
        let text = evidence.to_string();
        assert!(!text.contains("private literal"));
        assert!(!text.contains("private parameter"));
        assert_eq!(evidence["files"][0]["tier"], "h");
        let statement = &evidence["statements"][0];
        assert!(statement["sql"].as_str().unwrap().contains("{private:String}"));
        assert!(statement["native_settings"]["effective"].as_array().unwrap().iter()
            .any(|setting| setting["name"] == "max_threads" && setting["value"] == "2"));
        assert!(statement["storage_rows"].is_u64());
        assert_eq!(statement["lane"], "small");
        assert!(statement["lane_wait_ms"].as_f64().unwrap() >= 0.0);
    }
}

#[cfg(test)]
mod stats_page_tests {
    use super::*;
    #[test]
    fn exact_group_total_survives_paging_and_metadata_is_private() {
        let mut rows = vec![json!({"count":"15", "__nano_stats_total":"193567", "__nano_stats_ordinal":"1"}),
                            json!({"count":"12", "__nano_stats_total":"193567", "__nano_stats_ordinal":"2"})];
        assert_eq!(stats_page_total(true, 0, &mut rows).unwrap(), Some(193567));
        assert!(rows.iter().all(|row| row.get("__nano_stats_total").is_none()));
        let (page, more) = page_decoded(rows.clone(), &BTreeSet::new(), 0, 1);
        assert!(more);
        assert_eq!(page[0]["count"], "15");
        assert!(page_decoded(rows, &BTreeSet::new(), 10, 1).0.is_empty());
        assert_eq!(stats_page_total(true, 0, &mut Vec::new()).unwrap(), Some(0));
    }
    #[test]
    fn ordinary_aliases_are_preserved_and_malformed_totals_fail_closed() {
        let mut ordinary = vec![json!({"__nano_stats_total": "mine"})];
        assert_eq!(stats_page_total(false, 0, &mut ordinary).unwrap(), None);
        assert_eq!(ordinary[0]["__nano_stats_total"], "mine");
        for mut rows in [vec![json!({"count":1})],
            vec![json!({"__nano_stats_total":"invalid"})],
            vec![json!({"__nano_stats_total":2}), json!({"__nano_stats_total":3})]] {
            assert!(stats_page_total(true, 0, &mut rows).is_err());
        }
    }
}

#[cfg(test)]
mod cold_scan_tests {
    use super::*;

    #[test]
    fn cold_ceiling_fetch_retains_bytes_and_is_not_a_lane_memory_refusal() {
        let cache = crate::reader_object_cache::ReaderCacheError::ScanTooLarge {
            required_bytes: 14_800_000_000, ceiling_bytes: 9_663_676_416, background_bytes: 9_663_676_416,
        };
        assert!(!cache.retryable());
        assert_eq!(cache.reason(), "cold_scan_too_large");
        let mapped = map_fetch_error(anyhow::Error::new(cache).context("fetch selected parts"));
        assert!(matches!(mapped, PartQueryError::ColdScanTooLarge {
            needed_bytes: 14_800_000_000, ceiling_bytes: 9_663_676_416, background_bytes: 9_663_676_416,
        }));
        assert_eq!((mapped.status(), mapped.reason()), (422, "cold_scan_too_large"));
        assert!(!super::super::memory_budget::is_budget_refusal(&mapped.to_string()));
        assert!(mapped.to_string().contains("~14.8 GB"), "{mapped}");
        assert!(!mapped.to_string().contains("narrow the time range or run it"), "{mapped}");
    }
}

/// NAN-3141: the search path's inner futures must stay small. They are
/// boxed by their callers, but `Box::pin(f())` still builds `f()` in the
/// caller's poll frame before moving it to the heap.
#[cfg(test)]
#[allow(unreachable_code, unused_variables, clippy::diverging_sub_expression)]
mod future_size_tests {
    use super::*;

    const FUTURE_BUDGET_BYTES: usize = 256 * 1024;

    fn ret<R>(_: impl FnOnce() -> R) -> usize { std::mem::size_of::<R>() }

    #[test]
    fn search_path_futures_stay_under_the_stack_budget() {
        // The closures are never called: they only name each future's type.
        let sizes: Vec<(&str, usize)> = vec![
            ("broad_npl_once", ret(|| { let e: &PartQueryEngine = unreachable!(); let r: &BroadNplRequest = unreachable!(); e.broad_npl_once(r) })),
            ("run_compiled", ret(|| { let e: &PartQueryEngine = unreachable!(); let r: &BroadNplRequest = unreachable!();
                let c: &CompiledQuery = unreachable!(); let f: &BTreeMap<String, String> = unreachable!();
                e.run_compiled(r, c, f, None, 0.0) })),
            ("progressive", ret(|| { let e: &PartQueryEngine = unreachable!(); let c: &CompiledQuery = unreachable!(); e.progressive(c, None, None, 0) })),
            ("fragment_aggregate", ret(|| { let e: &PartQueryEngine = unreachable!(); let c: &CompiledQuery = unreachable!(); e.fragment_aggregate(c, 0, 0, None) })),
            ("select_counting", ret(|| { let e: &PartQueryEngine = unreachable!(); e.select_counting(0, 0, &[], None, None) })),
            ("execute", ret(|| { let e: &PartQueryEngine = unreachable!(); let p: NativeQueryPlan = unreachable!(); e.execute(p) })),
            ("fetch_log", ret(|| { let e: &PartQueryEngine = unreachable!(); let r: &FetchLogRequest = unreachable!(); e.fetch_log(r) })),
            ("refresh", ret(|| { let e: &PartQueryEngine = unreachable!(); e.refresh() })),
            ("identity::backfill_once", ret(|| { let e: &PartQueryEngine = unreachable!(); let d: &std::path::Path = unreachable!();
                super::super::identity::backfill_once(e, d, 0, 0, None) })),
            ("product_state::prepare", ret(|| { let e: &PartQueryEngine = unreachable!(); let d: &std::path::Path = unreachable!();
                let w: super::super::product_state::Work = unreachable!(); super::super::product_state::prepare(e, d, w) })),
        ];
        for (name, size) in &sizes {
            eprintln!("future {name}: {size} bytes");
        }
        let over: Vec<_> = sizes.iter().filter(|(_, size)| *size > FUTURE_BUDGET_BYTES).collect();
        assert!(over.is_empty(), "search futures over the {FUTURE_BUDGET_BYTES}-byte stack budget (Box::pin the large inner work): {over:?}");
    }
}

#[cfg(test)]
#[path = "lean_query_native_tests.rs"]
pub(crate) mod lean_query_native;

#[cfg(all(test, feature = "enterprise"))]
#[path = "retro_hunt_native_tests.rs"]
mod retro_hunt_native;

#[cfg(test)]
#[path = "class_prune_native_tests.rs"]
mod class_prune_native;

#[cfg(test)]
#[path = "field_list_native_tests.rs"]
mod field_list_native;

/// NAN-3265: the progressive walk for pages of any depth, simulated over
/// fixture events with heavy time ties and compared row-for-row against the
/// materialized result (one global `ORDER BY time DESC, metadata.uid DESC`
/// with offset/limit). Each chunk statement is evaluated exactly as the
/// compiled one is: the chunk's time fence, its optional `(time, uid)`
/// cursor, the event order and the statement's `LIMIT`.
#[cfg(test)]
mod nan3265_row_cliff_tests {
    use super::*;
    use chrono::{DateTime, Duration as ChronoDuration, Utc};

    struct Walk {
        rows: Vec<(i64, String)>,
        statements: usize,
        max_statement_rows: usize,
        decoded_rows: usize,
        continuations: usize,
        rereads: usize,
    }

    fn clickhouse_time(us: i64) -> String {
        DateTime::<Utc>::from_timestamp_micros(us).unwrap().format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    }

    /// One chunk statement over `events` (sorted in event order).
    fn statement(events: &[(i64, String)], chunk: &progressive::Chunk, limit: usize) -> Vec<(i64, String)> {
        let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
        let after = chunk.after.as_ref().map(|(time, uid)| (progressive::row_time_us(time).unwrap(), uid.clone()));
        events
            .iter()
            .filter(|(time, _)| *time >= chunk.start_us && *time <= upper)
            .filter(|(time, uid)| after.as_ref().is_none_or(|(at, auid)| *time < *at || (*time == *at && uid < auid)))
            .take(limit)
            .cloned()
            .collect()
    }

    /// The engine's walk (`PartQueryEngine::progressive`) for a page of
    /// `limit` rows (offset + limit + sentinel), statement by statement.
    fn walk(events: &[(i64, String)], start: DateTime<Utc>, end: DateTime<Utc>, limit: usize) -> Walk {
        let (window_start_us, walk_end_us) = (start.timestamp_micros(), end.timestamp_micros());
        let mut pending = std::collections::VecDeque::from(progressive::seed_chunks(start, end));
        let mut out = Walk { rows: Vec::new(), statements: 0, max_statement_rows: 0, decoded_rows: 0, continuations: 0, rereads: 0 };
        let mut values: Vec<Value> = Vec::new();
        let row_capped = progressive::row_capped(limit);
        while let Some(chunk) = pending.pop_front() {
            assert!(out.statements < progressive::MAX_PLAN_ATTEMPTS);
            let kept_before = out.rows.len();
            let remaining = limit - kept_before;
            // Unchanged for a page within one cap: the compiled limit.
            let statement_rows = if row_capped { progressive::chunk_row_limit(limit, kept_before, chunk.uncapped) } else { limit };
            let got = statement(events, &chunk, statement_rows);
            out.statements += 1;
            out.max_statement_rows = out.max_statement_rows.max(got.len());
            out.decoded_rows += got.len();
            values.extend(got.iter().map(|(time, uid)| json!({"time": clickhouse_time(*time), "metadata.uid": uid})));
            out.rows.extend(got);
            if out.rows.len() >= limit {
                out.rows.truncate(limit);
                break;
            }
            match chunk_follow(&chunk, &values, out.rows.len() - kept_before, statement_rows, remaining, window_start_us) {
                ChunkFollow::Done => {
                    pending = progressive::reseed(window_start_us, chunk.start_us, walk_end_us - chunk.start_us, out.rows.len(),
                        progressive::step_target(out.rows.len(), limit)).into();
                }
                ChunkFollow::Continue(next) => {
                    out.continuations += 1;
                    pending.push_front(next);
                }
                ChunkFollow::Reread(again) => {
                    out.rereads += 1;
                    out.rows.truncate(kept_before);
                    values.truncate(kept_before);
                    pending.push_front(again);
                }
            }
        }
        out
    }

    /// `per_second` events in every whole second of `[start, end)` (each
    /// second a `per_second`-way tie, as the live apache_access source),
    /// uids scrambled so uid order is not arrival order; event order.
    fn fixture(start: DateTime<Utc>, end: DateTime<Utc>, per_second: u64) -> Vec<(i64, String)> {
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut events = Vec::new();
        let mut second = start.timestamp();
        while second < end.timestamp() {
            for _ in 0..per_second {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                events.push((second * 1_000_000, format!("uid-{:016x}", seed >> 4)));
            }
            second += 1;
        }
        events.sort_unstable_by(|a, b| b.cmp(a));
        events
    }

    fn materialized(events: &[(i64, String)], offset: usize, limit: usize) -> (Vec<(i64, String)>, bool) {
        (events.iter().skip(offset).take(limit).cloned().collect(), events.len() > offset + limit)
    }

    #[test]
    fn deep_pages_walk_and_equal_the_materialized_page() {
        let end = DateTime::parse_from_rfc3339("2026-10-08T04:30:00Z").unwrap().with_timezone(&Utc);
        let mut matrix = Vec::new();
        for (window_s, per_second) in [(180_i64, 20_u64), (3_600, 20)] {
            let start = end - ChronoDuration::seconds(window_s);
            let events = fixture(start, end, per_second);
            for limit in [200_usize, 750, 999, 1_000, 2_000, 5_000, 20_000, 50_000] {
                for offset in [0_usize, 800, 4_095, 10_000] {
                    // The worker's request limit: offset + limit + sentinel.
                    let wanted = offset + limit + 1;
                    let walked = walk(&events, start, end, wanted);
                    let (page, has_more) = (walked.rows.iter().skip(offset).take(limit).cloned().collect::<Vec<_>>(), walked.rows.len() > offset + limit);
                    let (truth, truth_more) = materialized(&events, offset, limit);
                    assert_eq!(page, truth, "window {window_s}s limit {limit} offset {offset}");
                    assert_eq!(has_more, truth_more, "window {window_s}s limit {limit} offset {offset}");
                    // Memory: no statement returns more than one cap of rows
                    // (or the page, within one cap), and the walk decodes at
                    // most the rows it keeps plus one statement's overshoot.
                    assert!(walked.max_statement_rows <= progressive::CHUNK_ROW_CAP.max(if progressive::row_capped(wanted) { 0 } else { wanted }),
                        "window {window_s}s limit {limit} offset {offset}: {} rows in one statement", walked.max_statement_rows);
                    assert!(walked.decoded_rows <= wanted + progressive::CHUNK_ROW_CAP, "window {window_s}s limit {limit} offset {offset}");
                    assert_eq!(walked.rereads, 0, "ties never defeat the cursor continuation");
                    matrix.push(format!("{window_s:>5}s limit {limit:>6} offset {offset:>6}: statements {:>3} (continuations {:>3}) max/stmt {:>5} decoded {:>6} kept {:>6}",
                        walked.statements, walked.continuations, walked.max_statement_rows, walked.decoded_rows, walked.rows.len()));
                }
            }
        }
        eprintln!("NAN-3265 progressive walk matrix (statement count is the latency driver):\n{}", matrix.join("\n"));
    }

    /// A tie wider than a cap (10,000 rows at one instant) continues on the
    /// uid alone; a tie at the very start of the window (where the planner
    /// admits no cursor) falls back to one uncapped reread, still exact.
    #[test]
    fn ties_wider_than_a_cap_continue_on_the_uid() {
        let end = DateTime::parse_from_rfc3339("2026-10-08T04:30:00Z").unwrap().with_timezone(&Utc);
        let start = end - ChronoDuration::minutes(10);
        let tie = |at: DateTime<Utc>, count: usize| (0..count).map(move |n| (at.timestamp_micros(), format!("uid-{:08}", (n * 7_919) % 100_003)));
        let mut events: Vec<_> = tie(end - ChronoDuration::seconds(30), 10_000).chain(fixture(start, end, 2)).collect();
        events.sort_unstable_by(|a, b| b.cmp(a));
        for wanted in [5_001_usize, 9_000, 12_001] {
            let walked = walk(&events, start, end, wanted);
            assert_eq!(walked.rows, events[..wanted.min(events.len())].to_vec(), "wanted {wanted}");
            assert!(walked.continuations >= 1 && walked.rereads == 0, "wanted {wanted}");
            assert!(walked.max_statement_rows <= progressive::CHUNK_ROW_CAP);
        }
        let mut at_start: Vec<_> = tie(start, 10_000).collect();
        at_start.sort_unstable_by(|a, b| b.cmp(a));
        let walked = walk(&at_start, start, end, 6_001);
        assert_eq!(walked.rows, at_start[..6_001].to_vec());
        assert_eq!(walked.rereads, 1, "no cursor at the window start: one uncapped reread");
    }

    #[test]
    fn follow_is_done_unless_a_capped_statement_came_back_full() {
        let end = DateTime::parse_from_rfc3339("2026-10-08T04:30:00Z").unwrap().with_timezone(&Utc);
        let chunk = progressive::seed_chunks(end - ChronoDuration::hours(1), end).remove(0);
        let row = json!({"time": "2026-10-08 04:29:30.250000", "metadata": {"uid": "uid-1"}});
        let start_us = (end - ChronoDuration::hours(1)).timestamp_micros();
        assert_eq!(chunk_follow(&chunk, std::slice::from_ref(&row), 10, 4_096, 50_000, start_us), ChunkFollow::Done);
        assert_eq!(chunk_follow(&chunk, std::slice::from_ref(&row), 1_001, 1_001, 1_001, start_us), ChunkFollow::Done);
        let ChunkFollow::Continue(next) = chunk_follow(&chunk, std::slice::from_ref(&row), 4_096, 4_096, 50_000, start_us) else { panic!("continue") };
        assert_eq!((next.start_us, next.end.as_str(), next.end_inclusive), (chunk.start_us, "2026-10-08T04:29:30.250000Z", true));
        assert_eq!(next.after, Some(("2026-10-08T04:29:30.250000Z".to_string(), "uid-1".to_string())));
        // No usable cursor on the last row: reread the chunk uncapped.
        let bare = json!({"time": "2026-10-08 04:29:30.250000"});
        let ChunkFollow::Reread(again) = chunk_follow(&chunk, std::slice::from_ref(&bare), 4_096, 4_096, 50_000, start_us) else { panic!("reread") };
        assert!(again.uncapped && again.start_us == chunk.start_us && again.end_us == chunk.end_us);
        assert_eq!(progressive::chunk_row_limit(50_001, 4_096, true), 45_905);
    }
}

/// NAN-3270: the progressive walk bounded by result bytes as well as rows,
/// simulated statement by statement exactly as [`PartQueryEngine::progressive`]
/// runs it (row caps, byte steps, admission, stubs, continuations), and the
/// search service's fill loop over byte-cut pages. Every filled page must
/// equal the materialized page (`ORDER BY time DESC, metadata.uid DESC`,
/// offset/limit) and the row-only walk.
#[cfg(test)]
mod nan3270_byte_cut_tests {
    use super::*;
    use chrono::{DateTime, Duration as ChronoDuration, Utc};

    const MIB: u64 = 1 << 20;

    type Event = (i64, String);

    fn clickhouse_time(us: i64) -> String {
        DateTime::<Utc>::from_timestamp_micros(us).unwrap().format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    }

    /// `per_second`-way ties in every second of `[start, end)`, scrambled
    /// uids, in event order.
    fn fixture(start: DateTime<Utc>, end: DateTime<Utc>, per_second: u64) -> Vec<Event> {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut events = Vec::new();
        for second in start.timestamp()..end.timestamp() {
            for _ in 0..per_second {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                events.push((second * 1_000_000, format!("uid-{:016x}", seed >> 4)));
            }
        }
        events.sort_unstable_by(|a, b| b.cmp(a));
        events
    }

    /// A row's raw width: `base` give or take half, varying per row.
    fn width(base: u64) -> impl Fn(&str) -> u64 {
        move |uid: &str| {
            let hash = uid.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3));
            base / 2 + hash % base.max(1)
        }
    }

    struct Walk {
        rows: Vec<Event>,
        continuation: Option<Continuation>,
        max_statement_bytes: u64,
        max_held_bytes: u64,
        statements: usize,
    }

    /// One statement: the chunk's fence, its own cursor or the request's,
    /// event order, `LIMIT`.
    fn statement(events: &[Event], chunk: &progressive::Chunk, cursor: Option<&Event>, limit: usize) -> Vec<Event> {
        let upper = if chunk.end_inclusive { chunk.end_us } else { chunk.end_us - 1 };
        let after = chunk.after.as_ref().map(|(time, uid)| (progressive::row_time_us(time).unwrap(), uid.clone())).or_else(|| cursor.cloned());
        events
            .iter()
            .filter(|(time, _)| *time >= chunk.start_us && *time <= upper)
            .filter(|(time, uid)| after.as_ref().is_none_or(|(at, auid)| *time < *at || (*time == *at && uid < auid)))
            .take(limit)
            .cloned()
            .collect()
    }

    /// The engine's walk for one `broad_npl` request: `skip` = offset,
    /// `wanted` = offset + limit + 1, an optional request cursor.
    fn walk(events: &[Event], start: DateTime<Utc>, end: DateTime<Utc>, skip: usize, wanted: usize,
        cursor: Option<&Event>, result_limit: Option<u64>, width: &dyn Fn(&str) -> u64) -> Walk {
        let end = cursor.map_or(end, |(time, _)| DateTime::<Utc>::from_timestamp_micros(*time).unwrap());
        let (window_start_us, walk_end_us) = (start.timestamp_micros(), end.timestamp_micros());
        let mut pending = std::collections::VecDeque::from(progressive::seed_chunks(start, end));
        let mut bytes = progressive::ByteBudget::new(result_limit, skip);
        let mut out = Walk { rows: Vec::new(), continuation: None, max_statement_bytes: 0, max_held_bytes: 0, statements: 0 };
        let mut values: Vec<Value> = Vec::new();
        let row_capped = progressive::row_capped(wanted);
        let mut cut = false;
        while let Some(chunk) = pending.pop_front() {
            assert!(out.statements < progressive::MAX_PLAN_ATTEMPTS);
            let kept_before = out.rows.len();
            let remaining = wanted - kept_before;
            let row_step = progressive::chunk_row_limit(wanted, kept_before, chunk.uncapped);
            let step_rows = match if chunk.uncapped { progressive::ByteStep::Rows(row_step) } else { bytes.step(kept_before, row_step) } {
                progressive::ByteStep::Rows(rows) => rows,
                progressive::ByteStep::Cut => {
                    cut = true;
                    break;
                }
            };
            // The compiled statement keeps its own LIMIT unless capped.
            let statement_rows = if row_capped || step_rows < remaining { step_rows } else { wanted };
            let mut got = statement(events, &chunk, cursor, statement_rows);
            out.statements += 1;
            let sizes = got.iter().map(|(_, uid)| width(uid)).collect::<Vec<_>>();
            out.max_statement_bytes = out.max_statement_bytes.max(sizes.iter().sum());
            let mut decoded = got.iter().map(|(time, uid)| json!({"time": clickhouse_time(*time), "metadata": {"uid": uid}, "pad": "x"})).collect::<Vec<_>>();
            let before_admit = bytes.clone();
            let admitted = bytes.admit(kept_before, &mut decoded, &sizes);
            got.truncate(admitted.kept);
            // Offset rows are held as (time, uid) stubs only.
            for (index, row) in decoded.iter().enumerate() {
                assert_eq!(kept_before + index < skip, row.get("pad").is_none(), "stub iff in the offset");
            }
            out.max_held_bytes = out.max_held_bytes.max(bytes.held_bytes());
            values.extend(decoded);
            out.rows.extend(got);
            if out.rows.len() >= wanted {
                out.rows.truncate(wanted);
                break;
            }
            if admitted.cut {
                cut = true;
                break;
            }
            match chunk_follow(&chunk, &values, out.rows.len() - kept_before, statement_rows, remaining, window_start_us) {
                ChunkFollow::Done => {
                    pending = progressive::reseed(window_start_us, chunk.start_us, walk_end_us - chunk.start_us, out.rows.len(),
                        progressive::step_target(out.rows.len(), wanted)).into();
                }
                ChunkFollow::Continue(next) => pending.push_front(next),
                ChunkFollow::Reread(again) => {
                    out.rows.truncate(kept_before);
                    values.truncate(kept_before);
                    bytes = before_admit;
                    pending.push_front(again);
                }
            }
        }
        if cut {
            out.continuation = Some(values.last().and_then(Continuation::after).expect("a byte-cut page names its cursor"));
        }
        out
    }

    struct Page {
        rows: Vec<Event>,
        has_more: bool,
        requests: usize,
        byte_cut: bool,
    }

    /// `broad_npl_once` (page_decoded + continuation) and the search
    /// service's fill loop over it.
    fn search_page(events: &[Event], start: DateTime<Utc>, end: DateTime<Utc>, offset: usize, limit: usize,
        result_limit: Option<u64>, width: &dyn Fn(&str) -> u64) -> Page {
        let first = walk(events, start, end, offset, offset + limit + 1, None, result_limit, width);
        let mut page = Page {
            rows: first.rows.iter().skip(offset).take(limit).cloned().collect(),
            has_more: first.rows.len() > offset + limit || first.continuation.is_some(),
            requests: 1,
            byte_cut: first.continuation.is_some(),
        };
        let mut next = first.continuation;
        while let Some(continuation) = next.take() {
            let wanted = limit - page.rows.len();
            if wanted == 0 {
                break;
            }
            assert!(page.requests <= 64, "fill made no progress");
            let cursor = (progressive::row_time_us(&continuation.cursor_time).unwrap(), continuation.cursor_event_uid.clone());
            let more = walk(events, start, end, 0, wanted + 1, Some(&cursor), result_limit, width);
            page.requests += 1;
            page.has_more = more.rows.len() > wanted || more.continuation.is_some();
            page.rows.extend(more.rows.into_iter().take(wanted));
            next = more.continuation;
        }
        page
    }

    fn window() -> (DateTime<Utc>, DateTime<Utc>) {
        let end = DateTime::parse_from_rfc3339("2026-10-08T05:00:00Z").unwrap().with_timezone(&Utc);
        (end - ChronoDuration::hours(1), end)
    }

    /// The live failure: ~10 KB rows, a 2,000-row page under a 16 MiB
    /// result budget. The first answer is a partial page within 75% of the
    /// budget plus a continuation, never an error.
    #[test]
    fn over_budget_wide_page_returns_a_partial_page_and_a_continuation() {
        let (start, end) = window();
        let events = fixture(start, end, 3);
        let wide = width(10_000);
        let walked = walk(&events, start, end, 0, 2_001, None, Some(16 * MIB), &wide);
        let next = walked.continuation.as_ref().expect("byte cut");
        assert!(!walked.rows.is_empty() && walked.rows.len() < 2_001, "{} rows", walked.rows.len());
        assert_eq!(walked.rows, events[..walked.rows.len()].to_vec(), "a prefix of the event order");
        assert!(walked.max_held_bytes <= 16 * MIB / 100 * progressive::PAGE_BYTE_HEADROOM_PERCENT, "{}", walked.max_held_bytes);
        assert!(walked.max_statement_bytes <= 16 * MIB, "no statement over the executor's own cap");
        let last = walked.rows.last().unwrap();
        assert_eq!(progressive::row_time_us(&next.cursor_time), Some(last.0));
        assert_eq!(next.cursor_event_uid, last.1);
        assert!(next.cursor_time.ends_with('Z') && DateTime::parse_from_rfc3339(&next.cursor_time).is_ok());
        // Narrow rows never cut, and without a result limit nothing does.
        assert!(walk(&events, start, end, 0, 2_001, None, Some(16 * MIB), &width(600)).continuation.is_none());
        assert!(walk(&events, start, end, 0, 2_001, None, None, &wide).continuation.is_none());
    }

    /// Filling from the continuation yields the materialized page: strict
    /// event order, no duplicate, no gap, the same has_more, the same rows
    /// as the row-only walk; across row widths, limits and offsets (offsets
    /// before, at and past where a byte cut lands).
    #[test]
    fn filled_pages_equal_the_materialized_page_across_byte_cuts() {
        let (start, end) = window();
        let events = fixture(start, end, 3);
        let mut matrix = Vec::new();
        for base in [600_u64, 10_000, 40_000] {
            let width = width(base);
            for limit in [100_usize, 2_000, 5_000] {
                for offset in [0_usize, 800, 1_100, 1_500, 4_095, 9_000] {
                    let page = search_page(&events, start, end, offset, limit, Some(16 * MIB), &width);
                    let truth = events.iter().skip(offset).take(limit).cloned().collect::<Vec<_>>();
                    let label = format!("width ~{base} limit {limit} offset {offset}");
                    assert!(page.rows == truth, "{label}: first mismatch at {:?}", page.rows.iter().zip(&truth).position(|(a, b)| a != b));
                    assert_eq!(page.has_more, events.len() > offset + limit, "{label}");
                    let mut seen = std::collections::BTreeSet::new();
                    assert!(page.rows.iter().all(|row| seen.insert(row.1.clone())), "{label}: duplicate row");
                    assert!(page.rows.windows(2).all(|pair| pair[0] > pair[1]), "{label}: not strictly (time, uid) descending");
                    let row_only = search_page(&events, start, end, offset, limit, None, &width);
                    assert_eq!(row_only.rows, page.rows, "{label}: row-only walk");
                    assert_eq!(row_only.requests, 1);
                    matrix.push(format!("{label:<40} requests {:>2} byte_cut {}", page.requests, page.byte_cut));
                }
            }
        }
        eprintln!("NAN-3270 byte-cut fill matrix:\n{}", matrix.join("\n"));
    }

    /// The offset is walked as stubs: a deep offset of wide rows costs no
    /// budget, so its page cuts (if at all) past the offset and the
    /// continuation never needs an offset.
    #[test]
    fn offset_rows_are_stubs_and_the_cut_lands_past_the_offset() {
        let (start, end) = window();
        let events = fixture(start, end, 3);
        let wide = width(10_000);
        for offset in [1_000_usize, 1_250, 3_000, 8_000] {
            let walked = walk(&events, start, end, offset, offset + 2_001, None, Some(16 * MIB), &wide);
            assert!(walked.rows.len() > offset, "offset {offset}: cut inside the offset ({} rows)", walked.rows.len());
            assert!(walked.continuation.is_some(), "offset {offset}: 2,000 wide rows exceed the budget");
            assert_eq!(walked.rows, events[..walked.rows.len()].to_vec(), "offset {offset}");
        }
    }

    #[test]
    fn byte_budget_steps_and_admission() {
        let budget = 16 * MIB / 100 * progressive::PAGE_BYTE_HEADROOM_PERCENT;
        let mut bytes = progressive::ByteBudget::new(Some(16 * MIB), 0);
        // Unknown width: the default guess sizes the first statement.
        assert_eq!(bytes.step(0, 101), progressive::ByteStep::Rows(101));
        assert_eq!(bytes.step(0, 2_001), progressive::ByteStep::Rows((budget / progressive::DEFAULT_ROW_BYTES) as usize));
        let mut rows = (0..100).map(|n| json!({"time": "2026-10-08 05:00:00", "metadata.uid": format!("u{n}")})).collect::<Vec<_>>();
        assert_eq!(bytes.admit(0, &mut rows, &[10_000; 100]), progressive::Admitted { kept: 100, cut: false });
        // Measured width (+25%) now sizes the step.
        assert_eq!(bytes.step(100, 2_000), progressive::ByteStep::Rows(((budget - 1_000_000) / 12_500) as usize));
        // Over the budget: the rows that fit are kept, the rest dropped.
        let mut rows = (0..2_000).map(|n| json!({"n": n})).collect::<Vec<_>>();
        let admitted = bytes.admit(100, &mut rows, &[10_000; 2_000]);
        assert!(admitted.cut && rows.len() == admitted.kept);
        assert_eq!(bytes.held_bytes(), (100 + admitted.kept as u64) * 10_000);
        assert!(bytes.held_bytes() <= budget && bytes.held_bytes() + 10_000 > budget);
        // Too little room left for a useful statement: cut.
        assert_eq!(bytes.step(100 + admitted.kept, 2_000), progressive::ByteStep::Cut);
        // A lone row wider than the budget is held, then the walk stops.
        let mut lone = progressive::ByteBudget::new(Some(MIB), 0);
        let mut rows = vec![json!({"a": 1}), json!({"b": 2})];
        assert_eq!(lone.admit(0, &mut rows, &[2 * MIB, 10]), progressive::Admitted { kept: 1, cut: true });
        // Offset rows are stubbed and never held.
        let mut skipping = progressive::ByteBudget::new(Some(MIB), 2);
        let mut rows = vec![
            json!({"time": "t0", "metadata": {"uid": "a"}, "wide": "x"}),
            json!({"time": "t1", "metadata.uid": "b", "wide": "y"}),
            json!({"time": "t2", "metadata.uid": "c", "wide": "z"}),
        ];
        assert_eq!(skipping.admit(0, &mut rows, &[MIB, MIB, 10]), progressive::Admitted { kept: 3, cut: false });
        assert_eq!(rows[0], json!({"time": "t0", "metadata.uid": "a"}));
        assert_eq!(rows[1], json!({"time": "t1", "metadata.uid": "b"}));
        assert_eq!(rows[2]["wide"], "z");
        assert_eq!(skipping.held_bytes(), 10);
        // No budget: rows only.
        assert_eq!(progressive::ByteBudget::new(None, 0).step(0, 50_000), progressive::ByteStep::Rows(50_000));
        assert_eq!(progressive::line_sizes(b"{\"a\":1}\n{\"bb\":2}\n"), vec![8, 9]);
    }

    #[test]
    fn continuation_needs_a_usable_cursor() {
        let next = Continuation::after(&json!({"time": "2026-10-08 04:59:59.250000", "metadata": {"uid": "uid-9"}})).unwrap();
        assert_eq!(next, Continuation { cursor_time: "2026-10-08T04:59:59.250000Z".into(), cursor_event_uid: "uid-9".into() });
        assert!(Continuation::after(&json!({"time": "2026-10-08 04:59:59"})).is_none());
        assert!(Continuation::after(&json!({"time": "2026-10-08 04:59:59", "metadata.uid": ""})).is_none());
        assert!(Continuation::after(&json!({"metadata.uid": "u"})).is_none());
    }
}

#[cfg(test)]
#[path = "row_cliff_native_tests.rs"]
mod row_cliff_native;

#[cfg(test)]
mod background_refresh_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// NAN-3392: the request path skips its catch-up only while a background
    /// refresher runs and the view is younger than the 1 s coalesce window.
    #[test]
    fn requests_skip_the_catch_up_only_within_the_staleness_bound() {
        let now = Instant::now();
        let at = |ms: u64| now.checked_sub(Duration::from_millis(ms));
        // No background refresher: every request catches up (pre-NAN-3392).
        assert!(!request_may_skip_catch_up(false, at(0), now));
        assert!(!request_may_skip_catch_up(false, at(10), now));
        // Refresher running: a view caught up < 1 s ago is used as is.
        assert!(request_may_skip_catch_up(true, at(0), now));
        assert!(request_may_skip_catch_up(true, at(999), now));
        // At or past the bound, or never caught up: catch up inline.
        assert!(!request_may_skip_catch_up(true, at(1_000), now));
        assert!(!request_may_skip_catch_up(true, at(5_000), now));
        assert!(!request_may_skip_catch_up(true, None, now));
        // The refresher's period keeps the view inside the bound with room
        // for a p95 catch-up (178 ms).
        assert!(BACKGROUND_REFRESH_PERIOD + Duration::from_millis(178) < CATCH_UP_COALESCE);
    }

    #[test]
    fn idle_background_refresh_is_bounded_and_activity_resets_it() {
        let base = BACKGROUND_REFRESH_PERIOD;
        let mut delay = base;
        for seconds in [1, 2, 4, 8, 16, 32, 60, 60] {
            delay = background_refresh_delay(base, delay, false);
            assert_eq!(delay, Duration::from_secs(seconds));
        }
        assert_eq!(background_refresh_delay(base, delay, true), base);
        assert_eq!(background_refresh_delay(Duration::from_secs(120), delay, false), Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_background_refresh_avoids_remote_ticks_without_extending_request_freshness() {
        let target = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_periodic(Arc::downgrade(&target), BACKGROUND_REFRESH_PERIOD, |target: Arc<AtomicUsize>| async move {
            target.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        }));
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(target.load(Ordering::SeqCst), 1);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(target.load(Ordering::SeqCst), 2);
        let caught_up = Instant::now();
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(target.load(Ordering::SeqCst), 2);
        assert!(!request_may_skip_catch_up(true, Some(caught_up), caught_up + Duration::from_secs(1)));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(target.load(Ordering::SeqCst), 3);
        task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn the_refresher_ticks_on_its_period_survives_errors_and_stops_with_its_target() {
        let target = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_periodic(Arc::downgrade(&target), BACKGROUND_REFRESH_PERIOD, |target: Arc<AtomicUsize>| async move {
            let tick = target.fetch_add(1, Ordering::SeqCst);
            if tick == 1 { Err(PartQueryError::Unavailable("store blip".into())) } else { Ok(true) }
        }));
        // First tick fires at once; then one per period, an error included.
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(target.load(Ordering::SeqCst), 1);
        tokio::time::sleep(BACKGROUND_REFRESH_PERIOD * 4).await;
        assert_eq!(target.load(Ordering::SeqCst), 5);
        drop(target);
        tokio::time::sleep(BACKGROUND_REFRESH_PERIOD * 2).await;
        assert!(task.is_finished(), "the refresher exits once its service is gone");
    }
}

#[cfg(test)]
mod no_schema_yet_tests {
    use super::*;
    use crate::parts::part_log::{LocalObjectStore, PartLogWriter};
    use crate::parts::provenance::tests::TENANT;
    use arrow_schema::{DataType, Field, Schema, TimeUnit};

    /// NAN-4316: a query process started at a tenant's birth opens its part
    /// log before ingest wrote the `genesis`. The engine's schema read says
    /// so as a typed, retryable `NoSchemaYet` (503 `no_schema`, which the
    /// prewarm, identity backfill and token-layout loops treat as a quiet
    /// no-op), never an `Internal` 500; once the genesis lands it reads.
    #[tokio::test]
    async fn an_empty_log_is_no_schema_yet_until_ingest_writes_its_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let mut view = PartLogView::open(&store, TENANT, super::super::log_view::tests::trusted()).await.unwrap();
        let error = read_schema(&mut view).unwrap_err();
        assert!(matches!(error, PartQueryError::NoSchemaYet), "{error}");
        assert_eq!((error.status(), error.reason()), (503, "no_schema"));

        let schema = Schema::new(vec![
            Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
            Field::new("message", DataType::Utf8, true),
        ]);
        PartLogWriter::open(&store, TENANT, 1, &schema, 1_790_330_500_000).await.unwrap();
        view.catch_up(&store).await.unwrap();
        assert_eq!(read_schema(&mut view).unwrap().fields().len(), 2);
    }
}
