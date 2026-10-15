// SPDX-License-Identifier: AGPL-3.0-or-later

//! One bounded record per interactive request, including errors and cancellation.
//! Native file opens are inside chDB's elapsed time; the C API does not expose
//! a separate open timer. `cpu_ms` is process CPU (all threads), not attributed
//! CPU when multiple requests or background hydration overlap; NAN-3165
//! `select_cpu_ms` is this request's own thread CPU in the Rust selection
//! (sidecar decode, bloom/footer pruning), summed over synchronous sections.
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Default, Debug, serde::Serialize)]
pub struct Phases {
    #[serde(skip)]
    pub request_id: String,
    #[serde(skip)]
    pub execution_seconds: u64,
    pub plan_ms: f64,
    pub tail_manifest_ms: f64,
    pub tail_objects: usize,
    pub tail_bytes: u64,
    pub budget_bytes: Option<u64>,
    pub estimated_bytes: Option<u64>,
    #[serde(skip)]
    pub interactive_memory_budget_bytes: Option<u64>,
    pub tail_objects_considered: usize,
    pub tail_open_ms: Option<f64>,
    pub derivative_ms: f64,
    #[serde(skip)]
    pub(crate) derivative_depth: usize,
    pub chdb_ms: f64,
    /// Native stream initialization includes SQL analysis and Parquet setup;
    /// the pinned C ABI cannot split these into independent timers.
    pub native_init_ms: f64,
    /// Rust parameter validation and C-string/pointer preparation.
    pub native_bind_ms: f64,
    /// Opaque chdb_stream_query_with_params call, including native file setup.
    pub native_init_abi_ms: f64,
    pub native_fetch_ms: f64,
    /// First fetch per statement, also included in native_fetch_ms.
    pub native_first_fetch_ms: f64,
    pub native_statements: usize,
    /// Statements using a lane connection already used by an earlier statement.
    pub native_session_reused: usize,
    pub native_fetch_calls: usize,
    pub sql_prepare_ms: f64,
    pub file_prepare_ms: f64,
    pub file_verify_ms: f64,
    pub footer_read_ms: f64,
    pub decode_ms: f64,
    pub lane_wait_ms: f64,
    /// NAN-3165: thread CPU of the request's synchronous Rust selection work
    /// (sidecar decode, entity/bloom/footer pruning), attributed per request.
    pub select_cpu_ms: f64,
    /// NAN-3737: hourly index and disjoint native-leg wall times. Hours are
    /// part-hour cells (including ragged native boundary hours), not unique UTC hours.
    pub entity_count_index_ms: f64,
    pub entity_count_native_ms: f64,
    pub entity_count_index_parts: usize,
    pub entity_count_native_parts: usize,
    pub entity_count_index_hours: usize,
    pub entity_count_native_hours: usize,
    pub entity_count_fallback_reasons: std::collections::BTreeSet<crate::part_query::entity_count::Reason>,
    /// NAN-3392: wall time of the selection's sub-stages, summed over every
    /// part selection of the request: uid/entity sidecars, token indexes,
    /// and the data-file footer/bloom probe (fan-out wall, not CPU).
    pub select_sidecar_ms: f64,
    pub select_token_ms: f64,
    pub select_bloom_ms: f64,
    /// NAN-3392: per-(file, hint) footer/bloom evidence cache lookups.
    pub evidence_cache_hits: usize,
    pub evidence_cache_misses: usize,
    #[serde(skip)]
    pub(crate) outcome: Option<&'static str>,
    /// Why the request failed, bounded. A failed record without a reason is
    /// indistinguishable from a transport fault (NAN-2361: 24 silent
    /// `outcome=error` records in 2 h were all memory-fence scan rejections).
    #[serde(skip)]
    pub(crate) error: Option<String>,
    pub encode_ms: f64,
    pub rows: usize,
    pub stale_tail: bool,
    pub cache_hit: bool,
    pub local_object_hits: u64,
    pub local_object_misses: u64,
    pub log_refresh_ms: f64,
    pub rollup_fetch_ms: f64,
    pub rollup_fold_ms: f64,
    pub rollup_memo_hits: usize,
    pub rollup_memo_misses: usize,
    pub prevalence_memo_hits: usize,
    pub prevalence_memo_misses: usize,
    /// NAN-3172: why the request read what it read (numeric/bool only).
    pub funnel: Funnel,
    /// NAN-3644: uncached bytes this request fetched / expects to fetch, and
    /// its place in the per-cell heavy cold-read queue (live, for progress).
    #[serde(skip)]
    pub cold_scan: Arc<ColdScan>,
    /// NAN-3644: wall time this request waited for a heavy cold-read slot.
    pub cold_queue_ms: f64,
}

/// NAN-3644: one request's live cold-read progress. The reader cache adds
/// the uncached bytes of each lease it is about to fetch to `total_bytes`
/// and each verified object to `read_bytes`; `queued` counts this request's
/// lease calls waiting for a heavy cold-read slot. The request also owns its
/// heavy slot here, so every selection of a request that went heavy shares
/// one slot and the slot is released when the request ends.
#[derive(Default, Debug)]
pub struct ColdScan {
    pub read_bytes: std::sync::atomic::AtomicU64,
    pub total_bytes: std::sync::atomic::AtomicU64,
    pub queued: std::sync::atomic::AtomicUsize,
    /// NAN-3644: a batched cold read's whole estimate, set before its first
    /// batch is leased, so progress shows the full size from the start
    /// instead of growing batch by batch (`total_bytes` counts leases only).
    pub planned_bytes: std::sync::atomic::AtomicU64,
    heavy: tokio::sync::Mutex<Option<Arc<tokio::sync::OwnedSemaphorePermit>>>,
}

impl ColdScan {
    /// The request's heavy slot, acquired once through `acquire` (which may
    /// wait in the cell's queue). Dropping the returned future while it
    /// waits leaves the queue without taking a slot.
    pub async fn heavy_permit<F, Fut>(&self, acquire: F) -> Option<Arc<tokio::sync::OwnedSemaphorePermit>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Option<tokio::sync::OwnedSemaphorePermit>>,
    {
        use std::sync::atomic::Ordering;
        struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Relaxed); }
        }
        self.queued.fetch_add(1, Ordering::Relaxed);
        let waiting = Waiting(&self.queued);
        let mut slot = self.heavy.lock().await;
        if let Some(permit) = slot.as_ref() {
            return Some(permit.clone());
        }
        let permit = Arc::new(acquire().await?);
        drop(waiting);
        *slot = Some(permit.clone());
        Some(permit)
    }

    /// Whether this request holds a heavy slot.
    pub fn holds_heavy(&self) -> bool {
        self.heavy.try_lock().map(|slot| slot.is_some()).unwrap_or(false)
    }

    fn release(&self) {
        if let Ok(mut slot) = self.heavy.try_lock() {
            slot.take();
        }
    }
}

/// NAN-3644: the cold-read progress of every in-flight request whose id is
/// `request_id` or starts with `{request_id}-` (Search's per-chunk and
/// companion requests), summed. `None` when no such request is in flight.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct ColdProgress {
    pub requests: usize,
    pub cold_bytes_read: u64,
    pub cold_bytes_total: u64,
    pub queued: bool,
}

type ColdRegistry = Mutex<Vec<(u64, String, Arc<ColdScan>)>>;

fn cold_registry() -> &'static ColdRegistry {
    static REGISTRY: std::sync::OnceLock<ColdRegistry> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(ColdRegistry::default)
}

fn register_cold_scan(request_id: &str, scan: Arc<ColdScan>) -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let seq = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    cold_registry().lock().unwrap_or_else(|e| e.into_inner()).push((seq, request_id.to_string(), scan));
    seq
}

fn unregister_cold_scan(seq: u64) {
    cold_registry().lock().unwrap_or_else(|e| e.into_inner()).retain(|(entry, _, _)| *entry != seq);
}

pub fn cold_progress(request_id: &str) -> Option<ColdProgress> {
    use std::sync::atomic::Ordering;
    if request_id.is_empty() {
        return None;
    }
    let registry = cold_registry().lock().unwrap_or_else(|e| e.into_inner());
    let mut progress = ColdProgress::default();
    for (_, id, scan) in registry.iter() {
        let related = id == request_id
            || id.strip_prefix(request_id).is_some_and(|rest| rest.starts_with('-'));
        if !related {
            continue;
        }
        progress.requests += 1;
        progress.cold_bytes_read = progress.cold_bytes_read.saturating_add(scan.read_bytes.load(Ordering::Relaxed));
        let total = scan.total_bytes.load(Ordering::Relaxed).max(scan.planned_bytes.load(Ordering::Relaxed));
        progress.cold_bytes_total = progress.cold_bytes_total.saturating_add(total);
        progress.queued |= scan.queued.load(Ordering::Relaxed) > 0;
    }
    (progress.requests > 0).then_some(progress)
}

/// NAN-3644: announce the current request's batched cold read (its
/// estimated uncached bytes) before the first batch is leased.
pub fn plan_cold_bytes(bytes: u64) {
    if let Some(scan) = cold_scan() {
        scan.planned_bytes.fetch_max(bytes, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The current request's cold-read progress record, if any.
pub fn cold_scan() -> Option<Arc<ColdScan>> {
    current().map(|phases| phases.lock().unwrap_or_else(|e| e.into_inner()).cold_scan.clone())
}

/// NAN-3172: the selection funnel of one request, bounded and value-free:
/// counters summed over every part selection the request ran (preselect,
/// progressive chunks, counting selections), the progressive summary, the
/// density/token seed summary and the hint shape. No query text, token or
/// entity values.
#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct Funnel {
    pub selections: usize,
    pub time_parts: usize,
    pub time_files: usize,
    pub source_family_pruned_files: usize,
    pub membership_pruned_parts: usize,
    pub token_pruned_files: usize,
    pub uid_pruned_files: usize,
    pub entity_sidecar_pruned_files: usize,
    pub infile_pruned_files: usize,
    pub resident_infile_files: usize,
    pub fetched_files: usize,
    pub row_groups: usize,
    pub kept_row_groups: usize,
    pub candidate_blocks: usize,
    pub fine_runs: usize,
    /// NAN-3171: block runs declined for whole row groups.
    pub fine_declined_runs: usize,
    pub count_groups: usize,
    pub keyword_hints: usize,
    pub entity_hints: usize,
    pub uses_entities: bool,
    pub token_seed_applies: bool,
    pub progressive: bool,
    pub counting: bool,
    pub two_pass: bool,
    /// The aggregate was answered by the per-part fragment path.
    pub fragment_aggregate: bool,
    /// NAN-3644: the read was over the cold ceiling and ran in batches.
    pub cold_batches: bool,
    pub whole_window_preselected: bool,
    pub chunks_executed: usize,
    pub payload_source_files: usize,
    pub payload_narrowed_files: usize,
    pub density_seed: bool,
    pub token_seed: bool,
    /// Parts (density seed) or files (token seed) the seed consulted.
    pub seed_consulted: usize,
    pub seed_complete: Option<bool>,
    pub seed_estimated_events: Option<f64>,
}

tokio::task_local! {
    static CURRENT: Arc<Mutex<Phases>>;
}

pub fn current() -> Option<Arc<Mutex<Phases>>> {
    CURRENT.try_with(Arc::clone).ok()
}

/// NAN-3392: run synchronous `work` (on a blocking-pool thread) under the
/// request's phase record captured by [`current`] on the async side, so
/// its timers and [`select_cpu`] sections are still attributed.
pub fn in_scope<R>(phases: Option<Arc<Mutex<Phases>>>, work: impl FnOnce() -> R) -> R {
    match phases {
        Some(phases) => CURRENT.sync_scope(phases, work),
        None => work(),
    }
}

pub fn record(update: impl FnOnce(&mut Phases)) {
    if let Some(phases) = current() {
        update(&mut phases.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

#[derive(Clone, Copy)]
pub enum Phase {
    Plan,
    TailManifest,
    Derivative,
    Encode,
    LogRefresh,
    RollupFetch,
    RollupFold,
    FilePrepare,
    FileVerify,
    FooterRead,
    Decode,
}

pub struct Timer {
    phases: Option<Arc<Mutex<Phases>>>,
    phase: Phase,
    started: Instant,
}

pub fn timer(phase: Phase) -> Timer {
    if matches!(phase, Phase::Derivative) {
        record(|p| p.derivative_depth += 1);
    }
    Timer {
        phases: current(),
        phase,
        started: Instant::now(),
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        let ms = self.started.elapsed().as_secs_f64() * 1000.0;
        if let Some(phases) = &self.phases {
            let p = &mut *phases.lock().unwrap_or_else(|e| e.into_inner());
            *match self.phase {
                Phase::Plan => &mut p.plan_ms,
                Phase::TailManifest => &mut p.tail_manifest_ms,
                Phase::Derivative => &mut p.derivative_ms,
                Phase::Encode => &mut p.encode_ms,
                Phase::LogRefresh => &mut p.log_refresh_ms,
                Phase::RollupFetch => &mut p.rollup_fetch_ms,
                Phase::RollupFold => &mut p.rollup_fold_ms,
                Phase::FilePrepare => &mut p.file_prepare_ms,
                Phase::FileVerify => &mut p.file_verify_ms,
                Phase::FooterRead => &mut p.footer_read_ms,
                Phase::Decode => &mut p.decode_ms,
            } += ms;
            if matches!(self.phase, Phase::Derivative) {
                p.derivative_depth = p.derivative_depth.saturating_sub(1);
            }
        }
    }
}

/// CPU time of the calling thread (ms). Only meaningful as a delta over a
/// section that does not await (a task can move threads at an await).
pub(crate) fn thread_cpu_ms() -> Option<f64> {
    let mut time = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes one initialized timespec through a valid pointer.
    (unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) } == 0)
        .then_some(time.tv_sec as f64 * 1000.0 + time.tv_nsec as f64 / 1_000_000.0)
}

/// NAN-3165: adds the calling thread's CPU over a synchronous section to the
/// request's `select_cpu_ms` (and to `total`, when given) on drop. Never hold
/// one across an `.await`.
pub struct SelectCpu<'a> {
    started: Option<f64>,
    total: Option<&'a mut f64>,
}

pub fn select_cpu(total: Option<&mut f64>) -> SelectCpu<'_> {
    SelectCpu { started: thread_cpu_ms(), total }
}

impl Drop for SelectCpu<'_> {
    fn drop(&mut self) {
        let Some(ms) = thread_cpu_ms().zip(self.started).map(|(end, start)| (end - start).max(0.0)) else { return };
        if let Some(total) = self.total.as_deref_mut() { *total += ms; }
        record(|p| p.select_cpu_ms += ms);
    }
}

pub(crate) fn process_cpu_ms() -> Option<f64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one initialized timespec through a valid pointer.
    (unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut time) } == 0)
        .then_some(time.tv_sec as f64 * 1000.0 + time.tv_nsec as f64 / 1_000_000.0)
}

struct RequestGuard {
    request_id: String,
    phases: Arc<Mutex<Phases>>,
    /// NAN-3644: this request's entry in the cold-progress registry.
    cold_seq: u64,
    started: Instant,
    cpu_started: Option<f64>,
    outcome: &'static str,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        unregister_cold_scan(self.cold_seq);
        let p = self.phases.lock().unwrap_or_else(|e| e.into_inner());
        // The heavy cold-read slot is the request's: release it now, not
        // whenever the last clone of the phase record goes away.
        p.cold_scan.release();
        let cpu_ms = process_cpu_ms()
            .zip(self.cpu_started)
            .map(|(end, start)| (end - start).max(0.0));
        tracing::info!(
            request_id = %self.request_id,
            outcome = if self.outcome == "cancelled" { "cancelled" } else { p.outcome.unwrap_or(self.outcome) },
            plan_ms = p.plan_ms, tail_manifest_ms = p.tail_manifest_ms,
            tail_objects = p.tail_objects, tail_bytes = p.tail_bytes,
            budget_bytes = p.budget_bytes, estimated_bytes = p.estimated_bytes,
            tail_objects_considered = p.tail_objects_considered,
            tail_open_ms = ?p.tail_open_ms, derivative_ms = p.derivative_ms,
            native_init_ms = p.native_init_ms, native_fetch_ms = p.native_fetch_ms,
            native_bind_ms = p.native_bind_ms, native_init_abi_ms = p.native_init_abi_ms,
            native_first_fetch_ms = p.native_first_fetch_ms,
            native_session_reused = p.native_session_reused,
            native_statements = p.native_statements, native_fetch_calls = p.native_fetch_calls,
            sql_prepare_ms = p.sql_prepare_ms, file_prepare_ms = p.file_prepare_ms,
            file_verify_ms = p.file_verify_ms,
            footer_read_ms = p.footer_read_ms, decode_ms = p.decode_ms,
            chdb_ms = p.chdb_ms, lane_wait_ms = p.lane_wait_ms, encode_ms = p.encode_ms, cpu_ms,
            select_cpu_ms = p.select_cpu_ms, select_cpu_scope = "request_threads_sync_sections",
            entity_count_index_ms = p.entity_count_index_ms, entity_count_native_ms = p.entity_count_native_ms,
            entity_count_index_parts = p.entity_count_index_parts, entity_count_native_parts = p.entity_count_native_parts,
            entity_count_index_hours = p.entity_count_index_hours, entity_count_native_hours = p.entity_count_native_hours,
            select_sidecar_ms = p.select_sidecar_ms, select_token_ms = p.select_token_ms,
            select_bloom_ms = p.select_bloom_ms,
            evidence_cache_hits = p.evidence_cache_hits, evidence_cache_misses = p.evidence_cache_misses,
            cpu_scope = "process", tail_open_scope = "included_in_chdb",
            tail_count_scope = "active_manifest",
            local_hit_ratio = p.local_object_hits as f64 / (p.local_object_hits + p.local_object_misses).max(1) as f64,
            local_object_hits = p.local_object_hits, local_object_misses = p.local_object_misses,
            rows = p.rows, stale_tail = p.stale_tail, cache_hit = p.cache_hit,
            log_refresh_ms = p.log_refresh_ms, rollup_fetch_ms = p.rollup_fetch_ms,
            rollup_fold_ms = p.rollup_fold_ms,
            rollup_memo_hits = p.rollup_memo_hits, rollup_memo_misses = p.rollup_memo_misses,
            prevalence_memo_hits = p.prevalence_memo_hits, prevalence_memo_misses = p.prevalence_memo_misses,
            error = p.error.as_deref(),
            funnel_selections = p.funnel.selections,
            funnel_time_parts = p.funnel.time_parts, funnel_time_files = p.funnel.time_files,
            funnel_source_family_pruned_files = p.funnel.source_family_pruned_files,
            funnel_membership_pruned_parts = p.funnel.membership_pruned_parts,
            funnel_token_pruned_files = p.funnel.token_pruned_files,
            funnel_uid_pruned_files = p.funnel.uid_pruned_files,
            funnel_entity_sidecar_pruned_files = p.funnel.entity_sidecar_pruned_files,
            funnel_infile_pruned_files = p.funnel.infile_pruned_files,
            funnel_resident_infile_files = p.funnel.resident_infile_files,
            funnel_fetched_files = p.funnel.fetched_files,
            funnel_row_groups = p.funnel.row_groups, funnel_kept_row_groups = p.funnel.kept_row_groups,
            funnel_candidate_blocks = p.funnel.candidate_blocks, funnel_fine_runs = p.funnel.fine_runs,
            funnel_fine_declined_runs = p.funnel.fine_declined_runs,
            funnel_count_groups = p.funnel.count_groups,
            funnel_keyword_hints = p.funnel.keyword_hints, funnel_entity_hints = p.funnel.entity_hints,
            funnel_uses_entities = p.funnel.uses_entities, funnel_token_seed_applies = p.funnel.token_seed_applies,
            funnel_progressive = p.funnel.progressive, funnel_counting = p.funnel.counting,
            funnel_two_pass = p.funnel.two_pass, funnel_fragment_aggregate = p.funnel.fragment_aggregate,
            funnel_cold_batches = p.funnel.cold_batches,
            funnel_whole_window_preselected = p.funnel.whole_window_preselected,
            funnel_chunks_executed = p.funnel.chunks_executed,
            funnel_payload_source_files = p.funnel.payload_source_files,
            funnel_payload_narrowed_files = p.funnel.payload_narrowed_files,
            funnel_density_seed = p.funnel.density_seed, funnel_token_seed = p.funnel.token_seed,
            funnel_seed_consulted = p.funnel.seed_consulted,
            funnel_seed_complete = p.funnel.seed_complete,
            funnel_seed_estimated_events = p.funnel.seed_estimated_events,
            wall_ms = self.started.elapsed().as_secs_f64() * 1000.0,
            "interactive query phases"
        );
    }
}

/// A process-stable tier budget: SQL and plan hashes do not vary per request.
pub fn interactive_execution_seconds() -> u64 {
    static SECONDS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SECONDS.get_or_init(|| parse_interactive_seconds(std::env::var("NANO_INTERACTIVE_EXECUTION_SECONDS").ok().as_deref()))
}

fn parse_interactive_seconds(value: Option<&str>) -> u64 {
    value.and_then(|s| s.parse::<u64>().ok()).filter(|n| *n > 0).unwrap_or(55).min(60)
}

pub fn execution_seconds(tenant_seconds: u64) -> u64 {
    current().map_or(tenant_seconds, |p| {
        tenant_seconds.min(p.lock().unwrap_or_else(|e| e.into_inner()).execution_seconds)
    })
}

pub async fn measure<T, E>(
    request_id: &str,
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, E> {
    // NAN-3141: both branches await `future`; boxed, it is laid out once
    // (on the heap) instead of inline per branch.
    let future = Box::pin(future);
    if current().is_some() {
        return future.await;
    }
    let cold_scan = Arc::new(ColdScan::default());
    let phases = Arc::new(Mutex::new(Phases {
        request_id: request_id.chars().take(128).collect(),
        execution_seconds: interactive_execution_seconds(),
        cold_scan: cold_scan.clone(),
        ..Phases::default()
    }));
    let request_id: String = request_id.chars().take(128).collect();
    let cold_seq = register_cold_scan(&request_id, cold_scan);
    let guard = RequestGuard {
        request_id,
        phases: phases.clone(),
        cold_seq,
        started: Instant::now(),
        cpu_started: process_cpu_ms(),
        outcome: "cancelled",
    };
    CURRENT
        .scope(phases, async move {
            let mut guard = guard;
            let result = future.await;
            guard.outcome = if result.is_ok() { "ok" } else { "error" };
            result
        })
        .await
}

/// Upper bound on the failure reason carried by one phase record.
pub const MAX_ERROR_REASON_CHARS: usize = 512;

/// [`measure`], plus the failure reason on the request's single phase record.
///
/// The reason is the error's `Display`. For every worker HTTP error except
/// `Internal` that is the text the caller already receives; `Internal`'s full
/// text is already logged at ERROR by `ServiceError::into_response`, so the
/// record adds no new disclosure to logs.
pub async fn measure_reported<T, E: std::fmt::Display>(
    request_id: &str,
    future: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, E> {
    measure(request_id, async {
        let result = future.await;
        if let Err(error) = &result {
            let reason = error.to_string().chars().take(MAX_ERROR_REASON_CHARS).collect::<String>();
            record(|p| {
                p.error.get_or_insert(reason);
            });
        }
        result
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn interactive_budget_config_is_positive_and_at_most_client_timeout() {
        for (value, expected) in [(None, 55), (Some("0"), 55), (Some("bad"), 55), (Some("1"), 1), (Some("59"), 59), (Some("300"), 60)] {
            assert_eq!(parse_interactive_seconds(value), expected);
        }
    }

    #[tokio::test]
    async fn one_complete_info_record_for_success_error_and_cancel() {
        use tracing::instrument::WithSubscriber;
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        async {
            measure("success", async {
                let _timer = timer(Phase::Plan);
                record(|p| {
                    p.rows = 3;
                    p.budget_bytes = Some(100);
                    p.estimated_bytes = Some(720);
                    p.tail_objects_considered = 7;
                    p.stale_tail = true;
                    p.funnel.selections = 2;
                    p.funnel.time_files = 40;
                    p.funnel.token_pruned_files = 31;
                    p.funnel.kept_row_groups = 3;
                    p.funnel.keyword_hints = 1;
                    p.funnel.token_seed_applies = true;
                    p.funnel.progressive = true;
                    p.funnel.seed_complete = Some(true);
                    p.funnel.seed_estimated_events = Some(144.0);
                });
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
            assert!(measure("error", async { Err::<(), _>(()) }).await.is_err());
            assert!(measure("lane-timeout", async {
                record(|p| {
                    p.outcome = Some("lane_wait_timeout");
                    p.lane_wait_ms = 20.0;
                });
                Err::<(), _>(())
            })
            .await
            .is_err());
            let cancelled = measure("cancel", async {
                // A dropped request must win over an earlier phase outcome,
                // and nested route measurement must emit only one record.
                record(|p| p.outcome = Some("lane_wait_timeout"));
                measure("nested", std::future::pending::<Result<(), ()>>()).await
            });
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(1), cancelled)
                    .await
                    .is_err()
            );
        }
        .with_subscriber(subscriber)
        .await;
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let records = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 4);
        for (record, outcome) in
            records
                .iter()
                .zip(["ok", "error", "lane_wait_timeout", "cancelled"])
        {
            assert_eq!(record["level"], "INFO");
            let fields = &record["fields"];
            assert_eq!(fields["outcome"], outcome);
            for key in [
                "request_id",
                "plan_ms",
                "tail_manifest_ms",
                "tail_objects",
                "tail_bytes",
                "tail_open_ms",
                "derivative_ms",
                "chdb_ms",
                "lane_wait_ms",
                "encode_ms",
                "cpu_ms",
                "rows",
            ] {
                assert!(fields.get(key).is_some(), "missing {key}: {fields}");
            }
        }
        assert_eq!(records[0]["fields"]["stale_tail"], true);
        assert_eq!(records[0]["fields"]["rows"], 3);
        assert_eq!(records[0]["fields"]["budget_bytes"], 100);
        assert_eq!(records[0]["fields"]["estimated_bytes"], 720);
        assert_eq!(records[0]["fields"]["tail_objects_considered"], 7);
        let first = &records[0]["fields"];
        assert_eq!(first["funnel_selections"], 2);
        assert_eq!(first["funnel_time_files"], 40);
        assert_eq!(first["funnel_token_pruned_files"], 31);
        assert_eq!(first["funnel_kept_row_groups"], 3);
        assert_eq!(first["funnel_keyword_hints"], 1);
        assert_eq!(first["funnel_token_seed_applies"], true);
        assert_eq!(first["funnel_progressive"], true);
        assert_eq!(first["funnel_counting"], false);
        assert_eq!(first["funnel_seed_complete"], true);
        assert_eq!(first["funnel_seed_estimated_events"], 144.0);
        // Every record carries the whole funnel, numeric/bool only (the
        // two optional seed fields only when a seed ran).
        for (index, record) in records.iter().enumerate() {
            let fields = record["fields"].as_object().unwrap();
            let funnel = fields.iter().filter(|(key, _)| key.starts_with("funnel_")).collect::<Vec<_>>();
            assert_eq!(funnel.len(), if index == 0 { 35 } else { 33 }, "{funnel:?}");
            for (key, value) in funnel {
                assert!(value.is_number() || value.is_boolean() || value.is_null(), "{key}={value}");
            }
        }
    }

    #[tokio::test]
    async fn an_error_record_names_its_reason() {
        use tracing::instrument::WithSubscriber;
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(move || writer.clone())
            .finish();
        async {
            measure_reported("ok", async { Ok::<_, String>(()) }).await.unwrap();
            let reason = "query scan budget rejected 767550979 bytes above 536870912";
            assert!(measure_reported("rejected", async { Err::<(), _>(reason.to_string()) })
                .await
                .is_err());
            let long = "x".repeat(4096);
            assert!(measure_reported("long", async { Err::<(), _>(long) }).await.is_err());
        }
        .with_subscriber(subscriber)
        .await;
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        let records = output
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["fields"]["outcome"], "ok");
        assert!(records[0]["fields"].get("error").is_none());
        assert_eq!(records[1]["fields"]["outcome"], "error");
        assert_eq!(
            records[1]["fields"]["error"],
            "query scan budget rejected 767550979 bytes above 536870912"
        );
        let bounded = records[2]["fields"]["error"].as_str().unwrap();
        assert!(bounded.chars().count() <= MAX_ERROR_REASON_CHARS, "{}", bounded.len());
    }

    #[tokio::test]
    async fn phase_shape_and_concurrent_requests_are_isolated() {
        async fn request(rows: usize) {
            measure("test", async {
                record(|p| p.rows = rows);
                tokio::task::yield_now().await;
                let value = serde_json::to_value(&*current().unwrap().lock().unwrap()).unwrap();
                for field in [
                    "plan_ms",
                    "tail_manifest_ms",
                    "tail_objects",
                    "tail_bytes",
                    "tail_open_ms",
                    "derivative_ms",
                    "chdb_ms",
                    "lane_wait_ms",
                    "native_init_ms",
                    "native_first_fetch_ms",
                    "native_statements",
                    "native_session_reused",
                    "native_fetch_calls",
                    "native_bind_ms",
                    "native_init_abi_ms",
                    "native_fetch_ms",
                    "sql_prepare_ms",
                    "file_prepare_ms",
                    "file_verify_ms",
                    "footer_read_ms",
                    "decode_ms",
                    "encode_ms",
                    "rows",
                ] {
                    assert!(value.get(field).is_some(), "missing {field}");
                }
                assert!(value["tail_open_ms"].is_null());
                assert_eq!(value["rows"], rows);
                Ok::<_, ()>(())
            })
            .await
            .unwrap();
        }
        tokio::join!(request(7), request(19));
        assert!(current().is_none());
    }
}
