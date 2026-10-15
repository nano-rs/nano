// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ingest[T]`: one process per active tenant (design §3.1).
//!
//! notices → existing bronze admission/normalize/enrich → uid window → L0
//! parts (+ token index, partials, blooms, signed provenance) → one `add` log
//! entry → ack notices. In the background of the same loop: tiered merges,
//! supersession GC, the hourly Iceberg export plan, and stall/lag health.
//!
//! Failure model: any error after rows enter the buffer is fail-stop. The
//! supervisor restarts the process; the log is the durable dedup state and
//! unacked notices are redelivered, so a restart (or `kill -9`) never loses
//! or duplicates a row.

use anyhow::{ensure, Context, Result};
use arrow_array::RecordBatch;
use arrow_schema::{Schema, SchemaRef};
use chrono::DateTime;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::dedup::{part_may_contain_any, payload_hash64, Seen, UidWindow, PAYLOAD_UNKNOWN};
use super::late_dedup::LateUidTier;
use super::discovery::{AckCounts, NoticeHandle, NoticeQueue, SourceNotice};
use super::export::{plan_export, ExportState};
use super::merge::{merge_parts, MergeInput};
use super::prevalence::IngestPrevalence;
use super::prevalence_owner_store::PrevalenceAccess;
use super::part_gc_gate::{
    PartGcAuthority, PartGcDecision, REASON_AUTHORITY_MISSING, REASON_AUTHORITY_UNREADABLE, REASON_SANCTIONED_PASS_PAUSED,
    REASON_SANCTIONED_PATH_UNAVAILABLE,
};
use super::schema::{additive_merge, align, coerce_to_schema, decode_parallel, infer_schema};
use super::writer::{publish_parts, sort_by_time_uid, FinishedPart, PartDraft, PartWriter, PartialSource};
use crate::bronze::{admit_bronze_files_attributing, NoCanonicalEvents, RowRefusal};
use crate::ingest_source_counters::{RefusedSources, SourceKey};
use crate::parts::refusal_tally;
use crate::enrichment::BronzeIngestEnricher;
use crate::parts::format::{LogKeys, PartId, PartKeys, PROVENANCE_FILE};
use crate::parts::levels::{plan_merges_with, FlushPolicy, Level, MergePolicy, FLUSH_MAX_ROWS};
use crate::parts::part_log::{AppendOutcome, LogEntry, LogOp, LogSchema, ObjectStore, PartLogWriter, PartRef, Rejection, SourceRef, WriteHints, WriterClass};
use super::finding_append::{FindingAppendRequest, FindingAppendResponse};
use super::finding_outbox::{committed_receipts, FindingReceipt};
use crate::parts::provenance::{
    Admission, PartInputs, PartSigner, PartialKind, SignedProvenance, SourceObject, TenantKeySet, ADMISSION_CONTRACT,
};
use crate::parts::{event_hour_of, sha256_hex, DedupPolicy, DedupWindow};

/// Errors no in-process retry can repair. The cell also checks its retry
/// window before starting GC, and credential epoch changes exit before tick.
pub(crate) fn fatal_ingest_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<crate::parts::part_log::Fenced>().is_some()
            || cause.downcast_ref::<crate::edge_log::EdgeLogFenced>().is_some()
            || cause.downcast_ref::<crate::parts::part_log::DoubleConsume>().is_some()
            || cause.downcast_ref::<super::r2_put::TerminalPutError>().is_some()
    })
}

#[derive(Debug, Clone)]
pub struct IngestConfig {
    pub tenant_id: String,
    /// 0700 per-tenant working directory (under ~/.cache in the lab).
    pub work_dir: PathBuf,
    pub build: String,
    pub merge_policy: MergePolicy,
    pub dedup: DedupPolicy,
    pub max_objects_per_admission: usize,
    pub max_merges_per_tick: usize,
    /// Run merges in bounded background lanes that `tick` polls without
    /// waiting (the cell sets this): an hour seal is minutes of CPU and must
    /// not hold admission, flushes and edge commits. Its result is committed
    /// by a later tick. While ingest is catching up (lag past the hour
    /// seal), only minute merges start. Off: merges run inside the tick
    /// (tests, lab).
    pub background_merges: bool,
    /// Heap the admission buffer may hold (estimated bytes of the buffered
    /// JSON rows): admission takes fewer objects and the buffer flushes at
    /// this bound, whatever its row count. Buffered OCSF rows cost ~34 KB
    /// each as JSON values (6 KB decoded Arrow), so the 65,536-row flush
    /// cap alone was ~2.2 GiB, plus its decode and sort copies (NAN-3056,
    /// the lab-tenant OOMs at 4.5 GiB). The cell derives it from memory.max.
    pub buffer_budget_bytes: u64,
    /// Pipelined flushes in flight at once (NAN-3619, [`FLUSH_DEPTH_ENV`]):
    /// 1 (default) seals the next flush only after the previous one
    /// committed; 2 lets it seal while the previous one still builds and
    /// publishes. Capped by the queue's `max_outstanding_ranges`. Commits,
    /// edge ranges and acks stay in seal order either way.
    pub flush_depth: usize,
    /// Commit a finished flight as soon as it is ready (NAN-3619,
    /// [`COMMIT_WHEN_READY_ENV`], default off): also after admission and
    /// before maintenance, not only at the next ingest phase; and look past
    /// held notices when sizing the pending window. Off: today's path.
    pub commit_when_ready: bool,
    pub writer_epoch: u64,
    /// Stall threshold: oldest pending notice older than this is `stalled`.
    pub lag_alert_ms: i64,
    /// When L0 parts are cut (NAN-2984): the age cap bounds the ingest share
    /// of arrival→searchable. Cell config `ingest_flush` overrides it.
    pub flush_policy: FlushPolicy,
    /// Fixed flush interval instead of the eps-derived one (tests, lab).
    pub flush_interval_override_ms: Option<i64>,
    /// True only once the owner trusts R2's stored checksum
    /// (`controlPlane.owner.lakePartRequireChecksum`, NAN-2884). While false
    /// the interim 2 GiB part cap stays on (the owner re-hashes cell parts).
    pub owner_requires_checksum: bool,
    /// When set, every notice key must be under this prefix (the tenant's
    /// bronze prefix, e.g. `bronze-v2/`…`tenant_id=<tenant>/`).
    pub source_key_prefix: Option<String>,
    /// uid window cap (`dedup::window_cap_for` the assignment's memory).
    pub max_window_uids: usize,
    /// NAN-3387: an event hour that ended more than this long before now
    /// is deduped without fetching parts from the store. Only the uid
    /// window and parts already in the local cache are consulted, so
    /// admission cost does not depend on how many old hours a backfill
    /// spans. `None` always fetches, which was the behavior before NAN-3387.
    /// Weakening, limited to those old hours: a late event that repeats a
    /// uid committed in a part not held locally (and not in the window) is
    /// admitted again. The next merge of that hour drops the copy, since
    /// merges dedup on `(time, uid)`. Until then a search can see it twice
    /// and prevalence counts it twice.
    pub late_hour_remote_dedup_ms: Option<i64>,
    /// Byte cap on the local part cache (`budget.cache_disk_bytes`);
    /// least-recently-used parts not needed right now are evicted.
    pub cache_max_bytes: u64,
    /// Tenant-scoped object-store credential for durable prevalence state.
    pub prevalence_location: Option<PrevalenceAccess>,
    /// `false` runs ingest with prevalence unstamped (no tenant state): a
    /// production exchange without the prevalence grant, which the platform
    /// does not serve yet. With `true` and no location the DB is local (lab).
    pub prevalence_enabled: bool,
    /// Wall time each tick may spend rebuilding or catching up the
    /// prevalence state (at least one chunk or entry per tick).
    pub prevalence_rebuild_budget_ms: u64,
    /// Longest any one prevalence operation (a rebuild/catch-up step, a
    /// batch's lookups, a committed Add's apply) may take. Past it the
    /// state is dropped as stalled, ingest keeps committing unstamped, and
    /// a reopen is retried with backoff: prevalence can never block ingest
    /// (a lean test tenant 2026-09-30: SlateDB backpressure never released).
    pub prevalence_op_timeout: std::time::Duration,
    /// NAN-3774: longest the ingest loop itself waits on any one prevalence
    /// operation (a batch's lookups, a committed `Add`'s apply, a tick's
    /// catch-up step, an open or placement). Past it ingest carries on
    /// (rows unstamped, the `Add` left pending) and prevalence catches up
    /// from the part log afterwards; only an operation that keeps failing to
    /// finish for `prevalence_op_timeout` drops the state as stalled.
    /// Prevalence is derived: it never holds a commit (tenant-a 2026-10-13, R2
    /// timeouts held flushes ~2 min behind 45 s waits).
    pub prevalence_ingest_wait: std::time::Duration,
    /// Hard ceiling on one prevalence open running in the background
    /// (NAN-3554): past it the open is taken as hung, aborted, and a fresh
    /// one is retried with the normal backoff.
    pub prevalence_open_hard_timeout: std::time::Duration,
    /// Read side of the granted prevalence state in place of the grant's S3
    /// endpoint (tests: an in-memory stand-in for R2). Mutations still go
    /// only through the owner. Production leaves it `None`.
    pub prevalence_read_store: Option<Arc<dyn slatedb::object_store::ObjectStore>>,
    /// The tenant's rarity threshold for ingest-time `is_rare` stamps
    /// (NAN-3492). The cell sets it from the assignment
    /// ([`crate::prevalence::assignment_rarity_threshold`]); the default is
    /// 3 ([`crate::prevalence::DEFAULT_RARITY_THRESHOLD`]).
    pub prevalence_rarity_threshold: u64,
    /// NAN-3849: the most entries one catch-up batch applies
    /// ([`super::prevalence::CATCH_UP_BATCH_ENTRIES`]; tests lower it to
    /// stop a catch-up between batches). Not an operator setting.
    pub prevalence_catch_up_batch_entries: usize,
    /// NAN-3662 ([`refusal_tally::WRITE_ENV`], default off): each `reject`
    /// entry's detail starts with the refused rows per source lane, so
    /// query[T] can count lean refusals per log source.
    pub refusal_source_counts: bool,
}

impl IngestConfig {
    /// Apply the NAN-2884 knob to the merge policy.
    pub fn with_owner_requires_checksum(mut self, on: bool) -> Self {
        self.owner_requires_checksum = on;
        self.merge_policy.max_part_bytes =
            if on { None } else { Some(crate::parts::levels::INTERIM_MAX_PART_BYTES) };
        self
    }
}

impl IngestConfig {
    pub fn new(tenant_id: &str, work_dir: impl AsRef<Path>) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            work_dir: work_dir.as_ref().to_path_buf(),
            build: format!("nanosiem-lake-worker {}", env!("CARGO_PKG_VERSION")),
            merge_policy: MergePolicy::default(),
            dedup: DedupPolicy::default(),
            max_objects_per_admission: 64,
            max_merges_per_tick: 2,
            background_merges: false,
            buffer_budget_bytes: DEFAULT_BUFFER_BUDGET_BYTES,
            flush_depth: 1,
            commit_when_ready: false,
            writer_epoch: 1,
            lag_alert_ms: 120_000,
            flush_policy: FlushPolicy::default(),
            flush_interval_override_ms: None,
            owner_requires_checksum: false,
            source_key_prefix: None,
            max_window_uids: super::dedup::MAX_WINDOW_UIDS,
            late_hour_remote_dedup_ms: Some(DedupPolicy::default().exact_window_ms),
            cache_max_bytes: 8 * 1024 * 1024 * 1024,
            prevalence_location: None,
            prevalence_enabled: true,
            prevalence_rebuild_budget_ms: 2_000,
            prevalence_op_timeout: PREVALENCE_OP_TIMEOUT,
            prevalence_ingest_wait: PREVALENCE_INGEST_WAIT,
            prevalence_open_hard_timeout: PREVALENCE_OPEN_HARD_TIMEOUT,
            prevalence_read_store: None,
            prevalence_rarity_threshold: crate::prevalence::DEFAULT_RARITY_THRESHOLD,
            prevalence_catch_up_batch_entries: super::prevalence::CATCH_UP_BATCH_ENTRIES,
            refusal_source_counts: false,
        }
    }
}

/// The running count rewrite (NAN-3772): input rows decoded once each.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct CoverageRewrite {
    pub event_hour: i32,
    pub age_ms: i64,
    pub rows_done: u64,
    pub rows_total: u64,
}

/// A count-backfill hour given up until restart or a new window.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct CoverageFailure {
    pub event_hour: i32,
    pub reason: String,
}

/// Health written to `{work_dir}/health.json` every tick (the supervisor
/// pages on `stalled`, NAN-2780 pattern).
#[derive(Debug, Clone, Default, Serialize)]
pub struct IngestHealth {
    pub tenant_id: String,
    pub updated_at_ms: i64,
    pub last_commit_ms: Option<i64>,
    pub pending_notices: usize,
    pub oldest_pending_notice_ms: Option<i64>,
    pub lag_ms: i64,
    pub stalled: bool,
    pub buffered_rows: usize,
    pub live_parts: usize,
    pub live_parts_by_level: BTreeMap<String, usize>,
    pub merge_backlog: usize,
    /// Arrival age, independent of continuing successful ingest commits.
    pub oldest_unmerged_l0_age_ms: i64,
    /// NAN-3701: how long the most overdue L0 has waited past its merge
    /// deadline under the merge policy (`parts::levels::l0_merge_overdue_ms`).
    /// A lone L0 waiting for its hour to seal is not overdue.
    pub l0_merge_overdue_ms: i64,
    /// Settled single-hour inventory; unknown includes not-yet-probed parts.
    /// The window is durable (tenant bucket, survives a cell handover). The
    /// part counts are re-derived by probing after a restart, and every
    /// `*_total`, rate and ETA below is per-process: they restart at zero.
    pub count_backfill_window: Option<super::reindex::CountBackfill>,
    pub count_backfill_paused: bool,
    pub coverage_parts_total: usize,
    pub coverage_parts_current: usize,
    pub coverage_parts_unknown: usize,
    pub coverage_parts_failed: usize,
    pub coverage_rewrites_total: u64,
    pub coverage_rewritten_bytes_total: u64,
    pub coverage_bytes_per_second: f64,
    /// Remaining input rows (stale and not yet probed parts, less the
    /// running rewrite's progress) over the observed backfill row rate since
    /// the window was queued; `None` until a rewrite has made progress.
    pub coverage_eta_seconds: Option<f64>,
    /// NAN-3772: parts waiting out a retry backoff after a failed probe or
    /// rewrite (`coverage_parts_failed` are given up until restart).
    pub coverage_parts_retrying: usize,
    /// Count-backfill probe/rewrite failures only; `merge_failures_total`
    /// also counts every ordinary merge.
    pub coverage_failures_total: u64,
    /// NAN-3795: each given-up hour (`coverage_parts_failed`) with its
    /// terminal reason, newest first (at most 32).
    pub coverage_failed_hours: Vec<CoverageFailure>,
    pub coverage_rows_rewritten_total: u64,
    pub coverage_rows_per_second: f64,
    /// Share of one core the count rewrite paces at (adaptive, permille).
    pub coverage_share_permille: u64,
    /// NAN-3795: the tenant searched within the quiet period, so backfill
    /// starts nothing and a running rewrite paces at the floor.
    pub coverage_yielding_to_search: bool,
    /// NAN-3811: the count backfill is yielding because the prevalence state
    /// is behind or an L0 merge is overdue past its alert threshold.
    pub coverage_yielding_to_ingest: bool,
    /// NAN-3801: parts, rows and bytes fetched by counts-only backfill in
    /// this process (per-process counters; a restart resets them).
    pub coverage_counts_only_parts: u64,
    pub coverage_counts_only_rows: u64,
    pub coverage_counts_only_fetched_bytes: u64,
    /// The owner cannot sign count records: counts use full rewrites.
    pub coverage_counts_only_unsupported: bool,
    pub coverage_rewrite_in_flight: Option<CoverageRewrite>,
    pub window_uids: usize,
    pub window_hours: usize,
    /// Live parts admission did not fetch to dedup an old event hour
    /// (NAN-3387, `IngestConfig::late_hour_remote_dedup_ms`).
    pub late_dedup_parts_unfetched_total: u64,
    /// NAN-3703 late-hour uid tier: rows of an event hour that ended 6–72 h
    /// ago dropped as duplicates of a uid the tier holds.
    pub late_dedup_tier_duplicates_total: u64,
    /// Rows of a 6–72 h event hour admitted while some live part of the
    /// hour was neither in the window, the tier nor the local cache (tier
    /// not loaded yet, or a background fold pending). Merge drops copies.
    pub late_dedup_unverified_rows_total: u64,
    /// Rows of an event hour that ended more than 72 h ago admitted without
    /// a complete dedup check (only the window and cached parts consulted).
    pub late_dedup_beyond_horizon_rows_total: u64,
    pub late_dedup_tier_hours: usize,
    pub late_dedup_tier_uids: u64,
    pub late_dedup_tier_bloom_bytes: u64,
    pub late_dedup_tier_ready: bool,
    pub late_dedup_tier_spills_total: u64,
    pub late_dedup_tier_folds_total: u64,
    pub late_dedup_tier_fold_failures_total: u64,
    pub late_dedup_tier_hours_dropped_over_budget_total: u64,
    pub rows_committed_total: u64,
    pub duplicates_dropped_total: u64,
    /// Of `duplicates_dropped_total`: cross-batch duplicates whose payload
    /// (source identity, `logged_time` / `processed_time` /
    /// `original_event_uid` excluded) differs from the kept first row's
    /// (NAN-3704). Duplicates of uids re-hydrated from parts are not
    /// compared and never count here. Also counts in-batch rows dropped
    /// because another row of the same admission holds their uid under a
    /// different source identity (NAN-3719); those are in-batch duplicates,
    /// not part of `duplicates_dropped_total`.
    pub same_uid_payload_diff_total: u64,
    pub objects_consumed_total: u64,
    pub objects_rejected_total: u64,
    pub objects_missing_total: u64,
    /// Notices for objects the log already consumed (crash replay).
    pub objects_replayed_total: u64,
    pub rows_rejected_total: u64,
    /// Rows whose type-drifted values moved into `unmapped.nano_coerced`.
    pub rows_coerced_total: u64,
    pub parts_written_total: u64,
    pub merges_total: u64,
    /// Per-process (since this ingest role started), like every `*_total`
    /// here: a restart or cell handover resets it to 0 by design.
    pub merge_failures_total: u64,
    pub cache_bytes: u64,
    /// Local prevalence cache/staging bytes; excludes durable R2 state.
    pub prevalence_index_bytes: u64,
    /// `stamping`, or why rows are unstamped, e.g.
    /// `unstamped: rebuilding (3/40 parts)`.
    pub prevalence_status: String,
    /// The prevalence grant is present but its state could not be opened or
    /// used (owner 403, stale epoch, network): rows go unstamped and the open
    /// is retried with backoff. Prevalence never stops ingest.
    pub prevalence_degraded: bool,
    /// NAN-3781: how long the state has been degraded without a break, in
    /// ms (0 while healthy). Backs the `prevalence_degraded` signal.
    pub prevalence_degraded_ms: u64,
    /// NAN-3781: total degraded time since process start, in ms (closed
    /// spells plus the current one): rows went unstamped for this long.
    pub prevalence_degraded_ms_total: u64,
    /// Failed prevalence open / reopen attempts since process start.
    pub prevalence_open_failures_total: u64,
    /// Prevalence operations abandoned past `prevalence_op_timeout`.
    pub prevalence_stalls_total: u64,
    /// NAN-3774: committed part-log entries not yet in the prevalence
    /// state (the log head minus the state's cursor; 0 while caught up or
    /// before the state's cursor is first read).
    pub prevalence_behind_entries: u64,
    /// NAN-3774: how long the state has been behind the log head without a
    /// break, in ms (0 while caught up). Backs the `prevalence_behind` signal.
    pub prevalence_behind_ms: u64,
    /// NAN-3774: prevalence operations the ingest loop stopped waiting on
    /// at `prevalence_ingest_wait` (ingest went on; prevalence catches up).
    pub prevalence_deferred_total: u64,
    /// NAN-3774: admission batches committed unstamped because the state's
    /// lookups were slower than `prevalence_ingest_wait`.
    pub prevalence_unstamped_batches_total: u64,
    /// NAN-3864: event hours holding rows committed unstamped, owed a
    /// restamp once the state is at the log head.
    pub prevalence_restamp_owed_hours: usize,
    /// NAN-3864: unstamped rows stamped by a later merge or rewrite.
    pub prevalence_restamped_rows_total: u64,
    /// NAN-3864: sealed hours rewritten only to restamp them.
    pub prevalence_restamp_rewrites_total: u64,
    /// NAN-3864: owed hours dropped without a restamp (failed repeatedly,
    /// no stamp columns, or their rows expired).
    pub prevalence_restamp_given_up_total: u64,
    /// A prevalence open is running in the background (NAN-3554): it
    /// outlived `prevalence_op_timeout` and is adopted when it finishes.
    pub prevalence_opening: bool,
    /// Wall time of the last prevalence open that finished, in ms.
    pub prevalence_last_open_ms: u64,
    /// Prevalence opens started (each fences the previous writer).
    pub prevalence_opens_started_total: u64,
    /// Background opens aborted at `prevalence_open_hard_timeout`.
    pub prevalence_open_aborts_total: u64,
    /// Part-log appends refused because an earlier attempt's reservation
    /// still held the entry key (`LogKeyHeld`, NAN-3181); each one is
    /// retried in-process until the owner hands the key over.
    pub log_key_held_total: u64,
    pub eps_ewma: f64,
    pub export_pending_hours: usize,
    pub cpu_ms_admission: u64,
    pub cpu_ms_parts: u64,
    pub cpu_ms_merges: u64,
    /// Flushes whose build and upload overlapped the next admission.
    pub flushes_pipelined_total: u64,
    /// Sealed flushes not yet committed, now (NAN-3619).
    pub flushes_in_flight: usize,
    /// Most flushes that were in flight at once since start.
    pub flushes_in_flight_peak: usize,
    /// Superseded parts kept because the lake-part delete gate is closed
    /// (`part_gc_gate`); `None` while deletion is authorized.
    pub part_gc_blocked: Option<nanosiem_lake_cell::contract::PartGcBlocked>,
    /// Part files deleted through the sanctioned path (exact receipts).
    pub part_gc_deleted_total: u64,
    /// Why the last sanctioned pass stopped early, if it did.
    pub part_gc_last_pause: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickReport {
    pub admitted_rows: u64,
    /// Source bytes of the admitted objects (NAN-3522: the hold's bytes-per-row estimate).
    pub admitted_bytes: u64,
    pub duplicates: u64,
    pub flushed_parts: usize,
    pub merges: usize,
}

struct Buffered {
    /// Admitted rows per event hour, already decoded to Arrow at admission
    /// (each batch under the pending schema of its admission; the flush
    /// aligns them). NAN-3183: buffered as JSON values a wide OCSF row cost
    /// ~50 KB of heap, which capped a catch-up flush at ~18k rows.
    hours: BTreeMap<i32, Vec<RecordBatch>>,
    /// Arrow memory of `hours`.
    bytes: u64,
    hour_duplicates: BTreeMap<i32, u64>,
    rejections: Vec<Rejection>,
    rows: usize,
    since_ms: Option<i64>,
    rows_in: u64,
    duplicates: u64,
    /// Of `duplicates`: those whose payload differs from the kept row's.
    same_uid_payload_diff: u64,
    sources: Vec<SourceObject>,
    handles: Vec<NoticeHandle>,
    /// Admitted handles: (handle, source rows, rows refused in it).
    admitted: Vec<(NoticeHandle, u64, u64)>,
    /// Handles refused whole: (handle, object-scope `rows_rejected`).
    refused: Vec<(NoticeHandle, u64)>,
    /// Crash replays of already-consumed objects: (handle, rows), every row
    /// a duplicate.
    replayed: Vec<(NoticeHandle, u64)>,
    rows_refused: u64,
    /// Rows bronze admission dropped as in-batch duplicates.
    bronze_duplicates: u64,
    // Flush progress. Each stage is recorded as it lands, so a retry after
    // any partial failure redoes only what is missing (B2) and nothing new
    // is admitted until the acks land (B1).
    /// Rejections already logged (reject entries are chunked, B3).
    rejections_logged: usize,
    /// Notices without rows acknowledged (`ack_skipped`).
    skips_acked: bool,
    /// The flush's edge range, issued once and reused by a retry.
    issued_range: Option<crate::parts::EdgeLogRange>,
    /// The buffer's `add` entry committed, and how many parts it carried.
    add_committed: bool,
    parts_committed: usize,
    handle_names: HashSet<String>,
}

impl Buffered {
    fn new() -> Self {
        Self {
            hours: BTreeMap::new(),
            bytes: 0,
            hour_duplicates: BTreeMap::new(),
            rejections: Vec::new(),
            admitted: Vec::new(),
            refused: Vec::new(),
            replayed: Vec::new(),
            rows_refused: 0,
            bronze_duplicates: 0,
            rejections_logged: 0,
            skips_acked: false,
            issued_range: None,
            add_committed: false,
            parts_committed: 0,
            rows: 0,
            since_ms: None,
            rows_in: 0,
            duplicates: 0,
            same_uid_payload_diff: 0,
            sources: Vec::new(),
            handles: Vec::new(),
            handle_names: HashSet::new(),
        }
    }

    /// Some of this buffer is in the log: it must reach its acks before
    /// anything new is admitted into it (B1).
    fn partially_committed(&self) -> bool {
        self.add_committed || self.rejections_logged > 0 || self.skips_acked || self.issued_range.is_some()
    }
}

/// Everything one flush's L0 parts are built from, detached from the
/// ingestor so the build can run off the tick (NAN-3183 pipelining).
struct FlushPlan {
    dir: PathBuf,
    tenant_id: String,
    signer_key_id: String,
    schema: SchemaRef,
    fingerprint: String,
    admission: Admission,
    sources: Vec<SourceObject>,
    edge_log: Option<crate::parts::EdgeLogRange>,
    build: String,
    /// (hour, its buffered batches, its duplicates).
    hours: Vec<(i32, Vec<RecordBatch>, u64)>,
    now_ms: i64,
    /// Parallel L0 part writers ([`super::memory::writers_for`]).
    writers: usize,
}

impl FlushPlan {
    /// Each hour's rows, sorted, cut into row ranges written as separate L0
    /// parts on parallel threads (the part write was ~0.4 ms/row on one
    /// thread, the catch-up bottleneck once a flush holds FLUSH_MAX_ROWS).
    fn build(self) -> Result<Vec<FinishedPart>> {
        let mut drafts = Vec::new();
        for (hour, batches, duplicates) in &self.hours {
            let batch = sorted_hour(batches, &self.schema)?;
            for (index, (offset, len)) in l0_chunks(batch.num_rows()).into_iter().enumerate() {
                // The hour's duplicates are accounted once, on its first part.
                let duplicates = if index == 0 { *duplicates } else { 0 };
                let draft = PartDraft {
                    tenant_id: self.tenant_id.clone(),
                    signer_key_id: self.signer_key_id.clone(),
                    level: Level::L0,
                    event_hour: *hour,
                    schema: self.schema.clone(),
                    schema_fingerprint: self.fingerprint.clone(),
                    // Every L0 record of the entry carries the entry's range.
                    inputs: PartInputs::Sources { sources: self.sources.clone(), edge_log: self.edge_log.clone() },
                    admission: Some(self.admission.clone()),
                    rows_in: len as u64 + duplicates,
                    duplicates_dropped: duplicates,
                    window: DedupWindow::Exact,
                    build: self.build.clone(),
                };
                drafts.push((draft, batch.slice(offset, len)));
            }
        }
        write_l0_parts_with(&self.dir, drafts, self.now_ms, self.writers)
    }
}

/// A sealed flush (rejections logged, skips acknowledged, edge range
/// issued, schema logged) whose parts build and upload in the background
/// while the next buffer admits. At most `flush_depth` exist (NAN-3619);
/// they commit strictly in seal order (only the oldest commits, a younger
/// one that finished first waits), so `add` entries, edge acks and edge
/// ranges keep their order.
struct InFlightFlush {
    buffer: Buffered,
    /// Working-budget bytes charged until it commits
    /// ([`super::memory::flight_bytes`]).
    reserved_bytes: u64,
    /// The schema its parts are built under (already in the log).
    schema: SchemaRef,
    sealed_ms: i64,
    /// `None` once taken: awaited, or failed (the retry rebuilds on the tick).
    task: Option<tokio::task::JoinHandle<Result<(Vec<FinishedPart>, Vec<PartRef>)>>>,
    /// Built and published, awaiting the `add`.
    published: Option<(Vec<FinishedPart>, Vec<PartRef>)>,
}

/// Where the tenant prevalence state stands against the part log. Rows are
/// stamped only in `Stamping`: a stamp is permanent, so a count from a
/// half-rebuilt state would stay wrong forever.
/// First retry delay after a prevalence open failure; doubles per failure.
pub(crate) const PREVALENCE_RETRY_BASE_MS: i64 = 30_000;
/// NAN-3781: an ongoing degraded spell is re-logged at ERROR this often.
pub(crate) const PREVALENCE_DEGRADED_LOG_EVERY_MS: i64 = 60_000;
/// NAN-3781: a held state whose rebuild/catch-up steps have all failed for
/// this long is degraded (not just behind).
pub(crate) const PREVALENCE_STEP_FAILING_DEGRADED_MS: i64 = 60_000;
/// Longest delay between prevalence open retries.
pub(crate) const PREVALENCE_RETRY_MAX_MS: i64 = 600_000;

/// NAN-3554: a prevalence open running as its own task. An open replays
/// the tenant's unflushed WAL and can outlive `prevalence_op_timeout`;
/// abandoning it mid-replay (the old behavior) left its SlateDB tasks running
/// and the next attempt fenced them, so an open slower than the budget never
/// finished. The task is never cancelled: ingest stays unstamped meanwhile
/// and adopts the result when it finishes. At most one runs per ingestor.
struct PrevalenceOpening {
    handle: tokio::task::JoinHandle<Result<IngestPrevalence>>,
    started: std::time::Instant,
    /// [`Ingestor::prevalence_grant_serial`] the open was started with.
    grant_serial: u64,
}

/// Two grants carry the same credentials (a retry, not a refresh).
fn same_prevalence_grant(a: &PrevalenceAccess, b: &PrevalenceAccess) -> bool {
    a.owner.url == b.owner.url && a.owner.bearer == b.owner.bearer && a.owner.expires_at == b.owner.expires_at
        && a.owner.writer_epoch == b.owner.writer_epoch && a.owner.assignment_generation == b.owner.assignment_generation
        && a.read.endpoint == b.read.endpoint && a.read.bucket == b.read.bucket && a.read.prefix == b.read.prefix
        && a.read.access_key_id == b.read.access_key_id && a.read.secret_access_key == b.read.secret_access_key
        && a.read.session_token == b.read.session_token && a.owner_ca_file == b.owner_ca_file
}

/// Start a prevalence open as its own task. `previous` (a state opened on
/// a superseded grant) is closed first, inside the task, so the new open
/// never fences a writer that is still running.
fn spawn_prevalence_open(cfg: &IngestConfig, access: Option<PrevalenceAccess>, previous: Option<IngestPrevalence>,
    grant_serial: u64) -> PrevalenceOpening {
    let tenant = cfg.tenant_id.clone();
    let work_dir = cfg.work_dir.clone();
    let reads = cfg.prevalence_read_store.clone();
    let handle = tokio::spawn(async move {
        if let Some(previous) = previous {
            if let Err(error) = previous.close().await {
                tracing::warn!(tenant = %tenant, error = %format!("{error:#}"),
                    "closing the prevalence state opened on a superseded grant failed");
            }
        }
        IngestPrevalence::open_with_reads(&tenant, &work_dir, access.as_ref(), reads).await
    });
    PrevalenceOpening { handle, started: std::time::Instant::now(), grant_serial }
}

/// NAN-3774: a batch's prevalence lookups running as their own task.
struct PrevalenceLookupFlight {
    handle: tokio::task::JoinHandle<Result<super::prevalence::Observed>>,
    started: std::time::Instant,
}

/// The prevalence grant is held but its state is unavailable. Ingest keeps
/// running unstamped and reopens from the tick once `next_at_ms` passes.
#[derive(Debug, Clone)]
struct PrevalenceRetry {
    failures: u32,
    next_at_ms: i64,
    last_error: String,
}

fn prevalence_retry_delay_ms(failures: u32) -> i64 {
    let shift = failures.saturating_sub(1).min(16);
    PREVALENCE_RETRY_BASE_MS.saturating_mul(1_i64 << shift).min(PREVALENCE_RETRY_MAX_MS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrevalencePhase {
    /// No prevalence grant.
    Disabled,
    /// Lost or first-enabled DB: applying the saved live-set part list.
    Rebuilding { done: u32, total: u32 },
    /// Applying the `Add`s committed after the cursor (after a rebuild or a
    /// restart).
    CatchingUp,
    /// NAN-3781: emptying the state for a rebuild from the live set: the log
    /// after the cursor names a part merged away and deleted while the state
    /// was unavailable ([`PrevalenceReplayGap`]).
    Resetting,
    Stamping,
}

/// NAN-3781: a part's prevalence partial (or its provenance) is not in the
/// store. Fatal for replay only when the part is also no longer live
/// ([`PrevalenceReplayGap`]); a live part's missing partial stays an error.
#[derive(Debug, thiserror::Error)]
#[error("prevalence partial of part {part_id} is missing")]
pub struct PrevalencePartialMissing {
    pub part_id: String,
}

/// NAN-3781: catch-up cannot replay the log. An `Add` after the cursor names
/// a part that a merge removed and GC deleted (merges run while the state is
/// unavailable, and GC deletes superseded parts after the supersede grace).
/// Its rows exist only inside the merged successor, together with rows the
/// state already counted, so the state is reset and rebuilt from the live
/// set (exact, like a lost DB) instead of being skipped (rows never counted)
/// or patched from the successor (occurrences counted twice).
#[derive(Debug, thiserror::Error)]
#[error("prevalence replay gap at part-log entry {seq}: part {part_id} was merged away and deleted; rebuilding from the live set")]
pub struct PrevalenceReplayGap {
    pub seq: u64,
    pub part_id: String,
}

pub struct Ingestor<'a> {
    cfg: IngestConfig,
    parts: &'a dyn ObjectStore,
    sources: &'a dyn ObjectStore,
    queue: &'a dyn NoticeQueue,
    signer: &'a dyn PartSigner,
    trusted: TenantKeySet,
    log: PartLogWriter<'a>,
    enricher: BronzeIngestEnricher,
    /// `None`: prevalence unstamped (no grant). Rows carry no `prevalence_*`
    /// values, which search reads as N/A; the state is rebuilt from the
    /// signed live parts once a grant arrives and ingest restarts.
    prevalence: Option<IngestPrevalence>,
    enrichment_revision: Option<String>,
    schema: SchemaRef,
    /// `schema` plus leaves admitted into the buffer but not yet logged.
    pending_schema: SchemaRef,
    window: UidWindow,
    /// NAN-3703: uids of event hours the window evicted, up to 72 h back.
    late: LateUidTier,
    buffer: Buffered,
    health: IngestHealth,
    export: ExportState,
    /// Local cache dirs of superseded parts already dropped (local disk only).
    gc_done: HashSet<PartId>,
    /// The lake-part delete gate; `None` = blocked (`authority_missing`).
    gc_authority: Option<Arc<dyn PartGcAuthority>>,
    local_gc: Option<Arc<crate::lake_part_gc::local::LocalDeleteAuthority>>,
    last_sanctioned_pass_ms: Option<i64>,
    /// NAN-3818: the last sanctioned pass stopped after one bounded log-fold
    /// step; the next step is due after [`SANCTIONED_GC_CATCH_UP_INTERVAL_MS`].
    sanctioned_gc_catching_up: bool,
    /// NAN-3852: receipted deletes from completed sanctioned-pass reports
    /// (process life). `health.part_gc_deleted_total` is the max of this and
    /// the pass's live counter, so neither double counts.
    gc_deleted_reported: u64,
    last_gc_block_reason: Option<&'static str>,
    gc_blocked_since_ms: Option<i64>,
    last_admit_ms: Option<i64>,
    /// Wall-clock hour (ms / 3.6e6) of the last sampled same-uid payload
    /// diff log line: at most one per tenant per hour (NAN-3704).
    payload_diff_logged_hour: Option<i64>,
    /// Same sampling for in-batch same-uid conflicts (NAN-3719).
    in_batch_conflict_logged_hour: Option<i64>,
    /// JSON-value heap bytes per source object byte, learned from admissions
    /// (starts conservative): bounds what one admission holds in flight.
    heap_per_source_byte: f64,
    /// Buffered Arrow bytes per source object byte, learned the same way:
    /// sizes the next admission to the room left in the buffer.
    arrow_per_source_byte: f64,
    /// (level, hour) → (consecutive failures, retry not before ms).
    merge_quarantine: BTreeMap<(String, i32), (u32, i64)>,
    /// Background merges, bounded independently by minute/history lane.
    merge_in_flight: Vec<InFlightMerge>,
    /// Pipelined flushes still building/publishing, oldest (next to
    /// commit) first (NAN-3183; up to `flush_depth`, NAN-3619).
    flush_in_flight: VecDeque<InFlightFlush>,
    /// Woken when a flight's build/publish task finishes, so the loop
    /// commits it now rather than after its idle sleep (NAN-3619).
    flight_wake: Option<std::sync::Arc<tokio::sync::Notify>>,
    merge_schedule_log_ms: i64,
    /// NAN-3077 old-hour reindex: per live `h` part, whether all enabled coverage goals
    /// are current (probed once per signed part), failed hours to skip, and the earliest next reindex start.
    index_current: std::collections::HashMap<crate::parts::format::PartId, bool>,
    reindexed_hours: std::collections::BTreeSet<i32>,
    /// NAN-3795: why each given-up hour in `reindexed_hours` stopped.
    coverage_given_up: BTreeMap<i32, String>,
    reindex_not_before_ms: i64,
    coverage_started_ms: Option<i64>,
    count_backfill: Option<super::reindex::CountBackfill>,
    count_backfill_attempts: std::collections::BTreeSet<i32>,
    /// NAN-3772: hour → (consecutive failures, retry not before ms) of a
    /// coverage probe or rewrite that failed; retried with backoff, given
    /// up (`reindexed_hours`) after [`super::reindex::MAX_COVERAGE_ATTEMPTS`].
    coverage_retry: BTreeMap<i32, (u32, i64)>,
    /// A stale, local part whose rewrite was planned but not launched (lane,
    /// memory or buffer busy): launched later without probing it again.
    reindex_ready: Option<PartRef>,
    /// Input rows of count rewrites committed since the window was queued.
    coverage_backfill_rows_done: u64,
    /// Counts-only rows of this process when the window was queued.
    counted_rows_base: u64,
    /// The store the background reindex fetch uses (`'static`: the cell's
    /// leaked handle); without one the reindex never runs.
    background_parts: Option<&'static dyn ObjectStore>,
    background_signer: Option<&'static dyn PartSigner>,
    /// The one in-flight background probe/fetch (see
    /// `probe_and_fetch_for_reindex`).
    reindex_fetch: Option<(PartRef, tokio::task::JoinHandle<Result<Option<(PathBuf, String)>>>)>,
    /// An `Add` committed to the log but not yet fully applied to the
    /// prevalence state. Merges wait for replay: merging an unapplied L0
    /// away would lose its observations.
    prevalence_pending: bool,
    prevalence_phase: PrevalencePhase,
    /// The saved rebuild part list while `Rebuilding`.
    prevalence_rebuild: Option<Arc<[PartRef]>>,
    /// A partial fetched and verified in this process whose apply yielded
    /// mid-part; reused by the next tick instead of downloading it again.
    prevalence_partial: Option<(String, PathBuf)>,
    /// Partials of the next parts, fetched ahead (at most
    /// [`PREVALENCE_PREFETCH`]), keyed by part id.
    prevalence_prefetched: BTreeMap<String, PathBuf>,
    /// Test hook: fail the next post-commit prevalence apply once.
    prevalence_fault: bool,
    /// Integration tests (NAN-3879): the next this-many state writes (a
    /// post-commit apply, a catch-up) stall past the ingest wait first.
    prevalence_stall_ops: u32,
    /// A refreshed exchange withheld the grant: the state was closed before
    /// its credential expired and reopens when a grant returns (NAN-3017).
    /// Also set for every reopen, retry and failed open (grant still held).
    prevalence_suspended: bool,
    /// NAN-3864: only the withheld grant ([`Self::suspend_prevalence`]), not
    /// a reopen or an unavailable state: rows committed then are not owed.
    prevalence_grant_withheld: bool,
    /// Set while the grant is held but the state is unavailable (open,
    /// hydrate or rotate failed): the tick retries the open with backoff.
    prevalence_retry: Option<PrevalenceRetry>,
    /// NAN-3867: the lean erasure executor (idle without an erasure ledger).
    erasure: erasure_exec::ErasureExec,
    /// The open in flight, if any (NAN-3554).
    prevalence_opening: Option<PrevalenceOpening>,
    /// Bumped whenever `cfg.prevalence_location` changes credentials: an
    /// open that finishes on an older grant is not adopted as is.
    prevalence_grant_serial: u64,
    /// NAN-3774: a batch lookup that outlived `prevalence_ingest_wait` and
    /// finishes in the background (warming the cache); later batches go
    /// unstamped without waiting until it does.
    prevalence_lookup: Option<PrevalenceLookupFlight>,
    /// NAN-3879: how long admission has waited on the state during the
    /// current overrun spell (an op past the ingest wait, or a lookup still
    /// in flight). Capped at [`PREVALENCE_ADMIT_OVERRUN_WAITS`] ingest waits;
    /// reset once the state answers.
    prevalence_admit_waited: std::time::Duration,
    /// NAN-3774: since when prevalence operations have been overrunning
    /// `prevalence_ingest_wait` without one finishing. While set, the commit
    /// path does not touch the state (rows unstamped, `Add`s pending); only
    /// the tick probes it, and past `prevalence_op_timeout` it is dropped as
    /// stalled and reopened.
    prevalence_blocked_since: Option<std::time::Instant>,
    /// NAN-3811: [`IngestPrevalence::chunk_reads_done`] at the last overrun.
    /// While it advances the store is answering (slowly), so the stall clock
    /// restarts instead of dropping a state that is making progress.
    prevalence_overrun_reads: Option<u64>,
    /// NAN-3774: the state is open but its placement against the part log
    /// (`hydrate_prevalence`) has not finished; the tick retries it.
    prevalence_unplaced: bool,
    /// NAN-3774: the state is being reopened (startup open past the ingest
    /// wait, credential rotation) as a routine step, not after a failure:
    /// committed `Add`s stay pending (merges wait) until it catches up.
    prevalence_reopening: bool,
    /// NAN-3774: the last log entry known to be fully in the state.
    prevalence_applied_seq: Option<u64>,
    /// NAN-3774: since when (ms) the state has been behind the log head.
    prevalence_behind_since_ms: Option<i64>,
    /// NAN-3781: since when (ms) the state has been degraded, the closed
    /// spells' total, and when the ongoing spell was last logged.
    prevalence_degraded_since_ms: Option<i64>,
    prevalence_degraded_closed_ms: u64,
    prevalence_degraded_logged_ms: i64,
    /// NAN-3781: since when (ms) every rebuild/catch-up step has failed.
    prevalence_step_failing_since_ms: Option<i64>,
    /// NAN-3849: part-log entries the batched catch-up has read and parsed
    /// (seq -> digest, entry), from the state's cursor on. A step cut at the
    /// ingest wait re-plans its batch from here instead of re-reading them.
    prevalence_log_cache: BTreeMap<u64, (String, Arc<LogEntry>)>,
    /// NAN-3849: the last entry of the catch-up batch in flight. A cut step
    /// re-plans exactly this batch, so its running reads are reused (a
    /// batch extended by newer entries would be a different batch).
    prevalence_batch_through: Option<u64>,
    last_cache_sweep_ms: i64,
    /// NAN-3864: event hours holding rows committed unstamped.
    prevalence_owed: super::restamp::OwedHours,
    /// NAN-3864: the owed hours saved in the tenant bucket by an earlier
    /// process have been merged into `prevalence_owed`.
    restamp_owed_loaded: bool,
    /// NAN-3864: name time of the newest owed-hours snapshot read or written.
    restamp_owed_saved_ms: i64,
    /// NAN-3864: a failed snapshot read or write is retried after this.
    restamp_owed_retry_ms: i64,
    /// NAN-3864: no sealed-hour restamp starts before this.
    restamp_not_before_ms: i64,
    /// NAN-3864: hour -> (consecutive failed sealed restamps, retry at ms).
    restamp_retry: BTreeMap<i32, (u32, i64)>,
    /// NAN-3864: the sealed `h` part the restamp planner chose last.
    restamp_planned: Option<PartId>,
    /// NAN-3522 over-commit hold: the cell pauses admission while the hold's
    /// token bucket is in debt. Flushes, acks and maintenance still run.
    admission_paused: bool,
    /// NAN-3522: held, an admission takes its first object plus further
    /// objects only while their source bytes fit this budget (the bucket's
    /// tokens in bytes): the debt stays at most one object, and a high hold
    /// rate is not capped at one object per tick. `None`: not held.
    admission_byte_budget: Option<u64>,
}

/// Read-only inputs of finding validation and replay proofs
/// ([`Ingestor::finding_context`]); usable without the ingestor lock.
#[derive(Clone)]
pub struct FindingAppendContext<'a> {
    pub parts: &'a dyn ObjectStore,
    pub tenant_id: String,
    pub writer_epoch: u64,
    pub trusted: TenantKeySet,
}

/// A finding append request whose receipts and signed parts were verified.
pub struct ValidatedFinding {
    pub request: FindingAppendRequest,
    proposed: Schema,
    /// An ingest attempt marker exists for a receipt: the log decides
    /// whether this is a replay ([`finding_replay_proof`]).
    pub needs_replay_proof: bool,
    /// Every stored object of every finding part (files + provenance), as
    /// its signed provenance names it.
    objects: Vec<FindingObject>,
    /// Set only by [`register_finding_parts`]; [`Ingestor::commit_finding`]
    /// refuses without it (NAN-3499).
    registered: bool,
}

#[cfg(test)]
impl ValidatedFinding {
    pub(crate) fn object_keys(&self) -> Vec<&str> {
        self.objects.iter().map(|object| object.key.as_str()).collect()
    }
}

/// One stored object of a finding part: key, SHA-256, size and the
/// writer authority's event bounds (the part's).
struct FindingObject {
    key: String,
    sha256: String,
    bytes: u64,
    hints: WriteHints,
}

/// Verify a finding append request against the store (receipts, attempt
/// markers, signed provenance). Read-only: safe to run without the ingestor
/// lock and to cancel at any point.
pub async fn validate_finding(context: &FindingAppendContext<'_>, request: FindingAppendRequest) -> Result<ValidatedFinding> {
    let tenant_id = context.tenant_id.as_str();
    ensure!(request.tenant_id == tenant_id, "finding append tenant differs");
    ensure!(request.writer_epoch == context.writer_epoch && request.writer_epoch > 0,
        "finding append writer epoch differs");
    ensure!(!request.receipts.is_empty() && request.receipts.len() <= super::finding_append::MAX_APPEND_RECEIPTS
        && !request.parts.is_empty() && request.parts.len() <= super::finding_append::MAX_APPEND_RECEIPTS,
        "finding append batch size is invalid");
    use futures::{StreamExt, TryStreamExt};
    // Receipt and marker reads run FINDING_IO_CONCURRENCY at a time: one GET
    // at a time was 256 round trips per 128-finding append (NAN-3067).
    let mut reads = Vec::with_capacity(request.receipts.len());
    for source in &request.receipts {
        reads.push(fetch_receipt_and_marker(context.parts, tenant_id, source));
    }
    let fetched = futures::stream::iter(reads).buffered(FINDING_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    let mut wanted = std::collections::BTreeMap::new();
    let mut needs_replay_proof = false;
    for (source, bytes, marker) in fetched {
        FindingReceipt::parse(&bytes, tenant_id, source)?;
        ensure!(wanted.insert((source.key.clone(), source.version.clone(), source.sha256.clone()), bytes.len() as u64).is_none(),
            "finding append repeats a receipt");
        if let Some(marker) = marker {
            ensure!(marker == serde_json::to_vec(source)?, "finding attempt marker differs");
            needs_replay_proof = true;
        }
    }
    let proposed = request.schema.to_arrow()?;
    let mut signed_sources = std::collections::BTreeSet::new();
    let mut objects = Vec::new();
    for part in &request.parts {
        ensure!(part.level == Level::L0, "finding publication must be an L0 part");
        ensure!(part.schema_fingerprint == request.schema.fingerprint,
            "finding part schema differs from its append request");
        let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
        let bytes = context.parts.get(&keys.provenance()).await?.context("finding provenance is absent")?;
        ensure!(crate::parts::sha256_hex(&bytes) == part.provenance_sha256, "finding provenance digest differs");
        let signed = SignedProvenance::verify_bytes(&bytes, tenant_id, &context.trusted)?;
        part.check_record(&signed.record, &part.provenance_sha256)?;
        ensure!(signed.record.admission.as_ref().is_some_and(|a| a.admission_contract == "finding-outbox-v1")
            && signed.record.files.partials.iter().any(|p| p.kind == PartialKind::Risk),
            "finding part lacks admitted risk provenance");
        let PartInputs::Sources { sources, edge_log: None } = &signed.record.inputs else {
            anyhow::bail!("finding part has non-receipt inputs");
        };
        let hints = super::writer::part_hints(&signed.record);
        for (name, sha256, size) in signed.record.files.all() {
            objects.push(FindingObject { key: keys.file(name), sha256: sha256.to_owned(), bytes: size, hints });
        }
        objects.push(FindingObject { key: keys.provenance(), sha256: part.provenance_sha256.clone(),
            bytes: bytes.len() as u64, hints });
        for source in sources {
            let identity = (source.key.clone(), source.version.clone(), source.sha256.clone());
            ensure!(wanted.get(&identity) == Some(&source.bytes) && source.rows == 1
                && signed_sources.insert(identity),
                "finding part names an extra or repeated receipt");
        }
    }
    ensure!(signed_sources == wanted.keys().cloned().collect(), "finding part omitted a receipt");
    Ok(ValidatedFinding { request, proposed, needs_replay_proof, objects, registered: false })
}

/// NAN-3499: detect's finding drain PUTs finding parts with its own
/// credential, outside the owner writer authority, so control holds no
/// completion receipt for their files. A committed part file without one can
/// never be deleted (lake_part_delete_attest NL007). Before the `add` commits,
/// register every object of every finding part through the cell's writer
/// authority (authorize, provider HEAD, complete). Waits for EVERY
/// registration before reporting the first error: a native write dropped
/// between authorize and complete leaves an unresolved intent. Never cancel
/// this future midway; it is bounded by the owner and store timeouts.
pub async fn register_finding_parts(context: &FindingAppendContext<'_>, validated: &mut ValidatedFinding) -> Result<()> {
    use futures::StreamExt;
    let mut registrations = Vec::with_capacity(validated.objects.len());
    for object in &validated.objects {
        registrations.push(register_finding_object(context.parts, object));
    }
    let results = futures::stream::iter(registrations)
        .buffer_unordered(FINDING_IO_CONCURRENCY)
        .collect::<Vec<_>>()
        .await;
    for result in results {
        result.context("register a finding part object with the writer authority")?;
    }
    validated.registered = true;
    Ok(())
}

async fn register_finding_object(parts: &dyn ObjectStore, object: &FindingObject) -> Result<bool> {
    parts.register_existing_with(&object.key, &object.sha256, object.bytes, &object.hints).await
}

/// A receipt with an attempt marker may already be in the log (a response
/// lost after the commit). `Some` is the committed entry; `None` means the
/// marker preceded a failed append and the request is still fresh. May scan
/// the whole log: run it WITHOUT the ingestor lock.
async fn fetch_receipt_and_marker<'s>(parts: &dyn ObjectStore, tenant_id: &str, source: &'s SourceRef)
    -> Result<(&'s SourceRef, Vec<u8>, Option<Vec<u8>>)> {
    let receipt = parts.get(&source.key).await?.context("finding receipt is absent")?;
    let marker = parts.get(&finding_attempt_key(tenant_id, source)?).await?;
    Ok((source, receipt, marker))
}

/// Partials fetched ahead during a prevalence rebuild or replay.
pub const PREVALENCE_PREFETCH: usize = 4;

/// NAN-3849: part-log entries one batched catch-up step scans past the
/// cursor (cached across steps), and how many entries / partials it fetches
/// at once.
pub const PREVALENCE_CATCH_UP_SCAN: u64 = 1_024;
pub const PREVALENCE_CATCH_UP_FETCHES: usize = 16;

/// NAN-3849: how long L0 merges yield to a prevalence catch-up. Merges wait
/// while the state replays committed `Add`s (they would otherwise race it
/// for the cell), but once the worst L0 merge is this overdue they run
/// beside the catch-up: tenant-a (2026-10-14 after r51) deferred them for the
/// whole catch-up and `l0_merge_overdue` climbed to its warn threshold
/// (15 min) and on toward its page. Below the warn threshold on purpose.
/// Merging an unapplied L0 is safe: its `Add` still names the part, whose
/// partial the replay reads from the local part cache, a copy retained when
/// that cache is evicted ([`Ingestor::retain_prevalence_inputs`]), or the
/// store (sanctioned GC keeps superseded parts at least an hour).
pub const PREVALENCE_L0_YIELD_MS: i64 = 10 * 60_000;

/// NAN-3849: L0 merges run during a prevalence catch-up once the worst L0
/// merge is [`PREVALENCE_L0_YIELD_MS`] overdue; before that they yield.
pub(crate) fn l0_merges_run_beside_prevalence(l0_merge_overdue_ms: i64) -> bool {
    l0_merge_overdue_ms >= PREVALENCE_L0_YIELD_MS
}

/// NAN-3849: outcome of one batched catch-up step.
enum CatchUpBatch {
    /// The state is at the log head.
    AtHead,
    /// A batch landed; more entries follow.
    Applied,
    /// The per-entry replay takes the next entry (one part-way in, one too
    /// large for a batch, a run of non-`Add` entries or a partial that
    /// could not be fetched: its replay-gap handling stays in one place).
    Unbatchable,
}

/// Default [`IngestConfig::prevalence_op_timeout`].
pub const PREVALENCE_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Default [`IngestConfig::prevalence_ingest_wait`]: well above a healthy
/// lookup or apply (milliseconds) and a catch-up step
/// (`prevalence_rebuild_budget_ms`, 2 s), far below the flush interval.
pub const PREVALENCE_INGEST_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// NAN-3879: admission waits (each at most the ingest wait) on a state that
/// is overrunning, per overrun spell. Past them batches go unstamped (owed a
/// restamp) until the state answers again, so a store that stops answering
/// costs ingest at most this many waits per spell, never a stall.
pub const PREVALENCE_ADMIT_OVERRUN_WAITS: u32 = 3;

/// Default [`IngestConfig::prevalence_open_hard_timeout`]: far above any
/// plausible replay (tenant-a's 470-WAL cold open is ~1-2 min), so only an open
/// that is genuinely hung (a read that never returns) reaches it.
pub const PREVALENCE_OPEN_HARD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// Concurrent object-store requests for one finding append or drain batch.
pub const FINDING_IO_CONCURRENCY: usize = 16;

pub async fn finding_replay_proof(context: &FindingAppendContext<'_>, receipts: &[SourceRef]) -> Result<Option<FindingAppendResponse>> {
    let committed = committed_receipts(context.parts, &context.tenant_id, receipts, &context.trusted).await?;
    if committed.is_empty() {
        // A marker can precede a failed append or a process crash. No
        // receipt was committed, so the original request remains valid.
        return Ok(None);
    }
    ensure!(committed.len() == receipts.len(), "finding append mixes committed and fresh receipts");
    let first = committed.values().next().context("missing committed receipt")?;
    ensure!(committed.values().all(|value| value == first), "finding append replay spans log entries");
    Ok(Some(FindingAppendResponse { seq: first.0, entry_sha256: first.1.clone() }))
}

/// A tick starts no further merge once its merges ran this long.
/// A merge running off the admission tick (`IngestConfig::background_merges`).
struct InFlightMerge {
    merge: crate::parts::levels::PlannedMerge,
    key: (String, i32),
    started_ms: i64,
    last_warn_ms: i64,
    handle: tokio::task::JoinHandle<Result<(super::merge::MergeResult, Option<PartRef>)>>,
    /// NAN-3864: the owed hour this merge restamps, its mark serial at
    /// launch, and what the task did.
    restamp: Option<InFlightRestamp>,
}

/// NAN-3864: a restamp riding on a merge.
struct InFlightRestamp {
    hour: i32,
    serial: u64,
    /// A sealed-hour rewrite planned only to restamp.
    sealed: bool,
    outcome: Arc<super::restamp::RestampOutcome>,
}

/// NAN-3864: the merge task's half of a restamp: scan the downloaded inputs
/// for unstamped rows, then read their artifacts from the state.
struct RestampTask {
    lookup: super::prevalence::PrevalenceLookup,
    hour: i32,
    sealed: bool,
    supported: bool,
    outcome: Arc<super::restamp::RestampOutcome>,
}

impl RestampTask {
    /// `Ok(None)`: merge without a restamp (nothing owed, no stamp columns,
    /// or the lookups failed; the outcome says which). A sealed-hour rewrite
    /// planned only to restamp stops instead ([`super::restamp::RestampSkip`]).
    async fn prepare(&self, inputs: &[MergeInput]) -> Result<Option<Arc<super::restamp::RestampMap>>> {
        use super::restamp::{RestampMap, RestampResult, RestampSkip};
        if !self.supported {
            self.outcome.set(RestampResult::Unsupported);
            return if self.sealed { Err(RestampSkip::NothingOwed(self.hour).into()) } else { Ok(None) };
        }
        let files = inputs.iter().map(|input| super::writer::local_data_files(&input.dir))
            .collect::<Result<Vec<_>>>()?.concat();
        let (rows, artifacts) = tokio::task::spawn_blocking(move || super::restamp::unstamped_artifacts(&files)).await
            .context("prevalence restamp scan panicked")??;
        if rows == 0 {
            self.outcome.set(RestampResult::NothingOwed);
            return if self.sealed { Err(RestampSkip::NothingOwed(self.hour).into()) } else { Ok(None) };
        }
        let failed = |reason: String| -> Result<Option<Arc<RestampMap>>> {
            tracing::warn!(hour = self.hour, rows, reason = %reason, "prevalence restamp lookups failed; the hour stays owed");
            self.outcome.set(RestampResult::LookupFailed(reason.clone()));
            if self.sealed { Err(RestampSkip::Deferred { hour: self.hour, reason }.into()) } else { Ok(None) }
        };
        let distinct = artifacts.len();
        let budget = if self.sealed { super::restamp::RESTAMP_LOOKUP_TIMEOUT } else { super::restamp::RESTAMP_MERGE_LOOKUP_TIMEOUT };
        match tokio::time::timeout(budget, self.lookup.clone().observe(artifacts)).await {
            Ok(Ok(observed)) => {
                tracing::info!(hour = self.hour, rows, artifacts = distinct, sealed = self.sealed, "prevalence restamp looked up");
                Ok(Some(Arc::new(RestampMap::new(observed.scalars()))))
            }
            Ok(Err(error)) => failed(format!("{error:#}")),
            Err(_) => failed(format!("lookups took over {} s", budget.as_secs())),
        }
    }
}

/// NAN-3864: record what a finished merge restamped.
fn restamp_applied(map: Option<&super::restamp::RestampMap>, outcome: Option<&super::restamp::RestampOutcome>, ok: bool) {
    if let (Some(map), Some(outcome), true) = (map, outcome, ok) {
        outcome.set(super::restamp::RestampResult::Applied { rows: map.restamped_rows() });
    }
}

/// Default [`IngestConfig::buffer_budget_bytes`] (lab, tests).
pub const DEFAULT_BUFFER_BUDGET_BYTES: u64 = 768 * 1024 * 1024;
/// Share of ingest[T]'s memory cap for its working set (NAN-3183 OOM): the
/// admission group, the filling Arrow buffer, the flush in flight with its
/// build copies and writers, and the merge lanes are all charged against it
/// (`super::memory`). The uid window (30%) and the process base sit beside.
pub const BUFFER_BUDGET_SHARE: f64 = 0.30;
/// Heap per compressed source byte before any admission was measured:
/// Parquet bronze of wide OCSF rows inflates into JSON values (the load-test tenant edge
/// segments model at 110 B/byte; NAN-3183 `catchup_memory_profile`).
const INITIAL_HEAP_PER_SOURCE_BYTE: f64 = 120.0;
/// Buffered Arrow bytes per compressed source byte before any admission
/// was measured (decoded Arrow is several times leaner than JSON values).
const INITIAL_ARROW_PER_SOURCE_BYTE: f64 = 40.0;

/// Estimated heap bytes of a JSON value (serde_json, BTreeMap objects):
/// malloc-rounded string buffers plus B-tree nodes (a leaf holds up to 11
/// `(String, Value)` slots, ~640 B, however few are used). Calibrated on
/// wide OCSF rows (NAN-3056 `hour_merge_memory_at_tenant_width`).
pub fn value_heap_bytes(value: &Value) -> u64 {
    // Allocator rounding and fragmentation measured on top of the node
    // model: resident growth was 1.8x the modelled bytes.
    value_node_bytes(value) * 9 / 5
}

fn value_node_bytes(value: &Value) -> u64 {
    fn text(len: usize) -> u64 {
        if len == 0 { 0 } else { (len as u64).div_ceil(16) * 16 + 16 }
    }
    match value {
        Value::String(value) => text(value.len()),
        Value::Array(items) => 16 + items.len() as u64 * 32 + items.iter().map(value_node_bytes).sum::<u64>(),
        Value::Object(map) => {
            let nodes = (map.len() as u64).div_ceil(8).max(1);
            nodes * 656 + map.iter().map(|(k, v)| text(k.len()) + value_node_bytes(v)).sum::<u64>()
        }
        _ => 0,
    }
}

/// The sources a buffer's `add` consumes, sorted.
fn consumed_sources(buffer: &Buffered) -> Vec<SourceRef> {
    let mut sources = buffer.sources.clone();
    sources.sort();
    sources.into_iter().map(|s| SourceRef { key: s.key, version: s.version, sha256: s.sha256 }).collect()
}

/// Rows sampled per [`sampled_value_heap`] estimate.
const HEAP_SAMPLE_STRIDE: usize = 16;

/// Estimated JSON-value heap of `rows` from every 16th row.
fn sampled_value_heap(rows: &[crate::iceberg::EventRow]) -> f64 {
    let sampled = rows.iter().step_by(HEAP_SAMPLE_STRIDE).map(|row| value_heap_bytes(&row.ocsf_event)).collect::<Vec<_>>();
    if sampled.is_empty() {
        return 0.0;
    }
    sampled.iter().sum::<u64>() as f64 * rows.len() as f64 / sampled.len() as f64
}

/// The window payload hash of each kept uid, row-aligned (NAN-3704). A uid
/// admission has no source identity for (never expected) is not compared.
fn payload_hashes(uids: &[String], digests: &BTreeMap<String, [u8; 32]>) -> Vec<u64> {
    uids.iter().map(|uid| digests.get(uid).map_or(PAYLOAD_UNKNOWN, payload_hash64)).collect()
}

/// The kept admission rows as (uids, Arrow rows under `schema`), row-aligned;
/// their JSON values are dropped here. `decoded` is the conform check's
/// decode of exactly these rows when it has one (else they decode now).
fn decoded_rows(rows: Vec<crate::iceberg::EventRow>, decoded: Option<RecordBatch>, schema: &SchemaRef)
    -> Result<(Vec<String>, Option<RecordBatch>)> {
    if rows.is_empty() {
        return Ok((Vec::new(), None));
    }
    let batch = match decoded {
        Some(batch) if batch.num_rows() == rows.len() && batch.schema().fields() == schema.fields() => batch,
        _ => {
            let refs = rows.iter().map(|row| &row.ocsf_event).collect::<Vec<_>>();
            decode_parallel(schema.clone(), &refs).context("admitted rows do not decode into the pending schema")?
        }
    };
    Ok((rows.into_iter().map(|row| row.event_uid).collect(), Some(batch)))
}

/// The admission buffer budget for a process memory cap.
pub fn buffer_budget_for(memory_cap_bytes: u64) -> u64 {
    if memory_cap_bytes == 0 {
        return DEFAULT_BUFFER_BUDGET_BYTES;
    }
    ((memory_cap_bytes as f64 * BUFFER_BUDGET_SHARE) as u64).clamp(64 * 1024 * 1024, 4 * 1024 * 1024 * 1024)
}

/// Env flag for [`IngestConfig::flush_depth`] (NAN-3619). Unset or `1`:
/// one flush in flight (the serial contract). `2`: two.
pub const FLUSH_DEPTH_ENV: &str = "NANO_LAKE_INGEST_FLUSH_DEPTH";
/// Env flag for [`IngestConfig::commit_when_ready`] (NAN-3619): `1`,
/// `true` or `on`. Default off.
pub const COMMIT_WHEN_READY_ENV: &str = "NANO_LAKE_INGEST_COMMIT_WHEN_READY";

/// [`COMMIT_WHEN_READY_ENV`] parsed.
pub fn commit_when_ready_from_env(value: Option<&str>) -> bool {
    matches!(value.map(|v| v.trim().to_ascii_lowercase()).as_deref(), Some("1" | "true" | "on"))
}

/// Most pipelined flushes ever in flight at once.
pub const MAX_FLUSH_DEPTH: usize = 2;

/// [`IngestConfig::flush_depth`] from [`FLUSH_DEPTH_ENV`]: `2` turns the
/// second flight on; anything else (unset, `1`, garbage) keeps 1.
pub fn flush_depth_from_env(value: Option<&str>) -> usize {
    match value.map(str::trim) {
        Some("2") => 2,
        _ => 1,
    }
}

/// The edge source settings for a flush depth: as many outstanding ranges
/// as flights, and pull headroom for the extra flight's unacked segments.
pub fn edge_source_config(flush_depth: usize) -> crate::edge_log::EdgeLogSourceConfig {
    let depth = flush_depth.clamp(1, MAX_FLUSH_DEPTH);
    let base = crate::edge_log::EdgeLogSourceConfig::default();
    crate::edge_log::EdgeLogSourceConfig {
        max_issued_ranges: depth,
        max_buffered_bytes: base.max_buffered_bytes.saturating_mul(depth as u64),
        ..base
    }
}

/// Age cap of a flush while ingest is behind (notices waiting): flushes then
/// close on their row/byte/object caps, this only bounds a slow trickle.
pub const CATCH_UP_FLUSH_MAX_AGE_MS: i64 = 30_000;

/// Rows below which an hour of a flush stays one L0 part; above it the
/// hour is cut into up to [`MAX_PARALLEL_L0_WRITES`] parts of equal rows.
pub const L0_PARALLEL_MIN_ROWS: usize = 16_384;
pub use super::memory::MAX_PARALLEL_L0_WRITES;

/// `(offset, len)` row ranges an hour of `rows` sorted rows is written as.
pub fn l0_chunks(rows: usize) -> Vec<(usize, usize)> {
    if rows == 0 {
        return Vec::new();
    }
    let parts = (rows / L0_PARALLEL_MIN_ROWS).clamp(1, MAX_PARALLEL_L0_WRITES);
    let size = rows.div_ceil(parts);
    (0..rows).step_by(size).map(|offset| (offset, size.min(rows - offset))).collect()
}

/// One hour's buffered batches (each under the pending schema of its
/// admission) aligned to `schema` and sorted by `(time, uid)`.
pub(crate) fn sorted_hour(batches: &[RecordBatch], schema: &SchemaRef) -> Result<RecordBatch> {
    let aligned = batches.iter().map(|batch| align(batch.clone(), schema)).collect::<Result<Vec<_>>>()?;
    let batch = match aligned.as_slice() {
        [one] => one.clone(),
        _ => arrow_select::concat::concat_batches(schema, &aligned)?,
    };
    drop(aligned);
    sort_by_time_uid(&batch)
}

/// Write each `(draft, sorted rows)` as one L0 part, up to
/// [`MAX_PARALLEL_L0_WRITES`] at once; results in input order. All are
/// written (or the first error is returned after every writer finished).
#[cfg(test)]
pub(crate) fn write_l0_parts(dir: &Path, drafts: Vec<(PartDraft, RecordBatch)>, now_ms: i64) -> Result<Vec<FinishedPart>> {
    write_l0_parts_with(dir, drafts, now_ms, MAX_PARALLEL_L0_WRITES)
}

/// [`write_l0_parts`] with at most `writers` part writers at once.
pub(crate) fn write_l0_parts_with(dir: &Path, drafts: Vec<(PartDraft, RecordBatch)>, now_ms: i64, writers: usize) -> Result<Vec<FinishedPart>> {
    let write = |(draft, batch): (PartDraft, RecordBatch)| -> Result<FinishedPart> {
        let mut writer = PartWriter::create(dir, draft, PartialSource::FromRows, now_ms, batch.num_rows() as u64)?;
        writer.write(&batch)?;
        writer.finish()
    };
    if drafts.len() <= 1 {
        return drafts.into_iter().map(write).collect();
    }
    let jobs = std::sync::Mutex::new(drafts.into_iter().enumerate().collect::<std::collections::VecDeque<_>>());
    let total = jobs.lock().expect("l0 jobs").len();
    let results = std::sync::Mutex::new((0..total).map(|_| None).collect::<Vec<Option<Result<FinishedPart>>>>());
    std::thread::scope(|scope| {
        for _ in 0..writers.clamp(1, MAX_PARALLEL_L0_WRITES).min(total) {
            scope.spawn(|| loop {
                let Some((index, job)) = jobs.lock().expect("l0 jobs").pop_front() else { break };
                let result = write(job);
                results.lock().expect("l0 results")[index] = Some(result);
            });
        }
    });
    results.into_inner().expect("l0 results").into_iter()
        .map(|result| result.context("an L0 part writer did not finish")?)
        .collect()
}

pub const MERGE_TICK_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

fn parts_dir(work_dir: &Path) -> PathBuf {
    work_dir.join("parts")
}

/// The ingest-owned completion marker (under `log/checkpoints/`) proving the
/// finding attempt index covers every historical finding `Add`. Once it
/// exists, a receipt with no attempt marker was never offered to the log.
pub(crate) const FINDING_ATTEMPT_INDEX_READY: &str = "finding-attempt-index-v1";

/// The attempt marker ingest writes before any `Add` that consumes `source`.
pub(crate) fn finding_attempt_key(tenant_id: &str, source: &SourceRef) -> Result<String> {
    crate::parts::format::validate_tenant_uuid(tenant_id)?;
    Ok(format!("{}/tenant={tenant_id}/finding-outbox/receipts/.ingest-attempts/{}.json",
        crate::parts::format::PARTS_ROOT, sha256_hex(source.key.as_bytes())))
}

async fn put_finding_attempt(store: &dyn ObjectStore, tenant_id: &str, source: &SourceRef, now_ms: i64) -> Result<()> {
    let key = finding_attempt_key(tenant_id, source)?;
    let bytes = serde_json::to_vec(source)?;
    let hints = WriteHints { class: WriterClass::LakePart,
        event_hour: event_hour_of(now_ms.saturating_mul(1_000)), min_time_ms: now_ms, max_time_ms: now_ms };
    if !store.put_if_absent_with(&key, &bytes, &hints).await? {
        ensure!(store.get(&key).await?.as_deref() == Some(bytes.as_slice()),
            "finding attempt marker differs");
    }
    Ok(())
}

/// Migrate pre-index finding entries once. The immutable completion marker is
/// written last, so interruption safely resumes the migration; later ingest
/// restarts use one GET and keep no lifetime-sized receipt set in memory.
async fn initialize_finding_attempt_index(store: &dyn ObjectStore, tenant_id: &str, head: Option<u64>, now_ms: i64) -> Result<()> {
    let keys = LogKeys::new(tenant_id)?;
    // Only the ingest credential can write this checkpoint-side completion
    // marker; Detect's receipt credential can create attempt markers but
    // cannot assert that historical migration has completed.
    let ready = format!("{}{FINDING_ATTEMPT_INDEX_READY}", keys.checkpoints_prefix());
    if let Some(bytes) = store.get(&ready).await? {
        ensure!(bytes == FINDING_ATTEMPT_INDEX_READY.as_bytes(), "finding attempt index marker differs");
        return Ok(());
    }
    let receipt_prefix = format!("{}/tenant={tenant_id}/finding-outbox/receipts/", crate::parts::format::PARTS_ROOT);
    if let Some(head) = head {
        for seq in 0..=head {
            let bytes = store.get(&keys.entry(seq)).await?.context("committed part-log entry disappeared during attempt migration")?;
            let entry = LogEntry::parse_bytes(&bytes, tenant_id)?;
            if let LogOp::Add { consumed, .. } = entry.op {
                for source in consumed {
                    if source.key.starts_with(&receipt_prefix) {
                        put_finding_attempt(store, tenant_id, &source, now_ms).await?;
                    }
                }
            }
        }
    }
    let bytes = FINDING_ATTEMPT_INDEX_READY.as_bytes();
    let hints = WriteHints { class: WriterClass::LakePart,
        event_hour: event_hour_of(now_ms.saturating_mul(1_000)), min_time_ms: now_ms, max_time_ms: now_ms };
    if !store.put_if_absent_with(&ready, bytes, &hints).await? {
        ensure!(store.get(&ready).await?.as_deref() == Some(bytes),
            "finding attempt index marker differs");
    }
    Ok(())
}

fn strip_untrusted_risk_fields(event: &mut Value) {
    if let Some(unmapped) = event.get_mut("unmapped").and_then(Value::as_object_mut) {
        unmapped.remove("nano_compact_finding");
        unmapped.remove("nano_finding_outbox_trusted");
    }
}

/// A minimal seed schema for an empty log; admission grows it additively.
pub fn seed_schema() -> Schema {
    use arrow_schema::{DataType, Field, Fields, TimeUnit};
    Schema::new(vec![
        Field::new("time", DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())), false),
        Field::new(
            "metadata",
            DataType::Struct(Fields::from(vec![
                Field::new("uid", DataType::Utf8, true),
                Field::new("tenant_uid", DataType::Utf8, true),
                Field::new("version", DataType::Utf8, true),
                Field::new("log_source", DataType::Utf8, true),
            ])),
            true,
        ),
    ])
}

impl<'a> Ingestor<'a> {
    /// Open the tenant's log (genesis with `seed` when empty) and rebuild the
    /// uid window from parts committed within the window.
    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        cfg: IngestConfig,
        parts: &'a dyn ObjectStore,
        sources: &'a dyn ObjectStore,
        queue: &'a dyn NoticeQueue,
        signer: &'a dyn PartSigner,
        trusted: TenantKeySet,
        enricher: BronzeIngestEnricher,
        seed: &Schema,
        now_ms: i64,
    ) -> Result<Self> {
        std::fs::create_dir_all(parts_dir(&cfg.work_dir))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg.work_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let log = PartLogWriter::open(parts, &cfg.tenant_id, cfg.writer_epoch, seed, now_ms).await?;
        initialize_finding_attempt_index(parts, &cfg.tenant_id, log.live().head().map(|head| head.0), now_ms).await?;
        let schema = Arc::new(log.live().schema().context("log has no schema")?.to_arrow()?);
        let window = UidWindow::with_cap(&cfg.tenant_id, cfg.dedup, cfg.max_window_uids);
        let late = LateUidTier::open(&cfg.work_dir, &cfg.tenant_id, super::late_dedup::bloom_budget_for(cfg.max_window_uids), now_ms);
        let export = ExportState::load(&cfg.work_dir)?;
        // Opening the tenant's SlateDB bumps its writer epoch and writes a
        // fencing WAL: a stale writer for this tenant (an old cell) fails
        // its next state write. The part log was fenced by `writer_epoch`
        // above, so from here on this process is the only writer of both.
        // Prevalence is never fatal to ingest (degrade, don't die): with a
        // production grant, an open failure (owner 403 / stale epoch /
        // network) runs ingest unstamped and the tick retries the open.
        let mut open_failure = None;
        let mut opening_in_flight = None;
        let mut opens_started = 0;
        let mut last_open_ms = 0;
        let prevalence = if cfg.prevalence_enabled {
            // NAN-3554: the open runs as its own task. Past the budget it is
            // left running (never cancelled mid-replay) and adopted later.
            let mut opening = spawn_prevalence_open(&cfg, cfg.prevalence_location.clone(), None, 0);
            opens_started = 1;
            // NAN-3774: a granted state gets the ingest wait, not the 45 s
            // op budget: an open still replaying (tenant-a: 8-10 s) is adopted by
            // a later tick, and the first flush never waits on it. (Lab-only
            // local state keeps the op budget: a failure there is a bug.)
            let wait = match cfg.prevalence_location {
                Some(_) => cfg.prevalence_ingest_wait.min(cfg.prevalence_op_timeout),
                None => cfg.prevalence_op_timeout,
            };
            let opened = match tokio::time::timeout(wait, &mut opening.handle).await {
                Ok(joined) => {
                    last_open_ms = opening.started.elapsed().as_millis() as u64;
                    tracing::info!(tenant = %cfg.tenant_id, open_ms = last_open_ms, ok = matches!(joined, Ok(Ok(_))),
                        "prevalence state open finished");
                    joined.unwrap_or_else(|error| Err(anyhow::anyhow!("prevalence open task failed: {error}"))).map(Some)
                }
                Err(_) if cfg.prevalence_location.is_some() => {
                    tracing::info!(tenant = %cfg.tenant_id, wait_ms = wait.as_millis() as u64,
                        "prevalence state still opening (WAL replay); ingest starts unstamped and adopts it when it finishes");
                    opening_in_flight = Some(opening);
                    Ok(None)
                }
                Err(_) => {
                    opening.handle.abort();
                    Err(anyhow::anyhow!("prevalence open did not finish within {} s", cfg.prevalence_op_timeout.as_secs()))
                }
            };
            match (opened, cfg.prevalence_location.is_some()) {
                (Ok(Some(mut prevalence)), _) => {
                    prevalence.set_rarity_threshold(cfg.prevalence_rarity_threshold);
                    Some(prevalence)
                }
                (Ok(None), _) => None,
                (Err(error), true) => {
                    open_failure = Some(error);
                    None
                }
                // Lab-only local state: a failure there is a local bug.
                (Err(error), false) => return Err(error),
            }
        } else {
            tracing::warn!(tenant = %cfg.tenant_id, "no prevalence grant; ingest runs with prevalence unstamped");
            None
        };
        let count_backfill = load_count_backfill(parts, &cfg.tenant_id, &cfg.work_dir, now_ms).await?;
        let mut ingestor = Self {
            health: IngestHealth { tenant_id: cfg.tenant_id.clone(), count_backfill_window: count_backfill.clone(), ..IngestHealth::default() },
            cfg,
            parts,
            sources,
            queue,
            signer,
            trusted,
            log,
            enricher,
            prevalence,
            enrichment_revision: None,
            pending_schema: schema.clone(),
            schema,
            window,
            late,
            buffer: Buffered::new(),
            export,
            gc_done: HashSet::new(),
            gc_authority: None,
            local_gc: None,
            last_sanctioned_pass_ms: None,
            sanctioned_gc_catching_up: false,
            gc_deleted_reported: 0,
            last_gc_block_reason: None,
            gc_blocked_since_ms: None,
            last_admit_ms: None,
            payload_diff_logged_hour: None,
            in_batch_conflict_logged_hour: None,
            heap_per_source_byte: INITIAL_HEAP_PER_SOURCE_BYTE,
            arrow_per_source_byte: INITIAL_ARROW_PER_SOURCE_BYTE,
            merge_quarantine: BTreeMap::new(),
            merge_in_flight: Vec::new(),
            flush_in_flight: VecDeque::new(),
            flight_wake: None,
            merge_schedule_log_ms: 0,
            index_current: Default::default(),
            reindexed_hours: Default::default(),
            coverage_given_up: Default::default(),
            reindex_not_before_ms: 0,
            coverage_started_ms: None,
            count_backfill,
            count_backfill_attempts: Default::default(),
            coverage_retry: BTreeMap::new(),
            reindex_ready: None,
            coverage_backfill_rows_done: 0,
            counted_rows_base: 0,
            background_parts: None,
            background_signer: None,
            reindex_fetch: None,
            prevalence_pending: false,
            prevalence_phase: PrevalencePhase::Disabled,
            prevalence_rebuild: None,
            prevalence_partial: None,
            prevalence_prefetched: BTreeMap::new(),
            prevalence_fault: false,
            prevalence_stall_ops: 0,
            prevalence_suspended: false,
            prevalence_grant_withheld: false,
            prevalence_retry: None,
            prevalence_opening: opening_in_flight,
            prevalence_grant_serial: 0,
            prevalence_lookup: None,
            prevalence_admit_waited: std::time::Duration::ZERO,
            prevalence_blocked_since: None,
            prevalence_overrun_reads: None,
            prevalence_unplaced: false,
            prevalence_reopening: false,
            prevalence_applied_seq: None,
            prevalence_behind_since_ms: None,
            prevalence_degraded_since_ms: None,
            prevalence_degraded_closed_ms: 0,
            prevalence_degraded_logged_ms: 0,
            prevalence_step_failing_since_ms: None,
            prevalence_log_cache: BTreeMap::new(),
            prevalence_batch_through: None,
            last_cache_sweep_ms: 0,
            prevalence_owed: super::restamp::OwedHours::default(),
            restamp_owed_loaded: false,
            restamp_owed_saved_ms: 0,
            restamp_owed_retry_ms: 0,
            restamp_not_before_ms: 0,
            restamp_retry: BTreeMap::new(),
            restamp_planned: None,
            admission_paused: false,
            admission_byte_budget: None,
            erasure: erasure_exec::ErasureExec::default(),
        };
        ingestor.health.prevalence_opens_started_total = opens_started;
        ingestor.health.prevalence_last_open_ms = last_open_ms;
        ingestor.sweep_cache()?;
        // Do not scan every recent hour before the first admission. The
        // empty window is incomplete; prepare_hour loads authoritative
        // live parts on demand before accepting any UID for that hour.
        super::startup::advance("prevalence placement");
        if let Some(error) = open_failure {
            ingestor.prevalence_unavailable(error.context("open tenant prevalence state"), now_ms);
        } else if ingestor.prevalence_opening.is_some() {
            // Routine, not a failure: the tick adopts the open when it finishes.
            ingestor.prevalence_reopening = true;
            ingestor.prevalence_suspended = true;
        } else if ingestor.prevalence.is_some() {
            // NAN-3774: placement gets the ingest wait too; past it the tick
            // finishes it, and nothing before the first flush waits longer.
            ingestor.prevalence_unplaced = true;
            let wait = ingestor.ingest_wait();
            match tokio::time::timeout(wait, ingestor.hydrate_prevalence()).await {
                Ok(Ok(())) => ingestor.prevalence_unplaced = false,
                Ok(Err(error)) => {
                    if ingestor.cfg.prevalence_location.is_none() {
                        return Err(error);
                    }
                    ingestor.close_prevalence().await;
                    ingestor.prevalence_unavailable(error.context("place tenant prevalence state"), now_ms);
                }
                Err(_) => ingestor.prevalence_overran(now_ms, "placement at open"),
            }
        } else {
            ingestor.prevalence_phase = PrevalencePhase::Disabled;
        }
        if ingestor.prevalence_phase == PrevalencePhase::Stamping {
            if let Some(prevalence) = ingestor.prevalence.as_mut() {
                prevalence.advance_watermark(now_ms.saturating_mul(1_000));
            }
        }
        Ok(ingestor)
    }

    pub fn live_parts(&self) -> Vec<PartRef> {
        self.log.live().parts().cloned().collect()
    }

    /// Install the lake-part delete gate. Without one, no part file is
    /// ever deleted (fail closed).
    pub fn set_local_gc(&mut self, authority: Arc<crate::lake_part_gc::local::LocalDeleteAuthority>) {
        self.gc_authority = Some(Arc::new(crate::lake_part_gc::local::LocalPartGcAuthority(authority.clone())));
        self.local_gc = Some(authority);
    }

    pub fn set_part_gc_authority(&mut self, authority: Arc<dyn PartGcAuthority>) {
        self.gc_authority = Some(authority);
    }

    /// NAN-3810: feed the GC index watermark from this ingestor's part-log
    /// appends (production R2 store with the native writer only).
    pub fn set_receipted_appends(&mut self, receipted: Arc<crate::lake_part_gc::index::ReceiptedAppends>) {
        self.log.set_receipted_appends(receipted);
    }

    /// NAN-3522 over-commit hold: `byte_budget` (held) limits each admission
    /// to its first object plus what fits the budget; `paused` (only while
    /// held) admits nothing this tick. The notices stay pending in the
    /// source (edge log / Bronze), unacked.
    pub fn set_admission_hold(&mut self, byte_budget: Option<u64>, paused: bool) {
        self.admission_byte_budget = byte_budget;
        self.admission_paused = byte_budget.is_some() && paused;
    }

    pub fn health(&self) -> &IngestHealth {
        &self.health
    }

    pub fn schema(&self) -> &SchemaRef {
        &self.schema
    }

    pub fn set_initial_enrichment_revision(&mut self, revision: Option<String>) -> Result<()> {
        ensure!(self.buffer.rows == 0, "initial enrichment revision requires an empty buffer");
        self.enrichment_revision = revision;
        Ok(())
    }

    /// Rotate the tenant snapshot only at a part boundary. Buffered rows
    /// retain their old feed pins; new rows use the new immutable revision.
    pub async fn replace_enricher(&mut self, enricher: BronzeIngestEnricher, revision: Option<String>, now_ms: i64) -> Result<()> {
        self.flush_now(now_ms).await?;
        self.enricher = enricher;
        self.enrichment_revision = revision;
        Ok(())
    }

    pub fn window_uids(&self) -> usize {
        self.window.len()
    }

    /// The sole durable append point for a Detect finding publication:
    /// [`validate_finding`] + [`finding_replay_proof`] + [`Self::commit_finding`]
    /// in one call. The cell service runs the first two WITHOUT the ingestor
    /// lock (`finding_gate`), so a slow replay proof never stalls ingestion;
    /// this composition serves tests and the lab.
    pub async fn append_finding(&mut self, request: FindingAppendRequest, now_ms: i64) -> Result<FindingAppendResponse> {
        let context = self.finding_context();
        let mut validated = validate_finding(&context, request).await?;
        if validated.needs_replay_proof {
            if let Some(committed) = finding_replay_proof(&context, &validated.request.receipts).await? {
                return Ok(committed);
            }
        }
        register_finding_parts(&context, &mut validated).await?;
        self.commit_finding(validated, now_ms).await
    }

    /// What finding validation and replay proofs read: the part store, the
    /// tenant, the writer epoch and the trusted keys. Fixed for the process.
    pub fn finding_context(&self) -> FindingAppendContext<'a> {
        FindingAppendContext {
            parts: self.parts,
            tenant_id: self.cfg.tenant_id.clone(),
            writer_epoch: self.cfg.writer_epoch,
            trusted: self.trusted.clone(),
        }
    }

    /// The short, lock-holding half of a finding append: schema, durable
    /// attempt markers and the log `Add`. Serialized with `tick` by the
    /// caller's ingestor lock, so source flushes and findings share FIFO
    /// part-log order. Never cancel this future midway (the log append is
    /// not cancellation-safe); bound the wait for the lock instead.
    pub async fn commit_finding(&mut self, validated: ValidatedFinding, now_ms: i64) -> Result<FindingAppendResponse> {
        ensure!(validated.registered, "finding part objects are not registered with the writer authority");
        let ValidatedFinding { request, proposed, .. } = validated;
        // Never commit an append its requester already gave up on: its ack
        // would be lost (Broken pipe) and the next pass would have to prove
        // the replay against the log (a lean test tenant 2026-09-30, NAN-3067).
        if let Some(deadline) = request.deadline_unix_ms {
            ensure!(now_ms <= deadline, super::finding_gate::FindingRefused::Deadline("the requester's deadline passed before the commit"));
        }
        ensure!(request.tenant_id == self.cfg.tenant_id, "finding append tenant differs");
        ensure!(request.writer_epoch == self.cfg.writer_epoch && request.writer_epoch > 0,
            "finding append writer epoch differs");
        if let Some(next) = super::schema::additive_merge(&self.schema, &proposed)? {
            self.log.append(LogOp::Schema { schema: LogSchema::from_arrow(&next)? }, now_ms).await?;
            let pending = additive_merge(&next, &self.pending_schema)?.unwrap_or_else(|| next.clone());
            self.schema = Arc::new(next);
            self.pending_schema = Arc::new(pending);
        }
        // Durable intent precedes the log append. A crash in either gap
        // makes replay scan the authoritative log; a fresh request costs only
        // one point lookup and conditional marker PUT per receipt.
        {
            use futures::{StreamExt, TryStreamExt};
            let (parts, tenant) = (self.parts, self.cfg.tenant_id.as_str());
            let mut puts = Vec::with_capacity(request.receipts.len());
            for source in &request.receipts {
                puts.push(put_finding_attempt(parts, tenant, source, now_ms));
            }
            futures::stream::iter(puts).buffer_unordered(FINDING_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
        }
        // Like `commit_parts`: every committed `Add` reaches the prevalence
        // state in log order. The next tick's `advance_prevalence` replays it.
        if self.prevalence_held() {
            self.prevalence_pending = true;
        }
        let outcome = self.log.append(LogOp::Add {
            parts: request.parts, consumed: request.receipts, edge_log: None,
        }, now_ms).await?;
        let crate::parts::part_log::AppendOutcome::Committed { seq, entry_sha256 } = outcome;
        self.health.last_commit_ms = Some(now_ms);
        Ok(FindingAppendResponse { seq, entry_sha256 })
    }

    /// Fail the next post-commit prevalence apply (integration tests).
    #[doc(hidden)]
    pub fn fail_next_prevalence_apply(&mut self) {
        self.prevalence_fault = true;
    }

    /// Make the next `ops` prevalence state writes (post-commit applies and
    /// catch-up steps) overrun the ingest wait, like a busy store (NAN-3879
    /// integration tests). The stall comes before any write, so a cut op
    /// leaves the state exactly as it was.
    #[doc(hidden)]
    pub fn stall_next_prevalence_ops(&mut self, ops: u32) {
        self.prevalence_stall_ops = ops;
    }

    async fn injected_prevalence_stall(&mut self) {
        if self.prevalence_stall_ops > 0 {
            self.prevalence_stall_ops -= 1;
            tokio::time::sleep(self.ingest_wait().saturating_mul(4)).await;
        }
    }

    /// An `Add` is committed but not yet in the prevalence state.
    pub fn prevalence_pending(&self) -> bool {
        self.prevalence_pending
    }

    /// `stamping`, or why admitted rows are unstamped.
    pub fn prevalence_status(&self) -> String {
        if let (None, Some(retry)) = (&self.prevalence, &self.prevalence_retry) {
            return format!("unstamped: prevalence state unavailable ({} failures; retry at {} ms): {}",
                retry.failures, retry.next_at_ms, retry.last_error);
        }
        if self.prevalence.is_none() && self.prevalence_reopening {
            return "unstamped: prevalence state opening".into();
        }
        if self.prevalence.is_some() && self.prevalence_unplaced {
            return "unstamped: placing prevalence state".into();
        }
        if let Some(since) = self.prevalence_blocked_since {
            return format!("unstamped: prevalence state not responding for {} s; catching up once it does",
                since.elapsed().as_secs());
        }
        match self.prevalence_phase {
            PrevalencePhase::Disabled => "unstamped: no prevalence grant".into(),
            PrevalencePhase::Rebuilding { done, total } => format!("unstamped: rebuilding ({done}/{total} parts)"),
            PrevalencePhase::CatchingUp => "unstamped: catching up with committed adds".into(),
            PrevalencePhase::Resetting => "unstamped: resetting to rebuild from the live set (a replayed part was merged away)".into(),
            PrevalencePhase::Stamping if self.prevalence_pending => "stamping (replay pending)".into(),
            PrevalencePhase::Stamping => "stamping".into(),
        }
    }

    /// NAN-3774: the most the ingest loop waits on one prevalence operation.
    fn ingest_wait(&self) -> std::time::Duration {
        self.cfg.prevalence_ingest_wait.min(self.cfg.prevalence_op_timeout)
    }

    /// The commit path may use the state now: open, placed, and not
    /// overrunning (NAN-3774). Otherwise it does not wait on it at all.
    /// NAN-3864: the tenant holds a prevalence grant, so rows committed
    /// unstamped are owed a restamp (without one there is no state).
    /// A reopen, retry or unavailable state (`prevalence_suspended`) is
    /// exactly when rows are owed (tenant-a 10-14 reopened every ~5 min); only a
    /// withheld grant is not.
    fn restamp_eligible(&self) -> bool {
        self.cfg.prevalence_enabled && !self.prevalence_grant_withheld
    }

    /// NAN-3864: the state holds every committed `Add`, so a lookup now
    /// counts every row already written. Restamps run only then.
    fn restamp_ready(&self) -> bool {
        self.prevalence_phase == PrevalencePhase::Stamping && !self.prevalence_pending && self.prevalence_ready()
    }

    /// Event hours owed a prevalence restamp (NAN-3864).
    pub fn prevalence_owed_hours(&self) -> Vec<i32> {
        self.prevalence_owed.hours().collect()
    }

    /// NAN-3864: the restamp `merge` carries: an hour seal (`h` output) of an
    /// owed hour while the state is at the head. Sealed when the restamp
    /// planner chose it (a rewrite of an existing `h` part).
    fn restamp_for(&mut self, merge: &crate::parts::levels::PlannedMerge, now_ms: i64)
        -> Option<(InFlightRestamp, super::prevalence::PrevalenceLookup)> {
        let sealed = merge.inputs.len() == 1
            && self.restamp_planned.as_ref().is_some_and(|planned| *planned == merge.inputs[0].part_id);
        if sealed {
            self.restamp_planned = None;
        }
        // Only the hour seal looks up: L0 and minute merges are on the
        // freshness path, and the hour stays owed until it is one sealed `h`
        // part anyway. Day merges (off) are NAN-3871.
        if merge.output_level != Level::Hour || !self.restamp_ready() {
            return None;
        }
        let serial = self.prevalence_owed.serial_of(merge.event_hour)?;
        let prevalence = self.prevalence.as_mut()?;
        // The lookup window ends now, exactly as a batch admitted now.
        prevalence.advance_watermark(now_ms.saturating_mul(1_000));
        let lookup = prevalence.lookup();
        Some((InFlightRestamp { hour: merge.event_hour, serial, sealed, outcome: Arc::default() }, lookup))
    }

    /// NAN-3864: account a committed (or dropped) merge that carried a
    /// restamp. The hour is cleared once one sealed `h` part holds all of it
    /// and no unstamped batch for it was admitted since the restamp began.
    fn restamp_merged(&mut self, restamp: &InFlightRestamp, committed: bool, now_ms: i64) {
        use super::restamp::RestampResult;
        if restamp.sealed {
            self.restamp_not_before_ms = now_ms.saturating_add(super::restamp::RESTAMP_SPACING_MS);
        }
        if !committed {
            return;
        }
        match restamp.outcome.get() {
            Some(RestampResult::Applied { rows }) => {
                self.health.prevalence_restamped_rows_total = self.health.prevalence_restamped_rows_total.saturating_add(rows);
                if restamp.sealed {
                    self.health.prevalence_restamp_rewrites_total = self.health.prevalence_restamp_rewrites_total.saturating_add(1);
                }
                self.restamp_retry.remove(&restamp.hour);
                let cleared = self.hour_is_one_sealed_part(restamp.hour) && self.prevalence_owed.clear_if(restamp.hour, restamp.serial);
                tracing::info!(tenant = %self.cfg.tenant_id, hour = restamp.hour, rows, sealed = restamp.sealed, cleared,
                    owed = self.prevalence_owed.len(), "prevalence restamp committed");
            }
            Some(RestampResult::NothingOwed) => {
                if self.hour_is_one_sealed_part(restamp.hour) {
                    self.prevalence_owed.clear_if(restamp.hour, restamp.serial);
                }
            }
            Some(RestampResult::Unsupported) => self.restamp_give_up(restamp.hour, "the lake schema has no prevalence stamp columns"),
            Some(RestampResult::LookupFailed(_)) | None => {}
        }
    }

    /// NAN-3864: one sealed `h` part holds every live row of `hour`.
    fn hour_is_one_sealed_part(&self, hour: i32) -> bool {
        let live = self.parts_of_hour(hour);
        live.len() == 1 && live[0].level == Level::Hour && live[0].event_hour == hour
    }

    /// NAN-3864: a sealed-hour restamp stopped before rewriting (nothing
    /// owed, no stamp columns, or the lookups failed). `false`: not a skip.
    fn restamp_skipped(&mut self, restamp: &InFlightRestamp, error: &anyhow::Error, now_ms: i64) -> bool {
        use super::restamp::{RestampResult, RestampSkip};
        let Some(skip) = error.downcast_ref::<RestampSkip>() else { return false };
        self.restamp_not_before_ms = now_ms.saturating_add(super::restamp::RESTAMP_SPACING_MS);
        match (skip, restamp.outcome.get()) {
            (_, Some(RestampResult::Unsupported)) => self.restamp_give_up(restamp.hour, "the lake schema has no prevalence stamp columns"),
            (RestampSkip::NothingOwed(_), _) => {
                self.prevalence_owed.clear_if(restamp.hour, restamp.serial);
                tracing::info!(tenant = %self.cfg.tenant_id, hour = restamp.hour, "owed hour holds no unstamped rows; cleared without a rewrite");
            }
            (RestampSkip::Deferred { reason, .. }, _) => {
                let reason = reason.clone();
                self.restamp_failed(restamp, now_ms, &reason);
            }
        }
        true
    }

    /// NAN-3864: a sealed-hour restamp failed: retried with the coverage
    /// backoff, given up after [`super::restamp::MAX_RESTAMP_ATTEMPTS`].
    fn restamp_failed(&mut self, restamp: &InFlightRestamp, now_ms: i64, reason: &str) {
        if !restamp.sealed {
            return;
        }
        let failures = self.restamp_retry.get(&restamp.hour).map_or(0, |(n, _)| *n) + 1;
        if failures >= super::restamp::MAX_RESTAMP_ATTEMPTS {
            self.restamp_retry.remove(&restamp.hour);
            self.restamp_give_up(restamp.hour, reason);
            return;
        }
        let backoff_ms = super::reindex::coverage_retry_backoff_ms(failures);
        self.restamp_retry.insert(restamp.hour, (failures, now_ms.saturating_add(backoff_ms)));
        tracing::warn!(tenant = %self.cfg.tenant_id, hour = restamp.hour, failures, backoff_ms, reason,
            "prevalence restamp failed; retrying with backoff");
    }

    fn restamp_give_up(&mut self, hour: i32, reason: &str) {
        if self.prevalence_owed.remove(hour) {
            self.health.prevalence_restamp_given_up_total = self.health.prevalence_restamp_given_up_total.saturating_add(1);
            tracing::error!(tenant = %self.cfg.tenant_id, hour, reason,
                "PREVALENCE DEGRADED: owed hour dropped without a restamp; its unstamped rows stay N/A");
        }
    }

    /// NAN-3864: the next owed hour that is already one sealed `h` part,
    /// newest first, rewritten only to restamp it. One at a time, spaced, and
    /// only while the state is at the head and ingest is not catching up
    /// (the old-hour reindex rules), so ingest freshness never waits on it.
    fn next_sealed_restamp(&mut self, planned: &[crate::parts::levels::PlannedMerge], now_ms: i64, lag_ms: i64)
        -> Option<crate::parts::levels::PlannedMerge> {
        self.prune_owed(now_ms);
        if self.prevalence_owed.is_empty() || !self.restamp_ready() || now_ms < self.restamp_not_before_ms
            || self.catching_up(lag_ms) || self.buffer.rows > 0 || !self.buffer.handles.is_empty()
            || self.merge_in_flight.iter().any(|flight| flight.restamp.as_ref().is_some_and(|restamp| restamp.sealed)) {
            return None;
        }
        let hours = self.prevalence_owed.hours().rev().collect::<Vec<_>>();
        for hour in hours {
            let busy = planned.iter().chain(self.merge_in_flight.iter().map(|flight| &flight.merge))
                .any(|merge| merge.event_hour == hour);
            if busy || self.restamp_retry.get(&hour).is_some_and(|(_, until)| *until > now_ms) {
                continue;
            }
            let live = self.parts_of_hour(hour);
            if let [part] = live.as_slice() {
                if part.level == Level::Hour && part.sorted && part.event_hour == hour {
                    self.restamp_planned = Some(part.part_id.clone());
                    tracing::info!(tenant = %self.cfg.tenant_id, hour, part = %part.part_id.as_str(), rows = part.rows,
                        owed = self.prevalence_owed.len(), "rewriting a sealed hour to restamp its prevalence");
                    return Some(crate::parts::levels::PlannedMerge { output_level: Level::Hour, event_hour: hour, inputs: vec![part.clone()] });
                }
            }
        }
        None
    }

    /// NAN-3864: owed hours whose rows are gone (no live part, well past
    /// any flush still in flight) are dropped.
    fn prune_owed(&mut self, now_ms: i64) {
        let now_hour = event_hour_of(now_ms.saturating_mul(1_000));
        let gone = self.prevalence_owed.hours()
            .filter(|hour| *hour < now_hour - super::restamp::OWED_ORPHAN_AGE_HOURS && self.parts_of_hour(*hour).is_empty())
            .collect::<Vec<_>>();
        for hour in gone {
            self.restamp_give_up(hour, "no live part holds the hour any more");
        }
    }

    /// NAN-3864: merge in the owed hours an earlier process saved, then save
    /// this set when it changed, as an immutable snapshot in the tenant bucket
    /// ([`PREVALENCE_RESTAMP_DIR`]). It never touches the prevalence state:
    /// the set matters exactly while that state does not answer, and a roll
    /// in that spell must not drop it. Each step is bounded by the ingest
    /// wait; a failed one is retried a minute later. Never saves before the stored set was
    /// read (a snapshot without its hours would drop them).
    async fn sync_restamp_owed(&mut self, now_ms: i64) {
        self.health.prevalence_restamp_owed_hours = self.prevalence_owed.len();
        if !self.restamp_eligible() || now_ms < self.restamp_owed_retry_ms
            || (self.restamp_owed_loaded && !self.prevalence_owed.dirty()) {
            return;
        }
        let wait = self.ingest_wait();
        // A failed or slow step waits a minute: a refused or hung store
        // costs one bounded call a minute, never one per tick.
        let retry_at = now_ms.saturating_add(60_000);
        if !self.restamp_owed_loaded {
            match tokio::time::timeout(wait, load_restamp_owed(self.parts, &self.cfg.tenant_id)).await {
                Ok(Ok(stored)) => {
                    let before = self.prevalence_owed.len();
                    let dirty = self.prevalence_owed.dirty();
                    if let Some((written_ms, hours)) = stored {
                        self.restamp_owed_saved_ms = written_ms;
                        let same = self.prevalence_owed.hours().eq(hours.iter().copied());
                        self.prevalence_owed.extend(hours.iter().copied());
                        if same || (!dirty && self.prevalence_owed.hours().eq(hours.iter().copied())) {
                            self.prevalence_owed.mark_saved();
                        }
                    }
                    self.restamp_owed_loaded = true;
                    if self.prevalence_owed.len() > before {
                        tracing::info!(tenant = %self.cfg.tenant_id, owed = self.prevalence_owed.len(),
                            "prevalence restamp: hours owed by an earlier process restored");
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %format!("{error:#}"), "read the owed prevalence restamp hours failed; retrying in a minute");
                    self.restamp_owed_retry_ms = retry_at;
                    return;
                }
                Err(_) => {
                    tracing::warn!("read the owed prevalence restamp hours timed out; retrying in a minute");
                    self.restamp_owed_retry_ms = retry_at;
                    return;
                }
            }
        }
        if self.prevalence_owed.dirty() {
            let bytes = self.prevalence_owed.to_bytes();
            // Strictly after the snapshot read or written last: the newest
            // name is the set.
            let written_ms = now_ms.max(self.restamp_owed_saved_ms.saturating_add(1));
            match tokio::time::timeout(wait, persist_restamp_owed(self.parts, &self.cfg.tenant_id, &bytes, written_ms)).await {
                Ok(Ok(())) => {
                    self.prevalence_owed.mark_saved();
                    self.restamp_owed_saved_ms = written_ms;
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %format!("{error:#}"), "save the owed prevalence restamp hours failed; retrying in a minute");
                    self.restamp_owed_retry_ms = retry_at;
                }
                Err(_) => {
                    tracing::warn!("save the owed prevalence restamp hours timed out; retrying in a minute");
                    self.restamp_owed_retry_ms = retry_at;
                }
            }
        }
        self.health.prevalence_restamp_owed_hours = self.prevalence_owed.len();
    }

    /// NAN-3864 operator backfill: mark every hour of `window` that has live
    /// parts as owed a restamp (rows ingested unstamped before this fix).
    /// Only rows without a stamp are changed; stamped rows are never touched.
    /// The window starts at most [`super::restamp::RESTAMP_MAX_AGE_MS`] ago,
    /// so every restamped row is still inside the state's 30-day window.
    pub fn queue_prevalence_restamp(&mut self, window: super::reindex::CountBackfill, now_ms: i64) -> Result<Vec<i32>> {
        window.validate(now_ms)?;
        ensure!(window.start_ms >= now_ms.saturating_sub(super::restamp::RESTAMP_MAX_AGE_MS),
            "a prevalence restamp window may start at most 7 days ago (older rows would read as never seen)");
        ensure!(self.restamp_eligible(), "the tenant has no prevalence grant");
        let first = event_hour_of(window.start_ms.saturating_mul(1_000));
        let last = event_hour_of(window.end_ms.saturating_sub(1).saturating_mul(1_000));
        let hours = (first..=last).filter(|hour| !self.parts_of_hour(*hour).is_empty()).collect::<Vec<_>>();
        self.prevalence_owed.mark(hours.iter().copied());
        self.restamp_retry.retain(|hour, _| !hours.contains(hour));
        self.health.prevalence_restamp_owed_hours = self.prevalence_owed.len();
        tracing::info!(tenant = %self.cfg.tenant_id, start_ms = window.start_ms, end_ms = window.end_ms, hours = hours.len(),
            owed = self.prevalence_owed.len(), "operator queued a prevalence restamp window");
        Ok(hours)
    }

    fn prevalence_ready(&self) -> bool {
        self.prevalence.is_some() && !self.prevalence_unplaced && self.prevalence_blocked_since.is_none()
    }

    /// The tenant's prevalence state exists for this process, even if it is
    /// not usable right now (opening, rotating, retrying after a failure):
    /// committed `Add`s are owed to it.
    fn prevalence_held(&self) -> bool {
        self.prevalence.is_some() || self.prevalence_reopening
    }

    /// A prevalence operation overran [`Self::ingest_wait`]: ingest stops
    /// waiting on it (the next commits leave the state alone) and the tick
    /// keeps probing. Only after `prevalence_op_timeout` without one finishing
    /// is the state dropped as stalled and reopened with backoff.
    fn prevalence_overran(&mut self, now_ms: i64, what: &str) {
        self.health.prevalence_deferred_total = self.health.prevalence_deferred_total.saturating_add(1);
        // NAN-3811: a step cut at the ingest wait keeps its chunk's reads
        // running; reads still landing are a slow store, not a hung one.
        // Only `prevalence_op_timeout` with no read finishing drops it.
        let reads = self.prevalence.as_ref().map(|prevalence| prevalence.chunk_reads_done());
        let reading = reads.is_some() && self.prevalence_overrun_reads.is_some() && reads != self.prevalence_overrun_reads;
        self.prevalence_overrun_reads = reads;
        let since = *self.prevalence_blocked_since.get_or_insert_with(std::time::Instant::now);
        let since = if reading {
            let now = std::time::Instant::now();
            self.prevalence_blocked_since = Some(now);
            now
        } else {
            since
        };
        if since.elapsed() >= self.cfg.prevalence_op_timeout {
            self.prevalence_stalled(now_ms, what);
            return;
        }
        tracing::warn!(tenant = %self.cfg.tenant_id, what, wait_ms = self.ingest_wait().as_millis() as u64,
            blocked_ms = since.elapsed().as_millis() as u64,
            "prevalence {what} did not finish within the ingest wait; ingest continues, prevalence catches up afterwards");
    }

    /// A prevalence operation finished within the ingest wait.
    /// NAN-3781: switch to [`PrevalencePhase::Resetting`]; the next steps
    /// empty the state and rebuild it from the live set. Merges stay held
    /// (`prevalence_pending`) so the rebuild's part list stays live.
    fn start_prevalence_reset(&mut self) {
        self.prevalence_batch_through = None;
        self.prevalence_log_cache.clear();
        self.prevalence_phase = PrevalencePhase::Resetting;
        self.prevalence_pending = true;
        self.prevalence_applied_seq = None;
        self.prevalence_rebuild = None;
        if let Some((_, path)) = self.prevalence_partial.take() {
            let _ = std::fs::remove_file(path);
        }
    }

    fn prevalence_progressed(&mut self) {
        self.prevalence_overrun_reads = None;
        self.prevalence_admit_waited = std::time::Duration::ZERO;
        if let Some(since) = self.prevalence_blocked_since.take() {
            tracing::info!(tenant = %self.cfg.tenant_id, blocked_ms = since.elapsed().as_millis() as u64,
                "prevalence state responding again; catching up with committed adds");
        }
    }

    /// Forget the per-state runtime (lookup in flight, overrun clock,
    /// placement) when the state is dropped or replaced.
    fn reset_prevalence_runtime(&mut self) {
        if let Some(flight) = self.prevalence_lookup.take() {
            flight.handle.abort();
        }
        self.prevalence_blocked_since = None;
        self.prevalence_overrun_reads = None;
        self.prevalence_admit_waited = std::time::Duration::ZERO;
        self.prevalence_unplaced = false;
        self.prevalence_step_failing_since_ms = None;
        self.prevalence_batch_through = None;
        self.prevalence_log_cache.clear();
    }

    /// A refresh inside one assignment only. A new generation or writer
    /// epoch means a cell move: restart ingest so the part log and the
    /// prevalence DB are both reopened (and fence their predecessors).
    pub async fn refresh_prevalence_credential(&mut self, access: &PrevalenceAccess) -> Result<()> {
        ensure!(access.owner.tenant_id == self.cfg.tenant_id
            && access.owner.writer_epoch > 0
            && access.owner.writer_epoch as u64 == self.cfg.writer_epoch,
            "refreshed prevalence credential rotated tenant or writer epoch; restart ingest");
        if let Some(old) = &self.cfg.prevalence_location {
            ensure!(old.owner.assignment_generation == access.owner.assignment_generation,
                "refreshed prevalence assignment generation changed; restart ingest");
        }
        let now_ms = chrono::Utc::now().timestamp_millis();
        let wait = self.ingest_wait();
        if self.prevalence.is_none() {
            if self.prevalence_suspended {
                return match tokio::time::timeout(wait, self.resume_prevalence(Some(access), now_ms)).await {
                    Ok(result) => result,
                    Err(_) => {
                        self.prevalence_overran(now_ms, "reopen on a refreshed grant");
                        Ok(())
                    }
                };
            }
            // A grant arriving mid-process (it was off, or not yet minted,
            // at start): open and place the state now. Placement never does
            // the rebuild itself: ticks run it under their budget. A failure
            // is recorded and retried with backoff; the refresh itself stays
            // good (no re-exchange loop), and ingest never waits on it.
            self.cfg.prevalence_enabled = true;
            tracing::info!("prevalence grant arrived mid-process; opening the tenant state in-process");
            match tokio::time::timeout(wait, self.resume_prevalence(Some(access), now_ms)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(error = %format!("{error:#}"), "prevalence state not opened yet; retrying with backoff"),
                Err(_) => self.prevalence_overran(now_ms, "open on a new grant"),
            }
            return Ok(());
        }
        // NAN-3849: a routine refresh (same generation, epoch, owner and
        // bucket) swaps the credential under the open state: no close, no
        // 17-19 s reopen with WAL replay, no cold block/index/filter caches,
        // and catch-up reads in flight keep running. tenant-a reopened every ~5
        // min. Anything else falls through to the background reopen.
        if self.prevalence_opening.is_none() && !self.prevalence_reopening {
            if let Some(prevalence) = self.prevalence.as_mut() {
                match prevalence.refresh_credential_in_place(access, self.cfg.prevalence_read_store.clone()) {
                    Ok(true) => {
                        self.set_prevalence_grant(access);
                        tracing::info!(tenant = %self.cfg.tenant_id, "prevalence credential refreshed in place; state stays open");
                        return Ok(());
                    }
                    Ok(false) => {}
                    Err(error) => tracing::warn!(error = %format!("{error:#}"),
                        "in-place prevalence credential refresh failed; reopening the state"),
                }
            }
        }
        // NAN-3774: rotate as a background reopen (the task closes the old
        // writer, flushing its memtable, then opens on the new credential),
        // never inline: a rotation whose close or open hangs on R2 must not
        // hold the ingest loop. Rows go unstamped for the swap (seconds);
        // `Add`s committed meanwhile stay pending and are replayed in log
        // order once the new writer is placed.
        self.set_prevalence_grant(access);
        let previous = self.prevalence.take();
        self.reset_prevalence_runtime();
        self.prevalence_phase = PrevalencePhase::Disabled;
        self.prevalence_rebuild = None;
        self.prevalence_partial = None;
        for (_, path) in std::mem::take(&mut self.prevalence_prefetched) {
            let _ = std::fs::remove_file(path);
        }
        self.prevalence_reopening = true;
        self.prevalence_suspended = true;
        if let Some(stale) = self.prevalence_opening.take() {
            stale.handle.abort();
        }
        self.prevalence_opening = Some(spawn_prevalence_open(&self.cfg, Some(access.clone()), previous,
            self.prevalence_grant_serial));
        self.health.prevalence_opens_started_total = self.health.prevalence_opens_started_total.saturating_add(1);
        match tokio::time::timeout(wait, self.resume_prevalence(Some(access), now_ms)).await {
            Ok(result) => result.context("rotate tenant prevalence credential"),
            Err(_) => {
                self.prevalence_overran(now_ms, "placement after a credential rotation");
                Ok(())
            }
        }
    }

    /// A refreshed exchange withheld the prevalence grant. The current
    /// credential (read key + owner bearer) cannot be renewed, so the state is
    /// closed now, before it expires, instead of failing every write later:
    /// rows go unstamped exactly as for a process started without a grant,
    /// and the state's replay cursor stays where it is. Returns whether a
    /// live (or retrying) state was suspended.
    pub async fn suspend_prevalence(&mut self) -> bool {
        // No grant, nothing to retry with: the next grant resumes it.
        let retrying = self.prevalence_retry.take().is_some();
        let opening = self.discard_prevalence_opening();
        let reopening = std::mem::take(&mut self.prevalence_reopening);
        self.reset_prevalence_runtime();
        let Some(prevalence) = self.prevalence.take() else {
            self.prevalence_phase = PrevalencePhase::Disabled;
            self.prevalence_pending = false;
            self.prevalence_grant_withheld = true;
            return retrying || opening || reopening;
        };
        self.close_in_background(prevalence, "closing the prevalence state on grant withdrawal failed").await;
        self.prevalence_phase = PrevalencePhase::Disabled;
        self.prevalence_pending = false;
        self.prevalence_rebuild = None;
        self.prevalence_partial = None;
        for (_, path) in std::mem::take(&mut self.prevalence_prefetched) {
            let _ = std::fs::remove_file(path);
        }
        self.prevalence_suspended = true;
        self.prevalence_grant_withheld = true;
        true
    }

    /// Close a state as its own task, waiting at most the ingest wait: a
    /// close (memtable flush + WAL close) hung on R2 never holds the loop.
    async fn close_in_background(&self, prevalence: IngestPrevalence, failed: &'static str) {
        let handle = tokio::spawn(async move {
            if let Err(error) = prevalence.close().await {
                tracing::warn!(error = %format!("{error:#}"), "{failed}");
            }
        });
        let _ = tokio::time::timeout(self.ingest_wait(), handle).await;
    }

    /// The grant came back after [`Self::suspend_prevalence`], a retry of a
    /// failed open is due, a background open finished, or a credential
    /// rotation's reopen is running: collect the open (waiting at most the
    /// ingest wait) and place the state in-process (ticks catch it up under
    /// a budget). A failure leaves ingest unstamped and schedules the next
    /// retry; it never stops ingest. `access` is `None` for lab-only local
    /// state.
    async fn resume_prevalence(&mut self, access: Option<&PrevalenceAccess>, now_ms: i64) -> Result<()> {
        if let Some(access) = access {
            self.set_prevalence_grant(access);
        }
        self.prevalence_suspended = true;
        let wait = self.ingest_wait();
        let prevalence = match self.collect_prevalence_open(access, wait).await {
            Ok(Some(mut prevalence)) => {
                prevalence.set_rarity_threshold(self.cfg.prevalence_rarity_threshold);
                prevalence
            }
            // Still opening: a later tick adopts it.
            Ok(None) => return Ok(()),
            Err(error) => {
                let error = error.context("reopen tenant prevalence state");
                let message = format!("{error:#}");
                self.prevalence_unavailable(error, now_ms);
                anyhow::bail!("{message}");
            }
        };
        self.prevalence = Some(prevalence);
        self.prevalence_unplaced = true;
        self.place_prevalence(now_ms).await
    }

    /// Place an adopted state against the part log ([`Self::hydrate_prevalence`]).
    /// Safe to drop mid-way: the state stays `prevalence_unplaced` and the
    /// next tick places it again.
    async fn place_prevalence(&mut self, now_ms: i64) -> Result<()> {
        if let Err(error) = self.hydrate_prevalence().await {
            self.close_prevalence().await;
            let error = error.context("place reopened tenant prevalence state");
            let message = format!("{error:#}");
            self.prevalence_unavailable(error, now_ms);
            anyhow::bail!("{message}");
        }
        self.prevalence_unplaced = false;
        self.prevalence_suspended = false;
        let reopened = std::mem::take(&mut self.prevalence_reopening);
        let recovered = self.prevalence_retry.take();
        self.prevalence_progressed();
        // A reopen (rotation, retry) usually finds the cursor at or near the
        // head: one budgeted step stamps again at once. Dropped by the
        // caller's wait, the tick finishes it.
        if self.prevalence_phase == PrevalencePhase::CatchingUp {
            if let Err(error) = self.advance_prevalence().await {
                tracing::warn!(error = %format!("{error:#}"), "prevalence catch-up after reopen failed; retrying next tick");
            }
        }
        if self.prevalence_phase == PrevalencePhase::Stamping {
            if let Some(prevalence) = self.prevalence.as_mut() {
                prevalence.advance_watermark(now_ms.saturating_mul(1_000));
            }
        }
        match recovered {
            Some(retry) => tracing::warn!(status = %self.prevalence_status(), failures = retry.failures,
                "prevalence state reopened after {} failed attempts; prevalence restored", retry.failures),
            None if reopened => tracing::info!(status = %self.prevalence_status(), "prevalence state reopened"),
            None => tracing::info!(status = %self.prevalence_status(), "prevalence grant returned; state reopened"),
        }
        Ok(())
    }

    /// Record `access` as the current grant; a credential change bumps
    /// [`Self::prevalence_grant_serial`].
    fn set_prevalence_grant(&mut self, access: &PrevalenceAccess) {
        self.prevalence_grant_withheld = false;
        let same = self.cfg.prevalence_location.as_ref().is_some_and(|old| same_prevalence_grant(old, access));
        if !same {
            self.prevalence_grant_serial = self.prevalence_grant_serial.wrapping_add(1);
        }
        self.cfg.prevalence_location = Some(access.clone());
    }

    /// Collect the open in flight (starting one if none is), waiting at
    /// most `wait`: `Ok(None)` while it still runs. Cancel-safe: dropped by
    /// the caller's budget, the task keeps running in
    /// [`Self::prevalence_opening`]. A result opened on a superseded grant
    /// is closed and reopened on `access` in one task, so the new writer
    /// never fences a live one.
    async fn collect_prevalence_open(&mut self, access: Option<&PrevalenceAccess>, wait: std::time::Duration)
        -> Result<Option<IngestPrevalence>> {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            if self.prevalence_opening.is_none() {
                self.prevalence_opening = Some(spawn_prevalence_open(&self.cfg, access.cloned(), None,
                    self.prevalence_grant_serial));
                self.health.prevalence_opens_started_total = self.health.prevalence_opens_started_total.saturating_add(1);
            }
            let joined = {
                let opening = self.prevalence_opening.as_mut().expect("an open is in flight");
                match tokio::time::timeout_at(deadline, &mut opening.handle).await {
                    Ok(joined) => joined,
                    Err(_) => return Ok(None),
                }
            };
            let opening = self.prevalence_opening.take().expect("an open is in flight");
            let open_ms = opening.started.elapsed().as_millis() as u64;
            self.health.prevalence_last_open_ms = open_ms;
            let prevalence = match joined {
                Ok(Ok(prevalence)) => prevalence,
                Ok(Err(error)) => {
                    tracing::info!(tenant = %self.cfg.tenant_id, open_ms, ok = false, "prevalence state open finished");
                    return Err(error);
                }
                Err(error) => return Err(anyhow::anyhow!("prevalence open task failed: {error}")),
            };
            if opening.grant_serial == self.prevalence_grant_serial {
                tracing::info!(tenant = %self.cfg.tenant_id, open_ms, ok = true, "prevalence state open finished");
                return Ok(Some(prevalence));
            }
            tracing::info!(tenant = %self.cfg.tenant_id, open_ms,
                "prevalence state opened on a superseded grant; closing it and reopening on the current grant");
            self.prevalence_opening = Some(spawn_prevalence_open(&self.cfg, access.cloned(), Some(prevalence),
                self.prevalence_grant_serial));
            self.health.prevalence_opens_started_total = self.health.prevalence_opens_started_total.saturating_add(1);
        }
    }

    /// An open in flight past `prevalence_open_hard_timeout` is hung, not
    /// slow: abort it and record a failure, so the normal backoff starts a
    /// fresh open (NAN-3554). Safe mid-open: aborting drops only the open
    /// future. A writer it already fenced in has tasks that outlive it, but
    /// the next open claims a higher writer epoch and fences them; their
    /// next manifest or WAL write fails `Fenced` and they stop.
    fn abort_hung_prevalence_open(&mut self, now_ms: i64) {
        let ceiling = self.cfg.prevalence_open_hard_timeout;
        let hung = self.prevalence_opening.as_ref()
            .is_some_and(|opening| !opening.handle.is_finished() && opening.started.elapsed() >= ceiling);
        if !hung {
            return;
        }
        let opening = self.prevalence_opening.take().expect("checked above");
        opening.handle.abort();
        self.health.prevalence_open_aborts_total = self.health.prevalence_open_aborts_total.saturating_add(1);
        tracing::warn!(tenant = %self.cfg.tenant_id, open_secs = opening.started.elapsed().as_secs(),
            ceiling_secs = ceiling.as_secs(), aborts = self.health.prevalence_open_aborts_total,
            "prevalence open exceeded its hard ceiling; aborted, a fresh open retries with backoff");
        self.prevalence_unavailable(anyhow::anyhow!("prevalence open hung past its {} s ceiling and was aborted",
            ceiling.as_secs()), now_ms);
    }

    /// Stop waiting for an open in flight: whenever it finishes, its state
    /// is closed (never left running to be fenced). Returns whether one was.
    fn discard_prevalence_opening(&mut self) -> bool {
        let Some(opening) = self.prevalence_opening.take() else { return false };
        tokio::spawn(async move {
            if let Ok(Ok(prevalence)) = opening.handle.await {
                let _ = prevalence.close().await;
            }
        });
        true
    }

    /// Close and drop a (possibly broken) open prevalence state.
    async fn close_prevalence(&mut self) {
        self.reset_prevalence_runtime();
        if let Some(prevalence) = self.prevalence.take() {
            self.close_in_background(prevalence, "closing the unusable prevalence state failed").await;
        }
        self.prevalence_phase = PrevalencePhase::Disabled;
        self.prevalence_pending = false;
        self.prevalence_rebuild = None;
        self.prevalence_partial = None;
        for (_, path) in std::mem::take(&mut self.prevalence_prefetched) {
            let _ = std::fs::remove_file(path);
        }
    }

    /// The grant is held but the state could not be opened or used: record
    /// the failure loudly (log + health), keep ingesting unstamped, and
    /// schedule the next open with backoff.
    fn prevalence_unavailable(&mut self, error: anyhow::Error, now_ms: i64) {
        let failures = self.prevalence_retry.as_ref().map_or(0, |retry| retry.failures).saturating_add(1);
        let delay_ms = prevalence_retry_delay_ms(failures);
        let last_error = format!("{error:#}");
        tracing::error!(tenant = %self.cfg.tenant_id, error = %last_error, failures, retry_in_ms = delay_ms,
            "PREVALENCE DEGRADED: tenant prevalence state unavailable; ingest continues with prevalence unstamped");
        self.reset_prevalence_runtime();
        self.prevalence_reopening = false;
        self.prevalence_phase = PrevalencePhase::Disabled;
        self.prevalence_pending = false;
        self.prevalence_suspended = true;
        self.health.prevalence_open_failures_total = self.health.prevalence_open_failures_total.saturating_add(1);
        self.health.prevalence_degraded = true;
        self.prevalence_retry = Some(PrevalenceRetry { failures, next_at_ms: now_ms.saturating_add(delay_ms), last_error });
    }

    /// Adopt a background open that finished, or retry a failed open once
    /// its backoff has elapsed.
    async fn retry_prevalence_if_due(&mut self, now_ms: i64) {
        if self.prevalence.is_some() || !self.cfg.prevalence_enabled {
            return;
        }
        self.abort_hung_prevalence_open(now_ms);
        // A background open that finished is collected at once (NAN-3554).
        let finished = self.prevalence_opening.as_ref().is_some_and(|opening| opening.handle.is_finished());
        let due = finished || self.prevalence_retry.as_ref().is_some_and(|retry| now_ms >= retry.next_at_ms);
        if !due {
            return;
        }
        let access = self.cfg.prevalence_location.clone();
        // Failures are recorded (and the next retry scheduled) inside.
        let _ = self.resume_prevalence(access.as_ref(), now_ms).await;
    }

    /// Place the tenant's prevalence state against the part log without
    /// doing the (possibly hours-long) work: ticks do it under a budget.
    ///
    /// - Missing DB, no live parts: initialize it complete at the head and
    ///   stamp immediately.
    /// - Missing DB, live parts: save the live set as the rebuild part list
    ///   and rebuild in the background, unstamped.
    /// - Interrupted rebuild: resume the saved list at the cursor.
    /// - Otherwise: catch up with the `Add`s after the cursor.
    async fn hydrate_prevalence(&mut self) -> Result<()> {
        let Some(prevalence) = self.prevalence.as_mut() else {
            self.prevalence_phase = PrevalencePhase::Disabled;
            return Ok(());
        };
        if prevalence.reset_pending() {
            // NAN-3781: a reset a previous process started (or this one, cut
            // by the ingest wait) is finished before anything reads the state.
            tracing::warn!(tenant = %self.cfg.tenant_id, "prevalence reset in progress; resuming it before the rebuild");
            self.prevalence_phase = PrevalencePhase::Resetting;
            self.prevalence_pending = true;
            self.prevalence_applied_seq = None;
            return Ok(());
        }
        let (head, head_sha, _) = self.log.live().head().context("part log has no head")?;
        let head_sha = head_sha.to_owned();
        if prevalence.is_new() {
            if self.log.live().parts().next().is_none() {
                prevalence.initialize_at(head, &head_sha).await?;
                self.prevalence_phase = PrevalencePhase::Stamping;
                self.prevalence_applied_seq = Some(head);
                return Ok(());
            }
            let mut parts = self.live_parts();
            parts.sort_by(|a, b| (a.max_time_us, a.part_id.as_str()).cmp(&(b.max_time_us, b.part_id.as_str())));
            let total = u32::try_from(parts.len()).context("too many live parts to rebuild prevalence")?;
            let entry = super::prevalence::EntryRef { seq: head, sha256: &head_sha, rebuild: true, parts: total };
            self.prevalence.as_mut().context("prevalence is disabled")?.initialize_rebuild(&entry, &parts).await?;
            tracing::warn!(tenant = %self.cfg.tenant_id, parts = total, head,
                "prevalence unstamped: rebuilding (0/{total} parts) from the signed live set");
            self.prevalence_rebuild = Some(parts.into());
            self.prevalence_phase = PrevalencePhase::Rebuilding { done: 0, total };
            self.prevalence_pending = true;
            self.prevalence_applied_seq = None;
            return Ok(());
        }
        let cursor = prevalence.applied().await?
            .context("prevalence state has no replay cursor; delete the tenant DB to rebuild it")?;
        self.prevalence_pending = true;
        if cursor.rebuild && !cursor.is_complete() {
            let parts = prevalence.rebuild_parts().await?
                .context("interrupted prevalence rebuild has no saved part list")?;
            ensure!(parts.len() == cursor.parts as usize, "saved prevalence rebuild part list differs from its cursor");
            tracing::warn!(tenant = %self.cfg.tenant_id, "prevalence unstamped: resuming rebuild ({}/{} parts)",
                cursor.next_part, cursor.parts);
            self.prevalence_phase = PrevalencePhase::Rebuilding { done: cursor.next_part, total: cursor.parts };
            self.prevalence_rebuild = Some(parts.into());
            self.prevalence_applied_seq = None;
            return Ok(());
        }
        // Applied through the cursor's entry, or the one before it while
        // that entry is part-way in.
        self.prevalence_applied_seq = Some(if cursor.is_complete() { cursor.seq } else { cursor.seq.saturating_sub(1) });
        self.prevalence_phase = PrevalencePhase::CatchingUp;
        Ok(())
    }

    /// One budgeted step toward the log head. Runs at the start of every
    /// tick, so a short backlog (a restart) is gone before admission.
    async fn advance_prevalence(&mut self) -> Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(self.cfg.prevalence_rebuild_budget_ms);
        self.advance_prevalence_until(deadline).await
    }

    async fn advance_prevalence_until(&mut self, deadline: std::time::Instant) -> Result<()> {
        match self.prevalence_phase {
            PrevalencePhase::Disabled => {}
            PrevalencePhase::Rebuilding { total, .. } => {
                let prevalence = self.prevalence.as_ref().context("prevalence is disabled")?;
                let cursor = prevalence.applied().await?.context("prevalence rebuild has no cursor")?;
                // Shared, not taken: a step dropped at the ingest wait
                // (NAN-3774) leaves the list in place for the next tick.
                let parts = self.prevalence_rebuild.clone().context("prevalence rebuild has no part list")?;
                let entry = super::prevalence::EntryRef { seq: cursor.seq, sha256: &cursor.entry_sha256, rebuild: true, parts: cursor.parts };
                let finished = self.apply_prevalence_parts(&entry, &parts, Some(deadline)).await?;
                // One durable flush per rebuild step (not per chunk): a
                // restart resumes where this step stopped.
                self.prevalence.as_mut().context("prevalence is disabled")?.make_durable().await?;
                let done = self.prevalence.as_ref().context("prevalence is disabled")?
                    .applied().await?.map_or(0, |cursor| cursor.next_part);
                self.prevalence_phase = PrevalencePhase::Rebuilding { done, total };
                tracing::info!(tenant = %self.cfg.tenant_id, done, total, "prevalence unstamped: rebuilding ({done}/{total} parts)");
                if finished {
                    self.prevalence_rebuild = None;
                    self.prevalence_applied_seq = Some(cursor.seq);
                    self.prevalence_phase = PrevalencePhase::CatchingUp;
                    tracing::info!(tenant = %self.cfg.tenant_id, "prevalence rebuild complete; catching up with adds committed since");
                    if std::time::Instant::now() < deadline {
                        return Box::pin(self.advance_prevalence_until(deadline)).await;
                    }
                }
            }
            PrevalencePhase::Resetting => {
                let prevalence = self.prevalence.as_mut().context("prevalence is disabled")?;
                if !prevalence.reset_pending() {
                    prevalence.begin_reset().await?;
                }
                if prevalence.continue_reset(Some(deadline)).await? {
                    tracing::warn!(tenant = %self.cfg.tenant_id, "prevalence state reset; rebuilding from the live set");
                    // Empty again: place it like a lost DB (a rebuild from
                    // the signed live set, then catch-up).
                    self.hydrate_prevalence().await?;
                }
            }
            PrevalencePhase::CatchingUp => {
                if self.replay_prevalence(Some(deadline)).await? {
                    self.prevalence_pending = false;
                    self.prevalence_phase = PrevalencePhase::Stamping;
                    tracing::info!(tenant = %self.cfg.tenant_id, "prevalence state at the log head; stamping");
                }
            }
            PrevalencePhase::Stamping => {
                if self.prevalence_pending && self.replay_prevalence(Some(deadline)).await? {
                    self.prevalence_pending = false;
                }
            }
        }
        Ok(())
    }

    /// Apply the committed `Add` entries after the prevalence cursor, in log
    /// order. The cursor's own entry must still be in this tenant's log with
    /// the same digest; otherwise the state belongs to another log.
    /// `Ok(false)`: `deadline` passed before the head (at least one `Add` is
    /// applied per call).
    async fn replay_prevalence(&mut self, deadline: Option<std::time::Instant>) -> Result<bool> {
        self.injected_prevalence_stall().await;
        // NAN-3849: whole entries in batches (one read pass and one write per
        // batch). The per-entry loop below takes what a batch cannot.
        loop {
            match self.replay_prevalence_batch().await? {
                CatchUpBatch::AtHead => return Ok(true),
                CatchUpBatch::Applied => {
                    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        return Ok(false);
                    }
                }
                CatchUpBatch::Unbatchable => break,
            }
        }
        let cursor = self.prevalence.as_ref().context("prevalence is disabled")?
            .applied().await?.context("prevalence state has no replay cursor")?;
        ensure!(!cursor.rebuild || cursor.is_complete(), "prevalence rebuild is not complete");
        let (head, head_sha, _) = self.log.live().head().context("part log has no head")?;
        let head_sha = head_sha.to_owned();
        let keys = LogKeys::new(&self.cfg.tenant_id)?;
        ensure!(cursor.seq <= head, "prevalence state is ahead of the part log");
        let mut seq = cursor.seq;
        let mut previous = String::new();
        loop {
            let bytes = self.parts.get(&keys.entry(seq)).await?
                .with_context(|| format!("part-log entry {seq} is missing"))?;
            let sha = sha256_hex(&bytes);
            let entry = LogEntry::parse_bytes(&bytes, &self.cfg.tenant_id)?;
            if seq == cursor.seq {
                ensure!(sha == cursor.entry_sha256, "prevalence state does not belong to this part log");
            } else {
                ensure!(entry.seq == seq && entry.prev_sha256 == previous, "part-log chain differs at {seq}");
            }
            if let LogOp::Add { parts, .. } = &entry.op {
                if !(cursor.rebuild && seq == cursor.seq) {
                    let applied = super::prevalence::EntryRef {
                        seq,
                        sha256: &sha,
                        rebuild: false,
                        parts: u32::try_from(parts.len()).context("too many parts in one add")?,
                    };
                    if !self.apply_prevalence_parts(&applied, parts, deadline).await? {
                        return Ok(false);
                    }
                    if seq != head && deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        return Ok(false);
                    }
                }
            }
            previous = sha;
            self.prevalence_applied_seq = Some(seq);
            if seq == head {
                break;
            }
            seq += 1;
        }
        ensure!(previous == head_sha, "part-log head changed during prevalence replay");
        Ok(true)
    }

    /// NAN-3849: plan and apply one catch-up batch: the whole committed
    /// `Add` entries after a complete cursor, up to
    /// [`super::prevalence::CATCH_UP_BATCH_ENTRIES`] entries and
    /// [`super::prevalence::CATCH_UP_BATCH_ROWS`] partial rows, verified
    /// against the log's digest chain exactly like the per-entry replay.
    /// Cancel-safe at every await: entries and partials fetched so far are
    /// kept, and the batch's reads keep running in the state (see
    /// [`IngestPrevalence::apply_entries_batch`]).
    async fn replay_prevalence_batch(&mut self) -> Result<CatchUpBatch> {
        use super::prevalence::{partial_rows, BatchEntry, CATCH_UP_BATCH_ENTRIES, CATCH_UP_BATCH_ROWS};
        use futures::stream::{self, StreamExt};
        let cursor = self.prevalence.as_ref().context("prevalence is disabled")?
            .applied().await?.context("prevalence state has no replay cursor")?;
        if !cursor.is_complete() {
            return Ok(CatchUpBatch::Unbatchable);
        }
        let (head, head_sha, _) = self.log.live().head().context("part log has no head")?;
        let head_sha = head_sha.to_owned();
        ensure!(cursor.seq <= head, "prevalence state is ahead of the part log");
        self.prevalence_log_cache.retain(|seq, _| *seq >= cursor.seq);
        let through = self.prevalence_batch_through.filter(|through| *through > cursor.seq);
        let scan_end = head.min(cursor.seq.saturating_add(PREVALENCE_CATCH_UP_SCAN));
        let missing = (cursor.seq..=scan_end).filter(|seq| !self.prevalence_log_cache.contains_key(seq)).collect::<Vec<_>>();
        if !missing.is_empty() {
            let keys = LogKeys::new(&self.cfg.tenant_id)?;
            let parts = self.parts;
            let fetched = stream::iter(missing.into_iter().map(|seq| {
                let key = keys.entry(seq);
                async move { (seq, parts.get(&key).await) }
            }))
            .buffered(PREVALENCE_CATCH_UP_FETCHES)
            .collect::<Vec<_>>()
            .await;
            for (seq, bytes) in fetched {
                let bytes = bytes?.with_context(|| format!("part-log entry {seq} is missing"))?;
                let entry = LogEntry::parse_bytes(&bytes, &self.cfg.tenant_id)?;
                self.prevalence_log_cache.insert(seq, (sha256_hex(&bytes), Arc::new(entry)));
            }
        }
        let (cursor_sha, _) = self.prevalence_log_cache.get(&cursor.seq).context("part-log entry is missing")?;
        ensure!(*cursor_sha == cursor.entry_sha256, "prevalence state does not belong to this part log");
        // Walk the chain; candidates are the non-empty `Add`s.
        let mut previous = cursor.entry_sha256.clone();
        let mut candidates = Vec::<(u64, String, Vec<PartRef>)>::new();
        let mut scanned = cursor.seq;
        for seq in cursor.seq + 1..=scan_end {
            let (sha, entry) = self.prevalence_log_cache.get(&seq).context("part-log entry is missing")?;
            ensure!(entry.seq == seq && entry.prev_sha256 == previous, "part-log chain differs at {seq}");
            if let LogOp::Add { parts, .. } = &entry.op {
                if !parts.is_empty() {
                    if candidates.len() >= self.cfg.prevalence_catch_up_batch_entries.clamp(1, CATCH_UP_BATCH_ENTRIES)
                        || through.is_some_and(|through| seq > through) {
                        break;
                    }
                    candidates.push((seq, sha.clone(), parts.clone()));
                }
            }
            previous = sha.clone();
            scanned = seq;
        }
        if candidates.is_empty() {
            if scanned == head {
                ensure!(previous == head_sha, "part-log head changed during prevalence replay");
                self.prevalence_applied_seq = Some(head);
                return Ok(CatchUpBatch::AtHead);
            }
            return Ok(CatchUpBatch::Unbatchable);
        }
        // Partials of every candidate part at once (local part cache first).
        let wanted = candidates.iter().flat_map(|(_, _, parts)| parts.iter())
            .filter(|part| !self.prevalence_prefetched.get(part.part_id.as_str()).is_some_and(|path| path.exists()))
            .cloned()
            .collect::<Vec<_>>();
        let fetched = {
            let this = &*self;
            stream::iter(wanted.into_iter().map(|part| async move {
                let fetched = this.fetch_prevalence_partial(&part).await;
                (part, fetched)
            }))
            .buffered(PREVALENCE_CATCH_UP_FETCHES)
            .collect::<Vec<_>>()
            .await
        };
        let mut unfetched = BTreeSet::new();
        for (part, fetched) in fetched {
            match fetched {
                Ok(path) => {
                    self.prevalence_prefetched.insert(part.part_id.as_str().to_owned(), path);
                }
                Err(error) => {
                    tracing::debug!(error = %format!("{error:#}"), part = part.part_id.as_str(),
                        "prevalence partial for a catch-up batch not fetched; the batch stops before it");
                    unfetched.insert(part.part_id.as_str().to_owned());
                }
            }
        }
        let mut batch = Vec::<BatchEntry>::new();
        let mut rows = 0_u64;
        for (seq, sha, parts) in &candidates {
            if parts.iter().any(|part| unfetched.contains(part.part_id.as_str())) {
                break;
            }
            let mut entry_rows = 0_u64;
            let mut entry_parts = Vec::with_capacity(parts.len());
            for part in parts {
                let path = self.prevalence_prefetched.get(part.part_id.as_str()).context("prefetched partial is missing")?;
                entry_rows = entry_rows.saturating_add(partial_rows(path)?);
                entry_parts.push((part.part_id.as_str().to_owned(), path.clone(), part.max_time_us));
            }
            if !batch.is_empty() && rows.saturating_add(entry_rows) > CATCH_UP_BATCH_ROWS {
                break;
            }
            if batch.is_empty() && entry_rows > CATCH_UP_BATCH_ROWS {
                // Larger than a batch: the per-entry replay chunks it.
                return Ok(CatchUpBatch::Unbatchable);
            }
            rows = rows.saturating_add(entry_rows);
            batch.push(BatchEntry { seq: *seq, sha256: sha.clone(), parts: entry_parts });
        }
        let Some(last) = batch.last().map(|entry| entry.seq) else {
            return Ok(CatchUpBatch::Unbatchable);
        };
        // Through the batch, or through the scan when every candidate is in
        // it (trailing non-`Add` entries are applied by definition).
        let covered = if batch.len() == candidates.len() { scanned } else { last };
        self.prevalence_batch_through = Some(last);
        let started = std::time::Instant::now();
        let applied = self.prevalence.as_mut().context("prevalence is disabled")?
            .apply_entries_batch(&self.cfg.tenant_id, &batch).await?;
        self.prevalence_batch_through = None;
        for entry in &batch {
            for (part_id, _, _) in &entry.parts {
                if let Some(path) = self.prevalence_prefetched.remove(part_id) {
                    let _ = std::fs::remove_file(path);
                }
                self.release_retained_partial(part_id);
            }
        }
        self.prevalence_applied_seq = Some(covered);
        let behind = head.saturating_sub(covered);
        tracing::info!(tenant = %self.cfg.tenant_id, first_seq = batch[0].seq, last_seq = last, entries = applied.entries,
            parts = applied.parts, rows = applied.rows, keys = applied.keys, fold_ms = applied.fold_ms,
            read_ms = applied.read_ms, write_ms = applied.write_ms, wall_ms = started.elapsed().as_millis() as u64,
            behind_entries = behind, "prevalence catch-up batch applied");
        if covered == head {
            let (sha, _) = self.prevalence_log_cache.get(&head).context("part-log entry is missing")?;
            ensure!(*sha == head_sha, "part-log head changed during prevalence replay");
            return Ok(CatchUpBatch::AtHead);
        }
        Ok(CatchUpBatch::Applied)
    }

    /// `Ok(false)`: `deadline` passed; the cursor resumes where this stopped.
    async fn apply_prevalence_parts(&mut self, entry: &super::prevalence::EntryRef<'_>, parts: &[PartRef],
        deadline: Option<std::time::Instant>) -> Result<bool> {
        let Some(start) = self.prevalence.as_ref().context("prevalence is disabled")?
            .pending_from(entry).await? else { return Ok(true) };
        for (index, part) in parts.iter().enumerate().skip(start as usize) {
            // The partial in hand is recorded before the apply starts, so a
            // step dropped mid-apply (NAN-3774) reuses it next tick.
            let path = match &self.prevalence_partial {
                Some((id, path)) if id == part.part_id.as_str() && path.exists() => path.clone(),
                _ => {
                    if let Some((_, stale)) = self.prevalence_partial.take() {
                        let _ = std::fs::remove_file(stale);
                    }
                    if let Err(error) = self.prefetch_prevalence_partials(&parts[index..]).await {
                        // NAN-3781: a replayed part that is gone from the store
                        // and no longer live was merged away; only a rebuild
                        // from the live set recovers its rows exactly.
                        if !entry.rebuild && error.downcast_ref::<PrevalencePartialMissing>().is_some()
                            && self.log.live().get(&part.part_id).is_none() {
                            return Err(anyhow::Error::new(PrevalenceReplayGap {
                                seq: entry.seq, part_id: part.part_id.as_str().to_owned(),
                            }));
                        }
                        return Err(error);
                    }
                    let path = self.prevalence_prefetched.remove(part.part_id.as_str()).context("prefetched partial is missing")?;
                    self.prevalence_partial = Some((part.part_id.as_str().to_owned(), path.clone()));
                    path
                }
            };
            let result = self.prevalence.as_mut().context("prevalence is disabled")?.apply_part_until(&self.cfg.tenant_id,
                entry, index as u32, part.part_id.as_str(), &path, part.max_time_us, deadline).await;
            match result {
                Ok(true) => {
                    self.prevalence_partial = None;
                    let _ = std::fs::remove_file(path);
                    if !entry.rebuild {
                        self.release_retained_partial(part.part_id.as_str());
                    }
                }
                Ok(false) => return Ok(false),
                Err(error) => {
                    self.prevalence_partial = None;
                    let _ = std::fs::remove_file(path);
                    return Err(error);
                }
            }
            if index + 1 < parts.len() && deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Fetch the partials of up to [`PREVALENCE_PREFETCH`] upcoming parts
    /// at once (the first is needed now): a rebuild no longer waits for one
    /// provenance + partial round trip per part.
    async fn prefetch_prevalence_partials(&mut self, upcoming: &[PartRef]) -> Result<()> {
        let window = upcoming.iter().take(PREVALENCE_PREFETCH)
            .filter(|part| !self.prevalence_prefetched.get(part.part_id.as_str()).is_some_and(|path| path.exists()))
            .cloned()
            .collect::<Vec<_>>();
        let fetched = futures::future::join_all(window.iter().map(|part| self.fetch_prevalence_partial(part))).await;
        for (part, fetched) in window.iter().zip(fetched) {
            match fetched {
                Ok(path) => {
                    self.prevalence_prefetched.insert(part.part_id.as_str().to_owned(), path);
                }
                // Only the part needed now fails the step; a later one is
                // simply fetched again when its turn comes.
                Err(error) if part.part_id == upcoming[0].part_id => return Err(error),
                Err(error) => tracing::debug!(error = %format!("{error:#}"), "prefetch of a later prevalence partial failed"),
            }
        }
        Ok(())
    }

    /// Verify provenance and fetch only the compact partial. Full part data
    /// can be multi-gigabyte and is not needed to recover stamp state.
    async fn fetch_prevalence_partial(&self, part: &PartRef) -> Result<PathBuf> {
        // NAN-3849: a part this cell wrote or merged is usually still in its
        // local part cache (or its partial was retained when that cache was
        // evicted): no store round trip, and it survives the part being
        // merged away and collected while the state was behind.
        match self.local_prevalence_partial(part) {
            Ok(Some(path)) => return Ok(path),
            Ok(None) => {}
            Err(error) => tracing::debug!(error = %format!("{error:#}"), part = part.part_id.as_str(),
                "local prevalence partial unusable; fetching it from the store"),
        }
        let keys = PartKeys::new(&self.cfg.tenant_id, part.level, part.event_hour, &part.part_id)?;
        let provenance = self.parts.get(&keys.provenance()).await?
            .ok_or_else(|| PrevalencePartialMissing { part_id: part.part_id.as_str().to_owned() })
            .context("part has no provenance")?;
        ensure!(sha256_hex(&provenance) == part.provenance_sha256, "part provenance does not match the log");
        let signed = SignedProvenance::verify_bytes(&provenance, &self.cfg.tenant_id, &self.trusted)?;
        part.check_record(&signed.record, &part.provenance_sha256)?;
        let name = crate::parts::format::PARTIAL_PREVALENCE_FILE;
        let partial = signed.record.files.partials.iter().find(|file| file.name == name)
            .context("live part has no prevalence partial")?;
        let directory = self.cfg.work_dir.join("prevalence").join(&self.cfg.tenant_id);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}.parquet", part.part_id));
        let temporary = path.with_extension("partial");
        let _ = std::fs::remove_file(&temporary);
        if !self.parts.get_to_file(&keys.file(name), &temporary).await? {
            return Err(anyhow::Error::new(PrevalencePartialMissing { part_id: part.part_id.as_str().to_owned() })
                .context("live prevalence partial is missing"));
        }
        let (_, digest) = super::writer::file_digest(&temporary)?;
        ensure!(digest == partial.sha256, "live prevalence partial does not match signed provenance");
        std::fs::rename(&temporary, &path)?;
        Ok(path)
    }

    /// NAN-3849: where a part's prevalence partial is kept after its local
    /// part directory is evicted while the state is behind.
    fn retained_partial_dir(&self, part_id: &str) -> PathBuf {
        self.cfg.work_dir.join("prevalence-retained").join(&self.cfg.tenant_id).join(part_id)
    }

    /// NAN-3849: the part's prevalence partial from the local part cache or
    /// a retained copy, verified exactly as a store fetch is (the provenance
    /// digest the log names, its signature, the record, the partial's
    /// signed digest), copied to the replay's working path. `None`: not
    /// held locally.
    fn local_prevalence_partial(&self, part: &PartRef) -> Result<Option<PathBuf>> {
        let name = crate::parts::format::PARTIAL_PREVALENCE_FILE;
        let sources = [
            self.find_local(&part.part_id).map(|dir| (dir.join(PROVENANCE_FILE), dir.join(name))),
            Some(self.retained_partial_dir(part.part_id.as_str()))
                .map(|dir| (dir.join(PROVENANCE_FILE), dir.join("prevalence.parquet"))),
        ];
        let Some((provenance, local)) = sources.into_iter().flatten()
            .find(|(provenance, local)| provenance.exists() && local.exists()) else { return Ok(None) };
        let provenance = std::fs::read(provenance)?;
        ensure!(sha256_hex(&provenance) == part.provenance_sha256, "local part provenance does not match the log");
        let signed = SignedProvenance::verify_bytes(&provenance, &self.cfg.tenant_id, &self.trusted)?;
        part.check_record(&signed.record, &part.provenance_sha256)?;
        let partial = signed.record.files.partials.iter().find(|file| file.name == name)
            .context("live part has no prevalence partial")?;
        let directory = self.cfg.work_dir.join("prevalence").join(&self.cfg.tenant_id);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}.parquet", part.part_id));
        let temporary = path.with_extension("partial");
        let _ = std::fs::remove_file(&temporary);
        std::fs::copy(&local, &temporary)?;
        let (_, digest) = super::writer::file_digest(&temporary)?;
        if digest != partial.sha256 {
            let _ = std::fs::remove_file(&temporary);
            anyhow::bail!("local prevalence partial does not match signed provenance");
        }
        std::fs::rename(&temporary, &path)?;
        Ok(Some(path))
    }

    /// NAN-3849: the state is not at the log head, so a superseded part's
    /// `Add` may still be unapplied: keep its provenance and prevalence
    /// partial (a few hundred KB) before its local directory is evicted.
    fn retain_prevalence_inputs(&self, dir: &Path, part_id: &str) {
        let source = (dir.join(PROVENANCE_FILE), dir.join(crate::parts::format::PARTIAL_PREVALENCE_FILE));
        if !(source.0.exists() && source.1.exists()) {
            return;
        }
        let target = self.retained_partial_dir(part_id);
        let kept = std::fs::create_dir_all(&target)
            .and_then(|_| std::fs::copy(&source.0, target.join(PROVENANCE_FILE)))
            .and_then(|_| std::fs::copy(&source.1, target.join("prevalence.parquet")));
        if let Err(error) = kept {
            tracing::warn!(error = %error, part_id, "could not retain a superseded part's prevalence partial; the replay fetches it from the store");
            let _ = std::fs::remove_dir_all(&target);
        }
    }

    /// NAN-3849: a part's `Add` is in the state; its retained copy is spent.
    fn release_retained_partial(&self, part_id: &str) {
        let _ = std::fs::remove_dir_all(self.retained_partial_dir(part_id));
    }

    /// NAN-3849: the state reached the log head, so every retained partial
    /// is spent.
    fn release_all_retained_partials(&self) {
        let _ = std::fs::remove_dir_all(self.cfg.work_dir.join("prevalence-retained").join(&self.cfg.tenant_id));
    }

    /// The state is behind the log head (an `Add` may be unapplied).
    fn prevalence_behind(&self) -> bool {
        self.prevalence_held() && (self.prevalence_pending || self.prevalence_phase != PrevalencePhase::Stamping)
    }

    /// Live parts whose event range covers this hour.
    fn parts_of_hour(&self, hour: i32) -> Vec<PartRef> {
        self.log
            .live()
            .parts()
            .filter(|p| match p.level {
                Level::Day => p.event_hour <= hour && hour < p.event_hour + 24,
                _ => p.event_hour == hour,
            })
            .cloned()
            .collect()
    }

    /// One loop iteration. Preserve ingest errors; only retryable errors
    /// may service sanctioned GC before returning to the caller.
    pub async fn tick(&mut self, now_ms: i64) -> Result<TickReport> {
        self.tick_prevalence(now_ms).await;
        let (mut report, pending) = match self.tick_ingest(now_ms).await {
            Ok(result) => result,
            Err(error) => {
                if !fatal_ingest_error(&error) {
                    self.tick_gc(now_ms).await;
                }
                return Err(error);
            }
        };
        self.tick_maintain(now_ms, &pending, &mut report).await?;
        Ok(report)
    }

    /// Tick phase 1: one bounded prevalence rebuild / catch-up step. The
    /// cell runs the phases under separate ingestor-lock holds so a finding
    /// append waits for one phase, never a whole tick (NAN-3067).
    ///
    /// NAN-3774: every wait here is at most [`Self::ingest_wait`] (a step cut
    /// there resumes next tick from the state's cursor), so a store hung on
    /// R2 costs a tick seconds, never `prevalence_op_timeout`.
    pub async fn tick_prevalence(&mut self, now_ms: i64) {
        self.tick_prevalence_step(now_ms).await;
        // NAN-3864: keep the owed restamp hours saved in the tenant bucket.
        self.sync_restamp_owed(now_ms).await;
    }

    async fn tick_prevalence_step(&mut self, now_ms: i64) {
        let wait = self.ingest_wait();
        self.check_prevalence_lookup(now_ms);
        if self.prevalence.is_some() && !self.prevalence_behind() {
            self.release_all_retained_partials();
        }
        if tokio::time::timeout(wait, self.retry_prevalence_if_due(now_ms)).await.is_err() {
            self.prevalence_overran(now_ms, "reopen");
            return;
        }
        if let Some(reason) = self.prevalence.as_ref().and_then(|prevalence| prevalence.closed()) {
            self.prevalence_closed_by_store(now_ms, reason);
            return;
        }
        if self.prevalence.is_some() && self.prevalence_unplaced {
            match tokio::time::timeout(wait, self.place_prevalence(now_ms)).await {
                Ok(_) => {}
                Err(_) => {
                    self.prevalence_overran(now_ms, "placement");
                    return;
                }
            }
            if self.prevalence.is_none() || self.prevalence_unplaced {
                return;
            }
        }
        // Before admission, so a short catch-up (a restart) stamps this tick.
        let has_work = match self.prevalence_phase {
            PrevalencePhase::Disabled => false,
            PrevalencePhase::Stamping => self.prevalence_pending,
            PrevalencePhase::Rebuilding { .. } | PrevalencePhase::CatchingUp | PrevalencePhase::Resetting => true,
        };
        if has_work {
            match tokio::time::timeout(wait, self.advance_prevalence()).await {
                Ok(Ok(())) => {
                    self.prevalence_step_failing_since_ms = None;
                    self.prevalence_progressed();
                }
                Ok(Err(error)) if error.downcast_ref::<PrevalenceReplayGap>().is_some() => {
                    tracing::warn!(tenant = %self.cfg.tenant_id, error = %format!("{error:#}"),
                        "prevalence replay gap; resetting the state to rebuild it from the live set");
                    self.prevalence_step_failing_since_ms = None;
                    self.start_prevalence_reset();
                }
                Ok(Err(error)) => {
                    self.prevalence_step_failing_since_ms.get_or_insert(now_ms);
                    tracing::warn!(error = %format!("{error:#}"), status = %self.prevalence_status(),
                        "prevalence rebuild/catch-up step failed; rows stay unstamped, retrying next tick");
                }
                Err(_) => {
                    self.prevalence_overran(now_ms, "rebuild/catch-up step");
                    return;
                }
            }
        } else if self.prevalence_blocked_since.is_some() {
            // Nothing to replay: probe whether the state's writes land again.
            let probe = match self.prevalence.as_mut() {
                Some(prevalence) => tokio::time::timeout(wait, prevalence.make_durable()).await,
                None => return,
            };
            match probe {
                Ok(Ok(())) => self.prevalence_progressed(),
                Ok(Err(error)) => tracing::warn!(error = %format!("{error:#}"), "prevalence state probe failed"),
                Err(_) => {
                    self.prevalence_overran(now_ms, "durability probe");
                    return;
                }
            }
        }
        // NAN-3554: bound the WAL the next open replays (a flush waiting on
        // L0 room is retried a window later, never stalls). NAN-3774: never
        // longer than the ingest wait, and not while the state is overrunning.
        if self.prevalence_blocked_since.is_none() {
            if let Some(prevalence) = self.prevalence.as_mut() {
                if prevalence.memtable_flush_due() {
                    prevalence.flush_memtable_within(wait, "cadence").await;
                }
            }
        }
    }

    /// NAN-3774: a batch lookup left running in the background past
    /// `prevalence_op_timeout` is a stalled store (R2 reads that never
    /// return): drop the state and reopen with backoff, without waiting.
    fn check_prevalence_lookup(&mut self, now_ms: i64) {
        let Some(flight) = &self.prevalence_lookup else { return };
        if flight.handle.is_finished() {
            self.prevalence_lookup = None;
            return;
        }
        if flight.started.elapsed() >= self.cfg.prevalence_op_timeout {
            self.prevalence_stalled(now_ms, "batch lookup");
        }
    }

    /// A prevalence operation outlived `prevalence_op_timeout` (a store
    /// whose flushes never complete, e.g. SlateDB backpressure with L0 at
    /// its cap and no compaction): drop the state without waiting on it,
    /// keep ingesting unstamped, report it, and retry the open with backoff.
    fn prevalence_stalled(&mut self, now_ms: i64, what: &str) {
        self.reset_prevalence_runtime();
        if let Some(prevalence) = self.prevalence.take() {
            // Closing flushes too: never wait on it here.
            tokio::spawn(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(30), prevalence.close()).await;
            });
        }
        self.prevalence_rebuild = None;
        self.prevalence_partial = None;
        for (_, path) in std::mem::take(&mut self.prevalence_prefetched) {
            let _ = std::fs::remove_file(path);
        }
        self.health.prevalence_stalls_total = self.health.prevalence_stalls_total.saturating_add(1);
        let error = match &self.prevalence_opening {
            Some(opening) => anyhow::anyhow!("prevalence {what} did not finish within {} s; the open continues in the \
                background (WAL replay, {} s so far) and is adopted when it finishes",
                self.cfg.prevalence_op_timeout.as_secs(), opening.started.elapsed().as_secs()),
            None => anyhow::anyhow!("prevalence {what} did not finish within {} s; the state store is not flushing",
                self.cfg.prevalence_op_timeout.as_secs()),
        };
        self.prevalence_unavailable(error, now_ms);
    }

    /// NAN-3873: SlateDB closed the open state after a background store
    /// error and now answers every call with that cached error, without any
    /// I/O. Drop it (there is nothing left to flush) and reopen with the
    /// usual backoff; the reopen replays the WAL and catches up the adds
    /// committed meanwhile.
    fn prevalence_closed_by_store(&mut self, now_ms: i64, reason: slatedb::CloseReason) {
        self.prevalence.take();
        self.prevalence_rebuild = None;
        self.prevalence_partial = None;
        for (_, path) in std::mem::take(&mut self.prevalence_prefetched) {
            let _ = std::fs::remove_file(path);
        }
        self.health.prevalence_stalls_total = self.health.prevalence_stalls_total.saturating_add(1);
        self.prevalence_unavailable(
            anyhow::anyhow!("prevalence state closed by the store ({reason:?}) after a failed background write; reopening"),
            now_ms,
        );
    }

    /// NAN-3774: read this batch's prevalence as its own task and wait for
    /// it at most [`Self::ingest_wait`]. `None`: the batch goes unstamped
    /// and its hours are owed an exact restamp (not stamping, a committed
    /// `Add` not yet in the state, or the read failed or was slower than the
    /// wait; a slow read keeps running in the background, warming the cache).
    ///
    /// NAN-3879: a stamp is permanent, so it is never taken from a state
    /// missing committed rows: while an `Add` is pending (an apply cut at the
    /// ingest wait, a failed apply, a catch-up) the batch is unstamped and
    /// owed, blocked or not. An earlier batch's lookup still in flight is
    /// waited out within this batch's one ingest wait (it used to skip at
    /// once); per overrun spell admission waits at most
    /// [`PREVALENCE_ADMIT_OVERRUN_WAITS`] ingest waits.
    async fn stamp_lookup(&mut self, rows: &[crate::iceberg::EventRow], now_ms: i64) -> Option<super::prevalence::Observed> {
        if self.prevalence_phase != PrevalencePhase::Stamping {
            return None;
        }
        // A flight past `prevalence_op_timeout` drops the state as stalled.
        self.check_prevalence_lookup(now_ms);
        if self.prevalence.is_none() || self.prevalence_unplaced {
            return None;
        }
        if self.prevalence_pending {
            return self.lookup_skipped();
        }
        let overrunning = self.prevalence_blocked_since.is_some() || self.prevalence_lookup.is_some();
        let wait = if overrunning {
            let budget = self.ingest_wait().saturating_mul(PREVALENCE_ADMIT_OVERRUN_WAITS);
            self.ingest_wait().min(budget.saturating_sub(self.prevalence_admit_waited))
        } else {
            self.ingest_wait()
        };
        if wait.is_zero() {
            // The spell's waits are spent: unstamped (owed) until it answers.
            return self.lookup_skipped();
        }
        let started = std::time::Instant::now();
        if let Some(flight) = self.prevalence_lookup.as_mut() {
            // An earlier batch's read: wait it out (it warms the cache this
            // batch reads), within this batch's wait.
            if tokio::time::timeout(wait, &mut flight.handle).await.is_err() {
                self.prevalence_admit_waited = self.prevalence_admit_waited.saturating_add(started.elapsed());
                return self.lookup_skipped();
            }
            self.prevalence_lookup = None;
        }
        let left = wait.saturating_sub(started.elapsed());
        let prevalence = self.prevalence.as_mut()?;
        prevalence.advance_watermark(now_ms.saturating_mul(1_000));
        let artifacts = match super::prevalence::stamp_artifacts(rows.iter().map(|row| &row.ocsf_event)) {
            Ok(artifacts) => artifacts,
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"),
                    "PREVALENCE DEGRADED: prevalence lookup failed; this batch is unstamped");
                return None;
            }
        };
        let mut handle = tokio::spawn(prevalence.lookup().observe(artifacts));
        match tokio::time::timeout(left, &mut handle).await {
            Ok(Ok(Ok(observed))) => {
                // The store answered within the wait.
                self.prevalence_admit_waited = std::time::Duration::ZERO;
                Some(observed)
            }
            Ok(Ok(Err(error))) => {
                tracing::error!(error = %format!("{error:#}"),
                    "PREVALENCE DEGRADED: prevalence lookup failed; this batch is unstamped");
                None
            }
            Ok(Err(error)) => {
                tracing::error!(error = %error, "PREVALENCE DEGRADED: prevalence lookup task failed; this batch is unstamped");
                None
            }
            Err(_) => {
                self.prevalence_admit_waited = self.prevalence_admit_waited.saturating_add(started.elapsed());
                self.health.prevalence_unstamped_batches_total = self.health.prevalence_unstamped_batches_total.saturating_add(1);
                tracing::warn!(tenant = %self.cfg.tenant_id, wait_ms = self.ingest_wait().as_millis() as u64,
                    "prevalence lookups slower than the ingest wait; this batch is unstamped, the reads finish in the background");
                self.prevalence_lookup = Some(PrevalenceLookupFlight { handle, started });
                None
            }
        }
    }

    /// NAN-3879: an admission batch skips its lookup (counted; its hours are
    /// owed a restamp by the caller).
    fn lookup_skipped(&mut self) -> Option<super::prevalence::Observed> {
        self.health.prevalence_unstamped_batches_total = self.health.prevalence_unstamped_batches_total.saturating_add(1);
        None
    }

    /// Tick phase 2: edge points, admission and the due flush.
    pub async fn tick_ingest(&mut self, now_ms: i64) -> Result<(TickReport, Vec<(NoticeHandle, SourceNotice)>)> {
        let mut report = TickReport::default();
        // Late-tier runs finished in the background since the last tick.
        self.late.poll(now_ms).await;
        // Pipelined flushes whose parts are published commit first.
        report.flushed_parts = self.reap_in_flight(now_ms, usize::MAX).await?;
        self.apply_points(now_ms).await?;
        // Look past what is already buffered or in flight (still pending
        // until acked), or a large flight fills the window and catch-up
        // looks idle: no admission and no pipelining (NAN-3619).
        // (Flag on only; off keeps today's fixed window.)
        let held = if self.cfg.commit_when_ready {
            self.buffer.handles.len() + self.flush_in_flight.iter().map(|flight| flight.buffer.handles.len()).sum::<usize>()
        } else {
            0
        };
        let pending = self.queue.pending(self.cfg.max_objects_per_admission * 4 + held).await?;
        // Handles of the flushes in flight are not acked yet: still pending.
        let in_flight = &self.flush_in_flight;
        let pending_fresh = |handle: &NoticeHandle| !self.buffer.handle_names.contains(&handle.0)
            && !in_flight.iter().any(|flight| flight.buffer.handle_names.contains(&handle.0));
        // A full buffer admits nothing more; it flushes below (NAN-3006).
        let room = MAX_FLUSH_OBJECTS.saturating_sub(self.buffer.handles.len());
        // Byte-bounded too (NAN-3183 OOM): one working budget is charged
        // with the filling buffer, the flush in flight (its rows, build
        // copies and writers) and the merges; an admission takes only the
        // room left for its peak (JSON values while they decode) plus the
        // Arrow rows it adds. With nothing else held, at least one object is
        // admitted so a huge object still makes progress.
        let (mut predicted_heap, mut predicted_arrow) = (0.0, 0.0);
        let committed = self.committed_bytes();
        let idle = self.buffer.bytes == 0 && self.flush_in_flight.is_empty();
        let mut held_bytes = 0_u64;
        let hold_budget = self.admission_byte_budget;
        let fresh = pending
            .iter()
            .filter(|(handle, _)| pending_fresh(handle))
            .take(self.cfg.max_objects_per_admission.min(room))
            .enumerate()
            .take_while(|(index, (_, notice))| {
                // An object whose size the source did not report still counts (≥ 1 byte).
                held_bytes = held_bytes.saturating_add(notice.bytes.max(1));
                *index == 0 || hold_budget.is_none_or(|budget| held_bytes <= budget)
            })
            .take_while(|(index, (_, notice))| {
                predicted_heap += notice.bytes as f64 * self.heap_per_source_byte;
                predicted_arrow += notice.bytes as f64 * self.arrow_per_source_byte;
                *index == 0 && idle
                    || super::memory::admission_fits(self.cfg.buffer_budget_bytes, committed, predicted_heap, predicted_arrow)
            })
            .map(|(_, notice)| notice.clone())
            .collect::<Vec<_>>();
        // Never admit into a buffer that is partly in the log (B1): its
        // appends are skipped on retry, so new rows would be acked unwritten.
        if !fresh.is_empty() && !self.buffer.partially_committed() && !self.admission_paused {
            let started = cpu_now();
            let (rows, dups) = self.admit(&fresh, now_ms).await?;
            self.health.cpu_ms_admission += cpu_now().saturating_sub(started);
            report.admitted_rows = rows;
            report.admitted_bytes = fresh.iter().map(|(_, notice)| notice.bytes).sum();
            report.duplicates = dups;
        }
        // NAN-3619: a flight that finished while admission ran commits now,
        // not at the next tick (on the load-test tenant they waited 9-26 s). Only ready
        // flights, oldest first: the same commit `flush` would make first.
        if self.cfg.commit_when_ready {
            report.flushed_parts += self.reap_in_flight(now_ms, usize::MAX).await?;
        }
        let mut interval = self.cfg.flush_interval_override_ms.unwrap_or_else(|| self.cfg.flush_policy.interval_ms(self.health.eps_ewma));
        // Catching up (notices pulled but not yet admitted): the age cap
        // would cut a flush every few seconds whatever its size, and every
        // flush pays fixed owner/R2/edge round trips. Fill the flush to its
        // row/byte/object caps instead, bounded by CATCH_UP_FLUSH_MAX_AGE_MS
        // (NAN-3183).
        let in_flight = &self.flush_in_flight;
        let behind = pending.iter().any(|(handle, _)| !self.buffer.handle_names.contains(&handle.0)
            && !in_flight.iter().any(|flight| flight.buffer.handle_names.contains(&handle.0)));
        if behind && self.cfg.flush_interval_override_ms.is_none() {
            interval = interval.max(CATCH_UP_FLUSH_MAX_AGE_MS);
        }
        let due = self.buffer.since_ms.is_some_and(|since| now_ms - since >= interval)
            || self.buffer.rows >= FLUSH_MAX_ROWS
            || self.buffer.bytes >= super::memory::buffer_cap(self.cfg.buffer_budget_bytes)
            // The budget is spent (flight + merges + buffer): admission is
            // stalled, so seal what is buffered rather than wait out the age.
            || (self.buffer.rows > 0 && self.committed_bytes() >= self.cfg.buffer_budget_bytes)
            || self.buffer.handles.len() >= MAX_FLUSH_OBJECTS
            || self.buffer.rejections.len() >= MAX_REJECTIONS_PER_ENTRY;
        if due || self.buffer.partially_committed() || (self.buffer.rows == 0 && !self.buffer.handles.is_empty()) {
            let started = cpu_now();
            // Behind, the flush pipelines: its build and upload overlap the
            // next admissions (the cell supplies the 'static handles).
            report.flushed_parts += self.flush(now_ms, behind).await?;
            self.health.cpu_ms_parts += cpu_now().saturating_sub(started);
        }
        Ok((report, pending))
    }

    /// Tick phase 3: merges, GC, evictions, export plan, health.
    pub async fn tick_maintain(&mut self, now_ms: i64, pending: &[(NoticeHandle, SourceNotice)], report: &mut TickReport) -> Result<()> {
        // NAN-3619: commit flights that finished during the ingest phase
        // before merges and GC take their turn (ready ones only, in order).
        // A failure keeps the flight oldest; the next ingest phase retries
        // it and reports the error there, exactly as before this reap.
        if self.cfg.commit_when_ready {
            match self.reap_in_flight(now_ms, usize::MAX).await {
                Ok(parts) => report.flushed_parts += parts,
                Err(error) => tracing::warn!(error = %format!("{error:#}"), "committing a finished flush failed; the ingest phase retries it"),
            }
        }
        // Merges and GC hold no unacknowledged data: their failures are
        // isolated (logged, backed off), never fail-stop.
        let started = cpu_now();
        // Lag as of THIS tick's pull (the health value is last tick's, and
        // zero right after a restart, which once let a big merge start
        // mid catch-up after every OOM restart).
        let lag_now = pending.iter().map(|(_, n)| n.notified_at_ms).min().map_or(0, |oldest| (now_ms - oldest).max(0));
        report.merges = self.run_merges(now_ms, lag_now).await;
        self.health.cpu_ms_merges += cpu_now().saturating_sub(started);
        // NAN-3867: one bounded data-subject erasure step (a rewrite is a
        // merge: same fence, same prevalence wait, same lanes).
        self.tick_erasure(now_ms, lag_now).await;
        // Retire only on successful maintenance, never on the retry-only GC
        // path. Both appends and the local GC pass hold the ingestor mutex.
        if let Some(authority) = self.local_gc.clone() {
            if let Err(error) = self.retire_local_expired(&authority, now_ms).await {
                tracing::warn!(error = %error, "local retention retirement failed; keeping parts");
            }
        }
        self.evict_superseded_cache(now_ms);
        self.tick_gc(now_ms).await;
        // The flush in flight is not in the log yet: its hours stay in the
        // window too, or a redelivered row of it would pass dedup.
        let buffered_hours = self.buffer.hours.keys()
            .chain(self.flush_in_flight.iter().flat_map(|flight| flight.buffer.hours.keys()))
            .copied().collect::<BTreeSet<_>>();
        let mut spilled = Vec::new();
        self.window.evict_into(now_ms, &buffered_hours, &mut spilled);
        for hour in spilled {
            self.late.spill(hour, now_ms);
        }
        self.tick_late_tier(now_ms).await;
        if let Err(error) = self.evict_cache(now_ms) {
            tracing::warn!(error = %format!("{error:#}"), "cache eviction failed");
        }
        if let Err(error) = self.export_plan(now_ms) {
            tracing::warn!(error = %format!("{error:#}"), "export plan failed");
        }
        self.update_health(pending, now_ms)?;
        Ok(())
    }

    /// Flush whatever is buffered now (shutdown, tests).
    pub async fn flush_now(&mut self, now_ms: i64) -> Result<usize> {
        self.flush(now_ms, false).await
    }

    async fn admit(&mut self, notices: &[(NoticeHandle, SourceNotice)], now_ms: i64) -> Result<(u64, u64)> {
        let src_dir = self.cfg.work_dir.join("src");
        std::fs::create_dir_all(&src_dir)?;
        let mut files = Vec::new();
        for (handle, notice) in notices {
            ensure!(notice.tenant_id == self.cfg.tenant_id, "notice for another tenant");
            if let Some(prefix) = &self.cfg.source_key_prefix {
                if !key_inside_prefix(&notice.key, prefix) || notice.key.chars().any(char::is_control) {
                    // Never read outside the tenant's bronze prefix.
                    self.hold_rejection(handle, notice, "0".repeat(64), "object", 0, "admission_invalid", "key outside the tenant's bronze prefix");
                    continue;
                }
            }
            let target = src_dir.join(format!("fetch-{}.parquet", uuid::Uuid::new_v4().simple()));
            if !self.sources.get_to_file(&notice.key, &target).await? {
                tracing::warn!(key = %notice.key, "notified bronze object is missing; recording and acknowledging");
                self.health.objects_missing_total += 1;
                self.hold_rejection(handle, notice, "0".repeat(64), "object", 0, "missing", "notified object not found");
                continue;
            }
            let (bytes, sha) = super::writer::file_digest(&target)?;
            if notice.sha256.as_ref().is_some_and(|expected| *expected != sha) {
                // Objects are immutable: a digest mismatch is deterministic.
                let _ = std::fs::remove_file(&target);
                self.hold_rejection(handle, notice, sha, "object", 0, "digest_mismatch", "object differs from its notified sha256");
                continue;
            }
            // Crash replay: the log (or this buffer) already consumed this
            // exact object. Its rows are all duplicates; consuming it again
            // would be refused (B2). Acknowledge it without admitting.
            let identity = SourceRef { key: notice.key.clone(), version: notice.version.clone(), sha256: sha.clone() };
            let buffered = self.buffer.sources.iter().any(|s| s.key == notice.key && s.version == notice.version && s.sha256 == sha)
                || files.iter().any(|(_, n, _, s, _): &(NoticeHandle, SourceNotice, PathBuf, String, u64)| n.key == notice.key && n.version == notice.version && *s == sha);
            if buffered || self.log.live().consumed(&identity) {
                tracing::info!(key = %notice.key, "object already consumed; acknowledging the replayed notice");
                // Every row is a duplicate (edge sources account them).
                let rows = crate::bronze::bronze_file_row_count(&target).unwrap_or(0);
                let _ = std::fs::remove_file(&target);
                self.health.objects_replayed_total += 1;
                if self.buffer.handle_names.insert(handle.0.clone()) {
                    self.buffer.handles.push(handle.clone());
                    self.buffer.replayed.push((handle.clone(), rows));
                }
                self.mark_since(now_ms);
                continue;
            }
            let path = src_dir.join(format!("{sha}.parquet"));
            std::fs::rename(&target, &path)?;
            files.push((handle.clone(), notice.clone(), path, sha, bytes));
        }
        if files.is_empty() {
            self.mark_since(now_ms);
            return Ok((0, 0));
        }
        // Admit each group, then conform its rows to the (pending) schema
        // BEFORE any row enters the buffer or the uid window:
        // - a row admission refuses on its own (bad or missing `time`,
        //   unparseable JSON) is refused alone (`rows` rejection);
        // - type drift is never a refusal: drifted values move into
        //   `unmapped.nano_coerced` (counted as coerced);
        // - a row that still does not decode is refused; a multi-object group
        //   holding one is split so the refusal names its object;
        // - an object admission itself refuses is refused whole.
        type File<'f> = &'f (NoticeHandle, SourceNotice, PathBuf, String, u64);
        struct Admitted<'f> {
            group: Vec<File<'f>>,
            rows_by_path: BTreeMap<PathBuf, u64>,
            /// Kept rows: their uids, payload hashes, times and the Arrow
            /// decode, row-aligned.
            uids: Vec<String>,
            payloads: Vec<u64>,
            batch: Option<RecordBatch>,
            times: Vec<i64>,
            /// Per file: (rows refused, first refusal, value-free).
            refused: BTreeMap<PathBuf, (u64, RowRefusal)>,
            /// NAN-3662: per file, the refused rows per source lane.
            refused_sources: BTreeMap<PathBuf, RefusedSources>,
            /// Rows admission dropped as in-batch duplicates.
            bronze_duplicates: u64,
            /// Of those, rows whose uid's kept copy has a different source
            /// identity (NAN-3719): counted like a cross-batch payload diff.
            conflicting_replays: u64,
        }
        let mut queue: Vec<Vec<File>> = vec![files.iter().collect()];
        let mut admitted: Vec<Admitted> = Vec::new();
        // JSON-value heap of the admitted rows (sampled): sizes the next
        // admission's in-flight share.
        let mut value_heap = 0_f64;
        while let Some(group) = queue.pop() {
            let paths = group.iter().map(|f| f.2.clone()).collect::<Vec<_>>();
            let (mut admission, refused, mut refused_sources) = match admit_bronze_files_attributing(&paths, &self.cfg.tenant_id, &self.enricher) {
                Ok((admission, refused, sources)) => {
                    // NAN-3662: a rejection names one object, so its
                    // per-source counts must be that object's alone. The
                    // per-source refusals are per group; a group whose
                    // refusals span objects is admitted one by one.
                    if self.cfg.refusal_source_counts && refused.len() > 1 && group.len() > 1 {
                        tracing::debug!(objects = group.len(), "refusals in several objects; admitting objects one by one");
                        queue.extend(group.into_iter().map(|file| vec![file]));
                        continue;
                    }
                    // NAN-3680: name the sources whose rows were refused
                    // (value-free).
                    sources.log("part_ingest");
                    let by_path = refused.keys().next().filter(|_| refused.len() == 1).map(|path| (path.clone(), sources)).into_iter().collect::<BTreeMap<_, _>>();
                    (admission, refused, by_path)
                }
                Err(error) if is_transient(&error) => return Err(error.context("transient admission failure")),
                Err(error) if group.len() > 1 => {
                    tracing::warn!(error = %error, objects = group.len(), "group admission failed; admitting objects one by one");
                    queue.extend(group.into_iter().map(|file| vec![file]));
                    continue;
                }
                Err(error) => {
                    let file = group[0];
                    let detail = format!("{error:#}");
                    let rows = crate::bronze::bronze_file_row_count(&file.2).unwrap_or(0);
                    // NAN-3490: every row refused. Name the first row's cause
                    // (value-free) instead of only "no canonical events".
                    let refused = error.downcast_ref::<NoCanonicalEvents>();
                    if let Some(refused) = refused {
                        refused.refused_sources.log("part_ingest");
                    }
                    let first_row = refused.and_then(|e| e.first_row.clone());
                    let sources = refused.map(|e| &e.refused_sources);
                    self.hold_rejection_with(&file.0, &file.1, file.3.clone(), "object", rows, "admission_invalid", &detail, first_row.as_ref(), sources);
                    let _ = std::fs::remove_file(&file.2);
                    continue;
                }
            };
            let rows_by_path = admission.files.iter().map(|f| (f.path.clone(), f.rows)).collect::<BTreeMap<_, _>>();
            // `duplicate_rows_removed` is source rows minus admitted
            // identities, so it also counts the rows salvaging refused.
            let salvaged = refused.values().map(|(count, _)| *count).sum::<u64>();
            let bronze_duplicates = admission.duplicate_rows_removed.saturating_sub(salvaged);
            let conflicting_replays = admission.conflicting_replay_rows_dropped;
            // The in-batch admission's source identities (NAN-3704): the
            // cross-batch window compares the same normalisation.
            let digests = admission.take_source_identity_digests();
            let mut rows = admission.batch.into_rows();
            value_heap += sampled_value_heap(&rows);
            // This namespace belongs to the authenticated finding-outbox
            // drain. A raw event must not become a risk contribution after
            // its part is merged with a genuine finding part.
            for row in &mut rows {
                strip_untrusted_risk_fields(&mut row.ocsf_event);
            }
            // A failed or slow lookup never fails or holds the tick: this
            // batch goes unstamped (a partial stamp is stripped whole).
            // Unstamped (no grant, rebuilding, catching up, state busy): a
            // source-supplied value must not pose as ours.
            let stamped = match self.stamp_lookup(&rows, now_ms).await {
                Some(observed) => match observed.stamp(rows.iter_mut().map(|row| &mut row.ocsf_event)) {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::error!(error = %format!("{error:#}"),
                            "PREVALENCE DEGRADED: prevalence stamping failed; this batch is unstamped");
                        false
                    }
                },
                None => false,
            };
            if !stamped {
                rows.iter_mut().for_each(|row| super::prevalence::strip_stamps(&mut row.ocsf_event));
            }
            // Admission normalized `time`; a row whose time still does not
            // parse is refused alone (never a tick error).
            let mut bad_time = BTreeSet::new();
            let times = rows
                .iter()
                .enumerate()
                .map(|(index, row)| {
                    event_time_us(&row.ocsf_event).unwrap_or_else(|_| {
                        bad_time.insert(index);
                        0
                    })
                })
                .collect::<Vec<_>>();
            // NAN-3864: rows written unstamped while the tenant holds a grant
            // are owed a restamp once the state reaches the log head; never
            // left null for their retention.
            if !stamped && self.restamp_eligible() {
                let hours = times.iter().enumerate().filter(|(index, _)| !bad_time.contains(index))
                    .map(|(_, time)| event_hour_of(*time)).collect::<BTreeSet<_>>();
                if self.prevalence_owed.mark(hours.iter().copied()) {
                    tracing::info!(tenant = %self.cfg.tenant_id, hours = ?hours, owed = self.prevalence_owed.len(),
                        status = %self.prevalence_status(), "rows committed unstamped; their hours are owed a prevalence restamp");
                }
            }
            let (grown, undecodable, coerced, decoded) = self.conform(&mut rows, &bad_time);
            if (!undecodable.is_empty() || !bad_time.is_empty()) && group.len() > 1 {
                tracing::warn!(objects = group.len(), rows = undecodable.len(), "undecodable rows; admitting objects one by one");
                queue.extend(group.into_iter().map(|file| vec![file]));
                continue;
            }
            self.pending_schema = grown;
            if coerced > 0 {
                tracing::warn!(rows = coerced, objects = group.len(), "type-drifted values moved into unmapped.nano_coerced");
            }
            self.health.rows_coerced_total += coerced;
            let mut refused = refused;
            let dropped = bad_time.len() + undecodable.len();
            if dropped > 0 {
                // Single-object group here (multi-object groups split above).
                let entry = refused.entry(group[0].2.clone()).or_insert_with(|| (0, RowRefusal::new("schema_decode", None)));
                entry.0 += dropped as u64;
                // NAN-3662: the dropped rows by source lane (value-free).
                let sources = refused_sources.entry(group[0].2.clone()).or_default();
                let (time, decode) = (RowRefusal::new("time_invalid", Some("time")), RowRefusal::new("schema_decode", None));
                for (index, row) in rows.iter().enumerate() {
                    let refusal = if bad_time.contains(&index) { &time } else if undecodable.contains(&index) { &decode } else { continue };
                    sources.note(SourceKey::of(&row.ocsf_event), refusal, None);
                }
                let keep = (0..rows.len()).filter(|i| !bad_time.contains(i) && !undecodable.contains(i)).collect::<BTreeSet<_>>();
                let mut index = 0;
                rows.retain(|_| {
                    let kept = keep.contains(&index);
                    index += 1;
                    kept
                });
                let times_kept = times.iter().enumerate().filter(|(i, _)| keep.contains(i)).map(|(_, t)| *t).collect::<Vec<_>>();
                // Whole-group checks decoded every row but the bad-time ones,
                // which are exactly the dropped rows when none is undecodable.
                let decoded = decoded.filter(|_| undecodable.is_empty());
                let (uids, batch) = decoded_rows(rows, decoded, &self.pending_schema)?;
                let payloads = payload_hashes(&uids, &digests);
                admitted.push(Admitted { group, rows_by_path, uids, payloads, batch, times: times_kept, refused, refused_sources, bronze_duplicates, conflicting_replays });
            } else {
                let (uids, batch) = decoded_rows(rows, decoded, &self.pending_schema)?;
                let payloads = payload_hashes(&uids, &digests);
                admitted.push(Admitted { group, rows_by_path, uids, payloads, batch, times, refused, refused_sources, bronze_duplicates, conflicting_replays });
            }
        }
        // Commit groups to the buffer atomically: every fallible step
        // (window preparation) runs before any row or uid is added, so an
        // error here leaves the buffer as it was and replay is safe.
        let mut rows_total = 0_u64;
        let mut admitted_bytes = 0_u64;
        let source_bytes = files.iter().map(|f| f.4).sum::<u64>();
        let mut dups_total = 0_u64;
        for Admitted { group, rows_by_path, uids, payloads, batch, times, refused, refused_sources, bronze_duplicates, conflicting_replays } in admitted {
            self.buffer.bronze_duplicates += bronze_duplicates;
            self.buffer.same_uid_payload_diff += conflicting_replays;
            if conflicting_replays > 0 {
                self.log_in_batch_conflict(conflicting_replays, group.len(), now_ms);
            }
            self.buffer.rows_refused += refused.values().map(|(count, _)| *count).sum::<u64>();
            let mut by_hour: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
            for (index, time_us) in times.iter().enumerate() {
                by_hour.entry(event_hour_of(*time_us)).or_default().push(index);
            }
            let mut unverified = BTreeSet::new();
            for (hour, rows) in &by_hour {
                if self.prepare_hour(*hour, rows.iter().map(|i| uids[*i].as_str()), now_ms).await? {
                    unverified.insert(*hour);
                }
            }
            for (hour, rows) in by_hour {
                let mut keep = Vec::with_capacity(rows.len());
                // NAN-3703: an hour the late tier holds is checked against
                // it too (bloom, then a local exact lookup; no store I/O).
                let tiered = self.late.has_hour(hour);
                let unverified = unverified.contains(&hour);
                for index in rows {
                    let uid = &uids[index];
                    self.buffer.rows_in += 1;
                    rows_total += 1;
                    let payload = payloads[index];
                    let key = self.window.key(uid);
                    let seen = if tiered && !self.window.contains_key(hour, &key) && self.late.contains(hour, &key) {
                        self.health.late_dedup_tier_duplicates_total += 1;
                        Seen::Duplicate
                    } else {
                        self.window.observe_key(hour, key, payload, now_ms)
                    };
                    if seen == Seen::New && unverified {
                        if super::late_dedup::within_horizon(hour, now_ms) {
                            self.health.late_dedup_unverified_rows_total += 1;
                        } else {
                            self.health.late_dedup_beyond_horizon_rows_total += 1;
                        }
                    }
                    if seen != Seen::New {
                        self.buffer.duplicates += 1;
                        *self.buffer.hour_duplicates.entry(hour).or_default() += 1;
                        dups_total += 1;
                        if let Seen::PayloadDiff { first } = seen {
                            self.buffer.same_uid_payload_diff += 1;
                            self.log_payload_diff(hour, uid, first, payload, now_ms);
                        }
                        continue;
                    }
                    keep.push(u32::try_from(index).context("admission row index")?);
                }
                if keep.is_empty() {
                    continue;
                }
                let batch = batch.as_ref().context("admitted rows without their decode")?;
                let kept = arrow_select::take::take_record_batch(batch, &arrow_array::UInt32Array::from(keep))?;
                let bytes = kept.get_array_memory_size() as u64;
                admitted_bytes += bytes;
                self.buffer.bytes += bytes;
                self.buffer.rows += kept.num_rows();
                self.buffer.hours.entry(hour).or_default().push(kept);
            }
            for (handle, notice, path, sha, bytes) in group {
                if let Some((count, first)) = refused.get(path) {
                    let detail = format!("{count} rows refused; {first}");
                    self.hold_rejection_with(handle, notice, sha.clone(), "rows", *count, "admission_invalid", &detail, Some(first), refused_sources.get(path));
                }
                self.buffer.sources.push(SourceObject {
                    key: notice.key.clone(),
                    version: notice.version.clone(),
                    bytes: *bytes,
                    sha256: sha.clone(),
                    rows: rows_by_path.get(path).copied().unwrap_or_default(),
                    edge_sha256: notice.edge_sha256.clone(),
                });
                if self.buffer.handle_names.insert(handle.0.clone()) {
                    self.buffer.handles.push(handle.clone());
                }
                let source_rows = rows_by_path.get(path).copied().unwrap_or_default();
                let refused_here = refused.get(path).map_or(0, |(count, _)| *count);
                self.buffer.admitted.push((handle.clone(), source_rows, refused_here));
                let _ = std::fs::remove_file(path);
            }
        }
        self.mark_since(now_ms);
        if source_bytes > 0 && admitted_bytes > 0 {
            let observed = admitted_bytes as f64 / source_bytes as f64;
            self.arrow_per_source_byte = 0.5 * self.arrow_per_source_byte + 0.5 * observed;
        }
        if source_bytes > 0 && value_heap > 0.0 {
            let observed = value_heap / source_bytes as f64;
            self.heap_per_source_byte = 0.5 * self.heap_per_source_byte + 0.5 * observed;
        }
        // Rate estimate (events/s) for the flush interval.
        if let Some(last) = self.last_admit_ms.replace(now_ms) {
            let seconds = ((now_ms - last).max(1) as f64) / 1_000.0;
            let eps = rows_total as f64 / seconds;
            self.health.eps_ewma = if self.health.eps_ewma == 0.0 { eps } else { 0.8 * self.health.eps_ewma + 0.2 * eps };
        }
        Ok((rows_total, dups_total))
    }

    fn mark_since(&mut self, now_ms: i64) {
        if self.buffer.since_ms.is_none() && (!self.buffer.handles.is_empty() || !self.buffer.rejections.is_empty()) {
            self.buffer.since_ms = Some(now_ms);
        }
    }

    /// Record a refusal durably with the next flush (a `reject` log entry)
    /// and acknowledge the notice only after that entry commits.
    #[allow(clippy::too_many_arguments)]
    fn hold_rejection(
        &mut self,
        handle: &NoticeHandle,
        notice: &SourceNotice,
        sha256: String,
        scope: &str,
        rows_rejected: u64,
        reason: &str,
        detail: &str,
    ) {
        self.hold_rejection_with(handle, notice, sha256, scope, rows_rejected, reason, detail, None, None);
    }

    /// [`Self::hold_rejection`] naming the first refused row's cause as
    /// structured, value-free fields (NAN-3490) and, with
    /// [`IngestConfig::refusal_source_counts`], the refused rows per source
    /// lane as the entry's detail tag (NAN-3662, [`refusal_tally`]).
    #[allow(clippy::too_many_arguments)]
    fn hold_rejection_with(
        &mut self,
        handle: &NoticeHandle,
        notice: &SourceNotice,
        sha256: String,
        scope: &str,
        rows_rejected: u64,
        reason: &str,
        detail: &str,
        first_row: Option<&RowRefusal>,
        sources: Option<&RefusedSources>,
    ) {
        match first_row {
            Some(first) => tracing::error!(key = %notice.key, reason, scope, rows_rejected, detail,
                first_row_reason = first.reason, first_row_field = first.field_name(), "bronze data refused"),
            None => tracing::error!(key = %notice.key, reason, scope, rows_rejected, detail, "bronze data refused"),
        }
        if scope == "object" {
            self.health.objects_rejected_total += 1;
            self.buffer.refused.push((handle.clone(), rows_rejected));
        }
        self.health.rows_rejected_total += rows_rejected;
        // The tag goes first and is at most 320 ASCII bytes, so the cut below
        // only ever shortens the human-readable rest.
        let detail = match sources.filter(|_| self.cfg.refusal_source_counts) {
            Some(sources) => refusal_tally::tag_detail(&refusal_tally::tallies(sources), detail),
            None => detail.to_string(),
        };
        let detail = detail.chars().filter(|c| !c.is_control()).take(480).collect::<String>();
        self.buffer.rejections.push(Rejection {
            source: SourceRef { key: notice.key.clone(), version: notice.version.clone(), sha256 },
            scope: scope.to_string(),
            rows_rejected,
            reason: reason.to_string(),
            detail,
        });
        if self.buffer.handle_names.insert(handle.0.clone()) {
            self.buffer.handles.push(handle.clone());
        }
    }

    /// `schema` grown by `events` (additive), with no integer truncation,
    /// and every event decoding, plus that decode (NAN-3183: the buffer
    /// keeps it, so rows are decoded once). Deterministic.
    pub(crate) fn shape_check(schema: &SchemaRef, events: &[&Value]) -> Result<(SchemaRef, Option<RecordBatch>)> {
        if events.is_empty() {
            return Ok((schema.clone(), None));
        }
        use rayon::prelude::*;
        // Common case (a settled schema): no row chunk adds a leaf, which
        // is exactly when one inference over every row adds none either
        // (leaves are the union over rows; an existing scalar keeps its type;
        // a shape conflict fails a chunk too). Chunks infer in parallel;
        // anything else takes the whole-group inference.
        let settled = events.len() > super::schema::DECODE_CHUNK_ROWS && events
            .par_chunks(super::schema::DECODE_CHUNK_ROWS)
            .all(|chunk| infer_schema(chunk).and_then(|proposed| additive_merge(schema, &proposed)).is_ok_and(|grown| grown.is_none()));
        let grown = if settled {
            schema.clone()
        } else {
            match additive_merge(schema, &infer_schema(events)?)? {
                Some(grown) => Arc::new(grown),
                None => schema.clone(),
            }
        };
        let root = arrow_schema::DataType::Struct(grown.fields().clone());
        ensure!(!events.par_iter().any(|e| truncates(e, &root)), "a fractional number would truncate into an integer leaf");
        let batch = decode_parallel(grown.clone(), events).context("rows do not decode into the tenant schema")?;
        Ok((grown, Some(batch)))
    }

    /// Conform `rows` (except `skip`) to the pending schema: `(grown schema,
    /// undecodable row indexes, rows coerced, the decoded rows except `skip`
    /// when a whole-group check produced them)`. Type drift is coerced into
    /// `unmapped` (B4), never refused. Cost: one infer + decode for a clean
    /// group; one coercion walk plus one infer + decode for a drifted one;
    /// the per-row path only when rows conflict with each other.
    fn conform(&self, rows: &mut [crate::iceberg::EventRow], skip: &BTreeSet<usize>) -> (SchemaRef, BTreeSet<usize>, u64, Option<RecordBatch>) {
        let live = (0..rows.len()).filter(|i| !skip.contains(i)).collect::<Vec<_>>();
        let check = |schema: &SchemaRef, rows: &[crate::iceberg::EventRow], idx: &[usize]| {
            let refs = idx.iter().map(|i| &rows[*i].ocsf_event).collect::<Vec<_>>();
            Self::shape_check(schema, &refs)
        };
        if let Ok((grown, batch)) = check(&self.pending_schema, rows, &live) {
            return (grown, BTreeSet::new(), 0, batch);
        }
        let mut coerced = BTreeSet::new();
        for &index in &live {
            if coerce_to_schema(&mut rows[index].ocsf_event, &self.pending_schema) > 0 {
                coerced.insert(index);
            }
        }
        if let Ok((grown, batch)) = check(&self.pending_schema, rows, &live) {
            return (grown, BTreeSet::new(), coerced.len() as u64, batch);
        }
        // New leaves conflict between rows: grow row by row, coercing each
        // row against the schema grown so far.
        let mut schema = self.pending_schema.clone();
        let mut undecodable = BTreeSet::new();
        for &index in &live {
            if let Ok((grown, _)) = check(&schema, rows, &[index]) {
                schema = grown;
                continue;
            }
            if coerce_to_schema(&mut rows[index].ocsf_event, &schema) > 0 {
                coerced.insert(index);
            }
            match check(&schema, rows, &[index]) {
                Ok((grown, _)) => schema = grown,
                Err(_) => {
                    undecodable.insert(index);
                }
            }
        }
        (schema, undecodable, coerced.len() as u64, None)
    }

    /// Should dedup of `hour` fetch its parts from the store? Only for hours
    /// that ended inside the horizon (NAN-3387); see
    /// `IngestConfig::late_hour_remote_dedup_ms`.
    fn remote_dedup(&self, hour: i32, now_ms: i64) -> bool {
        let hour_end_ms = (i64::from(hour) + 1) * 3_600_000;
        self.cfg.late_hour_remote_dedup_ms.is_none_or(|horizon| hour_end_ms > now_ms.saturating_sub(horizon))
    }

    /// One sampled line per tenant per wall-clock hour when a cross-batch
    /// duplicate's payload differs from the kept row's (NAN-3704): the uid
    /// and both payload hashes, never the payload.
    fn log_payload_diff(&mut self, event_hour: i32, uid: &str, first: u64, dropped: u64, now_ms: i64) {
        let hour = now_ms.div_euclid(3_600_000);
        if self.payload_diff_logged_hour == Some(hour) {
            return;
        }
        self.payload_diff_logged_hour = Some(hour);
        tracing::warn!(tenant = %self.cfg.tenant_id, event_hour, uid, kept_payload_hash = %format!("{first:016x}"),
            dropped_payload_hash = %format!("{dropped:016x}"),
            "same uid with a different payload dropped as a duplicate (first row kept); sampled once per tenant per hour");
    }

    /// NAN-3719: the integrity signal the whole-object `ConflictingReplay`
    /// refusal used to carry, row-scoped and sampled like
    /// [`Self::log_payload_diff`]: rows of one admission held the same uid
    /// under different source identities; one copy was kept. Usually benign
    /// (identical raw lines through a parser's raw-hash fallback), rarely a
    /// producer bug. The full count is `same_uid_payload_diff_total`.
    fn log_in_batch_conflict(&mut self, rows_dropped: u64, objects: usize, now_ms: i64) {
        let hour = now_ms.div_euclid(3_600_000);
        if self.in_batch_conflict_logged_hour == Some(hour) {
            return;
        }
        self.in_batch_conflict_logged_hour = Some(hour);
        tracing::warn!(tenant = %self.cfg.tenant_id, rows_dropped, objects,
            "same uid with a different source identity inside one admission: one copy kept per uid, the rest dropped as duplicates, no object refused; sampled once per tenant per hour");
    }

    /// NAN-3703: apply finished late-tier work and start the next
    /// background fold. Never waits on the store: a fold downloads and
    /// reads its part in a spawned task, and needs the static background
    /// store (lab callers without one never fold; their late rows are
    /// admitted and counted).
    async fn tick_late_tier(&mut self, now_ms: i64) {
        self.late.poll(now_ms).await;
        let Some(store) = self.background_parts else { return };
        let live = self.log.live();
        let Some(part) = self.late.next_fold(now_ms, |part| live.get(&part.part_id).is_some()) else { return };
        let (tenant, trusted, work_dir) = (self.cfg.tenant_id.clone(), self.trusted.clone(), self.cfg.work_dir.clone());
        let tier_dir = self.late.dir().to_path_buf();
        let target = part.clone();
        tracing::info!(hour = part.event_hour, part = %part.part_id.as_str(), "late uid tier: folding a part in the background");
        let task = tokio::spawn(async move {
            let dir = download_part(store, &tenant, &trusted, &work_dir, &target).await?;
            tokio::task::spawn_blocking(move || super::late_dedup::fold_part(&tier_dir, &tenant, &target, &dir, now_ms))
                .await
                .context("late uid fold task")?
        });
        self.late.start_fold(part, task);
    }

    /// Make the window authoritative for `uids` of `hour`: load any live
    /// part of the hour whose uid bloom admits one of them. When an hour is
    /// past the remote-dedup horizon, only parts already in the local cache
    /// are consulted, and the hour stays incomplete. A part the late-hour
    /// tier covers needs no load: admission checks the tier (NAN-3703).
    /// Returns true when some live part of the hour could not be consulted
    /// (neither loaded, covered nor cached); for an hour inside the 72 h
    /// horizon such a part is queued for a background fold.
    async fn prepare_hour<'u>(&mut self, hour: i32, uids: impl Iterator<Item = &'u str>, now_ms: i64) -> Result<bool> {
        if self.window.is_complete(hour) {
            return Ok(false);
        }
        let parts = self.parts_of_hour(hour);
        if parts.is_empty() {
            self.window.set_complete(hour, true, now_ms);
            return Ok(false);
        }
        let remote = self.remote_dedup(hour, now_ms);
        let uids = uids.collect::<Vec<_>>();
        let mut all_loaded = true;
        let mut unfetched = 0_u64;
        for part in &parts {
            if self.window.has_loaded(hour, part.part_id.as_str()) || self.late.covers(hour, part.part_id.as_str()) {
                continue;
            }
            let dir = if remote {
                let dir = self.ensure_local(part).await?;
                // Store progress the stall watchdog credits (NAN-3387).
                super::stall_watchdog::note_progress();
                dir
            } else if let Some(dir) = self.find_local(&part.part_id).filter(|dir| dir.join(PROVENANCE_FILE).exists()) {
                dir
            } else {
                all_loaded = false;
                unfetched += 1;
                if super::late_dedup::within_horizon(hour, now_ms) {
                    self.late.request_fold(part);
                }
                continue;
            };
            if part.level != Level::Day || part_may_contain_any(&dir, &uids)? {
                // Hourly parts of a live hour are cheap to load and make
                // the hour complete; day parts only on a bloom hit.
                self.window.load_part(hour, part.part_id.as_str(), &dir, now_ms)?;
                tokio::task::yield_now().await;
            } else {
                all_loaded = false;
            }
        }
        if unfetched > 0 {
            self.health.late_dedup_parts_unfetched_total += unfetched;
            tracing::debug!(hour, parts = unfetched, "old event hour deduped without fetching its parts");
        }
        self.window.set_complete(hour, all_loaded, now_ms);
        Ok(unfetched > 0)
    }

    /// Commit the buffer, in the order the edge contract needs (4.1.1,
    /// 5.1.1), each stage recorded as it lands so a retry after any partial
    /// failure redoes only what is missing (B2) and nothing new is admitted
    /// until the acks land (B1):
    /// 1. `reject` entries (chunked, B3) for held refusals, before any ack;
    /// 2. `ack_skipped` for notices without rows (refused whole, replayed,
    ///    or every object when the flush holds no rows);
    /// 3. the flush's edge range (issued once), its parts and one `add`
    ///    entry carrying the range (as does every L0 record);
    /// 4. `ack` of the consumed notices (an edge source commits the range).
    ///
    /// `pipeline` (catch-up, NAN-3183): after step 3 issues the range, the
    /// sealed buffer builds and uploads its parts in the background and the
    /// tick goes on admitting into a fresh buffer; its `add` and `ack` land
    /// in [`Self::reap_in_flight`]. Any flush first commits the one in
    /// flight, so entries, edge ranges and acks stay in flush order.
    async fn flush(&mut self, now_ms: i64, pipeline: bool) -> Result<usize> {
        // Commit what is ready, then wait until this seal may join the
        // flights left (NAN-3619): with depth 1, or whenever this seal would
        // log anything ahead of an earlier flight's `add` (rejections, skip
        // acks, a schema change) or not pipeline at all, every flight
        // commits first, exactly as before.
        let keep = if self.may_seal_beside_flights(pipeline) { self.flush_depth() - 1 } else { 0 };
        let reaped = self.reap_in_flight(now_ms, keep).await?;
        if self.buffer.handles.is_empty() && self.buffer.rows == 0 {
            return Ok(reaped);
        }
        let no_rows = self.buffer.rows == 0;
        while self.buffer.rejections_logged < self.buffer.rejections.len() {
            let chunk = reject_chunk(&self.buffer.rejections[self.buffer.rejections_logged..]);
            let taken = chunk.len();
            self.log.append(LogOp::Reject { rejections: chunk }, now_ms).await?;
            self.buffer.rejections_logged += taken;
        }
        if !self.buffer.skips_acked {
            let mut skips = self
                .buffer
                .refused
                .iter()
                .map(|(h, rows)| (h.clone(), AckCounts { rows: *rows, rows_rejected: *rows, rows_duplicate: 0 }))
                .chain(
                    self.buffer
                        .replayed
                        .iter()
                        .map(|(h, rows)| (h.clone(), AckCounts { rows: *rows, rows_rejected: 0, rows_duplicate: *rows })),
                )
                .collect::<Vec<_>>();
            if no_rows {
                skips.extend(self.buffer.admitted.iter().map(|(h, rows, refused)| {
                    let rejected = (*refused).min(*rows);
                    (h.clone(), AckCounts { rows: *rows, rows_rejected: rejected, rows_duplicate: rows - rejected })
                }));
            }
            // Nothing to skip: no queue call (every queue treats an empty
            // ack as a no-op; with flights out it must not look like one).
            // (Either flag on; both off keeps today's unconditional call.)
            if !skips.is_empty() || !(self.cfg.commit_when_ready || self.flush_depth() > 1) {
                self.queue.ack_skipped(&skips).await?;
            }
            self.buffer.skips_acked = true;
        }
        if !no_rows && !self.buffer.add_committed {
            if self.buffer.issued_range.is_none() {
                let mut sources = self.buffer.sources.clone();
                sources.sort();
                self.buffer.issued_range = self
                    .queue
                    .range_for_flush(&sources, self.buffer.rows_refused, self.buffer.duplicates + self.buffer.bronze_duplicates)
                    .await?;
            }
            let range = self.buffer.issued_range.clone();
            if let (true, Some(store), Some(signer)) = (pipeline, self.background_parts, self.background_signer) {
                self.log_pending_schema(now_ms).await?;
                let plan = self.flush_plan(&self.buffer, self.schema.clone(), range, now_ms)?;
                let reserved_bytes = super::memory::flight_bytes(self.buffer.bytes, plan.writers);
                let trusted = self.trusted.clone();
                let wake = self.flight_wake.clone();
                let task = tokio::spawn(async move {
                    let result = async {
                        let finished = tokio::task::spawn_blocking(move || plan.build()).await.context("flush part build task")??;
                        let refs = publish_parts(store, signer, &trusted, &finished).await?;
                        Ok((finished, refs))
                    }.await;
                    if let Some(wake) = wake {
                        wake.notify_one();
                    }
                    result
                });
                let buffer = std::mem::replace(&mut self.buffer, Buffered::new());
                self.flush_in_flight.push_back(InFlightFlush { buffer, reserved_bytes, schema: self.schema.clone(), sealed_ms: now_ms, task: Some(task), published: None });
                self.health.flushes_pipelined_total += 1;
                self.health.flushes_in_flight_peak = self.health.flushes_in_flight_peak.max(self.flush_in_flight.len());
                return Ok(reaped);
            }
            self.buffer.parts_committed = self.commit_parts(now_ms, range).await?;
            self.buffer.add_committed = true;
        }
        if !no_rows {
            let consumed = self.buffer.admitted.iter().map(|(h, _, _)| h.clone()).collect::<Vec<_>>();
            self.queue.ack(&consumed).await?;
        }
        let buffer = std::mem::replace(&mut self.buffer, Buffered::new());
        Ok(reaped + self.finish_flush(buffer, now_ms, None))
    }

    /// Health accounting of a flush whose acks landed.
    /// `sealed_ms` is when a pipelined flush was sealed (its commit lag).
    fn finish_flush(&mut self, buffer: Buffered, now_ms: i64, sealed_ms: Option<i64>) -> usize {
        let count = buffer.parts_committed;
        if buffer.rows > 0 {
            tracing::info!(tenant = %self.cfg.tenant_id, rows = buffer.rows, objects = buffer.handles.len(), parts = count,
                pipelined = sealed_ms.is_some(), sealed_to_commit_ms = sealed_ms.map(|sealed| now_ms - sealed),
                "ingest flush committed");
        }
        self.health.last_commit_ms = Some(now_ms);
        self.health.rows_committed_total += buffer.rows as u64;
        self.health.duplicates_dropped_total += buffer.duplicates;
        self.health.same_uid_payload_diff_total += buffer.same_uid_payload_diff;
        self.health.objects_consumed_total += buffer.handles.len() as u64;
        self.health.parts_written_total += count as u64;
        // The flush's rows and build copies were just dropped: hand their
        // pages back (glibc arenas keep them otherwise; NAN-3183 OOM).
        drop(buffer);
        super::memory::release_freed();
        count
    }

    /// Commit pipelined flights oldest first: every one that is ready (parts
    /// published, or its task done), and wait for the oldest while more than
    /// `keep` remain (`usize::MAX`: never wait; 0: commit all). Stops at the
    /// first flight still building, so commits stay in seal order. A failed
    /// build/publish is redone under fresh part ids, a published flush whose
    /// `add` failed retries the `add` (the flight stays oldest). Returns the
    /// parts committed.
    async fn reap_in_flight(&mut self, now_ms: i64, keep: usize) -> Result<usize> {
        let mut committed = 0;
        while let Some(front) = self.flush_in_flight.front() {
            // Only the oldest flight may commit: a younger one that finished
            // first waits behind it (seal order = log, range and ack order).
            let must_wait = self.flush_in_flight.len() > keep;
            let ready = front.published.is_some() || front.buffer.add_committed
                || front.task.as_ref().is_none_or(|task| task.is_finished());
            if !must_wait && !ready {
                break;
            }
            committed += self.commit_oldest_flight(now_ms).await?;
        }
        Ok(committed)
    }

    /// Commit the oldest flight, waiting for its build/publish if needed:
    /// its `add`, then the acks. Every stage is recorded as it lands; on
    /// error the flight stays the oldest and the next call resumes it.
    async fn commit_oldest_flight(&mut self, now_ms: i64) -> Result<usize> {
        let Some(mut flight) = self.flush_in_flight.pop_front() else { return Ok(0) };
        if flight.published.is_none() && !flight.buffer.add_committed {
            let outcome = match flight.task.take() {
                Some(task) => match task.await {
                    Ok(result) => result,
                    Err(error) => Err(anyhow::anyhow!("pipelined flush task failed: {error}")),
                },
                None => {
                    let plan = self.flush_plan(&flight.buffer, flight.schema.clone(), flight.buffer.issued_range.clone(), now_ms);
                    match plan.and_then(FlushPlan::build) {
                        Ok(finished) => publish_parts(self.parts, self.signer, &self.trusted, &finished).await.map(|refs| (finished, refs)),
                        Err(error) => Err(error),
                    }
                }
            };
            match outcome {
                Ok(published) => flight.published = Some(published),
                Err(error) => {
                    self.flush_in_flight.push_front(flight);
                    return Err(error.context("pipelined flush build/publish"));
                }
            }
        }
        if !flight.buffer.add_committed {
            let (finished, refs) = flight.published.as_ref().expect("published above");
            let consumed = consumed_sources(&flight.buffer);
            match self.commit_add(finished, refs.clone(), consumed, flight.buffer.issued_range.clone(), now_ms).await {
                Ok(count) => {
                    flight.buffer.parts_committed = count;
                    flight.buffer.add_committed = true;
                }
                Err(error) => {
                    self.flush_in_flight.push_front(flight);
                    return Err(error);
                }
            }
        }
        let handles = flight.buffer.admitted.iter().map(|(h, _, _)| h.clone()).collect::<Vec<_>>();
        if let Err(error) = self.queue.ack(&handles).await {
            self.flush_in_flight.push_front(flight);
            return Err(error);
        }
        Ok(self.finish_flush(flight.buffer, now_ms, Some(flight.sealed_ms)))
    }

    /// Flushes allowed in flight at once: the configured depth, capped by
    /// what the queue lets be outstanding (NAN-3619).
    fn flush_depth(&self) -> usize {
        self.cfg.flush_depth.clamp(1, MAX_FLUSH_DEPTH).min(self.queue.max_outstanding_ranges().max(1))
    }

    /// Whether the buffer may seal while earlier flights are still in
    /// flight: only a pipelined seal that appends nothing to the part log
    /// and acks nothing ahead of their `add`s (no rejections, no skip acks,
    /// no pending schema, rows to write, not resumed mid-commit).
    fn may_seal_beside_flights(&self, pipeline: bool) -> bool {
        pipeline
            && self.flush_depth() > 1
            && self.background_parts.is_some()
            && self.background_signer.is_some()
            && self.buffer.rows > 0
            && !self.buffer.partially_committed()
            && self.buffer.rejections.is_empty()
            && self.buffer.refused.is_empty()
            && self.buffer.replayed.is_empty()
            && self.pending_schema.fields() == self.schema.fields()
    }

    /// Append the floor/end op the queue asks for (edge sources), then tell
    /// it. Only between flushes.
    async fn apply_points(&mut self, now_ms: i64) -> Result<()> {
        if self.buffer.partially_committed() || !self.flush_in_flight.is_empty() {
            return Ok(());
        }
        while let Some(point) = self.queue.point_due(now_ms).await? {
            self.log.append(point.op.clone(), now_ms).await?;
            self.queue.point_appended(&point).await?;
            if point.end {
                tracing::info!("edge log ended (drained); ingest stops pulling from it");
                break;
            }
        }
        Ok(())
    }

    /// Log the pending schema's additive growth (checked at admission)
    /// before the parts that need it.
    async fn log_pending_schema(&mut self, now_ms: i64) -> Result<()> {
        if self.pending_schema.fields() != self.schema.fields() {
            let schema = LogSchema::from_arrow(&self.pending_schema)?;
            self.log.append(LogOp::Schema { schema }, now_ms).await?;
            self.schema = self.pending_schema.clone();
        }
        Ok(())
    }

    /// The parts plan of `buffer` under `schema` (logged).
    fn flush_plan(&self, buffer: &Buffered, schema: SchemaRef, edge_log: Option<crate::parts::EdgeLogRange>, now_ms: i64) -> Result<FlushPlan> {
        let fingerprint = crate::parts::format::schema_fingerprint(&schema)?;
        let feed = self.enricher.initial_metrics();
        let mut admission = Admission {
            ocsf_version: crate::iceberg::OCSF_VERSION.to_string(),
            admission_contract: ADMISSION_CONTRACT.to_string(),
            feed_pins: BTreeMap::from([
                ("ioc".to_string(), feed.ioc_snapshot_sha256.clone()),
                ("ioc_revision".to_string(), self.enrichment_revision.clone()),
                ("ip_context".to_string(), feed.ip_context_snapshot_sha256.clone()),
                ("ipinfo".to_string(), feed.ipinfo_snapshot_sha256.clone()),
                ("platform_bundle".to_string(), feed.platform_admission_sha256.clone()),
                ("platform_policy_revision".to_string(), feed.platform_policy_revision.clone()),
            ]),
        };
        // NAN-3503: pinned only while a directory is installed, so a part
        // written with enrichment off keeps exactly the pins it had before.
        // The directory is swapped by a background task without a part cut
        // (identity is advisory context, never replayed), so this records the
        // revision installed when the part is planned: rows buffered just
        // before a swap may carry the previous revision.
        if let Some(revision) = feed.identity_revision.clone() {
            admission.feed_pins.insert("identity_revision".to_string(), Some(revision));
        }
        let mut sources = buffer.sources.clone();
        sources.sort();
        Ok(FlushPlan {
            dir: parts_dir(&self.cfg.work_dir),
            tenant_id: self.cfg.tenant_id.clone(),
            signer_key_id: self.signer.key_id().to_string(),
            schema,
            fingerprint,
            admission,
            sources,
            edge_log,
            build: self.cfg.build.clone(),
            hours: buffer.hours.iter()
                .map(|(hour, batches)| (*hour, batches.clone(), buffer.hour_duplicates.get(hour).copied().unwrap_or_default()))
                .collect(),
            now_ms,
            writers: self.flush_writers(buffer.bytes),
        })
    }

    /// Bytes reserved for the running background merges (each at its decode
    /// window of [`super::merge::MERGE_ROW_BYTES`] rows plus its writer).
    fn merges_reserved_bytes(&self) -> u64 {
        self.merge_in_flight.len() as u64 * super::merge::merge_reserve_bytes()
    }

    /// Everything the working budget is charged with now: the filling
    /// buffer, the flush in flight (rows + build + writers) and the merges.
    fn committed_bytes(&self) -> u64 {
        self.buffer.bytes
            .saturating_add(self.flush_in_flight.iter().map(|flight| flight.reserved_bytes).sum::<u64>())
            .saturating_add(self.merges_reserved_bytes())
    }

    /// Parallel writers for a flush of `buffer_bytes`: the most whose build
    /// fits beside the merges and a full next buffer (NAN-3183 OOM).
    fn flush_writers(&self, buffer_bytes: u64) -> usize {
        let budget = self.cfg.buffer_budget_bytes;
        // Earlier flights still in flight (depth > 1) hold their build too.
        let flights = self.flush_in_flight.iter().map(|flight| flight.reserved_bytes).sum::<u64>();
        let others = self.merges_reserved_bytes().saturating_add(super::memory::buffer_cap(budget)).saturating_add(flights);
        super::memory::writers_for(buffer_bytes, budget.saturating_sub(others))
    }

    async fn commit_parts(&mut self, now_ms: i64, edge_log: Option<crate::parts::EdgeLogRange>) -> Result<usize> {
        self.log_pending_schema(now_ms).await?;
        let finished_parts = self.flush_plan(&self.buffer, self.schema.clone(), edge_log.clone(), now_ms)?.build()?;
        let refs = publish_parts(self.parts, self.signer, &self.trusted, &finished_parts).await?;
        let consumed = consumed_sources(&self.buffer);
        self.commit_add(&finished_parts, refs, consumed, edge_log, now_ms).await
    }

    /// Append the flush's `add` for its published parts and apply it to the
    /// prevalence state. Nothing after the append fails.
    async fn commit_add(&mut self, finished_parts: &[FinishedPart], refs: Vec<PartRef>, consumed: Vec<SourceRef>,
        edge_log: Option<crate::parts::EdgeLogRange>, now_ms: i64) -> Result<usize> {
        let prevalence_parts = finished_parts.iter()
            .map(|part| (part.dir.join(crate::parts::format::PARTIAL_PREVALENCE_FILE), part.record.max_time_us))
            .collect::<Vec<_>>();
        if let Some(prevalence) = &self.prevalence {
            prevalence.check_parts(&self.cfg.tenant_id,
                &prevalence_parts.iter().map(|(path, time)| (path.as_path(), *time)).collect::<Vec<_>>())?;
        }
        let count = refs.len();
        // Merges must not consume these L0s until their partials are in the
        // prevalence state; `replay_prevalence` clears this after a failure.
        let already_pending = self.prevalence_pending;
        self.prevalence_pending = self.prevalence_held();
        let AppendOutcome::Committed { seq, entry_sha256 } =
            self.log.append(LogOp::Add { parts: refs.clone(), consumed, edge_log }, now_ms).await?;
        // The Add is committed: nothing after this may fail the flush, or the
        // retry would re-consume its sources (DoubleConsume, fatal). A state
        // write that fails stays pending and `run_merges` replays it.
        // While rebuilding or catching up the Add stays pending: ticks
        // apply it in log order after the rebuild. NAN-3774: so it does
        // while the state is opening, rotating or overrunning, and the apply
        // here waits at most the ingest wait: the commit is already done,
        // and the cursor makes the catch-up exactly-once (a cut apply's
        // chunks and cursor land together or not at all).
        if self.prevalence_phase == PrevalencePhase::Stamping && self.prevalence_ready() {
            let wait = self.ingest_wait();
            let applied = if already_pending {
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(self.cfg.prevalence_rebuild_budget_ms);
                tokio::time::timeout(wait, self.replay_prevalence(Some(deadline))).await
            } else {
                tokio::time::timeout(wait, self.apply_committed_prevalence(seq, &entry_sha256, &refs, finished_parts)).await
                    .map(|applied| applied.map(|()| true))
            };
            match applied {
                Ok(Ok(caught_up)) => {
                    self.prevalence_progressed();
                    if caught_up {
                        self.prevalence_pending = false;
                    }
                }
                Ok(Err(error)) => tracing::warn!(error = %format!("{error:#}"), seq,
                    "prevalence apply failed after the add committed; replaying before the next merge"),
                Err(_) => self.prevalence_overran(now_ms, "apply of a committed add"),
            }
        }
        for part in &refs {
            // Our own uids are already in the window.
            self.window.load_marker(part.event_hour, part.part_id.as_str(), now_ms);
        }
        Ok(count)
    }

    async fn apply_committed_prevalence(&mut self, seq: u64, entry_sha256: &str, refs: &[PartRef],
        finished_parts: &[FinishedPart]) -> Result<()> {
        let entry = super::prevalence::EntryRef {
            seq,
            sha256: entry_sha256,
            rebuild: false,
            parts: u32::try_from(refs.len()).context("too many parts in one add")?,
        };
        if std::mem::take(&mut self.prevalence_fault) {
            anyhow::bail!("injected prevalence apply failure");
        }
        self.injected_prevalence_stall().await;
        let prevalence = self.prevalence.as_mut().context("prevalence is disabled")?;
        for (index, part) in refs.iter().enumerate() {
            let finished = finished_parts.iter()
                .find(|finished| finished.record.part_id == part.part_id)
                .context("published part has no local draft")?;
            prevalence.apply_part(&self.cfg.tenant_id, &entry, index as u32, part.part_id.as_str(),
                &finished.dir.join(crate::parts::format::PARTIAL_PREVALENCE_FILE), finished.record.max_time_us).await?;
        }
        self.prevalence_applied_seq = Some(seq);
        Ok(())
    }

    /// Download and verify a part into the local cache (no-op when local).
    async fn ensure_local(&self, part: &PartRef) -> Result<PathBuf> {
        download_part(self.parts, &self.cfg.tenant_id, &self.trusted, &self.cfg.work_dir, part).await
    }

    /// Run due merges; a failing merge plan is quarantined with backoff
    /// (keyed by level + hour) and never stops ingest.
    async fn run_merges(&mut self, now_ms: i64, lag_ms: i64) -> usize {
        // NAN-3772/NAN-3811: sample the backfill's headroom first, so it
        // also sees the ticks whose merges wait for prevalence below (tenant-a:
        // 2.5 h of those, while a rewrite kept pacing).
        if self.count_backfill.is_some() {
            let overdue = crate::parts::levels::l0_merge_overdue_ms(self.log.live().parts(), now_ms, &self.cfg.merge_policy);
            super::merge_quota::observe_backfill_headroom(lag_ms, self.health.prevalence_behind_ms, overdue);
        }
        // Merges yield to a prevalence catch-up, but only for a bounded time
        // (NAN-3849): once the worst L0 merge is PREVALENCE_L0_YIELD_MS
        // overdue they run beside it. Merging an unapplied L0 keeps its
        // partial readable for the replay (local part cache, a retained copy
        // on eviction, or the store within GC grace).
        if self.prevalence_pending {
            let caught_up = if self.prevalence_phase == PrevalencePhase::Stamping && self.prevalence_ready() {
                let deadline = std::time::Instant::now() + std::time::Duration::from_millis(self.cfg.prevalence_rebuild_budget_ms);
                match tokio::time::timeout(self.ingest_wait(), self.replay_prevalence(Some(deadline))).await {
                    Ok(Ok(true)) => {
                        self.prevalence_progressed();
                        self.prevalence_pending = false;
                        true
                    }
                    Ok(Ok(false)) => {
                        self.prevalence_progressed();
                        false
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(error = %format!("{error:#}"), "prevalence replay before merges failed");
                        false
                    }
                    Err(_) => {
                        self.prevalence_overran(now_ms, "replay before merges");
                        false
                    }
                }
            } else {
                false
            };
            if !caught_up {
                let overdue = crate::parts::levels::l0_merge_overdue_ms(self.log.live().parts(), now_ms, &self.cfg.merge_policy);
                let log_due = now_ms.saturating_sub(self.merge_schedule_log_ms) >= 60_000;
                if log_due {
                    self.merge_schedule_log_ms = now_ms;
                }
                if !l0_merges_run_beside_prevalence(overdue) {
                    if log_due {
                        tracing::info!(tenant = %self.cfg.tenant_id, reason = "prevalence_pending", l0_merge_overdue_ms = overdue,
                            yield_ms = PREVALENCE_L0_YIELD_MS, "compaction scheduling deferred");
                    }
                    // NAN-3801: the count probes consume no L0, so they
                    // do not wait for the prevalence catch-up.
                    let live = self.live_parts();
                    self.advance_count_backfill_probes(&live, now_ms, lag_ms).await;
                    return 0;
                }
                if log_due {
                    tracing::info!(tenant = %self.cfg.tenant_id, l0_merge_overdue_ms = overdue, yield_ms = PREVALENCE_L0_YIELD_MS,
                        status = %self.prevalence_status(), "compaction running beside the prevalence catch-up (L0 yield bound reached)");
                }
            }
        }
        let live = self.live_parts();
        // NAN-3187: quiet sealed hours plan straight into `h` only while an
        // `h` merge can start; the background lane defers them in catch-up.
        let history_open = !(self.cfg.background_merges && self.catching_up(lag_ms));
        let mut planned = plan_merges_with(&live, now_ms, &self.cfg.merge_policy, history_open);
        self.health.merge_backlog = planned.len();
        // NAN-3864: an owed hour already sealed into one `h` part gets one
        // more rewrite to restamp it (bounded: see `next_sealed_restamp`).
        if let Some(merge) = self.next_sealed_restamp(&planned, now_ms, lag_ms) {
            planned.push(merge);
        }
        if now_ms.saturating_sub(self.merge_schedule_log_ms) >= 60_000 {
            self.merge_schedule_log_ms = now_ms;
            let reason = if !self.merge_in_flight.is_empty() { "lanes_active" }
                else if planned.is_empty() { "no_candidates" }
                else if self.cfg.background_merges && self.catching_up(lag_ms) { "catch_up_minute_only" }
                else if self.cfg.background_merges && (self.buffer.rows > 0 || !self.buffer.handles.is_empty()) { "admission_buffer_not_empty" }
                else if planned.iter().all(|merge| self.merge_quarantine
                    .get(&(merge.output_level.code().to_owned(), merge.event_hour))
                    .is_some_and(|(_, until)| *until > now_ms)) { "quarantined" }
                else { "ready" };
            tracing::info!(tenant = %self.cfg.tenant_id, candidates = planned.len(), reason,
                l0_inputs = live.iter().filter(|p| p.level == Level::L0).count(),
                "compaction scheduling decision");
        }
        // NAN-3077: with nothing else due, bring one pre-current-index hour
        // up to the current token index (see `super::reindex`). Same rules as
        // any background hour merge below (never while catching up, only
        // with an empty buffer, one at a time).
        //
        // NAN-3772: a count backfill paces itself to the cell's headroom, so
        // it yields only to history merges (which take its lane first), not
        // to every minute merge: on tenant-a a minute merge is nearly always in
        // flight. The next part's probe and download overlap the running
        // rewrite. NAN-3795: a second rewrite runs beside it only while the
        // adaptive share says the cell has two cores to spare.
        let quiet = self.cfg.background_merges
            && !self.catching_up(lag_ms)
            && self.buffer.rows == 0
            && self.buffer.handles.is_empty();
        let rewrites_in_flight = self.merge_in_flight.iter().filter(|flight| self.is_reindex_rewrite(&flight.merge)).count();
        let rewrite_slots = if self.count_backfill.is_some() { super::merge_quota::backfill_rewrite_slots() } else { 1 };
        let legacy_due = planned.is_empty() && self.merge_in_flight.is_empty();
        let backfill_due = self.count_backfill.is_some() && !planned.iter().any(|merge| merge.output_level != Level::Minute);
        let mut coverage_plan = None;
        if quiet && (legacy_due || backfill_due) {
            if let Some(merge) = self.next_reindex(&live, now_ms, rewrites_in_flight < rewrite_slots).await {
                coverage_plan = Some(merge.inputs[0].clone());
                planned.push(merge);
            }
        } else if self.count_backfill.is_some() {
            // Not quiet (rows buffered, catching up) or a history merge is
            // due: no rewrite starts, but the background probes keep going
            // unless that history merge takes the tick (NAN-3801).
            if backfill_due {
                self.advance_count_backfill_probes(&live, now_ms, lag_ms).await;
            } else {
                let inventory = self.coverage_inventory(&live, now_ms);
                self.refresh_coverage_health(&inventory, now_ms);
            }
        }
        self.merge_quarantine.retain(|_, (_, until)| *until > now_ms - 86_400_000);
        if self.cfg.background_merges {
            let done = self.run_background_merge(planned, now_ms, lag_ms).await;
            // Not launched (lane, memory or admission buffer busy): keep the
            // local stale part for the next pass instead of probing it again.
            if let Some(part) = coverage_plan {
                if !self.merge_in_flight.iter().any(|flight| flight.merge.inputs.iter().any(|p| p.part_id == part.part_id))
                    && !self.coverage_backing_off(part.event_hour, now_ms) {
                    self.reindex_ready = Some(part);
                }
            }
            return done;
        }
        self.run_merges_inline(planned, now_ms).await
    }

    /// NAN-3801 (production, 2026-10-15): reap the finished coverage probe and start
    /// the next one on a tick that starts no rewrite. A probe runs in the
    /// background, consumes no L0 and holds no merge lane; a counts-only
    /// hour is published by the probe itself. It still never runs while
    /// catching up, and `next_reindex_step` still yields to searches and to
    /// prevalence / L0 debt past their alert thresholds (NAN-3811).
    ///
    /// Before this, the probes ran only on a tick that passed BOTH the
    /// prevalence-pending gate and the empty-admission-buffer gate. On a production tenant
    /// every flush's prevalence apply overran the ingest wait from 10:00Z,
    /// so the only ticks with an empty buffer (flush ticks) always deferred,
    /// and the ticks after a catch-up always had rows buffered: no tick
    /// passed both, and the backfill stopped for 30+ min with a finished
    /// probe never reaped (`coverage_parts_current` stuck at 130).
    async fn advance_count_backfill_probes(&mut self, live: &[PartRef], now_ms: i64, lag_ms: i64) {
        if self.count_backfill.is_none() {
            return;
        }
        if self.cfg.background_merges && !self.catching_up(lag_ms) {
            // `may_launch` false: never returns a rewrite; a stale part
            // waits in `reindex_ready` for a quiet tick.
            let plan = self.next_reindex(live, now_ms, false).await;
            debug_assert!(plan.is_none(), "a probe-only step never plans a rewrite");
        } else {
            let inventory = self.coverage_inventory(live, now_ms);
            self.refresh_coverage_health(&inventory, now_ms);
        }
    }

    /// A single-input rewrite of a part whose coverage is known stale: an
    /// old-hour reindex or a count backfill rewrite.
    fn is_reindex_rewrite(&self, merge: &crate::parts::levels::PlannedMerge) -> bool {
        merge.inputs.len() == 1 && self.index_current.get(&merge.inputs[0].part_id) == Some(&false)
    }

    /// A rewrite paced by the count backfill (it holds the backfill lane, not
    /// a history admission slot; NAN-3795). Legacy reindex rewrites without a
    /// window still hold a history slot and count against the history lanes.
    fn is_count_rewrite(&self, merge: &crate::parts::levels::PlannedMerge) -> bool {
        self.is_reindex_rewrite(merge)
            && self.count_backfill.as_ref().is_some_and(|window| window.contains(&merge.inputs[0]))
    }

    fn coverage_backing_off(&self, hour: i32, now_ms: i64) -> bool {
        self.coverage_retry.get(&hour).is_some_and(|(_, until)| *until > now_ms)
    }

    /// NAN-3772: a failed coverage probe or rewrite is retried with backoff
    /// (the rest of the window proceeds meanwhile) and given up only after
    /// [`super::reindex::MAX_COVERAGE_ATTEMPTS`] consecutive failures.
    fn coverage_failed(&mut self, hour: i32, now_ms: i64, error: &anyhow::Error) {
        let failures = self.coverage_retry.get(&hour).map_or(0, |(n, _)| *n) + 1;
        let backoff_ms = super::reindex::coverage_retry_backoff_ms(failures);
        self.health.coverage_failures_total += 1;
        if self.reindex_ready.as_ref().is_some_and(|part| part.event_hour == hour) {
            self.reindex_ready = None;
        }
        if failures >= super::reindex::MAX_COVERAGE_ATTEMPTS {
            self.coverage_retry.remove(&hour);
            self.reindexed_hours.insert(hour);
            self.coverage_given_up.insert(hour, format!("failed {failures} times: {error:#}"));
            tracing::warn!(hour, failures, error = %format!("{error:#}"), "coverage rewrite failed repeatedly; hour skipped until restart or a new window");
        } else {
            self.coverage_retry.insert(hour, (failures, now_ms + backoff_ms));
            tracing::warn!(hour, failures, backoff_ms, error = %format!("{error:#}"), "coverage rewrite failed; retrying with backoff");
        }
    }

    /// Run due merges inside the tick (up to `max_merges_per_tick`, within
    /// [`MERGE_TICK_BUDGET`]).
    async fn run_merges_inline(&mut self, planned: Vec<crate::parts::levels::PlannedMerge>, now_ms: i64) -> usize {
        let mut done = 0;
        // Failed merges count too: a failing sign (expired owner bearer)
        // once made one tick attempt EVERY planned merge, each minutes of
        // CPU, while the tick held the ingestor for ~20 min (the 2026-09-29
        // a lean test tenant wedge). Past the time budget, the rest wait a tick.
        let mut attempts = 0;
        let started = std::time::Instant::now();
        for merge in planned {
            if attempts >= self.cfg.max_merges_per_tick || (attempts > 0 && started.elapsed() >= MERGE_TICK_BUDGET) {
                break;
            }
            let key = (merge.output_level.code().to_string(), merge.event_hour);
            if self.merge_quarantine.get(&key).is_some_and(|(_, until)| *until > now_ms) {
                continue;
            }
            attempts += 1;
            match self.run_merge(merge, now_ms).await {
                Ok(()) => {
                    self.merge_quarantine.remove(&key);
                    done += 1;
                }
                Err(error) => {
                    let failures = self.merge_quarantine.get(&key).map_or(0, |(n, _)| *n) + 1;
                    let backoff_ms = (60_000_i64 << (failures - 1).min(6)).min(3_600_000);
                    self.merge_quarantine.insert(key, (failures, now_ms + backoff_ms));
                    self.health.merge_failures_total += 1;
                    tracing::error!(error = %format!("{error:#}"), failures, backoff_ms, "merge failed; quarantined");
                }
            }
        }
        done
    }

    /// Reap without waiting, commit serially on the ingest tick, and fill the
    /// independent minute/history lanes. Catch-up still defers history work.
    async fn run_background_merge(&mut self, mut planned: Vec<crate::parts::levels::PlannedMerge>, now_ms: i64,
        lag_ms: i64) -> usize {
        let mut done = 0;
        let mut index = 0;
        while index < self.merge_in_flight.len() {
            if !self.merge_in_flight[index].handle.is_finished() {
                let flight = &mut self.merge_in_flight[index];
                if now_ms.saturating_sub(flight.last_warn_ms) >= 60_000 {
                    flight.last_warn_ms = now_ms;
                    tracing::info!(level = flight.merge.output_level.code(), hour = flight.merge.event_hour,
                        age_ms = now_ms.saturating_sub(flight.started_ms), "compaction lane busy");
                }
                index += 1;
                continue;
            }
            let flight = self.merge_in_flight.remove(index);
            let key = flight.key.clone();
            let rewrite = self.is_reindex_rewrite(&flight.merge).then_some(flight.merge.event_hour);
            let restamp = flight.restamp;
            let outcome = match flight.handle.await {
                Ok(Ok((result, published))) => self.commit_merge(flight.merge, result, published, now_ms).await,
                Ok(Err(error)) => Err(error),
                Err(join) => Err(anyhow::anyhow!("merge task panicked or was cancelled: {join}")),
            };
            match outcome {
                Ok(committed) => {
                    self.merge_quarantine.remove(&key);
                    if let Some(hour) = rewrite { self.coverage_retry.remove(&hour); }
                    if let Some(restamp) = &restamp { self.restamp_merged(restamp, committed, now_ms); }
                    done += usize::from(committed);
                }
                // NAN-3864: a sealed-hour restamp with nothing to do (or no
                // lookups yet) skips its rewrite; it is not a merge failure.
                Err(error) if restamp.as_ref().is_some_and(|restamp| self.restamp_skipped(restamp, &error, now_ms)) => {}
                Err(error) => {
                    if let Some(hour) = rewrite { self.coverage_failed(hour, now_ms, &error); }
                    if let Some(restamp) = &restamp { self.restamp_failed(restamp, now_ms, &format!("{error:#}")); }
                    self.quarantine_merge(key, now_ms, &error);
                }
            }
            super::memory::release_freed();
        }
        // Plans were computed before reaping. A committed job may have
        // superseded a candidate's inputs; never launch that stale plan.
        planned.retain(|merge| merge.inputs.iter().all(|p| self.log.live().get(&p.part_id).is_some()));
        // Fresh hours first in the minute lane; history takes the most
        // fragmented hour first, newest on ties (NAN-3400).
        super::merge_lanes::launch_order(&mut planned);
        for merge in planned {
            let minute = merge.output_level == Level::Minute;
            if !minute && (self.catching_up(lag_ms) || self.buffer.rows > 0 || !self.buffer.handles.is_empty()) {
                continue;
            }
            // NAN-3795: count rewrites are bounded by their own lane, not the
            // history lanes: a sealed-hour merge never waits behind them. It
            // still needs the memory headroom they use.
            let candidate_rewrite = self.is_count_rewrite(&merge);
            let active = self.merge_in_flight.iter().map(|f| &f.merge)
                .filter(|m| candidate_rewrite || !self.is_count_rewrite(m)).collect::<Vec<_>>();
            if !super::merge_lanes::available(&merge, &active) { continue; }
            if !candidate_rewrite && !minute && active.iter().all(|m| m.output_level == Level::Minute)
                && self.merge_in_flight.iter().any(|f| self.is_count_rewrite(&f.merge))
                && !super::merge_lanes::history_memory_admits(super::merge_lanes::MemorySnapshot::read()) {
                continue;
            }
            // A merge is charged against the working budget too: beside a
            // full catch-up cycle only the first lane runs (NAN-3183 OOM).
            if !self.merge_in_flight.is_empty() && self.committed_bytes().saturating_add(super::merge::merge_reserve_bytes())
                > self.cfg.buffer_budget_bytes {
                continue;
            }
            let key = (merge.output_level.code().to_string(), merge.event_hour);
            if self.merge_quarantine.get(&key).is_some_and(|(_, until)| *until > now_ms) { continue; }
            let rewrite = self.is_reindex_rewrite(&merge).then_some(merge.event_hour);
            match self.spawn_merge(merge, now_ms).await {
                Ok(handle) => self.merge_in_flight.push(handle),
                Err(error) => {
                    if let Some(hour) = rewrite { self.coverage_failed(hour, now_ms, &error); }
                    self.quarantine_merge(key, now_ms, &error);
                }
            }
        }
        done
    }

    /// Let the old-hour reindex fetch parts in the background with `store`
    /// (NAN-3077; the cell passes its `'static` part store).
    pub fn set_background_store(&mut self, store: &'static dyn ObjectStore) {
        self.background_parts = Some(store);
    }

    /// Wake the ingest loop when a pipelined flush finishes publishing, so
    /// it commits without waiting out the loop's idle sleep (NAN-3619).
    pub fn set_flight_wake(&mut self, wake: std::sync::Arc<tokio::sync::Notify>) {
        self.flight_wake = Some(wake);
    }

    /// Keep fetch, pacing and publication off the production admission tick.
    pub fn set_background_signer(&mut self, signer: &'static dyn PartSigner) {
        self.background_signer = Some(signer);
    }

    /// The next old-hour reindex merge, if one is due (NAN-3077). Nothing
    /// here waits on the network: the probe and the part download run in a
    /// background task, and a merge is planned only for a part that is
    /// already local, so `spawn_merge`'s `ensure_local` is a no-op.
    /// `may_launch` false (a rewrite is running): only refresh the status and
    /// keep the next part's probe/download going in the background.
    async fn next_reindex(&mut self, live: &[PartRef], now_ms: i64, may_launch: bool) -> Option<crate::parts::levels::PlannedMerge> {
        let plan = self.next_reindex_step(live, now_ms, may_launch).await;
        // Status reflects this step's outcome (a failure just recorded, a
        // part just found current), not the previous tick's.
        if self.count_backfill.is_some() || super::reindex::keyword_enabled() || super::reindex::sidecar_enabled() {
            let inventory = self.coverage_inventory(live, now_ms);
            self.refresh_coverage_health(&inventory, now_ms);
        }
        plan
    }

    /// Settled single-hour parts the coverage work covers: every candidate
    /// for the legacy old-hour reindex, else those in the count window.
    fn coverage_inventory(&self, live: &[PartRef], now_ms: i64) -> Vec<PartRef> {
        let legacy = super::reindex::keyword_enabled() || super::reindex::sidecar_enabled();
        super::reindex::candidates(live, now_ms, &self.cfg.merge_policy, &Default::default())
            .into_iter().filter(|part| legacy || self.count_backfill.as_ref().is_some_and(|window| window.contains(part))).collect()
    }

    async fn next_reindex_step(&mut self, live: &[PartRef], now_ms: i64, may_launch: bool) -> Option<crate::parts::levels::PlannedMerge> {
        let legacy_coverage = super::reindex::keyword_enabled() || super::reindex::sidecar_enabled();
        let counts = self.count_backfill.is_some() && count_writer_enabled();
        self.health.count_backfill_paused = self.count_backfill.is_some() && !counts;
        if !legacy_coverage && !counts { return None; }
        let store = self.background_parts?;
        self.coverage_started_ms.get_or_insert(now_ms);
        // NAN-3795: while the tenant searches, start no probe, download or
        // rewrite (a running rewrite paces at the floor in merge_quota).
        // NAN-3811: likewise while prevalence or L0 merges are behind.
        if super::merge_quota::backfill_yielding() {
            return None;
        }
        let in_window = |backfill: &Option<super::reindex::CountBackfill>, part: &PartRef|
            legacy_coverage || (counts && backfill.as_ref().is_some_and(|window| window.contains(part)));
        self.coverage_retry.retain(|_, (failures, until)| *failures > 0 && *until > now_ms - 86_400_000);
        let live_and_due = |this: &Self, part: &PartRef| live.iter().any(|live| live.part_id == part.part_id)
            && in_window(&this.count_backfill, part) && !this.reindexed_hours.contains(&part.event_hour)
            && !this.coverage_backing_off(part.event_hour, now_ms);
        if let Some(part) = self.reindex_ready.take() {
            if live_and_due(self, &part) && self.index_current.get(&part.part_id) == Some(&false) {
                if !may_launch {
                    self.reindex_ready = Some(part);
                    return None;
                }
                tracing::info!(hour = part.event_hour, part = %part.part_id.as_str(), "rewriting an old hour for current index and sidecar coverage");
                return Some(crate::parts::levels::PlannedMerge { output_level: Level::Hour, event_hour: part.event_hour, inputs: vec![part] });
            }
        }
        if let Some((part, handle)) = self.reindex_fetch.take() {
            // A finished stale probe waits (local) until no rewrite runs.
            if !handle.is_finished() || (!may_launch && self.reindex_ready.is_some()) {
                self.reindex_fetch = Some((part, handle));
                return None;
            }
            match handle.await {
                Ok(Ok(Some((_, why)))) if live_and_due(self, &part) => {
                    self.index_current.insert(part.part_id.clone(), false);
                    if counts && self.count_backfill.as_ref().is_some_and(|window| window.contains(&part)) && self.count_backfill_attempts.contains(&part.event_hour) {
                        // This process already rewrote the hour with the
                        // current writer: rewriting again yields the same
                        // part, so it is terminal, with the probe's reason.
                        self.reindexed_hours.insert(part.event_hour);
                        self.health.coverage_failures_total += 1;
                        let reason = format!("still uncovered after its count rewrite: {why}");
                        tracing::warn!(hour = part.event_hour, part = %part.part_id.as_str(), reason = %reason,
                            "count rewrite remains uncovered; hour skipped until restart or a new window");
                        self.coverage_given_up.insert(part.event_hour, reason);
                        return None;
                    }
                    tracing::info!(hour = part.event_hour, part = %part.part_id.as_str(), why = %why, "old hour is not current");
                    if !may_launch {
                        self.reindex_ready = Some(part);
                        return None;
                    }
                    self.reindex_not_before_ms = now_ms + super::reindex::REINDEX_SPACING_MS;
                    tracing::info!(hour = part.event_hour, part = %part.part_id.as_str(), "rewriting an old hour for current index and sidecar coverage");
                    return Some(crate::parts::levels::PlannedMerge { output_level: Level::Hour, event_hour: part.event_hour, inputs: vec![part] });
                }
                Ok(Ok(Some(_))) => {}
                Ok(Ok(None)) => {
                    self.index_current.insert(part.part_id.clone(), true);
                    self.coverage_retry.remove(&part.event_hour);
                }
                Ok(Err(error)) => {
                    tracing::warn!(hour = part.event_hour, part = %part.part_id.as_str(), error = %format!("{error:#}"),
                        "old-hour reindex fetch failed");
                    self.coverage_failed(part.event_hour, now_ms, &error);
                }
                Err(join) => {
                    let error = anyhow::anyhow!("old-hour reindex fetch task failed: {join}");
                    self.coverage_failed(part.event_hour, now_ms, &error);
                }
            }
        }
        // Prefetch beside a running rewrite needs no spacing: it only reads.
        if may_launch && now_ms < self.reindex_not_before_ms {
            return None;
        }
        let live_ids = live.iter().map(|part| part.part_id.clone()).collect::<std::collections::HashSet<_>>();
        self.index_current.retain(|part, _| live_ids.contains(part));
        let mut skip = self.reindexed_hours.clone();
        skip.extend(self.coverage_retry.iter().filter(|(_, (_, until))| *until > now_ms).map(|(hour, _)| *hour));
        let busy = self.merge_in_flight.iter().flat_map(|flight| flight.merge.inputs.iter().map(|p| p.part_id.clone()))
            .chain(self.reindex_ready.iter().map(|p| p.part_id.clone())).collect::<std::collections::HashSet<_>>();
        let next = super::reindex::candidates(live, now_ms, &self.cfg.merge_policy, &skip)
            .into_iter()
            .find(|part| self.index_current.get(&part.part_id) != Some(&true) && !busy.contains(&part.part_id)
                && in_window(&self.count_backfill, part))?;
        tracing::info!(hour = next.event_hour, part = %next.part_id.as_str(), "old-hour reindex: probing signed coverage in the background");
        let task = probe_and_fetch_for_coverage(store, self.cfg.tenant_id.clone(), self.trusted.clone(), self.cfg.work_dir.clone(), next.clone(), counts && self.count_backfill.as_ref().is_some_and(|window| window.contains(&next)), self.background_signer, now_ms);
        self.reindex_fetch = Some((next, tokio::spawn(task)));
        None
    }

    /// NAN-3772 status: parts, rows and an ETA from what was actually done.
    fn refresh_coverage_health(&mut self, inventory: &[PartRef], now_ms: i64) {
        let running = self.merge_in_flight.iter().find(|flight| self.is_reindex_rewrite(&flight.merge)
            && self.count_backfill.as_ref().is_some_and(|window| window.contains(&flight.merge.inputs[0])));
        let progress = running.and(super::merge_quota::backfill_progress());
        self.health.coverage_rewrite_in_flight = running.map(|flight| {
            let (rows_done, rows_total) = progress.unwrap_or((0, flight.merge.inputs[0].rows));
            CoverageRewrite { event_hour: flight.merge.event_hour, age_ms: now_ms.saturating_sub(flight.started_ms), rows_done, rows_total }
        });
        let h = &mut self.health;
        h.coverage_parts_total = inventory.len();
        h.coverage_parts_failed = inventory.iter().filter(|part| self.reindexed_hours.contains(&part.event_hour)).count();
        h.coverage_failed_hours = inventory.iter().filter(|part| self.reindexed_hours.contains(&part.event_hour))
            .map(|part| CoverageFailure { event_hour: part.event_hour,
                reason: self.coverage_given_up.get(&part.event_hour).cloned().unwrap_or_else(|| "given up".into()) })
            .take(32).collect();
        h.coverage_parts_retrying = inventory.iter().filter(|part| self.coverage_retry.get(&part.event_hour)
            .is_some_and(|(_, until)| *until > now_ms)).count();
        h.coverage_parts_current = inventory.iter().filter(|p| self.index_current.get(&p.part_id) == Some(&true)).count();
        h.coverage_parts_unknown = inventory.iter().filter(|p| !self.index_current.contains_key(&p.part_id)).count();
        h.coverage_share_permille = super::merge_quota::backfill_share_permille();
        h.coverage_yielding_to_search = super::merge_quota::search_active();
        h.coverage_yielding_to_ingest = self.count_backfill.is_some() && super::merge_quota::ingest_behind();
        let seconds = (now_ms - self.coverage_started_ms.unwrap_or(now_ms)).max(1) as f64 / 1000.0;
        h.coverage_bytes_per_second = h.coverage_rewritten_bytes_total as f64 / seconds;
        let in_flight_rows = h.coverage_rewrite_in_flight.as_ref().map_or(0, |r| r.rows_done);
        let (counted_parts, counted_rows, counted_bytes) = super::count_record::counted_totals();
        h.coverage_counts_only_parts = counted_parts;
        h.coverage_counts_only_rows = counted_rows;
        h.coverage_counts_only_fetched_bytes = counted_bytes;
        h.coverage_counts_only_unsupported = super::count_record::count_signing_unsupported();
        let done_rows = self.coverage_backfill_rows_done + in_flight_rows + counted_rows.saturating_sub(self.counted_rows_base);
        h.coverage_rows_rewritten_total = self.coverage_backfill_rows_done;
        h.coverage_rows_per_second = done_rows as f64 / seconds;
        // Unknown parts count as remaining: an upper bound until probed.
        let remaining = inventory.iter()
            .filter(|p| self.index_current.get(&p.part_id) != Some(&true) && !self.reindexed_hours.contains(&p.event_hour))
            .map(|p| p.rows).sum::<u64>().saturating_sub(in_flight_rows);
        h.coverage_eta_seconds = (h.coverage_rows_per_second > 0.0).then(|| remaining as f64 / h.coverage_rows_per_second);
    }

    /// Queue without restarting either tenant role or touching query caches.
    pub async fn start_count_backfill(&mut self, window: super::reindex::CountBackfill, now_ms: i64) -> Result<()> {
        self.queue_count_backfill(window, now_ms, count_writer_enabled()).await
    }

    async fn queue_count_backfill(&mut self, window: super::reindex::CountBackfill, now_ms: i64, writer_enabled: bool) -> Result<()> {
        window.validate(now_ms)?;
        ensure!(writer_enabled, "entity count writer must be enabled");
        ensure!(!self.merge_in_flight.iter().any(|flight| self.count_backfill.as_ref()
            .is_some_and(|active| flight.merge.inputs.iter().any(|part| active.contains(part)))),
            "count backfill window has an in-flight rewrite");
        // The cell's work dir is a per-pod volume that a ZDR handover starts
        // EMPTY: the admission is durable only once it is in the tenant's
        // bucket, so that write comes first and a failure refuses the request.
        persist_count_backfill(self.parts, &self.cfg.tenant_id, &window, now_ms).await
            .context("count backfill admission could not be made durable")?;
        tracing::info!(tenant = %self.cfg.tenant_id, start_ms = window.start_ms, end_ms = window.end_ms, "operator queued count coverage backfill");
        if let Some((_, task)) = self.reindex_fetch.take() { task.abort(); }
        self.health.count_backfill_window = Some(window.clone());
        self.count_backfill = Some(window);
        self.count_backfill_attempts.clear();
        self.index_current.clear();
        self.reindexed_hours.clear();
        self.coverage_given_up.clear();
        self.coverage_retry.clear();
        self.reindex_ready = None;
        self.coverage_started_ms = Some(now_ms);
        self.coverage_backfill_rows_done = 0;
        self.counted_rows_base = super::count_record::counted_totals().1;
        Ok(())
    }

    /// Lag past the hour seal: the backlog is feeding sealed hours.
    fn catching_up(&self, lag_ms: i64) -> bool {
        lag_ms > self.cfg.merge_policy.hour_seal_ms
    }

    fn quarantine_merge(&mut self, key: (String, i32), now_ms: i64, error: &anyhow::Error) {
        let failures = self.merge_quarantine.get(&key).map_or(0, |(n, _)| *n) + 1;
        let backoff_ms = (60_000_i64 << (failures - 1).min(6)).min(3_600_000);
        self.merge_quarantine.insert(key, (failures, now_ms + backoff_ms));
        self.health.merge_failures_total += 1;
        tracing::error!(error = %format!("{error:#}"), failures, backoff_ms, "merge failed; quarantined");
    }

    /// Fetch the inputs and start the merge on the blocking pool.
    async fn spawn_merge(&mut self, merge: crate::parts::levels::PlannedMerge, now_ms: i64) -> Result<InFlightMerge> {
        let fingerprint = self.log.live().schema().context("log schema")?.fingerprint.clone();
        let (dir, tenant, schema, key_id, build) = (
            parts_dir(&self.cfg.work_dir), self.cfg.tenant_id.clone(), self.schema.clone(),
            self.signer.key_id().to_string(), self.cfg.build.clone(),
        );
        let (level, hour) = (merge.output_level, merge.event_hour);
        tracing::info!(tenant = %tenant, level = level.code(), hour, inputs = merge.inputs.len(),
            rows = merge.inputs.iter().map(|p| p.rows).sum::<u64>(), "compaction merge starting");
        let coverage_rewrite = self.is_count_rewrite(&merge);
        // NAN-3864: a merge of an owed hour restamps it once the state is at
        // the head (the lookups run in the task, never on the tick).
        let (restamp, restamp_task) = match self.restamp_for(&merge, now_ms) {
            Some((info, lookup)) => {
                let task = RestampTask {
                    lookup, hour, sealed: info.sealed, outcome: info.outcome.clone(),
                    supported: super::restamp::schema_supports(&schema),
                };
                (Some(info), Some(task))
            }
            None => (None, None),
        };
        let handle = if let (Some(store), Some(signer)) = (self.background_parts, self.background_signer) {
            let parts = merge.inputs.clone();
            let trusted = self.trusted.clone();
            let work_dir = self.cfg.work_dir.clone();
            tokio::spawn(async move {
                // Hold a process-wide backfill slot through fetch, compute and
                // publication. Waiting happens in this task, outside the tick.
                let _backfill = if coverage_rewrite {
                    Some(super::merge_quota::reserve_count_backfill().await?)
                } else { None };
                let mut inputs = Vec::new();
                for part in parts {
                    let local = download_part_with_quota(store, &tenant, &trusted, &work_dir, &part, true).await?;
                    inputs.push(MergeInput { part, dir: local });
                }
                let (map, outcome) = match restamp_task {
                    Some(task) => (task.prepare(&inputs).await?, Some(task.outcome)),
                    None => (None, None),
                };
                let (result, _backfill) = super::merge_lanes::compute(move || {
                    // Compute cannot be cancelled once its OS thread starts.
                    // Move the slot with it so aborting the async task cannot
                    // admit a second rewrite while the first still computes.
                    let result = super::restamp::with_restamp(map.clone(), || super::merge_quota::with_count_backfill(coverage_rewrite, ||
                        merge_parts(&dir, &tenant, level, hour, &inputs, schema, &fingerprint, &key_id, &build, now_ms)));
                    restamp_applied(map.as_deref(), outcome.as_deref(), result.is_ok());
                    result.map(|result| (result, _backfill))
                }).await??;
                let published = if coverage_rewrite {
                    super::writer::publish_backfilled_parts(store, signer, &trusted, std::slice::from_ref(&result.finished)).await?
                } else {
                    super::writer::publish_compacted_parts(store, signer, &trusted, std::slice::from_ref(&result.finished)).await?
                }.remove(0);
                Ok((result, Some(published)))
            })
        } else {
            // Lab/inline callers have borrowed handles; production always supplies
            // the static store and signer above, so its tick never waits on I/O.
            let mut inputs = Vec::new();
            for part in &merge.inputs {
                inputs.push(MergeInput { part: part.clone(), dir: download_part_with_quota(self.parts, &self.cfg.tenant_id, &self.trusted, &self.cfg.work_dir, part, true).await? });
            }
            tokio::spawn(async move {
                let _backfill = if coverage_rewrite {
                    Some(super::merge_quota::reserve_count_backfill().await?)
                } else { None };
                let (map, outcome) = match restamp_task {
                    Some(task) => (task.prepare(&inputs).await?, Some(task.outcome)),
                    None => (None, None),
                };
                super::merge_lanes::compute(move || {
                    let _backfill = _backfill;
                    let result = super::restamp::with_restamp(map.clone(), || super::merge_quota::with_count_backfill(coverage_rewrite, ||
                        merge_parts(&dir, &tenant, level, hour, &inputs, schema, &fingerprint, &key_id, &build, now_ms)));
                    restamp_applied(map.as_deref(), outcome.as_deref(), result.is_ok());
                    result.map(|result| (result, None))
                }).await?
            })
        };
        let key = (level.code().to_string(), hour);
        Ok(InFlightMerge { merge, key, started_ms: now_ms, last_warn_ms: now_ms, handle, restamp })
    }

    async fn run_merge(&mut self, merge: crate::parts::levels::PlannedMerge, now_ms: i64) -> Result<()> {
        let flight = self.spawn_merge(merge, now_ms).await?;
        let restamp = flight.restamp;
        let joined = flight.handle.await.context("merge task panicked or was cancelled")?;
        let (result, published) = match joined {
            Ok(done) => done,
            Err(error) => {
                if let Some(restamp) = &restamp {
                    if self.restamp_skipped(restamp, &error, now_ms) {
                        return Ok(());
                    }
                    self.restamp_failed(restamp, now_ms, &format!("{error:#}"));
                }
                return Err(error);
            }
        };
        let committed = self.commit_merge(flight.merge, result, published, now_ms).await?;
        if let Some(restamp) = &restamp {
            self.restamp_merged(restamp, committed, now_ms);
        }
        Ok(())
    }

    /// Publish a finished merge and append its `merge` entry. `Ok(false)`:
    /// an input stopped being live while it ran (overlapping ranges are
    /// excluded and flushes only add parts); the output is
    /// left unreferenced for orphan GC if background publication completed.
    async fn commit_merge(&mut self, merge: crate::parts::levels::PlannedMerge, result: super::merge::MergeResult,
        published: Option<PartRef>, now_ms: i64) -> Result<bool> {
        if !merge.inputs.iter().all(|p| self.log.live().get(&p.part_id).is_some()) {
            tracing::warn!(hour = merge.event_hour, level = merge.output_level.code(), "merge inputs changed while it ran; dropping its output");
            let _ = std::fs::remove_dir_all(&result.finished.dir);
            return Ok(false);
        }
        let output = match published {
            Some(part) => part,
            None => super::writer::publish_compacted_parts(self.parts, self.signer, &self.trusted, std::slice::from_ref(&result.finished))
                .await?.remove(0),
        };
        let supersedes = merge.inputs.iter().map(|p| p.part_id.clone()).collect::<Vec<_>>();
        self.log.append(LogOp::Merge { output: output.clone(), supersedes }, now_ms).await?;
        // Keep window completeness: the output holds exactly the uids of
        // inputs already loaded for each of its hours.
        // NAN-3703: likewise for the late-hour tier; inputs split between
        // the window and the tier mark the output in the window (the two
        // together hold its uids, and admission consults both).
        for hour in hours_of(&output) {
            let inputs = merge.inputs.iter().filter(|p| hours_of(p).contains(&hour))
                .map(|p| p.part_id.as_str()).collect::<Vec<_>>();
            let tiered = self.late.inherit(hour, &inputs, output.part_id.as_str());
            if inputs.iter().all(|p| self.window.has_loaded(hour, p) || (!tiered && self.late.covers(hour, p))) {
                self.window.load_marker(hour, output.part_id.as_str(), now_ms);
            }
        }
        if merge.inputs.len() == 1 && self.index_current.get(&merge.inputs[0].part_id) == Some(&false) {
            if self.count_backfill.is_some() { self.count_backfill_attempts.insert(merge.event_hour); }
            self.health.coverage_rewrites_total += 1;
            self.health.coverage_rewritten_bytes_total += merge.inputs[0].data_bytes;
            if self.count_backfill.as_ref().is_some_and(|window| window.contains(&merge.inputs[0])) {
                self.coverage_backfill_rows_done += merge.inputs[0].rows;
            }
            // The next pass probes the signed output, so restart and changed
            // writer configuration never trust an in-memory completion marker.
        }
        self.health.merges_total += 1;
        tracing::info!(tenant = %self.cfg.tenant_id, level = output.level.code(), hour = output.event_hour,
            inputs = merge.inputs.len(), rows = output.rows, "compaction merge committed");
        self.health.duplicates_dropped_total += result.duplicates_dropped;
        Ok(true)
    }

    async fn retire_local_expired(&mut self, authority: &crate::lake_part_gc::local::LocalDeleteAuthority, now_ms: i64) -> Result<()> {
        let Some(days) = authority.refresh_policy().await?.retention_days else { return Ok(()); };
        let cutoff_us = now_ms.saturating_sub((days as i64).saturating_mul(86_400_000)).saturating_mul(1_000);
        let expired: Vec<_> = self.log.live().parts()
            .filter(|part| part.max_time_us < cutoff_us)
            .take(512).map(|part| part.part_id.clone()).collect();
        if !expired.is_empty() {
            self.log.append(LogOp::Retire { parts: expired,
                reason: crate::parts::part_log::RetireReason::Retention,
                deletion_unit: uuid::Uuid::new_v4().to_string(),
            }, now_ms).await?;
        }
        Ok(())
    }

    /// Poll and schedule only sanctioned GC. Safe after a retryable ingest
    /// error: no merges, cache eviction, export, buffer mutation or queue ACK.
    pub async fn tick_gc(&mut self, now_ms: i64) {
        if let Err(error) = self.gc(now_ms).await {
            tracing::warn!(error = %format!("{error:#}"), "part GC failed; retrying next tick");
        }
    }

    fn evict_superseded_cache(&mut self, now_ms: i64) {
        let cutoff = now_ms - self.cfg.merge_policy.supersede_grace_ms;
        let live = self.log.live();
        let uncached = live.removed_before(cutoff)
            .filter(|id| !self.gc_done.contains(*id)).cloned().collect::<Vec<_>>();
        self.gc_done.retain(|id| live.is_removed(id));
        let behind = self.prevalence_behind();
        for id in uncached {
            if let Some(dir) = self.find_local(&id) {
                if behind {
                    self.retain_prevalence_inputs(&dir, id.as_str());
                }
                let _ = std::fs::remove_dir_all(dir);
            }
            self.gc_done.insert(id);
        }
    }

    /// Supersession GC (contract 6.4), fail closed.
    ///
    /// Ingest never deletes a remote part file with its own credential.
    /// Remote data, sidecars and orphans are deleted solely by the sanctioned
    /// GC pass, only while the delete gate allows it (the tenant's
    /// lake_part delete grant is enabled and a sanctioned path is wired).
    /// Otherwise every part is kept and `part_gc_blocked` reports the
    /// superseded parts and bytes past the grace window.
    /// The count covers parts the log still remembers as removed (its id
    /// memory); older ones are kept too and fall to the sanctioned pass's
    /// orphan planning once deletion is enabled. Local cache eviction belongs
    /// to successful ingest maintenance, never to the retry path.
    async fn gc(&mut self, now_ms: i64) -> Result<()> {
        let cutoff = now_ms - self.cfg.merge_policy.supersede_grace_ms;
        let (pending_parts, pending_bytes) = {
            let live = self.log.live();
            let (mut parts, mut bytes) = (0_u64, 0_u64);
            for id in live.removed_before(cutoff) {
                parts += 1;
                bytes += live.removed_ref(id).map_or(0, |part| part.data_bytes);
            }
            (parts, bytes)
        };
        if let Some(authority) = self.gc_authority.clone() {
            if let Some(result) = authority.poll_report(now_ms).await {
                self.record_sanctioned_gc_report(result, pending_parts, pending_bytes, now_ms);
            }
            // NAN-3852: a sanctioned task runs for up to an hour and reports
            // its deletes only when it ends; the metric follows them live.
            if let Some(live) = authority.deleted_total() {
                self.health.part_gc_deleted_total = self.health.part_gc_deleted_total.max(live);
            }
        }
        let pass = match &self.gc_authority {
            None => Err(REASON_AUTHORITY_MISSING),
            Some(authority) => match authority.decision(now_ms).await {
                Ok(PartGcDecision::Sanctioned(pass)) => Ok(pass),
                Ok(PartGcDecision::Blocked(reason)) => Err(reason),
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"), "lake-part delete authority unreadable; keeping every part");
                    Err(REASON_AUTHORITY_UNREADABLE)
                }
            },
        };
        let pass = match pass {
            Ok(pass) => pass,
            Err(reason) => {
                self.gc_blocked(reason, pending_parts, pending_bytes, now_ms);
                return Ok(());
            }
        };
        if !sanctioned_pass_due(self.last_sanctioned_pass_ms, self.sanctioned_gc_catching_up, now_ms) {
            return Ok(());
        }
        self.last_sanctioned_pass_ms = Some(now_ms);
        if let Some(result) = pass.schedule_pass(now_ms).await {
            self.record_sanctioned_gc_report(result, pending_parts, pending_bytes, now_ms);
        }
        Ok(())
    }

    fn record_sanctioned_gc_report(&mut self, result: Result<crate::lake_part_gc::PassReport>,
        pending_parts: u64, pending_bytes: u64, now_ms: i64) {
        self.sanctioned_gc_catching_up = result.as_ref().is_ok_and(pass_is_catching_up);
        match result {
            Ok(report) => {
                self.gc_deleted_reported = self.gc_deleted_reported.saturating_add(report.deleted);
                self.health.part_gc_deleted_total = self.health.part_gc_deleted_total.max(self.gc_deleted_reported);
                self.health.part_gc_last_pause = report.paused_reason.clone();
                match report.paused_reason {
                    Some(paused) if self.sanctioned_gc_catching_up => {
                        // Routine after every restart: one step per few seconds.
                        tracing::info!(%paused, "sanctioned lake-part GC still folding its log view; continuing shortly");
                        self.gc_blocked(REASON_SANCTIONED_PASS_PAUSED, pending_parts, pending_bytes, now_ms);
                    }
                    Some(paused) => {
                        tracing::warn!(%paused, deleted = report.deleted, "sanctioned lake-part GC pass paused");
                        self.gc_blocked(REASON_SANCTIONED_PASS_PAUSED, pending_parts, pending_bytes, now_ms);
                    }
                    None => {
                        if report.deleted > 0 {
                            tracing::info!(deleted = report.deleted, "sanctioned lake-part GC deleted part files");
                        }
                        self.health.part_gc_blocked = None;
                        self.last_gc_block_reason = None;
                        self.gc_blocked_since_ms = None;
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "sanctioned lake-part GC pass failed; retrying later");
                self.health.part_gc_last_pause = Some(format!("pass_failed: {error:#}"));
                self.gc_blocked(REASON_SANCTIONED_PASS_PAUSED, pending_parts, pending_bytes, now_ms);
            }
        }
    }

    fn gc_blocked(&mut self, reason: &'static str, parts: u64, bytes: u64, now_ms: i64) {
        let detail = if reason == REASON_SANCTIONED_PATH_UNAVAILABLE {
            self.gc_authority.as_ref().map_or("sanctioned_route_not_wired", |authority| authority.blocked_detail())
        } else {
            ""
        };
        if parts == 0 {
            self.gc_blocked_since_ms = None;
        }
        let blocked_seconds = if parts > 0 {
            now_ms.saturating_sub(*self.gc_blocked_since_ms.get_or_insert(now_ms)).max(0) as u64 / 1000
        } else {
            0
        };
        if self.last_gc_block_reason != Some(reason) {
            tracing::warn!(reason, detail, pending_parts = parts, pending_bytes = bytes,
                "lake-part GC blocked; keeping superseded parts (queries are unaffected)");
            self.last_gc_block_reason = Some(reason);
        }
        self.health.part_gc_blocked =
            Some(nanosiem_lake_cell::contract::PartGcBlocked { reason: reason.to_string(), parts, bytes, detail: detail.to_string(), blocked_seconds });
    }

    /// At start: drop cache directories that are not live parts (crashed
    /// writes, superseded parts, temp dirs). Their data is in the store.
    fn sweep_cache(&mut self) -> Result<()> {
        // Fetched sources of admissions that never completed: redelivered.
        if let Ok(entries) = std::fs::read_dir(self.cfg.work_dir.join("src")) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let dir = parts_dir(&self.cfg.work_dir);
        let Ok(entries) = std::fs::read_dir(&dir) else { return Ok(()) };
        let mut removed = 0;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let live = PartId::parse(&name).ok().is_some_and(|id| self.log.live().get(&id).is_some());
            if !live {
                let _ = std::fs::remove_dir_all(entry.path());
                removed += 1;
            }
        }
        if removed > 0 {
            tracing::info!(removed, "swept non-live part cache directories");
        }
        Ok(())
    }

    /// Keep the local part cache under `cache_max_bytes`: evict the
    /// least-recently-used live parts (re-fetched and re-verified on demand).
    fn evict_cache(&mut self, now_ms: i64) -> Result<()> {
        if now_ms - self.last_cache_sweep_ms < 60_000 {
            return Ok(());
        }
        self.last_cache_sweep_ms = now_ms;
        let dir = parts_dir(&self.cfg.work_dir);
        let mut parts = Vec::new();
        let mut total = 0_u64;
        // A running merge reads its inputs from the cache: never evict them.
        let mut busy = self.merge_in_flight.iter().flat_map(|flight| {
            flight.merge.inputs.iter().flat_map(|p| {
                let path = dir.join(p.part_id.as_str());
                [path.with_extension("partial"), path]
            })
        }).collect::<BTreeSet<_>>();
        // So does a background late-tier fold (NAN-3703).
        if let Some(part) = self.late.folding() {
            let path = dir.join(part.part_id.as_str());
            busy.insert(path.with_extension("partial"));
            busy.insert(path);
        }
        // A background reindex owns both its download directory and the
        // completed cache entry until the tick hands it to the merge.
        if let Some((part, _)) = &self.reindex_fetch {
            let path = dir.join(part.part_id.as_str());
            busy.insert(path.with_extension("partial"));
            busy.insert(path);
        }
        // The pipelined flush writes and uploads its parts in the background.
        let flush_sealed_ms = self.flush_in_flight.iter().map(|flight| flight.sealed_ms).min();
        for entry in std::fs::read_dir(&dir)?.flatten() {
            let path = entry.path();
            let flushing = flush_sealed_ms.is_some_and(|sealed| crate::parts::format::PartId::parse(&entry.file_name().to_string_lossy())
                .is_ok_and(|id| id.created_unix_ms() >= sealed));
            let active_draft = flushing || self.merge_in_flight.iter().any(|flight| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(".merge-") || name.starts_with(".family-")
                    || crate::parts::format::PartId::parse(&name)
                        .is_ok_and(|id| id.created_unix_ms() >= flight.started_ms)
            });
            if busy.contains(&path) || active_draft {
                continue;
            }
            let mut bytes = 0_u64;
            let mut stack = vec![path.clone()];
            while let Some(d) = stack.pop() {
                for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                    let meta = e.metadata()?;
                    if meta.is_dir() {
                        stack.push(e.path());
                    } else {
                        bytes += meta.len();
                    }
                }
            }
            let used = std::fs::metadata(path.join(".used"))
                .or_else(|_| std::fs::metadata(&path))
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            total += bytes;
            parts.push((used, bytes, path));
        }
        parts.sort();
        let mut evicted = 0;
        for (_, bytes, path) in parts {
            if total <= self.cfg.cache_max_bytes {
                break;
            }
            let _ = std::fs::remove_dir_all(&path);
            total = total.saturating_sub(bytes);
            evicted += 1;
        }
        self.health.cache_bytes = total;
        if evicted > 0 {
            tracing::info!(evicted, cache_bytes = total, "evicted least-recently-used parts from the local cache");
        }
        Ok(())
    }

    fn find_local(&self, id: &PartId) -> Option<PathBuf> {
        let dir = parts_dir(&self.cfg.work_dir).join(id.as_str());
        dir.exists().then_some(dir)
    }

    fn export_plan(&mut self, now_ms: i64) -> Result<()> {
        let live = self.live_parts();
        let pending = plan_export(&live, &self.export, now_ms, &self.cfg.merge_policy);
        self.health.export_pending_hours = pending.len();
        if !pending.is_empty() && self.export.due(now_ms) {
            self.export.record_plan(&self.cfg.work_dir, &self.cfg.tenant_id, &pending, now_ms)?;
            self.export.prune(&self.cfg.work_dir, now_ms, 400 * 24, 7 * 86_400_000)?;
        }
        Ok(())
    }

    fn update_health(&mut self, pending: &[(NoticeHandle, SourceNotice)], now_ms: i64) -> Result<()> {
        let oldest = pending.iter().map(|(_, n)| n.notified_at_ms).min();
        let prevalence_status = self.prevalence_status();
        let h = &mut self.health;
        h.updated_at_ms = now_ms;
        h.pending_notices = pending.len();
        h.oldest_pending_notice_ms = oldest;
        h.lag_ms = oldest.map_or(0, |o| (now_ms - o).max(0));
        let was_stalled = h.stalled;
        h.stalled = h.lag_ms > self.cfg.lag_alert_ms;
        h.buffered_rows = self.buffer.rows + self.flush_in_flight.iter().map(|flight| flight.buffer.rows).sum::<usize>();
        h.flushes_in_flight = self.flush_in_flight.len();
        h.window_uids = self.window.len();
        let late = self.late.stats();
        h.late_dedup_tier_hours = late.hours;
        h.late_dedup_tier_uids = late.uids;
        h.late_dedup_tier_bloom_bytes = late.bloom_bytes;
        h.late_dedup_tier_ready = late.ready;
        h.late_dedup_tier_spills_total = late.spills_total;
        h.late_dedup_tier_folds_total = late.folds_total;
        h.late_dedup_tier_fold_failures_total = late.fold_failures_total;
        h.late_dedup_tier_hours_dropped_over_budget_total = late.hours_dropped_over_budget_total;
        h.window_hours = self.window.hours();
        h.prevalence_status = prevalence_status;
        // NAN-3781: a held state whose every rebuild/catch-up step fails
        // stamps nothing either (CT 106: "live prevalence partial is missing"
        // twice a second, health said not degraded): degraded once that lasts
        // PREVALENCE_STEP_FAILING_DEGRADED_MS.
        let step_failing = self.prevalence_step_failing_since_ms
            .is_some_and(|since| now_ms.saturating_sub(since) >= PREVALENCE_STEP_FAILING_DEGRADED_MS);
        h.prevalence_degraded = (self.prevalence.is_none() && self.prevalence_retry.is_some()) || step_failing;
        // NAN-3781: degraded time is a signal and a counter, and an ongoing
        // spell is logged at ERROR every minute: a reopen that hangs (CT 106,
        // a state stalled at the L0 cap) otherwise logs one ERROR and goes
        // quiet for up to `prevalence_open_hard_timeout`.
        if h.prevalence_degraded {
            let unavailable = self.prevalence_retry.is_some();
            let since = *self.prevalence_degraded_since_ms.get_or_insert_with(|| {
                // An unavailable state logged its ERROR when it failed; a
                // failing step has not, so its first one is due now.
                self.prevalence_degraded_logged_ms =
                    if unavailable { now_ms } else { now_ms.saturating_sub(PREVALENCE_DEGRADED_LOG_EVERY_MS) };
                now_ms
            });
            h.prevalence_degraded_ms = now_ms.saturating_sub(since).max(0) as u64;
            if now_ms.saturating_sub(self.prevalence_degraded_logged_ms) >= PREVALENCE_DEGRADED_LOG_EVERY_MS {
                self.prevalence_degraded_logged_ms = now_ms;
                let retry = self.prevalence_retry.as_ref();
                tracing::error!(tenant = %self.cfg.tenant_id, degraded_secs = h.prevalence_degraded_ms / 1_000,
                    failures = retry.map_or(0, |retry| retry.failures), opening = self.prevalence_opening.is_some(),
                    step_failing, status = %h.prevalence_status,
                    last_error = retry.map_or("", |retry| retry.last_error.as_str()),
                    "PREVALENCE DEGRADED: tenant prevalence state still unavailable; ingest continues with prevalence unstamped");
            }
        } else {
            if let Some(since) = self.prevalence_degraded_since_ms.take() {
                let spell = now_ms.saturating_sub(since).max(0) as u64;
                self.prevalence_degraded_closed_ms = self.prevalence_degraded_closed_ms.saturating_add(spell);
                tracing::info!(tenant = %self.cfg.tenant_id, degraded_secs = spell / 1_000,
                    degraded_total_secs = self.prevalence_degraded_closed_ms / 1_000, "prevalence degraded spell ended");
            }
            h.prevalence_degraded_ms = 0;
        }
        h.prevalence_degraded_ms_total = self.prevalence_degraded_closed_ms.saturating_add(h.prevalence_degraded_ms);
        // NAN-3774: "prevalence is behind", not an ingest symptom. Behind
        // while a held state (open, opening, rotating or retrying) is not
        // stamping at the log head; a process without a grant is unstamped
        // by design and never behind.
        let held = self.prevalence.is_some() || self.prevalence_reopening || self.prevalence_retry.is_some()
            || self.prevalence_opening.is_some();
        let behind = held && (self.prevalence_pending || self.prevalence_phase != PrevalencePhase::Stamping
            || self.prevalence_unplaced || self.prevalence_blocked_since.is_some());
        let head = self.log.live().head().map(|(seq, _, _)| seq);
        h.prevalence_behind_entries = match (behind, head, self.prevalence_applied_seq) {
            (true, Some(head), Some(applied)) => head.saturating_sub(applied),
            _ => 0,
        };
        if behind {
            let since = *self.prevalence_behind_since_ms.get_or_insert(now_ms);
            h.prevalence_behind_ms = now_ms.saturating_sub(since).max(0) as u64;
        } else {
            self.prevalence_behind_since_ms = None;
            h.prevalence_behind_ms = 0;
        }
        h.prevalence_opening = self.prevalence_opening.is_some();
        h.prevalence_index_bytes = match &self.prevalence {
            Some(prevalence) => prevalence.disk_bytes()?,
            None => 0,
        };
        let mut by_level = BTreeMap::new();
        let mut live = 0;
        for part in self.log.live().parts() {
            *by_level.entry(part.level.code().to_string()).or_default() += 1;
            live += 1;
        }
        h.live_parts = live;
        h.log_key_held_total = self.log.log_key_held_total();
        h.live_parts_by_level = by_level;
        h.oldest_unmerged_l0_age_ms = self.log.live().parts()
            .filter(|part| part.level == Level::L0)
            .map(|part| now_ms.saturating_sub(part.part_id.created_unix_ms()).max(0))
            .max().unwrap_or(0);
        h.l0_merge_overdue_ms = crate::parts::levels::l0_merge_overdue_ms(self.log.live().parts(), now_ms, &self.cfg.merge_policy);
        if h.stalled && !was_stalled {
            tracing::error!(lag_ms = h.lag_ms, tenant = %h.tenant_id, "ingest lag exceeds its alert threshold");
        }
        let path = self.cfg.work_dir.join("health.json");
        let temp = self.cfg.work_dir.join(".health.json.tmp");
        std::fs::write(&temp, serde_json::to_vec_pretty(h)?)?;
        std::fs::rename(temp, path)?;
        Ok(())
    }
}

/// Is `key` inside the tenant prefix? Anchored: the prefix (for example
/// `tenant_id=<uuid>/`) starts the key or follows the fixed bronze layout
/// `bronze-v2/shard=<n>/`, never an arbitrary `/` inside the key.
pub fn key_inside_prefix(key: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_start_matches('/');
    if prefix.is_empty() || key.split('/').any(|segment| segment == ".." || segment == ".") {
        return false;
    }
    if key.starts_with(prefix) {
        return true;
    }
    let mut segments = key.splitn(3, '/');
    match (segments.next(), segments.next(), segments.next()) {
        (Some("bronze-v2"), Some(shard), Some(rest)) => {
            shard.strip_prefix("shard=").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                && rest.starts_with(prefix)
        }
        _ => false,
    }
}

/// Least time between sanctioned lake-part GC passes (each lists the
/// tenant's `parts/` prefix).
pub const SANCTIONED_GC_INTERVAL_MS: i64 = 600_000;

/// NAN-3818: least time between bounded log-fold steps while a sanctioned
/// pass is still catching its view up to the log head (after every restart
/// the local view folds from genesis, [`MAX_LOG_ENTRIES_PER_PASS`] entries a
/// step). Waiting the full pass interval per step left CT 106 (7.5k entries)
/// without GC for ~40 min after each restart. Each step is still bounded and
/// runs between ingest ticks, so ingest keeps the mutex most of the time.
///
/// [`MAX_LOG_ENTRIES_PER_PASS`]: crate::lake_part_gc::executor::MAX_LOG_ENTRIES_PER_PASS
pub const SANCTIONED_GC_CATCH_UP_INTERVAL_MS: i64 = 5_000;

/// Whether ingest starts a sanctioned GC pass now: the first time, after the
/// pass interval, or after the short catch-up interval while the previous
/// pass only advanced its log view.
pub(crate) fn sanctioned_pass_due(last_pass_ms: Option<i64>, catching_up: bool, now_ms: i64) -> bool {
    let interval = if catching_up { SANCTIONED_GC_CATCH_UP_INTERVAL_MS } else { SANCTIONED_GC_INTERVAL_MS };
    last_pass_ms.is_none_or(|last| now_ms - last >= interval)
}

/// A pass that stopped mid log-fold and asks for no back-off: progressing.
pub(crate) fn pass_is_catching_up(report: &crate::lake_part_gc::PassReport) -> bool {
    !report.backoff && report.paused_reason.as_deref() == Some(crate::lake_part_gc::executor::LOG_CATCHING_UP)
}

/// Source objects (edge segments or bronze notices) one flush may take
/// (NAN-3006). Every L0 record of a flush names all of them (and the edge
/// range lists every skipped segment), so this bounds a record: even at the
/// 1 KiB key maximum 512 sources stay well under `MAX_PROVENANCE_BYTES`, and
/// a restart backlog drains in several flushes instead of one oversized one.
pub const MAX_FLUSH_OBJECTS: usize = 512;

/// Rejections per `reject` entry (the log's validation cap).
pub const MAX_REJECTIONS_PER_ENTRY: usize = 1_000;
/// Serialized bytes per `reject` entry, well under one log object.
const MAX_REJECT_ENTRY_BYTES: usize = crate::parts::part_log::MAX_ENTRY_BYTES / 2;

/// The longest prefix of `pending` that fits one `reject` entry (B3): at
/// most 1,000 items and half a log object; always at least one item (a
/// single rejection is bounded far below the cap by key + 512-byte detail).
fn reject_chunk(pending: &[Rejection]) -> Vec<Rejection> {
    let mut bytes = 0;
    let mut out = Vec::new();
    for rejection in pending.iter().take(MAX_REJECTIONS_PER_ENTRY) {
        let size = serde_json::to_vec(rejection).map_or(4_096, |b| b.len()) + 1;
        if !out.is_empty() && bytes + size > MAX_REJECT_ENTRY_BYTES {
            break;
        }
        bytes += size;
        out.push(rejection.clone());
    }
    out
}

/// Would decoding `value` into `data_type` silently truncate a fractional
/// number into an integer leaf? (arrow-json parses 1.5 into Int64 as 1.)
pub fn truncates(value: &Value, data_type: &arrow_schema::DataType) -> bool {
    use arrow_schema::DataType as D;
    match (value, data_type) {
        (Value::Object(map), D::Struct(fields)) => fields
            .iter()
            .any(|field| map.get(field.name()).is_some_and(|child| truncates(child, field.data_type()))),
        (Value::Array(items), D::List(field) | D::LargeList(field)) => items.iter().any(|item| truncates(item, field.data_type())),
        (Value::Number(n), D::Int8 | D::Int16 | D::Int32 | D::Int64 | D::UInt8 | D::UInt16 | D::UInt32 | D::UInt64) => {
            n.as_i64().is_none() && n.as_u64().is_none() && n.as_f64().is_some_and(|f| f.fract() != 0.0)
        }
        _ => false,
    }
}

/// Errors from IO or resources are retried by fail-stop and replay; only
/// deterministic validation failures reject an object.
fn is_transient(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        #[cfg(all(feature = "enterprise", target_os = "linux"))]
        if cause.downcast_ref::<crate::platform_stamping::AdmissionUnavailable>().is_some() {
            return true;
        }
        cause.downcast_ref::<std::io::Error>().is_some()
    })
}

fn hours_of(part: &PartRef) -> Vec<i32> {
    match part.level {
        Level::Day => (event_hour_of(part.min_time_us)..=event_hour_of(part.max_time_us)).collect(),
        _ => vec![part.event_hour],
    }
}

pub(crate) fn event_time_us(event: &Value) -> Result<i64> {
    let time = event.get("time").context("normalized event has no time")?;
    if let Some(ms) = time.as_i64() {
        return Ok(ms * 1_000);
    }
    let text = time.as_str().context("normalized event time is not a string")?;
    let parsed = DateTime::parse_from_rfc3339(text).context("normalized event time is not RFC 3339")?;
    Ok(parsed.timestamp_micros())
}

/// Process CPU time in ms (user + system), for the budget counters.
pub fn cpu_now() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes into the provided struct only.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let ms = |t: libc::timeval| t.tv_sec as u64 * 1_000 + t.tv_usec as u64 / 1_000;
    ms(usage.ru_utime) + ms(usage.ru_stime)
}


/// Download and verify a part into the local cache (no-op when local): the
/// signed provenance, every data, token and partial file against it.
async fn download_part(
    parts: &dyn ObjectStore,
    tenant_id: &str,
    trusted: &TenantKeySet,
    work_dir: &Path,
    part: &PartRef,
) -> Result<PathBuf> {
    download_part_with_quota(parts, tenant_id, trusted, work_dir, part, false).await
}

async fn download_part_with_quota(
    parts: &dyn ObjectStore, tenant_id: &str, trusted: &TenantKeySet,
    work_dir: &Path, part: &PartRef, compacting: bool,
) -> Result<PathBuf> {
    let dir = parts_dir(work_dir).join(part.part_id.as_str());
    if dir.join(PROVENANCE_FILE).exists() {
        let _ = std::fs::write(dir.join(".used"), b"");
        return Ok(dir);
    }
    let keys = PartKeys::new(tenant_id, part.level, part.event_hour, &part.part_id)?;
    // Provenance is bounded metadata; conservatively reserve its full cap.
    let provenance = super::merge_quota::remote_transfer(compacting, crate::parts::provenance::MAX_PROVENANCE_BYTES as u64, parts.get(&keys.provenance()))
        .await?.context("live part has no provenance")?;
    ensure!(sha256_hex(&provenance) == part.provenance_sha256, "part provenance does not match the log");
    let signed = SignedProvenance::verify_bytes(&provenance, tenant_id, trusted)?;
    part.check_record(&signed.record, &part.provenance_sha256)?;
    let temp = dir.with_extension("partial");
    let _ = std::fs::remove_dir_all(&temp);
    std::fs::create_dir_all(temp.join("partials"))?;
    // (remote key, local name, sha256). An adopted part's data file is
    // its original object at `data_key` (contract 8.1); locally every
    // part uses the written layout.
    let record = &signed.record;
    let mut files = Vec::new();
    for (index, data) in record.files.data.iter().enumerate() {
        let remote = record.data_key(&keys, index).context("data file index")?;
        files.push((remote, crate::parts::format::data_file_name(index), data.sha256.clone(), data.bytes));
        files.push((keys.file(&data.tokens.name), data.tokens.name.clone(), data.tokens.sha256.clone(), data.tokens.bytes));
        if let Some(locator) = &data.entity_locators {
            files.push((keys.file(&locator.name), locator.name.clone(), locator.sha256.clone(), locator.bytes));
        }
        if let Some(entity) = &data.entity_blooms {
            files.push((keys.file(&entity.name), entity.name.clone(), entity.sha256.clone(), entity.bytes));
        }
        if let Some(uid) = &data.uid_blooms {
            files.push((keys.file(&uid.name), uid.name.clone(), uid.sha256.clone(), uid.bytes));
        }
    }
    for partial in &record.files.partials {
        files.push((keys.file(&partial.name), partial.name.clone(), partial.sha256.clone(), partial.bytes));
    }
    for (remote, local, sha, bytes) in files {
        let target = temp.join(&local);
        // NAN-3772: a large input downloads under a progress (idle) timeout.
        ensure!(super::merge_quota::remote_download(compacting, bytes, &target, parts.get_to_file(&remote, &target)).await?, "part file {remote} missing");
        let (actual_bytes, actual) = super::writer::file_digest(&target)?;
        ensure!(actual == sha && actual_bytes == bytes, "part file {remote} does not match its record");
    }
    std::fs::write(temp.join(PROVENANCE_FILE), &provenance)?;
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::rename(&temp, &dir)?;
    Ok(dir)
}

fn count_writer_enabled() -> bool {
    #[cfg(test)]
    if let Some(enabled) = tests::COUNT_WRITER_OVERRIDE.with(|value| value.get()) {
        return enabled;
    }
    crate::parts::entity_counts::enabled(std::env::var("NANO_LAKE_ENTITY_COUNT_WRITE").ok().as_deref())
}

/// Admitted count-backfill windows, one immutable record per admission, under
/// the tenant's `log/checkpoints/` (the scope of the `lake_part` credential,
/// like [`FINDING_ATTEMPT_INDEX_READY`]): `{admitted_ms:013}-{sha256[..16]}.json`.
/// The newest admission is the window. Progress needs no record of its own:
/// rewritten parts are committed to the part log, and a restarted ingest
/// re-probes them as current. Only the coverage counters and the ETA in
/// [`IngestHealth`] are per-process.
pub(crate) const COUNT_BACKFILL_DIR: &str = "count-backfill-v1/";
/// Pre-durable images kept the window only here, on the pod-local volume.
const LOCAL_COUNT_BACKFILL_FILE: &str = "count-backfill.json";

fn count_backfill_prefix(tenant_id: &str) -> Result<String> {
    Ok(format!("{}{COUNT_BACKFILL_DIR}", LogKeys::new(tenant_id)?.checkpoints_prefix()))
}

fn count_backfill_key(tenant_id: &str, admitted_ms: i64, bytes: &[u8]) -> Result<String> {
    ensure!((0..=9_999_999_999_999).contains(&admitted_ms), "count backfill admission time out of range");
    Ok(format!("{}{admitted_ms:013}-{}.json", count_backfill_prefix(tenant_id)?, &sha256_hex(bytes)[..16]))
}

/// The record's name binds its bytes: a record whose content differs from its
/// name (or a foreign name under the prefix) is never a window.
fn count_backfill_record_matches(prefix: &str, key: &str, bytes: &[u8]) -> bool {
    key.strip_prefix(prefix).is_some_and(|name| name.len() == 35
        && name.as_bytes()[..13].iter().all(u8::is_ascii_digit)
        && name[13..] == format!("-{}.json", &sha256_hex(bytes)[..16]))
}

async fn persist_count_backfill(store: &dyn ObjectStore, tenant_id: &str,
    window: &super::reindex::CountBackfill, admitted_ms: i64) -> Result<()> {
    let bytes = serde_json::to_vec(window)?;
    let key = count_backfill_key(tenant_id, admitted_ms, &bytes)?;
    if !store.put_if_absent(&key, &bytes).await? {
        ensure!(store.get(&key).await?.as_deref() == Some(bytes.as_slice()), "count backfill record differs");
    }
    Ok(())
}

/// The newest durable admission. A listing or read error fails the open like
/// every other part-store read here (the role restarts), never a silent
/// "no backfill".
async fn load_count_backfill(store: &dyn ObjectStore, tenant_id: &str, work_dir: &Path, now_ms: i64)
    -> Result<Option<super::reindex::CountBackfill>> {
    let prefix = count_backfill_prefix(tenant_id)?;
    let mut keys = store.list(&prefix).await?;
    keys.retain(|key| key.starts_with(&prefix));
    keys.sort_unstable();
    for key in keys.iter().rev() {
        let Some(bytes) = store.get(key).await? else { continue };
        match serde_json::from_slice::<super::reindex::CountBackfill>(&bytes) {
            // Re-validated: a record only ever names a past window of at most 31 days.
            Ok(window) if count_backfill_record_matches(&prefix, key, &bytes) && window.validate(now_ms).is_ok() =>
                return Ok(Some(window)),
            _ => tracing::warn!(tenant = %tenant_id, %key, "skipping unreadable count backfill record"),
        }
    }
    let local = match std::fs::read(work_dir.join(LOCAL_COUNT_BACKFILL_FILE)) {
        Ok(bytes) => serde_json::from_slice::<super::reindex::CountBackfill>(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    persist_count_backfill(store, tenant_id, &local, now_ms).await?;
    tracing::info!(tenant = %tenant_id, start_ms = local.start_ms, end_ms = local.end_ms,
        "count backfill window moved from the pod-local volume to the tenant bucket");
    Ok(Some(local))
}

/// NAN-3864: hours owed a prevalence restamp, one immutable snapshot per
/// change under the tenant's `log/checkpoints/` (named and bound like
/// [`COUNT_BACKFILL_DIR`] records): `{written_ms:013}-{sha256[..16]}.json`,
/// a JSON array of event hours. The newest valid snapshot is the set. It is
/// kept out of the prevalence state on purpose: the hours are owed while
/// that state is not answering. Written only when the set changes (an hour
/// newly owed or cleared), so a few small objects per outage.
///
/// A roll can lose at most the marks of the old process's last tick (a
/// commit fenced out after the new process read the set); the operator
/// window ([`Ingestor::queue_prevalence_restamp`]) covers any such hour.
pub(crate) const PREVALENCE_RESTAMP_DIR: &str = "prevalence-restamp-v1/";

fn restamp_owed_prefix(tenant_id: &str) -> Result<String> {
    Ok(format!("{}{PREVALENCE_RESTAMP_DIR}", LogKeys::new(tenant_id)?.checkpoints_prefix()))
}

async fn persist_restamp_owed(store: &dyn ObjectStore, tenant_id: &str, bytes: &[u8], written_ms: i64) -> Result<()> {
    ensure!((0..=9_999_999_999_999).contains(&written_ms), "restamp snapshot time out of range");
    let key = format!("{}{written_ms:013}-{}.json", restamp_owed_prefix(tenant_id)?, &sha256_hex(bytes)[..16]);
    if !store.put_if_absent(&key, bytes).await? {
        ensure!(store.get(&key).await?.as_deref() == Some(bytes), "restamp snapshot differs");
    }
    Ok(())
}

/// The newest valid snapshot: its name time and hours. An unreadable or
/// foreign record is skipped; a listing or read error is returned (the
/// caller retries next tick, ingest is never held).
async fn load_restamp_owed(store: &dyn ObjectStore, tenant_id: &str) -> Result<Option<(i64, Vec<i32>)>> {
    let prefix = restamp_owed_prefix(tenant_id)?;
    let mut keys = store.list(&prefix).await?;
    keys.retain(|key| key.starts_with(&prefix));
    keys.sort_unstable();
    for key in keys.iter().rev() {
        let Some(bytes) = store.get(key).await? else { continue };
        match super::restamp::OwedHours::parse(&bytes) {
            Ok(hours) if count_backfill_record_matches(&prefix, key, &bytes) => {
                let written_ms = key[prefix.len()..prefix.len() + 13].parse::<i64>()?;
                return Ok(Some((written_ms, hours)));
            }
            _ => tracing::warn!(tenant = %tenant_id, %key, "skipping unreadable prevalence restamp snapshot"),
        }
    }
    Ok(None)
}

/// NAN-3077 background half of the old-hour reindex (never on the tick):
/// verify every signed token file's group coverage and, when any index is not the writer's
/// current format, download the whole part into the local cache.
/// `Ok(None)`: already current. `Ok(Some((dir, why)))`: stale and local.
#[cfg(test)]
pub(super) async fn probe_and_fetch_for_reindex(
    parts: &'static dyn ObjectStore,
    tenant_id: String,
    trusted: TenantKeySet,
    work_dir: PathBuf,
    part: PartRef,
) -> Result<Option<PathBuf>> {
    probe_and_fetch_for_coverage(parts, tenant_id, trusted, work_dir, part, false, None, 0).await.map(|stale| stale.map(|(dir, _)| dir))
}

/// `counts_signer` (NAN-3801): when counts are the ONLY stale coverage, count
/// the part from its count columns and publish its signed count record
/// instead of downloading it for a full rewrite (`Ok(None)` afterwards). An
/// owner without the count route falls back to the full rewrite.
#[allow(clippy::too_many_arguments)]
pub(super) async fn probe_and_fetch_for_coverage(
    parts: &'static dyn ObjectStore, tenant_id: String, trusted: TenantKeySet,
    work_dir: PathBuf, part: PartRef, counts: bool, counts_signer: Option<&'static dyn PartSigner>, now_ms: i64,
) -> Result<Option<(PathBuf, String)>> {
    let keys = PartKeys::new(&tenant_id, part.level, part.event_hour, &part.part_id)?;
    let provenance = super::merge_quota::remote_transfer(true, crate::parts::provenance::MAX_PROVENANCE_BYTES as u64, parts.get(&keys.provenance()))
        .await?.context("live part has no provenance")?;
    ensure!(sha256_hex(&provenance) == part.provenance_sha256, "part provenance does not match the log");
    let signed = SignedProvenance::verify_bytes(&provenance, &tenant_id, &trusted)?;
    part.check_record(&signed.record, &part.provenance_sha256)?;
    ensure!(!signed.record.files.data.is_empty(), "part has no data file");
    // Coverage is per data file. One small current index cannot attest that
    // all other files in a historical part also have exact count evidence.
    let sidecars = super::reindex::sidecar_enabled();
    let entities = !super::writer::entity_sidecar_fields(std::env::var("NANO_LAKE_ENTITY_SIDECAR_FIELDS").ok().as_deref()).is_empty();
    let mut stale = Vec::<String>::new();
    if sidecars && !super::reindex::sidecars_are_current(&signed.record, entities) {
        stale.push("uid/entity blooms missing".into());
    }
    for data in signed.record.files.data.iter().filter(|_| super::reindex::keyword_enabled()) {
        let tokens = &data.tokens;
        let local = parts_dir(&work_dir).join(part.part_id.as_str()).join(&tokens.name);
        let bytes = match std::fs::read(&local) {
            Ok(bytes) => bytes,
            Err(_) => {
                super::merge_quota::remote_transfer(true, tokens.bytes, parts.get(&keys.file(&tokens.name))).await?.context("token file missing")?
            },
        };
        ensure!(sha256_hex(&bytes) == tokens.sha256, "token file does not match its record");
        let groups = crate::parts::sidecar::decode_leased_token_index(&bytes)?;
        if !super::reindex::groups_are_current(&groups, data.rows, data.row_groups, crate::parts::sidecar::trigrams_enabled()) {
            stale.push(format!("token index of {} not current", data.name));
        }
    }
    if counts {
        // NAN-3795: say why counts are not current, so a part that stays
        // uncovered after its own rewrite reports a terminal reason.
        let reason = match signed.record.files.partials.iter().find(|p| p.kind == crate::parts::provenance::PartialKind::EntityRanges) {
            None => Some("no entity-ranges partial".to_string()),
            Some(partial) if partial.bytes < 8 => Some("entity-ranges partial is truncated".to_string()),
            Some(partial) => {
                let key = keys.file(&partial.name);
                match super::merge_quota::remote_transfer(true, 8, parts.get_range(&key, partial.bytes - 8..partial.bytes)).await? {
                    Some(tail) if tail.len() == 8 && &tail[4..] == b"PAR1" => {
                        let length = u32::from_le_bytes(tail[..4].try_into()?) as u64;
                        if length > partial.bytes - 8 {
                            Some(format!("entity-ranges footer length {length} exceeds the file"))
                        } else if length > super::reindex::COUNT_HINT_FOOTER_MAX_BYTES {
                            Some(format!("entity-ranges footer is {length} bytes, over the {} byte count-hint cap", super::reindex::COUNT_HINT_FOOTER_MAX_BYTES))
                        } else {
                            // NAN-3801: footers up to the 8 MiB hint cap exceed the S3
                            // store's 4 MiB ranged GET (r52 tenant-a: 48 "export object range
                            // exceeds budget" probe failures); read them in chunks.
                            match super::count_record::read_range_bounded(parts, &key, partial.bytes - 8 - length..partial.bytes - 8,
                                super::reindex::COUNT_HINT_FOOTER_MAX_BYTES).await? {
                                Some(footer) if super::reindex::v2_hint(&footer)? => None,
                                Some(_) => Some("no v2 count coverage hint (every entity kind dropped its counts)".to_string()),
                                None => Some("entity-ranges footer missing".to_string()),
                            }
                        }
                    }
                    _ => Some("entity-ranges partial has no parquet tail".to_string()),
                }
            }
        };
        // NAN-3801: a valid signed count record makes the counts current.
        let reason = match reason {
            Some(reason) => match super::count_record::stored_count_record(parts, &keys, &part, &tenant_id, &trusted).await {
                Ok(Some(_)) => None,
                Ok(None) => Some(reason),
                Err(error) => Some(format!("{reason}; {error:#}")),
            },
            None => None,
        };
        if let (Some(reason), true, Some(signer)) = (&reason, stale.is_empty(), counts_signer) {
            if !super::count_record::count_signing_unsupported() {
                let started = std::time::Instant::now();
                match super::count_record::backfill_counts(parts, signer, &trusted, &tenant_id, &work_dir, &part, &signed.record, now_ms).await {
                    Ok(done) => {
                        super::count_record::note_counted(&part, &done);
                        tracing::info!(hour = part.event_hour, part = %part.part_id.as_str(), rows = part.rows,
                            fetched_bytes = done.fetched.bytes, data_bytes = part.data_bytes, whole_files = done.fetched.whole_files,
                            count_rows = done.record.record.count_rows, existing = done.existing,
                            elapsed_ms = started.elapsed().as_millis() as u64, was = %reason,
                            "counts-only backfill: count record published");
                        return Ok(None);
                    }
                    Err(error) if super::count_record::is_unsupported(&error) => {
                        super::count_record::mark_count_signing_unsupported(&error);
                    }
                    Err(error) => return Err(error.context("counts-only backfill")),
                }
            }
        }
        stale.extend(reason);
    }
    if stale.is_empty() {
        return Ok(None);
    }
    let reason = stale.join("; ");
    download_part_with_quota(parts, &tenant_id, &trusted, &work_dir, &part, true).await.map(|dir| Some((dir, reason)))
}

#[path = "ingest_erasure.rs"]
mod erasure_exec;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn count_backfill_admitted_without_compaction_pacing_and_rejects_in_flight() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        let now = 1_800_000_000_000;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c1";
        let store = LocalObjectStore::new(root.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("backfill-test", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut cfg = IngestConfig::new(tenant, root.path().join("ingest"));
        cfg.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        let window = super::super::reindex::CountBackfill { start_ms: now - 7 * 86_400_000, end_ms: now };
        assert!(std::env::var_os("NANO_LAKE_COMPACTION_PACING").is_none());
        assert!(ingestor.queue_count_backfill(window.clone(), now, false).await.is_err());
        ingestor.queue_count_backfill(window.clone(), now, true).await.unwrap();
        let restored = load_count_backfill(&store, tenant, &ingestor.cfg.work_dir, now).await.unwrap().unwrap();
        assert_eq!(restored.start_ms, window.start_ms);
        ingestor.queue_count_backfill(window.clone(), now, true).await.unwrap();
        let part = PartRef {
            part_id: crate::parts::format::PartId::new(now).unwrap(), level: Level::Hour,
            event_hour: (window.start_ms / 3_600_000) as i32, event_day: None, rows: 1,
            min_time_us: window.start_ms * 1000, max_time_us: window.start_ms * 1000,
            schema_fingerprint: String::new(), provenance_sha256: String::new(), merkle_root: String::new(),
            sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
        };
        let handle = tokio::spawn(std::future::pending());
        ingestor.merge_in_flight.push(InFlightMerge {
            merge: crate::parts::levels::PlannedMerge { output_level: Level::Hour, event_hour: part.event_hour, inputs: vec![part] },
            key: ("h".into(), 0), started_ms: now, last_warn_ms: now, handle, restamp: None,
        });
        let error = ingestor.queue_count_backfill(window.clone(), now, true).await.unwrap_err();
        assert!(error.to_string().contains("in-flight"));
        assert_eq!(load_count_backfill(&store, tenant, &ingestor.cfg.work_dir, now).await.unwrap().unwrap().start_ms, window.start_ms);
        ingestor.merge_in_flight.pop().unwrap().handle.abort();
    }

    /// NAN-3849 (tenant-a 2026-10-14 after r51): a prevalence catch-up that never
    /// reaches the head deferred every L0 merge (l0_merge_overdue 269 s ->
    /// 2,396 s, live parts 263 -> 351, zero merges since the roll). Merges
    /// yield to the catch-up only until the worst L0 merge is
    /// PREVALENCE_L0_YIELD_MS overdue (below the 15 min warn), then run.
    #[test]
    fn l0_merges_yield_to_a_prevalence_catch_up_only_for_a_bounded_time() {
        let policy = crate::parts::levels::MergePolicy::default();
        let roll_ms = 1_791_992_220_000_i64; // 2026-10-14 15:37Z
        let hour = (roll_ms / 3_600_000) as i32;
        // One sorted L0 flush every 22 s since the roll, none merged.
        let l0_since_roll = |now_ms: i64| (0..).map(|n| roll_ms + n * 22_000).take_while(|created| *created <= now_ms)
            .map(|created| PartRef {
                part_id: crate::parts::format::PartId::new(created).unwrap(), level: Level::L0,
                event_hour: hour, event_day: None, rows: 10_000,
                min_time_us: created * 1_000, max_time_us: created * 1_000,
                schema_fingerprint: String::new(), provenance_sha256: "0".repeat(64), merkle_root: String::new(),
                sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
            }).collect::<Vec<_>>();
        let overdue = |now_ms: i64| crate::parts::levels::l0_merge_overdue_ms(l0_since_roll(now_ms).iter(), now_ms, &policy);
        // Shortly after the roll the catch-up keeps the cell: merges wait.
        let early = roll_ms + 5 * 60_000;
        assert!(overdue(early) < PREVALENCE_L0_YIELD_MS, "{}", overdue(early));
        assert!(!l0_merges_run_beside_prevalence(overdue(early)));
        // Never past the bound: from there on merges run beside it, before
        // l0_merge_overdue warns (15 min).
        let bound = (roll_ms..).step_by(1_000).find(|now| l0_merges_run_beside_prevalence(overdue(*now))).unwrap();
        assert!(overdue(bound) < 15 * 60_000, "merges resume before the warn threshold");
        // tenant-a's sample at 16:12Z (1,795 s overdue) runs merges.
        let sampled = roll_ms + 35 * 60_000;
        assert!(overdue(sampled) >= 1_795_000 - 120_000, "{}", overdue(sampled));
        assert!(l0_merges_run_beside_prevalence(overdue(sampled)));
        assert!(!l0_merges_run_beside_prevalence(0), "an idle tenant never forces a merge");
    }

    /// NAN-3852 stand-in: a sanctioned task in flight with a live receipted
    /// delete counter; its report (the same deletes) arrives only at the end.
    #[derive(Default)]
    struct LiveCountGate {
        live: std::sync::atomic::AtomicU64,
        report: std::sync::Mutex<Option<u64>>,
    }

    #[async_trait::async_trait]
    impl PartGcAuthority for LiveCountGate {
        async fn decision(&self, _now_ms: i64) -> Result<PartGcDecision> {
            Ok(PartGcDecision::Blocked("test_gate_closed"))
        }
        async fn poll_report(&self, _now_ms: i64) -> Option<Result<crate::lake_part_gc::PassReport>> {
            let deleted = self.report.lock().unwrap().take()?;
            Some(Ok(crate::lake_part_gc::PassReport { deleted, ..Default::default() }))
        }
        fn deleted_total(&self) -> Option<u64> {
            Some(self.live.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    /// NAN-3852 (the load-test tenant, 10-14): the GC log said `deleted_total 26` while
    /// `lake_part_gc_deleted_total` stayed 0 until the hour-long task ended.
    /// The metric follows the live count, and the task's final report (the
    /// same deletes) never double counts them.
    #[tokio::test]
    async fn gc_deleted_metric_follows_an_in_flight_pass_without_double_counting() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        use std::sync::atomic::Ordering;
        let now = 1_800_000_000_000;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c2";
        let store = LocalObjectStore::new(root.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("gc-metric-test", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut cfg = IngestConfig::new(tenant, root.path().join("ingest"));
        cfg.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        let gate = Arc::new(LiveCountGate::default());
        ingestor.set_part_gc_authority(gate.clone());
        ingestor.gc(now).await.unwrap();
        assert_eq!(ingestor.health().part_gc_deleted_total, 0);
        gate.live.store(26, Ordering::SeqCst);
        ingestor.gc(now + 1_000).await.unwrap();
        assert_eq!(ingestor.health().part_gc_deleted_total, 26, "in-flight deletes are visible");
        gate.live.store(410, Ordering::SeqCst);
        *gate.report.lock().unwrap() = Some(410);
        ingestor.gc(now + 2_000).await.unwrap();
        assert_eq!(ingestor.health().part_gc_deleted_total, 410, "the final report is the same 410 deletes");
        ingestor.gc(now + 3_000).await.unwrap();
        assert_eq!(ingestor.health().part_gc_deleted_total, 410);
        // A later task: live and reported both advance; still no double count.
        gate.live.store(500, Ordering::SeqCst);
        *gate.report.lock().unwrap() = Some(90);
        ingestor.gc(now + 4_000).await.unwrap();
        assert_eq!(ingestor.health().part_gc_deleted_total, 500);
    }

    thread_local! {
        pub(super) static COUNT_WRITER_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    /// A sealed single `h` part of `hour` inside a 7-day window ending at `now`.
    fn sealed_hour_part(hour: i32, created_ms: i64) -> PartRef {
        let start_us = i64::from(hour) * crate::parts::HOUR_US;
        PartRef {
            part_id: crate::parts::format::PartId::new(created_ms).unwrap(), level: Level::Hour,
            event_hour: hour, event_day: None, rows: 1_000_000,
            min_time_us: start_us, max_time_us: start_us + crate::parts::HOUR_US - 1,
            schema_fingerprint: String::new(), provenance_sha256: "0".repeat(64), merkle_root: String::new(),
            sorted: true, data_bytes: 100, row_groups: 1, data_files: 1,
        }
    }

    async fn backfill_ingestor<'a>(root: &Path, tenant: &str, store: &'static crate::parts::part_log::LocalObjectStore,
        signer: &'a crate::parts::provenance::LocalPartSigner, queue: &'a super::super::discovery::SpoolQueue, now: i64) -> Ingestor<'a> {
        let mut cfg = IngestConfig::new(tenant, root.join("ingest"));
        cfg.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(cfg, store, store, queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        ingestor.set_background_store(store);
        ingestor.queue_count_backfill(super::super::reindex::CountBackfill { start_ms: now - 7 * 86_400_000, end_ms: now }, now, true).await.unwrap();
        ingestor
    }

    async fn settle_fetch(ingestor: &mut Ingestor<'_>) {
        if let Some((_, handle)) = &ingestor.reindex_fetch {
            while !handle.is_finished() { tokio::task::yield_now().await; }
        }
    }

    /// NAN-3772: a failed probe/fetch is retried with backoff while the rest
    /// of the window proceeds, and given up only after repeated failures.
    #[tokio::test]
    async fn count_backfill_retries_a_failed_part_with_backoff() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        COUNT_WRITER_OVERRIDE.with(|value| value.set(Some(true)));
        let now = 1_800_000_000_000_i64;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c2";
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new("backfill-retry", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut ingestor = backfill_ingestor(root.path(), tenant, store, &signer, &queue, now).await;
        let hour = (now / 3_600_000) as i32 - 3;
        // Neither part exists in the store: every probe fails.
        let newer = sealed_hour_part(hour, now - 10);
        let older = sealed_hour_part(hour - 1, now - 20);
        let live = vec![newer.clone(), older.clone()];
        assert!(ingestor.next_reindex(&live, now, true).await.is_none());
        assert_eq!(ingestor.reindex_fetch.as_ref().unwrap().0.event_hour, hour, "newest first");
        settle_fetch(&mut ingestor).await;
        assert!(ingestor.next_reindex(&live, now + 1, true).await.is_none());
        assert_eq!(ingestor.coverage_retry.get(&hour).map(|(n, _)| *n), Some(1));
        assert!(!ingestor.reindexed_hours.contains(&hour), "one failure never strands an hour");
        assert_eq!(ingestor.health.coverage_failures_total, 1);
        // The rest of the window proceeds while the failed hour backs off.
        assert_eq!(ingestor.reindex_fetch.as_ref().unwrap().0.event_hour, hour - 1);
        settle_fetch(&mut ingestor).await;
        assert!(ingestor.next_reindex(&live, now + 2, true).await.is_none());
        assert!(ingestor.reindex_fetch.is_none(), "both hours back off");
        assert_eq!(ingestor.health.coverage_parts_retrying, 2);
        // After its backoff the hour is probed again, with a longer backoff.
        let mut at = now + 2 + super::super::reindex::coverage_retry_backoff_ms(1);
        assert!(ingestor.next_reindex(&live, at, true).await.is_none());
        assert_eq!(ingestor.reindex_fetch.as_ref().unwrap().0.event_hour, hour);
        for failures in 1..super::super::reindex::MAX_COVERAGE_ATTEMPTS {
            settle_fetch(&mut ingestor).await;
            // Retire the older hour's retries from this test's timeline.
            ingestor.coverage_retry.insert(hour - 1, (1, i64::MAX));
            assert!(ingestor.next_reindex(&live, at + 1, true).await.is_none());
            if failures + 1 < super::super::reindex::MAX_COVERAGE_ATTEMPTS {
                assert_eq!(ingestor.coverage_retry.get(&hour).map(|(n, _)| *n), Some(failures + 1));
                at = ingestor.coverage_retry[&hour].1;
                assert!(ingestor.next_reindex(&live, at, true).await.is_none());
            }
        }
        assert!(ingestor.reindexed_hours.contains(&hour), "given up after repeated failures");
        assert_eq!(ingestor.health.coverage_parts_failed, 1);
        COUNT_WRITER_OVERRIDE.with(|value| value.set(None));
    }

    /// NAN-3801 r52: tenant-a's admitted window (243 sealed hour parts) made no
    /// progress in 42 min: 48 probes failed "export object range exceeds
    /// budget" (4-8 MiB count-hint footers / >4 MiB count column chunks vs
    /// the S3 store's 4 MiB GET) and 5 "entity counts dropped" (spill dir
    /// missing). This drives the real scheduler over a tenant-a-shaped backlog on
    /// a simulated clock: every probe takes the observed probe cadence plus
    /// the hour's counts-only cost (fetch + scan at the pace floor). With
    /// the failures the window never completes (hours are given up after
    /// MAX_COVERAGE_ATTEMPTS); with every probe succeeding it converges, one
    /// probe per hour, within a bounded time.
    #[tokio::test]
    async fn b12_count_backlog_converges_once_probes_succeed() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        COUNT_WRITER_OVERRIDE.with(|value| value.set(Some(true)));
        // tenant-a (r52 cell log): ~6.27M rows/day -> ~261k rows per hour on
        // average, diurnal 0.5x-1.5x; probes ~20 s apart (provenance, footer
        // and record reads plus the ingest tick).
        const HOURS: i32 = 243;
        const PROBE_MS: i64 = 20_000;
        const MEAN_ROWS: u64 = 261_000;
        // Counts-only cost per row: ~3 us of decode + builder in release,
        // x10 at the pace floor (share 100 permille); ~40 count-column bytes
        // per row fetched at 8 MB/s over capped 4 MiB GETs.
        const SCAN_US_PER_ROW_AT_FLOOR: f64 = 30.0;
        const FETCH_BYTES_PER_ROW: f64 = 40.0;
        const FETCH_BYTES_PER_S: f64 = 8.0e6;
        let rows_of = |hour: i32| (MEAN_ROWS as f64 * (1.0 + 0.5 * (f64::from(hour % 24) / 24.0 * std::f64::consts::TAU).sin())) as u64;
        let cost_ms = |hour: i32| {
            let rows = rows_of(hour) as f64;
            PROBE_MS + (rows * SCAN_US_PER_ROW_AT_FLOOR / 1_000.0 + rows * FETCH_BYTES_PER_ROW / FETCH_BYTES_PER_S * 1_000.0) as i64
        };
        let now = 1_800_000_000_000_i64;
        let newest = (now / 3_600_000) as i32 - 2;
        let live = (0..HOURS).map(|i| {
            let mut part = sealed_hour_part(newest - i, now - 1_000 - i64::from(i));
            part.rows = rows_of(newest - i);
            part
        }).collect::<Vec<_>>();
        let live = &live;
        // Bugged: ~1 in 5 hours fails every attempt (r52: 53 failed probes in 42 min).
        let failing = |hour: i32| hour % 5 == 0;
        let run = |fixed: bool, seed: u8| async move {
            let root = tempfile::tempdir().unwrap();
            let tenant = "00000000-0000-4000-8000-0000000000c9";
            let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.path().join("store")).unwrap()));
            let signer = LocalPartSigner::new("backfill-converge", ed25519_dalek::SigningKey::from_bytes(&[seed; 32])).unwrap();
            let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
            let mut ingestor = backfill_ingestor(root.path(), tenant, store, &signer, &queue, now).await;
            ingestor.queue_count_backfill(super::super::reindex::CountBackfill { start_ms: now - 11 * 86_400_000, end_ms: now }, now, true).await.unwrap();
            let (mut at, mut probes) = (now, 0_u32);
            let deadline = now + 24 * 3_600_000;
            while at < deadline {
                assert!(ingestor.next_reindex(live, at, true).await.is_none(), "counts-only never plans a rewrite");
                let health = &ingestor.health;
                if health.coverage_parts_current + health.coverage_parts_failed == HOURS as usize { break; }
                match ingestor.reindex_fetch.take() {
                    Some((part, real)) => {
                        real.abort();
                        let hour = part.event_hour;
                        let outcome = !fixed && failing(hour);
                        ingestor.reindex_fetch = Some((part, tokio::spawn(async move {
                            if outcome { Err(anyhow::anyhow!("export object range exceeds budget")) } else { Ok(None) }
                        })));
                        settle_fetch(&mut ingestor).await;
                        probes += 1;
                        at += if outcome { PROBE_MS } else { cost_ms(hour) };
                    }
                    // Nothing due (every remaining hour backing off): next tick.
                    None => at += 5_000,
                }
            }
            (ingestor.health.clone(), at - now, probes)
        };
        let (bugged, bugged_ms, _) = run(false, 9).await;
        assert!(bugged.coverage_parts_current < HOURS as usize, "the failing hours never become current");
        assert!(bugged.coverage_parts_failed > 0, "they are given up after repeated failures");
        let (fixed, fixed_ms, probes) = run(true, 10).await;
        assert_eq!(fixed.coverage_parts_current, HOURS as usize, "every hour in the window becomes current");
        assert_eq!((fixed.coverage_parts_failed, fixed.coverage_parts_retrying), (0, 0));
        assert_eq!(probes, HOURS as u32, "one probe per hour: no re-probes, no wasted slots");
        let modelled_ms = (0..HOURS).map(|i| cost_ms(newest - i)).sum::<i64>();
        assert!(fixed_ms <= modelled_ms + 5_000 * i64::from(HOURS), "the scheduler adds at most a tick per hour");
        println!("tenant-a count backlog: {HOURS} hours converge in {:.1} h ({:.0} s/hour); bugged run: {} current, {} given up after {:.1} h",
            fixed_ms as f64 / 3.6e6, fixed_ms as f64 / 1e3 / f64::from(HOURS), bugged.coverage_parts_current, bugged.coverage_parts_failed, bugged_ms as f64 / 3.6e6);
        assert!(fixed_ms < 3 * 3_600_000, "tenant-a's window drains within 3 h: {:.1} h", fixed_ms as f64 / 3.6e6);
        COUNT_WRITER_OVERRIDE.with(|value| value.set(None));
    }

    /// NAN-3772: a failed count rewrite (e.g. a store timeout) backs off and
    /// is re-planned, and the next part's probe runs beside a rewrite.
    #[tokio::test]
    async fn count_backfill_rewrite_failure_is_retried_and_next_part_prefetches() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        COUNT_WRITER_OVERRIDE.with(|value| value.set(Some(true)));
        let now = 1_800_000_000_000_i64;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c3";
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new("backfill-rewrite", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut ingestor = backfill_ingestor(root.path(), tenant, store, &signer, &queue, now).await;
        let hour = (now / 3_600_000) as i32 - 3;
        let running = sealed_hour_part(hour, now - 10);
        let next = sealed_hour_part(hour - 1, now - 20);
        let live = vec![running.clone(), next.clone()];
        // A rewrite of `running` is in flight (stale, local).
        ingestor.index_current.insert(running.part_id.clone(), false);
        let (fail, failed) = tokio::sync::oneshot::channel::<()>();
        ingestor.merge_in_flight.push(InFlightMerge {
            merge: crate::parts::levels::PlannedMerge { output_level: Level::Hour, event_hour: hour, inputs: vec![running.clone()] },
            key: ("h".into(), hour), started_ms: now, last_warn_ms: now, restamp: None,
            handle: tokio::spawn(async move {
                let _ = failed.await;
                Err(anyhow::anyhow!("compaction remote transfer timed out; lane released"))
            }),
        });
        // Beside it, the next part is probed (never the running one) but
        // its rewrite is withheld until the lane frees.
        assert!(ingestor.next_reindex(&live, now, false).await.is_none());
        assert_eq!(ingestor.reindex_fetch.as_ref().unwrap().0.part_id, next.part_id);
        ingestor.reindex_fetch = Some((next.clone(), tokio::spawn(async { Ok(Some((PathBuf::new(), "test".to_string()))) })));
        settle_fetch(&mut ingestor).await;
        assert!(ingestor.next_reindex(&live, now + 1, false).await.is_none());
        assert_eq!(ingestor.reindex_ready.as_ref().unwrap().part_id, next.part_id);
        assert_eq!(ingestor.health.coverage_rewrite_in_flight.as_ref().unwrap().event_hour, hour);
        // The running rewrite fails: backoff, not stranded.
        fail.send(()).unwrap();
        while !ingestor.merge_in_flight[0].handle.is_finished() { tokio::task::yield_now().await; }
        ingestor.run_background_merge(Vec::new(), now + 2, 0).await;
        assert!(ingestor.merge_in_flight.is_empty());
        assert_eq!(ingestor.coverage_retry.get(&hour).map(|(n, _)| *n), Some(1));
        assert_eq!(ingestor.health.coverage_failures_total, 1);
        assert!(!ingestor.reindexed_hours.contains(&hour));
        // The prefetched part launches without another probe.
        let plan = ingestor.next_reindex(&live, now + 3, true).await.unwrap();
        assert_eq!(plan.inputs[0].part_id, next.part_id);
        // After its backoff the failed hour is planned again.
        let at = ingestor.coverage_retry[&hour].1;
        assert!(ingestor.next_reindex(&live, at, true).await.is_none());
        assert_eq!(ingestor.reindex_fetch.as_ref().unwrap().0.part_id, running.part_id);
        ingestor.reindex_fetch = Some((running.clone(), tokio::spawn(async { Ok(Some((PathBuf::new(), "test".to_string()))) })));
        settle_fetch(&mut ingestor).await;
        let plan = ingestor.next_reindex(&live, at + 1, true).await.unwrap();
        assert_eq!(plan.inputs[0].part_id, running.part_id);
        COUNT_WRITER_OVERRIDE.with(|value| value.set(None));
    }

    /// NAN-3801 (production, 2026-10-15 10:10Z): every flush's prevalence apply
    /// overran the ingest wait, so `run_merges` deferred on every tick with
    /// an empty admission buffer and every other tick had rows buffered. The
    /// count backfill (in-window hours unknown, two unsealed hours owed a
    /// restamp) must keep probing through both, without planning a rewrite.
    #[tokio::test]
    async fn count_backfill_probes_advance_while_prevalence_pending_and_rows_buffered() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        COUNT_WRITER_OVERRIDE.with(|value| value.set(Some(true)));
        let now = 1_800_000_000_000_i64;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c5";
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new("backfill-prevalence", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut ingestor = backfill_ingestor(root.path(), tenant, store, &signer, &queue, now).await;
        ingestor.cfg.background_merges = true;
        let now_hour = (now / 3_600_000) as i32;
        let fingerprint = ingestor.log.live().schema().unwrap().fingerprint.clone();
        // A sealed hour enters the log as its L0 flush, then the hour seal.
        async fn seal(ingestor: &mut Ingestor<'_>, tenant: &str, fingerprint: &str, hour: i32, created_ms: i64, name: &str) -> PartRef {
            let mut part = sealed_hour_part(hour, created_ms);
            part.schema_fingerprint = fingerprint.to_owned();
            part.merkle_root = "0".repeat(64);
            let mut l0 = sealed_hour_part(hour, created_ms - 100_000);
            l0.level = Level::L0;
            l0.schema_fingerprint = fingerprint.to_owned();
            l0.merkle_root = "0".repeat(64);
            ingestor.log.append(LogOp::Add { parts: vec![l0.clone()], consumed: vec![nan3781_source(tenant, name)], edge_log: None }, created_ms).await.unwrap();
            ingestor.log.append(LogOp::Merge { output: part.clone(), supersedes: vec![l0.part_id] }, created_ms).await.unwrap();
            part
        }
        let hours = [now_hour - 3, now_hour - 4, now_hour - 5, now_hour - 6];
        let mut parts = Vec::new();
        for (i, hour) in hours.iter().enumerate() {
            parts.push(seal(&mut ingestor, tenant, &fingerprint, *hour, now - 1_000 - i as i64, &format!("nan3801-{i}")).await);
        }
        // Production case: hours 497793/497794 (current, unsealed) owed a restamp.
        ingestor.prevalence_owed.mark([now_hour - 1, now_hour]);
        let mut at = now;
        for (step, part) in parts.iter().enumerate() {
            // Odd steps: prevalence pending, buffer empty (a flush tick).
            // Even steps: prevalence caught up, rows buffered (any other tick).
            let (pending, buffered) = if step % 2 == 1 { (true, 0) } else { (false, 1) };
            ingestor.prevalence_pending = pending;
            ingestor.buffer.rows = buffered;
            assert_eq!(ingestor.run_merges(at, 0).await, 0, "no merge runs");
            let (probed, real) = ingestor.reindex_fetch.take().unwrap_or_else(|| panic!("step {step}: no probe started"));
            assert_eq!(probed.part_id, part.part_id, "newest unknown hour first");
            real.abort();
            ingestor.reindex_fetch = Some((probed, tokio::spawn(async { Ok(None) })));
            settle_fetch(&mut ingestor).await;
            at += 20_000;
        }
        // The last probe is reaped on the next (deferred) tick.
        ingestor.prevalence_pending = true;
        ingestor.buffer.rows = 0;
        ingestor.run_merges(at, 0).await;
        assert!(ingestor.merge_in_flight.is_empty() && ingestor.reindex_ready.is_none(), "probes never plan a rewrite");
        assert_eq!(ingestor.health.coverage_parts_current, hours.len(), "every in-window hour became current");
        assert_eq!(ingestor.health.coverage_parts_unknown, 0);
        assert!(ingestor.reindex_fetch.is_none());
        assert_eq!(ingestor.prevalence_owed_hours(), vec![now_hour - 1, now_hour], "the restamp debt is untouched");
        // Catching up still holds the probes.
        seal(&mut ingestor, tenant, &fingerprint, now_hour - 7, now - 2_000, "nan3801-late").await;
        let catching_up = ingestor.cfg.merge_policy.hour_seal_ms + 1;
        ingestor.run_merges(at + 1, catching_up).await;
        assert!(ingestor.reindex_fetch.is_none(), "no probe while catching up");
        assert_eq!(ingestor.health.coverage_parts_unknown, 1, "status stays current");
        COUNT_WRITER_OVERRIDE.with(|value| value.set(None));
    }

    /// r49b hour 497754: a part still uncovered after this process rewrote
    /// it is terminal (the same writer yields the same part) and health says
    /// why, instead of a bare "failed" with zero failures counted.
    #[tokio::test]
    async fn count_rewrite_that_stays_uncovered_reports_a_terminal_reason() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        COUNT_WRITER_OVERRIDE.with(|value| value.set(Some(true)));
        let now = 1_800_000_000_000_i64;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c4";
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(root.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new("backfill-terminal", ed25519_dalek::SigningKey::from_bytes(&[8; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut ingestor = backfill_ingestor(root.path(), tenant, store, &signer, &queue, now).await;
        let hour = (now / 3_600_000) as i32 - 3;
        let rewritten = sealed_hour_part(hour, now - 10);
        let live = vec![rewritten.clone()];
        ingestor.count_backfill_attempts.insert(hour);
        assert!(ingestor.next_reindex(&live, now, true).await.is_none());
        assert_eq!(ingestor.reindex_fetch.as_ref().unwrap().0.part_id, rewritten.part_id);
        let why = "entity-ranges footer is 9000000 bytes, over the 8388608 byte count-hint cap";
        ingestor.reindex_fetch = Some((rewritten.clone(), tokio::spawn(async move { Ok(Some((PathBuf::new(), why.to_string()))) })));
        settle_fetch(&mut ingestor).await;
        assert!(ingestor.next_reindex(&live, now + 1, true).await.is_none(), "never rewritten again");
        assert!(ingestor.reindexed_hours.contains(&hour));
        assert_eq!(ingestor.health.coverage_parts_failed, 1);
        assert_eq!(ingestor.health.coverage_failures_total, 1);
        assert_eq!(ingestor.health.coverage_failed_hours.len(), 1);
        assert_eq!(ingestor.health.coverage_failed_hours[0].event_hour, hour);
        assert!(ingestor.health.coverage_failed_hours[0].reason.contains(why), "{:?}", ingestor.health.coverage_failed_hours);
        // A new window starts the hour over.
        ingestor.queue_count_backfill(ingestor.count_backfill.clone().unwrap(), now + 2, true).await.unwrap();
        assert!(ingestor.coverage_given_up.is_empty());
        COUNT_WRITER_OVERRIDE.with(|value| value.set(None));
    }

    /// r49b: a ZDR handover starts the new pod with an EMPTY work dir. The
    /// admitted window must come back from the tenant bucket alone, the newest
    /// admission wins, and another tenant never sees it.
    #[tokio::test]
    async fn count_backfill_window_survives_a_handover_to_an_empty_work_dir() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        let now = 1_800_000_000_000;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c2";
        let other = "00000000-0000-4000-8000-0000000000c3";
        let store = LocalObjectStore::new(root.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("handover-test", ed25519_dalek::SigningKey::from_bytes(&[8; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let seed = seed_schema();
        let open = |work: &str, at: i64| {
            let mut cfg = IngestConfig::new(tenant, root.path().join(work));
            cfg.prevalence_enabled = false;
            Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(), BronzeIngestEnricher::disabled(), &seed, at)
        };
        let old = super::super::reindex::CountBackfill { start_ms: now - 7 * 86_400_000, end_ms: now };
        let newer = super::super::reindex::CountBackfill { start_ms: now - 3 * 86_400_000, end_ms: now };
        {
            let mut before = open("pod-a", now).await.unwrap();
            assert!(before.health().count_backfill_window.is_none());
            before.queue_count_backfill(old.clone(), now, true).await.unwrap();
            before.queue_count_backfill(newer.clone(), now + 1, true).await.unwrap();
            // Re-admitting the same window at the same instant is idempotent.
            before.queue_count_backfill(newer.clone(), now + 1, true).await.unwrap();
        }
        assert!(!root.path().join("pod-b").exists());
        let after = open("pod-b", now + 2).await.unwrap();
        let restored = after.health().count_backfill_window.clone().expect("window survives the handover");
        assert_eq!((restored.start_ms, restored.end_ms), (newer.start_ms, newer.end_ms));
        assert!(after.count_backfill.is_some());
        assert!(load_count_backfill(&store, other, &root.path().join("pod-c"), now).await.unwrap().is_none());
        // A record whose bytes differ from its name is skipped, never trusted.
        let forged = serde_json::to_vec(&old).unwrap();
        let key = format!("{}{:013}-{}.json", count_backfill_prefix(tenant).unwrap(), now + 9, "0".repeat(16));
        assert!(store.put_if_absent(&key, &forged).await.unwrap());
        let still = load_count_backfill(&store, tenant, &root.path().join("pod-d"), now).await.unwrap().unwrap();
        assert_eq!(still.start_ms, newer.start_ms);
    }

    /// The old pod-local file (pre-durable images) is moved into the bucket
    /// the first time it is seen, so the following handover keeps it.
    #[tokio::test]
    async fn count_backfill_local_window_is_moved_to_the_bucket() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::parts::part_log::LocalObjectStore::new(root.path().join("store")).unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c4";
        let work = root.path().join("pod-a");
        std::fs::create_dir(&work).unwrap();
        let window = super::super::reindex::CountBackfill { start_ms: 1, end_ms: 2 };
        std::fs::write(work.join(LOCAL_COUNT_BACKFILL_FILE), serde_json::to_vec(&window).unwrap()).unwrap();
        let restored = load_count_backfill(&store, tenant, &work, 1_800_000_000_000).await.unwrap().unwrap();
        assert_eq!((restored.start_ms, restored.end_ms), (1, 2));
        let empty = root.path().join("pod-b");
        let moved = load_count_backfill(&store, tenant, &empty, 1_800_000_000_001).await.unwrap().unwrap();
        assert_eq!((moved.start_ms, moved.end_ms), (1, 2));
        // Checkpoint discovery ignores the record.
        let prefix = LogKeys::new(tenant).unwrap().checkpoints_prefix();
        assert!(store.list(&prefix).await.unwrap().iter().all(|key| !crate::parts::part_log::is_snapshot_checkpoint_key(key)));
    }

    #[tokio::test]
    async fn lake_part_gc_retention_retires_only_expired_parts_idempotently() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        use crate::lake_part_gc::{local::LocalDeleteAuthority, GcPolicy};
        const TENANT: &str = "00000000-0000-4000-8000-0000000000c1";
        let now = 1_800_000_000_000_i64;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path().join("store")).unwrap());
        let signer = LocalPartSigner::new("local-retention-test", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(cfg, &*store, &*store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        let fingerprint = ingestor.log.live().schema().unwrap().fingerprint.clone();
        let part = |at: i64| PartRef {
            part_id: crate::parts::format::PartId::new(at).unwrap(), level: Level::L0,
            event_hour: (at / 3_600_000) as i32, event_day: None, rows: 1,
            min_time_us: at * 1000, max_time_us: at * 1000,
            schema_fingerprint: fingerprint.clone(), provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64), sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
        };
        let expired = part(now - 2 * 86_400_000);
        let recent = part(now - 1000);
        ingestor.log.append(LogOp::Add { parts: vec![expired, recent.clone()], consumed: vec![crate::parts::part_log::SourceRef { key: format!("tenant_id={TENANT}/logs/fixture.parquet"), version: "v1".into(), sha256: "0".repeat(64) }], edge_log: None }, now).await.unwrap();
        let disabled = LocalDeleteAuthority::new(store.clone(), TENANT, signer.trusted(), GcPolicy::default(), None).unwrap();
        ingestor.retire_local_expired(&disabled, now).await.unwrap();
        assert_eq!(ingestor.log.live().parts().count(), 2);
        let enabled = LocalDeleteAuthority::new(store.clone(), TENANT, signer.trusted(), GcPolicy {
            retention_days: Some(1), ..Default::default()
        }, None).unwrap();
        ingestor.retire_local_expired(&enabled, now).await.unwrap();
        let remaining: Vec<_> = ingestor.log.live().parts().map(|p| p.part_id.clone()).collect();
        assert_eq!(remaining, vec![recent.part_id]);
        let head = ingestor.log.live().head().unwrap().0;
        ingestor.retire_local_expired(&enabled, now).await.unwrap();
        assert_eq!(ingestor.log.live().head().unwrap().0, head);
    }

    /// NAN-3781 fixtures: an ingestor with a local prevalence state on a
    /// local part store, and a fake L0 part (no files in the store).
    async fn nan3781_ingestor<'a>(dir: &Path, store: &'a crate::parts::part_log::LocalObjectStore,
        signer: &'a crate::parts::provenance::LocalPartSigner, queue: &'a super::super::discovery::SpoolQueue,
        tenant: &str, now: i64) -> Ingestor<'a> {
        let cfg = IngestConfig::new(tenant, dir.join("ingest"));
        Ingestor::open(cfg, store, store, queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap()
    }

    fn nan3781_part(fingerprint: &str, at: i64) -> PartRef {
        PartRef {
            part_id: crate::parts::format::PartId::new(at).unwrap(), level: Level::L0,
            event_hour: (at / 3_600_000) as i32, event_day: None, rows: 1,
            min_time_us: at * 1000, max_time_us: at * 1000,
            schema_fingerprint: fingerprint.into(), provenance_sha256: "0".repeat(64),
            merkle_root: "0".repeat(64), sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
        }
    }

    fn nan3781_source(tenant: &str, name: &str) -> crate::parts::part_log::SourceRef {
        crate::parts::part_log::SourceRef {
            key: format!("tenant_id={tenant}/logs/{name}.parquet"), version: "v1".into(), sha256: "0".repeat(64),
        }
    }

    /// NAN-3873 (tenant-a, staging 10-14): an owner roll failed one of the
    /// state's background writes; SlateDB closed the DB on that error and
    /// answered every later call with it, without any I/O. The ingestor kept
    /// retrying the dead handle for 40 min (and NAN-3849's in-place refresh
    /// kept it open). A store-closed state is now dropped and reopened, and
    /// stamping resumes without a restart.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_state_closed_by_the_store_is_reopened_and_stamping_resumes() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        const TENANT: &str = "00000000-0000-4000-8000-000000003873";
        let now = 1_800_000_000_000_i64;
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("nan3873-closed", ed25519_dalek::SigningKey::from_bytes(&[73; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut ingestor = nan3781_ingestor(dir.path(), &store, &signer, &queue, TENANT, now).await;
        assert_eq!(ingestor.prevalence_status(), "stamping");
        assert!(ingestor.prevalence.as_ref().unwrap().closed().is_none());

        // SlateDB closes the DB under the open state.
        ingestor.prevalence.as_ref().unwrap().close_db_for_test().await;
        assert!(ingestor.prevalence.as_ref().unwrap().closed().is_some());

        // The next tick drops the dead handle instead of retrying it.
        ingestor.tick(now + 1_000).await.unwrap();
        assert!(ingestor.prevalence.is_none(), "a store-closed state is dropped");
        assert!(ingestor.health().prevalence_degraded);

        // After the backoff the state reopens and stamps again.
        let mut at = now + 1_000 + PREVALENCE_RETRY_BASE_MS + 1;
        for _ in 0..10 {
            if ingestor.prevalence.is_some() && ingestor.prevalence_status() == "stamping" {
                break;
            }
            ingestor.tick(at).await.unwrap();
            at += 1_000;
        }
        assert_eq!(ingestor.prevalence_status(), "stamping", "stamping resumes after the reopen");
        assert!(ingestor.prevalence.as_ref().unwrap().closed().is_none(), "the reopened writer is live");
    }

    /// NAN-3781 (CT 106 train 3 lab): while the state was unavailable, an
    /// `Add` committed and its part was later superseded and deleted. On the
    /// next open catch-up met that `Add`, its partial was gone ("live
    /// prevalence partial is missing" twice a second, forever) and stamping
    /// never resumed. Now the gap resets the state and rebuilds it from the
    /// live set: stamping resumes and nothing from the old state survives
    /// (no double counting).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replayed_part_merged_away_during_a_stall_resets_and_stamping_resumes() {
        use crate::lake_part_gc::{local::LocalDeleteAuthority, GcPolicy};
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        const TENANT: &str = "00000000-0000-4000-8000-0000000037a1";
        let now = 1_800_000_000_000_i64;
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(LocalObjectStore::new(dir.path().join("store")).unwrap());
        let signer = LocalPartSigner::new("nan3781-gap", ed25519_dalek::SigningKey::from_bytes(&[37; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut ingestor = nan3781_ingestor(dir.path(), &store, &signer, &queue, TENANT, now).await;
        assert_eq!(ingestor.prevalence_status(), "stamping", "an empty tenant stamps at once");
        // Counts the old state holds (they must not survive the rebuild).
        ingestor.prevalence.as_mut().unwrap().write_test_wals(1).await.unwrap();

        // The stall: an Add commits that the state never applies (straight
        // to the log, as while the state was unavailable), then its part is
        // superseded and deleted (retired here; its files never existed).
        let fingerprint = ingestor.log.live().schema().unwrap().fingerprint.clone();
        let gone = nan3781_part(&fingerprint, now - 2 * 86_400_000);
        ingestor.log.append(LogOp::Add { parts: vec![gone.clone()], consumed: vec![nan3781_source(TENANT, "gap")],
            edge_log: None }, now).await.unwrap();
        let retire = LocalDeleteAuthority::new(store.clone(), TENANT, signer.trusted(), GcPolicy {
            retention_days: Some(1), ..Default::default()
        }, None).unwrap();
        ingestor.retire_local_expired(&retire, now).await.unwrap();
        assert!(ingestor.log.live().get(&gone.part_id).is_none(), "the stalled window's part is no longer live");
        ingestor.prevalence.take().unwrap().close().await.unwrap();
        drop(ingestor);

        // Reopen: catch-up meets the gap, resets, and stamps again.
        let mut ingestor = nan3781_ingestor(dir.path(), &store, &signer, &queue, TENANT, now + 1_000).await;
        let mut at = now + 2_000;
        for _ in 0..10 {
            if ingestor.prevalence_status() == "stamping" {
                break;
            }
            ingestor.tick(at).await.unwrap();
            at += 1_000;
        }
        assert_eq!(ingestor.prevalence_status(), "stamping", "stamping resumes after the reset");
        assert!(!ingestor.prevalence_pending());
        let state = ingestor.prevalence.as_ref().unwrap();
        assert!(!state.reset_pending());
        assert!(!state.has_test_key(0).await, "the reset emptied the old state before the rebuild");
        assert!(!ingestor.health().prevalence_degraded);
    }

    /// NAN-3781: a held state whose every catch-up step fails (here a live
    /// part's partial is missing, which is not a replay gap) stamps nothing:
    /// after a minute it is degraded, with an ERROR, though the state is open.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_catch_up_that_keeps_failing_is_degraded() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        const TENANT: &str = "00000000-0000-4000-8000-0000000037a2";
        let now = 1_800_000_000_000_i64;
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("nan3781-stuck", ed25519_dalek::SigningKey::from_bytes(&[38; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut ingestor = nan3781_ingestor(dir.path(), &store, &signer, &queue, TENANT, now).await;
        let fingerprint = ingestor.log.live().schema().unwrap().fingerprint.clone();
        let live = nan3781_part(&fingerprint, now - 1_000);
        ingestor.log.append(LogOp::Add { parts: vec![live.clone()], consumed: vec![nan3781_source(TENANT, "stuck")],
            edge_log: None }, now).await.unwrap();
        ingestor.prevalence.take().unwrap().close().await.unwrap();
        drop(ingestor);

        let mut ingestor = nan3781_ingestor(dir.path(), &store, &signer, &queue, TENANT, now + 1_000).await;
        assert!(ingestor.log.live().get(&live.part_id).is_some());
        ingestor.tick(now + 2_000).await.unwrap();
        assert_eq!(ingestor.prevalence_status(), "unstamped: catching up with committed adds");
        assert!(!ingestor.health().prevalence_degraded, "one failed step is not yet degraded");
        ingestor.tick(now + 2_000 + PREVALENCE_STEP_FAILING_DEGRADED_MS).await.unwrap();
        assert!(ingestor.prevalence.is_some(), "the state is open, yet stamps nothing");
        assert!(ingestor.health().prevalence_degraded, "a minute of failing steps is degraded");
        let spell = ingestor.health().prevalence_degraded_ms;
        ingestor.tick(now + 2_000 + 2 * PREVALENCE_STEP_FAILING_DEGRADED_MS).await.unwrap();
        assert!(ingestor.health().prevalence_degraded_ms >= spell + PREVALENCE_STEP_FAILING_DEGRADED_MS as u64);
        assert_eq!(ingestor.prevalence_status(), "unstamped: catching up with committed adds",
            "a live part's missing partial is an error, never a reset");
    }

    #[test]
    fn fatal_ingest_classification_survives_context() {
        let errors = [
            anyhow::Error::new(crate::parts::part_log::Fenced { seq: 1 }),
            anyhow::Error::new(crate::edge_log::EdgeLogFenced),
            anyhow::Error::new(crate::parts::part_log::DoubleConsume { key: "test".into() }),
            anyhow::Error::new(super::super::r2_put::TerminalPutError {
                key: "test".into(), status: 403, code: "AccessDenied".into(),
            }),
        ];
        for error in errors {
            assert!(fatal_ingest_error(&error.context("ingest tick")));
        }
        assert!(!fatal_ingest_error(&anyhow::anyhow!("retryable flush failure")));
        // NAN-3181: a held part-log key is an abandoned reservation, not a
        // fence; the owner hands it over after 90 idle seconds.
        let held = anyhow::Error::new(crate::parts::part_log::LogKeyHeld { key: "log/entries/1.json".into() });
        assert!(!fatal_ingest_error(&held.context("ingest tick")));
    }

    #[test]
    fn raw_ingest_strips_reserved_finding_fields_before_part_merge() {
        let mut event = serde_json::json!({"unmapped": {
            "nano_compact_finding": "forged", "nano_finding_outbox_trusted": "v1",
            "user_field": "kept"
        }});
        strip_untrusted_risk_fields(&mut event);
        assert_eq!(event["unmapped"], serde_json::json!({"user_field": "kept"}));
    }

    #[test]
    fn owner_requires_checksum_defaults_off_and_lifts_the_cap_only_when_on() {
        let cfg = IngestConfig::new("t", "/tmp/x");
        assert!(!cfg.owner_requires_checksum);
        assert_eq!(cfg.merge_policy.max_part_bytes, Some(crate::parts::levels::INTERIM_MAX_PART_BYTES));
        let on = IngestConfig::new("t", "/tmp/x").with_owner_requires_checksum(true);
        assert_eq!(on.merge_policy.max_part_bytes, None);
        let off = on.with_owner_requires_checksum(false);
        assert!(off.merge_policy.max_part_bytes.is_some());
    }

    #[test]
    fn prevalence_retry_backoff_doubles_to_a_cap() {
        assert_eq!(prevalence_retry_delay_ms(1), PREVALENCE_RETRY_BASE_MS);
        assert_eq!(prevalence_retry_delay_ms(2), 2 * PREVALENCE_RETRY_BASE_MS);
        assert_eq!(prevalence_retry_delay_ms(3), 4 * PREVALENCE_RETRY_BASE_MS);
        assert_eq!(prevalence_retry_delay_ms(50), PREVALENCE_RETRY_MAX_MS);
    }

    /// A minimal prevalence owner: 403 (`authorize_stale_epoch`) while
    /// `refuse` is set, else a conditional create into `objects`.
    #[derive(Clone)]
    struct Owner {
        objects: Arc<slatedb::object_store::memory::InMemory>,
        refuse: Arc<std::sync::atomic::AtomicBool>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
        /// Accept requests and never answer (a store that never flushes).
        hang: Arc<std::sync::atomic::AtomicBool>,
    }

    async fn owner_mutate(
        axum::extract::State(owner): axum::extract::State<Owner>,
        headers: axum::http::HeaderMap,
        body: axum::body::Bytes,
    ) -> Result<axum::Json<Value>, axum::http::StatusCode> {
        use base64::Engine;
        use slatedb::object_store::{path::Path as StorePath, ObjectStore as _, PutMode};
        use std::sync::atomic::Ordering;
        owner.calls.fetch_add(1, Ordering::SeqCst);
        if owner.hang.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        if owner.refuse.load(Ordering::SeqCst) {
            return Err(axum::http::StatusCode::FORBIDDEN);
        }
        let envelope = headers.get("x-nano-owner-request").and_then(|v| v.to_str().ok())
            .and_then(|v| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v).ok())
            .ok_or(axum::http::StatusCode::BAD_REQUEST)?;
        let mut request: Value = serde_json::from_slice(&envelope).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;
        let key = request["object_key"].as_str().ok_or(axum::http::StatusCode::BAD_REQUEST)?;
        let relative = key.split_once("/db/").map(|(_, rest)| format!("db/{rest}")).ok_or(axum::http::StatusCode::FORBIDDEN)?;
        let path = StorePath::from(relative);
        let put = owner.objects.put_opts(&path, body.to_vec().into(), PutMode::Create.into()).await
            .map_err(|_| axum::http::StatusCode::PRECONDITION_FAILED)?;
        request["result_etag"] = serde_json::json!(put.e_tag.unwrap_or_default());
        request["result_version"] = serde_json::json!(put.version);
        request["completed"] = serde_json::json!(true);
        request["head_verified"] = serde_json::json!(true);
        Ok(axum::Json(request))
    }

    /// a lean test tenant (2026-09-30): the prevalence grant arrived after ingest
    /// started and only took effect after a manual restart (which broke
    /// detect's append stream). A grant arriving on a credential refresh
    /// now opens the state in-process and the next ticks stamp.
    #[tokio::test]
    async fn the_background_reindex_probe_fails_fast_on_a_missing_part() {
        // NAN-3077: the probe runs in its own task with the 'static store and
        // reports a missing or unverifiable part as an error (the tick then
        // skips that hour) instead of blocking anything.
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f3";
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer = LocalPartSigner::new("lab-signer-reindex", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let part = PartRef {
            part_id: crate::parts::format::PartId::new(1_790_000_000_000).unwrap(),
            level: Level::Hour,
            event_hour: 497_222,
            event_day: None,
            rows: 1,
            min_time_us: 0,
            max_time_us: 0,
            schema_fingerprint: String::new(),
            provenance_sha256: "0".repeat(64),
            merkle_root: String::new(),
            sorted: true,
            data_bytes: 1,
            row_groups: 1,
            data_files: 1,
        };
        let task = tokio::spawn(probe_and_fetch_for_reindex(store, TENANT.to_string(), signer.trusted(), dir.path().join("ingest"), part.clone()));
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), task).await.expect("never hangs").unwrap();
        assert!(outcome.unwrap_err().to_string().contains("no provenance"));

        // Even under cache pressure, preserve the pending download and its
        // completed entry until the ingest tick consumes the task result.
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.cache_max_bytes = 0;
        cfg.prevalence_enabled = false;
        let now_ms = 1_800_000_000_000_i64;
        let mut ingestor = Ingestor::open(cfg, store, store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.unwrap();
        let cached = parts_dir(&ingestor.cfg.work_dir).join(part.part_id.as_str());
        let partial = cached.with_extension("partial");
        let unrelated = parts_dir(&ingestor.cfg.work_dir).join("unrelated");
        for path in [&cached, &partial, &unrelated] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("data"), b"cache pressure").unwrap();
        }
        ingestor.reindex_fetch = Some((part, tokio::spawn(async { Ok(Some((PathBuf::new(), "test".to_string()))) })));
        ingestor.evict_cache(now_ms + 60_000).unwrap();
        assert!(cached.exists());
        assert!(partial.exists());
        assert!(!unrelated.exists());
    }

    /// NAN-3183 OOM: the working budget is charged with the flush in flight
    /// at its build cost (rows + build copies + writers) and with every
    /// running merge, not only with buffered rows; a tight budget gives the
    /// next flush fewer parallel part writers (never zero).
    #[tokio::test]
    async fn in_flight_flush_and_merges_count_against_the_working_budget() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use super::super::memory::{flight_bytes, L0_WRITER_BYTES};
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f5";
        const MIB: u64 = 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-signer-mem", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap()));
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.prevalence_enabled = false;
        cfg.buffer_budget_bytes = 4096 * MIB;
        let mut ingestor = Ingestor::open(cfg, store, store, &queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), 1_800_000_000_000).await.unwrap();
        let rows = 200 * MIB;
        ingestor.buffer.bytes = rows;
        assert_eq!(ingestor.committed_bytes(), rows);
        assert_eq!(ingestor.flush_writers(rows), 4, "a roomy budget writes 4 parts at once");
        // Seal it: the flight is charged rows + 2x build + 4 writers.
        let reserved = flight_bytes(rows, 4);
        assert_eq!(reserved, 3 * rows + 4 * L0_WRITER_BYTES);
        ingestor.flush_in_flight.push_back(InFlightFlush {
            buffer: Buffered::new(), reserved_bytes: reserved, schema: ingestor.schema.clone(), sealed_ms: 0, task: None, published: None,
        });
        ingestor.buffer.bytes = 0;
        assert_eq!(ingestor.committed_bytes(), reserved, "the in-flight flush is charged its build, not only its rows");
        // A running merge is charged too.
        ingestor.merge_in_flight.push(InFlightMerge {
            merge: crate::parts::levels::PlannedMerge { output_level: Level::Minute, event_hour: 497_222, inputs: Vec::new() },
            key: ("m".into(), 497_222), started_ms: 0, last_warn_ms: 0, restamp: None,
            handle: tokio::spawn(async { Err(anyhow::anyhow!("never run")) }),
        });
        assert_eq!(ingestor.committed_bytes(), reserved + super::super::merge::merge_reserve_bytes());
        // Admission sees only the room left: a 1 GiB-peak group fits an
        // empty 4 GiB budget but not beside the flight and the merge.
        let heap = 600.0 * MIB as f64;
        assert!(super::super::memory::admission_fits(4096 * MIB, 0, heap, 50.0 * MIB as f64));
        assert!(!super::super::memory::admission_fits(4096 * MIB, ingestor.committed_bytes() + 2048 * MIB, heap, 50.0 * MIB as f64));
        // NAN-3619: a second flush sealed beside a flight in flight (depth 2)
        // must fit its build beside that flight's: here it cannot fit one
        // more writer than the minimum. At depth 1 every flight commits
        // before the next plan, so the writer count below is unchanged.
        ingestor.cfg.buffer_budget_bytes = fits_beside_nothing(rows);
        assert_eq!(ingestor.flush_writers(rows), 1, "a flight in flight leaves room for one writer");
        ingestor.flush_in_flight.clear();
        // Tighter budgets: fewer parallel writers, never zero.
        let merge = super::super::merge::merge_reserve_bytes();
        let writers_at = |ingestor: &mut Ingestor<'_>, budget: u64| {
            ingestor.cfg.buffer_budget_bytes = budget;
            ingestor.flush_writers(rows)
        };
        let fits = |w: usize| {
            // budget b with b - b/5 - merge == flight_bytes(rows, w)
            ((flight_bytes(rows, w) + merge) as f64 / (1.0 - super::super::memory::BUFFER_SHARE_OF_WORKING)).ceil() as u64 + 1
        };
        assert_eq!(writers_at(&mut ingestor, fits(4)), 4);
        assert_eq!(writers_at(&mut ingestor, fits(2)), 2);
        assert_eq!(writers_at(&mut ingestor, fits(1)), 1);
        assert_eq!(writers_at(&mut ingestor, 64 * MIB), 1, "a flush always makes progress");
        for flight in ingestor.merge_in_flight.drain(..) {
            flight.handle.abort();
        }
    }

    /// A budget whose room after the next buffer and one merge fits exactly a
    /// 4-writer build of `rows` (and nothing beside it).
    fn fits_beside_nothing(rows: u64) -> u64 {
        let merge = super::super::merge::merge_reserve_bytes();
        ((super::super::memory::flight_bytes(rows, 4) + merge) as f64
            / (1.0 - super::super::memory::BUFFER_SHARE_OF_WORKING)).ceil() as u64 + 1
    }

    #[tokio::test]
    async fn blocked_compaction_remote_lane_does_not_block_ingest_or_search() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f4";
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-signer-quota", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap()));
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.prevalence_enabled = false;
        cfg.cache_max_bytes = 0;
        let mut ingestor = Ingestor::open(cfg, store, store, &queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), 1_800_000_000_000).await.unwrap();
        ingestor.set_background_store(store);
        ingestor.set_background_signer(signer);
        let part = PartRef {
            part_id: crate::parts::format::PartId::new(1_790_000_000_000).unwrap(),
            level: Level::L0, event_hour: 497_222, event_day: None, rows: 1,
            min_time_us: 0, max_time_us: 0, schema_fingerprint: "0".repeat(64),
            provenance_sha256: "0".repeat(64), merkle_root: "0".repeat(64),
            sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
        };
        let permit = super::super::merge_quota::hold_remote_lane().await;
        let flight = tokio::time::timeout(std::time::Duration::from_secs(1), ingestor.spawn_merge(
            crate::parts::levels::PlannedMerge { output_level: Level::Minute, event_hour: part.event_hour, inputs: vec![part] },
            1_800_000_000_001,
        )).await.expect("admission tick must not wait for a compaction transfer").unwrap();
        tokio::task::yield_now().await;
        assert!(!flight.handle.is_finished(), "the transfer is still blocked");
        // Ingest publication and an interactive object read use the same store
        // while compaction's lane is occupied, without acquiring that lane.
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            assert!(store.put_if_absent("concurrent-event", b"event").await.unwrap());
            assert_eq!(store.get("concurrent-event").await.unwrap().unwrap(), b"event");
        }).await.expect("ingest and query I/O remain independent");
        let partial = parts_dir(&ingestor.cfg.work_dir).join(flight.merge.inputs[0].part_id.as_str()).with_extension("partial");
        let draft = parts_dir(&ingestor.cfg.work_dir).join(crate::parts::format::PartId::new(flight.started_ms).unwrap().as_str());
        for path in [&partial, &draft] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("draft"), b"in-flight output").unwrap();
        }
        ingestor.merge_in_flight.push(flight);
        ingestor.evict_cache(1_800_000_060_000).unwrap();
        assert!(partial.exists());
        assert!(draft.exists());
        let flight = ingestor.merge_in_flight.pop().unwrap();
        flight.handle.abort();
        let _ = flight.handle.await;
        drop(permit);
    }

    #[tokio::test]
    async fn background_scheduler_fills_minute_lanes_during_history_and_catch_up() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use crate::parts::levels::PlannedMerge;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f5";
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-merge-lanes", ed25519_dalek::SigningKey::from_bytes(&[8; 32])).unwrap()));
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.prevalence_enabled = false;
        cfg.background_merges = true;
        // Room for every lane: this pins lane scheduling, not the memory
        // gate (`merges_beyond_the_first_wait_for_working_budget_room`).
        cfg.buffer_budget_bytes = 4 * 1024 * 1024 * 1024;
        let now = 1_800_000_000_000;
        let mut ingestor = Ingestor::open(cfg, store, store, &queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        ingestor.set_background_store(store);
        ingestor.set_background_signer(signer);
        let history = PlannedMerge { output_level: Level::Hour, event_hour: 499_997, inputs: vec![] };
        ingestor.merge_in_flight.push(InFlightMerge {
            merge: history, key: ("h".into(), 499_997), started_ms: now, last_warn_ms: now, restamp: None,
            handle: tokio::spawn(std::future::pending()),
        });
        let planned = [499_999, 500_000, 500_000, 499_997].into_iter().map(|event_hour|
            PlannedMerge { output_level: Level::Minute, event_hour, inputs: vec![] }).collect();
        // Even a nonempty admission buffer and catch-up lag cannot force
        // minute jobs inline or make them wait on the history task.
        ingestor.buffer.rows = 1;
        tokio::time::timeout(std::time::Duration::from_millis(100),
            ingestor.run_background_merge(planned, now, 3_600_000)).await
            .expect("scheduler must not wait on merges");
        assert_eq!(ingestor.merge_in_flight.len(), 3);
        let hours = ingestor.merge_in_flight.iter().map(|f| f.merge.event_hour).collect::<BTreeSet<_>>();
        assert_eq!(hours, BTreeSet::from([499_997, 499_999, 500_000]));
        for flight in ingestor.merge_in_flight.drain(..) {
            flight.handle.abort();
            let _ = flight.handle.await;
        }
    }

    /// NAN-3183 OOM: a merge lane beyond the first starts only when its
    /// reserve fits the working budget beside the buffer and the flight.
    #[tokio::test]
    async fn merges_beyond_the_first_wait_for_working_budget_room() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use crate::parts::levels::PlannedMerge;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f6";
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-merge-gate", ed25519_dalek::SigningKey::from_bytes(&[10; 32])).unwrap()));
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.prevalence_enabled = false;
        cfg.background_merges = true;
        let reserve = super::super::merge::merge_reserve_bytes();
        // Room for one merge beside the buffer, not two.
        cfg.buffer_budget_bytes = 2 * reserve;
        let now = 1_800_000_000_000;
        let mut ingestor = Ingestor::open(cfg, store, store, &queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        ingestor.set_background_store(store);
        ingestor.set_background_signer(signer);
        ingestor.buffer.bytes = 1;
        let planned = || [499_999, 500_000].into_iter().map(|event_hour|
            PlannedMerge { output_level: Level::Minute, event_hour, inputs: vec![] }).collect::<Vec<_>>();
        ingestor.run_background_merge(planned(), now, 3_600_000).await;
        assert_eq!(ingestor.merge_in_flight.len(), 1, "the second lane waits for room");
        for flight in ingestor.merge_in_flight.drain(..) {
            flight.handle.abort();
            let _ = flight.handle.await;
        }
        // With room, both lanes run.
        ingestor.cfg.buffer_budget_bytes = 4 * reserve;
        ingestor.run_background_merge(planned(), now, 3_600_000).await;
        assert_eq!(ingestor.merge_in_flight.len(), 2);
        for flight in ingestor.merge_in_flight.drain(..) {
            flight.handle.abort();
            let _ = flight.handle.await;
        }
    }

    #[tokio::test]
    async fn a_prevalence_grant_arriving_mid_process_applies_without_a_restart() {
        use super::super::discovery::SpoolQueue;
        use super::super::prevalence_owner_store::OwnerAccess;
        use super::super::s3_store::S3Location;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f2";
        let owner = Owner {
            objects: Arc::new(slatedb::object_store::memory::InMemory::new()),
            refuse: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let app = axum::Router::new().route("/mutate", axum::routing::post(owner_mutate)).with_state(owner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        // Started without a grant, like a production exchange without one.
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.writer_epoch = 3;
        cfg.prevalence_enabled = false;
        cfg.prevalence_read_store = Some(owner.objects.clone());
        let t0 = 1_800_000_000_000_i64;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert!(ingestor.prevalence.is_none());
        assert_eq!(ingestor.prevalence_status(), "unstamped: no prevalence grant");

        let access = PrevalenceAccess {
            read: S3Location {
                endpoint: "https://r2.example".into(), region: "auto".into(), bucket: "bucket".into(),
                prefix: format!("lake/prevalence-state/v1/tenant={TENANT}/"),
                access_key_id: "read".into(), secret_access_key: "read".into(), session_token: None,
            },
            owner: OwnerAccess {
                url: format!("http://{address}/mutate"), bearer: "owner-token".into(),
                tenant_id: TENANT.into(), assignment_generation: 2, writer_epoch: 3, expires_at: None,
            },
            owner_ca_file: None,
        };
        ingestor.refresh_prevalence_credential(&access).await.unwrap();
        assert!(ingestor.prevalence.is_some(), "the grant opened the state in-process");
        assert_eq!(ingestor.prevalence_status(), "stamping", "an empty tenant stamps at once");
        assert!(owner.calls.load(std::sync::atomic::Ordering::SeqCst) >= 1, "state writes go through the owner");
        ingestor.tick(t0 + 1_000).await.unwrap();
        assert_eq!(ingestor.prevalence_status(), "stamping");
        assert!(!ingestor.health().prevalence_degraded);
    }

    /// A tenant grant for the NAN-3554 tests (`bearer` distinguishes a
    /// refreshed grant from a retry).
    fn nan3554_access(tenant: &str, address: std::net::SocketAddr, bearer: &str) -> PrevalenceAccess {
        use super::super::prevalence_owner_store::OwnerAccess;
        use super::super::s3_store::S3Location;
        PrevalenceAccess {
            read: S3Location {
                endpoint: "https://r2.example".into(), region: "auto".into(), bucket: "bucket".into(),
                prefix: format!("lake/prevalence-state/v1/tenant={tenant}/"),
                access_key_id: "read".into(), secret_access_key: "read".into(), session_token: None,
            },
            owner: OwnerAccess {
                url: format!("http://{address}/mutate"), bearer: bearer.into(),
                tenant_id: tenant.into(), assignment_generation: 2, writer_epoch: 3, expires_at: None,
            },
            owner_ca_file: None,
        }
    }

    async fn nan3554_owner() -> (Owner, std::net::SocketAddr) {
        let owner = Owner {
            objects: Arc::new(slatedb::object_store::memory::InMemory::new()),
            refuse: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let app = axum::Router::new().route("/mutate", axum::routing::post(owner_mutate)).with_state(owner.clone())
            .layer(axum::extract::DefaultBodyLimit::disable());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (owner, address)
    }

    /// NAN-3554 (the load-test tenant, 2026-10-10): a low-write tenant's memtable never
    /// reached L0, so every open replayed hours of WAL. After a roll the cold
    /// open needed more than the 45 s budget; each attempt was abandoned
    /// mid-replay (its SlateDB tasks left running, then fenced by the next
    /// attempt) and prevalence never came back. Now an open slower than the
    /// budget keeps running in the background, exactly one is started, and
    /// it is adopted when it finishes: stamping resumes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_slower_than_its_budget_finishes_in_the_background_and_stamping_resumes() {
        use super::super::discovery::SpoolQueue;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use slatedb::object_store::throttle::{ThrottleConfig, ThrottledStore};
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f3";
        let (owner, address) = nan3554_owner().await;
        let reads = Arc::new(ThrottledStore::new(owner.objects.clone(), ThrottleConfig::default()));
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let config = |work: &str| {
            let mut cfg = IngestConfig::new(TENANT, dir.path().join(work));
            cfg.writer_epoch = 3;
            cfg.prevalence_location = Some(nan3554_access(TENANT, address, "owner-token"));
            cfg.prevalence_read_store = Some(reads.clone());
            cfg
        };
        let t0 = 1_800_000_000_000_i64;

        // A stamping tenant leaves a WAL backlog behind (the pre-fix close).
        let mut first = Ingestor::open(config("first"), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert_eq!(first.prevalence_status(), "stamping");
        let mut state = first.prevalence.take().unwrap();
        state.write_test_wals(40).await.unwrap();
        state.close_wal_only_for_test().await.unwrap();
        drop(first);
        assert!(super::super::prevalence::wal_replay_backlog(owner.objects.clone()).await >= 40);

        // A cold process: every read is slow, the replay outlives the budget.
        reads.config_mut(|c| c.wait_get_per_call = std::time::Duration::from_millis(40));
        let mut cfg = config("second");
        cfg.prevalence_op_timeout = std::time::Duration::from_millis(300);
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await
            .expect("a slow prevalence open never fails ingest open");
        assert!(ingestor.prevalence.is_none(), "the open outlived its budget");
        assert!(ingestor.prevalence_opening.is_some(), "and keeps running in the background");
        // NAN-3774: a slow open is routine, not a failure (no degraded page).
        assert_eq!(ingestor.prevalence_status(), "unstamped: prevalence state opening");
        assert!(!ingestor.health().prevalence_degraded);

        let mut now = t0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while ingestor.prevalence.is_none() {
            assert!(std::time::Instant::now() < deadline, "the background open never finished");
            now += 1_000;
            let tick = std::time::Instant::now();
            ingestor.tick(now).await.expect("ingest keeps ticking while the open runs");
            assert!(tick.elapsed() < std::time::Duration::from_secs(5), "a tick never waits on the replay");
            assert_eq!(ingestor.health().prevalence_opens_started_total, 1,
                "no second open is started (it would fence the one replaying)");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(ingestor.prevalence_status(), "stamping");
        assert!(!ingestor.health().prevalence_degraded);
        assert!(!ingestor.health().prevalence_opening);
        assert!(ingestor.health().prevalence_last_open_ms >= 300, "the open's duration is reported");
        // The adopted writer owns the DB: its state writes are not fenced.
        reads.config_mut(|c| c.wait_get_per_call = std::time::Duration::ZERO);
        ingestor.prevalence.as_mut().unwrap().write_test_wals(1).await.expect("the adopted writer is not fenced");
    }

    /// Reads of `db/wal/*` (not HEADs) wait `delay_ms` first: an open that
    /// is fenced in and then stuck mid-replay.
    #[derive(Debug)]
    struct SlowWalReads {
        inner: Arc<slatedb::object_store::memory::InMemory>,
        delay_ms: Arc<std::sync::atomic::AtomicU64>,
        wal_gets: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl std::fmt::Display for SlowWalReads {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "SlowWalReads")
        }
    }

    #[async_trait::async_trait]
    impl slatedb::object_store::ObjectStore for SlowWalReads {
        async fn put_opts(&self, path: &slatedb::object_store::path::Path, payload: slatedb::object_store::PutPayload,
            opts: slatedb::object_store::PutOptions) -> slatedb::object_store::Result<slatedb::object_store::PutResult> {
            self.inner.put_opts(path, payload, opts).await
        }
        async fn put_multipart_opts(&self, path: &slatedb::object_store::path::Path, opts: slatedb::object_store::PutMultipartOptions)
            -> slatedb::object_store::Result<Box<dyn slatedb::object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(path, opts).await
        }
        async fn get_opts(&self, path: &slatedb::object_store::path::Path, options: slatedb::object_store::GetOptions)
            -> slatedb::object_store::Result<slatedb::object_store::GetResult> {
            if path.as_ref().starts_with("db/wal/") && !options.head {
                self.wal_gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let delay = self.delay_ms.load(std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            }
            self.inner.get_opts(path, options).await
        }
        fn delete_stream(&self, locations: futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>>)
            -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::path::Path>> {
            self.inner.delete_stream(locations)
        }
        fn list(&self, prefix: Option<&slatedb::object_store::path::Path>)
            -> futures::stream::BoxStream<'static, slatedb::object_store::Result<slatedb::object_store::ObjectMeta>> {
            self.inner.list(prefix)
        }
        async fn list_with_delimiter(&self, prefix: Option<&slatedb::object_store::path::Path>)
            -> slatedb::object_store::Result<slatedb::object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }
        async fn copy_opts(&self, from: &slatedb::object_store::path::Path, to: &slatedb::object_store::path::Path,
            options: slatedb::object_store::CopyOptions) -> slatedb::object_store::Result<()> {
            self.inner.copy_opts(from, to, options).await
        }
    }

    /// NAN-3554 hard ceiling: an open that hangs mid-replay (after it has
    /// fenced in: manifest epoch bumped, fence WAL written, SlateDB tasks
    /// running) is aborted at the ceiling, a failure is recorded, and after
    /// the backoff a fresh open claims a higher epoch, supersedes the
    /// aborted writer, and stamps. Nothing the aborted open left blocks it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_hung_mid_replay_is_aborted_at_its_ceiling_and_a_fresh_open_stamps() {
        use super::super::discovery::SpoolQueue;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use std::sync::atomic::Ordering;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f6";
        let (owner, address) = nan3554_owner().await;
        let reads = Arc::new(SlowWalReads {
            inner: owner.objects.clone(),
            delay_ms: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            wal_gets: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let config = |work: &str| {
            let mut cfg = IngestConfig::new(TENANT, dir.path().join(work));
            cfg.writer_epoch = 3;
            cfg.prevalence_location = Some(nan3554_access(TENANT, address, "owner-token"));
            cfg.prevalence_read_store = Some(reads.clone());
            cfg
        };
        let t0 = 1_800_000_000_000_i64;
        let mut first = Ingestor::open(config("first"), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        let mut state = first.prevalence.take().unwrap();
        state.write_test_wals(20).await.unwrap();
        state.close_wal_only_for_test().await.unwrap();
        drop(first);
        let manifests = || async {
            use futures::StreamExt;
            use slatedb::object_store::ObjectStore as _;
            owner.objects.list(Some(&slatedb::object_store::path::Path::from("db/manifest"))).count().await
        };
        let before = manifests().await;

        // Every WAL read hangs: the open fences in, then never finishes replay.
        reads.delay_ms.store(3_600_000, Ordering::SeqCst);
        let mut cfg = config("second");
        cfg.prevalence_op_timeout = std::time::Duration::from_millis(200);
        cfg.prevalence_open_hard_timeout = std::time::Duration::from_secs(2);
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert!(ingestor.prevalence_opening.is_some());
        let fenced_by = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while reads.wal_gets.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < fenced_by, "the open never reached its replay");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(manifests().await > before, "the open had fenced in (writer epoch bumped) before it hung");

        let mut now = t0;
        let started = std::time::Instant::now();
        while ingestor.health().prevalence_open_aborts_total == 0 {
            assert!(started.elapsed() < std::time::Duration::from_secs(30), "the hung open was never aborted");
            now += 1_000;
            ingestor.tick(now).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(started.elapsed() >= std::time::Duration::from_millis(1_500), "not before its ceiling");
        assert!(ingestor.prevalence_opening.is_none(), "the hung open was dropped");
        assert!(ingestor.prevalence.is_none());
        assert!(ingestor.health().prevalence_degraded, "the abort is a recorded failure");
        assert_eq!(ingestor.health().prevalence_opens_started_total, 1, "no fresh open before the backoff");

        // Reads recover; after the backoff a fresh open supersedes the aborted one.
        reads.delay_ms.store(0, Ordering::SeqCst);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while ingestor.prevalence.is_none() {
            assert!(std::time::Instant::now() < deadline, "no fresh open succeeded after the abort");
            now += PREVALENCE_RETRY_MAX_MS;
            ingestor.tick(now).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(ingestor.health().prevalence_opens_started_total, 2);
        assert_eq!(ingestor.health().prevalence_open_aborts_total, 1);
        assert_eq!(ingestor.prevalence_status(), "stamping");
        assert!(!ingestor.health().prevalence_degraded);
        // The fresh writer owns the DB: its writes and a flush land, and
        // every key the aborted open was replaying is there.
        let prevalence = ingestor.prevalence.as_mut().unwrap();
        prevalence.write_test_wals(1).await.expect("the fresh writer is not fenced by the aborted one");
        assert!(prevalence.flush_memtable_bounded("test").await, "its L0 flush is not fenced either");
        assert!(prevalence.has_test_key(19).await, "the aborted replay lost nothing");
    }

    /// NAN-3554: a grant refreshed while the open runs never waits on it,
    /// and the open (on the superseded grant) is not adopted as is: it is
    /// closed (flushing what it replayed) and reopened on the current grant
    /// in the same task, so no two writers ever fight over the fence.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_open_finishing_on_a_superseded_grant_is_closed_and_reopened_on_the_current_one() {
        use super::super::discovery::SpoolQueue;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use slatedb::object_store::throttle::{ThrottleConfig, ThrottledStore};
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f4";
        let (owner, address) = nan3554_owner().await;
        let reads = Arc::new(ThrottledStore::new(owner.objects.clone(), ThrottleConfig::default()));
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let config = |work: &str| {
            let mut cfg = IngestConfig::new(TENANT, dir.path().join(work));
            cfg.writer_epoch = 3;
            cfg.prevalence_location = Some(nan3554_access(TENANT, address, "owner-token"));
            cfg.prevalence_read_store = Some(reads.clone());
            cfg
        };
        let t0 = 1_800_000_000_000_i64;
        let mut first = Ingestor::open(config("first"), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        let mut state = first.prevalence.take().unwrap();
        state.write_test_wals(40).await.unwrap();
        state.close_wal_only_for_test().await.unwrap();
        drop(first);

        reads.config_mut(|c| c.wait_get_per_call = std::time::Duration::from_millis(40));
        let mut cfg = config("second");
        cfg.prevalence_op_timeout = std::time::Duration::from_millis(300);
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert!(ingestor.prevalence_opening.is_some());

        let refreshed = nan3554_access(TENANT, address, "owner-token-2");
        let started = std::time::Instant::now();
        ingestor.refresh_prevalence_credential(&refreshed).await.expect("a refresh never fails on an open in flight");
        assert!(started.elapsed() < std::time::Duration::from_secs(5), "the refresh did not wait on the replay");
        assert!(ingestor.prevalence.is_none());

        let mut now = t0;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        while ingestor.prevalence.is_none() {
            assert!(std::time::Instant::now() < deadline, "the reopen on the current grant never finished");
            now += 1_000;
            ingestor.tick(now).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(ingestor.health().prevalence_opens_started_total, 2, "one open, one reopen on the refreshed grant");
        assert_eq!(ingestor.prevalence_status(), "stamping");
        assert_eq!(ingestor.cfg.prevalence_location.as_ref().unwrap().owner.bearer, "owner-token-2");
        // The superseded open was closed with an L0 flush: the reopen
        // replayed (and left) almost nothing.
        reads.config_mut(|c| c.wait_get_per_call = std::time::Duration::ZERO);
        assert!(super::super::prevalence::wal_replay_backlog(owner.objects.clone()).await <= 2);
        ingestor.prevalence.as_mut().unwrap().write_test_wals(1).await.expect("the adopted writer is not fenced");
    }

    /// NAN-3554: the replay after K credential rotations stays bounded by
    /// one flush window instead of growing with K. NAN-3849: a routine
    /// refresh no longer reopens the state at all (it swaps the credential
    /// in place), so the WAL is bounded by the memtable flush cadence.
    #[tokio::test]
    async fn replay_after_many_credential_rotations_stays_bounded() {
        use super::super::discovery::SpoolQueue;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f5";
        const ROTATIONS: u32 = 6;
        const WALS: u32 = 8;
        let (owner, address) = nan3554_owner().await;
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.writer_epoch = 3;
        cfg.prevalence_location = Some(nan3554_access(TENANT, address, "owner-token"));
        cfg.prevalence_read_store = Some(owner.objects.clone());
        let t0 = 1_800_000_000_000_i64;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert_eq!(ingestor.prevalence_status(), "stamping");
        let opens = ingestor.health().prevalence_opens_started_total;
        for k in 0..ROTATIONS {
            ingestor.prevalence.as_mut().unwrap().write_test_wals(WALS).await.unwrap();
            let access = nan3554_access(TENANT, address, &format!("owner-token-{k}"));
            ingestor.refresh_prevalence_credential(&access).await.unwrap();
            assert_eq!(ingestor.prevalence_status(), "stamping");
        }
        assert_eq!(ingestor.health().prevalence_opens_started_total, opens, "every refresh swapped in place, no reopen");
        assert!(ingestor.prevalence.is_some() && ingestor.prevalence_opening.is_none());
        // The memtable cadence (not a reopen) bounds the WAL a later open replays.
        ingestor.prevalence.as_mut().unwrap().age_last_l0_flush(super::super::prevalence::MEMTABLE_FLUSH_EVERY);
        ingestor.tick(t0 + 1_000).await.unwrap();
        let backlog = super::super::prevalence::wal_replay_backlog(owner.objects.clone()).await;
        assert!(backlog <= 2, "after {ROTATIONS} rotations an open replays {backlog} WALs");
    }

    /// Dan's rule for prevalence: degrade, don't die. An owner refusing
    /// every mutation (403 authorize_stale_epoch) must not stop ingest: open
    /// succeeds unstamped and degraded, ticks keep running, the open is
    /// retried only after its backoff, and once the owner recovers the
    /// state reopens and stamping resumes. No refused request is left in
    /// the owner journal to wedge the recovered retry.
    #[tokio::test]
    async fn owner_403_on_prevalence_open_degrades_and_recovers() {
        use super::super::discovery::SpoolQueue;
        use super::super::prevalence_owner_store::OwnerAccess;
        use super::super::s3_store::S3Location;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use std::sync::atomic::Ordering;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f1";

        let owner = Owner {
            objects: Arc::new(slatedb::object_store::memory::InMemory::new()),
            refuse: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let app = axum::Router::new().route("/mutate", axum::routing::post(owner_mutate)).with_state(owner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.writer_epoch = 3;
        cfg.prevalence_location = Some(PrevalenceAccess {
            read: S3Location {
                endpoint: "https://r2.example".into(), region: "auto".into(), bucket: "bucket".into(),
                prefix: format!("lake/prevalence-state/v1/tenant={TENANT}/"),
                access_key_id: "read".into(), secret_access_key: "read".into(), session_token: None,
            },
            owner: OwnerAccess {
                url: format!("http://{address}/mutate"), bearer: "owner-token".into(),
                tenant_id: TENANT.into(), assignment_generation: 2, writer_epoch: 3, expires_at: None,
            },
            owner_ca_file: None,
        });
        cfg.prevalence_read_store = Some(owner.objects.clone());
        let journal = dir.path().join("ingest/prevalence").join(TENANT).join("owner-pending");
        let journal_len = || std::fs::read_dir(&journal).map(|d| d.count()).unwrap_or(0);

        let t0 = 1_800_000_000_000_i64;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await
            .expect("an owner 403 must not fail ingest open");
        assert!(owner.calls.load(Ordering::SeqCst) >= 1, "the open reached the owner");
        assert!(ingestor.prevalence_status().starts_with("unstamped: prevalence state unavailable"),
            "{}", ingestor.prevalence_status());
        assert!(ingestor.prevalence.is_none());
        assert_eq!(journal_len(), 0, "a definite 403 leaves no pending owner request");

        ingestor.tick(t0 + 1_000).await.expect("ingest keeps ticking while prevalence is degraded");
        assert!(ingestor.health().prevalence_degraded);
        assert_eq!(ingestor.health().prevalence_open_failures_total, 1);
        let calls = owner.calls.load(Ordering::SeqCst);
        ingestor.tick(t0 + PREVALENCE_RETRY_BASE_MS - 1).await.unwrap();
        assert_eq!(owner.calls.load(Ordering::SeqCst), calls, "no retry before the backoff");
        // NAN-3781: the ongoing spell is measured (signal + counter).
        let spell = ingestor.health().prevalence_degraded_ms;
        assert!(spell >= (PREVALENCE_RETRY_BASE_MS - 1_001) as u64, "degraded for {spell} ms");
        assert_eq!(ingestor.health().prevalence_degraded_ms_total, spell);

        // Still refused: the retry fails, backs off further, ingest runs on.
        ingestor.tick(t0 + PREVALENCE_RETRY_BASE_MS).await.unwrap();
        assert!(owner.calls.load(Ordering::SeqCst) > calls, "the retry reached the owner");
        assert_eq!(ingestor.health().prevalence_open_failures_total, 2);
        assert!(ingestor.health().prevalence_degraded);

        // The owner recovers: the next due retry reopens and stamps.
        owner.refuse.store(false, Ordering::SeqCst);
        let later = t0 + PREVALENCE_RETRY_BASE_MS + 2 * PREVALENCE_RETRY_BASE_MS;
        ingestor.tick(later - 1).await.unwrap();
        assert!(ingestor.prevalence.is_none(), "still backing off");
        ingestor.tick(later).await.unwrap();
        assert!(ingestor.prevalence.is_some(), "prevalence re-opened after the owner recovered");
        assert_eq!(ingestor.prevalence_status(), "stamping");
        assert!(!ingestor.health().prevalence_degraded);
        // NAN-3781: the spell closed into the total.
        assert_eq!(ingestor.health().prevalence_degraded_ms, 0);
        assert!(ingestor.health().prevalence_degraded_ms_total >= (later - t0 - 1_000) as u64,
            "total {} ms", ingestor.health().prevalence_degraded_ms_total);
        assert_eq!(journal_len(), 0);
    }

    /// NAN-3864 review: the owed hours are kept in the tenant bucket, not the
    /// prevalence state. On tenant-a (10-14) the state did not answer for the
    /// whole spell; a roll in that spell must still carry every owed hour to
    /// the next process. Here the owner refuses every open across both
    /// processes, so the state never opens at all.
    #[tokio::test]
    async fn owed_restamp_hours_survive_a_roll_while_the_state_never_answers() {
        use super::super::discovery::SpoolQueue;
        use super::super::prevalence_owner_store::OwnerAccess;
        use super::super::s3_store::S3Location;
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use std::sync::atomic::Ordering;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f2";

        let owner = Owner {
            objects: Arc::new(slatedb::object_store::memory::InMemory::new()),
            refuse: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let app = axum::Router::new().route("/mutate", axum::routing::post(owner_mutate)).with_state(owner.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
        let queue = SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let signer = LocalPartSigner::new("lab-signer-prev", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        // Each process has its own pod-local volume (the roll).
        let config = |pod: &str, epoch: u64| {
            let mut cfg = IngestConfig::new(TENANT, dir.path().join(pod));
            cfg.writer_epoch = epoch;
            cfg.prevalence_location = Some(PrevalenceAccess {
                read: S3Location {
                    endpoint: "https://r2.example".into(), region: "auto".into(), bucket: "bucket".into(),
                    prefix: format!("lake/prevalence-state/v1/tenant={TENANT}/"),
                    access_key_id: "read".into(), secret_access_key: "read".into(), session_token: None,
                },
                owner: OwnerAccess {
                    url: format!("http://{address}/mutate"), bearer: "owner-token".into(),
                    tenant_id: TENANT.into(), assignment_generation: 2, writer_epoch: epoch as i64, expires_at: None,
                },
                owner_ca_file: None,
            });
            cfg.prevalence_read_store = Some(owner.objects.clone());
            cfg
        };

        let t0 = 1_800_000_000_000_i64;
        let mut ingestor = Ingestor::open(config("pod-a", 3), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert!(ingestor.prevalence.is_none() && ingestor.restamp_eligible(),
            "an unavailable state with the grant held owes its unstamped rows");
        // Two batches committed unstamped while the state is unavailable.
        let hours = [event_hour_of(t0 * 1_000) - 1, event_hour_of(t0 * 1_000)];
        ingestor.prevalence_owed.mark(hours);
        ingestor.tick(t0 + 1_000).await.unwrap();
        assert!(ingestor.prevalence.is_none(), "the state never answered");
        assert!(!ingestor.prevalence_owed.dirty(), "saved without the state");
        let prefix = restamp_owed_prefix(TENANT).unwrap();
        assert_eq!(store.list(&prefix).await.unwrap().len(), 1, "one snapshot in the tenant bucket");
        // An unchanged set is not written again.
        ingestor.tick(t0 + 2_000).await.unwrap();
        assert_eq!(store.list(&prefix).await.unwrap().len(), 1);
        drop(ingestor);

        // The roll: a new pod, a new epoch, the owner still refusing.
        let calls = owner.calls.load(Ordering::SeqCst);
        let mut ingestor = Ingestor::open(config("pod-b", 4), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0 + 60_000).await.unwrap();
        assert!(owner.calls.load(Ordering::SeqCst) > calls);
        ingestor.tick(t0 + 61_000).await.unwrap();
        assert!(ingestor.prevalence.is_none(), "still unavailable after the roll");
        assert_eq!(ingestor.prevalence_owed_hours(), hours.to_vec(), "the roll kept every owed hour");
        assert_eq!(ingestor.health().prevalence_restamp_owed_hours, 2);
        assert_eq!(store.list(&prefix).await.unwrap().len(), 1, "a restored, unchanged set is not rewritten");

        // A change is a newer snapshot; the newest one is the set.
        ingestor.prevalence_owed.remove(hours[0]);
        ingestor.tick(t0 + 62_000).await.unwrap();
        assert_eq!(store.list(&prefix).await.unwrap().len(), 2);
        assert_eq!(load_restamp_owed(&store, TENANT).await.unwrap().unwrap().1, vec![hours[1]]);
        // A foreign or tampered record under the prefix is never the set.
        store.put_if_absent(&format!("{prefix}9999999999999-0000000000000000.json"), b"[1]").await.unwrap();
        assert_eq!(load_restamp_owed(&store, TENANT).await.unwrap().unwrap().1, vec![hours[1]]);
        // Only a withheld grant stops owing (a reopen or failed open never does).
        ingestor.suspend_prevalence().await;
        assert!(!ingestor.restamp_eligible(), "no grant: nothing owed");
    }
}
