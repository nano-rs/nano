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
use super::quarantine::{Kept, Quarantine, QuarantineEntry, Refusal, QUARANTINE_REPLAY_VERSION};
use super::admission_attempts::{object_id, AdmissionAttempts, ADMISSION_CRASHED, MAX_ADMISSION_CRASHES, RESERVE_REFUSED};
use super::part_gc_gate::{
    PartGcAuthority, PartGcDecision, REASON_AUTHORITY_MISSING, REASON_AUTHORITY_UNREADABLE, REASON_CATALOG_HELD,
    REASON_SANCTIONED_PASS_PAUSED, REASON_SANCTIONED_PATH_UNAVAILABLE,
};
use super::schema::{additive_merge, align, coerce_to_schema, decode_parallel, infer_schema};
use super::writer::{sort_by_time_uid, FinishedPart, PartDraft, PartWriter, PartialSource};
use crate::bronze::{admit_bronze_files_received_bounded, AdmissionHeapExceeded, ClampedSources, IngestTimes, NoCanonicalEvents, RowRefusal};
use crate::ingest_source_counters::{RefusedSources, SourceKey};
use crate::parts::refusal_tally;
use crate::enrichment::BronzeIngestEnricher;
use crate::parts::format::{LogKeys, PartId, PartKeys, PROVENANCE_FILE};
use crate::parts::levels::{plan_merges_with, FlushPolicy, Level, MergePolicy, FLUSH_MAX_ROWS};
use crate::parts::part_log::{AppendOutcome, LogEntry, LogOp, LogSchema, ObjectStore, PartLogWriter, PartRef, Rejection, SourceRef, WriteHints, WriterClass};
use super::finding_append::{FindingAppendRequest, FindingAppendResponse};
use super::finding_outbox::{committed_receipts_cached, FindingReceipt};
use super::finding_floors::{put_floor_logged, FloorCache};
use super::finding_attempts::{attempted_receipts, legacy_attempt_key, put_attempt_batch, AttemptCache};
use crate::parts::provenance::{
    Admission, PartInputs, PartSigner, PartialKind, SignedProvenance, SourceObject, TenantKeySet, ADMISSION_CONTRACT,
};
use crate::parts::{event_hour_of, sha256_hex, DedupPolicy, DedupWindow};

/// Why an object is refused whole before admission (NAN-4319 / NAN-4336).
#[derive(Debug, Clone, Copy)]
enum PoisonCause {
    /// Ingest died this many times with it admitted and unacknowledged.
    Crashed { attempts: u32 },
    /// The writer owner refused its own flush's reservation permanently.
    ReserveRefused,
}

/// NAN-4336: source slugs `rows_time_clamped_by_source` keeps.
pub const MAX_CLAMPED_SOURCES: usize = 256;

/// Errors no in-process retry can repair. The cell also checks its retry
/// window before starting GC, and credential epoch changes exit before tick.
pub(crate) fn fatal_ingest_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<crate::parts::part_log::Fenced>().is_some()
            || cause.downcast_ref::<crate::edge_log::EdgeLogFenced>().is_some()
            || cause.downcast_ref::<crate::parts::part_log::DoubleConsume>().is_some()
            || cause.downcast_ref::<AdoptionRefused>().is_some()
            || cause.downcast_ref::<super::r2_put::TerminalPutError>().is_some()
            || cause.downcast_ref::<super::writer_lease::LeaseLost>().is_some()
            // NAN-4336: the owner refused a flush's part reservation
            // permanently. No in-process retry can succeed and the flush
            // cannot drop its rows in place: exit, and the restarted
            // ingest isolates and quarantines the object
            // (`AdmissionAttempts::mark_reserve_refused`).
            || cause.downcast_ref::<super::native_writer::OwnerRefused>().is_some_and(|refused| refused.is_reservation_refused())
    })
}

/// NAN-4554 (review P1): one failing quarantine mirror id's retry state.
#[derive(Debug, Clone, Default)]
struct MirrorRetry {
    failures: u32,
    next_ms: i64,
    /// Its object PUT already succeeded (only the record is retried).
    object_mirrored: bool,
    failing_since_ms: Option<i64>,
}

/// NAN-4553 (review P1): ingest's tick retry window ran out
/// (`MAX_RETRY_WINDOW`). Attached as context to the exiting error so the
/// exit is classified as one the object in flight may have caused.
#[derive(Debug, thiserror::Error)]
#[error("ingest tick failing for {0} s (retry window exhausted)")]
pub(crate) struct RetryWindowExhausted(pub u64);

/// NAN-4553 (review P1): whether a coded ingest exit keeps this process's
/// crash-ledger charges (the object in flight may be the cause) or undoes
/// them (it cannot be). `None` is a clean end of the loop.
///
/// Kept: the tick retry window ran out ([`RetryWindowExhausted`]), or a
/// store refusal of a part ingest produced with a 4xx other than 401/403
/// (400 BadDigest / InvalidArgument are the bytes'). Undone: everything
/// else that reaches a coded exit: fencing, a double consume, a 401/403
/// (credentials), the writer lease lost, the owner refusing a reservation
/// (isolated by its own ledger mark), an epoch change, enrichment, and a
/// clean end. A wedge (stall watchdog) and a crash never reach this.
pub(crate) fn exit_keeps_charges(error: Option<&anyhow::Error>) -> bool {
    let Some(error) = error else { return false };
    if error.downcast_ref::<RetryWindowExhausted>().is_some() {
        return true;
    }
    error.chain().any(|cause| {
        cause.downcast_ref::<super::r2_put::TerminalPutError>()
            .is_some_and(|put| (400..500).contains(&put.status) && put.status != 401 && put.status != 403)
    })
}

/// NAN-4539: a flush's parts are already in the part log but its sources
/// are not consumed there. Only a broken invariant (an id reused, or a log
/// written by something else) gets here; retrying cannot fix it, so ingest
/// exits at once instead of retrying until the retry window closes.
#[derive(Debug, thiserror::Error)]
#[error("flush parts are already in the part log but their sources are not consumed: refusing to adopt")]
pub(crate) struct AdoptionRefused;

fn catalog_failure_health(reason: &'static str) -> serde_json::Value {
    serde_json::json!({"custody_attached":false,"gc_attached":false,"converged":false,
        "degraded":true,"reason":reason})
}

#[derive(Debug, Clone)]
pub struct IngestConfig {
    pub tenant_id: String,
    /// Tenant-owned catalog custody, supplied by the provisioning runtime.
    /// No environment toggle: a provisioned catalog must participate in erasure.
    pub catalog: Option<Arc<super::iceberg_export::lifecycle::TenantCatalog>>,
    /// Derived from an installed lane's failed attachment, never an operator
    /// switch. Continue appends while holding erasure and all physical GC.
    pub catalog_attachment_failure: Option<&'static str>,
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
    /// Working-budget room kept for one merge even before it starts. Derived
    /// from the role cap; admission and flights cannot borrow this headroom.
    pub merge_headroom_bytes: u64,
    /// Constructor policy ceiling, capped by queue, background handles, memory
    /// and privacy barriers. Production uses two; one is the serial baseline.
    pub flush_depth: usize,
    /// Commit ready flights after admission and before maintenance. Production
    /// defaults on; retained for the serial comparison in offline tests.
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
    /// NAN-4592: longest one admission batch waits for its prevalence
    /// lookups (never more than `prevalence_ingest_wait`). A batch whose
    /// lookups are not ready by then is committed unstamped and its hours
    /// are owed an exact restamp; the reads keep warming the cache.
    pub prevalence_stamp_wait: std::time::Duration,
    /// NAN-4592: cap on the remote prevalence state's local disk cache
    /// (sized from the state's measured SSTs within it,
    /// [`super::prevalence::object_cache_bytes`]). Production:
    /// `cell::prevalence_cache_bytes_for`.
    pub prevalence_cache_max_bytes: u64,
    /// NAN-4723: how a prevalence state on the local filesystem (compacted
    /// in-process) is sized: compaction jobs, L0 room and unflushed bytes.
    /// Production: [`super::prevalence::LocalStateSizing::for_placement`]
    /// from the role's CPU limit and memory cap (`cell`).
    pub prevalence_local_sizing: super::prevalence::LocalStateSizing,
    /// Hard ceiling on one prevalence open running in the background
    /// (NAN-3554): past it the open is taken as hung, aborted, and a fresh
    /// one is retried with the normal backoff.
    pub prevalence_open_hard_timeout: std::time::Duration,
    /// Reproduce main's read policy for the physical-I/O cost comparison.
    #[cfg(test)]
    pub prevalence_main_read_policy: bool,
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
    /// NAN-4460: the most partial rows one catch-up batch may fold, from
    /// the process's memory cap
    /// ([`super::prevalence::catch_up_max_rows_for`]; the cell sets it from
    /// the assignment). Batches grow toward it only while the backlog is
    /// long. Not an operator setting.
    pub prevalence_catch_up_max_rows: u64,
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
            catalog: None,
            catalog_attachment_failure: None,
            work_dir: work_dir.as_ref().to_path_buf(),
            build: format!("nanosiem-lake-worker {}", env!("CARGO_PKG_VERSION")),
            merge_policy: MergePolicy::default(),
            dedup: DedupPolicy::default(),
            max_objects_per_admission: 64,
            max_merges_per_tick: 2,
            background_merges: false,
            buffer_budget_bytes: DEFAULT_BUFFER_BUDGET_BYTES,
            merge_headroom_bytes: 0,
            flush_depth: MAX_FLUSH_DEPTH,
            commit_when_ready: true,
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
            prevalence_stamp_wait: PREVALENCE_STAMP_WAIT,
            prevalence_cache_max_bytes: super::prevalence::OBJECT_CACHE_FLOOR_BYTES,
            prevalence_local_sizing: super::prevalence::LocalStateSizing::FLOOR,
            prevalence_open_hard_timeout: PREVALENCE_OPEN_HARD_TIMEOUT,
            #[cfg(test)]
            prevalence_main_read_policy: false,
            prevalence_read_store: None,
            prevalence_rarity_threshold: crate::prevalence::DEFAULT_RARITY_THRESHOLD,
            prevalence_catch_up_batch_entries: super::prevalence::CATCH_UP_BATCH_ENTRIES,
            prevalence_catch_up_max_rows: super::prevalence::CATCH_UP_BATCH_ROWS,
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
    /// Present only for a coordinator-installed catalog. Unactivated tenants
    /// retain the exact old wire representation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_catalog: Option<serde_json::Value>,
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
    /// NAN-4674: the most live parts any one event hour holds (what a query
    /// over that hour opens), and the hours at or past
    /// [`crate::parts::levels::FRAGMENTED_HOUR_PARTS`].
    pub max_parts_per_hour: usize,
    pub fragmented_hours: usize,
    /// NAN-4674: runs of tiny batches folded by [`compact_tiny_batches`].
    pub tiny_batch_folds_total: u64,
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
    /// NAN-3643: objects refused whole and kept in the tenant's quarantine.
    pub objects_quarantined_total: u64,
    /// NAN-4319: objects refused whole because ingest died with them
    /// admitted [`MAX_ADMISSION_CRASHES`] times.
    pub objects_admission_crashed_total: u64,
    /// NAN-4553: objects too large for the admission budget that were
    /// admitted in row slices instead of whole.
    pub objects_admitted_in_slices_total: u64,
    /// NAN-4770: of those, objects sliced beside flushes still in flight
    /// (the next buffer's first object, admission pipelined with them).
    pub objects_sliced_beside_flights_total: u64,
    /// Completed JSON/Arrow admission groups and the most objects decoded
    /// together in one group (calibrated reservations enable parallel decode).
    pub admission_groups_total: u64,
    pub admission_group_objects_peak: usize,
    /// NAN-3643: operator replays of quarantined objects that committed.
    pub quarantine_replays_total: u64,
    /// NAN-4554: quarantine changes mirrored into the tenant bucket, the
    /// mirror attempts that failed, and the entries a fresh work dir
    /// restored from it.
    pub quarantine_mirrored_total: u64,
    pub quarantine_mirror_failures_total: u64,
    pub quarantine_restored_total: u64,
    /// NAN-4554: objects an operator imported from an export (kept new).
    pub quarantine_imported_total: u64,
    /// NAN-4554 (review): ids whose mirror is failing now (each backs off on
    /// its own), and since when the oldest of them has failed.
    pub quarantine_mirror_failing_ids: usize,
    pub quarantine_mirror_failing_since_ms: Option<i64>,
    /// NAN-4554 (review): a fresh work dir's restore has not completed yet
    /// (retried with backoff), its last error, and a named reason it
    /// stopped early (`restore_disk_low`). The roll gates on these.
    pub quarantine_restore_pending: bool,
    pub quarantine_restore_error: Option<String>,
    pub quarantine_restore_refused: Option<String>,
    /// Live entries a restore left in the bucket (beyond the local caps),
    /// and records it listed past (beyond its read bound).
    pub quarantine_restore_over_cap: u64,
    pub quarantine_restore_records_beyond_bound: u64,
    /// NAN-3643: entries in the quarantine now, and their bytes.
    pub quarantine_objects: usize,
    pub quarantine_bytes: u64,
    pub rows_rejected_total: u64,
    /// Rows whose type-drifted values moved into `unmapped.nano_coerced`.
    pub rows_coerced_total: u64,
    /// NAN-4336: rows whose `time` was more than 5 min past their ingest
    /// time, admitted with `time` clamped to it (the original kept in
    /// `metadata.original_time`, `metadata.labels` += `time_clamped`).
    pub rows_time_clamped_total: u64,
    /// NAN-4573: clamped rows dropped because another delivery of the same
    /// event was already admitted under its original event hour.
    pub clamped_cross_hour_duplicates_total: u64,
    /// NAN-4336: the same, per counter source slug (at most
    /// [`MAX_CLAMPED_SOURCES`] slugs; the rest fold into `default`).
    pub rows_time_clamped_by_source: BTreeMap<String, u64>,
    /// NAN-4336: objects refused whole and quarantined because the writer
    /// owner refused their part's reservation permanently (HTTP 422).
    pub objects_reserve_refused_total: u64,
    pub parts_written_total: u64,
    pub merges_total: u64,
    /// Per-process (since this ingest role started), like every `*_total`
    /// here: a restart or cell handover resets it to 0 by design.
    pub merge_failures_total: u64,
    /// NAN-4755: merges the memory guard stopped before the cgroup OOM
    /// (each reruns smaller, or waits once at the smallest shape).
    pub merge_memory_stops_total: u64,
    /// NAN-4755: merges left unmerged because even their smallest chunk did
    /// not fit the role's memory (gauge; their parts stay live and
    /// readable). Nonzero means an hour needs a bigger ingest role.
    pub merges_left_unmerged: u64,
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
    /// NAN-4445: false while this process does not yet know whether a
    /// degraded spell is under way: it has not read the spell an earlier
    /// process persisted, or its first open has not settled. The supervisor
    /// then reports no `prevalence_degraded` signal (a roll must not resolve
    /// an alert on a 0). True without a prevalence grant.
    pub prevalence_degraded_known: bool,
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
    /// NAN-4460: catch-up batches applied since process start.
    pub prevalence_catch_up_batches_total: u64,
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
    /// NAN-4539 step 3a: age-due seals deferred beside an unfinished flight,
    /// seals made before the ready oldest flight committed, and the longest
    /// one buffer stayed deferred before it sealed (ms): a deferral lasts at
    /// most until a flight slot frees, so the live check can confirm 3a
    /// engaged and that its deferral stays bounded.
    pub seals_deferred_total: u64,
    pub seals_first_total: u64,
    pub seal_deferred_max_ms: i64,
    /// Superseded parts kept because the lake-part delete gate is closed
    /// (`part_gc_gate`); `None` while deletion is authorized.
    pub part_gc_blocked: Option<nanosiem_lake_cell::contract::PartGcBlocked>,
    pub part_gc_capacity: Option<nanosiem_lake_cell::contract::PartGcCapacity>,
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
    buffered_since: Option<std::time::Instant>,
    flush_started_ms: Option<i64>,
    progress: Option<Arc<std::sync::Mutex<FlushStage>>>,
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
    /// Foreground flush output survives publication and Add failures.
    built: Option<Vec<FinishedPart>>,
    /// NAN-3899: rows kept per credential, folded into the credential
    /// activity only once this flush committed.
    activity: super::credential_activity::FlushTally,
    /// NAN-3643: this buffer holds exactly one quarantine replay (its id)
    /// and nothing else; it is flushed on its own.
    replay: Option<String>,
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
            buffered_since: None,
            flush_started_ms: None,
            progress: None,
            rows_in: 0,
            duplicates: 0,
            same_uid_payload_diff: 0,
            sources: Vec::new(),
            handles: Vec::new(),
            handle_names: HashSet::new(),
            built: None,
            activity: Default::default(),
            replay: None,
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
    /// (hour, its buffered batches, its duplicates, its dedicated L0
    /// `(source, class)` families: [`l0_class_families`]).
    hours: Vec<(i32, Vec<RecordBatch>, u64, Vec<(String, i64)>)>,
    now_ms: i64,
    /// Parallel L0 part writers ([`super::memory::writers_for`]).
    writers: usize,
}

impl FlushPlan {
    /// Each hour's rows, sorted, cut into row ranges written as separate L0
    /// parts on parallel threads (the part write was ~0.4 ms/row on one
    /// thread, the catch-up bottleneck once a flush holds FLUSH_MAX_ROWS).
    ///
    /// NAN-4750: an hour's dedicated `(source, class)` families (planned in
    /// `flush_plan`) are written as their own class-labelled L0 parts, the
    /// rest as mixed parts; every group keeps its `(time, uid)` order and
    /// the hour's part count stays within [`l0_group_parts`]' bound.
    fn build(self) -> Result<Vec<FinishedPart>> {
        let mut drafts = Vec::new();
        for (hour, batches, duplicates, families) in &self.hours {
            let batch = sorted_hour(batches, &self.schema)?;
            let groups = split_l0_families(&batch, families)?;
            drop(batch);
            let parts = l0_group_parts(&groups.iter().map(|(_, rows)| rows.num_rows()).collect::<Vec<_>>());
            let chunks = groups.into_iter().zip(parts)
                .flat_map(|((family, rows), parts)| l0_chunks_into(rows.num_rows(), parts).into_iter()
                    .map(move |(offset, len)| (family.clone(), rows.slice(offset, len))))
                .collect::<Vec<_>>();
            for (index, (family, rows)) in chunks.into_iter().enumerate() {
                let len = rows.num_rows();
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
                drafts.push((draft, rows, family));
            }
        }
        write_l0_family_parts_with(&self.dir, drafts, self.now_ms, self.writers)
    }
}

pub use super::diagnostics::PipelineDiagnostics;
use super::diagnostics::FlushStage;

/// A sealed flush (rejections logged, skips acknowledged, edge range
/// issued, schema logged) whose parts build and upload in the background
/// while the next buffer admits. At most [`MAX_FLUSH_DEPTH`] exist, fewer
/// when the queue, background handles, memory or a privacy/catalog barrier
/// say so (NAN-3619, NAN-4539); they commit strictly in seal order (only the
/// oldest commits, a younger one that finished first waits), so `add`
/// entries, edge acks and edge ranges keep their order. A flight leaves the
/// queue only once its acks landed: a cancelled commit keeps it (and its
/// reservation, task and immutable output) for the next attempt.
struct InFlightFlush {
    buffer: Buffered,
    /// Working-budget bytes charged until it commits
    /// ([`super::memory::flight_bytes`]).
    reserved_bytes: u64,
    /// The schema its parts are built under (already in the log).
    schema: SchemaRef,
    sealed_ms: i64,
    progress: std::sync::Arc<std::sync::Mutex<FlushStage>>,
    /// `None` once taken: awaited, or failed (the retry resumes on the tick).
    task: Option<tokio::task::JoinHandle<Result<(Vec<FinishedPart>, Result<Vec<PartRef>>)>>>,
    /// Immutable output, kept from build until the flight's acks land:
    /// retries keep part ids and cache eviction keeps its directories.
    built: Option<Vec<FinishedPart>>,
    /// `built` is published (these refs), awaiting the `add`.
    published: Option<Vec<PartRef>>,
    /// NAN-4539 step 3a: set by the background task once its parts are
    /// published. Its build copies and writers are freed by then, so the
    /// flight holds only its retained rows ([`Ingestor::settle_published_flights`]).
    published_ok: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// What [`Ingestor::commit_add`] needs of a finished part once it is
/// published: owned, so the immutable output stays with its flush while the
/// append and the prevalence apply await (NAN-4539 cancellation safety).
#[derive(Clone)]
struct AddPart {
    part_id: PartId,
    partial_prevalence: PathBuf,
    max_time_us: i64,
}

fn add_parts(finished: &[FinishedPart]) -> Vec<AddPart> {
    finished.iter().map(|part| AddPart {
        part_id: part.record.part_id.clone(),
        partial_prevalence: part.dir.join(crate::parts::format::PARTIAL_PREVALENCE_FILE),
        max_time_us: part.record.max_time_us,
    }).collect()
}

/// NAN-4737: a committed `Add` whose prevalence apply was deferred off the
/// serial commit, to run beside the next admission's parse. Only metadata:
/// the partials stay on disk in the flight's part directories.
struct DeferredApply {
    seq: u64,
    entry_sha256: String,
    refs: Vec<PartRef>,
    parts: Vec<AddPart>,
    /// The state's complete cursor when it was deferred `(seq, digest)`:
    /// the entry applies on its own only while the cursor is still there
    /// (a reopen, rotation or lost WAL tail meanwhile goes through the
    /// replay, which never skips an entry).
    cursor: (u64, String),
    /// The `tick_ingest` that deferred it; the next one applies it at the
    /// latest.
    tick: u64,
}

/// NAN-4737: the state's cursor if it is complete (no part half-applied).
async fn complete_cursor(prevalence: Option<&IngestPrevalence>) -> Option<(u64, String)> {
    let cursor = prevalence?.applied().await.ok()??;
    cursor.is_complete().then_some((cursor.seq, cursor.entry_sha256))
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
/// NAN-4445: how long a new process may report its degraded spell as
/// unknown (no `prevalence_degraded` signal) while it reads the persisted
/// spell and its first open runs (a cold open is about 1-2 min; the large tenant's failing
/// opens took 21-27 s). Past it the signal is reported regardless.
pub(crate) const PREVALENCE_SPELL_UNKNOWN_MAX_MS: i64 = 5 * 60_000;

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
    let cache_cap = cfg.prevalence_cache_max_bytes;
    let local_sizing = cfg.prevalence_local_sizing;
    #[cfg(test)]
    let main_read_policy = cfg.prevalence_main_read_policy;
    let handle = tokio::spawn(async move {
        if let Some(previous) = previous {
            if let Err(error) = previous.close().await {
                tracing::warn!(tenant = %tenant, error = %format!("{error:#}"),
                    "closing the prevalence state opened on a superseded grant failed");
            }
        }
        let opened = IngestPrevalence::open_sized(&tenant, &work_dir, access.as_ref(), reads, cache_cap, local_sizing);
        #[cfg(test)]
        { return super::prevalence_io::MAIN_POLICY.scope(main_read_policy, opened).await; }
        #[cfg(not(test))]
        opened.await
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
    /// NAN-4181: finding batch attempt markers known to this process.
    finding_attempts: Arc<AttemptCache>,
    /// NAN-4656: replay floor bodies this process read.
    finding_floors: Arc<FloorCache>,
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
    catalog_flight: Option<super::iceberg_export::lifecycle::CatalogFlight>,
    catalog_applied_seq: Option<u64>,
    catalog_due_ms: i64,
    catalog_retry_ms: i64,
    /// Local cache dirs of superseded parts already dropped (local disk only).
    gc_done: HashSet<PartId>,
    /// The lake-part delete gate; `None` = blocked (`authority_missing`).
    gc_authority: Option<Arc<dyn PartGcAuthority>>,
    /// NAN-4601: the delete gate set aside by [`Self::hold_catalog`]. Only
    /// its index-only feed is driven (never a delete decision or pass).
    held_index_feed: Option<Arc<dyn PartGcAuthority>>,
    /// NAN-4601: when this process first reported the catalog hold, and when
    /// it last logged it (re-logged every [`CATALOG_HELD_LOG_INTERVAL_MS`]).
    catalog_held_since_ms: Option<i64>,
    catalog_held_logged_ms: Option<i64>,
    local_gc: Option<Arc<crate::lake_part_gc::local::LocalDeleteAuthority>>,
    /// NAN-4726: when the hosted retention retire step last scanned the live
    /// set (at most once per [`HOSTED_RETENTION_SCAN_INTERVAL_MS`]).
    last_retention_scan_ms: Option<i64>,
    last_sanctioned_pass_ms: Option<i64>,
    /// NAN-3818: the last sanctioned pass stopped after one bounded log-fold
    /// step; the next step is due after [`SANCTIONED_GC_CATCH_UP_INTERVAL_MS`].
    sanctioned_gc_catching_up: bool,
    /// NAN-4728: wall time the last foreground sanctioned pass held the
    /// ingestor; paces catch-up passes ([`sanctioned_pass_due_paced`]).
    last_sanctioned_pass_busy_ms: i64,
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
    /// NAN-4770: admission's heap and Arrow per decoded byte, learned per
    /// object prefix from the rows admitted (the fixed model until measured).
    calibration: super::memory::AdmissionCalibration,
    /// (level, hour) → (consecutive failures, retry not before ms).
    merge_quarantine: BTreeMap<(String, i32), (u32, i64)>,
    /// NAN-4796: guard stops of a merge that started without the normal
    /// room (process memory held elsewhere), since its last commit. Bounded
    /// by [`MAX_UNCHARGED_MEMORY_STOPS`]: past it, stops shrink it again.
    merge_memory_waits: BTreeMap<(String, i32), u32>,
    /// Background merges, bounded independently by minute/history lane.
    merge_in_flight: Vec<InFlightMerge>,
    /// Pipelined flushes still building/publishing, oldest (next to
    /// commit) first (NAN-3183; up to the effective `flush_depth`).
    flush_in_flight: VecDeque<InFlightFlush>,
    diagnostics: PipelineDiagnostics,
    /// Woken when a flight's build/publish task finishes, so the loop
    /// commits it now rather than after its idle sleep (NAN-3619).
    flight_wake: Option<std::sync::Arc<tokio::sync::Notify>>,
    /// Age-due seals deferred beside an unfinished flight (NAN-4539 step 3a).
    /// When the filling buffer's age-due seal was first deferred.
    seal_deferred_since_ms: Option<i64>,
    /// Whether the last ingest tick saw fresh notices pending (catch-up).
    behind_last_tick: bool,
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
    /// NAN-4737: at most one committed `Add` whose apply runs beside the
    /// next admission's parse (`prevalence_pending` stays set until it
    /// lands, so stamps, merges and restamps wait exactly as for any owed
    /// apply, and a crash leaves it to the cursor replay).
    prevalence_deferred: Option<DeferredApply>,
    /// `tick_ingest` calls so far (bounds a deferred apply to one tick).
    ingest_ticks: u64,
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
    /// NAN-3899: per-credential activity (hosted lean only; `None` keeps
    /// admission free of the per-row credential read).
    credential_activity: Option<super::credential_activity::ActivityExec>,
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
    /// NAN-4460: the catch-up batch scale (1..=`CATCH_UP_MAX_SCALE`) for the
    /// next batch; it follows the backlog and the cell's headroom
    /// ([`super::prevalence::next_catch_up_scale`]).
    prevalence_catch_up_scale: usize,
    prevalence_read_stats_at_ms: i64,
    /// NAN-4464: when the catch-up watchdog last saw the state's read or
    /// commit progress advance, and its value then
    /// ([`Self::catch_up_reads_patient`]).
    prevalence_reads_watch: Option<(std::time::Instant, u64)>,
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
    /// NAN-4445: the degraded spell's start as persisted in the tenant
    /// bucket ([`super::prevalence_spell`]), so a roll continues it.
    prevalence_spell: super::prevalence_spell::SpellSync,
    /// NAN-4445: this process's first open has settled (state placed, or
    /// failed and scheduled for retry).
    prevalence_first_settled: bool,
    /// NAN-4445: the first health update of this process.
    prevalence_health_started_ms: Option<i64>,
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
    /// NAN-4161: bounded scan for the newest snapshot, resumed across ticks.
    restamp_scan: RestampScan,
    /// NAN-4161: bytes of the newest snapshot read or written (an identical
    /// set is never written again).
    restamp_owed_saved_bytes: Option<Vec<u8>>,
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
    /// NAN-3643: refused objects kept for an operator replay (`None` when
    /// the directory could not be opened: refusals then behave as before).
    quarantine: Option<Quarantine>,
    quarantine_swept_ms: i64,
    /// NAN-4554: since when the bucket has refused a quarantine change (the
    /// flush acknowledging it waits up to `MIRROR_HOLD_MS`), and the last
    /// record time written (strictly increasing: the newest record wins).
    quarantine_mirror_failing_since: Option<i64>,
    quarantine_record_ms: i64,
    /// NAN-4554 (review P1): per-id mirror backoff (failures, next try) and
    /// whether that id's object PUT already succeeded.
    quarantine_mirror_backoff: BTreeMap<String, MirrorRetry>,
    /// NAN-4554 (review P1): restore backoff (failures, next try).
    quarantine_restore_retry: (u32, i64),
    /// A replay may be requested: look at the quarantine directory only
    /// then, not every tick (true at open: a request may predate a restart).
    quarantine_replay_pending: bool,
    /// NAN-4338: reports quarantined (and replayed) edge segments to the
    /// tenant's landing ledger, so its per-source `rows` count only stored
    /// rows. `None`: not an edge-log tenant (nothing to report to).
    quarantine_ledger: Option<super::quarantine_ledger::QuarantineLedger>,
    /// NAN-4319: admissions begun and not yet acknowledged, durable across
    /// a crash, so an object that kills the process is refused after
    /// [`MAX_ADMISSION_CRASHES`] instead of wedging the tenant.
    admission_attempts: AdmissionAttempts,
    /// NAN-4755: merges begun and not yet ended, durable across a crash, so
    /// a merge that kills the process reruns smaller (or waits) instead of
    /// restart-looping it.
    merge_attempts: super::merge_attempts::MergeAttempts,
    /// NAN-4755: last "history merge waits for memory" log.
    merge_memory_wait_log_ms: i64,
    /// NAN-4319: this tick's admission left objects pending because their
    /// decoded rows did not fit the working budget.
    admission_deferred: bool,
    /// Tests: refuse every admission whole (an admission bug).
    #[cfg(test)]
    refuse_admissions: bool,
    /// Tests (NAN-4770 before/after): the pre-calibration admission (the
    /// fixed model, slicing only from idle).
    #[cfg(test)]
    pub(super) fixed_admission_model: bool,
}

/// Read-only inputs of finding validation and replay proofs
/// ([`Ingestor::finding_context`]); usable without the ingestor lock.
#[derive(Clone)]
pub struct FindingAppendContext<'a> {
    pub parts: &'a dyn ObjectStore,
    pub tenant_id: String,
    pub writer_epoch: u64,
    pub trusted: TenantKeySet,
    /// NAN-4181: batch attempt marker bodies this process wrote or read.
    pub attempts: Arc<AttemptCache>,
    /// NAN-4656: replay floor bodies this process read.
    pub floors: Arc<FloorCache>,
}

/// A finding append request whose receipts and signed parts were verified.
pub struct ValidatedFinding {
    pub request: FindingAppendRequest,
    proposed: Schema,
    /// An ingest attempt marker names a receipt: the log decides
    /// whether this is a replay ([`finding_replay_proof`]).
    pub needs_replay_proof: bool,
    /// NAN-4656: the receipts an attempt marker names, the only ones the
    /// proof reads the log for. A receipt no marker names was never offered
    /// to the log (the drain relies on the same rule).
    pub attempted: Vec<SourceRef>,
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
    // Receipt reads run FINDING_IO_CONCURRENCY at a time: one GET at a
    // time was 256 round trips per 128-finding append (NAN-3067).
    let mut reads = Vec::with_capacity(request.receipts.len());
    for source in &request.receipts {
        reads.push(fetch_receipt(context.parts, source));
    }
    let fetched = futures::stream::iter(reads).buffered(FINDING_IO_CONCURRENCY).try_collect::<Vec<_>>().await?;
    let mut wanted = std::collections::BTreeMap::new();
    for (source, bytes) in fetched {
        FindingReceipt::parse(&bytes, tenant_id, source)?;
        ensure!(wanted.insert((source.key.clone(), source.version.clone(), source.sha256.clone()), bytes.len() as u64).is_none(),
            "finding append repeats a receipt");
    }
    // NAN-4181: one LIST of the batch markers since the oldest receipt
    // (plus the legacy per-receipt probes), not one marker per receipt.
    let marked = attempted_receipts(context.parts, tenant_id, &request.receipts, &context.attempts).await?;
    let attempted = request.receipts.iter()
        .filter(|source| marked.contains(&(source.key.clone(), source.sha256.clone(), source.version.clone())))
        .cloned()
        .collect::<Vec<_>>();
    let needs_replay_proof = !attempted.is_empty();
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
    Ok(ValidatedFinding { request, proposed, needs_replay_proof, attempted, objects, registered: false })
}

/// NAN-3067: never START an append whose requester already gave up on it
/// (its acknowledgement would be lost). Checked before the parts are
/// registered with the writer authority; once they are, the append commits
/// even past the deadline (NAN-4700, [`Ingestor::commit_finding`]).
pub fn requester_still_waiting(request: &FindingAppendRequest, now_ms: i64) -> Result<()> {
    if let Some(deadline) = request.deadline_unix_ms {
        ensure!(now_ms <= deadline,
            super::finding_gate::FindingRefused::Deadline("the requester's deadline passed before the registration"));
    }
    Ok(())
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

async fn fetch_receipt<'s>(parts: &dyn ObjectStore, source: &'s SourceRef) -> Result<(&'s SourceRef, Vec<u8>)> {
    let receipt = parts.get(&source.key).await?.context("finding receipt is absent")?;
    Ok((source, receipt))
}

/// Partials fetched ahead during a prevalence rebuild or replay.
pub const PREVALENCE_PREFETCH: usize = 4;

/// NAN-3849: part-log entries one batched catch-up step scans past the
/// cursor (cached across steps), and how many entries / partials it fetches
/// at once.
// A 1,024-entry preload costs >6 s at 100 ms/GET even with 16 lanes,
// exceeding the 5 s ingest wait before the first durable apply.
pub const PREVALENCE_CATCH_UP_SCAN: u64 = 32;
pub const PREVALENCE_CATCH_UP_FETCHES: usize = 16;
/// NAN-4460: a scaled batch (scale `s`) scans `s` times
/// [`PREVALENCE_CATCH_UP_SCAN`] entries and fetches on `min(s, 4)` times
/// [`PREVALENCE_CATCH_UP_FETCHES`] lanes. At scale 8 that is a 256-entry
/// scan on 64 lanes: 4 rounds of GETs, and completed GETs survive a cut
/// step.
pub const PREVALENCE_CATCH_UP_FETCH_SCALE_MAX: usize = 4;

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
    /// NAN-4464: the batch's reads are still running past the step's
    /// deadline; a later step commits it.
    Reading,
}

/// Default [`IngestConfig::prevalence_op_timeout`].
pub const PREVALENCE_OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// Default [`IngestConfig::prevalence_ingest_wait`]: well above a healthy
/// lookup or apply (milliseconds) and a catch-up step
/// (`prevalence_rebuild_budget_ms`, 2 s), far below the flush interval.
pub const PREVALENCE_INGEST_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Default [`IngestConfig::prevalence_stamp_wait`] (NAN-4592). A warm
/// lookup (disk-cached state) of a large-tenant-sized batch (~2-5k artifacts at 256
/// lanes) takes tens of milliseconds; a cold one reads R2 for seconds. The large tenant
/// (hosted, 2026-10-26) spent the whole 5 s ingest wait on 65 of 274
/// flushes (~28%) and then committed those batches unstamped anyway: past
/// this wait the batch is owed a restamp instead of holding admission.
pub const PREVALENCE_STAMP_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// NAN-3879: admission waits (each at most the stamp wait, NAN-4592) on a state that
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

/// Is this append a replay of a committed `Add`? `attempted` are the
/// request's receipts an attempt marker names (the only ones the log can
/// hold); `receipts` is the whole request. NAN-4656: resumes after the
/// durable replay floors, so a retry reads only entries not yet proven.
pub async fn finding_replay_proof(context: &FindingAppendContext<'_>, receipts: &[SourceRef], attempted: &[SourceRef])
    -> Result<Option<FindingAppendResponse>> {
    if attempted.is_empty() {
        return Ok(None);
    }
    let committed = committed_receipts_cached(context.parts, &context.tenant_id, attempted, &context.trusted,
        &context.floors).await?;
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
        match self.lookup.clone().observe_restamp(artifacts, self.sealed).await {
            Ok((scalars, complete)) => {
                tracing::info!(hour = self.hour, rows, artifacts = distinct, completed_artifacts = scalars.len(),
                    complete, sealed = self.sealed, "prevalence restamp looked up");
                Ok(Some(Arc::new(RestampMap::with_completion(scalars, complete))))
            }
            Err(error) => failed(format!("{error:#}")),
        }
    }
}

/// NAN-3864: record what a finished merge restamped.
fn restamp_applied(map: Option<&super::restamp::RestampMap>, outcome: Option<&super::restamp::RestampOutcome>, ok: bool) {
    if let (Some(map), Some(outcome), true) = (map, outcome, ok) {
        outcome.set(super::restamp::RestampResult::Applied { rows: map.restamped_rows(), complete: map.complete() });
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
pub(crate) const INITIAL_ARROW_PER_SOURCE_BYTE: f64 = 40.0;
/// Modelled JSON-value heap ([`value_heap_bytes`]) per uncompressed bronze
/// byte (NAN-4319). Measured 15.3 on Tenzir OCSF 3002 landing objects (10k
/// and 50k rows; the 50k-row object was 911 KB compressed, 48 MB decoded,
/// 698 MB modelled). Independent of how well the object compressed.
pub(crate) const HEAP_PER_DECODED_BYTE: f64 = 16.0;
/// Buffered Arrow bytes per uncompressed bronze byte (NAN-4319; measured
/// 0.53 on the same objects).
pub(crate) const ARROW_PER_DECODED_BYTE: f64 = 1.0;

/// Predicted admission (modelled JSON heap, Arrow rows) of objects whose
/// rows decode to `decoded` uncompressed bytes.
pub(crate) fn decoded_admission_cost(decoded: u64) -> (f64, f64) {
    (decoded as f64 * HEAP_PER_DECODED_BYTE, decoded as f64 * ARROW_PER_DECODED_BYTE)
}

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

/// NAN-4573: the event hour of a clamped row's source time, when it is not
/// the hour the row is stored in (`clamped`: source time in epoch ms by uid).
fn original_hour_of(clamped: &BTreeMap<String, i64>, uids: &[String], index: usize, hour: i32) -> Option<i32> {
    clamped.get(&uids[index]).map(|ms| event_hour_of(ms.saturating_mul(1_000))).filter(|original| *original != hour)
}

/// The window payload hash of each kept uid, row-aligned (NAN-3704). A uid
/// admission has no source identity for (never expected) is not compared.
fn payload_hashes(uids: &[String], digests: &BTreeMap<String, [u8; 32]>) -> Vec<u64> {
    uids.iter().map(|uid| digests.get(uid).map_or(PAYLOAD_UNKNOWN, payload_hash64)).collect()
}

/// NAN-3899: each row's credential (row-aligned), or nothing when
/// credential activity is off.
fn row_credentials(rows: &[crate::iceberg::EventRow], track: bool) -> Vec<Option<String>> {
    if !track {
        return Vec::new();
    }
    rows.iter().map(super::credential_activity::row_credential).collect()
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

/// NAN-4553: removes admission slice files when an admission returns,
/// whichever way (a missing file is fine: the fold removed it already).
struct RemoveOnDrop(Vec<PathBuf>);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = std::fs::remove_file(path);
        }
    }
}

type AdmissionFile = (NoticeHandle, SourceNotice, PathBuf, String, u64);

/// NAN-4553: cut `file` (one fetched bronze object) into Parquet slices of
/// at most `rows` rows next to it, each carrying the object's identity.
/// Admission then holds one slice's JSON values at a time. Row order is
/// kept; the slices are removed by the caller once admitted.
fn write_admission_slices(file: &AdmissionFile, rows: u64) -> Result<Vec<AdmissionFile>> {
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    let (handle, notice, path, sha, bytes) = file;
    let batch_rows = usize::try_from(rows.max(1)).unwrap_or(usize::MAX);
    let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path)?)?.with_batch_size(batch_rows).build()?;
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::ZSTD(Default::default()))
        .build();
    let dir = path.parent().context("admission object has no directory")?;
    let mut slices = Vec::new();
    let cut = (|| -> Result<()> {
        for batch in reader {
            let batch = batch?;
            if batch.num_rows() == 0 {
                continue;
            }
            let slice = dir.join(format!("{sha}.slice-{:05}.parquet", slices.len()));
            slices.push((handle.clone(), notice.clone(), slice.clone(), sha.clone(), *bytes));
            let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(&slice)?, batch.schema(), Some(props.clone()))?;
            writer.write(&batch)?;
            writer.close()?;
        }
        ensure!(!slices.is_empty(), "admission object has no rows to slice");
        Ok(())
    })();
    if let Err(error) = cut {
        for slice in &slices {
            let _ = std::fs::remove_file(&slice.2);
        }
        return Err(error);
    }
    Ok(slices)
}

/// Beside a flight, validate the real slice footers, not the object's
/// average. Retry with smaller slices down to the pipelining minimum;
/// when even those do not fit, wait for idle admission instead.
fn write_pipelined_admission_slices(file: &AdmissionFile, mut rows: u64,
    budget: u64, committed: u64) -> Result<Option<Vec<AdmissionFile>>> {
    let object_decoded = crate::bronze::bronze_file_decoded_bytes(&file.2)?;
    loop {
        let slices = write_admission_slices(file, rows)?;
        let mut cleanup = RemoveOnDrop(slices.iter().map(|slice| slice.2.clone()).collect());
        let decoded = slices.iter().map(|slice| crate::bronze::bronze_file_decoded_bytes(&slice.2)).collect::<Result<Vec<_>>>()?;
        if super::memory::pipelined_slices_fit(budget, committed, object_decoded, &decoded) {
            cleanup.0.clear();
            return Ok(Some(slices));
        }
        drop(cleanup);
        if rows <= super::memory::MIN_PIPELINED_SLICE_ROWS {
            return Ok(None);
        }
        rows = (rows / 2).max(super::memory::MIN_PIPELINED_SLICE_ROWS);
    }
}

/// Size ingest[T]'s memory-bound knobs from its process memory cap (the
/// cell's `memory_cap_bytes`): the uid window, the working budget that
/// bounds admission, flushes and merges (NAN-3183, NAN-4553), and (NAN-4460)
/// the prevalence catch-up batch. The production cell and the memory tests
/// both size through here.
pub fn size_for_memory_cap(cfg: &mut IngestConfig, memory_cap_bytes: u64) {
    cfg.max_window_uids = super::dedup::window_cap_for(memory_cap_bytes);
    cfg.buffer_budget_bytes = buffer_budget_for(memory_cap_bytes);
    cfg.merge_headroom_bytes = if memory_cap_bytes == 0 { 0 } else {
        super::merge::decode_window_rows_for(memory_cap_bytes) as u64 * super::merge::MERGE_ROW_BYTES
    };
    cfg.prevalence_catch_up_max_rows = super::prevalence::catch_up_max_rows_for(memory_cap_bytes);
}

/// The admission buffer budget for a process memory cap.
pub fn buffer_budget_for(memory_cap_bytes: u64) -> u64 {
    if memory_cap_bytes == 0 {
        return DEFAULT_BUFFER_BUDGET_BYTES;
    }
    ((memory_cap_bytes as f64 * BUFFER_BUDGET_SHARE) as u64).clamp(64 * 1024 * 1024, 4 * 1024 * 1024 * 1024)
}

/// Most sealed flushes in flight per tenant. No deployment switch.
pub const MAX_FLUSH_DEPTH: usize = 2;

/// The edge source settings for a flush depth: as many outstanding ranges
/// as flights. The pulled-bytes allowance stays the single-flight one, so a
/// second range never raises the source's memory (a large first flight
/// simply leaves less to pull for the second).
pub fn edge_source_config(flush_depth: usize) -> crate::edge_log::EdgeLogSourceConfig {
    let depth = flush_depth.clamp(1, MAX_FLUSH_DEPTH);
    let base = crate::edge_log::EdgeLogSourceConfig::default();
    crate::edge_log::EdgeLogSourceConfig {
        max_issued_ranges: depth,
        // Range capacity does not increase the source memory allowance.
        max_buffered_bytes: base.max_buffered_bytes,
        ..base
    }
}

/// Age cap of a flush while ingest is behind (notices waiting): flushes then
/// close on their row/byte/object caps, this only bounds a slow trickle.
pub const CATCH_UP_FLUSH_MAX_AGE_MS: i64 = 30_000;

/// Rows below which an hour of a flush stays one L0 part; above it the
/// hour is cut into up to [`MAX_PARALLEL_L0_WRITES`] parts of equal rows.
pub const L0_PARALLEL_MIN_ROWS: usize = 16_384;
/// NAN-4539 step 3a: the smallest buffer that seals before a published
/// flight's inline commit (one full L0 part's rows).
pub const SEAL_FIRST_MIN_ROWS: usize = L0_PARALLEL_MIN_ROWS;
pub use super::memory::MAX_PARALLEL_L0_WRITES;

/// L0 parts a flush of `buffer` writes: [`l0_chunks`] of every hour.
#[cfg(test)]
fn planned_l0_parts(buffer: &Buffered) -> usize {
    buffer.hours.values()
        .map(|batches| l0_chunks(batches.iter().map(|batch| batch.num_rows()).sum()).len())
        .sum()
}

/// `(offset, len)` row ranges an hour of `rows` sorted rows is written as.
pub fn l0_chunks(rows: usize) -> Vec<(usize, usize)> {
    l0_chunks_into(rows, (rows / L0_PARALLEL_MIN_ROWS).clamp(1, MAX_PARALLEL_L0_WRITES))
}

/// `(offset, len)` ranges cutting `rows` into at most `parts` equal ranges.
fn l0_chunks_into(rows: usize, parts: usize) -> Vec<(usize, usize)> {
    if rows == 0 {
        return Vec::new();
    }
    let size = rows.div_ceil(parts.max(1));
    (0..rows).step_by(size).map(|offset| (offset, size.min(rows - offset))).collect()
}

/// NAN-4750: dedicated `(source, class)` L0 drafts one hour of one flush
/// may get, beside its one mixed rest group. With the rest that is at most
/// [`MAX_PARALLEL_L0_WRITES`] groups, so an hour of a flush writes at most
/// `max(l0_chunks(rows).len(), groups)` <= `MAX_PARALLEL_L0_WRITES` L0
/// parts: never more than a 64k-row flush hour already wrote before.
pub const MAX_L0_CLASS_DRAFTS: usize = MAX_PARALLEL_L0_WRITES - 1;

/// NAN-4750: the `(source, class)` families of one hour's buffered rows
/// that get their own class-labelled L0 part: those of at least
/// [`super::merge::CLASS_FAMILY_MIN_ROWS`] rows (the hour merge's floor for
/// a dedicated file), largest first, at most [`MAX_L0_CLASS_DRAFTS`]. Rows
/// without a source or class (and batches whose schema has neither yet) are
/// not counted; they stay in the mixed rest. Only the choice depends on
/// these counts: [`split_l0_families`] decides each row's group on the
/// aligned rows themselves.
fn l0_class_families(batches: &[RecordBatch]) -> Result<Vec<(String, i64)>> {
    // A low-rate flush (the common case) skips the per-row count on the tick.
    if (batches.iter().map(RecordBatch::num_rows).sum::<usize>() as u64) < super::merge::CLASS_FAMILY_MIN_ROWS {
        return Ok(Vec::new());
    }
    let mut counts = super::merge::ClassCounts::new();
    for batch in batches {
        if batch.column_by_name("class_uid").is_none() || super::writer::log_source_strings(batch).is_err() {
            continue;
        }
        super::merge::count_source_classes(batch, &mut counts)?;
    }
    Ok(super::merge::ranked_class_families(counts, super::merge::CLASS_FAMILY_MIN_ROWS, MAX_L0_CLASS_DRAFTS)
        .into_iter().map(|(family, _)| family).collect())
}

/// NAN-4750: split one hour's `(time, uid)`-sorted rows into the
/// dedicated `families` (in that order) and the mixed rest (last). Each
/// group keeps the sorted order; empty groups are dropped. Every row lands
/// in exactly one group.
fn split_l0_families(batch: &RecordBatch, families: &[(String, i64)]) -> Result<Vec<(Option<(String, i64)>, RecordBatch)>> {
    if families.is_empty() || batch.num_rows() == 0 {
        return Ok(vec![(None, batch.clone())]);
    }
    let sources = super::writer::log_source_strings(batch)?;
    let classes = batch.column_by_name("class_uid");
    let mut rows: Vec<Vec<u32>> = vec![Vec::new(); families.len() + 1];
    for row in 0..batch.num_rows() {
        let group = if arrow_array::Array::is_null(&sources, row) { None } else {
            super::merge::class_at(classes, row).and_then(|class| {
                let source = sources.value(row);
                families.iter().position(|(s, c)| *c == class && s == source)
            })
        };
        rows[group.unwrap_or(families.len())].push(u32::try_from(row)?);
    }
    let mut groups = Vec::with_capacity(rows.len());
    for (index, indices) in rows.into_iter().enumerate() {
        if indices.is_empty() {
            continue;
        }
        let indices = arrow_array::UInt32Array::from(indices);
        let columns = batch.columns().iter().map(|column| arrow_select::take::take(column.as_ref(), &indices, None))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        groups.push((families.get(index).cloned(), RecordBatch::try_new(batch.schema(), columns)?));
    }
    ensure!(groups.iter().map(|(_, rows)| rows.num_rows()).sum::<usize>() == batch.num_rows(), "L0 family split lost rows");
    Ok(groups)
}

/// NAN-4750: L0 parts per group of `rows` (an hour's family groups): each
/// group as [`l0_chunks`] would cut it, then trimmed (fewest rows per part
/// first) until the hour writes at most `max(l0_chunks(total).len(),
/// groups)` parts. A class split therefore adds parts only to an hour of
/// fewer than `MAX_PARALLEL_L0_WRITES * L0_PARALLEL_MIN_ROWS` rows, and at
/// most [`MAX_L0_CLASS_DRAFTS`] of them.
fn l0_group_parts(rows: &[usize]) -> Vec<usize> {
    let total = rows.iter().sum::<usize>();
    let budget = l0_chunks(total).len().max(rows.len());
    let mut parts = rows.iter().map(|rows| (rows / L0_PARALLEL_MIN_ROWS).clamp(1, MAX_PARALLEL_L0_WRITES)).collect::<Vec<_>>();
    while parts.iter().sum::<usize>() > budget {
        // Some group has more than one part: the sum exceeds the group count.
        let index = (0..parts.len()).filter(|i| parts[*i] > 1)
            .min_by_key(|i| (rows[*i] / parts[*i], *i)).expect("a group with more than one part");
        parts[index] -= 1;
    }
    parts
}

/// NAN-4674: a buffered batch below this many rows is tiny.
pub const TINY_BATCH_ROWS: usize = 256;
/// NAN-4674: a run of this many tiny batches at the end of an hour is folded
/// into one.
pub const TINY_BATCH_RUN: usize = 32;

/// NAN-4674: fold the trailing run of tiny batches of one hour (same
/// schema, in order) into one batch once it is [`TINY_BATCH_RUN`] long.
/// A backfill object spread over ~166 hours leaves about one row per hour,
/// and a one-row batch of the wide OCSF schema holds a 64-byte-aligned
/// buffer per array: tens of KB for one row, which sealed a wide buffer on
/// its byte cap long before its row cap. Live batches (hundreds of rows per
/// object in one or two hours) are never touched. Rows, their order and
/// schema are unchanged; the flush concatenates and sorts each hour anyway.
/// Returns the Arrow bytes freed and added.
pub fn compact_tiny_batches(batches: &mut Vec<RecordBatch>) -> Result<(u64, u64)> {
    // Cheap first: only a tail of TINY_BATCH_RUN tiny batches is worth a
    // schema check (a deep compare, about once per run, not per push).
    let n = batches.len();
    if n < TINY_BATCH_RUN || batches[n - TINY_BATCH_RUN..].iter().any(|batch| batch.num_rows() >= TINY_BATCH_ROWS) {
        return Ok((0, 0));
    }
    let schema = batches[n - 1].schema();
    let run = batches.iter().rev()
        .take_while(|batch| batch.num_rows() < TINY_BATCH_ROWS
            && (Arc::ptr_eq(&batch.schema(), &schema) || batch.schema() == schema))
        .count();
    if run < TINY_BATCH_RUN {
        return Ok((0, 0));
    }
    // Fold first, then replace: an error leaves the hour's batches as they were.
    let start = n - run;
    let folded = arrow_select::concat::concat_batches(&schema, &batches[start..])?;
    debug_assert_eq!(folded.num_rows(), batches[start..].iter().map(RecordBatch::num_rows).sum::<usize>());
    let freed = batches[start..].iter().map(|batch| batch.get_array_memory_size() as u64).sum::<u64>();
    let added = folded.get_array_memory_size() as u64;
    batches.truncate(start);
    batches.push(folded);
    Ok((freed, added))
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
#[cfg(test)]
pub(crate) fn write_l0_parts_with(dir: &Path, drafts: Vec<(PartDraft, RecordBatch)>, now_ms: i64, writers: usize) -> Result<Vec<FinishedPart>> {
    write_l0_family_parts_with(dir, drafts.into_iter().map(|(draft, batch)| (draft, batch, None)).collect(), now_ms, writers)
}

/// [`write_l0_parts_with`] where a draft may name the one `(source, class)`
/// family all its rows belong to (NAN-4750: its files are class-labelled).
pub(crate) fn write_l0_family_parts_with(dir: &Path, drafts: Vec<(PartDraft, RecordBatch, Option<(String, i64)>)>, now_ms: i64,
    writers: usize) -> Result<Vec<FinishedPart>> {
    let write = |(draft, batch, family): (PartDraft, RecordBatch, Option<(String, i64)>)| -> Result<FinishedPart> {
        let mut writer = PartWriter::create(dir, draft, PartialSource::FromRows, now_ms, batch.num_rows() as u64)?;
        if let Some((source, class)) = family {
            writer.label_l0_class_family(&source, class)?;
        }
        writer.write(&batch)?;
        writer.finish()
    };
    if drafts.len() <= 1 {
        return drafts.into_iter().map(write).collect();
    }
    let jobs = std::sync::Mutex::new(drafts.into_iter().enumerate().collect::<std::collections::VecDeque<_>>());
    let total = jobs.lock().expect("l0 jobs").len();
    let results = std::sync::Mutex::new((0..total).map(|_| None).collect::<Vec<Option<Result<FinishedPart>>>>());
    #[cfg(test)]
    let tracked = crate::test_heap::tracking_current_thread();
    std::thread::scope(|scope| {
        for _ in 0..writers.clamp(1, MAX_PARALLEL_L0_WRITES).min(total) {
            scope.spawn(|| {
                #[cfg(test)]
                crate::test_heap::track_current_thread(tracked);
                loop {
                    let Some((index, job)) = jobs.lock().expect("l0 jobs").pop_front() else { break };
                    let result = write(job);
                    results.lock().expect("l0 results")[index] = Some(result);
                }
            });
        }
    });
    results.into_inner().expect("l0 results").into_iter()
        .map(|result| result.context("an L0 part writer did not finish")?)
        .collect()
}

pub const MERGE_TICK_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);
/// NAN-4796: a merge stopped by memory the process held elsewhere (not
/// its own growth) retries after this, at the same shape, uncounted.
pub const MEMORY_STOP_RETRY_MS: i64 = 60_000;
/// NAN-4796: such stops of one merge before they count against its shape
/// again (the ledger's bounded ladder): a process that never gets back
/// under the start share cannot hold an hour's merge waiting forever.
pub const MAX_UNCHARGED_MEMORY_STOPS: u32 = 3;

fn parts_dir(work_dir: &Path) -> PathBuf {
    work_dir.join("parts")
}

/// The ingest-owned completion marker (under `log/checkpoints/`) proving the
/// finding attempt index covers every historical finding `Add`. Once it
/// exists, a receipt with no attempt marker was never offered to the log.
pub(crate) const FINDING_ATTEMPT_INDEX_READY: &str = "finding-attempt-index-v1";

/// The per-receipt attempt marker of releases before NAN-4181 (still read;
/// no longer written: see [`super::finding_attempts`]).
pub(crate) fn finding_attempt_key(tenant_id: &str, source: &SourceRef) -> Result<String> {
    legacy_attempt_key(tenant_id, source)
}

/// Migrate pre-index finding entries once. The immutable completion marker is
/// written last, so interruption safely resumes the migration; later ingest
/// restarts use one GET and keep no lifetime-sized receipt set in memory.
async fn initialize_finding_attempt_index(store: &dyn ObjectStore, tenant_id: &str, head: Option<u64>, now_ms: i64,
    attempts: &AttemptCache) -> Result<()> {
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
                // NAN-4181: one batch marker per historical `Add`.
                let findings = consumed.into_iter().filter(|source| source.key.starts_with(&receipt_prefix)).collect::<Vec<_>>();
                if !findings.is_empty() {
                    put_attempt_batch(store, tenant_id, &findings, now_ms, attempts).await?;
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

/// NAN-4749: `f` on every admission row, in
/// [`super::schema::DECODE_CHUNK_ROWS`] chunks on the rayon pool like the
/// decode (row order and results are the serial ones); one chunk runs inline.
fn for_each_row_chunk<T: Send>(rows: &mut [T], f: impl Fn(&mut [T]) -> Result<()> + Sync + Send) -> Result<()> {
    use rayon::prelude::*;
    if rows.len() <= super::schema::DECODE_CHUNK_ROWS {
        return f(rows);
    }
    rows.par_chunks_mut(super::schema::DECODE_CHUNK_ROWS).try_for_each(f)
}

/// NAN-4749: `f` of every admission row, row-aligned, chunked like
/// [`for_each_row_chunk`].
fn map_rows<T: Sync, U: Send>(rows: &[T], f: impl Fn(&T) -> U + Sync + Send) -> Vec<U> {
    use rayon::prelude::*;
    if rows.len() <= super::schema::DECODE_CHUNK_ROWS {
        return rows.iter().map(f).collect();
    }
    rows.par_iter().with_min_len(super::schema::DECODE_CHUNK_ROWS).map(f).collect()
}

fn strip_untrusted_risk_fields(event: &mut Value) {
    // NAN-4664: the IOC indicator columns are derived by the part writer
    // only; a source-supplied one would shadow them.
    if let Some(root) = event.as_object_mut() {
        root.retain(|key, _| !nanosiem_core::search::lake_indicators::is_indicator_column(key));
    }
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
        if let Some(catalog) = &cfg.catalog {
            catalog.validate_tenant(&cfg.tenant_id)?;
        }
        std::fs::create_dir_all(parts_dir(&cfg.work_dir))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg.work_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let log = PartLogWriter::open(parts, &cfg.tenant_id, cfg.writer_epoch, seed, now_ms).await?;
        let finding_attempts = Arc::new(AttemptCache::default());
        initialize_finding_attempt_index(parts, &cfg.tenant_id, log.live().head().map(|head| head.0), now_ms,
            &finding_attempts).await?;
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
        let mut admission_attempts = AdmissionAttempts::open(&cfg.work_dir);
        let mut merge_attempts = super::merge_attempts::MergeAttempts::open(&cfg.work_dir, now_ms);
        if merge_attempts.died_during_merge() {
            // NAN-4755: the kill may as well have been the merge's: the
            // objects the dead process admitted alone are not charged for
            // it (they stay suspects, isolated as before).
            let forgiven = admission_attempts.forgive_last_process()
                .context("persist admission forgiveness after merge death")?;
            if forgiven > 0 {
                tracing::warn!(tenant = %cfg.tenant_id, forgiven,
                    "ingest died with a merge in flight; its admission charges are not counted against the objects");
            }
            merge_attempts.admission_forgiven().context("acknowledge admission forgiveness")?;
        }
        if !admission_attempts.is_empty() {
            tracing::warn!(tenant = %cfg.tenant_id,
                "ingest restarted with objects admitted and unacknowledged; admitting one object at a time until they commit");
        }
        let mut ingestor = Self {
            health: IngestHealth { agent_catalog: cfg.catalog_attachment_failure.map(catalog_failure_health), tenant_id: cfg.tenant_id.clone(), count_backfill_window: count_backfill.clone(), ..IngestHealth::default() },
            cfg,
            parts,
            finding_attempts,
            finding_floors: Arc::new(FloorCache::default()),
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
            catalog_flight: None,
            catalog_applied_seq: None,
            catalog_due_ms: 0,
            catalog_retry_ms: 0,
            gc_done: HashSet::new(),
            gc_authority: None,
            held_index_feed: None,
            catalog_held_since_ms: None,
            catalog_held_logged_ms: None,
            local_gc: None,
            last_retention_scan_ms: None,
            last_sanctioned_pass_ms: None,
            sanctioned_gc_catching_up: false,
            last_sanctioned_pass_busy_ms: 0,
            gc_deleted_reported: 0,
            last_gc_block_reason: None,
            gc_blocked_since_ms: None,
            last_admit_ms: None,
            payload_diff_logged_hour: None,
            in_batch_conflict_logged_hour: None,
            heap_per_source_byte: INITIAL_HEAP_PER_SOURCE_BYTE,
            arrow_per_source_byte: INITIAL_ARROW_PER_SOURCE_BYTE,
            calibration: super::memory::AdmissionCalibration::default(),
            merge_quarantine: BTreeMap::new(),
            merge_memory_waits: BTreeMap::new(),
            merge_in_flight: Vec::new(),
            flush_in_flight: VecDeque::new(),
            diagnostics: PipelineDiagnostics::default(),
            flight_wake: None,
            seal_deferred_since_ms: None,
            behind_last_tick: false,
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
            prevalence_deferred: None,
            ingest_ticks: 0,
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
            prevalence_catch_up_scale: 1,
            prevalence_read_stats_at_ms: 0,
            prevalence_reads_watch: None,
            prevalence_blocked_since: None,
            prevalence_overrun_reads: None,
            prevalence_unplaced: false,
            prevalence_reopening: false,
            prevalence_applied_seq: None,
            prevalence_behind_since_ms: None,
            prevalence_degraded_since_ms: None,
            prevalence_degraded_closed_ms: 0,
            prevalence_degraded_logged_ms: 0,
            prevalence_spell: Default::default(),
            prevalence_first_settled: false,
            prevalence_health_started_ms: None,
            prevalence_step_failing_since_ms: None,
            prevalence_log_cache: BTreeMap::new(),
            prevalence_batch_through: None,
            last_cache_sweep_ms: 0,
            prevalence_owed: super::restamp::OwedHours::default(),
            restamp_owed_loaded: false,
            restamp_owed_saved_ms: 0,
            restamp_owed_retry_ms: 0,
            restamp_scan: RestampScan::default(),
            restamp_owed_saved_bytes: None,
            restamp_not_before_ms: 0,
            restamp_retry: BTreeMap::new(),
            restamp_planned: None,
            admission_paused: false,
            admission_byte_budget: None,
            erasure: erasure_exec::ErasureExec::default(),
            credential_activity: None,
            quarantine: None,
            quarantine_swept_ms: 0,
            quarantine_mirror_failing_since: None,
            quarantine_record_ms: 0,
            quarantine_mirror_backoff: BTreeMap::new(),
            quarantine_restore_retry: (0, i64::MIN),
            quarantine_replay_pending: true,
            quarantine_ledger: None,
            admission_attempts,
            merge_attempts,
            merge_memory_wait_log_ms: 0,
            admission_deferred: false,
            #[cfg(test)]
            refuse_admissions: false,
            #[cfg(test)]
            fixed_admission_model: false,
        };
        ingestor.quarantine = match Quarantine::open(&ingestor.cfg.work_dir, &ingestor.cfg.tenant_id) {
            Ok(quarantine) => Some(quarantine),
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "bronze quarantine unavailable; refused objects are not kept");
                None
            }
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
        ingestor.update_pipeline_diagnostics();
        Ok(ingestor)
    }

    pub fn live_parts(&self) -> Vec<PartRef> {
        self.log.live().parts().cloned().collect()
    }

    /// NAN-3899: keep per-credential activity and write it through `exec`.
    pub fn set_credential_activity(&mut self, exec: super::credential_activity::ActivityExec) {
        self.credential_activity = Some(exec);
    }

    /// NAN-4338: report quarantined edge segments to the tenant's landing
    /// ledger through `sink`. Every entry already kept is reported again
    /// (idempotent at the ledger), so nothing kept before a restart, or
    /// before this report existed, is missed.
    pub fn set_quarantine_ledger(&mut self, sink: Arc<dyn super::quarantine_ledger::QuarantineLedgerSink>) {
        let mut ledger = super::quarantine_ledger::QuarantineLedger::open(&self.cfg.tenant_id, Some(&self.cfg.work_dir), sink);
        let kept = self.quarantine.as_ref().map(Quarantine::list).transpose().unwrap_or_else(|error| {
            tracing::warn!(error = %format!("{error:#}"), "bronze quarantine unreadable; kept entries are not reported to the landing ledger");
            None
        });
        for entry in kept.unwrap_or_default() {
            if let Some(report) = ledger_report(&self.cfg.tenant_id, &entry.source_key, entry.rows_rejected,
                super::quarantine_ledger::ReportState::Quarantined) {
                ledger.enqueue(report);
            }
        }
        self.quarantine_ledger = Some(ledger);
    }

    /// The landing-ledger reporter, if installed (tests, health).
    pub fn quarantine_ledger(&self) -> Option<&super::quarantine_ledger::QuarantineLedger> {
        self.quarantine_ledger.as_ref()
    }

    /// NAN-4338: wait for the landing-ledger reports in flight (tests).
    pub async fn settle_quarantine_ledger(&mut self, now_ms: i64) {
        if let Some(ledger) = &mut self.quarantine_ledger {
            ledger.settle(now_ms).await;
        }
    }

    /// The credential activity aggregate, if kept (tests, health).
    pub fn credential_activity(&self) -> Option<&super::credential_activity::CredentialActivity> {
        self.credential_activity.as_ref().map(|exec| &exec.activity)
    }

    /// A recorded catalog still owns its files even when its remote service
    /// is unavailable. Dropping custody here would let GC/erasure bypass it.
    ///
    /// NAN-4601: deletes stay held (fail closed), but the sanctioned gate is
    /// kept aside as [`Self::held_index_feed`] so the part-log index keeps
    /// following the log; the hold is reported as `catalog_held` and logged
    /// every [`CATALOG_HELD_LOG_INTERVAL_MS`].
    pub fn hold_catalog(&mut self, reason: &'static str) {
        self.cfg.catalog_attachment_failure = Some(reason);
        self.health.agent_catalog = Some(catalog_failure_health(reason));
        if let Some(authority) = self.gc_authority.take() {
            self.held_index_feed = Some(authority);
        }
        self.local_gc = None;
    }

    /// Install the lake-part delete gate. Without one, no part file is
    /// ever deleted (fail closed).
    pub fn set_local_gc(&mut self, authority: Arc<crate::lake_part_gc::local::LocalDeleteAuthority>) {
        if self.cfg.catalog.is_some() || self.cfg.catalog_attachment_failure.is_some() {
            // Basin is a hosted tenant-bucket lane. Never let a local delete
            // authority silently bypass its catalog custody.
            tracing::error!("local GC cannot own a hosted catalog; keeping parts");
            self.gc_authority = None;
            self.local_gc = None;
            return;
        }
        self.gc_authority = Some(Arc::new(crate::lake_part_gc::local::LocalPartGcAuthority(authority.clone())));
        self.local_gc = Some(authority);
    }

    pub fn set_part_gc_authority(&mut self, authority: Arc<dyn PartGcAuthority>) {
        if let Some(reason) = self.cfg.catalog_attachment_failure {
            self.hold_catalog(reason);
            // NAN-4601: the index feed only; deletes stay held.
            self.held_index_feed = Some(authority);
            return;
        }
        self.held_index_feed = None;
        if let Some(catalog) = &self.cfg.catalog {
            if let Err(error) = authority.attach_catalog(catalog.clone()) {
                tracing::error!(%error, "GC lacks catalog custody; keeping parts");
                self.gc_authority = None;
                self.health.agent_catalog = Some(serde_json::json!({"custody_attached":true,"gc_attached":false,"converged":false}));
                return;
            }
            self.health.agent_catalog = Some(serde_json::json!({"custody_attached":true,"gc_attached":true,"converged":false}));
        }
        self.gc_authority = Some(authority);
    }

    /// NAN-3810: feed the GC index watermark from this ingestor's part-log
    /// appends (production R2 store with the native writer only).
    pub fn set_receipted_appends(&mut self, receipted: Arc<crate::lake_part_gc::index::ReceiptedAppends>) {
        self.log.set_receipted_appends(receipted);
    }

    /// NAN-4052: every later part-log append must pass `gate` (the cell
    /// writer lease) right before its commit.
    pub fn set_append_gate(&mut self, gate: Arc<dyn crate::parts::part_log::AppendGate>) {
        self.log.set_append_gate(gate);
    }

    /// NAN-3522 over-commit hold: `byte_budget` (held) limits each admission
    /// to its first object plus what fits the budget; `paused` (only while
    /// held) admits nothing this tick. The notices stay pending in the
    /// source (edge log / Bronze), unacked.
    pub fn set_admission_hold(&mut self, byte_budget: Option<u64>, paused: bool) {
        self.admission_byte_budget = byte_budget;
        self.admission_paused = byte_budget.is_some() && paused;
    }

    pub fn diagnostics(&self) -> PipelineDiagnostics { self.diagnostics.clone() }

    fn update_pipeline_diagnostics(&self) {
        let mut state = self.diagnostics.state.lock().expect("pipeline diagnostics");
        state.rows = self.buffer.rows + self.flush_in_flight.iter().map(|flight| flight.buffer.rows).sum::<usize>();
        state.bytes = self.buffer.bytes + self.flush_in_flight.iter().map(|flight| flight.buffer.bytes).sum::<u64>();
        state.flights = self.flush_in_flight.len() + usize::from(self.buffer.flush_started_ms.is_some());
        state.oldest_flush_ms = self.flush_in_flight.front().map(|flight| flight.sealed_ms).into_iter()
            .chain(self.buffer.flush_started_ms).min();
        state.foreground = self.buffer.progress.clone();
        state.oldest_background = self.flush_in_flight.front().map(|flight| flight.progress.clone()).or_else(|| self.buffer.progress.clone());
        state.occupancy_observed = Some(std::time::Instant::now());
        state.occupancy = serde_json::json!({
            "configured_flush_depth": self.cfg.flush_depth, "effective_flush_depth": self.flush_depth(),
            "queue_range_capacity": self.queue.max_outstanding_ranges(), "filling_rows": self.buffer.rows,
            "filling_arrow_bytes": self.buffer.bytes, "filling_objects": self.buffer.handles.len(),
            "flight_rows": self.flush_in_flight.iter().map(|f| f.buffer.rows).sum::<usize>(),
            "flight_reserved_bytes": self.flush_in_flight.iter().map(|f| f.reserved_bytes).sum::<u64>(),
            "merge_reserved_bytes": self.merges_reserved_bytes(), "working_reserved_bytes": self.committed_bytes(),
            "working_budget_bytes": self.cfg.buffer_budget_bytes,
            "background_publish_available": self.background_parts.is_some() && self.background_signer.is_some(),
            "memory_budget_exhausted": self.committed_bytes() >= self.cfg.buffer_budget_bytes,
            "admission_paused": self.admission_paused, "partially_committed": self.buffer.partially_committed(),
            "pending_schema_change": self.pending_schema.fields() != self.schema.fields(),
            "rejections_or_skips": !self.buffer.rejections.is_empty() || !self.buffer.refused.is_empty() || !self.buffer.replayed.is_empty(),
            "may_seal_beside_flights": self.may_seal_beside_flights(true),
            "held_notices": self.buffer.handles.len() + self.flush_in_flight.iter().map(|f| f.buffer.handles.len()).sum::<usize>()});
        state.tracking_oldest = false;
        state.buffered_since = self.buffer.buffered_since.into_iter()
            .chain(self.flush_in_flight.iter().filter_map(|flight| flight.buffer.buffered_since)).min();
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
            if let Some(committed) = finding_replay_proof(&context, &validated.request.receipts, &validated.attempted).await? {
                return Ok(committed);
            }
        }
        requester_still_waiting(&validated.request, now_ms)?;
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
            attempts: self.finding_attempts.clone(),
            floors: self.finding_floors.clone(),
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
        // NAN-4700: the requester's deadline is checked BEFORE the parts are
        // registered ([`requester_still_waiting`]), not here. An append whose
        // registration outlived it still commits: refusing threw the
        // registration away, the next pass built new parts and registered
        // them from scratch, and a slow writer authority (FP ops, 2026-10-27:
        // `lake-writers:complete` 503s, no batch completion) refused every
        // pass. The lost acknowledgement is the ordinary lost-ack path: the
        // attempt marker and the floor written below send the next pass's
        // proof to the entries after this head, and it acknowledges this
        // `Add` instead of appending a second one.
        if let Some(deadline) = request.deadline_unix_ms.filter(|deadline| now_ms > *deadline) {
            tracing::info!(tenant = %self.cfg.tenant_id, late_ms = now_ms - deadline, receipts = request.receipts.len(),
                "finding append commits past its requester's deadline; the next drain pass acknowledges it from the log");
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
        let op = LogOp::Add { parts: request.parts, consumed: request.receipts, edge_log: None };
        let LogOp::Add { consumed, .. } = &op else { unreachable!("built as an Add") };
        // The writer refuses a repeat within its memory; refuse it before
        // any durable intent is recorded.
        self.log.live().check_consumes(&op)?;
        // Durable intent precedes the log append. A crash in either gap
        // makes replay scan the authoritative log. NAN-4181: ONE conditional
        // marker PUT per append, whatever its receipt count (one per receipt
        // was a Class A PUT per finding, repeated on every retry).
        put_attempt_batch(self.parts, &self.cfg.tenant_id, consumed, now_ms, &self.finding_attempts).await?;
        // NAN-4656: these receipts are not consumed through the head this
        // `Add` follows: each was proven absent by the replay proof or was
        // never offered (no marker). Recorded so the proof of an interrupted
        // append reads only the entries after it, not the log from genesis.
        // One conditional PUT per append; best effort.
        if let Some((seq, sha, _)) = self.log.live().head() {
            put_floor_logged(self.parts, &self.cfg.tenant_id, seq, sha, consumed).await;
        }
        // Like `commit_parts`: every committed `Add` reaches the prevalence
        // state in log order. The next tick's `advance_prevalence` replays it.
        if self.prevalence_held() {
            self.prevalence_pending = true;
        }
        let outcome = self.log.append(op, now_ms).await?;
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

    /// NAN-4460: the scale the next catch-up batch is planned at.
    pub fn prevalence_catch_up_scale(&self) -> usize {
        self.prevalence_catch_up_scale
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

    /// NAN-4592: the most one admission batch waits for its lookups.
    fn stamp_wait(&self) -> std::time::Duration {
        self.cfg.prevalence_stamp_wait.min(self.ingest_wait())
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
            Some(RestampResult::Applied { rows, complete }) => {
                self.health.prevalence_restamped_rows_total = self.health.prevalence_restamped_rows_total.saturating_add(rows);
                if restamp.sealed {
                    self.health.prevalence_restamp_rewrites_total = self.health.prevalence_restamp_rewrites_total.saturating_add(1);
                }
                self.restamp_retry.remove(&restamp.hour);
                let cleared = complete && self.hour_is_one_sealed_part(restamp.hour)
                    && self.prevalence_owed.clear_if(restamp.hour, restamp.serial);
                tracing::info!(tenant = %self.cfg.tenant_id, hour = restamp.hour, rows, complete, sealed = restamp.sealed, cleared,
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
        // NAN-4161: a non-empty set unchanged for half the scan horizon is
        // written again, so the newest snapshot never ages out of the scan.
        let refresh_due = self.restamp_owed_loaded && !self.prevalence_owed.is_empty()
            && now_ms.saturating_sub(self.restamp_owed_saved_ms) >= RESTAMP_SNAPSHOT_HORIZON_MS / 2;
        if !self.restamp_eligible() || now_ms < self.restamp_owed_retry_ms
            || (self.restamp_owed_loaded && !self.prevalence_owed.dirty() && !refresh_due) {
            return;
        }
        let wait = self.ingest_wait();
        // A failed or slow step waits a minute: a refused or hung store
        // costs one bounded call a minute, never one per tick.
        let retry_at = now_ms.saturating_add(60_000);
        if !self.restamp_owed_loaded {
            let scan = scan_restamp_owed(self.parts, &self.cfg.tenant_id, &mut self.restamp_scan, now_ms);
            match tokio::time::timeout(wait, scan).await {
                // NAN-4161: more pages remain; the scan resumes next tick,
                // at most RESTAMP_SCAN_PAGES_PER_CALL pages per tick. Nothing
                // is saved before the stored set was read.
                Ok(Ok(None)) => return,
                Ok(Ok(Some(stored))) => {
                    let before = self.prevalence_owed.len();
                    let dirty = self.prevalence_owed.dirty();
                    if let Some((written_ms, hours)) = stored {
                        self.restamp_owed_saved_ms = written_ms;
                        self.restamp_owed_saved_bytes = serde_json::to_vec(&hours).ok();
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
        let refresh_due = refresh_due || (!self.prevalence_owed.is_empty()
            && now_ms.saturating_sub(self.restamp_owed_saved_ms) >= RESTAMP_SNAPSHOT_HORIZON_MS / 2);
        if self.prevalence_owed.dirty() && !refresh_due
            && self.restamp_owed_saved_bytes.as_deref() == Some(self.prevalence_owed.to_bytes().as_slice()) {
            // NAN-4161: changed and changed back since the last snapshot.
            self.prevalence_owed.mark_saved();
        }
        if self.prevalence_owed.dirty() || refresh_due {
            let bytes = self.prevalence_owed.to_bytes();
            // Strictly after the snapshot read or written last: the newest
            // name is the set.
            let written_ms = now_ms.max(self.restamp_owed_saved_ms.saturating_add(1));
            match tokio::time::timeout(wait, persist_restamp_owed(self.parts, &self.cfg.tenant_id, &bytes, written_ms)).await {
                Ok(Ok(())) => {
                    self.prevalence_owed.mark_saved();
                    self.restamp_owed_saved_ms = written_ms;
                    self.restamp_owed_saved_bytes = Some(bytes);
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
        // Only completed state reads or WAL durability barriers count. Cache
        // growth from foreground ingest cannot prove a stalled WAL recovered.
        let reads = self.prevalence.as_ref().map(IngestPrevalence::watchdog_progress);
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
        self.prevalence_reads_watch = None;
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
            // NAN-4464: never wait on a batch's reads past the step's
            // deadline while they progress (the watchdog stops this).
            let patience = deadline.filter(|_| self.catch_up_reads_patient());
            match self.replay_prevalence_batch(patience).await? {
                CatchUpBatch::AtHead => {
                    // A prior tick may have been cut after its atomic cursor
                    // write but before WAL durability. Never stamp that cursor
                    // until its flush has completed (also covers scan-only spans).
                    self.prevalence.as_mut().context("prevalence is disabled")?.make_durable().await?;
                    return Ok(true);
                }
                CatchUpBatch::Applied => {
                    if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                        return Ok(false);
                    }
                }
                CatchUpBatch::Reading => return Ok(false),
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
    ///
    /// NAN-4464: `patience` bounds the wait for the batch's reads
    /// ([`IngestPrevalence::apply_entries_batch_within`]); past it the batch
    /// stays planned ([`CatchUpBatch::Reading`]).
    async fn replay_prevalence_batch(&mut self, patience: Option<std::time::Instant>) -> Result<CatchUpBatch> {
        use super::prevalence::{partial_rows, BatchEntry, CATCH_UP_BATCH_ENTRIES, CATCH_UP_BATCH_ROWS, CATCH_UP_MAX_SCALE};
        use futures::stream::{self, StreamExt};
        // NAN-4460: the batch's size, set when the previous batch committed
        // (so a batch cut mid-way is planned identically next step).
        let scale = self.prevalence_catch_up_scale.clamp(1, CATCH_UP_MAX_SCALE);
        let base_entries = self.cfg.prevalence_catch_up_batch_entries.clamp(1, CATCH_UP_BATCH_ENTRIES);
        let max_entries = base_entries * scale;
        let max_rows = (CATCH_UP_BATCH_ROWS * scale as u64)
            .min(self.cfg.prevalence_catch_up_max_rows.max(CATCH_UP_BATCH_ROWS));
        let fetches = PREVALENCE_CATCH_UP_FETCHES * scale.min(PREVALENCE_CATCH_UP_FETCH_SCALE_MAX);
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
        let scan_end = head.min(cursor.seq.saturating_add(PREVALENCE_CATCH_UP_SCAN * scale as u64));
        tracing::debug!(tenant = %self.cfg.tenant_id, cursor_seq = cursor.seq, head, scan_end,
            cached_entries = self.prevalence_log_cache.len(), "prevalence catch-up scan");
        let missing = (cursor.seq..=scan_end).filter(|seq| !self.prevalence_log_cache.contains_key(seq)).collect::<Vec<_>>();
        if !missing.is_empty() {
            let keys = LogKeys::new(&self.cfg.tenant_id)?;
            let parts = self.parts;
            let mut fetched = stream::iter(missing.into_iter().map(|seq| {
                let key = keys.entry(seq);
                async move { (seq, parts.get(&key).await) }
            }))
            .buffer_unordered(fetches);
            // Keep each verified completion before awaiting another GET.
            // Dropping a tick must never discard a whole scan's progress.
            while let Some((seq, bytes)) = fetched.next().await {
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
                    if candidates.len() >= max_entries || through.is_some_and(|through| seq > through) {
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
            }
            if scanned > cursor.seq {
                self.prevalence.as_mut().context("prevalence is disabled")?
                    .checkpoint_scanned(scanned, &previous).await?;
            }
            self.prevalence_applied_seq = Some(scanned);
            if scanned == head {
                self.prevalence_catch_up_scale = 1;
                return Ok(CatchUpBatch::AtHead);
            }
            return Ok(CatchUpBatch::Applied);
        }
        // Partials of every candidate part at once (local part cache first).
        let wanted = candidates.iter().flat_map(|(_, _, parts)| parts.iter())
            .filter(|part| !self.prevalence_prefetched.get(part.part_id.as_str()).is_some_and(|path| path.exists()))
            .cloned()
            .collect::<Vec<_>>();
        let mut remote = Vec::new();
        for part in wanted {
            match self.local_prevalence_partial(&part) {
                Ok(Some(path)) => {
                    self.prevalence_prefetched.insert(part.part_id.as_str().to_owned(), path);
                }
                _ => remote.push(part),
            }
        }
        let (cfg, parts, trusted) = (&self.cfg, self.parts, &self.trusted);
        let mut fetched = stream::iter(remote.into_iter().map(|part| async move {
            let fetched = Self::fetch_remote_prevalence_partial(cfg, parts, trusted, &part).await;
            (part, fetched)
        })).buffer_unordered(fetches);
        let mut unfetched = BTreeSet::new();
        while let Some((part, fetched)) = fetched.next().await {
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
        drop(fetched);
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
            if !batch.is_empty() && rows.saturating_add(entry_rows) > max_rows {
                break;
            }
            if batch.is_empty() && entry_rows > max_rows {
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
            .apply_entries_batch_within(&self.cfg.tenant_id, &batch, patience).await?;
        let Some(applied) = applied else { return Ok(CatchUpBatch::Reading) };
        self.prevalence_batch_through = None;
        self.prevalence_reads_watch = None;
        for entry in &batch {
            for (part_id, _, _) in &entry.parts {
                if let Some(path) = self.prevalence_prefetched.remove(part_id) {
                    let _ = std::fs::remove_file(path);
                }
                self.release_retained_partial(part_id);
            }
        }
        self.prevalence_applied_seq = Some(covered);
        self.health.prevalence_catch_up_batches_total = self.health.prevalence_catch_up_batches_total.saturating_add(1);
        let behind = head.saturating_sub(covered);
        tracing::info!(tenant = %self.cfg.tenant_id, first_seq = batch[0].seq, last_seq = last, entries = applied.entries,
            parts = applied.parts, rows = applied.rows, keys = applied.keys, fold_ms = applied.fold_ms,
            read_ms = applied.read_ms, write_ms = applied.write_ms, wall_ms = started.elapsed().as_millis() as u64,
            behind_entries = behind, scale, max_entries, max_rows, "prevalence catch-up batch applied");
        self.rescale_prevalence_catch_up(behind, base_entries);
        if covered == head {
            let (sha, _) = self.prevalence_log_cache.get(&head).context("part-log entry is missing")?;
            ensure!(*sha == head_sha, "part-log head changed during prevalence replay");
            return Ok(CatchUpBatch::AtHead);
        }
        Ok(CatchUpBatch::Applied)
    }

    /// NAN-4460: size the next catch-up batch from the backlog left and the
    /// cell's headroom ([`super::prevalence::next_catch_up_scale`]).
    fn rescale_prevalence_catch_up(&mut self, behind: u64, base_entries: usize) {
        let previous = self.prevalence_catch_up_scale;
        let headroom = super::merge_quota::catch_up_headroom(self.health.lag_ms, self.cfg.lag_alert_ms);
        let next = super::prevalence::next_catch_up_scale(previous, behind, base_entries, headroom);
        if next != previous {
            self.prevalence_catch_up_scale = next;
            tracing::info!(tenant = %self.cfg.tenant_id, scale = next, previous_scale = previous, behind_entries = behind,
                headroom = ?headroom, lag_ms = self.health.lag_ms, lag_bound_ms = self.cfg.lag_alert_ms,
                max_rows = self.cfg.prevalence_catch_up_max_rows,
                "prevalence catch-up batch scale adjusted to the backlog and cell headroom");
        }
    }

    /// NAN-4464: whether a step may return while a catch-up batch's reads
    /// run (and the tick skip its steps until they finish). True while they
    /// make progress (completed point reads or durable commits); after
    /// `prevalence_op_timeout` without any, steps wait on them again, so a
    /// hung store overruns the ingest wait and trips the stall watchdog
    /// ([`Self::prevalence_overran`]) as before.
    fn catch_up_reads_patient(&mut self) -> bool {
        let Some(progress) = self.prevalence.as_ref().map(IngestPrevalence::watchdog_progress) else { return false };
        match self.prevalence_reads_watch {
            Some((since, seen)) if seen == progress => since.elapsed() < self.cfg.prevalence_op_timeout,
            _ => {
                self.prevalence_reads_watch = Some((std::time::Instant::now(), progress));
                true
            }
        }
    }

    /// NAN-4464: a planned catch-up batch whose reads are still running and
    /// progressing: this tick's step would only wait on them.
    fn prevalence_catch_up_reading(&mut self) -> bool {
        self.prevalence_batch_through.is_some()
            && self.prevalence.as_ref().is_some_and(IngestPrevalence::catch_up_reads_in_flight)
            && self.catch_up_reads_patient()
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
        Self::fetch_remote_prevalence_partial(&self.cfg, self.parts, &self.trusted, part).await
    }

    async fn fetch_remote_prevalence_partial(
        cfg: &IngestConfig, parts: &dyn ObjectStore, trusted: &TenantKeySet, part: &PartRef,
    ) -> Result<PathBuf> {
        let keys = PartKeys::new(&cfg.tenant_id, part.level, part.event_hour, &part.part_id)?;
        let provenance = parts.get(&keys.provenance()).await?
            .ok_or_else(|| PrevalencePartialMissing { part_id: part.part_id.as_str().to_owned() })
            .context("part has no provenance")?;
        ensure!(sha256_hex(&provenance) == part.provenance_sha256, "part provenance does not match the log");
        let signed = SignedProvenance::verify_bytes(&provenance, &cfg.tenant_id, trusted)?;
        part.check_record(&signed.record, &part.provenance_sha256)?;
        let name = crate::parts::format::PARTIAL_PREVALENCE_FILE;
        let partial = signed.record.files.partials.iter().find(|file| file.name == name)
            .context("live part has no prevalence partial")?;
        let directory = cfg.work_dir.join("prevalence").join(&cfg.tenant_id);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}.parquet", part.part_id));
        let temporary = path.with_extension("partial");
        let _ = std::fs::remove_file(&temporary);
        if !parts.get_to_file(&keys.file(name), &temporary).await? {
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
        // NAN-4731: per-phase elapsed times (heartbeat `operation_timings`).
        let _timing = self.diagnostics.operations.start("tick_prevalence");
        self.tick_prevalence_step(now_ms).await;
        // NAN-3864: keep the owed restamp hours saved in the tenant bucket.
        self.sync_restamp_owed(now_ms).await;
        // NAN-4445: and the degraded spell's start.
        self.sync_prevalence_spell(now_ms).await;
    }

    /// NAN-4445: read the degraded spell an earlier process left open, then
    /// save this process's spell start / end when it changes, as immutable
    /// records in the tenant bucket ([`super::prevalence_spell`]). Each step
    /// is bounded by the ingest wait; a failed one is retried a minute later.
    /// Nothing is written before the stored spell was read and this
    /// process's first open settled (an unsettled open says nothing yet).
    async fn sync_prevalence_spell(&mut self, now_ms: i64) {
        if !self.restamp_eligible() || now_ms < self.prevalence_spell.retry_ms {
            return;
        }
        let wait = self.ingest_wait();
        let retry_at = now_ms.saturating_add(60_000);
        if !self.prevalence_spell.loaded {
            let scan = super::prevalence_spell::scan_spell(self.parts, &self.cfg.tenant_id, &mut self.prevalence_spell.scan, now_ms);
            match tokio::time::timeout(wait, scan).await {
                Ok(Ok(None)) => return,
                Ok(Ok(Some(found))) => {
                    self.prevalence_spell.loaded = true;
                    if let Some((written_ms, record)) = found {
                        self.prevalence_spell.saved = Some(record);
                        self.prevalence_spell.saved_ms = written_ms;
                        if record.cleared_ms.is_none() {
                            tracing::warn!(tenant = %self.cfg.tenant_id, since_ms = record.since_ms,
                                degraded_secs = now_ms.saturating_sub(record.since_ms) / 1_000,
                                "an earlier process left a prevalence degraded spell open; continuing it");
                            self.prevalence_spell.inherited_since_ms = Some(record.since_ms);
                        }
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %format!("{error:#}"), "read the prevalence degraded spell failed; retrying in a minute");
                    self.prevalence_spell.retry_ms = retry_at;
                    return;
                }
                Err(_) => {
                    tracing::warn!("read the prevalence degraded spell timed out; retrying in a minute");
                    self.prevalence_spell.retry_ms = retry_at;
                    return;
                }
            }
        }
        if !self.prevalence_first_settled || self.prevalence_spell.inherited_since_ms.is_some() {
            return;
        }
        let Some(record) = self.prevalence_spell.wanted(self.prevalence_degraded_since_ms, now_ms) else { return };
        let written_ms = now_ms.max(self.prevalence_spell.saved_ms.saturating_add(1));
        let save = super::prevalence_spell::persist_spell(self.parts, &self.cfg.tenant_id, record, written_ms);
        match tokio::time::timeout(wait, save).await {
            Ok(Ok(())) => {
                self.prevalence_spell.saved = Some(record);
                self.prevalence_spell.saved_ms = written_ms;
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %format!("{error:#}"), "save the prevalence degraded spell failed; retrying in a minute");
                self.prevalence_spell.retry_ms = retry_at;
            }
            Err(_) => {
                tracing::warn!("save the prevalence degraded spell timed out; retrying in a minute");
                self.prevalence_spell.retry_ms = retry_at;
            }
        }
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
            // NAN-4737: a deferred apply is the next admission's, beside its
            // parse; replaying it here would serialize it again.
            PrevalencePhase::Stamping => self.prevalence_pending && self.prevalence_deferred.is_none(),
            PrevalencePhase::Rebuilding { .. } | PrevalencePhase::CatchingUp | PrevalencePhase::Resetting => true,
        };
        if has_work && self.prevalence_catch_up_reading() {
            // NAN-4464: a catch-up batch's reads are running and progressing;
            // the first step after they finish commits it. Waiting here
            // would only take the ingest wait from this tick.
            tracing::debug!(tenant = %self.cfg.tenant_id, "prevalence catch-up batch still reading; step skipped");
        } else if has_work {
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
    /// it at most [`Self::stamp_wait`] (NAN-4592: 1 s, was the 5 s ingest
    /// wait). `None`: the batch goes unstamped and its hours are owed an
    /// exact restamp (not stamping, a committed `Add` not yet in the state,
    /// or the read failed or was slower than the wait; a slow read keeps
    /// running in the background, warming the cache).
    ///
    /// What a late stamp writes (NAN-4592, unchanged from NAN-3774/3864):
    /// every row of the batch is committed with no `prevalence_*` column
    /// value and no nano prevalence enrichment (`strip_stamps`; never a
    /// partial stamp or a stamp from part of the reads), the batch counts in
    /// `prevalence_unstamped_batches_total`, and the event hours of its rows
    /// are marked owed (`prevalence_owed`). The hour's restamp later stamps
    /// exactly those unstamped rows from the state at the log head; rows
    /// stamped on arrival are never changed. The late reads never stamp
    /// anything: their result is dropped and only their cached blocks remain.
    ///
    /// NAN-3879: a stamp is permanent, so it is never taken from a state
    /// missing committed rows: while an `Add` is pending (an apply cut at the
    /// ingest wait, a failed apply, a catch-up) the batch is unstamped and
    /// owed, blocked or not. An earlier batch's lookup still in flight is
    /// waited out within this batch's one stamp wait (it used to skip at
    /// once); per overrun spell admission waits at most
    /// [`PREVALENCE_ADMIT_OVERRUN_WAITS`] stamp waits.
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
            let budget = self.stamp_wait().saturating_mul(PREVALENCE_ADMIT_OVERRUN_WAITS);
            self.stamp_wait().min(budget.saturating_sub(self.prevalence_admit_waited))
        } else {
            self.stamp_wait()
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
        let artifacts = match super::prevalence::stamp_artifacts_of(rows) {
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
                tracing::warn!(tenant = %self.cfg.tenant_id, wait_ms = self.stamp_wait().as_millis() as u64,
                    "prevalence lookups slower than the stamp wait; this batch is unstamped, the reads finish in the background");
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
        self.restore_quarantine(now_ms).await;
        self.ingest_ticks += 1;
        let mut report = TickReport::default();
        // Late-tier runs finished in the background since the last tick.
        self.late.poll(now_ms).await;
        report.flushed_parts += self.seal_before_commit(now_ms).await?;
        // Pipelined flushes whose parts are published commit first.
        report.flushed_parts += self.reap_in_flight(now_ms, usize::MAX).await?;
        self.apply_points(now_ms).await?;
        // NAN-3643: an operator replay is admitted and flushed on its own.
        if self.admit_quarantine_replay(now_ms).await? {
            report.flushed_parts += self.flush(now_ms, false).await?;
            return Ok((report, Vec::new()));
        }
        // Look past what is already buffered or in flight (still pending
        // until acked), or a large flight fills the window and catch-up
        // looks idle: no admission and no pipelining (NAN-3619).
        // (Production default; the serial comparison policy keeps the fixed window.)
        let held = if self.cfg.commit_when_ready {
            self.buffer.handles.len() + self.flush_in_flight.iter().map(|flight| flight.buffer.handles.len()).sum::<usize>()
        } else {
            0
        };
        let pending_limit = self.cfg.max_objects_per_admission * 4 + held;
        let pending = self.queue.pending(pending_limit).await?;
        { let mut diagnostics = self.diagnostics.state.lock().expect("pipeline diagnostics");
            diagnostics.queue = serde_json::json!({"pending_sampled": pending.len(), "sample_limit": pending_limit,
                "fresh_pending_sampled": pending.iter().filter(|(handle, _)| !self.buffer.handle_names.contains(&handle.0)
                    && !self.flush_in_flight.iter().any(|flight| flight.buffer.handle_names.contains(&handle.0))).count(),
                "may_be_truncated": pending.len() == pending_limit});
            diagnostics.queue_observed = Some(std::time::Instant::now()); }
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
        // NAN-4749: the room is per admission group (decoded one after
        // another), not for the whole tick at once.
        let committed = self.committed_bytes();
        let mut packing = super::memory::AdmissionGroups::new(self.cfg.buffer_budget_bytes, committed,
            self.buffer.bytes, self.buffer.rows as u64);
        let idle = self.buffer.bytes == 0 && self.flush_in_flight.is_empty();
        let fixed_admission_model = self.fixed_admission_model();
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
                let (heap, arrow) = (notice.bytes as f64 * self.heap_per_source_byte, notice.bytes as f64 * self.arrow_per_source_byte);
                if packing.offer(heap, arrow, 0) != super::memory::Offer::Refused {
                    return true;
                }
                if *index == 0 && idle {
                    packing.force(heap, arrow, 0);
                    return true;
                }
                // NAN-4770: the next buffer's first object may be admitted in
                // row slices beside the flights; admission decides on its
                // footer (an unknown size is left to it).
                if *index == 0 && self.buffer.handles.is_empty() && !fixed_admission_model
                    && super::memory::admission_fits(self.cfg.buffer_budget_bytes, committed, 0.0, arrow) {
                    packing.force(heap, arrow, 0);
                    return true;
                }
                false
            })
            .map(|(_, notice)| notice.clone())
            .collect::<Vec<_>>();
        // NAN-4539 step 3a: an admission that takes only part of the fresh
        // notices (bounded by memory or by group) ticks again at once: the
        // cell loop's idle second otherwise caps catch-up admission at one
        // bounded group per second.
        let more_fresh = pending.iter().filter(|(handle, _)| pending_fresh(handle)).count() > fresh.len();
        // NAN-4319: objects acknowledged since leave the crash ledger.
        self.forget_acknowledged(&pending);
        self.admission_deferred = false;
        // Never admit into a buffer that is partly in the log (B1): its
        // appends are skipped on retry, so new rows would be acked unwritten.
        // NAN-4674: behind, a wide (backfill) buffer keeps admitting up to
        // the wide hour cap; see [`flush_event_hour_cap`].
        if !fresh.is_empty() && !self.buffer.partially_committed() && !self.admission_paused
            && self.buffer.hours.len() < flush_event_hour_cap(self.behind_last_tick)
            && self.buffer.replay.is_none()
            && !self.buffer_holds_suspect()
        {
            let fresh = self.crash_guard(fresh, now_ms).await?;
            if !fresh.is_empty() {
                let started = cpu_now();
                let admission_timing = self.diagnostics.operations.start("admission");
                let (rows, dups) = self.admit(&fresh, now_ms).await?;
                drop(admission_timing);
                self.health.cpu_ms_admission += cpu_now().saturating_sub(started);
                report.admitted_rows = rows;
                report.admitted_bytes = fresh.iter().map(|(_, notice)| notice.bytes).sum();
                report.duplicates = dups;
                if more_fresh && rows > 0 && !self.admission_deferred {
                    if let Some(wake) = &self.flight_wake {
                        wake.notify_one();
                    }
                }
            }
        }
        // NAN-3619: a flight that finished while admission ran commits now,
        // not at the next tick (on the load-test tenant they waited 9-26 s). Only ready
        // flights, oldest first: the same commit `flush` would make first.
        if self.cfg.commit_when_ready {
            report.flushed_parts += self.seal_before_commit(now_ms).await?;
            report.flushed_parts += self.reap_in_flight(now_ms, usize::MAX).await?;
        }
        // Catching up (notices pulled but not yet admitted): the age cap
        // would cut a flush every few seconds whatever its size, and every
        // flush pays fixed owner/R2/edge round trips. Fill the flush to its
        // row/byte/object caps instead, bounded by CATCH_UP_FLUSH_MAX_AGE_MS
        // (NAN-3183).
        let in_flight = &self.flush_in_flight;
        let behind = pending.iter().any(|(handle, _)| !self.buffer.handle_names.contains(&handle.0)
            && !in_flight.iter().any(|flight| flight.buffer.handle_names.contains(&handle.0)));
        self.behind_last_tick = behind;
        let (due_by_age, due_by_cap) = self.seal_due_parts(now_ms, behind);
        // NAN-4539 step 3a: behind, a seal that only its age made due and
        // that would have to wait for an unfinished flight is deferred: the
        // tick returns, admission keeps filling the buffer (within every cap
        // and the working budget above), and the seal lands on the first
        // tick a flight slot is free (the finished-flight wake). Waiting
        // here held the single ingest task for the whole oldest flight, so
        // the next seal was small and catch-up ran below its flight cost.
        let due = due_by_cap || (due_by_age && !(behind && self.seal_would_wait_for_flight(behind && self.buffer.replay.is_none())));
        if due_by_age && !due {
            self.diagnostics.stage("seal_deferred_beside_flight");
            self.health.seals_deferred_total = self.health.seals_deferred_total.saturating_add(1);
            self.seal_deferred_since_ms.get_or_insert(now_ms);
        }
        if due || self.buffer.partially_committed() || (self.buffer.rows == 0 && !self.buffer.handles.is_empty())
            || self.buffer.replay.is_some()
        {
            let started = cpu_now();
            // Behind, the flush pipelines: its build and upload overlap the
            // next admissions (the cell supplies the 'static handles).
            // A replay retry never pipelines (NAN-3643).
            let pipelined_before = self.health.flushes_pipelined_total;
            report.flushed_parts += self.flush(now_ms, behind && self.buffer.replay.is_none()).await?;
            self.health.cpu_ms_parts += cpu_now().saturating_sub(started);
            // NAN-4731: a pipelined seal while behind empties the buffer and
            // notices are waiting. The admission wake above is skipped when
            // the seal was forced by a deferred object (`admission_deferred`),
            // and the flight wakes the loop only once it is published
            // (~2 s), so the cell loop idled on its 1 s timer once per flush
            // (the NAN-4689 soak: ~1 s of every ~8.6 s flush cycle). Admit the
            // next round now; its room is the budget beside the new flight.
            if behind && self.health.flushes_pipelined_total > pipelined_before {
                if let Some(wake) = &self.flight_wake {
                    wake.notify_one();
                }
            }
        }
        // NAN-4737: an apply deferred by an earlier tick whose admission
        // never came (nothing fresh, paused, the buffer full) lands now: a
        // deferral outlives at most one ingest phase.
        if self.prevalence_deferred.as_ref().is_some_and(|deferred| deferred.tick < self.ingest_ticks) {
            self.finish_deferred_prevalence(now_ms).await;
        }
        Ok((report, pending))
    }

    /// Tick phase 3: merges, GC, evictions, export plan, health.
    pub async fn tick_maintain(&mut self, now_ms: i64, pending: &[(NoticeHandle, SourceNotice)], report: &mut TickReport) -> Result<()> {
        let _timing = self.diagnostics.operations.start("tick_maintain");
        // NAN-3619: commit flights that finished during the ingest phase
        // before merges and GC take their turn (ready ones only, in order).
        // A failure keeps the flight oldest; the next ingest phase retries
        // it and reports the error there, exactly as before this reap.
        if self.cfg.commit_when_ready {
            match self.seal_before_commit(now_ms).await {
                Ok(parts) => report.flushed_parts += parts,
                Err(error) => tracing::warn!(error = %format!("{error:#}"), "sealing beside a published flush failed; the ingest phase retries it"),
            }
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
        self.tick_catalog(now_ms).await;
        self.tick_erasure(now_ms, lag_now).await;
        // NAN-3899: at most one bounded credential activity write, off the tick.
        if let Some(exec) = &mut self.credential_activity {
            exec.tick(&self.cfg.tenant_id, now_ms).await;
        }
        // Retire only on successful maintenance, never on the retry-only GC
        // path. Both appends and the local GC pass hold the ingestor mutex.
        if let Some(authority) = self.local_gc.clone() {
            if let Err(error) = self.retire_local_expired(&authority, now_ms).await {
                tracing::warn!(error = %error, "local retention retirement failed; keeping parts");
            }
        } else if let Err(error) = self.retire_hosted_expired(now_ms).await {
            tracing::warn!(error = %format!("{error:#}"), "hosted retention retirement failed; keeping parts");
        }
        self.evict_superseded_cache(now_ms);
        self.tick_catalog(now_ms).await;
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
        self.tick_quarantine(now_ms);
        if let Err(error) = self.mirror_quarantine(now_ms, false).await {
            tracing::warn!(error = %format!("{error:#}"), "bronze quarantine mirror failed; retried next tick");
        }
        // NAN-4338: at most one bounded flight of landing-ledger reports, off the tick.
        if let Some(ledger) = &mut self.quarantine_ledger {
            ledger.tick(now_ms).await;
        }
        self.update_health(pending, now_ms)?;
        Ok(())
    }

    /// Catalog network IO never holds an ingest tick. At most one bounded
    /// flight owns this tenant's durable catalog state; erasure waits for its
    /// committed log sequence before reporting completion.
    async fn tick_catalog(&mut self, now_ms: i64) {
        if self.cfg.catalog_attachment_failure.is_some() { return; }
        let Some(catalog) = self.cfg.catalog.clone() else { return };
        if self.catalog_flight.as_ref().is_some_and(|f| f.handle.is_finished()) {
            let mut flight = self.catalog_flight.take().expect("finished catalog flight");
            match (&mut flight.handle).await {
                Ok(Ok(())) => {
                    self.catalog_applied_seq = Some(flight.head);
                    if let Some(status)=&mut self.health.agent_catalog {status["converged"]=serde_json::Value::Bool(true);status["part_log_seq"]=flight.head.into();
                        if let Some(status)=status.as_object_mut() {status.remove("export_blocked");}}
                    self.catalog_due_ms = now_ms.saturating_add(3_600_000);
                    self.catalog_retry_ms = 0;
                }
                outcome => {
                    // NAN-4627: an export chain the writer cannot rebuild never
                    // heals by retrying; surface a stable alert label.
                    let unrecoverable = matches!(&outcome, Ok(Err(error))
                        if error.downcast_ref::<super::iceberg_export::ExportStateUnrecoverable>().is_some());
                    if let Some(status)=&mut self.health.agent_catalog {status["converged"]=serde_json::Value::Bool(false);
                        if unrecoverable {status["export_blocked"]=super::iceberg_export::ExportStateUnrecoverable::CODE.into();}}
                    // NAN-4614: a sync that spent its budget committing
                    // durable batches made progress; resume on the next tick.
                    let progressed = matches!(&outcome, Ok(Err(error))
                        if error.downcast_ref::<super::iceberg_export::lifecycle::CatalogSyncIncomplete>().is_some());
                    if unrecoverable {
                        tracing::error!(?outcome, reason = super::iceberg_export::ExportStateUnrecoverable::CODE,
                            "catalog export state unrecoverable; export and GC stay held");
                    } else if progressed {
                        tracing::info!(?outcome, "catalog export batches committed; resuming next tick, erasure and GC retain custody");
                    } else {
                        tracing::warn!(?outcome, "catalog reconciliation pending; erasure and GC retain custody");
                    }
                    self.catalog_retry_ms = if progressed { now_ms } else { now_ms.saturating_add(30_000) };
                }
            }
        }
        if self.catalog_flight.is_some() || now_ms < self.catalog_retry_ms { return; }
        let Some((head, _, _)) = self.log.live().head() else { return };
        if self.catalog_applied_seq == Some(head) && now_ms < self.catalog_due_ms && !catalog.recovery_required() { return; }
        let tenant = self.cfg.tenant_id.clone();
        let live = self.log.live().parts().cloned().collect();
        let policy = self.cfg.merge_policy;
        let handle = tokio::spawn(async move { catalog.sync_parts(&tenant, live, now_ms, &policy).await });
        self.catalog_flight = Some(super::iceberg_export::lifecycle::CatalogFlight { head, handle });
    }

    #[cfg(test)]
    pub(crate) fn catalog_synced(&self) -> bool { self.catalog_applied_seq.is_some() }

    /// Flush whatever is buffered now (shutdown, tests).
    pub async fn flush_now(&mut self, now_ms: i64) -> Result<usize> {
        self.flush(now_ms, false).await
    }

    /// NAN-4319: drop crash-ledger entries of objects no longer pending
    /// (their flush committed and the source acknowledged them).
    fn forget_acknowledged(&mut self, pending: &[(NoticeHandle, SourceNotice)]) {
        if self.admission_attempts.is_empty() {
            return;
        }
        let ids = pending.iter().map(|(_, notice)| object_id(&notice.key, &notice.version)).collect::<Vec<_>>();
        if let Err(error) = self.admission_attempts.retain_pending(ids.iter().map(String::as_str)) {
            tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not updated");
        }
    }

    /// NAN-4319: before admitting, durably count the admission of each
    /// object. While an object a previous process died with is pending,
    /// admit one object at a time (oldest first: ranges stay contiguous);
    /// one admitted [`MAX_ADMISSION_CRASHES`] times without an
    /// acknowledgement is refused whole and quarantined instead.
    async fn crash_guard(&mut self, mut fresh: Vec<(NoticeHandle, SourceNotice)>, now_ms: i64)
        -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        if !self.admission_attempts.has_suspects() {
            return Ok(fresh);
        }
        let suspected = fresh.iter().any(|(_, notice)| self.admission_attempts.suspect(&object_id(&notice.key, &notice.version)).is_some());
        if suspected {
            // NAN-4542: one object, from idle only (it flushes a tick later:
            // see `crash_recovery_seal`), so a crash names exactly it.
            if !self.buffer.handles.is_empty() || !self.flush_in_flight.is_empty() {
                return Ok(Vec::new());
            }
            let (handle, notice) = fresh[0].clone();
            let id = object_id(&notice.key, &notice.version);
            // NAN-4553: bisection. A group of the oldest suspects (half of
            // what the last crash interrupted) goes together; a group that
            // crashes is halved by the next process. An object already
            // charged as a singleton stays one.
            let head = self.admission_attempts.suspect(&id);
            let group = if head.is_some_and(|attempts| attempts > 0) || self.admission_attempts.reserve_refused(&id) {
                1
            } else {
                fresh.iter().take(self.admission_attempts.group_limit())
                    .take_while(|(_, notice)| {
                        // Only uncharged suspects join a group: one charged
                        // (or marked refused) alone stays alone.
                        let member = object_id(&notice.key, &notice.version);
                        self.admission_attempts.suspect(&member) == Some(0) && !self.admission_attempts.reserve_refused(&member)
                    })
                    .count()
                    .max(1)
            };
            fresh.truncate(group);
            if group > 1 {
                tracing::warn!(key = %notice.key, version = %notice.version, objects = group,
                    "admitting a group of suspects together: an earlier ingest process died with them admitted and unacknowledged");
                return Ok(fresh);
            }
            if let Some(attempts) = head {
                // NAN-4336: the owner refused this object's own flush
                // permanently: refuse it now, whatever its attempt count.
                let reserve_refused = self.admission_attempts.reserve_refused(&id);
                if reserve_refused || attempts >= MAX_ADMISSION_CRASHES {
                    let cause = if reserve_refused { PoisonCause::ReserveRefused } else { PoisonCause::Crashed { attempts } };
                    if !reserve_refused {
                        // NAN-4553: the refusal reads the object's footer
                        // (its row count) too; a death there counts, and a
                        // refusal that died before skips the footer.
                        if let Err(error) = self.admission_attempts.charge_suspect(&id) {
                            tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not written");
                        }
                    }
                    self.refuse_poison(&handle, &notice, cause, now_ms).await?;
                    if let Err(error) = self.admission_attempts.forget(&id) {
                        tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not updated");
                    }
                    return Ok(Vec::new());
                }
                tracing::warn!(key = %notice.key, version = %notice.version, attempts,
                    "admitting an object alone: an earlier ingest process died with it admitted and unacknowledged");
            }
        }
        Ok(fresh)
    }

    /// NAN-4319: durably count one admission of each object about to be
    /// admitted (those [`Self::admit`] keeps, never the ones it defers).
    /// NAN-4542: `idle` (nothing buffered or in flight) with one object is an
    /// admission alone, the only kind a crash is charged to.
    ///
    /// NAN-4553: `recorded` is the first object, already recorded before its
    /// fetch ([`Self::record_before_fetch`]); it is charged now if it turned
    /// out to be admitted alone and was not charged then.
    fn begin_admission(&mut self, files: &[(NoticeHandle, SourceNotice, PathBuf, String, u64)], idle: bool, recorded: Option<&str>) {
        let ids = files.iter().map(|(_, notice, ..)| object_id(&notice.key, &notice.version)).collect::<Vec<_>>();
        let alone = idle && ids.len() == 1;
        let rest = ids.iter().map(String::as_str).filter(|id| Some(*id) != recorded).collect::<Vec<_>>();
        let result = match recorded {
            Some(id) if alone && ids[0] == id => self.admission_attempts.charge(id),
            _ if rest.is_empty() => Ok(()),
            _ => self.admission_attempts.begin_group(rest, alone, ids.len()),
        };
        if let Err(error) = result {
            // Best effort: a crash then goes uncounted, as before NAN-4319.
            tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not written");
        }
    }

    /// NAN-4553: record the first object of an admission from idle before
    /// its source GET, digest and footer read: an object that kills ingest
    /// there must be charged like one that kills it in decode (it used to
    /// loop forever, uncounted). Charged now when it is the only object
    /// offered (it can only be admitted alone).
    fn record_before_fetch(&mut self, notice: &SourceNotice, offered: usize) -> String {
        let id = object_id(&notice.key, &notice.version);
        if let Err(error) = self.admission_attempts.begin_group([id.as_str()], offered == 1, offered) {
            tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not written");
        }
        id
    }

    /// NAN-4553: ingest is exiting on a coded path. One the object in flight
    /// may have caused ([`exit_keeps_charges`]: the retry window, a 400 on
    /// its part) keeps the charges, so a deterministically failing object
    /// is refused after [`MAX_ADMISSION_CRASHES`] exits; any other undoes
    /// this process's charges (not a crash, not the object).
    pub fn note_coded_exit(&mut self, error: Option<&anyhow::Error>, reason: &str) {
        if exit_keeps_charges(error) {
            tracing::warn!(tenant = %self.cfg.tenant_id, reason,
                "coded exit the object in flight may have caused: crash-ledger charges kept");
            return;
        }
        self.note_orderly_exit(reason);
    }

    /// NAN-4553: undo this process's crash-ledger charges (an exit that is
    /// never the object's: fencing, an epoch change, the lease lost,
    /// credentials, enrichment or catalog custody giving up).
    pub fn note_orderly_exit(&mut self, reason: &str) {
        match self.admission_attempts.uncharge_this_process() {
            Ok(0) => {}
            Ok(undone) => tracing::info!(tenant = %self.cfg.tenant_id, undone, reason,
                "orderly exit: crash-ledger charges of this process undone (not a crash)"),
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not updated"),
        }
    }

    /// NAN-4319: refuse an object ingest died with [`MAX_ADMISSION_CRASHES`]
    /// times, or (NAN-4336) whose own flush the writer owner refused
    /// permanently. It is kept in the quarantine for an operator replay and
    /// acknowledged with the flush, so the source (the edge log) moves past
    /// it. Its rows count as rejected (`rows_rejected_total`, the reject
    /// entry, the edge ack), never as stored. The reject entry keeps the
    /// `admission_invalid` code every log reader accepts; the detail names
    /// [`ADMISSION_CRASHED`] or [`RESERVE_REFUSED`].
    async fn refuse_poison(&mut self, handle: &NoticeHandle, notice: &SourceNotice, cause: PoisonCause, now_ms: i64) -> Result<()> {
        let src_dir = self.cfg.work_dir.join("src");
        std::fs::create_dir_all(&src_dir)?;
        let target = src_dir.join(format!("fetch-{}.parquet", uuid::Uuid::new_v4().simple()));
        if !self.sources.get_to_file(&notice.key, &target).await? {
            self.health.objects_missing_total += 1;
            self.hold_rejection(handle, notice, "0".repeat(64), "object", 0, "missing", "notified object not found");
            self.mark_since(now_ms);
            return Ok(());
        }
        let (bytes, sha) = super::writer::file_digest(&target)?;
        // NAN-4553: a refusal of a crashed object that itself died (it read
        // the footer) does not read it again: the rows count as unknown (0).
        let footer_unsafe = matches!(cause, PoisonCause::Crashed { attempts } if attempts > MAX_ADMISSION_CRASHES);
        let rows = if footer_unsafe { 0 } else { crate::bronze::bronze_file_row_count(&target).unwrap_or(0) };
        let detail = match cause {
            PoisonCause::Crashed { attempts } => {
                tracing::error!(tenant = %self.cfg.tenant_id, key = %notice.key, version = %notice.version, attempts, rows, bytes,
                    reason = ADMISSION_CRASHED, "INGEST POISON OBJECT: refused whole and quarantined after repeated crashes");
                self.health.objects_admission_crashed_total += 1;
                format!(
                    "{ADMISSION_CRASHED}: ingest died {attempts} times with this object admitted and unacknowledged \
                     ({bytes} bytes, {rows} rows); refused so later data flows"
                )
            }
            PoisonCause::ReserveRefused => {
                tracing::error!(tenant = %self.cfg.tenant_id, key = %notice.key, version = %notice.version, rows, bytes,
                    reason = RESERVE_REFUSED, "INGEST RESERVE REFUSED: the writer owner refused this object's part reservation \
                    permanently; refused whole and quarantined so later data flows");
                self.health.objects_reserve_refused_total += 1;
                format!(
                    "{RESERVE_REFUSED}: the writer owner refused this object's part reservation permanently \
                     (HTTP {}) ({bytes} bytes, {rows} rows); refused so later data flows",
                    super::native_writer::OWNER_RESERVATION_REFUSED_STATUS
                )
            }
        };
        self.hold_rejection(handle, notice, sha.clone(), "object", rows, "admission_invalid", &detail);
        self.quarantine_refused(notice, &sha, &target, rows, &detail, now_ms);
        let _ = std::fs::remove_file(&target);
        self.mark_since(now_ms);
        Ok(())
    }

    /// NAN-4542: while a crash is being isolated (a suspect pending), what
    /// admission buffered (one object) is due a tick after it was admitted,
    /// never after the flush age: nothing may join it anyway, and waiting the
    /// age (up to 30 s while behind) per suspect would turn the recovery from
    /// a crash with hundreds of objects in flight into hours of lag.
    fn crash_recovery_seal(&self, now_ms: i64) -> bool {
        (self.admission_attempts.has_suspects() || self.admission_attempts.has_isolating())
            && !self.buffer.handles.is_empty()
            && self.buffer.since_ms.is_some_and(|since| now_ms > since)
    }

    /// NAN-4336: the buffer holds an object a previous process died with
    /// (admitted alone by [`Self::crash_guard`]): admit nothing beside it
    /// until it flushes, so an owner refusal of that flush names exactly it.
    ///
    /// NAN-4542: such an object stops being a suspect the moment it is
    /// admitted, so this used to ask the wrong question and never held:
    /// later objects joined its buffer (4 per flush in the kill -9 test),
    /// and the next crash counted against every one of them until healthy
    /// objects were refused as poison. It now asks whether the buffer, or a
    /// flush still in flight, holds a re-admitted suspect that is still
    /// pending: at most one such object is ever admitted and unacknowledged.
    fn buffer_holds_suspect(&self) -> bool {
        if !self.admission_attempts.has_isolating() {
            return false;
        }
        let isolating = |sources: &[SourceObject]| sources.iter()
            .any(|source| self.admission_attempts.isolating(&object_id(&source.key, &source.version)));
        isolating(&self.buffer.sources) || self.flush_in_flight.iter().any(|flight| isolating(&flight.buffer.sources))
    }

    /// NAN-4336: a flush failed. When the writer owner refused its part
    /// reservation permanently, say so (distinct line), drop a quarantine
    /// replay's request (it stays quarantined) and, when the flush held ONE
    /// object, mark it so the restarted ingest refuses it whole. A flush of
    /// several objects marks none: the restart admits each alone, and the
    /// culprit's own flush is refused next. Every other failure: nothing.
    fn note_flush_failure(&mut self, sources: &[SourceObject], replay: Option<&str>, error: &anyhow::Error, now_ms: i64) {
        if !super::native_writer::reservation_refused(error) {
            return;
        }
        tracing::error!(tenant = %self.cfg.tenant_id, objects = sources.len(), reason = RESERVE_REFUSED,
            keys = %sources.iter().map(|source| source.key.as_str()).collect::<Vec<_>>().join(","),
            "INGEST RESERVE REFUSED: the writer owner refused a flush's part reservation permanently; \
             ingest restarts to isolate and quarantine the object");
        if let (Some(id), Some(quarantine)) = (replay, &self.quarantine) {
            if let Err(error) = quarantine.clear_replay(id, now_ms) {
                tracing::warn!(id, error = %format!("{error:#}"), "quarantine replay request could not be cleared");
            }
            return;
        }
        if let [source] = sources {
            if let Err(error) = self.admission_attempts.mark_reserve_refused(&object_id(&source.key, &source.version)) {
                tracing::warn!(error = %format!("{error:#}"), "admission attempt ledger not updated");
            }
        }
    }

    async fn admit(&mut self, notices: &[(NoticeHandle, SourceNotice)], now_ms: i64) -> Result<(u64, u64)> {
        self.admit_with_calibration(notices, now_ms, true).await
    }

    async fn admit_with_calibration(&mut self, notices: &[(NoticeHandle, SourceNotice)], now_ms: i64,
        calibrated: bool) -> Result<(u64, u64)> {
        let sliced_before = (self.health.objects_admitted_in_slices_total, self.health.objects_sliced_beside_flights_total);
        let deferred_before = self.admission_deferred;
        // NAN-3899: read each row's credential only when activity is kept.
        let track_credentials = self.credential_activity.is_some();
        let src_dir = self.cfg.work_dir.join("src");
        std::fs::create_dir_all(&src_dir)?;
        let mut files = Vec::new();
        let committed = self.committed_bytes();
        let idle = self.buffer.bytes == 0 && self.flush_in_flight.is_empty();
        // NAN-4553: the first object from idle, recorded before its fetch.
        let mut recorded: Option<String> = None;
        // NAN-4749: the tick's objects, packed into groups that decode one
        // after another (`files` indices where a group starts).
        let mut packing = super::memory::AdmissionGroups::new(self.cfg.buffer_budget_bytes, committed,
            self.buffer.bytes, self.buffer.rows as u64);
        let mut group_starts: Vec<usize> = Vec::new();
        // NAN-4553: rows per slice of a lone object too large to admit whole.
        let mut slice_rows: Option<u64> = None;
        for (handle, notice) in notices {
            ensure!(notice.tenant_id == self.cfg.tenant_id, "notice for another tenant");
            // NAN-3643: a replay reads this tenant's own quarantine, and only
            // under the replay handle ingest itself issued.
            let replay = self.quarantine.as_ref()
                .and_then(|quarantine| quarantine.replay_id(&notice.key).map(str::to_string))
                .filter(|id| handle.0 == Quarantine::replay_handle(id) && notice.version == QUARANTINE_REPLAY_VERSION);
            if let (None, Some(prefix)) = (&replay, &self.cfg.source_key_prefix) {
                if !key_inside_prefix(&notice.key, prefix) || notice.key.chars().any(char::is_control) {
                    // Never read outside the tenant's bronze prefix.
                    self.hold_rejection(handle, notice, "0".repeat(64), "object", 0, "admission_invalid", "key outside the tenant's bronze prefix");
                    continue;
                }
            }
            if files.is_empty() && recorded.is_none() && idle && self.buffer.handles.is_empty() {
                recorded = Some(self.record_before_fetch(notice, notices.len()));
            }
            let target = src_dir.join(format!("fetch-{}.parquet", uuid::Uuid::new_v4().simple()));
            let fetched = match (&replay, &self.quarantine) {
                (Some(id), Some(quarantine)) => quarantine.copy_to(id, &target)?,
                _ => self.sources.get_to_file(&notice.key, &target).await?,
            };
            if !fetched {
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
            // NAN-4319: admission holds the group's decoded rows as JSON
            // values. Bound it by the objects' uncompressed bytes (Parquet
            // footer), not their compressed size: a 1 MB landing segment
            // carried 50k rows and OOM-killed a 1.2 GB ingest. The first
            // object from idle always goes (progress); the rest wait,
            // pending, for the next tick (a prefix, so ranges stay
            // contiguous).
            //
            // NAN-4553: that first object is no exception to the bound. One
            // landing object may hold 10k rows / 32 MiB of events (~16x that
            // as JSON values); admitted whole it OOM-killed a 512 MiB ingest
            // role every 2-3 min, and the crash ledger then quarantined it
            // as "poison". An object that does not fit alone is admitted in
            // row slices, one slice's JSON values at a time.
            //
            // NAN-4749: a group's JSON values are freed once it decodes, so
            // an object that does not fit the open group may start the next
            // one ([`super::memory::AdmissionGroups`]).
            //
            // NAN-4805: learned reservations carry margin and floors; the
            // bronze reader checks actual heap and retries an underestimate
            // with the cold model before it can accumulate a whole group.
            // The next buffer's first object that does not fit whole is sliced beside
            // the flights in flight when its Arrow rows and a slice fit
            // there: admission no longer waits for every flight to commit.
            let decoded = crate::bronze::bronze_file_decoded_bytes(&target).unwrap_or(0);
            let prefix = super::memory::calibration_prefix(&notice.key);
            let fixed_admission_model = self.fixed_admission_model() || !calibrated;
            let (heap, arrow) = if fixed_admission_model { decoded_admission_cost(decoded) } else { self.calibration.reservation_cost(prefix, decoded) };
            let rows = crate::bronze::bronze_file_row_count(&target).unwrap_or(0);
            if !idle && (decoded == 0 || rows == 0) {
                let _ = std::fs::remove_file(&target);
                self.admission_deferred = true;
                break;
            }
            let offer = if slice_rows.is_some() { super::memory::Offer::Refused } else { packing.offer(heap, arrow, rows) };
            let fits = offer != super::memory::Offer::Refused;
            let beside = (files.is_empty() && !idle && !fits && self.buffer.handles.is_empty() && !fixed_admission_model)
                .then(|| super::memory::pipelined_slice_rows(self.cfg.buffer_budget_bytes, committed, heap, arrow, rows))
                .flatten();
            if !(files.is_empty() && idle) && !fits && beside.is_none() {
                let _ = std::fs::remove_file(&target);
                // NAN-4539 step 3a: seal only when the buffer (with the
                // flights and merges) is what keeps this object out. When
                // it alone fits beside them, only this group's transient
                // decode peak bounded it: the next tick admits it into the
                // same buffer, so the flush grows to its caps instead of
                // sealing at one admission group.
                if !super::memory::admission_fits(self.cfg.buffer_budget_bytes, committed, heap, arrow) {
                    self.admission_deferred = true;
                }
                tracing::info!(objects_admitted = files.len(), groups = packing.groups(), decoded_bytes = decoded,
                    "admission bounded by decoded size; the rest stays pending");
                break;
            }
            if !fits {
                slice_rows = Some(beside.unwrap_or_else(|| super::memory::admission_slice_rows(self.cfg.buffer_budget_bytes, committed, heap, arrow, rows)));
                packing.force(heap, arrow, rows);
            }
            if offer == super::memory::Offer::NewGroup {
                group_starts.push(files.len());
            }
            let path = src_dir.join(format!("{sha}.parquet"));
            std::fs::rename(&target, &path)?;
            files.push((handle.clone(), notice.clone(), path, sha, bytes));
        }
        if files.is_empty() {
            self.mark_since(now_ms);
            return Ok((0, 0));
        }
        self.begin_admission(&files, idle && self.buffer.handles.is_empty(), recorded.as_deref());
        // NAN-4553: the lone oversized object, cut into slice files that
        // carry its identity (handle, notice, sha, bytes) and are admitted
        // one after another; only their Arrow rows accumulate.
        let slices = match slice_rows {
            Some(rows) if files.len() == 1 => match if idle {
                write_admission_slices(&files[0], rows).map(Some)
            } else {
                write_pipelined_admission_slices(&files[0], rows, self.cfg.buffer_budget_bytes, committed)
            } {
                Ok(Some(slices)) => slices,
                Ok(None) => {
                    let _ = std::fs::remove_file(&files[0].2);
                    self.admission_deferred = true;
                    self.mark_since(now_ms);
                    return Ok((0, 0));
                }
                Err(error) if !idle => {
                    tracing::warn!(tenant = %self.cfg.tenant_id, key = %files[0].1.key, error = %format!("{error:#}"),
                        "pipelined admission slices could not be written; waiting for idle admission");
                    let _ = std::fs::remove_file(&files[0].2);
                    self.admission_deferred = true;
                    self.mark_since(now_ms);
                    return Ok((0, 0));
                }
                Err(error) => {
                    // An object that cannot be re-read in slices (a corrupt
                    // row group) is admitted whole: its decode refuses it
                    // whole, as before. Never a tick error: that would retry
                    // the same object until the retry window ends ingest.
                    tracing::warn!(tenant = %self.cfg.tenant_id, key = %files[0].1.key, error = %format!("{error:#}"),
                        "oversized object could not be cut into admission slices; admitting it whole");
                    Vec::new()
                }
            },
            _ => Vec::new(),
        };
        // NAN-4553 (review P3): every return from here (a `?` included)
        // removes the slice files; the normal paths also remove them early.
        let _slice_files = RemoveOnDrop(slices.iter().map(|slice| slice.2.clone()).collect());
        if !slices.is_empty() {
            tracing::info!(tenant = %self.cfg.tenant_id, key = %files[0].1.key, slices = slices.len(), requested_rows_per_slice = slice_rows.unwrap_or(0),
                budget_bytes = self.cfg.buffer_budget_bytes, "object larger than the admission budget; admitting it in row slices");
            self.health.objects_admitted_in_slices_total += 1;
            if !idle {
                self.health.objects_sliced_beside_flights_total += 1;
            }
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
            /// NAN-3899: each kept row's credential (row-aligned; empty
            /// when credential activity is off).
            credentials: Vec<Option<String>>,
            /// Rows admission dropped as in-batch duplicates.
            bronze_duplicates: u64,
            /// Of those, rows whose uid's kept copy has a different source
            /// identity (NAN-3719): counted like a cross-batch payload diff.
            conflicting_replays: u64,
            /// NAN-4336: rows clamped to their ingest time, per source.
            time_clamped: ClampedSources,
            /// NAN-4553: a kept row's share of its object's stored bytes when
            /// the group is one slice of it (None: from the group itself).
            row_bytes: Option<u64>,
            /// NAN-4573: clamped rows' source time (epoch ms) by uid.
            clamped: BTreeMap<String, i64>,
        }
        let mut queue: Vec<Vec<File>> = if slices.is_empty() {
            // A stack: the first group is admitted first (NAN-4749).
            let mut bounds = vec![0];
            bounds.extend(group_starts.iter().copied());
            bounds.push(files.len());
            bounds.windows(2).rev().map(|range| files[range[0]..range[1]].iter().collect()).collect()
        } else {
            // A stack: the first slice is admitted first.
            slices.iter().rev().map(|slice| vec![slice]).collect()
        };
        let mut admitted: Vec<Admitted> = Vec::new();
        let schema_before_admission = self.pending_schema.clone();
        let coerced_before_admission = self.health.rows_coerced_total;
        // NAN-4553: a slice whose every row is refused (refused rows of the
        // object), and a slice admission refused outright (refuses the
        // whole object, as an unsliced admission would).
        let mut slice_refused: Option<(u64, RowRefusal, RefusedSources)> = None;
        let mut slice_failure: Option<String> = None;
        // JSON-value heap of the admitted rows (sampled): sizes the next
        // admission's in-flight share.
        let mut value_heap = 0_f64;
        while let Some(group) = queue.pop() {
            let paths = group.iter().map(|f| f.2.clone()).collect::<Vec<_>>();
            let (mut learned_heap, mut fixed_heap, mut fixed_arrow) = (0.0, 0.0, 0.0);
            for file in &group {
                let decoded = crate::bronze::bronze_file_decoded_bytes(&file.2).unwrap_or(0);
                learned_heap += self.calibration.reservation_cost(super::memory::calibration_prefix(&file.1.key), decoded).0;
                let fixed = decoded_admission_cost(decoded);
                fixed_heap += fixed.0;
                fixed_arrow += fixed.1;
            }
            let retained_arrow = admitted.iter().filter_map(|entry| entry.batch.as_ref())
                .map(|batch| batch.get_array_memory_size() as u64).sum::<u64>();
            let room = self.cfg.buffer_budget_bytes.saturating_sub(committed).saturating_sub(retained_arrow) as f64;
            let heap_allowance = (calibrated && !self.fixed_admission_model() && learned_heap < fixed_heap).then(|| {
                learned_heap.min((room - fixed_arrow).max(0.0) / super::memory::ADMISSION_PEAK_PER_MODELLED_HEAP) as u64
            });
            // NAN-4336: each file's ingest time is when its object reached
            // the tenant (the notice); future-dated rows clamp against it.
            let ingest_times = IngestTimes {
                received_ms: group.iter().map(|f| (f.2.clone(), f.1.notified_at_ms)).collect(),
                now_ms,
            };
            // With a deferred apply this is the wall time of both (the apply
            // is also timed on its own as `prevalence_apply`).
            let parse_timing = self.diagnostics.operations.start("admission_parse");
            let admission_result = if self.prevalence_deferred.is_some() {
                // NAN-4737: the previous flush's prevalence apply runs on
                // this task while the group parses on the blocking pool; the
                // stamp below then reads a state holding that flush.
                let (owned_paths, tenant, enricher, times) =
                    (paths.clone(), self.cfg.tenant_id.clone(), self.enricher.clone(), ingest_times.clone());
                let parse = tokio::task::spawn_blocking(move || admit_bronze_files_received_bounded(&owned_paths, &tenant, &enricher, &times, heap_allowance));
                self.finish_deferred_prevalence(now_ms).await;
                match parse.await {
                    Ok(result) => result,
                    Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
                    // Cancelled with the runtime: transient, never a refusal.
                    Err(error) => Err(anyhow::Error::new(std::io::Error::other(format!("admission parse task: {error}")))),
                }
            } else {
                admit_bronze_files_received_bounded(&paths, &self.cfg.tenant_id, &self.enricher, &ingest_times, heap_allowance)
            };
            drop(parse_timing);
            #[cfg(test)]
            let admission_result = if self.refuse_admissions {
                Err(anyhow::anyhow!("simulated admission bug"))
            } else {
                admission_result
            };
            let (mut admission, refused, mut refused_sources) = match admission_result {
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
                Err(error) if error.downcast_ref::<AdmissionHeapExceeded>().is_some() => {
                    // No decoded rows have entered the uid window or buffer.
                    // Drop this tick's retained Arrow, forget stale estimates,
                    // and repack/slice with the cold model. This never becomes
                    // a poison-object refusal or a crash-ledger charge.
                    tracing::info!(objects = group.len(), "admission shape changed; retrying with the cold memory model");
                    self.calibration = super::memory::AdmissionCalibration::default();
                    self.pending_schema = schema_before_admission;
                    self.health.rows_coerced_total = coerced_before_admission;
                    self.health.objects_admitted_in_slices_total = sliced_before.0;
                    self.health.objects_sliced_beside_flights_total = sliced_before.1;
                    self.admission_deferred = deferred_before;
                    drop(admitted);
                    drop(queue);
                    for file in files.iter().chain(slices.iter()) {
                        let _ = std::fs::remove_file(&file.2);
                    }
                    // Fetch-time refusals and earlier failed groups already
                    // hold their handles in the buffer. Preserve those results
                    // instead of reporting/refusing the same object twice.
                    let retry = notices.iter().filter(|(handle, _)| !self.buffer.handle_names.contains(&handle.0))
                        .cloned().collect::<Vec<_>>();
                    return Box::pin(self.admit_with_calibration(&retry, now_ms, false)).await;
                }
                Err(error) if is_transient(&error) => {
                    // NAN-4553: the next admission cuts its own slices.
                    for slice in &slices {
                        let _ = std::fs::remove_file(&slice.2);
                    }
                    return Err(error.context("transient admission failure"));
                }
                Err(error) if group.len() > 1 => {
                    tracing::warn!(error = %error, objects = group.len(), "group admission failed; admitting objects one by one");
                    queue.extend(group.into_iter().map(|file| vec![file]));
                    continue;
                }
                Err(error) if !slices.is_empty() => {
                    let detail = format!("{error:#}");
                    match error.downcast_ref::<NoCanonicalEvents>() {
                        Some(refused) => {
                            let rows = crate::bronze::bronze_file_row_count(&group[0].2).unwrap_or(0);
                            let first = refused.first_row.clone().unwrap_or_else(|| RowRefusal::new("no_canonical_events", None));
                            let entry = slice_refused.get_or_insert_with(|| (0, first, RefusedSources::default()));
                            entry.0 += rows;
                            entry.2.merge(&refused.refused_sources);
                        }
                        None => {
                            slice_failure = Some(detail);
                            break;
                        }
                    }
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
                    // NAN-3643: keep the refused bytes for a replay.
                    self.quarantine_refused(&file.1, &file.3, &file.2, rows, &detail, now_ms);
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
            let time_clamped = std::mem::take(&mut admission.time_clamped);
            let clamped = std::mem::take(&mut admission.clamped_original_ms);
            // The in-batch admission's source identities (NAN-3704): the
            // cross-batch window compares the same normalisation.
            let digests = admission.take_source_identity_digests();
            let mut rows = admission.batch.into_rows();
            let group_heap = sampled_value_heap(&rows);
            value_heap += group_heap;
            // Per source row: rows deduplicated in the batch were decoded too.
            let source_rows = rows_by_path.values().sum::<u64>().max(rows.len() as u64);
            let group_heap = group_heap * source_rows as f64 / rows.len().max(1) as f64;
            // NAN-4770: what this group's rows decode from (a slice: its own footer).
            let group_decoded = paths.iter().map(|path| crate::bronze::bronze_file_decoded_bytes(path).unwrap_or(0)).sum::<u64>();
            let group_prefixes = group.iter().map(|file| super::memory::calibration_prefix(&file.1.key).to_string()).collect::<Vec<_>>();
            let calibrated_before = admitted.len();
            // This namespace belongs to the authenticated finding-outbox
            // drain. A raw event must not become a risk contribution after
            // its part is merged with a genuine finding part.
            for_each_row_chunk(&mut rows, |chunk| {
                chunk.iter_mut().for_each(|row| strip_untrusted_risk_fields(&mut row.ocsf_event));
                Ok(())
            })?;
            // A failed or slow lookup never fails or holds the tick: this
            // batch goes unstamped (a partial stamp is stripped whole).
            // Unstamped (no grant, rebuilding, catching up, state busy): a
            // source-supplied value must not pose as ours.
            let stamp_timing = self.diagnostics.operations.start("stamp_lookup");
            let observed = self.stamp_lookup(&rows, now_ms).await;
            drop(stamp_timing);
            let stamped = match observed {
                // NAN-4749: chunked; a failed chunk strips the batch whole below.
                Some(observed) => match for_each_row_chunk(&mut rows, |chunk| observed.stamp(chunk.iter_mut().map(|row| &mut row.ocsf_event))) {
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
                for_each_row_chunk(&mut rows, |chunk| {
                    chunk.iter_mut().for_each(|row| super::prevalence::strip_stamps(&mut row.ocsf_event));
                    Ok(())
                })?;
            }
            // Admission normalized `time`; a row whose time still does not
            // parse is refused alone (never a tick error).
            let parsed = map_rows(&rows, |row| event_time_us(&row.ocsf_event).ok());
            let bad_time = parsed.iter().enumerate().filter(|(_, time)| time.is_none()).map(|(index, _)| index).collect::<BTreeSet<_>>();
            let times = parsed.into_iter().map(|time| time.unwrap_or(0)).collect::<Vec<_>>();
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
                let credentials = row_credentials(&rows, track_credentials);
                let (uids, batch) = decoded_rows(rows, decoded, &self.pending_schema)?;
                let payloads = payload_hashes(&uids, &digests);
                admitted.push(Admitted { group, rows_by_path, uids, payloads, batch, times: times_kept, refused, refused_sources, credentials, bronze_duplicates, conflicting_replays, time_clamped, row_bytes: None, clamped });
            } else {
                let credentials = row_credentials(&rows, track_credentials);
                let (uids, batch) = decoded_rows(rows, decoded, &self.pending_schema)?;
                let payloads = payload_hashes(&uids, &digests);
                admitted.push(Admitted { group, rows_by_path, uids, payloads, batch, times, refused, refused_sources, credentials, bronze_duplicates, conflicting_replays, time_clamped, row_bytes: None, clamped });
            }
            if let Some(entry) = admitted.get(calibrated_before) {
                self.health.admission_groups_total += 1;
                self.health.admission_group_objects_peak = self.health.admission_group_objects_peak.max(entry.group.len());
                let kept = entry.uids.len().max(1) as f64;
                let arrow = entry.batch.as_ref().map_or(0, |batch| batch.get_array_memory_size()) as f64 * source_rows as f64 / kept;
                let prefixes = group_prefixes.iter().map(String::as_str).collect::<Vec<_>>();
                self.calibration.observe(&prefixes, source_rows, group_decoded, group_heap, arrow);
            }
        }
        // NAN-4553: fold the slices back into their object. The object is
        // refused whole exactly when an unsliced admission would refuse it
        // (an admission error, or every row refused); otherwise its slices
        // commit as one object: one source, one notice, one row count, one
        // `reject` entry for its refused rows.
        if !slices.is_empty() {
            for slice in &slices {
                let _ = std::fs::remove_file(&slice.2);
            }
            let original = &files[0];
            let whole_refusal = match (slice_failure, admitted.is_empty()) {
                (Some(detail), _) => Some((detail, None, None)),
                (None, true) => {
                    let (_, first, sources) = slice_refused.take().unwrap_or_else(|| (0, RowRefusal::new("no_canonical_events", None), RefusedSources::default()));
                    let refused = NoCanonicalEvents { first_row: Some(first), refused_sources: sources };
                    Some((refused.to_string(), refused.first_row.clone(), Some(refused.refused_sources)))
                }
                (None, false) => None,
            };
            if let Some((detail, first_row, sources)) = whole_refusal {
                admitted.clear();
                let rows = crate::bronze::bronze_file_row_count(&original.2).unwrap_or(0);
                if let Some(sources) = &sources {
                    sources.log("part_ingest");
                }
                self.hold_rejection_with(&original.0, &original.1, original.3.clone(), "object", rows, "admission_invalid", &detail,
                    first_row.as_ref(), sources.as_ref());
                self.quarantine_refused(&original.1, &original.3, &original.2, rows, &detail, now_ms);
                let _ = std::fs::remove_file(&original.2);
                self.mark_since(now_ms);
                return Ok((0, 0));
            }
            let kept = admitted.iter().map(|entry| entry.uids.len() as u64).sum::<u64>().max(1);
            let mut source_rows = 0_u64;
            let mut refused: Option<(u64, RowRefusal)> = None;
            let mut refused_sources = RefusedSources::default();
            if let Some((rows, first, sources)) = slice_refused.take() {
                source_rows += rows;
                refused = Some((rows, first));
                refused_sources.merge(&sources);
            }
            for entry in &mut admitted {
                source_rows += entry.rows_by_path.values().sum::<u64>();
                for (count, first) in std::mem::take(&mut entry.refused).into_values() {
                    let total = refused.get_or_insert_with(|| (0, first));
                    total.0 += count;
                }
                for sources in std::mem::take(&mut entry.refused_sources).into_values() {
                    refused_sources.merge(&sources);
                }
                entry.rows_by_path.clear();
                entry.group.clear();
                entry.row_bytes = Some(original.4 / kept);
            }
            let last = admitted.last_mut().expect("a sliced object admitted rows");
            last.group = vec![original];
            last.rows_by_path.insert(original.2.clone(), source_rows);
            if let Some(refused) = refused {
                last.refused.insert(original.2.clone(), refused);
            }
            if !refused_sources.is_empty() {
                last.refused_sources.insert(original.2.clone(), refused_sources);
            }
        }
        // Commit groups to the buffer atomically: every fallible step
        // (window preparation, remote GETs) runs for EVERY admitted entry
        // (every row slice of a sliced object) before any row or uid is
        // added, so an error here leaves the buffer and the window's
        // observed uids as they were and replay is safe (NAN-4553 review P2:
        // a failure on slice k+1 left slices 1..k buffered without their
        // source, so a due flush could commit part of an unacked object).
        // Preparation only loads committed parts into the window; it never
        // depends on rows observed by an earlier entry.
        let mut prepared = Vec::with_capacity(admitted.len());
        for entry in &admitted {
            let mut by_hour: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
            for (index, time_us) in entry.times.iter().enumerate() {
                by_hour.entry(event_hour_of(*time_us)).or_default().push(index);
            }
            let mut unverified = BTreeSet::new();
            for (hour, rows) in &by_hour {
                if self.prepare_hour(*hour, rows.iter().map(|i| entry.uids[*i].as_str()), now_ms).await? {
                    unverified.insert(*hour);
                }
            }
            // NAN-4573: a clamped row's `time` is its delivery's ingest
            // time (clamped here or by the landing stage), so another
            // delivery of the same event can be stored in another hour
            // (clamped to a different ingest time, or not clamped at all).
            // Every delivery shares the source's time: a clamped row is
            // also deduped against, and recorded under, that time's hour,
            // where an unclamped copy is stored and every clamped copy is
            // recorded. In memory only: a clamped copy admitted before a
            // restart is not found by a later unclamped one (its part is in
            // the clamped hour); the reverse order hydrates from the parts.
            let mut by_original: BTreeMap<i32, Vec<usize>> = BTreeMap::new();
            for (hour, rows) in &by_hour {
                for index in rows {
                    if let Some(original) = original_hour_of(&entry.clamped, &entry.uids, *index, *hour) {
                        by_original.entry(original).or_default().push(*index);
                    }
                }
            }
            for (hour, rows) in &by_original {
                self.prepare_hour(*hour, rows.iter().map(|i| entry.uids[*i].as_str()), now_ms).await?;
            }
            prepared.push((by_hour, unverified));
        }
        let mut rows_total = 0_u64;
        let mut admitted_bytes = 0_u64;
        let source_bytes = files.iter().map(|f| f.4).sum::<u64>();
        let mut dups_total = 0_u64;
        // NAN-4765: the uid-window walk and buffer append, apart from the
        // parse and the stamp (heartbeat `operation_timings`).
        let dedupe_timing = self.diagnostics.operations.start("admission_dedupe");
        for (Admitted { group, rows_by_path, uids, payloads, batch, times: _, refused, refused_sources, credentials, bronze_duplicates, conflicting_replays, time_clamped, row_bytes, clamped }, (by_hour, unverified)) in admitted.into_iter().zip(prepared) {
            self.note_time_clamped(&time_clamped, group.len().max(1));
            // NAN-3899: a kept row's share of its objects' stored bytes.
            let row_bytes = row_bytes.unwrap_or_else(|| group.iter().map(|file| file.4).sum::<u64>() / (uids.len().max(1) as u64));
            self.buffer.bronze_duplicates += bronze_duplicates;
            self.buffer.same_uid_payload_diff += conflicting_replays;
            if conflicting_replays > 0 {
                self.log_in_batch_conflict(conflicting_replays, group.len(), now_ms);
            }
            self.buffer.rows_refused += refused.values().map(|(count, _)| *count).sum::<u64>();
            // NAN-4573: the hours each clamped row is also checked against
            // and recorded under (see the preparation above).
            let original_hour = |index: usize, hour: i32| original_hour_of(&clamped, &uids, index, hour);
            // NAN-4749: the window keys (a keyed hash per uid) off the
            // serial window walk, chunked on the rayon pool.
            let window = &self.window;
            let keys = map_rows(&uids, |uid| window.key(uid));
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
                    let key = keys[index];
                    let original = original_hour(index, hour);
                    let seen = if tiered && !self.window.contains_key(hour, &key) && self.late.contains(hour, &key) {
                        self.health.late_dedup_tier_duplicates_total += 1;
                        Seen::Duplicate
                    } else if original.is_some_and(|original| self.window.contains_key(original, &key)
                        || (self.late.has_hour(original) && self.late.contains(original, &key))) {
                        self.health.clamped_cross_hour_duplicates_total += 1;
                        Seen::Duplicate
                    } else {
                        self.window.observe_key(hour, key, payload, now_ms)
                    };
                    if let (Seen::New, Some(original)) = (seen, original) {
                        self.window.observe_key(original, key, payload, now_ms);
                    }
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
                    if let Some(Some(credential)) = credentials.get(index) {
                        self.buffer.activity.note(credential, row_bytes);
                    }
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
                self.buffer.buffered_since.get_or_insert_with(std::time::Instant::now);
                self.update_pipeline_diagnostics();
                let batches = self.buffer.hours.entry(hour).or_default();
                batches.push(kept);
                // NAN-4674: a wide object leaves a row or two per hour; fold
                // runs of such tiny batches so their per-array overhead does
                // not spend the buffer's byte cap.
                let (freed, added) = compact_tiny_batches(batches)?;
                if freed > 0 {
                    self.health.tiny_batch_folds_total += 1;
                }
                self.buffer.bytes = self.buffer.bytes.saturating_sub(freed).saturating_add(added);
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
        drop(dedupe_timing);
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

    /// NAN-4336: count rows admission clamped to their ingest time, per
    /// source, and say so once per admitted group (value-free: source slugs
    /// and counts only).
    fn note_time_clamped(&mut self, clamped: &ClampedSources, objects: usize) {
        let rows = clamped.values().sum::<u64>();
        if rows == 0 {
            return;
        }
        self.health.rows_time_clamped_total += rows;
        for (slug, count) in clamped {
            let by_source = &mut self.health.rows_time_clamped_by_source;
            let slug = if by_source.contains_key(slug) || by_source.len() < MAX_CLAMPED_SOURCES {
                slug.as_str()
            } else {
                crate::ingest_source_counters::DEFAULT_SOURCE
            };
            *by_source.entry(slug.to_string()).or_default() += count;
        }
        let sources = clamped.iter().map(|(slug, count)| format!("{slug}:{count}")).collect::<Vec<_>>().join(",");
        tracing::warn!(tenant = %self.cfg.tenant_id, rows, objects, sources = %sources,
            max_future_skew_ms = crate::bronze::MAX_FUTURE_EVENT_SKEW_MS,
            "future-dated rows clamped to their ingest time (original kept in metadata.original_time)");
    }

    fn mark_since(&mut self, now_ms: i64) {
        if self.buffer.since_ms.is_none() && (!self.buffer.handles.is_empty() || !self.buffer.rejections.is_empty()) {
            self.buffer.since_ms = Some(now_ms);
        }
    }

    /// NAN-3643: keep an object admission refused whole in the tenant's
    /// quarantine. Best effort: a failure never blocks the refusal itself.
    fn quarantine_refused(&mut self, notice: &SourceNotice, sha256: &str, path: &Path, rows: u64, detail: &str, now_ms: i64) {
        let Some(quarantine) = &self.quarantine else { return };
        let refusal = Refusal {
            source_key: &notice.key, source_version: &notice.version, scope: "object",
            reason: "admission_invalid", detail, rows_rejected: rows,
        };
        let kept = quarantine.keep(path, sha256, &refusal, now_ms);
        // NAN-4338: an edge segment refused whole was not stored (kept for
        // a replay or not); the landing ledger moves its rows out of the
        // source's `rows`.
        if let (Some(ledger), Some(report)) = (&mut self.quarantine_ledger, ledger_report(&self.cfg.tenant_id, &notice.key, rows,
            super::quarantine_ledger::ReportState::Quarantined)) {
            ledger.enqueue(report);
        }
        match kept {
            Ok(Kept::New) => {
                self.health.objects_quarantined_total += 1;
                // Refresh the usage gauges (and hold the cap) next tick.
                self.quarantine_swept_ms = 0;
                tracing::warn!(tenant = %self.cfg.tenant_id, key = %notice.key, id = %sha256, rows,
                    "refused bronze object quarantined; replay it once the cause is fixed");
            }
            Ok(Kept::Again) => tracing::warn!(tenant = %self.cfg.tenant_id, id = %sha256,
                "quarantined bronze object refused again; it stays quarantined"),
            Ok(Kept::TooLarge) => tracing::error!(tenant = %self.cfg.tenant_id, key = %notice.key,
                "refused bronze object is over the quarantine object cap; not kept"),
            Err(error) => tracing::error!(tenant = %self.cfg.tenant_id, key = %notice.key, error = %format!("{error:#}"),
                "refused bronze object could not be quarantined"),
        }
    }

    /// NAN-3643: expire quarantined objects past their TTL, hold the size
    /// cap and refresh the usage gauges, at most every few minutes.
    fn tick_quarantine(&mut self, now_ms: i64) {
        let Some(quarantine) = &self.quarantine else { return };
        if now_ms.saturating_sub(self.quarantine_swept_ms) < super::quarantine::SWEEP_INTERVAL_MS {
            return;
        }
        self.quarantine_swept_ms = now_ms;
        match quarantine.sweep(now_ms) {
            Ok(0) => {}
            Ok(dropped) => tracing::info!(tenant = %self.cfg.tenant_id, dropped, "expired bronze quarantine entries dropped"),
            Err(error) => tracing::warn!(error = %format!("{error:#}"), "bronze quarantine sweep failed"),
        }
        if let Ok((objects, bytes)) = quarantine.usage() {
            self.health.quarantine_objects = objects;
            self.health.quarantine_bytes = bytes;
        }
    }

    /// NAN-4554: once per work dir (a pod replacement starts a fresh one),
    /// rebuild the quarantine from the tenant bucket before anything is
    /// admitted or replayed. A failure is retried next tick and never holds
    /// ingest (the objects stay in the bucket).
    async fn restore_quarantine(&mut self, now_ms: i64) {
        let Some(quarantine) = self.quarantine.clone() else { return };
        if !quarantine.needs_restore() {
            self.health.quarantine_restore_pending = false;
            return;
        }
        self.health.quarantine_restore_pending = true;
        // NAN-4554 (review P1): a failing restore backs off (never a LIST
        // storm every tick).
        if now_ms < self.quarantine_restore_retry.1 {
            return;
        }
        match super::quarantine_store::restore(self.parts, &quarantine, now_ms).await {
            Ok(restored) => {
                self.health.quarantine_restore_error = None;
                self.health.quarantine_restore_refused = restored.refused.map(str::to_string);
                if restored.refused.is_some() {
                    // Review P2: a restore stopped early (restore_disk_low)
                    // stays pending, so what it left in the bucket is
                    // restored once space frees; retried at most every
                    // RESTORE_REFUSED_RETRY_MS (each pass re-reads the
                    // records). What it already restored is kept.
                    let failures = self.quarantine_restore_retry.0.saturating_add(1);
                    let wait = super::quarantine_store::retry_after_ms(failures).max(super::quarantine_store::RESTORE_REFUSED_RETRY_MS);
                    self.quarantine_restore_retry = (failures, now_ms.saturating_add(wait));
                    self.health.quarantine_restored_total += restored.entries as u64;
                    self.quarantine_replay_pending = true;
                    tracing::warn!(tenant = %self.cfg.tenant_id, restored = restored.entries, refused = ?restored.refused,
                        retry_in_ms = wait, "bronze quarantine restore stopped early; it stays pending and is retried");
                    return;
                }
                if let Err(error) = quarantine.mark_restored(restored.low_water_ms) {
                    tracing::warn!(error = %format!("{error:#}"), "bronze quarantine restore marker not written");
                }
                self.quarantine_restore_retry = (0, i64::MIN);
                self.health.quarantine_restore_pending = false;
                self.health.quarantine_restore_over_cap += restored.over_cap as u64;
                self.health.quarantine_restore_records_beyond_bound += restored.records_beyond_bound as u64;
                self.health.quarantine_restored_total += restored.entries as u64;
                self.quarantine_replay_pending = true;
                self.quarantine_swept_ms = 0;
                if restored.entries + restored.skipped + restored.over_cap > 0 || restored.refused.is_some() {
                    tracing::warn!(tenant = %self.cfg.tenant_id, restored = restored.entries, skipped = restored.skipped,
                        over_cap = restored.over_cap, beyond_bound = restored.records_beyond_bound, refused = ?restored.refused,
                        "bronze quarantine restored from the tenant bucket (fresh work dir)");
                }
            }
            Err(error) => {
                let failures = self.quarantine_restore_retry.0.saturating_add(1);
                let wait = super::quarantine_store::retry_after_ms(failures);
                self.quarantine_restore_retry = (failures, now_ms.saturating_add(wait));
                self.health.quarantine_restore_error = Some(format!("{error:#}").chars().take(300).collect());
                tracing::warn!(tenant = %self.cfg.tenant_id, error = %format!("{error:#}"), failures, retry_in_ms = wait,
                    "bronze quarantine restore failed; retried with backoff");
            }
        }
    }

    /// NAN-4554: mirror queued quarantine changes into the tenant bucket.
    /// `hold` (a flush about to acknowledge refused objects): while the
    /// bucket refuses, fail the flush (retried in-process) for up to
    /// `MIRROR_HOLD_MS`, then proceed with the change kept pod-local.
    async fn mirror_quarantine(&mut self, now_ms: i64, hold: bool) -> Result<()> {
        let Some(quarantine) = self.quarantine.clone() else { return Ok(()) };
        let queued = match quarantine.outbox() {
            Ok(queued) => queued,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "bronze quarantine outbox unreadable");
                return Ok(());
            }
        };
        // Ids no longer queued (mirrored, or dropped) forget their backoff.
        self.quarantine_mirror_backoff.retain(|id, _| queued.iter().any(|(queued, _)| queued == id));
        let mut last_error: Option<anyhow::Error> = None;
        let mut waiting = false;
        for (id, _) in queued {
            let retry = self.quarantine_mirror_backoff.get(&id).cloned().unwrap_or_default();
            if now_ms < retry.next_ms {
                // Backing off: not retried before its time (the hold below
                // still keeps the acknowledging flush waiting).
                waiting = true;
                continue;
            }
            let written_ms = now_ms.max(self.quarantine_record_ms + 1);
            let mut object_mirrored = retry.object_mirrored;
            let result = super::quarantine_store::mirror_once(self.parts, &quarantine, &id, written_ms, &mut object_mirrored).await;
            match result {
                Ok(()) => {
                    self.quarantine_record_ms = written_ms;
                    self.health.quarantine_mirrored_total += 1;
                    self.quarantine_mirror_backoff.remove(&id);
                    if let Err(error) = quarantine.outbox_done(&id) {
                        tracing::warn!(id, error = %format!("{error:#}"), "bronze quarantine outbox entry not cleared");
                    }
                }
                Err(error) => {
                    // NAN-4554 (review P1): this id backs off on its own; the
                    // next ids are still tried (no head-of-line block).
                    self.health.quarantine_mirror_failures_total += 1;
                    let failures = retry.failures.saturating_add(1);
                    let wait = super::quarantine_store::retry_after_ms(failures);
                    self.quarantine_mirror_backoff.insert(id.clone(), MirrorRetry {
                        failures, next_ms: now_ms.saturating_add(wait), object_mirrored,
                        failing_since_ms: retry.failing_since_ms.or(Some(now_ms)),
                    });
                    tracing::warn!(tenant = %self.cfg.tenant_id, id, failures, retry_in_ms = wait, error = %format!("{error:#}"),
                        "bronze quarantine change not mirrored; retried with backoff");
                    last_error = Some(error);
                }
            }
        }
        let failing_since = self.quarantine_mirror_backoff.values().filter_map(|retry| retry.failing_since_ms).min();
        self.health.quarantine_mirror_failing_ids = self.quarantine_mirror_backoff.len();
        self.health.quarantine_mirror_failing_since_ms = failing_since;
        self.quarantine_mirror_failing_since = failing_since;
        if failing_since.is_none() || !hold || !(waiting || last_error.is_some()) {
            return Ok(());
        }
        let detail = last_error.map(|error| format!("{error:#}")).unwrap_or_else(|| "backing off".into());
        // The hold runs per id from its first failure: a change that only
        // started failing is held its full window even when another id has
        // been failing longer.
        let newest_failure = self.quarantine_mirror_backoff.values().filter_map(|retry| retry.failing_since_ms).max().unwrap_or(now_ms);
        let since = failing_since.unwrap_or(now_ms);
        if now_ms.saturating_sub(newest_failure) < super::quarantine_store::MIRROR_HOLD_MS {
            // Flattened: a mirror refusal (even a 403) only delays the
            // flush; it is never a fatal ingest error.
            return Err(anyhow::anyhow!("bronze quarantine change not in the tenant bucket yet; the flush acknowledging it waits: {detail}"));
        }
        tracing::error!(tenant = %self.cfg.tenant_id, failing_ids = self.health.quarantine_mirror_failing_ids,
            failing_for_s = now_ms.saturating_sub(since) / 1_000, error = %detail,
            "BRONZE QUARANTINE NOT DURABLE: the tenant bucket refused it past the hold; proceeding with the copy pod-local only");
        Ok(())
    }

    /// NAN-3643: this tenant's quarantined objects (operator listing).
    pub fn quarantine_entries(&self) -> Result<Vec<QuarantineEntry>> {
        self.quarantine.as_ref().context("bronze quarantine is unavailable")?.list()
    }

    /// NAN-4554: the quarantine directory (an import stages its body there
    /// without holding the ingestor).
    pub fn quarantine_handle(&self) -> Option<Quarantine> {
        self.quarantine.clone()
    }

    /// NAN-4554: an operator imports one object exported from an earlier pod
    /// (`staged`, verified and moved in by [`Quarantine::import`]); a kept
    /// one is mirrored into the tenant bucket by this cell's own credential.
    /// One audit line per import: ids and counts, never payloads.
    pub fn import_quarantined(&mut self, entry: &QuarantineEntry, staged: &Path, now_ms: i64)
        -> Result<super::quarantine::Imported> {
        use super::quarantine::Imported;
        let quarantine = match self.quarantine.clone() {
            Some(quarantine) => quarantine,
            None => {
                let _ = std::fs::remove_file(staged);
                anyhow::bail!("bronze quarantine is unavailable");
            }
        };
        let result = quarantine.import(entry, staged, now_ms);
        let outcome = match &result {
            Ok(Imported::New) => "imported",
            Ok(Imported::Exists) => "exists",
            Err(error) => match error.downcast_ref::<super::quarantine::ImportRefused>() {
                Some(_) => "refused",
                None => "failed",
            },
        };
        let reason = result.as_ref().err().map(|error| format!("{error:#}"));
        tracing::info!(audit = "bronze_quarantine_import", tenant = %self.cfg.tenant_id, id = %entry.id,
            bytes = entry.bytes, rows_rejected = entry.rows_rejected, outcome, reason = reason.as_deref().unwrap_or(""),
            "bronze quarantine import");
        if let Ok(Imported::New) = result {
            self.health.quarantine_imported_total += 1;
            if let Ok((objects, bytes)) = quarantine.usage() {
                self.health.quarantine_objects = objects;
                self.health.quarantine_bytes = bytes;
            }
        }
        result
    }

    /// NAN-3643: an operator asks to replay quarantined object `id` of
    /// `tenant`. Another tenant, a malformed id or an unknown object is
    /// refused ([`super::quarantine::ReplayRefused`]).
    pub fn request_quarantine_replay(&mut self, tenant: &str, id: &str, now_ms: i64) -> Result<QuarantineEntry> {
        let entry = self.quarantine.as_ref().context("bronze quarantine is unavailable")?.request_replay(tenant, id, now_ms)?;
        self.quarantine_replay_pending = true;
        tracing::info!(tenant = %self.cfg.tenant_id, id, source = %entry.source_key, "bronze quarantine replay requested");
        Ok(entry)
    }

    /// NAN-3643: admit the oldest requested replay, alone: only into an
    /// empty buffer with nothing in flight, so its `add` never carries edge
    /// segments (an edge range covers edge segments only).
    async fn admit_quarantine_replay(&mut self, now_ms: i64) -> Result<bool> {
        if !self.quarantine_replay_pending || self.buffer.replay.is_some() || !self.buffer.handles.is_empty() || self.buffer.rows > 0
            || !self.buffer.rejections.is_empty() || self.buffer.partially_committed()
            || !self.flush_in_flight.is_empty() || self.admission_paused
        {
            return Ok(false);
        }
        let Some(quarantine) = &self.quarantine else { return Ok(false) };
        let Some(entry) = quarantine.next_replay()? else {
            self.quarantine_replay_pending = false;
            return Ok(false);
        };
        let notice = SourceNotice {
            tenant_id: self.cfg.tenant_id.clone(),
            key: super::quarantine::quarantine_replay_key(&self.cfg.tenant_id, &entry.id),
            version: QUARANTINE_REPLAY_VERSION.to_string(),
            bytes: entry.bytes,
            sha256: Some(entry.id.clone()),
            edge_sha256: None,
            notified_at_ms: now_ms,
        };
        let handle = NoticeHandle(Quarantine::replay_handle(&entry.id));
        tracing::info!(tenant = %self.cfg.tenant_id, id = %entry.id, source = %entry.source_key,
            "replaying a quarantined bronze object through admission");
        self.buffer.replay = Some(entry.id.clone());
        if let Err(error) = self.admit(&[(handle, notice)], now_ms).await {
            if self.buffer.handles.is_empty() && self.buffer.rows == 0 && self.buffer.rejections.is_empty() {
                self.buffer.replay = None;
            }
            return Err(error);
        }
        Ok(true)
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
        self.flush_ordered(now_ms, pipeline, true).await
    }

    /// [`Self::flush`]; with `commit_ready` false (NAN-4539 step 3a, the
    /// seal-first tick) a seal that may sit beside every flight left seals
    /// before the ready oldest commits, so its build overlaps that commit.
    async fn flush_ordered(&mut self, now_ms: i64, pipeline: bool, commit_ready: bool) -> Result<usize> {
        // Commit what is ready, then wait until this seal may join the
        // flights left (NAN-3619): with depth 1, or whenever this seal would
        // log anything ahead of an earlier flight's `add` (rejections, skip
        // acks, a schema change) or not pipeline at all, every flight
        // commits first, exactly as before.
        let mut keep = if self.may_seal_beside_flights(pipeline) { self.flush_depth() - 1 } else { 0 };
        let mut commit_ready = commit_ready;
        self.diagnostics.state.lock().expect("pipeline diagnostics").tracking_oldest = false;
        self.diagnostics.stage("waiting_for_oldest_flush");
        // NAN-4539 step 3a: when only the working budget keeps this seal
        // from sitting beside the flights (a slot is free), wait for the
        // oldest flight's publication, not its commit. Published, it holds
        // only its retained rows; if the seal fits then, it seals first and
        // its build overlaps that flight's inline commit.
        if self.cfg.commit_when_ready && pipeline && self.flush_in_flight.len() > keep
            && self.flush_in_flight.len() < self.flush_depth()
        {
            self.diagnostics.stage("waiting_for_oldest_publication");
            self.await_oldest_task().await;
            self.settle_published_flights();
            if self.may_seal_beside_flights(pipeline) {
                keep = self.flush_depth() - 1;
                commit_ready = false;
                self.health.seals_first_total = self.health.seals_first_total.saturating_add(1);
            }
        }
        let reaped = if commit_ready || self.flush_in_flight.len() > keep { self.reap_in_flight(now_ms, keep).await? } else { 0 };
        if self.buffer.handles.is_empty() && self.buffer.rows == 0 {
            return Ok(reaped);
        }
        if let Some(since) = self.seal_deferred_since_ms.take() {
            self.health.seal_deferred_max_ms = self.health.seal_deferred_max_ms.max(now_ms.saturating_sub(since));
        }
        // NAN-4554: a refused object's quarantined copy reaches the tenant
        // bucket before the flush acknowledging it to its source.
        self.mirror_quarantine(now_ms, true).await?;
        self.buffer.flush_started_ms.get_or_insert(now_ms);
        if self.buffer.progress.is_none() {
            self.buffer.progress = Some(self.diagnostics.new_flush(self.buffer.rows, self.buffer.bytes));
        }
        self.update_pipeline_diagnostics();
        self.diagnostics.stage("seal_rejections_and_skips");
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
            // (The serial comparison policy keeps the unconditional call.)
            // NAN-3643: a replay's handle was never issued by the queue.
            skips.retain(|(handle, _)| !Quarantine::is_replay_handle(&handle.0));
            if !skips.is_empty() || !(self.cfg.commit_when_ready || self.flush_depth() > 1) {
                self.queue.ack_skipped(&skips).await?;
            }
            self.buffer.skips_acked = true;
        }
        if !no_rows && !self.buffer.add_committed {
            self.diagnostics.stage("issue_edge_range");
            if self.buffer.issued_range.is_none() {
                let mut sources = self.buffer.sources.clone();
                sources.sort();
                self.buffer.issued_range = self
                    .queue
                    .range_for_flush(&sources, self.buffer.rows_refused, self.buffer.duplicates + self.buffer.bronze_duplicates)
                    .await?;
            }
            let range = self.buffer.issued_range.clone();
            if let (true, Some(store), Some(signer)) = (pipeline && self.buffer.built.is_none(), self.background_parts, self.background_signer) {
                self.diagnostics.stage("log_schema");
                self.log_pending_schema(now_ms).await?;
                let plan = self.flush_plan(&self.buffer, self.schema.clone(), range, now_ms)?;
                let reserved_bytes = super::memory::flight_bytes(self.buffer.bytes, plan.writers);
                let trusted = self.trusted.clone();
                let wake = self.flight_wake.clone();
                let progress = self.buffer.progress.clone().expect("sealed diagnostics");
                progress.lock().expect("flush diagnostics").set("build_parts");
                let operations = self.diagnostics.operations.clone();
                let task_progress = progress.clone();
                let published_ok = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let task_published = published_ok.clone();
                let task = tokio::spawn(async move {
                    let result = async {
                        let finished = tokio::task::spawn_blocking(move || plan.build()).await.context("flush part build task")??;
                        { let mut progress = task_progress.lock().expect("flush diagnostics");
                            progress.built(&finished); progress.set("publish_parts"); }
                        let refs = super::writer::publish_parts_observed(store, signer, &trusted, &finished, &operations).await;
                        if refs.is_ok() {
                            task_progress.lock().expect("flush diagnostics").set("awaiting_part_log");
                            task_published.store(true, std::sync::atomic::Ordering::Release);
                        }
                        Ok((finished, refs))
                    }.await;
                    if let Some(wake) = wake {
                        wake.notify_one();
                    }
                    result
                });
                let buffer = std::mem::replace(&mut self.buffer, Buffered::new());
                let sealed_ms = buffer.flush_started_ms.unwrap_or(now_ms);
                self.flush_in_flight.push_back(InFlightFlush { buffer, reserved_bytes, schema: self.schema.clone(), sealed_ms, progress, task: Some(task), built: None, published: None, published_ok });
                self.update_pipeline_diagnostics();
                self.diagnostics.stage("build_and_publish");
                self.health.flushes_pipelined_total += 1;
                self.health.flushes_in_flight_peak = self.health.flushes_in_flight_peak.max(self.flush_in_flight.len());
                return Ok(reaped);
            }
            self.diagnostics.stage("build_publish_and_append");
            self.buffer.parts_committed = match self.commit_parts(now_ms, range).await {
                Ok(count) => count,
                Err(error) => {
                    let (sources, replay) = (self.buffer.sources.clone(), self.buffer.replay.clone());
                    self.note_flush_failure(&sources, replay.as_deref(), &error, now_ms);
                    return Err(error);
                }
            };
            self.buffer.add_committed = true;
        }
        if !no_rows {
            let consumed = self.buffer.admitted.iter().map(|(h, _, _)| h.clone())
                .filter(|handle| !Quarantine::is_replay_handle(&handle.0)).collect::<Vec<_>>();
            self.diagnostics.stage("edge_ack");
            if !consumed.is_empty() || self.buffer.replay.is_none() {
                self.queue.ack(&consumed).await?;
            }
        }
        let buffer = std::mem::replace(&mut self.buffer, Buffered::new());
        Ok(reaped + self.finish_flush(buffer, now_ms, None))
    }

    /// Health accounting of a flush whose acks landed.
    /// `sealed_ms` is when a pipelined flush was sealed (its commit lag).
    fn finish_flush(&mut self, mut buffer: Buffered, now_ms: i64, sealed_ms: Option<i64>) -> usize {
        if let Some(progress) = &buffer.progress { self.diagnostics.completed(progress); }
        self.update_pipeline_diagnostics();
        self.diagnostics.stage(if self.flush_in_flight.is_empty() { "idle" } else { "build_and_publish" });
        let count = buffer.parts_committed;
        // NAN-3643: a replay's flush is durable. Admitted (or already
        // consumed): drop it from the quarantine. Refused again: `keep`
        // already recorded the new refusal and it stays.
        if let (Some(id), Some(quarantine)) = (buffer.replay.as_deref(), &self.quarantine) {
            let refused_again = !buffer.refused.is_empty();
            if refused_again {
                // `keep` cleared the request when admission refused it; a
                // refusal before admission (bytes gone) must not loop.
                if let Err(error) = quarantine.clear_replay(id, now_ms) {
                    tracing::warn!(id, error = %format!("{error:#}"), "quarantine replay request could not be cleared");
                }
            } else {
                // NAN-4338: queue the replay's report before the entry goes
                // (its source key and rows live only in the entry).
                if let Some(ledger) = &mut self.quarantine_ledger {
                    match quarantine.get(id) {
                        Ok(Some(entry)) => {
                            if let Some(report) = ledger_report(&self.cfg.tenant_id, &entry.source_key, entry.rows_rejected,
                                super::quarantine_ledger::ReportState::Replayed) {
                                ledger.enqueue(report);
                            }
                        }
                        Ok(None) => {}
                        Err(error) => tracing::warn!(id, error = %format!("{error:#}"),
                            "replayed quarantine entry unreadable; the landing ledger keeps its rows as quarantined"),
                    }
                }
                match quarantine.release(id, now_ms) {
                    Ok(()) => {
                        self.health.quarantine_replays_total += 1;
                        self.quarantine_swept_ms = 0;
                        tracing::info!(tenant = %self.cfg.tenant_id, id, rows = buffer.rows,
                            "quarantined bronze object replayed and committed");
                    }
                    Err(error) => tracing::warn!(id, error = %format!("{error:#}"), "replayed quarantine entry could not be removed"),
                }
            }
        }
        // NAN-3899: the flush committed (parts in the log, acks landed): its
        // rows are credential activity now, and never again on a replay.
        if let Some(exec) = &mut self.credential_activity {
            if !buffer.activity.is_empty() {
                exec.activity.absorb(std::mem::take(&mut buffer.activity), now_ms);
            }
        }
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
    /// build is retried; a failed publish retains immutable output and ids.
    /// A published flush whose `add` failed retries the `add`. Returns the
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
    ///
    /// Cancellation safe (NAN-4539): the flight stays at the front of
    /// `flush_in_flight` across every await, owning its memory reservation,
    /// background task (awaited by reference, never detached), immutable
    /// output and handles; it is removed only after its acks landed. A
    /// dropped call therefore resumes exactly where it stopped, and an `add`
    /// that landed under a dropped call is adopted by [`Self::commit_add`],
    /// never appended twice.
    async fn commit_oldest_flight(&mut self, now_ms: i64) -> Result<usize> {
        self.update_pipeline_diagnostics();
        self.diagnostics.state.lock().expect("pipeline diagnostics").tracking_oldest = true;
        let Some(front) = self.flush_in_flight.front_mut() else { return Ok(0) };
        let needs_publication = front.published.is_none() && !front.buffer.add_committed;
        // 1. The background build/publish, if one is still owned.
        let joined = match front.task.as_mut() {
            Some(task) if needs_publication => {
                let joined = task.await;
                front.task = None;
                Some(joined)
            }
            _ => None,
        };
        let mut failure = None;
        match joined {
            Some(Ok(Ok((finished, refs)))) => {
                let front = self.flush_in_flight.front_mut().expect("oldest flight");
                front.built = Some(finished);
                match refs {
                    Ok(refs) => front.published = Some(refs),
                    Err(error) => failure = Some(error),
                }
            }
            // The build failed: nothing was built, the retry builds again.
            Some(Ok(Err(error))) => return Err(error.context("pipelined flush build/publish")),
            Some(Err(error)) => return Err(anyhow::anyhow!("pipelined flush task failed: {error}").context("pipelined flush build/publish")),
            None => {}
        }
        // 2. No task (a retry): build if needed, then publish in place. The
        // output stays in the flight while the upload awaits.
        let front = self.flush_in_flight.front().expect("oldest flight");
        if failure.is_none() && front.published.is_none() && !front.buffer.add_committed {
            if front.built.is_none() {
                self.diagnostics.stage("build_parts");
                let finished = self.flush_plan(&front.buffer, front.schema.clone(), front.buffer.issued_range.clone(), now_ms)
                    .and_then(FlushPlan::build)
                    .map_err(|error| error.context("pipelined flush build/publish"))?;
                self.flush_in_flight.front_mut().expect("oldest flight").built = Some(finished);
            }
            self.diagnostics.stage("publish_parts");
            let front = self.flush_in_flight.front().expect("oldest flight");
            let finished = front.built.as_ref().expect("built above");
            front.progress.lock().expect("flush diagnostics").built(finished);
            match super::writer::publish_parts_observed(self.parts, self.signer, &self.trusted, finished, &self.diagnostics.operations).await {
                Ok(refs) => self.flush_in_flight.front_mut().expect("oldest flight").published = Some(refs),
                Err(error) => failure = Some(error),
            }
        }
        if let Some(error) = failure {
            let (sources, replay) = {
                let front = self.flush_in_flight.front().expect("oldest flight");
                (front.buffer.sources.clone(), front.buffer.replay.clone())
            };
            self.note_flush_failure(&sources, replay.as_deref(), &error, now_ms);
            // Synchronous: the output is out of the flight only while no
            // await can drop this call.
            let mut finished = self.flush_in_flight.front_mut().expect("oldest flight").built.take().expect("published output");
            let front = self.flush_in_flight.front().expect("oldest flight");
            let rebuilt = self.rebuild_unresolved_publication(&front.buffer, front.schema.clone(), &mut finished, &error, now_ms);
            self.flush_in_flight.front_mut().expect("oldest flight").built = Some(finished);
            let error = rebuilt.err().unwrap_or(error);
            return Err(error.context("pipelined flush build/publish"));
        }
        // 3. The `add` (adopted if an earlier, dropped attempt landed it).
        let front = self.flush_in_flight.front().expect("oldest flight");
        if !front.buffer.add_committed {
            let refs = front.published.clone().expect("published above");
            let parts = add_parts(front.built.as_ref().expect("published output is retained"));
            let (consumed, range) = (consumed_sources(&front.buffer), front.buffer.issued_range.clone());
            self.diagnostics.stage("append_part_log");
            // NAN-4737: behind with a background pipeline, the next
            // admission follows: its parse runs beside this add's apply.
            let defer_apply = self.behind_last_tick && self.background_parts.is_some();
            let count = self.commit_add(&parts, refs, consumed, range, now_ms, defer_apply).await?;
            let front = self.flush_in_flight.front_mut().expect("oldest flight");
            front.buffer.parts_committed = count;
            front.buffer.add_committed = true;
        }
        // 4. The acks; only then does the flight leave the queue.
        let handles = self.flush_in_flight.front().expect("oldest flight").buffer.admitted.iter().map(|(h, _, _)| h.clone())
            .filter(|handle| !Quarantine::is_replay_handle(&handle.0)).collect::<Vec<_>>();
        self.diagnostics.stage("edge_ack");
        self.queue.ack(&handles).await?;
        let flight = self.flush_in_flight.pop_front().expect("oldest flight");
        Ok(self.finish_flush(flight.buffer, now_ms, Some(flight.sealed_ms)))
    }

    /// Flushes allowed in flight at once: the configured depth, capped by
    /// what the queue lets be outstanding (NAN-3619). NAN-4539: one (the
    /// serial contract) without the cell's background handles, while the
    /// over-commit hold pauses admission, while the catalog attachment is
    /// degraded and while an erasure order or step is active.
    fn flush_depth(&self) -> usize {
        if self.background_parts.is_none() || self.background_signer.is_none()
            || self.admission_paused || self.cfg.catalog_attachment_failure.is_some()
            || self.erasure_pipeline_barrier()
        {
            return 1;
        }
        self.cfg.flush_depth.clamp(1, MAX_FLUSH_DEPTH).min(self.queue.max_outstanding_ranges().max(1))
    }

    /// Whether sealing now would block on an unfinished flight (NAN-4539
    /// step 3a): flights beyond what this seal may sit beside are still out
    /// (ready ones were committed earlier in the tick). Only with the
    /// production commit-when-ready policy; the serial comparison policy
    /// keeps waiting.
    fn seal_would_wait_for_flight(&self, pipeline: bool) -> bool {
        if !self.cfg.commit_when_ready || self.flush_in_flight.is_empty()
            || self.buffer.partially_committed() || self.buffer.replay.is_some() || self.buffer.rows == 0
        {
            return false;
        }
        let keep = if self.may_seal_beside_flights(pipeline) { self.flush_depth() - 1 } else { 0 };
        self.flush_in_flight.len() > keep
    }

    /// Age-due seals deferred beside an unfinished flight, and seals made
    /// before the ready oldest flight committed (NAN-4539 step 3a).
    pub fn seals_deferred(&self) -> (u64, u64) {
        (self.health.seals_deferred_total, self.health.seals_first_total)
    }

    /// Whether the buffer is due to seal: `(by age, by a cap)`.
    fn seal_due_parts(&self, now_ms: i64, behind: bool) -> (bool, bool) {
        let mut interval = self.cfg.flush_interval_override_ms.unwrap_or_else(|| self.cfg.flush_policy.interval_ms(self.health.eps_ewma));
        if behind && self.cfg.flush_interval_override_ms.is_none() {
            interval = interval.max(CATCH_UP_FLUSH_MAX_AGE_MS);
        }
        let due_by_age = self.buffer.since_ms.is_some_and(|since| now_ms - since >= interval);
        let due_by_cap = self.buffer.rows >= FLUSH_MAX_ROWS
            || self.buffer.bytes >= super::memory::buffer_cap(self.cfg.buffer_budget_bytes)
            // The budget is spent (flight + merges + buffer): admission is
            // stalled, so seal what is buffered rather than wait out the age.
            || (self.buffer.rows > 0 && self.committed_bytes() >= self.cfg.buffer_budget_bytes)
            || self.buffer.hours.len() >= flush_event_hour_cap(behind)
            || self.buffer.handles.len() >= MAX_FLUSH_OBJECTS
            || self.buffer.rejections.len() >= MAX_REJECTIONS_PER_ENTRY
            // NAN-4319: the next object's decoded rows did not fit beside
            // the buffer; seal it so the next tick admits from idle.
            || (self.buffer.rows > 0 && self.admission_deferred)
            || self.crash_recovery_seal(now_ms);
        (due_by_age, due_by_cap)
    }

    fn seal_due(&self, now_ms: i64, behind: bool) -> bool {
        let (age, cap) = self.seal_due_parts(now_ms, behind);
        age || cap
    }

    /// NAN-4539 step 3a: before a published flight commits inline (its
    /// part-log append and prevalence apply hold this task, and admission
    /// with it), a catch-up buffer that fits beside the flights left seals
    /// first, so its build and upload overlap that commit. Only a buffer
    /// that is due, or holds at least one full L0 part.
    async fn seal_before_commit(&mut self, now_ms: i64) -> Result<usize> {
        self.settle_published_flights();
        if self.cfg.commit_when_ready && self.behind_last_tick && self.buffer.replay.is_none()
            && self.flush_in_flight.len() < self.flush_depth()
            && self.flush_in_flight.front().is_some_and(|front| front.published_ok.load(std::sync::atomic::Ordering::Acquire))
            && (self.seal_due(now_ms, true) || self.buffer.rows >= SEAL_FIRST_MIN_ROWS)
            && self.may_seal_beside_flights(true)
        {
            self.health.seals_first_total = self.health.seals_first_total.saturating_add(1);
            return self.flush_ordered(now_ms, true, false).await;
        }
        Ok(0)
    }

    /// Wait until the oldest flight's background task finished (published
    /// or failed), without taking its result: the commit stays with
    /// [`Self::commit_oldest_flight`]. Cancellation safe (no state change).
    /// Without the finished-flight wake it returns at once (the caller then
    /// waits on the commit, as before).
    async fn await_oldest_task(&self) {
        let Some(wake) = self.flight_wake.clone() else { return };
        while self.flush_in_flight.front().is_some_and(|front| front.task.as_ref().is_some_and(|task| !task.is_finished())) {
            let _ = tokio::time::timeout(std::time::Duration::from_millis(250), wake.notified()).await;
        }
    }

    /// NAN-4539 step 3a: a flight whose background task published its parts
    /// has freed its build copies and writers; it holds only the rows it
    /// retains until its acks land (a retry rebuilds from them inline).
    fn settle_published_flights(&mut self) {
        for flight in &mut self.flush_in_flight {
            if flight.published_ok.load(std::sync::atomic::Ordering::Acquire) {
                flight.reserved_bytes = flight.reserved_bytes.min(flight.buffer.bytes);
            }
        }
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
            // The one-object progress escape belongs to the serial path. A
            // second seal must fit its full build/writer reservation, even if
            // admission itself fitted. Future admission uses the remaining room.
            && self.flush_in_flight.iter().map(|f| f.reserved_bytes).sum::<u64>()
                .saturating_add(self.merges_reserved_bytes())
                .saturating_add(super::memory::flight_bytes(self.buffer.bytes, 1))
                <= self.cfg.buffer_budget_bytes
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
        // NAN-4750: the open hour's L0 parts are class-pure where a class
        // fills a dedicated part, so class-filtered queries prune them.
        let hours = buffer.hours.iter()
            .map(|(hour, batches)| Ok((*hour, batches.clone(), buffer.hour_duplicates.get(hour).copied().unwrap_or_default(),
                l0_class_families(batches)?)))
            .collect::<Result<Vec<_>>>()?;
        let planned_parts = hours.iter()
            .map(|(_, batches, _, families)| {
                let rows = batches.iter().map(RecordBatch::num_rows).sum::<usize>();
                l0_chunks(rows).len().max(usize::from(rows > 0) + families.len())
            })
            .sum::<usize>();
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
            hours,
            now_ms,
            // NAN-4539 step 3a: reserve only the writers the plan can use
            // (`write_l0_parts_with` runs at most one per part; NAN-4750:
            // at most this many with its class drafts).
            writers: self.flush_writers(buffer.bytes).min(planned_parts.max(1)),
        })
    }

    /// Bytes reserved for running merges, with room for at least one merge
    /// kept even before it starts. Admission and flush writers share the rest.
    fn merges_reserved_bytes(&self) -> u64 {
        (self.merge_in_flight.len() as u64 * super::merge::merge_reserve_bytes()).max(self.cfg.merge_headroom_bytes)
    }

    /// Tests (NAN-4770 before/after): the fixed admission model, slicing
    /// only from idle. Always false in production.
    fn fixed_admission_model(&self) -> bool {
        #[cfg(test)]
        return self.fixed_admission_model;
        #[cfg(not(test))]
        false
    }

    /// Everything the working budget is charged with now: the filling
    /// buffer, the flush in flight (rows + build + writers) and the merges.
    fn committed_bytes(&self) -> u64 {
        self.buffer.bytes
            .saturating_add(self.flush_in_flight.iter().map(|flight| flight.reserved_bytes).sum::<u64>())
            .saturating_add(self.merges_reserved_bytes())
    }

    fn another_merge_fits(&self, level: Level) -> bool {
        let reserve = super::merge::merge_reserve_bytes();
        let other = self.committed_bytes().saturating_sub(self.merges_reserved_bytes());
        let mut slots = self.merge_in_flight.len() + 1;
        if level != Level::Minute {
            // The role pool is larger than the ingest working budget on big
            // hosts (the latter caps at 4 GiB). History/rewrite jobs must not
            // fill that budget and block every minute merge until they finish.
            // Retain the original two-history service rate in smaller lab
            // budgets that cannot hold a minute job beside both histories.
            let affordable = (self.cfg.buffer_budget_bytes.saturating_sub(other) / reserve).saturating_sub(2) as usize;
            let progress = super::merge_lanes::MergeCapacity::read().minute_progress_slots().min(affordable);
            let minutes = self.merge_in_flight.iter().filter(|flight| flight.merge.output_level == Level::Minute).count();
            slots += progress.saturating_sub(minutes);
        }
        let next = (slots as u64 * reserve)
            .max(self.cfg.merge_headroom_bytes);
        other.saturating_add(next) <= self.cfg.buffer_budget_bytes
    }

    /// Parallel writers for a flush of `buffer_bytes`: the most whose build
    /// fits beside merge room, a full next buffer and fresh admission.
    fn flush_writers(&self, buffer_bytes: u64) -> usize {
        let budget = self.cfg.buffer_budget_bytes;
        // Earlier flights still in flight (depth > 1) hold their build too.
        let flights = self.flush_in_flight.iter().map(|flight| flight.reserved_bytes).sum::<u64>();
        // The next admission has a JSON peak as well as retained Arrow.
        // Without this reserve, small-role flights spend all freed buffer
        // room on extra writers and admission still cannot overlap them.
        let admission = (budget / 3).min(super::memory::FLIGHT_ADMISSION_BYTES);
        let others = self.merges_reserved_bytes().saturating_add(super::memory::buffer_cap(budget))
            .saturating_add(admission).saturating_add(flights);
        super::memory::writers_for(buffer_bytes, budget.saturating_sub(others))
    }

    /// Unknown native PUT outcomes must keep their original journal fenced.
    /// Rebuild only that hour from retained Arrow rows: Parquet embeds its part
    /// ID, so changing just the provenance ID would invalidate the contract.
    /// Completed parts of every other hour retain their IDs and native receipts.
    fn rebuild_unresolved_publication(&self, buffer: &Buffered, schema: SchemaRef,
        finished: &mut Vec<FinishedPart>, error: &anyhow::Error, now_ms: i64) -> Result<bool> {
        let Some(hour) = super::writer::unresolved_publication_hour(finished, error)? else { return Ok(false) };
        self.diagnostics.stage("rebuild_unresolved_hour");
        let previous = finished.iter().find(|part| part.record.event_hour == hour)
            .context("unresolved publication hour missing")?;
        let mut plan = self.flush_plan(buffer, schema, buffer.issued_range.clone(), now_ms)?;
        // Preserve the original admission pins even if advisory state changes.
        plan.admission = previous.record.admission.clone().context("L0 admission missing")?;
        plan.signer_key_id = previous.record.signer_key_id.clone();
        plan.build = previous.record.writer.build.clone();
        plan.hours.retain(|(candidate, _, _, _)| *candidate == hour);
        ensure!(!plan.hours.is_empty(), "unresolved publication has no buffered rows");
        let rebuilt = plan.build()?;
        let old_rows = finished.iter().filter(|part| part.record.event_hour == hour)
            .map(|part| part.record.rows).sum::<u64>();
        ensure!(rebuilt.iter().map(|part| part.record.rows).sum::<u64>() == old_rows,
            "unresolved publication rebuild changed row count");
        finished.retain(|part| part.record.event_hour != hour);
        finished.extend(rebuilt);
        finished.sort_by_key(|part| (part.record.event_hour, part.record.min_time_us));
        Ok(true)
    }

    async fn commit_parts(&mut self, now_ms: i64, edge_log: Option<crate::parts::EdgeLogRange>) -> Result<usize> {
        self.diagnostics.stage("log_schema");
        self.log_pending_schema(now_ms).await?;
        self.diagnostics.stage("build_parts");
        if self.buffer.built.is_none() {
            self.buffer.built = Some(self.flush_plan(&self.buffer, self.schema.clone(), edge_log.clone(), now_ms)?.build()?);
        }
        // The output stays in the buffer across the awaits below (a dropped
        // call keeps its part ids; NAN-4539), until the buffer's acks land.
        let finished_parts = self.buffer.built.as_ref().expect("built above");
        if let Some(progress) = &self.buffer.progress { progress.lock().expect("flush diagnostics").built(finished_parts); }
        self.diagnostics.stage("publish_parts");
        let outcome = match super::writer::publish_parts_observed(self.parts, self.signer, &self.trusted, finished_parts, &self.diagnostics.operations).await {
            Ok(refs) => {
                let parts = add_parts(finished_parts);
                let consumed = consumed_sources(&self.buffer);
                self.commit_add(&parts, refs, consumed, edge_log, now_ms, false).await
            }
            Err(error) => Err(error),
        };
        match outcome {
            Ok(count) => Ok(count),
            Err(error) => {
                // Synchronous: no await while the output is out of the buffer.
                let mut finished_parts = self.buffer.built.take().expect("built above");
                let rebuilt = self.rebuild_unresolved_publication(&self.buffer, self.schema.clone(), &mut finished_parts, &error, now_ms);
                self.buffer.built = Some(finished_parts);
                Err(rebuilt.err().unwrap_or(error))
            }
        }
    }

    /// Append the flush's `add` for its published parts and apply it to the
    /// prevalence state. Nothing after the append fails.
    ///
    /// NAN-4539: an earlier attempt of this same `add` may have committed
    /// with its outcome lost to a dropped call (a cancelled tick, or one
    /// cancelled inside the part log's post-commit checkpoint). When the log
    /// already knows every one of its parts it is adopted, never appended
    /// again (that would double-consume its sources, a fatal error), and its
    /// prevalence apply is left to the exactly-once cursor replay.
    /// `defer_apply` (NAN-4737, pipelined catch-up only): the prevalence
    /// apply of this `Add` may run beside the next admission's parse
    /// instead of on the serial commit. Ack ordering is unchanged: the
    /// caller acks after this returns, i.e. after the append is durable; the
    /// apply is replayable from the log and is not an ack precondition.
    async fn commit_add(&mut self, finished_parts: &[AddPart], refs: Vec<PartRef>, consumed: Vec<SourceRef>,
        edge_log: Option<crate::parts::EdgeLogRange>, now_ms: i64, defer_apply: bool) -> Result<usize> {
        // NAN-4737: at most one deferred apply. A second commit before the
        // next admission applies the first now (backpressure), so the cursor
        // is at the previous `Add` again before this one is appended.
        self.finish_deferred_prevalence(now_ms).await;
        let count = refs.len();
        if !refs.is_empty() && refs.iter().all(|part| self.log.live().knows(&part.part_id)) {
            // Defense in depth: the landed add also consumed these sources.
            if !consumed.iter().all(|source| self.log.live().consumed(source)) {
                return Err(AdoptionRefused.into());
            }
            if self.prevalence_held() {
                self.prevalence_pending = true;
            }
            for part in &refs {
                self.window.load_marker(part.event_hour, part.part_id.as_str(), now_ms);
            }
            tracing::warn!(tenant = %self.cfg.tenant_id, parts = count,
                "flush add already committed by an interrupted attempt; adopted without a second append");
            return Ok(count);
        }
        if let Some(prevalence) = &self.prevalence {
            prevalence.check_parts(&self.cfg.tenant_id,
                &finished_parts.iter().map(|part| (part.partial_prevalence.as_path(), part.max_time_us)).collect::<Vec<_>>())?;
        }
        // Merges must not consume these L0s until their partials are in the
        // prevalence state; `replay_prevalence` clears this after a failure.
        let already_pending = self.prevalence_pending;
        self.prevalence_pending = self.prevalence_held();
        self.diagnostics.stage("append_part_log");
        let append_timing = self.diagnostics.operations.start("part_log_append");
        let AppendOutcome::Committed { seq, entry_sha256 } =
            self.log.append(LogOp::Add { parts: refs.clone(), consumed, edge_log }, now_ms).await?;
        drop(append_timing);
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
            // NAN-4737: the state holds every earlier `Add` (nothing was
            // pending), so this one is the next to apply. It stays pending
            // until the next admission's parse runs beside it.
            let cursor = if defer_apply && !already_pending && self.prevalence_pending {
                complete_cursor(self.prevalence.as_ref()).await.filter(|(cursor, _)| *cursor < seq)
            } else {
                None
            };
            if let Some(cursor) = cursor {
                self.diagnostics.stage("apply_prevalence_deferred");
                self.prevalence_deferred = Some(DeferredApply {
                    seq, entry_sha256, refs: refs.clone(), parts: finished_parts.to_vec(), cursor, tick: self.ingest_ticks,
                });
            } else {
                self.diagnostics.stage("apply_prevalence");
                self.apply_committed_add(seq, &entry_sha256, &refs, finished_parts, already_pending, now_ms).await;
            }
        }
        for part in &refs {
            // Our own uids are already in the window.
            self.window.load_marker(part.event_hour, part.part_id.as_str(), now_ms);
        }
        Ok(count)
    }

    /// Apply a committed `Add` within the ingest wait: the entry itself
    /// when the state holds every earlier one, else the replay from the
    /// cursor. Never fails: a cut or failed apply stays pending and the
    /// cursor replay (merges, the prevalence step) lands it exactly once.
    async fn apply_committed_add(&mut self, seq: u64, entry_sha256: &str, refs: &[PartRef], finished_parts: &[AddPart],
        replay: bool, now_ms: i64) {
        let _prevalence_timing = self.diagnostics.operations.start("prevalence_apply");
        let wait = self.ingest_wait();
        let applied = if replay {
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(self.cfg.prevalence_rebuild_budget_ms);
            tokio::time::timeout(wait, self.replay_prevalence(Some(deadline))).await
        } else {
            tokio::time::timeout(wait, self.apply_committed_prevalence(seq, entry_sha256, refs, finished_parts)).await
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

    /// NAN-4737: land the deferred apply, if any. It runs only while the
    /// state is still stamping with that `Add` owed; otherwise (closed,
    /// rotated, rebuilding) it is dropped and the cursor replay owns it. A
    /// cursor that moved since the deferral (a reopen or rotation that lost
    /// a WAL tail) or a partial evicted from the local part cache meanwhile
    /// goes through the replay (retained copy or store) instead.
    async fn finish_deferred_prevalence(&mut self, now_ms: i64) {
        let Some(deferred) = self.prevalence_deferred.take() else { return };
        if !(self.prevalence_pending && self.prevalence_phase == PrevalencePhase::Stamping && self.prevalence_ready()) {
            return;
        }
        let unmoved = complete_cursor(self.prevalence.as_ref()).await.is_some_and(|cursor| cursor == deferred.cursor);
        // The fast path applies this one entry and then clears pending, so
        // it is exact only while the deferred `Add` is still the log head. A
        // finding `Add` (`commit_finding`) committed meanwhile is owed to the
        // replay; clearing pending after the fast path would skip it, and the
        // next `Add`'s apply would move the cursor past it for good.
        let at_head = self.log.live().head().is_some_and(|(head, _, _)| head == deferred.seq);
        let replay = !unmoved || !at_head || !deferred.parts.iter().all(|part| part.partial_prevalence.exists());
        self.apply_committed_add(deferred.seq, &deferred.entry_sha256, &deferred.refs, &deferred.parts, replay, now_ms).await;
    }

    /// NAN-4737: whether a committed `Add`'s apply is waiting for the next
    /// admission (tests and diagnostics).
    #[doc(hidden)]
    pub fn prevalence_apply_deferred(&self) -> bool {
        self.prevalence_deferred.is_some()
    }

    async fn apply_committed_prevalence(&mut self, seq: u64, entry_sha256: &str, refs: &[PartRef],
        finished_parts: &[AddPart]) -> Result<()> {
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
                .find(|finished| finished.part_id == part.part_id)
                .context("published part has no local draft")?;
            prevalence.apply_part(&self.cfg.tenant_id, &entry, index as u32, part.part_id.as_str(),
                &finished.partial_prevalence, finished.max_time_us).await?;
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
        let overdue = crate::parts::levels::l0_merge_overdue_ms(self.log.live().parts(), now_ms, &self.cfg.merge_policy);
        if let Some(state) = &self.prevalence {
            state.update_restamp_headroom(lag_ms, self.cfg.lag_alert_ms, overdue);
            if now_ms.saturating_sub(self.prevalence_read_stats_at_ms) >= 60_000 {
                self.prevalence_read_stats_at_ms = now_ms;
                for read in state.read_stats() {
                    tracing::info!(tenant = %self.cfg.tenant_id, path = read.path, r2_gets = read.gets,
                        r2_heads = read.heads, r2_bytes = read.bytes, point_cache_hits = read.point_cache_hits,
                        memory_cache_hits = read.memory_cache_hits, db_reads = read.db_reads, "prevalence read I/O since open");
                }
            }
        }

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
            // NAN-4737: a deferred apply lands beside the next admission
            // (within one tick); merges wait for it like any owed apply.
            let caught_up = if self.prevalence_deferred.is_none() && self.prevalence_phase == PrevalencePhase::Stamping
                && self.prevalence_ready()
            {
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
        let live_hours = live.iter().map(|part| part.event_hour).collect();
        if let Err(error) = self.merge_attempts.retain_live_hours(&live_hours) {
            tracing::warn!(error = %format!("{error:#}"), "merge attempt ledger not pruned");
        }
        let planned = plan_merges_with(&live, now_ms, &self.cfg.merge_policy, history_open);
        let mut planned = self.converge_memory_bound_merges(planned);
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
            if self.merge_parked(&key, now_ms) {
                continue;
            }
            if merge.output_level != Level::Minute && !super::merge_quota::history_merge_may_start() {
                continue;
            }
            attempts += 1;
            let inputs = merge.inputs.len();
            match self.run_merge(merge, now_ms).await {
                Ok(()) => {
                    self.merge_attempt_ended(&key, inputs, None, now_ms);
                    self.merge_quarantine.remove(&key);
                    done += 1;
                }
                Err(error) => {
                    self.merge_attempt_ended(&key, inputs, Some(&error), now_ms);
                    self.quarantine_merge(key, now_ms, &error);
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
            let inputs = flight.merge.inputs.len();
            let outcome = match flight.handle.await {
                Ok(Ok((result, published))) => self.commit_merge(flight.merge, result, published, now_ms).await,
                Ok(Err(error)) => Err(error),
                Err(join) => Err(anyhow::anyhow!("merge task panicked or was cancelled: {join}")),
            };
            self.merge_attempt_ended(&key, inputs, outcome.as_ref().err(), now_ms);
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
        // Fresh hours first in the minute lane; history takes the hour that
        // just closed first (NAN-4750), then the most fragmented hour,
        // newest on ties (NAN-3400).
        super::merge_lanes::launch_order_at(&mut planned, now_ms);
        for merge in planned {
            let minute = merge.output_level == Level::Minute;
            if !minute && (self.catching_up(lag_ms) || self.buffer.rows > 0 || !self.buffer.handles.is_empty())
                && !self.fragmented_merge_may_run_beside_admission(&merge)
                && !(super::merge_lanes::fresh_runs_beside_admission(&merge, now_ms, self.catching_up(lag_ms),
                    self.merge_in_flight.iter().map(|flight| &flight.merge),
                    || super::merge_lanes::history_memory_admits(super::merge_lanes::MemorySnapshot::read()))
                    // NAN-4750/NAN-4755: beside a live buffer even a first
                    // merge must fit the working budget.
                    && self.another_merge_fits(merge.output_level)) {
                continue;
            }
            // NAN-3795: count rewrites are bounded by their own lane, not the
            // history lanes: a sealed-hour merge never waits behind them. It
            // still needs the memory headroom they use.
            // NAN-4826: reserve peaks across BOTH lanes and count rewrites,
            // including jobs launched this tick whose RSS has not grown yet.
            if !super::merge_lanes::MergeCapacity::read().fits(merge.output_level,
                self.merge_in_flight.iter().map(|flight| &flight.merge)) {
                continue;
            }
            let candidate_rewrite = self.is_count_rewrite(&merge);
            let active = self.merge_in_flight.iter().map(|f| &f.merge)
                .filter(|m| candidate_rewrite || !self.is_count_rewrite(m)).collect::<Vec<_>>();
            if !super::merge_lanes::available_at(&merge, &active, now_ms) { continue; }
            if !candidate_rewrite && !minute && active.iter().all(|m| m.output_level == Level::Minute)
                && self.merge_in_flight.iter().any(|f| self.is_count_rewrite(&f.merge))
                && !super::merge_lanes::history_memory_admits(super::merge_lanes::MemorySnapshot::read()) {
                continue;
            }
            // The first merge consumes the headroom already reserved for
            // it; further lanes need additional room in the same budget.
            if !self.another_merge_fits(merge.output_level) {
                continue;
            }
            let key = (merge.output_level.code().to_string(), merge.event_hour);
            if self.merge_quarantine.get(&key).is_some_and(|(_, until)| *until > now_ms) { continue; }
            if self.merge_parked(&key, now_ms) { continue; }
            // NAN-4755: admission comes first. A history merge starts only
            // while the role has room beside it; the guard stops a running
            // one (`merge_quota::memory_guard`) before the cgroup OOM.
            if !minute && !super::merge_quota::history_merge_may_start() {
                if now_ms.saturating_sub(self.merge_memory_wait_log_ms) >= 60_000 {
                    self.merge_memory_wait_log_ms = now_ms;
                    tracing::info!(tenant = %self.cfg.tenant_id, level = merge.output_level.code(), hour = merge.event_hour,
                        "history merge waits: ingest is using the role's memory");
                }
                continue;
            }
            let rewrite = self.is_reindex_rewrite(&merge).then_some(merge.event_hour);
            let inputs = merge.inputs.len();
            match self.spawn_merge(merge, now_ms).await {
                Ok(handle) => self.merge_in_flight.push(handle),
                Err(error) => {
                    self.merge_attempt_ended(&key, inputs, Some(&error), now_ms);
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

    /// Tests of the cell constructor (NAN-4539): the effective depth.
    #[cfg(test)]
    pub(crate) fn effective_flush_depth_for_test(&self) -> usize {
        self.flush_depth()
    }

    /// Tests of the cell constructor (NAN-4539): the wake a finished flight
    /// notifies.
    #[cfg(test)]
    pub(crate) fn flight_wake_for_test(&self) -> Option<&std::sync::Arc<tokio::sync::Notify>> {
        self.flight_wake.as_ref()
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

    /// NAN-4674: history merges wait while ingest catches up or rows are
    /// buffered, except ONE that consolidates a fragmented hour (a
    /// backfill adds a part to every hour it spans on every flush, and
    /// catch-up lasts as long as the backfill). One at a time: no other
    /// history merge (or count rewrite) may be in flight, so admission keeps
    /// the rest of the cell. Lane, memory and budget gates still apply.
    fn fragmented_merge_may_run_beside_admission(&self, merge: &crate::parts::levels::PlannedMerge) -> bool {
        super::merge_lanes::fragmented_runs_beside_admission(merge, self.merge_in_flight.iter().map(|flight| &flight.merge))
            // Splitting changes the candidate's fan-in, not the hour's
            // fragmentation. Keep its one catch-up lane until the live
            // hour is below the fragmentation threshold.
            || (merge.output_level == Level::Hour
                && self.merge_attempts.max_inputs(&super::merge_attempts::merge_id("h", merge.event_hour)).is_some()
                && crate::parts::levels::hour_is_fragmented(self.log.live().parts()
                    .filter(|part| part.event_hour == merge.event_hour).count())
                && self.merge_in_flight.iter().all(|flight| flight.merge.output_level == Level::Minute))
    }

    /// Lag past the hour seal: the backlog is feeding sealed hours.
    fn catching_up(&self, lag_ms: i64) -> bool {
        lag_ms > self.cfg.merge_policy.hour_seal_ms
    }

    /// NAN-4755: a merge that ran out of memory at its smallest shape
    /// waits out its park; ingest and every other merge go on.
    fn merge_parked(&self, key: &(String, i32), now_ms: i64) -> bool {
        let id = super::merge_attempts::merge_id(&key.0, key.1);
        self.merge_attempts.left_unmerged(&id) || self.merge_attempts.parked_until(&id, now_ms).is_some()
    }

    /// NAN-4755: end a merge's attempt in the ledger. A commit clears it; a
    /// memory-guard stop shrinks it (or parks it) without a restart; any
    /// other failure just ends it (the quarantine backs it off).
    fn merge_attempt_ended(&mut self, key: &(String, i32), inputs: usize, error: Option<&anyhow::Error>, now_ms: i64) {
        let id = super::merge_attempts::merge_id(&key.0, key.1);
        let recorded = match error {
            None => {
                self.merge_memory_waits.remove(key);
                self.merge_attempts.committed(&id)
            }
            Some(error) if super::merge_quota::memory_pressure_of(error).is_some_and(|stop| !stop.charged_to_merge())
                && self.merge_memory_waits.get(key).copied().unwrap_or(0) < MAX_UNCHARGED_MEMORY_STOPS => {
                // NAN-4796: the merge started with the process already
                // past the start share: memory held elsewhere (admission,
                // flushes) left it no room. Running it smaller would not
                // fit better, so it keeps its shape and retries after
                // MEMORY_STOP_RETRY_MS, a bounded number of times.
                self.health.merge_memory_stops_total += 1;
                *self.merge_memory_waits.entry(key.clone()).or_default() += 1;
                self.merge_quarantine.insert(key.clone(), (self.merge_quarantine.get(key).map_or(0, |(n, _)| *n), now_ms + MEMORY_STOP_RETRY_MS));
                tracing::info!(tenant = %self.cfg.tenant_id, merge = %id, error = %format!("{error:#}"),
                    "merge stopped by memory held elsewhere, not its own growth; it keeps its shape and retries shortly");
                self.merge_attempts.ended(&id)
            }
            Some(error) if super::merge_quota::is_memory_pressure(error) => {
                self.health.merge_memory_stops_total += 1;
                // NAN-4796: no quarantine, but not again on this tick: its
                // plan was made before this reap, at the old shape and
                // fan-in. The next tick replans it smaller.
                self.merge_quarantine.insert(key.clone(), (self.merge_quarantine.get(key).map_or(0, |(n, _)| *n), now_ms + 1));
                let splittable = if key.0 == Level::Day.code() { 0 } else { inputs };
                self.merge_attempts.shrink(&id, now_ms, splittable).map(|outcome| {
                    if outcome == super::merge_attempts::Shrunk::LeftUnmerged {
                        tracing::error!(tenant = %self.cfg.tenant_id, merge = %id, error = %format!("{error:#}"),
                            "merge left unmerged: even its smallest chunk does not fit the ingest role's memory; its parts stay live and readable, ingest keeps running (retried only if memory.max grows)");
                    } else {
                        tracing::warn!(tenant = %self.cfg.tenant_id, merge = %id, outcome = ?outcome, error = %format!("{error:#}"),
                            "merge stopped before the cgroup OOM; it reruns smaller (or waits) and ingest keeps running");
                    }
                })
            }
            Some(_) => self.merge_attempts.ended(&id),
        };
        if let Err(error) = recorded {
            tracing::warn!(error = %format!("{error:#}"), merge = %id, "merge attempt ledger not updated");
        }
    }

    /// NAN-4755: planned merges as the attempt ledger bounds them. A merge
    /// split past its smallest shape runs as chunks of at most its cap; one
    /// left unmerged is not planned (nor counted as backlog) at all, unless
    /// the role's `memory.max` grew since. Catch-up converges in a bounded
    /// number of attempts either way.
    fn converge_memory_bound_merges(&mut self, planned: Vec<crate::parts::levels::PlannedMerge>) -> Vec<crate::parts::levels::PlannedMerge> {
        if self.merge_attempts.left_unmerged_count() > 0 {
            match self.merge_attempts.rearm_if_limit_grew(super::merge_quota::memory_limit()) {
                Ok(0) => {}
                Ok(rearmed) => tracing::info!(tenant = %self.cfg.tenant_id, rearmed, "memory.max grew; merges left unmerged get one more bounded attempt"),
                Err(error) => tracing::warn!(error = %format!("{error:#}"), "merge attempt ledger not updated"),
            }
        }
        self.health.merges_left_unmerged = self.merge_attempts.left_unmerged_count() as u64;
        planned.into_iter().flat_map(|merge| {
            let id = super::merge_attempts::merge_id(merge.output_level.code(), merge.event_hour);
            if self.merge_attempts.left_unmerged(&id) {
                return Vec::new();
            }
            // Model only work that can start: memory held by admission
            // must not permanently shrink an otherwise healthy hour.
            if merge.output_level == Level::Hour && super::merge_quota::history_merge_may_start()
                && !self.merge_attempts.entry(&id).is_some_and(|entry| entry.in_flight) {
                let headroom = super::merge_quota::merge_headroom();
                let mut shift = self.merge_attempts.shift(&id);
                let mut cap = self.merge_attempts.max_inputs(&id);
                // Already committed h chunks are final. Their rows and
                // metadata must not make the remaining chunks shrink again.
                loop {
                    let previous = (shift, cap);
                    let candidates = match cap {
                        Some(cap) => crate::parts::levels::split_merge(merge.clone(), cap),
                        None => vec![merge.clone()],
                    };
                    for candidate in &candidates {
                        let choice = super::merge::initial_shape(candidate, headroom, self.cfg.merge_headroom_bytes, shift);
                        shift = shift.max(choice.shift);
                        if let Some(smaller) = choice.max_inputs {
                            cap = Some(cap.map_or(smaller, |old| old.min(smaller)));
                        }
                    }
                    // A smaller global cap changes chunk boundaries. Recheck
                    // those actual chunks before making the choice durable.
                    if (shift, cap) == previous { break; }
                }
                if let Err(error) = self.merge_attempts.plan_at_least(&id, shift, cap) {
                    self.health.merge_failures_total += 1;
                    tracing::warn!(merge = %id, error = %format!("{error:#}"), "initial merge shape not persisted; compaction deferred");
                    return Vec::new();
                }
            }
            match self.merge_attempts.max_inputs(&id) {
                Some(cap) => crate::parts::levels::split_merge(merge, cap),
                None => vec![merge],
            }
        }).collect()
    }

    /// A failed merge backs off. NAN-4796: a memory-guard stop is not a
    /// failure of its input and is never quarantined: the attempt ledger's
    /// bounded ladder (shape, split fan-in, park) is its backoff, so the
    /// smaller rerun starts on the next tick instead of after a doubling
    /// wait (FP cell-us-1: 1 -> 32 min per rung, no `h` commit in 47 min).
    /// (A stop by memory held elsewhere waits [`MEMORY_STOP_RETRY_MS`],
    /// set by `merge_attempt_ended`.) Quarantine is for errors: a
    /// poisonous input, I/O, signing.
    fn quarantine_merge(&mut self, key: (String, i32), now_ms: i64, error: &anyhow::Error) {
        if super::merge_quota::is_memory_pressure(error) {
            return;
        }
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
        // Size hour merges before their first attempt. The durable floor
        // also preserves the retry ladder after a guard stop or restart.
        let attempt = super::merge_attempts::merge_id(level.code(), hour);
        // Failure here defers only compaction; ingest keeps running. Never
        // start work whose death would leave no durable recovery record.
        let splittable = if level == Level::Day { 0 } else { merge.inputs.len() };
        let headroom = if level == Level::Hour { super::merge_quota::merge_headroom() } else { None };
        let initial_shift = super::merge::starting_shape(&merge, headroom, self.cfg.merge_headroom_bytes);
        let shift = self.merge_attempts.begin_at_least(&attempt, splittable, initial_shift)
            .context("record merge attempt before starting")?;
        tracing::info!(tenant = %tenant, level = level.code(), hour, inputs = merge.inputs.len(),
            rows = merge.inputs.iter().map(|p| p.rows).sum::<u64>(), shape_shift = shift,
            guard_headroom_bytes = ?headroom, initial_shape_shift = initial_shift,
            max_inputs = ?self.merge_attempts.max_inputs(&attempt), "compaction merge starting");
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
                    let result = super::merge::with_shape(shift, || super::restamp::with_restamp(map.clone(), || super::merge_quota::with_count_backfill(coverage_rewrite, ||
                        merge_parts(&dir, &tenant, level, hour, &inputs, schema, &fingerprint, &key_id, &build, now_ms))));
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
                    let result = super::merge::with_shape(shift, || super::restamp::with_restamp(map.clone(), || super::merge_quota::with_count_backfill(coverage_rewrite, ||
                        merge_parts(&dir, &tenant, level, hour, &inputs, schema, &fingerprint, &key_id, &build, now_ms))));
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
        let days = authority.refresh_policy().await?.retention_days;
        self.retire_expired(days, now_ms).await.map(|_| ())
    }

    /// NAN-4726: the hosted cell's retention step. The retention comes from
    /// the delete gate (`policy.retention_days` on the exchanged
    /// `lake_part_gc` route, only while the grant is open); no route, no
    /// policy, a closed or unreadable gate, or a catalog hold (no
    /// `gc_authority`) retires nothing. Retired parts are deleted later only
    /// by the sanctioned pass (owner authorize, control attest, Worker
    /// delete), once their whole day is past retention. One live-set scan
    /// per [`HOSTED_RETENTION_SCAN_INTERVAL_MS`]; at most
    /// [`RETENTION_RETIRE_BATCH`] parts, one log append, per scan.
    async fn retire_hosted_expired(&mut self, now_ms: i64) -> Result<usize> {
        let Some(authority) = self.gc_authority.clone() else { return Ok(0) };
        if self.cfg.catalog_attachment_failure.is_some()
            || !hosted_retention_scan_due(self.last_retention_scan_ms, now_ms)
        {
            return Ok(0);
        }
        self.last_retention_scan_ms = Some(now_ms);
        let days = authority.retention_days(now_ms).await?;
        self.retire_expired(days, now_ms).await
    }

    /// Retire (reason `Retention`) live parts whose WHOLE time range is older
    /// than `now - days`; a part straddling the cutoff stays until its newest
    /// row expires. `None` retires nothing. Shared by the local (sovereign)
    /// and hosted steps.
    async fn retire_expired(&mut self, days: Option<u64>, now_ms: i64) -> Result<usize> {
        let Some(days) = days.filter(|days| *days > 0) else { return Ok(0); };
        let cutoff_us = now_ms.saturating_sub((days as i64).saturating_mul(86_400_000)).saturating_mul(1_000);
        let expired: Vec<_> = self.log.live().parts()
            .filter(|part| part.max_time_us < cutoff_us)
            .take(RETENTION_RETIRE_BATCH).map(|part| part.part_id.clone()).collect();
        let retired = expired.len();
        if retired > 0 {
            self.log.append(LogOp::Retire { parts: expired,
                reason: crate::parts::part_log::RetireReason::Retention,
                deletion_unit: uuid::Uuid::new_v4().to_string(),
            }, now_ms).await?;
            tracing::info!(tenant = %self.cfg.tenant_id, retention_days = days, parts = retired,
                "lake parts past retention retired");
        }
        Ok(retired)
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
        let result = self.gc_inner(now_ms).await;
        self.health.part_gc_capacity = self.gc_authority.as_ref().and_then(|authority| authority.capacity_status());
        result
    }

    async fn gc_inner(&mut self, now_ms: i64) -> Result<()> {
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
        if let Some(reason) = self.cfg.catalog_attachment_failure {
            // NAN-4601: fail closed on deletes; the index keeps following the
            // log (it deletes nothing and every later delete needs it).
            // `gc_authority` is never consulted here: no decision, no pass.
            if let Some(feed) = self.held_index_feed.clone() {
                if let Some(Ok(report)) = feed.feed_index_only(now_ms).await {
                    // A pass that finished before the hold: history, not permission.
                    self.gc_deleted_reported = self.gc_deleted_reported.saturating_add(report.deleted);
                    self.health.part_gc_deleted_total = self.health.part_gc_deleted_total.max(self.gc_deleted_reported);
                }
            }
            self.catalog_held(reason, pending_parts, pending_bytes, now_ms);
            return Ok(());
        }
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
        if !sanctioned_pass_due_paced(self.last_sanctioned_pass_ms, self.sanctioned_gc_catching_up,
            self.last_sanctioned_pass_busy_ms, now_ms) {
            return Ok(());
        }
        self.last_sanctioned_pass_ms = Some(now_ms);
        // NAN-4728: a trusted-local pass runs inline under the ingestor; its
        // wall time paces the next catch-up pass. A background (hosted) route
        // returns at once, so its cadence is unchanged.
        let started = std::time::Instant::now();
        let result = pass.schedule_pass(now_ms).await;
        self.last_sanctioned_pass_busy_ms = i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX);
        if let Some(result) = result {
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

    /// NAN-4601: report the catalog hold as `lake_part_gc_blocked{reason="catalog_held",detail=<attach failure>}`.
    /// `blocked_seconds` counts from the first held tick (with or without
    /// pending parts), and the hold is logged at once and then every
    /// [`CATALOG_HELD_LOG_INTERVAL_MS`], not only on the first tick.
    fn catalog_held(&mut self, detail: &'static str, parts: u64, bytes: u64, now_ms: i64) {
        let since = *self.catalog_held_since_ms.get_or_insert(now_ms);
        let blocked_seconds = now_ms.saturating_sub(since).max(0) as u64 / 1000;
        if catalog_held_log_due(self.catalog_held_logged_ms, now_ms) {
            self.catalog_held_logged_ms = Some(now_ms);
            tracing::error!(reason = REASON_CATALOG_HELD, detail, pending_parts = parts, pending_bytes = bytes,
                held_seconds = blocked_seconds, index_feed = self.held_index_feed.is_some(),
                "lake-part deletes held: catalog custody not attached; keeping every part, part-log index feed continues");
        }
        self.last_gc_block_reason = Some(REASON_CATALOG_HELD);
        self.health.part_gc_blocked = Some(nanosiem_lake_cell::contract::PartGcBlocked {
            reason: REASON_CATALOG_HELD.to_string(), parts, bytes, detail: detail.to_string(), blocked_seconds });
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
        // Publication retries own immutable local output until the Add lands.
        if let Some(finished) = &self.buffer.built {
            busy.extend(finished.iter().map(|part| part.dir.clone()));
        }
        for flight in &self.flush_in_flight {
            if let Some(finished) = &flight.built {
                busy.extend(finished.iter().map(|part| part.dir.clone()));
            }
        }
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
        // NAN-4721: agent-catalog work (cold serving-epoch prepares) yields
        // to ingest, and is paced, from before the lag alert (or on cell
        // strain). Agents never compete with analysts.
        if let Some(catalog) = &self.cfg.catalog {
            catalog.ingest_pressure().set(h.stalled
                || super::agent_lane::agent_pressure(h.lag_ms, self.cfg.lag_alert_ms));
        }
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
        // NAN-4445: continue a spell an earlier process persisted. Until this
        // process's first open settles it is unknown (the supervisor reports
        // nothing), unless that open has run past PREVALENCE_SPELL_UNKNOWN_MAX_MS
        // with the inherited spell still open: rows are still unstamped.
        let started = *self.prevalence_health_started_ms.get_or_insert(now_ms);
        let unknown_expired = now_ms.saturating_sub(started) >= PREVALENCE_SPELL_UNKNOWN_MAX_MS;
        self.prevalence_first_settled |= self.prevalence.is_some() || self.prevalence_retry.is_some();
        let inherited = self.prevalence_spell.inherited_since_ms;
        if inherited.is_some() && self.prevalence.is_none() && unknown_expired {
            h.prevalence_degraded = true;
        }
        if let Some(since) = inherited {
            if h.prevalence_degraded {
                let current = self.prevalence_degraded_since_ms.unwrap_or(now_ms);
                if since < current {
                    self.prevalence_degraded_since_ms = Some(since);
                    self.prevalence_degraded_logged_ms = now_ms;
                }
            }
            if self.prevalence_first_settled {
                // Settled: continued above, or the first open succeeded and
                // the spell ends (sync writes it cleared).
                self.prevalence_spell.inherited_since_ms = None;
            }
        }
        h.prevalence_degraded_known = !self.cfg.prevalence_enabled || self.prevalence_grant_withheld || unknown_expired
            || (self.prevalence_spell.loaded && self.prevalence_first_settled);
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
        // NAN-4737: an apply deferred to the next admission (at most one
        // tick) is the pipeline, not the state falling behind.
        let owed = self.prevalence_pending && self.prevalence_deferred.is_none();
        let behind = held && (owed || self.prevalence_phase != PrevalencePhase::Stamping
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
        let mut by_hour: BTreeMap<i32, usize> = BTreeMap::new();
        let mut live = 0;
        for part in self.log.live().parts() {
            *by_level.entry(part.level.code().to_string()).or_default() += 1;
            if part.level.is_hourly() {
                *by_hour.entry(part.event_hour).or_default() += 1;
            }
            live += 1;
        }
        h.live_parts = live;
        h.max_parts_per_hour = by_hour.values().copied().max().unwrap_or(0);
        h.fragmented_hours = by_hour.values().filter(|parts| crate::parts::levels::hour_is_fragmented(**parts)).count();
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

/// NAN-4601: how often a held catalog's delete hold is logged again (the large tenant logged
/// it once at 15:28Z and then nothing for a day).
pub const CATALOG_HELD_LOG_INTERVAL_MS: i64 = 15 * 60_000;

pub(crate) fn catalog_held_log_due(last_logged_ms: Option<i64>, now_ms: i64) -> bool {
    last_logged_ms.is_none_or(|last| now_ms.saturating_sub(last) >= CATALOG_HELD_LOG_INTERVAL_MS)
}

/// NAN-3818: least time between bounded log-fold steps while a sanctioned
/// pass is still catching its view up to the log head (after every restart
/// the local view folds from genesis, [`MAX_LOG_ENTRIES_PER_PASS`] entries a
/// step). Waiting the full pass interval per step left CT 106 (7.5k entries)
/// without GC for ~40 min after each restart. Each step is still bounded and
/// runs between ingest ticks, so ingest keeps the mutex most of the time.
///
/// [`MAX_LOG_ENTRIES_PER_PASS`]: crate::lake_part_gc::executor::MAX_LOG_ENTRIES_PER_PASS
pub const SANCTIONED_GC_CATCH_UP_INTERVAL_MS: i64 = 5_000;

/// NAN-4726: most parts one retention retire appends (one log entry).
pub(crate) const RETENTION_RETIRE_BATCH: usize = 512;
/// NAN-4726: least time between hosted retention scans of the live set.
pub(crate) const HOSTED_RETENTION_SCAN_INTERVAL_MS: i64 = 60_000;

pub(crate) fn hosted_retention_scan_due(last_scan_ms: Option<i64>, now_ms: i64) -> bool {
    last_scan_ms.is_none_or(|last| now_ms - last >= HOSTED_RETENTION_SCAN_INTERVAL_MS)
}

/// Whether ingest starts a sanctioned GC pass now: the first time, after the
/// pass interval, or after the short catch-up interval while the previous
/// pass only advanced its log view.
pub(crate) fn sanctioned_pass_due(last_pass_ms: Option<i64>, catching_up: bool, now_ms: i64) -> bool {
    sanctioned_pass_due_paced(last_pass_ms, catching_up, 0, now_ms)
}

/// NAN-4728: a catch-up pass starts no sooner than this many times the last
/// pass's busy time after that pass started, so a backlog drain (each
/// trusted-local pass hashes, re-checks and fsyncs up to 512 files inline,
/// holding the ingestor) takes at most 1/N of ingest's wall time. 512 files
/// per 4 x busy still outruns the ~3 files/s a 12k eps tenant supersedes
/// while a pass stays under ~40 s.
pub const SANCTIONED_GC_CATCH_UP_PACE: i64 = 4;

/// [`sanctioned_pass_due`] with the last pass's busy time: while catching
/// up, the gap is the catch-up interval or [`SANCTIONED_GC_CATCH_UP_PACE`] x
/// busy, whichever is longer, never longer than the ordinary pass interval.
pub(crate) fn sanctioned_pass_due_paced(last_pass_ms: Option<i64>, catching_up: bool, last_busy_ms: i64, now_ms: i64) -> bool {
    let interval = if catching_up {
        SANCTIONED_GC_CATCH_UP_INTERVAL_MS
            .max(last_busy_ms.max(0).saturating_mul(SANCTIONED_GC_CATCH_UP_PACE))
            .min(SANCTIONED_GC_INTERVAL_MS)
    } else {
        SANCTIONED_GC_INTERVAL_MS
    };
    last_pass_ms.is_none_or(|last| now_ms - last >= interval)
}

#[cfg(test)]
mod nan4601_catalog_held_log_tests {
    use super::*;

    /// NAN-4601: the hold is logged at once and then on a fixed cadence, not once per process.
    #[test]
    fn the_catalog_hold_is_logged_again_every_interval() {
        assert!(catalog_held_log_due(None, 0), "the first held tick logs");
        assert!(!catalog_held_log_due(Some(0), CATALOG_HELD_LOG_INTERVAL_MS - 1));
        assert!(catalog_held_log_due(Some(0), CATALOG_HELD_LOG_INTERVAL_MS));
        assert!(catalog_held_log_due(Some(1_000), 1_000 + 24 * 3_600_000), "a day later it is still logged");
    }
}

/// A pass that stopped mid log-fold, or (NAN-4728, trusted-local) filled its
/// delete bound with progress and more eligible files listed, and asks for no
/// back-off: progressing. One bounded batch per 10-min interval reclaimed
/// ~512 files while a 12k eps tenant superseded ~2,000: the store grew forever.
pub(crate) fn pass_is_catching_up(report: &crate::lake_part_gc::PassReport) -> bool {
    !report.backoff
        && (report.more_eligible
            || report.paused_reason.as_deref() == Some(crate::lake_part_gc::executor::LOG_CATCHING_UP))
}

/// Source objects (edge segments or bronze notices) one flush may take
/// (NAN-3006). Every L0 record of a flush names all of them (and the edge
/// range lists every skipped segment), so this bounds a record: even at the
/// 1 KiB key maximum 512 sources stay well under `MAX_PROVENANCE_BYTES`, and
/// a restart backlog drains in several flushes instead of one oversized one.
pub const MAX_FLUSH_OBJECTS: usize = 512;
/// Seal wide-history buffers promptly. Admission is atomic per source group,
/// so a single admission may exceed this trigger; no subsequent tick adds to it.
pub const MAX_FLUSH_EVENT_HOURS: usize = 48;
/// NAN-4674: the event-hour cap of a buffer while ingest is behind. Every
/// hour of a flush is at least one L0 part, so with the 48-hour cap a
/// backfill whose objects each span ~166 hours sealed after ONE admission
/// group: ~8k rows over 166 hours, ~50-row parts, each paying an owner sign,
/// ~8 PUTs, an `add` line and a prevalence apply (Dan's bakeoff 2026-10-27:
/// 21,929 parts for 1.1M rows, admission at 1/7 of the firehose). Behind, the
/// buffer instead fills to its row, byte, object and catch-up age caps, so
/// each hour's part carries many groups' rows. 512 hours is the publication
/// fanout NAN-3947 proved under a slow owner. One buffer is still one `add`
/// entry and its acks follow that entry: custody is unchanged.
pub const MAX_WIDE_FLUSH_EVENT_HOURS: usize = 512;

/// NAN-4674: the event hours a buffer may span before it is due (and before
/// admission stops adding to it). Not behind, the live lane's 48-hour cap,
/// unchanged; behind, [`MAX_WIDE_FLUSH_EVENT_HOURS`].
pub fn flush_event_hour_cap(behind: bool) -> usize {
    if behind { MAX_WIDE_FLUSH_EVENT_HOURS } else { MAX_FLUSH_EVENT_HOURS }
}

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
/// NAN-4161: the snapshots are never pruned (no ingest or GC delete class
/// covers `log/`), so a read pages only the last
/// [`RESTAMP_SNAPSHOT_HORIZON_MS`] of names, a bounded number of pages per
/// tick; the cost no longer grows with the backlog.
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

/// NAN-4161: snapshots older than this are never read. The hours a snapshot
/// owes are at or before its write time, so past the prevalence state's
/// 30-day window a restamp would read their rows as never seen anyway. A
/// non-empty set is rewritten every half horizon, so the newest snapshot is
/// always inside it.
pub(crate) const RESTAMP_SNAPSHOT_HORIZON_MS: i64 = 30 * 86_400_000;
/// NAN-4161: keys per listing page and pages per call of the snapshot scan.
pub(crate) const RESTAMP_SCAN_PAGE_KEYS: usize = 256;
pub(crate) const RESTAMP_SCAN_PAGES_PER_CALL: usize = 4;
/// Newest snapshot names kept as candidates while the scan pages forward.
const RESTAMP_SCAN_TAIL: usize = 32;

/// NAN-4161: the continuation of a bounded scan for the newest restamp
/// snapshot. The snapshots are never deleted (ingest holds no delete
/// authority under `log/checkpoints/`), so the scan starts at the horizon
/// and pages forward a bounded number of pages per call.
#[derive(Debug, Default)]
pub(crate) struct RestampScan {
    after: Option<String>,
    tail: VecDeque<String>,
}

/// One bounded step of the scan. `Ok(None)`: more pages remain (call again).
/// `Ok(Some(newest))`: done; the newest valid snapshot (name time, hours),
/// if any. An unreadable or foreign record is skipped; a listing or read
/// error is returned and the scan resumes where it stopped.
async fn scan_restamp_owed(store: &dyn ObjectStore, tenant_id: &str, scan: &mut RestampScan, now_ms: i64)
    -> Result<Option<Option<(i64, Vec<i32>)>>> {
    let prefix = restamp_owed_prefix(tenant_id)?;
    if scan.after.is_none() {
        // Every name with an earlier time sorts before this bare time.
        scan.after = Some(format!("{prefix}{:013}", now_ms.saturating_sub(RESTAMP_SNAPSHOT_HORIZON_MS).max(0)));
    }
    let mut done = false;
    for _ in 0..RESTAMP_SCAN_PAGES_PER_CALL {
        let page = store.list_page(&prefix, scan.after.as_deref(), RESTAMP_SCAN_PAGE_KEYS).await?;
        for key in &page {
            ensure!(key.starts_with(&prefix), "restamp snapshot listing escaped its prefix");
            scan.tail.push_back(key.clone());
            if scan.tail.len() > RESTAMP_SCAN_TAIL { scan.tail.pop_front(); }
        }
        if let Some(last) = page.last() { scan.after = Some(last.clone()); }
        if page.len() < RESTAMP_SCAN_PAGE_KEYS {
            done = true;
            break;
        }
    }
    if !done {
        return Ok(None);
    }
    let tail = std::mem::take(&mut scan.tail);
    *scan = RestampScan::default();
    for key in tail.iter().rev() {
        let Some(bytes) = store.get(key).await? else { continue };
        match super::restamp::OwedHours::parse(&bytes) {
            Ok(hours) if count_backfill_record_matches(&prefix, key, &bytes) => {
                let written_ms = key[prefix.len()..prefix.len() + 13].parse::<i64>()?;
                return Ok(Some(Some((written_ms, hours))));
            }
            _ => tracing::warn!(tenant = %tenant_id, %key, "skipping unreadable prevalence restamp snapshot"),
        }
    }
    Ok(Some(None))
}

/// The whole scan in one go (tests).
#[cfg(test)]
async fn load_restamp_owed(store: &dyn ObjectStore, tenant_id: &str, now_ms: i64) -> Result<Option<(i64, Vec<i32>)>> {
    let mut scan = RestampScan::default();
    loop {
        if let Some(found) = scan_restamp_owed(store, tenant_id, &mut scan, now_ms).await? {
            return Ok(found);
        }
    }
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

/// NAN-4338: the landing-ledger report for a kept object, when it is an
/// edge segment of this tenant (landing[T] produces only those; a replay's
/// own source key or a listed bronze object is never one).
fn ledger_report(tenant_id: &str, key: &str, rows: u64, state: super::quarantine_ledger::ReportState)
    -> Option<super::quarantine_ledger::QuarantineReport> {
    crate::parts::provenance::is_edge_segment_key(tenant_id, key)
        .then(|| super::quarantine_ledger::QuarantineReport { segment_key: key.to_string(), rows, state })
}

#[cfg(test)]
#[path = "quarantine_ingest_tests.rs"]
mod quarantine_ingest_tests;

#[cfg(test)]
#[path = "nan4338_ingest_tests.rs"]
mod nan4338_ingest_tests;

#[cfg(test)]
#[path = "nan4319_ingest_tests.rs"]
mod nan4319_ingest_tests;

#[cfg(test)]
#[path = "nan4336_ingest_tests.rs"]
pub(super) mod nan4336_ingest_tests;

#[cfg(test)]
#[path = "nan4553_ingest_tests.rs"]
mod nan4553_ingest_tests;
#[cfg(test)]
#[path = "nan4731_ingest_tests.rs"]
mod nan4731_ingest_tests;

#[cfg(test)]
#[path = "nan4737_ingest_tests.rs"]
mod nan4737_ingest_tests;
#[cfg(test)]
#[path = "nan4749_ingest_tests.rs"]
mod nan4749_ingest_tests;

#[cfg(test)]
#[path = "nan4806_ingest_tests.rs"]
mod nan4806_ingest_tests;

#[cfg(test)]
#[path = "nan4770_ingest_tests.rs"]
mod nan4770_ingest_tests;

#[cfg(test)]
#[path = "nan4750_ingest_tests.rs"]
mod nan4750_ingest_tests;
#[cfg(test)]
#[path = "nan4765_ingest_tests.rs"]
mod nan4765_ingest_tests;

/// NAN-4750: the pure L0 family planning (part bound, split exactness).
#[cfg(test)]
mod l0_class_family_tests {
    use super::*;
    use arrow_array::{Array, ArrayRef, Int64Array, StringArray, StructArray};
    use arrow_schema::{DataType, Field, Fields, Schema};

    /// An hour's parts with a class split never exceed
    /// `max(l0_chunks(total).len(), groups)`, never exceed
    /// MAX_PARALLEL_L0_WRITES with the draft cap, and keep the old cut
    /// when there is nothing to split.
    #[test]
    fn group_parts_stay_within_the_hour_bound() {
        let s = L0_PARALLEL_MIN_ROWS;
        assert_eq!(l0_group_parts(&[20_000]), vec![1], "no split: unchanged");
        assert_eq!(l0_group_parts(&[5 * s]), vec![l0_chunks(5 * s).len()]);
        // 20k rows: one part before, three groups now (+2 parts).
        assert_eq!(l0_group_parts(&[9_000, 9_000, 2_000]), vec![1, 1, 1]);
        // A 64k+ hour already wrote four parts: the split re-cuts them.
        let parts = l0_group_parts(&[3 * s, s / 2, 2 * s]);
        assert_eq!(parts.iter().sum::<usize>(), MAX_PARALLEL_L0_WRITES);
        assert!(parts.iter().all(|p| *p >= 1));
        for rows in [vec![8_192, 8_192, 8_192, 1], vec![4 * s, 4 * s, 4 * s, 4 * s], vec![s, 9 * s, 8_192, 8_192], vec![1, 8_192]] {
            let parts = l0_group_parts(&rows);
            let total = rows.iter().sum::<usize>();
            let bound = l0_chunks(total).len().max(rows.len());
            assert!(parts.iter().sum::<usize>() <= bound, "{rows:?} -> {parts:?}");
            assert!(parts.iter().sum::<usize>() <= MAX_PARALLEL_L0_WRITES, "{rows:?} -> {parts:?}");
            assert!(parts.iter().all(|p| *p >= 1));
        }
        assert_eq!(l0_chunks_into(10, 4), vec![(0, 3), (3, 3), (6, 3), (9, 1)]);
        assert_eq!(l0_chunks_into(9, 4).iter().map(|(_, len)| len).sum::<usize>(), 9);
        assert!(l0_chunks_into(0, 2).is_empty());
    }

    fn batch(rows: &[(Option<&str>, Option<i64>)]) -> RecordBatch {
        let sources: ArrayRef = Arc::new(StringArray::from(rows.iter().map(|(s, _)| *s).collect::<Vec<_>>()));
        let metadata = StructArray::new(Fields::from(vec![Field::new("log_source", DataType::Utf8, true)]), vec![sources], None);
        let schema = Arc::new(Schema::new(vec![
            Field::new("seq", DataType::Int64, false),
            Field::new("class_uid", DataType::Int64, true),
            Field::new("metadata", metadata.data_type().clone(), true),
        ]));
        RecordBatch::try_new(schema, vec![
            Arc::new(Int64Array::from((0..rows.len() as i64).collect::<Vec<_>>())),
            Arc::new(Int64Array::from(rows.iter().map(|(_, c)| *c).collect::<Vec<_>>())),
            Arc::new(metadata),
        ]).unwrap()
    }

    /// Every row lands in exactly one group, in its sorted order; nulls and
    /// non-chosen families go to the rest.
    #[test]
    fn split_is_exact_and_keeps_order() {
        let rows = [(Some("a"), Some(1)), (Some("b"), Some(1)), (None, Some(1)), (Some("a"), None), (Some("a"), Some(1)), (Some("a"), Some(2))];
        let batch = batch(&rows);
        let groups = split_l0_families(&batch, &[("a".to_string(), 1), ("c".to_string(), 9)]).unwrap();
        let seqs = |b: &RecordBatch| b.column(0).as_any().downcast_ref::<Int64Array>().unwrap().values().to_vec();
        assert_eq!(groups.len(), 2, "an empty family group is dropped");
        assert_eq!(groups[0].0, Some(("a".to_string(), 1)));
        assert_eq!(seqs(&groups[0].1), vec![0, 4]);
        assert_eq!(groups[1].0, None);
        assert_eq!(seqs(&groups[1].1), vec![1, 2, 3, 5]);
        let none = split_l0_families(&batch, &[]).unwrap();
        assert_eq!((none.len(), none[0].1.num_rows()), (1, rows.len()));
    }

    /// The families chosen: at least CLASS_FAMILY_MIN_ROWS buffered rows
    /// over every batch of the hour, largest first, at most
    /// MAX_L0_CLASS_DRAFTS; batches without the columns are skipped.
    #[test]
    fn families_counted_over_the_hour_and_capped() {
        let min = super::super::merge::CLASS_FAMILY_MIN_ROWS as usize;
        let rows = |source: &'static str, class: i64, n: usize| vec![(Some(source), Some(class)); n];
        let half = |source, class| batch(&rows(source, class, min / 2));
        // Split over two batches, a family still reaches the floor.
        let mut batches = vec![half("a", 1), half("a", 1), batch(&rows("b", 2, min - 1))];
        assert_eq!(l0_class_families(&batches).unwrap(), vec![("a".to_string(), 1)]);
        batches.push(RecordBatch::try_new(Arc::new(Schema::new(vec![Field::new("seq", DataType::Int64, false)])),
            vec![Arc::new(Int64Array::from(vec![1]))]).unwrap());
        assert_eq!(l0_class_families(&batches).unwrap(), vec![("a".to_string(), 1)], "a batch without the columns counts nothing");
        let many = (0..5).map(|class| batch(&rows("s", class, min + class as usize))).collect::<Vec<_>>();
        assert_eq!(l0_class_families(&many).unwrap(), vec![("s".to_string(), 4), ("s".to_string(), 3), ("s".to_string(), 2)]);
        assert_eq!(MAX_L0_CLASS_DRAFTS + 1, MAX_PARALLEL_L0_WRITES);
    }
}

#[cfg(test)]
#[path = "nan4755_ingest_tests.rs"]
mod nan4755_ingest_tests;

#[cfg(test)]
#[path = "nan4796_ingest_tests.rs"]
mod nan4796_ingest_tests;

#[cfg(test)]
#[path = "nan4818_fanin_tests.rs"]
mod nan4818_fanin_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_committed_partial_restamp_preserves_its_incomplete_outcome() {
        let map = super::super::restamp::RestampMap::with_completion(Default::default(), false);
        let outcome = super::super::restamp::RestampOutcome::default();
        restamp_applied(Some(&map), Some(&outcome), true);
        assert_eq!(outcome.get(), Some(super::super::restamp::RestampResult::Applied { rows: 0, complete: false }));
    }

    /// Seven hours at one log entry / 20 s. Exercise the real planner,
    /// durable scan cursor, timeout and restart, while the writer continues
    /// appending. Delays are scaled 100 ms -> 2 ms to keep the test short.
    /// The old 1,025-GET collect cannot finish inside the scaled ingest wait.
    #[tokio::test]
    async fn seven_hour_log_backlog_checkpoints_under_cost_with_live_appends() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct SlowLog {
            store: LocalObjectStore,
            slow: AtomicBool,
            hold_genesis: AtomicBool,
        }
        #[async_trait::async_trait]
        impl ObjectStore for SlowLog {
            async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
                if self.hold_genesis.load(Ordering::Relaxed) && key.ends_with("/entries/00000000000000000000.json") {
                    std::future::pending::<()>().await;
                }
                if self.slow.load(Ordering::Relaxed) && key.contains("/entries/") {
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                self.store.get(key).await
            }
            async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> {
                self.store.put_if_absent(key, bytes).await
            }
            async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.store.put(key, bytes).await }
            async fn delete(&self, key: &str) -> Result<()> { self.store.delete(key).await }
            async fn list(&self, prefix: &str) -> Result<Vec<String>> { self.store.list(prefix).await }
        }
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c2";
        let store = SlowLog { store: LocalObjectStore::new(root.path().join("store")).unwrap(), slow: AtomicBool::new(false), hold_genesis: AtomicBool::new(false) };
        let signer = LocalPartSigner::new("scan-test", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut cfg = IngestConfig::new(tenant, root.path().join("work"));
        cfg.prevalence_enabled = false;
        let now = 1_800_000_000_000;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        let memory = Arc::new(slatedb::object_store::memory::InMemory::new());
        let mut state = IngestPrevalence::open_shared(tenant, memory.clone()).await.unwrap();
        let (seq, sha, _) = ingestor.log.live().head().unwrap();
        state.initialize_at(seq, sha).await.unwrap();
        ingestor.prevalence = Some(state);
        let op = LogOp::Schema { schema: LogSchema::from_arrow(&seed_schema()).unwrap() };
        for n in 1..=7 * 3_600 / 20 {
            ingestor.log.append(op.clone(), now + n * 20_000).await.unwrap();
        }
        store.slow.store(true, Ordering::Relaxed);
        assert_eq!(seq, 0);
        store.hold_genesis.store(true, Ordering::Relaxed);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100),
            ingestor.replay_prevalence_batch(None)).await.is_err());
        assert_eq!(ingestor.prevalence_log_cache.len(), PREVALENCE_CATCH_UP_SCAN as usize,
            "completed GETs survive cancellation even when the first request hangs");
        store.hold_genesis.store(false, Ordering::Relaxed);
        ingestor.cfg.prevalence_op_timeout = std::time::Duration::from_millis(50);
        ingestor.prevalence_overran(now, "test baseline");
        let mut previous = seq;
        let mut foreground = 0;
        for tick in 1..=100 {
            // The producer keeps publishing during catch-up.
            ingestor.log.append(op.clone(), now + (7 * 3_600 + tick * 20) * 1_000).await.unwrap();
            let outcome = tokio::time::timeout(std::time::Duration::from_millis(100),
                ingestor.replay_prevalence_batch(None)).await.expect("bounded scan must yield to foreground").unwrap();
            let cursor = ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap();
            assert!(cursor.seq > previous, "every tick must durably advance");
            previous = cursor.seq;
            // Model a catch-up lasting beyond the watchdog interval overall.
            // Each durable scan must reset it even when cache cardinality is flat.
            ingestor.prevalence_blocked_since = Some(std::time::Instant::now()
                - ingestor.cfg.prevalence_op_timeout);
            ingestor.prevalence_overran(now, "slow durable catch-up");
            assert_eq!(ingestor.health.prevalence_stalls_total, 0,
                "durable checkpoints keep slow catch-up alive");
            foreground += 1;
            if tick == 10 {
                // Reopen the actual DB, discarding the runtime log cache.
                ingestor.prevalence.take().unwrap().close().await.unwrap();
                ingestor.prevalence_log_cache.clear();
                ingestor.prevalence = Some(IngestPrevalence::open_shared(tenant, memory.clone()).await.unwrap());
                ingestor.reset_prevalence_runtime();
                ingestor.prevalence_overran(now, "reopened baseline");
                assert_eq!(ingestor.prevalence.as_ref().unwrap().applied().await.unwrap().unwrap().seq, previous);
            }
            if matches!(outcome, CatchUpBatch::AtHead) { break; }
        }
        assert!(foreground < 100, "seven-hour backlog must drain with ongoing appends");
        assert_eq!(previous, ingestor.log.live().head().unwrap().0);
        assert!(foreground > 10, "restart occurred during catch-up");
        // Existing merge scheduling remains bounded even if prevalence is slow.
        assert!(l0_merges_run_beside_prevalence(PREVALENCE_L0_YIELD_MS));
        ingestor.prevalence.take().unwrap().close().await.unwrap();
    }

    /// NAN-4464 (a large hosted tenant, 2026-10-23 20:37Z): with #7678 live the
    /// catch-up scale never left 1. The large tenant's ingest lag sat at 72-98 s while
    /// ingest kept up, and the 30 s backfill backoff read that as pressure on
    /// every batch. Through the production constructor and rescale path:
    /// The large tenant's live lag lets the scale rise to the backlog's, and only lag past
    /// the ingest stall bound halves it.
    #[tokio::test]
    async fn b12_live_ingest_lag_lets_the_catch_up_scale_rise() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        use super::super::prevalence::{catch_up_max_rows_for, CATCH_UP_BATCH_ENTRIES, CATCH_UP_MAX_SCALE};
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c4";
        let store = LocalObjectStore::new(root.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("scale-test", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut cfg = IngestConfig::new(tenant, root.path().join("work"));
        cfg.prevalence_enabled = false;
        cfg.prevalence_catch_up_max_rows = catch_up_max_rows_for(4_831_838_208);
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), 1_800_000_000_000).await.unwrap();
        assert_eq!(ingestor.cfg.lag_alert_ms, 120_000);
        assert_eq!(ingestor.prevalence_catch_up_scale(), 1);
        // the large tenant's "count backfill pace adjusted" lag samples, then two in between.
        let mut scales = Vec::new();
        for (lag_ms, behind) in [(71_910, 8_423), (98_018, 8_397), (85_000, 8_371), (76_000, 8_345), (98_018, 8_190)] {
            ingestor.health.lag_ms = lag_ms;
            ingestor.rescale_prevalence_catch_up(behind, CATCH_UP_BATCH_ENTRIES);
            scales.push(ingestor.prevalence_catch_up_scale());
        }
        assert_eq!(scales, [2, 2, 4, 8, 8], "the large tenant's lag grows the scale (holds near the bound), never pins it at 1");
        assert_eq!(scales.last().copied(), Some(CATCH_UP_MAX_SCALE));
        ingestor.health.lag_ms = 120_001;
        ingestor.rescale_prevalence_catch_up(8_000, CATCH_UP_BATCH_ENTRIES);
        assert_eq!(ingestor.prevalence_catch_up_scale(), 4, "lag past the ingest stall bound halves it");
    }

    /// Foreground cache churn is not evidence of a responding state store.
    #[tokio::test]
    async fn cache_growth_without_durable_progress_trips_prevalence_watchdog() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c3";
        let store = LocalObjectStore::new(root.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("watchdog-test", ed25519_dalek::SigningKey::from_bytes(&[7; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut cfg = IngestConfig::new(tenant, root.path().join("work"));
        cfg.prevalence_enabled = false;
        cfg.prevalence_op_timeout = std::time::Duration::from_millis(10);
        let now = 1_800_000_000_000;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        ingestor.prevalence = Some(IngestPrevalence::open_shared(tenant,
            Arc::new(slatedb::object_store::memory::InMemory::new())).await.unwrap());
        ingestor.prevalence_overran(now, "stalled WAL baseline");
        let keys = LogKeys::new(tenant).unwrap();
        let bytes = store.get(&keys.entry(0)).await.unwrap().unwrap();
        let entry = Arc::new(LogEntry::parse_bytes(&bytes, tenant).unwrap());
        // Model foreground log/partial publication while WAL durability hangs.
        for seq in 0..8 {
            ingestor.prevalence_log_cache.insert(seq, (sha256_hex(&bytes), entry.clone()));
            ingestor.prevalence_prefetched.insert(format!("foreground-{seq}"), root.path().join(format!("partial-{seq}")));
        }
        ingestor.prevalence_blocked_since = Some(std::time::Instant::now()
            - ingestor.cfg.prevalence_op_timeout);
        ingestor.prevalence_overran(now, "WAL still stalled despite cache growth");
        assert_eq!(ingestor.health.prevalence_stalls_total, 1);
        assert!(ingestor.health.prevalence_degraded);
    }

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

    /// NAN-4728 stand-in for the trusted-local pass: runs inline (foreground
    /// `schedule_pass`), holds the ingestor `busy`, fills its batch with
    /// progress (`more_eligible`) every time.
    struct BusyBacklogPass {
        busy: std::time::Duration,
        passes: std::sync::atomic::AtomicU64,
    }

    #[async_trait::async_trait]
    impl crate::part_ingest::part_gc_gate::SanctionedPartGc for BusyBacklogPass {
        async fn run_pass(&self, _now_ms: i64) -> Result<crate::lake_part_gc::PassReport> {
            self.passes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(self.busy).await;
            Ok(crate::lake_part_gc::PassReport { deleted: 512, more_eligible: true, ..Default::default() })
        }
    }

    struct SanctionedGate(Arc<BusyBacklogPass>);

    #[async_trait::async_trait]
    impl PartGcAuthority for SanctionedGate {
        async fn decision(&self, _now_ms: i64) -> Result<PartGcDecision> {
            Ok(PartGcDecision::Sanctioned(self.0.clone()))
        }
    }

    /// NAN-4728: through `Ingestor::gc` (the production scheduler), a backlog
    /// drain continues on the catch-up cadence but paced by the pass's busy
    /// time: a pass that held the ingestor 1.5 s is not re-run 5 s later
    /// (GC would take ~1/4 of ingest's wall time at most), and it is re-run
    /// well before the 10-min interval.
    #[tokio::test]
    async fn a_backlog_drain_is_paced_by_the_pass_busy_time() {
        use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
        use std::sync::atomic::Ordering;
        let now = 1_800_000_000_000;
        let root = tempfile::tempdir().unwrap();
        let tenant = "00000000-0000-4000-8000-0000000000c2";
        let store = LocalObjectStore::new(root.path().join("store")).unwrap();
        let signer = LocalPartSigner::new("gc-pace-test", ed25519_dalek::SigningKey::from_bytes(&[9; 32])).unwrap();
        let queue = super::super::discovery::SpoolQueue::new(root.path().join("spool"), tenant).unwrap();
        let mut cfg = IngestConfig::new(tenant, root.path().join("ingest"));
        cfg.prevalence_enabled = false;
        let mut ingestor = Ingestor::open(cfg, &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now).await.unwrap();
        let pass = Arc::new(BusyBacklogPass { busy: std::time::Duration::from_millis(1_500), passes: Default::default() });
        ingestor.set_part_gc_authority(Arc::new(SanctionedGate(pass.clone())));
        ingestor.gc(now).await.unwrap();
        assert_eq!(pass.passes.load(Ordering::SeqCst), 1);
        assert!(ingestor.sanctioned_gc_catching_up, "a full batch with progress continues soon");
        assert!(ingestor.last_sanctioned_pass_busy_ms >= 1_500, "{}", ingestor.last_sanctioned_pass_busy_ms);
        ingestor.gc(now + SANCTIONED_GC_CATCH_UP_INTERVAL_MS).await.unwrap();
        assert_eq!(pass.passes.load(Ordering::SeqCst), 1, "a 1.5 s pass waits 4 x 1.5 s, not 5 s");
        let paced = ingestor.last_sanctioned_pass_busy_ms * SANCTIONED_GC_CATCH_UP_PACE;
        assert!(paced < 60_000, "{paced}");
        ingestor.gc(now + paced).await.unwrap();
        assert_eq!(pass.passes.load(Ordering::SeqCst), 2, "the drain continues long before the 10-min interval");
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
            anyhow::Error::new(AdoptionRefused),
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

    /// NAN-4539 step 3a: a flight is charged its full build reservation
    /// until its background task publishes, then only the rows it retains;
    /// the writers a plan reserves never exceed the L0 parts it writes.
    #[tokio::test]
    async fn a_published_flight_holds_only_its_retained_rows() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use super::super::memory::flight_bytes;
        const TENANT: &str = "00000000-0000-4000-8000-0000000000f6";
        const MIB: u64 = 1024 * 1024;
        let dir = tempfile::tempdir().unwrap();
        let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
        let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-signer-settle", ed25519_dalek::SigningKey::from_bytes(&[8; 32])).unwrap()));
        let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
        let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
        cfg.prevalence_enabled = false;
        cfg.buffer_budget_bytes = 4096 * MIB;
        let mut ingestor = Ingestor::open(cfg, store, store, &queue, signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), 1_800_000_000_000).await.unwrap();
        let rows = 100 * MIB;
        let flight = |published: bool, ingestor: &Ingestor<'_>| {
            let mut buffer = Buffered::new();
            buffer.bytes = rows;
            InFlightFlush {
                buffer, reserved_bytes: flight_bytes(rows, 4), schema: ingestor.schema.clone(), sealed_ms: 0,
                progress: ingestor.diagnostics.new_flush(0, 0), task: None, built: None, published: None,
                published_ok: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(published)),
            }
        };
        let (oldest, younger) = (flight(true, &ingestor), flight(false, &ingestor));
        ingestor.flush_in_flight.push_back(oldest);
        ingestor.flush_in_flight.push_back(younger);
        assert_eq!(ingestor.committed_bytes(), 2 * flight_bytes(rows, 4));
        ingestor.settle_published_flights();
        assert_eq!(ingestor.committed_bytes(), rows + flight_bytes(rows, 4),
            "the published flight keeps only its rows; the building one keeps its full reservation");
        // Settling is idempotent and never raises a reservation.
        ingestor.settle_published_flights();
        assert_eq!(ingestor.committed_bytes(), rows + flight_bytes(rows, 4));
        // An empty buffer plans no parts and reserves one writer at most.
        ingestor.flush_in_flight.clear();
        assert_eq!(planned_l0_parts(&ingestor.buffer), 0);
        assert_eq!(l0_chunks(L0_PARALLEL_MIN_ROWS - 1).len(), 1, "a sub-16k-row hour is one part, one writer");
        assert_eq!(l0_chunks(4 * L0_PARALLEL_MIN_ROWS).len(), MAX_PARALLEL_L0_WRITES);
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
            buffer: Buffered::new(), reserved_bytes: reserved, schema: ingestor.schema.clone(), sealed_ms: 0,
            progress: ingestor.diagnostics.new_flush(0, 0), task: None, built: None, published: None, published_ok: Default::default(),
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
            // Budget after its buffer, merge and admission room fits this flight.
            ((flight_bytes(rows, w) + merge + super::super::memory::FLIGHT_ADMISSION_BYTES) as f64 / (1.0 - super::super::memory::BUFFER_SHARE_OF_WORKING)).ceil() as u64 + 1
        };
        assert_eq!(writers_at(&mut ingestor, fits(4)), 4);
        assert_eq!(writers_at(&mut ingestor, fits(2)), 2);
        assert_eq!(writers_at(&mut ingestor, fits(1)), 1);
        assert_eq!(writers_at(&mut ingestor, 64 * MIB), 1, "a flush always makes progress");
        for flight in ingestor.merge_in_flight.drain(..) {
            flight.handle.abort();
        }
    }

    /// NAN-4749 (1.0.11 bakeoff wall #1): a 16 GiB / 8 CPU open-core cell
    /// placed from the host gave ingest a 4 GiB cap, so a full catch-up flush
    /// (65,536 rows, ~206 MiB of Arrow) beside two minute merges ran ONE L0
    /// writer. `trusted-local init --target-eps 10000` must place a cap at
    /// which all four run. Production path: the placement `init` renders, the
    /// supervisor's ingest cap for it, `size_for_memory_cap` (as `cell.rs`
    /// sizes a spawned ingest) and `Ingestor::open`.
    #[tokio::test]
    async fn a_target_eps_placement_runs_four_l0_writers() {
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        use nanosiem_lake_cell::budget::GIB;
        use nanosiem_lake_cell::trusted_local::{init, InitArgs};
        const MIB: u64 = 1024 * 1024;
        const TENANT: &str = "00000000-0000-4000-8000-0000000004f9";
        // `hosted` re-places the tenant as a hosted cell does (eps, ingest
        // role limit from the hosted placement).
        let placed_cap = |target_eps: Option<u32>, hosted: Option<(f64, u64)>| {
            let dir = tempfile::tempdir().unwrap();
            let out = dir.path().join("out");
            let args = InitArgs { out: out.clone(), chdb_sha256: Some("a".repeat(64)), memory_bytes: Some(16 * GIB),
                cpus: Some(8), target_eps, ..Default::default() };
            init(&args, &|name| name.starts_with("NANO_LAKE_").then(|| "k".to_string())).unwrap();
            let mut placement: nanosiem_lake_cell::config::Placement =
                serde_json::from_slice(&std::fs::read(out.join("cell/placement.json")).unwrap()).unwrap();
            if let Some((eps, ingest_limit)) = hosted {
                placement.tenants[0].eps = eps;
                placement.tenants[0].ingest_limit_memory_bytes = Some(ingest_limit);
            }
            nanosiem_lake_cell::supervisor::ingest_memory_cap_bytes(&placement.tenants[0])
        };
        // A full catch-up flush of wide OCSF rows (memory.rs: 3.15 KB/row);
        // a flush at `eps` holds its catch-up age of rows, up to the row cap.
        let full = 206 * MIB;
        let flush_rows = |eps: u32| ((eps as u64 * nanosiem_lake_cell::budget::CATCH_UP_FLUSH_AGE_SECS) as usize).min(FLUSH_MAX_ROWS);
        let flush_bytes = |rows: usize| full * rows as u64 / FLUSH_MAX_ROWS as u64;
        let writers_at = |cap: u64, bytes: u64| async move {
            let dir = tempfile::tempdir().unwrap();
            let store: &'static LocalObjectStore = Box::leak(Box::new(LocalObjectStore::new(dir.path().join("store")).unwrap()));
            let signer: &'static LocalPartSigner = Box::leak(Box::new(LocalPartSigner::new("lab-signer-4749", ed25519_dalek::SigningKey::from_bytes(&[49; 32])).unwrap()));
            let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT).unwrap();
            let mut cfg = IngestConfig::new(TENANT, dir.path().join("ingest"));
            cfg.prevalence_enabled = false;
            size_for_memory_cap(&mut cfg, cap);
            let mut ingestor = Ingestor::open(cfg, store, store, &queue, signer, signer.trusted(),
                BronzeIngestEnricher::disabled(), &seed_schema(), 1_800_000_000_000).await.unwrap();
            // Two minute merges at the largest decode window (32,768 rows at
            // MERGE_ROW_BYTES each; `cap` would set a window no larger). They
            // are charged here as reserved working-budget bytes, exactly as
            // `flush_writers` charges merges, so the process-wide window other
            // tests set cannot change the answer.
            let merges = 2 * 32_768 * super::super::merge::MERGE_ROW_BYTES;
            // Charge the two merge windows as merge room. Fabricating a
            // flush flight here would also reserve a third future merge.
            ingestor.cfg.merge_headroom_bytes = merges;
            assert!(super::super::memory::buffer_cap(ingestor.cfg.buffer_budget_bytes) >= bytes || cap < 5 * GIB,
                "a full-flush placement buffers the flush before its byte cap");
            ingestor.flush_writers(bytes)
        };
        // The shared sizing's rates are this worker's row, part and age caps.
        assert_eq!(nanosiem_lake_cell::budget::CATCH_UP_FLUSH_AGE_SECS * 1000, CATCH_UP_FLUSH_MAX_AGE_MS as u64);
        assert_eq!(nanosiem_lake_cell::budget::FULL_FLUSH_EPS, FLUSH_MAX_ROWS as u64 / (CATCH_UP_FLUSH_MAX_AGE_MS as u64 / 1000));
        assert_eq!(nanosiem_lake_cell::budget::L0_PART_MIN_ROWS, L0_PARALLEL_MIN_ROWS as u64);
        let two_parts = nanosiem_lake_cell::budget::PARALLEL_FLUSH_EPS as u32;
        assert_eq!((l0_chunks(flush_rows(two_parts - 1)).len(), l0_chunks(flush_rows(two_parts)).len()), (1, 2));
        // Host sizing (the 1.0.11 bakeoff): one L0 writer for a full flush.
        let host = placed_cap(None, None);
        assert_eq!((host, writers_at(host, full).await), (6 * GIB, 4), "default sizing leaves parallel-flush and merge headroom");
        // The shared derivation, placed by trusted-local init: every rate
        // from two parts up has a writer per L0 part, and a catch-up flush four.
        for eps in [two_parts, 1_638, 2_000, 2_184, 10_000] {
            let cap = placed_cap(Some(eps), None);
            assert_eq!(cap, nanosiem_lake_cell::budget::INGEST_MEMORY_FOR_FULL_FLUSH, "{eps} eps");
            let parts = l0_chunks(flush_rows(eps)).len();
            // `flush_writers` is the memory bound; the flush uses min(it, parts).
            assert!(writers_at(cap, flush_bytes(flush_rows(eps))).await >= parts, "{eps} eps: a writer per L0 part");
            assert_eq!(writers_at(cap, full).await, MAX_PARALLEL_L0_WRITES, "{eps} eps: a catch-up flush, four writers");
        }
        // Hosted: a hosted 2,000-eps tenant whose ingest role limit is 4.5 GiB:
        // the role limit binds the cap and its 3-part flushes run one writer;
        // with the role limit at the shared need (NAN-4749) all three.
        let steady = flush_bytes(flush_rows(2_000));
        assert_eq!(l0_chunks(flush_rows(2_000)).len(), 3);
        let live = placed_cap(None, Some((2_000.0, 4_831_838_208)));
        assert_eq!((live, writers_at(live, steady).await), (4_831_838_208, 1));
        let need = nanosiem_lake_cell::budget::ingest_memory_for_eps(2_000.0);
        let shared = placed_cap(None, Some((2_000.0, need)));
        assert_eq!(shared, need);
        assert!(writers_at(shared, steady).await >= 3);
    }

    /// A budget whose room after the next buffer and one merge fits exactly a
    /// 4-writer build of `rows` (and nothing beside it).
    fn fits_beside_nothing(rows: u64) -> u64 {
        let merge = super::super::merge::merge_reserve_bytes();
        ((super::super::memory::flight_bytes(rows, 4) + merge + super::super::memory::FLIGHT_ADMISSION_BYTES) as f64
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
        // The first lane must fit too: it cannot borrow admission's budget
        // merely because no other merge has started yet.
        ingestor.cfg.buffer_budget_bytes = reserve / 2;
        ingestor.run_background_merge(planned(), now, 3_600_000).await;
        assert!(ingestor.merge_in_flight.is_empty());
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
        assert_eq!(load_restamp_owed(&store, TENANT, t0 + 62_000).await.unwrap().unwrap().1, vec![hours[1]]);
        // NAN-4161: a set changed and changed back is not written again.
        assert!(ingestor.prevalence_owed.mark([hours[0]]));
        assert!(ingestor.prevalence_owed.remove(hours[0]));
        assert!(ingestor.prevalence_owed.dirty());
        ingestor.tick(t0 + 63_000).await.unwrap();
        assert!(!ingestor.prevalence_owed.dirty());
        assert_eq!(store.list(&prefix).await.unwrap().len(), 2, "an identical set is never rewritten");
        // An unchanged, non-empty set is refreshed every half horizon so the
        // bounded scan always finds it.
        let refresh = t0 + 62_000 + RESTAMP_SNAPSHOT_HORIZON_MS / 2;
        ingestor.sync_restamp_owed(refresh).await;
        assert_eq!(store.list(&prefix).await.unwrap().len(), 3);
        assert_eq!(load_restamp_owed(&store, TENANT, refresh + RESTAMP_SNAPSHOT_HORIZON_MS - 1).await.unwrap().unwrap().1,
            vec![hours[1]], "the refreshed snapshot is inside the horizon");
        // A foreign or tampered record under the prefix is never the set.
        store.put_if_absent(&format!("{prefix}9999999999999-0000000000000000.json"), b"[1]").await.unwrap();
        assert_eq!(load_restamp_owed(&store, TENANT, t0 + 62_000).await.unwrap().unwrap().1, vec![hours[1]]);
        // Only a withheld grant stops owing (a reopen or failed open never does).
        ingestor.suspend_prevalence().await;
        assert!(!ingestor.restamp_eligible(), "no grant: nothing owed");
    }

    /// NAN-4445 (the large tenant, 41 h): a degraded spell survives a roll. The first
    /// process persists the spell's start in the tenant bucket; the next
    /// pod (new volume, new epoch) continues it, so the `prevalence_degraded`
    /// value is the spell's real age, not the time since the roll. The spell
    /// ends (and is recorded cleared) when the state opens.
    #[tokio::test]
    async fn prevalence_degraded_spell_survives_a_roll_and_clears_on_open() {
        use super::super::discovery::SpoolQueue;
        use super::super::prevalence_spell::{scan_spell, spell_prefix, SpellScan};
        use crate::parts::part_log::LocalObjectStore;
        use crate::parts::provenance::LocalPartSigner;
        const TENANT: &str = "00000000-0000-4000-8000-000000004445";

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
        let config = |pod: &str, epoch: u64| {
            let mut cfg = IngestConfig::new(TENANT, dir.path().join(pod));
            cfg.writer_epoch = epoch;
            let mut access = nan3554_access(TENANT, address, "owner-token");
            access.owner.writer_epoch = epoch as i64;
            cfg.prevalence_location = Some(access);
            cfg.prevalence_read_store = Some(owner.objects.clone());
            cfg
        };
        let newest = |at: i64| {
            let store = &store;
            async move {
                let mut scan = SpellScan::default();
                loop {
                    if let Some(found) = scan_spell(store, TENANT, &mut scan, at).await.unwrap() { return found; }
                }
            }
        };

        let t0 = 1_800_000_000_000_i64;
        let mut ingestor = Ingestor::open(config("pod-a", 3), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), t0).await.unwrap();
        assert!(ingestor.prevalence.is_none());
        ingestor.tick(t0 + 1_000).await.unwrap();
        ingestor.tick(t0 + 2_000).await.unwrap();
        assert!(ingestor.health().prevalence_degraded);
        assert!(ingestor.health().prevalence_degraded_known);
        let (_, open) = newest(t0 + 2_000).await.expect("the spell is persisted in the tenant bucket");
        assert_eq!(open.cleared_ms, None);
        let since = open.since_ms;
        assert!((t0..=t0 + 1_000).contains(&since), "spell start {since}");
        let records = store.list(&spell_prefix(TENANT).unwrap()).await.unwrap().len();
        ingestor.tick(t0 + 3_000).await.unwrap();
        assert_eq!(store.list(&spell_prefix(TENANT).unwrap()).await.unwrap().len(), records, "an unchanged spell is not rewritten");
        drop(ingestor);

        // The roll, an hour later: a new pod and epoch, the owner still refusing.
        let tb = t0 + 3_600_000;
        let mut ingestor = Ingestor::open(config("pod-b", 4), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), tb).await.unwrap();
        ingestor.tick(tb + 1_000).await.unwrap();
        ingestor.tick(tb + 2_000).await.unwrap();
        let health = ingestor.health();
        assert!(health.prevalence_degraded && health.prevalence_degraded_known);
        assert_eq!(health.prevalence_degraded_ms, (tb + 2_000 - since) as u64, "the spell's age, not the time since the roll");
        assert!(health.prevalence_degraded_ms >= 3_600_000, "past the page threshold");
        assert_eq!(newest(tb + 2_000).await.unwrap().1, open, "the continued spell is the same record");

        // The owner recovers: the state opens, the spell ends and is cleared.
        owner.refuse.store(false, std::sync::atomic::Ordering::SeqCst);
        let tc = tb + 10 * PREVALENCE_RETRY_BASE_MS;
        ingestor.tick(tc).await.unwrap();
        assert!(ingestor.prevalence.is_some(), "prevalence re-opened");
        ingestor.tick(tc + 1_000).await.unwrap();
        assert!(!ingestor.health().prevalence_degraded);
        assert_eq!(ingestor.health().prevalence_degraded_ms, 0);
        let (_, cleared) = newest(tc + 1_000).await.unwrap();
        assert_eq!(cleared.since_ms, since);
        assert!(cleared.cleared_ms.is_some_and(|at| at >= tc), "{cleared:?}");
        drop(ingestor);

        // The next pod starts clean.
        let td = tc + 60_000;
        let mut ingestor = Ingestor::open(config("pod-c", 5), &store, &store, &queue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), td).await.unwrap();
        ingestor.tick(td + 1_000).await.unwrap();
        ingestor.tick(td + 2_000).await.unwrap();
        assert!(!ingestor.health().prevalence_degraded && ingestor.health().prevalence_degraded_known);
        assert_eq!(ingestor.health().prevalence_degraded_ms, 0);
    }
}

#[cfg(test)]
mod restamp_scan_tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TENANT: &str = "00000000-0000-4000-8000-000000004161";

    struct Counting { inner: LocalObjectStore, pages: AtomicUsize, listed: AtomicUsize }

    #[async_trait::async_trait]
    impl ObjectStore for Counting {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> { self.inner.get(key).await }
        async fn put_if_absent(&self, key: &str, bytes: &[u8]) -> Result<bool> { self.inner.put_if_absent(key, bytes).await }
        async fn put(&self, key: &str, bytes: &[u8]) -> Result<()> { self.inner.put(key, bytes).await }
        async fn delete(&self, key: &str) -> Result<()> { self.inner.delete(key).await }
        async fn list(&self, _prefix: &str) -> Result<Vec<String>> { anyhow::bail!("the restamp scan must never list the whole prefix") }
        async fn list_page(&self, prefix: &str, start_after: Option<&str>, limit: usize) -> Result<Vec<String>> {
            assert!(limit <= RESTAMP_SCAN_PAGE_KEYS);
            self.pages.fetch_add(1, Ordering::SeqCst);
            let page = self.inner.list_page(prefix, start_after, limit).await?;
            self.listed.fetch_add(page.len(), Ordering::SeqCst);
            Ok(page)
        }
    }

    #[tokio::test]
    async fn the_snapshot_scan_is_bounded_per_call_and_converges_on_a_large_backlog() {
        let dir = tempfile::tempdir().unwrap();
        let store = Counting { inner: LocalObjectStore::new(dir.path()).unwrap(), pages: Default::default(), listed: Default::default() };
        let now = 1_800_000_000_000_i64;
        // 600 snapshots older than the horizon (never read) and 1,500 inside
        // it, the newest one last: years of churn at today's ~45 a day.
        let old = now - RESTAMP_SNAPSHOT_HORIZON_MS - 600 * 60_000;
        for n in 0..600 {
            persist_restamp_owed(&store, TENANT, format!("[{n}]").as_bytes(), old + n * 60_000).await.unwrap();
        }
        let recent = now - 1_500 * 60_000;
        for n in 0..1_500_i64 {
            persist_restamp_owed(&store, TENANT, format!("[{}]", 100_000 + n).as_bytes(), recent + n * 60_000).await.unwrap();
        }
        let mut scan = RestampScan::default();
        let per_call = RESTAMP_SCAN_PAGE_KEYS * RESTAMP_SCAN_PAGES_PER_CALL;
        let bound = 1_500_usize.div_ceil(per_call) + 1;
        let mut calls = 0;
        let found = loop {
            let pages = store.pages.load(Ordering::SeqCst);
            let step = scan_restamp_owed(&store, TENANT, &mut scan, now).await.unwrap();
            calls += 1;
            assert!(store.pages.load(Ordering::SeqCst) - pages <= RESTAMP_SCAN_PAGES_PER_CALL, "per-call cost is bounded");
            if let Some(found) = step { break found; }
            assert!(calls < bound, "the scan did not converge within {bound} calls");
        };
        assert!(calls > 1, "the backlog needs more than one bounded call");
        let (written_ms, hours) = found.expect("the newest snapshot");
        assert_eq!((written_ms, hours), (recent + 1_499 * 60_000, vec![101_499]));
        assert_eq!(store.listed.load(Ordering::SeqCst), 1_500, "snapshots past the horizon are never listed");
    }

    #[tokio::test]
    async fn the_newest_valid_snapshot_wins_over_a_tampered_newer_name() {
        let dir = tempfile::tempdir().unwrap();
        let store = Counting { inner: LocalObjectStore::new(dir.path()).unwrap(), pages: Default::default(), listed: Default::default() };
        let now = 1_800_000_000_000_i64;
        persist_restamp_owed(&store, TENANT, b"[7]", now - 2_000).await.unwrap();
        let prefix = restamp_owed_prefix(TENANT).unwrap();
        store.put_if_absent(&format!("{prefix}{:013}-0000000000000000.json", now - 1_000), b"[1]").await.unwrap();
        assert_eq!(load_restamp_owed(&store, TENANT, now).await.unwrap(), Some((now - 2_000, vec![7])));
        assert_eq!(load_restamp_owed(&store, TENANT, now + RESTAMP_SNAPSHOT_HORIZON_MS).await.unwrap(), None,
            "a snapshot past the horizon is never read");
    }
}

#[cfg(test)]
mod pipeline_diagnostics_tests {
    use super::*;

    #[test]
    fn stalled_pipeline_snapshot_is_independent_and_ages_without_an_ingest_tick() {
        let diagnostics = PipelineDiagnostics::default();
        {
            let mut state = diagnostics.state.lock().unwrap();
            state.rows = 17;
            state.bytes = 4096;
            state.flights = 1;
            state.buffered_since = Some(std::time::Instant::now() - std::time::Duration::from_secs(12));
            state.oldest_flush_ms = Some(chrono::Utc::now().timestamp_millis() - 7000);
        }
        diagnostics.stage("append_part_log");
        let heartbeat_handle = diagnostics.clone();
        let first = heartbeat_handle.snapshot();
        assert_eq!(first["buffered_rows"], 17);
        assert_eq!(first["buffered_bytes"], 4096);
        assert_eq!(first["flushes_in_flight"], 1);
        assert!(first["buffered_age_seconds"].as_f64().unwrap() >= 12.0);
        assert!(first["oldest_flush_age_seconds"].as_f64().unwrap() >= 7.0);
        assert_eq!(first["oldest_flush_stage"], "append_part_log");
        assert!(heartbeat_handle.snapshot()["oldest_flush_stage_age_seconds"].as_f64().unwrap()
            >= first["oldest_flush_stage_age_seconds"].as_f64().unwrap());
    }
}

#[cfg(test)]
mod oldest_flush_diagnostics_tests {
    use super::*;
    #[test]
    fn younger_flush_work_cannot_replace_oldest_background_stage() {
        let diagnostics = PipelineDiagnostics::default();
        let background = diagnostics.new_flush(0, 0);
        background.lock().unwrap().set("build_parts");
        {
            let mut state = diagnostics.state.lock().unwrap();
            state.flights = 2;
            state.oldest_background = Some(background.clone());
        }
        diagnostics.stage("issue_edge_range");
        assert_eq!(diagnostics.snapshot()["oldest_flush_stage"], "build_parts");
        background.lock().unwrap().set("publish_parts");
        assert_eq!(diagnostics.snapshot()["oldest_flush_stage"], "publish_parts");
        diagnostics.state.lock().unwrap().tracking_oldest = true;
        diagnostics.stage("append_part_log");
        assert_eq!(diagnostics.snapshot()["oldest_flush_stage"], "append_part_log");
    }
}

#[cfg(test)]
#[path = "prevalence_pipeline_tests.rs"]
mod prevalence_pipeline_tests;

#[cfg(test)]
#[path = "ingest_retention_tests.rs"]
mod nan4726_retention_tests;
