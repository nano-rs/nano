// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361: single sizing entry point for the security lake.
//!
//! Today ~300 bounds are scattered across six layers (packer, compactor,
//! signer, activator, worker executor, search client) that do not know about
//! each other, and their unenforced cross-layer inequalities have already
//! caused a total production outage: `MAX_PACK_ROWS` (250_000,
//! `lake_tail_pack.rs:30`) times the measured 248 B/row tops out at ~62 MB —
//! permanently under the compactor's registration floor
//! `(target_bytes + 1) / 2` = 64 MiB (`lake_tail_compact.rs:495`), so a busy
//! hour could never register and the tail grew until every query failed
//! closed. Nothing asserted the inequality; this module now does.
//!
//! `LakeBoundsProfile` is a pure, dependency-light description of every bound
//! that is *derivable* from a deployment's measured inputs. It is serialized
//! into `worker.json` under the optional top-level `bounds_profile` key
//! (which every lake process already reads or can be pointed at), and is
//! deliberately EXCLUDED from `event_config_sha256` — sizing is a
//! runner-capacity concern, the exact category that digest already excludes
//! (`config.rs::event_config_sha256`), so retuning a deployment's size never
//! changes an event-generation identity or orphans queued durable jobs.
//!
//! Wired consumers (NAN-2361):
//! - `lake_tail_pack` — per-pack row cap (`--max-pack-rows` still wins).
//! - `lake_tail_compact` — compaction target / registration floor
//!   (`--target-bytes` still wins).
//! - `lake_staged_tail_manage` — hot-tail signer byte bound (`--max-bytes`
//!   still wins), read from its existing `--worker-config`.
//! - `prevalence_build` — derivative-build memory ceiling
//!   (`NANO_LAKE_BUILD_MEMORY_BYTES` still wins).
//! Every consumer resolves via [`resolve_operational_bound`]: explicit
//! operator override > profile > compiled default, conflicts logged loudly,
//! and a resolved value that violates a profile inequality REFUSES to start.
//!
//! ## What deliberately stays OUT of the profile
//!
//! Bounds that are security floors or format invariants must not become
//! operator-tunable, because "sizing" a fence off is how fences die:
//! - Path sanitization and tenant-prefix checks (`generation.rs`
//!   `local_objects`: no absolute paths, no `..`, `s3://` scheme pin).
//! - SHA-256 / version-id identity verification of staged objects — the
//!   *cost* of verification is a sizing wall (see soft walls below), but the
//!   requirement to verify is not negotiable.
//! - Iceberg tail format invariants: `MAX_PACK_LEVEL` (15) and
//!   `PACK_MERGE_FANOUT` (4) in `lake_tail_pack.rs` define the merge-tree
//!   shape; changing them changes on-disk semantics, not capacity.
//! - IOC record-shape truncation sentinels (`MAX_IOC_VALUE_BYTES` 4096,
//!   `MAX_IOC_TEXT_BYTES` 1024, `MAX_IOC_TAGS` 64, `enrichment.rs`) — these
//!   bound a *record*, not a deployment, and exist to keep hostile feed
//!   content from inflating snapshots.
//! - HMAC / entropy floors in the identity pipeline.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Mirrored compile-time ceilings.
//
// Each constant below is a MIRROR of a bound that today lives as a literal in
// another layer. The profile validates against the mirror; the follow-up
// wiring pass replaces each source literal with a read from the profile (at
// which point the mirror becomes the single source). Citations are to the
// NAN-2361 worktree at the time of writing.
// ---------------------------------------------------------------------------

/// Peak decoded bytes per row, rounded up from >=9,676 B/row in the
/// 2026-09-21 packer OOM (221,895 wide OCSF rows in a 2 GiB container).
pub const DECODED_ROW_BYTES: u64 = 10_240;
/// Non-row resident allowance for the 2026-09-21 OOM sizing model.
pub const ROW_RESIDENT_OVERHEAD_BYTES: u64 = 256 * 1_048_576;
/// Safety margin after the 2026-09-21 OOM; mirrors HOT_TAIL_HEADROOM_FACTOR.
pub const ROW_MEMORY_HEADROOM: u64 = HOT_TAIL_HEADROOM_FACTOR;
/// Conservative fallback: the 2026-09-21 packer/compactor limit was 2 GiB.
pub const DEFAULT_CONTAINER_MEMORY_BYTES: u64 = 2 * 1_073_741_824;

pub fn rows_in_flight_max(memory: u64) -> u64 {
    memory.saturating_sub(ROW_RESIDENT_OVERHEAD_BYTES) / (ROW_MEMORY_HEADROOM * DECODED_ROW_BYTES)
}

/// No-headroom ceiling for a solo raw rewrite or an immutable reserved retry.
/// At 2 GiB, the aggregate ceiling is 91,750 rows and this ceiling is 183,500.
/// The incident's 221,895-row OOM exceeds both. A 110,000-row solo object uses
/// 110,000 * 10,240 + 268,435,456 = 1.395 GB (65% of 2 GiB), so it drains;
/// two such objects (220,000 rows) still cannot enter a new aggregate rewrite.
pub fn solo_rows_max(memory: u64) -> u64 {
    memory.saturating_sub(ROW_RESIDENT_OVERHEAD_BYTES) / DECODED_ROW_BYTES
}

/// cgroup v2 may be unavailable or say `max`; neither prevents startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryProvenance { Cgroup, Profile, CompiledFallback }

pub fn runtime_container_memory_bytes(profile: Option<&LakeBoundsProfile>) -> (u64, MemoryProvenance) {
    let resolved = resolve_container_memory_bytes(
        std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok().as_deref(),
        profile.map(|p| p.inputs.container_memory_bytes),
    );
    if resolved.1 == MemoryProvenance::CompiledFallback {
        tracing::warn!(container_memory_bytes = resolved.0, provenance = ?resolved.1,
            "container memory unavailable; using compiled fallback");
    }
    resolved
}

fn resolve_container_memory_bytes(cgroup: Option<&str>, profile: Option<u64>) -> (u64, MemoryProvenance) {
    if let Some(memory) = cgroup.and_then(|s| s.trim().parse::<u64>().ok()).filter(|m| *m > 0) {
        (memory, MemoryProvenance::Cgroup)
    } else if let Some(memory) = profile {
        (memory, MemoryProvenance::Profile)
    } else {
        (DEFAULT_CONTAINER_MEMORY_BYTES, MemoryProvenance::CompiledFallback)
    }
}

pub fn resolve_tail_serving_bound(explicit: Option<u64>, profile: Option<&LakeBoundsProfile>) -> u64 {
    let (value, source) = resolve_operational_bound("hot_tail_max_objects", explicit,
        profile.map(|p| p.hot_tail_staged_max_objects()), HOT_TAIL_OBJECT_FORMAT_CEILING);
    tracing::info!(serving_bound_objects = value, provenance = ?source, "resolved tail serving bound");
    value
}

/// Safety always wins over the operator's throughput target.
pub fn clamp_decode_rows(name: &str, requested: u64, memory: u64) -> u64 {
    let ceiling = rows_in_flight_max(memory).min(GENERATION_REWRITE_ROWS_CEILING);
    if requested > ceiling {
        tracing::error!(bound = name, requested, rows_in_flight_max = ceiling,
            container_memory_bytes = memory, decoded_row_bytes = DECODED_ROW_BYTES,
            "row target exceeds container decode capacity; clamping");
    }
    requested.min(ceiling)
}

/// Historical packer default, kept for regressions proving the shipped
/// registration and 2026-09-21 decode-memory pairs fail validation.
pub const SHIPPED_MAX_PACK_ROWS: u64 = 250_000;

/// `lake_tail_pack.rs:29` (`MAX_PACK_BYTES`) and `lake_tail_compact.rs:26`
/// (`MAX_COMPACTION_BYTES`): 1 GiB absolute ceiling on a pack / compaction
/// target. Two names, one value, two files — exactly the clone pattern this
/// module exists to end.
pub const PACK_BYTES_CEILING: u64 = 1_073_741_824;

/// `iceberg.rs:68` (`MAX_GENERATION_REWRITE_ROWS`). Compile-time cap on rows
/// a single rewrite/pack may carry. Together with the measured row width it
/// bounds the largest pack the packer can EVER emit:
/// `min(1_000_000 * row_width, 1 GiB)`.
pub const GENERATION_REWRITE_ROWS_CEILING: u64 = 1_000_000;

/// Absolute staged hot-tail serving ceiling shared by signer, activator,
/// manager, manifest validator, and query reader.
///
/// This is a metadata/scan envelope, not a resident-memory allocation. The
/// old 1 GiB literal was repeated in five call sites and wedged publication
/// after a healthy 1 TB/day run produced 1.059 GiB of not-yet-indexed
/// Parquet. Keep the absolute safety fence finite, but high enough for the
/// largest shipped size-class stall calculation; deployments still select a
/// lower rate/cadence-derived `hot_tail_max_bytes` and queries retain their
/// independent per-request scan and memory budgets.
pub const HOT_TAIL_SERVING_CEILING_BYTES: u64 = 256 * 1_073_741_824;

/// Absolute configuration ceiling for one query's estimated source scan.
/// This remains independent of resident query memory: chDB streams and spills
/// scans, while `per_query_memory_bytes` and the worker cgroup bound RAM. The
/// old worker-bootstrap parser stopped at 64 GiB, which left no variation
/// headroom over the measured ~63.6 GB ten-minute 30 TB/day campaign slice.
pub const QUERY_SCAN_BUDGET_CEILING_BYTES: u64 = 256 * 1_073_741_824;

/// The 4_096 hot-tail object format cap, repeated verbatim in
/// `generation.rs::validate_hot_tail_manifest`, `build_hot_tail_manifest`,
/// `build_staged_hot_tail_manifest`, `planner.rs::hot_tail_source`,
/// `planner.rs::exact_versioned_parquet_source`,
/// `lake_staged_tail_manage.rs` (`--max-objects` validation) and
/// `lake_generation_activate.rs` (`--hot-tail-max-objects` validation).
/// It bounds the exact-object `UNION ALL` the planner emits, so it is a
/// format/plan-shape invariant, not a tunable.
pub const HOT_TAIL_OBJECT_FORMAT_CEILING: u64 = 4_096;

/// `lake_staged_tail_manage.rs`: the signer's compiled default
/// `--max-objects` — the staged (Tier A) object-count envelope.
pub const SHIPPED_STAGED_TAIL_MAX_OBJECTS: u64 = 256;

/// `lake_tail_pack.rs:31/32` (`PACK_MERGE_FANOUT`, `MAX_PACK_LEVEL`): the
/// merge-tree shape that bounds how many STAGED pack objects one event hour
/// can hold — at most FANOUT unmerged runs per level. Mirrored here because
/// the staged-tier object bound is derived from that shape.
pub const TAIL_PACK_MERGE_FANOUT: u64 = 4;
pub const TAIL_PACK_MAX_LEVEL: u64 = 15;

/// NAN-2361 two-tier hot tail: the committed tier must absorb at least this
/// many days of compaction output between generation activations, or the
/// object-count bound recreates the very activation-coupled ceiling the
/// committed tier exists to remove.
const MIN_COMMITTED_TAIL_HEADROOM_DAYS: u64 = 2;

/// `generation.rs:774` / `generation.rs:1083`: an Iceberg snapshot with more
/// than 100_000 data files is rejected outright at plan time.
pub const ICEBERG_DATA_FILE_CEILING: u64 = 100_000;

/// `generation.rs:906`: snapshot-ancestry walks bail past 100_000 ancestors.
pub const SNAPSHOT_ANCESTRY_CEILING: u64 = 100_000;

/// Object-identity ceiling.
///
/// NAN-2361: this was `u16::MAX` and described a rewrite cascade -- ordinals
/// were sort positions, so retiring one object renumbered every later one and
/// forced a parquet restamp. Commit 58d94f708 replaced ordinals with a
/// persisted monotonic u32 allocator keyed by immutable object identity, and
/// `local_objects` now bails at `u32::MAX` (`generation.rs`). This mirror was
/// left behind, so the profile kept REFUSING size classes the code had already
/// grown out of -- a sizing gate is only as good as its agreement with the
/// thing it gates. Verified against the current bail, not the old comment.
pub const OBJECT_ORDINAL_CEILING: u64 = u32::MAX as u64; // 4_294_967_295

/// `nanosiem-core/src/search/lake.rs:26` (`DEFAULT_TIMEOUT_SECS`). The search
/// client gives up after this; any worker execution bound must finish first
/// or the client times out while the worker keeps burning memory.
pub const SEARCH_CLIENT_TIMEOUT_SECS: u64 = 130;

/// Margin the worker must leave under the client timeout so the worker's own
/// deadline error (not a client-side hangup) is what the analyst sees.
pub const CLIENT_TIMEOUT_MARGIN_SECS: u64 = 10;

/// `tail_health.rs:34` (`HOT_TAIL_ROTATION_GRACE_MS`). Deliberately above the
/// manager's maximum `--activation-wait-seconds` so a held rotation lock is
/// not misread as a wedge.
pub const HOT_TAIL_ROTATION_GRACE_MS: u64 = 330_000;

/// `lake_generation_manage.rs:1309`: `--activation-wait-seconds` is validated
/// into `1.0..=300.0`.
pub const ACTIVATION_WAIT_CEILING_SECS: u64 = 300;

/// Margin the rotation grace must keep above the activation wait, mirroring
/// the 30 s headroom the shipped constants encode (330 s vs 300 s).
pub const ROTATION_GRACE_MARGIN_MS: u64 = 30_000;

/// `enrichment.rs:30` (`MAX_IOC_SNAPSHOT_BYTES`): the OUTPUT cap on a
/// published IOC snapshot. `lake_ioc_publish.rs:13` accepts INPUTS up to
/// 2 GiB — violated by construction today; an accepted 2 GiB input can
/// produce an unwritable snapshot. The profile derives the input gate FROM
/// the output cap so the pair cannot diverge again.
pub const IOC_SNAPSHOT_CEILING_BYTES: u64 = 1_073_741_824;

/// `lake_ioc_publish.rs:13` (`MAX_INPUT_BYTES`) — kept only for the
/// regression test proving today's shipped pair fails validation.
pub const SHIPPED_IOC_INPUT_GATE_BYTES: u64 = 2 * 1_073_741_824;

/// `config.rs:353`: the shipped per-query execution bound.
pub const SHIPPED_MAX_EXECUTION_SECS: u64 = 120;

// ---------------------------------------------------------------------------
// Derivation constants (assumptions, not mirrors — each is a policy choice
// the formulas below make explicit so it can be challenged in review).
// ---------------------------------------------------------------------------

const SECONDS_PER_DAY: u64 = 86_400;

/// Minimum compaction target. Below this, per-object overhead (metadata.json
/// growth per commit, HEAD/GET round trips) dominates; 32 MiB keeps a 5
/// GB/day deployment at ~47 files/day.
const MIN_COMPACTION_TARGET_BYTES: u64 = 32 * 1_048_576;

/// Headroom divisor on the u16 ordinal cap: derivation sizes files so the
/// retention window fits in HALF the ordinal space, leaving room for
/// compaction churn and uneven hours. Validation enforces only the hard cap.
const ORDINAL_HEADROOM_DIVISOR: u64 = 2;

/// Target file-count-per-day used when throughput, not the ordinal cap, is
/// what sizes files: one file roughly every ~169 s of ingest.
const THROUGHPUT_FILES_PER_DAY: u64 = 512;

/// Floor of the pipeline-stall window the hot tail must absorb:
/// activation wait ceiling (300 s) + promotion/commit floor (60 s) + the
/// object-store commit-latency margin. The signer inequality is
/// `hot_tail_max_bytes >= compressed_rate * stall_window`.
const STALL_PROMOTION_FLOOR_SECS: u64 = 60;

/// The derived hot-tail bound doubles the required buffer — the outage
/// showed running AT a ceiling means the first anomaly wedges.
const HOT_TAIL_HEADROOM_FACTOR: u64 = 2;

/// Minimum hot-tail bound; below this the tail rotates too often to batch.
const MIN_HOT_TAIL_BYTES: u64 = 64 * 1_048_576;

/// Resident query-worker overhead (indexes, sidecar maps, chdb runtime)
/// reserved before dividing container memory across concurrent queries.
const QUERY_RESIDENT_OVERHEAD_BYTES: u64 = 1_073_741_824;

/// Resident generation-manager overhead outside chDB's derivative build
/// ceiling. The 1 TB/day AWS gate measured 8.787 GiB at the cgroup while the
/// derivative lane was capped at 7 GiB: the former 1 GiB allowance was false
/// and tripped the deployment's 85% safety fence despite abundant host RAM.
/// Reserve 2 GiB so the configured chDB limit and its owning process actually
/// fit the same container envelope.
const DERIVATIVE_RESIDENT_OVERHEAD_BYTES: u64 = 2 * 1_073_741_824;

/// Floor for a useful per-query memory grant; below this chdb aggregations
/// spill or fail on realistic hunt queries.
const MIN_QUERY_MEMORY_BYTES: u64 = 512 * 1_048_576;

/// GC grace ceiling in days; more grace than a week buys nothing and eats
/// ancestry budget.
const MAX_GC_GRACE_DAYS: u64 = 7;

/// Floor/ceiling for the derivative-build memory ceiling, mirroring the
/// FLOOR/CEILING inside `prevalence_build.rs::build_memory_bytes` — below the
/// floor realistic prevalence builds abort (chDB `Code: 241` on a single
/// column read, the 2026-08-19 activation wedge); above the ceiling one build
/// claims a whole worker.
const MIN_DERIVATIVE_BUILD_MEMORY_BYTES: u64 = 512 * 1_048_576;
const MAX_DERIVATIVE_BUILD_MEMORY_BYTES: u64 = 16 * 1_073_741_824;

// Soft structural walls (assumptions marked as such; see StructuralFinding).

/// Local hydration throughput assumption for the whole-table rebuild path
/// (`generation.rs:720..946` `hydrate_snapshot_inner`): ~200 MiB/s from
/// object store to local NVMe, 2 h budget per activation.
const HYDRATION_WALL_TABLE_BYTES: u64 = 200 * 1_048_576 * 7_200; // ~1.5 TB

/// O(table) re-verification wall.
///
/// NAN-2361: this cited `verified_copy`, which NO LONGER EXISTS -- 0d16842c9
/// replaced that full copy + double hash with a hard link. Citing deleted code
/// made the wall look addressed when it is not. The surviving O(table)
/// re-verification is in the ACTIVATION path, which 0d16842c9 explicitly did
/// not fix: `lake_generation_activate` still `index_directory_sha256`s the
/// keyword, fragment and count-rollup trees and `file_sha256`s every
/// prevalence part on EVERY activation. `verify_unique_event_uids` also still
/// goes full-table whenever the reused set shrinks -- i.e. every retention
/// day. ~500 MiB/s hashing, 30 min budget.
const VERIFICATION_WALL_TABLE_BYTES: u64 = 500 * 1_048_576 * 1_800; // ~944 GB

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Object-store class, because commit latency and versioning semantics feed
/// the stall window the hot tail must ride out.
///
/// All classes MUST support object versioning: staged-object identity pins
/// (`verify_exact_staged_object`, `lake_tail_compact.rs`) read by version id.
/// A non-versioned store is not a sizing question — it is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStoreClass {
    /// AWS S3: strong read-after-write, versioned, ~60 s worst-case commit
    /// convergence budget under contention.
    AwsS3,
    /// Third-party S3-compatible stores with versioning (Wasabi, R2 with
    /// versioning, Ceph RGW): budget a wider commit margin.
    S3CompatibleVersioned,
    /// Local MinIO (compose / air-gapped): near-zero commit latency.
    LocalMinio,
}

impl ObjectStoreClass {
    fn commit_latency_margin_secs(self) -> u64 {
        match self {
            ObjectStoreClass::AwsS3 => 60,
            ObjectStoreClass::S3CompatibleVersioned => 90,
            ObjectStoreClass::LocalMinio => 15,
        }
    }
}

/// The measured inputs a profile is derived from.
///
/// NOTE on the input list (challenged per NAN-2361 review): raw ingest
/// bytes/sec alone cannot yield a row rate, and every binding inequality is
/// in ROWS x COMPRESSED-BYTES space. `mean_raw_row_bytes` is therefore a
/// required input alongside `mean_compressed_row_bytes`; both are MEASURED
/// (the outage existed only because the measured compressed width, 248 B,
/// fell under the 268.4 B break-even nobody had computed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LakeBoundsInputs {
    /// Raw log bytes per second at target load.
    pub target_ingest_bytes_per_sec: u64,
    /// Measured mean RAW event size (bytes) — converts byte rate to row rate.
    pub mean_raw_row_bytes: u64,
    /// Measured mean COMPRESSED row width in the tail packs (bytes).
    pub mean_compressed_row_bytes: u64,
    /// Retention window in days.
    pub retention_days: u64,
    /// Memory limit of the query-serving worker container.
    pub container_memory_bytes: u64,
    /// Concurrent interactive queries the deployment must sustain.
    pub interactive_query_concurrency: u64,
    /// Object store the lake commits to.
    pub object_store_class: ObjectStoreClass,
}

// ---------------------------------------------------------------------------
// Structural walls and findings
// ---------------------------------------------------------------------------

/// A compile-time architectural wall that NO profile value can move. When a
/// requested size hits one of these, `derive` REFUSES rather than emitting a
/// profile that silently cannot work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "wall", rename_all = "snake_case")]
pub enum StructuralWall {
    /// The registration requirement cannot fit in the container decode budget.
    PackRowsExceedMemory { required_rows: u64, rows_in_flight_max: u64 },
    /// Required hot-tail buffer exceeds the centralized absolute serving
    /// ceiling. This is a real refusal: selecting a deployment override above
    /// it cannot make binaries accept the resulting manifest.
    HotTailServingCeiling {
        required_bytes: u64,
        ceiling_bytes: u64,
    },
    /// The registration floor for the file size the retention window needs
    /// exceeds the largest pack the packer can physically emit
    /// (`min(MAX_GENERATION_REWRITE_ROWS * row_width, 1 GiB)`). At 248 B rows
    /// this caps a table at ~32.5 TiB compressed (zero headroom). Fix: lift
    /// MAX_GENERATION_REWRITE_ROWS (iceberg.rs:68) or add multi-pass packing.
    PackCapacityBelowRegistrationFloor {
        registration_floor_bytes: u64,
        max_pack_capacity_bytes: u64,
    },
    /// Even 1 GiB files cannot fit the retention window under the 100_000
    /// data-file plan-time cap (generation.rs:774/1083). Binds at ~97 TiB
    /// compressed table. Fix: manifest-level partition pruning before the
    /// file-count check.
    DataFileCeiling { projected_files: u64, ceiling: u64 },
    /// Even 1 GiB files exceed the u16 object-ordinal space
    /// (generation.rs:2155). Binds at 64 TiB compressed table. Fix: widen the
    /// ordinal type and version the stamp manifest (rewrite cascade).
    ObjectOrdinalCeiling { projected_files: u64, ceiling: u64 },
    /// The needed per-file target exceeds the 1 GiB pack/compaction byte
    /// ceiling (lake_tail_pack.rs:29, lake_tail_compact.rs:26).
    CompactionTargetCeiling {
        needed_target_bytes: u64,
        ceiling_bytes: u64,
    },
}

/// Soft walls: the profile is deliverable, but an O(table) code path binds
/// before the hard ceilings do. Reported, not refused — throughput
/// assumptions are stated so operators can re-measure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralFinding {
    pub concern: SoftWall,
    /// Table size (compressed bytes) at which the wall binds under the
    /// stated throughput assumption.
    pub binds_at_table_bytes: u64,
    /// Projected steady-state table size for these inputs.
    pub projected_table_bytes: u64,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftWall {
    /// Whole-table local hydration on activation (generation.rs:720..946).
    WholeTableHydration,
    /// O(table) re-verification. NAN-2361: no longer `verified_copy` (deleted
    /// in 0d16842c9 in favour of hard links) -- the surviving cost is the
    /// ACTIVATION verifier re-hashing every derivative tree, plus the
    /// full-table uid proof that runs whenever the reused set shrinks.
    FullTableReverification,
    /// The all-or-nothing activation gate serializes availability on the two
    /// walls above: while they run, no partial generation serves.
    AllOrNothingActivation,
}

// ---------------------------------------------------------------------------
// Errors — every message names BOTH bounds in conflict, with values.
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BoundsError {
    #[error("max_pack_rows ({max_pack_rows}) exceeds container rows_in_flight_max ({rows_in_flight_max})")]
    PackRowsExceedMemory { max_pack_rows: u64, rows_in_flight_max: u64 },
    // The NAN-2361 outage inequality.
    #[error(
        "pack registration deadlock: max_pack_rows ({max_pack_rows}) x mean_compressed_row_bytes ({row_bytes}) = {pack_bytes} is below registration_floor_bytes ({floor}); a full pack can never register and the tail grows unboundedly (a past outage)"
    )]
    PackRegistrationDeadlock {
        max_pack_rows: u64,
        row_bytes: u64,
        pack_bytes: u64,
        floor: u64,
    },

    #[error(
        "max_pack_rows ({max_pack_rows}) exceeds MAX_GENERATION_REWRITE_ROWS ({ceiling}, iceberg.rs:68); the packer clamps and the effective pack shrinks below what the profile assumes"
    )]
    PackRowsExceedRewriteCeiling { max_pack_rows: u64, ceiling: u64 },

    #[error(
        "compaction_target_bytes ({target}) exceeds the pack/compaction byte ceiling ({ceiling}, MAX_PACK_BYTES/MAX_COMPACTION_BYTES)"
    )]
    CompactionTargetExceedsCeiling { target: u64, ceiling: u64 },

    #[error(
        "hot_tail_max_bytes ({hot_tail}) exceeds the compiled serving ceiling ({ceiling}, bounds::HOT_TAIL_SERVING_CEILING_BYTES)"
    )]
    HotTailExceedsServingCeiling { hot_tail: u64, ceiling: u64 },

    #[error(
        "hot_tail_max_bytes ({hot_tail}) is below compressed_rate x stall_window = {required}; one activation-length stall overruns the signer bound and publication wedges"
    )]
    HotTailBufferTooSmall { hot_tail: u64, required: u64 },

    #[error(
        "retention file count: daily_data_files ({daily}) x retention_days ({days}) = {projected} exceeds the Iceberg data-file cap ({ceiling}, generation.rs:774/1083)"
    )]
    DataFileCapExceeded {
        daily: u64,
        days: u64,
        projected: u64,
        ceiling: u64,
    },

    #[error(
        "retention file count: daily_data_files ({daily}) x retention_days ({days}) = {projected} exceeds the u16 object-ordinal cap ({ceiling}, generation.rs:2155)"
    )]
    ObjectOrdinalCapExceeded {
        daily: u64,
        days: u64,
        projected: u64,
        ceiling: u64,
    },

    #[error(
        "snapshot ancestry: gc_grace_days ({grace}) x commits_per_day ({commits}) = {projected} exceeds the ancestry cap ({ceiling}, generation.rs:906)"
    )]
    AncestryCapExceeded {
        grace: u64,
        commits: u64,
        projected: u64,
        ceiling: u64,
    },

    #[error(
        "max_execution_seconds ({exec}) + margin ({margin}) exceeds the search client timeout ({client}, nanosiem-core/src/search/lake.rs:26); the client hangs up before the worker's own deadline"
    )]
    ExecutionExceedsClientTimeout { exec: u64, margin: u64, client: u64 },

    #[error(
        "activation_wait_seconds ({wait}) x 1000 + margin ({margin_ms} ms) exceeds HOT_TAIL_ROTATION_GRACE_MS ({grace_ms}, tail_health.rs:34); a healthy rotation reads as a wedge and fails closed"
    )]
    RotationGraceInversion {
        wait: u64,
        margin_ms: u64,
        grace_ms: u64,
    },

    #[error(
        "activation_wait_seconds ({wait}) exceeds the manager ceiling ({ceiling}, lake_generation_manage.rs:1309)"
    )]
    ActivationWaitExceedsCeiling { wait: u64, ceiling: u64 },

    #[error(
        "ioc_max_input_bytes ({input}) exceeds ioc_max_snapshot_bytes ({snapshot}); an accepted input can produce an unwritable snapshot (lake_ioc_publish.rs:13 vs enrichment.rs:30 — violated by the shipped constants)"
    )]
    IocInputExceedsSnapshotCap { input: u64, snapshot: u64 },

    #[error(
        "query memory overcommit: interactive_query_concurrency ({concurrency}) x per_query_memory_bytes ({per_query}) + resident overhead ({overhead}) = {total} exceeds container_memory_bytes ({container})"
    )]
    QueryMemoryOvercommit {
        concurrency: u64,
        per_query: u64,
        overhead: u64,
        total: u64,
        container: u64,
    },

    #[error(
        "container_memory_bytes ({container}) cannot grant {concurrency} queries the {floor}-byte minimum after {overhead} resident overhead"
    )]
    ContainerTooSmall {
        container: u64,
        concurrency: u64,
        floor: u64,
        overhead: u64,
    },

    #[error(
        "derivative_build_memory_bytes ({build}) plus resident overhead ({overhead}) exceeds container_memory_bytes ({container}); the build OOM-kills mid-activation, and activation is the only path that drains the hot tail"
    )]
    DerivativeBuildMemoryOvercommit {
        build: u64,
        overhead: u64,
        container: u64,
    },

    #[error(
        "derivative_build_memory_bytes ({build}) is below the floor ({floor}); realistic prevalence builds abort with chDB Code 241 before activation completes"
    )]
    DerivativeBuildMemoryBelowFloor { build: u64, floor: u64 },

    #[error(
        "hot-tail tier bounds overflow the object format cap: staged ({staged}) + committed ({committed}) = {total} exceeds the 4_096 exact-object plan ceiling ({ceiling}, generation.rs::validate_hot_tail_manifest / planner.rs::hot_tail_source)"
    )]
    HotTailTierObjectsExceedFormatCeiling {
        staged: u64,
        committed: u64,
        total: u64,
        ceiling: u64,
    },

    #[error(
        "committed hot-tail headroom too small: hot_tail_committed_max_objects ({committed}) cannot hold {days} days of compaction output ({required} = {days} x daily_data_files {daily}); the committed tier would wedge on activation delay, recreating the activation-coupled ceiling it exists to remove"
    )]
    CommittedTailHeadroomTooSmall {
        committed: u64,
        days: u64,
        required: u64,
        daily: u64,
    },

    #[error("input {name} must be nonzero")]
    ZeroInput { name: &'static str },

    #[error(
        "requested size exceeds what the current architecture can deliver at any profile setting; structural work required: {walls:?}"
    )]
    StructuralRefusal { walls: Vec<StructuralWall> },
}

// ---------------------------------------------------------------------------
// The profile
// ---------------------------------------------------------------------------

/// Every derived bound, with the formula it came from and the inequality it
/// satisfies recorded at the derivation site in `derive()`.
/// NAN-2361: deserialization runs `validate()` via `try_from`.
///
/// `derive()` validates what it builds, but the profile's whole purpose is to
/// be written into `worker.json` and read back by six independent lake
/// processes. A hand-edited, stale, or downgraded `worker.json` reaching a
/// consumer unchecked would install exactly the unvalidated cross-layer
/// bounds this module exists to prevent — the safety net would be decoration.
/// Deserializing into the wire twin and converting is the only way every
/// consumer gets the check for free, including ones written later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "LakeBoundsProfileWire")]
pub struct LakeBoundsProfile {
    /// The inputs this profile was derived from (echoed for auditability —
    /// a worker.json reader can re-run `validate_profile` without guessing).
    pub inputs: LakeBoundsInputs,

    // -- derived rates -----------------------------------------------------
    /// rows/sec = ceil(target_ingest_bytes_per_sec / mean_raw_row_bytes)
    pub rows_per_sec: u64,
    /// compressed bytes/sec = rows_per_sec x mean_compressed_row_bytes
    pub compressed_bytes_per_sec: u64,
    /// compressed bytes/day = compressed_bytes_per_sec x 86_400
    pub compressed_bytes_per_day: u64,
    /// steady-state table size = compressed_bytes_per_day x retention_days
    pub projected_table_bytes: u64,

    // -- pack / compaction layer --------------------------------------------
    /// Per-file compaction target. Formula:
    /// max(32 MiB, table/(65_535/2), table/(100_000/2), day/512), <= 1 GiB.
    /// Satisfies: retention file count fits both the u16 ordinal space and
    /// the 100k data-file cap with 2x headroom.
    pub compaction_target_bytes: u64,
    /// (compaction_target_bytes + 1) / 2 — mirror of lake_tail_compact.rs:495.
    pub registration_floor_bytes: u64,
    /// ceil(2 x target / row_bytes), <= MAX_GENERATION_REWRITE_ROWS.
    /// Satisfies THE outage inequality:
    /// max_pack_rows x mean_compressed_row_bytes >= registration_floor_bytes.
    pub max_pack_rows: u64,
    /// ceil(compressed_bytes_per_day / compaction_target_bytes), min 24
    /// (hour partitioning emits at least one file per hour).
    pub daily_data_files: u64,

    // -- snapshot / GC layer -------------------------------------------------
    /// Registrations + compaction rewrites + maintenance commits.
    /// Formula: 2 x daily_data_files + 48.
    pub commits_per_day: u64,
    /// min(7, (100_000/2) / commits_per_day), >= 1.
    /// Satisfies: gc_grace_days x commits_per_day <= ancestry cap.
    pub gc_grace_days: u64,

    // -- hot tail / signer layer ----------------------------------------------
    /// Stall window = activation ceiling + promotion floor + store commit
    /// margin (object_store_class dependent).
    pub stall_window_secs: u64,
    /// clamp(2 x compressed_rate x stall_window, 64 MiB, 1 GiB ceiling).
    /// Satisfies BOTH: >= compressed_rate x stall_window (signer inequality)
    /// and <= the compiled serving ceiling.
    pub hot_tail_max_bytes: u64,

    // -- query serving layer ---------------------------------------------------
    /// min(shipped 120, client 130 - margin 10). Satisfies:
    /// max_execution_seconds + margin <= SEARCH_CLIENT_TIMEOUT_SECS.
    pub max_execution_seconds: u64,
    /// (container - 1 GiB resident overhead) / concurrency, >= 512 MiB.
    /// Satisfies: concurrency x per_query + overhead <= container.
    pub per_query_memory_bytes: u64,
    /// Memory ceiling for one derivative-build query
    /// (`prevalence_build.rs::build_memory_bytes`).
    /// Formula: clamp(container - 2 GiB resident overhead, 512 MiB, 16 GiB).
    /// Satisfies: derivative_build_memory_bytes + derivative-process overhead
    /// <= container, so a build can never be OOM-killed by the very container
    /// the deployment sized — the 2026-08-19 activation wedge (NAN-2361).
    pub derivative_build_memory_bytes: u64,

    // -- activation / rotation layer ---------------------------------------------
    /// <= 300 (manager ceiling) and satisfies
    /// wait x 1000 + 30_000 <= HOT_TAIL_ROTATION_GRACE_MS.
    pub activation_wait_seconds: u64,

    // -- IOC layer -------------------------------------------------------------
    /// = IOC snapshot output cap, so the input gate can never again accept
    /// what the output cannot write.
    pub ioc_max_input_bytes: u64,

    /// Soft walls that bind before the hard ceilings for these inputs.
    /// Non-empty findings downgrade the verdict — see [`LakeBoundsProfile::verdict`].
    pub structural_findings: Vec<StructuralFinding>,
}

/// What a successfully derived profile actually promises.
///
/// NAN-2361: these were one state, and that conflation is what let a
/// deployment read "deliverable" while sitting on an O(table) path that took
/// the query surface down for 3h40m on 2026-08-19. The soft walls are not
/// latency advisories: the activation gate is all-or-nothing, so while
/// whole-table hydration and re-verification run, NO generation serves — a
/// throughput wall on that path is an availability wall. A profile that trips
/// one is still runnable, but it is not the thing an operator means when they
/// ask whether a size is supported, and it violates the standing goal that
/// background maintenance cost track new data rather than total table size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Every bound holds and no O(table) path binds at this size.
    Deliverable,
    /// Every bound holds, but at least one O(table) maintenance path binds
    /// before the hard ceilings do. Runnable; not a clean yes.
    DeliverableWithDegradation,
}

/// Field-identical wire twin of [`LakeBoundsProfile`].
///
/// Exists only so `try_from` can run `validate()` on the way in without the
/// infinite recursion a self-referential `try_from` would cause.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LakeBoundsProfileWire {
    inputs: LakeBoundsInputs,
    rows_per_sec: u64,
    compressed_bytes_per_sec: u64,
    compressed_bytes_per_day: u64,
    projected_table_bytes: u64,
    compaction_target_bytes: u64,
    registration_floor_bytes: u64,
    max_pack_rows: u64,
    daily_data_files: u64,
    commits_per_day: u64,
    gc_grace_days: u64,
    stall_window_secs: u64,
    hot_tail_max_bytes: u64,
    max_execution_seconds: u64,
    per_query_memory_bytes: u64,
    derivative_build_memory_bytes: u64,
    activation_wait_seconds: u64,
    ioc_max_input_bytes: u64,
    structural_findings: Vec<StructuralFinding>,
}

impl TryFrom<LakeBoundsProfileWire> for LakeBoundsProfile {
    type Error = BoundsError;

    fn try_from(wire: LakeBoundsProfileWire) -> Result<Self, Self::Error> {
        let mut profile = LakeBoundsProfile {
            inputs: wire.inputs,
            rows_per_sec: wire.rows_per_sec,
            compressed_bytes_per_sec: wire.compressed_bytes_per_sec,
            compressed_bytes_per_day: wire.compressed_bytes_per_day,
            projected_table_bytes: wire.projected_table_bytes,
            compaction_target_bytes: wire.compaction_target_bytes,
            registration_floor_bytes: wire.registration_floor_bytes,
            max_pack_rows: wire.max_pack_rows,
            daily_data_files: wire.daily_data_files,
            commits_per_day: wire.commits_per_day,
            gc_grace_days: wire.gc_grace_days,
            stall_window_secs: wire.stall_window_secs,
            hot_tail_max_bytes: wire.hot_tail_max_bytes,
            max_execution_seconds: wire.max_execution_seconds,
            per_query_memory_bytes: wire.per_query_memory_bytes,
            derivative_build_memory_bytes: wire.derivative_build_memory_bytes,
            activation_wait_seconds: wire.activation_wait_seconds,
            ioc_max_input_bytes: wire.ioc_max_input_bytes,
            structural_findings: wire.structural_findings,
        };
        // Old worker.json profiles predate the decode ceiling. Normalize
        // this operational cap on read so a rolling upgrade does not turn a
        // safe clamp into a startup failure. All other inequalities still
        // validate, including whether the smaller pack clears registration.
        if matches!(profile.validate(), Err(BoundsError::PackRowsExceedMemory { .. })) {
            profile.max_pack_rows = clamp_decode_rows("max_pack_rows", profile.max_pack_rows,
                profile.inputs.container_memory_bytes);
        }
        profile.validate()?;
        Ok(profile)
    }
}

fn ceil_div(a: u64, b: u64) -> u64 {
    debug_assert!(b > 0);
    a.div_ceil(b)
}

impl LakeBoundsProfile {
    /// Derived, not serialized: adding a wire field breaks rolling upgrades.
    /// Uses the 2026-09-21 OOM model with this profile's existing memory input.
    pub fn rows_in_flight_max(&self) -> u64 {
        rows_in_flight_max(self.inputs.container_memory_bytes)
    }

    /// Derive every bound from the measured inputs, refusing outright when
    /// the requested size collides with a compile-time architectural wall.
    pub fn derive(inputs: LakeBoundsInputs) -> Result<Self, BoundsError> {
        for (name, value) in [
            (
                "target_ingest_bytes_per_sec",
                inputs.target_ingest_bytes_per_sec,
            ),
            ("mean_raw_row_bytes", inputs.mean_raw_row_bytes),
            (
                "mean_compressed_row_bytes",
                inputs.mean_compressed_row_bytes,
            ),
            ("retention_days", inputs.retention_days),
            ("container_memory_bytes", inputs.container_memory_bytes),
            (
                "interactive_query_concurrency",
                inputs.interactive_query_concurrency,
            ),
        ] {
            if value == 0 {
                return Err(BoundsError::ZeroInput { name });
            }
        }

        // Rates. Rows are the unit every binding inequality is written in.
        let rows_per_sec = ceil_div(
            inputs.target_ingest_bytes_per_sec,
            inputs.mean_raw_row_bytes,
        )
        .max(1);
        let compressed_bytes_per_sec = rows_per_sec * inputs.mean_compressed_row_bytes;
        let compressed_bytes_per_day = compressed_bytes_per_sec * SECONDS_PER_DAY;
        let projected_table_bytes = compressed_bytes_per_day * inputs.retention_days;

        let mut walls = Vec::new();

        // File sizing: the target must be large enough that the retention
        // window fits the ordinal and data-file caps (with headroom), and
        // large enough that a day stays near THROUGHPUT_FILES_PER_DAY files.
        let need_ordinal = ceil_div(
            projected_table_bytes,
            OBJECT_ORDINAL_CEILING / ORDINAL_HEADROOM_DIVISOR,
        );
        let need_file_cap = ceil_div(
            projected_table_bytes,
            ICEBERG_DATA_FILE_CEILING / ORDINAL_HEADROOM_DIVISOR,
        );
        let need_throughput = compressed_bytes_per_day / THROUGHPUT_FILES_PER_DAY;
        let unclamped_target = need_ordinal
            .max(need_file_cap)
            .max(need_throughput)
            .max(MIN_COMPACTION_TARGET_BYTES);

        if unclamped_target > PACK_BYTES_CEILING {
            // Even the largest legal file cannot fit this retention window.
            walls.push(StructuralWall::CompactionTargetCeiling {
                needed_target_bytes: unclamped_target,
                ceiling_bytes: PACK_BYTES_CEILING,
            });
            let files_at_ceiling = ceil_div(projected_table_bytes, PACK_BYTES_CEILING);
            if files_at_ceiling > ICEBERG_DATA_FILE_CEILING {
                walls.push(StructuralWall::DataFileCeiling {
                    projected_files: files_at_ceiling,
                    ceiling: ICEBERG_DATA_FILE_CEILING,
                });
            }
            if files_at_ceiling > OBJECT_ORDINAL_CEILING {
                walls.push(StructuralWall::ObjectOrdinalCeiling {
                    projected_files: files_at_ceiling,
                    ceiling: OBJECT_ORDINAL_CEILING,
                });
            }
        }
        let compaction_target_bytes = unclamped_target.min(PACK_BYTES_CEILING);

        // The outage inequality, from the other side: the packer can emit at
        // most min(rewrite-row ceiling x row width, byte ceiling) per pack.
        // The registration floor for our target must fit under that, or the
        // hour can never drain — the exact NAN-2361 deadlock.
        let registration_floor_bytes = (compaction_target_bytes + 1) / 2;
        let max_pack_capacity_bytes = (GENERATION_REWRITE_ROWS_CEILING
            * inputs.mean_compressed_row_bytes)
            .min(PACK_BYTES_CEILING);
        if max_pack_capacity_bytes < registration_floor_bytes {
            walls.push(StructuralWall::PackCapacityBelowRegistrationFloor {
                registration_floor_bytes,
                max_pack_capacity_bytes,
            });
        }
        // Aim packs at 2x the target so merges reach it; clamp to the
        // compile-time row ceiling the packer enforces anyway.
        let max_pack_rows = ceil_div(
            2 * compaction_target_bytes,
            inputs.mean_compressed_row_bytes,
        )
        .min(GENERATION_REWRITE_ROWS_CEILING)
        .min(rows_in_flight_max(inputs.container_memory_bytes));
        let required_rows = ceil_div(registration_floor_bytes, inputs.mean_compressed_row_bytes);
        if required_rows > rows_in_flight_max(inputs.container_memory_bytes) {
            walls.push(StructuralWall::PackRowsExceedMemory {
                required_rows,
                rows_in_flight_max: rows_in_flight_max(inputs.container_memory_bytes),
            });
        }

        // Hot tail: must absorb one full pipeline stall (signer inequality),
        // must fit under the compiled serving ceiling.
        let stall_window_secs = ACTIVATION_WAIT_CEILING_SECS
            + STALL_PROMOTION_FLOOR_SECS
            + inputs.object_store_class.commit_latency_margin_secs();
        let required_hot_tail = compressed_bytes_per_sec * stall_window_secs;
        if required_hot_tail > HOT_TAIL_SERVING_CEILING_BYTES {
            walls.push(StructuralWall::HotTailServingCeiling {
                required_bytes: required_hot_tail,
                ceiling_bytes: HOT_TAIL_SERVING_CEILING_BYTES,
            });
        }
        let hot_tail_max_bytes = (required_hot_tail * HOT_TAIL_HEADROOM_FACTOR)
            .max(MIN_HOT_TAIL_BYTES)
            .min(HOT_TAIL_SERVING_CEILING_BYTES);

        if !walls.is_empty() {
            return Err(BoundsError::StructuralRefusal { walls });
        }

        // Hour partitioning emits at least one file per closed hour.
        let daily_data_files = ceil_div(compressed_bytes_per_day, compaction_target_bytes).max(24);
        // One registration commit + one compaction rewrite per file, plus
        // hourly maintenance (retention, GC, heartbeat) commits.
        let commits_per_day = 2 * daily_data_files + 48;
        let gc_grace_days = ((SNAPSHOT_ANCESTRY_CEILING / ORDINAL_HEADROOM_DIVISOR)
            / commits_per_day)
            .clamp(1, MAX_GC_GRACE_DAYS);

        // Query serving: leave the client the last word only on margin.
        let max_execution_seconds =
            SHIPPED_MAX_EXECUTION_SECS.min(SEARCH_CLIENT_TIMEOUT_SECS - CLIENT_TIMEOUT_MARGIN_SECS);
        let budget = inputs
            .container_memory_bytes
            .checked_sub(QUERY_RESIDENT_OVERHEAD_BYTES)
            .ok_or(BoundsError::ContainerTooSmall {
                container: inputs.container_memory_bytes,
                concurrency: inputs.interactive_query_concurrency,
                floor: MIN_QUERY_MEMORY_BYTES,
                overhead: QUERY_RESIDENT_OVERHEAD_BYTES,
            })?;
        let per_query_memory_bytes = budget / inputs.interactive_query_concurrency;
        if per_query_memory_bytes < MIN_QUERY_MEMORY_BYTES {
            return Err(BoundsError::ContainerTooSmall {
                container: inputs.container_memory_bytes,
                concurrency: inputs.interactive_query_concurrency,
                floor: MIN_QUERY_MEMORY_BYTES,
                overhead: QUERY_RESIDENT_OVERHEAD_BYTES,
            });
        }
        // NAN-2361: one derivative build gets everything the container has
        // after resident overhead, clamped to the useful range. The value is
        // derived FROM container memory so the coupling that OOM-killed every
        // activation on 2026-08-19 (env-set build ceiling vs actual container
        // limit) is enforced instead of hoped for.
        let derivative_budget = inputs
            .container_memory_bytes
            .checked_sub(DERIVATIVE_RESIDENT_OVERHEAD_BYTES)
            .ok_or(BoundsError::ContainerTooSmall {
                container: inputs.container_memory_bytes,
                concurrency: 1,
                floor: MIN_DERIVATIVE_BUILD_MEMORY_BYTES,
                overhead: DERIVATIVE_RESIDENT_OVERHEAD_BYTES,
            })?;
        let derivative_build_memory_bytes = derivative_budget.clamp(
            MIN_DERIVATIVE_BUILD_MEMORY_BYTES,
            MAX_DERIVATIVE_BUILD_MEMORY_BYTES,
        );

        // Rotation grace must exceed the activation wait by the shipped
        // margin, and the manager caps the wait at 300 s.
        let activation_wait_seconds = ACTIVATION_WAIT_CEILING_SECS
            .min((HOT_TAIL_ROTATION_GRACE_MS - ROTATION_GRACE_MARGIN_MS) / 1000);

        // Soft walls: report where O(table) paths bind for these inputs.
        let mut structural_findings = Vec::new();
        if projected_table_bytes > VERIFICATION_WALL_TABLE_BYTES {
            structural_findings.push(StructuralFinding {
                concern: SoftWall::FullTableReverification,
                binds_at_table_bytes: VERIFICATION_WALL_TABLE_BYTES,
                projected_table_bytes,
                detail: "verified_copy re-hashes every reused object (generation.rs:2359..2372) and \
                         verify_unique_event_uids streams all entity sidecars each promotion \
                         (generation.rs:2770); assumes ~500 MiB/s hashing and a 30 min promotion budget"
                    .to_string(),
            });
            structural_findings.push(StructuralFinding {
                concern: SoftWall::AllOrNothingActivation,
                binds_at_table_bytes: VERIFICATION_WALL_TABLE_BYTES,
                projected_table_bytes,
                detail:
                    "the activation gate is all-or-nothing: while hydration/verification run, no \
                         partial generation serves, so their wall is also an availability wall"
                        .to_string(),
            });
        }
        if projected_table_bytes > HYDRATION_WALL_TABLE_BYTES {
            structural_findings.push(StructuralFinding {
                concern: SoftWall::WholeTableHydration,
                binds_at_table_bytes: HYDRATION_WALL_TABLE_BYTES,
                projected_table_bytes,
                detail: "activation hydrates the whole table locally (generation.rs:720..946); \
                         assumes ~200 MiB/s and a 2 h activation budget"
                    .to_string(),
            });
        }

        let profile = LakeBoundsProfile {
            inputs,
            rows_per_sec,
            compressed_bytes_per_sec,
            compressed_bytes_per_day,
            projected_table_bytes,
            compaction_target_bytes,
            registration_floor_bytes,
            max_pack_rows,
            daily_data_files,
            commits_per_day,
            gc_grace_days,
            stall_window_secs,
            hot_tail_max_bytes,
            max_execution_seconds,
            per_query_memory_bytes,
            derivative_build_memory_bytes,
            activation_wait_seconds,
            ioc_max_input_bytes: IOC_SNAPSHOT_CEILING_BYTES,
            structural_findings,
        };
        // Belt and braces: derivation is supposed to satisfy every
        // inequality by construction; prove it before handing the profile out.
        profile.validate()?;
        Ok(profile)
    }

    /// NAN-2361 two-tier hot tail, Tier A: the staged (not-yet-committed)
    /// object-count envelope the signer refuses past.
    ///
    /// Deliberately a METHOD, not a serialized field: an old binary reads a
    /// profile written by a new one through a `deny_unknown_fields` wire twin,
    /// so a new field would crash every not-yet-upgraded lake process at
    /// startup during a rolling deploy. A pure derivation from existing fields
    /// gives every upgraded consumer the same value with zero wire change.
    ///
    /// Derivation: staged rows are merge-tree packs, at most
    /// `TAIL_PACK_MERGE_FANOUT` unmerged runs per level per event hour
    /// (`lake_tail_pack.rs`), and the tail must ride out one pipeline stall
    /// spanning `ceil(stall_window/3600) + 1` open hours. Floored at the
    /// shipped default so a profile can only widen, never silently narrow,
    /// today's behavior.
    pub fn hot_tail_staged_max_objects(&self) -> u64 {
        let stall_hours = self.stall_window_secs.div_ceil(3_600) + 1;
        (stall_hours * TAIL_PACK_MERGE_FANOUT * (TAIL_PACK_MAX_LEVEL + 1))
            .max(SHIPPED_STAGED_TAIL_MAX_OBJECTS)
    }

    /// NAN-2361 two-tier hot tail, Tier B: the committed-but-not-yet-indexed
    /// object-count bound. Committed objects are already durable in Iceberg
    /// and correctness-served by the full unfenced tail scan, so their BYTES
    /// are governed by the per-query scan budget, not a publication envelope;
    /// only the exact-object plan shape needs a count bound. Give the
    /// committed tier all format headroom the staged envelope leaves.
    pub fn hot_tail_committed_max_objects(&self) -> u64 {
        HOT_TAIL_OBJECT_FORMAT_CEILING.saturating_sub(self.hot_tail_staged_max_objects())
    }

    /// Whether this size is a clean yes or a yes-with-an-availability-caveat.
    pub fn verdict(&self) -> Verdict {
        if self.structural_findings.is_empty() {
            Verdict::Deliverable
        } else {
            Verdict::DeliverableWithDegradation
        }
    }

    /// Assert EVERY cross-layer inequality. Called by `derive`, and callable
    /// on a profile deserialized from worker.json (operators hand-edit).
    pub fn validate(&self) -> Result<(), BoundsError> {
        // 1. THE NAN-2361 outage inequality: a full pack must clear the
        //    compactor's registration floor, or the tail never drains.
        let full_pack_bytes = self.max_pack_rows * self.inputs.mean_compressed_row_bytes;
        if full_pack_bytes < self.registration_floor_bytes {
            return Err(BoundsError::PackRegistrationDeadlock {
                max_pack_rows: self.max_pack_rows,
                row_bytes: self.inputs.mean_compressed_row_bytes,
                pack_bytes: full_pack_bytes,
                floor: self.registration_floor_bytes,
            });
        }
        // 2. Pack rows under the compiled rewrite ceiling.
        if self.max_pack_rows > GENERATION_REWRITE_ROWS_CEILING {
            return Err(BoundsError::PackRowsExceedRewriteCeiling {
                max_pack_rows: self.max_pack_rows,
                ceiling: GENERATION_REWRITE_ROWS_CEILING,
            });
        }
        // 3. Compaction target under the pack byte ceiling.
        if self.compaction_target_bytes > PACK_BYTES_CEILING {
            return Err(BoundsError::CompactionTargetExceedsCeiling {
                target: self.compaction_target_bytes,
                ceiling: PACK_BYTES_CEILING,
            });
        }
        if self.max_pack_rows > self.rows_in_flight_max() {
            return Err(BoundsError::PackRowsExceedMemory {
                max_pack_rows: self.max_pack_rows,
                rows_in_flight_max: self.rows_in_flight_max(),
            });
        }
        // 4/5. Hot tail between the signer requirement and the serving ceiling.
        if self.hot_tail_max_bytes > HOT_TAIL_SERVING_CEILING_BYTES {
            return Err(BoundsError::HotTailExceedsServingCeiling {
                hot_tail: self.hot_tail_max_bytes,
                ceiling: HOT_TAIL_SERVING_CEILING_BYTES,
            });
        }
        let required = self.compressed_bytes_per_sec * self.stall_window_secs;
        if self.hot_tail_max_bytes < required {
            return Err(BoundsError::HotTailBufferTooSmall {
                hot_tail: self.hot_tail_max_bytes,
                required,
            });
        }
        // 6/7. Retention file count under both plan-time caps.
        let projected_files = self.daily_data_files * self.inputs.retention_days;
        if projected_files > ICEBERG_DATA_FILE_CEILING {
            return Err(BoundsError::DataFileCapExceeded {
                daily: self.daily_data_files,
                days: self.inputs.retention_days,
                projected: projected_files,
                ceiling: ICEBERG_DATA_FILE_CEILING,
            });
        }
        if projected_files > OBJECT_ORDINAL_CEILING {
            return Err(BoundsError::ObjectOrdinalCapExceeded {
                daily: self.daily_data_files,
                days: self.inputs.retention_days,
                projected: projected_files,
                ceiling: OBJECT_ORDINAL_CEILING,
            });
        }
        // 8. Ancestry walk stays under its safety bound for the whole grace.
        let ancestry = self.gc_grace_days * self.commits_per_day;
        if ancestry > SNAPSHOT_ANCESTRY_CEILING {
            return Err(BoundsError::AncestryCapExceeded {
                grace: self.gc_grace_days,
                commits: self.commits_per_day,
                projected: ancestry,
                ceiling: SNAPSHOT_ANCESTRY_CEILING,
            });
        }
        // 9. Worker deadline fires before the search client hangs up.
        if self.max_execution_seconds + CLIENT_TIMEOUT_MARGIN_SECS > SEARCH_CLIENT_TIMEOUT_SECS {
            return Err(BoundsError::ExecutionExceedsClientTimeout {
                exec: self.max_execution_seconds,
                margin: CLIENT_TIMEOUT_MARGIN_SECS,
                client: SEARCH_CLIENT_TIMEOUT_SECS,
            });
        }
        // 10. Rotation grace stays above the activation wait.
        if self.activation_wait_seconds > ACTIVATION_WAIT_CEILING_SECS {
            return Err(BoundsError::ActivationWaitExceedsCeiling {
                wait: self.activation_wait_seconds,
                ceiling: ACTIVATION_WAIT_CEILING_SECS,
            });
        }
        if self.activation_wait_seconds * 1000 + ROTATION_GRACE_MARGIN_MS
            > HOT_TAIL_ROTATION_GRACE_MS
        {
            return Err(BoundsError::RotationGraceInversion {
                wait: self.activation_wait_seconds,
                margin_ms: ROTATION_GRACE_MARGIN_MS,
                grace_ms: HOT_TAIL_ROTATION_GRACE_MS,
            });
        }
        // 11. IOC input gate never accepts what the snapshot cap can't write.
        if self.ioc_max_input_bytes > IOC_SNAPSHOT_CEILING_BYTES {
            return Err(BoundsError::IocInputExceedsSnapshotCap {
                input: self.ioc_max_input_bytes,
                snapshot: IOC_SNAPSHOT_CEILING_BYTES,
            });
        }
        // 12. Query concurrency fits container memory with resident overhead.
        let total = self.inputs.interactive_query_concurrency * self.per_query_memory_bytes
            + QUERY_RESIDENT_OVERHEAD_BYTES;
        if total > self.inputs.container_memory_bytes {
            return Err(BoundsError::QueryMemoryOvercommit {
                concurrency: self.inputs.interactive_query_concurrency,
                per_query: self.per_query_memory_bytes,
                overhead: QUERY_RESIDENT_OVERHEAD_BYTES,
                total,
                container: self.inputs.container_memory_bytes,
            });
        }
        // 13/14. Derivative-build memory fits its container and clears the
        // floor below which builds abort (NAN-2361: both directions have
        // wedged activation — OOM kill above, chDB Code 241 below).
        if self
            .derivative_build_memory_bytes
            .saturating_add(DERIVATIVE_RESIDENT_OVERHEAD_BYTES)
            > self.inputs.container_memory_bytes
        {
            return Err(BoundsError::DerivativeBuildMemoryOvercommit {
                build: self.derivative_build_memory_bytes,
                overhead: DERIVATIVE_RESIDENT_OVERHEAD_BYTES,
                container: self.inputs.container_memory_bytes,
            });
        }
        if self.derivative_build_memory_bytes < MIN_DERIVATIVE_BUILD_MEMORY_BYTES {
            return Err(BoundsError::DerivativeBuildMemoryBelowFloor {
                build: self.derivative_build_memory_bytes,
                floor: MIN_DERIVATIVE_BUILD_MEMORY_BYTES,
            });
        }
        // 15/16. NAN-2361 two-tier hot tail. Both tiers ride in ONE signed
        // manifest whose exact-object plan shape caps at 4_096 objects, and
        // the committed tier must absorb realistic activation delay or its
        // count bound recreates the activation-coupled ceiling.
        let staged = self.hot_tail_staged_max_objects();
        let committed = self.hot_tail_committed_max_objects();
        let total = staged.saturating_add(committed);
        if total > HOT_TAIL_OBJECT_FORMAT_CEILING {
            return Err(BoundsError::HotTailTierObjectsExceedFormatCeiling {
                staged,
                committed,
                total,
                ceiling: HOT_TAIL_OBJECT_FORMAT_CEILING,
            });
        }
        let committed_required =
            MIN_COMMITTED_TAIL_HEADROOM_DAYS.saturating_mul(self.daily_data_files);
        if committed < committed_required {
            return Err(BoundsError::CommittedTailHeadroomTooSmall {
                committed,
                days: MIN_COMMITTED_TAIL_HEADROOM_DAYS,
                required: committed_required,
                daily: self.daily_data_files,
            });
        }
        Ok(())
    }

    /// True when no soft wall binds — a profile an operator can run without
    /// scheduling structural work.
    pub fn deliverable_without_structural_work(&self) -> bool {
        self.structural_findings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Consumer-side resolution — one precedence rule for every wired process.
// ---------------------------------------------------------------------------

/// Where a resolved operational bound came from, so consumers can log and
/// tests can assert precedence rather than just the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundSource {
    /// An explicit operator override (CLI flag or environment variable).
    ExplicitOverride,
    /// Derived from the deployment's [`LakeBoundsProfile`].
    Profile,
    /// The compiled-in default; behavior identical to before NAN-2361 wiring.
    CompiledDefault,
}

/// NAN-2361: resolve one operational bound with a single precedence rule —
/// explicit operator override > profile-derived > compiled default.
///
/// A conflict between an explicit override and a present profile is LOGGED at
/// error level naming both values, never silently resolved: the override wins
/// (operators must keep an escape hatch), but the disagreement is unmissable.
/// Callers still run their own inequality checks on the resolved value and
/// refuse to start when the profile's inequalities cannot hold — this
/// function only picks the value and reports its provenance.
pub fn resolve_operational_bound(
    name: &str,
    explicit: Option<u64>,
    profile_derived: Option<u64>,
    compiled_default: u64,
) -> (u64, BoundSource) {
    match (explicit, profile_derived) {
        (Some(value), Some(derived)) => {
            if value != derived {
                tracing::error!(
                    bound = name,
                    explicit_override = value,
                    profile_derived = derived,
                    "explicit override disagrees with the deployment bounds profile; \
                     honoring the override (escape hatch) — remove the \
                     override or re-derive the profile so the deployment is sized \
                     in one place"
                );
            }
            (value, BoundSource::ExplicitOverride)
        }
        (Some(value), None) => (value, BoundSource::ExplicitOverride),
        (None, Some(derived)) => {
            tracing::info!(
                bound = name,
                value = derived,
                "bound derived from lake bounds profile"
            );
            (derived, BoundSource::Profile)
        }
        (None, None) => (compiled_default, BoundSource::CompiledDefault),
    }
}

// ---------------------------------------------------------------------------
// Named size classes — what an operator actually picks.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeClass {
    /// ~5 GB/day raw: open-core compose, edge collectors. 365 d retention.
    Edge5GbDay,
    /// ~100 GB/day raw: typical mid-size tenant. 180 d retention.
    Team100GbDay,
    /// ~1 TB/day raw. REFUSED today: the pack-capacity/registration-floor
    /// envelope binds (see the class table test).
    Enterprise1TbDay,
    /// ~30 TB/day raw. REFUSED today: the data-file and compaction-target
    /// ceilings bind. The centralized hot-tail ceiling no longer binds.
    Hyperscale30TbDay,
}

impl SizeClass {
    /// Row widths default to the values MEASURED during the NAN-2361 outage
    /// (248 B compressed, ~800 B raw). A real deployment overrides them from
    /// its own tail measurements — the whole point is that 248 vs 269 decided
    /// whether the deadlock existed.
    pub fn inputs(self) -> LakeBoundsInputs {
        const GIB: u64 = 1_073_741_824;
        let (daily_raw_bytes, retention_days, container, concurrency) = match self {
            SizeClass::Edge5GbDay => (5_000_000_000_u64, 365, 4 * GIB, 2),
            SizeClass::Team100GbDay => (100_000_000_000, 180, 8 * GIB, 4),
            SizeClass::Enterprise1TbDay => (1_000_000_000_000, 90, 32 * GIB, 8),
            SizeClass::Hyperscale30TbDay => (30_000_000_000_000, 30, 128 * GIB, 32),
        };
        LakeBoundsInputs {
            target_ingest_bytes_per_sec: daily_raw_bytes / SECONDS_PER_DAY,
            mean_raw_row_bytes: 800,
            mean_compressed_row_bytes: 248,
            retention_days,
            container_memory_bytes: container,
            interactive_query_concurrency: concurrency,
            object_store_class: ObjectStoreClass::AwsS3,
        }
    }

    pub fn derive(self) -> Result<LakeBoundsProfile, BoundsError> {
        LakeBoundsProfile::derive(self.inputs())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incident_memory_ceiling_and_runtime_fallbacks() {
        assert_eq!(rows_in_flight_max(2 << 30), 91_750);
        assert_eq!(solo_rows_max(2 << 30), 183_500);
        assert_eq!(solo_rows_max(ROW_RESIDENT_OVERHEAD_BYTES), 0);
        assert_eq!(solo_rows_max(0), 0);
        assert_eq!(rows_in_flight_max(ROW_RESIDENT_OVERHEAD_BYTES), 0);
        assert_eq!(resolve_container_memory_bytes(Some("2147483648\n"), Some(8 << 30)), (2 << 30, MemoryProvenance::Cgroup));
        for value in [None, Some("max"), Some("bad"), Some("0")] {
            assert_eq!(resolve_container_memory_bytes(value, Some(4 << 30)), (4 << 30, MemoryProvenance::Profile));
            assert_eq!(resolve_container_memory_bytes(value, None), (2 << 30, MemoryProvenance::CompiledFallback));
        }
        let mut p = baseline();
        p.inputs.container_memory_bytes = 2 << 30;
        p.max_pack_rows = SHIPPED_MAX_PACK_ROWS;
        assert_eq!(p.validate(), Err(BoundsError::PackRowsExceedMemory {
            max_pack_rows: 250_000, rows_in_flight_max: 91_750,
        }));
    }

    #[test]
    fn narrow_rows_expose_the_memory_registration_wall_without_new_wire_fields() {
        let mut inputs = SizeClass::Edge5GbDay.inputs();
        inputs.container_memory_bytes = 2 << 30;
        inputs.mean_compressed_row_bytes = 144;
        let Err(BoundsError::StructuralRefusal { walls }) = LakeBoundsProfile::derive(inputs) else {
            panic!("registration floor cannot fit the memory-safe row capacity");
        };
        assert!(walls.iter().any(|w| matches!(w, StructuralWall::PackRowsExceedMemory {
            required_rows: 116_509, rows_in_flight_max: 91_750,
        })));
        let mut value = serde_json::to_value(baseline()).unwrap();
        assert!(value.get("rows_in_flight_max").is_none());
        value["max_pack_rows"] = serde_json::json!(270_601);
        let upgraded: LakeBoundsProfile = serde_json::from_value(value).unwrap();
        assert_eq!(upgraded.max_pack_rows, 196_608);
        upgraded.validate().unwrap();
    }

    fn baseline() -> LakeBoundsProfile {
        SizeClass::Edge5GbDay
            .derive()
            .expect("edge class must derive")
    }

    // -- size-class table: the concrete numbers, visible and reviewable -----

    #[test]
    fn size_class_edge_5gb_day_values() {
        let p = baseline();
        assert_eq!(p.rows_per_sec, 73); // ceil(57_870 / 800)
        assert_eq!(p.compressed_bytes_per_sec, 18_104); // 73 x 248
        assert_eq!(p.compressed_bytes_per_day, 1_564_185_600);
        assert_eq!(p.projected_table_bytes, 570_927_744_000); // ~571 GB
        assert_eq!(p.compaction_target_bytes, 33_554_432); // 32 MiB floor
        assert_eq!(p.registration_floor_bytes, 16_777_216);
        assert_eq!(p.max_pack_rows, 196_608); // 4 GiB decode ceiling
        assert_eq!(p.daily_data_files, 47);
        assert_eq!(p.daily_data_files * p.inputs.retention_days, 17_155); // <= 100k, <= 65_535
        assert_eq!(p.commits_per_day, 142);
        assert_eq!(p.gc_grace_days, 7);
        assert_eq!(p.stall_window_secs, 420); // 300 + 60 + 60 (AWS S3)
        assert_eq!(p.hot_tail_max_bytes, 67_108_864); // 64 MiB min clamp
        assert_eq!(p.max_execution_seconds, 120);
        assert_eq!(p.per_query_memory_bytes, 1_610_612_736); // (4 GiB - 1 GiB) / 2
        assert_eq!(p.derivative_build_memory_bytes, 2_147_483_648); // 4 GiB - 2 GiB
        assert_eq!(p.activation_wait_seconds, 300);
        assert_eq!(p.ioc_max_input_bytes, 1_073_741_824);
        assert!(p.deliverable_without_structural_work());
    }

    // -- NAN-2361 two-tier hot tail bounds -----------------------------------

    #[test]
    fn tier_bounds_are_derived_and_partition_the_object_format_ceiling() {
        // Edge: 420 s stall -> ceil(420/3600)+1 = 2 open hours x 4 fanout x 16
        // levels = 128, floored at the shipped 256 default.
        let edge = baseline();
        assert_eq!(edge.hot_tail_staged_max_objects(), 256);
        assert_eq!(edge.hot_tail_committed_max_objects(), 4_096 - 256);
        // Team shares the same stall window, so the same staged envelope; the
        // committed tier keeps every remaining format slot.
        let team = SizeClass::Team100GbDay.derive().expect("team derives");
        assert_eq!(team.hot_tail_staged_max_objects(), 256);
        assert_eq!(team.hot_tail_committed_max_objects(), 3_840);
        // The inequalities the tiers must satisfy, asserted directly so a
        // formula edit that breaks either fails here, not in production:
        for profile in [&edge, &team] {
            assert!(
                profile.hot_tail_staged_max_objects() + profile.hot_tail_committed_max_objects()
                    <= HOT_TAIL_OBJECT_FORMAT_CEILING
            );
            assert!(
                profile.hot_tail_committed_max_objects() >= 2 * profile.daily_data_files,
                "committed tier must absorb two days of compaction output"
            );
        }
    }

    #[test]
    fn a_committed_tier_too_small_for_activation_delay_is_refused() {
        // Mutation this catches: dropping (or inverting) the committed-tail
        // headroom inequality in validate(). A profile whose daily file count
        // alone exceeds the committed tier's whole format headroom cannot ride
        // out even two days between activations — publishing it would
        // reinstate the activation-coupled wedge.
        let mut profile = baseline();
        profile.daily_data_files = 2_048; // 2 x 2_048 > 4_096 - 256
                                          // Keep the earlier retention-file-count inequalities satisfied so the
                                          // headroom check is what fires.
        profile.inputs.retention_days = 1;
        let error = profile
            .validate()
            .expect_err("headroom violation must refuse");
        assert!(matches!(
            error,
            BoundsError::CommittedTailHeadroomTooSmall {
                committed: 3_840,
                required: 4_096,
                ..
            }
        ));
    }

    #[test]
    fn size_class_team_100gb_day_values() {
        let p = SizeClass::Team100GbDay
            .derive()
            .expect("team class must derive");
        assert_eq!(p.rows_per_sec, 1_447); // ceil(1_157_407 / 800)
        assert_eq!(p.compressed_bytes_per_sec, 358_856);
        assert_eq!(p.compressed_bytes_per_day, 31_005_158_400); // ~31 GB
        assert_eq!(p.projected_table_bytes, 5_580_928_512_000); // ~5.6 TB
                                                                // NAN-2361: was 170_321_620, sized by the u16 ordinal cap with 2x
                                                                // headroom (ceil(5_580_928_512_000 / 32_767)). 58d94f708 replaced
                                                                // ordinals with a u32 allocator, so that divisor stopped binding and
                                                                // the 100k data-file ceiling now sets the target instead:
                                                                // ceil(5_580_928_512_000 / 50_000) = 111_618_571 (~112 MB files).
        assert_eq!(p.compaction_target_bytes, 111_618_571);
        // Half the target, so it tracks it down: 111_618_571 / 2.
        assert_eq!(p.registration_floor_bytes, 55_809_286);
        // Decode memory limits the nominal 900_150 rows to 406_323;
        // ~101 MB compressed still clears the 56 MB registration floor.
        assert_eq!(p.max_pack_rows, 406_323); // 8 GiB decode ceiling
        // Smaller target files means MORE of them per day -- the cost of
        // dropping the ordinal divisor, and exactly why the 100k data-file
        // ceiling is now the binding term for this class.
        assert_eq!(p.daily_data_files, 278);
        assert_eq!(p.daily_data_files * p.inputs.retention_days, 50_040); // <= 100_000 cap
                                                                          // Rises with the file count for the same reason (smaller objects =>
                                                                          // more commits). Still far under any catalog CAS concern, and the
                                                                          // gc_grace x commit_rate ancestry inequality below still holds.
        assert_eq!(p.commits_per_day, 604);
        assert_eq!(p.gc_grace_days, 7);
        assert_eq!(p.hot_tail_max_bytes, 301_439_040); // 2 x 358_856 x 420, under 1 GiB
        assert_eq!(p.per_query_memory_bytes, 1_879_048_192); // (8 GiB - 1 GiB) / 4
        assert_eq!(p.derivative_build_memory_bytes, 6_442_450_944); // 8 GiB - 2 GiB
                                                                    // Deliverable, but past both O(table) soft walls (~5.6 TB table):
                                                                    // full-table re-verification, all-or-nothing activation, hydration.
        assert!(!p.deliverable_without_structural_work());
        assert_eq!(p.structural_findings.len(), 3);
    }

    #[test]
    fn size_class_enterprise_1tb_day_is_refused_with_named_walls() {
        let err = SizeClass::Enterprise1TbDay
            .derive()
            .expect_err("1 TB/day must refuse today");
        let BoundsError::StructuralRefusal { walls } = err else {
            panic!("expected StructuralRefusal, got {err:?}");
        };
        // Wall 1: the pack the packer can emit (1M rows x 248 B = 248 MB)
        // is below the registration floor the 90 d retention window needs
        // (~426 MB) — the outage deadlock, resurfacing at the row ceiling.
        assert!(
            walls.iter().any(|w| matches!(
                w,
                StructuralWall::PackCapacityBelowRegistrationFloor {
                    max_pack_capacity_bytes: 248_000_000,
                    ..
                }
            )),
            "expected pack-capacity wall in {walls:?}"
        );
        // The old repeated 1 GiB hot-tail literal also refused this class.
        // It is now a centralized 256 GiB ceiling, so only the independent
        // pack-capacity wall remains.
        assert!(
            !walls
                .iter()
                .any(|w| matches!(w, StructuralWall::HotTailServingCeiling { .. })),
            "the retired 1 GiB hot-tail wall resurfaced in {walls:?}"
        );
    }

    #[test]
    fn size_class_hyperscale_30tb_day_is_refused_with_named_walls() {
        let err = SizeClass::Hyperscale30TbDay
            .derive()
            .expect_err("30 TB/day must refuse today");
        let BoundsError::StructuralRefusal { walls } = err else {
            panic!("expected StructuralRefusal, got {err:?}");
        };
        let has = |f: fn(&StructuralWall) -> bool| walls.iter().any(f);
        assert!(has(|w| matches!(
            w,
            StructuralWall::CompactionTargetCeiling { .. }
        )));
        assert!(has(|w| matches!(w, StructuralWall::DataFileCeiling { .. })));
        // NAN-2361: ObjectOrdinalCeiling is deliberately NOT asserted here any
        // more. 58d94f708 replaced u16 sort-position ordinals with a u32
        // allocator, so that wall no longer binds at any realistic size --
        // asserting it would be testing a mirror we have since corrected.
        // 30 TB/day is still refused, by walls that are actually real:
        assert!(has(|w| matches!(w, StructuralWall::DataFileCeiling { .. })));
        assert!(has(|w| matches!(
            w,
            StructuralWall::CompactionTargetCeiling { .. }
        )));
        assert!(
            !has(|w| matches!(w, StructuralWall::HotTailServingCeiling { .. })),
            "the 256 GiB hot-tail ceiling must cover the shipped 30 TB/day stall calculation"
        );
    }

    #[test]
    fn hot_tail_ceiling_is_above_the_observed_one_gib_wedge_and_remains_finite() {
        let mut p = baseline();
        p.hot_tail_max_bytes = 128 * 1_073_741_824;
        assert!(
            p.validate().is_ok(),
            "the 128 GiB campaign envelope must be admissible"
        );
        p.hot_tail_max_bytes = HOT_TAIL_SERVING_CEILING_BYTES + 1;
        assert!(matches!(
            p.validate(),
            Err(BoundsError::HotTailExceedsServingCeiling { .. })
        ));
    }

    // -- regression test for today's outage ---------------------------------

    /// NAN-2361: the production wedge. MAX_PACK_ROWS (250_000,
    /// lake_tail_pack.rs:30) x the measured 248 B/row = 62_000_000 bytes,
    /// below the compactor's 64 MiB registration floor
    /// (lake_tail_compact.rs:495 with the deployed 128 MiB target). This
    /// exact configuration ran in production; it must never validate again.
    #[test]
    fn regression_nan2361_shipped_pack_rows_below_registration_floor_must_fail() {
        let mut p = baseline();
        p.inputs.mean_compressed_row_bytes = 248;
        p.compaction_target_bytes = 128 * 1_048_576;
        p.registration_floor_bytes = (p.compaction_target_bytes + 1) / 2; // 64 MiB
        p.max_pack_rows = SHIPPED_MAX_PACK_ROWS;
        assert_eq!(
            p.validate(),
            Err(BoundsError::PackRegistrationDeadlock {
                max_pack_rows: 250_000,
                row_bytes: 248,
                pack_bytes: 62_000_000,
                floor: 67_108_864,
            })
        );
        // And the break-even the outage hinged on: at >= 269 B/row the same
        // configuration is fine (268.4 B is the exact threshold).
        p.inputs.mean_compressed_row_bytes = 269;
        p.inputs.container_memory_bytes = 8 * 1_073_741_824;
        assert!(p.validate().is_ok());
    }

    // -- one violating profile per inequality --------------------------------

    #[test]
    fn violation_pack_rows_exceed_rewrite_ceiling() {
        let mut p = baseline();
        p.max_pack_rows = GENERATION_REWRITE_ROWS_CEILING + 1;
        assert!(matches!(
            p.validate(),
            Err(BoundsError::PackRowsExceedRewriteCeiling { .. })
        ));
    }

    #[test]
    fn violation_compaction_target_exceeds_ceiling() {
        let mut p = baseline();
        p.compaction_target_bytes = PACK_BYTES_CEILING + 1;
        // Keep the floor consistent, and widen the rows so the deadlock and
        // rewrite-ceiling checks pass — only the target check may fire.
        p.registration_floor_bytes = (p.compaction_target_bytes + 1) / 2;
        p.max_pack_rows = GENERATION_REWRITE_ROWS_CEILING;
        p.inputs.mean_compressed_row_bytes = 4_096; // 1M x 4096 B >= the floor
        assert!(matches!(
            p.validate(),
            Err(BoundsError::CompactionTargetExceedsCeiling { .. })
        ));
    }

    #[test]
    fn violation_hot_tail_exceeds_serving_ceiling() {
        let mut p = baseline();
        p.hot_tail_max_bytes = HOT_TAIL_SERVING_CEILING_BYTES + 1;
        assert!(matches!(
            p.validate(),
            Err(BoundsError::HotTailExceedsServingCeiling { .. })
        ));
    }

    #[test]
    fn violation_hot_tail_buffer_too_small() {
        let mut p = baseline();
        // One stall at 18_104 B/s x 420 s = 7_603_680; anything below wedges.
        p.hot_tail_max_bytes = 7_603_679;
        assert_eq!(
            p.validate(),
            Err(BoundsError::HotTailBufferTooSmall {
                hot_tail: 7_603_679,
                required: 7_603_680
            })
        );
    }

    #[test]
    fn violation_data_file_cap_exceeded() {
        let mut p = baseline();
        p.daily_data_files = 300; // 300 x 365 = 109_500 > 100_000
        assert!(matches!(
            p.validate(),
            Err(BoundsError::DataFileCapExceeded {
                projected: 109_500,
                ..
            })
        ));
    }

    #[test]
    fn violation_object_ordinal_cap_exceeded() {
        // NAN-2361: this fired at 73_000 projected objects against the u16
        // ceiling (65_535). 58d94f708 replaced sort-position ordinals with a
        // u32 allocator, so 73_000 is now unremarkable -- and asserting the
        // old refusal would test a limit the code no longer has.
        //
        // What must remain true: a projection that WOULD have tripped the u16
        // cap now passes, and the ordinal space genuinely reflects u32.
        let mut p = SizeClass::Team100GbDay.derive().expect("team derives");
        p.daily_data_files = 1_000;
        p.inputs.retention_days = 73; // 73_000 objects: over u16, far under u32
        assert!(
            p.validate().is_ok(),
            "73_000 objects tripped the old u16 ordinal cap and must now pass: {:?}",
            p.validate()
        );
        assert!(
            OBJECT_ORDINAL_CEILING > 4_000_000_000,
            "ordinal ceiling must reflect the u32 allocator, not the retired u16 ordinals"
        );

        // The data-file ceiling is what actually binds now, and still does.
        p.daily_data_files = 1_500;
        assert!(
            matches!(
                p.validate(),
                Err(BoundsError::DataFileCapExceeded {
                    projected: 109_500,
                    ..
                })
            ),
            "the 100k data-file ceiling must still refuse: {:?}",
            p.validate()
        );
    }

    #[test]
    fn violation_ancestry_cap_exceeded() {
        let mut p = baseline();
        p.commits_per_day = 20_000;
        p.gc_grace_days = 6; // 120_000 > 100_000
        assert!(matches!(
            p.validate(),
            Err(BoundsError::AncestryCapExceeded {
                projected: 120_000,
                ..
            })
        ));
    }

    #[test]
    fn violation_execution_exceeds_client_timeout() {
        let mut p = baseline();
        p.max_execution_seconds = 125; // 125 + 10 > 130
        assert!(matches!(
            p.validate(),
            Err(BoundsError::ExecutionExceedsClientTimeout { exec: 125, .. })
        ));
    }

    #[test]
    fn violation_activation_wait_exceeds_manager_ceiling() {
        let mut p = baseline();
        p.activation_wait_seconds = 301;
        assert!(matches!(
            p.validate(),
            Err(BoundsError::ActivationWaitExceedsCeiling { wait: 301, .. })
        ));
    }

    #[test]
    fn violation_rotation_grace_inversion() {
        // A profile whose wait fits the manager ceiling can still invert the
        // rotation grace if the margin shrinks; prove the check is separate
        // by shrinking the grace's headroom via a 300 s wait against the
        // mirrored 330 s grace minus a hypothetical larger margin. With the
        // shipped constants, 300 x 1000 + 30_000 == 330_000 exactly — the
        // boundary holds; one more second of wait trips the CEILING check
        // first, so exercise the grace check directly at the boundary.
        let mut p = baseline();
        p.activation_wait_seconds = 300;
        assert!(p.validate().is_ok(), "shipped boundary must hold exactly");
        // Simulate the inversion the inequality guards (a future grace cut):
        // wait such that wait*1000 + margin > grace while wait <= 300.
        // 300_000 + 30_000 = 330_000 is NOT > 330_000; there is no legal wait
        // that trips it with shipped constants — which is precisely the
        // invariant. Assert the arithmetic relationship itself.
        assert!(
            ACTIVATION_WAIT_CEILING_SECS * 1000 + ROTATION_GRACE_MARGIN_MS
                <= HOT_TAIL_ROTATION_GRACE_MS
        );
    }

    #[test]
    fn violation_ioc_input_exceeds_snapshot_cap_shipped_constants() {
        // The SHIPPED pair is violated by construction: 2 GiB input gate
        // (lake_ioc_publish.rs:13) vs 1 GiB snapshot cap (enrichment.rs:30).
        let mut p = baseline();
        p.ioc_max_input_bytes = SHIPPED_IOC_INPUT_GATE_BYTES;
        assert_eq!(
            p.validate(),
            Err(BoundsError::IocInputExceedsSnapshotCap {
                input: 2_147_483_648,
                snapshot: 1_073_741_824,
            })
        );
    }

    #[test]
    fn violation_query_memory_overcommit() {
        let mut p = baseline();
        p.per_query_memory_bytes = 2 * 1_073_741_824; // 2 x 2 GiB + 1 GiB > 4 GiB
        assert!(matches!(
            p.validate(),
            Err(BoundsError::QueryMemoryOvercommit { .. })
        ));
    }

    #[test]
    fn violation_derivative_build_memory_overcommit() {
        // A hand-edited build ceiling above what the container can grant is
        // exactly the coupling that OOM-killed every activation (NAN-2361).
        let mut p = baseline();
        p.derivative_build_memory_bytes = 3 * 1_073_741_824; // + 2 GiB overhead > 4 GiB container
        assert!(matches!(
            p.validate(),
            Err(BoundsError::DerivativeBuildMemoryOvercommit {
                build: 3_221_225_472,
                ..
            })
        ));
    }

    #[test]
    fn violation_derivative_build_memory_below_floor() {
        let mut p = baseline();
        p.derivative_build_memory_bytes = 1_048_576; // 1 MiB: builds abort with Code 241
        assert!(matches!(
            p.validate(),
            Err(BoundsError::DerivativeBuildMemoryBelowFloor {
                build: 1_048_576,
                ..
            })
        ));
    }

    // -- consumer-side precedence -------------------------------------------

    #[test]
    fn resolve_operational_bound_precedence() {
        // Profile derived when no explicit override.
        assert_eq!(
            resolve_operational_bound("x", None, Some(42), 7),
            (42, BoundSource::Profile)
        );
        // Explicit override wins over the profile (escape hatch), including
        // when they disagree (the conflict is logged, not resolved away).
        assert_eq!(
            resolve_operational_bound("x", Some(41), Some(42), 7),
            (41, BoundSource::ExplicitOverride)
        );
        assert_eq!(
            resolve_operational_bound("x", Some(41), None, 7),
            (41, BoundSource::ExplicitOverride)
        );
        // No profile, no override: compiled default, pre-NAN-2361 behavior.
        assert_eq!(
            resolve_operational_bound("x", None, None, 7),
            (7, BoundSource::CompiledDefault)
        );
    }

    #[test]
    fn container_too_small_is_refused() {
        let mut inputs = SizeClass::Edge5GbDay.inputs();
        inputs.container_memory_bytes = 1_073_741_824;
        // Decode memory now binds before the query-worker overhead check.
        let Err(BoundsError::StructuralRefusal { walls }) = LakeBoundsProfile::derive(inputs) else {
            panic!("undersized container must refuse");
        };
        assert!(walls.iter().any(|w| matches!(w, StructuralWall::PackRowsExceedMemory { .. })));
    }

    #[test]
    fn zero_inputs_are_refused() {
        let mut inputs = SizeClass::Edge5GbDay.inputs();
        inputs.mean_compressed_row_bytes = 0;
        assert_eq!(
            LakeBoundsProfile::derive(inputs),
            Err(BoundsError::ZeroInput {
                name: "mean_compressed_row_bytes"
            })
        );
    }

    // -- serde round trip: the profile must survive worker.json --------------

    #[test]
    fn profile_round_trips_through_json() {
        let p = baseline();
        let json = serde_json::to_string_pretty(&p).expect("serialize");
        let back: LakeBoundsProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
        back.validate().expect("deserialized profile revalidates");
    }

    // -- derived profiles satisfy every inequality by construction -----------

    #[test]
    fn every_deliverable_class_validates_and_row_width_sweep_never_deadlocks() {
        // The variable that decided whether today's bug existed at all is the
        // measured row width; sweep it and prove no width can produce a
        // profile that deadlocks — derive() either refuses or satisfies.
        for class in [SizeClass::Edge5GbDay, SizeClass::Team100GbDay] {
            for row_bytes in [64_u64, 128, 200, 248, 269, 512, 1_024, 4_096] {
                let mut inputs = class.inputs();
                inputs.mean_compressed_row_bytes = row_bytes;
                match LakeBoundsProfile::derive(inputs) {
                    Ok(p) => p.validate().unwrap_or_else(|e| {
                        panic!("{class:?} at {row_bytes} B/row derived an invalid profile: {e}")
                    }),
                    Err(BoundsError::StructuralRefusal { .. }) => {} // honest refusal is fine
                    Err(other) => panic!("{class:?} at {row_bytes} B/row: unexpected {other}"),
                }
            }
        }
    }

    #[test]
    fn a_tampered_worker_json_profile_is_rejected_on_deserialize() {
        // NAN-2361 review P1: derive() validates, but consumers read the
        // profile back from worker.json. Deserialization must run the same
        // gate, or a hand-edited file installs unchecked bounds.
        let good = SizeClass::Edge5GbDay.derive().expect("edge derives");
        let json = serde_json::to_string(&good).expect("serialize");

        // Round-trips while it is internally consistent.
        let restored: LakeBoundsProfile = serde_json::from_str(&json).expect("valid profile loads");
        assert_eq!(restored, good);

        // Now tamper exactly as an operator "raising a limit" would: shrink
        // max_pack_rows so a full pack no longer clears the registration
        // floor. This is the 2026-08-19 outage inequality.
        let tampered = json.replace(
            &format!("\"max_pack_rows\":{}", good.max_pack_rows),
            "\"max_pack_rows\":1000",
        );
        assert_ne!(tampered, json, "tamper must actually change the document");
        let err = serde_json::from_str::<LakeBoundsProfile>(&tampered)
            .expect_err("a profile that cannot drain must not deserialize");
        // Assert the SPECIFIC inequality, not just "some error": a loose
        // match here would pass on an unrelated serde failure and quietly
        // stop testing the thing this guard exists for.
        let message = err.to_string();
        assert!(
            message.contains("pack registration deadlock")
                && message.contains("registration_floor_bytes"),
            "rejection must name the NAN-2361 inequality, got: {message}"
        );
    }

    #[test]
    fn soft_walls_downgrade_the_verdict_instead_of_reading_as_a_clean_yes() {
        // NAN-2361 review P2: an O(table) path that binds is an AVAILABILITY
        // wall (the activation gate is all-or-nothing), so a profile carrying
        // findings must not report the same verdict as one carrying none.
        let edge = SizeClass::Edge5GbDay.derive().expect("edge derives");
        assert_eq!(edge.verdict(), Verdict::Deliverable);
        assert!(edge.structural_findings.is_empty());

        let team = SizeClass::Team100GbDay.derive().expect("team derives");
        assert!(
            !team.structural_findings.is_empty(),
            "100 GB/day is known to trip the O(table) maintenance walls"
        );
        assert_eq!(team.verdict(), Verdict::DeliverableWithDegradation);
    }
}
