// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rust-native immutable prevalence derivatives for an event generation.
//!
//! NAN-2361 incremental aggregation. Per-object observation PARTS were already
//! reused by immutable identity, but every promotion re-aggregated ALL parts
//! for the daily history and each window snapshot — Θ(total observation rows),
//! which is why the same derivative build took 104 seconds in the morning and
//! 11 minutes in the afternoon on identical hardware. The build now maintains
//! a global per-day aggregate (`daily/global-daily.parquet`) that is merged
//! forward from the prior snapshot plus only the identity-new parts, and the
//! daily history and window snapshots are derived from that aggregate plus a
//! row-exact raw scan of each window's boundary day.
//!
//! ## What stays exact and what does not
//!
//! - `total_occurrences`, `daily_count`, `first_seen`, `last_seen`,
//!   `is_private`, and the `host_count_saturated` flag are EXACT: they are all
//!   losslessly mergeable (sum / min / max / or), and per-day partial
//!   aggregates are combined without approximation. Late-arriving events with
//!   old timestamps land in identity-new parts and are merged into the day
//!   they belong to — a "closed" day's counts DO change when late data for it
//!   arrives, exactly as a full rebuild would change them.
//! - `host_fingerprints` MEMBERSHIP for an entity with MORE than 65 distinct
//!   hosts is an approximation in BOTH the old and the new build:
//!   `groupUniqArray(65)` keeps an arbitrary 65 under parallel aggregation, so two
//!   full rebuilds of the same corpus could already disagree on which 65
//!   fingerprints survive. The incremental merge (union of per-day capped
//!   sets, re-capped to 65) preserves the exact served semantics — the
//!   distinct-host COUNT is exact up to the 65 cap and the saturation flag is
//!   exact — but may retain a different arbitrary 65 than a full rebuild.
//!   Entities at or below 65 distinct hosts get the exact fingerprint set.
//!
//! ## Incremental state and rolling deploys
//!
//! All incremental state lives in a sidecar file (`incremental.json`) plus the
//! `daily/global-daily.parquet` aggregate. Manifest v3 adds an optional
//! materialized explorer to each window, while the prior-state reader accepts
//! both v2 and v3:
//! - New builder + old snapshot (no sidecar): the global aggregate is rebuilt
//!   from all parts once (same cost as the old full aggregation), and the next
//!   promotion is incremental.
//! - New builder + v2 snapshot with a sidecar: parts and the exact global
//!   aggregate remain carryable; only the new explorer projection is added.
//! - An older binary cannot activate a v3 worker assignment because strict
//!   config decoding rejects the new artifact field. Roll back the active
//!   generation before the binary; do not mix a v3 assignment with a v2
//!   worker.
//!
//! The incremental path is only taken when every part of the prior snapshot is
//! still present (by immutable identity) in the current object set. A retired
//! or rewritten event object makes the carried aggregate a superset of the
//! table, so the build falls back to a full re-aggregation — counts must never
//! include data that left the table.

use anyhow::{bail, Context, Result};
use arrow_array::types::{
    TimestampMicrosecondType, TimestampMillisecondType, TimestampNanosecondType,
    TimestampSecondType,
};
use arrow_array::{
    Array, Int64Array, LargeStringArray, PrimitiveArray, StringArray, StringViewArray, StructArray,
};
use futures::{StreamExt, TryStreamExt};
use hmac::{Hmac, Mac};
use parquet::arrow::arrow_reader::{ParquetRecordBatchReader, ParquetRecordBatchReaderBuilder};
use parquet::file::reader::FileReader;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use slatedb::admin::Admin;
use slatedb::config::{
    CheckpointOptions, CheckpointScope, CompressionCodec, GarbageCollectorDirectoryOptions,
    GarbageCollectorOptions, Settings,
};
use slatedb::object_store::local::LocalFileSystem;
use slatedb::object_store::ObjectStore;
use slatedb::{Db, MergeOperator, MergeOperatorError, WriteBatch};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use crate::generation::ObjectStampManifest;
use crate::native::{file_sha256, NativeConnection};

const VALUE_VERSION: u8 = 1;
const HOST_CAP: usize = 65;
const BATCH_ROWS: usize = 10_000;
const PREVALENCE_MANIFEST_SCHEMA_VERSION: u64 = 3;
const PREVALENCE_DERIVATIVE_CONTRACT_VERSION: &str = "nano-prevalence-derivative-v3";
pub(crate) const PREVALENCE_WINDOWS: &[(&str, i64)] = &[
    ("1h", 3_600),
    ("24h", 86_400),
    ("7d", 604_800),
    ("30d", 2_592_000),
];

/// Incremental sidecar schema. Lives NEXT TO `manifest.json`, never inside it:
/// `lake_generation_activate` deserializes `PrevalenceBuildManifest` with
/// `deny_unknown_fields` and constructs it literally, so growing the manifest
/// would break both old readers of new snapshots and the activation binary.
const PREVALENCE_INCREMENTAL_SCHEMA_VERSION: u64 = 1;
const INCREMENTAL_SIDECAR_FILE: &str = "incremental.json";
const GLOBAL_DAILY_RELATIVE: &str = "daily/global-daily.parquet";

/// Days of per-day aggregate retained, measured back from the event-time
/// watermark. The deepest consumer is the 30d window whose INTERIOR days start
/// at `date(watermark) - 29`; one extra day is kept as slack. Days older than
/// this can never appear in any output of this or any future promotion
/// (the watermark is monotone while the part set only grows), so pruning them
/// is exact, and a late-arriving event older than the horizon is invisible to
/// every output by the same argument.
const GLOBAL_DAILY_RETENTION_DAYS: i64 = 30;
/// Row-group size of the concatenated global aggregate. Day-major order plus
/// modest row groups let `day` filters prune by row-group statistics.
const GLOBAL_DAILY_ROW_GROUP_ROWS: usize = 65_536;

/// Memory ceiling for a derivative-build query, in bytes.
///
/// NAN-2361. These were three different hard-coded literals baked into the SQL
/// text (512 MiB here, 1 GiB in the two builders below) with no stated reason
/// for the difference and no relationship to the memory the process actually
/// has. On 2026-08-19 the 512 MiB one aborted every prevalence build once a
/// single source object grew large enough that reading one column exceeded it
/// — `Code: 241 ... column: metadata.uid`. That blocked generation activation,
/// which is the ONLY path that drains the hot tail, which meant a wedged lake
/// could not recover at all. Raising the container limit did nothing, because
/// this ceiling lives inside the query string.
///
/// A build bound must track the memory the build has, not a number chosen once.
/// `NANO_LAKE_BUILD_MEMORY_BYTES` overrides; the floor keeps a mis-set env from
/// making builds fail in a new way, and the cap keeps one build from claiming a
/// whole worker.
const BUILD_MEMORY_DEFAULT: u64 = 2 * 1024 * 1024 * 1024;
pub const PREVALENCE_BUILD_MEMORY_FLOOR_BYTES: u64 = 512 * 1024 * 1024;
pub const PREVALENCE_BUILD_MEMORY_CEILING_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Minimum query budget for one observation-part child lane.
///
/// This is deliberately higher than the generic build-memory floor above.
/// The 2026-08-24 scale03 1 TB/day gate measured a single bounded-object query
/// at 803.13 MiB; dividing the 6 GiB reservation into eight 768 MiB lanes made
/// the pool fail while the container and host still had ample memory. A second
/// bounded object then crossed 1.50 GiB by one 4.04 MiB allocation. A 2 GiB
/// floor keeps measured headroom and reduces process fanout while staying
/// inside the existing total reservation.
pub const PREVALENCE_PART_LANE_MEMORY_FLOOR_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// One-shot SlateDB loads serve no point/range reads, so their decoded
/// block/metadata cache is disabled. SlateDB configures 640 MiB of decoded
/// cache capacity per database by default; removing it makes a 1.5-GiB lane
/// the conservative equivalent of the prior two-GiB lane without changing
/// the pod envelope.
const PREVALENCE_SLATE_LOAD_LANE_MEMORY_FLOOR_BYTES: u64 = 3 * 512 * 1024 * 1024;
/// Bound native-process fanout independently of the generation's CPU-thread
/// count. A deployment can legitimately give non-chDB stages more than 32
/// threads, while starting hundreds of 432 MiB native runtimes would be a
/// resource-exhaustion bug rather than useful parallelism.
const PREVALENCE_PART_PROCESS_CEILING: usize = 32;
/// Hard ceiling for one native aggregation query. The CLI accepts the same
/// upper bound; deployments normally choose a much smaller host allocation.
const PREVALENCE_AGGREGATE_THREAD_CEILING: usize = 256;

/// NAN-2361: resolve the derivative-build memory ceiling with the standard
/// precedence — explicit `NANO_LAKE_BUILD_MEMORY_BYTES` override > the
/// deployment bounds profile's `derivative_build_memory_bytes` > the compiled
/// default — then clamp into the useful range. The profile value already
/// satisfies `build + resident overhead <= container_memory_bytes`
/// (bounds.rs validation 13), which is the coupling nothing enforced when
/// every activation OOM-killed on 2026-08-19. An env override that exceeds
/// the profile's derivation is honored (the generation container may
/// genuinely have more memory than the profile's worker container) but the
/// disagreement is logged at error level by `resolve_operational_bound`.
fn resolve_build_memory(env_override: Option<u64>, profile_derived: Option<u64>) -> u64 {
    let (bytes, _source) = crate::bounds::resolve_operational_bound(
        "derivative_build_memory_bytes",
        env_override,
        profile_derived,
        BUILD_MEMORY_DEFAULT,
    );
    bytes.clamp(
        PREVALENCE_BUILD_MEMORY_FLOOR_BYTES,
        PREVALENCE_BUILD_MEMORY_CEILING_BYTES,
    )
}

fn build_memory_env_override() -> Option<u64> {
    std::env::var("NANO_LAKE_BUILD_MEMORY_BYTES")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

/// External-aggregation spill threshold derived from the memory ceiling.
///
/// NAN-2361: the spill and temp-disk knobs were hard-coded literals with no
/// relationship to `max_memory_usage` once that became configurable — exactly
/// the class of uncoupled triple that produced the 2026-08-19 outage. The
/// required inequality is `2 * spill < max_memory < temp_disk`: both the
/// group-by and the sort spill threshold must fit under the memory ceiling
/// together, and the temp-disk cap must never be the binding constraint before
/// memory is. `spill = memory / 4` and `temp_disk = memory * 4` satisfy it for
/// every value the clamp in `resolve_build_memory` can produce.
fn spill_bytes(build_memory_bytes: u64) -> u64 {
    (build_memory_bytes / 4).max(1)
}

fn temp_disk_bytes(build_memory_bytes: u64) -> u64 {
    build_memory_bytes.saturating_mul(4)
}

/// Substitute every deployment-coupled limit into a derivative-build statement.
///
/// Textual substitution rather than `format!` on purpose: these statements
/// carry chDB `{name:Type}` parameter placeholders, which a format string
/// would try to interpret. The canonical literals below are the exact spelling
/// used by every template in `DERIVATIVE_SQL_TEMPLATES`; a test asserts that
/// no template retains a canonical literal after substitution.
struct PrevalenceBuildLimits {
    memory_bytes: u64,
    aggregate_threads: usize,
}

fn apply_build_limits(sql: &str, limits: &PrevalenceBuildLimits) -> String {
    let spill = spill_bytes(limits.memory_bytes);
    let temp_disk = temp_disk_bytes(limits.memory_bytes);
    let mut out = sql.to_string();
    for (literal, replacement) in [
        (
            "max_memory_usage=536870912",
            format!("max_memory_usage={}", limits.memory_bytes),
        ),
        (
            "max_memory_usage=1073741824",
            format!("max_memory_usage={}", limits.memory_bytes),
        ),
        (
            "max_bytes_before_external_group_by=268435456",
            format!("max_bytes_before_external_group_by={spill}"),
        ),
        (
            "max_bytes_before_external_sort=268435456",
            format!("max_bytes_before_external_sort={spill}"),
        ),
        (
            "max_temporary_data_on_disk_size_for_query=8589934592",
            format!("max_temporary_data_on_disk_size_for_query={temp_disk}"),
        ),
        (
            "max_threads=4",
            format!("max_threads={}", limits.aggregate_threads),
        ),
    ] {
        out = out.replace(literal, &replacement);
    }
    out
}

/// Extract one immutable event object into a narrow observation part. The
/// exact event-time/source watermark is collected independently from Arrow so
/// even an object with no IP, domain, or hash artifacts remains represented.
const SQL_OBSERVATION_PART: &str = r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
WITH observations AS
(
    SELECT 'ip' kind, metadata.log_source scope, lower(trim(entity)) entity,
           cityHash64(host) host, is_private, time
    FROM
    (
        SELECT arrayJoin(arrayFilter(value -> value != '', __IP_ENTITY_LIST__)) entity,
               lower(trim(__HOST_IP__)) host,
               toUInt8(isIPAddressInRange(entity, '10.0.0.0/8') OR isIPAddressInRange(entity, '172.16.0.0/12') OR isIPAddressInRange(entity, '192.168.0.0/16')) is_private,
               metadata, time
        FROM file({source:String}, Parquet)
    ) WHERE isNotNull(toIPv6OrNull(entity))
    -- NAN-2361: these source paths MUST stay a superset of the ingest stamper's
    -- (`enrichment.rs::artifact_candidates`). They had drifted: the stamper reads
    -- url.hostname / query.hostname / actor.process.file.hashes, none of which
    -- the builder ingested, so every DNS-query domain and actor-process hash was
    -- stamped `is_new: true` at ingest and then could never enter any baseline to
    -- stop being new. An artifact that is permanently novel is noise, and it is
    -- the exact signal an analyst is asked to trust.
    --
    -- The path lists are TOKENS, rendered per source object by
    -- `render_observation_sql` against the columns that object physically
    -- carries. `file(..., Parquet)` infers its schema from the file, so naming a
    -- column the file lacks is a hard UNKNOWN_IDENTIFIER error rather than a
    -- NULL — a superset list that is not schema-aware fails the entire
    -- generation. Superset where the column exists; skip the leg where it does
    -- not.
    UNION ALL
    SELECT 'domain', metadata.log_source, lower(trim(entity)), cityHash64(host), 0, time
    FROM
    (
        SELECT arrayJoin(arrayFilter(value -> value != '', __DOMAIN_ENTITY_LIST__)) entity,
               lower(trim(__HOST_ENDPOINT__)) host,
               metadata, time
        FROM file({source:String}, Parquet)
    ) WHERE position(entity, '.') > 0 AND isNull(toIPv6OrNull(entity))
    UNION ALL
    SELECT 'hash', metadata.log_source, lower(trim(hash_value)), cityHash64(host), 0, time
    FROM
    (
        SELECT arrayJoin(__HASH_VALUE_CONCAT__) hash_value,
               lower(trim(__HOST_ENDPOINT__)) host,
               metadata, time
        FROM file({source:String}, Parquet)
    ) WHERE length(hash_value) IN (32, 40, 64) AND match(lower(hash_value), '^[a-f0-9]+$')
)
SELECT kind, lower(scope) scope, entity, host, toUInt8(is_private) is_private, time
FROM observations
SETTINGS output_format_parquet_compression_method='zstd', output_format_compression_level=6,
         output_format_parquet_write_bloom_filter=1, output_format_parquet_write_page_index=1,
         max_memory_usage=536870912, max_threads=1, max_block_size=16384,
         use_query_cache=0, use_hive_partitioning=0
"#;

/// Shared settings tail for every aggregation statement below. The memory,
/// spill, and temp-disk literals are canonical placeholders replaced by
/// `apply_build_limits`.
///
/// NAN-2614: the two `max_bytes_ratio_before_external_*` settings are zeroed
/// so the absolute thresholds above are the only spill triggers. chDB 26.7
/// defaults both ratios to 0.5, and with the sort ratio set a sort NEVER
/// spilled: measured locally, `ORDER BY` over 20 M observation rows failed
/// at a 1 GiB cap with no temporary file written, while the same statement
/// with the ratio zeroed spilled five runs and finished under the cap.
macro_rules! aggregate_settings {
    () => {
        r#"
SETTINGS output_format_parquet_compression_method='zstd', output_format_compression_level=6,
         output_format_parquet_write_bloom_filter=1, output_format_parquet_write_page_index=1,
         max_memory_usage=1073741824, max_threads=4, max_block_size=16384,
         max_bytes_before_external_group_by=268435456,
         max_bytes_before_external_sort=268435456,
         max_bytes_ratio_before_external_group_by=0,
         max_bytes_ratio_before_external_sort=0,
         max_temporary_data_on_disk_size_for_query=8589934592,
         use_query_cache=0, use_hive_partitioning=0
"#
    };
}

/// Global per-day aggregate, built one bounded SLICE at a time.
///
/// NAN-2614. The global aggregate used to be ONE statement over every
/// observation part (or over the whole prior aggregate plus the delta),
/// `GROUP BY kind, scope, entity, day ORDER BY kind, scope, entity, day`.
/// Its memory grew with the retained data, not with anything the budget
/// controls: on staging tenant1 it crossed chDB's 2 GiB query cap writing
/// `daily/global-daily.parquet` and every generation cycle died there. The
/// spill thresholds did not save it: with chDB's default
/// `max_bytes_ratio_before_external_sort=0.5` the sort never spilled at all,
/// and even with spilling forced the merge of the spilled runs holds one
/// read buffer per run, which again grows with the data.
///
/// `day` is a GROUP BY key, so the aggregate partitions exactly by day, and
/// within a day by a hash of the remaining key. Each slice aggregates one
/// (day, hash bucket) with a row estimate held under a budget-derived target
/// (`global_daily_slice_rows`), and the slices are concatenated into the
/// single artifact by a streaming Parquet copy. No statement ever sees more
/// than one slice, so memory is fixed by the budget however much data the
/// horizon holds. Every column stays exact: a (kind, scope, entity, day)
/// group lives in exactly one slice, and the aggregation inside a slice is
/// the same expression as before.
///
/// The concatenated file is ordered by (day, bucket, kind, scope, entity).
/// Nothing reads it positionally: every consumer filters by `day` and
/// re-aggregates, and day-major order lets Parquet row-group statistics prune
/// those `day` filters. Its bytes are fenced by the sidecar's own digest.
///
/// Day bucketing is pinned to UTC so it cannot drift with the process
/// timezone.
const SQL_GLOBAL_DAILY_SLICE_FULL: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, toDate(time, 'UTC') day,
       arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) host_fingerprints,
       max(is_private) is_private, min(time) first_seen, max(time) last_seen,
       count() daily_count
FROM file({source:String}, Parquet)
WHERE kind != '__meta' AND toDate(time, 'UTC') = toDate({day:String})
  AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
GROUP BY kind, scope, entity, day
ORDER BY kind, scope, entity, day
"#,
    aggregate_settings!()
);

/// Incremental slice: the prior snapshot's aggregate for one (day, bucket)
/// merged with the per-day aggregate of ONLY the identity-new parts that can
/// hold rows for that day. Exact for every column (see module docs); host
/// fingerprints are exact below the 65 cap, and the saturation condition
/// `length = 65` is exact because any capped input set forces the merged
/// union to at least 65 members.
const SQL_GLOBAL_DAILY_SLICE_MERGE: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, day,
       arraySort(groupUniqArrayArray(65)(host_fingerprints)) host_fingerprints,
       max(is_private) is_private, min(first_seen) first_seen, max(last_seen) last_seen,
       sum(daily_count) daily_count
FROM
(
    SELECT kind, scope, entity, day, host_fingerprints, is_private, first_seen, last_seen, daily_count
    FROM file({prior:String}, Parquet)
    WHERE day = toDate({day:String})
      AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
    UNION ALL
    SELECT kind, scope, entity, toDate(time, 'UTC') day,
           arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) host_fingerprints,
           max(is_private) is_private, min(time) first_seen, max(time) last_seen,
           count() daily_count
    FROM file({delta:String}, Parquet)
    WHERE kind != '__meta' AND toDate(time, 'UTC') = toDate({day:String})
      AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
    GROUP BY kind, scope, entity, day
)
GROUP BY kind, scope, entity, day
ORDER BY kind, scope, entity, day
"#,
    aggregate_settings!()
);

/// Incremental slice for a day no identity-new part can touch: the prior
/// aggregate's rows for that (day, bucket) re-emitted unchanged. The prior
/// file holds exactly one row per (kind, scope, entity, day), so no
/// aggregation is needed.
const SQL_GLOBAL_DAILY_SLICE_CARRY: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, day, host_fingerprints, is_private, first_seen, last_seen, daily_count
FROM file({prior:String}, Parquet)
WHERE day = toDate({day:String})
  AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
ORDER BY kind, scope, entity, day
"#,
    aggregate_settings!()
);

/// Rows per retained day of the prior aggregate. Sizes the incremental
/// slices; the result is at most `GLOBAL_DAILY_RETENTION_DAYS + 1` rows.
const SQL_GLOBAL_DAILY_PRIOR_DAY_ROWS: &str = concat!(
    r#"
SELECT toString(day) day_text, count() day_rows
FROM file({prior:String}, Parquet)
WHERE day >= toDate({horizon:String})
GROUP BY day
ORDER BY day
"#,
    aggregate_settings!()
);

/// Daily history is a pure projection of the global aggregate: its boundary is
/// day-aligned by construction, so no raw rows are ever re-read for it.
const SQL_DAILY_HISTORY_FROM_GLOBAL: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, day, daily_count
FROM file({source:String}, Parquet)
WHERE day >= toDate({daily_start:String})
ORDER BY kind, scope, entity, day
"#,
    aggregate_settings!()
);

/// Window snapshot from the global aggregate plus a row-exact raw scan of the
/// window's boundary day. Interior days (`day > edge_day`) lie entirely inside
/// the window, so their per-day aggregates merge exactly; only the day the
/// window boundary cuts through needs raw rows, and only from the parts whose
/// event-time bounds can overlap that day.
const SQL_WINDOW_FROM_GLOBAL_AND_EDGE: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity,
       arraySort(groupUniqArrayArray(65)(hf)) host_fingerprints,
       toUInt8(length(host_fingerprints) = 65) host_count_saturated,
       max(private_flag) is_private, min(first_us) first_seen, max(last_us) last_seen,
       sum(occurrence_count) total_occurrences
FROM
(
    SELECT kind, scope, entity, host_fingerprints hf, is_private private_flag,
           first_seen first_us, last_seen last_us, daily_count occurrence_count
    FROM file({global:String}, Parquet)
    WHERE day > toDate({edge_day:String})
    UNION ALL
    SELECT kind, scope, entity,
           arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) hf,
           max(is_private) private_flag, min(time) first_us, max(time) last_us,
           count() occurrence_count
    FROM file({edge:String}, Parquet)
    WHERE kind != '__meta'
      AND toUnixTimestamp64Micro(time) >= toInt64({start_us:String})
      AND toDate(time, 'UTC') = toDate({edge_day:String})
    GROUP BY kind, scope, entity
)
GROUP BY kind, scope, entity
ORDER BY kind, scope, entity
"#,
    aggregate_settings!()
);

/// Window snapshot when no part overlaps the boundary day (all data is either
/// strictly inside interior days or entirely outside the window).
const SQL_WINDOW_FROM_GLOBAL: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity,
       arraySort(groupUniqArrayArray(65)(host_fingerprints)) host_fingerprints,
       toUInt8(length(host_fingerprints) = 65) host_count_saturated,
       max(is_private) is_private, min(first_seen) first_seen, max(last_seen) last_seen,
       sum(daily_count) total_occurrences
FROM file({global:String}, Parquet)
WHERE day > toDate({edge_day:String})
GROUP BY kind, scope, entity
ORDER BY kind, scope, entity
"#,
    aggregate_settings!()
);

/// Cross-source explorer projection for the common no-deny-list path.
///
/// The scoped window snapshot remains authoritative for point lookups and
/// requests that exclude source types. Repeating this exact aggregation on
/// every default explorer request made latency grow linearly with retention:
/// 16.5 million scoped rows took about seven seconds in scale03. Materialize
/// it once with the immutable generation so serving only scans merged scalars.
const SQL_EXPLORER_FROM_WINDOW: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, entity, length(hosts) AS host_count,
       toUInt8(any_saturated OR length(hosts) = 65) AS saturated,
       private, first_seen, last_seen, total_occurrences
FROM
(
    SELECT kind, entity,
           groupUniqArrayArray(65)(host_fingerprints) AS hosts,
           max(toUInt8(host_count_saturated)) = 1 AS any_saturated,
           max(toUInt8(is_private)) AS private,
           min(first_seen) AS first_seen, max(last_seen) AS last_seen,
           sum(total_occurrences) AS total_occurrences
    FROM file({source:String}, Parquet)
    GROUP BY kind, entity
)
ORDER BY last_seen DESC, kind ASC, entity ASC
"#,
    aggregate_settings!()
);

// ----- NAN-2828: sliced window / explorer aggregation ------------------------
//
// The window snapshots and the explorer projection were each ONE `GROUP BY`
// over the whole window. Spilling happened, but merging the spilled two-level
// aggregation opens every temporary file at once, so the merge's memory grew
// with the data however low the spill threshold was: on staging tenant1 the
// 24h window died at chDB's 2 GiB cap "While executing SourceFromNativeStream",
// and a local 64 M-row repro fails identically. Disabling the ORDER BY or
// `aggregation_memory_efficient_merge_threads=1` does not change that.
//
// The statements below are the SAME aggregations restricted to one hash bucket
// of the GROUP BY key and written, unordered, to a zstd Parquet work file
// (Parquet round-trips every column type here exactly, and an empty bucket
// still writes a readable file; a Native work file is 4x larger uncompressed
// and a compressed empty one is unreadable). A group lives in exactly one bucket,
// so the union of the buckets is exactly the single statement's result. One
// sort-only statement then writes the artifact with the original ORDER BY; the
// ORDER BY key is unique per row, so the rows AND their order are identical to
// the unsliced build. A sort is bounded by its spill runs, not by aggregate
// state, and measured under the same 2 GiB cap it completes where the
// aggregation did not (24h repro: 17 slices, 132 s, 1.2 GiB peak RSS).
//
// One caveat, and it already applied before slicing: for a SATURATED row
// (65 hosts), `groupUniqArray(65)` keeps whichever 65 hosts it happens to see
// first, so `host_fingerprints` on those rows depends on read and spill order.
// Two unsliced runs of the same input at 4 GiB and 8 GiB disagreed on 7,794 of
// 11,817 saturated rows. Every other column, every unsaturated fingerprint
// set, the row set and the row order are exact.

/// One hash bucket of `SQL_WINDOW_FROM_GLOBAL_AND_EDGE`, unordered.
const SQL_WINDOW_FROM_GLOBAL_AND_EDGE_SLICE: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity,
       arraySort(groupUniqArrayArray(65)(hf)) host_fingerprints,
       toUInt8(length(host_fingerprints) = 65) host_count_saturated,
       max(private_flag) is_private, min(first_us) first_seen, max(last_us) last_seen,
       sum(occurrence_count) total_occurrences
FROM
(
    SELECT kind, scope, entity, host_fingerprints hf, is_private private_flag,
           first_seen first_us, last_seen last_us, daily_count occurrence_count
    FROM file({global:String}, Parquet)
    WHERE day > toDate({edge_day:String})
      AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
    UNION ALL
    SELECT kind, scope, entity,
           arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) hf,
           max(is_private) private_flag, min(time) first_us, max(time) last_us,
           count() occurrence_count
    FROM file({edge:String}, Parquet)
    WHERE kind != '__meta'
      AND toUnixTimestamp64Micro(time) >= toInt64({start_us:String})
      AND toDate(time, 'UTC') = toDate({edge_day:String})
      AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
    GROUP BY kind, scope, entity
)
GROUP BY kind, scope, entity
"#,
    aggregate_settings!()
);

/// One hash bucket of `SQL_WINDOW_FROM_GLOBAL`, unordered.
const SQL_WINDOW_FROM_GLOBAL_SLICE: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity,
       arraySort(groupUniqArrayArray(65)(host_fingerprints)) host_fingerprints,
       toUInt8(length(host_fingerprints) = 65) host_count_saturated,
       max(is_private) is_private, min(first_seen) first_seen, max(last_seen) last_seen,
       sum(daily_count) total_occurrences
FROM file({global:String}, Parquet)
WHERE day > toDate({edge_day:String})
  AND cityHash64(kind, scope, entity) % {buckets:UInt64} = {bucket:UInt64}
GROUP BY kind, scope, entity
"#,
    aggregate_settings!()
);

/// Writes the window artifact from its slices with the unsliced ORDER BY.
const SQL_WINDOW_FROM_SLICES: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, host_fingerprints, host_count_saturated, is_private,
       first_seen, last_seen, total_occurrences
FROM file({source:String}, Parquet)
ORDER BY kind, scope, entity
"#,
    aggregate_settings!()
);

/// One hash bucket of `SQL_EXPLORER_FROM_WINDOW`, unordered. The explorer
/// groups by (kind, entity), so that is the bucket key.
const SQL_EXPLORER_FROM_WINDOW_SLICE: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, entity, length(hosts) AS host_count,
       toUInt8(any_saturated OR length(hosts) = 65) AS saturated,
       private, first_seen, last_seen, total_occurrences
FROM
(
    SELECT kind, entity,
           groupUniqArrayArray(65)(host_fingerprints) AS hosts,
           max(toUInt8(host_count_saturated)) = 1 AS any_saturated,
           max(toUInt8(is_private)) AS private,
           min(first_seen) AS first_seen, max(last_seen) AS last_seen,
           sum(total_occurrences) AS total_occurrences
    FROM file({source:String}, Parquet)
    WHERE cityHash64(kind, entity) % {buckets:UInt64} = {bucket:UInt64}
    GROUP BY kind, entity
)
"#,
    aggregate_settings!()
);

/// Writes the explorer artifact from its slices with the unsliced ORDER BY.
const SQL_EXPLORER_FROM_SLICES: &str = concat!(
    r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, entity, host_count, saturated, private, first_seen, last_seen,
       total_occurrences
FROM file({source:String}, Parquet)
ORDER BY last_seen DESC, kind ASC, entity ASC
"#,
    aggregate_settings!()
);

/// Every derivative-build statement, so tests can prove `apply_build_limits`
/// covers each canonical literal in each template. Keep this list in sync when
/// adding a statement — the substitution-completeness test walks it.
#[cfg_attr(not(test), allow(dead_code))]
const DERIVATIVE_SQL_TEMPLATES: &[(&str, &str)] = &[
    ("observation_part", SQL_OBSERVATION_PART),
    ("global_daily_slice_full", SQL_GLOBAL_DAILY_SLICE_FULL),
    ("global_daily_slice_merge", SQL_GLOBAL_DAILY_SLICE_MERGE),
    ("global_daily_slice_carry", SQL_GLOBAL_DAILY_SLICE_CARRY),
    (
        "global_daily_prior_day_rows",
        SQL_GLOBAL_DAILY_PRIOR_DAY_ROWS,
    ),
    ("daily_history_from_global", SQL_DAILY_HISTORY_FROM_GLOBAL),
    (
        "window_from_global_and_edge",
        SQL_WINDOW_FROM_GLOBAL_AND_EDGE,
    ),
    ("window_from_global", SQL_WINDOW_FROM_GLOBAL),
    ("explorer_from_window", SQL_EXPLORER_FROM_WINDOW),
    (
        "window_from_global_and_edge_slice",
        SQL_WINDOW_FROM_GLOBAL_AND_EDGE_SLICE,
    ),
    ("window_from_global_slice", SQL_WINDOW_FROM_GLOBAL_SLICE),
    ("window_from_slices", SQL_WINDOW_FROM_SLICES),
    ("explorer_from_window_slice", SQL_EXPLORER_FROM_WINDOW_SLICE),
    ("explorer_from_slices", SQL_EXPLORER_FROM_SLICES),
];

pub fn derivative_compatibility_contract() -> serde_json::Value {
    serde_json::json!({
        "contract_version": PREVALENCE_DERIVATIVE_CONTRACT_VERSION,
        "manifest_schema_version": PREVALENCE_MANIFEST_SCHEMA_VERSION,
        "value_version": VALUE_VERSION,
        "host_cap": HOST_CAP,
        "windows": PREVALENCE_WINDOWS,
        "daily_history_days": 30,
        "materialized_explorer": "cross-source-v1",
        "normalization": "lower-trim-v1",
        "artifacts": ["ip", "domain", "hash"],
        // NAN-2361: kept in lockstep with the extraction SQL above AND with the
        // ingest stamper's `artifact_candidates`. This list is content-addressed
        // into the derivative contract sha, so adding a source here correctly
        // invalidates existing derivatives and forces a rebuild -- which is
        // required, since baselines built before the addition are blind to the
        // new paths.
        "source_fields": [
            "time",
            "metadata.log_source",
            "device.hostname",
            "src_endpoint.ip",
            "dst_endpoint.ip",
            "src_endpoint.hostname",
            "dst_endpoint.hostname",
            "http_request.url.hostname",
            "url.hostname",
            "query.hostname",
            "file.hashes.value",
            "process.file.hashes.value",
            "actor.process.file.hashes.value",
        ],
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceWindowBuild {
    pub window: String,
    pub snapshot_id: String,
    pub checkpoint_id: uuid::Uuid,
    pub database_path: String,
    pub scan_file: PathBuf,
    pub scan_sha256: String,
    pub scan_bytes: u64,
    pub rows: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explorer: Option<PrevalenceExplorerBuild>,
    pub source_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceExplorerBuild {
    pub scan_file: PathBuf,
    pub scan_sha256: String,
    pub scan_bytes: u64,
    pub rows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceBuildManifest {
    pub schema_version: u64,
    pub tenant_id: String,
    pub event_snapshot_id: i64,
    pub object_stamp_sha256: String,
    #[serde(default)]
    pub parts: Vec<PrevalencePartBuild>,
    #[serde(default)]
    pub reused_source_files: usize,
    #[serde(default)]
    pub built_source_files: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_history: Option<PrevalenceDailyHistoryBuild>,
    pub windows: Vec<PrevalenceWindowBuild>,
}

/// Process-only result emitted by `lake_prevalence_build`. The flattened
/// manifest keeps the manager's existing metrics projection compatible while
/// phase timings remain outside immutable `manifest.json` and therefore do
/// not change the signed serving contract.
#[derive(Debug, Clone, Serialize)]
pub struct PrevalenceGenerationBuildResult {
    #[serde(flatten)]
    pub manifest: PrevalenceBuildManifest,
    pub phase_timings_seconds: PrevalenceBuildPhaseTimings,
    pub slatedb_load_concurrency: usize,
    pub slatedb_unique_loads: usize,
    pub slatedb_reused_loads: usize,
    pub slatedb_incremental_loads: usize,
    pub slatedb_changed_rows: u64,
    pub slatedb_deleted_rows: u64,
    pub window_materializations_reused: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrevalenceBuildPhaseTimings {
    pub observation_parts: f64,
    pub global_daily: f64,
    pub daily_history: f64,
    pub window_materialization: f64,
    pub slatedb_load: f64,
    pub finalization: f64,
    pub total: f64,
}

struct PendingPrevalenceWindowBuild {
    window: String,
    snapshot_id: String,
    database_path: String,
    scan_file: PathBuf,
    scan_sha256: String,
    scan_bytes: u64,
    rows: u64,
    explorer: PrevalenceExplorerBuild,
    source_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrevalenceScanIdentity {
    sha256: String,
    bytes: u64,
    rows: u64,
}

#[derive(Debug)]
struct PendingPrevalenceDatabaseLoad {
    scan_file: PathBuf,
    database_path: String,
    prior: Option<PriorPrevalenceDatabase>,
}

#[derive(Debug, Clone)]
struct PriorPrevalenceDatabase {
    scan_file: PathBuf,
    scan_sha256: String,
    scan_bytes: u64,
    rows: u64,
    database_path: String,
    checkpoint_id: uuid::Uuid,
}

#[derive(Debug)]
struct LoadedPrevalenceDatabase {
    checkpoint_id: uuid::Uuid,
    database_path: String,
    incremental: bool,
    changed_rows: u64,
    deleted_rows: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalencePartBuild {
    pub relative_path: String,
    pub event_object_key: String,
    pub event_object_version: String,
    pub event_object_bytes: u64,
    pub part_file: PathBuf,
    pub part_sha256: String,
    pub part_bytes: u64,
    pub rows: u64,
    pub max_event_time_us: i64,
    pub source_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceDailyHistoryBuild {
    pub scan_file: PathBuf,
    pub scan_sha256: String,
    pub scan_bytes: u64,
    pub rows: u64,
    pub daily_start: String,
}

/// Incremental sidecar (`incremental.json`) carried inside each prevalence
/// snapshot. Purely an optimization artifact: any absent, unreadable, or
/// non-matching sidecar downgrades the next promotion to a full
/// re-aggregation and is logged loudly — it can never change what a build
/// produces, only how much work producing it takes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceIncrementalSidecar {
    pub schema_version: u64,
    pub tenant_id: String,
    pub event_snapshot_id: i64,
    /// Event-time watermark this snapshot's aggregate was built against.
    pub max_event_time_us: i64,
    /// Oldest day retained in `daily/global-daily.parquet` (UTC, `%Y-%m-%d`).
    pub horizon_day: String,
    pub global_daily_sha256: String,
    pub global_daily_bytes: u64,
    pub global_daily_rows: u64,
    /// True when this snapshot's aggregate was merged forward from a prior
    /// aggregate rather than rebuilt from every part.
    pub global_daily_incremental: bool,
    /// Number of identity-new parts merged into the aggregate this build.
    pub delta_source_files: usize,
    /// Per-part minimum event time, used to prune parts from window boundary
    /// scans. A part absent here (or recorded as 0) is treated as "could
    /// overlap anything" — pruning is only ever an optimization.
    pub part_event_time_bounds: Vec<PartEventTimeBound>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartEventTimeBound {
    pub event_object_key: String,
    pub event_object_version: String,
    pub event_object_bytes: u64,
    pub min_event_time_us: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Value {
    hosts: BTreeSet<u64>,
    saturated: bool,
    private: bool,
    first_us: i64,
    last_us: i64,
    occurrences: u64,
}

#[derive(Debug, PartialEq, Eq)]
struct PrevalenceScanRow {
    kind: String,
    scope: String,
    entity: String,
    value: Value,
}

impl PrevalenceScanRow {
    fn identity(&self) -> (&str, &str, &str) {
        (&self.kind, &self.scope, &self.entity)
    }
}

struct PrevalenceScanRows {
    reader: ParquetRecordBatchReader,
    current: std::vec::IntoIter<PrevalenceScanRow>,
}

struct ValueMerge;

impl MergeOperator for ValueMerge {
    fn merge(
        &self,
        _key: &slatedb::bytes::Bytes,
        existing: Option<slatedb::bytes::Bytes>,
        incoming: slatedb::bytes::Bytes,
    ) -> std::result::Result<slatedb::bytes::Bytes, MergeOperatorError> {
        let mut incoming = decode(&incoming).map_err(merge_error)?;
        if let Some(existing) = existing {
            let existing = decode(&existing).map_err(merge_error)?;
            incoming.hosts.extend(existing.hosts);
            incoming.hosts = incoming.hosts.into_iter().take(HOST_CAP).collect();
            incoming.saturated |= existing.saturated || incoming.hosts.len() == HOST_CAP;
            incoming.private |= existing.private;
            incoming.first_us = incoming.first_us.min(existing.first_us);
            incoming.last_us = incoming.last_us.max(existing.last_us);
            incoming.occurrences = incoming
                .occurrences
                .checked_add(existing.occurrences)
                .ok_or_else(|| merge_error(anyhow::anyhow!("prevalence count overflow")))?;
        }
        encode(&incoming)
            .map(slatedb::bytes::Bytes::from)
            .map_err(merge_error)
    }
}

fn merge_error(error: anyhow::Error) -> MergeOperatorError {
    MergeOperatorError::Callback {
        message: error.to_string(),
    }
}

/// Verified prior aggregate available for an incremental carry.
struct PriorGlobalDaily {
    file: PathBuf,
    max_event_time_us: i64,
}

/// Everything usable from a prior snapshot's incremental sidecar.
struct PriorIncrementalState {
    min_event_times: BTreeMap<PrevalenceObjectIdentity, i64>,
    global_daily: Option<PriorGlobalDaily>,
}

/// Production-only process pool for per-object observation extraction. chDB
/// permits one native connection per process, so independent source objects
/// use bounded child processes rather than pretending extra Rust threads can
/// safely share or multiply native connections in one address space.
pub struct PrevalencePartProcessPool<'a> {
    pub binary: &'a Path,
    pub worker_config: &'a Path,
    pub threads: usize,
    pub total_memory_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceObservationPartBuild {
    pub part_sha256: String,
    pub part_bytes: u64,
    pub rows: u64,
    pub min_event_time_us: i64,
    pub max_event_time_us: i64,
    pub source_types: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceObservationPartJob {
    pub source: PathBuf,
    pub output: PathBuf,
}

fn prevalence_part_process_layout(
    requested_threads: usize,
    pending_parts: usize,
    total_memory_bytes: u64,
) -> Result<(usize, u64)> {
    if requested_threads == 0
        || pending_parts == 0
        || !(PREVALENCE_PART_LANE_MEMORY_FLOOR_BYTES..=64_000_000_000).contains(&total_memory_bytes)
    {
        bail!("prevalence part process-pool resources are invalid");
    }
    let memory_lanes =
        usize::try_from(total_memory_bytes / PREVALENCE_PART_LANE_MEMORY_FLOOR_BYTES)?;
    let processes = requested_threads
        .min(pending_parts)
        .min(memory_lanes)
        .min(PREVALENCE_PART_PROCESS_CEILING);
    let lane_memory_bytes =
        (total_memory_bytes / processes as u64).min(PREVALENCE_BUILD_MEMORY_CEILING_BYTES);
    Ok((processes, lane_memory_bytes))
}

fn slatedb_load_concurrency(window_count: usize, total_memory_bytes: u64) -> Result<usize> {
    if window_count == 0
        || !(PREVALENCE_SLATE_LOAD_LANE_MEMORY_FLOOR_BYTES..=64_000_000_000)
            .contains(&total_memory_bytes)
    {
        bail!("prevalence SlateDB load resources are invalid");
    }
    let memory_lanes =
        usize::try_from(total_memory_bytes / PREVALENCE_SLATE_LOAD_LANE_MEMORY_FLOOR_BYTES)?;
    Ok(window_count.min(memory_lanes).max(1))
}

fn prevalence_aggregate_threads(
    requested_threads: usize,
    total_memory_bytes: u64,
) -> Result<usize> {
    if requested_threads == 0
        || !(PREVALENCE_PART_LANE_MEMORY_FLOOR_BYTES..=64_000_000_000).contains(&total_memory_bytes)
    {
        bail!("prevalence aggregate resources are invalid");
    }
    let memory_lanes =
        usize::try_from(total_memory_bytes / PREVALENCE_PART_LANE_MEMORY_FLOOR_BYTES)?;
    Ok(requested_threads
        .min(memory_lanes)
        .min(PREVALENCE_AGGREGATE_THREAD_CEILING)
        .max(1))
}

impl PriorIncrementalState {
    fn empty() -> Self {
        Self {
            min_event_times: BTreeMap::new(),
            global_daily: None,
        }
    }
}

pub async fn build_prevalence_generation(
    connection: &NativeConnection,
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    hmac_key_path: &Path,
    prior_root: Option<&Path>,
    part_process_pool: Option<&PrevalencePartProcessPool<'_>>,
    bounds: Option<&crate::bounds::LakeBoundsProfile>,
) -> Result<PrevalenceGenerationBuildResult> {
    let build_started = Instant::now();
    // NAN-2361: one resolution for every derivative-build statement in this
    // generation. The env override stays the operator escape hatch; the
    // profile supplies the container-coupled value; the compiled default is
    // the pre-profile behavior.
    let build_memory_bytes = resolve_build_memory(
        build_memory_env_override(),
        bounds.map(|profile| profile.derivative_build_memory_bytes),
    );
    // Observation-part children deliberately use one query thread each and
    // gain parallelism through their bounded process pool. Aggregations run
    // on this coordinator connection, so cap their requested CPU parallelism
    // by the same measured two-GiB native-memory lanes. Passing all eight
    // configured threads through a six-GiB build budget produced eight native
    // aggregation states and repeatedly crossed chDB's exact 6-GiB limit.
    let (requested_aggregate_threads, aggregate_memory_bytes) = part_process_pool
        .map(|pool| (pool.threads, pool.total_memory_bytes))
        .unwrap_or((4, build_memory_bytes));
    let aggregate_threads =
        prevalence_aggregate_threads(requested_aggregate_threads, aggregate_memory_bytes)?;
    let build_limits = PrevalenceBuildLimits {
        memory_bytes: build_memory_bytes,
        aggregate_threads,
    };
    if output_root.exists() {
        bail!(
            "prevalence output already exists: {}",
            output_root.display()
        );
    }
    let stamps: ObjectStampManifest = serde_json::from_slice(&std::fs::read(stamp_manifest)?)?;
    let stamp_sha = file_sha256(stamp_manifest)?;
    let hmac_key = trim_ascii(&std::fs::read(hmac_key_path)?).to_vec();
    if hmac_key.len() < 32 || stamps.snapshot_id <= 0 || tenant_id.is_empty() {
        bail!("prevalence generation identity or HMAC key is invalid");
    }
    let source_files = stamps
        .objects
        .iter()
        .map(|object| input_root.join(&object.relative_path))
        .collect::<Vec<_>>();
    if source_files.is_empty() || source_files.iter().any(|path| !path.is_file()) {
        bail!("prevalence generation source is incomplete");
    }
    let candidate = tempfile::Builder::new()
        .prefix(crate::orphan_temp::PREVALENCE_BUILDER_TEMP_PREFIX)
        .tempdir_in(
            output_root
                .parent()
                .context("prevalence output has no parent")?,
        )?;
    // NAN-2830: the candidate sits inside the derivatives tree, where any
    // hidden entry blocks bundle publishing. Hold a liveness lease for the
    // whole build so the next manager reclaims it the moment we die, rather
    // than after the 24-hour age grace.
    let _builder_lease = crate::orphan_temp::BuilderTempLease::acquire(candidate.path())?;
    let parts_root = candidate.path().join("parts");
    std::fs::create_dir(&parts_root)?;
    let prior_parts = prior_prevalence_parts(prior_root, tenant_id)?;
    let prior_state = prior_incremental_state(prior_root, tenant_id, &prior_parts);
    let prior_databases = prior_prevalence_databases(prior_root, tenant_id);
    let observation_parts_started = Instant::now();
    let mut parts = Vec::with_capacity(stamps.objects.len());
    // Minimum event time per part, parallel to `parts`. 0 means unknown
    // (a part reused from a snapshot that predates the sidecar).
    let mut part_min_event_times = Vec::with_capacity(stamps.objects.len());
    let mut reused_source_files = 0_usize;
    let mut resolved = Vec::with_capacity(stamps.objects.len());
    let mut pending = Vec::new();
    for (index, (stamp, source_file)) in stamps.objects.iter().zip(&source_files).enumerate() {
        let destination = parts_root.join(format!("object-{index:04}.parquet"));
        let identity =
            prevalence_object_identity(&stamp.source_uri, &stamp.version_id, stamp.size_bytes);
        let reused = prior_parts
            .get(&identity)
            .filter(|part| verified_part(part).unwrap_or(false));
        if let Some(part) = reused {
            if std::fs::hard_link(&part.part_file, &destination).is_err() {
                std::fs::copy(&part.part_file, &destination)?;
            }
            reused_source_files += 1;
            resolved.push((
                index,
                PrevalencePartBuild {
                    relative_path: stamp.relative_path.clone(),
                    event_object_key: stamp.source_uri.clone(),
                    event_object_version: stamp.version_id.clone(),
                    event_object_bytes: stamp.size_bytes,
                    part_file: destination,
                    part_sha256: part.part_sha256.clone(),
                    part_bytes: part.part_bytes,
                    rows: part.rows,
                    max_event_time_us: part.max_event_time_us,
                    source_types: part.source_types.clone(),
                },
                prior_state
                    .min_event_times
                    .get(&identity)
                    .copied()
                    .unwrap_or(0),
            ));
        } else {
            pending.push((index, stamp.clone(), source_file.clone(), destination));
        }
    }
    let built = if let Some(pool_config) = part_process_pool.filter(|_| !pending.is_empty()) {
        if !pool_config.binary.is_file() || !pool_config.worker_config.is_file() {
            bail!("prevalence part process-pool contract is invalid");
        }
        let (processes, lane_memory_bytes) = prevalence_part_process_layout(
            pool_config.threads,
            pending.len(),
            pool_config.total_memory_bytes,
        )?;
        // Each lane receives a batch, not one process per object. Apart from
        // process-start overhead, this is security-critical performance:
        // NativeChdb::load_verified hashes the 432 MiB executable artifact.
        // One persistent child per lane verifies and loads it once, then
        // processes that lane's sources serially on one supported connection.
        let chunk_size = pending.len().div_ceil(processes);
        let mut batches = Vec::with_capacity(processes);
        for start in (0..pending.len()).step_by(chunk_size) {
            let end = (start + chunk_size).min(pending.len());
            let jobs = pending[start..end]
                .iter()
                .map(|(_, _, source, output)| PrevalenceObservationPartJob {
                    source: source.clone(),
                    output: output.clone(),
                })
                .collect::<Vec<_>>();
            let mut job_file = tempfile::Builder::new()
                .prefix(".prevalence-part-jobs-")
                .suffix(".json")
                .tempfile_in(candidate.path())?;
            serde_json::to_writer(job_file.as_file_mut(), &jobs)?;
            job_file.as_file_mut().flush()?;
            batches.push((job_file, start, end));
        }
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(processes)
            .thread_name(|index| format!("prevalence-part-{index}"))
            .build()
            .context("build bounded prevalence part process pool")?;
        pool.install(|| {
            batches
                .par_iter()
                .map(|(job_file, start, end)| {
                    let output = Command::new(pool_config.binary)
                        .arg("--worker-config")
                        .arg(pool_config.worker_config)
                        .arg("--part-jobs")
                        .arg(job_file.path())
                        .arg("--build-memory-bytes")
                        .arg(lane_memory_bytes.to_string())
                        .output()
                        .context("run isolated prevalence observation builder")?;
                    if !output.status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stderr = stderr.trim();
                        bail!(
                            "prevalence observation builder failed ({status}): {detail}",
                            status = output.status,
                            detail = if stderr.is_empty() {
                                "<empty stderr>"
                            } else {
                                stderr
                            },
                        );
                    }
                    let built: Vec<PrevalenceObservationPartBuild> =
                        serde_json::from_slice(&output.stdout)
                            .context("decode prevalence observation build results")?;
                    let source_batch = &pending[*start..*end];
                    if built.len() != source_batch.len() {
                        bail!("prevalence observation builder returned an incomplete batch");
                    }
                    Ok::<_, anyhow::Error>(
                        source_batch
                            .iter()
                            .zip(built)
                            .map(|((index, stamp, _, destination), built)| {
                                (
                                    *index,
                                    PrevalencePartBuild {
                                        relative_path: stamp.relative_path.clone(),
                                        event_object_key: stamp.source_uri.clone(),
                                        event_object_version: stamp.version_id.clone(),
                                        event_object_bytes: stamp.size_bytes,
                                        part_file: destination.clone(),
                                        part_sha256: built.part_sha256,
                                        part_bytes: built.part_bytes,
                                        rows: built.rows,
                                        max_event_time_us: built.max_event_time_us,
                                        source_types: built.source_types,
                                    },
                                    built.min_event_time_us,
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Result<Vec<_>>>()
                .map(|batches| batches.into_iter().flatten().collect())
        })?
    } else {
        pending
            .iter()
            .map(|(index, stamp, source_file, destination)| {
                let built = build_prevalence_observation_part(
                    connection,
                    source_file,
                    destination,
                    build_memory_bytes,
                )?;
                Ok((
                    *index,
                    PrevalencePartBuild {
                        relative_path: stamp.relative_path.clone(),
                        event_object_key: stamp.source_uri.clone(),
                        event_object_version: stamp.version_id.clone(),
                        event_object_bytes: stamp.size_bytes,
                        part_file: destination.clone(),
                        part_sha256: built.part_sha256,
                        part_bytes: built.part_bytes,
                        rows: built.rows,
                        max_event_time_us: built.max_event_time_us,
                        source_types: built.source_types,
                    },
                    built.min_event_time_us,
                ))
            })
            .collect::<Result<Vec<_>>>()?
    };
    let built_source_files = built.len();
    resolved.extend(built);
    resolved.sort_unstable_by_key(|(index, _, _)| *index);
    for (expected, (index, part, min_event_time_us)) in resolved.into_iter().enumerate() {
        if index != expected {
            bail!("prevalence part ordering is incomplete");
        }
        part_min_event_times.push(min_event_time_us);
        parts.push(part);
    }
    let observation_parts_seconds = observation_parts_started.elapsed().as_secs_f64();
    let source_types = parts
        .iter()
        .flat_map(|part| part.source_types.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if source_types.is_empty() {
        bail!("prevalence generation has no source types");
    }
    let max_time_us = parts
        .iter()
        .map(|part| part.max_event_time_us)
        .max()
        .context("prevalence generation has no event-time watermark")?;
    let watermark_day =
        utc_day(max_time_us).context("prevalence generation maximum event time is invalid")?;
    let horizon_day = watermark_day - chrono::Duration::days(GLOBAL_DAILY_RETENTION_DAYS);
    let daily_start = watermark_day - chrono::Duration::days(29);

    // ----- global per-day aggregate ---------------------------------------
    let current_identities = parts.iter().map(part_identity).collect::<BTreeSet<_>>();
    let prior_identities = prior_parts.keys().cloned().collect::<BTreeSet<_>>();
    // The carried aggregate is exact only if the current object set is a
    // superset of the prior one: a retired or rewritten object would leave
    // its observations inside the carry with nothing to subtract them.
    let eligible_prior_global = match prior_state.global_daily {
        Some(prior_global)
            if !prior_identities.is_empty()
                && prior_identities.is_subset(&current_identities)
                && prior_global.max_event_time_us <= max_time_us =>
        {
            Some(prior_global)
        }
        Some(_) => {
            tracing::info!(
                "prior prevalence aggregate is not carryable (object set shrank or watermark regressed); rebuilding the global aggregate from all parts"
            );
            None
        }
        None => None,
    };
    let work_root = candidate.path().join(".work");
    std::fs::create_dir(&work_root)?;
    std::fs::create_dir(candidate.path().join("daily"))?;
    let global_daily_file = candidate.path().join(GLOBAL_DAILY_RELATIVE);
    let horizon_text = horizon_day.format("%Y-%m-%d").to_string();
    let global_daily_started = Instant::now();
    // NAN-2614: sliced by (day, entity-hash bucket) so no statement's memory
    // grows with the retained data; see `SQL_GLOBAL_DAILY_SLICE_FULL`.
    let slice_rows = global_daily_slice_rows(build_limits.memory_bytes);
    let (global_daily_incremental, delta_source_files, slices) =
        if let Some(prior_global) = eligible_prior_global {
            // Delta selection is by immutable IDENTITY, not by whether the
            // part file happened to be rebuilt: a part rebuilt because its
            // prior file failed verification extracts the identical rows from
            // the identical source object, and those rows are already inside
            // the carried aggregate. Treating "rebuilt" as "new" would count
            // them twice.
            let delta_indexes = delta_part_indexes(&parts, &prior_identities);
            let prior_day_rows = global_daily_prior_day_rows(
                connection,
                &prior_global.file,
                &horizon_text,
                &build_limits,
            )?;
            let slices = plan_global_daily_slices(
                &parts,
                &part_min_event_times,
                &delta_indexes,
                Some(&prior_day_rows),
                horizon_day,
                watermark_day,
                slice_rows,
            )?;
            build_global_daily_slices(
                connection,
                &slices,
                &parts,
                Some(&prior_global.file),
                &work_root,
                &global_daily_file,
                &build_limits,
            )?;
            (true, delta_indexes.len(), slices.len())
        } else {
            let all_indexes = (0..parts.len()).collect::<Vec<_>>();
            let slices = plan_global_daily_slices(
                &parts,
                &part_min_event_times,
                &all_indexes,
                None,
                horizon_day,
                watermark_day,
                slice_rows,
            )?;
            build_global_daily_slices(
                connection,
                &slices,
                &parts,
                None,
                &work_root,
                &global_daily_file,
                &build_limits,
            )?;
            (false, parts.len(), slices.len())
        };
    tracing::info!(
        incremental = global_daily_incremental,
        delta_source_files,
        total_parts = parts.len(),
        slices,
        slice_rows,
        "prevalence global aggregate built"
    );
    let global_daily_seconds = global_daily_started.elapsed().as_secs_f64();
    // NAN-2828: the global aggregate's rows per day size every window slice
    // plan below; one cheap GROUP BY day over the finished artifact.
    let window_slicing = WindowSlicing {
        global_day_rows: global_daily_prior_day_rows(
            connection,
            &global_daily_file,
            &horizon_text,
            &build_limits,
        )?,
        slice_rows,
    };

    // ----- daily history (pure projection, day-aligned, exact) ------------
    let daily_history_started = Instant::now();
    let daily_history_file = candidate.path().join("daily-history.parquet");
    build_daily_history_from_global(
        connection,
        &global_daily_file,
        &daily_history_file,
        &daily_start.format("%Y-%m-%d").to_string(),
        &build_limits,
    )?;
    let daily_history = PrevalenceDailyHistoryBuild {
        scan_sha256: file_sha256(&daily_history_file)?,
        scan_bytes: std::fs::metadata(&daily_history_file)?.len(),
        rows: parquet_rows(&daily_history_file)?,
        scan_file: daily_history_file,
        daily_start: daily_start.format("%Y-%m-%d").to_string(),
    };
    let daily_history_seconds = daily_history_started.elapsed().as_secs_f64();

    // ----- window snapshots ------------------------------------------------
    let window_materialization_started = Instant::now();
    let mut pending_windows = Vec::with_capacity(PREVALENCE_WINDOWS.len());
    let mut full_coverage_materialization = None::<(PathBuf, PathBuf)>;
    let mut window_materializations_reused = 0_usize;
    for &(window, seconds) in PREVALENCE_WINDOWS {
        let root = candidate.path().join(window);
        std::fs::create_dir_all(&root)?;
        let scan = root.join("snapshot.parquet");
        let start_us = max_time_us - seconds * 1_000_000;
        let explorer_file = root.join("explorer.parquet");
        let covers_every_source_row =
            window_covers_all_source_rows(start_us, &part_min_event_times);
        if covers_every_source_row {
            if let Some((canonical_scan, canonical_explorer)) =
                full_coverage_materialization.as_ref()
            {
                link_or_copy(canonical_scan, &scan)?;
                link_or_copy(canonical_explorer, &explorer_file)?;
                window_materializations_reused = window_materializations_reused
                    .checked_add(1)
                    .context("prevalence reused-window count overflow")?;
                tracing::info!(
                    window,
                    canonical_scan = %canonical_scan.display(),
                    "prevalence full-coverage window reused an exact materialization"
                );
            } else {
                build_prevalence_window(
                    connection,
                    &global_daily_file,
                    &work_root,
                    &parts,
                    &part_min_event_times,
                    window,
                    start_us,
                    &scan,
                    &build_limits,
                    &window_slicing,
                )?;
                build_explorer_from_window(
                    connection,
                    &scan,
                    &work_root,
                    &explorer_file,
                    &build_limits,
                    &window_slicing,
                )?;
                full_coverage_materialization = Some((scan.clone(), explorer_file.clone()));
            }
        } else {
            build_prevalence_window(
                connection,
                &global_daily_file,
                &work_root,
                &parts,
                &part_min_event_times,
                window,
                start_us,
                &scan,
                &build_limits,
                &window_slicing,
            )?;
            build_explorer_from_window(
                connection,
                &scan,
                &work_root,
                &explorer_file,
                &build_limits,
                &window_slicing,
            )?;
        }
        let rows = parquet_rows(&scan)?;
        let explorer = PrevalenceExplorerBuild {
            scan_sha256: file_sha256(&explorer_file)?,
            scan_bytes: std::fs::metadata(&explorer_file)?.len(),
            rows: parquet_rows(&explorer_file)?,
            scan_file: explorer_file,
        };
        let database_path = object_store_path(&root.join("slatedb"))?;
        let scan_sha256 = file_sha256(&scan)?;
        pending_windows.push(PendingPrevalenceWindowBuild {
            window: window.to_string(),
            // Stable deployment alias. The worker's composite generation,
            // checkpoint UUID, scan digest, and ArcSwap request pinning carry
            // the immutable version. A stable alias avoids restarting API
            // pods after every prevalence publication.
            snapshot_id: format!("prevalence-{tenant_id}-{window}"),
            database_path,
            scan_file: scan,
            scan_sha256,
            scan_bytes: std::fs::metadata(root.join("snapshot.parquet"))?.len(),
            rows,
            explorer,
            source_types: source_types.clone(),
        });
    }
    let window_materialization_seconds = window_materialization_started.elapsed().as_secs_f64();

    // These databases are immutable, disjoint, and derived from already
    // materialized scans. Loading them serially left one core busy while the
    // other 63 scale03 cores were idle. Each write-only loader disables the
    // default 640-MiB decoded read cache, so four measured 1.5-GiB lanes fit
    // the same six-GiB derivative reservation. `buffered` preserves the
    // canonical 1h/24h/7d/30d order even when loads complete out of order.
    let slatedb_memory_bytes = part_process_pool
        .map(|pool| pool.total_memory_bytes)
        .unwrap_or(build_memory_bytes);
    let (database_loads, window_database_indexes) =
        plan_prevalence_database_loads(&pending_windows, &prior_databases);
    let slatedb_unique_loads = database_loads.len();
    let slatedb_reused_loads = pending_windows.len().saturating_sub(slatedb_unique_loads);
    let slatedb_load_concurrency =
        slatedb_load_concurrency(slatedb_unique_loads, slatedb_memory_bytes)?;
    tracing::info!(
        windows = pending_windows.len(),
        unique_loads = slatedb_unique_loads,
        reused_loads = slatedb_reused_loads,
        load_concurrency = slatedb_load_concurrency,
        "prevalence immutable database load plan resolved"
    );
    let slatedb_load_started = Instant::now();
    let loaded_databases = futures::stream::iter(database_loads.into_iter().map(|pending| {
        let hmac_key = &hmac_key;
        async move { load_prevalence_database(pending, hmac_key).await }
    }))
    .buffered(slatedb_load_concurrency)
    .try_collect::<Vec<_>>()
    .await?;
    let slatedb_incremental_loads = loaded_databases
        .iter()
        .filter(|database| database.incremental)
        .count();
    let slatedb_changed_rows = loaded_databases
        .iter()
        .map(|database| database.changed_rows)
        .sum();
    let slatedb_deleted_rows = loaded_databases
        .iter()
        .map(|database| database.deleted_rows)
        .sum();
    let windows = pending_windows
        .into_iter()
        .zip(window_database_indexes)
        .map(|(pending, database_index)| {
            let database = loaded_databases
                .get(database_index)
                .context("prevalence database load plan is incomplete")?;
            Ok(PrevalenceWindowBuild {
                window: pending.window,
                snapshot_id: pending.snapshot_id,
                checkpoint_id: database.checkpoint_id,
                database_path: database.database_path.clone(),
                scan_file: pending.scan_file,
                scan_sha256: pending.scan_sha256,
                scan_bytes: pending.scan_bytes,
                rows: pending.rows,
                explorer: Some(pending.explorer),
                source_types: pending.source_types,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let slatedb_load_seconds = slatedb_load_started.elapsed().as_secs_f64();

    let finalization_started = Instant::now();
    // The work directory only ever held hardlinks into parts/; nothing in the
    // published snapshot may reference it.
    std::fs::remove_dir_all(&work_root)?;

    // ----- sidecar for the NEXT promotion ----------------------------------
    let sidecar = PrevalenceIncrementalSidecar {
        schema_version: PREVALENCE_INCREMENTAL_SCHEMA_VERSION,
        tenant_id: tenant_id.to_string(),
        event_snapshot_id: stamps.snapshot_id,
        max_event_time_us: max_time_us,
        horizon_day: horizon_text,
        global_daily_sha256: file_sha256(&global_daily_file)?,
        global_daily_bytes: std::fs::metadata(&global_daily_file)?.len(),
        global_daily_rows: parquet_rows(&global_daily_file)?,
        global_daily_incremental,
        delta_source_files,
        part_event_time_bounds: parts
            .iter()
            .zip(&part_min_event_times)
            .map(|(part, min)| PartEventTimeBound {
                event_object_key: part.event_object_key.clone(),
                event_object_version: part.event_object_version.clone(),
                event_object_bytes: part.event_object_bytes,
                min_event_time_us: *min,
            })
            .collect(),
    };
    write_json(&candidate.path().join(INCREMENTAL_SIDECAR_FILE), &sidecar)?;

    let mut manifest = PrevalenceBuildManifest {
        schema_version: PREVALENCE_MANIFEST_SCHEMA_VERSION,
        tenant_id: tenant_id.to_string(),
        event_snapshot_id: stamps.snapshot_id,
        object_stamp_sha256: stamp_sha,
        parts,
        reused_source_files,
        built_source_files,
        daily_history: Some(daily_history),
        windows,
    };
    // Paths in the final manifest must point at the final immutable directory,
    // not the temporary publication root.
    for window in &mut manifest.windows {
        let relative_scan = window
            .scan_file
            .strip_prefix(candidate.path())?
            .to_path_buf();
        let database_absolute = Path::new("/").join(&window.database_path);
        let relative_db = database_absolute
            .strip_prefix(candidate.path())?
            .to_path_buf();
        window.scan_file = output_root.join(relative_scan);
        window.database_path = object_store_path(&output_root.join(relative_db))?;
        if let Some(explorer) = window.explorer.as_mut() {
            let relative = explorer
                .scan_file
                .strip_prefix(candidate.path())?
                .to_path_buf();
            explorer.scan_file = output_root.join(relative);
        }
    }
    for part in &mut manifest.parts {
        let relative = part.part_file.strip_prefix(candidate.path())?.to_path_buf();
        part.part_file = output_root.join(relative);
    }
    if let Some(history) = manifest.daily_history.as_mut() {
        let relative_scan = history
            .scan_file
            .strip_prefix(candidate.path())?
            .to_path_buf();
        history.scan_file = output_root.join(relative_scan);
    }
    write_json(&candidate.path().join("manifest.json"), &manifest)?;
    sync_tree(candidate.path())?;
    let candidate_path = candidate.keep();
    std::fs::rename(candidate_path, output_root)?;
    File::open(output_root.parent().expect("parent checked"))?.sync_all()?;
    let finalization_seconds = finalization_started.elapsed().as_secs_f64();
    Ok(PrevalenceGenerationBuildResult {
        manifest,
        phase_timings_seconds: PrevalenceBuildPhaseTimings {
            observation_parts: observation_parts_seconds,
            global_daily: global_daily_seconds,
            daily_history: daily_history_seconds,
            window_materialization: window_materialization_seconds,
            slatedb_load: slatedb_load_seconds,
            finalization: finalization_seconds,
            total: build_started.elapsed().as_secs_f64(),
        },
        slatedb_load_concurrency,
        slatedb_unique_loads,
        slatedb_reused_loads,
        slatedb_incremental_loads,
        slatedb_changed_rows,
        slatedb_deleted_rows,
        window_materializations_reused,
    })
}

type PrevalenceObjectIdentity = (String, String, u64);

fn prevalence_object_identity(
    event_object_key: &str,
    event_object_version: &str,
    event_object_bytes: u64,
) -> PrevalenceObjectIdentity {
    (
        event_object_key.to_string(),
        event_object_version.to_string(),
        event_object_bytes,
    )
}

fn part_identity(part: &PrevalencePartBuild) -> PrevalenceObjectIdentity {
    prevalence_object_identity(
        &part.event_object_key,
        &part.event_object_version,
        part.event_object_bytes,
    )
}

/// Indexes of the parts whose immutable identity is NOT already covered by
/// the carried aggregate. Membership is by IDENTITY, never by whether the part
/// file happened to be rebuilt this promotion.
fn delta_part_indexes(
    parts: &[PrevalencePartBuild],
    prior_identities: &BTreeSet<PrevalenceObjectIdentity>,
) -> Vec<usize> {
    parts
        .iter()
        .enumerate()
        .filter(|(_, part)| !prior_identities.contains(&part_identity(part)))
        .map(|(index, _)| index)
        .collect()
}

/// Parts whose event-time bounds can overlap a window's boundary day
/// `[start_us, edge_day_end_us)`. A part with `max < start_us` has no row in
/// the window at all; a part whose minimum is at or past the end of the
/// boundary day has rows only in interior days, which the global aggregate
/// already covers exactly. An unknown minimum (`<= 0`) is conservatively
/// treated as overlapping — pruning is an optimization, never a filter on
/// correctness.
fn edge_part_indexes(
    parts: &[PrevalencePartBuild],
    part_min_event_times: &[i64],
    start_us: i64,
    edge_day_end_us: i64,
) -> Vec<usize> {
    parts
        .iter()
        .zip(part_min_event_times)
        .enumerate()
        .filter(|(_, (part, min))| {
            part.max_event_time_us >= start_us && (**min <= 0 || **min < edge_day_end_us)
        })
        .map(|(index, _)| index)
        .collect()
}

fn window_covers_all_source_rows(start_us: i64, part_min_event_times: &[i64]) -> bool {
    !part_min_event_times.is_empty()
        && part_min_event_times
            .iter()
            .all(|minimum| *minimum > 0 && start_us <= *minimum)
}

#[allow(clippy::too_many_arguments)]
fn build_prevalence_window(
    connection: &NativeConnection,
    global_daily_file: &Path,
    work_root: &Path,
    parts: &[PrevalencePartBuild],
    part_min_event_times: &[i64],
    window: &str,
    start_us: i64,
    scan: &Path,
    build_limits: &PrevalenceBuildLimits,
    slicing: &WindowSlicing,
) -> Result<()> {
    let edge_day = utc_day(start_us).context("prevalence window boundary is invalid")?;
    let edge_day_end_us = utc_day_start_us(edge_day + chrono::Duration::days(1))?;
    let edge_indexes = edge_part_indexes(parts, part_min_event_times, start_us, edge_day_end_us);
    let edge_day_text = edge_day.format("%Y-%m-%d").to_string();
    // Upper bound on the rows the window's GROUP BY reads: every global row
    // after the edge day plus every row of the parts that can hold the edge
    // day (their time filter can only remove rows).
    let global_rows = slicing.global_rows_after(edge_day);
    let slice_work = work_root.join(format!("window-{window}-slices"));
    if edge_indexes.is_empty() {
        let buckets = slicing.buckets(global_rows);
        tracing::info!(
            window,
            estimated_rows = global_rows,
            buckets,
            "prevalence window slice plan"
        );
        build_window_from_global(
            connection,
            global_daily_file,
            &slice_work,
            scan,
            &edge_day_text,
            build_limits,
            buckets,
        )
    } else {
        let edge_rows = edge_indexes.iter().fold(0_u64, |total, index| {
            total.saturating_add(parts[*index].rows)
        });
        let estimated_rows = global_rows.saturating_add(edge_rows);
        let buckets = slicing.buckets(estimated_rows);
        tracing::info!(
            window,
            estimated_rows,
            buckets,
            "prevalence window slice plan"
        );
        let edge_dir = link_parts(
            &work_root.join(format!("edge-{window}")),
            parts,
            &edge_indexes,
        )?;
        build_window_from_global_and_edge(
            connection,
            global_daily_file,
            &edge_dir,
            &slice_work,
            scan,
            start_us,
            &edge_day_text,
            build_limits,
            buckets,
        )
    }
}

/// NAN-2828: how many hash buckets a window or explorer aggregation is split
/// into. The per-slice row target is the global-daily one
/// (`global_daily_slice_rows`), which was measured for the same
/// `groupUniqArray(65)` aggregate shape.
struct WindowSlicing {
    /// Rows of the global per-day aggregate, per day.
    global_day_rows: BTreeMap<chrono::NaiveDate, u64>,
    slice_rows: u64,
}

impl WindowSlicing {
    fn global_rows_after(&self, edge_day: chrono::NaiveDate) -> u64 {
        self.global_day_rows
            .range(edge_day.succ_opt().unwrap_or(chrono::NaiveDate::MAX)..)
            .fold(0_u64, |total, (_, rows)| total.saturating_add(*rows))
    }

    fn buckets(&self, estimated_rows: u64) -> u64 {
        aggregation_buckets(estimated_rows, self.slice_rows)
    }
}

fn aggregation_buckets(estimated_rows: u64, slice_rows: u64) -> u64 {
    estimated_rows
        .div_ceil(slice_rows.max(1))
        .clamp(1, GLOBAL_DAILY_MAX_BUCKETS_PER_DAY)
}

fn utc_day(us: i64) -> Option<chrono::NaiveDate> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_micros(us).map(|value| value.date_naive())
}

fn utc_day_start_us(day: chrono::NaiveDate) -> Result<i64> {
    Ok(day
        .and_hms_opt(0, 0, 0)
        .context("prevalence day boundary is invalid")?
        .and_utc()
        .timestamp_micros())
}

/// Hardlink the selected parts into a scratch directory so one glob covers
/// exactly that subset. Same filesystem as the candidate, so links are free;
/// copy is the fallback for exotic filesystems.
fn link_parts(
    directory: &Path,
    parts: &[PrevalencePartBuild],
    indexes: &[usize],
) -> Result<PathBuf> {
    std::fs::create_dir_all(directory)?;
    for index in indexes {
        let part = &parts[*index];
        let destination = directory.join(format!("object-{index:04}.parquet"));
        if std::fs::hard_link(&part.part_file, &destination).is_err() {
            std::fs::copy(&part.part_file, &destination)?;
        }
    }
    Ok(directory.to_path_buf())
}

fn link_or_copy(source: &Path, destination: &Path) -> Result<()> {
    if std::fs::hard_link(source, destination).is_err() {
        std::fs::copy(source, destination)?;
    }
    Ok(())
}

fn plan_prevalence_database_loads(
    windows: &[PendingPrevalenceWindowBuild],
    prior_databases: &BTreeMap<String, PriorPrevalenceDatabase>,
) -> (Vec<PendingPrevalenceDatabaseLoad>, Vec<usize>) {
    let mut database_indexes = BTreeMap::<PrevalenceScanIdentity, usize>::new();
    let mut loads = Vec::new();
    let mut window_indexes = Vec::with_capacity(windows.len());
    for window in windows {
        let identity = PrevalenceScanIdentity {
            sha256: window.scan_sha256.clone(),
            bytes: window.scan_bytes,
            rows: window.rows,
        };
        let database_index = *database_indexes.entry(identity).or_insert_with(|| {
            let index = loads.len();
            loads.push(PendingPrevalenceDatabaseLoad {
                scan_file: window.scan_file.clone(),
                database_path: window.database_path.clone(),
                prior: prior_databases.get(&window.window).cloned(),
            });
            index
        });
        window_indexes.push(database_index);
    }
    (loads, window_indexes)
}

fn prior_prevalence_parts(
    prior_root: Option<&Path>,
    tenant_id: &str,
) -> Result<BTreeMap<PrevalenceObjectIdentity, PrevalencePartBuild>> {
    let Some(prior_root) = prior_root else {
        return Ok(BTreeMap::new());
    };
    let manifest_path = prior_root.join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(BTreeMap::new());
    }
    let manifest: PrevalenceBuildManifest = match serde_json::from_slice(&std::fs::read(
        manifest_path,
    )?) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "prior prevalence manifest is incompatible; rebuilding exact parts");
            return Ok(BTreeMap::new());
        }
    };
    if !matches!(manifest.schema_version, 2 | 3)
        || manifest.tenant_id != tenant_id
        || manifest.parts.is_empty()
    {
        return Ok(BTreeMap::new());
    }
    let mut parts = BTreeMap::new();
    for part in manifest.parts {
        let identity = prevalence_object_identity(
            &part.event_object_key,
            &part.event_object_version,
            part.event_object_bytes,
        );
        if part.relative_path.is_empty()
            || part.event_object_key.is_empty()
            || part.event_object_version.is_empty()
            || part.event_object_bytes == 0
            || parts.insert(identity, part).is_some()
        {
            return Ok(BTreeMap::new());
        }
    }
    Ok(parts)
}

/// Resolve only fully verified prior window databases. This is an optional
/// acceleration source: an old manifest, a missing file, or any identity
/// mismatch merely selects the existing full-load path for that window.
fn prior_prevalence_databases(
    prior_root: Option<&Path>,
    tenant_id: &str,
) -> BTreeMap<String, PriorPrevalenceDatabase> {
    let Some(prior_root) = prior_root else {
        return BTreeMap::new();
    };
    let manifest_path = prior_root.join("manifest.json");
    let manifest: PrevalenceBuildManifest = match std::fs::read(&manifest_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<PrevalenceBuildManifest>(&bytes).ok())
    {
        Some(manifest)
            if matches!(manifest.schema_version, 2 | 3) && manifest.tenant_id == tenant_id =>
        {
            manifest
        }
        _ => return BTreeMap::new(),
    };
    let mut databases = BTreeMap::new();
    for window in manifest.windows {
        let database_path = Path::new("/").join(&window.database_path);
        let verified = window.scan_file.is_file()
            && database_path.is_dir()
            && std::fs::metadata(&window.scan_file)
                .map(|metadata| metadata.len() == window.scan_bytes)
                .unwrap_or(false)
            && parquet_rows(&window.scan_file)
                .map(|rows| rows == window.rows)
                .unwrap_or(false)
            && file_sha256(&window.scan_file)
                .map(|sha256| sha256 == window.scan_sha256)
                .unwrap_or(false);
        if !verified {
            tracing::warn!(
                window = %window.window,
                "prior prevalence database failed its immutable scan fence; using a full load"
            );
            continue;
        }
        let prior = PriorPrevalenceDatabase {
            scan_file: window.scan_file,
            scan_sha256: window.scan_sha256,
            scan_bytes: window.scan_bytes,
            rows: window.rows,
            database_path: window.database_path,
            checkpoint_id: window.checkpoint_id,
        };
        if databases.insert(window.window, prior).is_some() {
            tracing::warn!(
                "prior prevalence manifest repeated a window; using a full load for that identity"
            );
            return BTreeMap::new();
        }
    }
    databases
}

/// Load whatever the prior snapshot's sidecar can prove. Every failure mode is
/// a downgrade to the full aggregation path, never an error: the sidecar is an
/// optimization artifact and an old snapshot legitimately has none.
fn prior_incremental_state(
    prior_root: Option<&Path>,
    tenant_id: &str,
    prior_parts: &BTreeMap<PrevalenceObjectIdentity, PrevalencePartBuild>,
) -> PriorIncrementalState {
    let Some(prior_root) = prior_root else {
        return PriorIncrementalState::empty();
    };
    if prior_parts.is_empty() {
        return PriorIncrementalState::empty();
    }
    let sidecar_path = prior_root.join(INCREMENTAL_SIDECAR_FILE);
    if !sidecar_path.is_file() {
        tracing::info!(
            "prior prevalence snapshot has no incremental sidecar; rebuilding the global aggregate from all parts"
        );
        return PriorIncrementalState::empty();
    }
    let sidecar: PrevalenceIncrementalSidecar = match std::fs::read(&sidecar_path)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(anyhow::Error::from))
    {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "prior prevalence incremental sidecar is unreadable; rebuilding the global aggregate from all parts");
            return PriorIncrementalState::empty();
        }
    };
    if sidecar.schema_version != PREVALENCE_INCREMENTAL_SCHEMA_VERSION
        || sidecar.tenant_id != tenant_id
        || sidecar.max_event_time_us <= 0
    {
        tracing::warn!(
            "prior prevalence incremental sidecar identity does not match; rebuilding the global aggregate from all parts"
        );
        return PriorIncrementalState::empty();
    }
    let min_event_times = sidecar
        .part_event_time_bounds
        .iter()
        .map(|bound| {
            (
                prevalence_object_identity(
                    &bound.event_object_key,
                    &bound.event_object_version,
                    bound.event_object_bytes,
                ),
                bound.min_event_time_us,
            )
        })
        .collect::<BTreeMap<_, _>>();
    // The aggregate file itself must byte-verify against the sidecar before
    // it may seed a carry: prevalence feeds detection thresholds, and a
    // silently altered aggregate would be a silently altered detection.
    let global_daily_file = prior_root.join(GLOBAL_DAILY_RELATIVE);
    let verified = global_daily_file.is_file()
        && std::fs::metadata(&global_daily_file)
            .map(|meta| meta.len() == sidecar.global_daily_bytes)
            .unwrap_or(false)
        && sidecar.global_daily_rows > 0
        && file_sha256(&global_daily_file)
            .map(|sha| sha == sidecar.global_daily_sha256)
            .unwrap_or(false);
    if !verified {
        tracing::warn!(
            "prior prevalence global aggregate failed its byte fence; rebuilding the global aggregate from all parts"
        );
        return PriorIncrementalState {
            min_event_times,
            global_daily: None,
        };
    }
    PriorIncrementalState {
        min_event_times,
        global_daily: Some(PriorGlobalDaily {
            file: global_daily_file,
            max_event_time_us: sidecar.max_event_time_us,
        }),
    }
}

fn verified_part(part: &PrevalencePartBuild) -> Result<bool> {
    Ok(part.part_file.is_file()
        && part.part_bytes > 0
        && part.max_event_time_us > 0
        && !part.source_types.is_empty()
        && std::fs::metadata(&part.part_file)?.len() == part.part_bytes
        && file_sha256(&part.part_file)? == part.part_sha256)
}

fn source_metadata(source_file: &Path) -> Result<(i64, i64, Vec<String>)> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(source_file)?)?
        .with_batch_size(BATCH_ROWS)
        .build()?;
    let mut min_event_time_us = None::<i64>;
    let mut max_event_time_us = None::<i64>;
    let mut source_types = BTreeSet::new();
    for batch in reader {
        let batch = batch?;
        let time = column(&batch, "time")?;
        let metadata = column(&batch, "metadata")?
            .as_any()
            .downcast_ref::<StructArray>()
            .context("expected OCSF metadata struct")?;
        let source_index = metadata
            .fields()
            .iter()
            .position(|field| field.name() == "log_source")
            .context("OCSF metadata.log_source is absent")?;
        let sources = metadata.column(source_index);
        for row in 0..batch.num_rows() {
            if let Some(value) = event_time_us(time, row) {
                max_event_time_us = Some(max_event_time_us.map_or(value, |prior| prior.max(value)));
                min_event_time_us = Some(min_event_time_us.map_or(value, |prior| prior.min(value)));
            }
            if let Some(source) = string_value(sources.as_ref(), row) {
                let source = source.trim().to_ascii_lowercase();
                if !source.is_empty() {
                    source_types.insert(source);
                }
            }
        }
    }
    Ok((
        min_event_time_us.context("prevalence source object has no valid OCSF time")?,
        max_event_time_us.context("prevalence source object has no valid OCSF time")?,
        source_types.into_iter().collect(),
    ))
}

fn event_time_us(array: &dyn Array, row: usize) -> Option<i64> {
    if row >= array.len() || array.is_null(row) {
        return None;
    }
    match array.data_type() {
        arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Second, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampSecondType>>()
            .map(|values| values.value(row).saturating_mul(1_000_000)),
        arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Millisecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMillisecondType>>()
            .map(|values| values.value(row).saturating_mul(1_000)),
        arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMicrosecondType>>()
            .map(|values| values.value(row)),
        arrow_schema::DataType::Timestamp(arrow_schema::TimeUnit::Nanosecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampNanosecondType>>()
            .map(|values| values.value(row) / 1_000),
        arrow_schema::DataType::Int64 => array
            .as_any()
            .downcast_ref::<Int64Array>()
            .map(|values| values.value(row)),
        _ => None,
    }
}

fn string_value(array: &dyn Array, row: usize) -> Option<&str> {
    if row >= array.len() || array.is_null(row) {
        return None;
    }
    if let Some(values) = array.as_any().downcast_ref::<StringArray>() {
        return Some(values.value(row));
    }
    if let Some(values) = array.as_any().downcast_ref::<LargeStringArray>() {
        return Some(values.value(row));
    }
    array
        .as_any()
        .downcast_ref::<StringViewArray>()
        .map(|values| values.value(row))
}

/// NAN-2361: artifact source paths for the observation part, resolved against
/// the columns a given immutable object PHYSICALLY carries.
///
/// The build statement reads one Parquet object through `file(..., Parquet)`,
/// which infers its schema from that file. Referencing a column the file does
/// not contain is a hard `UNKNOWN_IDENTIFIER` error, not a NULL — so a single
/// hardcoded path list fails the whole generation the moment one object lacks
/// one column. That is exactly what happened: `url` is absent from this
/// tenant's event schema entirely (57 top-level columns, no `url`), so the
/// `url.hostname` leg added to keep these paths a superset of the ingest
/// stamper's crash-looped the generation manager with
/// "mandatory prevalence builder failed ... Unknown expression or function
/// identifier `url.hostname`", leaving the active generation fenced while
/// /health still read 200.
///
/// Filtering by TOP-LEVEL column keeps the superset property wherever the
/// column exists and degrades to "skip that leg" where it does not — the same
/// contract the query path gets from profile-driven observable resolution.
const OBSERVATION_IP_PATHS: &[&str] = &["src_endpoint.ip", "dst_endpoint.ip"];
/// The generation builder's domain paths, FROZEN at the
/// `nano-prevalence-derivative-v3` contract. NAN-3213 removed
/// `src_endpoint.hostname` from the shared lean list
/// ([`crate::ocsf_domains::PREVALENCE_DOMAIN_PATHS`]); changing this list would
/// change the content-addressed derivative contract and force every generation
/// tenant to rebuild. It stays a SUPERSET of the shared list, which is all the
/// ingest stamper needs (pinned by `generation_domain_paths_cover_the_shared_list`).
const OBSERVATION_DOMAIN_PATHS: &[&str] = &[
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "http_request.url.hostname",
    "url.hostname",
    "query.hostname",
];
const OBSERVATION_HASH_ARRAYS: &[&str] = &[
    "file.hashes",
    "process.file.hashes",
    "actor.process.file.hashes",
];
/// Opening of the per-array projection to hash value strings; the caller
/// appends the array expression and the closing paren. See NAN-3449 in
/// `render_observation_sql`.
const HASH_VALUE_PROJECTION: &str =
    "arrayMap(h -> CAST(tupleElement(h, 'value', NULL), 'Nullable(String)'), ";
/// Host identity for the IP leg (a network row has sidedness) and for the
/// domain/hash legs (endpoint rows do not).
const OBSERVATION_HOST_IP_PATHS: &[&str] = &[
    "device.hostname",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
];
const OBSERVATION_HOST_ENDPOINT_PATHS: &[&str] = &["device.hostname", "src_endpoint.hostname"];

/// Top-level column names physically present in one Parquet object. Read from
/// the file's own metadata (like `parquet_rows`) rather than a chDB probe, so
/// it costs no query and cannot disagree with what `file()` will infer.
fn parquet_top_level_columns(path: &Path) -> Result<std::collections::HashSet<String>> {
    let reader = parquet::file::reader::SerializedFileReader::new(File::open(path)?)?;
    let descr = reader.metadata().file_metadata().schema_descr();
    // Every FULL dotted leaf path the file physically carries, not just the
    // roots. NAN-2361: root-only presence is not enough — `actor` existing does
    // NOT prove `actor.process.file.hashes` exists, so a partially-populated
    // nested struct still rendered a column chDB has never heard of and failed
    // the build with UNKNOWN_IDENTIFIER, which is the exact failure this
    // function exists to prevent. `column(i).path()` gives the leaf's full
    // dotted path; every ancestor prefix is recorded too so a reference to an
    // intermediate struct (`file.hashes`, an Array(Tuple)) also resolves.
    let mut available = std::collections::HashSet::new();
    for index in 0..descr.num_columns() {
        let parts = descr.column(index).path().parts().to_vec();
        for depth in 1..=parts.len() {
            available.insert(parts[..depth].join("."));
        }
    }
    Ok(available)
}

/// A path is usable only when the object carries it. Checked against FULL
/// dotted paths (see `parquet_top_level_columns`), so a present root can no
/// longer vouch for an absent leaf.
fn column_is_available(available: &std::collections::HashSet<String>, path: &str) -> bool {
    if available.contains(path) {
        return true;
    }
    // Parquet flattens a repeated group through synthetic `list.element`
    // levels, so `file.hashes` may appear as `file.hashes.list.element.value`.
    // Treat the logical path as present when any physical leaf descends from it.
    let prefix = format!("{path}.");
    available.iter().any(|column| column.starts_with(&prefix))
}

/// Render the observation statement for the columns this object actually has.
/// A leg whose top-level column is absent is dropped; if every leg of a kind is
/// absent the list renders as an empty array literal, which `arrayFilter`
/// yields zero rows for — the object simply contributes no artifacts of that
/// kind instead of failing the build.
fn render_observation_sql(available: &std::collections::HashSet<String>) -> String {
    let keep = |paths: &[&str]| -> Vec<String> {
        paths
            .iter()
            .filter(|path| column_is_available(available, path))
            .map(|path| (*path).to_string())
            .collect()
    };
    let string_list = |paths: Vec<String>| {
        if paths.is_empty() {
            // TYPED empty array, exactly like the hash arm below. A bare `[]` is
            // `Array(Nothing)`, so `arrayJoin` yields a Nothing-typed `entity`
            // and the expressions wrapping it (`lower(trim(entity))`,
            // `isIPAddressInRange`, `position(entity, '.')`) fail at ANALYSIS
            // time — regardless of row count. That is the whole-generation build
            // failure this schema-awareness exists to prevent, just reached
            // through a different shape: a source with no IP columns at all
            // (endpoint-only Sysmon process/file events).
            "CAST([], 'Array(String)')".to_string()
        } else {
            format!(
                "[{}]",
                paths
                    .iter()
                    .map(|path| format!("coalesce({path}, '')"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    };
    // `coalesce()` needs at least one argument; with no host column at all the
    // identity is the literal 'unknown' bucket rather than a SQL error.
    let host_expr = |paths: Vec<String>| {
        if paths.is_empty() {
            "'unknown'".to_string()
        } else {
            format!(
                "coalesce({}, 'unknown')",
                paths
                    .iter()
                    .map(|path| format!("nullIf({path}, '')"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    };
    let hashes = keep(OBSERVATION_HASH_ARRAYS);
    let hash_concat = if hashes.is_empty() {
        // Typed empty array so `arrayJoin` produces no rows and `hash_value`
        // still has the String type the outer WHERE expects.
        "CAST([], 'Array(Nullable(String))')".to_string()
    } else {
        // NAN-3449: project each hashes array down to its `value` strings
        // BEFORE concatenating. The OCSF fingerprint struct's member set is
        // inferred per column from the first event that populated it, so one
        // object can legitimately carry `file.hashes` as
        // Tuple(algorithm, algorithm_id, value) and `process.file.hashes` as
        // Tuple(algorithm_id, value). Concatenating the raw tuple arrays then
        // has no common supertype (chDB Code 386 NO_COMMON_TYPE) and fails the
        // whole mandatory build. `value` is the only member prevalence reads;
        // `tupleElement(.., NULL)` also tolerates a struct lacking it.
        format!(
            "arrayConcat({})",
            hashes
                .iter()
                .map(|path| format!("{HASH_VALUE_PROJECTION}coalesce({path}, []))"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    SQL_OBSERVATION_PART
        .replace(
            "__IP_ENTITY_LIST__",
            &string_list(keep(OBSERVATION_IP_PATHS)),
        )
        .replace(
            "__DOMAIN_ENTITY_LIST__",
            &string_list(keep(OBSERVATION_DOMAIN_PATHS)),
        )
        .replace("__HASH_VALUE_CONCAT__", &hash_concat)
        .replace("__HOST_IP__", &host_expr(keep(OBSERVATION_HOST_IP_PATHS)))
        .replace(
            "__HOST_ENDPOINT__",
            &host_expr(keep(OBSERVATION_HOST_ENDPOINT_PATHS)),
        )
}

#[cfg(test)]
mod nan2361_observation_schema_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn generation_domain_paths_cover_the_shared_list() {
        for path in crate::ocsf_domains::PREVALENCE_DOMAIN_PATHS {
            assert!(OBSERVATION_DOMAIN_PATHS.contains(path), "{path}");
        }
    }

    fn cols(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| (*n).to_string()).collect()
    }

    /// The live failure: this tenant's event schema has 57 top-level columns and
    /// no `url` at all, so the `url.hostname` leg crash-looped the generation
    /// manager and left the active generation fenced.
    #[test]
    fn absent_top_level_column_is_dropped_not_referenced() {
        let sql = render_observation_sql(&cols(&[
            "time",
            "metadata",
            "device.hostname",
            "src_endpoint.hostname",
            "src_endpoint.ip",
            "dst_endpoint.hostname",
            "dst_endpoint.ip",
            "http_request.url.hostname",
            "query.hostname",
            "file.hashes",
            "process.file.hashes",
            "actor.process.file.hashes",
        ]));
        assert!(
            !sql.contains("coalesce(url.hostname"),
            "url.hostname must not be REFERENCED (it may still appear in the SQL comment): {sql}"
        );
        assert!(
            !sql.contains("__"),
            "an unsubstituted token survived: {sql}"
        );
        // every leg whose column DOES exist must still be present
        for kept in [
            "coalesce(http_request.url.hostname",
            "coalesce(query.hostname",
            "coalesce(src_endpoint.hostname",
            "coalesce(dst_endpoint.hostname",
            "coalesce(src_endpoint.ip",
            "coalesce(file.hashes",
            "coalesce(actor.process.file.hashes",
        ] {
            assert!(sql.contains(kept), "dropped a present path {kept}: {sql}");
        }
    }

    /// `http_request.url.hostname` and `url.hostname` share no top-level column
    /// — dropping `url` must not take the http_request leg with it.
    #[test]
    fn nested_paths_are_keyed_on_their_own_full_path() {
        let sql = render_observation_sql(&cols(&[
            "http_request",
            "http_request.url.hostname",
            "metadata",
            "time",
        ]));
        assert!(sql.contains("coalesce(http_request.url.hostname"));
        assert!(!sql.contains("coalesce(url.hostname"));
    }

    /// NAN-2361 (review): a present ROOT must not vouch for an ABSENT LEAF.
    /// Filtering on the top-level name alone admitted
    /// `actor.process.file.hashes` whenever any `actor.*` column existed, so a
    /// partially-populated nested struct still rendered a nonexistent column
    /// and failed the build — the very failure this filtering prevents.
    #[test]
    fn a_present_root_does_not_vouch_for_an_absent_leaf() {
        // `actor` exists (via actor.user.name) but the process hash leaf does not.
        let available = cols(&["actor", "actor.user.name", "metadata", "time"]);
        assert!(
            !column_is_available(&available, "actor.process.file.hashes"),
            "absent leaf must not be admitted by a present root"
        );
        let sql = render_observation_sql(&available);
        assert!(
            !sql.contains("coalesce(actor.process.file.hashes"),
            "absent leaf must not be REFERENCED (it may appear in the SQL comment): {sql}"
        );
        assert!(!sql.contains("__"), "unsubstituted token: {sql}");
    }

    /// A repeated group is flattened by Parquet into `list.element` levels, so
    /// the logical path must still resolve from its physical descendants.
    #[test]
    fn a_repeated_group_resolves_through_its_flattened_leaves() {
        let available = cols(&["file", "file.hashes.list.element.value", "metadata", "time"]);
        assert!(
            column_is_available(&available, "file.hashes"),
            "logical array path must resolve from its flattened leaf"
        );
    }

    /// NAN-3449: every hashes array is projected to its `value` strings before
    /// the concat, so arrays whose OCSF fingerprint tuples carry different
    /// member sets never have to share a tuple supertype.
    #[test]
    fn hash_arrays_are_projected_to_values_before_concat() {
        let sql = render_observation_sql(&cols(&[
            "time",
            "metadata",
            "file.hashes",
            "process.file.hashes",
            "actor.process.file.hashes",
        ]));
        for path in OBSERVATION_HASH_ARRAYS {
            let projected = format!("{HASH_VALUE_PROJECTION}coalesce({path}, []))");
            assert!(sql.contains(&projected), "{path} not projected: {sql}");
        }
        assert!(
            !sql.contains("arrayConcat(coalesce("),
            "raw tuple arrays must never be concatenated: {sql}"
        );
        assert!(!sql.contains("hash.value"), "tuple member access survived: {sql}");
        assert!(!sql.contains("__"), "unsubstituted token: {sql}");

        let none = render_observation_sql(&cols(&["time", "metadata"]));
        assert!(none.contains("CAST([], 'Array(Nullable(String))')"), "{none}");
    }

    /// A kind with no surviving legs must yield zero rows, not invalid SQL.
    #[test]
    fn a_kind_with_no_available_columns_degrades_to_empty() {
        let sql = render_observation_sql(&cols(&["time", "metadata"]));
        assert!(!sql.contains("__"), "unsubstituted token: {sql}");
        assert!(sql.contains("[]"), "empty entity list expected: {sql}");
        // no host column at all still produces a valid identity expression
        assert!(sql.contains("'unknown'"));
        assert!(
            !sql.contains("coalesce(, "),
            "malformed empty coalesce: {sql}"
        );
    }
}

/// NAN-2869: the observation rows of one local part `data.parquet` as a
/// plain SELECT over `{<source_param>:String}` (no INSERT, no settings), for
/// the query process's exact window edges. Identical legs and entity paths to
/// [`SQL_OBSERVATION_PART`]; the host fingerprint is the part contract's
/// `xxHash64(lower(trim(host)))` (contract 3.3) so edge rows union with the
/// per-part prevalence partials.
pub fn observation_select_sql(source_file: &Path, source_param: &str) -> Result<String> {
    if source_param.is_empty() || !source_param.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        bail!("observation source parameter is invalid");
    }
    let available = parquet_top_level_columns(source_file)?;
    let rendered = render_observation_sql(&available);
    let body = rendered
        .trim_start()
        .strip_prefix("INSERT INTO FUNCTION file({output:String}, Parquet)")
        .context("observation statement lost its INSERT header")?;
    let body = body
        .rsplit_once("\nSETTINGS ")
        .map(|(select, _)| select)
        .context("observation statement lost its settings tail")?;
    if body.matches("cityHash64(host)").count() != 3 {
        bail!("observation statement host fingerprint legs changed");
    }
    Ok(body
        .replace("cityHash64(host)", "xxHash64(host)")
        .replace("{source:String}", &format!("{{{source_param}:String}}")))
}

pub fn build_prevalence_observation_part(
    connection: &NativeConnection,
    source_file: &Path,
    output: &Path,
    build_memory_bytes: u64,
) -> Result<PrevalenceObservationPartBuild> {
    if !(PREVALENCE_BUILD_MEMORY_FLOOR_BYTES..=PREVALENCE_BUILD_MEMORY_CEILING_BYTES)
        .contains(&build_memory_bytes)
        || !source_file.is_file()
        || output.exists()
    {
        bail!("prevalence observation part contract is invalid");
    }
    let (min_event_time_us, max_event_time_us, source_types) = source_metadata(source_file)?;
    let params = [
        ("source", source_file.to_string_lossy().into_owned()),
        ("output", output.to_string_lossy().into_owned()),
    ];
    let available = parquet_top_level_columns(source_file)?;
    let sql = render_observation_sql(&available);
    let limits = PrevalenceBuildLimits {
        memory_bytes: build_memory_bytes,
        aggregate_threads: 1,
    };
    run_build_statement(connection, &sql, &params, output, &limits)?;
    Ok(PrevalenceObservationPartBuild {
        part_sha256: file_sha256(output)?,
        part_bytes: std::fs::metadata(output)?.len(),
        rows: parquet_rows(output)?,
        min_event_time_us,
        max_event_time_us,
        source_types,
    })
}

/// Observation rows one global-daily slice may be planned to aggregate,
/// derived from the per-statement memory budget.
///
/// NAN-2614. Measured with chDB 26.7 on synthetic observation parts in which
/// almost every row is its own (kind, scope, entity, day) group, which is the
/// worst case because nothing collapses. The smallest cap one slice completed
/// under was 110 MiB at 0.5 M rows, 203 MiB at 1 M and 265 MiB at 1.9 M
/// (about 140 B per row). At 512 B per row a 2 GiB budget plans about 4.2 M
/// rows per slice, about 3.5 times that headroom, to allow for wider entities
/// and full 65-host fingerprint arrays in the prior aggregate. The floor keeps
/// a tiny budget from planning millions of slices. The spill settings remain
/// the safety net for a slice whose estimate was low.
const GLOBAL_DAILY_SLICE_BYTES_PER_ROW: u64 = 512;
const GLOBAL_DAILY_SLICE_MIN_ROWS: u64 = 100_000;
/// Upper bound on hash buckets for one day, so a corrupt row estimate cannot
/// plan an unbounded number of statements.
const GLOBAL_DAILY_MAX_BUCKETS_PER_DAY: u64 = 4_096;

fn global_daily_slice_rows(memory_bytes: u64) -> u64 {
    (memory_bytes / GLOBAL_DAILY_SLICE_BYTES_PER_ROW).max(GLOBAL_DAILY_SLICE_MIN_ROWS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GlobalDailySliceSource {
    /// Every raw observation row for the day, from the parts that can hold it.
    Full,
    /// Prior aggregate rows plus the identity-new parts that can hold the day.
    Merge,
    /// Prior aggregate rows only.
    Carry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GlobalDailySlice {
    day: chrono::NaiveDate,
    bucket: u64,
    buckets: u64,
    source: GlobalDailySliceSource,
    /// Parts (indexes into `parts`) whose event-time bounds can overlap `day`.
    part_indexes: Vec<usize>,
}

/// Whether a part's event-time bounds can overlap `[day_start_us, day_end_us)`.
/// An unknown minimum (`<= 0`) is treated as overlapping every day up to the
/// part's maximum: pruning is an optimization, never a correctness filter.
fn part_overlaps_day(max_us: i64, min_us: i64, day_start_us: i64, day_end_us: i64) -> bool {
    max_us >= day_start_us && (min_us <= 0 || min_us < day_end_us)
}

/// Plan the (day, bucket) slices for the global aggregate.
///
/// `raw_indexes` are the parts whose raw rows feed the aggregate (every part
/// for a full build, the identity-new parts for an incremental one).
/// `prior_day_rows` is `None` for a full build. A day's bucket count is its
/// row ESTIMATE divided by `slice_rows`; the estimate charges a part's full
/// row count to every day it can overlap, so it only ever over-slices.
fn plan_global_daily_slices(
    parts: &[PrevalencePartBuild],
    part_min_event_times: &[i64],
    raw_indexes: &[usize],
    prior_day_rows: Option<&BTreeMap<chrono::NaiveDate, u64>>,
    horizon_day: chrono::NaiveDate,
    watermark_day: chrono::NaiveDate,
    slice_rows: u64,
) -> Result<Vec<GlobalDailySlice>> {
    if slice_rows == 0 || horizon_day > watermark_day || parts.len() != part_min_event_times.len() {
        bail!("prevalence global aggregate slice plan inputs are invalid");
    }
    let mut slices = Vec::new();
    let mut day = horizon_day;
    while day <= watermark_day {
        let day_start_us = utc_day_start_us(day)?;
        let day_end_us = utc_day_start_us(day + chrono::Duration::days(1))?;
        let overlapping = raw_indexes
            .iter()
            .copied()
            .filter(|index| {
                part_overlaps_day(
                    parts[*index].max_event_time_us,
                    part_min_event_times[*index],
                    day_start_us,
                    day_end_us,
                )
            })
            .collect::<Vec<_>>();
        let prior_rows = prior_day_rows
            .and_then(|rows| rows.get(&day).copied())
            .unwrap_or(0);
        let source = match (prior_day_rows.is_some(), overlapping.is_empty()) {
            (false, true) => None,
            (false, false) => Some(GlobalDailySliceSource::Full),
            (true, false) => Some(GlobalDailySliceSource::Merge),
            (true, true) if prior_rows > 0 => Some(GlobalDailySliceSource::Carry),
            (true, true) => None,
        };
        if let Some(source) = source {
            let estimated_rows = overlapping
                .iter()
                .map(|index| parts[*index].rows)
                .fold(prior_rows, u64::saturating_add);
            let buckets = estimated_rows
                .div_ceil(slice_rows)
                .clamp(1, GLOBAL_DAILY_MAX_BUCKETS_PER_DAY);
            for bucket in 0..buckets {
                slices.push(GlobalDailySlice {
                    day,
                    bucket,
                    buckets,
                    source,
                    part_indexes: overlapping.clone(),
                });
            }
        }
        day += chrono::Duration::days(1);
    }
    if slices.is_empty() {
        match prior_day_rows {
            // Nothing inside the horizon at all: one empty carry slice still
            // writes a schema-bearing (zero-row) aggregate.
            Some(_) => slices.push(GlobalDailySlice {
                day: watermark_day,
                bucket: 0,
                buckets: 1,
                source: GlobalDailySliceSource::Carry,
                part_indexes: Vec::new(),
            }),
            // The part holding the watermark always overlaps the watermark day.
            None => bail!("prevalence global aggregate has no part inside the horizon"),
        }
    }
    Ok(slices)
}

fn global_daily_prior_day_rows(
    connection: &NativeConnection,
    prior_global: &Path,
    horizon: &str,
    limits: &PrevalenceBuildLimits,
) -> Result<BTreeMap<chrono::NaiveDate, u64>> {
    let prior = prior_global.to_string_lossy();
    let sql = apply_build_limits(SQL_GLOBAL_DAILY_PRIOR_DAY_ROWS, limits);
    let output = connection
        .query_with_params(
            &sql,
            "TSV",
            &[("prior", prior.as_ref()), ("horizon", horizon)],
        )
        .context("count prior prevalence aggregate rows per day")?;
    let text = std::str::from_utf8(&output.data).context("prior day rows are not UTF-8")?;
    let mut rows = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let (day, count) = line
            .split_once('\t')
            .context("prior day rows line is malformed")?;
        let day = chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d")
            .context("prior day rows day is invalid")?;
        let count = count
            .parse::<u64>()
            .context("prior day rows count is invalid")?;
        if rows.insert(day, count).is_some() {
            bail!("prior day rows repeat a day");
        }
    }
    Ok(rows)
}

/// Run every planned slice, then stream-concatenate the slice files into
/// `output`. Slice files and per-day part links live under `work_root` and are
/// removed as soon as they are consumed.
fn build_global_daily_slices(
    connection: &NativeConnection,
    slices: &[GlobalDailySlice],
    parts: &[PrevalencePartBuild],
    prior_global: Option<&Path>,
    work_root: &Path,
    output: &Path,
    limits: &PrevalenceBuildLimits,
) -> Result<()> {
    let slice_root = work_root.join("global-daily-slices");
    let parts_root = work_root.join("global-daily-parts");
    std::fs::create_dir_all(&slice_root)?;
    let mut slice_files = Vec::with_capacity(slices.len());
    let mut linked_day = None::<(chrono::NaiveDate, PathBuf)>;
    for (index, slice) in slices.iter().enumerate() {
        let day_text = slice.day.format("%Y-%m-%d").to_string();
        let slice_file = slice_root.join(format!("slice-{index:06}.parquet"));
        let mut params = vec![
            ("output", slice_file.to_string_lossy().into_owned()),
            ("day", day_text.clone()),
            ("buckets", slice.buckets.to_string()),
            ("bucket", slice.bucket.to_string()),
        ];
        if slice.source != GlobalDailySliceSource::Carry {
            // One link directory per day, shared by that day's buckets.
            let directory = match &linked_day {
                Some((day, directory)) if *day == slice.day => directory.clone(),
                _ => {
                    if let Some((_, previous)) = linked_day.take() {
                        std::fs::remove_dir_all(previous)?;
                    }
                    let directory =
                        link_parts(&parts_root.join(&day_text), parts, &slice.part_indexes)?;
                    linked_day = Some((slice.day, directory.clone()));
                    directory
                }
            };
            let name = if slice.source == GlobalDailySliceSource::Full {
                "source"
            } else {
                "delta"
            };
            params.push((name, format!("{}/*.parquet", directory.to_string_lossy())));
        }
        let template = match slice.source {
            GlobalDailySliceSource::Full => SQL_GLOBAL_DAILY_SLICE_FULL,
            GlobalDailySliceSource::Merge => SQL_GLOBAL_DAILY_SLICE_MERGE,
            GlobalDailySliceSource::Carry => SQL_GLOBAL_DAILY_SLICE_CARRY,
        };
        if slice.source != GlobalDailySliceSource::Full {
            let prior = prior_global.context("incremental global slice has no prior aggregate")?;
            params.push(("prior", prior.to_string_lossy().into_owned()));
        }
        run_build_statement(connection, template, &params, &slice_file, limits)?;
        slice_files.push(slice_file);
    }
    if let Some((_, directory)) = linked_day {
        std::fs::remove_dir_all(directory)?;
    }
    concatenate_parquet_slices(&slice_files, output)?;
    std::fs::remove_dir_all(&slice_root)?;
    Ok(())
}

/// Stream every slice file, in order, into one Parquet file. Memory is one
/// record batch plus one in-progress row group, independent of the total.
fn concatenate_parquet_slices(slices: &[PathBuf], output: &Path) -> Result<()> {
    use parquet::arrow::ArrowWriter;
    use parquet::basic::{Compression, ZstdLevel};
    use parquet::file::properties::{EnabledStatistics, WriterProperties};

    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_statistics_enabled(EnabledStatistics::Page)
        .set_max_row_group_size(GLOBAL_DAILY_ROW_GROUP_ROWS)
        .build();
    let mut writer = None::<ArrowWriter<File>>;
    let mut schema = None::<arrow_schema::SchemaRef>;
    for slice in slices {
        let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(slice)?)
            .with_context(|| format!("open prevalence slice {}", slice.display()))?;
        let slice_schema = builder.schema().clone();
        match &schema {
            None => {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(output)?;
                writer = Some(ArrowWriter::try_new(
                    file,
                    slice_schema.clone(),
                    Some(properties.clone()),
                )?);
                schema = Some(slice_schema);
            }
            Some(expected) if expected.fields() == slice_schema.fields() => {}
            Some(_) => bail!(
                "prevalence slice {} has a different schema than the first slice",
                slice.display()
            ),
        }
        let writer = writer
            .as_mut()
            .context("prevalence slice writer is missing")?;
        for batch in builder.with_batch_size(BATCH_ROWS).build()? {
            writer.write(&batch?)?;
        }
    }
    writer
        .context("prevalence global aggregate has no slices")?
        .close()?;
    File::open(output)?.sync_all()?;
    Ok(())
}

fn build_daily_history_from_global(
    connection: &NativeConnection,
    global_daily: &Path,
    output: &Path,
    daily_start: &str,
    limits: &PrevalenceBuildLimits,
) -> Result<()> {
    let params = [
        ("source", global_daily.to_string_lossy().into_owned()),
        ("output", output.to_string_lossy().into_owned()),
        ("daily_start", daily_start.to_string()),
    ];
    run_build_statement(
        connection,
        SQL_DAILY_HISTORY_FROM_GLOBAL,
        &params,
        output,
        limits,
    )
}

fn build_window_from_global(
    connection: &NativeConnection,
    global_daily: &Path,
    slice_work: &Path,
    output: &Path,
    edge_day: &str,
    limits: &PrevalenceBuildLimits,
    buckets: u64,
) -> Result<()> {
    let params = [
        ("global", global_daily.to_string_lossy().into_owned()),
        ("edge_day", edge_day.to_string()),
    ];
    build_sliced_aggregate(
        connection,
        SlicedAggregate {
            whole: SQL_WINDOW_FROM_GLOBAL,
            slice: SQL_WINDOW_FROM_GLOBAL_SLICE,
            from_slices: SQL_WINDOW_FROM_SLICES,
        },
        &params,
        buckets,
        slice_work,
        output,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_window_from_global_and_edge(
    connection: &NativeConnection,
    global_daily: &Path,
    edge_dir: &Path,
    slice_work: &Path,
    output: &Path,
    start_us: i64,
    edge_day: &str,
    limits: &PrevalenceBuildLimits,
    buckets: u64,
) -> Result<()> {
    let params = [
        ("global", global_daily.to_string_lossy().into_owned()),
        ("edge", format!("{}/*.parquet", edge_dir.to_string_lossy())),
        ("start_us", start_us.to_string()),
        ("edge_day", edge_day.to_string()),
    ];
    build_sliced_aggregate(
        connection,
        SlicedAggregate {
            whole: SQL_WINDOW_FROM_GLOBAL_AND_EDGE,
            slice: SQL_WINDOW_FROM_GLOBAL_AND_EDGE_SLICE,
            from_slices: SQL_WINDOW_FROM_SLICES,
        },
        &params,
        buckets,
        slice_work,
        output,
        limits,
    )
}

fn build_explorer_from_window(
    connection: &NativeConnection,
    source: &Path,
    work_root: &Path,
    output: &Path,
    limits: &PrevalenceBuildLimits,
    slicing: &WindowSlicing,
) -> Result<()> {
    // The explorer reads the finished window scan, so its row count is exact.
    let buckets = slicing.buckets(parquet_rows(source)?);
    let slice_work = work_root.join(format!(
        "explorer-{}-slices",
        source
            .parent()
            .and_then(Path::file_name)
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let params = [("source", source.to_string_lossy().into_owned())];
    build_sliced_aggregate(
        connection,
        SlicedAggregate {
            whole: SQL_EXPLORER_FROM_WINDOW,
            slice: SQL_EXPLORER_FROM_WINDOW_SLICE,
            from_slices: SQL_EXPLORER_FROM_SLICES,
        },
        &params,
        buckets,
        &slice_work,
        output,
        limits,
    )
}

/// The three statements of one sliceable aggregation (NAN-2828).
struct SlicedAggregate {
    /// The unsliced statement, run as-is when one bucket suffices.
    whole: &'static str,
    /// One hash bucket, unordered, to a Parquet work file.
    slice: &'static str,
    /// Sort-only statement writing the artifact from every slice.
    from_slices: &'static str,
}

/// Run `statements.whole` when the estimate fits one slice; otherwise run one
/// `statements.slice` per hash bucket and write the artifact from the slices
/// with `statements.from_slices`. Both paths produce the same rows in the same
/// order (see `SQL_WINDOW_FROM_GLOBAL_AND_EDGE_SLICE`).
fn build_sliced_aggregate(
    connection: &NativeConnection,
    statements: SlicedAggregate,
    params: &[(&str, String)],
    buckets: u64,
    slice_work: &Path,
    output: &Path,
    limits: &PrevalenceBuildLimits,
) -> Result<()> {
    let with_output = |extra: &[(&'static str, String)]| {
        let mut all = params.to_vec();
        all.push(("output", output.to_string_lossy().into_owned()));
        all.extend_from_slice(extra);
        all
    };
    if buckets <= 1 {
        return run_build_statement(
            connection,
            statements.whole,
            &with_output(&[]),
            output,
            limits,
        );
    }
    if slice_work.exists() {
        std::fs::remove_dir_all(slice_work)?;
    }
    std::fs::create_dir_all(slice_work)?;
    let mut non_empty_slices = 0_u64;
    for bucket in 0..buckets {
        let slice_file = slice_work.join(format!("slice-{bucket:06}.parquet"));
        let mut slice_params = params.to_vec();
        slice_params.extend([
            ("output", slice_file.to_string_lossy().into_owned()),
            ("buckets", buckets.to_string()),
            ("bucket", bucket.to_string()),
        ]);
        run_query_statement(
            connection,
            statements.slice,
            &slice_params,
            &slice_file,
            limits,
        )?;
        // An empty bucket writes a zero-row Parquet file; a zero-byte file (or
        // none) would break schema inference for the glob, so drop it.
        match std::fs::metadata(&slice_file) {
            Ok(metadata) if metadata.len() > 0 => non_empty_slices += 1,
            Ok(_) => std::fs::remove_file(&slice_file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if non_empty_slices == 0 {
        // Nothing survived the filters: the unsliced statement over the same
        // empty input writes the canonical empty artifact.
        std::fs::remove_dir_all(slice_work)?;
        return run_build_statement(
            connection,
            statements.whole,
            &with_output(&[]),
            output,
            limits,
        );
    }
    let source = format!("{}/*.parquet", slice_work.to_string_lossy());
    run_build_statement(
        connection,
        statements.from_slices,
        &[
            ("source", source),
            ("output", output.to_string_lossy().into_owned()),
        ],
        output,
        limits,
    )?;
    std::fs::remove_dir_all(slice_work)?;
    Ok(())
}

fn run_build_statement(
    connection: &NativeConnection,
    template: &str,
    params: &[(&str, String)],
    output: &Path,
    limits: &PrevalenceBuildLimits,
) -> Result<()> {
    run_query_statement(connection, template, params, output, limits)?;
    File::open(output)?.sync_all()?;
    Ok(())
}

/// Run one derivative statement without requiring that it wrote `output`
/// (an empty aggregation slice may write nothing).
fn run_query_statement(
    connection: &NativeConnection,
    template: &str,
    params: &[(&str, String)],
    output: &Path,
    limits: &PrevalenceBuildLimits,
) -> Result<()> {
    let refs = params
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect::<Vec<_>>();
    let sql = apply_build_limits(template, limits);
    connection
        .query_with_params(&sql, "Null", &refs)
        .with_context(|| format!("build prevalence output {}", output.display()))?;
    Ok(())
}

async fn load_prevalence_database(
    pending: PendingPrevalenceDatabaseLoad,
    secret: &[u8],
) -> Result<LoadedPrevalenceDatabase> {
    if let Some(prior) = pending.prior.as_ref() {
        match load_slatedb_incremental(
            &prior.scan_file,
            &pending.scan_file,
            &prior.database_path,
            prior.checkpoint_id,
            &pending.database_path,
            secret,
        )
        .await
        {
            Ok((checkpoint_id, changed_rows, deleted_rows)) => {
                tracing::info!(
                    prior_scan_sha256 = %prior.scan_sha256,
                    prior_scan_bytes = prior.scan_bytes,
                    prior_rows = prior.rows,
                    changed_rows,
                    deleted_rows,
                    database_path = %pending.database_path,
                    "prevalence SlateDB database advanced incrementally"
                );
                return Ok(LoadedPrevalenceDatabase {
                    checkpoint_id,
                    database_path: pending.database_path,
                    incremental: true,
                    changed_rows,
                    deleted_rows,
                });
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    database_path = %pending.database_path,
                    "incremental prevalence SlateDB advance failed; rebuilding the database exactly"
                );
                let candidate = Path::new("/").join(&pending.database_path);
                if candidate.exists() {
                    std::fs::remove_dir_all(&candidate).with_context(|| {
                        format!(
                            "remove failed incremental prevalence database {}",
                            candidate.display()
                        )
                    })?;
                }
            }
        }
    }
    let checkpoint_id = load_slatedb(&pending.scan_file, &pending.database_path, secret).await?;
    Ok(LoadedPrevalenceDatabase {
        checkpoint_id,
        database_path: pending.database_path,
        incremental: false,
        changed_rows: pending
            .scan_file
            .is_file()
            .then(|| parquet_rows(&pending.scan_file))
            .transpose()?
            .unwrap_or(0),
        deleted_rows: 0,
    })
}

/// Advance an immutable point-lookup database from a verified prior window.
/// The source and destination scans are sorted by the exact logical key, so a
/// streaming merge emits only inserts, replacements, and removals. Immutable
/// SSTs are hardlinked while mutable manifests are copied; pruning the prior
/// generation therefore cannot invalidate the new database, and publishing a
/// new manifest cannot mutate the prior one through a shared inode.
async fn load_slatedb_incremental(
    prior_scan: &Path,
    scan: &Path,
    prior_database_path: &str,
    prior_checkpoint_id: uuid::Uuid,
    database_path: &str,
    secret: &[u8],
) -> Result<(uuid::Uuid, u64, u64)> {
    let prior_database = Path::new("/").join(prior_database_path);
    let database = Path::new("/").join(database_path);
    if !prior_scan.is_file() || !scan.is_file() || !prior_database.is_dir() || database.exists() {
        bail!("incremental prevalence database paths are invalid");
    }
    clone_slatedb_tree(&prior_database, &database)?;
    let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix("/")?);
    let admin = Admin::builder(database_path, store.clone()).build();
    let checkpoints = admin.list_checkpoints(None).await?;
    if !checkpoints
        .iter()
        .any(|checkpoint| checkpoint.id == prior_checkpoint_id)
    {
        bail!("prior prevalence checkpoint is absent from the copied database");
    }

    if file_sha256(prior_scan)? == file_sha256(scan)?
        && std::fs::metadata(prior_scan)?.len() == std::fs::metadata(scan)?.len()
        && parquet_rows(prior_scan)? == parquet_rows(scan)?
    {
        return Ok((prior_checkpoint_id, 0, 0));
    }

    for checkpoint in checkpoints {
        admin.delete_checkpoint(checkpoint.id).await?;
    }
    let database_handle = Db::builder(database_path, store.clone())
        .with_settings(Settings {
            wal_enabled: false,
            compression_codec: Some(CompressionCodec::Zstd),
            ..Settings::default()
        })
        .with_db_cache_disabled()
        .with_merge_operator(Arc::new(ValueMerge))
        .build()
        .await?;
    let mut prior_rows = PrevalenceScanRows::open(prior_scan)?;
    let mut rows = PrevalenceScanRows::open(scan)?;
    let mut prior_row = prior_rows.next_row()?;
    let mut row = rows.next_row()?;
    let mut batch = WriteBatch::new();
    let mut batch_rows = 0_usize;
    let mut changed_rows = 0_u64;
    let mut deleted_rows = 0_u64;
    while prior_row.is_some() || row.is_some() {
        match (&prior_row, &row) {
            (Some(prior), Some(current)) => match prior.identity().cmp(&current.identity()) {
                std::cmp::Ordering::Less => {
                    batch.delete(key(secret, &prior.kind, &prior.scope, &prior.entity)?);
                    batch_rows += 1;
                    deleted_rows = deleted_rows
                        .checked_add(1)
                        .context("prevalence deleted-row count overflow")?;
                    prior_row = prior_rows.next_row()?;
                }
                std::cmp::Ordering::Greater => {
                    put_prevalence_row(&mut batch, current, secret)?;
                    batch_rows += 1;
                    changed_rows = changed_rows
                        .checked_add(1)
                        .context("prevalence changed-row count overflow")?;
                    row = rows.next_row()?;
                }
                std::cmp::Ordering::Equal => {
                    if prior.value != current.value {
                        put_prevalence_row(&mut batch, current, secret)?;
                        batch_rows += 1;
                        changed_rows = changed_rows
                            .checked_add(1)
                            .context("prevalence changed-row count overflow")?;
                    }
                    prior_row = prior_rows.next_row()?;
                    row = rows.next_row()?;
                }
            },
            (Some(prior), None) => {
                batch.delete(key(secret, &prior.kind, &prior.scope, &prior.entity)?);
                batch_rows += 1;
                deleted_rows = deleted_rows
                    .checked_add(1)
                    .context("prevalence deleted-row count overflow")?;
                prior_row = prior_rows.next_row()?;
            }
            (None, Some(current)) => {
                put_prevalence_row(&mut batch, current, secret)?;
                batch_rows += 1;
                changed_rows = changed_rows
                    .checked_add(1)
                    .context("prevalence changed-row count overflow")?;
                row = rows.next_row()?;
            }
            (None, None) => break,
        }
        if batch_rows >= BATCH_ROWS {
            let ready = std::mem::replace(&mut batch, WriteBatch::new());
            database_handle
                .write_with_options(
                    ready,
                    &slatedb::config::WriteOptions {
                        await_durable: false,
                        ..Default::default()
                    },
                )
                .await?;
            batch_rows = 0;
        }
    }
    if batch_rows > 0 {
        database_handle
            .write_with_options(
                batch,
                &slatedb::config::WriteOptions {
                    await_durable: false,
                    ..Default::default()
                },
            )
            .await?;
    }
    database_handle.flush().await?;
    let checkpoint = database_handle
        .create_checkpoint(
            CheckpointScope::All,
            &CheckpointOptions {
                lifetime: None,
                source: None,
                name: Some("nano-immutable-prevalence".to_string()),
            },
        )
        .await?;
    database_handle.close().await?;
    scrub_slatedb(database_path, store).await?;
    Ok((checkpoint.id, changed_rows, deleted_rows))
}

fn put_prevalence_row(
    batch: &mut WriteBatch,
    row: &PrevalenceScanRow,
    secret: &[u8],
) -> Result<()> {
    batch.put(
        key(secret, &row.kind, &row.scope, &row.entity)?,
        encode(&row.value)?,
    );
    Ok(())
}

fn clone_slatedb_tree(source: &Path, destination: &Path) -> Result<()> {
    std::fs::create_dir(destination)?;
    for path in walk(source)? {
        let relative = path.strip_prefix(source)?;
        let target = destination.join(relative);
        if path.is_dir() {
            std::fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let immutable_sst = path.extension().is_some_and(|extension| extension == "sst");
        if !immutable_sst || std::fs::hard_link(&path, &target).is_err() {
            std::fs::copy(&path, &target)?;
        }
    }
    Ok(())
}

async fn load_slatedb(scan: &Path, database_path: &str, secret: &[u8]) -> Result<uuid::Uuid> {
    let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix("/")?);
    // NAN-2361 footprint: this database is written exactly once inside a
    // candidate directory that is only published (renamed + fsynced) after the
    // build succeeds, so WAL durability buys nothing — a crash mid-load
    // discards the whole candidate. With the WAL enabled, every key/value pair
    // was stored a THIRD time as WAL SSTs that survived into the immutable
    // snapshot: 368 MB of the 943 MB 7d window on the 2026-08-19 live stack
    // (prevalence-snapshot-v2 was 2,497 MB, 55% of the event data it indexes,
    // and 87% of that was SlateDB state). Zstd block compression shrinks the
    // SSTs that remain; readers pick the codec up from each SST's metadata, so
    // previously published snapshots are unaffected either way.
    let database = Db::builder(database_path, store.clone())
        .with_settings(Settings {
            wal_enabled: false,
            compression_codec: Some(CompressionCodec::Zstd),
            ..Settings::default()
        })
        // The caller only writes, flushes, checkpoints, and closes. Internal
        // compaction may read each block while producing its output, but this
        // one-shot path serves no repeated point/range lookups that benefit
        // from SlateDB's 512-MiB block plus 128-MiB metadata cache. Reader
        // processes reopen the immutable DB with their separately bounded
        // shared cache.
        .with_db_cache_disabled()
        .with_merge_operator(Arc::new(ValueMerge))
        .build()
        .await?;
    let mut reader = ParquetRecordBatchReaderBuilder::try_new(File::open(scan)?)?
        .with_batch_size(BATCH_ROWS)
        .build()?;
    for batch in &mut reader {
        let batch = batch?;
        let kinds = strings(&batch, "kind")?;
        let scopes = strings(&batch, "scope")?;
        let entities = strings(&batch, "entity")?;
        let hosts = list_u64(&batch, "host_fingerprints")?;
        let saturated = u8s(&batch, "host_count_saturated")?;
        let private = u8s(&batch, "is_private")?;
        let first = timestamp_us(&batch, "first_seen")?;
        let last = timestamp_us(&batch, "last_seen")?;
        let occurrences = u64s(&batch, "total_occurrences")?;
        let mut writes = WriteBatch::new();
        for index in 0..batch.num_rows() {
            let value = Value {
                hosts: hosts[index].iter().copied().take(HOST_CAP).collect(),
                saturated: saturated[index] != 0,
                private: private[index] != 0,
                first_us: first[index],
                last_us: last[index],
                occurrences: occurrences[index],
            };
            writes.put(
                key(secret, &kinds[index], &scopes[index], &entities[index])?,
                encode(&value)?,
            );
        }
        // With the WAL disabled, an await-durable write would block until the
        // memtable reaches its L0 flush threshold — which a small window never
        // does. Durability comes from the explicit flush below plus the
        // candidate-directory sync/rename that publishes the snapshot.
        database
            .write_with_options(
                writes,
                &slatedb::config::WriteOptions {
                    await_durable: false,
                    ..Default::default()
                },
            )
            .await?;
    }
    database.flush().await?;
    let checkpoint = database
        .create_checkpoint(
            CheckpointScope::All,
            &CheckpointOptions {
                lifetime: None,
                source: None,
                name: Some("nano-immutable-prevalence".to_string()),
            },
        )
        .await?;
    database.close().await?;
    scrub_slatedb(database_path, store).await?;
    Ok(checkpoint.id)
}

/// Compaction during a load leaves superseded L0 SSTs on disk. They are not
/// referenced by the final manifest/checkpoint, so one foreground collection
/// removes only load-time scaffolding. The read-back tests prove that every
/// checkpointed key survives both full and incremental publication.
async fn scrub_slatedb(database_path: &str, store: Arc<dyn ObjectStore>) -> Result<()> {
    let scrub = || {
        Some(GarbageCollectorDirectoryOptions {
            interval: None,
            min_age: std::time::Duration::ZERO,
            dry_run: false,
        })
    };
    Admin::builder(database_path, store)
        .build()
        .run_gc_once(GarbageCollectorOptions {
            manifest_options: scrub(),
            wal_options: scrub(),
            // WAL fences only matter to concurrent live writers; this database
            // is closed and never written again, but there is also nothing to
            // collect with the WAL disabled — leave the risky knob off.
            wal_fence_options: None,
            compacted_options: scrub(),
            compactions_options: scrub(),
            ..GarbageCollectorOptions::default()
        })
        .await?;
    Ok(())
}

impl PrevalenceScanRows {
    fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            reader: ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?
                .with_batch_size(BATCH_ROWS)
                .build()?,
            current: Vec::new().into_iter(),
        })
    }

    fn next_row(&mut self) -> Result<Option<PrevalenceScanRow>> {
        loop {
            if let Some(row) = self.current.next() {
                return Ok(Some(row));
            }
            let Some(batch) = self.reader.next() else {
                return Ok(None);
            };
            self.current = prevalence_scan_rows(batch?)?.into_iter();
        }
    }
}

fn prevalence_scan_rows(batch: arrow_array::RecordBatch) -> Result<Vec<PrevalenceScanRow>> {
    let kinds = strings(&batch, "kind")?;
    let scopes = strings(&batch, "scope")?;
    let entities = strings(&batch, "entity")?;
    let hosts = list_u64(&batch, "host_fingerprints")?;
    let saturated = u8s(&batch, "host_count_saturated")?;
    let private = u8s(&batch, "is_private")?;
    let first = timestamp_us(&batch, "first_seen")?;
    let last = timestamp_us(&batch, "last_seen")?;
    let occurrences = u64s(&batch, "total_occurrences")?;
    Ok((0..batch.num_rows())
        .map(|index| PrevalenceScanRow {
            kind: kinds[index].clone(),
            scope: scopes[index].clone(),
            entity: entities[index].clone(),
            value: Value {
                hosts: hosts[index].iter().copied().take(HOST_CAP).collect(),
                saturated: saturated[index] != 0,
                private: private[index] != 0,
                first_us: first[index],
                last_us: last[index],
                occurrences: occurrences[index],
            },
        })
        .collect())
}

fn key(secret: &[u8], kind: &str, scope: &str, entity: &str) -> Result<Vec<u8>> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(secret)?;
    hmac.update(b"prevalence-v1\0");
    hmac.update(entity.trim().to_ascii_lowercase().as_bytes());
    let mut key = format!("{kind}\0{scope}\0").into_bytes();
    key.extend_from_slice(&hmac.finalize().into_bytes());
    Ok(key)
}

fn encode(value: &Value) -> Result<Vec<u8>> {
    let hosts = value
        .hosts
        .iter()
        .copied()
        .take(HOST_CAP)
        .collect::<Vec<_>>();
    let mut output = Vec::with_capacity(28 + hosts.len() * 8);
    output.push(VALUE_VERSION);
    output.push(u8::try_from(hosts.len())?);
    output.push(u8::from(value.saturated || hosts.len() == HOST_CAP));
    output.push(u8::from(value.private));
    output.extend_from_slice(&value.first_us.to_be_bytes());
    output.extend_from_slice(&value.last_us.to_be_bytes());
    output.extend_from_slice(&value.occurrences.to_be_bytes());
    for host in hosts {
        output.extend_from_slice(&host.to_be_bytes());
    }
    Ok(output)
}

fn decode(value: &[u8]) -> Result<Value> {
    if value.len() < 28 || value[0] != VALUE_VERSION || value.len() != 28 + value[1] as usize * 8 {
        bail!("invalid prevalence value");
    }
    let mut hosts = BTreeSet::new();
    for bytes in value[28..].chunks_exact(8) {
        hosts.insert(u64::from_be_bytes(bytes.try_into()?));
    }
    Ok(Value {
        hosts,
        saturated: value[2] != 0,
        private: value[3] != 0,
        first_us: i64::from_be_bytes(value[4..12].try_into()?),
        last_us: i64::from_be_bytes(value[12..20].try_into()?),
        occurrences: u64::from_be_bytes(value[20..28].try_into()?),
    })
}

fn parquet_rows(path: &Path) -> Result<u64> {
    let metadata = parquet::file::reader::SerializedFileReader::new(File::open(path)?)?
        .metadata()
        .file_metadata()
        .num_rows();
    Ok(u64::try_from(metadata)?)
}

fn column<'a>(
    batch: &'a arrow_array::RecordBatch,
    name: &str,
) -> Result<&'a dyn arrow_array::Array> {
    Ok(batch.column(batch.schema().index_of(name)?).as_ref())
}

fn strings(batch: &arrow_array::RecordBatch, name: &str) -> Result<Vec<String>> {
    let values = column(batch, name)?
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .context("expected String")?;
    Ok((0..values.len())
        .map(|i| values.value(i).to_string())
        .collect())
}

fn u8s(batch: &arrow_array::RecordBatch, name: &str) -> Result<Vec<u8>> {
    let values = column(batch, name)?
        .as_any()
        .downcast_ref::<arrow_array::UInt8Array>()
        .context("expected UInt8")?;
    Ok((0..values.len()).map(|i| values.value(i)).collect())
}

fn u64s(batch: &arrow_array::RecordBatch, name: &str) -> Result<Vec<u64>> {
    let values = column(batch, name)?
        .as_any()
        .downcast_ref::<arrow_array::UInt64Array>()
        .context("expected UInt64")?;
    Ok((0..values.len()).map(|i| values.value(i)).collect())
}

fn timestamp_us(batch: &arrow_array::RecordBatch, name: &str) -> Result<Vec<i64>> {
    let values = column(batch, name)?
        .as_any()
        .downcast_ref::<arrow_array::TimestampMicrosecondArray>()
        .context("expected timestamp[us]")?;
    Ok((0..values.len()).map(|i| values.value(i)).collect())
}

fn list_u64(batch: &arrow_array::RecordBatch, name: &str) -> Result<Vec<Vec<u64>>> {
    let values = column(batch, name)?
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .context("expected List(UInt64)")?;
    (0..values.len())
        .map(|i| {
            let item = values.value(i);
            let item = item
                .as_any()
                .downcast_ref::<arrow_array::UInt64Array>()
                .context("expected list item UInt64")?;
            Ok((0..item.len()).map(|j| item.value(j)).collect())
        })
        .collect()
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    for entry in walk(root)? {
        if entry.is_file() {
            File::open(&entry)?.sync_all()?;
        } else if entry.is_dir() {
            directories.push(entry);
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

fn walk(root: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            result.push(path);
        }
    }
    Ok(result)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn object_store_path(path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix("/")
        .context("local prevalence database path must be absolute")?;
    let value = relative.to_string_lossy().into_owned();
    if value.is_empty() || value.contains("..") {
        bail!("local prevalence database path is invalid");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- NAN-2361: build-memory resolution -----------------------------------

    #[test]
    fn prevalence_process_layout_bounds_native_loads_and_memory() {
        assert_eq!(
            prevalence_part_process_layout(8, 40, 6 * 1024 * 1024 * 1024).unwrap(),
            (3, 2 * 1024 * 1024 * 1024),
        );
        assert_eq!(
            prevalence_part_process_layout(256, 100, 64_000_000_000).unwrap(),
            (29, 64_000_000_000 / 29),
        );
        assert_eq!(
            prevalence_part_process_layout(8, 3, 6 * 1024 * 1024 * 1024).unwrap(),
            (3, 2 * 1024 * 1024 * 1024),
        );
        assert!(prevalence_part_process_layout(8, 1, 2 * 1024 * 1024 * 1024 - 1).is_err());
    }

    #[test]
    fn slatedb_window_loads_share_the_derivative_memory_envelope() {
        assert_eq!(
            slatedb_load_concurrency(4, 6 * 1024 * 1024 * 1024).unwrap(),
            4,
        );
        assert_eq!(
            slatedb_load_concurrency(4, 16 * 1024 * 1024 * 1024).unwrap(),
            4,
        );
        assert!(
            slatedb_load_concurrency(4, PREVALENCE_SLATE_LOAD_LANE_MEMORY_FLOOR_BYTES - 1,)
                .is_err()
        );
        assert!(slatedb_load_concurrency(0, 6 * 1024 * 1024 * 1024).is_err());
    }

    #[test]
    fn full_coverage_window_reuse_requires_every_exact_minimum() {
        assert!(window_covers_all_source_rows(100, &[100, 101, 10_000]));
        assert!(!window_covers_all_source_rows(101, &[100, 101, 10_000]));
        assert!(!window_covers_all_source_rows(100, &[0, 101, 10_000]));
        assert!(!window_covers_all_source_rows(100, &[]));
    }

    #[test]
    fn slatedb_load_plan_reuses_only_exact_scan_identities() {
        let pending =
            |window: &str, sha256: &str, bytes: u64, rows: u64| PendingPrevalenceWindowBuild {
                window: window.to_string(),
                snapshot_id: format!("prevalence-tenant-a-{window}"),
                database_path: format!("candidate/{window}/slatedb"),
                scan_file: PathBuf::from(format!("candidate/{window}/snapshot.parquet")),
                scan_sha256: sha256.to_string(),
                scan_bytes: bytes,
                rows,
                explorer: PrevalenceExplorerBuild {
                    scan_file: PathBuf::from(format!("candidate/{window}/explorer.parquet")),
                    scan_sha256: "e".repeat(64),
                    scan_bytes: 1,
                    rows: 1,
                },
                source_types: vec!["apache_access".to_string()],
            };
        let windows = vec![
            pending("1h", &"a".repeat(64), 10, 1),
            pending("24h", &"b".repeat(64), 20, 2),
            pending("7d", &"c".repeat(64), 30, 3),
            pending("30d", &"c".repeat(64), 30, 3),
        ];
        let (loads, indexes) = plan_prevalence_database_loads(&windows, &BTreeMap::new());
        assert_eq!(loads.len(), 3);
        assert_eq!(indexes, vec![0, 1, 2, 2]);
        assert_eq!(loads[2].database_path, "candidate/7d/slatedb");

        for changed in [
            pending("30d", &"d".repeat(64), 30, 3),
            pending("30d", &"c".repeat(64), 31, 3),
            pending("30d", &"c".repeat(64), 30, 4),
        ] {
            let (loads, indexes) = plan_prevalence_database_loads(
                &[pending("7d", &"c".repeat(64), 30, 3), changed],
                &BTreeMap::new(),
            );
            assert_eq!(loads.len(), 2);
            assert_eq!(indexes, vec![0, 1]);
        }
    }

    #[test]
    fn aggregate_threads_share_the_native_memory_lane_envelope() {
        assert_eq!(
            prevalence_aggregate_threads(8, 6 * 1024 * 1024 * 1024).unwrap(),
            3,
        );
        assert_eq!(
            prevalence_aggregate_threads(2, 6 * 1024 * 1024 * 1024).unwrap(),
            2,
        );
        assert_eq!(
            prevalence_aggregate_threads(256, 64_000_000_000).unwrap(),
            29,
        );
        assert!(prevalence_aggregate_threads(8, 2 * 1024 * 1024 * 1024 - 1).is_err());
    }

    #[test]
    fn build_memory_uses_the_profile_when_no_env_override_is_set() {
        let profile = crate::bounds::SizeClass::Edge5GbDay
            .derive()
            .expect("edge profile derives");
        assert_eq!(
            resolve_build_memory(None, Some(profile.derivative_build_memory_bytes)),
            2_147_483_648, // 4 GiB container - 2 GiB resident overhead
        );
        // Without a profile the compiled default is unchanged behavior.
        assert_eq!(resolve_build_memory(None, None), BUILD_MEMORY_DEFAULT);
    }

    #[test]
    fn explicit_env_override_still_wins_over_the_profile() {
        // The generation container may genuinely have more memory than the
        // profile's worker container; the env override is the escape hatch
        // and the disagreement is logged, not silently resolved.
        assert_eq!(
            resolve_build_memory(Some(4 * 1024 * 1024 * 1024), Some(2_147_483_648)),
            4 * 1024 * 1024 * 1024,
        );
    }

    #[test]
    fn contradictory_build_memory_is_clamped_into_the_working_range() {
        // A mis-set override below the floor made every build abort with
        // chDB Code 241 (NAN-2361); one above the ceiling would claim a whole
        // worker. Both are clamped, whatever their source.
        assert_eq!(
            resolve_build_memory(Some(1), Some(3_221_225_472)),
            PREVALENCE_BUILD_MEMORY_FLOOR_BYTES
        );
        assert_eq!(
            resolve_build_memory(None, Some(u64::MAX)),
            PREVALENCE_BUILD_MEMORY_CEILING_BYTES
        );
        // And a profile that ships a violating value never gets this far:
        // it fails deserialization inside worker.json (bounds.rs wire twin).
        let mut tampered =
            serde_json::to_value(crate::bounds::SizeClass::Edge5GbDay.derive().unwrap()).unwrap();
        tampered["derivative_build_memory_bytes"] = serde_json::json!(64_u64 * 1024 * 1024 * 1024);
        assert!(
            serde_json::from_value::<crate::bounds::LakeBoundsProfile>(tampered).is_err(),
            "a build ceiling the container cannot grant must not deserialize"
        );
    }

    // -- NAN-2361: spill/temp-disk coupling ----------------------------------

    #[test]
    fn spill_and_temp_disk_limits_satisfy_the_ordering_for_every_reachable_memory() {
        // The inequality nothing asserted before 2026-08-19:
        //   2 * spill < max_memory < temp_disk
        // Checked across the entire clamp range plus both edges.
        for memory in [
            PREVALENCE_BUILD_MEMORY_FLOOR_BYTES,
            BUILD_MEMORY_DEFAULT,
            3_221_225_472,
            PREVALENCE_BUILD_MEMORY_CEILING_BYTES,
        ] {
            let spill = spill_bytes(memory);
            let temp_disk = temp_disk_bytes(memory);
            assert!(
                2 * spill < memory,
                "2*spill ({}) must stay under max_memory ({memory})",
                2 * spill
            );
            assert!(
                memory < temp_disk,
                "max_memory ({memory}) must stay under temp_disk ({temp_disk})"
            );
        }
    }

    #[test]
    fn every_template_has_all_canonical_limits_substituted() {
        // Each canonical literal that appears in a template must be replaced
        // by apply_build_limits; a stale literal is exactly the uncoupled
        // constant class that caused the 2026-08-19 outage.
        let canonical = [
            "max_memory_usage=536870912",
            "max_memory_usage=1073741824",
            "max_bytes_before_external_group_by=268435456",
            "max_bytes_before_external_sort=268435456",
            "max_temporary_data_on_disk_size_for_query=8589934592",
        ];
        let memory = 7 * 1024 * 1024 * 1024_u64;
        let aggregate_threads = 13;
        let limits = PrevalenceBuildLimits {
            memory_bytes: memory,
            aggregate_threads,
        };
        for (name, template) in DERIVATIVE_SQL_TEMPLATES {
            // Every template must name a memory ceiling at all.
            assert!(
                template.contains("max_memory_usage="),
                "{name} lacks a memory ceiling"
            );
            let applied = apply_build_limits(template, &limits);
            for literal in canonical {
                assert!(
                    !applied.contains(literal),
                    "{name} retains canonical literal {literal} after substitution"
                );
            }
            assert!(
                applied.contains(&format!("max_memory_usage={memory}")),
                "{name} did not receive the derived memory ceiling"
            );
            if template.contains("max_threads=4") {
                assert!(
                    applied.contains(&format!("max_threads={aggregate_threads}"))
                        && !applied.contains("max_threads=4"),
                    "{name} did not receive the declared aggregate thread budget"
                );
            } else {
                assert!(
                    applied.contains("max_threads=1"),
                    "{name} changed the intentional single-thread observation lane"
                );
            }
            // Any template that spills must have received the DERIVED pair,
            // coupled to the same memory value.
            if template.contains("max_bytes_before_external_group_by") {
                assert!(
                    applied.contains(&format!(
                        "max_bytes_before_external_group_by={}",
                        spill_bytes(memory)
                    )) && applied.contains(&format!(
                        "max_bytes_before_external_sort={}",
                        spill_bytes(memory)
                    )) && applied.contains(&format!(
                        "max_temporary_data_on_disk_size_for_query={}",
                        temp_disk_bytes(memory)
                    )),
                    "{name} spill/temp-disk knobs are not derived from the memory ceiling"
                );
                // NAN-2614: with chDB's default 0.5 ratios the absolute sort
                // threshold is ignored and a sort never spills.
                assert!(
                    applied.contains("max_bytes_ratio_before_external_group_by=0,")
                        && applied.contains("max_bytes_ratio_before_external_sort=0,"),
                    "{name} leaves a ratio spill trigger that overrides the absolute threshold"
                );
            }
        }
    }

    #[test]
    fn retained_volume_host_aggregates_are_bounded_before_finalization() {
        for (name, template) in [
            ("global_daily_slice_merge", SQL_GLOBAL_DAILY_SLICE_MERGE),
            (
                "window_from_global_and_edge",
                SQL_WINDOW_FROM_GLOBAL_AND_EDGE,
            ),
            ("window_from_global", SQL_WINDOW_FROM_GLOBAL),
            ("explorer_from_window", SQL_EXPLORER_FROM_WINDOW),
        ] {
            assert!(
                template.contains("groupUniqArrayArray(65)"),
                "{name} lost the 65-host aggregate-state bound"
            );
            assert!(
                !template.contains("groupArray(host_fingerprints)")
                    && !template.contains("groupArray(hf)"),
                "{name} retains an unbounded array aggregate"
            );
        }
        assert!(SQL_EXPLORER_FROM_WINDOW.contains("length(hosts) = 65"));
        assert!(SQL_EXPLORER_FROM_WINDOW.contains("any_saturated"));
        assert!(!SQL_EXPLORER_FROM_WINDOW.contains("uniqExactArray"));
    }

    // -- part reuse ----------------------------------------------------------

    #[test]
    fn prior_parts_require_exact_identity_size_and_digest() {
        let root = tempfile::tempdir().unwrap();
        let part = root.path().join("part.parquet");
        std::fs::write(&part, b"immutable-part").unwrap();
        let part_build = PrevalencePartBuild {
            relative_path: "hour=1/object.parquet".to_string(),
            event_object_key: "s3://test/events/hour=1/object.parquet".to_string(),
            event_object_version: "version-1".to_string(),
            event_object_bytes: 123,
            part_file: part.clone(),
            part_sha256: file_sha256(&part).unwrap(),
            part_bytes: std::fs::metadata(&part).unwrap().len(),
            rows: 1,
            max_event_time_us: 1_000_000,
            source_types: vec!["windows_sysmon".to_string()],
        };
        let manifest = PrevalenceBuildManifest {
            schema_version: 2,
            tenant_id: "tenant-a".to_string(),
            event_snapshot_id: 1,
            object_stamp_sha256: "a".repeat(64),
            parts: vec![part_build.clone()],
            reused_source_files: 0,
            built_source_files: 1,
            daily_history: None,
            windows: Vec::new(),
        };
        write_json(&root.path().join("manifest.json"), &manifest).unwrap();
        let parts = prior_prevalence_parts(Some(root.path()), "tenant-a").unwrap();
        let identity = prevalence_object_identity(
            &part_build.event_object_key,
            &part_build.event_object_version,
            part_build.event_object_bytes,
        );
        assert!(verified_part(&parts[&identity]).unwrap());

        std::fs::write(&part, b"mutated-part").unwrap();
        assert!(!verified_part(&parts[&identity]).unwrap());
        assert!(prior_prevalence_parts(Some(root.path()), "tenant-b")
            .unwrap()
            .is_empty());
    }

    // -- incremental planning (pure) ------------------------------------------

    fn identity(key: &str) -> PrevalenceObjectIdentity {
        prevalence_object_identity(key, "v1", 100)
    }

    fn part_named(key: &str, max_us: i64) -> PrevalencePartBuild {
        PrevalencePartBuild {
            relative_path: format!("{key}.parquet"),
            event_object_key: key.to_string(),
            event_object_version: "v1".to_string(),
            event_object_bytes: 100,
            part_file: PathBuf::from(format!("/nonexistent/{key}.parquet")),
            part_sha256: "0".repeat(64),
            part_bytes: 1,
            rows: 1,
            max_event_time_us: max_us,
            source_types: vec!["fw".to_string()],
        }
    }

    #[test]
    fn delta_membership_is_by_identity_not_by_rebuild() {
        // A part whose file was rebuilt (corruption) but whose IDENTITY is
        // already in the prior snapshot extracts the same rows from the same
        // immutable object; treating it as delta would double count.
        let parts = vec![part_named("s3://b/a", 10), part_named("s3://b/b", 10)];
        let prior = [identity("s3://b/a")].into_iter().collect::<BTreeSet<_>>();
        assert_eq!(delta_part_indexes(&parts, &prior), vec![1]);
        let both = [identity("s3://b/a"), identity("s3://b/b")]
            .into_iter()
            .collect::<BTreeSet<_>>();
        assert!(delta_part_indexes(&parts, &both).is_empty());
    }

    #[test]
    fn edge_scan_prunes_by_event_time_bounds_and_never_by_unknown_minimum() {
        let parts = vec![
            part_named("old", 900),           // entirely before the window
            part_named("edge", 1_500),        // overlaps the boundary day
            part_named("recent", 9_000),      // min proves it is interior-only
            part_named("unknown-min", 9_000), // min unknown: must be scanned
        ];
        let mins = vec![100, 1_100, 2_500, 0];
        // Window starts at 1_000; the boundary day ends at 2_000.
        let indexes = edge_part_indexes(&parts, &mins, 1_000, 2_000);
        assert_eq!(indexes, vec![1, 3]);
    }

    fn utc_date(text: &str) -> chrono::NaiveDate {
        chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    fn part_in_day(key: &str, day: &str, rows: u64) -> (PrevalencePartBuild, i64) {
        let start = utc_day_start_us(utc_date(day)).unwrap();
        let mut part = part_named(key, start + 3_600_000_000);
        part.rows = rows;
        (part, start + 60_000_000)
    }

    #[test]
    fn global_daily_slice_rows_track_the_budget_with_a_floor() {
        assert_eq!(global_daily_slice_rows(2 * 1024 * 1024 * 1024), 4_194_304);
        assert_eq!(global_daily_slice_rows(3 * 1024 * 1024 * 1024), 6_291_456);
        assert_eq!(global_daily_slice_rows(1), GLOBAL_DAILY_SLICE_MIN_ROWS);
    }

    #[test]
    fn window_slicing_plans_buckets_from_the_rows_after_the_edge_day() {
        // NAN-2828: the window/explorer aggregation splits into as many hash
        // buckets as its estimated input needs at the global-daily row target,
        // one bucket when it fits (the unsliced statement), capped.
        let slicing = WindowSlicing {
            global_day_rows: [
                (utc_date("2026-09-21"), 1_000),
                (utc_date("2026-09-22"), 2_000),
                (utc_date("2026-09-23"), 4_000),
                (utc_date("2026-09-24"), 8_000),
            ]
            .into_iter()
            .collect(),
            slice_rows: 5_000,
        };
        assert_eq!(slicing.global_rows_after(utc_date("2026-09-22")), 12_000);
        assert_eq!(slicing.global_rows_after(utc_date("2026-09-24")), 0);
        assert_eq!(slicing.global_rows_after(utc_date("2026-09-01")), 15_000);
        assert_eq!(slicing.buckets(0), 1);
        assert_eq!(slicing.buckets(5_000), 1);
        assert_eq!(slicing.buckets(5_001), 2);
        assert_eq!(slicing.buckets(12_000), 3);
        assert_eq!(
            aggregation_buckets(u64::MAX, 1),
            GLOBAL_DAILY_MAX_BUCKETS_PER_DAY
        );
        assert_eq!(
            aggregation_buckets(10, 0),
            GLOBAL_DAILY_MAX_BUCKETS_PER_DAY.min(10)
        );
        // tenant1 24h at the 2 GiB default: ~64 M edge rows plan 16 slices.
        assert_eq!(
            aggregation_buckets(64_000_000, global_daily_slice_rows(2 << 30)),
            16
        );
    }

    #[test]
    fn full_global_daily_slices_hold_each_statement_under_the_row_target() {
        // NAN-2614: the single statement aggregated every part at once. The
        // plan must give every statement at most `slice_rows` estimated rows,
        // however many rows the horizon holds.
        let (parts, mins): (Vec<_>, Vec<_>) = [
            part_in_day("d1-a", "2026-08-01", 150),
            part_in_day("d1-b", "2026-08-01", 150),
            part_in_day("d3", "2026-08-03", 40),
            part_in_day("too-old", "2026-07-01", 1_000),
        ]
        .into_iter()
        .unzip();
        let slices = plan_global_daily_slices(
            &parts,
            &mins,
            &[0, 1, 2, 3],
            None,
            utc_date("2026-08-01"),
            utc_date("2026-08-03"),
            100,
        )
        .unwrap();
        let summary = slices
            .iter()
            .map(|slice| {
                (
                    slice.day.to_string(),
                    slice.bucket,
                    slice.buckets,
                    slice.part_indexes.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            vec![
                ("2026-08-01".to_string(), 0, 3, vec![0, 1]),
                ("2026-08-01".to_string(), 1, 3, vec![0, 1]),
                ("2026-08-01".to_string(), 2, 3, vec![0, 1]),
                ("2026-08-03".to_string(), 0, 1, vec![2]),
            ],
            "300 rows split into three buckets of 100; the empty day and the pre-horizon part are skipped"
        );
        assert!(slices
            .iter()
            .all(|slice| slice.source == GlobalDailySliceSource::Full));
        // Tripling the input triples the slices, never the per-slice target.
        let (parts, mins): (Vec<_>, Vec<_>) = (0..9)
            .map(|index| part_in_day(&format!("p{index}"), "2026-08-01", 100))
            .unzip();
        let tripled = plan_global_daily_slices(
            &parts,
            &mins,
            &(0..9).collect::<Vec<_>>(),
            None,
            utc_date("2026-08-01"),
            utc_date("2026-08-01"),
            100,
        )
        .unwrap();
        assert_eq!(tripled.len(), 9);
        assert!(tripled.iter().all(|slice| slice.buckets == 9));
    }

    #[test]
    fn incremental_global_daily_slices_merge_only_where_the_delta_can_land() {
        let (mut parts, mut mins): (Vec<_>, Vec<_>) = [
            part_in_day("carried", "2026-08-01", 500),
            part_in_day("new", "2026-08-02", 30),
        ]
        .into_iter()
        .unzip();
        // A reused part with an unknown minimum spans every day up to its max.
        let (unknown, _) = part_in_day("unknown-min", "2026-08-03", 10);
        parts.push(unknown);
        mins.push(0);
        let prior_rows = BTreeMap::from([
            (utc_date("2026-08-01"), 250_u64),
            (utc_date("2026-08-02"), 90),
        ]);
        let slices = plan_global_daily_slices(
            &parts,
            &mins,
            &[1, 2],
            Some(&prior_rows),
            utc_date("2026-08-01"),
            utc_date("2026-08-03"),
            100,
        )
        .unwrap();
        let summary = slices
            .iter()
            .map(|slice| {
                (
                    slice.day.to_string(),
                    slice.bucket,
                    slice.buckets,
                    slice.source,
                    slice.part_indexes.clone(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            summary,
            vec![
                // The unknown-minimum part may hold rows for every day.
                (
                    "2026-08-01".to_string(),
                    0,
                    3,
                    GlobalDailySliceSource::Merge,
                    vec![2]
                ),
                (
                    "2026-08-01".to_string(),
                    1,
                    3,
                    GlobalDailySliceSource::Merge,
                    vec![2]
                ),
                (
                    "2026-08-01".to_string(),
                    2,
                    3,
                    GlobalDailySliceSource::Merge,
                    vec![2]
                ),
                (
                    "2026-08-02".to_string(),
                    0,
                    2,
                    GlobalDailySliceSource::Merge,
                    vec![1, 2]
                ),
                (
                    "2026-08-02".to_string(),
                    1,
                    2,
                    GlobalDailySliceSource::Merge,
                    vec![1, 2]
                ),
                (
                    "2026-08-03".to_string(),
                    0,
                    1,
                    GlobalDailySliceSource::Merge,
                    vec![2]
                ),
            ]
        );
        // With no delta at all, prior days are carried and empty days skipped.
        let carried = plan_global_daily_slices(
            &parts,
            &mins,
            &[],
            Some(&prior_rows),
            utc_date("2026-08-01"),
            utc_date("2026-08-03"),
            100,
        )
        .unwrap();
        assert_eq!(carried.len(), 4);
        assert!(carried
            .iter()
            .all(|slice| slice.source == GlobalDailySliceSource::Carry
                && slice.part_indexes.is_empty()));
        // Nothing inside the horizon still yields one schema-bearing slice.
        let empty = plan_global_daily_slices(
            &parts,
            &mins,
            &[],
            Some(&BTreeMap::new()),
            utc_date("2026-08-01"),
            utc_date("2026-08-03"),
            100,
        )
        .unwrap();
        assert_eq!(empty.len(), 1);
        assert_eq!(empty[0].source, GlobalDailySliceSource::Carry);
    }

    #[test]
    fn a_missing_or_tampered_sidecar_downgrades_to_a_full_rebuild() {
        let root = tempfile::tempdir().unwrap();
        let part = root.path().join("part.parquet");
        std::fs::write(&part, b"immutable-part").unwrap();
        let part_build = PrevalencePartBuild {
            relative_path: "hour=1/object.parquet".to_string(),
            event_object_key: "s3://test/events/hour=1/object.parquet".to_string(),
            event_object_version: "version-1".to_string(),
            event_object_bytes: 123,
            part_file: part.clone(),
            part_sha256: file_sha256(&part).unwrap(),
            part_bytes: std::fs::metadata(&part).unwrap().len(),
            rows: 1,
            max_event_time_us: 1_000_000,
            source_types: vec!["fw".to_string()],
        };
        let identity = prevalence_object_identity(
            &part_build.event_object_key,
            &part_build.event_object_version,
            part_build.event_object_bytes,
        );
        let prior_parts = [(identity.clone(), part_build)]
            .into_iter()
            .collect::<BTreeMap<_, _>>();

        // No sidecar at all: no carry, no bounds.
        let state = prior_incremental_state(Some(root.path()), "tenant-a", &prior_parts);
        assert!(state.global_daily.is_none() && state.min_event_times.is_empty());

        // A sidecar whose aggregate file digest does not match: bounds are
        // still usable (pruning is only an optimization) but the carry is
        // refused — a silently altered aggregate would silently alter
        // detection thresholds.
        std::fs::create_dir_all(root.path().join("daily")).unwrap();
        let global = root.path().join(GLOBAL_DAILY_RELATIVE);
        std::fs::write(&global, b"aggregate-bytes").unwrap();
        let sidecar = PrevalenceIncrementalSidecar {
            schema_version: PREVALENCE_INCREMENTAL_SCHEMA_VERSION,
            tenant_id: "tenant-a".to_string(),
            event_snapshot_id: 7,
            max_event_time_us: 1_000_000,
            horizon_day: "2026-07-20".to_string(),
            global_daily_sha256: file_sha256(&global).unwrap(),
            global_daily_bytes: std::fs::metadata(&global).unwrap().len(),
            global_daily_rows: 3,
            global_daily_incremental: false,
            delta_source_files: 1,
            part_event_time_bounds: vec![PartEventTimeBound {
                event_object_key: identity.0.clone(),
                event_object_version: identity.1.clone(),
                event_object_bytes: identity.2,
                min_event_time_us: 555,
            }],
        };
        write_json(&root.path().join(INCREMENTAL_SIDECAR_FILE), &sidecar).unwrap();
        let state = prior_incremental_state(Some(root.path()), "tenant-a", &prior_parts);
        assert!(state.global_daily.is_some());
        assert_eq!(state.min_event_times.get(&identity), Some(&555));

        // Tamper with the aggregate file: carry must be refused.
        std::fs::write(&global, b"tampered-aggregate").unwrap();
        let state = prior_incremental_state(Some(root.path()), "tenant-a", &prior_parts);
        assert!(state.global_daily.is_none());
        assert_eq!(state.min_event_times.get(&identity), Some(&555));

        // Wrong tenant: nothing is usable.
        let state = prior_incremental_state(Some(root.path()), "tenant-b", &prior_parts);
        assert!(state.global_daily.is_none() && state.min_event_times.is_empty());
    }

    // -- value/key encoding (unchanged serving contract) ----------------------

    #[test]
    fn value_encoding_matches_serving_contract_and_merges() {
        let first = Value {
            hosts: [1, 2].into_iter().collect(),
            saturated: false,
            private: false,
            first_us: 10,
            last_us: 20,
            occurrences: 3,
        };
        assert_eq!(decode(&encode(&first).unwrap()).unwrap().hosts, first.hosts);
        let second = Value {
            hosts: [2, 3].into_iter().collect(),
            saturated: false,
            private: true,
            first_us: 5,
            last_us: 30,
            occurrences: 4,
        };
        let merged = ValueMerge
            .merge(
                &slatedb::bytes::Bytes::new(),
                Some(encode(&first).unwrap().into()),
                encode(&second).unwrap().into(),
            )
            .unwrap();
        let merged = decode(&merged).unwrap();
        assert_eq!(merged.hosts, [1, 2, 3].into_iter().collect());
        assert_eq!(
            (merged.first_us, merged.last_us, merged.occurrences),
            (5, 30, 7)
        );
        assert!(merged.private);
    }

    #[test]
    fn keys_are_normalized_scoped_and_hmaced() {
        let secret = vec![7; 32];
        assert_eq!(
            key(&secret, "ip", "source-a", " 10.0.0.1 ").unwrap(),
            key(&secret, "ip", "source-a", "10.0.0.1").unwrap()
        );
        assert_ne!(
            key(&secret, "ip", "source-a", "10.0.0.1").unwrap(),
            key(&secret, "ip", "source-b", "10.0.0.1").unwrap()
        );
    }

    // -- SlateDB physical format (NAN-2361 footprint) --------------------------
    //
    // The load below writes each window database exactly once, so the WAL is
    // pure scaffolding (it was 29% of the live prevalence derivative) and the
    // superseded L0 SSTs plus stale manifests left behind by load-time
    // compaction are garbage. These tests prove the slimmed physical format
    // (WAL disabled, zstd SST blocks, one-shot GC) still serves EVERY row of
    // the scan parquet byte-exactly through the same checkpoint reader the
    // serving worker uses.

    /// Write a parquet file with the exact window-snapshot schema, bypassing
    /// chDB so this test runs everywhere.
    fn write_window_scan_parquet(
        path: &Path,
        rows: &[(String, String, String, Vec<u64>, u8, u8, i64, i64, u64)],
    ) {
        use arrow_array::builder::{ListBuilder, UInt64Builder};
        use arrow_array::{RecordBatch, TimestampMicrosecondArray, UInt64Array, UInt8Array};
        use arrow_schema::{DataType, Field, Schema, TimeUnit};
        use std::sync::Arc as StdArc;
        let schema = StdArc::new(Schema::new(vec![
            Field::new("kind", DataType::Utf8, false),
            Field::new("scope", DataType::Utf8, false),
            Field::new("entity", DataType::Utf8, false),
            Field::new(
                "host_fingerprints",
                DataType::List(StdArc::new(Field::new("item", DataType::UInt64, false))),
                false,
            ),
            Field::new("host_count_saturated", DataType::UInt8, false),
            Field::new("is_private", DataType::UInt8, false),
            Field::new(
                "first_seen",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new(
                "last_seen",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            Field::new("total_occurrences", DataType::UInt64, false),
        ]));
        let mut hosts = ListBuilder::new(UInt64Builder::new()).with_field(Field::new(
            "item",
            DataType::UInt64,
            false,
        ));
        for row in rows {
            hosts.values().append_slice(&row.3);
            hosts.append(true);
        }
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                StdArc::new(StringArray::from_iter_values(
                    rows.iter().map(|row| row.0.as_str()),
                )),
                StdArc::new(StringArray::from_iter_values(
                    rows.iter().map(|row| row.1.as_str()),
                )),
                StdArc::new(StringArray::from_iter_values(
                    rows.iter().map(|row| row.2.as_str()),
                )),
                StdArc::new(hosts.finish()),
                StdArc::new(UInt8Array::from_iter_values(rows.iter().map(|row| row.4))),
                StdArc::new(UInt8Array::from_iter_values(rows.iter().map(|row| row.5))),
                StdArc::new(TimestampMicrosecondArray::from_iter_values(
                    rows.iter().map(|row| row.6),
                )),
                StdArc::new(TimestampMicrosecondArray::from_iter_values(
                    rows.iter().map(|row| row.7),
                )),
                StdArc::new(UInt64Array::from_iter_values(rows.iter().map(|row| row.8))),
            ],
        )
        .unwrap();
        let mut writer =
            parquet::arrow::ArrowWriter::try_new(File::create(path).unwrap(), schema, None)
                .unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    /// Read every row of a window scan parquet back through the checkpointed
    /// SlateDB using the SAME reader mode as the serving worker, and require
    /// decoded-value equality. This is the fence that makes any physical-format
    /// change (compression, WAL, GC) provably contract-preserving.
    async fn assert_slatedb_serves_scan_exactly(
        scan: &Path,
        database_path: &str,
        checkpoint_id: uuid::Uuid,
        secret: &[u8],
    ) -> usize {
        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix("/").unwrap());
        let reader = slatedb::DbReaderBuilder::new(database_path, store)
            .with_reader_mode(slatedb::DbReaderMode::Checkpoint(checkpoint_id))
            .build()
            .await
            .expect("open checkpoint reader");
        let parquet = ParquetRecordBatchReaderBuilder::try_new(File::open(scan).unwrap())
            .unwrap()
            .with_batch_size(BATCH_ROWS)
            .build()
            .unwrap();
        let mut checked = 0_usize;
        for batch in parquet {
            let batch = batch.unwrap();
            let kinds = strings(&batch, "kind").unwrap();
            let scopes = strings(&batch, "scope").unwrap();
            let entities = strings(&batch, "entity").unwrap();
            let hosts = list_u64(&batch, "host_fingerprints").unwrap();
            let saturated = u8s(&batch, "host_count_saturated").unwrap();
            let private = u8s(&batch, "is_private").unwrap();
            let first = timestamp_us(&batch, "first_seen").unwrap();
            let last = timestamp_us(&batch, "last_seen").unwrap();
            let occurrences = u64s(&batch, "total_occurrences").unwrap();
            for index in 0..batch.num_rows() {
                let stored = reader
                    .get(key(secret, &kinds[index], &scopes[index], &entities[index]).unwrap())
                    .await
                    .expect("checkpoint read")
                    .unwrap_or_else(|| {
                        panic!("entity {} is missing from the checkpoint", entities[index])
                    });
                let stored = decode(&stored).unwrap();
                assert_eq!(
                    stored.hosts,
                    hosts[index]
                        .iter()
                        .copied()
                        .take(HOST_CAP)
                        .collect::<BTreeSet<_>>(),
                    "host fingerprints diverged for {}",
                    entities[index]
                );
                assert_eq!(
                    (
                        stored.saturated,
                        stored.private,
                        stored.first_us,
                        stored.last_us,
                        stored.occurrences,
                    ),
                    (
                        saturated[index] != 0 || hosts[index].len() >= HOST_CAP,
                        private[index] != 0,
                        first[index],
                        last[index],
                        occurrences[index],
                    ),
                    "scalar prevalence value diverged for {}",
                    entities[index]
                );
                checked += 1;
            }
        }
        // A key that was never written must stay absent (the reader is not
        // somehow serving from a shared or stale sorted run).
        assert!(
            reader
                .get(key(secret, "ip", "no-such-scope", "203.0.113.254").unwrap())
                .await
                .unwrap()
                .is_none(),
            "an unwritten key must not resolve"
        );
        checked
    }

    fn directory_bytes(root: &Path) -> u64 {
        if !root.is_dir() {
            return 0;
        }
        walk(root)
            .unwrap()
            .into_iter()
            .filter(|path| path.is_file())
            .map(|path| std::fs::metadata(path).unwrap().len())
            .sum()
    }

    fn file_count(root: &Path) -> usize {
        if !root.is_dir() {
            return 0;
        }
        walk(root)
            .unwrap()
            .into_iter()
            .filter(|path| path.is_file())
            .count()
    }

    #[tokio::test]
    async fn slatedb_load_is_wal_free_scrubbed_and_read_back_exact() {
        // Deterministic corpus, large enough that multiple memtable batches
        // and manifest updates happen, with realistic value shapes (skewed
        // host-set sizes up to and past the cap).
        let mut state = 0x2545F4914F6CDD1D_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let scopes = ["fw", "windows_sysmon", "aws_cloudtrail"];
        let kinds = ["ip", "domain", "hash"];
        let mut rows = Vec::new();
        for index in 0..50_000_u64 {
            let kind = kinds[(next() % 3) as usize];
            let scope = scopes[(next() % 3) as usize];
            let entity = match kind {
                "ip" => format!("10.{}.{}.{}", next() % 256, next() % 256, next() % 256),
                "domain" => format!("host-{index}.example.com"),
                _ => format!("{:032x}", next()),
            };
            let host_count = match next() % 10 {
                0 => 70, // past the cap: capped upstream to 65
                1..=3 => 1,
                _ => (next() % 8 + 1) as usize,
            };
            let hosts = (0..host_count.min(HOST_CAP))
                .map(|_| next())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let saturated = u8::from(host_count >= HOST_CAP);
            let first = 1_700_000_000_000_000 + (next() % 1_000_000_000) as i64;
            rows.push((
                kind.to_string(),
                scope.to_string(),
                entity,
                hosts,
                saturated,
                (next() % 2) as u8,
                first,
                first + (next() % 1_000_000_000) as i64,
                next() % 100_000,
            ));
        }
        // The scan is unique per (kind, scope, entity) by construction of the
        // GROUP BY that produces it; deduplicate the synthetic corpus the same
        // way so read-back equality is well defined.
        rows.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
        rows.dedup_by(|a, b| (&a.0, &a.1, &a.2) == (&b.0, &b.1, &b.2));

        let root = tempfile::tempdir().unwrap();
        let scan = root.path().join("snapshot.parquet");
        write_window_scan_parquet(&scan, &rows);
        let secret = vec![9_u8; 32];
        let database_root = root.path().join("slatedb");
        let database_path = object_store_path(&database_root).unwrap();
        let checkpoint_id = load_slatedb(&scan, &database_path, &secret).await.unwrap();

        // WAL bytes were 29% of the live derivative and provide nothing for a
        // write-once database published by rename: there must be no WAL
        // payload. (A zero-byte writer-epoch FENCE object is expected — it is
        // fencing metadata, not logged data, and its GC knob is deliberately
        // left off.)
        assert_eq!(
            directory_bytes(&database_root.join("wal")),
            0,
            "the write-once prevalence load must not persist WAL payload bytes"
        );
        // The one-shot GC must have scrubbed stale manifests (every flush and
        // the checkpoint write each leave one behind; only the checkpointed
        // state may remain).
        assert!(
            file_count(&database_root.join("manifest")) <= 2,
            "stale manifests survived the post-load garbage collection"
        );

        let checked =
            assert_slatedb_serves_scan_exactly(&scan, &database_path, checkpoint_id, &secret).await;
        assert_eq!(checked, rows.len(), "every scan row must be checked");
        // Report (not assert) the physical footprint so before/after runs are
        // comparable in test output.
        eprintln!(
            "slatedb bytes={} scan_bytes={} rows={}",
            directory_bytes(&database_root),
            std::fs::metadata(&scan).unwrap().len(),
            rows.len()
        );
    }

    #[tokio::test]
    async fn slatedb_incremental_advance_is_exact_and_does_not_mutate_prior() {
        let row = |entity: &str, hosts: Vec<u64>, occurrences: u64| {
            (
                "ip".to_string(),
                "fw".to_string(),
                entity.to_string(),
                hosts,
                0,
                0,
                1_700_000_000_000_000,
                1_700_000_001_000_000,
                occurrences,
            )
        };
        let prior_rows = vec![
            row("10.0.0.1", vec![1], 1),
            row("10.0.0.2", vec![2], 2),
            row("10.0.0.3", vec![3], 3),
        ];
        let rows = vec![
            row("10.0.0.1", vec![1], 1),
            row("10.0.0.2", vec![2, 20], 20),
            row("10.0.0.4", vec![4], 4),
        ];
        let root = tempfile::tempdir().unwrap();
        let prior_scan = root.path().join("prior.parquet");
        let scan = root.path().join("next.parquet");
        write_window_scan_parquet(&prior_scan, &prior_rows);
        write_window_scan_parquet(&scan, &rows);
        let secret = vec![11_u8; 32];
        let prior_database_root = root.path().join("prior-slatedb");
        let database_root = root.path().join("next-slatedb");
        let prior_database_path = object_store_path(&prior_database_root).unwrap();
        let database_path = object_store_path(&database_root).unwrap();
        let prior_checkpoint_id = load_slatedb(&prior_scan, &prior_database_path, &secret)
            .await
            .unwrap();
        let (checkpoint_id, changed_rows, deleted_rows) = load_slatedb_incremental(
            &prior_scan,
            &scan,
            &prior_database_path,
            prior_checkpoint_id,
            &database_path,
            &secret,
        )
        .await
        .unwrap();
        assert_eq!((changed_rows, deleted_rows), (2, 1));
        assert_eq!(
            assert_slatedb_serves_scan_exactly(&scan, &database_path, checkpoint_id, &secret).await,
            rows.len()
        );

        let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix("/").unwrap());
        let reader = slatedb::DbReaderBuilder::new(database_path.as_str(), store)
            .with_reader_mode(slatedb::DbReaderMode::Checkpoint(checkpoint_id))
            .build()
            .await
            .unwrap();
        assert!(
            reader
                .get(key(&secret, "ip", "fw", "10.0.0.3").unwrap())
                .await
                .unwrap()
                .is_none(),
            "a row absent from the new scan survived the incremental tombstone"
        );
        assert_eq!(
            assert_slatedb_serves_scan_exactly(
                &prior_scan,
                &prior_database_path,
                prior_checkpoint_id,
                &secret,
            )
            .await,
            prior_rows.len(),
            "incremental publication mutated its immutable parent database"
        );
    }

    // -- end-to-end equivalence against a real chDB ---------------------------
    //
    // These scenarios drive build_prevalence_generation itself (the call
    // site, not a helper) against a real native chDB and prove:
    //   A. an incremental chain produces results provably equal to a full
    //      rebuild AND to the frozen pre-incremental SQL,
    //   B. a closed day's parts are NOT re-read by an incremental build,
    //   C. a retired prior part forces (and gets) a full re-aggregation,
    //   D. saturated-host semantics (count + flag) survive the merge exactly.

    /// The daily-history and window-scan statements exactly as they were
    /// before the incremental build (frozen oracle — do not "fix" these, their
    /// value is that they are the OLD behavior).
    const ORACLE_DAILY_HISTORY: &str = r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, toDate(time) day, count() daily_count
FROM file({source:String}, Parquet)
WHERE kind != '__meta' AND toUnixTimestamp64Micro(time) >= toInt64({start_us:String})
GROUP BY kind, scope, entity, day
ORDER BY kind, scope, entity, day
SETTINGS max_memory_usage=1073741824, max_threads=4, use_query_cache=0, use_hive_partitioning=0
"#;

    const ORACLE_WINDOW_SCAN: &str = r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) host_fingerprints,
       toUInt8(length(host_fingerprints) = 65) host_count_saturated,
       max(is_private) is_private, min(time) first_seen, max(time) last_seen,
       count() total_occurrences
FROM file({source:String}, Parquet)
WHERE kind != '__meta' AND toUnixTimestamp64Micro(time) >= toInt64({start_us:String})
GROUP BY kind, scope, entity
ORDER BY kind, scope, entity
SETTINGS max_memory_usage=1073741824, max_threads=4, use_query_cache=0, use_hive_partitioning=0
"#;

    struct Ev {
        ts: &'static str,
        log_source: &'static str,
        device_host: String,
        sip: Option<&'static str>,
        dip: Option<&'static str>,
        dhost: Option<&'static str>,
        hash: Option<&'static str>,
    }

    fn ev(
        ts: &'static str,
        device_host: &str,
        sip: Option<&'static str>,
        dip: Option<&'static str>,
        dhost: Option<&'static str>,
        hash: Option<&'static str>,
    ) -> Ev {
        Ev {
            ts,
            log_source: "fw",
            device_host: device_host.to_string(),
            sip,
            dip,
            dhost,
            hash,
        }
    }

    fn write_source_object(connection: &NativeConnection, output: &Path, events: &[Ev]) {
        // chDB string parameters cannot carry newlines, so the JSONEachRow
        // payload travels hex-encoded and is decoded inside the statement.
        let data = events
            .iter()
            .map(|event| {
                serde_json::json!({
                    "ts": event.ts,
                    "log_source": event.log_source,
                    "device_host": event.device_host,
                    "sip": event.sip,
                    "dip": event.dip,
                    "shost": serde_json::Value::Null,
                    "dhost": event.dhost,
                    "uhost": serde_json::Value::Null,
                    "hashes": event.hash.map(|h| vec![h]).unwrap_or_default(),
                    "phashes": Vec::<String>::new(),
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        let structure = "ts String, log_source String, device_host Nullable(String), \
                         sip Nullable(String), dip Nullable(String), shost Nullable(String), \
                         dhost Nullable(String), uhost Nullable(String), \
                         hashes Array(String), phashes Array(String)";
        let sql = r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT toDateTime64(ts, 6, 'UTC') AS time,
       CAST(tuple(log_source), 'Tuple(log_source Nullable(String))') AS metadata,
       CAST(tuple(device_host), 'Tuple(hostname Nullable(String))') AS device,
       CAST(tuple(sip, shost), 'Tuple(ip Nullable(String), hostname Nullable(String))') AS src_endpoint,
       CAST(tuple(dip, dhost), 'Tuple(ip Nullable(String), hostname Nullable(String))') AS dst_endpoint,
       CAST(tuple(tuple(uhost)), 'Tuple(url Tuple(hostname Nullable(String)))') AS http_request,
       CAST(tuple(arrayMap(h -> tuple(h), hashes)), 'Tuple(hashes Array(Tuple(value String)))') AS file,
       CAST(tuple(tuple(arrayMap(h -> tuple(h), phashes))), 'Tuple(file Tuple(hashes Array(Tuple(value String))))') AS process
FROM format(JSONEachRow, {structure:String}, unhex({data:String}))
SETTINGS use_query_cache=0
"#;
        let data_hex = hex::encode(data.as_bytes());
        connection
            .query_with_params(
                sql,
                "Null",
                &[
                    ("output", output.to_string_lossy().as_ref()),
                    ("structure", structure),
                    ("data", data_hex.as_str()),
                ],
            )
            .expect("write source object");
    }

    /// NAN-3449: the CT 106 shape. The OCSF fingerprint struct's member set
    /// is fixed per column by whichever event first populated it, so one
    /// object can carry `file.hashes` as Tuple(algorithm, algorithm_id, value)
    /// and `process.file.hashes` as Tuple(algorithm_id, value), and a second
    /// object the reverse. `arrayConcat` over the raw tuple arrays failed the
    /// mandatory build with chDB Code 386 NO_COMMON_TYPE. Every hash value from
    /// both parts must now survive. Run alone (one chDB connection per
    /// process):
    /// `NANO_CHDB_LIBRARY_PATH=... cargo test -p nanosiem-lake-worker --lib \
    ///  observation_part_tolerates_hash_struct_member_drift -- --ignored`
    #[test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH (and optionally NANO_CHDB_LIBRARY_SHA256)"]
    fn observation_part_tolerates_hash_struct_member_drift() {
        let library = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("library path");
        let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256")
            .unwrap_or_else(|_| file_sha256(Path::new(&library)).expect("digest library"));
        let runtime =
            crate::native::NativeChdb::load_verified(&library, &digest).expect("load chDB");
        let connection = runtime.connect(&[]).expect("connect");
        let root = tempfile::tempdir().unwrap();
        let root = root.path();

        const WITH_ALGORITHM: &str =
            "Array(Tuple(algorithm Nullable(String), algorithm_id Nullable(Int64), value Nullable(String)))";
        const WITHOUT_ALGORITHM: &str =
            "Array(Tuple(algorithm_id Nullable(Int64), value Nullable(String)))";
        let file_md5 = "0123456789abcdef0123456789abcdef";
        let process_sha256 = "aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999";
        let actor_sha1 = "0123456789abcdef0123456789abcdef01234567";
        let other_md5 = "fedcba9876543210fedcba9876543210";
        // (object, file.hashes type, file rows, process.file.hashes type, process rows)
        let parts = [
            (
                "object-a.parquet",
                WITH_ALGORITHM,
                format!("[('MD5', 1, '{file_md5}')]"),
                WITHOUT_ALGORITHM,
                format!("[(3, '{process_sha256}')]"),
            ),
            (
                "object-b.parquet",
                WITHOUT_ALGORITHM,
                format!("[(1, '{other_md5}'), (NULL, NULL)]"),
                WITH_ALGORITHM,
                "[]".to_string(),
            ),
        ];
        let mut entities = std::collections::BTreeSet::new();
        for (name, file_type, file_rows, process_type, process_rows) in &parts {
            let source = root.join(name);
            let sql = format!(
                "INSERT INTO FUNCTION file({{output:String}}, Parquet) \
                 SELECT toDateTime64('2026-10-09 14:32:06', 6, 'UTC') AS time, \
                        CAST(tuple('windows_sysmon'), 'Tuple(log_source Nullable(String))') AS metadata, \
                        CAST(tuple('host-a'), 'Tuple(hostname Nullable(String))') AS device, \
                        CAST(tuple(CAST({file_rows}, '{file_type}')), 'Tuple(hashes {file_type})') AS file, \
                        CAST(tuple(tuple(CAST({process_rows}, '{process_type}'))), \
                             'Tuple(file Tuple(hashes {process_type}))') AS process, \
                        CAST(tuple(tuple(tuple(CAST([(3, '{actor_sha1}')], '{WITHOUT_ALGORITHM}')))), \
                             'Tuple(process Tuple(file Tuple(hashes {WITHOUT_ALGORITHM})))') AS actor \
                 SETTINGS use_query_cache=0"
            );
            connection
                .query_with_params(
                    &sql,
                    "Null",
                    &[("output", source.to_string_lossy().as_ref())],
                )
                .expect("write drifted source object");
            let output = root.join(format!("observed-{name}"));
            build_prevalence_observation_part(
                &connection,
                &source,
                &output,
                PREVALENCE_BUILD_MEMORY_FLOOR_BYTES,
            )
            .unwrap_or_else(|error| panic!("{name}: observation build failed: {error:#}"));
            let rows = connection
                .query_with_params(
                    "SELECT kind, entity FROM file({output:String}, Parquet) ORDER BY entity",
                    "TSV",
                    &[("output", output.to_string_lossy().as_ref())],
                )
                .expect("read observation part");
            for line in String::from_utf8(rows.data).unwrap().lines() {
                let (kind, entity) = line.split_once('\t').expect("kind\tentity");
                assert_eq!(kind, "hash", "{name}: unexpected kind in {line}");
                entities.insert(entity.to_string());
            }
        }
        let expected: std::collections::BTreeSet<String> =
            [file_md5, process_sha256, actor_sha1, other_md5]
                .iter()
                .map(|v| v.to_string())
                .collect();
        assert_eq!(
            entities, expected,
            "every prevalence-relevant hash value must survive"
        );
    }

    /// NAN-2828: the sliced window and explorer builds write byte-identical
    /// artifacts to the unsliced statements. Run alone (one chDB connection
    /// per process):
    /// `NANO_CHDB_LIBRARY_PATH=... cargo test -p nanosiem-lake-worker --lib \
    ///  sliced_window_and_explorer_match_the_unsliced_statements -- --ignored`
    #[test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH (and optionally NANO_CHDB_LIBRARY_SHA256)"]
    fn sliced_window_and_explorer_match_the_unsliced_statements() {
        let library = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("library path");
        let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256")
            .unwrap_or_else(|_| file_sha256(Path::new(&library)).expect("digest library"));
        let runtime =
            crate::native::NativeChdb::load_verified(&library, &digest).expect("load chDB");
        let connection = runtime.connect(&[]).expect("connect");
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let limits = PrevalenceBuildLimits {
            memory_bytes: 1 << 30,
            aggregate_threads: 1,
        };
        // Observation parts for the edge day 2026-09-23 and the open day
        // 2026-09-24: repeated entities across scopes, hosts past the 65 cap,
        // private IPs, and rows before the window start that must drop out.
        let edge_dir = root.join("edge");
        std::fs::create_dir(&edge_dir).unwrap();
        for (index, day) in ["2026-09-23", "2026-09-23", "2026-09-24"]
            .iter()
            .enumerate()
        {
            let output = edge_dir.join(format!("object-{index:04}.parquet"));
            connection
                .query_with_params(
                    "INSERT INTO FUNCTION file({output:String}, Parquet) \
                     SELECT multiIf(number % 5 = 0, 'domain', number % 7 = 0, 'hash', 'ip') kind, \
                            concat('src', toString(number % 3)) scope, \
                            multiIf(kind = 'domain', concat('d', toString(number % 997), '.example.com'), \
                                    kind = 'hash', lower(hex(MD5(toString(number % 311)))), \
                                    IPv4NumToString(toUInt32(167772160 + (number * 7919) % 4099))) entity, \
                            cityHash64(number % 151, {seed:UInt64}) host, \
                            toUInt8(kind = 'ip' AND number % 2 = 0) is_private, \
                            toDateTime64({day:String}, 6, 'UTC') + toIntervalSecond(intDiv(number * 86399, 60000)) time \
                     FROM numbers(60000)",
                    "Null",
                    &[
                        ("output", output.to_string_lossy().as_ref()),
                        ("day", day),
                        ("seed", &index.to_string()),
                    ],
                )
                .expect("write observation part");
        }
        let global = root.join("global-daily.parquet");
        connection
            .query_with_params(
                "INSERT INTO FUNCTION file({output:String}, Parquet) \
                 SELECT kind, scope, entity, toDate(time, 'UTC') day, \
                        arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) host_fingerprints, \
                        max(is_private) is_private, min(time) first_seen, max(time) last_seen, \
                        count() daily_count \
                 FROM file({source:String}, Parquet) \
                 GROUP BY kind, scope, entity, day ORDER BY kind, scope, entity, day",
                "Null",
                &[
                    ("output", global.to_string_lossy().as_ref()),
                    (
                        "source",
                        &format!("{}/*.parquet", edge_dir.to_string_lossy()),
                    ),
                ],
            )
            .expect("write global aggregate");
        let start_us = utc_day_start_us(utc_date("2026-09-23")).unwrap() + 3 * 3_600_000_000;
        let work = root.join("work");
        let sha = |path: &Path| file_sha256(path).unwrap();
        let build = |name: &str, buckets: u64, edge: bool| {
            let window = root.join(format!("{name}-window.parquet"));
            if edge {
                build_window_from_global_and_edge(
                    &connection,
                    &global,
                    &edge_dir,
                    &work.join(name),
                    &window,
                    start_us,
                    "2026-09-23",
                    &limits,
                    buckets,
                )
                .unwrap();
            } else {
                build_window_from_global(
                    &connection,
                    &global,
                    &work.join(name),
                    &window,
                    "2026-09-22",
                    &limits,
                    buckets,
                )
                .unwrap();
            }
            window
        };
        for edge in [true, false] {
            let whole = build(&format!("whole-{edge}"), 1, edge);
            assert!(
                parquet_rows(&whole).unwrap() > 1_000,
                "fixture is too small to slice"
            );
            for buckets in [2, 7, 64] {
                let sliced = build(&format!("sliced-{edge}-{buckets}"), buckets, edge);
                assert_eq!(
                    sha(&sliced),
                    sha(&whole),
                    "window (edge={edge}) sliced into {buckets} buckets diverged from the unsliced statement"
                );
                assert!(
                    !work.join(format!("sliced-{edge}-{buckets}")).exists(),
                    "slice work left behind"
                );
            }
            // Explorer: the unsliced statement vs the sliced build over the same window.
            let explorer_whole = root.join(format!("explorer-whole-{edge}.parquet"));
            let explorer_sliced = root.join(format!("explorer-sliced-{edge}.parquet"));
            let one = WindowSlicing {
                global_day_rows: BTreeMap::new(),
                slice_rows: u64::MAX,
            };
            let many = WindowSlicing {
                global_day_rows: BTreeMap::new(),
                slice_rows: 500,
            };
            build_explorer_from_window(&connection, &whole, &work, &explorer_whole, &limits, &one)
                .unwrap();
            build_explorer_from_window(
                &connection,
                &whole,
                &work,
                &explorer_sliced,
                &limits,
                &many,
            )
            .unwrap();
            assert_eq!(
                sha(&explorer_sliced),
                sha(&explorer_whole),
                "sliced explorer (edge={edge}) diverged from the unsliced statement"
            );
        }
        // A window whose filters keep nothing still writes the canonical
        // (empty) artifact through the unsliced fallback.
        let empty_whole = root.join("empty-whole.parquet");
        let empty_sliced = root.join("empty-sliced.parquet");
        build_window_from_global(
            &connection,
            &global,
            &work.join("ew"),
            &empty_whole,
            "2026-09-30",
            &limits,
            1,
        )
        .unwrap();
        build_window_from_global(
            &connection,
            &global,
            &work.join("es"),
            &empty_sliced,
            "2026-09-30",
            &limits,
            5,
        )
        .unwrap();
        assert_eq!(parquet_rows(&empty_sliced).unwrap(), 0);
        assert_eq!(sha(&empty_sliced), sha(&empty_whole));
        drop(connection);
        std::mem::forget(runtime);
    }

    fn table_text(connection: &NativeConnection, path: &Path) -> String {
        let output = connection
            .query_with_params(
                "SELECT * FROM file({p:String}, Parquet) ORDER BY ALL",
                "JSONEachRow",
                &[("p", path.to_string_lossy().as_ref())],
            )
            .expect("read table");
        String::from_utf8(output.data).expect("utf8 table text")
    }

    fn table_text_without_fingerprints(connection: &NativeConnection, path: &Path) -> String {
        let output = connection
            .query_with_params(
                "SELECT kind, scope, entity, length(host_fingerprints) fingerprint_count, \
                 host_count_saturated, is_private, first_seen, last_seen, total_occurrences \
                 FROM file({p:String}, Parquet) ORDER BY ALL",
                "JSONEachRow",
                &[("p", path.to_string_lossy().as_ref())],
            )
            .expect("read table without fingerprints");
        String::from_utf8(output.data).expect("utf8 table text")
    }

    struct Corpus {
        input_root: PathBuf,
        objects: Vec<(String, PathBuf)>, // (relative_path, absolute path)
    }

    impl Corpus {
        fn stamp_manifest(&self, root: &Path, snapshot_id: i64, skip: &[&str]) -> PathBuf {
            let objects = self
                .objects
                .iter()
                .filter(|(rel, _)| !skip.contains(&rel.as_str()))
                .map(|(rel, path)| crate::generation::ObjectStamp {
                    relative_path: rel.clone(),
                    source_uri: format!("s3://corpus/{rel}"),
                    version_id: "v1".to_string(),
                    size_bytes: std::fs::metadata(path).unwrap().len(),
                    sha256: file_sha256(path).unwrap(),
                })
                .collect::<Vec<_>>();
            let manifest = ObjectStampManifest {
                metadata_location: "s3://corpus/metadata.json".to_string(),
                snapshot_id,
                table: "events".to_string(),
                objects,
                table_uuid: None,
            };
            let path = root.join(format!("stamps-{snapshot_id}.json"));
            write_json(&path, &manifest).unwrap();
            path
        }
    }

    fn load_sidecar(root: &Path) -> PrevalenceIncrementalSidecar {
        serde_json::from_slice(&std::fs::read(root.join(INCREMENTAL_SIDECAR_FILE)).unwrap())
            .unwrap()
    }

    async fn build(
        connection: &NativeConnection,
        corpus: &Corpus,
        root: &Path,
        name: &str,
        stamps: &Path,
        prior: Option<&Path>,
    ) -> PrevalenceBuildManifest {
        build_prevalence_generation(
            connection,
            &corpus.input_root,
            &root.join(name),
            stamps,
            "tenant-a",
            &root.join("hmac.key"),
            prior,
            None,
            None,
        )
        .await
        .unwrap_or_else(|error| panic!("build {name} failed: {error:#}"))
        .manifest
    }

    /// End-to-end incremental correctness against a real chDB. Everything runs
    /// inside ONE test so the process uses one native connection (chDB permits
    /// a single connection per process).
    #[tokio::test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH (and optionally NANO_CHDB_LIBRARY_SHA256)"]
    async fn incremental_prevalence_matches_full_rebuild_end_to_end() {
        let library = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("library path");
        let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256")
            .unwrap_or_else(|_| file_sha256(Path::new(&library)).expect("digest library"));
        let runtime =
            crate::native::NativeChdb::load_verified(&library, &digest).expect("load chDB");
        let connection = runtime.connect(&[]).expect("connect");

        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        std::fs::write(root.join("hmac.key"), [7u8; 64]).unwrap();
        let input_root = root.join("input");

        // D = 2026-08-15. All timestamps are explicit UTC.
        // O1: closed day D-10. O2: day D-1 around the 24h boundary.
        // O3: open day D through the P1 watermark (10:00).
        // O4 (P2): advances the watermark to 12:00.
        // O5 (P3): LATE ARRIVAL into closed day D-5, plus one open-day row.
        let objects: [(&str, Vec<Ev>); 5] = [
            (
                "hour=a/o1.parquet",
                vec![
                    ev(
                        "2026-08-05 09:00:00",
                        "h1",
                        Some("203.0.113.5"),
                        None,
                        None,
                        None,
                    ),
                    ev(
                        "2026-08-05 10:00:00",
                        "h1",
                        Some("203.0.113.5"),
                        None,
                        None,
                        None,
                    ),
                    ev(
                        "2026-08-05 11:00:00",
                        "h2",
                        Some("10.0.0.9"),
                        None,
                        None,
                        Some("0123456789abcdef0123456789abcdef"),
                    ),
                ],
            ),
            (
                "hour=b/o2.parquet",
                vec![
                    ev(
                        "2026-08-14 11:30:00",
                        "h2",
                        Some("203.0.113.5"),
                        None,
                        None,
                        None,
                    ),
                    ev(
                        "2026-08-14 13:00:00",
                        "h3",
                        None,
                        Some("198.51.100.2"),
                        Some("evil.example.com"),
                        None,
                    ),
                ],
            ),
            (
                "hour=c/o3.parquet",
                vec![
                    ev(
                        "2026-08-15 09:30:00",
                        "h1",
                        Some("203.0.113.5"),
                        None,
                        None,
                        None,
                    ),
                    ev(
                        "2026-08-15 10:00:00",
                        "h4",
                        None,
                        Some("198.51.100.2"),
                        None,
                        None,
                    ),
                ],
            ),
            (
                "hour=d/o4.parquet",
                vec![
                    ev(
                        "2026-08-15 11:15:00",
                        "h5",
                        Some("203.0.113.5"),
                        None,
                        None,
                        None,
                    ),
                    ev(
                        "2026-08-15 12:00:00",
                        "h1",
                        None,
                        None,
                        Some("evil.example.com"),
                        None,
                    ),
                ],
            ),
            (
                "hour=e/o5.parquet",
                vec![
                    // Late arrival: an event that belongs to CLOSED day D-5.
                    ev(
                        "2026-08-10 14:00:00",
                        "h6",
                        Some("203.0.113.5"),
                        None,
                        None,
                        None,
                    ),
                    ev(
                        "2026-08-15 11:59:00",
                        "h6",
                        Some("192.168.1.50"),
                        None,
                        None,
                        None,
                    ),
                ],
            ),
        ];
        let mut corpus = Corpus {
            input_root: input_root.clone(),
            objects: Vec::new(),
        };
        for (rel, events) in &objects {
            let path = input_root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            write_source_object(&connection, &path, events);
            corpus.objects.push(((*rel).to_string(), path));
        }

        // ---- Scenario A: three-promotion incremental chain -----------------
        let stamps1 = corpus.stamp_manifest(root, 1, &["hour=d/o4.parquet", "hour=e/o5.parquet"]);
        let stamps2 = corpus.stamp_manifest(root, 2, &["hour=e/o5.parquet"]);
        let stamps3 = corpus.stamp_manifest(root, 3, &[]);
        build(&connection, &corpus, root, "snap1", &stamps1, None).await;
        assert!(
            !load_sidecar(&root.join("snap1")).global_daily_incremental,
            "first build has no prior aggregate and must be full"
        );
        let manifest2 = build(
            &connection,
            &corpus,
            root,
            "snap2",
            &stamps2,
            Some(&root.join("snap1")),
        )
        .await;
        assert_eq!(manifest2.reused_source_files, 3);
        let sidecar2 = load_sidecar(&root.join("snap2"));
        assert!(
            sidecar2.global_daily_incremental && sidecar2.delta_source_files == 1,
            "second build must merge exactly the one identity-new part"
        );
        let incremental_started = std::time::Instant::now();
        let manifest3 = build(
            &connection,
            &corpus,
            root,
            "snap3",
            &stamps3,
            Some(&root.join("snap2")),
        )
        .await;
        let incremental_ms = incremental_started.elapsed().as_secs_f64() * 1000.0;
        let sidecar3 = load_sidecar(&root.join("snap3"));
        assert!(
            sidecar3.global_daily_incremental && sidecar3.delta_source_files == 1,
            "third build must merge exactly the late-arrival part"
        );

        // Full rebuild over the same corpus, no prior at all.
        let full_started = std::time::Instant::now();
        let manifest_full = build(&connection, &corpus, root, "snap-full", &stamps3, None).await;
        eprintln!("NAN2460 prevalence fixture: full_ms={:.3} incremental_ms={:.3} reused_sources={} new_sources={}",
            full_started.elapsed().as_secs_f64() * 1000.0, incremental_ms,
            manifest3.reused_source_files, manifest3.built_source_files);
        assert!(!load_sidecar(&root.join("snap-full")).global_daily_incremental);

        // Provable equality: daily history and all four windows, row for row.
        let daily_incremental = manifest3.daily_history.as_ref().unwrap();
        let daily_full = manifest_full.daily_history.as_ref().unwrap();
        assert_eq!(
            table_text(&connection, &daily_incremental.scan_file),
            table_text(&connection, &daily_full.scan_file),
            "incremental daily history diverged from a full rebuild"
        );
        for (window_incremental, window_full) in
            manifest3.windows.iter().zip(&manifest_full.windows)
        {
            assert_eq!(window_incremental.window, window_full.window);
            assert_eq!(
                table_text(&connection, &window_incremental.scan_file),
                table_text(&connection, &window_full.scan_file),
                "incremental {} window diverged from a full rebuild",
                window_incremental.window
            );
        }

        // Frozen-oracle equality: the OLD raw-scan SQL over the full parts set
        // must agree with the incremental outputs.
        let oracle_parts = root.join("snap-full").join("parts");
        let parts_glob = format!("{}/**/*.parquet", oracle_parts.to_string_lossy());
        let max_time_us = manifest3
            .parts
            .iter()
            .map(|part| part.max_event_time_us)
            .max()
            .unwrap();
        let daily_start_us =
            utc_day_start_us(utc_day(max_time_us).unwrap() - chrono::Duration::days(29)).unwrap();
        let oracle_daily = root.join("oracle-daily.parquet");
        connection
            .query_with_params(
                ORACLE_DAILY_HISTORY,
                "Null",
                &[
                    ("source", parts_glob.as_str()),
                    ("output", oracle_daily.to_string_lossy().as_ref()),
                    ("start_us", daily_start_us.to_string().as_str()),
                ],
            )
            .expect("oracle daily history");
        assert_eq!(
            table_text(&connection, &daily_incremental.scan_file),
            table_text(&connection, &oracle_daily),
            "incremental daily history diverged from the frozen pre-incremental SQL"
        );
        for &(window, seconds) in PREVALENCE_WINDOWS {
            let oracle_scan = root.join(format!("oracle-{window}.parquet"));
            let start_us = max_time_us - seconds * 1_000_000;
            connection
                .query_with_params(
                    ORACLE_WINDOW_SCAN,
                    "Null",
                    &[
                        ("source", parts_glob.as_str()),
                        ("output", oracle_scan.to_string_lossy().as_ref()),
                        ("start_us", start_us.to_string().as_str()),
                    ],
                )
                .expect("oracle window scan");
            let built = manifest3
                .windows
                .iter()
                .find(|candidate| candidate.window == window)
                .unwrap();
            assert_eq!(
                table_text(&connection, &built.scan_file),
                table_text(&connection, &oracle_scan),
                "incremental {window} window diverged from the frozen pre-incremental SQL"
            );
        }

        // Physical-format fence: every window database (WAL-free, zstd SSTs,
        // GC-scrubbed) must serve, through the same checkpoint reader mode the
        // worker uses, exactly the rows of the scan parquet that the frozen
        // oracle just validated — for the incremental AND the full build.
        for manifest in [&manifest3, &manifest_full] {
            for window in &manifest.windows {
                let checked = assert_slatedb_serves_scan_exactly(
                    &window.scan_file,
                    &window.database_path,
                    window.checkpoint_id,
                    &[7u8; 64],
                )
                .await;
                assert_eq!(
                    checked as u64, window.rows,
                    "slatedb read-back must cover every row of the {} window",
                    window.window
                );
            }
        }

        // The late arrival mutated the closed day D-5 exactly once.
        let closed_day_rows = connection
            .query_with_params(
                "SELECT entity, daily_count FROM file({p:String}, Parquet) WHERE day = toDate('2026-08-10') ORDER BY ALL",
                "JSONEachRow",
                &[("p", daily_incremental.scan_file.to_string_lossy().as_ref())],
            )
            .expect("closed day rows");
        assert_eq!(
            String::from_utf8(closed_day_rows.data).unwrap().trim(),
            r#"{"entity":"203.0.113.5","daily_count":1}"#,
            "late-arriving event must land in its closed day exactly once"
        );

        // ---- Scenario B: a closed day's parts are NOT re-read ---------------
        // Tamper with the O1 part inside snap2 (its rows live on closed day
        // D-10, far from every window boundary) by doubling its rows, and fix
        // up snap2's manifest so part reuse still verifies. An incremental
        // build carries the prior aggregate and must keep the ORIGINAL counts;
        // any path that re-reads the closed-day part would double them.
        let snap2_manifest_path = root.join("snap2").join("manifest.json");
        let mut snap2_manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&snap2_manifest_path).unwrap()).unwrap();
        let tampered_part = root.join("snap2").join("parts").join("object-0000.parquet");
        let tampered_replacement = root.join("tampered-part.parquet");
        connection
            .query_with_params(
                "INSERT INTO FUNCTION file({out:String}, Parquet) \
                 SELECT * FROM file({src:String}, Parquet) \
                 UNION ALL SELECT * FROM file({src:String}, Parquet) \
                 SETTINGS use_query_cache=0",
                "Null",
                &[
                    ("out", tampered_replacement.to_string_lossy().as_ref()),
                    ("src", tampered_part.to_string_lossy().as_ref()),
                ],
            )
            .expect("build tampered part");
        std::fs::remove_file(&tampered_part).unwrap();
        std::fs::copy(&tampered_replacement, &tampered_part).unwrap();
        let entry = &mut snap2_manifest["parts"][0];
        entry["part_sha256"] = serde_json::json!(file_sha256(&tampered_part).unwrap());
        entry["part_bytes"] = serde_json::json!(std::fs::metadata(&tampered_part).unwrap().len());
        entry["rows"] = serde_json::json!(parquet_rows(&tampered_part).unwrap());
        write_json(&snap2_manifest_path, &snap2_manifest).unwrap();

        let manifest3b = build(
            &connection,
            &corpus,
            root,
            "snap3b",
            &stamps3,
            Some(&root.join("snap2")),
        )
        .await;
        assert!(
            load_sidecar(&root.join("snap3b")).global_daily_incremental,
            "tampered-part scenario must still take the incremental path"
        );
        let day_counts = |manifest: &PrevalenceBuildManifest| {
            let scan = &manifest.daily_history.as_ref().unwrap().scan_file;
            let rows = connection
                .query_with_params(
                    "SELECT entity, daily_count FROM file({p:String}, Parquet) WHERE day = toDate('2026-08-05') ORDER BY ALL",
                    "JSONEachRow",
                    &[("p", scan.to_string_lossy().as_ref())],
                )
                .expect("closed day counts");
            String::from_utf8(rows.data).unwrap()
        };
        assert_eq!(
            day_counts(&manifest3b),
            day_counts(&manifest3),
            "an incremental build re-read (and double counted) a closed day's part; \
             closed days must come from the carried aggregate"
        );

        // ---- Scenario C: a retired prior part forces a full rebuild ---------
        let stamps_retired = corpus.stamp_manifest(root, 4, &["hour=a/o1.parquet"]);
        let manifest_retired = build(
            &connection,
            &corpus,
            root,
            "snap-retired",
            &stamps_retired,
            Some(&root.join("snap3")),
        )
        .await;
        assert!(
            !load_sidecar(&root.join("snap-retired")).global_daily_incremental,
            "a prior part missing from the current object set must refuse the carry"
        );
        let retired_daily = &manifest_retired.daily_history.as_ref().unwrap().scan_file;
        let retired_day_rows = connection
            .query_with_params(
                "SELECT count() c FROM file({p:String}, Parquet) WHERE day = toDate('2026-08-05')",
                "JSONEachRow",
                &[("p", retired_daily.to_string_lossy().as_ref())],
            )
            .expect("retired day rows");
        assert_eq!(
            String::from_utf8(retired_day_rows.data).unwrap().trim(),
            r#"{"c":0}"#,
            "counts from a retired object leaked into the rebuild"
        );

        // ---- Scenario D: saturated-host semantics survive the merge ---------
        let saturated_root = root.join("saturated-input");
        std::fs::create_dir_all(&saturated_root).unwrap();
        let mut saturated_corpus = Corpus {
            input_root: saturated_root.clone(),
            objects: Vec::new(),
        };
        let day_hosts: [(&str, &str, usize); 3] = [
            ("s1.parquet", "2026-08-13 10:00:00", 40),
            ("s2.parquet", "2026-08-14 10:00:00", 40),
            ("s3.parquet", "2026-08-15 10:00:00", 5),
        ];
        for (index, (rel, ts, hosts)) in day_hosts.iter().enumerate() {
            let events = (0..*hosts)
                .map(|host| Ev {
                    ts,
                    log_source: "fw",
                    device_host: format!("host-{index}-{host:02}"),
                    sip: Some("198.51.100.7"),
                    dip: None,
                    dhost: None,
                    hash: None,
                })
                .collect::<Vec<_>>();
            let path = saturated_root.join(rel);
            write_source_object(&connection, &path, &events);
            saturated_corpus.objects.push(((*rel).to_string(), path));
        }
        let saturated_stamps1 = saturated_corpus.stamp_manifest(root, 10, &["s3.parquet"]);
        let saturated_stamps2 = saturated_corpus.stamp_manifest(root, 11, &[]);
        build(
            &connection,
            &saturated_corpus,
            root,
            "sat1",
            &saturated_stamps1,
            None,
        )
        .await;
        let saturated_incremental = build(
            &connection,
            &saturated_corpus,
            root,
            "sat2",
            &saturated_stamps2,
            Some(&root.join("sat1")),
        )
        .await;
        assert!(load_sidecar(&root.join("sat2")).global_daily_incremental);
        let saturated_full = build(
            &connection,
            &saturated_corpus,
            root,
            "sat-full",
            &saturated_stamps2,
            None,
        )
        .await;
        // MEMBERSHIP of the 65 retained fingerprints is the one documented
        // approximation (arbitrary in both paths); count, saturation flag,
        // times, and occurrences must be exactly equal.
        for (window_incremental, window_full) in saturated_incremental
            .windows
            .iter()
            .zip(&saturated_full.windows)
        {
            assert_eq!(
                table_text_without_fingerprints(&connection, &window_incremental.scan_file),
                table_text_without_fingerprints(&connection, &window_full.scan_file),
                "saturated {} window scalar columns diverged",
                window_incremental.window
            );
        }
        let saturated_7d = saturated_incremental
            .windows
            .iter()
            .find(|window| window.window == "7d")
            .unwrap();
        let saturated_row = connection
            .query_with_params(
                "SELECT length(host_fingerprints) fingerprint_count, host_count_saturated, total_occurrences \
                 FROM file({p:String}, Parquet) WHERE entity = '198.51.100.7'",
                "JSONEachRow",
                &[("p", saturated_7d.scan_file.to_string_lossy().as_ref())],
            )
            .expect("saturated row");
        assert_eq!(
            String::from_utf8(saturated_row.data).unwrap().trim(),
            r#"{"fingerprint_count":65,"host_count_saturated":1,"total_occurrences":85}"#,
            "saturation cap/flag/occurrences must be exact through the merge"
        );
        // chDB installs C++ thread-local destructors on this Rust test thread.
        // Keep its code mapped until process exit; dlclose before the test
        // thread exits can leave those destructors pointing at unmapped code.
        // This is a one-test process fixture, not a production runtime change.
        drop(connection);
        std::mem::forget(runtime);
    }

    /// The pre-NAN-2614 global aggregate, verbatim: one statement over every
    /// part with chDB's default spill ratios. Frozen as the oracle for both
    /// the failure (it needs memory proportional to the input) and the exact
    /// result the sliced build must reproduce.
    const ORACLE_GLOBAL_DAILY_SINGLE_STATEMENT: &str = r#"
INSERT INTO FUNCTION file({output:String}, Parquet)
SELECT kind, scope, entity, toDate(time, 'UTC') day,
       arraySlice(arraySort(groupUniqArray(65)(host)), 1, 65) host_fingerprints,
       max(is_private) is_private, min(time) first_seen, max(time) last_seen,
       count() daily_count
FROM file({source:String}, Parquet)
WHERE kind != '__meta' AND toDate(time, 'UTC') >= toDate({horizon:String})
GROUP BY kind, scope, entity, day
ORDER BY kind, scope, entity, day
SETTINGS output_format_parquet_compression_method='zstd', output_format_compression_level=6,
         output_format_parquet_write_bloom_filter=1, output_format_parquet_write_page_index=1,
         max_memory_usage=1073741824, max_threads=4, max_block_size=16384,
         max_bytes_before_external_group_by=268435456,
         max_bytes_before_external_sort=268435456,
         max_temporary_data_on_disk_size_for_query=8589934592,
         use_query_cache=0, use_hive_partitioning=0
"#;

    /// Order-independent digest of a global aggregate: row count, total
    /// occurrences, and a sum of per-row hashes over every column.
    fn global_daily_digest(connection: &NativeConnection, path: &Path) -> String {
        let output = connection
            .query_with_params(
                "SELECT count(), sum(daily_count), \
                 sum(cityHash64(kind, scope, entity, toString(day), arrayStringConcat(arrayMap(x -> toString(x), host_fingerprints), ','), \
                                is_private, toString(first_seen), toString(last_seen), daily_count)) \
                 FROM file({p:String}, Parquet) SETTINGS max_memory_usage=4294967296",
                "TSV",
                &[("p", path.to_string_lossy().as_ref())],
            )
            .expect("digest global aggregate");
        String::from_utf8(output.data).unwrap().trim().to_string()
    }

    /// NAN-2614 acceptance: the global per-day aggregate stays under a FIXED
    /// chDB memory budget as input rows triple, for both the full and the
    /// incremental path, and reproduces the old single statement exactly.
    /// The same budget is shown to be too small for the old statement on the
    /// tripled input, so the test discriminates.
    ///
    /// Run alone (chDB permits one connection per process):
    /// `NANO_CHDB_LIBRARY_PATH=... cargo test -p nanosiem-lake-worker --lib \
    ///   global_daily_memory_is_bounded_as_input_triples -- --ignored`
    #[tokio::test]
    #[ignore = "requires NANO_CHDB_LIBRARY_PATH (and optionally NANO_CHDB_LIBRARY_SHA256)"]
    async fn global_daily_memory_is_bounded_as_input_triples() {
        const DAYS: i64 = 10;
        const ROWS_PER_PART: u64 = 300_000;
        const BUDGET: u64 = 512 * 1024 * 1024;
        let library = std::env::var("NANO_CHDB_LIBRARY_PATH").expect("library path");
        let digest = std::env::var("NANO_CHDB_LIBRARY_SHA256")
            .unwrap_or_else(|_| file_sha256(Path::new(&library)).expect("digest library"));
        let runtime =
            crate::native::NativeChdb::load_verified(&library, &digest).expect("load chDB");
        let connection = runtime.connect(&[]).expect("connect");
        let root = tempfile::tempdir().unwrap();
        let root = root.path();
        let first_day = utc_date("2026-08-01");
        let horizon = first_day.format("%Y-%m-%d").to_string();
        let watermark_day = first_day + chrono::Duration::days(DAYS - 1);

        // Three parts per day. Almost every row is its own (kind, scope,
        // entity, day) group, the worst case: nothing collapses in the
        // aggregation. Scale 1 is part 0 of each day, scale 3 all three.
        let mut parts = Vec::new();
        let mut mins = Vec::new();
        for day_offset in 0..DAYS {
            let day = first_day + chrono::Duration::days(day_offset);
            let day_start = utc_day_start_us(day).unwrap();
            for copy in 0..3_i64 {
                let key = format!("d{day_offset:02}-c{copy}");
                let file = root.join("parts").join(format!("{key}.parquet"));
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                connection
                    .query_with_params(
                        "INSERT INTO FUNCTION file({output:String}, Parquet) \
                         SELECT ['ip', 'domain', 'hash'][1 + h % 3] kind, concat('src', toString(h % 7)) scope, \
                                concat('entity-', toString(h)) entity, cityHash64(h % 211) host, \
                                toUInt8(0) is_private, \
                                toDateTime64({day:String}, 6, 'UTC') + toIntervalMicrosecond(sipHash64(number, {seed:UInt64}) % 86400000000) time \
                         FROM (SELECT number, sipHash64(number, {seed:UInt64}, 1) % 50000000 h FROM numbers({rows:UInt64})) \
                         SETTINGS max_threads=2",
                        "Null",
                        &[
                            ("output", file.to_string_lossy().as_ref()),
                            ("day", &day.format("%Y-%m-%d 00:00:00").to_string()),
                            ("seed", &(day_offset * 3 + copy).to_string()),
                            ("rows", &ROWS_PER_PART.to_string()),
                        ],
                    )
                    .expect("write observation part");
                let mut part = part_named(&key, day_start + 86_399_999_999);
                part.part_file = file;
                part.rows = ROWS_PER_PART;
                parts.push(part);
                mins.push(day_start);
            }
        }
        let scale_one = (0..parts.len()).step_by(3).collect::<Vec<_>>();
        let scale_three = (0..parts.len()).collect::<Vec<_>>();
        let delta = scale_three
            .iter()
            .copied()
            .filter(|index| index % 3 != 0)
            .collect::<Vec<_>>();
        let tight = PrevalenceBuildLimits {
            memory_bytes: BUDGET,
            aggregate_threads: 1,
        };
        let generous = PrevalenceBuildLimits {
            memory_bytes: 8 * 1024 * 1024 * 1024,
            aggregate_threads: 1,
        };

        // The old single statement over the tripled input: exact at a
        // generous budget, over the cap at the fixed one.
        let all_parts = link_parts(&root.join("all"), &parts, &scale_three).unwrap();
        let oracle = root.join("oracle.parquet");
        let old_params = [
            (
                "source",
                format!("{}/*.parquet", all_parts.to_string_lossy()),
            ),
            ("output", oracle.to_string_lossy().into_owned()),
            ("horizon", horizon.clone()),
        ];
        run_build_statement(
            &connection,
            ORACLE_GLOBAL_DAILY_SINGLE_STATEMENT,
            &old_params,
            &oracle,
            &generous,
        )
        .expect("old statement at a generous budget");
        let expected = global_daily_digest(&connection, &oracle);
        let over_cap = root.join("over-cap.parquet");
        let old_error = run_build_statement(
            &connection,
            ORACLE_GLOBAL_DAILY_SINGLE_STATEMENT,
            &[
                old_params[0].clone(),
                ("output", over_cap.to_string_lossy().into_owned()),
                old_params[2].clone(),
            ],
            &over_cap,
            &tight,
        )
        .expect_err("the old single statement must not fit the fixed budget at 3x");
        assert!(
            format!("{old_error:#}").contains("MEMORY_LIMIT_EXCEEDED"),
            "old statement failed for another reason: {old_error:#}"
        );

        let slice_rows = global_daily_slice_rows(tight.memory_bytes);
        let build = |name: &str, raw: &[usize], prior: Option<&Path>| {
            let work = root.join(format!("work-{name}"));
            std::fs::create_dir_all(&work).unwrap();
            let output = root.join(format!("{name}.parquet"));
            let prior_rows = prior.map(|prior| {
                global_daily_prior_day_rows(&connection, prior, &horizon, &tight).unwrap()
            });
            let slices = plan_global_daily_slices(
                &parts,
                &mins,
                raw,
                prior_rows.as_ref(),
                first_day,
                watermark_day,
                slice_rows,
            )
            .unwrap();
            build_global_daily_slices(&connection, &slices, &parts, prior, &work, &output, &tight)
                .unwrap_or_else(|error| panic!("{name} under the fixed budget: {error:#}"));
            output
        };
        // Full path, 1x then 3x, same fixed budget.
        let one = build("full-1x", &scale_one, None);
        let three = build("full-3x", &scale_three, None);
        assert_eq!(
            parquet_rows(&three).unwrap(),
            parquet_rows(&oracle).unwrap()
        );
        assert!(parquet_rows(&three).unwrap() > 2 * parquet_rows(&one).unwrap());
        assert_eq!(
            global_daily_digest(&connection, &three),
            expected,
            "sliced full build must reproduce the single statement exactly"
        );
        // Incremental path: the 1x aggregate as prior plus the other 2x as
        // delta, same fixed budget, same exact result.
        let merged = build("merge-3x", &delta, Some(&one));
        assert_eq!(
            global_daily_digest(&connection, &merged),
            expected,
            "sliced incremental merge must reproduce the single statement exactly"
        );
        // Carry path: nothing new, the prior re-emitted row for row.
        let carried = build("carry-3x", &[], Some(&merged));
        assert_eq!(global_daily_digest(&connection, &carried), expected);
        // Mixed: late data for day 0 only, so day 0 merges and days 1..9 are
        // carried. Merge and carry slices must concatenate into one schema.
        let without_late = scale_three
            .iter()
            .copied()
            .filter(|index| !matches!(index, 1 | 2))
            .collect::<Vec<_>>();
        let before_late = build("before-late", &without_late, None);
        let mixed = build("mixed-3x", &[1, 2], Some(&before_late));
        assert_eq!(
            global_daily_digest(&connection, &mixed),
            expected,
            "merge and carry slices in one build must reproduce the single statement exactly"
        );

        drop(connection);
        std::mem::forget(runtime);
    }
}
