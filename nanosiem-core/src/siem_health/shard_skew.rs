// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5342: SIEM Health finding when ClickHouse shards drift apart.
//!
//! Vector spreads rows evenly across shards, but nothing told an operator
//! when one shard started taking more writes than the others (a misconfigured
//! external writer pinned to one shard, a lost replica), held far more parts,
//! or ran its merge pool flat out. On a large deployment that one shard
//! becomes the capacity limit for the whole cluster.
//!
//! Detection only. Every read is a `system.*` table through `cluster(...)`
//! (one replica per shard, `shardNum()` = the `system.clusters` shard number);
//! no event table is scanned. History comes from the system log tables nano
//! ships enabled (`clickhouse/config.d/system_logs.xml`): `part_log` (3 days),
//! `metric_log` and `asynchronous_metric_log` (1 day). That gives the
//! "sustained for 30 / 15 minutes" condition at report time without a new
//! sampler or scheduler.
//!
//! Signals, in aligned 5-minute buckets:
//! - **rows/s**: rows of inserted parts (level 0, not mutated) on the hot
//!   tables, from `part_log` `NewPart` + `DownloadPart`. Each inserted part
//!   appears on every replica of its shard as exactly one of the two, so the
//!   count does not depend on which replica `cluster()` reads. The same query
//!   proves liveness: a live node logs system-log flush parts every few
//!   seconds, so a `(shard, bucket)` row exists exactly when that shard
//!   answered and was up in that bucket. A missing bucket is unknown, never 0.
//! - **active parts**: the busiest hot-table partition per shard now
//!   (`system.parts`), gated on node-wide `MaxPartCountForPartition`
//!   (`asynchronous_metric_log`) having been skewed the same way for the
//!   whole window. The node-wide metric alone covers every table, so it never
//!   fires by itself.
//! - **merge pool**: share of `metric_log` samples where
//!   `BackgroundMergesAndMutationsPoolTask >= ...PoolSize`.
//!
//! Identity: the probe runs as the admin client; `cluster()` needs REMOTE,
//! which only the admin holds. Remote shards answer as the `remote_servers`
//! user (Compose / role-split: the runtime user) or as the propagated
//! initiator (cluster `<secret>`: Helm, operator manifests). Both carry the
//! column grants in `clickhouse/users.d/nanosiem-users.xml`, the operator
//! manifests, and migration 199. A probe that still fails raises a low
//! SIEM Health notice instead of staying silent.
//!
//! Single-node installs run no query at all; a clustered install with one
//! shard runs one local `system.clusters` count and stops.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::types::Recommendation;

/// A shard is skewed when it is this far from the median (fraction).
pub const DEVIATION_LIMIT: f64 = 0.25;
/// Width of one history bucket.
pub const BUCKET_SECS: u32 = 300;
/// rows/s and active parts must deviate in every bucket of this window.
pub const SKEW_WINDOW_SECS: u32 = 30 * 60;
/// The merge pool must stay saturated in every bucket of this window.
pub const MERGE_WINDOW_SECS: u32 = 15 * 60;
/// A merge bucket counts as saturated when at least this share of its
/// `metric_log` samples had every pool slot busy.
pub const MERGE_SATURATED_SHARE: f64 = 0.9;
/// Below this cluster median, rows/s differences are noise (a quiet lab
/// cluster at 10 vs 20 rows/s is not a capacity problem).
pub const MIN_MEDIAN_ROWS_PER_SEC: f64 = 50.0;
/// Below this median, part-count differences are noise.
pub const MIN_MEDIAN_PARTS: f64 = 20.0;

/// Stable title (suppressions key on the title).
pub const SHARD_SKEW_TITLE: &str = "ClickHouse shards are out of balance";
/// Stable title of the notice raised when a probe could not run.
pub const SHARD_SKEW_UNAVAILABLE_TITLE: &str = "Shard balance check could not run";

/// Local MergeTree tables that carry the ingested events. In a cluster the
/// local table keeps the bare name (`TableNames::local`); `_local` covers
/// installs with a split `<t>_local` / `<t>` Distributed pair.
const HOT_TABLES: &[&str] = &["logs", "ocsf_logs", "logs_local", "ocsf_logs_local"];

const fn buckets(window_secs: u32) -> usize {
    (window_secs / BUCKET_SECS) as usize
}

// ---------------------------------------------------------------------------
// Rows returned by the probes
// ---------------------------------------------------------------------------

/// One `(shard, bucket)` value. `ago` 0 is the most recent complete bucket.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct BucketRow {
    pub shard: u32,
    pub ago: u32,
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct MergeBucketRow {
    pub shard: u32,
    pub ago: u32,
    /// Share of samples in the bucket with every merge slot busy.
    pub saturated_share: f64,
    /// Mean merges/mutations running.
    pub tasks: f64,
    /// Merge pool size (slots).
    pub pool: f64,
}

#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct QueuedMergesRow {
    pub shard: u32,
    pub queued: u64,
}

/// The partition with the most active parts on a shard, hot tables only.
#[derive(Debug, Clone, PartialEq, clickhouse::Row, Serialize, Deserialize)]
pub struct HotPartitionRow {
    pub shard: u32,
    pub table: String,
    pub partition: String,
    pub parts: u64,
}

// ---------------------------------------------------------------------------
// Collected metrics (stored in the report's metrics JSON)
// ---------------------------------------------------------------------------

/// A probe that failed (access denied, missing system log table, ...).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProbeFailure {
    pub probe: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShardSkewMetrics {
    /// Shards the cluster defines (0 when the count itself failed).
    pub shard_count: u32,
    /// rows/s per shard per bucket (`ago` index, 0 = newest). `None` = the
    /// shard did not answer for that bucket (down, restarted, skipped).
    pub rows_per_sec: BTreeMap<u32, Vec<Option<f64>>>,
    /// Node-wide mean `MaxPartCountForPartition` per shard per bucket.
    pub max_parts: BTreeMap<u32, Vec<Option<f64>>>,
    /// Merge-pool buckets per shard (`ago` index).
    pub merges: BTreeMap<u32, Vec<Option<MergeBucketRow>>>,
    /// Merges queued in `system.replication_queue` per shard (snapshot).
    pub queued_merges: BTreeMap<u32, u64>,
    /// Current busiest hot-table partition per shard (snapshot).
    pub hot_partitions: BTreeMap<u32, HotPartitionRow>,
    /// Probes that could not run.
    pub probe_failures: Vec<ProbeFailure>,
}

fn bucket_series(rows: Vec<BucketRow>, len: usize, scale: f64) -> BTreeMap<u32, Vec<Option<f64>>> {
    let mut out: BTreeMap<u32, Vec<Option<f64>>> = BTreeMap::new();
    for row in rows {
        if let Some(slot) = out
            .entry(row.shard)
            .or_insert_with(|| vec![None; len])
            .get_mut(row.ago as usize)
        {
            *slot = Some(row.value * scale);
        }
    }
    out
}

/// Assemble [`ShardSkewMetrics`] from probe rows. `None` for a probe that
/// failed (its failure is in `failures`).
pub fn assemble(
    shard_count: u32,
    rows: Option<Vec<BucketRow>>,
    parts: Option<Vec<BucketRow>>,
    merges: Option<Vec<MergeBucketRow>>,
    queued: Option<Vec<QueuedMergesRow>>,
    hot: Option<Vec<HotPartitionRow>>,
    failures: Vec<ProbeFailure>,
) -> ShardSkewMetrics {
    let skew_buckets = buckets(SKEW_WINDOW_SECS);
    let merge_buckets = buckets(MERGE_WINDOW_SECS);
    let mut out = ShardSkewMetrics {
        shard_count,
        probe_failures: failures,
        ..Default::default()
    };
    // Each `(shard, bucket)` row is that shard's own proof of life for the
    // bucket (see the module docs); absent buckets stay `None`.
    if let Some(rows) = rows {
        out.rows_per_sec = bucket_series(rows, skew_buckets, 1.0 / f64::from(BUCKET_SECS));
    }
    if let Some(parts) = parts {
        out.max_parts = bucket_series(parts, skew_buckets, 1.0);
    }
    for row in merges.into_iter().flatten() {
        let ago = row.ago as usize;
        if let Some(slot) = out
            .merges
            .entry(row.shard)
            .or_insert_with(|| vec![None; merge_buckets])
            .get_mut(ago)
        {
            *slot = Some(row);
        }
    }
    for row in queued.into_iter().flatten() {
        out.queued_merges.insert(row.shard, row.queued);
    }
    for row in hot.into_iter().flatten() {
        out.hot_partitions.insert(row.shard, row);
    }
    out
}

// ---------------------------------------------------------------------------
// Skew math
// ---------------------------------------------------------------------------

/// Median of a non-empty slice (mean of the middle two for an even count).
pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let mid = sorted.len() / 2;
    Some(if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkewMetric {
    RowsPerSec,
    ActiveParts,
}

/// A shard that stayed more than [`DEVIATION_LIMIT`] from the median, on the
/// same side, in every bucket of the window.
#[derive(Debug, Clone, PartialEq)]
pub struct Deviation {
    pub shard: u32,
    pub metric: SkewMetric,
    /// Window means.
    pub value: f64,
    pub median: f64,
    /// Mean signed deviation from the median (0.4 = 40% above).
    pub deviation: f64,
}

/// Shards whose value sits more than [`DEVIATION_LIMIT`] from the per-bucket
/// median in every one of `window` buckets, always on the same side.
///
/// A bucket where fewer than two shards have a value, or whose median is
/// below `floor`, breaks the streak for everyone: the condition must hold for
/// the whole window.
pub fn sustained_deviations(
    series: &BTreeMap<u32, Vec<Option<f64>>>,
    window: usize,
    floor: f64,
    metric: SkewMetric,
) -> Vec<Deviation> {
    if series.len() < 2 {
        return Vec::new();
    }
    // (sum of values, sum of medians, sum of deviations, sign, buckets held)
    let mut streak: BTreeMap<u32, (f64, f64, f64, i8, usize)> = BTreeMap::new();
    for bucket in 0..window {
        let values: Vec<(u32, f64)> = series
            .iter()
            .filter_map(|(shard, buckets)| buckets.get(bucket).copied().flatten().map(|v| (*shard, v)))
            .collect();
        if values.len() < 2 {
            return Vec::new();
        }
        let Some(med) = median(&values.iter().map(|(_, v)| *v).collect::<Vec<_>>()) else {
            return Vec::new();
        };
        if med < floor || med <= 0.0 {
            return Vec::new();
        }
        for (shard, value) in values {
            let deviation = (value - med) / med;
            let sign: i8 = if deviation > 0.0 { 1 } else { -1 };
            let entry = streak.entry(shard).or_insert((0.0, 0.0, 0.0, sign, 0));
            // Only extend an unbroken, same-side streak that started at bucket 0.
            if deviation.abs() > DEVIATION_LIMIT && entry.3 == sign && entry.4 == bucket {
                entry.0 += value;
                entry.1 += med;
                entry.2 += deviation;
                entry.4 += 1;
            }
        }
    }
    streak
        .into_iter()
        .filter(|(_, (_, _, _, _, held))| *held == window)
        .map(|(shard, (value, med, dev, _, _))| Deviation {
            shard,
            metric,
            value: value / window as f64,
            median: med / window as f64,
            deviation: dev / window as f64,
        })
        .collect()
}

/// A shard whose merge pool stayed saturated for the whole merge window.
#[derive(Debug, Clone, PartialEq)]
pub struct MergeSaturation {
    pub shard: u32,
    pub pool: f64,
    pub tasks: f64,
}

pub fn saturated_merge_pools(
    merges: &BTreeMap<u32, Vec<Option<MergeBucketRow>>>,
    window: usize,
) -> Vec<MergeSaturation> {
    merges
        .iter()
        .filter_map(|(shard, buckets)| {
            let window_buckets: Vec<&MergeBucketRow> =
                buckets.iter().take(window).filter_map(Option::as_ref).collect();
            let saturated = window_buckets.len() == window
                && window_buckets
                    .iter()
                    .all(|b| b.pool > 0.0 && b.saturated_share >= MERGE_SATURATED_SHARE);
            saturated.then(|| MergeSaturation {
                shard: *shard,
                pool: window_buckets.iter().map(|b| b.pool).fold(0.0, f64::max),
                tasks: window_buckets.iter().map(|b| b.tasks).sum::<f64>() / window as f64,
            })
        })
        .collect()
}

/// Hot-table part skew: the busiest hot-table partition is skewed NOW, and
/// the node-wide max parts per partition has been skewed the same way for
/// the whole window. Neither alone is enough: the snapshot has no history,
/// and the node-wide metric also counts unrelated tables.
pub fn hot_parts_deviations(metrics: &ShardSkewMetrics) -> Vec<Deviation> {
    let snapshot: BTreeMap<u32, Vec<Option<f64>>> = metrics
        .hot_partitions
        .iter()
        .map(|(shard, row)| (*shard, vec![Some(row.parts as f64)]))
        .collect();
    let now = sustained_deviations(&snapshot, 1, MIN_MEDIAN_PARTS, SkewMetric::ActiveParts);
    let history = sustained_deviations(
        &metrics.max_parts,
        buckets(SKEW_WINDOW_SECS),
        MIN_MEDIAN_PARTS,
        SkewMetric::ActiveParts,
    );
    now.into_iter()
        .filter(|d| {
            history
                .iter()
                .any(|h| h.shard == d.shard && h.deviation.signum() == d.deviation.signum())
        })
        .collect()
}

/// The SIEM Health findings for `metrics`: the skew finding when shards
/// disagree, and a low notice when a probe could not run.
pub fn shard_skew_recommendations(metrics: &ShardSkewMetrics) -> Vec<Recommendation> {
    let mut out = Vec::new();
    if let Some(rec) = unavailable_recommendation(metrics) {
        out.push(rec);
    }
    if metrics.shard_count < 2 {
        return out;
    }
    let window = buckets(SKEW_WINDOW_SECS);
    let mut lines: Vec<String> = Vec::new();

    for d in sustained_deviations(
        &metrics.rows_per_sec,
        window,
        MIN_MEDIAN_ROWS_PER_SEC,
        SkewMetric::RowsPerSec,
    ) {
        lines.push(format!(
            "Shard {}: writes {} rows/s against a cluster median of {} ({}) for the last 30 minutes.",
            d.shard,
            fmt_num(d.value),
            fmt_num(d.median),
            fmt_pct(d.deviation)
        ));
    }
    for d in hot_parts_deviations(metrics) {
        let Some(hot) = metrics.hot_partitions.get(&d.shard) else {
            continue;
        };
        lines.push(format!(
            "Shard {}: {} partition {} holds {} active parts against a cluster median of {} ({}), \
             and the shard's part count has been skewed the same way for the last 30 minutes.",
            d.shard,
            hot.table,
            hot.partition,
            hot.parts,
            fmt_num(d.median),
            fmt_pct(d.deviation)
        ));
    }
    for s in saturated_merge_pools(&metrics.merges, buckets(MERGE_WINDOW_SECS)) {
        let queued = metrics
            .queued_merges
            .get(&s.shard)
            .filter(|n| **n > 0)
            .map(|n| format!(", {n} merges queued"))
            .unwrap_or_default();
        lines.push(format!(
            "Shard {}: merge pool saturated for the last 15 minutes ({} of {} slots busy on average{queued}).",
            s.shard,
            fmt_num(s.tasks),
            fmt_num(s.pool)
        ));
    }

    if lines.is_empty() {
        return out;
    }
    out.push(Recommendation {
        title: SHARD_SKEW_TITLE.to_string(),
        description: format!(
            "{} One shard carrying more than its share becomes the capacity limit of the \
             whole cluster. Check for a writer that inserts into one shard's local table \
             instead of the `_distributed` table, a replica that is down or lagging, and \
             disk or CPU differences between shard hosts. See the sizing guide (\"Sizing \
             presets\" in the Kubernetes guide, or the multi-node self-hosting guide) for \
             per-shard capacity.",
            lines.join(" ")
        ),
        priority: "medium".to_string(),
    });
    out
}

fn unavailable_recommendation(metrics: &ShardSkewMetrics) -> Option<Recommendation> {
    let first = metrics.probe_failures.first()?;
    let probes = metrics
        .probe_failures
        .iter()
        .map(|f| f.probe.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let error: String = first.error.lines().next().unwrap_or("").chars().take(240).collect();
    Some(Recommendation {
        title: SHARD_SKEW_UNAVAILABLE_TITLE.to_string(),
        description: format!(
            "The shard balance check could not read {probes} on every shard, so uneven \
             writes, parts or merge load would go unnoticed. First error: {error} \
             The check runs as the ClickHouse admin identity (CLICKHOUSE_ADMIN_USER), which \
             needs REMOTE; remote shards answer as the cluster's remote_servers user, which \
             needs the system-table column grants in clickhouse/users.d/nanosiem-users.xml \
             (applied to SQL-created users by ClickHouse migration 199)."
        ),
        priority: "low".to_string(),
    })
}

fn fmt_num(v: f64) -> String {
    if v >= 100.0 {
        format!("{:.0}", v)
    } else {
        format!("{:.1}", v)
    }
}

fn fmt_pct(dev: f64) -> String {
    format!("{:+.0}%", dev * 100.0)
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/// Aligned window `[anchor - window, anchor)`; `anchor` is the start of the
/// current (incomplete) bucket, computed once in Rust so every shard buckets
/// against the same instant.
pub fn bucket_anchor(now_unix: i64) -> i64 {
    now_unix - now_unix.rem_euclid(i64::from(BUCKET_SECS))
}

fn cluster_source(cluster: &str, table: &str) -> String {
    format!(
        "cluster('{}', system.{table})",
        crate::sql_hygiene::escape_sql_string(cluster)
    )
}

fn window_predicate(anchor: i64, window_secs: u32) -> String {
    let start = anchor - i64::from(window_secs);
    format!(
        "event_date >= toDate(toDateTime({start})) \
         AND event_time >= toDateTime({start}) AND event_time < toDateTime({anchor})"
    )
}

fn ago_expr(anchor: i64) -> String {
    format!(
        "toUInt32(intDiv({} - toInt64(toUInt32(event_time)), {BUCKET_SECS}))",
        anchor - 1
    )
}

fn hot_tables_list() -> String {
    HOT_TABLES
        .iter()
        .map(|t| format!("'{t}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn db_literal(database: &str) -> String {
    format!("'{}'", crate::sql_hygiene::escape_sql_string(database))
}

/// Shards the cluster defines (local `system.clusters`, no fan-out).
pub fn shard_count_sql() -> String {
    format!(
        "SELECT toUInt32(uniqExact(shard_num)) FROM system.clusters WHERE {}",
        crate::db::clickhouse_migrate::server_cluster_rows_predicate("?")
    )
}

/// rows/s and per-bucket liveness in one read: every `part_log` row in the
/// window is grouped (a live node logs system-log flush parts every few
/// seconds), and only hot-table inserted parts are summed.
pub fn rows_sql(cluster: &str, database: &str, anchor: i64) -> String {
    format!(
        "SELECT toUInt32(shardNum()) AS shard, {ago} AS ago, \
         toFloat64(sumIf(rows, database = {db} AND table IN ({tables}) \
         AND event_type IN ('NewPart', 'DownloadPart') \
         AND length(splitByChar('_', part_name)) = 4 AND splitByChar('_', part_name)[4] = '0')) AS value \
         FROM {src} \
         WHERE {window} \
         GROUP BY shard, ago",
        ago = ago_expr(anchor),
        db = db_literal(database),
        src = cluster_source(cluster, "part_log"),
        window = window_predicate(anchor, SKEW_WINDOW_SECS),
        tables = hot_tables_list(),
    )
}

pub fn parts_sql(cluster: &str, anchor: i64) -> String {
    format!(
        "SELECT toUInt32(shardNum()) AS shard, {ago} AS ago, toFloat64(avg(value)) AS value \
         FROM {src} \
         WHERE {window} AND metric = 'MaxPartCountForPartition' \
         GROUP BY shard, ago",
        ago = ago_expr(anchor),
        src = cluster_source(cluster, "asynchronous_metric_log"),
        window = window_predicate(anchor, SKEW_WINDOW_SECS),
    )
}

pub fn merges_sql(cluster: &str, anchor: i64) -> String {
    format!(
        "SELECT toUInt32(shardNum()) AS shard, {ago} AS ago, \
         toFloat64(avg(CurrentMetric_BackgroundMergesAndMutationsPoolSize > 0 AND \
         CurrentMetric_BackgroundMergesAndMutationsPoolTask >= CurrentMetric_BackgroundMergesAndMutationsPoolSize)) AS saturated_share, \
         toFloat64(avg(CurrentMetric_BackgroundMergesAndMutationsPoolTask)) AS tasks, \
         toFloat64(max(CurrentMetric_BackgroundMergesAndMutationsPoolSize)) AS pool \
         FROM {src} WHERE {window} GROUP BY shard, ago",
        ago = ago_expr(anchor),
        src = cluster_source(cluster, "metric_log"),
        window = window_predicate(anchor, MERGE_WINDOW_SECS),
    )
}

pub fn queued_merges_sql(cluster: &str, database: &str) -> String {
    format!(
        "SELECT toUInt32(shardNum()) AS shard, toUInt64(countIf(type = 'MERGE_PARTS')) AS queued \
         FROM {} WHERE database = {} GROUP BY shard",
        cluster_source(cluster, "replication_queue"),
        db_literal(database)
    )
}

pub fn hot_partitions_sql(cluster: &str, database: &str) -> String {
    format!(
        "SELECT toUInt32(shardNum()) AS shard, table, partition, toUInt64(count()) AS parts \
         FROM {} WHERE active AND database = {} AND table IN ({}) \
         GROUP BY shard, table, partition ORDER BY parts DESC LIMIT 1 BY shard",
        cluster_source(cluster, "parts"),
        db_literal(database),
        hot_tables_list()
    )
}

// ---------------------------------------------------------------------------
// Collection
// ---------------------------------------------------------------------------

/// The system-table reads the collector needs. The ClickHouse implementation
/// runs [`shard_count_sql`] etc.; tests substitute fixture rows and count calls.
pub(crate) trait ShardSkewSource {
    async fn shard_count(&self, cluster: &str) -> Result<u32, String>;
    async fn rows(&self, sql: &str) -> Result<Vec<BucketRow>, String>;
    async fn merges(&self, sql: &str) -> Result<Vec<MergeBucketRow>, String>;
    async fn queued(&self, sql: &str) -> Result<Vec<QueuedMergesRow>, String>;
    async fn hot(&self, sql: &str) -> Result<Vec<HotPartitionRow>, String>;
}

/// ClickHouse-backed [`ShardSkewSource`]. Every fan-out read skips a dead
/// shard instead of failing (NAN-5215 posture).
pub(crate) struct ClickHouseShardSkewSource<'a>(pub &'a clickhouse::Client);

impl ShardSkewSource for ClickHouseShardSkewSource<'_> {
    async fn shard_count(&self, cluster: &str) -> Result<u32, String> {
        self.0
            .query(&shard_count_sql())
            .bind(cluster)
            .bind(cluster)
            .fetch_one::<u32>()
            .await
            .map_err(|e| e.to_string())
    }
    async fn rows(&self, sql: &str) -> Result<Vec<BucketRow>, String> {
        self.fan_out(sql).fetch_all().await.map_err(|e| e.to_string())
    }
    async fn merges(&self, sql: &str) -> Result<Vec<MergeBucketRow>, String> {
        self.fan_out(sql).fetch_all().await.map_err(|e| e.to_string())
    }
    async fn queued(&self, sql: &str) -> Result<Vec<QueuedMergesRow>, String> {
        self.fan_out(sql).fetch_all().await.map_err(|e| e.to_string())
    }
    async fn hot(&self, sql: &str) -> Result<Vec<HotPartitionRow>, String> {
        self.fan_out(sql).fetch_all().await.map_err(|e| e.to_string())
    }
}

impl ClickHouseShardSkewSource<'_> {
    fn fan_out(&self, sql: &str) -> clickhouse::query::Query {
        let (name, value) = super::collector::PROBE_SKIP_UNAVAILABLE_REPLICAS;
        self.0.clone().with_option(name, value).query(sql)
    }
}

/// `cluster` is `None` on a single-node install: no query runs. A cluster
/// with fewer than two shards stops after the shard count. `database` is the
/// configured ClickHouse database (`CLICKHOUSE_DATABASE`).
pub(crate) async fn collect_shard_skew<S: ShardSkewSource>(
    source: &S,
    cluster: Option<&str>,
    database: &str,
    now_unix: i64,
) -> Option<ShardSkewMetrics> {
    let cluster = cluster?;
    let mut failures = Vec::new();
    let Some(shard_count) = note(&mut failures, "system.clusters", source.shard_count(cluster).await) else {
        return Some(assemble(0, None, None, None, None, None, failures));
    };
    if shard_count < 2 {
        return None;
    }
    let anchor = bucket_anchor(now_unix);
    let rows = source.rows(&rows_sql(cluster, database, anchor)).await;
    let rows = note(&mut failures, "system.part_log", rows);
    let parts = source.rows(&parts_sql(cluster, anchor)).await;
    let parts = note(&mut failures, "system.asynchronous_metric_log", parts);
    let merges = source.merges(&merges_sql(cluster, anchor)).await;
    let merges = note(&mut failures, "system.metric_log", merges);
    let queued = source.queued(&queued_merges_sql(cluster, database)).await;
    let queued = note(&mut failures, "system.replication_queue", queued);
    let hot = source.hot(&hot_partitions_sql(cluster, database)).await;
    let hot = note(&mut failures, "system.parts", hot);
    Some(assemble(shard_count, rows, parts, merges, queued, hot, failures))
}

/// `Ok` as `Some`; an error is logged and recorded for the notice.
fn note<T>(failures: &mut Vec<ProbeFailure>, probe: &str, r: Result<T, String>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(error) => {
            warn!("Shard skew probe: {} unavailable: {}", probe, error);
            failures.push(ProbeFailure {
                probe: probe.to_string(),
                error,
            });
            None
        }
    }
}

/// Cluster name for the fan-out reads: the pool-detected `is_clustered` AND
/// the deploy's `CLICKHOUSE_CLUSTER` (same gate as the insert-integrity probes).
pub fn cluster_from_env(is_clustered: bool) -> Option<String> {
    if !is_clustered {
        return None;
    }
    std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
}

#[cfg(test)]
#[path = "shard_skew_tests.rs"]
mod tests;
