// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disk-Pressure-Based Data Retention
//!
//! Automatically drops oldest daily ClickHouse partitions when disk usage exceeds
//! configurable watermarks. Uses a FIFO strategy: oldest partitions are dropped first
//! until usage falls below the low watermark.
//!
//! Watermarks:
//! - High (default 80%): Start dropping oldest partitions
//! - Low (default 70%): Stop dropping (target)
//! - Critical (default 90%): Emit warning audit event; force drops even with tiering active
//! - Pause (default 92%): pause ingestion (NAN-5446; on by default)
//! - Emergency (default 95%): Critical health event
//!
//! The pause sits below the emergency level on purpose: on a single host,
//! ClickHouse, PostgreSQL and the Vector disk buffers share one filesystem.
//! Pausing at 92% gives senders a clean `503` + `Retry-After` at the ingest
//! edge while there is still room for Vector to hold what it already accepted,
//! instead of Vector hitting ENOSPC, stopping its whole topology and
//! restart-looping. The pause lifts automatically once usage is back below
//! the high watermark (or the drops reach the low watermark).
//!
//! NAN-5447 safety rails on the FIFO drop:
//! - Retention floor (`DISK_PRESSURE_MIN_RETENTION_DAYS`, default 7): a
//!   partition newer than `today - floor` is never dropped. When only
//!   floor-protected data is left, the service alarms and (at the critical
//!   level) pauses ingestion instead of deleting.
//! - ClickHouse attribution: partitions are dropped only when ClickHouse's own
//!   parts are what filled the disk (see [`eviction_gate`]). Growth from
//!   anything else on the filesystem raises an alarm instead.
//! - Audit trail: platform audit rows (`source_type = 'audit'`) live in the
//!   event tables. Before a partition holding audit rows is dropped, its
//!   audit rows are copied to `audit_archive` and the copy is verified
//!   ([`crate::audit::archive`]); the drop itself stays a cheap
//!   `DROP PARTITION` whatever the daily volume. If the copy or the check
//!   fails, nothing of that day is dropped.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use clickhouse::Client as ClickHouseClient;
use serde::Serialize;
use sqlx::PgPool;
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use utoipa::ToSchema;

use crate::audit::{AuditEmitter, AuditEvent, AuditSource};
use crate::db::dual_pool::on_cluster_clause;
use crate::db::NotificationRepository;
use crate::settings::ingestion_pause::{IngestionPauseService, IngestionPauseSource};
use crate::health::{HealthIssueType, HealthRepository};
use crate::models::notification::{NewNotification, NotificationType};
use crate::system_health::{
    HealthCategory, HealthSeverity, PublishHealthEvent, SystemHealthRepository,
};

// ---------------------------------------------------------------------------
// Cluster-aware runtime helpers (NAN-1728 H1)
//
// `DiskPressureService` holds a bare admin `ClickHouseClient` (no `DualPool`),
// so cluster mode is derived from the same `CLICKHOUSE_CLUSTER` env signal that
// gates `on_cluster_clause` — the deploy sets it only on clustered ClickHouse.
// On single-node / open-core (`CLICKHOUSE_CLUSTER` unset) every helper below
// falls back to the exact pre-cluster query, so this file is byte-identical
// there.
// ---------------------------------------------------------------------------

/// Configured ClickHouse cluster name, or `None` on single-node deployments.
fn clickhouse_cluster_name() -> Option<String> {
    std::env::var("CLICKHOUSE_CLUSTER").ok().and_then(|c| {
        let t = c.trim();
        (!t.is_empty()).then(|| t.to_string())
    })
}

/// `system.<table>` source visiting EVERY node (both replicas of every shard)
/// on a cluster via `clusterAllReplicas(...)`. Used for disk-pressure reads
/// where each physical node's own disk/parts matter (max usage / oldest
/// partition across the whole cluster). Plain `system.<table>` on single-node.
fn all_replicas_system(table: &str) -> String {
    match clickhouse_cluster_name() {
        Some(cl) => format!("clusterAllReplicas('{}', system.{})", cl, table),
        None => format!("system.{}", table),
    }
}

/// NAN-5215: settings for every read that goes through
/// [`all_replicas_system`]. A clustered install runs two replicas per shard
/// and must keep working with one hard-down; without
/// `skip_unavailable_shards = 1` a single dead replica fails every
/// `clusterAllReplicas` read, which disables the whole disk-pressure valve on
/// the healthy nodes.
///
/// Why skipping cannot cause a wrong (destructive) decision:
/// - Disk usage is the max over the nodes that answer. A down node is not
///   ingesting, so it is not the one filling; the live nodes are judged on
///   their own disks.
/// - Partition dates (oldest/newest, which tables hold a date) are
///   replica-invariant: the down replica's sibling holds the same parts. If a
///   whole shard is down, the live shards' oldest partition is still a real
///   partition at least as old as the policy picks, and a table seen only on
///   the down shard is simply not dropped this round (drops less, never more).
/// - The DROP itself is `ON CLUSTER`; the returning replica replays it from
///   the DDL queue, so the cluster converges on the same retention.
///
/// Byte sums keep using `cluster(...)` ([`parts_source_dedup`]), which fails
/// over to a live replica per shard on its own and must not skip a shard.
fn all_replicas_read_settings(cluster: Option<&str>) -> &'static [(&'static str, &'static str)] {
    match cluster {
        Some(_) => &[("skip_unavailable_shards", "1")],
        None => &[],
    }
}

/// `system.parts` source that dedupes replicas to one per shard on a cluster
/// (`cluster(...)`), so byte sums count each shard exactly once. Plain
/// `system.parts` on single-node.
fn parts_source_dedup() -> String {
    match clickhouse_cluster_name() {
        Some(cl) => format!("cluster('{}', system.parts)", cl),
        None => "system.parts".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the disk pressure service, driven by environment variables.
#[derive(Debug, Clone)]
pub struct DiskPressureConfig {
    /// How often to check disk usage (seconds)
    pub check_interval_secs: u64,
    /// Start dropping partitions above this fraction (0.0–1.0)
    pub high_watermark: f64,
    /// Stop dropping once below this fraction
    pub low_watermark: f64,
    /// Emit critical warning above this fraction
    pub critical_threshold: f64,
    /// Emergency level (Critical health event) above this fraction
    pub emergency_threshold: f64,
    /// Whether to pause ingestion automatically at `pause_threshold`
    /// (`DISK_PRESSURE_PAUSE_INGESTION`, default on since NAN-5446).
    pub pause_ingestion: bool,
    /// Pause ingestion at or above this fraction
    /// (`DISK_PRESSURE_PAUSE_THRESHOLD`, default 0.92).
    pub pause_threshold: f64,
    /// NAN-5447: never drop a partition newer than this many days before
    /// today (UTC). 0 keeps only today's partition protected (the pre-floor
    /// behavior). Capped at [`MAX_MIN_RETENTION_DAYS`].
    pub min_retention_days: u64,
    /// Whether `DISK_PRESSURE_MIN_RETENTION_DAYS` was set. When it was not,
    /// the floor is at most what the install holds ([`effective_floor_days`]),
    /// so an install sized for fewer than 7 days keeps evicting instead of
    /// pausing.
    pub min_retention_explicit: bool,
}

/// Upper bound for `DISK_PRESSURE_MIN_RETENTION_DAYS` (ten years): anything
/// larger means the evictor never drops, which is what the TTL is for.
pub const MAX_MIN_RETENTION_DAYS: u64 = 3650;

/// Default retention floor (days).
pub const DEFAULT_MIN_RETENTION_DAYS: u64 = 7;

impl Default for DiskPressureConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: env_u64("DISK_PRESSURE_CHECK_INTERVAL_SECS", 60),
            high_watermark: env_f64("DISK_PRESSURE_HIGH_WATERMARK", 0.80),
            low_watermark: env_f64("DISK_PRESSURE_LOW_WATERMARK", 0.70),
            critical_threshold: env_f64("DISK_PRESSURE_CRITICAL_THRESHOLD", 0.90),
            emergency_threshold: env_f64("DISK_PRESSURE_EMERGENCY_THRESHOLD", 0.95),
            pause_ingestion: env_bool("DISK_PRESSURE_PAUSE_INGESTION", true),
            pause_threshold: env_f64("DISK_PRESSURE_PAUSE_THRESHOLD", DEFAULT_PAUSE_THRESHOLD),
            min_retention_days: env_u64("DISK_PRESSURE_MIN_RETENTION_DAYS", DEFAULT_MIN_RETENTION_DAYS)
                .min(MAX_MIN_RETENTION_DAYS),
            min_retention_explicit: std::env::var("DISK_PRESSURE_MIN_RETENTION_DAYS")
                .ok()
                .is_some_and(|v| v.trim().parse::<u64>().is_ok()),
        }
        .sanitized()
    }
}

/// Default ingestion-pause threshold (NAN-5446): below the 95% emergency level
/// so Vector's disk buffers still fit on a shared filesystem once senders are
/// told to back off.
pub const DEFAULT_PAUSE_THRESHOLD: f64 = 0.92;

impl DiskPressureConfig {
    /// Clamp the pause threshold into `[high_watermark, 0.99]`. A pause below
    /// the high watermark would flap: the Normal level lifts an automatic
    /// pause on every cycle. A non-finite value falls back to the default.
    pub fn sanitized(mut self) -> Self {
        if !self.pause_threshold.is_finite() {
            warn!("DISK_PRESSURE_PAUSE_THRESHOLD is not a number; using the default");
            self.pause_threshold = DEFAULT_PAUSE_THRESHOLD;
        }
        let floor = self.high_watermark.min(0.99);
        let clamped = self.pause_threshold.clamp(floor, 0.99);
        if (clamped - self.pause_threshold).abs() > f64::EPSILON {
            warn!(
                configured = self.pause_threshold,
                used = clamped,
                "DISK_PRESSURE_PAUSE_THRESHOLD must be between the high watermark and 0.99; clamped"
            );
            self.pause_threshold = clamped;
        }
        self
    }

    /// Whether a usage reading should pause ingestion.
    pub fn should_pause(&self, usage: f64) -> bool {
        self.pause_ingestion && usage >= self.pause_threshold
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Current disk pressure level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskPressureLevel {
    /// Usage below high watermark — no action needed
    Normal,
    /// Usage between high and critical — partitions being dropped
    Elevated,
    /// Usage above critical — warning emitted
    Critical,
    /// Usage above emergency (ingestion is paused from the pause threshold)
    Emergency,
}

impl std::fmt::Display for DiskPressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Elevated => write!(f, "elevated"),
            Self::Critical => write!(f, "critical"),
            Self::Emergency => write!(f, "emergency"),
        }
    }
}

/// Full disk pressure status returned by the API.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DiskPressureStatus {
    /// Current disk usage fraction (0.0–1.0)
    pub usage_fraction: f64,
    /// Total disk bytes
    pub total_bytes: u64,
    /// Used disk bytes
    pub used_bytes: u64,
    /// Free disk bytes
    pub free_bytes: u64,
    /// Current pressure level
    pub level: DiskPressureLevel,
    /// Days of events the disk holds before disk pressure starts dropping
    /// the oldest (NAN-5450): the days stored now plus the headroom up to the
    /// high watermark, at the average daily partition size.
    pub estimated_retention_days: Option<f64>,
    /// Number of partition-dates dropped since service started
    pub partitions_dropped: u64,
    /// Whether ingestion is currently paused due to disk pressure
    pub ingestion_paused: bool,
    /// Configured high watermark
    pub high_watermark: f64,
    /// Configured low watermark
    pub low_watermark: f64,
    /// Configured critical threshold
    pub critical_threshold: f64,
    /// Configured emergency threshold
    pub emergency_threshold: f64,
    /// Whether ingestion pauses automatically (`DISK_PRESSURE_PAUSE_INGESTION`)
    pub auto_pause_enabled: bool,
    /// Usage fraction at which ingestion pauses
    pub pause_threshold: f64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum DiskPressureError {
    #[error("ClickHouse error: {0}")]
    ClickHouse(String),
    #[error("No disk information available from ClickHouse")]
    NoDiskInfo,
    /// NAN-5447: the audit rows of a partition could not be archived (the
    /// copy failed, or the check found rows missing from the archive). No
    /// table of that date is dropped.
    #[error("audit archive failed: {0}")]
    AuditArchiveFailed(String),
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Tables that use daily partitions and are candidates for pressure-based drops.
///
/// NAN-4982: `ocsf_logs` is the main event store on the OCSF profile (the v2
/// default) and `ocsf_logs_legacy_v179` is the OCSF 1.8 store that migration
/// 180 renamed aside on upgraded installs. Both partition by
/// `toYYYYMMDD(timestamp)` exactly like `logs`. Without them an OCSF box under
/// disk pressure reclaimed space only from the small side tables.
///
/// Only LOCAL MergeTree tables are listed, never a `*_distributed` wrapper: a
/// wrapper holds no parts (it never appears in `system.parts`), and the drop
/// runs `ON CLUSTER` against each shard's local table. A table that does not
/// exist on this deployment (`ocsf_logs` on a UDM-only box, the legacy table on
/// a fresh install) has no active parts, so [`DiskPressureService`] never
/// issues a DROP against it: drops target only the tables that hold the
/// partition being evicted.
const DAILY_TABLES: &[&str] = &[
    "logs",
    "ocsf_logs",
    "ocsf_logs_legacy_v179",
    "signals",
    "ingestion_errors",
    "identity_observations",
    "nat_candidates",
];

/// Maximum partition-dates to evict in a single check cycle.
const MAX_DROPS_PER_CYCLE: usize = 5;

/// Maximum candidates one cycle may find already gone (dropped by TTL or an
/// operator between the snapshot and the drop). They do not count toward
/// [`MAX_DROPS_PER_CYCLE`].
const MAX_SKIPS_PER_CYCLE: usize = 20;

/// Event tables that hold platform audit rows (`source_type = 'audit'`):
/// the UDM store and the OCSF stores (NAN-5354 writes audit to `ocsf_logs`
/// on OCSF installs; older installs also have it in `logs`). Before a
/// partition of one of these is dropped, its audit rows are archived.
const AUDIT_BEARING_TABLES: &[&str] = &["logs", "ocsf_logs", "ocsf_logs_legacy_v179"];

/// One `system.parts` snapshot of the daily tables, taken immediately before
/// a drop: the oldest partition strictly before the retention cutoff, and
/// the newest partition of any date (future-dated ones included).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartitionSnapshot {
    pub oldest_before_cutoff: Option<String>,
    pub newest: Option<String>,
}

fn is_partition_date(d: &str) -> bool {
    d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit())
}

/// The partition the evictor may drop given ONE snapshot, or `None`.
///
/// NAN-4982 (review P1s): the candidate must be strictly before the current
/// UTC partition AND strictly before the newest partition in the same
/// snapshot. Today's partition, and any future-dated one (a skewed source, or
/// one event stamped 2099), is never a candidate and never counts as "older"
/// data: a future partition cannot make today's evictable, and a partition that
/// TTL or an operator removed between two reads cannot turn the last remaining
/// partition into the candidate, because there is only one read.
///
/// NAN-5447: the candidate must also be strictly before `cutoff`, the
/// retention floor ([`retention_cutoff`]). The snapshot query already filters
/// on it; this re-check keeps the floor a property of this one function.
pub fn evictable_partition(snapshot: &PartitionSnapshot, today: &str, cutoff: &str) -> Option<String> {
    let candidate = snapshot.oldest_before_cutoff.as_deref()?;
    let newest = snapshot.newest.as_deref()?;
    (is_partition_date(candidate)
        && is_partition_date(today)
        && is_partition_date(cutoff)
        && cutoff <= today
        && candidate < cutoff
        && candidate < newest)
        .then(|| candidate.to_string())
}

/// The current UTC partition value (`toYYYYMMDD` of now, UTC).
pub fn utc_today_partition() -> String {
    chrono::Utc::now().format("%Y%m%d").to_string()
}

/// NAN-5447: the oldest partition value the retention floor protects:
/// `today - floor_days`. Partitions strictly before it may be evicted; it and
/// everything after it may not. `floor_days = 0` gives `today` (only today is
/// protected, the pre-floor behavior). `None` for a malformed `today`, which
/// the caller treats as "drop nothing".
pub fn retention_cutoff(today: &str, floor_days: u64) -> Option<String> {
    let date = chrono::NaiveDate::parse_from_str(today, "%Y%m%d").ok()?;
    let days = floor_days.min(MAX_MIN_RETENTION_DAYS);
    let cutoff = date.checked_sub_days(chrono::Days::new(days))?;
    Some(cutoff.format("%Y%m%d").to_string())
}

/// NAN-5447: the retention floor one pressure episode uses.
///
/// An explicitly configured floor (`DISK_PRESSURE_MIN_RETENTION_DAYS`) is
/// used as is. The default floor is at most what the install holds: an
/// install that is sized for fewer days than the default (say 4) would
/// otherwise hit the floor on its first episode after the upgrade and pause
/// ingestion where it used to evict. `days_held` is the age in days of the
/// oldest daily partition at the start of the episode; the floor keeps one
/// day less than that, so the oldest day stays evictable (never below one
/// day, so today and yesterday are always kept). The caller computes it once
/// per episode, so the floor cannot ratchet down while one episode drops.
pub fn effective_floor_days(configured: u64, explicit: bool, days_held: Option<u64>) -> u64 {
    let configured = configured.min(MAX_MIN_RETENTION_DAYS);
    match (explicit, days_held) {
        (true, _) | (false, None) => configured,
        (false, Some(held)) => configured.min(held.saturating_sub(1).max(1)),
    }
}

/// Age in days of partition `oldest` on `today` (both `YYYYMMDD`).
pub fn partition_age_days(oldest: &str, today: &str) -> Option<u64> {
    let parse = |d: &str| chrono::NaiveDate::parse_from_str(d, "%Y%m%d").ok();
    let days = (parse(today)? - parse(oldest)?).num_days();
    u64::try_from(days).ok()
}

/// One disk sample: the worst Local data disk (per [`DiskPressureService`]'s
/// selection) and the bytes ClickHouse's own parts occupy on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSample {
    pub host: String,
    pub disk: String,
    pub total: u64,
    pub free: u64,
    /// Bytes of ClickHouse data parts on this disk (all databases): active
    /// parts plus outdated parts that are not hard-link copies of an active
    /// part (see [`clickhouse_bytes_sql`]).
    pub ch_bytes: u64,
}

impl DiskSample {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }
    pub fn usage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.used() as f64 / self.total as f64
        }
    }
    /// Used bytes that are NOT ClickHouse parts (PostgreSQL, Vector buffers,
    /// Docker images, backups, logs, stray files on a shared filesystem).
    pub fn non_clickhouse(&self) -> u64 {
        self.used().saturating_sub(self.ch_bytes)
    }
}

/// NAN-5447: whether dropping ClickHouse partitions is the right response.
#[derive(Debug, Clone, PartialEq)]
pub enum EvictionGate {
    Drop,
    /// Something other than ClickHouse is what filled the disk: deleting
    /// history would not relieve it.
    NonClickHouse {
        /// Fraction of the disk used by non-ClickHouse data.
        non_clickhouse_fraction: f64,
        /// Non-ClickHouse growth since the last normal-pressure sample, if
        /// one exists for this disk.
        non_clickhouse_growth_bytes: Option<u64>,
    },
}

/// NAN-5447: drop only when ClickHouse data caused the pressure.
///
/// Two checks, both on the same disk sample:
///
/// 1. **Futility.** If the non-ClickHouse bytes alone are at or above the low
///    watermark, deleting every ClickHouse byte still would not bring the disk
///    back to the target. The loop would delete all history down to the floor
///    and relieve nothing. Never drop.
/// 2. **Cause.** `baseline` is the last sample of this disk taken at normal
///    pressure. Hold only when all of these are true: the non-ClickHouse
///    growth since then is material ([`material_growth_bytes`]), it is larger
///    than ClickHouse's own growth over the same period, and without it the
///    disk would be below the high watermark. Otherwise ClickHouse (or
///    nothing measurable) is what grew, and eviction is the right response.
///    Without a baseline (the service started under pressure) only the
///    futility check applies.
///
/// A sample with no total (no disk info) never gates: the caller has no disk
/// to act on anyway.
pub fn eviction_gate(sample: &DiskSample, baseline: Option<&DiskSample>, high: f64, low: f64) -> EvictionGate {
    if sample.total == 0 {
        return EvictionGate::Drop;
    }
    let total = sample.total as f64;
    let non_ch = sample.non_clickhouse();
    let non_ch_fraction = non_ch as f64 / total;
    let growth = baseline
        .filter(|b| b.host == sample.host && b.disk == sample.disk && b.total == sample.total)
        .map(|b| non_ch.saturating_sub(b.non_clickhouse()));
    let gated = EvictionGate::NonClickHouse {
        non_clickhouse_fraction: non_ch_fraction,
        non_clickhouse_growth_bytes: growth,
    };
    if non_ch_fraction >= low {
        return gated;
    }
    if let (Some(growth), Some(baseline)) = (growth, baseline) {
        let ch_growth = sample.ch_bytes.saturating_sub(baseline.ch_bytes);
        if growth >= material_growth_bytes(sample.total)
            && growth > ch_growth
            && (sample.used().saturating_sub(growth) as f64) < high * total
        {
            return gated;
        }
    }
    EvictionGate::Drop
}

/// Non-ClickHouse growth below this is noise (logs, a package cache, a
/// PostgreSQL vacuum) and never stops eviction: 1% of the disk, at least
/// 256 MiB.
pub fn material_growth_bytes(total: u64) -> u64 {
    (total / 100).max(256 * 1024 * 1024)
}

/// NAN-5447: the sample for the disk pressure is measured on, from every
/// Local disk (`disks`: host, name, total, free) and ClickHouse's part bytes
/// per (host, disk).
///
/// The disk is the one [`DiskPressureService`] reports: the worst used
/// fraction on a cluster, the largest otherwise (ties broken by host and
/// name, so the choice does not depend on row order). ClickHouse's bytes are
/// summed over EVERY disk on the same filesystem: ClickHouse disks on one
/// host that report the same `total_space` and `free_space` are paths on one
/// filesystem (Compose's `default` and `warm_disk` in
/// `clickhouse/config.d/storage.xml`). Counting only the chosen disk's parts
/// would read ClickHouse's bytes as ~0 when the parts live on the sibling,
/// and the gate would treat ClickHouse's own growth as foreign.
///
/// `disks` must carry PHYSICAL filesystem figures (see [`physical_disk`]):
/// `system.disks` reports total/free net of each disk's
/// `keep_free_space_bytes`, so Compose's `backups` disk (no reserve) and
/// `default` / `warm_disk` (1 GiB reserve) on one filesystem otherwise differ
/// by exactly the reserve and are not recognised as siblings (NAN-5463).
/// Among equally ranked disks, the one holding the most ClickHouse part bytes
/// names the sample, so it is reported as `default`, not `backups`.
pub fn select_disk_sample(
    disks: &[(String, String, u64, u64)],
    parts: &[(String, String, u64)],
    clustered: bool,
) -> Option<DiskSample> {
    let key = |d: &(String, String, u64, u64)| {
        if clustered {
            d.2.saturating_sub(d.3) as f64 / d.2.max(1) as f64
        } else {
            d.2 as f64
        }
    };
    let own_bytes = |d: &(String, String, u64, u64)| -> u64 {
        parts
            .iter()
            .filter(|(host, disk, _)| *host == d.0 && *disk == d.1)
            .map(|(_, _, b)| *b)
            .sum()
    };
    let worst = disks.iter().filter(|d| d.2 > 0).max_by(|a, b| {
        key(a)
            .partial_cmp(&key(b))
            .unwrap_or(std::cmp::Ordering::Equal)
            // NAN-5463: a disk that holds ClickHouse parts names the sample.
            .then_with(|| own_bytes(a).cmp(&own_bytes(b)))
            // Deterministic tie-break: the lexically smallest (host, name) wins.
            .then_with(|| (&b.0, &b.1).cmp(&(&a.0, &a.1)))
    })?;
    let same_fs: Vec<&str> = disks
        .iter()
        .filter(|d| d.0 == worst.0 && d.2 == worst.2 && d.3 == worst.3)
        .map(|d| d.1.as_str())
        .collect();
    let ch_bytes = parts
        .iter()
        .filter(|(host, disk, _)| *host == worst.0 && same_fs.contains(&disk.as_str()))
        .map(|(_, _, b)| *b)
        .sum();
    Some(DiskSample { host: worst.0.clone(), disk: worst.1.clone(), total: worst.2, free: worst.3, ch_bytes })
}

/// NAN-5463: one `system.disks` row as (host, name, total, free) of the
/// PHYSICAL filesystem: ClickHouse reports `total_space` and `free_space` net
/// of the disk's `keep_free_space_bytes`, which differs per disk on one
/// filesystem. Adding it back makes sibling disks compare equal in
/// [`select_disk_sample`].
pub fn physical_disk(host: String, name: String, total_space: u64, free_space: u64, keep_free_space: u64) -> (String, String, u64, u64) {
    (host, name, total_space.saturating_add(keep_free_space), free_space.saturating_add(keep_free_space))
}

/// What one eviction step removed from a partition date.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evicted {
    /// Tables the partition was dropped from.
    pub dropped: Vec<String>,
    /// Origin tables whose audit rows were copied to `audit_archive` (and
    /// verified) before the drop.
    pub archived_from: Vec<String>,
    /// Audit rows of this date now in the archive.
    pub archived_rows: u64,
}

impl Evicted {
    pub fn is_empty(&self) -> bool {
        self.dropped.is_empty()
    }
}

/// The partition operations the FIFO drop loop needs (a seam so the
/// fencing of the loop is testable without ClickHouse).
#[async_trait::async_trait]
pub trait PartitionDropper: Send + Sync {
    /// Snapshot of the daily tables' partitions relative to `cutoff` (the
    /// retention floor).
    async fn partition_snapshot(&self, cutoff: &str) -> Result<PartitionSnapshot, DiskPressureError>;
    /// Current disk usage, 0.0..=1.0.
    async fn usage(&self) -> Result<f64, DiskPressureError>;
    /// Evict partition `date` from every daily table that holds it, after
    /// archiving its audit rows. An empty result means the partition was
    /// already gone.
    async fn drop_partition(&self, date: &str) -> Result<Evicted, DiskPressureError>;
    /// Called after each successful eviction (audit, notification, counters).
    async fn dropped(&self, _date: &str, _evicted: &Evicted) {}
}

/// How a FIFO drop pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropLoopOutcome {
    /// Usage is at or below the low watermark.
    Relieved,
    /// Only partitions protected by the retention floor (or today's, or
    /// future-dated ones) are left: never dropped.
    Floor,
    NothingToDrop,
    /// This instance no longer holds the jobs lease epoch.
    Superseded,
    Failed,
    /// NAN-5447: the next candidate holds audit rows that could not be
    /// archived. Nothing of that date is dropped.
    AuditBlocked,
    MaxDrops,
}

/// What one guarded step did.
enum Step {
    Dropped(String, Evicted),
    Vanished(String),
    Floor,
    Nothing,
}

/// Drop oldest partitions until usage reaches `low_watermark`.
///
/// NAN-4933 (review P1): before EVERY drop the loop re-measures pressure and
/// runs the drop under [`crate::leader::LeaderFence::run_guarded`]: a leader
/// that was paused mid-loop and superseded is refused before it drops another
/// partition, and a takeover cannot complete while a drop is in flight.
///
/// NAN-4982: the candidate is chosen from ONE partition snapshot taken inside
/// that guarded operation, and only [`evictable_partition`] may name it, so
/// the current UTC partition (`today`) and anything after it are never dropped.
///
/// NAN-5447: nor anything at or after `cutoff` (the retention floor). Steps
/// that find the partition already gone do not count toward `max_drops`;
/// they are capped separately by [`MAX_SKIPS_PER_CYCLE`].
#[allow(clippy::too_many_arguments)]
pub async fn fifo_drop_loop(
    dropper: &dyn PartitionDropper,
    fence: &crate::leader::LeaderFence,
    pool: &PgPool,
    low_watermark: f64,
    max_drops: usize,
    settle: std::time::Duration,
    today: &str,
    cutoff: &str,
) -> DropLoopOutcome {
    let mut drops = 0usize;
    let mut skips = 0usize;
    while drops < max_drops {
        match dropper.usage().await {
            Ok(usage) if usage <= low_watermark => return DropLoopOutcome::Relieved,
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to recheck disk usage: {}", e);
                return DropLoopOutcome::Failed;
            }
        }
        let step = fence
            .run_guarded(pool, || async {
                let snapshot = dropper.partition_snapshot(cutoff).await?;
                let Some(date) = evictable_partition(&snapshot, today, cutoff) else {
                    return Ok::<_, DiskPressureError>(if snapshot.newest.is_some() { Step::Floor } else { Step::Nothing });
                };
                info!(partition_date = %date, drop = drops + 1, "Evicting partition");
                let evicted = dropper.drop_partition(&date).await?;
                Ok(if evicted.is_empty() {
                    Step::Vanished(date)
                } else {
                    Step::Dropped(date, evicted)
                })
            })
            .await;
        match step {
            Err(fence_error) => {
                warn!(error = %fence_error, "Partition drop refused by the leader fence");
                return DropLoopOutcome::Superseded;
            }
            Ok(Err(DiskPressureError::AuditArchiveFailed(why))) => {
                error!(reason = %why, "Audit rows could not be archived; not dropping the partition");
                return DropLoopOutcome::AuditBlocked;
            }
            Ok(Err(e)) => {
                error!("Failed to drop partition: {}", e);
                return DropLoopOutcome::Failed;
            }
            Ok(Ok(Step::Floor)) => {
                warn!(today = %today, cutoff = %cutoff, "Only partitions inside the retention floor remain; cannot drop further");
                return DropLoopOutcome::Floor;
            }
            Ok(Ok(Step::Nothing)) => {
                info!("No partitions to drop");
                return DropLoopOutcome::NothingToDrop;
            }
            Ok(Ok(Step::Vanished(date))) => {
                info!(
                    partition_date = %date,
                    "Partition already gone; skipping"
                );
                skips += 1;
                if skips >= MAX_SKIPS_PER_CYCLE {
                    return DropLoopOutcome::MaxDrops;
                }
                continue;
            }
            Ok(Ok(Step::Dropped(date, evicted))) => {
                drops += 1;
                dropper.dropped(&date, &evicted).await
            }
        }
        tokio::time::sleep(settle).await;
    }
    DropLoopOutcome::MaxDrops
}

#[async_trait::async_trait]
impl PartitionDropper for DiskPressureService {
    async fn partition_snapshot(&self, cutoff: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        self.read_partition_snapshot(cutoff).await
    }
    async fn usage(&self) -> Result<f64, DiskPressureError> {
        let (total, free) = self.get_disk_usage().await?;
        Ok(if total == 0 { 0.0 } else { total.saturating_sub(free) as f64 / total as f64 })
    }
    async fn drop_partition(&self, date: &str) -> Result<Evicted, DiskPressureError> {
        self.drop_partitions_for_date(date).await
    }
    async fn dropped(&self, date: &str, evicted: &Evicted) {
        self.partitions_dropped.fetch_add(1, Ordering::Relaxed);
        self.emit_drop_audit(date, evicted).await;
        self.notify_partition_dropped(date, evicted).await;
    }
}
/// Disk pressure management service.
///
/// Periodically checks ClickHouse disk usage and drops the oldest daily partitions
/// (FIFO) when usage exceeds the high watermark, stopping at the low watermark.
pub struct DiskPressureService {
    /// Admin ClickHouse client (system.* queries + DDL require elevated privileges)
    ch_admin: ClickHouseClient,
    /// PostgreSQL pool (for tiering status checks)
    pg_pool: PgPool,
    /// Audit emitter
    audit_emitter: AuditEmitter,
    /// Notification repository (in-app notifications for admin users)
    notification_repo: NotificationRepository,
    /// Health repository (issue tracking + deduplication)
    health_repo: HealthRepository,
    /// Durable owner-facing lifecycle and external delivery bus.
    system_health_repo: SystemHealthRepository,
    /// Configuration
    config: DiskPressureConfig,
    /// NAN-5217: the cluster-wide ingestion pause (PostgreSQL + ClickHouse
    /// guard). Shared with the API so the status and the admin actions see
    /// the same state on every host.
    ingestion_pause: Arc<IngestionPauseService>,
    /// Running counter of dropped partition-dates
    partitions_dropped: std::sync::atomic::AtomicU64,
    /// NAN-4933: the jobs lease epoch, set by `start`. Every partition drop
    /// runs under its strict guard.
    fence: std::sync::OnceLock<crate::leader::LeaderFence>,
    /// The admin client's database, read once from the server.
    database: std::sync::OnceLock<String>,
    /// NAN-5445: check cycles since start; the tiering health pass runs every
    /// `TIERING_HEALTH_EVERY_CYCLES`.
    cycles: std::sync::atomic::AtomicU64,
    /// NAN-5447: the last disk sample taken at normal pressure, the baseline
    /// for "what grew" in [`eviction_gate`].
    baseline: tokio::sync::Mutex<Option<DiskSample>>,
    /// NAN-5447: the retention floor of the current pressure episode
    /// ([`effective_floor_days`]), fixed at its first eviction and cleared at
    /// normal pressure.
    episode_floor_days: tokio::sync::Mutex<Option<u64>>,
    /// The active schema profile's audit store, for the audit archive.
    audit_store: crate::audit::query::AuditStore,
}

/// Run the storage-tiering health pass every N check cycles (10 min at the
/// default 60 s interval). The cold-read probe touches object storage.
const TIERING_HEALTH_EVERY_CYCLES: u64 = 10;

impl DiskPressureService {
    pub fn new(
        ch_admin: ClickHouseClient,
        pg_pool: PgPool,
        audit_emitter: AuditEmitter,
        config: DiskPressureConfig,
        ingestion_pause: Arc<IngestionPauseService>,
    ) -> Self {
        let notification_repo = NotificationRepository::new(pg_pool.clone());
        let health_repo = HealthRepository::new(pg_pool.clone());
        let system_health_repo = SystemHealthRepository::new(pg_pool.clone());
        Self {
            ch_admin,
            pg_pool,
            audit_emitter,
            notification_repo,
            health_repo,
            system_health_repo,
            config,
            ingestion_pause,
            partitions_dropped: std::sync::atomic::AtomicU64::new(0),
            fence: std::sync::OnceLock::new(),
            database: std::sync::OnceLock::new(),
            cycles: std::sync::atomic::AtomicU64::new(0),
            baseline: tokio::sync::Mutex::new(None),
            episode_floor_days: tokio::sync::Mutex::new(None),
            audit_store: crate::audit::query::AuditStore::for_active_profile(),
        }
    }

    /// Whether disk pressure pauses ingestion at the pause threshold
    /// (`DISK_PRESSURE_PAUSE_INGESTION`).
    pub fn auto_pause_enabled(&self) -> bool {
        self.config.pause_ingestion
    }

    // -- Storage tiering (NAN-5445) ------------------------------------------
    //
    // Enterprise-only: the cold-tier policy lookup, forced moves and the
    // tiering health pass live in `tiering/evictor.rs` (stripped from the
    // open-core mirror). Open core has no tiering: these are no-ops.

    /// Whether this node's catalog configures a cold-tier policy.
    #[cfg(not(feature = "enterprise"))]
    async fn cold_tier_configured(&self) -> bool {
        false
    }

    #[cfg(not(feature = "enterprise"))]
    async fn force_move_oldest_local(&self) {}

    #[cfg(not(feature = "enterprise"))]
    async fn check_tiering_health(&self) {}

    // -- Tiering check -----------------------------------------------------

    /// Whether object-storage tiering is active, so partition drops must stop.
    ///
    /// When tiering is active, ClickHouse moves parts to the cold volume (the
    /// policy's move_factor). We do NOT drop partitions in that case: the
    /// operator keeps data on object storage specifically to retain it.
    ///
    /// NAN-5445: ClickHouse is the only signal. The PostgreSQL
    /// `system_settings.tiering_enabled` flag was written by the removed in-app
    /// tiering flow, which never reached ClickHouse; trusting it switched
    /// cleanup off on installs where nothing ever left the local disk.
    async fn is_tiering_active(&self) -> bool {
        self.clickhouse_tiering_configured().await
    }

    /// Detect tiering from the ClickHouse storage layer directly.
    ///
    /// True if a storage policy that a daily table actually USES holds an
    /// object-storage disk (S3, Wasabi, GCS, R2, Azure: `ObjectStorage` type;
    /// see [`tiering_applies`]). On query error, returns false and logs — we'd
    /// rather drop partitions at high watermark than wedge the daemon if
    /// ClickHouse is flaky.
    ///
    /// NAN-4982: this used to answer true when ANY policy in the server config
    /// had a second volume. The Compose deployments mount
    /// `clickhouse/config.d/storage.xml`, which declares a `tiered` policy
    /// (two Local disks on the same filesystem) that no table uses, so every
    /// self-hosted Compose box counted as tiered and the evictor never dropped
    /// a partition from any table. Only a policy the event stores are on can
    /// move their parts off the local disk.
    async fn clickhouse_tiering_configured(&self) -> bool {
        match self.tiering_rows().await {
            Ok((used, policies, remote_disks)) => {
                let tiered = tiering_applies(&used, &policies, &remote_disks);
                if tiered {
                    info!(
                        policies = ?used,
                        "Tiering detected: a daily table uses a multi-volume or object-storage policy"
                    );
                }
                tiered
            }
            Err(e) => {
                // NAN-5445: fail closed when the server config has a cold
                // tier. With the object store down at ClickHouse start the
                // tiered tables never load and `system.tables` reads over the
                // database fail; answering "not tiered" here would drop
                // partitions the operator keeps on object storage. The policy
                // catalog (`system.storage_policies` / `system.disks`) does not
                // depend on the tables loading.
                if self.cold_tier_configured().await {
                    warn!(error = %e, "Cannot read which policies the event tables use, but a cold-tier \
                        policy is configured: treating tiering as active (no partition drops)");
                    return true;
                }
                warn!(error = %e, "Failed to read storage policies for tiering detection");
                false
            }
        }
    }

    /// Admin client for `clusterAllReplicas` reads: skips a down replica
    /// (see [`all_replicas_read_settings`]). Never used for DDL.
    fn all_replicas_reader(&self) -> ClickHouseClient {
        all_replicas_read_settings(clickhouse_cluster_name().as_deref())
            .iter()
            .fold(self.ch_admin.clone(), |client, (name, value)| {
                client.with_setting(*name, *value)
            })
    }

    /// (policies used by daily tables, every policy volume row, non-Local
    /// disks), read from every node (`clusterAllReplicas`) so detection is not
    /// blind to the shards the LB'd connection didn't land on (NAN-1728 H1).
    async fn tiering_rows(
        &self,
    ) -> Result<(Vec<String>, Vec<(String, u64, Vec<String>)>, Vec<String>), DiskPressureError> {
        let db = self.database().await?;
        let ch = |e: clickhouse::error::Error| DiskPressureError::ClickHouse(e.to_string());
        let used: Vec<String> = self
            .all_replicas_reader()
            .query(&used_policies_sql(&all_replicas_system("tables"), &db))
            .fetch_all::<String>()
            .await
            .map_err(ch)?;
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct PolicyRow {
            policy_name: String,
            volume_priority: u64,
            disks: Vec<String>,
        }
        let policies = self
            .all_replicas_reader()
            .query(&format!(
                "SELECT DISTINCT policy_name, toUInt64(volume_priority) AS volume_priority, disks FROM {}",
                all_replicas_system("storage_policies")
            ))
            .fetch_all::<PolicyRow>()
            .await
            .map_err(ch)?
            .into_iter()
            .map(|r| (r.policy_name, r.volume_priority, r.disks))
            .collect();
        let remote_disks: Vec<String> = self
            .all_replicas_reader()
            .query(&format!(
                "SELECT DISTINCT name FROM {} WHERE toString(type) = 'ObjectStorage'",
                all_replicas_system("disks")
            ))
            .fetch_all::<String>()
            .await
            .map_err(ch)?;
        Ok((used, policies, remote_disks))
    }

    // -- Queries -----------------------------------------------------------

    /// Query `system.disks` for the primary data disk.
    ///
    /// Selects the disk with the largest `total_space` rather than hardcoding
    /// `name = 'default'`. In Kubernetes with PVCs, the data volume may be
    /// named differently (e.g., the PVC mount), while `default` may refer to
    /// the small ephemeral container filesystem or not exist at all.
    async fn get_disk_usage(&self) -> Result<(u64, u64), DiskPressureError> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct DiskRow {
            total_space: u64,
            free_space: u64,
        }

        // Exclude ObjectStorage disks (S3/Wasabi) which report u64::MAX for total_space.
        // Only consider Local disks for pressure monitoring.
        //
        // NAN-1728 H1: on a cluster, disk pressure is the MAX usage across every
        // physical node (both replicas of every shard) — the emergency valve
        // must fire when ANY node is filling. Scan `clusterAllReplicas(system.disks)`
        // and pick the disk with the highest used-fraction so the caller's
        // `used/total` matches the worst node. On single-node this is
        // byte-identical: `system.disks` ordered by `total_space DESC`.
        let disks_src = all_replicas_system("disks");
        let order_by = if clickhouse_cluster_name().is_some() {
            "(total_space - free_space) / total_space DESC"
        } else {
            "total_space DESC"
        };
        let row = self
            .all_replicas_reader()
            .query(&format!(
                "SELECT total_space, free_space FROM {disks_src} WHERE type = 'Local' AND total_space > 0 ORDER BY {order_by} LIMIT 1"
            ))
            .fetch_optional::<DiskRow>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?
            .ok_or(DiskPressureError::NoDiskInfo)?;

        Ok((row.total_space, row.free_space))
    }

    /// Build a full status snapshot for the API.
    pub async fn get_status(&self) -> Result<DiskPressureStatus, DiskPressureError> {
        let (total, free) = self.get_disk_usage().await?;
        let used = total.saturating_sub(free);
        let usage = if total > 0 {
            used as f64 / total as f64
        } else {
            0.0
        };
        let level = self.classify(usage);

        let estimated_retention_days = self.estimate_retention_days(total, used).await.ok();

        Ok(DiskPressureStatus {
            usage_fraction: usage,
            total_bytes: total,
            used_bytes: used,
            free_bytes: free,
            level,
            estimated_retention_days,
            partitions_dropped: self.partitions_dropped.load(Ordering::Relaxed),
            // NAN-5217: PostgreSQL, not this process's memory: only the jobs
            // leader decides a pause, and every app host must report it.
            ingestion_paused: self
                .ingestion_pause
                .state()
                .await
                .map(|s| s.paused)
                .unwrap_or(false),
            high_watermark: self.config.high_watermark,
            low_watermark: self.config.low_watermark,
            critical_threshold: self.config.critical_threshold,
            emergency_threshold: self.config.emergency_threshold,
            auto_pause_enabled: self.config.pause_ingestion,
            pause_threshold: self.config.pause_threshold,
        })
    }

    /// One snapshot of the daily tables' partitions: the oldest strictly
    /// before `cutoff` and the newest overall.
    /// NAN-1728 H1: `min`/`max` of the partition value are replica-invariant,
    /// so scan every node via `clusterAllReplicas`; plain `system.parts` on
    /// single-node.
    async fn read_partition_snapshot(&self, cutoff: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        let query = partition_snapshot_sql(&all_replicas_system("parts"), &self.database().await?, cutoff)?;
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            oldest: String,
            newest: String,
        }
        let row = self
            .all_replicas_reader()
            .query(&query)
            .fetch_one::<Row>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;
        let some = |v: String| (!v.is_empty()).then_some(v);
        Ok(PartitionSnapshot { oldest_before_cutoff: some(row.oldest), newest: some(row.newest) })
    }

    /// The admin client's database, read once (NAN-4982: scopes the
    /// `system.parts` reads to the database the unqualified DROPs act on).
    async fn database(&self) -> Result<String, DiskPressureError> {
        if let Some(db) = self.database.get() {
            return Ok(db.clone());
        }
        let db = self
            .ch_admin
            .query("SELECT currentDatabase()")
            .fetch_one::<String>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;
        Ok(self.database.get_or_init(|| db).clone())
    }

    /// Daily tables holding an active part of partition `date` on any node.
    async fn tables_with_partition(&self, date: &str) -> Result<Vec<String>, DiskPressureError> {
        self.all_replicas_reader()
            .query(&tables_with_partition_sql(&all_replicas_system("parts"), &self.database().await?))
            .bind(date)
            .fetch_all::<String>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))
    }

    /// Evict a specific partition date from every daily table that holds it.
    ///
    /// NAN-4982: only the tables that actually hold the partition are altered
    /// (the OCSF store on an OCSF box, `logs` on a UDM box, the 1.8 legacy
    /// table while its rows age out), so a table missing on this deployment is
    /// never named in a DROP.
    ///
    /// NAN-5447: a partition with audit rows is dropped only after its audit
    /// rows are archived and verified ([`Self::archive_audit_rows`]); if
    /// that fails, the step stops before any table of this date is dropped.
    async fn drop_partitions_for_date(&self, date: &str) -> Result<Evicted, DiskPressureError> {
        // NAN-1728 H1: DROP PARTITION runs on the LOCAL MergeTree; `ON CLUSTER`
        // fans it out to every shard (empty clause → byte-identical on
        // single-node) so the emergency valve relieves the whole cluster, not
        // just the node the LB'd connection landed on.
        // NAN-4982: never today's or a future partition, whatever the caller.
        // NAN-5447: nor one inside the retention floor.
        let today = utc_today_partition();
        let floor = self.episode_floor_days.lock().await.unwrap_or(self.config.min_retention_days);
        let cutoff = retention_cutoff(&today, floor).unwrap_or_else(|| today.clone());
        if date >= cutoff.as_str() {
            return Err(DiskPressureError::ClickHouse(format!(
                "refusing to drop partition {date}: inside the retention floor (cutoff {cutoff}, today {today})"
            )));
        }
        let on_cluster = on_cluster_clause();
        let tables = self.tables_with_partition(date).await?;

        // NAN-5447: archive the audit rows first. Any failure stops the step
        // before a single table of this date is dropped.
        let mut audit_tables = Vec::new();
        for table in tables.iter().filter(|t| AUDIT_BEARING_TABLES.contains(&t.as_str())) {
            let (audit_rows, _) = self.audit_row_counts(table, date).await?;
            if audit_rows > 0 {
                audit_tables.push(table.as_str());
            }
        }
        let mut evicted = Evicted::default();
        if !audit_tables.is_empty() {
            evicted.archived_rows = self.archive_audit_rows(date, &audit_tables).await?;
            evicted.archived_from = audit_tables.iter().map(|t| t.to_string()).collect();
        }

        for table in &tables {
            let stmt = drop_partition_sql(table, &on_cluster, date)?;
            self.ch_admin
                .query(&stmt)
                .execute()
                .await
                .map_err(|e| DiskPressureError::ClickHouse(format!("{}: {}", table, e)))?;
            evicted.dropped.push(table.clone());
        }
        Ok(evicted)
    }

    /// NAN-5447: copy the audit rows of `date` (held by `audit_tables`) into
    /// `audit_archive` and check that every one arrived. Returns the number
    /// of archived rows for that date. Any failure is
    /// [`DiskPressureError::AuditArchiveFailed`].
    ///
    /// The copy is what the audit page showed for that day
    /// ([`crate::audit::archive::archive_sources`]), inserted only where it
    /// is missing, so a retry after a partial copy is safe. On a cluster the
    /// sources are read with `cluster(...)` (every shard) and the insert
    /// waits for a replica quorum, so the check that follows sees it.
    async fn archive_audit_rows(&self, date: &str, audit_tables: &[&str]) -> Result<u64, DiskPressureError> {
        use crate::audit::archive;
        let failed = |why: String| DiskPressureError::AuditArchiveFailed(format!("partition {date}: {why}"));
        let (start, end) = archive::day_window(date).ok_or_else(|| failed("invalid partition date".into()))?;
        let db = self.database().await?;
        let archive_write = archive::AUDIT_ARCHIVE_TABLE;
        let archive_read = self.table_source(&db, archive::AUDIT_ARCHIVE_TABLE);
        let sources = archive::archive_sources(self.audit_store, audit_tables, |t| self.table_source(&db, t), start, end);
        let clustered = clickhouse_cluster_name().is_some();

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Verify {
            expected: u64,
            missing: u64,
        }
        let mut archived = 0u64;
        for src in &sources {
            let (insert, binds) = archive::insert_sql(src, archive_write, &archive_read, start, end);
            let mut q = self.ch_admin.query(&insert);
            for b in &binds {
                q = q.bind(b.as_str());
            }
            if clustered {
                q = q.with_setting("insert_quorum", "auto");
            }
            q.execute().await.map_err(|e| failed(format!("copy from {} failed: {e}", src.origin)))?;

            let (verify, binds) = archive::verify_sql(src, &archive_read, start, end);
            let mut q = self.ch_admin.query(&verify);
            for b in &binds {
                q = q.bind(b.as_str());
            }
            let v = q
                .fetch_one::<Verify>()
                .await
                .map_err(|e| failed(format!("check of {} failed: {e}", src.origin)))?;
            if v.missing > 0 {
                return Err(failed(format!(
                    "{} of {} audit rows from {} are missing from the archive after the copy",
                    v.missing, v.expected, src.origin
                )));
            }
            info!(partition_date = %date, origin = src.origin, rows = v.expected, "Audit rows archived and verified");
            archived += v.expected;
        }
        Ok(archived)
    }

    /// `table` read source for row counts: one replica per shard on a
    /// cluster (`cluster(...)` fails over within a shard and errors when a
    /// whole shard is down, which stops the step instead of deciding "no
    /// audit rows" from partial data). The plain local table on single-node.
    fn table_source(&self, db: &str, table: &str) -> String {
        match clickhouse_cluster_name() {
            Some(cl) => format!(
                "cluster('{}', '{}', '{}')",
                crate::sql_hygiene::escape_sql_string(cl),
                crate::sql_hygiene::escape_sql_string(db),
                table
            ),
            None => table.to_string(),
        }
    }

    /// (audit rows, other rows) of one table's partition `date`.
    async fn audit_row_counts(&self, table: &str, date: &str) -> Result<(u64, u64), DiskPressureError> {
        let db = self.database().await?;
        let sql = audit_counts_sql(&self.table_source(&db, table), table, date)?;
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            audit_rows: u64,
            other_rows: u64,
        }
        let row = self
            .ch_admin
            .query(&sql)
            .fetch_one::<Row>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(format!("{table}: {e}")))?;
        Ok((row.audit_rows, row.other_rows))
    }

    /// One disk sample: the same disk [`Self::get_disk_usage`] picks, with the
    /// host name and ClickHouse's own bytes on its filesystem (NAN-5447,
    /// [`select_disk_sample`]).
    async fn disk_sample(&self) -> Result<DiskSample, DiskPressureError> {
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct DiskRow {
            host: String,
            name: String,
            total_space: u64,
            free_space: u64,
            keep_free_space: u64,
        }
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct PartsRow {
            host: String,
            disk: String,
            bytes: u64,
        }
        let ch = |e: clickhouse::error::Error| DiskPressureError::ClickHouse(e.to_string());
        let disks: Vec<_> = self
            .all_replicas_reader()
            .query(&format!(
                "SELECT hostName() AS host, name, total_space, free_space, keep_free_space FROM {} WHERE type = 'Local' AND total_space > 0",
                all_replicas_system("disks")
            ))
            .fetch_all::<DiskRow>()
            .await
            .map_err(ch)?
            .into_iter()
            .map(|d| physical_disk(d.host, d.name, d.total_space, d.free_space, d.keep_free_space))
            .collect();
        let parts: Vec<_> = self
            .all_replicas_reader()
            .query(&clickhouse_bytes_sql(&all_replicas_system("parts")))
            .fetch_all::<PartsRow>()
            .await
            .map_err(ch)?
            .into_iter()
            .map(|p| (p.host, p.disk, p.bytes))
            .collect();
        select_disk_sample(&disks, &parts, clickhouse_cluster_name().is_some()).ok_or(DiskPressureError::NoDiskInfo)
    }

    /// NAN-5447: the oldest daily partition at or before today on any node
    /// (the "days held" input of [`effective_floor_days`]).
    async fn oldest_partition(&self, today: &str) -> Result<Option<String>, DiskPressureError> {
        let sql = oldest_partition_sql(&all_replicas_system("parts"), &self.database().await?, today)?;
        let oldest = self
            .all_replicas_reader()
            .query(&sql)
            .fetch_one::<String>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;
        Ok((!oldest.is_empty()).then_some(oldest))
    }

    /// Estimate how many days of events the disk holds before eviction starts
    /// (NAN-5450): the stored days plus the headroom to the high watermark.
    /// Counting to 100 % overstated it: eviction starts at the high watermark.
    async fn estimate_retention_days(&self, total: u64, used: u64) -> Result<f64, DiskPressureError> {
        // NAN-1728 H1: average partition size across the whole cluster. Dedupe
        // replicas to one per shard (`cluster(...)`) so `sum(bytes_on_disk)` is
        // not doubled by the replica; `countDistinct(partition)` is date-count.
        // Plain `system.parts` on single-node.
        let query = avg_partition_bytes_sql(&parts_source_dedup(), &self.database().await?);

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            avg_partition_bytes: f64,
            partitions: u64,
        }

        let row = self
            .ch_admin
            .query(&query)
            .fetch_one::<Row>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;

        Ok(retention_days_at_high_watermark(
            total,
            used,
            self.config.high_watermark,
            row.avg_partition_bytes,
            row.partitions,
        ))
    }

    // -- Pressure classification -------------------------------------------

    fn classify(&self, usage: f64) -> DiskPressureLevel {
        if usage >= self.config.emergency_threshold {
            DiskPressureLevel::Emergency
        } else if usage >= self.config.critical_threshold {
            DiskPressureLevel::Critical
        } else if usage >= self.config.high_watermark {
            DiskPressureLevel::Elevated
        } else {
            DiskPressureLevel::Normal
        }
    }

    // -- Main check cycle --------------------------------------------------

    /// Run one check cycle: the disk check, then (always, even when the disk
    /// read failed) reconcile the ingestion-pause ClickHouse guard with the
    /// PostgreSQL flag, so a stale guard heals without a working disk read.
    async fn run_check_cycle(&self) {
        self.check_disk_pressure().await;
        if self.cycles.fetch_add(1, Ordering::Relaxed) % TIERING_HEALTH_EVERY_CYCLES == 0 {
            self.check_tiering_health().await;
        }
        // NAN-5217: converge the ClickHouse guard with the PostgreSQL flag
        // (a failed DDL, a restarted node, a pause set on another host).
        if let Err(error) = self.ingestion_pause.reconcile().await {
            warn!(%error, "ingestion pause reconcile failed");
        }
    }

    /// Read disk usage → classify → take action.
    async fn check_disk_pressure(&self) {
        let (total, free) = match self.get_disk_usage().await {
            Ok(v) => v,
            Err(e) => {
                warn!("Disk pressure check failed: {}", e);
                return;
            }
        };

        let used = total.saturating_sub(free);
        let usage = if total > 0 {
            used as f64 / total as f64
        } else {
            0.0
        };
        let level = self.classify(usage);

        // NAN-5446: pause first (drops can take a while), at the pause
        // threshold whatever the level. Lifting happens at Normal or once the
        // drops reach the low watermark, so there is a wide hysteresis band.
        if self.config.should_pause(usage) {
            self.auto_pause(usage).await;
        }

        match level {
            DiskPressureLevel::Emergency => {
                error!(
                    usage_pct = format!("{:.1}%", usage * 100.0),
                    "EMERGENCY disk pressure — usage above {}%",
                    self.config.emergency_threshold * 100.0
                );
                self.emit_critical_audit(usage).await;
                self.track_pressure_issue(usage, "emergency").await;

                // Still try to relieve pressure
                self.relieve_pressure(usage).await;
            }
            DiskPressureLevel::Critical => {
                warn!(
                    usage_pct = format!("{:.1}%", usage * 100.0),
                    "Critical disk pressure — usage above {}%",
                    self.config.critical_threshold * 100.0
                );
                self.emit_critical_audit(usage).await;
                self.track_pressure_issue(usage, "critical").await;
                self.relieve_pressure(usage).await;
            }
            DiskPressureLevel::Elevated => {
                info!(
                    usage_pct = format!("{:.1}%", usage * 100.0),
                    "Elevated disk pressure — dropping oldest partitions"
                );
                self.publish_pressure_health(usage, "elevated").await;
                self.relieve_pressure(usage).await;
            }
            DiskPressureLevel::Normal => {
                // Resolve any active disk pressure issue now that we're back to normal
                if let Err(e) = self
                    .health_repo
                    .resolve_issue(
                        &HealthIssueType::DiskPressure.to_string(),
                        "clickhouse_disk",
                    )
                    .await
                {
                    warn!("Failed to resolve disk pressure health issue: {}", e);
                }
                if let Err(error) = self
                    .system_health_repo
                    .resolve_by_dedup_key("storage:clickhouse:disk_pressure")
                    .await
                {
                    warn!(%error, "Failed to resolve disk-pressure system health event");
                }

                // Lift an automatic pause now that we're back to normal (a
                // manual pause stays until an administrator lifts it).
                self.auto_resume(usage, "disk pressure back to normal").await;
                self.on_normal_pressure().await;
            }
        }
    }

    /// Drop oldest partitions until usage is below the target watermark.
    ///
    /// **Storage-tiered deployments (multi-volume storage policy with cold
    /// object storage):** never drop. ClickHouse's
    /// `move_factor` is what bleeds parts off to warm storage, and the upstream
    /// classifier in `run_check_cycle` already emits `disk_pressure_critical`
    /// audit + notification at Critical/Emergency for ops visibility. Dropping
    /// locally while moves are stalled would delete data the customer is paying
    /// to retain — the part may not yet be in warm storage. Local-disk pressure
    /// here is a safety/alerting concern, not a data-loss concern.
    ///
    /// **Single-volume deployments (local storage only):** the existing FIFO
    /// drop loop is the retention mechanism.
    /// Drop oldest daily partitions until usage falls below the low watermark.
    async fn relieve_pressure(&self, current_usage: f64) {
        if self.is_tiering_active().await {
            if current_usage >= self.config.critical_threshold {
                warn!(
                    usage_pct = format!("{:.1}%", current_usage * 100.0),
                    "Storage tiering is active and disk is at critical levels — \
                     NOT dropping local partitions (parts may not yet be moved \
                     to warm). disk_pressure_critical audit already emitted by \
                     run_check_cycle; ops should investigate move_factor / \
                     stalled MOVEs in ClickHouse."
                );
                // NAN-5445: move_factor is a background process and can lag a
                // burst. Ask ClickHouse to move the oldest local partitions to
                // the cold volume now (async; a dead store just fails the
                // move, which SIEM Health reports). Never a drop.
                self.force_move_oldest_local().await;
            } else {
                info!(
                    usage_pct = format!("{:.1}%", current_usage * 100.0),
                    "Storage tiering is active — letting ClickHouse move_factor \
                     handle data movement to warm storage"
                );
            }
            return;
        }

        // Tiering not active — single-volume deployment, FIFO retention.
        //
        // NAN-5447: first make sure ClickHouse is what filled the disk.
        match self.disk_sample().await {
            Ok(sample) => {
                let baseline = self.baseline.lock().await.clone();
                let gate = eviction_gate(
                    &sample,
                    baseline.as_ref(),
                    self.config.high_watermark,
                    self.config.low_watermark,
                );
                if let EvictionGate::NonClickHouse { non_clickhouse_fraction, non_clickhouse_growth_bytes } = gate {
                    warn!(
                        usage_pct = format!("{:.1}%", current_usage * 100.0),
                        non_clickhouse_pct = format!("{:.1}%", non_clickhouse_fraction * 100.0),
                        clickhouse_bytes = sample.ch_bytes,
                        growth_bytes = ?non_clickhouse_growth_bytes,
                        "Disk pressure is not caused by ClickHouse data; NOT dropping partitions"
                    );
                    self.hold_and_alarm(
                        current_usage,
                        HoldReason::NonClickHouse { sample, non_clickhouse_growth_bytes },
                    )
                    .await;
                    return;
                }
            }
            Err(e) => {
                // Without attribution, fall back to the pre-NAN-5447
                // behavior: the floor and the audit protection still apply.
                warn!(error = %e, "Failed to measure ClickHouse's share of the disk; evicting on usage alone");
            }
        }

        let today = utc_today_partition();
        let floor_days = self.episode_floor(&today).await;
        let Some(cutoff) = retention_cutoff(&today, floor_days) else {
            error!(today = %today, "Invalid current partition value; not dropping");
            return;
        };
        let fence = self
            .fence
            .get()
            .cloned()
            .unwrap_or_else(crate::leader::LeaderFence::disabled);
        let outcome = fifo_drop_loop(
            self,
            &fence,
            &self.pg_pool,
            self.config.low_watermark,
            MAX_DROPS_PER_CYCLE,
            std::time::Duration::from_secs(2),
            &today,
            &cutoff,
        )
        .await;
        match outcome {
            DropLoopOutcome::Relieved => {
                info!("Disk usage below low watermark; stopping drops");
                // Lift an automatic pause only once the disk is below the
                // high watermark.
                match self.get_disk_usage().await {
                    Ok((total, free)) if total > 0 && (total.saturating_sub(free) as f64 / total as f64) < self.config.high_watermark => {
                        self.auto_resume(current_usage, "disk usage below the low watermark").await;
                    }
                    _ => {}
                }
            }
            DropLoopOutcome::MaxDrops => warn!(
                "Reached max drops per cycle ({}) — will continue next cycle",
                MAX_DROPS_PER_CYCLE
            ),
            DropLoopOutcome::Superseded => {
                warn!("No longer the jobs leader — stopping partition drops")
            }
            DropLoopOutcome::Floor => {
                self.hold_and_alarm(current_usage, HoldReason::RetentionFloor { cutoff, floor_days }).await;
            }
            DropLoopOutcome::AuditBlocked => {
                self.hold_and_alarm(current_usage, HoldReason::AuditArchiveFailed).await;
            }
            DropLoopOutcome::NothingToDrop | DropLoopOutcome::Failed => {}
        }
    }

    /// NAN-5447: the retention floor of this pressure episode, fixed at its
    /// first eviction ([`effective_floor_days`]). When the oldest partition
    /// cannot be read, the configured floor applies.
    async fn episode_floor(&self, today: &str) -> u64 {
        let mut floor = self.episode_floor_days.lock().await;
        if let Some(days) = *floor {
            return days;
        }
        let held = match self.oldest_partition(today).await {
            Ok(oldest) => oldest.and_then(|o| partition_age_days(&o, today)),
            Err(e) => {
                warn!(error = %e, "Failed to read the oldest partition; using the configured retention floor");
                None
            }
        };
        let days = effective_floor_days(self.config.min_retention_days, self.config.min_retention_explicit, held);
        if days < self.config.min_retention_days {
            info!(
                floor_days = days,
                configured = self.config.min_retention_days,
                days_held = ?held,
                "This install holds fewer days than the default retention floor; using a smaller floor for this episode"
            );
        }
        *floor = Some(days);
        days
    }

    // -- Hold instead of drop (NAN-5447) ------------------------------------

    /// The evictor will not (or cannot) free space by dropping: alarm once per
    /// episode, and at the critical level pause ingestion (when
    /// `DISK_PRESSURE_PAUSE_INGESTION` allows it) so the disk does not fill.
    /// Below critical the disk still has headroom; pausing there would stop
    /// ingest for a condition an operator can fix calmly.
    async fn hold_and_alarm(&self, usage: f64, reason: HoldReason) {
        let pause = self.config.pause_ingestion && usage >= self.config.critical_threshold;
        let (dedup_key, issue_key, title, detail) = reason.describe(&self.config);
        let pct = format!("{:.1}%", usage * 100.0);

        // Critical once the disk is at the critical level (ingest is being
        // paused); High while there is still headroom.
        let severity = if usage >= self.config.critical_threshold {
            HealthSeverity::Critical
        } else {
            HealthSeverity::High
        };
        let mut event = PublishHealthEvent::new(
            dedup_key,
            HealthCategory::Storage,
            severity,
            title.clone(),
            format!("Disk usage is {pct}. {detail}"),
            "clickhouse_storage",
            "disk_pressure_service",
        );
        event.resource_id = Some(issue_key.to_string());
        event.resource_name = Some("ClickHouse".to_string());
        event.diagnostic_context = reason.context(usage, &self.config, pause);
        event.remediation = Some(reason.remediation().to_string());
        if let Err(error) = self.system_health_repo.publish(&event).await {
            warn!(%error, "Failed to publish disk-pressure hold health event");
        }

        self.notify_once(issue_key, &title, &format!("Disk usage is {pct}. {detail}"), usage).await;

        if pause {
            self.pause_for_hold(usage, &format!("{title} (disk {pct} used)")).await;
        }
    }

    /// Pause ingestion for a hold (floor reached, non-ClickHouse growth, or
    /// audit rows that could not be archived) and audit the transition once.
    async fn pause_for_hold(&self, usage: f64, reason: &str) {
        match self
            .ingestion_pause
            .pause(IngestionPauseSource::DiskPressure, Some(reason), None)
            .await
        {
            Ok((_, true)) => {
                warn!(reason, "Ingestion PAUSED: disk pressure cannot be relieved by dropping partitions");
                self.emit_pause_audit(crate::audit::INGESTION_PAUSED, usage, reason).await;
            }
            Ok((_, false)) => {}
            Err(error) => error!(%error, "Failed to pause ingestion for a disk-pressure hold"),
        }
    }

    /// Notify admins once per episode for `issue_key` (the HealthScheduler
    /// pattern: create the issue, notify, mark sent; resolved at Normal).
    async fn notify_once(&self, issue_key: &str, title: &str, message: &str, usage: f64) {
        let issue_type = HealthIssueType::DiskPressure.to_string();
        let issue = match self.health_repo.find_active_issue(&issue_type, issue_key).await {
            Ok(Some(issue)) => issue,
            Ok(None) => match self.health_repo.create_issue(&issue_type, issue_key).await {
                Ok(issue) => issue,
                Err(e) => {
                    warn!(issue_key, "Failed to create disk-pressure hold issue: {}", e);
                    return;
                }
            },
            Err(e) => {
                warn!(issue_key, "Failed to check disk-pressure hold issue: {}", e);
                return;
            }
        };
        if issue.notification_sent {
            return;
        }
        let admin_ids = match self.health_repo.get_admin_user_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!("Failed to get admin user IDs for disk-pressure hold notification: {}", e);
                return;
            }
        };
        for user_id in &admin_ids {
            let notification = NewNotification {
                user_id: *user_id,
                notification_type: NotificationType::DiskPressureWarning,
                title: title.to_string(),
                message: Some(message.to_string()),
                link: Some("/settings/storage".to_string()),
                metadata: serde_json::json!({ "usage_fraction": usage, "issue": issue_key }),
            };
            if let Err(e) = self.notification_repo.create(&notification).await {
                warn!(user_id = %user_id, "Failed to create disk-pressure hold notification: {}", e);
            }
        }
        if let Err(e) = self.health_repo.mark_notification_sent(issue.id).await {
            warn!("Failed to mark disk-pressure hold notification as sent: {}", e);
        }
    }

    /// Back to normal: resolve the hold issues and events, and record the
    /// baseline sample for [`eviction_gate`].
    async fn on_normal_pressure(&self) {
        *self.episode_floor_days.lock().await = None;
        for (issue_key, dedup_key) in HoldReason::KEYS {
            if let Err(e) = self
                .health_repo
                .resolve_issue(&HealthIssueType::DiskPressure.to_string(), issue_key)
                .await
            {
                warn!(issue_key, "Failed to resolve disk-pressure hold issue: {}", e);
            }
            if let Err(error) = self.system_health_repo.resolve_by_dedup_key(dedup_key).await {
                warn!(%error, dedup_key, "Failed to resolve disk-pressure hold health event");
            }
        }
        match self.disk_sample().await {
            Ok(sample) => *self.baseline.lock().await = Some(sample),
            Err(e) => warn!(error = %e, "Failed to record the normal-pressure disk baseline"),
        }
    }

    // -- Ingestion pause (NAN-5217) ----------------------------------------

    /// Pause ingestion cluster-wide at the pause threshold, and audit the
    /// transition once.
    async fn auto_pause(&self, usage: f64) {
        let reason = format!(
            "Disk pressure: ClickHouse disk {:.1}% used (pause threshold {:.0}%)",
            usage * 100.0,
            self.config.pause_threshold * 100.0
        );
        match self
            .ingestion_pause
            .pause(IngestionPauseSource::DiskPressure, Some(&reason), None)
            .await
        {
            Ok((_, true)) => {
                warn!("Ingestion PAUSED due to disk pressure");
                self.emit_pause_audit(crate::audit::INGESTION_PAUSED, usage, &reason)
                    .await;
            }
            Ok((_, false)) => {}
            Err(error) => error!(%error, "Failed to pause ingestion at disk pressure"),
        }
    }

    /// Lift an automatic pause (never a manual one), and audit the transition.
    async fn auto_resume(&self, usage: f64, why: &str) {
        match self.ingestion_pause.resume(true).await {
            Ok((_, true)) => {
                info!("Ingestion RESUMED — {why}");
                self.emit_pause_audit(crate::audit::INGESTION_RESUMED, usage, why)
                    .await;
            }
            Ok((_, false)) => {}
            Err(error) => warn!(%error, "Failed to resume ingestion after disk pressure"),
        }
    }

    async fn emit_pause_audit(&self, action: &str, usage: f64, reason: &str) {
        let event = AuditEvent::builder(AuditSource::Storage, action)
            .resource("ingestion", None, Some("ingestion".to_string()))
            .success(true)
            .details(serde_json::json!({
                "source": IngestionPauseSource::DiskPressure.as_str(),
                "reason": reason,
                "usage_fraction": usage,
                "emergency_threshold": self.config.emergency_threshold,
            }))
            .build();
        if let Err(e) = self.audit_emitter.emit_durable(&event).await {
            warn!("Failed to emit {action} audit event: {e}");
        }
    }

    // -- Audit -------------------------------------------------------------

    /// NAN-5447: durable. Deleting stored events is exactly what an audit
    /// trail must record, and this emit races a disk that is filling.
    async fn emit_drop_audit(&self, date: &str, evicted: &Evicted) {
        let event = AuditEvent::builder(AuditSource::Storage, "partition_dropped")
            .resource("partition", None, Some(date.to_string()))
            .success(true)
            .details(drop_audit_details(date, evicted, self.config.min_retention_days))
            .build();

        if let Err(e) = self.audit_emitter.emit_durable(&event).await {
            warn!("Failed to emit partition_dropped audit event: {}", e);
        }
    }

    async fn emit_critical_audit(&self, usage: f64) {
        let event = AuditEvent::builder(AuditSource::Storage, "disk_pressure_critical")
            .success(true)
            .details(serde_json::json!({
                "usage_fraction": usage,
                "usage_percent": format!("{:.1}%", usage * 100.0),
            }))
            .build();

        if let Err(e) = self.audit_emitter.emit(&event).await {
            warn!("Failed to emit disk_pressure_critical audit event: {}", e);
        }
    }

    // -- Notifications / Health Issues -------------------------------------

    /// Track a disk pressure health issue and notify admins (deduplicated).
    ///
    /// Uses the same pattern as HealthScheduler: create_issue → send notification → mark sent.
    /// Only sends one notification per pressure episode (resolved when back to Normal).
    async fn track_pressure_issue(&self, usage: f64, severity: &str) {
        let issue_key = "clickhouse_disk";

        self.publish_pressure_health(usage, severity).await;

        let existing = match self
            .health_repo
            .find_active_issue(&HealthIssueType::DiskPressure.to_string(), issue_key)
            .await
        {
            Ok(issue) => issue,
            Err(e) => {
                warn!("Failed to check for existing disk pressure issue: {}", e);
                return;
            }
        };

        if let Some(issue) = existing {
            // Already tracking this episode — only notify if we haven't yet
            if !issue.notification_sent {
                self.send_pressure_notification(usage, severity).await;
                if let Err(e) = self.health_repo.mark_notification_sent(issue.id).await {
                    warn!("Failed to mark disk pressure notification as sent: {}", e);
                }
            }
        } else {
            // New pressure episode — create issue and notify
            match self
                .health_repo
                .create_issue(&HealthIssueType::DiskPressure.to_string(), issue_key)
                .await
            {
                Ok(issue) => {
                    self.send_pressure_notification(usage, severity).await;
                    if let Err(e) = self.health_repo.mark_notification_sent(issue.id).await {
                        warn!("Failed to mark disk pressure notification as sent: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Failed to create disk pressure health issue: {}", e);
                }
            }
        }
    }

    async fn publish_pressure_health(&self, usage: f64, severity: &str) {
        let health_severity = match severity {
            "emergency" => HealthSeverity::Critical,
            "critical" => HealthSeverity::High,
            _ => HealthSeverity::Medium,
        };
        let pct = format!("{:.1}%", usage * 100.0);
        let pause = if self.config.pause_ingestion {
            format!("{:.0}%", self.config.pause_threshold * 100.0)
        } else {
            "no level (automatic pause is off)".to_string()
        };
        let mut event = PublishHealthEvent::new(
            "storage:clickhouse:disk_pressure",
            HealthCategory::Storage,
            health_severity,
            format!("ClickHouse disk pressure is {severity}"),
            format!(
                "ClickHouse disk usage is {pct}. Oldest partitions may be dropped automatically, and ingestion pauses at {pause}."
            ),
            "clickhouse_storage",
            "disk_pressure_service",
        );
        event.resource_id = Some("clickhouse_disk".to_string());
        event.resource_name = Some("ClickHouse".to_string());
        event.diagnostic_context = serde_json::json!({
            "usage_fraction": usage,
            "severity": severity,
            "pause_ingestion_enabled": self.config.pause_ingestion,
            "pause_threshold": self.config.pause_threshold,
            "critical_threshold": self.config.critical_threshold,
            "emergency_threshold": self.config.emergency_threshold,
        });
        event.remediation = Some(
            "Check ClickHouse disk capacity, stalled tiering moves, retention settings, and ingestion volume immediately."
                .to_string(),
        );
        if let Err(error) = self.system_health_repo.publish(&event).await {
            warn!(%error, "Failed to publish disk-pressure system health event");
        }
    }

    /// Send in-app notification to all admin users about disk pressure.
    async fn send_pressure_notification(&self, usage: f64, severity: &str) {
        let admin_ids = match self.health_repo.get_admin_user_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!(
                    "Failed to get admin user IDs for disk pressure notification: {}",
                    e
                );
                return;
            }
        };

        if admin_ids.is_empty() {
            warn!("No admin users to notify about disk pressure");
            return;
        }

        let pct = format!("{:.1}%", usage * 100.0);
        let title = format!("Disk pressure {}: ClickHouse at {}", severity, pct);
        let message = format!(
            "ClickHouse disk usage is at {}. Oldest partitions are being dropped automatically to free space. \
             Check Storage & Retention settings for details.",
            pct
        );

        for user_id in &admin_ids {
            let notification = NewNotification {
                user_id: *user_id,
                notification_type: NotificationType::DiskPressureWarning,
                title: title.clone(),
                message: Some(message.clone()),
                link: Some("/settings/storage".to_string()),
                metadata: serde_json::json!({
                    "usage_fraction": usage,
                    "severity": severity,
                }),
            };

            if let Err(e) = self.notification_repo.create(&notification).await {
                warn!(user_id = %user_id, "Failed to create disk pressure notification: {}", e);
            }
        }

        info!(
            admin_count = admin_ids.len(),
            "Sent disk pressure notifications to admins"
        );
    }

    /// Notify admins that a partition was dropped.
    async fn notify_partition_dropped(&self, date: &str, evicted: &Evicted) {
        let admin_ids = match self.health_repo.get_admin_user_ids().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!(
                    "Failed to get admin user IDs for partition drop notification: {}",
                    e
                );
                return;
            }
        };

        for user_id in &admin_ids {
            let notification = NewNotification {
                user_id: *user_id,
                notification_type: NotificationType::DiskPressurePartitionDropped,
                title: format!("Partition {} dropped due to disk pressure", date),
                message: Some(partition_dropped_message(date, evicted)),
                link: Some("/settings/storage".to_string()),
                metadata: drop_audit_details(date, evicted, self.config.min_retention_days),
            };

            if let Err(e) = self.notification_repo.create(&notification).await {
                warn!(user_id = %user_id, "Failed to create partition drop notification: {}", e);
            }
        }
    }

    // -- Scheduler ---------------------------------------------------------

    /// Start the background scheduler. Returns a `JoinHandle` for shutdown management.
    /// `fence` is the jobs lease epoch: each partition drop runs under its
    /// strict guard (NAN-4933), so a superseded leader never drops another.
    pub fn start(self: Arc<Self>, fence: crate::leader::LeaderFence) -> JoinHandle<()> {
        let _ = self.fence.set(fence);
        tokio::spawn(async move {
            info!(
                interval_secs = self.config.check_interval_secs,
                high_watermark = format!("{:.0}%", self.config.high_watermark * 100.0),
                low_watermark = format!("{:.0}%", self.config.low_watermark * 100.0),
                critical = format!("{:.0}%", self.config.critical_threshold * 100.0),
                emergency = format!("{:.0}%", self.config.emergency_threshold * 100.0),
                min_retention_days = self.config.min_retention_days,
                "Starting disk pressure scheduler"
            );
            if self.config.min_retention_days == 0 {
                warn!("DISK_PRESSURE_MIN_RETENTION_DAYS=0: disk pressure may drop every partition except today's");
            }

            // NAN-5448: no TTL is rewritten here. Tiering moves parts with the
            // storage policy's move_factor; the DELETE TTL belongs to the
            // retention setting alone. (This used to rewrite the DELETE TTL of
            // logs/signals/ingestion_errors to WARM_RETENTION_DAYS, default 30,
            // at every jobs start whenever COLD_STORAGE_ENABLED was set.)

            // Run an immediate check on startup
            self.run_check_cycle().await;

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(
                self.config.check_interval_secs,
            ));
            // Skip the first tick (we already ran a check)
            interval.tick().await;

            loop {
                interval.tick().await;
                self.run_check_cycle().await;
            }
        })
    }
}

// ---------------------------------------------------------------------------
// SQL builders (pure; NAN-4982 tests in disk_pressure_tests.rs)
// ---------------------------------------------------------------------------

/// `table IN (...)` filter over [`DAILY_TABLES`], scoped to `db`, the admin
/// client's database (the one the unqualified DROPs resolve in), so a
/// same-named table in another database (a test database, a restored copy) is
/// never counted or chosen. `db` is a literal read once from the server, not
/// `currentDatabase()`, so a `clusterAllReplicas(...)` read filters on the same
/// database on every node.
fn daily_tables_filter(db: &str) -> String {
    let list = DAILY_TABLES
        .iter()
        .map(|t| format!("'{}'", t))
        .collect::<Vec<_>>()
        .join(",");
    let db = crate::sql_hygiene::escape_sql_string(db);
    format!("database = '{db}' AND table IN ({list}) AND active = 1 AND partition != ''")
}

/// The oldest partition strictly before `cutoff` and the newest of any
/// date, in one read (empty strings when there is none). The cutoff is
/// validated as `YYYYMMDD` before it reaches the SQL text.
fn partition_snapshot_sql(parts_src: &str, db: &str, cutoff: &str) -> Result<String, DiskPressureError> {
    if !is_partition_date(cutoff) {
        return Err(DiskPressureError::ClickHouse(format!("invalid cutoff partition '{cutoff}'")));
    }
    Ok(format!(
        "SELECT minIf(partition, partition < '{cutoff}') AS oldest, max(partition) AS newest FROM {parts_src} WHERE {}",
        daily_tables_filter(db)
    ))
}

/// NAN-5447: the oldest daily partition at or before `today` (empty when
/// there is none).
fn oldest_partition_sql(parts_src: &str, db: &str, today: &str) -> Result<String, DiskPressureError> {
    if !is_partition_date(today) {
        return Err(DiskPressureError::ClickHouse(format!("invalid partition '{today}'")));
    }
    Ok(format!(
        "SELECT minIf(partition, partition <= '{today}') FROM {parts_src} WHERE {}",
        daily_tables_filter(db)
    ))
}

/// NAN-5447: ClickHouse part bytes per (host, disk), every database.
///
/// Active parts count in full. An outdated part counts only when no active
/// part has the same (table, partition, block range, level, size): parts
/// replaced by a merge, a DROP or a rewriting mutation are still on disk until
/// `old_parts_lifetime` and are ClickHouse's bytes, but a mutation that does
/// not touch a part "bumps" it to a new version through hard links (same
/// block range, level and size; probed on 26.10), and counting both versions
/// would double the part.
fn clickhouse_bytes_sql(parts_src: &str) -> String {
    format!(
        "SELECT host, disk, toUInt64(sum(g)) AS bytes FROM (\
         SELECT hostName() AS host, disk_name AS disk, \
         if(max(active) = 1, sumIf(bytes_on_disk, active = 1), sum(bytes_on_disk)) AS g \
         FROM {parts_src} \
         GROUP BY host, disk, database, table, partition_id, min_block_number, max_block_number, level, bytes_on_disk\
         ) GROUP BY host, disk"
    )
}

/// NAN-5447: (audit rows, other rows) of one partition of an audit-bearing
/// table. `toYYYYMMDD(timestamp) = <date>` prunes to that partition by the
/// partition key.
fn audit_counts_sql(source: &str, table: &str, date: &str) -> Result<String, DiskPressureError> {
    if !AUDIT_BEARING_TABLES.contains(&table) {
        return Err(DiskPressureError::ClickHouse(format!("{table}: not an audit-bearing table")));
    }
    if !is_partition_date(date) {
        return Err(DiskPressureError::ClickHouse(format!("{table}: invalid partition '{date}'")));
    }
    Ok(format!(
        "SELECT toUInt64(countIf(source_type = 'audit')) AS audit_rows, toUInt64(countIf(source_type != 'audit')) AS other_rows \
         FROM {source} WHERE toYYYYMMDD(timestamp) = {date}"
    ))
}

/// NAN-5447: why the evictor is holding instead of dropping.
#[derive(Debug, Clone)]
pub enum HoldReason {
    /// Only partitions inside the retention floor are left.
    RetentionFloor { cutoff: String, floor_days: u64 },
    /// Something other than ClickHouse filled the disk.
    NonClickHouse { sample: DiskSample, non_clickhouse_growth_bytes: Option<u64> },
    /// The next candidate holds audit rows that could not be archived.
    AuditArchiveFailed,
}

impl HoldReason {
    /// (health issue key, system health dedup key) of every hold, resolved
    /// together when pressure is back to normal.
    pub const KEYS: [(&'static str, &'static str); 3] = [
        ("clickhouse_retention_floor", "storage:clickhouse:retention_floor"),
        ("non_clickhouse_disk_growth", "storage:disk:non_clickhouse_growth"),
        ("clickhouse_audit_archive_failed", "storage:clickhouse:audit_archive_failed"),
    ];

    fn index(&self) -> usize {
        match self {
            Self::RetentionFloor { .. } => 0,
            Self::NonClickHouse { .. } => 1,
            Self::AuditArchiveFailed => 2,
        }
    }

    /// (dedup key, issue key, title, detail).
    pub fn describe(&self, _config: &DiskPressureConfig) -> (&'static str, &'static str, String, String) {
        let (issue_key, dedup_key) = Self::KEYS[self.index()];
        let (title, detail) = match self {
            Self::RetentionFloor { cutoff, floor_days } => (
                "Disk pressure: retention floor reached".to_string(),
                format!(
                    "Only the last {floor_days} days of data (partitions from {cutoff} on) are left, and the retention floor protects them. No partition is dropped. Add disk capacity, lower ingest volume, or lower DISK_PRESSURE_MIN_RETENTION_DAYS."
                ),
            ),
            Self::NonClickHouse { sample, .. } => (
                "Disk pressure is not caused by ClickHouse data".to_string(),
                format!(
                    "ClickHouse data uses {:.1}% of the disk and other files use {:.1}%. Dropping event history would not relieve this, so no partition is dropped. Find what else is growing on the disk (PostgreSQL, Vector buffers, Docker images, backups, logs).",
                    sample.ch_bytes as f64 / sample.total.max(1) as f64 * 100.0,
                    sample.non_clickhouse() as f64 / sample.total.max(1) as f64 * 100.0
                ),
            ),
            Self::AuditArchiveFailed => (
                "Disk pressure: audit rows could not be archived".to_string(),
                "The oldest partition holds audit rows, and copying them to the audit archive failed or could not be verified. Nothing of that day is dropped, so the audit trail is not lost. Check the ClickHouse logs for the jobs service's error.".to_string(),
            ),
        };
        (dedup_key, issue_key, title, detail)
    }

    pub fn context(&self, usage: f64, config: &DiskPressureConfig, pausing: bool) -> serde_json::Value {
        let mut ctx = serde_json::json!({
            "usage_fraction": usage,
            "min_retention_days": config.min_retention_days,
            "min_retention_explicit": config.min_retention_explicit,
            "critical_threshold": config.critical_threshold,
            "pause_ingestion_enabled": config.pause_ingestion,
            "pausing_ingestion": pausing,
        });
        match self {
            Self::RetentionFloor { cutoff, floor_days } => {
                ctx["retention_cutoff"] = serde_json::json!(cutoff);
                ctx["floor_days"] = serde_json::json!(floor_days);
            }
            Self::NonClickHouse { sample, non_clickhouse_growth_bytes } => {
                ctx["host"] = serde_json::json!(sample.host);
                ctx["disk"] = serde_json::json!(sample.disk);
                ctx["total_bytes"] = serde_json::json!(sample.total);
                ctx["used_bytes"] = serde_json::json!(sample.used());
                ctx["clickhouse_bytes"] = serde_json::json!(sample.ch_bytes);
                ctx["non_clickhouse_bytes"] = serde_json::json!(sample.non_clickhouse());
                ctx["non_clickhouse_growth_bytes"] = serde_json::json!(non_clickhouse_growth_bytes);
            }
            Self::AuditArchiveFailed => {}
        }
        ctx
    }

    pub fn remediation(&self) -> &'static str {
        match self {
            Self::RetentionFloor { .. } => {
                "Grow the ClickHouse disk, reduce ingest, or lower DISK_PRESSURE_MIN_RETENTION_DAYS. Ingestion is paused at the critical level until there is headroom."
            }
            Self::NonClickHouse { .. } => {
                "Check `docker system df`, backups under .nano-backup, PostgreSQL size, and Vector buffer directories on the same filesystem."
            }
            Self::AuditArchiveFailed => {
                "Check that nanosiem.audit_archive exists (ClickHouse migration 201) and that the jobs service's ClickHouse user can insert into it; eviction retries on the next check. See docs/administration/disk-full-recovery.md to free space meanwhile."
            }
        }
    }
}

fn avg_partition_bytes_sql(parts_src: &str, db: &str) -> String {
    format!(
        "SELECT sum(bytes_on_disk) / countDistinct(partition) AS avg_partition_bytes, \
         toUInt64(countDistinct(partition)) AS partitions FROM {parts_src} WHERE {}",
        daily_tables_filter(db)
    )
}

/// NAN-5450: days of events the disk holds before eviction starts:
/// `partitions + (high x total - used) / avg_partition_bytes`, never below 0.
/// Above the high watermark the headroom is negative, so the result is fewer
/// days than are stored now (eviction will trim them). 0 without data.
pub fn retention_days_at_high_watermark(
    total: u64,
    used: u64,
    high_watermark: f64,
    avg_partition_bytes: f64,
    partitions: u64,
) -> f64 {
    if avg_partition_bytes.is_nan() || avg_partition_bytes <= 0.0 || total == 0 {
        return 0.0;
    }
    let headroom = high_watermark * total as f64 - used as f64;
    (partitions as f64 + headroom / avg_partition_bytes).max(0.0)
}

/// Tables holding partition `?`; `DISTINCT` collapses replicas and parts.
fn tables_with_partition_sql(parts_src: &str, db: &str) -> String {
    format!(
        "SELECT DISTINCT table FROM {parts_src} WHERE {} AND partition = ? ORDER BY table",
        daily_tables_filter(db)
    )
}

/// `ALTER TABLE <t> [ON CLUSTER] DROP PARTITION '<date>'`. Refuses anything
/// that is not a daily table or not a `YYYYMMDD` partition value, so a value
/// read back from `system.parts` can never smuggle SQL into the DDL.
fn drop_partition_sql(table: &str, on_cluster: &str, date: &str) -> Result<String, DiskPressureError> {
    if !DAILY_TABLES.contains(&table) {
        return Err(DiskPressureError::ClickHouse(format!("{table}: not a daily table")));
    }
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DiskPressureError::ClickHouse(format!("{table}: invalid partition '{date}'")));
    }
    Ok(format!("ALTER TABLE {table}{on_cluster} DROP PARTITION '{date}'"))
}

/// Storage policies of the daily tables (any node).
fn used_policies_sql(tables_src: &str, db: &str) -> String {
    let list = DAILY_TABLES
        .iter()
        .map(|t| format!("'{}'", t))
        .collect::<Vec<_>>()
        .join(",");
    let db = crate::sql_hygiene::escape_sql_string(db);
    format!(
        "SELECT DISTINCT storage_policy FROM {tables_src} WHERE database = '{db}' AND name IN ({list}) AND storage_policy != ''"
    )
}

/// Whether a policy a daily table uses keeps data on object storage: one of
/// its volumes holds a disk whose `system.disks.type` is `ObjectStorage`
/// (S3, GCS, Azure, or a cache disk over one). Then the evictor never drops:
/// the operator keeps that data on object storage to retain it.
///
/// NAN-5445: nothing else counts as tiering. The repo's placeholder `tiered`
/// policy (`clickhouse/config.d/storage.xml`: `hot` and `warm`, two Local
/// disks on the same filesystem) is what multi-host Compose creates `logs`
/// with; counting a second volume as tiering switched partition cleanup off
/// on every role-split install while nothing ever left the box. A non-Local
/// disk that is not object storage (an encrypted local disk) does not count
/// either: `object_disks` lists only `ObjectStorage` disks.
fn tiering_applies(used: &[String], policies: &[(String, u64, Vec<String>)], object_disks: &[String]) -> bool {
    policies.iter().any(|(name, _priority, disks)| {
        used.contains(name) && disks.iter().any(|d| object_disks.contains(d))
    })
}

/// Audit / notification details of one evicted partition date.
fn drop_audit_details(date: &str, evicted: &Evicted, min_retention_days: u64) -> serde_json::Value {
    serde_json::json!({
        "tables": evicted.dropped,
        "dropped_tables": evicted.dropped,
        "audit_archived_from": evicted.archived_from,
        "audit_archived_rows": evicted.archived_rows,
        "audit_archive_table": crate::audit::archive::AUDIT_ARCHIVE_TABLE,
        "partition_date": date,
        "candidate_tables": DAILY_TABLES,
        "min_retention_days": min_retention_days,
    })
}

/// Admin notification text for one evicted partition date.
fn partition_dropped_message(date: &str, evicted: &Evicted) -> String {
    let mut msg = format!("Data for {date} was removed to relieve disk pressure.");
    if !evicted.dropped.is_empty() {
        msg.push_str(&format!(" Dropped from: {}.", evicted.dropped.join(", ")));
    }
    if !evicted.archived_from.is_empty() {
        msg.push_str(&format!(
            " Its {} audit rows were moved to the audit archive first and stay on the Audit page.",
            evicted.archived_rows
        ));
    }
    msg
}

// NAN-5445: enterprise storage-tiering hooks of the evictor.
#[cfg(feature = "enterprise")]
#[path = "tiering/evictor.rs"]
mod tiering_evictor;

#[cfg(test)]
#[path = "disk_pressure_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "disk_pressure_safety_tests.rs"]
mod safety_tests;
