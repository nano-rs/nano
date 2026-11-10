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
//! - Emergency (default 95%): Optionally pause ingestion

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
    /// Optionally pause ingestion above this fraction
    pub emergency_threshold: f64,
    /// Whether to actually pause ingestion at emergency level
    pub pause_ingestion: bool,
    /// Whether cold/warm storage is enabled (S3/GCS tiered storage)
    pub cold_storage_enabled: bool,
    /// Maximum warm retention days — data on warm storage is deleted after this.
    /// Only applied when cold_storage_enabled is true.
    pub warm_retention_days: u64,
}

impl Default for DiskPressureConfig {
    fn default() -> Self {
        Self {
            check_interval_secs: env_u64("DISK_PRESSURE_CHECK_INTERVAL_SECS", 60),
            high_watermark: env_f64("DISK_PRESSURE_HIGH_WATERMARK", 0.80),
            low_watermark: env_f64("DISK_PRESSURE_LOW_WATERMARK", 0.70),
            critical_threshold: env_f64("DISK_PRESSURE_CRITICAL_THRESHOLD", 0.90),
            emergency_threshold: env_f64("DISK_PRESSURE_EMERGENCY_THRESHOLD", 0.95),
            pause_ingestion: env_bool("DISK_PRESSURE_PAUSE_INGESTION", false),
            cold_storage_enabled: env_bool("COLD_STORAGE_ENABLED", false),
            warm_retention_days: env_u64("WARM_RETENTION_DAYS", 180),
        }
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
    /// Usage above emergency — ingestion may be paused
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
    /// Estimated days of retention remaining at current ingestion rate
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

/// Tables where warm deletion TTL should be applied when cold storage is enabled.
/// These are the core data tables that get tiered to S3/GCS.
///
/// NAN-4982 deliberately leaves `ocsf_logs` out: `MODIFY TTL` replaces the
/// store's own `TTL ... DELETE WHERE timestamp > '2000-01-01'` and, with
/// `materialize_ttl_after_modify`, rewrites every part of the main event store
/// at boot. Warm retention on the OCSF store needs its own change.
const WARM_TTL_TABLES: &[(&str, &str)] = &[
    ("logs", "timestamp"),
    ("signals", "timestamp"),
    ("ingestion_errors", "timestamp"),
];

/// Maximum partition-dates to drop in a single check cycle.
const MAX_DROPS_PER_CYCLE: usize = 5;

/// One `system.parts` snapshot of the daily tables, taken immediately before
/// a drop: the oldest partition strictly before `today` and the newest
/// partition of any date (future-dated ones included).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PartitionSnapshot {
    pub oldest_before_today: Option<String>,
    pub newest: Option<String>,
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
pub fn evictable_partition(snapshot: &PartitionSnapshot, today: &str) -> Option<String> {
    let candidate = snapshot.oldest_before_today.as_deref()?;
    let newest = snapshot.newest.as_deref()?;
    let is_date = |d: &str| d.len() == 8 && d.bytes().all(|b| b.is_ascii_digit());
    (is_date(candidate) && is_date(today) && candidate < today && candidate < newest).then(|| candidate.to_string())
}

/// The current UTC partition value (`toYYYYMMDD` of now, UTC).
pub fn utc_today_partition() -> String {
    chrono::Utc::now().format("%Y%m%d").to_string()
}

/// The partition operations the FIFO drop loop needs (a seam so the
/// fencing of the loop is testable without ClickHouse).
#[async_trait::async_trait]
pub trait PartitionDropper: Send + Sync {
    /// Snapshot of the daily tables' partitions relative to `today`.
    async fn partition_snapshot(&self, today: &str) -> Result<PartitionSnapshot, DiskPressureError>;
    /// Current disk usage, 0.0..=1.0.
    async fn usage(&self) -> Result<f64, DiskPressureError>;
    /// Drop partition `date` from every daily table that holds it; returns the
    /// tables it was dropped from (empty when no table held it any more).
    async fn drop_partition(&self, date: &str) -> Result<Vec<String>, DiskPressureError>;
    /// Called after each successful drop (audit, notification, counters) with
    /// the tables the partition was dropped from.
    async fn dropped(&self, _date: &str, _tables: &[String]) {}
}

/// How a FIFO drop pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropLoopOutcome {
    /// Usage is at or below the low watermark.
    Relieved,
    /// Only today's (or future-dated) partitions are left: never dropped.
    Floor,
    NothingToDrop,
    /// This instance no longer holds the jobs lease epoch.
    Superseded,
    Failed,
    MaxDrops,
}

/// What one guarded step did.
enum Step {
    Dropped(String, Vec<String>),
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
pub async fn fifo_drop_loop(
    dropper: &dyn PartitionDropper,
    fence: &crate::leader::LeaderFence,
    pool: &PgPool,
    low_watermark: f64,
    max_drops: usize,
    settle: std::time::Duration,
    today: &str,
) -> DropLoopOutcome {
    for i in 0..max_drops {
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
                let snapshot = dropper.partition_snapshot(today).await?;
                let Some(date) = evictable_partition(&snapshot, today) else {
                    return Ok::<_, DiskPressureError>(if snapshot.newest.is_some() { Step::Floor } else { Step::Nothing });
                };
                info!(partition_date = %date, iteration = i + 1, "Dropping partition");
                let tables = dropper.drop_partition(&date).await?;
                Ok(if tables.is_empty() {
                    Step::Vanished(date)
                } else {
                    Step::Dropped(date, tables)
                })
            })
            .await;
        match step {
            Err(fence_error) => {
                warn!(error = %fence_error, "Partition drop refused by the leader fence");
                return DropLoopOutcome::Superseded;
            }
            Ok(Err(e)) => {
                error!("Failed to drop partition: {}", e);
                return DropLoopOutcome::Failed;
            }
            Ok(Ok(Step::Floor)) => {
                warn!(today = %today, "Only today's (or future-dated) partitions remain — cannot drop further");
                return DropLoopOutcome::Floor;
            }
            Ok(Ok(Step::Nothing)) => {
                info!("No partitions to drop");
                return DropLoopOutcome::NothingToDrop;
            }
            Ok(Ok(Step::Vanished(date))) => {
                info!(
                    partition_date = %date,
                    "Partition candidate vanished before table discovery — skipping"
                );
                continue;
            }
            Ok(Ok(Step::Dropped(date, tables))) => dropper.dropped(&date, &tables).await,
        }
        tokio::time::sleep(settle).await;
    }
    DropLoopOutcome::MaxDrops
}

#[async_trait::async_trait]
impl PartitionDropper for DiskPressureService {
    async fn partition_snapshot(&self, today: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        self.read_partition_snapshot(today).await
    }
    async fn usage(&self) -> Result<f64, DiskPressureError> {
        let (total, free) = self.get_disk_usage().await?;
        Ok(if total > 0 {
            total.saturating_sub(free) as f64 / total as f64
        } else {
            0.0
        })
    }
    async fn drop_partition(&self, date: &str) -> Result<Vec<String>, DiskPressureError> {
        self.drop_partitions_for_date(date).await
    }
    async fn dropped(&self, date: &str, tables: &[String]) {
        self.partitions_dropped.fetch_add(1, Ordering::Relaxed);
        self.emit_drop_audit(date, tables).await;
        self.notify_partition_dropped(date, tables).await;
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
}

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
        }
    }

    /// Whether the emergency level pauses ingestion
    /// (`DISK_PRESSURE_PAUSE_INGESTION`).
    pub fn auto_pause_enabled(&self) -> bool {
        self.config.pause_ingestion
    }

    // -- Warm TTL management ------------------------------------------------

    /// Apply warm deletion TTL to core tables when cold storage is enabled.
    ///
    /// Sets `TTL <col> + toIntervalDay(N) DELETE` so ClickHouse automatically
    /// deletes data from the warm (S3/GCS) volume after the configured retention
    /// period. This is idempotent — re-applying the same TTL is a no-op.
    async fn apply_warm_ttl_if_needed(&self) {
        if !self.config.cold_storage_enabled {
            info!("Cold storage not enabled — skipping warm TTL application");
            return;
        }

        let days = self.config.warm_retention_days;
        info!(
            warm_retention_days = days,
            "Applying warm deletion TTL to core tables"
        );

        // NAN-1728 H1: warm-TTL runs on the LOCAL MergeTree; `ON CLUSTER` fans
        // the ALTER out to every shard (empty clause → byte-identical on
        // single-node) so warm deletion applies cluster-wide.
        let on_cluster = on_cluster_clause();
        for (table, col) in WARM_TTL_TABLES {
            let stmt = format!(
                "ALTER TABLE nanosiem.{}{} MODIFY TTL {} + toIntervalDay({})",
                table, on_cluster, col, days
            );
            match self.ch_admin.query(&stmt).execute().await {
                Ok(_) => info!(table = table, days = days, "Applied warm deletion TTL"),
                Err(e) => warn!(table = table, "Failed to apply warm TTL: {}", e),
            }
        }
    }

    // -- Tiering check -----------------------------------------------------

    /// Check if S3/R2 storage tiering is active.
    ///
    /// When tiering is active, ClickHouse moves aged partitions to warm storage
    /// automatically via TTL rules. We should NOT drop partitions in that case —
    /// the customer is paying for offsite storage specifically to keep data.
    ///
    /// Tiering is detected from two independent sources:
    ///
    /// 1. Postgres `system_settings.tiering_enabled` — set by the in-app tiering
    ///    workflow when a user configures S3/R2 from the UI.
    /// 2. ClickHouse `system.storage_policies` / `system.disks` — set when the
    ///    platform layer (e.g. nano-main provisioning) bootstraps a multi-volume
    ///    policy without going through the app. The Postgres flag may never be
    ///    set in that case, but the storage layer is the authoritative truth.
    ///
    /// Returns true if either signal is positive.
    async fn is_tiering_active(&self) -> bool {
        if self.pg_tiering_flag_active().await {
            return true;
        }
        self.clickhouse_tiering_configured().await
    }

    async fn pg_tiering_flag_active(&self) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT tiering_enabled FROM system_settings WHERE id = 'default' AND tiering_status = 'active'"
        )
        .fetch_optional(&self.pg_pool)
        .await
        .unwrap_or(None)
        .unwrap_or(false)
    }

    /// Detect tiering from the ClickHouse storage layer directly.
    ///
    /// True if a storage policy that a daily table actually USES has more than
    /// one volume (a hot/cold split) or a non-Local disk (S3, Wasabi, GCS, R2 —
    /// `ObjectStorage` types). On query error, returns false and logs — we'd
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
                client.with_option(*name, *value)
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
                "SELECT DISTINCT name FROM {} WHERE type != 'Local'",
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

        let estimated_retention_days = self.estimate_retention_days(free).await.ok();

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
        })
    }

    /// One snapshot of the daily tables' partitions: the oldest strictly
    /// before `today` and the newest overall. NAN-1728 H1: `min`/`max` of the
    /// partition value are replica-invariant, so scan every node via
    /// `clusterAllReplicas`; plain `system.parts` on single-node.
    async fn read_partition_snapshot(&self, today: &str) -> Result<PartitionSnapshot, DiskPressureError> {
        let query = partition_snapshot_sql(&all_replicas_system("parts"), &self.database().await?, today)?;
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
        Ok(PartitionSnapshot { oldest_before_today: some(row.oldest), newest: some(row.newest) })
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

    /// Drop a specific partition date from every daily table that holds it.
    ///
    /// NAN-4982: only the tables that actually hold the partition are altered
    /// (the OCSF store on an OCSF box, `logs` on a UDM box, the 1.8 legacy
    /// table while its rows age out), so a table missing on this deployment is
    /// never named in a DROP. Returns the tables the partition was dropped from.
    async fn drop_partitions_for_date(&self, date: &str) -> Result<Vec<String>, DiskPressureError> {
        // NAN-1728 H1: DROP PARTITION runs on the LOCAL MergeTree; `ON CLUSTER`
        // fans it out to every shard (empty clause → byte-identical on
        // single-node) so the emergency valve relieves the whole cluster, not
        // just the node the LB'd connection landed on.
        // NAN-4982: never today's or a future partition, whatever the caller.
        let today = utc_today_partition();
        if date >= today.as_str() {
            return Err(DiskPressureError::ClickHouse(format!(
                "refusing to drop partition {date}: not before today ({today})"
            )));
        }
        let on_cluster = on_cluster_clause();
        let tables = self.tables_with_partition(date).await?;
        for table in &tables {
            let stmt = drop_partition_sql(table, &on_cluster, date)?;
            self.ch_admin
                .query(&stmt)
                .execute()
                .await
                .map_err(|e| DiskPressureError::ClickHouse(format!("{}: {}", table, e)))?;
        }
        Ok(tables)
    }

    /// Estimate how many days of data can still fit on disk, based on average partition size.
    async fn estimate_retention_days(&self, free_bytes: u64) -> Result<f64, DiskPressureError> {
        // NAN-1728 H1: average partition size across the whole cluster. Dedupe
        // replicas to one per shard (`cluster(...)`) so `sum(bytes_on_disk)` is
        // not doubled by the replica; `countDistinct(partition)` is date-count.
        // Plain `system.parts` on single-node.
        let query = avg_partition_bytes_sql(&parts_source_dedup(), &self.database().await?);

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            avg_partition_bytes: f64,
        }

        let row = self
            .ch_admin
            .query(&query)
            .fetch_one::<Row>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;

        if row.avg_partition_bytes <= 0.0 {
            return Ok(0.0);
        }

        Ok(free_bytes as f64 / row.avg_partition_bytes)
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

        match level {
            DiskPressureLevel::Emergency => {
                error!(
                    usage_pct = format!("{:.1}%", usage * 100.0),
                    "EMERGENCY disk pressure — usage above {}%",
                    self.config.emergency_threshold * 100.0
                );
                self.emit_critical_audit(usage).await;
                self.track_pressure_issue(usage, "emergency").await;

                if self.config.pause_ingestion {
                    self.auto_pause(usage).await;
                }

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
            &utc_today_partition(),
        )
        .await;
        match outcome {
            DropLoopOutcome::Relieved => {
                info!("Disk usage below low watermark — stopping drops");
                // Lift an automatic pause now that we have headroom.
                self.auto_resume(current_usage, "disk usage below the low watermark")
                    .await;
            }
            DropLoopOutcome::MaxDrops => warn!(
                "Reached max drops per cycle ({}) — will continue next cycle",
                MAX_DROPS_PER_CYCLE
            ),
            DropLoopOutcome::Superseded => {
                warn!("No longer the jobs leader — stopping partition drops")
            }
            DropLoopOutcome::Floor | DropLoopOutcome::NothingToDrop | DropLoopOutcome::Failed => {}
        }
    }

    // -- Ingestion pause (NAN-5217) ----------------------------------------

    /// Pause ingestion cluster-wide at the emergency level, and audit the
    /// transition once.
    async fn auto_pause(&self, usage: f64) {
        let reason = format!(
            "Emergency disk pressure: ClickHouse disk {:.1}% used (threshold {:.0}%)",
            usage * 100.0,
            self.config.emergency_threshold * 100.0
        );
        match self
            .ingestion_pause
            .pause(IngestionPauseSource::DiskPressure, Some(&reason), None)
            .await
        {
            Ok((_, true)) => {
                warn!("Ingestion PAUSED due to emergency disk pressure");
                self.emit_pause_audit(crate::audit::INGESTION_PAUSED, usage, &reason)
                    .await;
            }
            Ok((_, false)) => {}
            Err(error) => error!(%error, "Failed to pause ingestion at emergency disk pressure"),
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

    async fn emit_drop_audit(&self, date: &str, tables: &[String]) {
        let event = AuditEvent::builder(AuditSource::Storage, "partition_dropped")
            .resource("partition", None, Some(date.to_string()))
            .details(drop_audit_details(date, tables))
            .build();

        if let Err(e) = self.audit_emitter.emit(&event).await {
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
        let mut event = PublishHealthEvent::new(
            "storage:clickhouse:disk_pressure",
            HealthCategory::Storage,
            health_severity,
            format!("ClickHouse disk pressure is {severity}"),
            format!(
                "ClickHouse disk usage is {pct}. Oldest partitions may be dropped automatically, and emergency pressure can pause ingestion."
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
    async fn notify_partition_dropped(&self, date: &str, tables: &[String]) {
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
                message: Some(format!(
                    "The daily partition for {} was dropped from {} to relieve disk pressure.",
                    date,
                    tables.join(", ")
                )),
                link: Some("/settings/storage".to_string()),
                metadata: drop_audit_details(date, tables),
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
                "Starting disk pressure scheduler"
            );

            // Apply warm deletion TTL if cold storage is configured
            self.apply_warm_ttl_if_needed().await;

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

/// The oldest partition strictly before `today` and the newest of any date,
/// in one read (empty strings when there is none).
fn partition_snapshot_sql(parts_src: &str, db: &str, today: &str) -> Result<String, DiskPressureError> {
    if today.len() != 8 || !today.bytes().all(|b| b.is_ascii_digit()) {
        return Err(DiskPressureError::ClickHouse(format!("invalid today partition '{today}'")));
    }
    Ok(format!(
        "SELECT minIf(partition, partition < '{today}') AS oldest, max(partition) AS newest FROM {parts_src} WHERE {}",
        daily_tables_filter(db)
    ))
}

fn avg_partition_bytes_sql(parts_src: &str, db: &str) -> String {
    format!(
        "SELECT sum(bytes_on_disk) / countDistinct(partition) AS avg_partition_bytes FROM {parts_src} WHERE {}",
        daily_tables_filter(db)
    )
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

/// Whether a policy a daily table uses can move parts off the local disk: it
/// has a second volume, or one of its disks is not Local.
fn tiering_applies(used: &[String], policies: &[(String, u64, Vec<String>)], remote_disks: &[String]) -> bool {
    policies.iter().any(|(name, priority, disks)| {
        used.contains(name) && (*priority > 1 || disks.iter().any(|d| remote_disks.contains(d)))
    })
}

/// Audit / notification details of one evicted partition date.
fn drop_audit_details(date: &str, tables: &[String]) -> serde_json::Value {
    serde_json::json!({
        "tables": tables,
        "partition_date": date,
        "candidate_tables": DAILY_TABLES,
    })
}

#[cfg(test)]
#[path = "disk_pressure_tests.rs"]
mod tests;
