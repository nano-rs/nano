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

use std::sync::atomic::{AtomicBool, Ordering};
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
const DAILY_TABLES: &[&str] = &[
    "logs",
    "signals",
    "ingestion_errors",
    "identity_observations",
    "nat_candidates",
];

/// Tables where warm deletion TTL should be applied when cold storage is enabled.
/// These are the core data tables that get tiered to S3/GCS.
const WARM_TTL_TABLES: &[(&str, &str)] = &[
    ("logs", "timestamp"),
    ("signals", "timestamp"),
    ("ingestion_errors", "timestamp"),
];

/// Maximum partition-dates to drop in a single check cycle.
const MAX_DROPS_PER_CYCLE: usize = 5;

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
    /// Shared flag to pause ingestion
    ingestion_paused: Arc<AtomicBool>,
    /// Running counter of dropped partition-dates
    partitions_dropped: std::sync::atomic::AtomicU64,
}

impl DiskPressureService {
    pub fn new(
        ch_admin: ClickHouseClient,
        pg_pool: PgPool,
        audit_emitter: AuditEmitter,
        config: DiskPressureConfig,
        ingestion_paused: Arc<AtomicBool>,
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
            ingestion_paused,
            partitions_dropped: std::sync::atomic::AtomicU64::new(0),
        }
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
    /// True if any storage policy has more than one volume (a hot/cold split)
    /// OR any disk is non-Local (S3, Wasabi, GCS, R2 — `ObjectStorage` types).
    /// On query error, returns false and logs — we'd rather drop partitions
    /// at high watermark than wedge the daemon if ClickHouse is flaky.
    async fn clickhouse_tiering_configured(&self) -> bool {
        // NAN-1728 H1: tiering may be configured on any node — scan every node
        // (`clusterAllReplicas`) so detection isn't blind to shards the LB'd
        // connection didn't land on. Plain `system.*` on single-node.
        let storage_policies_src = all_replicas_system("storage_policies");
        let disks_src = all_replicas_system("disks");
        match self
            .ch_admin
            .query(&format!(
                "SELECT count() FROM {storage_policies_src} WHERE volume_priority > 1"
            ))
            .fetch_one::<u64>()
            .await
        {
            Ok(n) if n > 0 => {
                info!("Tiering detected via ClickHouse multi-volume storage policy");
                return true;
            }
            Ok(_) => {}
            Err(e) => warn!(
                error = %e,
                "Failed to query system.storage_policies for tiering detection",
            ),
        }

        match self
            .ch_admin
            .query(&format!(
                "SELECT count() FROM {disks_src} WHERE type != 'Local'"
            ))
            .fetch_one::<u64>()
            .await
        {
            Ok(n) if n > 0 => {
                info!("Tiering detected via ClickHouse non-Local disk (object storage)");
                true
            }
            Ok(_) => false,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to query system.disks for tiering detection",
                );
                false
            }
        }
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
            .ch_admin
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
            ingestion_paused: self.ingestion_paused.load(Ordering::Relaxed),
            high_watermark: self.config.high_watermark,
            low_watermark: self.config.low_watermark,
            critical_threshold: self.config.critical_threshold,
            emergency_threshold: self.config.emergency_threshold,
        })
    }

    /// Find the oldest partition date across all daily tables.
    async fn find_oldest_partition_date(&self) -> Result<Option<String>, DiskPressureError> {
        // system.parts stores partition values; for toYYYYMMDD partitions these are date strings like "20250101"
        let tables_list = DAILY_TABLES
            .iter()
            .map(|t| format!("'{}'", t))
            .collect::<Vec<_>>()
            .join(",");

        // NAN-1728 H1: oldest partition = MIN across all shards. `min(partition)`
        // is replica-invariant, so scan every node via `clusterAllReplicas`.
        // Plain `system.parts` on single-node (byte-identical).
        let parts_src = all_replicas_system("parts");
        let query = format!(
            "SELECT min(partition) AS oldest FROM {} WHERE table IN ({}) AND active = 1 AND partition != ''",
            parts_src, tables_list
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            oldest: String,
        }

        let row = self
            .ch_admin
            .query(&query)
            .fetch_optional::<Row>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;

        match row {
            Some(r) if !r.oldest.is_empty() => Ok(Some(r.oldest)),
            _ => Ok(None),
        }
    }

    /// Count distinct partition dates across daily tables.
    async fn count_daily_partitions(&self) -> Result<u64, DiskPressureError> {
        let tables_list = DAILY_TABLES
            .iter()
            .map(|t| format!("'{}'", t))
            .collect::<Vec<_>>()
            .join(",");

        // NAN-1728 H1: distinct partition dates across all shards.
        // `count(DISTINCT partition)` dedupes the replica rows, so scanning every
        // node via `clusterAllReplicas` yields the true cluster-wide date count.
        // Plain `system.parts` on single-node (byte-identical).
        let parts_src = all_replicas_system("parts");
        let query = format!(
            "SELECT count(DISTINCT partition) AS cnt FROM {} WHERE table IN ({}) AND active = 1 AND partition != ''",
            parts_src, tables_list
        );

        #[derive(clickhouse::Row, serde::Deserialize)]
        struct Row {
            cnt: u64,
        }

        let row = self
            .ch_admin
            .query(&query)
            .fetch_one::<Row>()
            .await
            .map_err(|e| DiskPressureError::ClickHouse(e.to_string()))?;

        Ok(row.cnt)
    }

    /// Drop a specific partition date from all daily tables.
    async fn drop_partitions_for_date(&self, date: &str) -> Result<(), DiskPressureError> {
        // NAN-1728 H1: DROP PARTITION runs on the LOCAL MergeTree; `ON CLUSTER`
        // fans it out to every shard (empty clause → byte-identical on
        // single-node) so the emergency valve relieves the whole cluster, not
        // just the node the LB'd connection landed on.
        let on_cluster = on_cluster_clause();
        for table in DAILY_TABLES {
            let stmt = format!("ALTER TABLE {}{} DROP PARTITION '{}'", table, on_cluster, date);
            self.ch_admin
                .query(&stmt)
                .execute()
                .await
                .map_err(|e| DiskPressureError::ClickHouse(format!("{}: {}", table, e)))?;
        }
        Ok(())
    }

    /// Estimate how many days of data can still fit on disk, based on average partition size.
    async fn estimate_retention_days(&self, free_bytes: u64) -> Result<f64, DiskPressureError> {
        let tables_list = DAILY_TABLES
            .iter()
            .map(|t| format!("'{}'", t))
            .collect::<Vec<_>>()
            .join(",");

        // NAN-1728 H1: average partition size across the whole cluster. Dedupe
        // replicas to one per shard (`cluster(...)`) so `sum(bytes_on_disk)` is
        // not doubled by the replica; `countDistinct(partition)` is date-count.
        // Plain `system.parts` on single-node (byte-identical).
        let parts_src = parts_source_dedup();
        let query = format!(
            "SELECT sum(bytes_on_disk) / countDistinct(partition) AS avg_partition_bytes \
             FROM {} WHERE table IN ({}) AND active = 1 AND partition != ''",
            parts_src, tables_list
        );

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

    /// Run one check cycle: read disk usage → classify → take action.
    async fn run_check_cycle(&self) {
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
                    let was_paused = self.ingestion_paused.swap(true, Ordering::SeqCst);
                    if !was_paused {
                        warn!("Ingestion PAUSED due to emergency disk pressure");
                        self.set_ingestion_paused_db(true).await;
                    }
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

                // Un-pause ingestion if it was paused and we're back to normal
                let was_paused = self.ingestion_paused.swap(false, Ordering::SeqCst);
                if was_paused {
                    info!("Ingestion RESUMED — disk pressure back to normal");
                    self.set_ingestion_paused_db(false).await;
                }
            }
        }
    }

    /// Drop oldest partitions until usage is below the target watermark.
    ///
    /// **Tiered deployments (Team / Business / Pro / Enterprise — multi-volume
    /// storage policy with cold object storage):** never drop. ClickHouse's
    /// `move_factor` is what bleeds parts off to warm storage, and the upstream
    /// classifier in `run_check_cycle` already emits `disk_pressure_critical`
    /// audit + notification at Critical/Emergency for ops visibility. Dropping
    /// locally while moves are stalled would delete data the customer is paying
    /// to retain — the part may not yet be in warm storage. Local-disk pressure
    /// here is a safety/alerting concern, not a data-loss concern.
    ///
    /// **Non-tiered deployments (Hobby / Startup / Growth — single Local
    /// volume on Hetzner):** existing FIFO drop loop is the retention mechanism.
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
        for i in 0..MAX_DROPS_PER_CYCLE {
            // Safety: never drop below 1 partition (today's data)
            match self.count_daily_partitions().await {
                Ok(count) if count <= 1 => {
                    warn!("Only 1 partition remaining — cannot drop further");
                    return;
                }
                Err(e) => {
                    warn!("Failed to count partitions: {}", e);
                    return;
                }
                _ => {}
            }

            let date = match self.find_oldest_partition_date().await {
                Ok(Some(d)) => d,
                Ok(None) => {
                    info!("No partitions to drop");
                    return;
                }
                Err(e) => {
                    warn!("Failed to find oldest partition: {}", e);
                    return;
                }
            };

            info!(partition_date = %date, iteration = i + 1, "Dropping partition");

            if let Err(e) = self.drop_partitions_for_date(&date).await {
                error!(partition_date = %date, "Failed to drop partition: {}", e);
                return;
            }

            self.partitions_dropped.fetch_add(1, Ordering::Relaxed);
            self.emit_drop_audit(&date).await;
            self.notify_partition_dropped(&date).await;

            // Brief pause to let ClickHouse settle
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Recheck — stop if below low watermark
            match self.get_disk_usage().await {
                Ok((total, free)) => {
                    let usage = if total > 0 {
                        total.saturating_sub(free) as f64 / total as f64
                    } else {
                        0.0
                    };
                    if usage <= self.config.low_watermark {
                        info!(
                            usage_pct = format!("{:.1}%", usage * 100.0),
                            "Disk usage below low watermark — stopping drops"
                        );
                        // Un-pause ingestion now that we have headroom
                        self.ingestion_paused.store(false, Ordering::SeqCst);
                        self.set_ingestion_paused_db(false).await;
                        return;
                    }
                }
                Err(e) => {
                    warn!("Failed to recheck disk usage: {}", e);
                    return;
                }
            }
        }

        warn!(
            "Reached max drops per cycle ({}) — will continue next cycle",
            MAX_DROPS_PER_CYCLE
        );
    }

    // -- PostgreSQL persistence (multi-node visibility) --------------------

    /// Persist ingestion_paused flag to PostgreSQL so all nodes see the same state.
    async fn set_ingestion_paused_db(&self, paused: bool) {
        if let Err(e) =
            sqlx::query("UPDATE system_settings SET ingestion_paused = $1 WHERE id = 'default'")
                .bind(paused)
                .execute(&self.pg_pool)
                .await
        {
            warn!("Failed to persist ingestion_paused={} to DB: {}", paused, e);
        }
    }

    // -- Audit -------------------------------------------------------------

    async fn emit_drop_audit(&self, date: &str) {
        let event = AuditEvent::builder(AuditSource::Storage, "partition_dropped")
            .resource("partition", None, Some(date.to_string()))
            .details(serde_json::json!({
                "tables": DAILY_TABLES,
                "partition_date": date,
            }))
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
    async fn notify_partition_dropped(&self, date: &str) {
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
                    "The daily partition for {} was dropped from {} tables to relieve disk pressure.",
                    date,
                    DAILY_TABLES.len()
                )),
                link: Some("/settings/storage".to_string()),
                metadata: serde_json::json!({
                    "partition_date": date,
                    "tables": DAILY_TABLES,
                }),
            };

            if let Err(e) = self.notification_repo.create(&notification).await {
                warn!(user_id = %user_id, "Failed to create partition drop notification: {}", e);
            }
        }
    }

    // -- Scheduler ---------------------------------------------------------

    /// Start the background scheduler. Returns a `JoinHandle` for shutdown management.
    pub fn start(self: Arc<Self>) -> JoinHandle<()> {
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
