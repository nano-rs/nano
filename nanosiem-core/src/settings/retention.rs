// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data Retention Settings
//!
//! Manages log retention policies for both PostgreSQL (metadata) and ClickHouse (logs).

use clickhouse::Client as ClickHouseClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;

use crate::db::dual_pool::{on_cluster_clause, TableNames};

// ---------------------------------------------------------------------------
// Cluster-aware runtime helpers (NAN-1728 H1)
//
// `ClickHouseStorageService` holds a bare `ClickHouseClient` (no `DualPool`), so
// cluster mode is derived from the same `CLICKHOUSE_CLUSTER` env signal that
// gates `on_cluster_clause` — the deploy sets it only on clustered ClickHouse.
// On single-node / open-core (`CLICKHOUSE_CLUSTER` unset) every helper below
// falls back to the exact pre-cluster form, so this file is byte-identical
// there.
// ---------------------------------------------------------------------------

/// Configured ClickHouse cluster name, or `None` on single-node deployments.
fn clickhouse_cluster_name() -> Option<String> {
    std::env::var("CLICKHOUSE_CLUSTER").ok().and_then(|c| {
        let t = c.trim();
        (!t.is_empty()).then(|| t.to_string())
    })
}

/// Read-side table name for `base`, routed to the `_distributed` wrapper so it
/// fans in across all shards on a cluster; bare local name (byte-identical to
/// the pre-cluster form) on single-node.
fn read_routed(base: &str) -> String {
    TableNames::new(clickhouse_cluster_name().is_some()).read_bare(base)
}

/// `system.parts` source that dedupes replicas to one per shard on a cluster
/// (`cluster(...)`), so byte/row sums count each shard exactly once. Plain
/// `system.parts` on single-node.
fn parts_source_dedup() -> String {
    match clickhouse_cluster_name() {
        Some(cl) => format!("cluster('{}', system.parts)", cl),
        None => "system.parts".to_string(),
    }
}

/// NAN-5346: the event tables a retention change applies to. The active
/// table first; under OCSF also the UDM `logs` table, which an OCSF install
/// still creates and which keeps its historical rows. Without it `logs` kept
/// the init.sql TTL whatever the operator set. UDM: `["logs"]` only.
pub(crate) fn retention_tables_for(active: &'static str) -> Vec<&'static str> {
    if active == "logs" {
        vec!["logs"]
    } else {
        vec![active, "logs"]
    }
}

/// The DELETE TTL a retention change applies to `table`. A metadata ALTER;
/// the server re-evaluates existing parts in a background mutation
/// (`materialize_ttl_after_modify`), so the request never waits on a rewrite.
///
/// NAN-5449: every table except the UDM `logs` keeps the NAN-1384 guard from
/// migration 127 (`DELETE WHERE timestamp > 2000-01-01`). Without it a
/// retention change re-armed the TTL that deleted direct-write rows with a
/// garbage pre-2000 `timestamp` at part-write while the INSERT returned 200.
pub(crate) fn retention_ttl_sql(table: &str, on_cluster: &str, days: u32) -> String {
    if table == "logs" {
        format!("ALTER TABLE {table}{on_cluster} MODIFY TTL timestamp + INTERVAL {days} DAY DELETE")
    } else {
        format!(
            "ALTER TABLE {table}{on_cluster} MODIFY TTL timestamp + INTERVAL {days} DAY DELETE \
             WHERE timestamp > toDateTime64('2000-01-01 00:00:00', 3, 'UTC')"
        )
    }
}

/// Smallest and largest event retention nano accepts (API, UI, migrator).
pub const MIN_CLICKHOUSE_RETENTION_DAYS: u32 = 1;
pub const MAX_CLICKHOUSE_RETENTION_DAYS: u32 = 3650;

/// Validate an event retention value against the accepted range.
pub fn validate_clickhouse_retention_days(days: u32) -> Result<u32, RetentionError> {
    if (MIN_CLICKHOUSE_RETENTION_DAYS..=MAX_CLICKHOUSE_RETENTION_DAYS).contains(&days) {
        Ok(days)
    } else {
        Err(RetentionError::InvalidPeriod(format!(
            "retention must be between {MIN_CLICKHOUSE_RETENTION_DAYS} and \
             {MAX_CLICKHOUSE_RETENTION_DAYS} days, got {days}"
        )))
    }
}

/// NAN-5449: the deployment retention setting. Unset or blank means "the
/// deployment does not manage retention": the migrator leaves the TTL alone.
pub const RETENTION_DAYS_ENV: &str = "NANO_RETENTION_DAYS";

/// Parse `NANO_RETENTION_DAYS`. `Ok(None)` for unset or blank; an error for
/// anything else that is not a whole number of days in range, so a typo
/// fails the migrator in its first second instead of being ignored.
pub fn retention_days_from_env(raw: Option<&str>) -> Result<Option<u32>, RetentionError> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let days: u32 = raw.parse().map_err(|_| {
        RetentionError::Config(format!(
            "{RETENTION_DAYS_ENV}={raw:?} is not a whole number of days"
        ))
    })?;
    validate_clickhouse_retention_days(days)
        .map(Some)
        .map_err(|e| RetentionError::Config(format!("{RETENTION_DAYS_ENV}: {e}")))
}

// Settings -> Storage and the NAN-5448 TTL repair read the TTL with
// `settings::clickhouse_ttl::delete_ttl_days` (NAN-5445). This parser stays
// for the enterprise Evidence Pack only, which also reports month/year TTLs.

/// The DELETE TTL in days from a `CREATE TABLE` statement, if any. Accepts the
/// normalized forms ClickHouse prints: `toIntervalDay(N)`, `INTERVAL N DAY`,
/// and `toIntervalMonth(N)` / `toIntervalYear(N)` (30 / 365 days). A move-only
/// TTL (`TO DISK` / `TO VOLUME`) is not a retention.
/// Used by the enterprise Evidence Pack.
pub fn parse_ttl_days(create_table_query: &str) -> Option<i64> {
    let upper = create_table_query.to_ascii_uppercase();
    let ttl_at = find_ttl_clause(&upper)?;
    let clause_end = upper[ttl_at..]
        .find(" SETTINGS ")
        .map(|i| ttl_at + i)
        .unwrap_or(upper.len());
    let clause = &upper[ttl_at..clause_end];
    // A TTL clause can list several expressions; take each DELETE (the default
    // action) and report the shortest.
    let mut best: Option<i64> = None;
    for expr in clause.split(',') {
        if expr.contains(" TO DISK") || expr.contains(" TO VOLUME") || expr.contains(" RECOMPRESS") {
            continue;
        }
        if let Some(days) = interval_days(expr) {
            best = Some(best.map_or(days, |b| b.min(days)));
        }
    }
    best
}

fn find_ttl_clause(upper: &str) -> Option<usize> {
    // The table-level TTL follows ORDER BY / PARTITION BY; column TTLs appear
    // inside the column list. The last top-level " TTL " is the table TTL.
    let mut found = None;
    let mut depth = 0i32;
    let bytes = upper.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'\'' => {
                // Skip a string literal.
                i += 1;
                while i < bytes.len() && bytes[i] != b'\'' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ => {
                if depth == 0 && upper[i..].starts_with(" TTL ") {
                    found = Some(i + 5);
                }
            }
        }
        i += 1;
    }
    found
}

fn interval_days(expr: &str) -> Option<i64> {
    let number_after = |s: &str, prefix: &str| -> Option<i64> {
        let at = s.find(prefix)? + prefix.len();
        let digits: String = s[at..].trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse().ok()
    };
    if let Some(n) = number_after(expr, "TOINTERVALDAY(") {
        return Some(n);
    }
    if let Some(n) = number_after(expr, "TOINTERVALMONTH(") {
        return Some(n * 30);
    }
    if let Some(n) = number_after(expr, "TOINTERVALYEAR(") {
        return Some(n * 365);
    }
    if let Some(at) = expr.find("INTERVAL ") {
        let rest = &expr[at + 9..];
        let digits: String = rest.trim_start().chars().take_while(|c| c.is_ascii_digit()).collect();
        let n: i64 = digits.parse().ok()?;
        let unit = rest.trim_start()[digits.len()..].trim_start();
        return if unit.starts_with("DAY") {
            Some(n)
        } else if unit.starts_with("MONTH") {
            Some(n * 30)
        } else if unit.starts_with("YEAR") {
            Some(n * 365)
        } else {
            None
        };
    }
    None
}

/// Who set the event retention last (`system_settings`, NAN-5449).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClickHouseRetentionRecord {
    pub days: Option<u32>,
    pub source: Option<String>,
    pub env_applied: Option<u32>,
}

/// What the migrator did with `NANO_RETENTION_DAYS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentRetentionOutcome {
    /// Unset: the deployment does not manage retention.
    NotConfigured,
    /// Same value as the last apply: a UI change since then is kept.
    Unchanged(u32),
    /// Applied to the ClickHouse TTL and recorded.
    Applied(u32),
}

/// Whether the migrator should apply `env_days`. Only a value that differs
/// from the one it last applied: editing `.env` (or Helm values) is an
/// explicit operator action and wins, while a plain restart keeps a value
/// set in Settings -> Storage since then.
pub fn deployment_retention_needs_apply(env_days: u32, record: &ClickHouseRetentionRecord) -> bool {
    record.env_applied != Some(env_days)
}

/// Read the retention record. Missing row or columns read as empty.
pub async fn read_clickhouse_retention_record(
    pool: &PgPool,
) -> Result<ClickHouseRetentionRecord, RetentionError> {
    let row = sqlx::query_as::<_, (Option<i32>, Option<String>, Option<i32>)>(
        r#"
        SELECT clickhouse_retention_days, clickhouse_retention_source,
               clickhouse_retention_env_applied
        FROM system_settings
        WHERE id = 'default'
        "#,
    )
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((days, source, env_applied)) => ClickHouseRetentionRecord {
            days: days.and_then(|d| u32::try_from(d).ok()),
            source,
            env_applied: env_applied.and_then(|d| u32::try_from(d).ok()),
        },
        None => ClickHouseRetentionRecord::default(),
    })
}

/// Record a retention value set in Settings -> Storage (or the API).
pub async fn record_ui_clickhouse_retention(pool: &PgPool, days: u32) -> Result<(), RetentionError> {
    sqlx::query(
        r#"
        UPDATE system_settings
        SET clickhouse_retention_days = $1,
            clickhouse_retention_source = 'ui',
            updated_at = NOW()
        WHERE id = 'default'
        "#,
    )
    .bind(days as i32)
    .execute(pool)
    .await?;
    Ok(())
}

/// NAN-5449: apply `NANO_RETENTION_DAYS` to the ClickHouse TTL (migrator).
/// `client` must be allowed to ALTER the event tables (the admin client).
pub async fn apply_deployment_retention(
    pool: &PgPool,
    client: &ClickHouseClient,
    env_days: Option<u32>,
) -> Result<DeploymentRetentionOutcome, RetentionError> {
    let Some(days) = env_days else {
        return Ok(DeploymentRetentionOutcome::NotConfigured);
    };
    let record = read_clickhouse_retention_record(pool).await?;
    if !deployment_retention_needs_apply(days, &record) {
        return Ok(DeploymentRetentionOutcome::Unchanged(days));
    }
    ClickHouseStorageService::new(client.clone())
        .update_retention(days)
        .await?;
    sqlx::query(
        r#"
        UPDATE system_settings
        SET clickhouse_retention_days = $1,
            clickhouse_retention_source = 'deployment',
            clickhouse_retention_env_applied = $1,
            updated_at = NOW()
        WHERE id = 'default'
        "#,
    )
    .bind(days as i32)
    .execute(pool)
    .await?;
    Ok(DeploymentRetentionOutcome::Applied(days))
}

/// Database predicate for `system.parts` reads. `currentDatabase()` is unsafe
/// inside `cluster(...)` (evaluated on remote shards, where the default DB may
/// not be `nanosiem`), so on a cluster pin the literal DB the app owns; keep
/// `currentDatabase()` on single-node so the query is byte-identical.
fn cluster_db_filter() -> &'static str {
    if clickhouse_cluster_name().is_some() {
        "database = 'nanosiem'"
    } else {
        "database = currentDatabase()"
    }
}

#[derive(Error, Debug)]
pub enum RetentionError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Invalid retention period: {0}")]
    InvalidPeriod(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("ClickHouse error: {0}")]
    ClickHouse(String),
    /// NAN-5450: ClickHouse refused the work for lack of disk space
    /// (NOT_ENOUGH_SPACE, 243). The message says what to do.
    #[error("ClickHouse disk full: {0}")]
    DiskFull(String),
}

/// NAN-5450: "Run retention now" refuses below this much ClickHouse free
/// space (above `keep_free_space_bytes`).
pub(crate) const RETENTION_MIN_FREE_BYTES: u64 = 1024 * 1024 * 1024;

/// NAN-5450: a ClickHouse error caused by a full disk: NOT_ENOUGH_SPACE (243),
/// `Cannot reserve N MiB`, or ENOSPC surfacing as a write error.
pub(crate) fn is_disk_full_error(message: &str) -> bool {
    message.contains("NOT_ENOUGH_SPACE")
        || message.contains("Code: 243")
        || message.contains("Cannot reserve")
        || message.contains("No space left on device")
}

/// The [`RetentionError`] for a failed retention statement on `table`.
pub(crate) fn retention_ch_error(table: &str, message: String) -> RetentionError {
    if is_disk_full_error(&message) {
        RetentionError::DiskFull(format!(
            "ClickHouse has no free space to run retention on {table}. Free space first: see \
             docs/administration/disk-full-recovery.md (lower keep_free_space_bytes, SYSTEM RELOAD \
             CONFIG, drop the oldest partitions, restore the reserve)."
        ))
    } else {
        RetentionError::ClickHouse(format!("{table}: {message}"))
    }
}

/// Retention policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    /// Whether retention policy is enabled
    pub enabled: bool,
    /// Retention period in days (logs older than this are deleted)
    pub retention_days: u32,
    /// Scheduled job ID (legacy, kept for API compatibility)
    pub job_id: Option<i32>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: 90,
            job_id: None,
        }
    }
}

/// Storage statistics for PostgreSQL (metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total size of logs table (including indexes)
    pub total_size_bytes: i64,
    /// Human-readable total size
    pub total_size_pretty: String,
    /// Number of chunks
    pub chunk_count: i64,
    /// Number of compressed chunks
    pub compressed_chunks: i64,
    /// Oldest log timestamp
    pub oldest_log: Option<chrono::DateTime<chrono::Utc>>,
    /// Newest log timestamp  
    pub newest_log: Option<chrono::DateTime<chrono::Utc>>,
    /// Total log count
    pub log_count: i64,
}

/// Storage statistics for ClickHouse (log telemetry)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseStorageStats {
    /// Total size of logs table in bytes
    pub total_size_bytes: u64,
    /// Human-readable total size
    pub total_size_pretty: String,
    /// Total number of rows
    pub row_count: u64,
    /// Number of partitions
    pub partition_count: u64,
    /// Number of parts (data files)
    pub parts_count: u64,
    /// Oldest log timestamp
    pub oldest_log: Option<chrono::DateTime<chrono::Utc>>,
    /// Newest log timestamp
    pub newest_log: Option<chrono::DateTime<chrono::Utc>>,
    /// Compression ratio (uncompressed/compressed)
    pub compression_ratio: f64,
    /// Uncompressed size in bytes
    pub uncompressed_size_bytes: u64,
    /// The event table's DELETE TTL in days, read from its DDL
    /// (`system.tables.create_table_query`). `None` when it cannot be read.
    pub ttl_days: Option<u32>,
    /// Who set the retention last: `deployment` (`NANO_RETENTION_DAYS`),
    /// `ui`, or `None` (the shipped default).
    pub retention_source: Option<String>,
    /// The `NANO_RETENTION_DAYS` value the migrator last applied.
    pub deployment_retention_days: Option<u32>,
}

/// Service for managing data retention
pub struct RetentionService {
    pool: PgPool,
}

impl RetentionService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get current retention configuration
    pub async fn get_config(&self) -> Result<RetentionConfig, RetentionError> {
        // PostgreSQL retention is managed via system_settings table (flat columns)
        // TimescaleDB is no longer used - logs are stored in ClickHouse
        let row = sqlx::query_as::<_, (bool, i32)>(
            r#"
            SELECT retention_enabled, retention_days
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((enabled, retention_days)) => Ok(RetentionConfig {
                enabled,
                retention_days: retention_days as u32,
                job_id: None,
            }),
            None => Ok(RetentionConfig::default()),
        }
    }

    /// Update retention configuration
    pub async fn update_config(
        &self,
        config: RetentionConfig,
    ) -> Result<RetentionConfig, RetentionError> {
        if config.enabled && config.retention_days < 1 {
            return Err(RetentionError::InvalidPeriod(
                "Retention period must be at least 1 day".to_string(),
            ));
        }

        // Store config in system_settings table (flat columns)
        sqlx::query(
            r#"
            UPDATE system_settings
            SET retention_enabled = $1, retention_days = $2, updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(config.enabled)
        .bind(config.retention_days as i32)
        .execute(&self.pool)
        .await?;

        Ok(RetentionConfig {
            enabled: config.enabled,
            retention_days: config.retention_days,
            job_id: None,
        })
    }

    /// Get storage statistics for PostgreSQL metadata tables
    pub async fn get_storage_stats(&self) -> Result<StorageStats, RetentionError> {
        // Get total database size (all metadata tables)
        let size_row = sqlx::query_as::<_, (i64, String)>(
            r#"
            SELECT
                pg_database_size(current_database())::bigint as total_bytes,
                pg_size_pretty(pg_database_size(current_database())) as total_pretty
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        // Get table count as "chunk count" for display purposes
        let table_count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)::bigint
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);

        // Get date range and counts from metadata tables
        #[derive(sqlx::FromRow)]
        struct MetadataStats {
            oldest: Option<chrono::DateTime<chrono::Utc>>,
            newest: Option<chrono::DateTime<chrono::Utc>>,
            total_records: i64,
        }

        // `detections` (a pre-ClickHouse table) no longer exists in any
        // schema, and `cases` is enterprise-only; naming a missing relation
        // failed the whole statement and the stats silently read as zero.
        #[cfg(feature = "enterprise")]
        let metadata_sql = r#"
            SELECT
                LEAST(
                    (SELECT MIN(created_at) FROM alerts),
                    (SELECT MIN(created_at) FROM cases)
                ) as oldest,
                GREATEST(
                    (SELECT MAX(created_at) FROM alerts),
                    (SELECT MAX(created_at) FROM cases)
                ) as newest,
                (
                    (SELECT COUNT(*) FROM alerts) +
                    (SELECT COUNT(*) FROM cases) +
                    (SELECT COUNT(*) FROM dashboards)
                )::bigint as total_records
            "#;
        #[cfg(not(feature = "enterprise"))]
        let metadata_sql = r#"
            SELECT
                (SELECT MIN(created_at) FROM alerts) as oldest,
                (SELECT MAX(created_at) FROM alerts) as newest,
                (
                    (SELECT COUNT(*) FROM alerts) +
                    (SELECT COUNT(*) FROM dashboards)
                )::bigint as total_records
            "#;

        let metadata = sqlx::query_as::<_, MetadataStats>(metadata_sql)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(MetadataStats {
            oldest: None,
            newest: None,
            total_records: 0,
        });

        Ok(StorageStats {
            total_size_bytes: size_row.0,
            total_size_pretty: size_row.1,
            chunk_count: table_count,
            compressed_chunks: 0, // No compression in standard PostgreSQL
            oldest_log: metadata.oldest,
            newest_log: metadata.newest,
            log_count: metadata.total_records,
        })
    }

    /// Manually run retention on PostgreSQL metadata tables
    /// Note: Log retention is handled by ClickHouse TTL
    pub async fn run_retention_now(&self) -> Result<i64, RetentionError> {
        let config = self.get_config().await?;

        if !config.enabled {
            return Err(RetentionError::InvalidPeriod(
                "Retention policy is not enabled".to_string(),
            ));
        }

        // Clean up old metadata (detection_matched_events, finding emissions,
        // search_history, etc.). NB: detection_matched_events is timestamped by
        // `matched_at` (there is no `detected_at` column — that prior typo made
        // this whole sweep error at runtime; fixed alongside NAN-1305).
        let deleted = sqlx::query_scalar::<_, i64>(
            r#"
            WITH deleted_events AS (
                DELETE FROM detection_matched_events
                WHERE matched_at < NOW() - ($1 || ' days')::interval
                RETURNING 1
            ),
            deleted_emissions AS (
                DELETE FROM detection_finding_emissions
                WHERE emitted_at < NOW() - ($1 || ' days')::interval
                RETURNING 1
            ),
            deleted_history AS (
                DELETE FROM search_history
                WHERE created_at < NOW() - ($1 || ' days')::interval
                RETURNING 1
            )
            SELECT (SELECT COUNT(*) FROM deleted_events)
                 + (SELECT COUNT(*) FROM deleted_emissions)
                 + (SELECT COUNT(*) FROM deleted_history)
            "#,
        )
        .bind(config.retention_days as i32)
        .fetch_one(&self.pool)
        .await?;

        Ok(deleted)
    }
}

/// Service for managing ClickHouse storage
pub struct ClickHouseStorageService {
    client: ClickHouseClient,
    /// NAN-5367: the identity that may fan out with `cluster(...)` (REMOTE):
    /// the admin client. The runtime user has no REMOTE by design.
    fanout_client: Option<ClickHouseClient>,
}

impl ClickHouseStorageService {
    pub fn new(client: ClickHouseClient) -> Self {
        Self { client, fanout_client: None }
    }

    /// NAN-5367: client for cross-shard `system.parts` reads (needs REMOTE).
    pub fn with_fanout_client(mut self, client: Option<ClickHouseClient>) -> Self {
        self.fanout_client = client;
        self
    }

    /// Get ClickHouse storage statistics for the logs table
    pub async fn get_storage_stats(&self) -> Result<ClickHouseStorageStats, RetentionError> {
        // Whether the active event table (ocsf_logs under OCSF) exists. Its
        // TTL is read below (`active_table_ttl_days`, NAN-5385 / NAN-5445).
        let engine: Option<String> = self
            .client
            .query(
                r#"
                SELECT name
                FROM system.tables
                WHERE database = currentDatabase() AND name = ?
            "#,
            )
            .bind(crate::schema::active_logs_table())
            .fetch_optional()
            .await
            .map_err(|e| {
                RetentionError::ClickHouse(format!("Failed to check table existence: {}", e))
            })?;
        if engine.is_none() {
            // Return empty stats if logs table doesn't exist
            return Ok(ClickHouseStorageStats {
                total_size_bytes: 0,
                total_size_pretty: "0 B".to_string(),
                row_count: 0,
                partition_count: 0,
                parts_count: 0,
                oldest_log: None,
                newest_log: None,
                compression_ratio: 1.0,
                uncompressed_size_bytes: 0,
                ttl_days: None,
                retention_source: None,
                deployment_retention_days: None,
            });
        }

        // Get table size and parts info - use COALESCE to handle empty tables
        // Note: system.parts requires elevated privileges, fall back gracefully if denied
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct TableStats {
            total_bytes: u64,
            total_rows: u64,
            parts_count: u64,
            uncompressed_bytes: u64,
            partition_count: u64,
        }

        // NAN-1241: storage stats for the active ingested-events table.
        // NAN-1728 H1: on a cluster, aggregate `system.parts` across shards via
        // `cluster(...)` (one replica per shard, so byte/row sums are not
        // double-counted). Plain `system.parts` on single-node. The parts still
        // belong to the LOCAL MergeTree, so the table filter uses the bare local
        // name (not the `_distributed` wrapper).
        let stats_logs_table = crate::schema::active_logs_table();
        // NAN-5367: fan out only through the admin identity (REMOTE); without
        // one, read the local shard instead of a query the runtime user is
        // denied.
        let fan_out = self.fanout_client.is_some() && clickhouse_cluster_name().is_some();
        let parts_source = if fan_out { parts_source_dedup() } else { "system.parts".to_string() };
        // Inside `cluster(...)` the WHERE runs on remote shards, where
        // `currentDatabase()` may resolve to the cluster connection's default
        // (not `nanosiem`) and drop every remote row — so on a cluster filter by
        // the literal DB. Single-node keeps `currentDatabase()` (byte-identical).
        let db_filter = if fan_out { cluster_db_filter() } else { "database = currentDatabase()" };
        let stats: Option<TableStats> = match self
            .fanout_client
            .as_ref()
            .filter(|_| fan_out)
            .unwrap_or(&self.client)
            .query(&format!(
                r#"
                SELECT
                    COALESCE(sum(bytes_on_disk), 0) as total_bytes,
                    COALESCE(sum(rows), 0) as total_rows,
                    count() as parts_count,
                    COALESCE(sum(data_uncompressed_bytes), 0) as uncompressed_bytes,
                    COALESCE(countDistinct(partition), 0) as partition_count
                FROM {parts_source}
                WHERE {db_filter}
                  AND table = '{stats_logs_table}'
                  AND active = 1
            "#
            ))
            .fetch_one()
            .await
        {
            Ok(s) => Some(s),
            Err(e) => {
                // Log the error but continue - system.parts requires elevated privileges
                tracing::warn!(
                    "Unable to query system.parts (requires SELECT on system.parts): {}",
                    e
                );
                None
            }
        };

        // Get time range and row count from actual data
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct RowCount {
            cnt: u64,
        }

        // NAN-1241: storage stats reflect the active ingested-events table
        // (ocsf_logs under OCSF — where the bulk of data lands). UDM-identical.
        // NAN-1728 H1: route the row-count / time-range reads through the
        // `_distributed` wrapper on a cluster so they cover all shards (~1/N
        // undercount otherwise); bare local name on single-node.
        let logs_table = read_routed(crate::schema::active_logs_table());
        let row_count: RowCount = self
            .client
            .query(&format!("SELECT count() as cnt FROM {logs_table}"))
            .fetch_one()
            .await
            .map_err(|e| RetentionError::ClickHouse(format!("Failed to get row count: {}", e)))?;

        // Only query time range if there's data
        let (oldest_log, newest_log) = if row_count.cnt > 0 {
            #[derive(clickhouse::Row, serde::Deserialize)]
            struct TimeRange {
                oldest: String,
                newest: String,
            }

            match self
                .client
                .query(&format!(
                    r#"
                    SELECT
                        formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') as oldest,
                        formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%sZ') as newest
                    FROM {logs_table}
                "#
                ))
                .fetch_one::<TimeRange>()
                .await
            {
                Ok(tr) => {
                    let oldest = chrono::DateTime::parse_from_rfc3339(&tr.oldest)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc));
                    let newest = chrono::DateTime::parse_from_rfc3339(&tr.newest)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc));
                    (oldest, newest)
                }
                Err(e) => {
                    tracing::warn!("Failed to get time range: {}", e);
                    (None, None)
                }
            }
        } else {
            (None, None)
        };

        // Use system.parts stats if available, otherwise use row count from logs table
        let (total_bytes, total_rows, parts_count, uncompressed_bytes, partition_count) =
            match stats {
                Some(s) => (
                    s.total_bytes,
                    s.total_rows,
                    s.parts_count,
                    s.uncompressed_bytes,
                    s.partition_count,
                ),
                None => (0, row_count.cnt, 0, 0, 0), // Fall back to basic stats
            };

        // Calculate compression ratio
        let compression_ratio = if total_bytes > 0 {
            uncompressed_bytes as f64 / total_bytes as f64
        } else {
            1.0
        };

        // Format size for display
        let total_size_pretty = if total_bytes > 0 {
            format_bytes(total_bytes)
        } else {
            "Unknown (insufficient privileges)".to_string()
        };

        Ok(ClickHouseStorageStats {
            total_size_bytes: total_bytes,
            total_size_pretty,
            row_count: total_rows,
            partition_count,
            parts_count,
            oldest_log,
            newest_log,
            compression_ratio,
            uncompressed_size_bytes: uncompressed_bytes,
            // NAN-5385 / NAN-5445: the real DELETE TTL of the active event
            // table, not a hard-coded 90.
            ttl_days: self.active_table_ttl_days().await,
            retention_source: None,
            deployment_retention_days: None,
        })
    }

    /// DELETE TTL in days of the active event table, read from its DDL.
    async fn active_table_ttl_days(&self) -> Option<u32> {
        let table = crate::schema::active_logs_table();
        let local = format!("{table}_local");
        self.client
            .query(
                "SELECT create_table_query FROM system.tables WHERE database = currentDatabase() \
                 AND name IN (?, ?) ORDER BY name = ? DESC LIMIT 1",
            )
            .bind(table)
            .bind(local.as_str())
            .bind(local.as_str())
            .fetch_optional::<String>()
            .await
            .ok()
            .flatten()
            .and_then(|q| crate::settings::clickhouse_ttl::delete_ttl_days(&q))
    }

    /// Update ClickHouse TTL retention period
    pub async fn update_retention(&self, days: u32) -> Result<(), RetentionError> {
        // NAN-1241: target the active ingested-events table (ocsf_logs under OCSF).
        // NAN-1728 H1: TTL runs on the LOCAL MergeTree; `ON CLUSTER` fans the
        // ALTER out to every shard (empty clause → byte-identical on single-node)
        // so all shards keep the same retention window.
        // NAN-5346: also the UDM `logs` table under OCSF (retention_tables_for).
        let on_cluster = on_cluster_clause();
        for table in retention_tables_for(crate::schema::active_logs_table()) {
            self.client
                .query(&retention_ttl_sql(table, &on_cluster, days))
                .execute()
                .await
                .map_err(|e| RetentionError::ClickHouse(format!("{table}: {e}")))?;
        }

        Ok(())
    }

    /// Free bytes above `keep_free_space_bytes` on the connected node's
    /// ClickHouse data disk (its largest Local disk, as disk pressure picks).
    /// A failed read (a role without access to `system.disks`) does not block
    /// retention: it answers "unknown" as `u64::MAX` and the run goes ahead.
    async fn min_data_disk_free(&self) -> Result<u64, RetentionError> {
        match self
            .client
            .query(
                "SELECT free_space FROM system.disks WHERE type = 'Local' AND total_space > 0 \
                 ORDER BY total_space DESC LIMIT 1",
            )
            .fetch_optional::<u64>()
            .await
        {
            Ok(free) => Ok(free.unwrap_or(u64::MAX)),
            Err(e) => {
                tracing::warn!(error = %e, "Could not read ClickHouse free space before retention; running it anyway");
                Ok(u64::MAX)
            }
        }
    }

    /// Force materialize TTL (delete expired data now)
    pub async fn run_retention_now(&self) -> Result<u64, RetentionError> {
        // Get row count before
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct RowCount {
            count: u64,
        }

        // NAN-1241: force TTL on the active ingested-events table (ocsf_logs
        // under OCSF — where the retention-relevant bulk data lives). UDM-identical.
        // NAN-1728 H1: before/after counts read the `_distributed` wrapper so
        // they see all shards; MATERIALIZE TTL runs on the LOCAL
        // MergeTree with `ON CLUSTER` fanning them out to every shard (empty
        // clause on single-node → byte-identical).
        let local_logs_table = crate::schema::active_logs_table();
        let read_logs_table = read_routed(local_logs_table);
        let on_cluster = on_cluster_clause();
        let before: RowCount = self
            .client
            .query(&format!("SELECT count() as count FROM {read_logs_table}"))
            .fetch_one()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

        // NAN-5450: refuse up front when ClickHouse has no room. Probed on
        // clickhouse-server 26.10.4.207 with a full disk: MATERIALIZE TTL is
        // accepted, then its mutation waits for space forever (with
        // mutations_sync the call hangs; without, a stuck mutation is left
        // queued ahead of every later one), and OPTIMIZE FINAL returns
        // success having done nothing.
        let free = self.min_data_disk_free().await?;
        if free < RETENTION_MIN_FREE_BYTES {
            return Err(RetentionError::DiskFull(format!(
                "ClickHouse has {} free above its reserve, too little to run retention. Free space \
                 first: see docs/administration/disk-full-recovery.md (lower keep_free_space_bytes, \
                 SYSTEM RELOAD CONFIG, drop the oldest partitions, restore the reserve).",
                format_bytes(free)
            )));
        }

        // NAN-5450: MATERIALIZE TTL only. With `ttl_only_drop_parts = 1`
        // (server default, clickhouse/config.d/mergetree.xml) expired parts
        // are dropped whole, which frees space without a merge. The old
        // `OPTIMIZE ... FINAL` that followed rewrote the whole table: heavy on
        // a healthy disk and refused (silently, as far as the caller could
        // tell) on a full one, where it needs room for a merged copy.
        // `mutations_sync = 1` waits for this replica's mutation so the
        // returned count reflects the drop (the handler bounds the wait).
        self.client
            .query(&format!(
                "ALTER TABLE {local_logs_table}{on_cluster} MATERIALIZE TTL"
            ))
            .with_setting("mutations_sync", "1")
            .execute()
            .await
            .map_err(|e| retention_ch_error(local_logs_table, e.to_string()))?;

        // Get row count after
        let after: RowCount = self
            .client
            .query(&format!("SELECT count() as count FROM {read_logs_table}"))
            .fetch_one()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

        // NAN-5346: under OCSF also expire the UDM `logs` table's historical
        // rows. MATERIALIZE TTL only: a background mutation that drops
        // expired parts, never a blocking OPTIMIZE FINAL of a table that no
        // longer takes writes. Its rows are not part of the returned count.
        for table in retention_tables_for(local_logs_table).into_iter().skip(1) {
            self.client
                .query(&format!("ALTER TABLE {table}{on_cluster} MATERIALIZE TTL"))
                .execute()
                .await
                .map_err(|e| retention_ch_error(table, e.to_string()))?;
        }

        Ok(before.count.saturating_sub(after.count))
    }
}

/// Format bytes into human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

#[cfg(test)]
#[path = "retention_tables_tests.rs"]
mod retention_tables_tests;

#[cfg(test)]
#[path = "retention_disk_full_tests.rs"]
mod retention_disk_full_tests;
