// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data Retention Settings
//!
//! Manages log retention policies for both PostgreSQL (metadata) and ClickHouse (logs).

use clickhouse::Client as ClickHouseClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;

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
    /// TTL retention days (from table settings)
    pub ttl_days: Option<u32>,
}

/// Service for managing data retention
pub struct RetentionService {
    pool: PgPool,
}

impl RetentionService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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

        let metadata = sqlx::query_as::<_, MetadataStats>(
            r#"
            SELECT
                LEAST(
                    (SELECT MIN(created_at) FROM alerts),
                    (SELECT MIN(created_at) FROM detections),
                    (SELECT MIN(created_at) FROM cases)
                ) as oldest,
                GREATEST(
                    (SELECT MAX(created_at) FROM alerts),
                    (SELECT MAX(created_at) FROM detections),
                    (SELECT MAX(created_at) FROM cases)
                ) as newest,
                (
                    (SELECT COUNT(*) FROM alerts) +
                    (SELECT COUNT(*) FROM detections) +
                    (SELECT COUNT(*) FROM cases) +
                    (SELECT COUNT(*) FROM dashboards)
                )::bigint as total_records
            "#,
        )
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

        // Clean up old metadata (detection_matched_events, search_history, etc.)
        let deleted = sqlx::query_scalar::<_, i64>(
            r#"
            WITH deleted_events AS (
                DELETE FROM detection_matched_events
                WHERE detected_at < NOW() - ($1 || ' days')::interval
                RETURNING 1
            ),
            deleted_history AS (
                DELETE FROM search_history
                WHERE created_at < NOW() - ($1 || ' days')::interval
                RETURNING 1
            )
            SELECT (SELECT COUNT(*) FROM deleted_events) + (SELECT COUNT(*) FROM deleted_history)
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
}

impl ClickHouseStorageService {
    pub fn new(client: ClickHouseClient) -> Self {
        Self { client }
    }

    /// Get ClickHouse storage statistics for the logs table
    pub async fn get_storage_stats(&self) -> Result<ClickHouseStorageStats, RetentionError> {
        // First check if logs table exists
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct TableExists {
            exists: u8,
        }

        let table_check: TableExists = self
            .client
            .query(
                r#"
                SELECT count() > 0 as exists
                FROM system.tables
                WHERE database = currentDatabase() AND name = 'logs'
            "#,
            )
            .fetch_one()
            .await
            .map_err(|e| {
                RetentionError::ClickHouse(format!("Failed to check table existence: {}", e))
            })?;

        if table_check.exists == 0 {
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
                ttl_days: Some(90),
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

        let stats: Option<TableStats> = match self
            .client
            .query(
                r#"
                SELECT
                    COALESCE(sum(bytes_on_disk), 0) as total_bytes,
                    COALESCE(sum(rows), 0) as total_rows,
                    count() as parts_count,
                    COALESCE(sum(data_uncompressed_bytes), 0) as uncompressed_bytes,
                    COALESCE(countDistinct(partition), 0) as partition_count
                FROM system.parts
                WHERE database = currentDatabase()
                  AND table = 'logs'
                  AND active = 1
            "#,
            )
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

        let row_count: RowCount = self
            .client
            .query("SELECT count() as cnt FROM logs")
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
                .query(
                    r#"
                    SELECT
                        formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') as oldest,
                        formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%sZ') as newest
                    FROM logs
                "#,
                )
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
            ttl_days: Some(90), // Default from init.sql
        })
    }

    /// Update ClickHouse TTL retention period
    pub async fn update_retention(&self, days: u32) -> Result<(), RetentionError> {
        let query = format!(
            "ALTER TABLE logs MODIFY TTL timestamp + INTERVAL {} DAY DELETE",
            days
        );

        self.client
            .query(&query)
            .execute()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

        Ok(())
    }

    /// Force materialize TTL (delete expired data now)
    pub async fn run_retention_now(&self) -> Result<u64, RetentionError> {
        // Get row count before
        #[derive(clickhouse::Row, serde::Deserialize)]
        struct RowCount {
            count: u64,
        }

        let before: RowCount = self
            .client
            .query("SELECT count() as count FROM logs")
            .fetch_one()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

        // Force TTL materialization
        self.client
            .query("ALTER TABLE logs MATERIALIZE TTL")
            .execute()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

        // Optimize to merge parts and actually delete data
        self.client
            .query("OPTIMIZE TABLE logs FINAL")
            .execute()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

        // Get row count after
        let after: RowCount = self
            .client
            .query("SELECT count() as count FROM logs")
            .fetch_one()
            .await
            .map_err(|e| RetentionError::ClickHouse(e.to_string()))?;

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
