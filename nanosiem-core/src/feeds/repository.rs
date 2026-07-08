// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feed repository for database operations
//!
//! This repository supports both PostgreSQL-only and dual-pool modes:
//! - PostgreSQL is always used for feed metadata (CRUD operations)
//! - ClickHouse is used for log statistics when DualPool is configured
//! - PostgreSQL is used for log statistics in legacy mode

use clickhouse::Client as ClickHouseClient;
use sqlx::{PgPool, Row};
use thiserror::Error;
use tracing::debug;
use uuid::Uuid;

use super::types::{Feed, FeedHealthMetrics, FeedHistoryPoint, FeedStats, NewFeed, UpdateFeed};

#[derive(Error, Debug)]
pub enum FeedRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),
    #[error("Feed not found: {0}")]
    NotFound(String),
    #[error("Feed name already exists: {0}")]
    DuplicateName(String),
}

pub struct FeedRepository {
    pool: PgPool,
    ch_client: Option<ClickHouseClient>,
    /// TableNames resolver — picks the `_distributed` rollup variant in
    /// cluster mode (NAN-735). Defaults to `is_clustered = false` so PG-only
    /// constructions still work; rollup reads only fire when `ch_client` is
    /// `Some`, so the standalone fallback never queries through this field.
    table_names: crate::db::TableNames,
}

impl FeedRepository {
    /// Generate a ClickHouse WHERE clause for matching logs to a feed.
    ///
    /// Priority:
    /// 1. Use `match_values` if set (exact match on source_type)
    /// 2. Use `match_pattern` if set (regex match on source_type)
    /// 3. Fall back to matching source_type = feed.name
    fn build_feed_where_clause(feed: &Feed) -> String {
        // If match_values is set, use IN clause
        if let Some(ref values) = feed.match_values {
            if !values.is_empty() {
                let escaped: Vec<String> = values
                    .iter()
                    .map(|v| format!("'{}'", crate::sql_hygiene::escape_sql_string(v)))
                    .collect();
                return format!("source_type IN ({})", escaped.join(", "));
            }
        }

        // If match_pattern is set, use regex match
        if let Some(ref pattern) = feed.match_pattern {
            if !pattern.is_empty() {
                // Use ClickHouse's match() function for regex
                let escaped_pattern = pattern.replace('\\', "\\\\").replace('\'', "''");
                return format!("match(source_type, '{}')", escaped_pattern);
            }
        }

        // Fall back to exact match on feed name
        format!(
            "source_type = '{}'",
            crate::sql_hygiene::escape_sql_string(&feed.name)
        )
    }
}

impl FeedRepository {
    /// Create a new repository with PostgreSQL only (legacy mode)
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ch_client: None,
            table_names: crate::db::TableNames::new(false),
        }
    }

    /// Create a new repository with DualPool (ClickHouse for log stats).
    /// `table_names` picks the `_distributed` rollup variant in cluster mode
    /// (NAN-735) — pass `TableNames::new(false)` for standalone deploys.
    pub fn with_clickhouse(
        pool: PgPool,
        ch_client: ClickHouseClient,
        table_names: crate::db::TableNames,
    ) -> Self {
        Self {
            pool,
            ch_client: Some(ch_client),
            table_names,
        }
    }

    /// List all feeds
    pub async fn list(&self) -> Result<Vec<Feed>, FeedRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, match_field, match_pattern,
                match_values, category, vendor, product, icon, color,
                enabled, stale_alert_enabled, stale_threshold_minutes,
                created_at, updated_at
            FROM feeds
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_feed).collect())
    }

    /// List enabled feeds only
    pub async fn list_enabled(&self) -> Result<Vec<Feed>, FeedRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, match_field, match_pattern,
                match_values, category, vendor, product, icon, color,
                enabled, stale_alert_enabled, stale_threshold_minutes,
                created_at, updated_at
            FROM feeds
            WHERE enabled = true
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_feed).collect())
    }

    /// Get a feed by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Feed, FeedRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, match_field, match_pattern,
                match_values, category, vendor, product, icon, color,
                enabled, stale_alert_enabled, stale_threshold_minutes,
                created_at, updated_at
            FROM feeds
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| FeedRepositoryError::NotFound(id.to_string()))?;

        Ok(row_to_feed(&row))
    }

    /// Get a feed by name
    pub async fn find_by_name(&self, name: &str) -> Result<Feed, FeedRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, match_field, match_pattern,
                match_values, category, vendor, product, icon, color,
                enabled, stale_alert_enabled, stale_threshold_minutes,
                created_at, updated_at
            FROM feeds
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| FeedRepositoryError::NotFound(name.to_string()))?;

        Ok(row_to_feed(&row))
    }

    /// Create a new feed
    ///
    /// Uses database unique constraint to atomically prevent duplicate names (race-condition safe)
    pub async fn create(&self, new_feed: &NewFeed) -> Result<Feed, FeedRepositoryError> {
        // Rely on unique constraint for name uniqueness (race-condition safe)
        let row = sqlx::query(
            r#"
            INSERT INTO feeds (name, description, match_field, match_pattern, match_values, category, vendor, product, icon, color)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, name, description, match_field, match_pattern, match_values, category, vendor, product, icon, color, enabled, stale_alert_enabled, stale_threshold_minutes, created_at, updated_at
            "#
        )
        .bind(&new_feed.name)
        .bind(&new_feed.description)
        .bind(&new_feed.match_field)
        .bind(&new_feed.match_pattern)
        .bind(&new_feed.match_values)
        .bind(&new_feed.category)
        .bind(&new_feed.vendor)
        .bind(&new_feed.product)
        .bind(&new_feed.icon)
        .bind(&new_feed.color)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            // Check for unique constraint violation
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("feeds_name_key") {
                    return FeedRepositoryError::DuplicateName(new_feed.name.clone());
                }
            }
            FeedRepositoryError::DatabaseError(e)
        })?;

        Ok(row_to_feed(&row))
    }

    /// Update a feed
    ///
    /// Uses database unique constraint to atomically prevent duplicate names (race-condition safe)
    pub async fn update(&self, id: Uuid, update: &UpdateFeed) -> Result<Feed, FeedRepositoryError> {
        // Check if feed exists
        self.find_by_id(id).await?;

        // Rely on unique constraint for name uniqueness (race-condition safe)
        let row = sqlx::query(
            r#"
            UPDATE feeds SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                match_field = COALESCE($4, match_field),
                match_pattern = COALESCE($5, match_pattern),
                match_values = COALESCE($6, match_values),
                category = COALESCE($7, category),
                vendor = COALESCE($8, vendor),
                product = COALESCE($9, product),
                icon = COALESCE($10, icon),
                color = COALESCE($11, color),
                enabled = COALESCE($12, enabled),
                stale_alert_enabled = COALESCE($13, stale_alert_enabled),
                stale_threshold_minutes = COALESCE($14, stale_threshold_minutes)
            WHERE id = $1
            RETURNING id, name, description, match_field, match_pattern, match_values, category, vendor, product, icon, color, enabled, stale_alert_enabled, stale_threshold_minutes, created_at, updated_at
            "#
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.match_field)
        .bind(&update.match_pattern)
        .bind(&update.match_values)
        .bind(&update.category)
        .bind(&update.vendor)
        .bind(&update.product)
        .bind(&update.icon)
        .bind(&update.color)
        .bind(update.enabled)
        .bind(update.stale_alert_enabled)
        .bind(update.stale_threshold_minutes)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            // Check for unique constraint violation
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("feeds_name_key") {
                    let name = update.name.clone().unwrap_or_default();
                    return FeedRepositoryError::DuplicateName(name);
                }
            }
            FeedRepositoryError::DatabaseError(e)
        })?;

        Ok(row_to_feed(&row))
    }

    /// Delete a feed
    pub async fn delete(&self, id: Uuid) -> Result<(), FeedRepositoryError> {
        let result = sqlx::query("DELETE FROM feeds WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(FeedRepositoryError::NotFound(id.to_string()));
        }

        Ok(())
    }

    /// Enable a feed
    pub async fn enable(&self, id: Uuid) -> Result<Feed, FeedRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE feeds SET enabled = true
            WHERE id = $1
            RETURNING id, name, description, match_field, match_pattern, match_values, category, vendor, product, icon, color, enabled, stale_alert_enabled, stale_threshold_minutes, created_at, updated_at
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| FeedRepositoryError::NotFound(id.to_string()))?;

        Ok(row_to_feed(&row))
    }

    /// Disable a feed
    pub async fn disable(&self, id: Uuid) -> Result<Feed, FeedRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE feeds SET enabled = false
            WHERE id = $1
            RETURNING id, name, description, match_field, match_pattern, match_values, category, vendor, product, icon, color, enabled, stale_alert_enabled, stale_threshold_minutes, created_at, updated_at
            "#
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| FeedRepositoryError::NotFound(id.to_string()))?;

        Ok(row_to_feed(&row))
    }

    /// Get feed statistics (event counts)
    pub async fn get_stats(&self) -> Result<Vec<FeedStats>, FeedRepositoryError> {
        // Get all enabled feeds first
        let feeds = self.list_enabled().await?;

        if let Some(ref ch_client) = self.ch_client {
            // Use ClickHouse for log statistics
            self.get_stats_clickhouse(ch_client, &feeds).await
        } else {
            // Legacy: use PostgreSQL
            self.get_stats_postgres(&feeds).await
        }
    }

    /// Get feed statistics from ClickHouse
    async fn get_stats_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        feeds: &[Feed],
    ) -> Result<Vec<FeedStats>, FeedRepositoryError> {
        let mut stats = Vec::new();

        // NAN-1728 (H5): route the logs read through the `_distributed` wrapper on
        // a cluster so feed stats cover ALL shards (~1/N undercount otherwise).
        // `read_bare` returns the bare `logs` on single-node — byte-identical.
        let logs_table = self.table_names.read_bare("logs");
        for feed in feeds {
            let where_clause = Self::build_feed_where_clause(feed);
            let sql = format!(
                r#"
                SELECT
                    count(*) as event_count,
                    max(timestamp) as last_event_at
                FROM {logs_table}
                WHERE {}
                "#,
                where_clause
            );

            debug!("ClickHouse feed stats query: {}", sql);

            // Execute query and parse results
            let mut cursor = ch_client
                .query(&sql)
                .fetch_bytes("JSONEachRow")
                .map_err(|e| FeedRepositoryError::ClickHouseError(e.to_string()))?;

            let mut response_bytes = Vec::new();
            while let Ok(Some(chunk)) = cursor.next().await {
                response_bytes.extend_from_slice(&chunk);
            }

            let response_str = String::from_utf8(response_bytes).map_err(|e| {
                FeedRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
            })?;

            // Parse the JSON response
            if let Some(line) = response_str.lines().next() {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                    let event_count = json
                        .get("event_count")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0);

                    let last_event_at = json
                        .get("last_event_at")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty() && *s != "1970-01-01 00:00:00.000000")
                        .and_then(|s| {
                            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok()
                        })
                        .map(|dt| dt.and_utc());

                    stats.push(FeedStats {
                        feed_id: feed.id,
                        feed_name: feed.name.clone(),
                        event_count,
                        last_event_at,
                    });
                }
            }
        }

        // Sort by event count descending
        stats.sort_by(|a, b| b.event_count.cmp(&a.event_count));

        Ok(stats)
    }

    /// Get feed statistics from PostgreSQL (legacy)
    async fn get_stats_postgres(
        &self,
        _feeds: &[Feed],
    ) -> Result<Vec<FeedStats>, FeedRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT 
                f.id as feed_id,
                f.name as feed_name,
                COALESCE(COUNT(l.id), 0) as event_count,
                MAX(l.timestamp) as last_event_at
            FROM feeds f
            LEFT JOIN logs l ON COALESCE(l.sourcetype, l.metadata->>'source_type') = f.name
            WHERE f.enabled = true
            GROUP BY f.id, f.name
            ORDER BY event_count DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| FeedStats {
                feed_id: row.get("feed_id"),
                feed_name: row.get("feed_name"),
                event_count: row.get::<i64, _>("event_count"),
                last_event_at: row.get("last_event_at"),
            })
            .collect())
    }

    /// Get detailed health metrics for a specific feed
    pub async fn get_health_metrics(
        &self,
        feed_id: Uuid,
    ) -> Result<FeedHealthMetrics, FeedRepositoryError> {
        // First get the feed to ensure it exists
        let feed = self.find_by_id(feed_id).await?;

        if let Some(ref ch_client) = self.ch_client {
            // Use ClickHouse for log statistics
            self.get_health_metrics_clickhouse(ch_client, &feed).await
        } else {
            // Legacy: use PostgreSQL
            self.get_health_metrics_postgres(&feed).await
        }
    }

    /// Get health metrics from ClickHouse
    async fn get_health_metrics_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        feed: &Feed,
    ) -> Result<FeedHealthMetrics, FeedRepositoryError> {
        let where_clause = Self::build_feed_where_clause(feed);

        // NAN-1728 (H5): route through the `_distributed` wrapper on a cluster so
        // feed health metrics cover all shards; bare `logs` on single-node.
        let logs_table = self.table_names.read_bare("logs");
        let sql = format!(
            r#"
            SELECT
                count(*) as total_events,
                countIf(timestamp >= now() - INTERVAL 24 HOUR) as events_last_24h,
                countIf(timestamp >= now() - INTERVAL 1 HOUR) as events_last_hour,
                max(timestamp) as last_event_at,
                min(timestamp) as first_event_at,
                if(max(timestamp) = toDateTime64('1970-01-01 00:00:00', 6, 'UTC'), NULL,
                   dateDiff('second', max(timestamp), now()) / 3600.0) as data_freshness_hours,
                sum(length(message) + length(metadata) + length(source_type) + 200) as total_size_bytes
            FROM {logs_table}
            WHERE {}
            "#,
            where_clause
        );

        debug!("ClickHouse health metrics query: {}", sql);

        // Execute query
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| FeedRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes)
            .map_err(|e| FeedRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e)))?;

        // Parse the JSON response
        let json: serde_json::Value = response_str
            .lines()
            .next()
            .and_then(|line| serde_json::from_str(line).ok())
            .unwrap_or(serde_json::json!({}));

        let total_events = json
            .get("total_events")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let events_last_24h = json
            .get("events_last_24h")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let events_last_hour = json
            .get("events_last_hour")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        let last_event_at = json
            .get("last_event_at")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
            .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok())
            .map(|dt| dt.and_utc());

        let first_event_at = json
            .get("first_event_at")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
            .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok())
            .map(|dt| dt.and_utc());

        let data_freshness_hours: Option<f64> = json
            .get("data_freshness_hours")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|&v| v >= 0.0);

        let total_size_bytes = json
            .get("total_size_bytes")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);

        // Get error metrics from PostgreSQL (ingestion_errors table)
        let error_row = sqlx::query(
            r#"
            SELECT 
                COALESCE(COUNT(*) FILTER (WHERE error_type = 'parse_error' AND timestamp >= NOW() - INTERVAL '24 hours'), 0) as parse_errors_24h,
                COALESCE(COUNT(*) FILTER (WHERE error_type = 'storage_error' AND timestamp >= NOW() - INTERVAL '24 hours'), 0) as storage_errors_24h
            FROM ingestion_errors
            WHERE source_type = $1
            "#
        )
        .bind(&feed.name)
        .fetch_optional(&self.pool)
        .await?;

        let (parse_errors_24h, storage_errors_24h) = error_row
            .map(|row| {
                let parse: i64 = row.try_get("parse_errors_24h").unwrap_or(0);
                let storage: i64 = row.try_get("storage_errors_24h").unwrap_or(0);
                (parse, storage)
            })
            .unwrap_or((0, 0));

        // Calculate derived metrics
        let avg_events_per_hour = if events_last_24h > 0 {
            events_last_24h as f64 / 24.0
        } else {
            0.0
        };

        let avg_event_size_bytes = if total_events > 0 {
            total_size_bytes as f64 / total_events as f64
        } else {
            0.0
        };

        let total_errors_24h = parse_errors_24h + storage_errors_24h;
        let total_attempts_24h = events_last_24h + total_errors_24h;
        let error_rate_24h = if total_attempts_24h > 0 {
            total_errors_24h as f64 / total_attempts_24h as f64
        } else {
            0.0
        };

        let ingestion_rate_trend = if total_events == 0 {
            "no_data".to_string()
        } else if events_last_hour > (avg_events_per_hour * 1.2) as i64 {
            "increasing".to_string()
        } else if events_last_hour < (avg_events_per_hour * 0.8) as i64 {
            "decreasing".to_string()
        } else {
            "stable".to_string()
        };

        let health_status = if !feed.enabled {
            "disabled".to_string()
        } else if total_events == 0 {
            "no_data".to_string()
        } else if let Some(freshness) = data_freshness_hours {
            if freshness > 24.0 {
                "stale".to_string()
            } else {
                "healthy".to_string()
            }
        } else {
            "no_data".to_string()
        };

        Ok(FeedHealthMetrics {
            feed_id: feed.id,
            feed_name: feed.name.clone(),
            total_events,
            events_last_24h,
            events_last_hour,
            avg_events_per_hour,
            last_event_at,
            first_event_at,
            data_freshness_hours,
            ingestion_rate_trend,
            health_status,
            total_size_bytes,
            avg_event_size_bytes,
            error_rate_24h,
            parse_errors_24h,
            storage_errors_24h,
        })
    }

    /// Get health metrics from PostgreSQL (legacy)
    async fn get_health_metrics_postgres(
        &self,
        feed: &Feed,
    ) -> Result<FeedHealthMetrics, FeedRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT 
                f.id as feed_id,
                f.name as feed_name,
                COALESCE(COUNT(l.id), 0) as total_events,
                COALESCE(COUNT(l.id) FILTER (WHERE l.timestamp >= NOW() - INTERVAL '24 hours'), 0) as events_last_24h,
                COALESCE(COUNT(l.id) FILTER (WHERE l.timestamp >= NOW() - INTERVAL '1 hour'), 0) as events_last_hour,
                MAX(l.timestamp) as last_event_at,
                MIN(l.timestamp) as first_event_at,
                CASE 
                    WHEN MAX(l.timestamp) IS NULL THEN NULL
                    ELSE CAST(EXTRACT(EPOCH FROM (NOW() - MAX(l.timestamp))) / 3600.0 AS FLOAT8)
                END as data_freshness_hours,
                COALESCE(SUM(
                    LENGTH(l.message) + 
                    LENGTH(l.metadata::text) + 
                    COALESCE(LENGTH(l.sourcetype), 0) +
                    -- Add estimated overhead for other columns (timestamps, IDs, etc.)
                    200
                ), 0) as total_size_bytes,
                -- Error metrics from ingestion_errors table
                COALESCE((
                    SELECT COUNT(*) 
                    FROM ingestion_errors e 
                    WHERE e.source_type = f.name 
                      AND e.error_type = 'parse_error'
                      AND e.timestamp >= NOW() - INTERVAL '24 hours'
                ), 0) as parse_errors_24h,
                COALESCE((
                    SELECT COUNT(*) 
                    FROM ingestion_errors e 
                    WHERE e.source_type = f.name 
                      AND e.error_type = 'storage_error'
                      AND e.timestamp >= NOW() - INTERVAL '24 hours'
                ), 0) as storage_errors_24h
            FROM feeds f
            LEFT JOIN logs l ON COALESCE(l.sourcetype, l.metadata->>'source_type') = f.name
            WHERE f.id = $1
            GROUP BY f.id, f.name
            "#
        )
        .bind(feed.id)
        .fetch_one(&self.pool)
        .await?;

        let total_events: i64 = row.get("total_events");
        let events_last_24h: i64 = row.get("events_last_24h");
        let events_last_hour: i64 = row.get("events_last_hour");
        let data_freshness_hours: Option<f64> = row.get("data_freshness_hours");
        let total_size_bytes: i64 = row.get("total_size_bytes");
        let parse_errors_24h: i64 = row.get("parse_errors_24h");
        let storage_errors_24h: i64 = row.get("storage_errors_24h");

        // Calculate average events per hour (over last 24h if we have data)
        let avg_events_per_hour = if events_last_24h > 0 {
            events_last_24h as f64 / 24.0
        } else {
            0.0
        };

        // Calculate average event size
        let avg_event_size_bytes = if total_events > 0 {
            total_size_bytes as f64 / total_events as f64
        } else {
            0.0
        };

        // Calculate error rate (errors / total attempts in last 24h)
        let total_errors_24h = parse_errors_24h + storage_errors_24h;
        let total_attempts_24h = events_last_24h + total_errors_24h;
        let error_rate_24h = if total_attempts_24h > 0 {
            total_errors_24h as f64 / total_attempts_24h as f64
        } else {
            0.0
        };

        // Determine ingestion rate trend (simplified - could be enhanced with more historical data)
        let ingestion_rate_trend = if total_events == 0 {
            "no_data".to_string()
        } else if events_last_hour > (avg_events_per_hour * 1.2) as i64 {
            "increasing".to_string()
        } else if events_last_hour < (avg_events_per_hour * 0.8) as i64 {
            "decreasing".to_string()
        } else {
            "stable".to_string()
        };

        // Determine health status
        let health_status = if !feed.enabled {
            "disabled".to_string()
        } else if total_events == 0 {
            "no_data".to_string()
        } else if let Some(freshness) = data_freshness_hours {
            if freshness > 24.0 {
                "stale".to_string()
            } else {
                "healthy".to_string()
            }
        } else {
            "no_data".to_string()
        };

        Ok(FeedHealthMetrics {
            feed_id: feed.id,
            feed_name: row.get("feed_name"),
            total_events,
            events_last_24h,
            events_last_hour,
            avg_events_per_hour,
            last_event_at: row.get("last_event_at"),
            first_event_at: row.get("first_event_at"),
            data_freshness_hours,
            ingestion_rate_trend,
            health_status,
            total_size_bytes,
            avg_event_size_bytes,
            error_rate_24h,
            parse_errors_24h,
            storage_errors_24h,
        })
    }

    /// Get historical ingestion data for charts (last 24 hours)
    pub async fn get_ingestion_history(
        &self,
        feed_id: Uuid,
    ) -> Result<Vec<FeedHistoryPoint>, FeedRepositoryError> {
        // First get the feed to ensure it exists
        let feed = self.find_by_id(feed_id).await?;

        if let Some(ref ch_client) = self.ch_client {
            // Use ClickHouse for log statistics
            self.get_ingestion_history_clickhouse(ch_client, &feed)
                .await
        } else {
            // Legacy: use PostgreSQL
            self.get_ingestion_history_postgres(&feed).await
        }
    }

    /// Get ingestion history from ClickHouse
    async fn get_ingestion_history_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        feed: &Feed,
    ) -> Result<Vec<FeedHistoryPoint>, FeedRepositoryError> {
        let where_clause = Self::build_feed_where_clause(feed);

        // NAN-1728 (H5): route through the `_distributed` wrapper on a cluster so
        // the ingestion-history buckets cover all shards; bare `logs` on single-node.
        let logs_table = self.table_names.read_bare("logs");
        let sql = format!(
            r#"
            SELECT
                toStartOfHour(timestamp) as hour_bucket,
                count(*) as event_count
            FROM {logs_table}
            WHERE {}
              AND timestamp >= now() - INTERVAL 24 HOUR
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            "#,
            where_clause
        );

        debug!("ClickHouse ingestion history query: {}", sql);

        // Execute query
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| FeedRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes)
            .map_err(|e| FeedRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e)))?;

        let history: Vec<FeedHistoryPoint> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let json: serde_json::Value = serde_json::from_str(line).ok()?;
                let time_str = json.get("hour_bucket")?.as_str()?;
                let event_count = json.get("event_count")?.as_str()?.parse::<i64>().ok()?;

                let time = chrono::NaiveDateTime::parse_from_str(time_str, "%Y-%m-%d %H:%M:%S")
                    .ok()
                    .map(|dt| dt.and_utc())?;

                Some(FeedHistoryPoint {
                    time,
                    event_count,
                    hour_label: time.format("%H:%M").to_string(),
                })
            })
            .collect();

        Ok(history)
    }

    /// Get ingestion history from PostgreSQL (legacy)
    async fn get_ingestion_history_postgres(
        &self,
        feed: &Feed,
    ) -> Result<Vec<FeedHistoryPoint>, FeedRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT 
                date_trunc('hour', l.timestamp) as hour_bucket,
                COUNT(*) as event_count
            FROM logs l
            WHERE COALESCE(l.sourcetype, l.metadata->>'source_type') = $1
              AND l.timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            "#,
        )
        .bind(&feed.name)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| {
                let time: chrono::DateTime<chrono::Utc> = row.get("hour_bucket");
                let event_count: i64 = row.get("event_count");

                FeedHistoryPoint {
                    time,
                    event_count,
                    hour_label: time.format("%H:%M").to_string(),
                }
            })
            .collect())
    }

    /// Get distinct sourcetypes from logs (for discovery)
    pub async fn get_discovered_sourcetypes(
        &self,
    ) -> Result<Vec<(String, i64)>, FeedRepositoryError> {
        if let Some(ref ch_client) = self.ch_client {
            // Use ClickHouse
            self.get_discovered_sourcetypes_clickhouse(ch_client).await
        } else {
            // Legacy: use PostgreSQL
            self.get_discovered_sourcetypes_postgres().await
        }
    }

    /// Get discovered sourcetypes from ClickHouse.
    ///
    /// Reads from the `logs_per_source_5m` rollup (NAN-735) — the rollup's
    /// 7-day TTL exactly matches what this discovery endpoint asks for, so
    /// no fallback path is needed. Replaces an un-scoped 7-day scan over
    /// raw `logs` with a tiny aggregated read.
    async fn get_discovered_sourcetypes_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
    ) -> Result<Vec<(String, i64)>, FeedRepositoryError> {
        let rollup = self.table_names.read("logs_per_source_5m");
        let sql = format!(
            "SELECT \
                source_type AS sourcetype, \
                sum(events) AS count \
             FROM {} \
             WHERE bucket_start > now() - INTERVAL 7 DAY \
             GROUP BY source_type \
             ORDER BY count DESC \
             LIMIT 100",
            rollup
        );

        debug!("ClickHouse discovered sourcetypes query: {}", sql);

        // Execute query
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| FeedRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes)
            .map_err(|e| FeedRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e)))?;

        let sourcetypes: Vec<(String, i64)> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let json: serde_json::Value = serde_json::from_str(line).ok()?;
                let sourcetype = json.get("sourcetype")?.as_str()?.to_string();
                let count = json.get("count")?.as_str()?.parse::<i64>().ok()?;
                Some((sourcetype, count))
            })
            .collect();

        Ok(sourcetypes)
    }

    /// Get discovered sourcetypes from PostgreSQL (legacy)
    async fn get_discovered_sourcetypes_postgres(
        &self,
    ) -> Result<Vec<(String, i64)>, FeedRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT 
                COALESCE(
                    sourcetype,
                    metadata->>'source_type',
                    'unknown'
                ) as sourcetype,
                COUNT(*) as count
            FROM logs
            WHERE timestamp > NOW() - INTERVAL '7 days'
            GROUP BY COALESCE(sourcetype, metadata->>'source_type', 'unknown')
            ORDER BY count DESC
            LIMIT 100
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| {
                let sourcetype: String = r.try_get("sourcetype").unwrap_or_default();
                let count: i64 = r.try_get("count").unwrap_or(0);
                (sourcetype, count)
            })
            .collect())
    }
}

/// Convert a database row to a Feed struct
fn row_to_feed(row: &sqlx::postgres::PgRow) -> Feed {
    Feed {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        match_field: row.get("match_field"),
        match_pattern: row.get("match_pattern"),
        match_values: row.get("match_values"),
        category: row.get("category"),
        vendor: row.get("vendor"),
        product: row.get("product"),
        icon: row.get("icon"),
        color: row.get("color"),
        enabled: row.get("enabled"),
        stale_alert_enabled: row.get("stale_alert_enabled"),
        stale_threshold_minutes: row.get("stale_threshold_minutes"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}
