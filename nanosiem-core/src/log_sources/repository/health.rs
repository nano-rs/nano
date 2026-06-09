// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health metrics and ClickHouse-backed statistics for log sources

use clickhouse::Client as ClickHouseClient;
use uuid::Uuid;

use super::super::types::{
    HealthStatus, HistoryPoint, IngestionHistoryPoint, IngestionTrend, ListParams, LogSource,
    LogSourceHealth, LogSourceHealthSummary,
};
use super::helpers::parse_json_i64;
use super::{LogSourceRepository, LogSourceRepositoryError};

impl LogSourceRepository {
    /// Get health summary for all log sources
    pub async fn get_all_health_summary(
        &self,
    ) -> Result<Vec<(Uuid, LogSourceHealthSummary)>, LogSourceRepositoryError> {
        // Get all log sources
        let log_sources = self.list(&ListParams::default()).await?;

        // Query ClickHouse for actual metrics if available
        if let Some(ref ch_client) = self.ch_client {
            return self
                .get_all_health_summary_clickhouse(ch_client, &log_sources)
                .await;
        }

        // Fallback: basic health based on enabled/deployed status
        Ok(log_sources
            .iter()
            .map(|ls| {
                let status = if !ls.enabled {
                    HealthStatus::Disabled
                } else if !ls.deployed {
                    HealthStatus::NoData
                } else {
                    HealthStatus::Healthy
                };

                (
                    ls.id,
                    LogSourceHealthSummary {
                        total_events: 0,
                        events_last_24h: 0,
                        last_event_at: None,
                        health_status: status,
                    },
                )
            })
            .collect())
    }

    /// Get health summary for all log sources from ClickHouse.
    ///
    /// Reads from the `logs_per_source_5m` rollup (NAN-734) — replaces the
    /// previous un-scoped `count(*) * 10 SAMPLE 0.1 FROM logs` over the
    /// 90-day TTL window with a single tiny aggregated read against the
    /// 7-day rollup. Numbers are now exact rather than sampled estimates.
    ///
    /// **`total_events` semantics change:** the rollup retains 7 days, so
    /// what's reported here is the 7-day sum, not a 90-day "ever-seen"
    /// total. The badge logic uses `events_last_24h` directly to decide
    /// `NoData` vs `Stale` vs `Healthy`, which is more accurate than the
    /// previous `total_events == 0` check (a source dormant for >24h used
    /// to show as `Healthy`; now correctly shows `NoData`).
    async fn get_all_health_summary_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        log_sources: &[LogSource],
    ) -> Result<Vec<(Uuid, LogSourceHealthSummary)>, LogSourceRepositoryError> {
        let rollup = self.table_names.read("logs_per_source_5m");
        // One scoped query against the rollup. The rollup MV writes
        // lowercased source_type, so reads compare against lowercased names
        // without runtime `lower()` overhead.
        let sql = format!(
            "SELECT \
                source_type AS source_type_lc, \
                sum(events) AS total_events, \
                sumIf(events, bucket_start >= now() - INTERVAL 24 HOUR) AS events_last_24h, \
                sumIf(events, bucket_start >= now() - INTERVAL 1 HOUR) AS events_last_hour, \
                max(last_event_at) AS last_event_at \
             FROM {} \
             WHERE bucket_start >= now() - INTERVAL 7 DAY \
             GROUP BY source_type",
            rollup
        );

        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;

        // Parse results into a map
        let mut stats_map: std::collections::HashMap<
            String,
            (i64, i64, i64, Option<chrono::DateTime<chrono::Utc>>),
        > = std::collections::HashMap::new();

        for line in response_str.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let source_type = json
                    .get("source_type_lc")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_lowercase();
                let total = parse_json_i64(&json, "total_events");
                let last_24h = parse_json_i64(&json, "events_last_24h");
                let last_hour = parse_json_i64(&json, "events_last_hour");
                let last_event = json
                    .get("last_event_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                            .or_else(|_| {
                                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                            })
                            .ok()
                    })
                    .map(|dt| dt.and_utc());

                stats_map.insert(source_type, (total, last_24h, last_hour, last_event));
            }
        }

        // Build results for all log sources. Health badge now derives from
        // events_last_24h instead of total_events — see the function-level
        // doc comment for the contract change.
        let mut results = Vec::new();
        for ls in log_sources {
            let source_key = ls.source_type.to_lowercase();
            let (total_events, events_last_24h, events_last_hour, last_event_at) = stats_map
                .get(&source_key)
                .cloned()
                .unwrap_or((0, 0, 0, None));

            let health_status = if !ls.enabled {
                HealthStatus::Disabled
            } else if !ls.deployed {
                HealthStatus::NoData
            } else if ls.validation_error.is_some() {
                HealthStatus::Error
            } else if events_last_24h == 0 {
                HealthStatus::NoData
            } else if events_last_hour == 0 {
                HealthStatus::Stale
            } else {
                HealthStatus::Healthy
            };

            results.push((
                ls.id,
                LogSourceHealthSummary {
                    total_events,
                    events_last_24h,
                    last_event_at,
                    health_status,
                },
            ));
        }

        Ok(results)
    }

    /// Get detailed health metrics for a specific log source
    pub async fn get_health(&self, id: Uuid) -> Result<LogSourceHealth, LogSourceRepositoryError> {
        let log_source = self.find_by_id(id).await?;

        // Query ClickHouse for actual metrics if available
        if let Some(ref ch_client) = self.ch_client {
            return self.get_health_clickhouse(ch_client, &log_source).await;
        }

        // Fallback: basic health based on enabled/deployed status
        let health_status = if !log_source.enabled {
            HealthStatus::Disabled
        } else if !log_source.deployed {
            HealthStatus::NoData
        } else if log_source.validation_error.is_some() {
            HealthStatus::Error
        } else {
            HealthStatus::Healthy
        };

        Ok(LogSourceHealth {
            log_source_id: log_source.id,
            log_source_name: log_source.name,
            total_events: 0,
            events_last_24h: 0,
            events_last_hour: 0,
            avg_events_per_hour: 0.0,
            last_event_at: None,
            first_event_at: None,
            data_freshness_hours: None,
            ingestion_rate_trend: IngestionTrend::Unknown,
            health_status,
            total_size_bytes: 0,
            avg_event_size_bytes: 0.0,
            error_rate_24h: 0.0,
            parse_errors_24h: 0,
        })
    }

    /// Get health metrics from ClickHouse
    async fn get_health_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        log_source: &LogSource,
    ) -> Result<LogSourceHealth, LogSourceRepositoryError> {
        let where_clause = Self::build_log_source_where_clause(log_source);

        // NAN-1241: read the active ingested-events table. Under OCSF the payload
        // is the single `event` JSON column (there is no `message`/`metadata`
        // column), so estimate row size from it; UDM keeps the original calc.
        let logs_table = crate::schema::active_logs_table();
        let size_expr = if logs_table == "ocsf_logs" {
            "length(toString(event)) + length(source_type) + 100"
        } else {
            "length(message) + length(metadata) + length(source_type) + 100"
        };

        // Query recent data with PREWHERE for partition pruning
        // Use 90-day window for total_events, dedicated counts for 24h/1h
        let sql = format!(
            r#"
            SELECT
                count(*) as total_events,
                countIf(timestamp >= now() - INTERVAL 24 HOUR) as events_last_24h,
                countIf(timestamp >= now() - INTERVAL 1 HOUR) as events_last_hour,
                max(timestamp) as last_event_at,
                min(timestamp) as first_event_at,
                sum({size_expr}) as total_size_bytes
            FROM {logs_table}
            PREWHERE timestamp >= now() - INTERVAL 90 DAY
            WHERE {where_clause}
            "#
        );

        // Execute query and parse results as JSON
        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;

        let (
            total_events,
            events_last_24h,
            events_last_hour,
            last_event_at,
            first_event_at,
            total_size_bytes,
        ) = if let Some(line) = response_str.lines().next() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let total = parse_json_i64(&json, "total_events");
                let last_24h = parse_json_i64(&json, "events_last_24h");
                let last_hour = parse_json_i64(&json, "events_last_hour");
                let size_bytes = parse_json_i64(&json, "total_size_bytes");

                let last_event = json
                    .get("last_event_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok()
                    })
                    .map(|dt| dt.and_utc());

                let first_event = json
                    .get("first_event_at")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f").ok()
                    })
                    .map(|dt| dt.and_utc());

                (
                    total,
                    last_24h,
                    last_hour,
                    last_event,
                    first_event,
                    size_bytes,
                )
            } else {
                (0, 0, 0, None, None, 0)
            }
        } else {
            (0, 0, 0, None, None, 0)
        };

        // Determine health status based on actual data
        let health_status = if !log_source.enabled {
            HealthStatus::Disabled
        } else if !log_source.deployed {
            HealthStatus::NoData
        } else if log_source.validation_error.is_some() {
            HealthStatus::Error
        } else if total_events == 0 {
            HealthStatus::NoData
        } else if events_last_hour == 0 && events_last_24h > 0 {
            HealthStatus::Stale
        } else {
            HealthStatus::Healthy
        };

        // Calculate data freshness
        let data_freshness_hours = last_event_at.map(|t| {
            let now = chrono::Utc::now();
            let diff = now.signed_duration_since(t);
            diff.num_minutes() as f64 / 60.0
        });

        // Calculate average events per hour
        let avg_events_per_hour = if let (Some(first), Some(last)) = (first_event_at, last_event_at)
        {
            let hours = last.signed_duration_since(first).num_hours().max(1) as f64;
            total_events as f64 / hours
        } else {
            0.0
        };

        // Determine trend
        let ingestion_rate_trend = if events_last_hour == 0 && events_last_24h == 0 {
            IngestionTrend::Unknown
        } else if (events_last_hour as f64) > (events_last_24h as f64 / 24.0) * 1.2 {
            IngestionTrend::Increasing
        } else if (events_last_hour as f64) < (events_last_24h as f64 / 24.0) * 0.8 {
            IngestionTrend::Decreasing
        } else {
            IngestionTrend::Stable
        };

        // Calculate average event size
        let avg_event_size_bytes = if total_events > 0 {
            total_size_bytes as f64 / total_events as f64
        } else {
            0.0
        };

        Ok(LogSourceHealth {
            log_source_id: log_source.id,
            log_source_name: log_source.name.clone(),
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
            error_rate_24h: 0.0, // Would need parse error tracking
            parse_errors_24h: 0, // Would need parse error tracking
        })
    }

    /// Build WHERE clause to match logs to a log source
    ///
    /// Priority:
    /// 1. Use `match_values` if set (exact match on match_field column)
    /// 2. Use `match_pattern` if set (regex match on match_field column)
    /// 3. Fall back to matching source_type = log_source.name
    fn build_log_source_where_clause(log_source: &LogSource) -> String {
        // Determine which column to match against
        let field = log_source
            .match_field
            .as_deref()
            .filter(|f| !f.is_empty())
            .unwrap_or("source_type");

        // If match_values is set, use case-insensitive IN clause
        if let Some(ref values) = log_source.match_values {
            if !values.is_empty() {
                let escaped: Vec<String> = values
                    .iter()
                    .map(|v| format!("'{}'", v.to_lowercase().replace('\'', "''")))
                    .collect();
                return format!("lower({}) IN ({})", field, escaped.join(", "));
            }
        }

        // If match_pattern is set, use case-insensitive regex
        if let Some(ref pattern) = log_source.match_pattern {
            if !pattern.is_empty() {
                let escaped_pattern = pattern.replace('\\', "\\\\").replace('\'', "''");
                return format!("match(lower({}), lower('{}'))", field, escaped_pattern);
            }
        }

        // Default: case-insensitive match by log source name
        format!(
            "lower(source_type) = lower('{}')",
            log_source.name.replace('\'', "''")
        )
    }

    /// Get ingestion history for charting
    pub async fn get_ingestion_history(
        &self,
        id: Uuid,
        _hours: i64,
    ) -> Result<Vec<HistoryPoint>, LogSourceRepositoryError> {
        // Verify log source exists
        self.find_by_id(id).await?;

        // In production, query ClickHouse for actual history
        // For now, return empty history
        Ok(Vec::new())
    }

    /// Get ingestion history for all log sources (for area chart)
    pub async fn get_all_ingestion_history(
        &self,
        hours: i64,
    ) -> Result<Vec<IngestionHistoryPoint>, LogSourceRepositoryError> {
        // Get all deployed log sources to build the WHERE clause
        let log_sources = self.list_deployed().await?;

        if log_sources.is_empty() {
            return Ok(Vec::new());
        }

        let Some(ref ch_client) = self.ch_client else {
            return Ok(Vec::new());
        };

        // Build a combined WHERE clause for all log sources
        let mut all_source_types: Vec<String> = Vec::new();
        for ls in &log_sources {
            if let Some(ref values) = ls.match_values {
                for v in values {
                    all_source_types.push(v.clone());
                }
            } else {
                all_source_types.push(ls.name.clone());
            }
        }

        if all_source_types.is_empty() {
            return Ok(Vec::new());
        }

        let escaped: Vec<String> = all_source_types
            .iter()
            .map(|v| format!("'{}'", v.to_lowercase().replace('\'', "''")))
            .collect();
        let in_clause = escaped.join(", ");

        // Read from the rollup (NAN-734) when the requested window fits in
        // its 7-day retention; otherwise fall back to scanning raw `logs`.
        // Rollup path uses sum(events) over 5-min buckets re-grouped by hour
        // — equivalent to the previous count() but reads ~7 buckets/hour
        // instead of every row in the 90d TTL window.
        let rollup_retention_hours: i64 = 7 * 24;
        let sql = if hours <= rollup_retention_hours {
            let rollup = self.table_names.read("logs_per_source_5m");
            format!(
                "SELECT \
                    source_type, \
                    toStartOfHour(bucket_start) AS hour, \
                    sum(events) AS count \
                 FROM {} \
                 WHERE bucket_start >= now() - INTERVAL {} HOUR \
                   AND source_type IN ({}) \
                 GROUP BY source_type, hour \
                 ORDER BY hour ASC",
                rollup, hours, in_clause
            )
        } else {
            format!(
                r#"
                SELECT
                    source_type,
                    toStartOfHour(timestamp) as hour,
                    count(*) as count
                FROM logs
                WHERE timestamp >= now() - INTERVAL {} HOUR
                  AND lower(source_type) IN ({})
                GROUP BY source_type, hour
                ORDER BY hour ASC
                "#,
                hours, in_clause
            )
        };

        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| LogSourceRepositoryError::ClickHouseError(e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            LogSourceRepositoryError::ClickHouseError(format!("Invalid UTF-8: {}", e))
        })?;

        let mut results = Vec::new();
        for line in response_str.lines() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                let source_type = json
                    .get("source_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let hour = json
                    .get("hour")
                    .and_then(|v| v.as_str())
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()
                    })
                    .map(|dt| dt.and_utc());

                let count = parse_json_i64(&json, "count");

                if let Some(timestamp) = hour {
                    results.push(IngestionHistoryPoint {
                        source_type,
                        timestamp,
                        count,
                    });
                }
            }
        }

        Ok(results)
    }
}

