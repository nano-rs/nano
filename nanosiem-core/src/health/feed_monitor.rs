// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data feed staleness monitoring
//!
//! Monitors log sources for staleness based on configured thresholds.

use chrono::{Duration, Utc};
use clickhouse::Client as ClickHouseClient;
use sqlx::{PgPool, Row};
use tracing::{debug, warn};

use super::types::FeedStalenessStatus;

/// Data feed staleness monitor (monitors log_sources table)
pub struct FeedMonitor {
    pool: PgPool,
    ch_client: Option<ClickHouseClient>,
}

impl FeedMonitor {
    /// Create monitor with PostgreSQL only
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ch_client: None,
        }
    }

    /// Create monitor with ClickHouse support
    pub fn with_clickhouse(pool: PgPool, ch_client: ClickHouseClient) -> Self {
        Self {
            pool,
            ch_client: Some(ch_client),
        }
    }

    /// Check staleness of all log sources with alerts enabled
    pub async fn check_all_feeds(&self) -> Vec<FeedStalenessStatus> {
        let mut statuses = Vec::new();

        // Get log sources with stale alerts enabled
        let sources = match self.get_log_sources_with_alerts_enabled().await {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to get log sources for staleness check: {}", e);
                return statuses;
            }
        };

        for source in sources {
            let status = self.check_feed_staleness(&source).await;
            statuses.push(status);
        }

        statuses
    }

    /// Get log sources that have stale alerts enabled
    async fn get_log_sources_with_alerts_enabled(&self) -> Result<Vec<LogSourceInfo>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, stale_threshold_minutes, match_pattern, match_values
            FROM log_sources
            WHERE enabled = true AND stale_alert_enabled = true
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| LogSourceInfo {
                id: r.get("id"),
                name: r.get("name"),
                stale_threshold_minutes: r.get("stale_threshold_minutes"),
                match_pattern: r.get("match_pattern"),
                match_values: r.get::<Option<Vec<String>>, _>("match_values"),
            })
            .collect())
    }

    /// Check staleness for a single log source
    async fn check_feed_staleness(&self, source: &LogSourceInfo) -> FeedStalenessStatus {
        let last_event_at = if let Some(ref ch_client) = self.ch_client {
            self.get_last_event_clickhouse(ch_client, source).await
        } else {
            self.get_last_event_postgres(&source.name).await
        };

        let now = Utc::now();
        let threshold = Duration::minutes(source.stale_threshold_minutes as i64);

        let (minutes_since_last_event, is_stale) = match last_event_at {
            Some(last) => {
                let since = now.signed_duration_since(last);
                let minutes = since.num_minutes();
                let stale = since > threshold;
                (Some(minutes), stale)
            }
            None => {
                // No events ever - consider stale if threshold is reasonably short
                // (e.g., log source should have data but doesn't)
                (None, true)
            }
        };

        debug!(
            log_source = %source.name,
            last_event_at = ?last_event_at,
            minutes_since = ?minutes_since_last_event,
            threshold_minutes = %source.stale_threshold_minutes,
            is_stale = %is_stale,
            "Log source staleness check"
        );

        FeedStalenessStatus {
            feed_id: source.id,
            feed_name: source.name.clone(),
            last_event_at,
            stale_threshold_minutes: source.stale_threshold_minutes,
            minutes_since_last_event,
            is_stale,
        }
    }

    /// Get last event timestamp from ClickHouse
    async fn get_last_event_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        source: &LogSourceInfo,
    ) -> Option<chrono::DateTime<Utc>> {
        let where_clause = source.build_where_clause();
        // NAN-1241: read the active ingested-events table (ocsf_logs under OCSF)
        // so feed staleness reflects where events actually land. UDM-identical.
        let logs_table = crate::schema::active_logs_table();
        let sql = format!(
            r#"
            SELECT max(timestamp) as last_event_at
            FROM {logs_table}
            WHERE {where_clause}
            "#,
        );

        let result = ch_client.query(&sql).fetch_bytes("JSONEachRow").ok();

        if let Some(mut cursor) = result {
            let mut response_bytes = Vec::new();
            while let Ok(Some(chunk)) = cursor.next().await {
                response_bytes.extend_from_slice(&chunk);
            }

            if let Ok(response_str) = String::from_utf8(response_bytes) {
                if let Some(line) = response_str.lines().next() {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                        return json
                            .get("last_event_at")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
                            .and_then(|s| {
                                chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                                    .ok()
                            })
                            .map(|dt| dt.and_utc());
                    }
                }
            }
        }

        None
    }

    /// Get last event timestamp from PostgreSQL
    async fn get_last_event_postgres(&self, feed_name: &str) -> Option<chrono::DateTime<Utc>> {
        let row = sqlx::query(
            r#"
            SELECT MAX(timestamp) as last_event_at
            FROM logs
            WHERE COALESCE(sourcetype, metadata->>'source_type') = $1
            "#,
        )
        .bind(feed_name)
        .fetch_optional(&self.pool)
        .await
        .ok()?;

        row.and_then(|r| r.get("last_event_at"))
    }
}

struct LogSourceInfo {
    id: uuid::Uuid,
    name: String,
    stale_threshold_minutes: i32,
    match_pattern: Option<String>,
    match_values: Option<Vec<String>>,
}

impl LogSourceInfo {
    /// Generate a ClickHouse WHERE clause for matching logs to this log source.
    fn build_where_clause(&self) -> String {
        // If match_values is set, use IN clause
        if let Some(ref values) = self.match_values {
            if !values.is_empty() {
                let escaped: Vec<String> = values
                    .iter()
                    .map(|v| format!("'{}'", crate::sql_hygiene::escape_sql_string(v)))
                    .collect();
                return format!("source_type IN ({})", escaped.join(", "));
            }
        }

        // If match_pattern is set, use regex match
        if let Some(ref pattern) = self.match_pattern {
            if !pattern.is_empty() {
                let escaped_pattern = pattern.replace('\\', "\\\\").replace('\'', "''");
                return format!("match(source_type, '{}')", escaped_pattern);
            }
        }

        // Fall back to exact match on log source name
        format!(
            "source_type = '{}'",
            crate::sql_hygiene::escape_sql_string(&self.name)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(name: &str, match_values: Option<Vec<String>>) -> LogSourceInfo {
        LogSourceInfo {
            id: uuid::Uuid::nil(),
            name: name.to_string(),
            stale_threshold_minutes: 60,
            match_pattern: None,
            match_values,
        }
    }

    /// NAN-1620: admin-controlled `match_values` go into a ClickHouse IN-list
    /// string literal. A backslash must be doubled (`\` -> `\\`), otherwise a
    /// value like a Windows source name corrupts/breaks the literal.
    #[test]
    fn match_values_in_list_escapes_backslashes() {
        let sql = info(
            "win",
            Some(vec![r"win\evtx".to_string(), "o'brien".to_string()]),
        )
        .build_where_clause();
        assert_eq!(
            sql,
            r"source_type IN ('win\\evtx', 'o''brien')",
            "backslash must be doubled and quote doubled: {sql}"
        );
    }

    /// Name fallback path also routes through the full escaper.
    #[test]
    fn name_fallback_escapes_backslashes() {
        let sql = info(r"win\evtx", None).build_where_clause();
        assert_eq!(sql, r"source_type = 'win\\evtx'", "{sql}");
    }
}
