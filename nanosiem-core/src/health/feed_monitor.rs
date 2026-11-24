// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data feed staleness monitoring
//!
//! Monitors log sources for staleness based on configured thresholds.

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client as ClickHouseClient;
use sqlx::{PgPool, Row};
use tracing::{debug, warn};

use super::types::FeedStalenessStatus;

/// Whether this deployment is a multi-shard ClickHouse cluster, derived from the
/// `CLICKHOUSE_CLUSTER` env — `FeedMonitor` holds a bare `ClickHouseClient` (no
/// `DualPool`), so it uses the same env signal `on_cluster_clause` / retention.rs
/// use. Unset (single-node / open-core) → `TableNames::new(false)` returns the
/// bare local table, byte-identical to the pre-cluster form (NAN-1728).
fn feed_monitor_is_clustered() -> bool {
    std::env::var("CLICKHOUSE_CLUSTER")
        .ok()
        .is_some_and(|c| !c.trim().is_empty())
}

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
            // NAN-5785: an unreadable probe is "unknown", never "fresh" nor
            // "never sent": the source is skipped this pass, so its state
            // (an open alert, or none) holds until a probe succeeds.
            if let Some(status) = self.check_feed_staleness(&source).await {
                statuses.push(status);
            }
        }

        statuses
    }

    /// Get log sources that have stale alerts enabled
    async fn get_log_sources_with_alerts_enabled(&self) -> Result<Vec<LogSourceInfo>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, source_type, stale_threshold_minutes, match_pattern, match_values,
                   -- NAN-5785: the never-sent grace window starts when the
                   -- source FIRST went live, which nothing rewrites
                   -- (`deployed_at` is refreshed by every deploy and
                   -- deploy-all): the earlier of the stamped
                   -- `first_deployed_at` (migration 399) and the first
                   -- successful deployment row, else `created_at`. Never the
                   -- mutable `deployed_at`.
                   COALESCE(
                       LEAST(
                           first_deployed_at,
                           (SELECT MIN(d.deployed_at) FROM log_source_deployments d
                            WHERE d.log_source_id = log_sources.id
                              AND d.action = 'deploy' AND d.status = 'success')
                       ),
                       created_at
                   ) AS live_since
            FROM log_sources
            WHERE enabled = true AND stale_alert_enabled = true
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| {
                let match_values = r.get::<Option<Vec<String>>, _>("match_values");
                let source_type: String = r.get("source_type");
                // NAN-3659: a sparse audit stream still on the 15-minute
                // default is judged against its stream's cadence.
                let stale_threshold_minutes =
                    crate::log_sources::cadence::effective_stale_threshold_minutes(
                        r.get("stale_threshold_minutes"),
                        &crate::log_sources::cadence::route_keys(
                            &source_type,
                            match_values.as_deref(),
                        ),
                    );
                LogSourceInfo {
                    id: r.get("id"),
                    name: r.get("name"),
                    stale_threshold_minutes,
                    live_since: r.get("live_since"),
                    match_pattern: r.get("match_pattern"),
                    match_values,
                }
            })
            .collect())
    }

    /// Check staleness for a single log source
    async fn check_feed_staleness(&self, source: &LogSourceInfo) -> Option<FeedStalenessStatus> {
        let probe: Result<Option<DateTime<Utc>>, String> = if let Some(ref ch_client) = self.ch_client {
            self.get_last_event_clickhouse(ch_client, source).await
        } else {
            #[cfg(feature = "enterprise")]
            {
                self.get_last_event_postgres(&source.name).await
            }
            #[cfg(not(feature = "enterprise"))]
            {
                Err("no event store client".to_string())
            }
        };
        let last_event_at = match probe {
            Ok(last) => last,
            Err(error) => {
                warn!(log_source = %source.name, %error,
                    "Could not read the log source's last event; skipping its staleness check");
                return None;
            }
        };

        let now = Utc::now();
        let threshold = Duration::minutes(source.stale_threshold_minutes as i64);

        let (minutes_since_last_event, is_stale) =
            staleness(last_event_at, source.live_since, threshold, now);

        debug!(
            log_source = %source.name,
            last_event_at = ?last_event_at,
            minutes_since = ?minutes_since_last_event,
            threshold_minutes = %source.stale_threshold_minutes,
            is_stale = %is_stale,
            "Log source staleness check"
        );

        Some(FeedStalenessStatus {
            feed_id: source.id,
            feed_name: source.name.clone(),
            last_event_at,
            stale_threshold_minutes: source.stale_threshold_minutes,
            minutes_since_last_event,
            is_stale,
        })
    }

    /// Get last event timestamp from ClickHouse
    async fn get_last_event_clickhouse(
        &self,
        ch_client: &ClickHouseClient,
        source: &LogSourceInfo,
    ) -> Result<Option<chrono::DateTime<Utc>>, String> {
        let where_clause = source.build_where_clause();
        // NAN-1241: read the active ingested-events table (ocsf_logs under OCSF)
        // so feed staleness reflects where events actually land. UDM-identical.
        // NAN-1728 (H5): route through the `_distributed` wrapper on a cluster so
        // `max(timestamp)` reflects ALL shards (otherwise the newest event on
        // another shard is invisible → false stale-feed alerts). `FeedMonitor`
        // holds a bare `ClickHouseClient` (no `DualPool`), so cluster mode comes
        // from the `CLICKHOUSE_CLUSTER` env — unset → bare local name,
        // byte-identical on single-node.
        let logs_table = crate::db::TableNames::new(feed_monitor_is_clustered())
            .read_bare(crate::schema::active_logs_table());
        let sql = format!(
            r#"
            SELECT max(timestamp) as last_event_at
            FROM {logs_table}
            WHERE {where_clause}
            "#,
        );

        let mut cursor = ch_client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| e.to_string())?;
        let mut response_bytes = Vec::new();
        while let Some(chunk) = cursor.next().await.map_err(|e| e.to_string())? {
            response_bytes.extend_from_slice(&chunk);
        }
        let response = String::from_utf8(response_bytes).map_err(|e| e.to_string())?;
        parse_last_event_response(&response)
    }

    /// Get last event timestamp from PostgreSQL
    #[cfg(feature = "enterprise")]
    async fn get_last_event_postgres(&self, feed_name: &str) -> Result<Option<chrono::DateTime<Utc>>, String> {
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
        .map_err(|e| e.to_string())?;

        Ok(row.and_then(|r| r.get("last_event_at")))
    }
}

/// Parse the `JSONEachRow` answer of the `max(timestamp)` probe. ClickHouse
/// answers `1970-01-01 00:00:00` (or an empty value) when the source has no
/// events: that is `Ok(None)`. Anything unreadable is an error, so the caller
/// treats the source as unknown rather than as never having sent.
fn parse_last_event_response(response: &str) -> Result<Option<DateTime<Utc>>, String> {
    let line = response
        .lines()
        .next()
        .ok_or_else(|| "empty last-event response".to_string())?;
    let json: serde_json::Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
    let value = json
        .get("last_event_at")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "last_event_at missing from the response".to_string())?;
    if value.is_empty() || value.starts_with("1970-01-01") {
        return Ok(None);
    }
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
        .map(|dt| Some(dt.and_utc()))
        .map_err(|e| format!("unreadable last_event_at {value:?}: {e}"))
}

/// Whether a source is stale, and how many minutes since its last event.
///
/// NAN-5785: a source that has never sent anything is not stale while it is
/// still inside its first threshold window since it went live (its first
/// successful deploy, or creation when it never deployed): a just-published
/// source is awaiting its first events, not "stopped". Past that window it is
/// flagged, since a source that should be sending and never has is worth an
/// alert. Not being stale never closes an open alert (see the scheduler's
/// recovery rule).
pub(crate) fn staleness(
    last_event_at: Option<DateTime<Utc>>,
    live_since: DateTime<Utc>,
    threshold: Duration,
    now: DateTime<Utc>,
) -> (Option<i64>, bool) {
    match last_event_at {
        Some(last) => {
            let since = now.signed_duration_since(last);
            (Some(since.num_minutes()), since > threshold)
        }
        None => (None, now.signed_duration_since(live_since) > threshold),
    }
}

struct LogSourceInfo {
    id: uuid::Uuid,
    name: String,
    stale_threshold_minutes: i32,
    /// When the source first went live (`first_deployed_at` / first
    /// successful deployment row), else `created_at`.
    live_since: DateTime<Utc>,
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
                let escaped_pattern = crate::sql_hygiene::escape_sql_string(pattern);
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
            live_since: Utc::now(),
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

    /// NAN-5785: a just-published source with no events is awaiting its first
    /// events, not stale; once its first threshold window has passed with
    /// nothing received, it is flagged.
    #[test]
    fn never_sent_source_is_stale_only_after_its_first_threshold_window() {
        let now = Utc::now();
        let threshold = Duration::minutes(15);
        assert_eq!(staleness(None, now - Duration::minutes(5), threshold, now), (None, false));
        assert_eq!(staleness(None, now - Duration::minutes(16), threshold, now), (None, true));
    }

    /// NAN-5785: an unreadable probe answer is an error (unknown), never
    /// "no events"; ClickHouse's epoch answer for an empty source is `None`.
    #[test]
    fn last_event_response_distinguishes_no_events_from_unreadable() {
        assert_eq!(parse_last_event_response(r#"{"last_event_at":"1970-01-01 00:00:00.000"}"#), Ok(None));
        assert_eq!(
            parse_last_event_response(r#"{"last_event_at":"2026-11-21 05:00:00.123"}"#)
                .unwrap()
                .map(|t| t.to_rfc3339()),
            Some("2026-11-21T05:00:00.123+00:00".to_string())
        );
        assert!(parse_last_event_response("").is_err());
        assert!(parse_last_event_response("Code: 241. DB::Exception: memory limit").is_err());
        assert!(parse_last_event_response(r#"{"other":1}"#).is_err());
        assert!(parse_last_event_response(r#"{"last_event_at":"garbage"}"#).is_err());
    }

    /// A source that has sent is judged by its last event, not its age.
    #[test]
    fn sending_source_is_judged_by_its_last_event() {
        let now = Utc::now();
        let threshold = Duration::minutes(15);
        let old = now - Duration::days(30);
        assert_eq!(
            staleness(Some(now - Duration::minutes(3)), old, threshold, now),
            (Some(3), false)
        );
        assert_eq!(
            staleness(Some(now - Duration::minutes(20)), now, threshold, now),
            (Some(20), true)
        );
    }
}
