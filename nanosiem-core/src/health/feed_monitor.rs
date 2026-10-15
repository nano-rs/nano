// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data feed staleness monitoring
//!
//! Monitors log sources for staleness based on configured thresholds.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use clickhouse::Client as ClickHouseClient;
use sqlx::{PgPool, Row};
use tracing::{debug, warn};

use super::types::FeedStalenessStatus;

/// NAN-3464: the newest event per `metadata.log_source` on the object lake.
///
/// A lake deployment has no ClickHouse or PostgreSQL `logs` table, so the
/// legacy `max(timestamp)` read found nothing and every source was "stopped
/// sending" forever. This is the same lake read `/api/log-sources/{id}/health`
/// serves (a `stats … max(time)` over the window), issued once per tick for
/// every source instead of once per source.
#[async_trait::async_trait]
pub trait LakeFeedFreshness: Send + Sync {
    /// `metadata.log_source` → newest event time in `[start, end]`. A source
    /// with no event in the window is absent. An error means "unknown", never
    /// "stale".
    async fn last_event_by_source(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<HashMap<String, DateTime<Utc>>, String>;
}

/// The lake query behind [`LakeFeedFreshness`] for the search service.
pub const LAKE_FEED_FRESHNESS_QUERY: &str =
    "metadata.log_source!=\"\" | stats max(time) as last_time by metadata.log_source";

/// Most distinct sources one freshness read returns.
const LAKE_FEED_FRESHNESS_SOURCE_CAP: usize = 10_000;

/// The window of the per-tick freshness read. It runs every scheduler tick,
/// so it stays bounded whatever thresholds are configured.
const LAKE_FEED_FRESHNESS_TICK_WINDOW_MINUTES: i64 = 24 * 60;

/// The longest window the follow-up read scans, issued only for silent
/// sources whose threshold exceeds the tick window. A longer threshold with
/// nothing in this window is left undecided.
const LAKE_FEED_FRESHNESS_MAX_WINDOW_MINUTES: i64 = 30 * 24 * 60;

#[async_trait::async_trait]
impl LakeFeedFreshness for crate::search::SearchService {
    async fn last_event_by_source(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<HashMap<String, DateTime<Utc>>, String> {
        let request = crate::search::SearchRequest {
            query: LAKE_FEED_FRESHNESS_QUERY.to_string(),
            time_range: crate::search::TimeRangeInput::new(start, end),
            limit: Some(LAKE_FEED_FRESHNESS_SOURCE_CAP),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        // The monitor reads on behalf of the deployment's admins, never for a
        // restricted member (same as the scheduled SIEM-health collector).
        let response = self
            .search(request, &crate::auth::ScopeSet::unrestricted())
            .await
            .map_err(|error| error.to_string())?;
        Ok(last_events_from_rows(&response.results))
    }
}

/// Fold `stats max(time) as last_time by metadata.log_source` rows.
fn last_events_from_rows(rows: &[serde_json::Value]) -> HashMap<String, DateTime<Utc>> {
    rows.iter()
        .filter_map(|row| {
            let source = row
                .get("metadata.log_source")
                .or_else(|| row.get("metadata").and_then(|m| m.get("log_source")))?
                .as_str()?
                .trim();
            let last = parse_lake_time(row.get("last_time")?.as_str()?)?;
            (!source.is_empty()).then(|| (source.to_string(), last))
        })
        .collect()
}

fn parse_lake_time(value: &str) -> Option<DateTime<Utc>> {
    chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
        .ok()
        .map(|value| value.and_utc())
        .or_else(|| DateTime::parse_from_rfc3339(value).ok().map(|value| value.to_utc()))
        .filter(|value| value.timestamp() > 0)
}

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
    /// NAN-3464: set on a lake deployment; the legacy tables are not read.
    lake: Option<Arc<dyn LakeFeedFreshness>>,
}

impl FeedMonitor {
    /// Create monitor with PostgreSQL only
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            ch_client: None,
            lake: None,
        }
    }

    /// Create monitor with ClickHouse support
    pub fn with_clickhouse(pool: PgPool, ch_client: ClickHouseClient) -> Self {
        Self {
            pool,
            ch_client: Some(ch_client),
            lake: None,
        }
    }

    /// NAN-3464: read source freshness from the object lake.
    pub fn with_lake_freshness(mut self, lake: Arc<dyn LakeFeedFreshness>) -> Self {
        self.lake = Some(lake);
        self
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

        if let Some(lake) = self.lake.as_ref() {
            return Self::check_lake_feeds(lake.as_ref(), &sources, Utc::now()).await;
        }

        for source in sources {
            let last_event_at = if let Some(ref ch_client) = self.ch_client {
                self.get_last_event_clickhouse(ch_client, &source).await
            } else {
                self.get_last_event_postgres(&source.name).await
            };
            if let Some(status) = staleness(&source, last_event_at, true, Utc::now()) {
                statuses.push(status);
            }
        }

        statuses
    }

    /// NAN-3464: one lake read per tick over the longest threshold window.
    async fn check_lake_feeds(
        lake: &dyn LakeFeedFreshness,
        sources: &[LogSourceInfo],
        now: DateTime<Utc>,
    ) -> Vec<FeedStalenessStatus> {
        let mut statuses = Vec::new();
        let mut pending = sources.iter().collect::<Vec<_>>();
        for cap in [
            LAKE_FEED_FRESHNESS_TICK_WINDOW_MINUTES,
            LAKE_FEED_FRESHNESS_MAX_WINDOW_MINUTES,
        ] {
            let Some(longest) = pending
                .iter()
                .map(|source| i64::from(source.stale_threshold_minutes.max(1)))
                .max()
            else {
                break;
            };
            let window = Duration::minutes(longest.min(cap));
            let last_events = match lake.last_event_by_source(now - window, now).await {
                Ok(last_events) => last_events,
                Err(error) => {
                    // Unknown is not stale: leave every open episode as it is.
                    warn!(%error, "Lake feed freshness read failed; skipping this staleness check");
                    break;
                }
            };
            let mut undecided = Vec::new();
            for source in pending {
                let last_event_at = source.lake_last_event(&last_events);
                let window_covers_threshold =
                    window >= Duration::minutes(i64::from(source.stale_threshold_minutes));
                match staleness(source, last_event_at, window_covers_threshold, now) {
                    Some(status) => statuses.push(status),
                    None => undecided.push(source),
                }
            }
            // Only a silent source with a threshold past the tick window
            // costs the wider follow-up read.
            pending = undecided;
        }
        statuses
    }

    /// Get log sources that have stale alerts enabled
    async fn get_log_sources_with_alerts_enabled(&self) -> Result<Vec<LogSourceInfo>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, source_type, stale_threshold_minutes, match_pattern, match_values,
                   created_at
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
                source_type: r.get("source_type"),
                stale_threshold_minutes: r.get("stale_threshold_minutes"),
                match_pattern: r.get("match_pattern"),
                match_values: r.get::<Option<Vec<String>>, _>("match_values"),
                created_at: r.get("created_at"),
            })
            .collect())
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

/// One source's verdict, or `None` when it cannot be decided this tick.
///
/// `absence_is_conclusive` says whether "no event found" proves the source
/// sent nothing within its threshold (a lake window shorter than the
/// threshold proves nothing). NAN-3464: a source that has never sent is not
/// stale until `created_at + threshold` has passed; the old `None => stale`
/// flagged a freshly deployed source before its first event could land.
fn staleness(
    source: &LogSourceInfo,
    last_event_at: Option<DateTime<Utc>>,
    absence_is_conclusive: bool,
    now: DateTime<Utc>,
) -> Option<FeedStalenessStatus> {
    let threshold = Duration::minutes(i64::from(source.stale_threshold_minutes));
    let (minutes_since_last_event, is_stale) = match last_event_at {
        Some(last) => {
            let since = now.signed_duration_since(last);
            (Some(since.num_minutes()), since > threshold)
        }
        None if !absence_is_conclusive => return None,
        None => (
            None,
            source
                .created_at
                .is_none_or(|created_at| now.signed_duration_since(created_at) > threshold),
        ),
    };

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

struct LogSourceInfo {
    id: uuid::Uuid,
    name: String,
    /// Transport lane (`routed`, `http`, …); also a lake label for direct
    /// sources.
    source_type: String,
    stale_threshold_minutes: i32,
    match_pattern: Option<String>,
    match_values: Option<Vec<String>>,
    created_at: Option<DateTime<Utc>>,
}

impl LogSourceInfo {
    /// NAN-3464: the `metadata.log_source` labels this entry answers for on
    /// the lake — the same set `/api/log-sources/{id}/health` queries:
    /// `match_values`, plus the transport `source_type` unless it is the
    /// shared `routed` lane.
    fn lake_labels(&self) -> Vec<&str> {
        let mut labels = self
            .match_values
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        let transport = self.source_type.trim();
        if transport != "routed" && !transport.is_empty() {
            labels.push(transport);
        }
        labels.sort_unstable();
        labels.dedup();
        labels
    }

    /// Newest lake event among this entry's labels; a pattern-only entry
    /// matches the source names by its regex, and an entry with neither by
    /// its name.
    fn lake_last_event(&self, last_events: &HashMap<String, DateTime<Utc>>) -> Option<DateTime<Utc>> {
        let labels = self.lake_labels();
        if !labels.is_empty() {
            return labels.iter().filter_map(|label| last_events.get(*label)).max().copied();
        }
        if let Some(pattern) = self.match_pattern.as_deref().filter(|p| !p.is_empty()) {
            let regex = regex::Regex::new(pattern).ok()?;
            return last_events
                .iter()
                .filter(|(source, _)| regex.is_match(source))
                .map(|(_, last)| *last)
                .max();
        }
        last_events.get(self.name.as_str()).copied()
    }

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
            source_type: "routed".to_string(),
            stale_threshold_minutes: 60,
            match_pattern: None,
            match_values,
            created_at: None,
        }
    }

    struct FixedLake(Result<HashMap<String, DateTime<Utc>>, String>);

    #[async_trait::async_trait]
    impl LakeFeedFreshness for FixedLake {
        async fn last_event_by_source(
            &self,
            _: DateTime<Utc>,
            _: DateTime<Utc>,
        ) -> Result<HashMap<String, DateTime<Utc>>, String> {
            self.0.clone()
        }
    }

    fn source(name: &str, source_type: &str, match_values: &[&str], threshold: i32, created_minutes_ago: i64, now: DateTime<Utc>) -> LogSourceInfo {
        LogSourceInfo {
            id: uuid::Uuid::now_v7(),
            name: name.to_string(),
            source_type: source_type.to_string(),
            stale_threshold_minutes: threshold,
            match_pattern: None,
            match_values: Some(match_values.iter().map(|v| v.to_string()).collect()),
            created_at: Some(now - Duration::minutes(created_minutes_ago)),
        }
    }

    /// NAN-3464: on the lake every source read "No data has ever been
    /// received" because the monitor queried a `logs` table that does not
    /// exist there. The lake's own last event per `metadata.log_source`
    /// decides now.
    #[tokio::test]
    async fn lake_sources_are_judged_by_the_lake_last_event() {
        let now = Utc::now();
        let lake = FixedLake(Ok(HashMap::from([
            ("windows_sysmon".to_string(), now - Duration::minutes(2)),
            ("oc-sweep-source".to_string(), now - Duration::seconds(30)),
            ("aws_cloudtrail".to_string(), now - Duration::minutes(90)),
        ])));
        let sources = vec![
            source("Microsoft Sysmon", "routed", &["windows_sysmon"], 15, 600, now),
            source("oc-sweep-source", "http", &[], 15, 1, now),
            source("CloudTrail", "routed", &["aws_cloudtrail"], 60, 600, now),
            source("Silent", "routed", &["never_sent"], 15, 600, now),
            source("Just deployed", "routed", &["brand_new"], 15, 1, now),
        ];
        let statuses = FeedMonitor::check_lake_feeds(&lake, &sources, now).await;
        let verdict = |name: &str| {
            statuses
                .iter()
                .find(|status| status.feed_name == name)
                .map(|status| status.is_stale)
        };
        assert_eq!(verdict("Microsoft Sysmon"), Some(false));
        assert_eq!(verdict("oc-sweep-source"), Some(false), "the transport label is a lake label");
        assert_eq!(verdict("CloudTrail"), Some(true));
        assert_eq!(verdict("Silent"), Some(true));
        assert_eq!(verdict("Just deployed"), Some(false), "never-sent waits out created_at + threshold");
        let sysmon = statuses.iter().find(|s| s.feed_name == "Microsoft Sysmon").unwrap();
        assert_eq!(sysmon.minutes_since_last_event, Some(2));
    }

    /// An unreadable lake is unknown, never "every source stopped sending".
    #[tokio::test]
    async fn lake_read_failure_decides_nothing() {
        let now = Utc::now();
        let lake = FixedLake(Err("worker unavailable".to_string()));
        let sources = vec![source("Microsoft Sysmon", "routed", &["windows_sysmon"], 15, 600, now)];
        assert!(FeedMonitor::check_lake_feeds(&lake, &sources, now).await.is_empty());
    }

    /// A threshold longer than the bounded lake window cannot be decided
    /// from an absence; one within the follow-up window can.
    #[tokio::test]
    async fn long_thresholds_use_the_bounded_follow_up_window() {
        let now = Utc::now();
        let lake = FixedLake(Ok(HashMap::new()));
        let beyond = (LAKE_FEED_FRESHNESS_MAX_WINDOW_MINUTES + 60) as i32;
        let weekly = (7 * 24 * 60) as i32;
        let sources = vec![
            source("Beyond", "routed", &["beyond"], beyond, 100_000, now),
            source("Weekly", "routed", &["weekly"], weekly, 100_000, now),
        ];
        let statuses = FeedMonitor::check_lake_feeds(&lake, &sources, now).await;
        assert_eq!(statuses.len(), 1);
        assert_eq!((statuses[0].feed_name.as_str(), statuses[0].is_stale), ("Weekly", true));
    }

    #[test]
    fn freshness_rows_parse_lake_times() {
        let rows = vec![
            serde_json::json!({"metadata.log_source": "windows_sysmon", "last_time": "2026-10-09 01:39:09.123000"}),
            serde_json::json!({"metadata.log_source": "", "last_time": "2026-10-09 01:39:09"}),
            serde_json::json!({"metadata.log_source": "x", "last_time": "1970-01-01 00:00:00"}),
        ];
        let parsed = last_events_from_rows(&rows);
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed["windows_sysmon"].to_rfc3339(),
            "2026-10-09T01:39:09.123+00:00"
        );
        crate::query::parse_query(LAKE_FEED_FRESHNESS_QUERY).expect("freshness query must parse");
    }

    #[test]
    fn lake_labels_match_the_health_endpoint() {
        let mut entry = info("Sysmon", Some(vec!["windows_sysmon".to_string(), " ".to_string()]));
        assert_eq!(entry.lake_labels(), vec!["windows_sysmon"]);
        entry.source_type = "http".to_string();
        assert_eq!(entry.lake_labels(), vec!["http", "windows_sysmon"]);
        let pattern = LogSourceInfo {
            match_values: None,
            match_pattern: Some("^win".to_string()),
            ..info("Pattern", None)
        };
        let now = Utc::now();
        let last = HashMap::from([
            ("windows_sysmon".to_string(), now - Duration::minutes(5)),
            ("winlog".to_string(), now - Duration::minutes(1)),
            ("linux".to_string(), now),
        ]);
        assert_eq!(pattern.lake_last_event(&last), Some(now - Duration::minutes(1)));
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
            sql, r"source_type IN ('win\\evtx', 'o''brien')",
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
