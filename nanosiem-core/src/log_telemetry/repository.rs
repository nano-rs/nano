// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse repository for the per-source_type log telemetry rollup.
//!
//! All reads target `nanosiem.logs_per_source_5m` (or its `_distributed`
//! variant in cluster mode) — a 5-minute, 7-day-retained AggregatingMergeTree
//! populated by a live materialized view from `nanosiem.logs`. See
//! `clickhouse/116_logs_per_source_5m.sql`.

use chrono::{DateTime, Utc};
use clickhouse::Client as ClickHouseClient;
use std::collections::{BTreeSet, HashMap};
use tracing::warn;

use crate::search::service::source_scope_sql_predicate;

use super::types::{BucketSize, HourlyPoint, SourceTypeStats};
use crate::db::TableNames;

/// Name of the rollup table (passed through `TableNames::read` so it picks
/// the `_distributed` wrapper in cluster mode).
const ROLLUP_TABLE: &str = "logs_per_source_5m";

#[derive(Clone)]
pub struct LogTelemetryRepository {
    /// ClickHouse client used to read the `logs_per_source_5m` rollup table.
    client: ClickHouseClient,
    table_names: TableNames,
}

impl LogTelemetryRepository {
    pub fn new(client: ClickHouseClient, table_names: TableNames) -> Self {
        Self {
            client,
            table_names,
        }
    }

    /// Returns the rollup's events / bytes / last_event_at / first_event_at
    /// totals for each requested `source_type`, summed over the last
    /// `window_hours` hours.
    ///
    /// Source_types are matched **after lowercasing** at the ClickHouse side
    /// — the rollup MV writes lowercased values, so callers don't need to
    /// pre-normalize. Unsafe values (anything not `[A-Za-z0-9_-]`) are
    /// rejected at SQL-build time.
    ///
    /// The returned map may be partial — source_types with no rollup rows in
    /// the window simply don't appear (caller treats them as zero).
    ///
    /// NAN-1801 (P3 side-doors): `deny_set` is the caller's effective
    /// per-source deny set ([`crate::auth::ScopeSet`] semantics — compose it
    /// via `AuthContext::effective_source_deny_set()` in handlers). Denied
    /// source_types are excluded at the SQL layer so a scoped viewer cannot
    /// recover volume / last-seen for a source they cannot search. An empty
    /// set emits byte-identical SQL to the pre-scoping form.
    pub async fn stats_by_source_type(
        &self,
        source_types: &[String],
        window_hours: i64,
        deny_set: &BTreeSet<String>,
    ) -> Result<HashMap<String, SourceTypeStats>, RepoError> {
        let table = self.table_names.read(ROLLUP_TABLE);
        let safe = sanitize_source_types(source_types);
        let Some(sql) = build_stats_sql(&table, &safe, window_hours, deny_set) else {
            // Empty input or every entry rejected — nothing to ask about.
            return Ok(HashMap::new());
        };
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_stats_rows(&rows))
    }

    /// Returns rollup stats for **every** source_type seen in the window.
    /// Used by callers that want to display all sources at once (Dashboard,
    /// log-sources health card). Skip if you only need a few — prefer
    /// `stats_by_source_type` to keep ClickHouse work scoped.
    pub async fn stats_all(
        &self,
        window_hours: i64,
    ) -> Result<HashMap<String, SourceTypeStats>, RepoError> {
        let table = self.table_names.read(ROLLUP_TABLE);
        let sql = build_stats_all_sql(&table, window_hours);
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_stats_rows(&rows))
    }

    /// Returns per-(source_type, bucket) event counts for the ingestion
    /// history area chart. `bucket` is rounded server-side; the rollup's
    /// native 5-minute granularity is the smallest available bucket.
    ///
    /// NAN-1801: `deny_set` — see [`Self::stats_by_source_type`]. Empty set
    /// emits byte-identical SQL.
    pub async fn buckets(
        &self,
        source_types: &[String],
        window_hours: i64,
        bucket: BucketSize,
        deny_set: &BTreeSet<String>,
    ) -> Result<Vec<HourlyPoint>, RepoError> {
        let table = self.table_names.read(ROLLUP_TABLE);
        let safe = sanitize_source_types(source_types);
        let Some(sql) = build_buckets_sql(&table, &safe, window_hours, bucket, deny_set) else {
            return Ok(Vec::new());
        };
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_bucket_rows(&rows))
    }

    /// Returns cluster-wide per-bucket totals (no source_type filter). Used by
    /// the dashboard activity timeline which wants `events_per_hour` summed
    /// across every source. Each `HourlyPoint`'s `source_type` is empty.
    pub async fn buckets_all(
        &self,
        window_hours: i64,
        bucket: BucketSize,
    ) -> Result<Vec<HourlyPoint>, RepoError> {
        let table = self.table_names.read(ROLLUP_TABLE);
        let sql = build_buckets_all_sql(&table, window_hours, bucket);
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_bucket_all_rows(&rows))
    }

    /// Returns the cluster-wide total event count for a window. Used by the
    /// dashboard's "events_24h / events_1h" headline numbers.
    pub async fn total_events(&self, window_hours: i64) -> Result<i64, RepoError> {
        let table = self.table_names.read(ROLLUP_TABLE);
        let sql = build_total_events_sql(&table, window_hours);
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_total_events(&rows))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("ClickHouse query failed: {0}")]
    ClickHouse(String),
    #[error("Invalid UTF-8 in ClickHouse response: {0}")]
    Encoding(String),
}

// ============================================================================
// SQL builders — pure functions, unit-tested below.
// ============================================================================

/// Allow-list filter for `source_type` values used in the SQL `IN (...)`
/// clause. Mirrors the same defensive filter as
/// `nanosiem-api/src/handlers/source_configs.rs::is_safe_source_type` — kept
/// here so every caller of the rollup benefits.
pub fn is_safe_source_type(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Filter `source_types` down to safe entries and warn for any rejected.
pub fn sanitize_source_types(source_types: &[String]) -> Vec<String> {
    let total = source_types.len();
    let safe: Vec<String> = source_types
        .iter()
        .filter(|s| is_safe_source_type(s))
        .map(|s| s.to_lowercase())
        .collect();
    if safe.len() < total {
        warn!(
            rejected = total - safe.len(),
            "Rejected source_types containing unsafe chars from rollup IN clause"
        );
    }
    safe
}

/// SQL for `stats_by_source_type`. Returns `None` when the safe input is
/// empty so the caller can skip the round-trip.
///
/// NAN-1801: per-source builder — `deny_set` appends the shared
/// `lower(source_type) NOT IN (...)` scope predicate (see
/// [`source_scope_sql_predicate`]). Empty deny set = byte-identical SQL.
pub fn build_stats_sql(
    table: &str,
    safe_source_types: &[String],
    window_hours: i64,
    deny_set: &BTreeSet<String>,
) -> Option<String> {
    if safe_source_types.is_empty() {
        return None;
    }
    let in_clause = safe_source_types
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ");
    let scope_and = source_scope_sql_predicate("source_type", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    Some(format!(
        "SELECT \
            source_type, \
            sum(events) AS events, \
            sum(bytes) AS bytes, \
            max(last_event_at) AS last_event_at, \
            min(first_event_at) AS first_event_at \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND source_type IN ({in_clause}){scope_and} \
         GROUP BY source_type"
    ))
}

/// SQL for `stats_all`. No IN-clause filter — returns every source_type with
/// rows in the window.
pub fn build_stats_all_sql(table: &str, window_hours: i64) -> String {
    format!(
        "SELECT \
            source_type, \
            sum(events) AS events, \
            sum(bytes) AS bytes, \
            max(last_event_at) AS last_event_at, \
            min(first_event_at) AS first_event_at \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
         GROUP BY source_type"
    )
}

/// SQL for `buckets`. Server-side rebucketing via `bucket.group_expr()`.
///
/// NAN-1801: per-source builder — `deny_set` appends the shared scope
/// predicate; empty deny set = byte-identical SQL.
pub fn build_buckets_sql(
    table: &str,
    safe_source_types: &[String],
    window_hours: i64,
    bucket: BucketSize,
    deny_set: &BTreeSet<String>,
) -> Option<String> {
    if safe_source_types.is_empty() {
        return None;
    }
    let in_clause = safe_source_types
        .iter()
        .map(|s| format!("'{}'", s))
        .collect::<Vec<_>>()
        .join(", ");
    let group_expr = bucket.group_expr();
    let scope_and = source_scope_sql_predicate("source_type", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    Some(format!(
        "SELECT \
            source_type, \
            {group_expr} AS bucket, \
            sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND source_type IN ({in_clause}){scope_and} \
         GROUP BY source_type, bucket \
         ORDER BY bucket ASC"
    ))
}

/// SQL for `buckets_all`. No source_type filter — sums every source per bucket
/// for the dashboard activity timeline. Always emits SQL (no empty-input
/// guard) since there's no IN clause to gate on.
pub fn build_buckets_all_sql(table: &str, window_hours: i64, bucket: BucketSize) -> String {
    let group_expr = bucket.group_expr();
    format!(
        "SELECT \
            {group_expr} AS bucket, \
            sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
         GROUP BY bucket \
         ORDER BY bucket ASC"
    )
}

/// SQL for `total_events`. Cluster-wide sum across every bucket in the window.
pub fn build_total_events_sql(table: &str, window_hours: i64) -> String {
    format!(
        "SELECT sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR"
    )
}

// ============================================================================
// JSONEachRow execution + parsing.
// ============================================================================

async fn run_jsoneachrow(client: &ClickHouseClient, sql: &str) -> Result<String, RepoError> {
    let mut cursor = client
        .query(sql)
        .fetch_bytes("JSONEachRow")
        .map_err(|e| RepoError::ClickHouse(e.to_string()))?;
    let mut buf = Vec::new();
    while let Some(chunk) = cursor
        .next()
        .await
        .map_err(|e| RepoError::ClickHouse(e.to_string()))?
    {
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|e| RepoError::Encoding(e.to_string()))
}

fn parse_stats_rows(body: &str) -> HashMap<String, SourceTypeStats> {
    let mut out: HashMap<String, SourceTypeStats> = HashMap::new();
    for line in body.lines() {
        if line.is_empty() {
            continue;
        }
        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let source_type = json
            .get("source_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        if source_type.is_empty() {
            continue;
        }
        out.insert(
            source_type.clone(),
            SourceTypeStats {
                source_type,
                events: parse_u64(&json, "events"),
                bytes: parse_u64(&json, "bytes"),
                last_event_at: parse_clickhouse_datetime(&json, "last_event_at"),
                first_event_at: parse_clickhouse_datetime(&json, "first_event_at"),
            },
        );
    }
    out
}

fn parse_bucket_rows(body: &str) -> Vec<HourlyPoint> {
    let mut out = Vec::new();
    for line in body.lines() {
        if line.is_empty() {
            continue;
        }
        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let source_type = json
            .get("source_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase();
        let Some(bucket_start) = parse_clickhouse_datetime(&json, "bucket") else {
            continue;
        };
        out.push(HourlyPoint {
            source_type,
            bucket_start,
            events: parse_u64(&json, "events"),
        });
    }
    out
}

/// Parses cluster-wide bucket rows (no source_type column). Each emitted
/// `HourlyPoint` has an empty `source_type` string.
fn parse_bucket_all_rows(body: &str) -> Vec<HourlyPoint> {
    let mut out = Vec::new();
    for line in body.lines() {
        if line.is_empty() {
            continue;
        }
        let Ok(json) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(bucket_start) = parse_clickhouse_datetime(&json, "bucket") else {
            continue;
        };
        out.push(HourlyPoint {
            source_type: String::new(),
            bucket_start,
            events: parse_u64(&json, "events"),
        });
    }
    out
}

fn parse_total_events(body: &str) -> i64 {
    body.lines()
        .find(|line| !line.is_empty())
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .map(|json| parse_u64(&json, "events") as i64)
        .unwrap_or(0)
}

/// ClickHouse encodes UInt64 as JSON strings (number is too big for
/// double-precision); also tolerate plain numbers for safety.
fn parse_u64(json: &serde_json::Value, key: &str) -> u64 {
    match json.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.parse::<u64>().unwrap_or(0),
        _ => 0,
    }
}

/// ClickHouse default DateTime serialization is `"YYYY-MM-DD HH:MM:SS"`
/// (no fractional in the rollup since we use plain `DateTime`, not
/// `DateTime64`). Tolerate the fractional form too in case someone later
/// promotes the columns.
fn parse_clickhouse_datetime(json: &serde_json::Value, key: &str) -> Option<DateTime<Utc>> {
    json.get(key)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty() && !s.starts_with("1970-01-01"))
        .and_then(|s| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S"))
                .ok()
        })
        .map(|dt| dt.and_utc())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_safe_source_type_accepts_typical_values() {
        assert!(is_safe_source_type("limacharlie_edr"));
        assert!(is_safe_source_type("aws-cloudtrail"));
        assert!(is_safe_source_type("microsoft_sysmon_json"));
        assert!(is_safe_source_type("ABC_def-123"));
    }

    #[test]
    fn is_safe_source_type_rejects_quote_breakouts_and_whitespace() {
        assert!(!is_safe_source_type(""));
        assert!(!is_safe_source_type("foo'OR'1'='1"));
        assert!(!is_safe_source_type("foo bar"));
        assert!(!is_safe_source_type("foo;DROP TABLE logs"));
        assert!(!is_safe_source_type("foo\\bar"));
        assert!(!is_safe_source_type("foo.bar"));
    }

    #[test]
    fn sanitize_source_types_lowercases_and_filters() {
        let input = vec![
            "LimaCharlie_EDR".to_string(),
            "foo'; DROP TABLE logs".to_string(),
            "AWS-CloudTrail".to_string(),
        ];
        let safe = sanitize_source_types(&input);
        assert_eq!(safe.len(), 2);
        assert!(safe.contains(&"limacharlie_edr".to_string()));
        assert!(safe.contains(&"aws-cloudtrail".to_string()));
    }

    fn no_deny() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn build_stats_sql_returns_none_for_empty_input() {
        assert!(build_stats_sql("nanosiem.logs_per_source_5m", &[], 24, &no_deny()).is_none());
    }

    #[test]
    fn build_stats_sql_partition_prunes_and_scopes_in_clause() {
        let safe = vec!["limacharlie_edr".to_string(), "aws-cloudtrail".to_string()];
        let sql = build_stats_sql("nanosiem.logs_per_source_5m", &safe, 24, &no_deny()).unwrap();
        assert!(
            sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"),
            "must keep the 24h bound, got: {sql}"
        );
        assert!(
            sql.contains("AND source_type IN ('limacharlie_edr', 'aws-cloudtrail')"),
            "expected scoped IN clause, got: {sql}"
        );
        assert!(sql.contains("sum(events) AS events"));
        assert!(sql.contains("sum(bytes) AS bytes"));
        assert!(sql.contains("max(last_event_at)"));
        assert!(sql.contains("min(first_event_at)"));
    }

    #[test]
    fn build_stats_sql_uses_provided_table_name() {
        let safe = vec!["foo".to_string()];
        let sql =
            build_stats_sql("nanosiem.logs_per_source_5m_distributed", &safe, 1, &no_deny())
                .unwrap();
        assert!(
            sql.contains("FROM nanosiem.logs_per_source_5m_distributed"),
            "got: {sql}"
        );
    }

    #[test]
    fn build_stats_all_sql_omits_in_clause() {
        let sql = build_stats_all_sql("nanosiem.logs_per_source_5m", 24);
        assert!(sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"));
        assert!(!sql.contains("source_type IN"));
        assert!(sql.contains("GROUP BY source_type"));
    }

    #[test]
    fn build_buckets_sql_groups_by_hour_when_requested() {
        let safe = vec!["limacharlie_edr".to_string()];
        let sql = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            &safe,
            24,
            BucketSize::Hour,
            &no_deny(),
        )
        .unwrap();
        assert!(sql.contains("toStartOfHour(bucket_start) AS bucket"));
        assert!(sql.contains("ORDER BY bucket ASC"));
    }

    #[test]
    fn build_buckets_sql_uses_native_5m_buckets() {
        let safe = vec!["foo".to_string()];
        let sql = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            &safe,
            1,
            BucketSize::FiveMin,
            &no_deny(),
        )
        .unwrap();
        // FiveMin selects the column directly — no re-bucket function.
        assert!(sql.contains("bucket_start AS bucket"), "got: {sql}");
        assert!(!sql.contains("toStartOf"), "5min must not call a re-bucket fn, got: {sql}");
    }

    #[test]
    fn build_buckets_sql_returns_none_for_empty_input() {
        assert!(build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            &[],
            1,
            BucketSize::Hour,
            &no_deny()
        )
        .is_none());
    }

    // ------------------------------------------------------------------
    // NAN-1801: per-source scope predicate threading
    // ------------------------------------------------------------------

    #[test]
    fn build_stats_sql_empty_deny_set_is_byte_identical() {
        let safe = vec!["foo".to_string()];
        let sql = build_stats_sql("nanosiem.logs_per_source_5m", &safe, 24, &no_deny()).unwrap();
        assert!(!sql.contains("NOT IN"), "got: {sql}");
        assert!(!sql.contains("!="), "got: {sql}");
    }

    #[test]
    fn build_stats_sql_appends_scope_predicate_before_group_by() {
        let safe = vec!["foo".to_string(), "audit".to_string()];
        let deny: BTreeSet<String> = ["audit".to_string(), "LimaCharlie_EDR".to_string()]
            .into_iter()
            .collect();
        let sql = build_stats_sql("nanosiem.logs_per_source_5m", &safe, 24, &deny).unwrap();
        // BTreeSet order is lexicographic; predicate lowercases values.
        assert!(
            sql.contains(
                "AND lower(source_type) NOT IN ('limacharlie_edr', 'audit')"
            ) || sql.contains("AND lower(source_type) NOT IN ('audit', 'limacharlie_edr')"),
            "expected scope predicate, got: {sql}"
        );
        let pred_pos = sql.find("NOT IN").unwrap();
        let group_pos = sql.find("GROUP BY").unwrap();
        assert!(pred_pos < group_pos, "predicate must precede GROUP BY: {sql}");
    }

    #[test]
    fn build_stats_sql_single_denied_source_uses_inequality_form() {
        let safe = vec!["foo".to_string()];
        let deny: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
        let sql = build_stats_sql("nanosiem.logs_per_source_5m", &safe, 24, &deny).unwrap();
        assert!(
            sql.contains("AND lower(source_type) != 'audit'"),
            "expected single-value inequality form, got: {sql}"
        );
    }

    #[test]
    fn build_buckets_sql_appends_scope_predicate() {
        let safe = vec!["foo".to_string()];
        let deny: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
        let sql = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            &safe,
            24,
            BucketSize::Hour,
            &deny,
        )
        .unwrap();
        assert!(
            sql.contains("AND lower(source_type) != 'audit'"),
            "expected scope predicate, got: {sql}"
        );
        let empty = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            &safe,
            24,
            BucketSize::Hour,
            &no_deny(),
        )
        .unwrap();
        assert!(!empty.contains("!= 'audit'"), "got: {empty}");
    }

    #[test]
    fn cluster_wide_builders_are_never_scope_predicated() {
        // NAN-1801 guard: buckets_all / total_events / stats_all have no
        // per-viewer deny parameter BY DESIGN — buckets_all and total_events
        // have no source_type dimension (predicating them would silently
        // shrink cluster-wide headline numbers per viewer), and stats_all's
        // consumers are covered by their own scoping seams.
        let a = build_buckets_all_sql("nanosiem.logs_per_source_5m", 24, BucketSize::Hour);
        let b = build_total_events_sql("nanosiem.logs_per_source_5m", 24);
        assert!(!a.contains("NOT IN") && !a.contains("lower(source_type)"), "got: {a}");
        assert!(!b.contains("NOT IN") && !b.contains("lower(source_type)"), "got: {b}");
    }

    #[test]
    fn build_buckets_all_sql_omits_in_clause_and_source_type_column() {
        let sql = build_buckets_all_sql("nanosiem.logs_per_source_5m", 24, BucketSize::Hour);
        assert!(sql.contains("toStartOfHour(bucket_start) AS bucket"));
        assert!(sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"));
        assert!(!sql.contains("source_type IN"), "got: {sql}");
        // Cluster-wide aggregate doesn't include source_type in SELECT.
        assert!(!sql.contains("source_type,"), "got: {sql}");
        assert!(sql.contains("GROUP BY bucket"));
        assert!(sql.contains("ORDER BY bucket ASC"));
    }

    #[test]
    fn build_total_events_sql_no_grouping() {
        let sql = build_total_events_sql("nanosiem.logs_per_source_5m", 24);
        assert!(sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"));
        assert!(sql.contains("sum(events) AS events"));
        assert!(!sql.contains("GROUP BY"));
    }

    #[test]
    fn parse_total_events_returns_zero_when_empty() {
        assert_eq!(parse_total_events(""), 0);
        assert_eq!(parse_total_events("\n"), 0);
    }

    #[test]
    fn parse_total_events_handles_string_uint64() {
        let body = r#"{"events":"1234567"}"#;
        assert_eq!(parse_total_events(body), 1234567);
    }

    #[test]
    fn parse_bucket_all_rows_strips_source_type() {
        let body = r#"{"bucket":"2026-05-04 18:00:00","events":"42"}"#;
        let points = parse_bucket_all_rows(body);
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].source_type, "");
        assert_eq!(points[0].events, 42);
    }

    #[test]
    fn parse_stats_rows_handles_string_uint64() {
        let body = r#"{"source_type":"aws-cloudtrail","events":"42","bytes":"1024","last_event_at":"2026-05-04 18:40:58","first_event_at":"2026-05-04 17:00:00"}"#;
        let map = parse_stats_rows(body);
        let s = map.get("aws-cloudtrail").expect("row should parse");
        assert_eq!(s.events, 42);
        assert_eq!(s.bytes, 1024);
        assert!(s.last_event_at.is_some());
        assert!(s.first_event_at.is_some());
    }

    #[test]
    fn parse_stats_rows_skips_empty_source_type() {
        let body = "{\"source_type\":\"\",\"events\":\"1\"}\n{\"source_type\":\"foo\",\"events\":\"2\"}";
        let map = parse_stats_rows(body);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("foo"));
    }

    #[test]
    fn parse_stats_rows_zero_when_clickhouse_returns_epoch() {
        // ClickHouse returns 1970-01-01 for max() over empty set; treat as None.
        let body = r#"{"source_type":"foo","events":"0","bytes":"0","last_event_at":"1970-01-01 00:00:00","first_event_at":"1970-01-01 00:00:00"}"#;
        let map = parse_stats_rows(body);
        let s = map.get("foo").unwrap();
        assert_eq!(s.events, 0);
        assert!(s.last_event_at.is_none());
        assert!(s.first_event_at.is_none());
    }
}
