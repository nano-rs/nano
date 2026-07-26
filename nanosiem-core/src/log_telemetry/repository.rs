// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse repository for the per-source_type log telemetry rollup.
//!
//! All reads target the profile-aware `nanosiem.logs_per_source_5m_v2` (or its
//! `_distributed` variant in cluster mode). UDM and OCSF MVs write separate
//! lanes, and every reader selects the active lane so Vector's transitional
//! dual-write is counted once. See migration 169.

use chrono::{DateTime, Utc};
use clickhouse::Client as ClickHouseClient;
use std::collections::{BTreeSet, HashMap};
use tracing::warn;

use crate::search::service::source_scope_sql_predicate;

use super::types::{BucketSize, HourlyPoint, SourceTypeStats};
use crate::db::TableNames;

/// Name of the rollup table (passed through `TableNames::read` so it picks
/// the `_distributed` wrapper in cluster mode).
const ROLLUP_TABLE: &str = "logs_per_source_5m_v2";
const ROLLUP_RETENTION_HOURS: i64 = 7 * 24;

#[derive(Clone)]
pub struct LogTelemetryRepository {
    /// ClickHouse client used to read the profile-aware source rollup.
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
        let profile = crate::schema::active_log_telemetry_profile();
        let safe = sanitize_source_types(source_types);
        let Some(sql) = build_stats_sql(&table, profile, &safe, window_hours, deny_set) else {
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
        let sql = build_stats_all_sql(
            &table,
            crate::schema::active_log_telemetry_profile(),
            window_hours,
        );
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
        let profile = crate::schema::active_log_telemetry_profile();
        let safe = sanitize_source_types(source_types);
        let Some(sql) = build_buckets_sql(&table, profile, &safe, window_hours, bucket, deny_set)
        else {
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
        deny_set: &BTreeSet<String>,
    ) -> Result<Vec<HourlyPoint>, RepoError> {
        // Longer restricted windows retain the raw fallback because the
        // seven-day rollup cannot represent expired buckets equivalently.
        let sql = if deny_set.is_empty() || window_hours <= ROLLUP_RETENTION_HOURS {
            build_buckets_all_sql(
                &self.table_names.read(ROLLUP_TABLE),
                crate::schema::active_log_telemetry_profile(),
                window_hours,
                bucket,
                deny_set,
            )
        } else {
            build_buckets_all_raw_sql(
                &self
                    .table_names
                    .read_bare(crate::schema::active_logs_table()),
                window_hours,
                bucket,
                deny_set,
            )
        };
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_bucket_all_rows(&rows))
    }

    /// Returns the cluster-wide total event count for a window. Used by the
    /// dashboard's "events_24h / events_1h" headline numbers.
    pub async fn total_events(
        &self,
        window_hours: i64,
        deny_set: &BTreeSet<String>,
    ) -> Result<i64, RepoError> {
        let sql = if deny_set.is_empty() || window_hours <= ROLLUP_RETENTION_HOURS {
            build_total_events_sql(
                &self.table_names.read(ROLLUP_TABLE),
                crate::schema::active_log_telemetry_profile(),
                window_hours,
                deny_set,
            )
        } else {
            build_total_events_raw_sql(
                &self
                    .table_names
                    .read_bare(crate::schema::active_logs_table()),
                window_hours,
                deny_set,
            )
        };
        let rows = run_jsoneachrow(&self.client, &sql).await?;
        Ok(parse_total_events(&rows))
    }

    /// Scoped event total over an explicit `[start, end)` range (NAN-2060).
    pub async fn total_events_range(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
        deny_set: &BTreeSet<String>,
    ) -> Result<i64, RepoError> {
        let within_retention =
            start >= Utc::now() - chrono::Duration::hours(ROLLUP_RETENTION_HOURS);
        let sql = if deny_set.is_empty() || within_retention {
            build_total_events_range_sql(
                &self.table_names.read(ROLLUP_TABLE),
                crate::schema::active_log_telemetry_profile(),
                start,
                end,
                deny_set,
            )
        } else {
            build_total_events_range_raw_sql(
                &self
                    .table_names
                    .read_bare(crate::schema::active_logs_table()),
                start,
                end,
                deny_set,
            )
        };
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
    profile: &str,
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
    let scope_and = rollup_scope_and(deny_set);
    Some(format!(
        "SELECT \
            source_type, \
            sum(events) AS events, \
            sum(bytes) AS bytes, \
            max(last_event_at) AS last_event_at, \
            min(first_event_at) AS first_event_at \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND schema_profile = '{profile}' \
           AND source_type IN ({in_clause}){scope_and} \
         GROUP BY source_type",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    ))
}

/// SQL for `stats_all`. No IN-clause filter — returns every source_type with
/// rows in the window.
pub fn build_stats_all_sql(table: &str, profile: &str, window_hours: i64) -> String {
    format!(
        "SELECT \
            source_type, \
            sum(events) AS events, \
            sum(bytes) AS bytes, \
            max(last_event_at) AS last_event_at, \
            min(first_event_at) AS first_event_at \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND schema_profile = '{profile}' \
         GROUP BY source_type",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    )
}

/// SQL for `buckets`. Server-side rebucketing via `bucket.group_expr()`.
///
/// NAN-1801: per-source builder — `deny_set` appends the shared scope
/// predicate; empty deny set = byte-identical SQL.
pub fn build_buckets_sql(
    table: &str,
    profile: &str,
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
    let scope_and = rollup_scope_and(deny_set);
    Some(format!(
        "SELECT \
            source_type, \
            {group_expr} AS bucket, \
            sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND schema_profile = '{profile}' \
           AND source_type IN ({in_clause}){scope_and} \
         GROUP BY source_type, bucket \
         ORDER BY bucket ASC",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    ))
}

/// Authorization suffix for the profile-aware rollup.
///
/// OCSF's display source may be a product name while canonical search scopes
/// the raw source_type. Restricted readers therefore authorize only on
/// `scope_source_type`, and reject rows whose raw provenance is incomplete.
fn rollup_scope_and(deny_set: &BTreeSet<String>) -> String {
    if deny_set.is_empty() {
        return String::new();
    }
    let predicate = source_scope_sql_predicate("scope_source_type", deny_set)
        .expect("a non-empty deny set always renders a predicate");
    format!(" AND scope_source_type_complete = 1 AND {predicate}")
}

/// SQL for `buckets_all`. No source_type IN-filter — sums every VISIBLE source
/// per bucket for the dashboard activity timeline. Always emits SQL (no
/// empty-input guard) since there's no IN clause to gate on.
///
/// NAN-2060: `deny_set` appends the shared scope predicate. NAN-1801 had left
/// this builder deliberately unscoped, reasoning that a cluster-wide headline
/// number should not shrink per viewer — but the rollup DOES carry a
/// `source_type` dimension (see [`build_stats_sql`], same table), and the
/// unscoped timeline was disclosing aggregate activity from denied feeds and
/// from `audit` to principals whose canonical search hides both. An EMPTY deny
/// set still yields byte-identical SQL, so unrestricted/SYSTEM callers keep the
/// exact cluster-wide totals.
pub fn build_buckets_all_sql(
    table: &str,
    profile: &str,
    window_hours: i64,
    bucket: BucketSize,
    deny_set: &BTreeSet<String>,
) -> String {
    let group_expr = bucket.group_expr();
    let scope_and = rollup_scope_and(deny_set);
    format!(
        "SELECT \
            {group_expr} AS bucket, \
            sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND schema_profile = '{profile}'{scope_and} \
         GROUP BY bucket \
         ORDER BY bucket ASC",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    )
}

/// SQL for `total_events`. Cluster-wide sum across every bucket in the window.
///
/// NAN-2060: scoped on the same terms as [`build_buckets_all_sql`].
pub fn build_total_events_sql(
    table: &str,
    profile: &str,
    window_hours: i64,
    deny_set: &BTreeSet<String>,
) -> String {
    let scope_and = rollup_scope_and(deny_set);
    format!(
        "SELECT sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= now() - INTERVAL {window_hours} HOUR \
           AND schema_profile = '{profile}'{scope_and}",
        profile = crate::sql_hygiene::escape_sql_string(profile),
    )
}

/// SQL for a scoped event total over an EXPLICIT `[start, end)` range.
///
/// NAN-2060: the dashboard overview needs a previous-period comparison window
/// (`now - 2h … now - h`), which the "last N hours" form above cannot express.
/// Restricted callers read their headline event counts through this builder
/// instead of `system.parts`, which has no `source_type` dimension at all and
/// therefore cannot honor a per-source boundary.
pub fn build_total_events_range_sql(
    table: &str,
    profile: &str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    deny_set: &BTreeSet<String>,
) -> String {
    let scope_and = rollup_scope_and(deny_set);
    // The rollup is 5-minute granular, and callers pass second-level `now()`
    // boundaries. Comparing those to `bucket_start` directly DROPS the partial
    // bucket the window starts inside — up to 5 minutes of a 60-minute tile,
    // ~8% low.
    //
    // BOTH bounds snap down to their bucket. Flooring only the lower bound
    // (the first attempt at this) makes adjacent periods OVERLAP: current
    // `[10:03, 11:03)` → `>= 10:00, < 11:03` and previous `[09:03, 10:03)` →
    // `>= 09:00, < 10:03` both contain the whole 10:00 bucket, so it is counted
    // twice and every trend comparison is distorted. Snapping both makes the
    // ranges exactly abut: `[10:00, 11:00)` and `[09:00, 10:00)`.
    //
    // The cost is that the in-progress bucket at `now` is excluded, so a
    // "last hour" tile can lag reality by up to 5 minutes. That is the right
    // trade here: these numbers exist to be COMPARED against the previous
    // period, and a consistent, disjoint, exactly-one-hour window matters more
    // than the freshest 5 minutes. It also errs low rather than high.
    format!(
        "SELECT sum(events) AS events \
         FROM {table} \
         WHERE bucket_start >= '{}' AND bucket_start < '{}' \
           AND schema_profile = '{profile}'{scope_and}",
        floor_to_bucket(start).format("%Y-%m-%d %H:%M:%S"),
        floor_to_bucket(end).format("%Y-%m-%d %H:%M:%S"),
        profile = crate::sql_hygiene::escape_sql_string(profile),
    )
}

/// Snap a timestamp down to the rollup's 5-minute bucket boundary.
fn floor_to_bucket(ts: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    const BUCKET_SECS: i64 = 300;
    let rem = ts.timestamp().rem_euclid(BUCKET_SECS);
    ts - chrono::Duration::seconds(rem)
}

/// Raw-events counterpart of [`build_total_events_sql`] — the "last N hours"
/// window form, used when [`rollup_scope_is_authoritative`] refuses the rollup.
pub fn build_total_events_raw_sql(
    logs_table: &str,
    window_hours: i64,
    deny_set: &BTreeSet<String>,
) -> String {
    let scope_and = source_scope_sql_predicate("source_type", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        "SELECT count() AS events \
         FROM {logs_table} \
         WHERE timestamp >= now() - INTERVAL {window_hours} HOUR{scope_and}"
    )
}

/// Raw-events counterpart of [`build_total_events_range_sql`], used when
/// [`rollup_scope_is_authoritative`] says the rollup key cannot carry the
/// caller's scope. Counts rows instead of summing pre-aggregated buckets, and
/// filters the RAW `source_type` the deny-set is actually defined over.
pub fn build_total_events_range_raw_sql(
    logs_table: &str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    deny_set: &BTreeSet<String>,
) -> String {
    let scope_and = source_scope_sql_predicate("source_type", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        "SELECT count() AS events \
         FROM {logs_table} \
         WHERE timestamp >= '{}' AND timestamp < '{}'{scope_and}",
        start.format("%Y-%m-%d %H:%M:%S"),
        end.format("%Y-%m-%d %H:%M:%S")
    )
}

/// Raw-events counterpart of [`build_buckets_all_sql`] — see
/// [`rollup_scope_is_authoritative`] for when this is used instead.
pub fn build_buckets_all_raw_sql(
    logs_table: &str,
    window_hours: i64,
    bucket: BucketSize,
    deny_set: &BTreeSet<String>,
) -> String {
    // The rollup's group expressions are written against `bucket_start`; the
    // raw table's time column is `timestamp`.
    let group_expr = match bucket {
        BucketSize::FiveMin => "toStartOfFiveMinute(timestamp)",
        BucketSize::Hour => "toStartOfHour(timestamp)",
    };
    let scope_and = source_scope_sql_predicate("source_type", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    format!(
        "SELECT \
            {group_expr} AS bucket, \
            count() AS events \
         FROM {logs_table} \
         WHERE timestamp >= now() - INTERVAL {window_hours} HOUR{scope_and} \
         GROUP BY bucket \
         ORDER BY bucket ASC"
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
        assert!(
            build_stats_sql("nanosiem.logs_per_source_5m", "udm", &[], 24, &no_deny()).is_none()
        );
    }

    #[test]
    fn build_stats_sql_partition_prunes_and_scopes_in_clause() {
        let safe = vec!["limacharlie_edr".to_string(), "aws-cloudtrail".to_string()];
        let sql =
            build_stats_sql("nanosiem.logs_per_source_5m", "udm", &safe, 24, &no_deny()).unwrap();
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
        let sql = build_stats_sql(
            "nanosiem.logs_per_source_5m_distributed",
            "udm",
            &safe,
            1,
            &no_deny(),
        )
        .unwrap();
        assert!(
            sql.contains("FROM nanosiem.logs_per_source_5m_distributed"),
            "got: {sql}"
        );
    }

    #[test]
    fn build_stats_all_sql_omits_in_clause() {
        let sql = build_stats_all_sql("nanosiem.logs_per_source_5m", "udm", 24);
        assert!(sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"));
        assert!(!sql.contains("source_type IN"));
        assert!(sql.contains("GROUP BY source_type"));
    }

    #[test]
    fn build_buckets_sql_groups_by_hour_when_requested() {
        let safe = vec!["limacharlie_edr".to_string()];
        let sql = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
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
            "udm",
            &safe,
            1,
            BucketSize::FiveMin,
            &no_deny(),
        )
        .unwrap();
        // FiveMin selects the column directly — no re-bucket function.
        assert!(sql.contains("bucket_start AS bucket"), "got: {sql}");
        assert!(
            !sql.contains("toStartOf"),
            "5min must not call a re-bucket fn, got: {sql}"
        );
    }

    #[test]
    fn build_buckets_sql_returns_none_for_empty_input() {
        assert!(build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
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
        let sql =
            build_stats_sql("nanosiem.logs_per_source_5m", "udm", &safe, 24, &no_deny()).unwrap();
        assert!(!sql.contains("NOT IN"), "got: {sql}");
        assert!(!sql.contains("!="), "got: {sql}");
    }

    #[test]
    fn build_stats_sql_appends_scope_predicate_before_group_by() {
        let safe = vec!["foo".to_string(), "audit".to_string()];
        let deny: BTreeSet<String> = ["audit".to_string(), "LimaCharlie_EDR".to_string()]
            .into_iter()
            .collect();
        let sql = build_stats_sql("nanosiem.logs_per_source_5m", "udm", &safe, 24, &deny).unwrap();
        // BTreeSet order is lexicographic; predicate lowercases values.
        assert!(
            sql.contains("AND lower(scope_source_type) NOT IN ('limacharlie_edr', 'audit')")
                || sql.contains("AND lower(scope_source_type) NOT IN ('audit', 'limacharlie_edr')"),
            "expected scope predicate, got: {sql}"
        );
        let pred_pos = sql.find("NOT IN").unwrap();
        let group_pos = sql.find("GROUP BY").unwrap();
        assert!(
            pred_pos < group_pos,
            "predicate must precede GROUP BY: {sql}"
        );
    }

    #[test]
    fn build_stats_sql_single_denied_source_uses_inequality_form() {
        let safe = vec!["foo".to_string()];
        let deny: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
        let sql = build_stats_sql("nanosiem.logs_per_source_5m", "udm", &safe, 24, &deny).unwrap();
        assert!(
            sql.contains("AND lower(scope_source_type) != 'audit'"),
            "expected single-value inequality form, got: {sql}"
        );
    }

    #[test]
    fn build_buckets_sql_appends_scope_predicate() {
        let safe = vec!["foo".to_string()];
        let deny: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
        let sql = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
            &safe,
            24,
            BucketSize::Hour,
            &deny,
        )
        .unwrap();
        assert!(
            sql.contains("AND lower(scope_source_type) != 'audit'"),
            "expected scope predicate, got: {sql}"
        );
        let empty = build_buckets_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
            &safe,
            24,
            BucketSize::Hour,
            &no_deny(),
        )
        .unwrap();
        assert!(!empty.contains("!= 'audit'"), "got: {empty}");
    }

    #[test]
    fn cluster_wide_builders_are_byte_identical_for_an_unrestricted_viewer() {
        // NAN-1801 originally asserted these builders could NEVER carry a scope
        // predicate. NAN-2060 supersedes that: the rollup does carry a
        // `source_type` dimension, and the unscoped forms leaked denied-feed and
        // `audit` activity to restricted principals. The surviving half of the
        // guarantee is what this now pins — an EMPTY deny set must still produce
        // exactly the pre-scoping SQL, so admin/SYSTEM headline numbers and the
        // query plan are unchanged.
        let a = build_buckets_all_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
            24,
            BucketSize::Hour,
            &no_deny(),
        );
        let b = build_total_events_sql("nanosiem.logs_per_source_5m", "udm", 24, &no_deny());
        assert!(
            !a.contains("NOT IN") && !a.contains("lower(source_type)"),
            "got: {a}"
        );
        assert!(
            !b.contains("NOT IN") && !b.contains("lower(source_type)"),
            "got: {b}"
        );
    }

    #[test]
    fn cluster_wide_builders_are_scope_predicated_for_a_restricted_viewer() {
        // NAN-2060: the dashboard timeline and headline totals must exclude a
        // denied source. One denied value renders as `!=`, several as `NOT IN`.
        let one: BTreeSet<String> = ["audit".to_string()].into_iter().collect();
        let many: BTreeSet<String> = ["audit".to_string(), "windows_sysmon".to_string()]
            .into_iter()
            .collect();

        let a = build_buckets_all_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
            24,
            BucketSize::Hour,
            &one,
        );
        assert!(
            a.contains("lower(scope_source_type) != 'audit'"),
            "got: {a}"
        );

        let b = build_total_events_sql("nanosiem.logs_per_source_5m", "udm", 24, &many);
        assert!(b.contains("lower(scope_source_type) NOT IN ("), "got: {b}");
        assert!(b.contains("'windows_sysmon'"), "got: {b}");

        // The explicit-range form used for the previous-period comparison is
        // scoped on the same terms — otherwise the "previous" tile becomes the
        // unscoped oracle for the "current" one.
        let start = chrono::DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-07-24T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let c =
            build_total_events_range_sql("nanosiem.logs_per_source_5m", "udm", start, end, &one);
        assert!(
            c.contains("lower(scope_source_type) != 'audit'"),
            "got: {c}"
        );
        assert!(
            c.contains("bucket_start >= '2026-07-24 00:00:00'"),
            "got: {c}"
        );
        assert!(
            c.contains("bucket_start < '2026-07-24 12:00:00'"),
            "got: {c}"
        );
        // Already bucket-aligned input is left untouched.
        assert!(!c.contains("23:55:00"), "got: {c}");

        let unscoped = build_total_events_range_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
            start,
            end,
            &no_deny(),
        );
        assert!(!unscoped.contains("source_type"), "got: {unscoped}");
    }

    #[test]
    fn build_buckets_all_sql_omits_in_clause_and_source_type_column() {
        let sql = build_buckets_all_sql(
            "nanosiem.logs_per_source_5m",
            "udm",
            24,
            BucketSize::Hour,
            &no_deny(),
        );
        assert!(sql.contains("toStartOfHour(bucket_start) AS bucket"));
        assert!(sql.contains("WHERE bucket_start >= now() - INTERVAL 24 HOUR"));
        assert!(!sql.contains("source_type IN"), "got: {sql}");
        // Cluster-wide aggregate doesn't include source_type in SELECT.
        assert!(!sql.contains("source_type,"), "got: {sql}");
        assert!(sql.contains("GROUP BY bucket"));
        assert!(sql.contains("ORDER BY bucket ASC"));
    }

    #[test]
    fn restricted_rollup_reads_use_raw_scope_and_fail_closed_on_incomplete_rows() {
        let restricted: BTreeSet<String> = ["unknown".to_string()].into_iter().collect();
        let sql = build_total_events_sql("rollup", "ocsf", 24, &restricted);
        assert!(sql.contains("schema_profile = 'ocsf'"), "got: {sql}");
        assert!(
            sql.contains("scope_source_type_complete = 1"),
            "legacy/incomplete rows must fail closed: {sql}"
        );
        assert!(
            sql.contains("lower(scope_source_type) != 'unknown'"),
            "authorization must use the preserved raw key: {sql}"
        );
        assert!(
            !sql.contains("lower(source_type)"),
            "display key must never authorize: {sql}"
        );
    }

    #[test]
    fn raw_builders_filter_the_raw_source_type_over_the_raw_time_column() {
        // The raw fallbacks exist precisely because the rollup key is a
        // different identifier space under OCSF. They must therefore query the
        // RAW column the deny-set is defined over, and use `timestamp` (the
        // rollup's `bucket_start` does not exist on the events table).
        let deny: BTreeSet<String> = ["unknown".to_string()].into_iter().collect();

        let buckets = build_buckets_all_raw_sql("nanosiem.ocsf_logs", 24, BucketSize::Hour, &deny);
        assert!(
            buckets.contains("lower(source_type) != 'unknown'"),
            "got: {buckets}"
        );
        assert!(
            buckets.contains("toStartOfHour(timestamp) AS bucket"),
            "got: {buckets}"
        );
        assert!(buckets.contains("count() AS events"), "got: {buckets}");
        assert!(!buckets.contains("bucket_start"), "got: {buckets}");

        let start = chrono::DateTime::parse_from_rfc3339("2026-07-24T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-07-24T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        // The "last N hours" window form must be scoped identically — it is the
        // one that briefly shipped scoped-but-not-diverted.
        let window = build_total_events_raw_sql("nanosiem.ocsf_logs", 24, &deny);
        assert!(
            window.contains("lower(source_type) != 'unknown'"),
            "got: {window}"
        );
        assert!(window.contains("count() AS events"), "got: {window}");
        assert!(
            window.contains("timestamp >= now() - INTERVAL 24 HOUR"),
            "got: {window}"
        );
        assert!(!window.contains("bucket_start"), "got: {window}");

        let total = build_total_events_range_raw_sql("nanosiem.ocsf_logs", start, end, &deny);
        assert!(
            total.contains("lower(source_type) != 'unknown'"),
            "got: {total}"
        );
        assert!(total.contains("count() AS events"), "got: {total}");
        assert!(
            total.contains("timestamp >= '2026-07-24 00:00:00'")
                && total.contains("timestamp < '2026-07-24 12:00:00'"),
            "got: {total}"
        );
        assert!(!total.contains("bucket_start"), "got: {total}");
    }

    #[test]
    fn raw_and_rollup_builders_agree_on_bucket_granularity() {
        // The two paths feed the same `parse_bucket_all_rows`, so their SELECT
        // aliases must match or the fallback would silently parse as empty.
        let deny: BTreeSet<String> = ["unknown".to_string()].into_iter().collect();
        for bucket in [BucketSize::Hour, BucketSize::FiveMin] {
            let rollup = build_buckets_all_sql("t", "udm", 24, bucket, &no_deny());
            let raw = build_buckets_all_raw_sql("t", 24, bucket, &deny);
            for expected in [
                "AS bucket",
                "AS events",
                "GROUP BY bucket",
                "ORDER BY bucket ASC",
            ] {
                assert!(
                    rollup.contains(expected),
                    "rollup missing {expected}: {rollup}"
                );
                assert!(raw.contains(expected), "raw missing {expected}: {raw}");
            }
        }
    }

    #[test]
    fn range_sql_snaps_both_bounds_so_adjacent_windows_are_disjoint() {
        // NAN-2055 (codex round 4): the dashboard passes second-level `now()`
        // boundaries into a 5-minute rollup. Without snapping, the bucket the
        // window starts inside is dropped entirely — up to 5 of 60 minutes
        // missing from the "last hour" tile.
        let start = chrono::DateTime::parse_from_rfc3339("2026-07-24T10:03:47Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-07-24T11:03:47Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let sql = build_total_events_range_sql("t", "udm", start, end, &no_deny());
        assert!(
            sql.contains("bucket_start >= '2026-07-24 10:00:00'"),
            "got: {sql}"
        );
        assert!(
            sql.contains("bucket_start < '2026-07-24 11:00:00'"),
            "got: {sql}"
        );

        // Adjacent periods must be DISJOINT. An earlier revision floored only
        // the lower bound, which left `< 11:03:47` / `< 10:03:47` and counted
        // the whole 10:00 bucket in BOTH the current and previous tiles —
        // silently inflating totals and distorting every trend. The previous
        // window's upper bound must equal this window's lower bound exactly.
        let prev = build_total_events_range_sql(
            "t",
            "udm",
            start - chrono::Duration::hours(1),
            start,
            &no_deny(),
        );
        assert!(
            prev.contains("bucket_start >= '2026-07-24 09:00:00'"),
            "got: {prev}"
        );
        assert!(
            prev.contains("bucket_start < '2026-07-24 10:00:00'"),
            "adjacent windows overlap — the boundary bucket is double-counted: {prev}"
        );
    }

    #[test]
    fn floor_to_bucket_is_idempotent_and_never_rounds_up() {
        let aligned = chrono::DateTime::parse_from_rfc3339("2026-07-24T10:05:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        assert_eq!(floor_to_bucket(aligned), aligned);
        assert_eq!(floor_to_bucket(floor_to_bucket(aligned)), aligned);

        for (input, want) in [
            ("2026-07-24T10:04:59Z", "2026-07-24T10:00:00Z"),
            ("2026-07-24T10:05:01Z", "2026-07-24T10:05:00Z"),
            ("2026-07-24T00:00:00Z", "2026-07-24T00:00:00Z"),
        ] {
            let i = chrono::DateTime::parse_from_rfc3339(input)
                .unwrap()
                .with_timezone(&chrono::Utc);
            let w = chrono::DateTime::parse_from_rfc3339(want)
                .unwrap()
                .with_timezone(&chrono::Utc);
            assert_eq!(floor_to_bucket(i), w, "floor({input})");
            assert!(floor_to_bucket(i) <= i, "floor rounded UP for {input}");
        }
    }

    #[test]
    fn build_total_events_sql_no_grouping() {
        let sql = build_total_events_sql("nanosiem.logs_per_source_5m", "udm", 24, &no_deny());
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
        let body =
            "{\"source_type\":\"\",\"events\":\"1\"}\n{\"source_type\":\"foo\",\"events\":\"2\"}";
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
