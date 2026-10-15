// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Query Service
//!
//! Queries audit events from ClickHouse (source_type='audit') instead of PostgreSQL.
//! This provides access to the full audit trail including events emitted via emit_audit().

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

use crate::db::DualPool;

/// Errors from audit query operations
#[derive(Debug, Error)]
pub enum AuditQueryError {
    #[error("ClickHouse query error: {0}")]
    QueryError(String),
    #[error("ClickHouse not available")]
    NotAvailable,
}

/// Query parameters for audit log search
#[derive(Debug, Clone, Default)]
pub struct ClickHouseAuditQuery {
    /// Filter by actor ID (from metadata)
    pub actor_id: Option<Uuid>,
    /// Filter by action
    pub action: Option<String>,
    /// Filter by source subsystem
    pub source: Option<String>,
    /// Filter by resource type (from metadata)
    pub resource_type: Option<String>,
    /// Filter by time range start
    pub start_time: Option<DateTime<Utc>>,
    /// Filter by time range end
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by success/failure status
    pub success: Option<bool>,
    /// Result limit
    pub limit: Option<i64>,
    /// Result offset
    pub offset: Option<i64>,
}

/// A single audit log entry from ClickHouse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseAuditEntry {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub user: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub src_ip: Option<String>,
    pub user_agent: Option<String>,
    pub status: Option<String>,
    pub message: String,
    pub metadata: serde_json::Value,
    /// Extracted from metadata for convenience
    pub actor_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    /// API key ID if the action was authenticated via an API key
    pub api_key_id: Option<String>,
    /// API key display name if the action was authenticated via an API key
    pub api_key_name: Option<String>,
}

/// Row returned from ClickHouse
#[derive(Debug, clickhouse::Row, Deserialize)]
struct AuditRow {
    id: String,
    timestamp_str: String,
    #[serde(rename = "user_val")]
    user_val: String,
    action: String,
    source: String,
    src_ip: String,
    user_agent: String,
    status: String,
    message: String,
    metadata: String,
}

/// Row for count query
#[derive(Debug, clickhouse::Row, Deserialize)]
struct CountRow {
    count: u64,
}

/// Row for distinct values
#[derive(Debug, clickhouse::Row, Deserialize)]
struct StringRow {
    value: String,
}

/// Row for the per-API-key daily usage aggregation. `day` is a UTC calendar
/// date rendered as `YYYY-MM-DD` (via `toString(toDate(...))`) so it round-trips
/// cleanly into `chrono::NaiveDate` without depending on the ClickHouse client's
/// `Date` codec.
#[derive(Debug, clickhouse::Row, Deserialize)]
struct DailyUsageRow {
    day: String,
    count: u64,
}

/// Resolved time range and filter flags for building WHERE clauses
struct ResolvedFilters {
    start_time: String,
    end_time: String,
    where_clause: String,
    has_action: bool,
    has_source: bool,
    has_actor: bool,
    has_resource_type: bool,
    has_status: bool,
    status_filter: Option<&'static str>,
}

/// Build shared WHERE clause and resolved time range from a query
fn resolve_filters(query: &ClickHouseAuditQuery) -> ResolvedFilters {
    let start_time = query
        .start_time
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let end_time = query.end_time.unwrap_or_else(|| Utc::now());
    let status_filter = query.success.map(|s| if s { "success" } else { "failure" });

    let mut conditions = Vec::new();
    let has_action = query.action.is_some();
    let has_source = query.source.is_some();
    let has_actor = query.actor_id.is_some();
    let has_resource_type = query.resource_type.is_some();
    let has_status = status_filter.is_some();

    if has_action {
        conditions.push("action = ?");
    }
    if has_source {
        conditions.push("source = ?");
    }
    if has_actor {
        conditions.push("JSONExtractString(metadata, 'actor_id') = ?");
    }
    if has_resource_type {
        conditions.push("JSONExtractString(metadata, 'resource_type') = ?");
    }
    if has_status {
        conditions.push("status = ?");
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    ResolvedFilters {
        start_time: crate::sql_hygiene::format_ch_bound_micros(&start_time).to_string(),
        end_time: crate::sql_hygiene::format_ch_bound_micros(&end_time).to_string(),
        where_clause,
        has_action,
        has_source,
        has_actor,
        has_resource_type,
        has_status,
        status_filter,
    }
}

/// Bind filter parameters to a ClickHouse query cursor
fn bind_filters<'a>(
    mut q: clickhouse::query::Query,
    query: &ClickHouseAuditQuery,
    filters: &ResolvedFilters,
) -> clickhouse::query::Query {
    if filters.has_action {
        q = q.bind(query.action.as_deref().unwrap_or(""));
    }
    if filters.has_source {
        q = q.bind(query.source.as_deref().unwrap_or(""));
    }
    if filters.has_actor {
        q = q.bind(query.actor_id.map(|id| id.to_string()).unwrap_or_default());
    }
    if filters.has_resource_type {
        q = q.bind(query.resource_type.as_deref().unwrap_or(""));
    }
    if filters.has_status {
        q = q.bind(filters.status_filter.unwrap_or(""));
    }
    q
}

fn row_to_entry(row: AuditRow) -> ClickHouseAuditEntry {
    let metadata: serde_json::Value =
        serde_json::from_str(&row.metadata).unwrap_or(serde_json::Value::Null);

    let timestamp =
        chrono::NaiveDateTime::parse_from_str(&row.timestamp_str, "%Y-%m-%d %H:%M:%S%.f")
            .map(|ndt| ndt.and_utc())
            .unwrap_or_default();

    ClickHouseAuditEntry {
        event_id: row.id,
        timestamp,
        // Prefer the display-case actor name preserved in metadata: the `user`
        // column is lowercased at write time (LOWERCASE_NORMALIZED_FIELDS
        // contract, NAN-1432) so the search-bar raw-equality fast path finds
        // audit rows. `actor_name` is present on both pre- and post-fix rows;
        // the column is the fallback for rows without it.
        user: metadata
            .get("actor_name")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| {
                if row.user_val.is_empty() {
                    None
                } else {
                    Some(row.user_val)
                }
            }),
        action: if row.action.is_empty() {
            None
        } else {
            Some(row.action)
        },
        source: if row.source.is_empty() {
            None
        } else {
            Some(row.source)
        },
        src_ip: if row.src_ip.is_empty() {
            None
        } else {
            Some(row.src_ip)
        },
        user_agent: if row.user_agent.is_empty() {
            None
        } else {
            Some(row.user_agent)
        },
        status: if row.status.is_empty() {
            None
        } else {
            Some(row.status)
        },
        message: row.message,
        actor_id: metadata
            .get("actor_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        resource_type: metadata
            .get("resource_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        resource_id: metadata
            .get("resource_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        resource_name: metadata
            .get("resource_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        api_key_id: metadata
            .get("api_key_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        api_key_name: metadata
            .get("api_key_name")
            .and_then(|v| v.as_str())
            .map(String::from),
        metadata,
    }
}

/// Service for querying audit events from ClickHouse
#[derive(Clone)]
pub struct AuditQueryService {
    dual_pool: DualPool,
    lake_mode: bool,
}

impl AuditQueryService {
    /// Create a new audit query service
    pub fn new(dual_pool: DualPool) -> Self {
        let lake_mode = crate::schema::log_query_backend_is_lake();
        Self {
            dual_pool,
            lake_mode,
        }
    }

    /// Query audit logs from ClickHouse
    pub async fn query(
        &self,
        query: &ClickHouseAuditQuery,
    ) -> Result<Vec<ClickHouseAuditEntry>, AuditQueryError> {
        if self.lake_mode {
            return self.query_postgres(query).await;
        }
        let client = self.dual_pool.clickhouse();
        let limit = query.limit.unwrap_or(50).min(1000);
        let offset = query.offset.unwrap_or(0);
        let filters = resolve_filters(query);

        let sql = format!(
            "SELECT toString(id) as id, toString(timestamp) as timestamp_str, `user` as user_val, action, source, src_ip, user_agent, status, message, metadata \
             FROM {} \
             PREWHERE timestamp >= ? AND timestamp <= ? AND source_type = 'audit' \
             {} \
             ORDER BY timestamp DESC \
             LIMIT ? OFFSET ?",
            self.dual_pool.logs_table(), filters.where_clause
        );

        let mut q = client
            .query(&sql)
            .bind(&filters.start_time)
            .bind(&filters.end_time);

        q = bind_filters(q, query, &filters);
        q = q.bind(limit as u64);
        q = q.bind(offset as u64);

        let rows: Vec<AuditRow> = q
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(row_to_entry).collect())
    }

    /// Count audit logs matching query
    pub async fn count(&self, query: &ClickHouseAuditQuery) -> Result<u64, AuditQueryError> {
        if self.lake_mode {
            return self.count_postgres(query).await;
        }
        let client = self.dual_pool.clickhouse();
        let filters = resolve_filters(query);

        let sql = format!(
            "SELECT count() as count FROM {} \
             PREWHERE timestamp >= ? AND timestamp <= ? AND source_type = 'audit' \
             {}",
            self.dual_pool.logs_table(),
            filters.where_clause
        );

        let mut q = client
            .query(&sql)
            .bind(&filters.start_time)
            .bind(&filters.end_time);

        q = bind_filters(q, query, &filters);

        let row: CountRow = q
            .fetch_one()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(row.count)
    }

    /// Get distinct action values from audit events
    pub async fn get_distinct_actions(&self) -> Result<Vec<String>, AuditQueryError> {
        if self.lake_mode {
            return self.distinct_postgres("action").await;
        }
        let client = self.dual_pool.clickhouse();
        let since = Utc::now() - chrono::Duration::days(90);

        let rows: Vec<StringRow> = client
            .query(&format!(
                "SELECT DISTINCT action as value FROM {} \
                 PREWHERE timestamp >= ? AND source_type = 'audit' \
                 WHERE action != '' \
                 ORDER BY value",
                self.dual_pool.logs_table()
            ))
            .bind(crate::sql_hygiene::format_ch_bound_micros(&since).to_string())
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.value).collect())
    }

    /// Get distinct source values from audit events
    pub async fn get_distinct_sources(&self) -> Result<Vec<String>, AuditQueryError> {
        if self.lake_mode {
            return self.distinct_postgres("source").await;
        }
        let client = self.dual_pool.clickhouse();
        let since = Utc::now() - chrono::Duration::days(90);

        let rows: Vec<StringRow> = client
            .query(&format!(
                "SELECT DISTINCT source as value FROM {} \
                 PREWHERE timestamp >= ? AND source_type = 'audit' \
                 WHERE source != '' \
                 ORDER BY value",
                self.dual_pool.logs_table()
            ))
            .bind(crate::sql_hygiene::format_ch_bound_micros(&since).to_string())
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.value).collect())
    }

    /// Count audited actions attributed to an API key, bucketed by UTC calendar
    /// day, for the window starting at `start` (inclusive).
    ///
    /// Reads the ClickHouse audit store (`source_type='audit'`) where the
    /// event's `metadata.api_key_id` matches the key — i.e. every action
    /// performed *via* that delegated credential (the key as the calling
    /// actor). Both handler mutations and authorization denials populate
    /// `metadata.api_key_id` (the `AuditEvent::api_key` builder), so this is the
    /// system-of-record source for per-key call volume.
    ///
    /// NAN-1622 migrated this off the retired PostgreSQL `audit_logs` table.
    /// This matches the documented "actor's api_key_id" intent: the PG column
    /// overloaded actor-credential and target-key meanings (lifecycle writers
    /// stored the *managed* key there), whereas the ClickHouse view is
    /// actor-only and additionally captures every mutation the key performed
    /// (those only ever emitted to ClickHouse). Admin lifecycle actions taken on
    /// a key carry the key in `metadata.resource_id`, not here.
    ///
    /// Returns only days with activity (sparse) ordered oldest-first; callers
    /// densify into a continuous zero-filled series.
    pub async fn api_key_daily_usage(
        &self,
        api_key_id: Uuid,
        start: DateTime<Utc>,
    ) -> Result<Vec<(chrono::NaiveDate, i64)>, AuditQueryError> {
        if self.lake_mode {
            let rows = sqlx::query(
                "SELECT (occurred_at AT TIME ZONE 'UTC')::date AS day, COUNT(*)::bigint AS count \
                 FROM platform_audit_events \
                 WHERE occurred_at >= $1 AND api_key_id = $2 \
                 GROUP BY day ORDER BY day",
            )
            .bind(start)
            .bind(api_key_id)
            .fetch_all(self.dual_pool.postgres())
            .await
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
            return rows
                .into_iter()
                .map(|row| {
                    Ok((
                        row.try_get("day")
                            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
                        row.try_get("count")
                            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
                    ))
                })
                .collect();
        }
        let client = self.dual_pool.clickhouse();

        // Bucket on the UTC calendar day explicitly so day boundaries match the
        // handler's UTC densification regardless of the column's timezone.
        let sql = format!(
            "SELECT toString(toDate(timestamp, 'UTC')) AS day, count() AS count \
             FROM {} \
             PREWHERE timestamp >= ? AND source_type = 'audit' \
             WHERE JSONExtractString(metadata, 'api_key_id') = ? \
             GROUP BY day \
             ORDER BY day",
            self.dual_pool.logs_table()
        );

        let rows: Vec<DailyUsageRow> = client
            .query(&sql)
            .bind(crate::sql_hygiene::format_ch_bound_micros(&start).to_string())
            .bind(api_key_id.to_string())
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                chrono::NaiveDate::parse_from_str(&r.day, "%Y-%m-%d")
                    .map(|day| (day, r.count as i64))
                    .map_err(|e| {
                        AuditQueryError::QueryError(format!("invalid day bucket '{}': {e}", r.day))
                    })
            })
            .collect()
    }

    async fn query_postgres(
        &self,
        query: &ClickHouseAuditQuery,
    ) -> Result<Vec<ClickHouseAuditEntry>, AuditQueryError> {
        let (where_sql, bind_values) = postgres_filter_sql(query);
        let limit = query.limit.unwrap_or(50).clamp(1, 1000);
        let offset = query.offset.unwrap_or(0).max(0);
        let sql = format!(
            "SELECT event_id, occurred_at, actor_name, action, source, ip_address, user_agent, \
                    status, message, metadata, resource_type, resource_id, resource_name, \
                    api_key_id, api_key_name \
             FROM platform_audit_events {where_sql} \
             ORDER BY occurred_at DESC LIMIT {limit} OFFSET {offset}"
        );
        let rows = bind_postgres_filters(sqlx::query(&sql), query, &bind_values)
            .fetch_all(self.dual_pool.postgres())
            .await
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;

        rows.into_iter().map(postgres_row_to_entry).collect()
    }

    async fn count_postgres(&self, query: &ClickHouseAuditQuery) -> Result<u64, AuditQueryError> {
        let (where_sql, bind_values) = postgres_filter_sql(query);
        let sql =
            format!("SELECT COUNT(*)::bigint AS count FROM platform_audit_events {where_sql}");
        let row = bind_postgres_filters(sqlx::query(&sql), query, &bind_values)
            .fetch_one(self.dual_pool.postgres())
            .await
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
        let count: i64 = row
            .try_get("count")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    async fn distinct_postgres(&self, column: &str) -> Result<Vec<String>, AuditQueryError> {
        // Callers pass one of the two fixed identifiers above; keep the match so
        // a future refactor cannot turn this into an identifier-injection seam.
        let column = match column {
            "action" => "action",
            "source" => "source",
            _ => {
                return Err(AuditQueryError::QueryError(
                    "invalid audit facet".to_string(),
                ))
            }
        };
        let sql = format!(
            "SELECT DISTINCT {column} AS value FROM platform_audit_events \
             WHERE occurred_at >= NOW() - INTERVAL '90 days' AND {column} != '' \
             ORDER BY value"
        );
        sqlx::query(&sql)
            .fetch_all(self.dual_pool.postgres())
            .await
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?
            .into_iter()
            .map(|row| {
                row.try_get("value")
                    .map_err(|error| AuditQueryError::QueryError(error.to_string()))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
enum PostgresAuditBind {
    Start,
    End,
    Action,
    Source,
    Actor,
    ResourceType,
    Status,
}

fn postgres_filter_sql(query: &ClickHouseAuditQuery) -> (String, Vec<PostgresAuditBind>) {
    let mut clauses = Vec::new();
    let mut binds = Vec::new();
    let mut next = 1;
    let mut add = |clause: String, bind: PostgresAuditBind| {
        clauses.push(clause.replace('?', &format!("${next}")));
        binds.push(bind);
        next += 1;
    };

    add("occurred_at >= ?".to_string(), PostgresAuditBind::Start);
    add("occurred_at <= ?".to_string(), PostgresAuditBind::End);
    if query.action.is_some() {
        add("action = ?".to_string(), PostgresAuditBind::Action);
    }
    if query.source.is_some() {
        add("source = ?".to_string(), PostgresAuditBind::Source);
    }
    if query.actor_id.is_some() {
        add("actor_id = ?".to_string(), PostgresAuditBind::Actor);
    }
    if query.resource_type.is_some() {
        add(
            "resource_type = ?".to_string(),
            PostgresAuditBind::ResourceType,
        );
    }
    if query.success.is_some() {
        add("status = ?".to_string(), PostgresAuditBind::Status);
    }
    (format!("WHERE {}", clauses.join(" AND ")), binds)
}

fn bind_postgres_filters<'q>(
    mut statement: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    query: &'q ClickHouseAuditQuery,
    binds: &[PostgresAuditBind],
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    let start = query
        .start_time
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let end = query.end_time.unwrap_or_else(Utc::now);
    for bind in binds {
        statement = match bind {
            PostgresAuditBind::Start => statement.bind(start),
            PostgresAuditBind::End => statement.bind(end),
            PostgresAuditBind::Action => statement.bind(query.action.as_deref().unwrap_or("")),
            PostgresAuditBind::Source => statement.bind(query.source.as_deref().unwrap_or("")),
            PostgresAuditBind::Actor => statement.bind(query.actor_id.unwrap_or_default()),
            PostgresAuditBind::ResourceType => {
                statement.bind(query.resource_type.as_deref().unwrap_or(""))
            }
            PostgresAuditBind::Status => statement.bind(if query.success.unwrap_or(false) {
                "success"
            } else {
                "failure"
            }),
        };
    }
    statement
}

fn postgres_row_to_entry(
    row: sqlx::postgres::PgRow,
) -> Result<ClickHouseAuditEntry, AuditQueryError> {
    let metadata: serde_json::Value = row
        .try_get("metadata")
        .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
    let event_id: Uuid = row
        .try_get("event_id")
        .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
    let resource_id: Option<Uuid> = row
        .try_get("resource_id")
        .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
    let api_key_id: Option<Uuid> = row
        .try_get("api_key_id")
        .map_err(|error| AuditQueryError::QueryError(error.to_string()))?;
    Ok(ClickHouseAuditEntry {
        event_id: event_id.to_string(),
        timestamp: row
            .try_get("occurred_at")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        user: row
            .try_get("actor_name")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        action: Some(
            row.try_get("action")
                .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        ),
        source: Some(
            row.try_get("source")
                .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        ),
        src_ip: row
            .try_get("ip_address")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        user_agent: row
            .try_get("user_agent")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        status: Some(
            row.try_get("status")
                .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        ),
        message: row
            .try_get("message")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        actor_id: metadata
            .get("actor_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        resource_type: row
            .try_get("resource_type")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        resource_id: resource_id.map(|id| id.to_string()),
        resource_name: row
            .try_get("resource_name")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        api_key_id: api_key_id.map(|id| id.to_string()),
        api_key_name: row
            .try_get("api_key_name")
            .map_err(|error| AuditQueryError::QueryError(error.to_string()))?,
        metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(user_val: &str, metadata: &str) -> AuditRow {
        AuditRow {
            id: "evt-1".to_string(),
            timestamp_str: "2026-06-12 12:00:00.000000".to_string(),
            user_val: user_val.to_string(),
            action: "rule_created".to_string(),
            source: "detection".to_string(),
            src_ip: "10.0.0.1".to_string(),
            user_agent: String::new(),
            status: "success".to_string(),
            message: "[detection] rule_created by Jane Analyst".to_string(),
            metadata: metadata.to_string(),
        }
    }

    /// NAN-1432: the `user` column is lowercased at write time so the
    /// search-bar raw-equality fast path finds audit rows; the audit page must
    /// keep rendering the display-case name, which lives in metadata.
    #[test]
    fn entry_user_prefers_display_case_actor_name_from_metadata() {
        let entry = row_to_entry(row("jane analyst", r#"{"actor_name":"Jane Analyst"}"#));
        assert_eq!(entry.user.as_deref(), Some("Jane Analyst"));
    }

    /// Rows without a metadata actor_name (system/API-key events, or legacy
    /// metadata shapes) fall back to the `user` column verbatim.
    #[test]
    fn entry_user_falls_back_to_column_without_actor_name() {
        let entry = row_to_entry(row("jane analyst", "{}"));
        assert_eq!(entry.user.as_deref(), Some("jane analyst"));

        let entry = row_to_entry(row("jane analyst", r#"{"actor_name":null}"#));
        assert_eq!(entry.user.as_deref(), Some("jane analyst"));

        let entry = row_to_entry(row("", "{}"));
        assert_eq!(entry.user, None);
    }

    #[test]
    fn postgres_audit_filters_are_parameterized_in_stable_order() {
        let actor = Uuid::now_v7();
        let query = ClickHouseAuditQuery {
            actor_id: Some(actor),
            action: Some("rule_created".to_string()),
            source: Some("detection".to_string()),
            resource_type: Some("detection_rule".to_string()),
            success: Some(true),
            ..Default::default()
        };

        let (sql, binds) = postgres_filter_sql(&query);

        assert_eq!(
            sql,
            "WHERE occurred_at >= $1 AND occurred_at <= $2 AND action = $3 AND source = $4 AND actor_id = $5 AND resource_type = $6 AND status = $7"
        );
        assert_eq!(binds.len(), 7);
        assert!(matches!(binds[0], PostgresAuditBind::Start));
        assert!(matches!(binds[6], PostgresAuditBind::Status));
    }
}
