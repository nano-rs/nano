// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Query Service
//!
//! Queries audit events from ClickHouse (source_type='audit') instead of PostgreSQL.
//! This provides access to the full audit trail including events emitted via emit_audit().

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
        start_time: start_time.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
        end_time: end_time.format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
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
        user: if row.user_val.is_empty() {
            None
        } else {
            Some(row.user_val)
        },
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
}

impl AuditQueryService {
    /// Create a new audit query service
    pub fn new(dual_pool: DualPool) -> Self {
        Self { dual_pool }
    }

    /// Query audit logs from ClickHouse
    pub async fn query(
        &self,
        query: &ClickHouseAuditQuery,
    ) -> Result<Vec<ClickHouseAuditEntry>, AuditQueryError> {
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
            .bind(since.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.value).collect())
    }

    /// Get distinct source values from audit events
    pub async fn get_distinct_sources(&self) -> Result<Vec<String>, AuditQueryError> {
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
            .bind(since.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
            .fetch_all()
            .await
            .map_err(|e| AuditQueryError::QueryError(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.value).collect())
    }
}
