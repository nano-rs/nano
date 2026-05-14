// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit Log API handlers
//!
//! Requirements: 9.5, 11.6
//!
//! This module provides handlers for:
//! - query_audit_logs() - Query audit logs with filtering (ClickHouse primary, PostgreSQL fallback)
//! - export_audit_logs() - Export audit logs to CSV/JSON
//! - get_action_types() - Get distinct action types
//! - get_resource_types() - Get distinct resource types (now "sources")

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::audit::{ClickHouseAuditEntry, ClickHouseAuditQuery};
use nanosiem_core::auth::{permissions, AuditLogWithNames, AuditRepositoryError};

use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for audit endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuditApiError {
    pub error: String,
    pub message: String,
}

impl AuditApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &AuditRepositoryError) -> (StatusCode, Self) {
        let (status, error_type) = match err {
            AuditRepositoryError::NotFound(_) => (StatusCode::NOT_FOUND, "audit_log_not_found"),
            AuditRepositoryError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database_error")
            }
        };

        (status, Self::new(error_type, &err.to_string()))
    }
}

/// Query parameters for listing audit logs
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListAuditLogsQuery {
    #[serde(default, with = "nanosiem_core::typeid::user::opt")]
    #[param(value_type = Option<String>)]
    pub user_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    /// Filter by audit source subsystem (auth, detection, dashboard, etc.)
    pub source: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub success: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Audit log list response (backward-compatible shape)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AuditLogListResponse {
    pub logs: Vec<AuditLogEntry>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Unified audit log entry (works for both ClickHouse and PostgreSQL sources)
///
/// `api_key_id` / `api_key_name` are populated when the action was performed
/// via an API key. `user_id` / `user_name` then identify the *owning* user of
/// that key — investigators must consult both pairs to see whether an action
/// was an interactive-session action or a delegated-credential action.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub user_name: Option<String>,
    pub action: Option<String>,
    pub source: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub message: Option<String>,
    pub details: Option<serde_json::Value>,
    /// API key ID when the action was authenticated via an API key
    pub api_key_id: Option<String>,
    /// API key display name when the action was authenticated via an API key
    pub api_key_name: Option<String>,
}

impl From<ClickHouseAuditEntry> for AuditLogEntry {
    fn from(e: ClickHouseAuditEntry) -> Self {
        let success = e.status.as_deref() == Some("success");
        Self {
            id: e.event_id,
            timestamp: e.timestamp,
            user_id: e.actor_id,
            user_name: e.user,
            action: e.action,
            source: e.source,
            resource_type: e.resource_type,
            resource_id: e.resource_id,
            resource_name: e.resource_name,
            ip_address: e.src_ip,
            user_agent: e.user_agent,
            success,
            message: Some(e.message),
            details: e.metadata.get("details").cloned(),
            api_key_id: e.api_key_id,
            api_key_name: e.api_key_name,
        }
    }
}

impl From<AuditLogWithNames> for AuditLogEntry {
    fn from(e: AuditLogWithNames) -> Self {
        let api_key_id = e.log.api_key_id.map(|u| u.to_string());
        let api_key_name = e.api_key_name.clone();
        Self {
            id: e.log.id.to_string(),
            timestamp: e.log.timestamp,
            user_id: e.log.user_id.map(|u| u.to_string()),
            user_name: e.user_name.or(e.user_email),
            action: Some(e.log.action),
            source: None, // PostgreSQL audit_logs don't have source
            resource_type: e.log.resource_type,
            resource_id: e.log.resource_id.map(|u| u.to_string()),
            resource_name: None,
            ip_address: e.log.ip_address,
            user_agent: e.log.user_agent,
            success: e.log.success,
            message: None,
            details: e.log.details,
            api_key_id,
            api_key_name,
        }
    }
}

/// Query audit logs with filtering
///
/// Queries ClickHouse (primary) with PostgreSQL fallback.
///
/// SECURITY: Non-admin users can only view their own audit logs.
/// Admin users (with settings:system permission) can view all audit logs.
///
/// GET /api/audit
#[utoipa::path(
    get,
    path = "/api/audit",
    tag = "audit",
    params(ListAuditLogsQuery),
    responses(
        (status = 200, description = "Successfully retrieved audit logs", body = AuditLogListResponse),
        (status = 403, description = "Permission denied", body = AuditApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn query_audit_logs(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<AuditLogListResponse>, (StatusCode, Json<AuditApiError>)> {
    check_permission(&auth, permissions::AUDIT_VIEW)
        .map_err(|(s, j)| (s, Json(AuditApiError::new(&j.error, &j.message))))?;

    // SECURITY: Check if user has admin access to view all audit logs
    let is_admin = check_permission(&auth, permissions::SETTINGS_SYSTEM).is_ok();
    let effective_user_id = if is_admin {
        query.user_id
    } else {
        Some(auth.user_id())
    };

    let limit = query.limit.unwrap_or(50).min(1000);
    let offset = query.offset.unwrap_or(0);

    let ch_query = ClickHouseAuditQuery {
        actor_id: effective_user_id,
        action: query.action,
        source: query.source,
        resource_type: query.resource_type,
        start_time: query.start_time,
        end_time: query.end_time,
        success: query.success,
        limit: Some(limit),
        offset: Some(offset),
    };

    let logs = state.audit_query_service.query(&ch_query).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuditApiError::new("query_error", &e.to_string())),
        )
    })?;

    let count_query = ClickHouseAuditQuery {
        limit: None,
        offset: None,
        ..ch_query
    };
    let total = state.audit_query_service.count(&count_query).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuditApiError::new("query_error", &e.to_string())),
        )
    })?;

    let entries: Vec<AuditLogEntry> = logs.into_iter().map(AuditLogEntry::from).collect();

    Ok(Json(AuditLogListResponse {
        logs: entries,
        total: total as i64,
        limit,
        offset,
    }))
}

/// Export format for audit logs
#[derive(Debug, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Json,
    Csv,
}

/// Query parameters for exporting audit logs
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ExportAuditLogsQuery {
    #[serde(default, with = "nanosiem_core::typeid::user::opt")]
    #[param(value_type = Option<String>)]
    pub user_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub source: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub success: Option<bool>,
    pub format: Option<ExportFormat>,
    pub limit: Option<i64>,
}

/// Export audit logs to CSV or JSON
///
/// SECURITY: Non-admin users can only export their own audit logs.
///
/// POST /api/audit/export
#[utoipa::path(
    post,
    path = "/api/audit/export",
    tag = "audit",
    params(ExportAuditLogsQuery),
    responses(
        (status = 200, description = "Successfully exported audit logs", content_type = "application/json", body = String),
        (status = 200, description = "Successfully exported audit logs", content_type = "text/csv", body = String),
        (status = 403, description = "Permission denied", body = AuditApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn export_audit_logs(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<ExportAuditLogsQuery>,
) -> Result<Response, (StatusCode, Json<AuditApiError>)> {
    check_permission(&auth, permissions::AUDIT_VIEW)
        .map_err(|(s, j)| (s, Json(AuditApiError::new(&j.error, &j.message))))?;

    let is_admin = check_permission(&auth, permissions::SETTINGS_SYSTEM).is_ok();
    let effective_user_id = if is_admin {
        query.user_id
    } else {
        Some(auth.user_id())
    };

    let limit = query.limit.unwrap_or(10000).min(100000);
    let format = query.format.unwrap_or_default();

    let ch_query = ClickHouseAuditQuery {
        actor_id: effective_user_id,
        action: query.action,
        source: query.source,
        resource_type: query.resource_type,
        start_time: query.start_time,
        end_time: query.end_time,
        success: query.success,
        limit: Some(limit),
        offset: Some(0),
    };

    let logs = state.audit_query_service.query(&ch_query).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AuditApiError::new("query_error", &e.to_string())),
        )
    })?;

    let entries: Vec<AuditLogEntry> = logs.into_iter().map(AuditLogEntry::from).collect();

    match format {
        ExportFormat::Json => {
            let json_data = serde_json::to_string_pretty(&entries).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuditApiError::new("serialization_error", &e.to_string())),
                )
            })?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit_logs.json\"",
                    ),
                ],
                json_data,
            )
                .into_response())
        }
        ExportFormat::Csv => {
            let csv_data = generate_csv(&entries).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AuditApiError::new("csv_generation_error", &e)),
                )
            })?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit_logs.csv\"",
                    ),
                ],
                csv_data,
            )
                .into_response())
        }
    }
}

/// Generate CSV from audit log entries
fn generate_csv(entries: &[AuditLogEntry]) -> Result<String, String> {
    let mut csv = String::new();

    // Header row
    csv.push_str("id,timestamp,user_id,user_name,api_key_id,api_key_name,action,source,resource_type,resource_id,resource_name,ip_address,success,message\n");

    for entry in entries {
        let row = format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            entry.id,
            entry.timestamp.to_rfc3339(),
            entry.user_id.as_deref().unwrap_or(""),
            escape_csv_field(entry.user_name.as_deref().unwrap_or("")),
            entry.api_key_id.as_deref().unwrap_or(""),
            escape_csv_field(entry.api_key_name.as_deref().unwrap_or("")),
            escape_csv_field(entry.action.as_deref().unwrap_or("")),
            escape_csv_field(entry.source.as_deref().unwrap_or("")),
            escape_csv_field(entry.resource_type.as_deref().unwrap_or("")),
            entry.resource_id.as_deref().unwrap_or(""),
            escape_csv_field(entry.resource_name.as_deref().unwrap_or("")),
            escape_csv_field(entry.ip_address.as_deref().unwrap_or("")),
            entry.success,
            escape_csv_field(entry.message.as_deref().unwrap_or("")),
        );
        csv.push_str(&row);
    }

    Ok(csv)
}

/// Escape a field for CSV output
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Get available action types
///
/// Returns distinct actions from ClickHouse (or PostgreSQL fallback).
///
/// GET /api/audit/actions
#[utoipa::path(
    get,
    path = "/api/audit/actions",
    tag = "audit",
    responses(
        (status = 200, description = "Successfully retrieved action types", body = Vec<String>),
        (status = 403, description = "Permission denied", body = AuditApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_action_types(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<AuditApiError>)> {
    check_permission(&auth, permissions::AUDIT_VIEW)
        .map_err(|(s, j)| (s, Json(AuditApiError::new(&j.error, &j.message))))?;

    let actions = state
        .audit_query_service
        .get_distinct_actions()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuditApiError::new("query_error", &e.to_string())),
            )
        })?;

    Ok(Json(actions))
}

/// Get available source types (audit subsystems)
///
/// Returns distinct source values from ClickHouse (or resource_types from PostgreSQL fallback).
///
/// GET /api/audit/resource-types
#[utoipa::path(
    get,
    path = "/api/audit/resource-types",
    tag = "audit",
    responses(
        (status = 200, description = "Successfully retrieved resource/source types", body = Vec<String>),
        (status = 403, description = "Permission denied", body = AuditApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_resource_types(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<Vec<String>>, (StatusCode, Json<AuditApiError>)> {
    check_permission(&auth, permissions::AUDIT_VIEW)
        .map_err(|(s, j)| (s, Json(AuditApiError::new(&j.error, &j.message))))?;

    let sources = state
        .audit_query_service
        .get_distinct_sources()
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuditApiError::new("query_error", &e.to_string())),
            )
        })?;

    Ok(Json(sources))
}

/// OpenAPI documentation for audit log endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        query_audit_logs,
        export_audit_logs,
        get_action_types,
        get_resource_types,
    ),
    components(schemas(
        AuditApiError,
        AuditLogListResponse,
        AuditLogEntry,
        ExportFormat,
    )),
    tags(
        (name = "audit", description = "Audit log management API")
    )
)]
pub struct AuditApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ch_entry_with_metadata(metadata: serde_json::Value) -> ClickHouseAuditEntry {
        ClickHouseAuditEntry {
            event_id: "evt_1".to_string(),
            timestamp: Utc::now(),
            user: Some("Dan Lussier".to_string()),
            action: Some("apikey_disabled".to_string()),
            source: Some("apikey".to_string()),
            src_ip: None,
            user_agent: None,
            status: Some("success".to_string()),
            message: "[apikey] apikey_disabled on api_key 'foo' by Dan Lussier via API key 'ci-bot'"
                .to_string(),
            metadata: metadata.clone(),
            actor_id: metadata
                .get("actor_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            api_key_id: metadata
                .get("api_key_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            api_key_name: metadata
                .get("api_key_name")
                .and_then(|v| v.as_str())
                .map(String::from),
        }
    }

    #[test]
    fn from_ch_entry_propagates_api_key_actor() {
        let key_id = uuid::Uuid::now_v7().to_string();
        let entry = ch_entry_with_metadata(json!({
            "api_key_id": key_id,
            "api_key_name": "ci-bot",
        }));

        let mapped = AuditLogEntry::from(entry);

        assert_eq!(mapped.api_key_id.as_deref(), Some(key_id.as_str()));
        assert_eq!(mapped.api_key_name.as_deref(), Some("ci-bot"));
    }

    #[test]
    fn from_ch_entry_human_actor_has_no_api_key_fields() {
        let entry = ch_entry_with_metadata(json!({
            "api_key_id": null,
            "api_key_name": null,
        }));

        let mapped = AuditLogEntry::from(entry);

        assert!(mapped.api_key_id.is_none());
        assert!(mapped.api_key_name.is_none());
    }

    #[test]
    fn csv_export_includes_api_key_columns() {
        let entry = AuditLogEntry {
            id: "evt_1".to_string(),
            timestamp: Utc::now(),
            user_id: None,
            user_name: Some("Dan Lussier".to_string()),
            action: Some("apikey_disabled".to_string()),
            source: Some("apikey".to_string()),
            resource_type: None,
            resource_id: None,
            resource_name: None,
            ip_address: None,
            user_agent: None,
            success: true,
            message: None,
            details: None,
            api_key_id: Some("key_abc".to_string()),
            api_key_name: Some("ci-bot".to_string()),
        };

        let csv = generate_csv(&[entry]).expect("csv");
        let mut lines = csv.lines();
        let header = lines.next().expect("header");
        let row = lines.next().expect("row");

        assert!(header.contains("api_key_id,api_key_name"), "header: {header}");
        assert!(row.contains("key_abc,ci-bot"), "row: {row}");
    }
}
