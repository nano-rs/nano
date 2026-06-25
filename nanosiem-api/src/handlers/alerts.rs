// SPDX-License-Identifier: AGPL-3.0-or-later

//! Alert endpoint handlers
//!
//! Implements:
//! - GET /api/alerts with filtering
//! - POST /api/alerts/:id/acknowledge, /close
//! - POST /api/alerts/bulk

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ALERT_ACKNOWLEDGED, ALERT_ASSIGNED,
    ALERT_BULK_ACKNOWLEDGED, ALERT_BULK_CLOSED, ALERT_CLOSED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{Alert, AlertStatus, Disposition, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::utils::BulkResponse;
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// Resolve the authenticated user into a stable display string for the
/// `acknowledged_by` / `closed_by` columns. Looks up the email from the
/// users table (JWT no longer carries PII — see `handlers/auth.rs:734`
/// for the same pattern). Falls back to the user UUID if the lookup
/// fails so we never block the action; the lookup only fails when the
/// caller's row is mid-delete, which is rare. NAN-1068.
async fn resolve_actor_display(state: &AppState, user_id: Uuid) -> String {
    state
        .user_repo
        .get_user_by_id(user_id)
        .await
        .map(|u| u.email)
        .unwrap_or_else(|_| user_id.to_string())
}

/// Recursively remove null, empty strings, and empty arrays/objects from JSON
fn strip_empty_values(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let filtered: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter_map(|(k, v)| {
                    let cleaned = strip_empty_values(v);
                    if is_empty_value(&cleaned) {
                        None
                    } else {
                        Some((k, cleaned))
                    }
                })
                .collect();
            serde_json::Value::Object(filtered)
        }
        serde_json::Value::Array(arr) => {
            let filtered: Vec<serde_json::Value> =
                arr.into_iter().map(strip_empty_values).collect();
            serde_json::Value::Array(filtered)
        }
        other => other,
    }
}

/// Check if a JSON value should be considered "empty"
/// Note: Numbers (including 0) are never empty - 0 is a valid value in security data
/// (e.g., port 0, exit code 0, process ID 0, status codes)
fn is_empty_value(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Number(_) => false, // 0 is a valid value, not empty
        serde_json::Value::Array(arr) => arr.is_empty(),
        serde_json::Value::Object(map) => map.is_empty(),
        serde_json::Value::Bool(_) => false,
    }
}

/// Query parameters for listing alerts
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct ListAlertsQuery {
    pub status: Option<AlertStatus>,
    pub severity: Option<Severity>,
    #[serde(default, with = "nanosiem_core::typeid::rule::opt")]
    #[param(value_type = Option<String>)]
    pub rule_id: Option<Uuid>,
    /// NAN-1541: comma-separated alert-spine kinds to include
    /// (`detection`, `metric_monitor`, `slo`, `synthetic`). Omitted = all
    /// kinds. The SIEM Alerts view passes `detection`; the Observability
    /// Alerts view passes the monitor kinds.
    #[serde(default)]
    pub kinds: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// Parse the comma-separated `kinds` query param into the slice form the
/// repository expects. Empty / whitespace-only entries are dropped; an
/// all-empty result yields `None` (= all kinds). NAN-1541.
fn parse_kinds(kinds: &Option<String>) -> Option<Vec<String>> {
    let raw = kinds.as_ref()?;
    let parsed: Vec<String> = raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    if parsed.is_empty() {
        None
    } else {
        Some(parsed)
    }
}

/// Query parameters for streaming alerts
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct StreamAlertsQuery {
    pub cursor: Option<String>,
    #[serde(default = "default_stream_limit")]
    pub limit: i64,
}

fn default_stream_limit() -> i64 {
    100
}

/// Response for alert stream
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AlertStreamResponse {
    pub alerts: Vec<Alert>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Request for closing an alert. NAN-1068: the actor (`closed_by`) is
/// derived server-side from the JWT — only the disposition is supplied
/// by the client.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CloseRequest {
    pub disposition: Disposition,
}

/// Request for assigning an alert
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssignRequest {
    pub assigned_to: String,
}

/// Request for bulk operations. NAN-1068: the actor is derived
/// server-side from the JWT.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BulkRequest {
    #[serde(alias = "alert_ids", with = "nanosiem_core::typeid::alert::vec")]
    #[schema(value_type = Vec<String>)]
    pub ids: Vec<Uuid>,
    pub action: BulkAction,
    pub disposition: Option<Disposition>,
}

/// Bulk action type
#[derive(Debug, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkAction {
    Acknowledge,
    Close,
}

/// Alert counts by status
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct AlertCounts {
    pub total: i64,
    pub new: i64,
    pub acknowledged: i64,
    pub closed: i64,
    pub by_severity: std::collections::HashMap<String, i64>,
}

/// List alerts with optional filters
#[utoipa::path(
    get,
    path = "/api/alerts",
    tag = "alerts",
    params(ListAlertsQuery),
    responses(
        (status = 200, description = "List of alerts", body = Vec<Alert>),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_alerts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListAlertsQuery>,
) -> Result<Json<Vec<Alert>>, ApiError> {
    check_permission(&auth, permissions::ALERTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:view".to_string()))?;

    let kinds = parse_kinds(&query.kinds);
    let alerts = if let Some(rule_id) = query.rule_id {
        state.detection_service.list_alerts_by_rule(rule_id).await?
    } else {
        state
            .detection_service
            .list_alerts(
                query.status,
                query.severity,
                kinds.as_deref(),
                query.limit,
                query.offset,
            )
            .await?
    };

    // Demo isolation: hide alerts from rules created by other demo users
    let alerts = if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if exclude_rule_ids.is_empty() {
            alerts
        } else {
            alerts
                .into_iter()
                .filter(|a| a.rule_id.map_or(true, |rid| !exclude_rule_ids.contains(&rid)))
                .collect()
        }
    } else {
        alerts
    };

    Ok(Json(alerts))
}

/// Stream alerts using cursor-based pagination for external systems (SOAR)
#[utoipa::path(
    get,
    path = "/api/alerts/stream",
    tag = "alerts",
    params(StreamAlertsQuery),
    responses(
        (status = 200, description = "Paginated alert stream", body = AlertStreamResponse),
        (status = 400, description = "Invalid cursor", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn stream_alerts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<StreamAlertsQuery>,
) -> Result<Json<AlertStreamResponse>, ApiError> {
    check_permission(&auth, permissions::ALERTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:view".to_string()))?;

    let (after_timestamp, after_id) = if let Some(cursor_str) = query.cursor {
        // Decode cursor: base64(rfc3339_timestamp|uuid)
        let decoded = BASE64.decode(cursor_str).map_err(|_| {
            ApiError::ValidationError("Invalid cursor: base64 decode failed".to_string())
        })?;
        let s = String::from_utf8(decoded).map_err(|_| {
            ApiError::ValidationError("Invalid cursor: utf8 decode failed".to_string())
        })?;

        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() != 2 {
            return Err(ApiError::ValidationError(
                "Invalid cursor: expected timestamp|uuid".to_string(),
            ));
        }

        let ts = chrono::DateTime::parse_from_rfc3339(parts[0])
            .map_err(|_| {
                ApiError::ValidationError("Invalid cursor: invalid timestamp".to_string())
            })?
            .with_timezone(&chrono::Utc);
        let id = Uuid::parse_str(parts[1])
            .map_err(|_| ApiError::ValidationError("Invalid cursor: invalid uuid".to_string()))?;

        (ts, id)
    } else {
        // No cursor, start from Unix epoch (PostgreSQL can't handle MIN_UTC)
        (chrono::DateTime::UNIX_EPOCH, Uuid::nil())
    };

    let limit = query.limit.min(1000); // Sanity check
    let alerts = state
        .detection_service
        .list_alerts_after(after_timestamp, after_id, limit)
        .await?;

    let has_more = alerts.len() == limit as usize;
    let next_cursor = alerts.last().map(|last| {
        let s = format!("{}|{}", last.created_at.to_rfc3339(), last.id);
        BASE64.encode(s)
    });

    // Strip empty values from matched_events to reduce payload size
    let alerts: Vec<Alert> = alerts
        .into_iter()
        .map(|mut alert| {
            alert.matched_events = strip_empty_values(alert.matched_events);
            alert
        })
        .collect();

    // Demo isolation: hide alerts from rules created by other demo users
    let alerts = if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if exclude_rule_ids.is_empty() {
            alerts
        } else {
            alerts
                .into_iter()
                .filter(|a| a.rule_id.map_or(true, |rid| !exclude_rule_ids.contains(&rid)))
                .collect()
        }
    } else {
        alerts
    };

    Ok(Json(AlertStreamResponse {
        alerts,
        next_cursor,
        has_more,
    }))
}

/// Get an alert by ID
#[utoipa::path(
    get,
    path = "/api/alerts/{id}",
    tag = "alerts",
    params(
        ("id" = String, Path, description = "Alert ID")
    ),
    responses(
        (status = 200, description = "Alert details", body = Alert),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Alert not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Alert>, ApiError> {
    check_permission(&auth, permissions::ALERTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:view".to_string()))?;

    let alert = state.detection_service.get_alert(*id).await?;

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if alert.rule_id.map_or(false, |rid| exclude_rule_ids.contains(&rid)) {
            return Err(ApiError::NotFound("Alert not found".to_string()));
        }
    }

    Ok(Json(alert))
}

/// Acknowledge an alert. The actor (`acknowledged_by`) is derived
/// server-side from the JWT — no request body is required (NAN-1068).
#[utoipa::path(
    post,
    path = "/api/alerts/{id}/acknowledge",
    tag = "alerts",
    params(
        ("id" = String, Path, description = "Alert ID")
    ),
    responses(
        (status = 200, description = "Alert acknowledged", body = Alert),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Alert not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn acknowledge_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<Alert>, ApiError> {
    check_permission(&auth, permissions::ALERTS_ACKNOWLEDGE)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:acknowledge".to_string()))?;

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let alert = state.detection_service.get_alert(*id).await?;
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if alert.rule_id.map_or(false, |rid| exclude_rule_ids.contains(&rid)) {
            return Err(ApiError::NotFound("Alert not found".to_string()));
        }
    }

    let actor = resolve_actor_display(&state, auth.user_id()).await;
    let alert = state
        .detection_service
        .acknowledge_alert(*id, &actor)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Alert, ALERT_ACKNOWLEDGED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("alert", Some(*id), alert.rule_name.clone())
            .client_context(&client)
            .build(),
    );

    Ok(Json(alert))
}

/// Close an alert
#[utoipa::path(
    post,
    path = "/api/alerts/{id}/close",
    tag = "alerts",
    params(
        ("id" = String, Path, description = "Alert ID")
    ),
    request_body = CloseRequest,
    responses(
        (status = 200, description = "Alert closed", body = Alert),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Alert not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn close_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<CloseRequest>,
) -> Result<Json<Alert>, ApiError> {
    check_permission(&auth, permissions::ALERTS_CLOSE)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:close".to_string()))?;

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let alert = state.detection_service.get_alert(*id).await?;
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if alert.rule_id.map_or(false, |rid| exclude_rule_ids.contains(&rid)) {
            return Err(ApiError::NotFound("Alert not found".to_string()));
        }
    }

    let actor = resolve_actor_display(&state, auth.user_id()).await;
    let alert = state
        .detection_service
        .close_alert(*id, &actor, request.disposition)
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Alert, ALERT_CLOSED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("alert", Some(*id), alert.rule_name.clone())
            .client_context(&client)
            .details(serde_json::json!({ "disposition": format!("{:?}", request.disposition) }))
            .build(),
    );

    Ok(Json(alert))
}

/// Assign an alert
#[utoipa::path(
    post,
    path = "/api/alerts/{id}/assign",
    tag = "alerts",
    params(
        ("id" = String, Path, description = "Alert ID")
    ),
    request_body = AssignRequest,
    responses(
        (status = 200, description = "Alert assigned", body = Alert),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 404, description = "Alert not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn assign_alert(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<AssignRequest>,
) -> Result<Json<Alert>, ApiError> {
    use nanosiem_core::db::repository::NotificationRepository;
    use nanosiem_core::models::notification::{NewNotification, NotificationType};

    check_permission(&auth, permissions::ALERTS_ASSIGN)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:assign".to_string()))?;

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let alert = state.detection_service.get_alert(*id).await?;
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if alert.rule_id.map_or(false, |rid| exclude_rule_ids.contains(&rid)) {
            return Err(ApiError::NotFound("Alert not found".to_string()));
        }
    }

    let alert = state
        .detection_service
        .assign_alert(*id, &request.assigned_to)
        .await?;

    // Send notification to assignee if assigned to someone other than self
    if let Ok(assigned_user_id) = Uuid::parse_str(&request.assigned_to) {
        if assigned_user_id != auth.user_id() {
            let notification_repo = NotificationRepository::new(state.pool.clone());
            // Fetch user name from database (JWT no longer contains PII)
            let assigner_name = state
                .user_repo
                .get_user_by_id(auth.user_id())
                .await
                .map(|u| u.name)
                .unwrap_or_else(|_| "Unknown User".to_string());

            let notification = NewNotification {
                user_id: assigned_user_id,
                notification_type: NotificationType::AlertAssigned,
                title: format!(
                    "Alert assigned to you: {}",
                    alert.rule_name.as_deref().unwrap_or("Unknown Rule")
                ),
                message: Some(format!(
                    "{} assigned you to a {:?} severity alert",
                    assigner_name, alert.severity
                )),
                link: Some(format!("/alerts/{}", id)),
                metadata: serde_json::json!({
                    "alert_id": id.to_string(),
                    "rule_id": alert.rule_id.map(|r| r.to_string()),
                    "rule_name": alert.rule_name,
                    "severity": format!("{:?}", alert.severity),
                    "assigner_id": auth.user_id().to_string(),
                    "assigner_name": assigner_name,
                }),
            };

            if let Err(e) = notification_repo.create(&notification).await {
                tracing::warn!(
                    user_id = %assigned_user_id,
                    alert_id = %id,
                    error = %e,
                    "Failed to create alert assignment notification"
                );
            }
        }
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Alert, ALERT_ASSIGNED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("alert", Some(*id), alert.rule_name.clone())
            .client_context(&client)
            .details(serde_json::json!({ "assigned_to": request.assigned_to }))
            .build(),
    );

    Ok(Json(alert))
}

/// Bulk operations on alerts
#[utoipa::path(
    post,
    path = "/api/alerts/bulk",
    tag = "alerts",
    request_body = BulkRequest,
    responses(
        (status = 200, description = "Bulk operation completed", body = BulkResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn bulk_alerts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<BulkRequest>,
) -> Result<Json<BulkResponse>, ApiError> {
    if request.ids.is_empty() {
        return Err(ApiError::BadRequest("No alert IDs provided".to_string()));
    }
    if request.ids.len() > 100 {
        return Err(ApiError::BadRequest(
            "Cannot process more than 100 alerts at once".to_string(),
        ));
    }

    // Check appropriate permission based on action
    match request.action {
        BulkAction::Acknowledge => {
            check_permission(&auth, permissions::ALERTS_ACKNOWLEDGE).map_err(|_| {
                ApiError::Forbidden("Missing permission: alerts:acknowledge".to_string())
            })?;
        }
        BulkAction::Close => {
            check_permission(&auth, permissions::ALERTS_CLOSE)
                .map_err(|_| ApiError::Forbidden("Missing permission: alerts:close".to_string()))?;
        }
    }

    // Demo isolation: filter out alerts from other demo users' rules
    let ids = if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if exclude_rule_ids.is_empty() {
            request.ids.clone()
        } else {
            let mut allowed = Vec::new();
            for id in &request.ids {
                if let Ok(alert) = state.detection_service.get_alert(*id).await {
                    if alert.rule_id.map_or(true, |rid| !exclude_rule_ids.contains(&rid)) {
                        allowed.push(*id);
                    }
                }
            }
            allowed
        }
    } else {
        request.ids.clone()
    };

    let actor = resolve_actor_display(&state, auth.user_id()).await;
    let affected = match request.action {
        BulkAction::Acknowledge => {
            state
                .detection_service
                .bulk_acknowledge_alerts(&ids, &actor)
                .await?
        }
        BulkAction::Close => {
            let disposition = request.disposition.ok_or_else(|| {
                ApiError::ValidationError("Disposition required for close action".to_string())
            })?;
            state
                .detection_service
                .bulk_close_alerts(&ids, &actor, disposition)
                .await?
        }
    };

    let audit_action = match request.action {
        BulkAction::Acknowledge => ALERT_BULK_ACKNOWLEDGED,
        BulkAction::Close => ALERT_BULK_CLOSED,
    };
    state.emit_audit(
        AuditEvent::builder(AuditSource::Alert, audit_action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .details(serde_json::json!({ "count": request.ids.len(), "affected": affected }))
            .build(),
    );

    Ok(Json(BulkResponse { affected }))
}

/// Query parameters for alert counts (NAN-1541: optional kind filter).
#[derive(Debug, Deserialize, Default, utoipa::IntoParams)]
pub struct AlertCountsQuery {
    /// Comma-separated alert-spine kinds to include. Omitted = all kinds.
    #[serde(default)]
    pub kinds: Option<String>,
}

/// Get alert counts by status
#[utoipa::path(
    get,
    path = "/api/alerts/counts",
    tag = "alerts",
    params(AlertCountsQuery),
    responses(
        (status = 200, description = "Alert counts by status", body = AlertCounts),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn alert_counts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<AlertCountsQuery>,
) -> Result<Json<AlertCounts>, ApiError> {
    check_permission(&auth, permissions::ALERTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:view".to_string()))?;

    let kinds = parse_kinds(&query.kinds);

    // Demo isolation: compute filtered counts for demo users
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if !exclude_rule_ids.is_empty() {
            let all_alerts = state
                .detection_service
                .list_alerts(None, None, kinds.as_deref(), 10000, 0)
                .await?;
            let filtered: Vec<_> = all_alerts
                .into_iter()
                .filter(|a| a.rule_id.map_or(true, |rid| !exclude_rule_ids.contains(&rid)))
                .collect();

            let mut total = 0i64;
            let mut new = 0i64;
            let mut acknowledged = 0i64;
            let mut closed = 0i64;
            for alert in &filtered {
                total += 1;
                match alert.status {
                    AlertStatus::New => new += 1,
                    AlertStatus::Acknowledged => acknowledged += 1,
                    AlertStatus::Closed => closed += 1,
                }
            }
            return Ok(Json(AlertCounts {
                total,
                new,
                acknowledged,
                closed,
                by_severity: std::collections::HashMap::new(),
            }));
        }
    }

    let counts = state
        .detection_service
        .get_alert_counts(kinds.as_deref())
        .await?;

    let mut total = 0i64;
    let mut new = 0i64;
    let mut acknowledged = 0i64;
    let mut closed = 0i64;

    for (status, count) in counts {
        total += count;
        match status {
            AlertStatus::New => new = count,
            AlertStatus::Acknowledged => acknowledged = count,
            AlertStatus::Closed => closed = count,
        }
    }

    // TODO: Add by_severity counts from a separate query
    let by_severity = std::collections::HashMap::new();

    Ok(Json(AlertCounts {
        total,
        new,
        acknowledged,
        closed,
        by_severity,
    }))
}

/// Velocity histogram point — one hourly bucket from /api/alerts/velocity.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VelocityBucket {
    /// Bucket start timestamp (UTC, ISO-8601).
    pub bucket_start: String,
    /// Alerts created in this hour.
    pub count: i64,
}

/// Query for /api/alerts/velocity. NAN-1019: powers the FIRING NOW
/// 24h sparkline on the Rules index. Hours is clamped to [1, 168]
/// (7 days) — long enough for weekly trend overlays without letting
/// callers DoS the DB with arbitrary windows.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct VelocityQuery {
    #[serde(default = "default_velocity_hours")]
    pub hours: u32,
    /// NAN-1541: comma-separated alert-spine kinds to include. Omitted = all
    /// kinds. The SIEM Rules sparkline passes `detection`.
    #[serde(default)]
    pub kinds: Option<String>,
}

fn default_velocity_hours() -> u32 {
    24
}

/// Get alert velocity (hourly histogram over the last N hours)
///
/// Returns one bucket per hour in the window, including hours with
/// zero alerts so the frontend can render a fixed-length sparkline
/// without filling gaps client-side. Buckets are ordered chronologically.
#[utoipa::path(
    get,
    path = "/api/alerts/velocity",
    tag = "alerts",
    params(VelocityQuery),
    responses(
        (status = 200, description = "Hourly velocity buckets", body = Vec<VelocityBucket>),
        (status = 403, description = "Forbidden", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn alert_velocity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<VelocityQuery>,
) -> Result<Json<Vec<VelocityBucket>>, ApiError> {
    check_permission(&auth, permissions::ALERTS_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: alerts:view".to_string()))?;

    let hours = query.hours.clamp(1, 168) as i64;
    let now = chrono::Utc::now();
    let start = now - chrono::Duration::hours(hours);

    // Bucket via date_trunc('hour', ...). LEFT JOIN against a generate_series
    // so every hour in the window is represented even when no alerts hit it
    // (otherwise the sparkline would have gaps + the frontend would have to
    // backfill).
    //
    // generate_series is inclusive on both ends, so the upper bound is `now -
    // 1h` rather than `now` — that gives exactly `hours` complete buckets
    // (the in-progress current hour is excluded; analysts see settled data).
    //
    // No demo-isolation filter (cf. `alert_counts`): a 24-bucket hourly
    // histogram doesn't expose per-rule attribution, so the aggregate is
    // safe to surface across demo_analyst boundaries.
    // NAN-1541: optional kind filter ($3::text[]; NULL = all kinds).
    let kinds = parse_kinds(&query.kinds);
    let sql = r#"
        SELECT
            bucket as bucket_start,
            COALESCE(c.count, 0) AS count
        FROM generate_series(
            date_trunc('hour', $1::timestamptz),
            date_trunc('hour', $2::timestamptz) - interval '1 hour',
            interval '1 hour'
        ) AS bucket
        LEFT JOIN (
            SELECT date_trunc('hour', created_at) AS bucket_start, COUNT(*) AS count
            FROM alerts
            WHERE created_at >= $1 AND created_at < $2
              AND ($3::text[] IS NULL OR kind = ANY($3))
            GROUP BY bucket_start
        ) c ON c.bucket_start = bucket
        ORDER BY bucket ASC
    "#;

    let rows = sqlx::query(sql)
        .bind(start)
        .bind(now)
        .bind(kinds)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    use sqlx::Row;
    let buckets: Vec<VelocityBucket> = rows
        .into_iter()
        .map(|row| {
            let bucket: chrono::DateTime<chrono::Utc> = row.get("bucket_start");
            let count: i64 = row.get("count");
            VelocityBucket {
                bucket_start: bucket.to_rfc3339(),
                count,
            }
        })
        .collect();

    Ok(Json(buckets))
}

/// OpenAPI documentation for alerts endpoints
pub struct AlertsApiDoc;

impl utoipa::OpenApi for AlertsApiDoc {
    fn openapi() -> utoipa::openapi::OpenApi {
        use utoipa::OpenApi;

        #[derive(OpenApi)]
        #[openapi(
            paths(
                list_alerts,
                stream_alerts,
                bulk_alerts,
                alert_counts,
                alert_velocity,
                get_alert,
                acknowledge_alert,
                close_alert,
                assign_alert,
            ),
            components(schemas(
                AlertStreamResponse,
                CloseRequest,
                AssignRequest,
                BulkRequest,
                BulkAction,
                AlertCounts,
                VelocityBucket,
            ))
        )]
        struct ApiDoc;

        ApiDoc::openapi()
    }
}
