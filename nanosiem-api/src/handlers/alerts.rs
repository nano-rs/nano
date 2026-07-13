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
use crate::middleware::{ensure_permission, AuthContext};
use crate::utils::BulkResponse;
use crate::{
    error::{ApiError, ErrorResponse},
    state::AppState,
};

/// NAN-1800: compose the caller's EFFECTIVE per-source deny scope for
/// detection-derived surfaces — the per-source RBAC deny set (NAN-1799)
/// unioned with the `audit` source unless the caller holds `audit:view`.
/// Mirrors the dashboards panel-query composition. An unrestricted caller
/// with `audit:view` yields an empty deny set, and every repository query
/// stays byte-identical to the pre-scoping SQL.
fn effective_viewer_scope(auth: &AuthContext) -> nanosiem_core::auth::ScopeSet {
    let mut deny = auth.denied_sources.deny_set().clone();
    if !auth.has_permission(permissions::AUDIT_VIEW) {
        deny.insert("audit".to_string());
    }
    nanosiem_core::auth::ScopeSet::from_denied(deny)
}

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

/// A10 (NAN-1747): clamp a page limit into `[1, 1000]`. Both the list and the
/// stream funnel through this. `limit=0` on the stream path returns an empty
/// page with `has_more=true` and `next_cursor=None`, so a spec-following SOAR
/// client loops forever; a negative limit reaches Postgres as `LIMIT -1` and
/// 500s. The upper bound is the existing 1000 sanity cap.
fn clamp_page_limit(limit: i64) -> i64 {
    limit.clamp(1, 1000)
}

/// A10 (NAN-1747): a negative `OFFSET` is a Postgres error (500); clamp to 0.
fn clamp_offset(offset: i64) -> i64 {
    offset.max(0)
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
    ensure_permission(&auth, permissions::ALERTS_VIEW)?;

    let kinds = parse_kinds(&query.kinds);
    let limit = clamp_page_limit(query.limit);
    let offset = clamp_offset(query.offset);
    // NAN-1800: per-source viewer scope, enforced inside the repository SQL.
    let scope = effective_viewer_scope(&auth);
    // A4 (NAN-1747): route the `rule_id` filter through the same unified list as
    // every other filter, so status/severity/kinds + limit/offset all apply. The
    // old `list_alerts_by_rule` short-circuit hard-capped at 100 and silently
    // dropped every other query param (a `status=new` filter would still return
    // closed alerts; alerts past the first 100 were unreachable). DetectionService
    // exposes no rule-scoped *filtered* list and is outside this fix's edit
    // scope, so build the repo from the shared pool directly (same pattern as
    // NotificationRepository in `assign_alert`).
    let alerts = if let Some(rule_id) = query.rule_id {
        nanosiem_core::db::repository::AlertRepository::new(state.pool.clone())
            .list_filtered(
                query.status,
                query.severity,
                Some(rule_id),
                kinds.as_deref(),
                limit,
                offset,
                scope.deny_set(),
            )
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?
    } else {
        state
            .detection_service
            .list_alerts(
                query.status,
                query.severity,
                kinds.as_deref(),
                limit,
                offset,
                scope.deny_set(),
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
    ensure_permission(&auth, permissions::ALERTS_VIEW)?;

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

    // A10 (NAN-1747): clamp to [1, 1000]. `limit=0` previously returned an empty
    // page with `has_more=true`/`next_cursor=None` → an infinite SOAR poll loop;
    // a negative limit 500'd at the DB.
    let limit = clamp_page_limit(query.limit);
    // NAN-1800: per-source viewer scope — the SOAR stream must not leak
    // alerts derived from sources the caller can't see.
    let scope = effective_viewer_scope(&auth);
    let alerts = state
        .detection_service
        .list_alerts_after(after_timestamp, after_id, limit, scope.deny_set())
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
    ensure_permission(&auth, permissions::ALERTS_VIEW)?;

    // NAN-1800: a source-denied alert reads as 404, indistinguishable from
    // nonexistent.
    let scope = effective_viewer_scope(&auth);
    let alert = state
        .detection_service
        .get_alert(*id, scope.deny_set())
        .await?;

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
    ensure_permission(&auth, permissions::ALERTS_ACKNOWLEDGE)?;

    // NAN-1800: mutations are deny-scoped too — a source-denied alert 404s
    // BEFORE any state change.
    let scope = effective_viewer_scope(&auth);

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let alert = state
            .detection_service
            .get_alert(*id, scope.deny_set())
            .await?;
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
        .acknowledge_alert(*id, &actor, scope.deny_set())
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
    ensure_permission(&auth, permissions::ALERTS_CLOSE)?;

    // NAN-1800: deny-scoped mutation (see acknowledge_alert).
    let scope = effective_viewer_scope(&auth);

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let alert = state
            .detection_service
            .get_alert(*id, scope.deny_set())
            .await?;
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
        .close_alert(*id, &actor, request.disposition, scope.deny_set())
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

    ensure_permission(&auth, permissions::ALERTS_ASSIGN)?;

    // NAN-1800: deny-scoped mutation (see acknowledge_alert).
    let scope = effective_viewer_scope(&auth);

    // Demo isolation: block access to alerts from other demo users' rules
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let alert = state
            .detection_service
            .get_alert(*id, scope.deny_set())
            .await?;
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if alert.rule_id.map_or(false, |rid| exclude_rule_ids.contains(&rid)) {
            return Err(ApiError::NotFound("Alert not found".to_string()));
        }
    }

    let alert = state
        .detection_service
        .assign_alert(*id, &request.assigned_to, scope.deny_set())
        .await?;

    // Send notification to assignee if assigned to someone other than self.
    // A3 (NAN-1747): the FE sends a typeid (`user_<base32>`), which
    // `Uuid::parse_str` always rejects — so the `if let Ok` silently skipped and
    // the assignee never got notified. `parse_any` accepts both the typeid and
    // the raw-UUID forms.
    if let Ok((prefix, assigned_user_id)) = nanosiem_core::typeid::parse_any(&request.assigned_to) {
        // Only treat this as a user id when it's a `user_…` typeid or a bare
        // UUID — a mismatched prefix (e.g. `case_…`) whose decoded UUID happens
        // to match a real user must NOT trigger a notification to that user.
        let is_user_id = prefix.is_empty() || prefix == nanosiem_core::typeid::user::PREFIX;
        if is_user_id && assigned_user_id != auth.user_id() {
            let notification_repo = NotificationRepository::new(state.pool.clone());
            // Fetch user name from database (JWT no longer contains PII)
            let assigner_name = state
                .user_repo
                .get_user_by_id(auth.user_id())
                .await
                .map(|u| u.name)
                .unwrap_or_else(|_| "Unknown User".to_string());

            // The `assign_alert` return is a bare `RETURNING *` with no joined
            // `rule_name`, so it was always None here — every assignment
            // notification rendered "Unknown Rule". Resolve the rule name via
            // the joined fetch (only on the notify path) (NAN-1754).
            let rule_display = state
                .detection_service
                .get_alert(*id, scope.deny_set())
                .await
                .ok()
                .and_then(|a| a.rule_name)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| "an alert".to_string());

            let notification = NewNotification {
                user_id: assigned_user_id,
                notification_type: NotificationType::AlertAssigned,
                title: format!("Alert assigned to you: {}", rule_display),
                message: Some(format!(
                    "{} assigned you to a {:?} severity alert",
                    assigner_name, alert.severity
                )),
                // A3: canonical prefixed typeid (matches the webhook link-back
                // form); `id`'s Display renders a prefix-less base32.
                link: Some(format!(
                    "/alerts/{}",
                    nanosiem_core::typeid::encode(nanosiem_core::typeid::alert::PREFIX, &id)
                )),
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
            ensure_permission(&auth, permissions::ALERTS_ACKNOWLEDGE)?;
        }
        BulkAction::Close => {
            ensure_permission(&auth, permissions::ALERTS_CLOSE)?;
        }
    }

    // NAN-1800: deny-scoped — the bulk UPDATE itself excludes source-denied
    // rows, so a restricted viewer can't mutate alerts they can't see.
    let scope = effective_viewer_scope(&auth);

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
                // A14 (NAN-1747): distinguish "not found" (skip this id) from a
                // transient DB error (fail the whole bulk op). The old
                // `if let Ok(..)` swallowed every error, silently shrinking the
                // affected set with no signal to the caller.
                match state.detection_service.get_alert(*id, scope.deny_set()).await {
                    Ok(alert) => {
                        if alert.rule_id.map_or(true, |rid| !exclude_rule_ids.contains(&rid)) {
                            allowed.push(*id);
                        }
                    }
                    Err(nanosiem_core::DetectionError::AlertNotFound(_)) => continue,
                    Err(e) => return Err(e.into()),
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
                .bulk_acknowledge_alerts(&ids, &actor, scope.deny_set())
                .await?
        }
        BulkAction::Close => {
            let disposition = request.disposition.ok_or_else(|| {
                ApiError::ValidationError("Disposition required for close action".to_string())
            })?;
            state
                .detection_service
                .bulk_close_alerts(&ids, &actor, disposition, scope.deny_set())
                .await?
        }
    };

    let audit_action = match request.action {
        BulkAction::Acknowledge => ALERT_BULK_ACKNOWLEDGED,
        BulkAction::Close => ALERT_BULK_CLOSED,
    };
    // A7 (NAN-1747): record WHICH alerts were operated on (the post-demo-filter
    // set) plus the disposition, so a bulk close/ack is reconstructable from the
    // audit trail. `count` is the requested id count; `affected` is the number
    // of rows the UPDATE actually touched; `alert_ids` is the filtered target set.
    let affected_typeids: Vec<String> = ids
        .iter()
        .map(|id| nanosiem_core::typeid::encode(nanosiem_core::typeid::alert::PREFIX, id))
        .collect();
    state.emit_audit(
        AuditEvent::builder(AuditSource::Alert, audit_action)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .client_context(&client)
            .details(serde_json::json!({
                "count": request.ids.len(),
                "affected": affected,
                "alert_ids": affected_typeids,
                "disposition": request.disposition.map(|d| format!("{:?}", d)),
            }))
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
    ensure_permission(&auth, permissions::ALERTS_VIEW)?;

    let kinds = parse_kinds(&query.kinds);
    // NAN-1800: counts must agree with the deny-scoped list.
    let scope = effective_viewer_scope(&auth);

    // Demo isolation: compute filtered counts for demo users
    if auth.claims.roles.contains(&"demo_analyst".to_string()) {
        let exclude_rule_ids = state
            .get_demo_exclude_ids(auth.user_id(), nanosiem_core::demo::DemoResourceType::Rule)
            .await;
        if !exclude_rule_ids.is_empty() {
            // A12 (NAN-1747): count with a single SQL aggregate (exclusion in the
            // WHERE) instead of materializing a 10k-row list and counting in Rust
            // — the old path also silently capped the demo total at 10k. NULL
            // rule_id rows (observability alerts) are kept, matching the
            // non-demo filter semantics.
            let exclude_vec: Vec<Uuid> = exclude_rule_ids.iter().copied().collect();
            let counts = nanosiem_core::db::repository::AlertRepository::new(state.pool.clone())
                .count_by_status_excluding_rules(kinds.as_deref(), &exclude_vec, scope.deny_set())
                .await
                .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

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
        .get_alert_counts(kinds.as_deref(), scope.deny_set())
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
    ensure_permission(&auth, permissions::ALERTS_VIEW)?;

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
    // NAN-1800: even an hourly histogram leaks existence/cadence of alerts
    // from denied sources — apply the same per-source deny filter as the list.
    // Empty deny set (unrestricted + audit:view) emits the pre-scoping SQL
    // byte-identically with no extra bind.
    let scope = effective_viewer_scope(&auth);
    let deny_vec: Option<Vec<String>> = if scope.deny_set().is_empty() {
        None
    } else {
        Some(
            scope
                .deny_set()
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
        )
    };
    let scope_sql = if deny_vec.is_some() {
        "\n              AND ($4::text[] = '{}' OR NOT (source_types && $4::text[]))"
    } else {
        ""
    };
    let sql = format!(
        r#"
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
              AND ($3::text[] IS NULL OR kind = ANY($3)){scope_sql}
            GROUP BY bucket_start
        ) c ON c.bucket_start = bucket
        ORDER BY bucket ASC
    "#
    );

    let mut velocity_query = sqlx::query(&sql).bind(start).bind(now).bind(kinds);
    if let Some(denied) = &deny_vec {
        velocity_query = velocity_query.bind(denied);
    }
    let rows = velocity_query
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

// NAN-1747 pure-logic tests (limit clamp A10, typeid parse A3) in a sibling file.
#[cfg(test)]
#[path = "alerts_nan1747_tests.rs"]
mod alerts_nan1747_tests;

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
