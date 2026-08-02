// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authorized system-health lifecycle and delivery-history API.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::{
    audit::{
        AuditEvent, AuditSource, ClientContext, SYSTEM_HEALTH_ACKNOWLEDGED, SYSTEM_HEALTH_RESOLVED,
    },
    auth::permissions,
    system_health::{
        HealthBusSummary, HealthDelivery, HealthEventList, SystemHealthError, SystemHealthEvent,
        SystemHealthRepository,
    },
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;

use crate::{
    error::{ApiError, ErrorResponse},
    handlers::AuditExt,
    middleware::{ensure_permission, AuthContext},
    state::AppState,
};

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListHealthEventsQuery {
    /// `active` or `resolved`.
    pub status: Option<String>,
    /// Normalized producer category, such as `integration` or `log_source`.
    pub category: Option<String>,
    /// Severity filter.
    pub severity: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct HealthDeliveriesQuery {
    pub limit: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/system-health/events",
    tag = "system_health",
    params(ListHealthEventsQuery),
    responses(
        (status = 200, description = "System health events", body = HealthEventList),
        (status = 403, description = "Missing system_health:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_health_events(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListHealthEventsQuery>,
) -> Result<Json<HealthEventList>, ApiError> {
    ensure_permission(&auth, permissions::SYSTEM_HEALTH_VIEW)?;
    validate_filters(&query)?;
    let repo = SystemHealthRepository::new(state.pool.clone());
    let (events, total) = repo
        .list(
            query.status.as_deref(),
            query.category.as_deref(),
            query.severity.as_deref(),
            query.limit.unwrap_or(50),
            query.offset.unwrap_or(0),
        )
        .await
        .map_err(map_error)?;
    Ok(Json(HealthEventList { events, total }))
}

#[utoipa::path(
    get,
    path = "/api/system-health/summary",
    tag = "system_health",
    responses(
        (status = 200, description = "Active lifecycle and delivery summary", body = HealthBusSummary),
        (status = 403, description = "Missing system_health:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_health_summary(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<HealthBusSummary>, ApiError> {
    ensure_permission(&auth, permissions::SYSTEM_HEALTH_VIEW)?;
    let summary = SystemHealthRepository::new(state.pool.clone())
        .summary()
        .await
        .map_err(map_error)?;
    Ok(Json(summary))
}

#[utoipa::path(
    post,
    path = "/api/system-health/events/{id}/acknowledge",
    tag = "system_health",
    params(("id" = Uuid, Path, description = "System health event UUID")),
    responses(
        (status = 200, description = "Acknowledged event", body = SystemHealthEvent),
        (status = 403, description = "Missing system_health:manage", body = ErrorResponse),
        (status = 404, description = "Event not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn acknowledge_health_event(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SystemHealthEvent>, ApiError> {
    ensure_permission(&auth, permissions::SYSTEM_HEALTH_MANAGE)?;
    let event = SystemHealthRepository::new(state.pool.clone())
        .acknowledge(id, auth.user_id())
        .await
        .map_err(map_error)?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, SYSTEM_HEALTH_ACKNOWLEDGED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("system_health_event", Some(id), Some(event.title.clone()))
            .client_context(&client)
            .build(),
    );
    Ok(Json(event))
}

#[utoipa::path(
    post,
    path = "/api/system-health/events/{id}/resolve",
    tag = "system_health",
    params(("id" = Uuid, Path, description = "System health event UUID")),
    responses(
        (status = 200, description = "Resolved event; recovery delivery queued", body = SystemHealthEvent),
        (status = 403, description = "Missing system_health:manage", body = ErrorResponse),
        (status = 404, description = "Active event not found", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn resolve_health_event(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<SystemHealthEvent>, ApiError> {
    ensure_permission(&auth, permissions::SYSTEM_HEALTH_MANAGE)?;
    let event = SystemHealthRepository::new(state.pool.clone())
        .resolve_by_id(id)
        .await
        .map_err(map_error)?;
    state.emit_audit(
        AuditEvent::builder(AuditSource::Settings, SYSTEM_HEALTH_RESOLVED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("system_health_event", Some(id), Some(event.title.clone()))
            .client_context(&client)
            .build(),
    );
    Ok(Json(event))
}

#[utoipa::path(
    get,
    path = "/api/system-health/events/{id}/deliveries",
    tag = "system_health",
    params(
        ("id" = Uuid, Path, description = "System health event UUID"),
        HealthDeliveriesQuery,
    ),
    responses(
        (status = 200, description = "Durable deliveries, including retries and dead letters", body = Vec<HealthDelivery>),
        (status = 403, description = "Missing system_health:view", body = ErrorResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_health_deliveries(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Query(query): Query<HealthDeliveriesQuery>,
) -> Result<Json<Vec<HealthDelivery>>, ApiError> {
    ensure_permission(&auth, permissions::SYSTEM_HEALTH_VIEW)?;
    let deliveries = SystemHealthRepository::new(state.pool.clone())
        .list_deliveries(id, query.limit.unwrap_or(50))
        .await
        .map_err(map_error)?;
    Ok(Json(deliveries))
}

fn validate_filters(query: &ListHealthEventsQuery) -> Result<(), ApiError> {
    if query
        .status
        .as_deref()
        .is_some_and(|v| !matches!(v, "active" | "resolved"))
    {
        return Err(ApiError::BadRequest(
            "status must be active or resolved".to_string(),
        ));
    }
    const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "informational"];
    if query
        .severity
        .as_deref()
        .is_some_and(|v| !SEVERITIES.contains(&v))
    {
        return Err(ApiError::BadRequest("invalid severity".to_string()));
    }
    const CATEGORIES: &[&str] = &[
        "integration",
        "enrichment",
        "log_source",
        "ingestion",
        "parser",
        "storage",
        "query",
        "credential",
        "service",
    ];
    if query
        .category
        .as_deref()
        .is_some_and(|v| !CATEGORIES.contains(&v))
    {
        return Err(ApiError::BadRequest("invalid category".to_string()));
    }
    Ok(())
}

fn map_error(error: SystemHealthError) -> ApiError {
    match error {
        SystemHealthError::NotFound(id) => {
            ApiError::NotFound(format!("System health event {id} not found"))
        }
        SystemHealthError::Invalid(message) => ApiError::BadRequest(message),
        SystemHealthError::Database(error) => {
            tracing::error!(%error, "System health repository operation failed");
            ApiError::InternalError("An internal error occurred".to_string())
        }
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_health_events,
        get_health_summary,
        acknowledge_health_event,
        resolve_health_event,
        list_health_deliveries,
    ),
    components(schemas(HealthEventList, HealthBusSummary, SystemHealthEvent, HealthDelivery,))
)]
pub struct SystemHealthEventsApiDoc;
