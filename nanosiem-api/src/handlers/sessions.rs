// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session Management API handlers
//!
//! Requirements: 7.2, 7.3, 7.4
//!
//! This module provides handlers for:
//! - list_all_sessions() - List all active sessions (admin)
//! - list_my_sessions() - List current user's sessions
//! - terminate_session() - Terminate a specific session

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, SESSION_TERMINATED, USER_SESSIONS_TERMINATED,
};
use nanosiem_core::auth::{permissions, SessionError, SessionResponse};
use nanosiem_core::typeid::TypeIdParam;

use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for session endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionApiError {
    pub error: String,
    pub message: String,
}

impl SessionApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_service_error(err: &SessionError) -> (StatusCode, Self) {
        let (status, error_type) = match err {
            SessionError::NotFound => (StatusCode::NOT_FOUND, "session_not_found"),
            SessionError::Expired => (StatusCode::UNAUTHORIZED, "session_expired"),
            SessionError::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
            SessionError::PermissionDenied => (StatusCode::FORBIDDEN, "permission_denied"),
            SessionError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
            SessionError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        (status, Self::new(error_type, &err.to_string()))
    }
}

/// Query parameters for listing sessions
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListSessionsQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Session list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionResponse>,
    pub total: i64,
}

/// List all active sessions (admin view)
///
/// Requirements: 7.2 - Allow administrators to view all active sessions
///
/// GET /api/sessions
#[utoipa::path(
    get,
    path = "/api/sessions",
    tag = "sessions",
    params(ListSessionsQuery),
    responses(
        (status = 200, description = "Successfully retrieved all sessions", body = SessionListResponse),
        (status = 403, description = "Permission denied", body = SessionApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_all_sessions(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<Json<SessionListResponse>, (StatusCode, Json<SessionApiError>)> {
    // H9: Require elevated permission for listing ALL sessions (not just users:view)
    check_permission(&auth, permissions::SESSIONS_ADMIN)
        .map_err(|(s, j)| (s, Json(SessionApiError::new(&j.error, &j.message))))?;

    let (limit, offset) =
        nanosiem_api_lib::Pagination::new(query.limit, query.offset).resolved_capped(50, 100);

    let sessions = state
        .session_service
        .get_all_sessions(limit, offset)
        .await
        .map_err(|e| {
            let (status, err) = SessionApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    let total = state
        .session_service
        .count_all_sessions()
        .await
        .map_err(|e| {
            let (status, err) = SessionApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    Ok(Json(SessionListResponse { sessions, total }))
}

/// List current user's sessions
///
/// Requirements: 7.4 - Allow users to view and terminate their own sessions
///
/// GET /api/sessions/me
#[utoipa::path(
    get,
    path = "/api/sessions/me",
    tag = "sessions",
    responses(
        (status = 200, description = "Successfully retrieved user's sessions", body = SessionListResponse),
        (status = 403, description = "Permission denied", body = SessionApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_my_sessions(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<SessionListResponse>, (StatusCode, Json<SessionApiError>)> {
    // Users can always view their own sessions, no permission check needed
    let user_id = auth.user_id();

    // Get the current session ID from the JWT claims (jti)
    let current_session_id = Some(auth.claims.jti);

    let sessions = state
        .session_service
        .get_user_sessions(user_id, current_session_id)
        .await
        .map_err(|e| {
            let (status, err) = SessionApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    let total = sessions.len() as i64;

    Ok(Json(SessionListResponse { sessions, total }))
}

/// Get a single session by ID
///
/// GET /api/sessions/{id}
#[utoipa::path(
    get,
    path = "/api/sessions/{id}",
    tag = "sessions",
    params(
        ("id" = String, Path, description = "Session ID")
    ),
    responses(
        (status = 200, description = "Successfully retrieved session", body = SessionResponse),
        (status = 403, description = "Permission denied", body = SessionApiError),
        (status = 404, description = "Session not found", body = SessionApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_session(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SessionResponse>, (StatusCode, Json<SessionApiError>)> {
    let session = state.session_service.get_session(*id).await.map_err(|e| {
        let (status, err) = SessionApiError::from_service_error(&e);
        (status, Json(err))
    })?;

    // Check if user can view this session (own session or admin)
    let is_own_session = session.user_id == auth.user_id();
    let is_admin = auth.has_permission(permissions::USERS_VIEW);

    if !is_own_session && !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(SessionApiError::new(
                "permission_denied",
                "Cannot view another user's session",
            )),
        ));
    }

    let is_current = auth.claims.jti == *id;

    Ok(Json(SessionResponse {
        session,
        is_current,
    }))
}

/// Terminate a specific session
///
/// Requirements: 7.3 - Allow administrators to terminate any session
/// Requirements: 7.4 - Allow users to terminate their own sessions
///
/// DELETE /api/sessions/{id}
#[utoipa::path(
    delete,
    path = "/api/sessions/{id}",
    tag = "sessions",
    params(
        ("id" = String, Path, description = "Session ID to terminate")
    ),
    responses(
        (status = 204, description = "Session successfully terminated"),
        (status = 403, description = "Permission denied", body = SessionApiError),
        (status = 404, description = "Session not found", body = SessionApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn terminate_session(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<SessionApiError>)> {
    // Use IP from ClientContext (populated by auth middleware with ConnectInfo fallback)
    let ip_address = client.ip_address.clone();
    let user_agent = client.user_agent.clone();
    let requesting_user_id = auth.user_id();
    let is_admin = auth.has_permission(permissions::USERS_EDIT);

    state
        .session_service
        .terminate_session(
            *id,
            requesting_user_id,
            is_admin,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
        .map_err(|e| {
            let (status, err) = SessionApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Session, SESSION_TERMINATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("session", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Terminate all sessions for a user
///
/// DELETE /api/sessions/user/{user_id}
#[utoipa::path(
    delete,
    path = "/api/sessions/user/{user_id}",
    tag = "sessions",
    params(
        ("user_id" = String, Path, description = "User ID whose sessions should be terminated")
    ),
    responses(
        (status = 200, description = "Sessions successfully terminated", body = TerminateSessionsResponse),
        (status = 403, description = "Permission denied", body = SessionApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn terminate_user_sessions(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(user_id): Path<TypeIdParam>,
) -> Result<Json<TerminateSessionsResponse>, (StatusCode, Json<SessionApiError>)> {
    // Use IP from ClientContext (populated by auth middleware with ConnectInfo fallback)
    let ip_address = client.ip_address.clone();
    let user_agent = client.user_agent.clone();
    let requesting_user_id = auth.user_id();
    let is_admin = auth.has_permission(permissions::USERS_EDIT);

    // Security: Verify user can terminate these sessions (own sessions or admin)
    // Defense-in-depth: service layer also checks, but validate here first
    if *user_id != requesting_user_id && !is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(SessionApiError::new(
                "permission_denied",
                "Cannot terminate another user's sessions without admin privileges",
            )),
        ));
    }

    let count = state
        .session_service
        .terminate_all_user_sessions(
            *user_id,
            requesting_user_id,
            is_admin,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
        .map_err(|e| {
            let (status, err) = SessionApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    // Security audit: Log bulk session termination (especially admin actions)
    if *user_id != requesting_user_id {
        tracing::info!(
            admin_user_id = %requesting_user_id,
            target_user_id = %user_id,
            terminated_count = count,
            "Admin terminated all sessions for another user"
        );
    }

    state.emit_audit(
        AuditEvent::builder(AuditSource::Session, USER_SESSIONS_TERMINATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("session", None, None)
            .client_context(&client)
            .details(serde_json::json!({ "user_id": user_id, "terminated_count": count }))
            .build(),
    );

    Ok(Json(TerminateSessionsResponse {
        terminated_count: count,
    }))
}

/// Response for terminating multiple sessions
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TerminateSessionsResponse {
    pub terminated_count: u64,
}

/// Count active sessions
///
/// GET /api/sessions/count
#[utoipa::path(
    get,
    path = "/api/sessions/count",
    tag = "sessions",
    responses(
        (status = 200, description = "Successfully retrieved session count", body = SessionCountResponse),
        (status = 403, description = "Permission denied", body = SessionApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn count_sessions(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<SessionCountResponse>, (StatusCode, Json<SessionApiError>)> {
    check_permission(&auth, permissions::USERS_VIEW)
        .map_err(|(s, j)| (s, Json(SessionApiError::new(&j.error, &j.message))))?;

    let total = state
        .session_service
        .count_all_sessions()
        .await
        .map_err(|e| {
            let (status, err) = SessionApiError::from_service_error(&e);
            (status, Json(err))
        })?;

    Ok(Json(SessionCountResponse { total }))
}

/// Response for session count
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionCountResponse {
    pub total: i64,
}

/// OpenAPI documentation for session management endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_all_sessions,
        list_my_sessions,
        count_sessions,
        get_session,
        terminate_session,
        terminate_user_sessions,
    ),
    components(schemas(
        SessionApiError,
        SessionListResponse,
        SessionCountResponse,
        TerminateSessionsResponse,
    )),
    tags(
        (name = "sessions", description = "Session management API")
    )
)]
pub struct SessionsApiDoc;
