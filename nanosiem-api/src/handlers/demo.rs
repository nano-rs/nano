// SPDX-License-Identifier: AGPL-3.0-or-later

//! Demo mode API handlers
//!
//! Endpoints for creating and managing demo sessions.
//! Only available when DEPLOYMENT_MODE=demo.

use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};

use crate::middleware::auth::AuthContext;
use crate::state::AppState;

/// Request to create a demo session
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateDemoSessionRequest {
    /// Optional display name for the demo user
    pub display_name: Option<String>,
}

/// Response after creating a demo session
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateDemoSessionResponse {
    #[serde(with = "nanosiem_core::typeid::session")]
    #[schema(value_type = String)]
    pub session_id: uuid::Uuid,
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub user_id: uuid::Uuid,
    /// One-time token for the demo link (e.g. /d/{token})
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub remaining_hours: f64,
    pub auth: DemoAuthResponse,
}

/// Auth tokens for the demo session
#[derive(Debug, Serialize, ToSchema)]
pub struct DemoAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub user: DemoUserInfo,
}

/// Minimal user info for demo response
#[derive(Debug, Serialize, ToSchema)]
pub struct DemoUserInfo {
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub id: uuid::Uuid,
    pub name: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

/// Demo session status response
#[derive(Debug, Serialize, ToSchema)]
pub struct DemoStatusResponse {
    #[serde(with = "nanosiem_core::typeid::session")]
    #[schema(value_type = String)]
    pub session_id: uuid::Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub remaining_hours: f64,
    pub resource_counts: nanosiem_core::demo::DemoResourceCounts,
}

/// Error response for demo endpoints
#[derive(Debug, Serialize, ToSchema)]
pub struct DemoErrorResponse {
    pub error: String,
}

fn demo_err(status: StatusCode, msg: impl ToString) -> (StatusCode, Json<DemoErrorResponse>) {
    (
        status,
        Json(DemoErrorResponse {
            error: msg.to_string(),
        }),
    )
}

/// Extract client IP from X-Forwarded-For or X-Real-IP headers
fn extract_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return Some(xff.split(',').next().unwrap_or(xff).trim().to_string());
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Create a new demo session
///
/// Creates an ephemeral user with analyst permissions and returns auth tokens.
/// Rate limited per IP address.
#[utoipa::path(
    post,
    path = "/api/demo/session",
    tag = "demo",
    request_body = CreateDemoSessionRequest,
    responses(
        (status = 201, body = CreateDemoSessionResponse, description = "Demo session created"),
        (status = 429, body = DemoErrorResponse, description = "Rate limit exceeded"),
        (status = 503, body = DemoErrorResponse, description = "Demo mode not enabled"),
    ),
)]
pub async fn create_demo_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateDemoSessionRequest>,
) -> Result<(StatusCode, Json<CreateDemoSessionResponse>), (StatusCode, Json<DemoErrorResponse>)> {
    let demo_service = state
        .demo_service
        .as_ref()
        .ok_or_else(|| demo_err(StatusCode::SERVICE_UNAVAILABLE, "Demo mode is not enabled"))?;

    let ip_address = extract_ip(&headers);
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let result = demo_service
        .create_session(
            body.display_name,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
        .await
        .map_err(|e| {
            let status = match &e {
                nanosiem_core::demo::DemoError::RateLimitExceeded(_) => {
                    StatusCode::TOO_MANY_REQUESTS
                }
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            demo_err(status, e)
        })?;

    let remaining = (result.session.expires_at - chrono::Utc::now()).num_minutes() as f64 / 60.0;

    Ok((
        StatusCode::CREATED,
        Json(CreateDemoSessionResponse {
            session_id: result.session.id,
            user_id: result.auth.user.id,
            token: result.session.token.clone(),
            expires_at: result.session.expires_at,
            remaining_hours: remaining,
            auth: DemoAuthResponse {
                access_token: result.auth.tokens.access_token,
                refresh_token: result.auth.tokens.refresh_token,
                expires_in: result.auth.tokens.expires_in,
                user: DemoUserInfo {
                    id: result.auth.user.id,
                    name: result.auth.user.name,
                    roles: result.auth.user.roles,
                    permissions: result.auth.user.permissions,
                },
            },
        }),
    ))
}

/// Get demo session status
///
/// Returns remaining time and resource counts for the current demo session.
#[utoipa::path(
    get,
    path = "/api/demo/session/status",
    tag = "demo",
    responses(
        (status = 200, body = DemoStatusResponse, description = "Demo session status"),
        (status = 404, body = DemoErrorResponse, description = "No active demo session"),
    ),
    security(("api_key" = [])),
)]
pub async fn get_demo_session_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<DemoStatusResponse>, (StatusCode, Json<DemoErrorResponse>)> {
    let demo_service = state
        .demo_service
        .as_ref()
        .ok_or_else(|| demo_err(StatusCode::SERVICE_UNAVAILABLE, "Demo mode is not enabled"))?;

    let status = demo_service
        .get_session_status(auth.user_id())
        .await
        .map_err(|e| demo_err(StatusCode::NOT_FOUND, e))?;

    Ok(Json(DemoStatusResponse {
        session_id: status.session_id,
        expires_at: status.expires_at,
        remaining_hours: status.remaining_hours,
        resource_counts: status.resource_counts,
    }))
}

/// Claim a demo session by token
///
/// Returns auth credentials for the session. The token is reusable for the
/// session lifetime (72h), so users can bookmark or re-open their demo link.
/// This is the endpoint that unique demo links (e.g. saturn.nano.rs/d/{token}) resolve to.
#[utoipa::path(
    post,
    path = "/api/demo/session/{token}/claim",
    tag = "demo",
    params(
        ("token" = String, Path, description = "Demo session token")
    ),
    responses(
        (status = 200, body = CreateDemoSessionResponse, description = "Token claimed, session active"),
        (status = 404, body = DemoErrorResponse, description = "Invalid or expired token"),
        (status = 409, body = DemoErrorResponse, description = "Token already used"),
    ),
)]
pub async fn claim_demo_token(
    State(state): State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Result<Json<CreateDemoSessionResponse>, (StatusCode, Json<DemoErrorResponse>)> {
    let demo_service = state
        .demo_service
        .as_ref()
        .ok_or_else(|| demo_err(StatusCode::SERVICE_UNAVAILABLE, "Demo mode is not enabled"))?;

    let result = demo_service.claim_token(&token).await.map_err(|e| {
        let status = match &e {
            nanosiem_core::demo::DemoError::InvalidToken => StatusCode::NOT_FOUND,
            nanosiem_core::demo::DemoError::TokenAlreadyBurned => StatusCode::CONFLICT,
            nanosiem_core::demo::DemoError::SessionExpired => StatusCode::GONE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        demo_err(status, e)
    })?;

    let remaining = (result.session.expires_at - chrono::Utc::now()).num_minutes() as f64 / 60.0;

    Ok(Json(CreateDemoSessionResponse {
        session_id: result.session.id,
        user_id: result.auth.user.id,
        token: result.session.token.clone(),
        expires_at: result.session.expires_at,
        remaining_hours: remaining,
        auth: DemoAuthResponse {
            access_token: result.auth.tokens.access_token,
            refresh_token: result.auth.tokens.refresh_token,
            expires_in: result.auth.tokens.expires_in,
            user: DemoUserInfo {
                id: result.auth.user.id,
                name: result.auth.user.name,
                roles: result.auth.user.roles,
                permissions: result.auth.user.permissions,
            },
        },
    }))
}

/// OpenAPI documentation for demo endpoints
#[derive(OpenApi)]
#[openapi(
    paths(create_demo_session, get_demo_session_status, claim_demo_token),
    components(schemas(
        CreateDemoSessionRequest,
        CreateDemoSessionResponse,
        DemoAuthResponse,
        DemoUserInfo,
        DemoStatusResponse,
        DemoErrorResponse,
        nanosiem_core::demo::DemoResourceCounts,
    ))
)]
pub struct DemoApiDoc;
