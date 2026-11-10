// SPDX-License-Identifier: AGPL-3.0-or-later

//! First-run setup API handlers
//!
//! Requirements: 13.4, 13.5
//!
//! This module provides handlers for:
//! - get_setup_status() - Check if system is initialized
//! - initialize_system() - Create initial admin account

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::auth::first_admin::{
    self, claim_first_admin, FirstAdminError, SetupRefusal, SetupToken,
};
use nanosiem_core::auth::{CreateUserRequest, UserRepositoryError};

use crate::handlers::AuditExt;
use crate::state::AppState;
use nanosiem_core::audit::{AuditEvent, AuditSource, SYSTEM_INITIALIZED};
#[cfg(feature = "enterprise")]
use nanosiem_enterprise::melod::ModelCatalogSyncService;

/// Setup status response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SetupStatusResponse {
    /// Whether the system has been initialized (admin account created)
    pub initialized: bool,
    /// Whether any users exist in the system
    pub has_users: bool,
    /// Whether `POST /api/setup/initialize` needs the installer's setup token
    /// (`Authorization: Bearer <NANO_SETUP_TOKEN>`). Always false once the
    /// system is initialized. The token itself is never returned.
    pub setup_token_required: bool,
}

/// Setup error response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SetupError {
    pub error: String,
    pub message: String,
}

impl SetupError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }
}

/// Check if system is initialized
///
/// Requirements: 13.4, 13.5
/// - 13.4: Mark the system as initialized when setup is complete
/// - 13.5: Setup wizard should not be accessible if system is initialized
///
/// GET /api/setup/status
#[utoipa::path(
    get,
    path = "/api/setup/status",
    tag = "setup",
    responses(
        (status = 200, description = "Setup status retrieved successfully", body = SetupStatusResponse),
        (status = 500, description = "Database error", body = SetupError),
    ),
    security(())
)]
pub async fn get_setup_status(
    State(state): State<AppState>,
) -> Result<Json<SetupStatusResponse>, (StatusCode, Json<SetupError>)> {
    // Check if system_initialized flag is set
    let initialized = first_admin::is_system_initialized(&state.pool).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new("database_error", &e.to_string())),
        )
    })?;

    // Check if any users exist
    let has_users = state.user_repo.has_users().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new("database_error", &e.to_string())),
        )
    })?;

    Ok(Json(SetupStatusResponse {
        initialized,
        has_users,
        setup_token_required: !initialized && SetupToken::from_env().is_configured(),
    }))
}

/// Request to initialize the system with an admin account
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct InitializeSystemRequest {
    /// Admin email address
    pub email: String,
    /// Admin display name
    pub name: String,
    /// Admin password
    pub password: String,
}

/// Response after successful initialization
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct InitializeSystemResponse {
    pub success: bool,
    pub message: String,
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
}

/// Initialize the system with the first admin account
///
/// Requirements: 13.4, 13.5
/// - 13.4: Mark the system as initialized when setup is complete
/// - 13.5: Setup wizard should not be accessible if system is initialized
///
/// POST /api/setup/initialize
#[utoipa::path(
    post,
    path = "/api/setup/initialize",
    tag = "setup",
    request_body = InitializeSystemRequest,
    responses(
        (status = 200, description = "System initialized successfully", body = InitializeSystemResponse),
        (status = 400, description = "Validation error", body = SetupError),
        (status = 401, description = "Setup token required: send Authorization: Bearer <NANO_SETUP_TOKEN>", body = SetupError),
        (status = 403, description = "Wrong setup token, or no setup token is configured and the caller is not on the API host", body = SetupError),
        (status = 409, description = "System already initialized or users exist", body = SetupError),
        (status = 500, description = "Database error", body = SetupError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn initialize_system(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<InitializeSystemRequest>,
) -> Result<Json<InitializeSystemResponse>, (StatusCode, Json<SetupError>)> {
    // An initialized system answers 409 to everyone, token or not: setup is
    // over, and `GET /api/setup/status` already says so publicly. The
    // authoritative re-check happens inside the claim transaction.
    let initialized = first_admin::is_system_initialized(&state.pool).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new("database_error", &e.to_string())),
        )
    })?;
    if initialized {
        return Err(already_initialized());
    }

    // NAN-5237: only the installer (setup token) or, with no token
    // configured, a caller on the API host itself may create the first Admin.
    let admitted_by = match authorize_setup(&SetupToken::from_env(), &headers, peer)? {
        first_admin::SetupAdmission::Token => "setup_token",
        first_admin::SetupAdmission::Loopback => "loopback",
    };

    // Validate the request
    if request.email.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupError::new("validation_error", "Email is required")),
        ));
    }

    if request.name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupError::new("validation_error", "Name is required")),
        ));
    }

    // Full authoritative policy, not just the length floor this used to check.
    // `UserRepository::create_user` re-validates (it is the layer that cannot be
    // bypassed); checking here too gives the first-run form the specific list of
    // unmet requirements without a database round trip.
    if let Err(e) = nanosiem_core::auth::validate_password(&request.password) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupError::new("password_requirements", &e.to_string())),
        ));
    }

    // Create the admin user
    let create_request = CreateUserRequest {
        email: request.email.clone(),
        name: request.name.clone(),
        password: request.password,
        group_ids: vec![], // Will be added to Everyone group automatically
    };

    let user = claim_first_admin(&state.pool, &create_request)
        .await
        .map_err(|e| {
            let (status, error_type, message) = match &e {
                FirstAdminError::AlreadyInitialized => return already_initialized(),
                FirstAdminError::UsersExist => (
                    StatusCode::CONFLICT,
                    "users_exist",
                    "Users already exist in the system. Cannot run setup.",
                ),
                FirstAdminError::User(UserRepositoryError::EmailExists(_)) => {
                    (StatusCode::CONFLICT, "email_exists", "Email already exists")
                }
                FirstAdminError::User(UserRepositoryError::PasswordRequirementsNotMet(msg)) => {
                    (StatusCode::BAD_REQUEST, "password_requirements", msg.as_str())
                }
                FirstAdminError::User(UserRepositoryError::PasswordHashError(msg)) => {
                    (StatusCode::BAD_REQUEST, "password_error", msg.as_str())
                }
                _ => {
                    tracing::error!(error = %e, "first-admin setup failed");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "database_error",
                        "Failed to initialize the system",
                    )
                }
            };
            (status, Json(SetupError::new(error_type, message)))
        })?;

    // Log the setup completion to the ClickHouse audit store (system-of-record).
    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, SYSTEM_INITIALIZED)
            .actor(Some(user.id), Some(request.name.clone()))
            .resource("system", None, None)
            .details(serde_json::json!({
                "admin_email": request.email,
                "admitted_by": admitted_by,
            }))
            .build(),
    );

    // Trigger model catalog sync in the background so the new instance
    // gets the latest available models from upstream immediately. Open-core
    // builds skip — there's no AI provider catalog to sync.
    #[cfg(feature = "enterprise")]
    {
        let pool = state.pool.clone();
        tokio::spawn(async move {
            let service = ModelCatalogSyncService::new(pool);
            match service.sync().await {
                Ok(result) => {
                    tracing::info!(
                        total = result.models_total,
                        deprecated = result.models_deprecated,
                        "Initial model catalog sync completed"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Initial model catalog sync failed — will retry on scheduler");
                }
            }
        });
    }

    Ok(Json(InitializeSystemResponse {
        success: true,
        message: "System initialized successfully. You can now log in with your admin account."
            .to_string(),
        user_id: user.id,
    }))
}

fn already_initialized() -> (StatusCode, Json<SetupError>) {
    (
        StatusCode::CONFLICT,
        Json(SetupError::new(
            "already_initialized",
            "System has already been initialized. Setup is not available.",
        )),
    )
}

/// Headers a reverse proxy adds to say who the real client is. Any of them
/// means the request did not come straight from a process on this host.
fn is_forwarding_header(name: &str) -> bool {
    matches!(
        name,
        "forwarded"
            | "x-real-ip"
            | "true-client-ip"
            | "cf-connecting-ip"
            | "x-client-ip"
            | "x-cluster-client-ip"
            | "fastly-client-ip"
    ) || name.starts_with("x-forwarded-")
}

/// NAN-5237 admission for first-admin setup; see
/// [`nanosiem_core::auth::first_admin`] for the rule. The token is never
/// logged or echoed.
pub(crate) fn authorize_setup(
    token: &SetupToken,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<first_admin::SetupAdmission, (StatusCode, Json<SetupError>)> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let authorization = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok(),
        _ => None,
    };
    let forwarded = headers.keys().any(|name| is_forwarding_header(name.as_str()));
    token
        .admit(authorization, Some(peer.ip()), forwarded)
        .map_err(|refusal| {
            tracing::warn!(
                peer = %peer.ip(),
                refusal = ?refusal,
                "refused first-admin setup request"
            );
            match refusal {
                SetupRefusal::TokenMissing => (
                    StatusCode::UNAUTHORIZED,
                    Json(SetupError::new(
                        "setup_token_required",
                        "Setup token required. The installer prints it; it is also NANO_SETUP_TOKEN in the install directory's .env (Helm: the chart's secret).",
                    )),
                ),
                SetupRefusal::TokenInvalid => (
                    StatusCode::FORBIDDEN,
                    Json(SetupError::new("invalid_setup_token", "The setup token is not correct.")),
                ),
                SetupRefusal::TokenPlaceholder => (
                    StatusCode::FORBIDDEN,
                    Json(SetupError::new(
                        "setup_token_placeholder",
                        "NANO_SETUP_TOKEN is still a placeholder. Set it to a generated value (openssl rand -hex 32) and restart nano-api.",
                    )),
                ),
                SetupRefusal::NotLocal => (
                    StatusCode::FORBIDDEN,
                    Json(SetupError::new(
                        "setup_not_local",
                        "No setup token is configured, so setup is accepted only from the API host itself. Set NANO_SETUP_TOKEN for nano-api, or re-run the installer.",
                    )),
                ),
            }
        })
}

#[cfg(test)]
#[path = "setup_tests.rs"]
mod tests;

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_setup_status, initialize_system),
    components(schemas(
        SetupStatusResponse,
        SetupError,
        InitializeSystemRequest,
        InitializeSystemResponse
    ))
)]
pub struct SetupApiDoc;
