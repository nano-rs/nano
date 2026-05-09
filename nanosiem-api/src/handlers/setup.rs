// SPDX-License-Identifier: AGPL-3.0-or-later

//! First-run setup API handlers
//!
//! Requirements: 13.4, 13.5
//!
//! This module provides handlers for:
//! - get_setup_status() - Check if system is initialized
//! - initialize_system() - Create initial admin account

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::auth::{builtin_groups, builtin_roles, config_keys, CreateUserRequest};

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
    let initialized = check_system_initialized(&state).await.map_err(|e| {
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
        (status = 409, description = "System already initialized or users exist", body = SetupError),
        (status = 500, description = "Database error", body = SetupError),
    ),
    security(())
)]
pub async fn initialize_system(
    State(state): State<AppState>,
    Json(request): Json<InitializeSystemRequest>,
) -> Result<Json<InitializeSystemResponse>, (StatusCode, Json<SetupError>)> {
    // Check if system is already initialized
    let initialized = check_system_initialized(&state).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new("database_error", &e.to_string())),
        )
    })?;

    if initialized {
        return Err((
            StatusCode::CONFLICT,
            Json(SetupError::new(
                "already_initialized",
                "System has already been initialized. Setup is not available.",
            )),
        ));
    }

    // Check if any users already exist
    let has_users = state.user_repo.has_users().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new("database_error", &e.to_string())),
        )
    })?;

    if has_users {
        return Err((
            StatusCode::CONFLICT,
            Json(SetupError::new(
                "users_exist",
                "Users already exist in the system. Cannot run setup.",
            )),
        ));
    }

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

    if request.password.len() < 12 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(SetupError::new(
                "validation_error",
                "Password must be at least 12 characters",
            )),
        ));
    }

    // Create the admin user
    let create_request = CreateUserRequest {
        email: request.email.clone(),
        name: request.name.clone(),
        password: request.password,
        group_ids: vec![], // Will be added to Everyone group automatically
    };

    let user = state
        .user_repo
        .create_user(&create_request)
        .await
        .map_err(|e| {
            let (status, error_type, message) = match &e {
                nanosiem_core::auth::UserRepositoryError::EmailExists(_) => {
                    (StatusCode::CONFLICT, "email_exists", "Email already exists")
                }
                nanosiem_core::auth::UserRepositoryError::PasswordHashError(msg) => {
                    (StatusCode::BAD_REQUEST, "password_error", msg.as_str())
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Failed to create user",
                ),
            };
            (status, Json(SetupError::new(error_type, message)))
        })?;

    // Create an "Admins" group and assign the Admin role to it
    let admins_group_id = create_admins_group(&state).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new(
                "database_error",
                &format!("Failed to create Admins group: {}", e),
            )),
        )
    })?;

    // Add the user to the Admins group
    state
        .user_repo
        .set_user_groups(user.id, &[admins_group_id, builtin_groups::EVERYONE_ID])
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SetupError::new(
                    "database_error",
                    &format!("Failed to add user to Admins group: {}", e),
                )),
            )
        })?;

    // Mark system as initialized
    set_system_initialized(&state).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(SetupError::new(
                "database_error",
                &format!("Failed to mark system as initialized: {}", e),
            )),
        )
    })?;

    // Log the setup completion (dual-write: PostgreSQL + ClickHouse)
    let _ = state
        .audit_repo
        .log_event(
            Some(user.id),
            None,
            "system_initialized",
            Some("system"),
            None,
            Some(serde_json::json!({
                "admin_email": request.email,
                "admin_name": request.name,
            })),
            None,
            None,
            true,
        )
        .await;

    state.emit_audit(
        AuditEvent::builder(AuditSource::Auth, SYSTEM_INITIALIZED)
            .actor(Some(user.id), Some(request.name.clone()))
            .resource("system", None, None)
            .details(serde_json::json!({
                "admin_email": request.email,
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

/// Check if the system has been initialized
async fn check_system_initialized(state: &AppState) -> Result<bool, sqlx::Error> {
    let result = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_config WHERE key = $1",
    )
    .bind(config_keys::SYSTEM_INITIALIZED)
    .fetch_optional(&state.pool)
    .await?;

    match result {
        Some(value) => Ok(value.as_bool().unwrap_or(false)),
        None => Ok(false),
    }
}

/// Mark the system as initialized
async fn set_system_initialized(state: &AppState) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO system_config (key, value, updated_at)
        VALUES ($1, $2, NOW())
        ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
        "#,
    )
    .bind(config_keys::SYSTEM_INITIALIZED)
    .bind(serde_json::json!(true))
    .execute(&state.pool)
    .await?;

    Ok(())
}

/// Create the Admins group with Admin role
async fn create_admins_group(state: &AppState) -> Result<Uuid, sqlx::Error> {
    // Check if Admins group already exists
    let existing = sqlx::query_scalar::<_, Uuid>("SELECT id FROM groups WHERE name = 'Admins'")
        .fetch_optional(&state.pool)
        .await?;

    if let Some(id) = existing {
        return Ok(id);
    }

    // Create the Admins group
    let group_id = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO groups (name, description, is_system)
        VALUES ('Admins', 'System administrators with full access', FALSE)
        RETURNING id
        "#,
    )
    .fetch_one(&state.pool)
    .await?;

    // Assign the Admin role to the Admins group
    sqlx::query(
        "INSERT INTO group_roles (group_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(group_id)
    .bind(builtin_roles::ADMIN_ID)
    .execute(&state.pool)
    .await?;

    Ok(group_id)
}

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
