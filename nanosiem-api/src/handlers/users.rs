// SPDX-License-Identifier: AGPL-3.0-or-later

//! User Management API handlers
//!
//! Requirements: 11.1
//!
//! This module provides handlers for:
//! - list_users() - List all users with status, groups, and last login
//! - get_user() - Get user details
//! - create_user() - Create a new local user
//! - update_user() - Update user details
//! - delete_user() - Delete a user
//! - update_user_groups() - Update user's group memberships
//! - unlock_user() - Unlock a locked user account
//! - disable_user() - Disable a user account
//! - enable_user() - Enable a disabled user account

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, USER_CREATED, USER_DELETED, USER_DISABLED,
    USER_ENABLED, USER_GROUPS_UPDATED, USER_UNLOCKED, USER_UPDATED,
};
use nanosiem_core::auth::{
    permissions, CreateUserRequest, UpdateUserPreferencesRequest, UpdateUserRequest,
    UserPreferences, UserRepositoryError, UserWithGroups,
};
use nanosiem_core::typeid::TypeIdParam;

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for user endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserApiError {
    pub error: String,
    pub message: String,
}

impl UserApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &UserRepositoryError) -> (StatusCode, Self) {
        // SECURITY: Normalize email-related errors to prevent enumeration attacks
        // Don't reveal whether an email already exists in the system
        let (status, error_type, message) = match err {
            UserRepositoryError::NotFound(_) => {
                (StatusCode::NOT_FOUND, "user_not_found", "User not found")
            }
            UserRepositoryError::NotFoundByEmail(_) => {
                (StatusCode::NOT_FOUND, "user_not_found", "User not found")
            }
            // SECURITY: Return generic error for email conflicts to prevent enumeration
            UserRepositoryError::EmailExists(_) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                "Unable to create user with provided details",
            ),
            UserRepositoryError::PasswordHashError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An error occurred",
            ),
            UserRepositoryError::InvalidResetToken => (
                StatusCode::BAD_REQUEST,
                "invalid_reset_token",
                "Invalid reset token",
            ),
            UserRepositoryError::ResetTokenExpired => (
                StatusCode::BAD_REQUEST,
                "reset_token_expired",
                "Reset token has expired",
            ),
            UserRepositoryError::DatabaseError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "An error occurred",
            ),
        };

        (status, Self::new(error_type, message))
    }
}

/// Query parameters for listing users
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListUsersQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// User list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserListResponse {
    pub users: Vec<UserWithGroups>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// List all users
///
/// Requirements: 11.1 - List all users with status, groups, and last login
///
/// GET /api/users
#[utoipa::path(
    get,
    path = "/api/users",
    tag = "users",
    params(ListUsersQuery),
    responses(
        (status = 200, description = "List of users with groups", body = UserListResponse),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_users(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_VIEW)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    let (limit, offset) =
        nanosiem_api_lib::Pagination::new(query.limit, query.offset).resolved_capped(50, 100);

    let users = state
        .user_repo
        .list_users(limit, offset)
        .await
        .map_err(|e| {
            let (status, err) = UserApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    let total = state.user_repo.count_users().await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    // Get groups for each user
    let mut users_with_groups = Vec::with_capacity(users.len());
    for user in users {
        let groups = state
            .user_repo
            .get_user_groups(user.id)
            .await
            .unwrap_or_default();

        users_with_groups.push(UserWithGroups { user, groups });
    }

    Ok(Json(UserListResponse {
        users: users_with_groups,
        total,
        limit,
        offset,
    }))
}

/// Get user details
///
/// GET /api/users/{id}
#[utoipa::path(
    get,
    path = "/api/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User details with groups", body = UserWithGroups),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<UserWithGroups>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_VIEW)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    let user = state.user_repo.get_user_by_id(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let groups = state
        .user_repo
        .get_user_groups(*id)
        .await
        .unwrap_or_default();

    Ok(Json(UserWithGroups { user, groups }))
}

/// Create a new user
///
/// POST /api/users
#[utoipa::path(
    post,
    path = "/api/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = UserWithGroups),
        (status = 400, description = "Bad request - validation error", body = UserApiError),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserWithGroups>), (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_CREATE)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    // Tier enforcement: check team member limit
    let tier_settings = nanosiem_core::TierSettings::new(state.pool.clone());
    let tier_limits = tier_settings.get_tier_limits().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(UserApiError::new("tier_error", &e.to_string())),
        )
    })?;
    if tier_limits.is_enforced() {
        let user_count = state
            .user_repo
            .count_users()
            .await
            .map(|c| c as u32)
            .unwrap_or(0);
        nanosiem_core::check_limit(
            "team members",
            user_count,
            tier_limits.max_team_members,
            tier_limits.tier,
            "Upgrade your plan for more team members.",
        )
        .map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                Json(UserApiError::new("tier_limit_exceeded", &e.to_string())),
            )
        })?;
    }

    let user = state.user_repo.create_user(&request).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let groups = state
        .user_repo
        .get_user_groups(user.id)
        .await
        .unwrap_or_default();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .build(),
    );

    Ok((StatusCode::CREATED, Json(UserWithGroups { user, groups })))
}

/// Update a user
///
/// PUT /api/users/{id}
#[utoipa::path(
    put,
    path = "/api/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = UserWithGroups),
        (status = 400, description = "Bad request - validation error", body = UserApiError),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserWithGroups>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    let user = state
        .user_repo
        .update_user(*id, &request)
        .await
        .map_err(|e| {
            let (status, err) = UserApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    // Update group memberships if provided
    if let Some(ref group_id_strings) = request.group_ids {
        let group_uuids: Vec<uuid::Uuid> = group_id_strings
            .iter()
            .filter_map(|s| nanosiem_core::typeid::decode("group", s).ok())
            .collect();
        state
            .user_repo
            .set_user_groups(*id, &group_uuids)
            .await
            .map_err(|e| {
                let (status, err) = UserApiError::from_repo_error(&e);
                (status, Json(err))
            })?;
    }

    let groups = state
        .user_repo
        .get_user_groups(*id)
        .await
        .unwrap_or_default();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// Delete a user
///
/// DELETE /api/users/{id}
#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_DELETE)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    // Get user email for audit before deleting
    let user_email = state
        .user_repo
        .get_user_by_id(*id)
        .await
        .map(|u| u.email)
        .unwrap_or_else(|_| "unknown".to_string());

    state.user_repo.delete_user(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(*id), Some(user_email))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Update user groups request
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateUserGroupsRequest {
    #[serde(with = "nanosiem_core::typeid::group::vec")]
    #[schema(value_type = Vec<String>)]
    pub group_ids: Vec<Uuid>,
}

/// Update user's group memberships
///
/// PUT /api/users/{id}/groups
#[utoipa::path(
    put,
    path = "/api/users/{id}/groups",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    request_body = UpdateUserGroupsRequest,
    responses(
        (status = 200, description = "User groups updated successfully", body = UserWithGroups),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_user_groups(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateUserGroupsRequest>,
) -> Result<Json<UserWithGroups>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    state
        .user_repo
        .set_user_groups(*id, &request.group_ids)
        .await
        .map_err(|e| {
            let (status, err) = UserApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    let user = state.user_repo.get_user_by_id(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let groups = state
        .user_repo
        .get_user_groups(*id)
        .await
        .unwrap_or_default();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_GROUPS_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "group_ids": request.group_ids,
            }))
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// Unlock a locked user account
///
/// POST /api/users/{id}/unlock
#[utoipa::path(
    post,
    path = "/api/users/{id}/unlock",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User unlocked successfully", body = UserWithGroups),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn unlock_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<UserWithGroups>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    state.user_repo.unlock_user(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let user = state.user_repo.get_user_by_id(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let groups = state
        .user_repo
        .get_user_groups(*id)
        .await
        .unwrap_or_default();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_UNLOCKED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// Disable a user account
///
/// POST /api/users/{id}/disable
#[utoipa::path(
    post,
    path = "/api/users/{id}/disable",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User disabled successfully", body = UserWithGroups),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn disable_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<UserWithGroups>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    // F-32: `disable_user` stamps `status='disabled'` + `tokens_valid_from=NOW()`
    // atomically, so outstanding access tokens are rejected by the middleware
    // status gate and refresh already rejects disabled users.
    state.user_repo.disable_user(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    // F-32: also revoke every active session so refresh tokens die immediately.
    // Best-effort — the status gate + refresh disabled-check are the primary
    // controls, so a session-delete hiccup must not fail the disable itself.
    if let Err(e) = state
        .session_service
        .terminate_all_user_sessions(*id, auth.user_id(), true, None, None)
        .await
    {
        tracing::warn!(user_id = %*id, error = %e, "failed to revoke sessions on user disable");
    }

    let user = state.user_repo.get_user_by_id(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let groups = state
        .user_repo
        .get_user_groups(*id)
        .await
        .unwrap_or_default();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_DISABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// Enable a disabled user account
///
/// POST /api/users/{id}/enable
#[utoipa::path(
    post,
    path = "/api/users/{id}/enable",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User enabled successfully", body = UserWithGroups),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn enable_user(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<UserWithGroups>, (StatusCode, Json<UserApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;

    state.user_repo.enable_user(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let user = state.user_repo.get_user_by_id(*id).await.map_err(|e| {
        let (status, err) = UserApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let groups = state
        .user_repo
        .get_user_groups(*id)
        .await
        .unwrap_or_default();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::User, USER_ENABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// Get current user's preferences
///
/// GET /api/users/me/preferences
#[utoipa::path(
    get,
    path = "/api/users/me/preferences",
    tag = "users",
    responses(
        (status = 200, description = "User preferences", body = UserPreferences),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_my_preferences(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<UserPreferences>, (StatusCode, Json<UserApiError>)> {
    let preferences = state
        .user_repo
        .get_preferences(auth.user_id())
        .await
        .map_err(|e| {
            let (status, err) = UserApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    Ok(Json(preferences))
}

/// Update current user's preferences
///
/// PATCH /api/users/me/preferences
#[utoipa::path(
    patch,
    path = "/api/users/me/preferences",
    tag = "users",
    request_body = UpdateUserPreferencesRequest,
    responses(
        (status = 200, description = "User preferences updated successfully", body = UserPreferences),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_my_preferences(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Json(request): Json<UpdateUserPreferencesRequest>,
) -> Result<Json<UserPreferences>, (StatusCode, Json<UserApiError>)> {
    let preferences = state
        .user_repo
        .update_preferences(
            auth.user_id(),
            request.preferred_query_mode,
            request.default_time_range,
            request.search_hub_style,
            request.landing_page,
        )
        .await
        .map_err(|e| {
            let (status, err) = UserApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    Ok(Json(preferences))
}

/// OpenAPI documentation for Users endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_users,
        get_user,
        create_user,
        update_user,
        delete_user,
        update_user_groups,
        unlock_user,
        disable_user,
        enable_user,
        get_my_preferences,
        update_my_preferences,
    ),
    components(schemas(
        UserApiError,
        UserListResponse,
        UpdateUserGroupsRequest,
    )),
    tags(
        (name = "users", description = "User management endpoints")
    )
)]
pub struct UsersApiDoc;
