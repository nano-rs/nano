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
    permissions, CreateUserRequest, PrincipalAction, UpdateUserPreferencesRequest,
    UpdateUserRequest, UserPreferences, UserRepositoryError, UserWithGroups,
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
            // The policy message names only the unmet requirements, never the
            // submitted password, so it is safe to return to the admin.
            UserRepositoryError::PasswordRequirementsNotMet(msg) => (
                StatusCode::BAD_REQUEST,
                "password_requirements",
                msg.as_str(),
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
            UserRepositoryError::GrantAuthorityChanged => (
                StatusCode::CONFLICT,
                "grant_authority_changed",
                "Authorization changed while the request was being validated; retry",
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
        (status = 409, description = "Email exists or grant authority changed", body = UserApiError),
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

    // NAN-2121: users:create authorizes creating the account, NOT placing it in
    // privileged groups. Deny unless the caller holds every permission the
    // requested groups transitively confer (prevents creating an Admin-group
    // member).
    let grant_stamp = crate::handlers::grant_authz::ensure_can_grant_groups(
        &auth,
        &state.pool,
        permissions::USERS_CREATE,
        &request.group_ids,
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

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

    let user = state
        .user_repo
        .create_user_authorized(&request, grant_stamp)
        .await
        .map_err(|e| {
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
        (status = 409, description = "Email exists or grant authority changed", body = UserApiError),
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

    // NAN-5014: your OWN password / email go through the self-service flow,
    // which re-authenticates with the current password and is session-only.
    // `users:edit` on yourself is not a way around that re-auth.
    if *id == auth.user_id() && (request.password.is_some() || request.email.is_some()) {
        return Err((
            StatusCode::CONFLICT,
            Json(UserApiError::new(
                "use_self_service",
                "Change your own password or email from your profile (PUT /api/auth/password).",
            )),
        ));
    }

    // NAN-5027: the SSO break-glass flag keeps a local password usable on an
    // IdP-managed account. It is tenant-level security policy, not account
    // administration: interactive session + `settings:system` only.
    if request.local_login_break_glass.is_some() {
        if auth.is_api_key {
            return Err((
                StatusCode::FORBIDDEN,
                Json(UserApiError::new(
                    "interactive_session_required",
                    "Changing local_login_break_glass requires an interactive session.",
                )),
            ));
        }
        check_permission(&auth, permissions::SETTINGS_SYSTEM)
            .map_err(|(s, j)| (s, Json(UserApiError::new(&j.error, &j.message))))?;
    }

    // NAN-5027: `status` is limited to the two values an administrator may set.
    // `locked` is owned by the login throttle and `system` marks platform
    // service accounts (exempt from the API-key owner checks) — neither may be
    // assigned through this endpoint.
    if let Some(ref status) = request.status {
        if status != "active" && status != "disabled" {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(UserApiError::new(
                    "invalid_status",
                    "status must be \"active\" or \"disabled\"",
                )),
            ));
        }
    }

    // NAN-5027: an SSO-linked account's email and password belong to the
    // identity provider. Writing a local password would open a side door around
    // the IdP (and its MFA); rewriting the email re-targets SSO account linking.
    if request.password.is_some() || request.email.is_some() {
        let target = state.user_repo.get_user_by_id(*id).await.map_err(|e| {
            let (status, err) = UserApiError::from_repo_error(&e);
            (status, Json(err))
        })?;
        if target.oidc_provider_id.is_some() {
            return Err((
                StatusCode::CONFLICT,
                Json(UserApiError::new(
                    "sso_managed",
                    "Email and password of an SSO user are managed by the identity provider.",
                )),
            ));
        }
    }

    // NAN-2121 P1 #4: decode + authorize BEFORE any write. Decode once and
    // reuse for both the check and the write so they cannot diverge.
    let group_uuids: Option<Vec<uuid::Uuid>> = request.group_ids.as_ref().map(|group_id_strings| {
        group_id_strings
            .iter()
            .filter_map(|s| nanosiem_core::typeid::decode("group", s).ok())
            .collect()
    });
    // NAN-5027: authority over the TARGET runs for EVERY field (it used to run
    // only when `group_ids` was present, so `{"password": ..}` alone rewrote an
    // Admin's credential). The requested group grants are validated in the
    // same snapshot, under one stamp.
    let grant_stamp = crate::handlers::grant_authz::ensure_can_manage_principal(
        &auth,
        &state.pool,
        permissions::USERS_EDIT,
        *id,
        group_uuids.as_deref(),
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

    // NAN-2121: commit the profile change and the (already-authorized) group
    // membership replacement in ONE transaction, under the verified stamp.
    let user = state
        .user_repo
        .update_user_with_groups_authorized(*id, &request, group_uuids.as_deref(), grant_stamp)
        .await
    .map_err(|e| {
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
        AuditEvent::builder(AuditSource::User, USER_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            // NAN-5014/5027: say WHICH fields changed (never their values) so an
            // administrator setting someone else's password is distinguishable
            // from a rename in the audit trail.
            .details(serde_json::json!({
                "fields_changed": update_user_fields_changed(&request),
                "credential_reset": request.password.is_some() || request.email.is_some(),
                "api_keys_revoked": request.revoke_api_keys == Some(true),
            }))
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// Names (never values) of the profile fields an update request touches.
fn update_user_fields_changed(request: &UpdateUserRequest) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if request.email.is_some() {
        fields.push("email");
    }
    if request.name.is_some() {
        fields.push("name");
    }
    if request.password.is_some() {
        fields.push("password");
    }
    if request.status.is_some() {
        fields.push("status");
    }
    if request.group_ids.is_some() {
        fields.push("group_ids");
    }
    if request.local_login_break_glass.is_some() {
        fields.push("local_login_break_glass");
    }
    fields
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

    // NAN-5027: authority over the target, re-verified in the write transaction.
    let stamp = crate::handlers::grant_authz::ensure_can_manage_principal(
        &auth,
        &state.pool,
        permissions::USERS_DELETE,
        *id,
        None,
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

    state
        .user_repo
        .apply_principal_action_authorized(*id, PrincipalAction::Delete, stamp)
        .await
        .map_err(|e| {
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
        (status = 400, description = "Bad request - unknown group id", body = UserApiError),
        (status = 403, description = "Forbidden - insufficient permissions", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
        (status = 409, description = "Grant authority changed; retry the request", body = UserApiError),
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

    // NAN-2121: deny unless the caller holds every permission the requested
    // groups confer (users:edit is not authority to add a user to Admins).
    // NAN-5027: AND authority over the target — replacing an Admin's groups
    // with `[]` demotes them, after which a narrow caller could manage them.
    // Same check as `update_user`, in one snapshot under one stamp.
    let grant_stamp = crate::handlers::grant_authz::ensure_can_manage_principal(
        &auth,
        &state.pool,
        permissions::USERS_EDIT,
        *id,
        Some(&request.group_ids),
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

    state
        .user_repo
        .set_user_groups_authorized(*id, &request.group_ids, grant_stamp)
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

    // NAN-5027: authority over the target, re-verified in the write transaction.
    let stamp = crate::handlers::grant_authz::ensure_can_manage_principal(
        &auth,
        &state.pool,
        permissions::USERS_EDIT,
        *id,
        None,
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

    state
        .user_repo
        .apply_principal_action_authorized(*id, PrincipalAction::Unlock, stamp)
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

    // F-32 / NAN-5014: the disable flips the status, stamps the revocation
    // watermark and deletes every session in ONE transaction.
    // NAN-5027: authority over the target, re-verified in the write transaction.
    let stamp = crate::handlers::grant_authz::ensure_can_manage_principal(
        &auth,
        &state.pool,
        permissions::USERS_EDIT,
        *id,
        None,
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

    state
        .user_repo
        .apply_principal_action_authorized(*id, PrincipalAction::Disable, stamp)
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

    // NAN-5027: authority over the target, re-verified in the write transaction.
    let stamp = crate::handlers::grant_authz::ensure_can_manage_principal(
        &auth,
        &state.pool,
        permissions::USERS_EDIT,
        *id,
        None,
    )
    .await
    .map_err(|g| (g.status, Json(UserApiError::new(g.code, &g.message))))?;

    state
        .user_repo
        .apply_principal_action_authorized(*id, PrincipalAction::Enable, stamp)
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
        AuditEvent::builder(AuditSource::User, USER_ENABLED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("user", Some(user.id), Some(user.email.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(UserWithGroups { user, groups }))
}

/// NAN-2099: 403 for an API key on interactive preference self-service. An API
/// key's `claims.sub` is its owner, so the ownership shortcut would let any key
/// read or mutate the human owner's UI preferences. Preferences are interactive
/// session state, not a machine capability.
fn preferences_interactive_only() -> (StatusCode, Json<UserApiError>) {
    (
        StatusCode::FORBIDDEN,
        Json(UserApiError::new(
            "interactive_session_required",
            "Preference self-service requires an interactive session; API keys are not permitted.",
        )),
    )
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
        (status = 403, description = "Forbidden — interactive session required (API keys not permitted)", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_my_preferences(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<UserPreferences>, (StatusCode, Json<UserApiError>)> {
    if auth.is_api_key {
        return Err(preferences_interactive_only());
    }
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
        (status = 403, description = "Forbidden — interactive session required (API keys not permitted)", body = UserApiError),
        (status = 404, description = "User not found", body = UserApiError),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_my_preferences(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Json(request): Json<UpdateUserPreferencesRequest>,
) -> Result<Json<UserPreferences>, (StatusCode, Json<UserApiError>)> {
    if auth.is_api_key {
        return Err(preferences_interactive_only());
    }
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

#[cfg(test)]
mod password_policy_tests {
    use super::*;

    /// The admin create/update endpoints must surface a policy rejection as a
    /// 400 the UI can act on — not the 500 that `PasswordHashError` returns.
    #[test]
    fn policy_rejection_maps_to_bad_request() {
        let (status, body) = UserApiError::from_repo_error(
            &UserRepositoryError::PasswordRequirementsNotMet(
                "Password must contain at least one digit".to_string(),
            ),
        );

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.error, "password_requirements");
        assert!(body.message.contains("digit"));
    }

    /// A hashing failure is an internal fault and must stay opaque.
    #[test]
    fn hash_failure_stays_a_generic_500() {
        let (status, body) =
            UserApiError::from_repo_error(&UserRepositoryError::PasswordHashError("bcrypt".into()));

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.error, "internal_error");
        assert!(!body.message.contains("bcrypt"));
    }
}
