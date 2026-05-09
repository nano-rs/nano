// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role Management API handlers
//!
//! Requirements: 11.3
//!
//! This module provides handlers for:
//! - list_roles() - List all roles with permission counts
//! - get_role() - Get role details with permissions
//! - create_role() - Create a new role
//! - update_role() - Update role details and permissions
//! - delete_role() - Delete a role
//! - list_permissions() - List all available permissions

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, ROLE_CREATED, ROLE_DELETED, ROLE_UPDATED,
};
use nanosiem_core::auth::{
    permissions as perm_constants, CreateRoleRequest, Permission, Role, RoleRepositoryError,
    UpdateRoleRequest,
};
use nanosiem_core::typeid::TypeIdParam;

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for role endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleApiError {
    pub error: String,
    pub message: String,
}

impl RoleApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &RoleRepositoryError) -> (StatusCode, Self) {
        let (status, error_type) = match err {
            RoleRepositoryError::NotFound(_) => (StatusCode::NOT_FOUND, "role_not_found"),
            RoleRepositoryError::NameExists(_) => (StatusCode::CONFLICT, "name_exists"),
            RoleRepositoryError::CannotModifySystemRole(_) => {
                (StatusCode::FORBIDDEN, "cannot_modify_system_role")
            }
            RoleRepositoryError::CannotDeleteSystemRole(_) => {
                (StatusCode::FORBIDDEN, "cannot_delete_system_role")
            }
            RoleRepositoryError::RoleInUse => (StatusCode::CONFLICT, "role_in_use"),
            RoleRepositoryError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database_error")
            }
        };

        (status, Self::new(error_type, &err.to_string()))
    }
}

/// Role with permissions
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleWithPermissions {
    #[serde(flatten)]
    pub role: Role,
    pub permissions: Vec<String>,
    pub permission_count: usize,
}

/// Role list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleListResponse {
    pub roles: Vec<RoleWithPermissions>,
    pub total: i64,
}

/// List all roles
///
/// Requirements: 11.3 - List roles with permission counts
///
/// GET /api/roles
#[utoipa::path(
    get,
    path = "/api/roles",
    tag = "roles",
    responses(
        (status = 200, description = "Successfully retrieved roles", body = RoleListResponse),
        (status = 403, description = "Permission denied", body = RoleApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_roles(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<RoleListResponse>, (StatusCode, Json<RoleApiError>)> {
    check_permission(&auth, perm_constants::ROLES_VIEW)
        .map_err(|(s, j)| (s, Json(RoleApiError::new(&j.error, &j.message))))?;

    let roles = state.role_repo.list_roles().await.map_err(|e| {
        let (status, err) = RoleApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = roles.len() as i64;

    // Get permissions for each role
    let mut roles_with_permissions = Vec::with_capacity(roles.len());
    for role in roles {
        let permissions = state
            .role_repo
            .get_role_permissions(role.id)
            .await
            .unwrap_or_default();

        let permission_count = permissions.len();

        roles_with_permissions.push(RoleWithPermissions {
            role,
            permissions,
            permission_count,
        });
    }

    Ok(Json(RoleListResponse {
        roles: roles_with_permissions,
        total,
    }))
}

/// Get role details
///
/// GET /api/roles/{id}
#[utoipa::path(
    get,
    path = "/api/roles/{id}",
    tag = "roles",
    params(
        ("id" = String, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Successfully retrieved role", body = RoleWithPermissions),
        (status = 403, description = "Permission denied", body = RoleApiError),
        (status = 404, description = "Role not found", body = RoleApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_role(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<RoleWithPermissions>, (StatusCode, Json<RoleApiError>)> {
    check_permission(&auth, perm_constants::ROLES_VIEW)
        .map_err(|(s, j)| (s, Json(RoleApiError::new(&j.error, &j.message))))?;

    let role = state.role_repo.get_role(*id).await.map_err(|e| {
        let (status, err) = RoleApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let permissions = state
        .role_repo
        .get_role_permissions(*id)
        .await
        .unwrap_or_default();

    let permission_count = permissions.len();

    Ok(Json(RoleWithPermissions {
        role,
        permissions,
        permission_count,
    }))
}

/// Create a new role
///
/// POST /api/roles
#[utoipa::path(
    post,
    path = "/api/roles",
    tag = "roles",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role successfully created", body = RoleWithPermissions),
        (status = 403, description = "Permission denied", body = RoleApiError),
        (status = 409, description = "Role name already exists", body = RoleApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_role(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleWithPermissions>), (StatusCode, Json<RoleApiError>)> {
    check_permission(&auth, perm_constants::ROLES_CREATE)
        .map_err(|(s, j)| (s, Json(RoleApiError::new(&j.error, &j.message))))?;

    let role = state.role_repo.create_role(&request).await.map_err(|e| {
        let (status, err) = RoleApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let permissions = state
        .role_repo
        .get_role_permissions(role.id)
        .await
        .unwrap_or_default();

    let permission_count = permissions.len();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Role, ROLE_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("role", Some(role.id), Some(role.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok((
        StatusCode::CREATED,
        Json(RoleWithPermissions {
            role,
            permissions,
            permission_count,
        }),
    ))
}

/// Update a role
///
/// PUT /api/roles/{id}
#[utoipa::path(
    put,
    path = "/api/roles/{id}",
    tag = "roles",
    params(
        ("id" = String, Path, description = "Role ID to update")
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role successfully updated", body = RoleWithPermissions),
        (status = 403, description = "Permission denied or cannot modify system role", body = RoleApiError),
        (status = 404, description = "Role not found", body = RoleApiError),
        (status = 409, description = "Role name already exists", body = RoleApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_role(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RoleWithPermissions>, (StatusCode, Json<RoleApiError>)> {
    check_permission(&auth, perm_constants::ROLES_EDIT)
        .map_err(|(s, j)| (s, Json(RoleApiError::new(&j.error, &j.message))))?;

    let role = state
        .role_repo
        .update_role(*id, &request)
        .await
        .map_err(|e| {
            let (status, err) = RoleApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    let permissions = state
        .role_repo
        .get_role_permissions(*id)
        .await
        .unwrap_or_default();

    let permission_count = permissions.len();

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Role, ROLE_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("role", Some(role.id), Some(role.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(RoleWithPermissions {
        role,
        permissions,
        permission_count,
    }))
}

/// Delete a role
///
/// DELETE /api/roles/{id}
#[utoipa::path(
    delete,
    path = "/api/roles/{id}",
    tag = "roles",
    params(
        ("id" = String, Path, description = "Role ID to delete")
    ),
    responses(
        (status = 204, description = "Role successfully deleted"),
        (status = 403, description = "Permission denied or cannot delete system role", body = RoleApiError),
        (status = 404, description = "Role not found", body = RoleApiError),
        (status = 409, description = "Role is in use", body = RoleApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_role(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<RoleApiError>)> {
    check_permission(&auth, perm_constants::ROLES_DELETE)
        .map_err(|(s, j)| (s, Json(RoleApiError::new(&j.error, &j.message))))?;

    // Get role name for audit before deleting
    let role_name = state
        .role_repo
        .get_role(*id)
        .await
        .map(|r| r.name)
        .unwrap_or_else(|_| "unknown".to_string());

    state.role_repo.delete_role(*id).await.map_err(|e| {
        let (status, err) = RoleApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Role, ROLE_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("role", Some(*id), Some(role_name))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Permission grouped by category
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PermissionCategory {
    pub category: String,
    pub permissions: Vec<Permission>,
}

/// Permissions list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PermissionsListResponse {
    pub permissions: Vec<Permission>,
    pub by_category: Vec<PermissionCategory>,
    pub total: usize,
}

/// List all available permissions
///
/// Requirements: 11.3 - Display permissions grouped by feature area
///
/// GET /api/permissions
#[utoipa::path(
    get,
    path = "/api/permissions",
    tag = "roles",
    responses(
        (status = 200, description = "Successfully retrieved permissions", body = PermissionsListResponse),
        (status = 403, description = "Permission denied", body = RoleApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_permissions(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<PermissionsListResponse>, (StatusCode, Json<RoleApiError>)> {
    check_permission(&auth, perm_constants::ROLES_VIEW)
        .map_err(|(s, j)| (s, Json(RoleApiError::new(&j.error, &j.message))))?;

    let permissions = state.role_repo.list_permissions().await.map_err(|e| {
        let (status, err) = RoleApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = permissions.len();

    // Group by category
    let mut categories: std::collections::HashMap<String, Vec<Permission>> =
        std::collections::HashMap::new();
    for perm in &permissions {
        categories
            .entry(perm.category.clone())
            .or_default()
            .push(perm.clone());
    }

    let mut by_category: Vec<PermissionCategory> = categories
        .into_iter()
        .map(|(category, perms)| PermissionCategory {
            category,
            permissions: perms,
        })
        .collect();

    // Sort categories alphabetically
    by_category.sort_by(|a, b| a.category.cmp(&b.category));

    Ok(Json(PermissionsListResponse {
        permissions,
        by_category,
        total,
    }))
}

/// OpenAPI documentation for role management endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_roles,
        create_role,
        get_role,
        update_role,
        delete_role,
        list_permissions,
    ),
    components(schemas(
        RoleApiError,
        RoleWithPermissions,
        RoleListResponse,
        PermissionCategory,
        PermissionsListResponse,
    )),
    tags(
        (name = "roles", description = "Role and permission management API")
    )
)]
pub struct RolesApiDoc;
