// SPDX-License-Identifier: AGPL-3.0-or-later

//! Group Management API handlers
//!
//! Requirements: 11.2
//!
//! This module provides handlers for:
//! - list_groups() - List all groups with role assignments and member counts
//! - get_group() - Get group details
//! - create_group() - Create a new group
//! - update_group() - Update group details
//! - delete_group() - Delete a group
//! - update_group_roles() - Update group's role assignments
//! - get_group_members() - List members of a group

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, GROUP_CREATED, GROUP_DELETED, GROUP_ROLES_UPDATED,
    GROUP_UPDATED,
};
use nanosiem_core::auth::{
    permissions, CreateGroupRequest, Group, GroupRepositoryError, RoleSummary, UpdateGroupRequest,
    User,
};
use nanosiem_core::typeid::TypeIdParam;

use crate::handlers::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for group endpoints
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GroupApiError {
    pub error: String,
    pub message: String,
}

impl GroupApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &GroupRepositoryError) -> (StatusCode, Self) {
        let (status, error_type) = match err {
            GroupRepositoryError::NotFound(_) => (StatusCode::NOT_FOUND, "group_not_found"),
            GroupRepositoryError::NameExists(_) => (StatusCode::CONFLICT, "name_exists"),
            GroupRepositoryError::CannotModifySystemGroup(_) => {
                (StatusCode::FORBIDDEN, "cannot_modify_system_group")
            }
            GroupRepositoryError::CannotDeleteSystemGroup(_) => {
                (StatusCode::FORBIDDEN, "cannot_delete_system_group")
            }
            GroupRepositoryError::DatabaseError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "database_error")
            }
        };

        (status, Self::new(error_type, &err.to_string()))
    }
}

/// Group with details (roles and member count)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GroupWithDetails {
    #[serde(flatten)]
    pub group: Group,
    pub roles: Vec<RoleSummary>,
    pub member_count: i64,
}

/// Group list response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GroupListResponse {
    pub groups: Vec<GroupWithDetails>,
    pub total: i64,
}

/// List all groups
///
/// Requirements: 11.2 - List groups with role assignments and member counts
///
/// GET /api/groups
#[utoipa::path(
    get,
    path = "/api/groups",
    tag = "groups",
    responses(
        (status = 200, description = "List of all groups with roles and member counts", body = GroupListResponse),
        (status = 403, description = "Forbidden - insufficient permissions", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_groups(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<GroupListResponse>, (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_VIEW)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    let groups = state.group_repo.list_groups().await.map_err(|e| {
        let (status, err) = GroupApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = groups.len() as i64;

    // Get roles and member count for each group
    let mut groups_with_details = Vec::with_capacity(groups.len());
    for group in groups {
        let roles = state
            .group_repo
            .get_group_roles(group.id)
            .await
            .unwrap_or_default();

        let member_count = state
            .group_repo
            .get_member_count(group.id)
            .await
            .unwrap_or(0);

        groups_with_details.push(GroupWithDetails {
            group,
            roles,
            member_count,
        });
    }

    Ok(Json(GroupListResponse {
        groups: groups_with_details,
        total,
    }))
}

/// Get group details
///
/// GET /api/groups/{id}
#[utoipa::path(
    get,
    path = "/api/groups/{id}",
    tag = "groups",
    params(
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "Group details with roles and member count", body = GroupWithDetails),
        (status = 403, description = "Forbidden - insufficient permissions", body = GroupApiError),
        (status = 404, description = "Group not found", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_group(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<GroupWithDetails>, (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_VIEW)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    let group = state.group_repo.get_group(*id).await.map_err(|e| {
        let (status, err) = GroupApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let roles = state
        .group_repo
        .get_group_roles(*id)
        .await
        .unwrap_or_default();

    let member_count = state.group_repo.get_member_count(*id).await.unwrap_or(0);

    Ok(Json(GroupWithDetails {
        group,
        roles,
        member_count,
    }))
}

/// Create a new group
///
/// POST /api/groups
#[utoipa::path(
    post,
    path = "/api/groups",
    tag = "groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "Group created successfully", body = GroupWithDetails),
        (status = 403, description = "Forbidden - insufficient permissions", body = GroupApiError),
        (status = 409, description = "Conflict - group name already exists", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_group(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Json(request): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<GroupWithDetails>), (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_CREATE)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    let group = state.group_repo.create_group(&request).await.map_err(|e| {
        let (status, err) = GroupApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let roles = state
        .group_repo
        .get_group_roles(group.id)
        .await
        .unwrap_or_default();

    let member_count = 0; // New group has no members

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Group, GROUP_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("group", Some(group.id), Some(group.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok((
        StatusCode::CREATED,
        Json(GroupWithDetails {
            group,
            roles,
            member_count,
        }),
    ))
}

/// Update a group
///
/// PUT /api/groups/{id}
#[utoipa::path(
    put,
    path = "/api/groups/{id}",
    tag = "groups",
    params(
        ("id" = String, Path, description = "Group ID")
    ),
    request_body = UpdateGroupRequest,
    responses(
        (status = 200, description = "Group updated successfully", body = GroupWithDetails),
        (status = 403, description = "Forbidden - insufficient permissions or system group", body = GroupApiError),
        (status = 404, description = "Group not found", body = GroupApiError),
        (status = 409, description = "Conflict - group name already exists", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_group(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateGroupRequest>,
) -> Result<Json<GroupWithDetails>, (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_EDIT)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    let group = state
        .group_repo
        .update_group(*id, &request)
        .await
        .map_err(|e| {
            let (status, err) = GroupApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    let roles = state
        .group_repo
        .get_group_roles(*id)
        .await
        .unwrap_or_default();

    let member_count = state.group_repo.get_member_count(*id).await.unwrap_or(0);

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Group, GROUP_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("group", Some(group.id), Some(group.name.clone()))
            .client_context(&client)
            .build(),
    );

    Ok(Json(GroupWithDetails {
        group,
        roles,
        member_count,
    }))
}

/// Delete a group
///
/// DELETE /api/groups/{id}
#[utoipa::path(
    delete,
    path = "/api/groups/{id}",
    tag = "groups",
    params(
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 204, description = "Group deleted successfully"),
        (status = 403, description = "Forbidden - insufficient permissions or system group", body = GroupApiError),
        (status = 404, description = "Group not found", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_group(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_DELETE)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    // Get group name for audit before deleting
    let group_name = state
        .group_repo
        .get_group(*id)
        .await
        .map(|g| g.name)
        .unwrap_or_else(|_| "unknown".to_string());

    state.group_repo.delete_group(*id).await.map_err(|e| {
        let (status, err) = GroupApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Group, GROUP_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("group", Some(*id), Some(group_name))
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Update group roles request
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateGroupRolesRequest {
    #[serde(with = "nanosiem_core::typeid::role::vec")]
    #[schema(value_type = Vec<String>)]
    pub role_ids: Vec<Uuid>,
}

/// Update group's role assignments
///
/// PUT /api/groups/{id}/roles
#[utoipa::path(
    put,
    path = "/api/groups/{id}/roles",
    tag = "groups",
    params(
        ("id" = String, Path, description = "Group ID")
    ),
    request_body = UpdateGroupRolesRequest,
    responses(
        (status = 200, description = "Group roles updated successfully", body = GroupWithDetails),
        (status = 403, description = "Forbidden - insufficient permissions or system group", body = GroupApiError),
        (status = 404, description = "Group not found", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn update_group_roles(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    client: axum::Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateGroupRolesRequest>,
) -> Result<Json<GroupWithDetails>, (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_EDIT)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    state
        .group_repo
        .set_group_roles(*id, &request.role_ids)
        .await
        .map_err(|e| {
            let (status, err) = GroupApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    let group = state.group_repo.get_group(*id).await.map_err(|e| {
        let (status, err) = GroupApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let roles = state
        .group_repo
        .get_group_roles(*id)
        .await
        .unwrap_or_default();

    let member_count = state.group_repo.get_member_count(*id).await.unwrap_or(0);

    // Emit audit event
    state.emit_audit(
        AuditEvent::builder(AuditSource::Group, GROUP_ROLES_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("group", Some(group.id), Some(group.name.clone()))
            .client_context(&client)
            .details(serde_json::json!({
                "role_ids": request.role_ids,
            }))
            .build(),
    );

    Ok(Json(GroupWithDetails {
        group,
        roles,
        member_count,
    }))
}

/// Group member summary (minimal user info)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GroupMemberSummary {
    #[serde(with = "nanosiem_core::typeid::user")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub status: String,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<User> for GroupMemberSummary {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.name,
            status: user.status,
            last_login_at: user.last_login_at,
        }
    }
}

/// Group members response
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct GroupMembersResponse {
    pub members: Vec<GroupMemberSummary>,
    pub total: i64,
}

/// Get members of a group
///
/// GET /api/groups/{id}/members
#[utoipa::path(
    get,
    path = "/api/groups/{id}/members",
    tag = "groups",
    params(
        ("id" = String, Path, description = "Group ID")
    ),
    responses(
        (status = 200, description = "List of group members", body = GroupMembersResponse),
        (status = 403, description = "Forbidden - insufficient permissions", body = GroupApiError),
        (status = 404, description = "Group not found", body = GroupApiError),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_group_members(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<GroupMembersResponse>, (StatusCode, Json<GroupApiError>)> {
    check_permission(&auth, permissions::GROUPS_VIEW)
        .map_err(|(s, j)| (s, Json(GroupApiError::new(&j.error, &j.message))))?;

    let members = state.group_repo.get_group_members(*id).await.map_err(|e| {
        let (status, err) = GroupApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    let total = members.len() as i64;
    let members: Vec<GroupMemberSummary> = members.into_iter().map(|u| u.into()).collect();

    Ok(Json(GroupMembersResponse { members, total }))
}

/// OpenAPI documentation for Groups endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_groups,
        get_group,
        create_group,
        update_group,
        delete_group,
        update_group_roles,
        get_group_members,
    ),
    components(schemas(
        GroupApiError,
        GroupWithDetails,
        GroupListResponse,
        UpdateGroupRolesRequest,
        GroupMemberSummary,
        GroupMembersResponse,
    )),
    tags(
        (name = "groups", description = "Group management endpoints")
    )
)]
pub struct GroupsApiDoc;
