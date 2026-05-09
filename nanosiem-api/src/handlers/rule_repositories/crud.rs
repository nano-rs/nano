// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, RULE_REPO_CREATED, RULE_REPO_DELETED, RULE_REPO_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;
use nanosiem_core::{NewRuleRepository, RuleRepository, UpdateRuleRepository};

use super::{
    get_rule_repo_service,
    types::{CreateRepositoryRequest, ListRepositoriesResponse, UpdateRepositoryRequest},
    AuditExt,
};
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// List all rule repositories
#[utoipa::path(
    get,
    path = "/api/rule-repositories",
    tag = "rule_repositories",
    responses(
        (status = 200, description = "Repositories retrieved successfully", body = ListRepositoriesResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_repositories(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListRepositoriesResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let repositories = service.list_repositories().await?;

    Ok(Json(ListRepositoriesResponse { repositories }))
}

/// Get a single repository
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Repository retrieved successfully", body = RuleRepository),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<RuleRepository>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let repository = service.get_repository(*id).await?;

    Ok(Json(repository))
}

/// Create a new repository
#[utoipa::path(
    post,
    path = "/api/rule-repositories",
    tag = "rule_repositories",
    request_body = CreateRepositoryRequest,
    responses(
        (status = 200, description = "Repository created successfully", body = RuleRepository),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn create_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<CreateRepositoryRequest>,
) -> Result<Json<RuleRepository>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_MANAGE).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:manage".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;

    let new_repo = NewRuleRepository {
        name: req.name,
        slug: None,
        description: req.description,
        url: req.url,
        branch: req.branch,
        rules_path: req.rules_path,
        rule_format: req.rule_format,
        auto_sync_enabled: req.auto_sync_enabled,
        sync_interval_hours: req.sync_interval_hours,
    };

    let repository = service
        .create_repository(new_repo, Some(auth.user_id()))
        .await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_REPO_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "rule_repository",
                Some(repository.id),
                Some(repository.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(repository))
}

/// Update a repository
#[utoipa::path(
    put,
    path = "/api/rule-repositories/{id}",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    request_body = UpdateRepositoryRequest,
    responses(
        (status = 200, description = "Repository updated successfully", body = RuleRepository),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
    Json(req): Json<UpdateRepositoryRequest>,
) -> Result<Json<RuleRepository>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_MANAGE).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:manage".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;

    let update = UpdateRuleRepository {
        name: req.name,
        description: req.description,
        branch: req.branch,
        rules_path: req.rules_path,
        auto_sync_enabled: req.auto_sync_enabled,
        sync_interval_hours: req.sync_interval_hours,
        enabled: req.enabled,
        selected_paths: req.selected_paths,
    };

    let repository = service.update_repository(*id, update).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_REPO_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "rule_repository",
                Some(repository.id),
                Some(repository.name.clone()),
            )
            .client_context(&client)
            .build(),
    );

    Ok(Json(repository))
}

/// Delete a repository
#[utoipa::path(
    delete,
    path = "/api/rule-repositories/{id}",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 204, description = "Repository deleted successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_MANAGE).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:manage".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    service.delete_repository(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_REPO_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule_repository", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(StatusCode::NO_CONTENT)
}
