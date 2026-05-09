// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, RULE_REPO_SYNCED};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;

use super::{
    get_rule_repo_service,
    types::{SyncStartResponse, SyncStatusResponse},
    AuditExt,
};
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Start syncing a repository from GitHub (async - returns immediately)
#[utoipa::path(
    post,
    path = "/api/rule-repositories/{id}/sync",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Sync started", body = SyncStartResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn sync_repository(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SyncStartResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_SYNC).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:sync".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;

    // Verify repository exists and start sync
    let repo = service.get_repository(*id).await?;

    // Start sync in background
    service.start_sync(*id).await?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, RULE_REPO_SYNCED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("rule_repository", Some(*id), None)
            .client_context(&client)
            .build(),
    );

    Ok(Json(SyncStartResponse {
        repository_id: *id,
        status: "syncing".to_string(),
        message: format!("Sync started for {}", repo.name),
    }))
}

/// Get sync status for a repository
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}/sync/status",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Sync status retrieved successfully", body = SyncStatusResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_sync_status(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<SyncStatusResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let repository = service.get_repository(*id).await?;

    Ok(Json(SyncStatusResponse {
        status: repository.last_sync_status,
        last_synced_at: repository.last_synced_at,
        last_sync_commit: repository.last_sync_commit,
        last_sync_error: repository.last_sync_error,
        rule_count: repository.rule_count,
    }))
}
