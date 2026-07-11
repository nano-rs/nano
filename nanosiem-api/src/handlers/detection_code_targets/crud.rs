// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRUD handlers for detection-as-code push targets.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::audit::{
    AuditEvent, AuditSource, ClientContext, DETECTION_CODE_TARGET_CREATED,
    DETECTION_CODE_TARGET_DELETED, DETECTION_CODE_TARGET_UPDATED,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::detection_code_target::{
    validate_git_ref, validate_path_template, validate_ref_prefix, DetectionCodeTarget,
    GitHubWriteClient, NewDetectionCodeTarget, UpdateDetectionCodeTarget,
};
use uuid::Uuid;

use super::{
    get_target_repo, map_target_err,
    types::{CreateTargetRequest, ListTargetsResponse, UpdateTargetRequest},
    AuditExt,
};
use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Validate the GitHub write parameters that are later interpolated into GitHub
/// API paths / git refs by the push service (NAN-1758). Only `Some` values are
/// checked; `None` leaves the persisted default in place. `repo_url` is validated
/// separately via `GitHubWriteClient::parse_github_repo`.
fn validate_write_params(
    base_branch: Option<&str>,
    path_template: Option<&str>,
    pr_branch_prefix: Option<&str>,
) -> Result<(), ApiError> {
    if let Some(b) = base_branch {
        validate_git_ref(b).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(p) = path_template {
        validate_path_template(p).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    if let Some(p) = pr_branch_prefix {
        validate_ref_prefix(p).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    Ok(())
}

/// List all detection-as-code push targets (secret-free).
#[utoipa::path(
    get,
    path = "/api/detection-code-targets",
    tag = "detection_code_targets",
    responses(
        (status = 200, description = "Targets retrieved", body = ListTargetsResponse),
        (status = 403, description = "Forbidden"),
    ),
    security(("api_key" = []))
)]
pub async fn list_targets(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<ListTargetsResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_VIEW)?;
    let targets = get_target_repo(&state)
        .list()
        .await
        .map_err(map_target_err)?;
    Ok(Json(ListTargetsResponse { targets }))
}

/// Get a single push target.
#[utoipa::path(
    get,
    path = "/api/detection-code-targets/{id}",
    tag = "detection_code_targets",
    params(("id" = String, Path, description = "Push target ID")),
    responses(
        (status = 200, description = "Target retrieved", body = DetectionCodeTarget),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_target(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<DetectionCodeTarget>, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_VIEW)?;
    let target = get_target_repo(&state)
        .get(id)
        .await
        .map_err(map_target_err)?;
    Ok(Json(target))
}

/// Create a new push target.
#[utoipa::path(
    post,
    path = "/api/detection-code-targets",
    tag = "detection_code_targets",
    request_body = CreateTargetRequest,
    responses(
        (status = 200, description = "Target created", body = DetectionCodeTarget),
        (status = 400, description = "Invalid repo URL"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Name already exists"),
    ),
    security(("api_key" = []))
)]
pub async fn create_target(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(req): Json<CreateTargetRequest>,
) -> Result<Json<DetectionCodeTarget>, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_MANAGE)?;

    // Reject non-github.com URLs (and malformed ones) up front with a 400.
    GitHubWriteClient::parse_github_repo(&req.repo_url)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    validate_write_params(
        req.base_branch.as_deref(),
        req.path_template.as_deref(),
        req.pr_branch_prefix.as_deref(),
    )?;

    let new_target = NewDetectionCodeTarget {
        name: req.name,
        repo_url: req.repo_url,
        base_branch: req.base_branch,
        path_template: req.path_template,
        pr_branch_prefix: req.pr_branch_prefix,
        rule_format: req.rule_format,
        enabled: req.enabled,
        token: req.token,
    };
    let target = get_target_repo(&state)
        .create(&new_target, Some(auth.user_id()))
        .await
        .map_err(map_target_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, DETECTION_CODE_TARGET_CREATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "detection_code_target",
                Some(target.id),
                Some(target.name.clone()),
            )
            .client_context(&client)
            .build(),
    );
    Ok(Json(target))
}

/// Update a push target's metadata (not the token).
#[utoipa::path(
    put,
    path = "/api/detection-code-targets/{id}",
    tag = "detection_code_targets",
    params(("id" = String, Path, description = "Push target ID")),
    request_body = UpdateTargetRequest,
    responses(
        (status = 200, description = "Target updated", body = DetectionCodeTarget),
        (status = 400, description = "Invalid repo URL"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn update_target(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTargetRequest>,
) -> Result<Json<DetectionCodeTarget>, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_MANAGE)?;

    if let Some(url) = req.repo_url.as_deref() {
        GitHubWriteClient::parse_github_repo(url)
            .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    }
    validate_write_params(
        req.base_branch.as_deref(),
        req.path_template.as_deref(),
        req.pr_branch_prefix.as_deref(),
    )?;

    let update = UpdateDetectionCodeTarget {
        name: req.name,
        repo_url: req.repo_url,
        base_branch: req.base_branch,
        path_template: req.path_template,
        pr_branch_prefix: req.pr_branch_prefix,
        enabled: req.enabled,
    };
    let target = get_target_repo(&state)
        .update(id, &update)
        .await
        .map_err(map_target_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, DETECTION_CODE_TARGET_UPDATED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource(
                "detection_code_target",
                Some(target.id),
                Some(target.name.clone()),
            )
            .client_context(&client)
            .build(),
    );
    Ok(Json(target))
}

/// Delete a push target.
#[utoipa::path(
    delete,
    path = "/api/detection-code-targets/{id}",
    tag = "detection_code_targets",
    params(("id" = String, Path, description = "Push target ID")),
    responses(
        (status = 204, description = "Target deleted"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 409, description = "Target is claimed by a tuning PR operation"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_target(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    ensure_permission(&auth, permissions::DETECTION_CODE_TARGETS_MANAGE)?;

    get_target_repo(&state)
        .delete(id)
        .await
        .map_err(map_target_err)?;

    state.emit_audit(
        AuditEvent::builder(AuditSource::RuleRepo, DETECTION_CODE_TARGET_DELETED)
            .actor(Some(auth.user_id()), None)
            .api_key(auth.api_key_id, auth.api_key_name.clone())
            .resource("detection_code_target", Some(id), None)
            .client_context(&client)
            .build(),
    );
    Ok(StatusCode::NO_CONTENT)
}
