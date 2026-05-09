// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::typeid::TypeIdParam;

use super::{get_rule_repo_service, types::UpstreamUpdatesResponse};
use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

/// Get list of imported rules with upstream changes
#[utoipa::path(
    get,
    path = "/api/rule-repositories/{id}/upstream-updates",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Repository ID")
    ),
    responses(
        (status = 200, description = "Upstream updates retrieved successfully", body = UpstreamUpdatesResponse),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_upstream_updates(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(repo_id): Path<TypeIdParam>,
) -> Result<Json<UpstreamUpdatesResponse>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let updates = service.check_for_updates(*repo_id).await?;
    let total_count = service.count_upstream_changes().await?;

    Ok(Json(UpstreamUpdatesResponse {
        updates,
        total_count,
    }))
}

/// Get diff between imported rule and upstream
#[utoipa::path(
    get,
    path = "/api/detection-rules/{id}/upstream-diff",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Upstream diff retrieved successfully", body = nanosiem_core::rule_repository::UpstreamDiff),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_upstream_diff(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(detection_rule_id): Path<TypeIdParam>,
) -> Result<Json<nanosiem_core::rule_repository::UpstreamDiff>, ApiError> {
    check_permission(&auth, permissions::RULE_REPOSITORIES_VIEW).map_err(|_| {
        ApiError::Forbidden("Missing permission: rule_repositories:view".to_string())
    })?;

    let service = get_rule_repo_service(&state)?;
    let diff = service.get_upstream_diff(*detection_rule_id).await?;

    Ok(Json(diff))
}

/// Dismiss upstream changes for a rule (acknowledge without updating)
#[utoipa::path(
    post,
    path = "/api/detection-rules/{id}/upstream-diff/dismiss",
    tag = "rule_repositories",
    params(
        ("id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 204, description = "Upstream changes dismissed successfully"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn dismiss_upstream_changes(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(detection_rule_id): Path<TypeIdParam>,
) -> Result<StatusCode, ApiError> {
    check_permission(&auth, permissions::DETECTIONS_EDIT)
        .map_err(|_| ApiError::Forbidden("Missing permission: detections:edit".to_string()))?;

    let service = get_rule_repo_service(&state)?;
    service.dismiss_upstream_changes(*detection_rule_id).await?;

    Ok(StatusCode::NO_CONTENT)
}
