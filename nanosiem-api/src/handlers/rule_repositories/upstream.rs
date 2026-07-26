// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Json,
};
use nanosiem_core::auth::{permissions, TargetEffect};
use nanosiem_core::typeid::TypeIdParam;

use super::{get_rule_repo_service, types::UpstreamUpdatesResponse};
use crate::handlers::repository_target_authz::ensure_target_effects;
use crate::middleware::{ensure_permission, AuthContext};
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
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;

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
        (status = 403, description = "Forbidden — missing rule_repositories:view or detections:view"),
        (status = 404, description = "Not found"),
    ),
    security(("api_key" = []))
)]
pub async fn get_upstream_diff(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(detection_rule_id): Path<TypeIdParam>,
) -> Result<Json<nanosiem_core::rule_repository::UpstreamDiff>, ApiError> {
    ensure_permission(&auth, permissions::RULE_REPOSITORIES_VIEW)?;
    // NAN-2103: the diff serializes the LIVE detection's `current_query` /
    // `current_title` / `current_description`. Repository visibility authorizes
    // the upstream/catalog half only — reading the private live object is what
    // `GET /api/rules/{id}` gates behind `detections:view`.
    ensure_target_effects(&auth, &[TargetEffect::DetectionView])?;

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
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    let service = get_rule_repo_service(&state)?;
    service.dismiss_upstream_changes(*detection_rule_id).await?;

    Ok(StatusCode::NO_CONTENT)
}
