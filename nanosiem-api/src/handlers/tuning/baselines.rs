// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::tuning::{Baseline, RuleMetrics, ThresholdBreach};
use nanosiem_core::typeid::TypeIdParam;

use super::effective_tuning_scope;
use super::types::{ListBreachesQuery, ListMetricsQuery};
use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// GET /api/tuning/baselines/:rule_id
///
/// Get baseline statistics for a detection rule.
///
/// Requirements: 1.1
#[utoipa::path(
    get,
    path = "/api/tuning/baselines/{rule_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID")
    ),
    responses(
        (status = 200, description = "Baseline retrieved successfully", body = Option<Baseline>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_baseline(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
) -> Result<Json<Option<Baseline>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let scope = effective_tuning_scope(&auth);
    let baseline = state
        .tuning_repository
        .get_baseline_for_scope(*rule_id, &scope)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch baseline: {}", e)))?;

    Ok(Json(baseline))
}

/// GET /api/tuning/metrics/:rule_id
///
/// Get recent metrics for a detection rule.
///
/// Requirements: 1.1
#[utoipa::path(
    get,
    path = "/api/tuning/metrics/{rule_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID"),
        ListMetricsQuery
    ),
    responses(
        (status = 200, description = "Metrics retrieved successfully", body = Vec<RuleMetrics>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_metrics(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
    Query(query): Query<ListMetricsQuery>,
) -> Result<Json<Vec<RuleMetrics>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let limit = query.limit.unwrap_or(100).min(1000); // Cap at 1000

    let scope = effective_tuning_scope(&auth);
    let metrics = state
        .tuning_repository
        .list_metrics_for_scope(*rule_id, limit, &scope)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch metrics: {}", e)))?;

    Ok(Json(metrics))
}

/// GET /api/tuning/breaches/:rule_id
///
/// Get threshold breach history for a detection rule.
///
/// Requirements: 2.1
#[utoipa::path(
    get,
    path = "/api/tuning/breaches/{rule_id}",
    tag = "tuning",
    params(
        ("rule_id" = String, Path, description = "Detection rule ID"),
        ListBreachesQuery
    ),
    responses(
        (status = 200, description = "Breaches retrieved successfully", body = Vec<ThresholdBreach>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_breaches(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(rule_id): Path<TypeIdParam>,
    Query(query): Query<ListBreachesQuery>,
) -> Result<Json<Vec<ThresholdBreach>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let limit = query.limit.unwrap_or(20).min(100); // Cap at 100

    let scope = effective_tuning_scope(&auth);
    let breaches = state
        .tuning_repository
        .list_breaches_for_scope(*rule_id, limit, &scope)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch breaches: {}", e)))?;

    Ok(Json(breaches))
}
