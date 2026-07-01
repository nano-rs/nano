// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::tuning::{Baseline, RuleMetrics, ThresholdBreach};
use nanosiem_core::typeid::TypeIdParam;

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

    use nanosiem_core::tuning::BaselineMonitor;

    let baseline_monitor = BaselineMonitor::new(state.pool.clone());
    let baseline = baseline_monitor
        .get_baseline(*rule_id)
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

    let metrics = sqlx::query_as::<_, RuleMetrics>(
        r#"
        SELECT
            rule_id,
            timestamp,
            alert_count_1h,
            alert_count_24h,
            alert_count_7d,
            unique_users,
            unique_hosts,
            unique_ips,
            avg_severity,
            execution_time_ms
        FROM detection_rule_metrics
        WHERE rule_id = $1
        ORDER BY timestamp DESC
        LIMIT $2
        "#,
    )
    .bind(*rule_id)
    .bind(limit)
    .fetch_all(&state.pool)
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

    let breaches = sqlx::query_as::<_, ThresholdBreach>(
        r#"
        SELECT
            rule_id,
            detected_at,
            current_value,
            baseline_mean,
            baseline_threshold,
            deviation_magnitude,
            consecutive_periods,
            tuning_triggered
        FROM detection_threshold_breaches
        WHERE rule_id = $1
        ORDER BY detected_at DESC
        LIMIT $2
        "#,
    )
    .bind(*rule_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::InternalError(format!("Failed to fetch breaches: {}", e)))?;

    Ok(Json(breaches))
}
