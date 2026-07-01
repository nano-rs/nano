// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::tuning::TuningLogEntry;
use nanosiem_core::typeid::TypeIdParam;

use super::types::{ApprovalResponse, ListLogsQuery, RevertRequest};
use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// GET /api/tuning/logs
///
/// List tuning log entries with optional filters.
///
/// Requirements: 8.1
#[utoipa::path(
    get,
    path = "/api/tuning/logs",
    tag = "tuning",
    params(ListLogsQuery),
    responses(
        (status = 200, description = "Logs listed successfully", body = Vec<TuningLogEntry>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn list_logs(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<ListLogsQuery>,
) -> Result<Json<Vec<TuningLogEntry>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // List tuning logs
    let logs = if let Some(rule_id) = query.rule_id {
        // Get logs for a specific rule
        state
            .tuning_repository
            .get_logs_for_rule(rule_id)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to list logs: {}", e)))?
    } else {
        // Get recent logs across all rules
        state
            .tuning_repository
            .get_recent_logs(query.limit as i32)
            .await
            .map_err(|e| ApiError::InternalError(format!("Failed to list logs: {}", e)))?
    };

    // Apply status filter if provided
    let filtered_logs = if let Some(status) = query.status {
        logs.into_iter()
            .filter(|log| log.status == status)
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect()
    } else {
        logs.into_iter()
            .skip(query.offset as usize)
            .take(query.limit as usize)
            .collect()
    };

    Ok(Json(filtered_logs))
}

/// GET /api/tuning/logs/:id
///
/// Get a specific tuning log entry by ID.
///
/// Requirements: 8.1
#[utoipa::path(
    get,
    path = "/api/tuning/logs/{id}",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Log entry ID")
    ),
    responses(
        (status = 200, description = "Log entry retrieved", body = TuningLogEntry),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 404, description = "Log entry not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn get_log(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<TuningLogEntry>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // Get log entry by ID
    let log = state
        .tuning_repository
        .get_log_entry(*id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to get log entry: {}", e)))?
        .ok_or_else(|| ApiError::NotFound("Log entry not found".to_string()))?;

    Ok(Json(log))
}

/// POST /api/tuning/logs/:id/revert
///
/// Revert a tuning by activating the previous version.
///
/// Requirements: 9.2
#[utoipa::path(
    post,
    path = "/api/tuning/logs/{id}/revert",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Log entry ID")
    ),
    request_body = RevertRequest,
    responses(
        (status = 200, description = "Tuning reverted", body = ApprovalResponse),
        (status = 403, description = "Missing permission: detections:edit"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn revert_tuning(
    State(_state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(_id): Path<TypeIdParam>,
    Json(request): Json<RevertRequest>,
) -> Result<Json<ApprovalResponse>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_EDIT)?;

    // TODO: Implement revert workflow
    // 1. Retrieve log entry
    // 2. Validate it represents an applied tuning
    // 3. Activate the specified previous version
    // 4. Update log entry with revert information
    // 5. Send notifications
    // 6. Set 7-day cooldown on auto-tuning

    Ok(Json(ApprovalResponse {
        success: false,
        message: "Revert workflow not yet implemented".to_string(),
        version_id: Some(request.version_id),
    }))
}
