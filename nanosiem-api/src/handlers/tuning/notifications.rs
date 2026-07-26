// SPDX-License-Identifier: AGPL-3.0-or-later

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::tuning::Notification;
use nanosiem_core::typeid::TypeIdParam;

use super::types::MarkReadRequest;
use crate::error::ApiError;
use crate::middleware::{ensure_permission, AuthContext};
use crate::state::AppState;

/// GET /api/tuning/notifications
///
/// Get pending tuning notifications for the current user.
///
/// Requirements: 7.1
#[utoipa::path(
    get,
    path = "/api/tuning/notifications",
    tag = "tuning",
    responses(
        (status = 200, description = "Notifications retrieved", body = Vec<Notification>),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn list_tuning_notifications(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<Vec<Notification>>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // Get user ID from auth context
    let user_id = auth.user_id();

    // Fetch pending notifications for the user
    let notifications = state
        .notification_service
        .get_pending_notifications(user_id)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch notifications: {}", e)))?;

    Ok(Json(notifications))
}

/// POST /api/tuning/notifications/:id/read
///
/// Mark a tuning notification as read.
///
/// Requirements: 7.1
#[utoipa::path(
    post,
    path = "/api/tuning/notifications/{id}/read",
    tag = "tuning",
    params(
        ("id" = String, Path, description = "Notification ID")
    ),
    request_body = MarkReadRequest,
    responses(
        (status = 200, description = "Notification marked as read", body = Notification),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 404, description = "Notification not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn mark_tuning_notification_read(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(_request): Json<MarkReadRequest>,
) -> Result<Json<Notification>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    let user_id = auth.user_id();

    // NAN-2087: the ownership predicate lives INSIDE the UPDATE. Previously
    // this handler mutated `read_at` for any id first and only then searched
    // the caller's own notifications, so a `detections:view` principal could
    // silently mark another user's tuning notification read and still get a
    // 404. A foreign id now leaves the row untouched.
    // The updated row comes straight back from the same statement, so there is
    // no follow-up scan that could mis-report an owned notification as missing.
    // A not-owned id and an unknown id are indistinguishable to the caller —
    // identical 404, no existence oracle.
    let notification = state
        .notification_service
        .mark_as_read(*id, user_id)
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("Failed to mark notification as read: {}", e))
        })?
        .ok_or_else(|| ApiError::NotFound("Notification not found".to_string()))?;

    Ok(Json(notification))
}

/// POST /api/tuning/notifications/read-all
///
/// Mark all tuning notifications as read for the current user.
///
/// Requirements: 7.1
#[utoipa::path(
    post,
    path = "/api/tuning/notifications/read-all",
    tag = "tuning",
    responses(
        (status = 200, description = "All notifications marked as read", body = serde_json::Value),
        (status = 403, description = "Missing permission: detections:view"),
        (status = 500, description = "Internal server error")
    ),
    security(("api_key" = []))
)]
pub async fn mark_all_tuning_notifications_read(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_permission(&auth, permissions::DETECTIONS_VIEW)?;

    // Get user ID from auth context
    let user_id = auth.user_id();

    // Mark all notifications as read for this user
    let count = state
        .notification_service
        .mark_all_as_read(user_id)
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("Failed to mark all notifications as read: {}", e))
        })?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Marked {} notifications as read", count),
        "count": count
    })))
}
