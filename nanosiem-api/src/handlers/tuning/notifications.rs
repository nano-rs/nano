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

    // Mark the notification as read
    state
        .notification_service
        .mark_as_read(*id)
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("Failed to mark notification as read: {}", e))
        })?;

    // Fetch and return the updated notification
    // Note: We need to get all user notifications and find the one we just updated
    let user_id = auth.user_id();
    let notifications = state
        .notification_service
        .get_user_notifications(user_id, 100)
        .await
        .map_err(|e| ApiError::InternalError(format!("Failed to fetch notification: {}", e)))?;

    // Find the notification we just marked as read
    let notification = notifications
        .into_iter()
        .find(|n| n.id == *id)
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
