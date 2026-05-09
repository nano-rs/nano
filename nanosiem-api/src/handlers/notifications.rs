// SPDX-License-Identifier: AGPL-3.0-or-later

//! Notification handlers
//!
//! This module provides handlers for user notifications.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use nanosiem_core::db::repository::{NotificationError, NotificationRepository};
use nanosiem_core::models::{Notification, UnreadCountResponse};
use nanosiem_core::typeid::TypeIdParam;

use crate::middleware::AuthContext;
use crate::state::AppState;

/// Error response for notification endpoints
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationApiError {
    pub error: String,
    pub message: String,
}

impl NotificationApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &NotificationError) -> (StatusCode, Self) {
        match err {
            NotificationError::NotFound(id) => (
                StatusCode::NOT_FOUND,
                Self::new(
                    "notification_not_found",
                    &format!("Notification {} not found", id),
                ),
            ),
            NotificationError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Self::new("database_error", &e.to_string()),
            ),
        }
    }
}

/// Response for notification list
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationListResponse {
    pub notifications: Vec<Notification>,
}

/// Response for single notification
#[derive(Debug, Serialize, ToSchema)]
pub struct NotificationResponse {
    pub notification: Notification,
}

/// Response for mark all read
#[derive(Debug, Serialize, ToSchema)]
pub struct MarkAllReadResponse {
    pub marked_count: i64,
}

/// Query parameters for listing notifications
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListNotificationsQuery {
    pub limit: Option<i64>,
    pub unread_only: Option<bool>,
}

/// List notifications for the current user
///
/// GET /api/notifications
#[utoipa::path(
    get,
    path = "/api/notifications",
    tag = "notifications",
    params(ListNotificationsQuery),
    responses(
        (status = 200, description = "Notifications retrieved successfully", body = NotificationListResponse),
        (status = 500, description = "Internal server error", body = NotificationApiError),
    ),
    security(("api_key" = []))
)]
pub async fn list_notifications(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<ListNotificationsQuery>,
) -> Result<Json<NotificationListResponse>, (StatusCode, Json<NotificationApiError>)> {
    let repo = NotificationRepository::new(state.pool.clone());
    let limit = query.limit.unwrap_or(50);
    let unread_only = query.unread_only.unwrap_or(false);

    let notifications = repo
        .list_for_user(auth.user_id(), limit, unread_only)
        .await
        .map_err(|e| {
            let (status, err) = NotificationApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    Ok(Json(NotificationListResponse { notifications }))
}

/// Get unread notification count for the current user
///
/// GET /api/notifications/unread-count
#[utoipa::path(
    get,
    path = "/api/notifications/unread-count",
    tag = "notifications",
    responses(
        (status = 200, description = "Unread count retrieved successfully", body = UnreadCountResponse),
        (status = 500, description = "Internal server error", body = NotificationApiError),
    ),
    security(("api_key" = []))
)]
pub async fn get_unread_count(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<UnreadCountResponse>, (StatusCode, Json<NotificationApiError>)> {
    let repo = NotificationRepository::new(state.pool.clone());

    let count = repo.get_unread_count(auth.user_id()).await.map_err(|e| {
        let (status, err) = NotificationApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(UnreadCountResponse { count }))
}

/// Mark a notification as read
///
/// POST /api/notifications/{id}/read
#[utoipa::path(
    post,
    path = "/api/notifications/{id}/read",
    tag = "notifications",
    params(
        ("id" = String, Path, description = "Notification ID")
    ),
    responses(
        (status = 200, description = "Notification marked as read", body = NotificationResponse),
        (status = 403, description = "Forbidden", body = NotificationApiError),
        (status = 404, description = "Not found", body = NotificationApiError),
    ),
    security(("api_key" = []))
)]
pub async fn mark_notification_read(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<NotificationResponse>, (StatusCode, Json<NotificationApiError>)> {
    let repo = NotificationRepository::new(state.pool.clone());

    // First verify the notification belongs to this user
    let notification = repo.get(*id).await.map_err(|e| {
        let (status, err) = NotificationApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    if notification.user_id != auth.user_id() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(NotificationApiError::new(
                "forbidden",
                "Cannot mark another user's notification as read",
            )),
        ));
    }

    let notification = repo.mark_read(*id).await.map_err(|e| {
        let (status, err) = NotificationApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(NotificationResponse { notification }))
}

/// Mark all notifications as read for the current user
///
/// POST /api/notifications/read-all
#[utoipa::path(
    post,
    path = "/api/notifications/read-all",
    tag = "notifications",
    responses(
        (status = 200, description = "All notifications marked as read", body = MarkAllReadResponse),
        (status = 500, description = "Internal server error", body = NotificationApiError),
    ),
    security(("api_key" = []))
)]
pub async fn mark_all_notifications_read(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
) -> Result<Json<MarkAllReadResponse>, (StatusCode, Json<NotificationApiError>)> {
    let repo = NotificationRepository::new(state.pool.clone());

    let marked_count = repo.mark_all_read(auth.user_id()).await.map_err(|e| {
        let (status, err) = NotificationApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(MarkAllReadResponse { marked_count }))
}

/// OpenAPI documentation for notification endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_notifications,
        get_unread_count,
        mark_notification_read,
        mark_all_notifications_read
    ),
    components(schemas(
        NotificationApiError,
        NotificationListResponse,
        NotificationResponse,
        MarkAllReadResponse
    ))
)]
pub struct NotificationsApiDoc;
