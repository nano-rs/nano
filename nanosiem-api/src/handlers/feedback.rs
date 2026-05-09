// SPDX-License-Identifier: AGPL-3.0-or-later

//! Feedback Management handlers
//!
//! This module provides handlers for user feedback submission and admin management.
//!
//! Permission requirements:
//! - Any authenticated user can create feedback and view their own feedback
//! - users:view permission required to list/view all feedback
//! - users:edit permission required to update or delete feedback

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use nanosiem_core::auth::permissions;
use nanosiem_core::db::repository::{
    CreateFeedbackRequest, Feedback, FeedbackError, FeedbackQuery, FeedbackRepository,
    FeedbackWithUser, UpdateFeedbackRequest,
};
use nanosiem_core::typeid::TypeIdParam;

use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;

/// Error response for feedback endpoints
#[derive(Debug, Serialize, ToSchema)]
pub struct FeedbackApiError {
    pub error: String,
    pub message: String,
}

impl FeedbackApiError {
    pub fn new(error: &str, message: &str) -> Self {
        Self {
            error: error.to_string(),
            message: message.to_string(),
        }
    }

    pub fn from_repo_error(err: &FeedbackError) -> (StatusCode, Self) {
        match err {
            FeedbackError::NotFound(id) => (
                StatusCode::NOT_FOUND,
                Self::new("feedback_not_found", &format!("Feedback {} not found", id)),
            ),
            FeedbackError::Database(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Self::new("database_error", &e.to_string()),
            ),
        }
    }
}

/// Response for single feedback
#[derive(Debug, Serialize, ToSchema)]
pub struct FeedbackResponse {
    pub feedback: Feedback,
}

/// Response for feedback list
#[derive(Debug, Serialize, ToSchema)]
pub struct FeedbackListResponse {
    pub feedback: Vec<FeedbackWithUser>,
    pub total: i64,
}

/// Response for user's own feedback list
#[derive(Debug, Serialize, ToSchema)]
pub struct MyFeedbackResponse {
    pub feedback: Vec<Feedback>,
}

/// Query parameters for listing feedback
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListFeedbackQuery {
    pub category: Option<String>,
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Query parameters for user's own feedback
#[derive(Debug, Deserialize, IntoParams)]
pub struct MyFeedbackQuery {
    pub limit: Option<i64>,
}

/// Create new feedback
///
/// POST /api/feedback
#[utoipa::path(
    post,
    path = "/api/feedback",
    tag = "feedback",
    request_body = CreateFeedbackRequest,
    responses(
        (status = 201, description = "Feedback created successfully", body = FeedbackResponse),
        (status = 400, description = "Bad request", body = FeedbackApiError),
    ),
    security(("api_key" = []))
)]
pub async fn create_feedback(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Json(request): Json<CreateFeedbackRequest>,
) -> Result<(StatusCode, Json<FeedbackResponse>), (StatusCode, Json<FeedbackApiError>)> {
    // Validate category
    if !["bug", "enhancement", "general"].contains(&request.category.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(FeedbackApiError::new(
                "invalid_category",
                "Category must be one of: bug, enhancement, general",
            )),
        ));
    }

    // Validate title and description
    if request.title.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(FeedbackApiError::new(
                "invalid_title",
                "Title cannot be empty",
            )),
        ));
    }

    if request.description.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(FeedbackApiError::new(
                "invalid_description",
                "Description cannot be empty",
            )),
        ));
    }

    let repo = FeedbackRepository::new(state.pool.clone());
    let feedback = repo.create(auth.user_id(), &request).await.map_err(|e| {
        let (status, err) = FeedbackApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok((StatusCode::CREATED, Json(FeedbackResponse { feedback })))
}

/// List all feedback (admin view with user info)
///
/// Requires: users:view permission
///
/// GET /api/feedback
#[utoipa::path(
    get,
    path = "/api/feedback",
    tag = "feedback",
    params(ListFeedbackQuery),
    responses(
        (status = 200, description = "Feedback list retrieved successfully", body = FeedbackListResponse),
        (status = 403, description = "Forbidden", body = FeedbackApiError),
    ),
    security(("api_key" = []))
)]
pub async fn list_feedback(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<ListFeedbackQuery>,
) -> Result<Json<FeedbackListResponse>, (StatusCode, Json<FeedbackApiError>)> {
    check_permission(&auth, permissions::USERS_VIEW)
        .map_err(|(s, j)| (s, Json(FeedbackApiError::new(&j.error, &j.message))))?;

    let repo = FeedbackRepository::new(state.pool.clone());
    let feedback_query = FeedbackQuery {
        category: query.category,
        status: query.status,
        limit: query.limit,
        offset: query.offset,
    };

    let (feedback, total) = repo.list(&feedback_query).await.map_err(|e| {
        let (status, err) = FeedbackApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(FeedbackListResponse { feedback, total }))
}

/// List current user's feedback
///
/// GET /api/feedback/me
#[utoipa::path(
    get,
    path = "/api/feedback/me",
    tag = "feedback",
    params(MyFeedbackQuery),
    responses(
        (status = 200, description = "User's feedback retrieved successfully", body = MyFeedbackResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_my_feedback(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Query(query): Query<MyFeedbackQuery>,
) -> Result<Json<MyFeedbackResponse>, (StatusCode, Json<FeedbackApiError>)> {
    let repo = FeedbackRepository::new(state.pool.clone());
    let feedback = repo
        .list_by_user(auth.user_id(), query.limit)
        .await
        .map_err(|e| {
            let (status, err) = FeedbackApiError::from_repo_error(&e);
            (status, Json(err))
        })?;

    Ok(Json(MyFeedbackResponse { feedback }))
}

/// Get a single feedback by ID
///
/// Requires: users:view permission
///
/// GET /api/feedback/{id}
#[utoipa::path(
    get,
    path = "/api/feedback/{id}",
    tag = "feedback",
    params(
        ("id" = String, Path, description = "Feedback ID")
    ),
    responses(
        (status = 200, description = "Feedback retrieved successfully", body = FeedbackResponse),
        (status = 403, description = "Forbidden", body = FeedbackApiError),
        (status = 404, description = "Not found", body = FeedbackApiError),
    ),
    security(("api_key" = []))
)]
pub async fn get_feedback(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<Json<FeedbackResponse>, (StatusCode, Json<FeedbackApiError>)> {
    check_permission(&auth, permissions::USERS_VIEW)
        .map_err(|(s, j)| (s, Json(FeedbackApiError::new(&j.error, &j.message))))?;

    let repo = FeedbackRepository::new(state.pool.clone());
    let feedback = repo.get(*id).await.map_err(|e| {
        let (status, err) = FeedbackApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(FeedbackResponse { feedback }))
}

/// Update feedback (admin only: status and notes)
///
/// Requires: users:edit permission
///
/// PUT /api/feedback/{id}
#[utoipa::path(
    put,
    path = "/api/feedback/{id}",
    tag = "feedback",
    params(
        ("id" = String, Path, description = "Feedback ID")
    ),
    request_body = UpdateFeedbackRequest,
    responses(
        (status = 200, description = "Feedback updated successfully", body = FeedbackResponse),
        (status = 400, description = "Bad request", body = FeedbackApiError),
        (status = 403, description = "Forbidden", body = FeedbackApiError),
        (status = 404, description = "Not found", body = FeedbackApiError),
    ),
    security(("api_key" = []))
)]
pub async fn update_feedback(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Json(request): Json<UpdateFeedbackRequest>,
) -> Result<Json<FeedbackResponse>, (StatusCode, Json<FeedbackApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(FeedbackApiError::new(&j.error, &j.message))))?;

    // Validate status if provided
    if let Some(ref status) = request.status {
        if !["open", "in_progress", "resolved", "closed"].contains(&status.as_str()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(FeedbackApiError::new(
                    "invalid_status",
                    "Status must be one of: open, in_progress, resolved, closed",
                )),
            ));
        }
    }

    let repo = FeedbackRepository::new(state.pool.clone());
    let feedback = repo.update(*id, &request).await.map_err(|e| {
        let (status, err) = FeedbackApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    Ok(Json(FeedbackResponse { feedback }))
}

/// Delete feedback
///
/// Requires: users:edit permission
///
/// DELETE /api/feedback/{id}
#[utoipa::path(
    delete,
    path = "/api/feedback/{id}",
    tag = "feedback",
    params(
        ("id" = String, Path, description = "Feedback ID")
    ),
    responses(
        (status = 204, description = "Feedback deleted successfully"),
        (status = 403, description = "Forbidden", body = FeedbackApiError),
        (status = 404, description = "Not found", body = FeedbackApiError),
    ),
    security(("api_key" = []))
)]
pub async fn delete_feedback(
    State(state): State<AppState>,
    auth: axum::Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
) -> Result<StatusCode, (StatusCode, Json<FeedbackApiError>)> {
    check_permission(&auth, permissions::USERS_EDIT)
        .map_err(|(s, j)| (s, Json(FeedbackApiError::new(&j.error, &j.message))))?;

    let repo = FeedbackRepository::new(state.pool.clone());
    let deleted = repo.delete(*id).await.map_err(|e| {
        let (status, err) = FeedbackApiError::from_repo_error(&e);
        (status, Json(err))
    })?;

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(FeedbackApiError::new(
                "feedback_not_found",
                &format!("Feedback {} not found", id),
            )),
        ))
    }
}

/// OpenAPI documentation for feedback endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_feedback,
        list_feedback,
        list_my_feedback,
        get_feedback,
        update_feedback,
        delete_feedback,
    ),
    components(schemas(
        FeedbackApiError,
        FeedbackResponse,
        FeedbackListResponse,
        MyFeedbackResponse,
    ))
)]
pub struct FeedbackApiDoc;
