// SPDX-License-Identifier: AGPL-3.0-or-later

//! Recent Activity API Handlers
//!
//! Tracks and retrieves user's recently viewed items for the "Continue Working" feature.

use axum::{
    extract::{Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::db::repository::{RecentActivityItem, RecentActivityRepository, RecentItemType};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use utoipa::{IntoParams, ToSchema};

use crate::middleware::AuthContext;
use crate::{error::ApiError, state::AppState};

/// Response for listing recent activity
#[derive(Debug, Serialize, ToSchema)]
pub struct RecentActivityResponse {
    pub items: Vec<RecentActivityItemResponse>,
}

/// Individual recent activity item
#[derive(Debug, Serialize, ToSchema)]
pub struct RecentActivityItemResponse {
    pub item_type: String,
    /// TypeID-prefixed entity ID (e.g. rule_xxx, alert_xxx, case_xxx, dash_xxx)
    pub item_id: String,
    pub title: String,
    pub metadata: JsonValue,
    pub accessed_at: DateTime<Utc>,
}

impl From<RecentActivityItem> for RecentActivityItemResponse {
    fn from(item: RecentActivityItem) -> Self {
        // Encode the UUID back to a TypeID based on item_type
        let prefixed_id = match item.item_type.as_str() {
            "detection" => nanosiem_core::typeid::encode("rule", &item.item_id),
            "alert" => nanosiem_core::typeid::encode("alert", &item.item_id),
            "case" => nanosiem_core::typeid::encode("case", &item.item_id),
            "dashboard" => nanosiem_core::typeid::encode("dash", &item.item_id),
            "notebook" => nanosiem_core::typeid::encode("nb", &item.item_id),
            _ => item.item_id.to_string(), // fallback to raw UUID
        };
        Self {
            item_type: item.item_type,
            item_id: prefixed_id,
            title: item.title,
            metadata: item.metadata,
            accessed_at: item.accessed_at,
        }
    }
}

/// Query params for listing activity
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListActivityParams {
    pub limit: Option<i64>,
    pub item_type: Option<String>,
}

/// Request to record an activity
#[derive(Debug, Deserialize, ToSchema)]
pub struct RecordActivityRequest {
    pub item_type: String,
    /// TypeID-prefixed entity ID (e.g. rule_xxx, alert_xxx)
    pub item_id: String,
    pub item_title: Option<String>,
    pub item_metadata: Option<JsonValue>,
}

fn parse_item_type(s: &str) -> Option<RecentItemType> {
    match s {
        "detection" => Some(RecentItemType::Detection),
        "alert" => Some(RecentItemType::Alert),
        "case" => Some(RecentItemType::Case),
        "dashboard" => Some(RecentItemType::Dashboard),
        _ => None,
    }
}

/// List recent activity for the current user
#[utoipa::path(
    get,
    path = "/api/me/recent",
    tag = "recent_activity",
    params(ListActivityParams),
    responses(
        (status = 200, description = "Recent activity retrieved successfully", body = RecentActivityResponse),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn list_recent_activity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListActivityParams>,
) -> Result<Json<RecentActivityResponse>, ApiError> {
    let user_id = auth.user_id();
    let repo = RecentActivityRepository::new(state.pool.clone());

    let items = if let Some(type_str) = params.item_type {
        let item_type = parse_item_type(&type_str)
            .ok_or_else(|| ApiError::BadRequest(format!("Invalid item_type: {}", type_str)))?;
        repo.get_by_type(user_id, item_type, params.limit)
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?
    } else {
        repo.get_all(user_id, params.limit)
            .await
            .map_err(|e| ApiError::DatabaseError(e.to_string()))?
    };

    Ok(Json(RecentActivityResponse {
        items: items.into_iter().map(Into::into).collect(),
    }))
}

/// Record a user viewing an item
#[utoipa::path(
    post,
    path = "/api/me/recent",
    tag = "recent_activity",
    request_body = RecordActivityRequest,
    responses(
        (status = 200, description = "Activity recorded successfully", body = serde_json::Value),
        (status = 400, description = "Bad request"),
    ),
    security(("api_key" = []))
)]
pub async fn record_activity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<RecordActivityRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = auth.user_id();
    let repo = RecentActivityRepository::new(state.pool.clone());

    let item_type = parse_item_type(&request.item_type)
        .ok_or_else(|| ApiError::BadRequest(format!("Invalid item_type: {}", request.item_type)))?;

    // Decode TypeID-prefixed string to raw UUID. The expected prefix mirrors
    // the encoding side in `From<RecentActivityItem>` above.
    let expected_prefix = match request.item_type.as_str() {
        "detection" => "rule",
        "alert" => "alert",
        "case" => "case",
        "dashboard" => "dash",
        // parse_item_type above already rejected anything else
        _ => unreachable!(),
    };
    let item_uuid = nanosiem_core::typeid::decode(expected_prefix, &request.item_id)
        .map_err(|e| ApiError::BadRequest(format!("Invalid item_id: {}", e)))?;

    repo.record(
        user_id,
        item_type,
        item_uuid,
        request.item_title.as_deref(),
        request.item_metadata,
    )
    .await
    .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(serde_json::json!({"recorded": true})))
}

/// Clear all recent activity for the current user
#[utoipa::path(
    delete,
    path = "/api/me/recent",
    tag = "recent_activity",
    responses(
        (status = 200, description = "Recent activity cleared successfully", body = serde_json::Value),
    ),
    security(("api_key" = []))
)]
pub async fn clear_recent_activity(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let user_id = auth.user_id();
    let repo = RecentActivityRepository::new(state.pool.clone());

    let count = repo
        .clear_all(user_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(serde_json::json!({"cleared": count})))
}

/// OpenAPI documentation for recent activity endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_recent_activity, record_activity, clear_recent_activity),
    components(schemas(
        RecentActivityResponse,
        RecentActivityItemResponse,
        RecordActivityRequest
    ))
)]
pub struct RecentActivityApiDoc;
