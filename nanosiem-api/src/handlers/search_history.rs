// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search History API Handlers
//!
//! Per-user search history stored in PostgreSQL.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use nanosiem_core::db::repository::{NewSearchHistoryEntry, SearchHistoryRepository};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::middleware::{check_permission, AuthContext};
use crate::{error::ApiError, state::AppState};
use nanosiem_core::typeid::TypeIdParam;

/// Response for a search history entry
#[derive(Debug, Serialize, ToSchema)]
pub struct SearchHistoryResponse {
    #[serde(with = "nanosiem_core::typeid::saved_search")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<DateTime<Utc>>,
    pub time_range_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Response for listing history
#[derive(Debug, Serialize, ToSchema)]
pub struct ListHistoryResponse {
    pub entries: Vec<SearchHistoryResponse>,
    pub history_enabled: bool,
}

/// Query params for listing history
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListHistoryParams {
    pub limit: Option<i64>,
}

/// Request to add a history entry
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddHistoryRequest {
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<String>,
    pub time_range_end: Option<String>,
}

/// Request to toggle history enabled
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetHistoryEnabledRequest {
    pub enabled: bool,
}

/// List search history for the current user
#[utoipa::path(
    get,
    path = "/api/search/history",
    tag = "search_history",
    params(ListHistoryParams),
    responses(
        (status = 200, description = "Search history entries", body = ListHistoryResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListHistoryParams>,
) -> Result<Json<ListHistoryResponse>, ApiError> {
    check_permission(&auth, permissions::SEARCH_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;

    let user_id = auth.user_id();
    let repo = SearchHistoryRepository::new(state.pool.clone());

    let history_enabled = repo
        .is_history_enabled(user_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let entries = repo
        .list(user_id, params.limit)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    let entries: Vec<SearchHistoryResponse> = entries
        .into_iter()
        .map(|e| SearchHistoryResponse {
            id: e.id,
            query: e.query,
            query_mode: e.query_mode,
            time_range_type: e.time_range_type,
            time_range_preset: e.time_range_preset,
            time_range_start: e.time_range_start,
            time_range_end: e.time_range_end,
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(ListHistoryResponse {
        entries,
        history_enabled,
    }))
}

/// Add a search to history
#[utoipa::path(
    post,
    path = "/api/search/history",
    tag = "search_history",
    request_body = AddHistoryRequest,
    responses(
        (status = 200, description = "History entry created", body = SearchHistoryResponse),
        (status = 400, description = "Search history is disabled"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn add_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<AddHistoryRequest>,
) -> Result<Json<SearchHistoryResponse>, ApiError> {
    check_permission(&auth, permissions::SEARCH_EXECUTE)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:execute".to_string()))?;

    let user_id = auth.user_id();
    let repo = SearchHistoryRepository::new(state.pool.clone());

    // Check if history is enabled for this user
    let enabled = repo
        .is_history_enabled(user_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    if !enabled {
        return Err(ApiError::BadRequest(
            "Search history is disabled".to_string(),
        ));
    }

    // Parse timestamps if provided
    let time_range_start = request
        .time_range_start
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let time_range_end = request
        .time_range_end
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let new_entry = NewSearchHistoryEntry {
        query: request.query,
        query_mode: request.query_mode,
        time_range_type: request.time_range_type,
        time_range_preset: request.time_range_preset,
        time_range_start,
        time_range_end,
    };

    let entry = repo
        .add(user_id, &new_entry)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(SearchHistoryResponse {
        id: entry.id,
        query: entry.query,
        query_mode: entry.query_mode,
        time_range_type: entry.time_range_type,
        time_range_preset: entry.time_range_preset,
        time_range_start: entry.time_range_start,
        time_range_end: entry.time_range_end,
        created_at: entry.created_at,
    }))
}

/// Delete a specific history entry
#[utoipa::path(
    delete,
    path = "/api/search/history/{id}",
    tag = "search_history",
    params(
        ("id" = String, Path, description = "History entry ID")
    ),
    responses(
        (status = 200, description = "History entry deleted"),
        (status = 404, description = "History entry not found"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn delete_history_entry(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(entry_id): Path<TypeIdParam>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::SEARCH_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;

    let user_id = auth.user_id();
    let repo = SearchHistoryRepository::new(state.pool.clone());

    let deleted = repo
        .delete(user_id, *entry_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    if !deleted {
        return Err(ApiError::NotFound("History entry not found".to_string()));
    }

    Ok(Json(serde_json::json!({"deleted": true})))
}

/// Clear all history for the current user
#[utoipa::path(
    delete,
    path = "/api/search/history",
    tag = "search_history",
    responses(
        (status = 200, description = "All history entries cleared"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn clear_history(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::SEARCH_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;

    let user_id = auth.user_id();
    let repo = SearchHistoryRepository::new(state.pool.clone());

    let count = repo
        .clear_all(user_id)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(serde_json::json!({"cleared": count})))
}

/// Set history enabled preference
#[utoipa::path(
    put,
    path = "/api/search/history/settings",
    tag = "search_history",
    request_body = SetHistoryEnabledRequest,
    responses(
        (status = 200, description = "History settings updated"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn set_history_enabled(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<SetHistoryEnabledRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_permission(&auth, permissions::SEARCH_VIEW)
        .map_err(|_| ApiError::Forbidden("Missing permission: search:view".to_string()))?;

    let user_id = auth.user_id();
    let repo = SearchHistoryRepository::new(state.pool.clone());

    repo.set_history_enabled(user_id, request.enabled)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(serde_json::json!({"enabled": request.enabled})))
}

// =============================================================================
// OpenAPI Documentation
// =============================================================================

#[derive(OpenApi)]
#[openapi(
    paths(
        list_history,
        add_history,
        delete_history_entry,
        clear_history,
        set_history_enabled,
    ),
    components(
        schemas(
            SearchHistoryResponse,
            ListHistoryResponse,
            AddHistoryRequest,
            SetHistoryEnabledRequest,
        )
    ),
    tags(
        (name = "search_history", description = "Search history management endpoints")
    )
)]
pub struct SearchHistoryApiDoc;
