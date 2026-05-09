// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query Library API Handlers

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use tracing::error;
use utoipa::{IntoParams, ToSchema};

use super::AuditExt;
use crate::middleware::{check_permission, AuthContext};
use crate::state::AppState;
use nanosiem_core::audit::{AuditEvent, AuditSource, ClientContext, QUERY_CREATED, QUERY_DELETED};
use nanosiem_core::auth::permissions;
use nanosiem_core::{CategoryCount, LibraryFilter, LibraryQuery, NewLibraryQuery};

/// Query parameters for listing queries
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListQueriesParams {
    pub category: Option<String>,
    pub difficulty: Option<String>,
    pub use_case: Option<String>,
    pub tag: Option<String>,
    pub search: Option<String>,
    pub builtin_only: Option<bool>,
}

/// Response for listing queries
#[derive(Debug, Serialize, ToSchema)]
pub struct ListQueriesResponse {
    pub queries: Vec<LibraryQuery>,
    pub total: usize,
}

/// Response for categories
#[derive(Debug, Serialize, ToSchema)]
pub struct CategoriesResponse {
    pub categories: Vec<CategoryCount>,
}

/// Response for tags
#[derive(Debug, Serialize, ToSchema)]
pub struct TagsResponse {
    pub tags: Vec<String>,
}

/// List all queries with optional filtering
#[utoipa::path(
    get,
    path = "/api/query-library",
    tag = "query_library",
    params(ListQueriesParams),
    responses(
        (status = 200, description = "Queries retrieved successfully", body = ListQueriesResponse),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error"),
    ),
    security(("api_key" = []))
)]
pub async fn list_queries(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ListQueriesParams>,
) -> Result<Json<ListQueriesResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::SEARCH_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: search:view".to_string(),
        )
    })?;

    let filter = LibraryFilter {
        category: params.category,
        difficulty: params.difficulty.and_then(|d| d.parse().ok()),
        use_case: params.use_case,
        tag: params.tag,
        search: params.search,
        builtin_only: params.builtin_only,
    };

    match state.query_library.list(&filter).await {
        Ok(queries) => {
            let total = queries.len();
            Ok(Json(ListQueriesResponse { queries, total }))
        }
        Err(e) => {
            error!("Failed to list queries: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Get a query by ID
#[utoipa::path(
    get,
    path = "/api/query-library/{id}",
    tag = "query_library",
    params(
        ("id" = i32, Path, description = "Query ID")
    ),
    responses(
        (status = 200, description = "Query retrieved successfully", body = LibraryQuery),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(("api_key" = []))
)]
pub async fn get_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<i32>,
) -> Result<Json<LibraryQuery>, (StatusCode, String)> {
    check_permission(&auth, permissions::SEARCH_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: search:view".to_string(),
        )
    })?;

    match state.query_library.get(id).await {
        Ok(Some(query)) => Ok(Json(query)),
        Ok(None) => Err((StatusCode::NOT_FOUND, "Query not found".to_string())),
        Err(e) => {
            error!("Failed to get query: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Create a new query
#[utoipa::path(
    post,
    path = "/api/query-library",
    tag = "query_library",
    request_body = NewLibraryQuery,
    responses(
        (status = 200, description = "Query created successfully", body = LibraryQuery),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Conflict - query name already exists"),
        (status = 500, description = "Internal server error"),
    ),
    security(("api_key" = []))
)]
pub async fn create_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Json(request): Json<NewLibraryQuery>,
) -> Result<Json<LibraryQuery>, (StatusCode, String)> {
    check_permission(&auth, permissions::SEARCH_SAVE).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: search:save".to_string(),
        )
    })?;

    // Validate the query name is unique
    if let Ok(Some(_)) = state.query_library.get_by_name(&request.name).await {
        return Err((
            StatusCode::CONFLICT,
            "Query with this name already exists".to_string(),
        ));
    }

    match state.query_library.create(&request).await {
        Ok(query) => {
            state.emit_audit(
                AuditEvent::builder(AuditSource::QueryLibrary, QUERY_CREATED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("library_query", None, Some(query.name.clone()))
                    .client_context(&client)
                    .build(),
            );
            Ok(Json(query))
        }
        Err(e) => {
            error!("Failed to create query: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Delete a query (only non-builtin)
#[utoipa::path(
    delete,
    path = "/api/query-library/{id}",
    tag = "query_library",
    params(
        ("id" = i32, Path, description = "Query ID")
    ),
    responses(
        (status = 204, description = "Query deleted successfully"),
        (status = 403, description = "Forbidden - cannot delete built-in queries"),
        (status = 404, description = "Not found"),
        (status = 500, description = "Internal server error"),
    ),
    security(("api_key" = []))
)]
pub async fn delete_query(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Extension(client): Extension<ClientContext>,
    Path(id): Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    check_permission(&auth, permissions::SEARCH_SAVE).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: search:save".to_string(),
        )
    })?;

    // Check if query exists and is not builtin
    let query_name = match state.query_library.get(id).await {
        Ok(Some(query)) => {
            if query.is_builtin {
                return Err((
                    StatusCode::FORBIDDEN,
                    "Cannot delete built-in queries".to_string(),
                ));
            }
            query.name
        }
        Ok(None) => return Err((StatusCode::NOT_FOUND, "Query not found".to_string())),
        Err(e) => {
            error!("Failed to get query: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
        }
    };

    match state.query_library.delete(id).await {
        Ok(true) => {
            state.emit_audit(
                AuditEvent::builder(AuditSource::QueryLibrary, QUERY_DELETED)
                    .actor(Some(auth.user_id()), None)
                    .api_key(auth.api_key_id, auth.api_key_name.clone())
                    .resource("library_query", None, Some(query_name))
                    .client_context(&client)
                    .build(),
            );
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(false) => Err((StatusCode::NOT_FOUND, "Query not found".to_string())),
        Err(e) => {
            error!("Failed to delete query: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Get all categories
#[utoipa::path(
    get,
    path = "/api/query-library/categories",
    tag = "query_library",
    responses(
        (status = 200, description = "Categories retrieved successfully", body = CategoriesResponse),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error"),
    ),
    security(("api_key" = []))
)]
pub async fn get_categories(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<CategoriesResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::SEARCH_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: search:view".to_string(),
        )
    })?;

    match state.query_library.get_categories().await {
        Ok(categories) => Ok(Json(CategoriesResponse { categories })),
        Err(e) => {
            error!("Failed to get categories: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Get all tags
#[utoipa::path(
    get,
    path = "/api/query-library/tags",
    tag = "query_library",
    responses(
        (status = 200, description = "Tags retrieved successfully", body = TagsResponse),
        (status = 403, description = "Forbidden"),
        (status = 500, description = "Internal server error"),
    ),
    security(("api_key" = []))
)]
pub async fn get_tags(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<TagsResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::SEARCH_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: search:view".to_string(),
        )
    })?;

    match state.query_library.get_tags().await {
        Ok(tags) => Ok(Json(TagsResponse { tags })),
        Err(e) => {
            error!("Failed to get tags: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// OpenAPI documentation for query library endpoints
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_queries,
        get_query,
        create_query,
        delete_query,
        get_categories,
        get_tags
    ),
    components(schemas(ListQueriesResponse, CategoriesResponse, TagsResponse))
)]
pub struct QueryLibraryApiDoc;
