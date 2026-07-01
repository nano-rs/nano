// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search endpoint handlers
//!
//! NOTE: Core search handlers have been moved to the standalone nanosiem-search service.
//! This file retains handlers for search-related features that remain in Main API:
//! - Shared searches (short URLs)
//! - Query explanations (AI reasoning cache)
//!
//! The Search Service runs on port 3002 and handles:
//! - POST /api/search - Execute piped query
//! - POST /api/search/sql - Execute raw SQL (SELECT only)
//! - POST /api/search/explain - Show generated SQL
//! - GET/POST /api/search/saved/* - Saved searches CRUD
//!
//! See: nanosiem-search/src/handlers.rs for the active implementation.
//!
//! Requirements: 1.4 (Main API delegates search to Search Service)

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use nanosiem_core::auth::permissions;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// =============================================================================
// ACTIVE: Shared search handlers (remain in Main API)
// =============================================================================

use nanosiem_core::{NewSharedSearch, SharedSearchResponse};

/// Request for creating a shared search (short URL)
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSharedSearchRequest {
    pub query: String,
    pub query_mode: String,
    pub time_range_type: String,
    pub time_range_preset: Option<String>,
    pub time_range_start: Option<String>,
    pub time_range_end: Option<String>,
}

/// Response for creating a shared search
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateSharedSearchResponse {
    pub id: String,
    pub short_url: String,
}

/// Create a shared search (short URL)
#[utoipa::path(
    post,
    path = "/api/search/share",
    tag = "search",
    request_body = CreateSharedSearchRequest,
    responses(
        (status = 200, description = "Shared search created", body = CreateSharedSearchResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn create_shared_search(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<CreateSharedSearchRequest>,
) -> Result<Json<CreateSharedSearchResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_SHARE)?;
    use nanosiem_core::db::repository::SharedSearchRepository;

    // Parse timestamps if provided
    let time_range_start: Option<DateTime<Utc>> = request
        .time_range_start
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let time_range_end: Option<DateTime<Utc>> = request
        .time_range_end
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let new_shared = NewSharedSearch {
        query: request.query,
        query_mode: request.query_mode,
        time_range_type: request.time_range_type,
        time_range_preset: request.time_range_preset,
        time_range_start,
        time_range_end,
    };

    let repo = SharedSearchRepository::new(state.pool.clone());
    let shared = repo
        .create(&new_shared)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(CreateSharedSearchResponse {
        id: shared.id.clone(),
        short_url: format!("/search?s={}", shared.id),
    }))
}

/// Get a shared search by short ID
#[utoipa::path(
    get,
    path = "/api/search/shared/{id}",
    tag = "search",
    params(
        ("id" = String, Path, description = "Shared search ID")
    ),
    responses(
        (status = 200, description = "Shared search details", body = SharedSearchResponse),
        (status = 404, description = "Shared search not found"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_shared_search(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> Result<Json<SharedSearchResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    use nanosiem_core::db::repository::SharedSearchRepository;

    let repo = SharedSearchRepository::new(state.pool.clone());
    let shared = repo.find_by_id(&id).await.map_err(|e| match e {
        nanosiem_core::db::repository::SharedSearchRepositoryError::NotFound(_) => {
            ApiError::NotFound(format!("Shared search not found: {}", id))
        }
        _ => ApiError::DatabaseError(e.to_string()),
    })?;

    Ok(Json(SharedSearchResponse::from(shared)))
}

// =============================================================================
// ACTIVE: Query Explanation Cache (remains in Main API - AI feature)
// =============================================================================

/// Request for storing a query explanation
#[derive(Debug, Deserialize, ToSchema)]
pub struct StoreQueryExplanationRequest {
    pub query: String,
    pub query_mode: String,
    #[serde(default)]
    pub natural_language_prompt: Option<String>,
    #[serde(default)]
    pub explanation: Option<String>,
    #[serde(default)]
    pub reasoning_steps: Option<Vec<ReasoningStepInput>>,
    #[serde(default)]
    pub fields_used: Option<Vec<String>>,
    #[serde(default)]
    pub generated_sql: Option<String>,
    #[serde(default)]
    pub complexity: Option<String>,
    #[serde(default)]
    pub suggested_time_range: Option<String>,
}

/// Reasoning step input from API
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReasoningStepInput {
    pub step_type: String,
    pub title: String,
    pub description: String,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

/// Response for query explanation
#[derive(Debug, Serialize, ToSchema)]
pub struct QueryExplanationResponse {
    pub query_hash: String,
    pub query: String,
    pub query_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub natural_language_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_steps: Option<Vec<ReasoningStepOutput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields_used: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_sql: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_time_range: Option<String>,
}

/// Reasoning step output for API
#[derive(Debug, Serialize, ToSchema)]
pub struct ReasoningStepOutput {
    pub step_type: String,
    pub title: String,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Store a query explanation
/// POST /api/search/explanation
#[utoipa::path(
    post,
    path = "/api/search/explanation",
    tag = "search",
    request_body = StoreQueryExplanationRequest,
    responses(
        (status = 200, description = "Query explanation stored", body = QueryExplanationResponse),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn store_query_explanation(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<StoreQueryExplanationRequest>,
) -> Result<Json<QueryExplanationResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_EXECUTE)?;
    use nanosiem_core::db::repository::{
        NewQueryExplanation, QueryExplanationRepository, ReasoningStepRow,
    };

    let reasoning_steps = request.reasoning_steps.map(|steps| {
        steps
            .into_iter()
            .map(|s| ReasoningStepRow {
                step_type: s.step_type,
                title: s.title,
                description: s.description,
                details: s.details,
            })
            .collect()
    });

    let new_explanation = NewQueryExplanation {
        query: request.query,
        query_mode: request.query_mode,
        natural_language_prompt: request.natural_language_prompt,
        explanation: request.explanation,
        reasoning_steps,
        fields_used: request.fields_used,
        generated_sql: request.generated_sql,
        complexity: request.complexity,
        suggested_time_range: request.suggested_time_range,
    };

    let repo = QueryExplanationRepository::new(state.pool.clone());
    let explanation = repo
        .upsert(&new_explanation)
        .await
        .map_err(|e| ApiError::DatabaseError(e.to_string()))?;

    Ok(Json(query_explanation_to_response(explanation)))
}

/// Get a query explanation by query text
/// GET /api/search/explanation?q=<query>
#[utoipa::path(
    get,
    path = "/api/search/explanation",
    tag = "search",
    params(GetExplanationParams),
    responses(
        (status = 200, description = "Query explanation found", body = QueryExplanationResponse),
        (status = 404, description = "No explanation found for this query"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_query_explanation(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    axum::extract::Query(params): axum::extract::Query<GetExplanationParams>,
) -> Result<Json<QueryExplanationResponse>, ApiError> {
    ensure_permission(&auth, permissions::SEARCH_VIEW)?;
    use nanosiem_core::db::repository::QueryExplanationRepository;

    let repo = QueryExplanationRepository::new(state.pool.clone());
    let explanation = repo.find_by_query(&params.q).await.map_err(|e| match e {
        nanosiem_core::db::repository::QueryExplanationError::NotFound(_) => {
            ApiError::NotFound("No explanation found for this query".to_string())
        }
        _ => ApiError::DatabaseError(e.to_string()),
    })?;

    Ok(Json(query_explanation_to_response(explanation)))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct GetExplanationParams {
    pub q: String,
}

fn query_explanation_to_response(
    exp: nanosiem_core::db::repository::QueryExplanation,
) -> QueryExplanationResponse {
    let reasoning_steps = exp.reasoning_steps.map(|json| {
        json.0
            .into_iter()
            .map(|s| ReasoningStepOutput {
                step_type: s.step_type,
                title: s.title,
                description: s.description,
                details: s.details,
            })
            .collect()
    });

    let fields_used = exp.fields_used.map(|json| json.0);

    QueryExplanationResponse {
        query_hash: exp.query_hash,
        query: exp.query,
        query_mode: exp.query_mode,
        natural_language_prompt: exp.natural_language_prompt,
        explanation: exp.explanation,
        reasoning_steps,
        fields_used,
        generated_sql: exp.generated_sql,
        complexity: exp.complexity,
        suggested_time_range: exp.suggested_time_range,
    }
}

// =============================================================================
// OpenAPI Documentation
// =============================================================================

#[derive(OpenApi)]
#[openapi(
    paths(
        create_shared_search,
        get_shared_search,
        store_query_explanation,
        get_query_explanation,
    ),
    components(
        schemas(
            CreateSharedSearchRequest,
            CreateSharedSearchResponse,
            StoreQueryExplanationRequest,
            ReasoningStepInput,
            QueryExplanationResponse,
            ReasoningStepOutput,
        )
    ),
    tags(
        (name = "search", description = "Search-related endpoints (shared searches, query explanations)")
    )
)]
pub struct SearchApiDoc;
