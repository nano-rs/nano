// SPDX-License-Identifier: AGPL-3.0-or-later

//! Artifact exploration handlers — rare, new, scatter, and query-based discovery

use axum::http::StatusCode;
use axum::{
    Extension, Json,
    extract::{Query, State},
};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use tracing::error;

use crate::middleware::{AuthContext, check_permission};
use crate::state::AppState;
use nanosiem_core::Query as ParsedQuery;
use nanosiem_core::auth::permissions;
use nanosiem_core::prevalence::{PrevalenceScatterData, PrevalenceSettings, TimeWindow};
use nanosiem_core::query::{ClickHouseSqlGenerator, SearchExpr};

use super::settings::prevalence_settings_error_to_response;
use nanosiem_core::prevalence::{ArtifactDetailResponse, ArtifactExplorerResponse, ArtifactType};

use super::types::{
    ArtifactDetailQuery, ArtifactExplorerQuery, ArtifactListResponse, ArtifactPoint,
    NewArtifactsQuery, QueryArtifactsRequest, QueryArtifactsResponse, RareArtifactsQuery,
    ScatterPlotRequest,
};
use super::{MAX_BULK_ARTIFACTS, parse_artifact_type, parse_time_window};

/// GET /api/prevalence/rare
///
/// Get artifacts below the rarity threshold.
/// Requirements: 7.1, 7.2
#[utoipa::path(
    get,
    path = "/api/prevalence/rare",
    tag = "prevalence",
    params(RareArtifactsQuery),
    responses(
        (status = 200, description = "Rare artifacts below threshold", body = ArtifactListResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_rare_artifacts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<RareArtifactsQuery>,
) -> Result<Json<ArtifactListResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    // Check if ClickHouse is enabled
    let dual_pool = state.dual_pool().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Prevalence tracking requires ClickHouse".to_string(),
        )
    })?;

    // Create service with database config for hot-reload support (Requirement 8.5)
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    let time_window = parse_time_window(params.window.as_deref());
    let artifact_type = parse_artifact_type(params.artifact_type.as_deref());
    let limit = params.limit.unwrap_or(25).min(100); // Default 25, max 100
    let offset = params.offset.unwrap_or(0).max(0);

    // Fetch one extra to determine if there are more results
    match prevalence_service
        .get_rare_artifacts(artifact_type, time_window, limit + 1 + offset)
        .await
    {
        Ok(all_artifacts) => {
            // Apply offset and limit
            let artifacts: Vec<_> = all_artifacts
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            let total = artifacts.len();
            let has_more = total == limit as usize; // If we got exactly limit, there might be more
            Ok(Json(ArtifactListResponse {
                artifacts,
                total,
                limit,
                offset,
                has_more,
            }))
        }
        Err(e) => {
            error!("Failed to get rare artifacts: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// GET /api/prevalence/new
///
/// Get artifacts with first_seen after specified time.
/// Requirements: 7.3
#[utoipa::path(
    get,
    path = "/api/prevalence/new",
    tag = "prevalence",
    params(NewArtifactsQuery),
    responses(
        (status = 200, description = "New artifacts after specified time", body = ArtifactListResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_new_artifacts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<NewArtifactsQuery>,
) -> Result<Json<ArtifactListResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    // Check if ClickHouse is enabled
    let dual_pool = state.dual_pool().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Prevalence tracking requires ClickHouse".to_string(),
        )
    })?;

    // Create service with database config for hot-reload support (Requirement 8.5)
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    // Parse since parameter (default to 24 hours ago)
    let since = params
        .since
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now() - Duration::hours(24));

    let artifact_type = parse_artifact_type(params.artifact_type.as_deref());
    let limit = params.limit.unwrap_or(25).min(100); // Default 25, max 100
    let offset = params.offset.unwrap_or(0).max(0);

    // Fetch extra to determine if there are more results
    match prevalence_service
        .get_new_artifacts(artifact_type, since, limit + 1 + offset)
        .await
    {
        Ok(all_artifacts) => {
            // Apply offset and limit
            let artifacts: Vec<_> = all_artifacts
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect();
            let total = artifacts.len();
            let has_more = total == limit as usize;
            Ok(Json(ArtifactListResponse {
                artifacts,
                total,
                limit,
                offset,
                has_more,
            }))
        }
        Err(e) => {
            error!("Failed to get new artifacts: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// GET /api/prevalence/explorer
///
/// Get artifact explorer data with daily breakdowns for heatmap visualization.
#[utoipa::path(
    get,
    path = "/api/prevalence/explorer",
    tag = "prevalence",
    params(ArtifactExplorerQuery),
    responses(
        (status = 200, description = "Artifact explorer data with daily breakdowns", body = ArtifactExplorerResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_artifact_explorer(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ArtifactExplorerQuery>,
) -> Result<Json<ArtifactExplorerResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    let dual_pool = state.dual_pool().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Prevalence tracking requires ClickHouse".to_string(),
        )
    })?;

    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    let time_window = parse_time_window(params.window.as_deref());
    let artifact_type = parse_artifact_type(params.artifact_type.as_deref());
    let risk_filter = params.risk_level.as_deref();
    let search = params.search.as_deref();
    let limit = params.limit.unwrap_or(50).min(200);
    let offset = params.offset.unwrap_or(0).max(0);

    match prevalence_service
        .get_artifact_explorer(
            artifact_type,
            time_window,
            risk_filter,
            search,
            limit,
            offset,
        )
        .await
    {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Failed to get artifact explorer data: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// GET /api/prevalence/explorer/detail
///
/// Get detailed context for a single artifact (top hosts, users, processes, network).
#[utoipa::path(
    get,
    path = "/api/prevalence/explorer/detail",
    tag = "prevalence",
    params(ArtifactDetailQuery),
    responses(
        (status = 200, description = "Artifact detail context", body = ArtifactDetailResponse),
        (status = 403, description = "Forbidden"),
        (status = 503, description = "Service unavailable"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_artifact_detail(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(params): Query<ArtifactDetailQuery>,
) -> Result<Json<ArtifactDetailResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    let dual_pool = state.dual_pool().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Prevalence tracking requires ClickHouse".to_string(),
        )
    })?;

    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    let time_window = parse_time_window(params.window.as_deref());
    let artifact_type = ArtifactType::detect(&params.artifact);
    let logs_table = dual_pool.table_names().read("logs");

    match prevalence_service
        .get_artifact_detail(&params.artifact, &artifact_type, &logs_table, time_window)
        .await
    {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Failed to get artifact detail: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// POST /api/prevalence/scatter
///
/// Get scatter plot data for visualization.
/// Requirements: 10.1, 10.2
#[utoipa::path(
    post,
    path = "/api/prevalence/scatter",
    tag = "prevalence",
    request_body = ScatterPlotRequest,
    responses(
        (status = 200, description = "Scatter plot data", body = PrevalenceScatterData),
        (status = 400, description = "Bad request - Too many artifacts"),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_scatter_data(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<ScatterPlotRequest>,
) -> Result<Json<PrevalenceScatterData>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    // Validate total artifact count
    let total_artifacts = request.artifacts.hashes.len()
        + request.artifacts.domains.len()
        + request.artifacts.ips.len();
    if total_artifacts > MAX_BULK_ARTIFACTS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Too many artifacts: {} (max: {})",
                total_artifacts, MAX_BULK_ARTIFACTS
            ),
        ));
    }

    // Check if ClickHouse is enabled
    let dual_pool = state.dual_pool().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Prevalence tracking requires ClickHouse".to_string(),
        )
    })?;

    // Create service with database config for hot-reload support (Requirement 8.5)
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    let time_window = parse_time_window(request.window.as_deref());

    match prevalence_service
        .get_scatter_data(
            &request.artifacts.hashes,
            &request.artifacts.domains,
            &request.artifacts.ips,
            time_window,
        )
        .await
    {
        Ok(data) => Ok(Json(data)),
        Err(e) => {
            error!("Failed to get scatter plot data: {}", e);
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
        }
    }
}

/// Row struct for fetching single string columns from ClickHouse
#[derive(Debug, clickhouse::Row, Deserialize)]
struct SingleStringRow {
    value: String,
}

/// POST /api/prevalence/query-artifacts
///
/// Get prevalence data for artifacts extracted from search results.
/// Executes the query to find unique hashes and domains, then looks up their prevalence.
#[utoipa::path(
    post,
    path = "/api/prevalence/query-artifacts",
    tag = "prevalence",
    request_body = QueryArtifactsRequest,
    responses(
        (status = 200, description = "Artifacts extracted from query with prevalence data", body = QueryArtifactsResponse),
        (status = 403, description = "Forbidden - Missing permission: prevalence:view"),
        (status = 503, description = "Service unavailable - Prevalence tracking requires ClickHouse"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_query_artifacts(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<QueryArtifactsRequest>,
) -> Result<Json<QueryArtifactsResponse>, (StatusCode, String)> {
    check_permission(&auth, permissions::PREVALENCE_VIEW).map_err(|_| {
        (
            StatusCode::FORBIDDEN,
            "Missing permission: prevalence:view".to_string(),
        )
    })?;

    // Check if ClickHouse is enabled
    let dual_pool = state.dual_pool().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Prevalence tracking requires ClickHouse".to_string(),
        )
    })?;

    // Create prevalence service with database config
    let prevalence_service = nanosiem_core::prevalence::PrevalenceService::with_database_config(
        dual_pool.clickhouse().clone(),
        dual_pool.table_names(),
        &state.pool,
    )
    .await;

    // Get rarity threshold from settings
    let settings = PrevalenceSettings::new(state.pool.clone());
    let config = settings
        .get_config()
        .await
        .map_err(prevalence_settings_error_to_response)?;
    let rarity_threshold = config.rarity_threshold;

    // Parse time range
    let time_range = parse_time_range_value(&request.time_range);

    // Query for unique hashes and domains from the search results
    let ch = dual_pool.clickhouse();

    // Build time filter
    let time_filter = match &time_range {
        Some((start, end)) => format!(
            "timestamp >= '{}' AND timestamp <= '{}'",
            start.format("%Y-%m-%d %H:%M:%S"),
            end.format("%Y-%m-%d %H:%M:%S")
        ),
        None => "timestamp >= now() - INTERVAL 24 HOUR".to_string(),
    };

    // Parse the user's search query and generate WHERE clause
    let query_filter = if request.query.trim().is_empty() || request.query.trim() == "*" {
        // No query filter needed for wildcard or empty query
        "1=1".to_string()
    } else {
        // Parse the query and generate SQL WHERE clause directly from the search expression
        // This handles piped queries correctly by extracting just the search filter part
        match nanosiem_core::parse_query(&request.query) {
            Ok(parsed_query) => {
                // Extract the root search expression (handles piped queries)
                match extract_search_expr(&parsed_query) {
                    Some(search_expr) => {
                        // Generate WHERE clause directly from the search expression
                        let logs_table = state
                            .dual_pool()
                            .map(|dp| dp.table_names().read("logs"))
                            .unwrap_or_else(|| "nanosiem.logs".to_string());
                        let sql_gen = ClickHouseSqlGenerator::with_table(&logs_table);
                        match sql_gen.generate_search_expr(search_expr) {
                            Ok(where_clause) => {
                                tracing::debug!("Generated query filter: {}", where_clause);
                                where_clause
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to generate WHERE clause for query '{}': {}",
                                    request.query,
                                    e
                                );
                                "1=1".to_string()
                            }
                        }
                    }
                    None => {
                        tracing::warn!(
                            "Could not extract search expression from query '{}'",
                            request.query
                        );
                        "1=1".to_string()
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to parse query '{}': {}", request.query, e);
                "1=1".to_string()
            }
        }
    };

    // Combine time filter with query filter
    let combined_filter = format!("({}) AND ({})", time_filter, query_filter);
    tracing::debug!("Combined filter for prevalence query: {}", combined_filter);

    // Get cluster-aware table name for logs
    let logs_table = dual_pool.table_names().read("logs");

    // Query for unique file hashes (no limit - let prevalence filtering handle it)
    let hash_query = format!(
        "SELECT DISTINCT file_hash AS value FROM {} WHERE {} AND file_hash != ''",
        logs_table, combined_filter
    );

    let hash_results: Vec<String> = ch
        .query(&hash_query)
        .fetch_all::<SingleStringRow>()
        .await
        .map(|rows| rows.into_iter().map(|r| r.value).collect())
        .unwrap_or_default();

    // Query for unique domains (from dest_host)
    let domain_query = format!(
        "SELECT DISTINCT dest_host AS value FROM {} WHERE {} AND dest_host != '' AND dest_host NOT LIKE '%%.internal' AND dest_host NOT LIKE '%%.local'",
        logs_table, combined_filter
    );

    let domain_results: Vec<String> = ch
        .query(&domain_query)
        .fetch_all::<SingleStringRow>()
        .await
        .map(|rows| rows.into_iter().map(|r| r.value).collect())
        .unwrap_or_default();

    tracing::info!(
        "Query artifacts: found {} hashes, {} domains for query '{}' in time range",
        hash_results.len(),
        domain_results.len(),
        request.query
    );

    // Look up prevalence for hashes
    let mut hash_points = Vec::new();
    if !hash_results.is_empty() {
        if let Ok(hash_data) = prevalence_service
            .get_bulk_prevalence(&hash_results, TimeWindow::ThirtyDays)
            .await
        {
            for data in hash_data {
                hash_points.push(ArtifactPoint {
                    artifact: data.artifact.clone(),
                    host_count: data.host_count,
                    first_seen: data.first_seen.to_rfc3339(),
                    last_seen: data.last_seen.to_rfc3339(),
                    total_occurrences: data.total_occurrences,
                    is_rare: data.is_rare,
                    prevalence_score: data.prevalence_score,
                });
            }
        }
    }

    // Look up prevalence for domains
    let mut domain_points = Vec::new();
    if !domain_results.is_empty() {
        if let Ok(domain_data) = prevalence_service
            .get_bulk_prevalence(&domain_results, TimeWindow::ThirtyDays)
            .await
        {
            for data in domain_data {
                domain_points.push(ArtifactPoint {
                    artifact: data.artifact.clone(),
                    host_count: data.host_count,
                    first_seen: data.first_seen.to_rfc3339(),
                    last_seen: data.last_seen.to_rfc3339(),
                    total_occurrences: data.total_occurrences,
                    is_rare: data.is_rare,
                    prevalence_score: data.prevalence_score,
                });
            }
        }
    }

    Ok(Json(QueryArtifactsResponse {
        hash_points,
        domain_points,
        rarity_threshold,
    }))
}

/// Extract the root SearchExpr from a ParsedQuery, handling piped queries
/// For piped queries like `sourcetype=foo | sort _time`, this extracts just the search part
fn extract_search_expr(query: &ParsedQuery) -> Option<&SearchExpr> {
    match query {
        ParsedQuery::Search(expr) => Some(expr),
        ParsedQuery::Piped { source, .. } => extract_search_expr(source),
    }
}

/// Parse time_range value from JSON (can be string preset or object with start/end)
fn parse_time_range_value(value: &serde_json::Value) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    if let Some(preset) = value.as_str() {
        // Handle preset strings like "Last 24 hours", "Last 7 days"
        let now = Utc::now();
        let start = match preset {
            "Last 1 hour" => now - Duration::hours(1),
            "Last 4 hours" => now - Duration::hours(4),
            "Last 12 hours" => now - Duration::hours(12),
            "Last 24 hours" => now - Duration::hours(24),
            "Last 7 days" => now - Duration::days(7),
            "Last 30 days" => now - Duration::days(30),
            "Last 90 days" => now - Duration::days(90),
            _ => now - Duration::hours(24),
        };
        Some((start, now))
    } else if let Some(obj) = value.as_object() {
        // Handle object with start/end
        let start = obj
            .get("start")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))?;
        let end = obj
            .get("end")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))?;
        Some((start, end))
    } else {
        None
    }
}
