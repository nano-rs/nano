// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search endpoints: execute, cancel, explain, fetch log, prevalence, field stats.

use axum::{
    Json,
    extract::{Path, State},
};
use nanosiem_core::{
    PrevalenceScatterData, RawSqlRequest, SearchRequest, SearchResponse, TimeRangeInput,
    auth::permissions,
    search::FieldValueInfo,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use super::SearchResultResponse;
use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

/// Enforce audit exclusion at AST level (prevents OR-based bypasses).
///
/// NAN-704: thin shim mapping `nanosiem_core::SearchError` from the
/// canonical implementation to this crate's local `SearchError` for
/// handler ergonomics.
fn enforce_non_audit_query(query: &str) -> Result<String, SearchError> {
    nanosiem_core::search::query_processing::enforce_non_audit_query(query).map_err(|e| {
        SearchError::QueryError(format!(
            "Query parsing failed for access control enforcement: {}",
            e
        ))
    })
}

/// Execute a piped query
///
/// POST /api/search
///
/// If async_mode=true, returns a job_id immediately for polling.
/// Otherwise, executes synchronously and returns results.
#[utoipa::path(
    post,
    path = "/api/search",
    tag = "search",
    request_body = SearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Search results (sync or async job id)", body = SearchResultResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn search(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(mut request): Json<SearchRequest>,
) -> Result<Json<SearchResultResponse>, SearchError> {
    use nanosiem_core::search::QueryPriority;

    // H1 fix: Users without audit:view permission cannot query audit source_type.
    // Inject a source_type exclusion into the nPL query so it is enforced server-side.
    if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        request.query = enforce_non_audit_query(&request.query)?;
    }
    if let Some(request_id) = request.request_id.clone() {
        state
            .search
            .query_tracker()
            .reserve_request(request_id, auth.claims.sub);
    }

    let user_id = auth.claims.sub;
    let priority = match request.priority.as_deref() {
        Some("analytics") => QueryPriority::Analytics,
        _ => QueryPriority::Interactive,
    };

    // Check for async mode — returns a job_id immediately for polling.
    if request.async_mode {
        let job_id = state
            .search
            .search_async_with_admission(request, user_id, priority)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to start async search");
                SearchError::QueryError("Failed to start search".to_string())
            })?;

        return Ok(Json(SearchResultResponse::Async(
            nanosiem_core::search::AsyncSearchResponse {
                job_id,
                status: "queued".to_string(),
            },
        )));
    }

    // Check search result cache (Dragonfly/Redis)
    if let Some(ref cache) = state.result_cache {
        if let Some(cached) = cache.get(&request).await {
            record_search_query("piped_cached", 0.0, true);
            return Ok(Json(SearchResultResponse::Sync(cached)));
        }
    }

    // Synchronous execution (cache miss). NAN-701: sync path now also goes
    // through the admission controller — previously it bypassed the
    // per-user limit / queue / timeout entirely, so dashboard panel
    // refreshes overshot `max_concurrent_queries_for_user`.
    let start = Instant::now();
    let result = state
        .search
        .search_with_admission(request.clone(), user_id, priority)
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("piped", duration_ms, result.is_ok());

    // Cache successful results in the background
    if let Ok(ref response) = result {
        if let Some(ref cache) = state.result_cache {
            let cache = cache.clone();
            let req = request.clone();
            let resp = response.clone();
            tokio::spawn(async move {
                cache.set(&req, &resp).await;
            });
        }
    }

    Ok(Json(SearchResultResponse::Sync(result?)))
}

/// Response for cancel_search endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CancelSearchResponse {
    /// Whether a query was actually cancelled
    pub cancelled: bool,
}

/// Cancel a running search query
///
/// Cancels a running query by its client-provided request_id.
/// Returns cancelled=true if a query was found and killed, cancelled=false if no matching query was running.
#[utoipa::path(
    delete,
    path = "/api/search/{request_id}",
    tag = "search",
    params(
        ("request_id" = String, Path, description = "Client-provided request ID of the running query")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Cancellation result", body = CancelSearchResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn cancel_search(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Path(request_id): Path<String>,
) -> Result<Json<CancelSearchResponse>, SearchError> {
    tracing::info!("Received cancel request for request_id: {}", request_id);

    let can_admin_cancel = auth.claims.has_permission(permissions::SETTINGS_SYSTEM);
    let query_info = state.search.query_tracker().get(&request_id);

    // Enforce ownership for request-id based cancellation.
    // If we can't prove ownership, return cancelled=false (do not leak existence details).
    let Some(query_info) = query_info else {
        return Ok(Json(CancelSearchResponse { cancelled: false }));
    };
    if !can_admin_cancel && query_info.owner_user_id != Some(auth.claims.sub) {
        return Ok(Json(CancelSearchResponse { cancelled: false }));
    }

    let cancelled = state.search.cancel_query(&request_id).await.map_err(|e| {
        tracing::error!(error = %e, request_id = %request_id, "Failed to cancel query");
        SearchError::QueryError("Failed to cancel query".to_string())
    })?;

    if cancelled {
        tracing::info!("Successfully cancelled query: {}", request_id);
    } else {
        tracing::debug!("No running query found for request_id: {}", request_id);
    }

    Ok(Json(CancelSearchResponse { cancelled }))
}

/// Execute a raw SQL query (SELECT only)
#[utoipa::path(
    post,
    path = "/api/search/sql",
    tag = "search",
    request_body = RawSqlRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "SQL search results", body = SearchResponse),
        (status = 400, description = "Invalid SQL or query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn search_sql(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(mut request): Json<RawSqlRequest>,
) -> Result<Json<SearchResponse>, SearchError> {
    // NAN-173: Gate raw SQL behind dedicated permission
    if !auth.claims.has_permission(permissions::SEARCH_SQL) {
        return Err(SearchError::Forbidden(
            "Raw SQL queries require the search:sql permission".to_string(),
        ));
    }

    // H1 fix: Users without audit:view permission cannot query audit source_type.
    // Wrap the user's SQL in a subquery with a source_type filter so it cannot be bypassed.
    if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        // Validate the user's original SQL BEFORE wrapping to prevent UNION injection.
        // An attacker could craft SQL with unbalanced parentheses (e.g. "SELECT * FROM logs) ...
        // UNION ALL SELECT ...") that, when wrapped in SELECT * FROM (...), breaks out of
        // the subquery and bypasses the audit filter. Validating the raw SQL first ensures
        // it parses as a valid single SELECT, which cannot contain unbalanced parens.
        nanosiem_core::search::validate_sql_query(request.sql.trim_end_matches(';'))
            .map_err(|e| SearchError::QueryError(format!("SQL validation failed: {}", e)))?;

        // Inject the audit filter using nanosiem_core's SQL manipulation utility.
        // We use inject_where_clause which parses the SQL, adds the condition to
        // the WHERE clause (or creates one), and serializes back. This avoids the
        // subquery wrapper approach which fails when the inner query uses aggregation
        // (e.g., SELECT count() — source_type not in output columns).
        request.sql = nanosiem_core::search::inject_audit_filter(request.sql.trim_end_matches(';'))
            .map_err(|e| {
                SearchError::QueryError(format!("Audit filter injection failed: {}", e))
            })?;
    }

    let start = Instant::now();
    let result = state.search.search_sql(request).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("sql", duration_ms, result.is_ok());

    Ok(Json(result?))
}

/// Request for explaining a query
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ExplainRequest {
    /// The piped query string to explain
    pub query: String,
    /// Time range for the query
    pub time_range: TimeRangeInput,
    /// Show SQL with table_view field pruning (matches actual search behavior)
    #[serde(default)]
    pub table_view: bool,
}

/// Response for explain endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ExplainResponse {
    /// The generated SQL query
    pub sql: String,
    /// Whether table_view field pruning was applied
    pub table_view: bool,
}

/// Explain a piped query (show generated SQL without executing)
#[utoipa::path(
    post,
    path = "/api/search/explain",
    tag = "search",
    request_body = ExplainRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Generated SQL for the query", body = ExplainResponse),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn explain(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(mut request): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>, SearchError> {
    if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        request.query = enforce_non_audit_query(&request.query)?;
    }
    let start = Instant::now();
    let result = state
        .search
        .explain(&request.query, &request.time_range, request.table_view);
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("explain", duration_ms, result.is_ok());

    let sql = result.map_err(|e| {
        tracing::error!(error = %e, "Query explain failed");
        // Surface user-actionable generation guardrails (see the SqlGenError
        // mapping in error.rs); mask internal failures.
        // FieldNotFound is the input-side field-validation rejection (NAN-1354)
        // — /api/search surfaces it verbatim via the From impl in error.rs, so
        // explain must match instead of masking it as "Query processing failed"
        // (NAN-1396). Only the user's own field names are echoed.
        if matches!(e, nanosiem_core::SearchError::FieldNotFound { .. }) {
            return e.into();
        }
        if let nanosiem_core::SearchError::SqlGenError(ref msg) = e {
            if msg.starts_with("Invalid query:")
                || msg.starts_with("Unsupported operation:")
            {
                return SearchError::QueryError(msg.clone());
            }
        }
        SearchError::QueryError("Query processing failed".to_string())
    })?;
    Ok(Json(ExplainResponse {
        sql,
        table_view: request.table_view,
    }))
}

/// Request for fetching a log event by ID
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FetchLogRequest {
    /// The log event ID
    pub id: String,
    /// Time range hint (for partition pruning)
    pub time_range: Option<TimeRangeInput>,
    /// Source type hint (NAN-1032). When provided, the query can use the
    /// `(source_type, timestamp, ...)` PK index for a tight range read instead
    /// of scanning every source_type's marks within the time window. Without
    /// this hint, S3-backed historical lookups take 12–60s vs <1s with it.
    pub source_type: Option<String>,
}

/// Response for fetch_log endpoint
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FetchLogResponse {
    /// The full log event as JSON
    pub event: Option<serde_json::Value>,
}

/// Fetch a single log event by ID (for row expansion)
///
/// Used when user expands a row in table_view mode to fetch full event data.
/// Much faster than SELECT * for all results since it only fetches one row.
#[utoipa::path(
    post,
    path = "/api/search/log",
    tag = "search",
    request_body = FetchLogRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Full log event data", body = FetchLogResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn fetch_log(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<FetchLogRequest>,
) -> Result<Json<FetchLogResponse>, SearchError> {
    // NAN-694: callers without audit:view must not retrieve audit rows by direct id.
    // Apply the exclusion at the SQL layer to match the rest of the search surface.
    let exclude_audit = !auth.claims.has_permission(permissions::AUDIT_VIEW);

    let start = Instant::now();
    let result = state
        .search
        .fetch_log_by_id(
            &request.id,
            request.time_range.as_ref(),
            request.source_type.as_deref(),
            exclude_audit,
        )
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("fetch_log", duration_ms, result.is_ok());

    match result {
        Ok(event) => Ok(Json(FetchLogResponse { event })),
        Err(e) => {
            tracing::error!(error = %e, log_id = %request.id, "Failed to fetch log");
            Err(SearchError::QueryError(
                "Failed to fetch log event".to_string(),
            ))
        }
    }
}

/// Get prevalence artifacts for a search query
///
/// Extracts distinct domains, hashes, and IPs from logs matching the query,
/// then returns their prevalence data for visualization. This runs asynchronously
/// after the main search to avoid slowing down initial results.
#[utoipa::path(
    post,
    path = "/api/search/prevalence-artifacts",
    tag = "search",
    request_body = SearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Prevalence scatter data for matched artifacts", body = PrevalenceScatterData),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn prevalence_artifacts(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(mut request): Json<SearchRequest>,
) -> Result<Json<PrevalenceScatterData>, SearchError> {
    if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        request.query = enforce_non_audit_query(&request.query)?;
    }

    let start = Instant::now();
    let result = state.search.get_prevalence_artifacts(&request).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("prevalence_artifacts", duration_ms, result.is_ok());

    match &result {
        Ok(_) => tracing::info!("Prevalence artifacts completed in {:.2}ms", duration_ms),
        Err(e) => tracing::error!("Prevalence artifacts failed: {:?}", e),
    }

    Ok(Json(result?))
}

/// Get field statistics for a search query (async, separate from main search)
///
/// Called in the background after search results load. Returns topK values
/// and cardinality (uniq) for all fields, enabling accurate field panel badges.
#[utoipa::path(
    post,
    path = "/api/search/field-stats",
    tag = "search",
    request_body = FieldStatsRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Field statistics with cardinality", body = FieldStatsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn field_stats_for_query(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<FieldStatsRequest>,
) -> Result<Json<FieldStatsResponse>, SearchError> {
    let query = if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        enforce_non_audit_query(&request.query)?
    } else {
        request.query.clone()
    };

    let time_range = TimeRangeInput {
        start: request.start,
        end: request.end,
    };

    let fields = state
        .search
        .get_field_stats_for_query(&query, &time_range)
        .await?;
    let total_events = fields.iter().map(|f| f.count).max().unwrap_or(0);

    Ok(Json(FieldStatsResponse {
        fields,
        total_events,
    }))
}

/// Get top values for a SINGLE field (on-demand, Kibana-style)
///
/// Called when user expands a field in the sidebar.
#[utoipa::path(
    post,
    path = "/api/search/field-values",
    tag = "search",
    request_body = FieldValuesRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Top field values with counts", body = FieldValuesResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn field_values(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<FieldValuesRequest>,
) -> Result<Json<FieldValuesResponse>, SearchError> {
    let start = Instant::now();

    let query = if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        enforce_non_audit_query(&request.query)?
    } else {
        request.query.clone()
    };

    let time_range = TimeRangeInput {
        start: request.start,
        end: request.end,
    };

    let result = state
        .search
        .get_field_values(&request.field, &query, &time_range, request.limit)
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("field_values", duration_ms, result.is_ok());

    let values = result?;
    let total_count: u64 = values.iter().map(|v| v.count).sum();

    Ok(Json(FieldValuesResponse {
        field: request.field,
        values,
        total_count,
    }))
}

/// Request for on-demand field values
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FieldValuesRequest {
    /// Field name to get values for
    pub field: String,
    /// The piped query string to filter events
    pub query: String,
    /// Start of time range
    pub start: chrono::DateTime<chrono::Utc>,
    /// End of time range
    pub end: chrono::DateTime<chrono::Utc>,
    /// Maximum number of values to return (default 100)
    #[serde(default = "default_field_values_limit")]
    pub limit: usize,
}

fn default_field_values_limit() -> usize {
    100
}

/// Response for field values
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FieldValuesResponse {
    /// The field name
    pub field: String,
    /// Top values with counts
    pub values: Vec<FieldValueInfo>,
    /// Total count across all values
    pub total_count: u64,
}

/// Request for async field stats
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FieldStatsRequest {
    /// The piped query string
    pub query: String,
    /// Start of time range
    pub start: chrono::DateTime<chrono::Utc>,
    /// End of time range
    pub end: chrono::DateTime<chrono::Utc>,
}

/// Response for field stats
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FieldStatsResponse {
    /// Field information list
    pub fields: Vec<nanosiem_core::search::FieldInfo>,
    /// Total number of events in the time range
    pub total_events: u64,
}
