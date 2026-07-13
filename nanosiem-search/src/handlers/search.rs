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

async fn reserve_query_owner(
    state: &SearchState,
    request_id: String,
    user_id: uuid::Uuid,
) -> Result<(), SearchError> {
    match state.reserve_query_owner(&request_id, user_id).await {
        Ok(true) => {
            state.search.query_tracker().reserve_request(request_id, user_id);
            Ok(())
        }
        Ok(false) => Err(SearchError::BadRequest("request_id is already in use".to_string())),
        Err(error) => {
            tracing::warn!(%error, %request_id, "Shared query ownership unavailable; using local ownership");
            state.search.query_tracker().reserve_request(request_id, user_id);
            Ok(())
        }
    }
}

/// Compose the caller's EFFECTIVE source-scope deny-set (NAN-1799).
///
/// The per-user `denied_sources` resolved by the middleware (fail-closed —
/// a resolver outage 503s the request before it reaches any handler) is
/// unioned with the `audit` source unless the caller holds `audit:view`.
/// An empty result is the unrestricted scope, which generates byte-identical
/// SQL to the pre-scoping behavior for audit-view admins.
///
/// This REPLACES the old handler-level `enforce_non_audit_query` rewrite of
/// the nPL text: the `SearchService` now injects the exclusion from the
/// `ScopeSet` itself on every nPL path, so handlers pass the composed scope
/// instead of pre-mangling `request.query`. The same composed scope MUST be
/// folded into every cache key (see `cache.rs`) — the scope changes the
/// executed SQL, so it is part of result identity.
pub(crate) fn effective_scope(auth: &crate::AuthContext) -> nanosiem_core::auth::ScopeSet {
    let mut deny = auth.denied_sources.deny_set().clone();
    if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        deny.insert("audit".to_string());
    }
    nanosiem_core::auth::ScopeSet::from_denied(deny)
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
        (status = 409, description = "Query was cancelled (request_id was killed via DELETE /api/search/{request_id} or an admin cancel)", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn search(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<SearchRequest>,
) -> Result<(axum::http::HeaderMap, Json<SearchResultResponse>), SearchError> {
    use crate::cache::cache_status_headers;
    use nanosiem_core::search::QueryPriority;

    // NAN-1799: compose the effective deny-set (per-user source scope ∪ audit
    // gate) ONCE, before the cache lookup — the scope is folded into the cache
    // key, and the service injects the exclusion into the executed SQL. This
    // replaces the old H1 `enforce_non_audit_query` rewrite of request.query.
    let scope = effective_scope(&auth);

    if let Some(request_id) = request.request_id.clone() {
        reserve_query_owner(&state, request_id, auth.claims.sub).await?;
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
            .search_async_with_admission(request, user_id, priority, &scope)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to start async search");
                SearchError::QueryError("Failed to start search".to_string())
            })?;

        return Ok((
            cache_status_headers(false, None),
            Json(SearchResultResponse::Async(
                nanosiem_core::search::AsyncSearchResponse {
                    job_id,
                    status: "queued".to_string(),
                },
            )),
        ));
    }

    // Check search result cache (Dragonfly/Redis). NAN-1595: skip on refresh
    // bypass; stamp x-nano-cache hit/age so the UI can show the cached notice.
    // NAN-1799: the effective deny-set is folded into the cache key (computed
    // above, BEFORE this lookup) so differently-scoped users never share an
    // entry.
    if !bypass {
        if let Some(ref cache) = state.result_cache {
            if let Some(cached) = cache.get(&request, &scope).await {
                record_search_query("piped_cached", 0.0, true);
                let age = cache
                    .age_secs(&crate::cache::SearchResultCache::cache_key(&request, &scope))
                    .await;
                return Ok((
                    cache_status_headers(true, age),
                    Json(SearchResultResponse::Sync(cached)),
                ));
            }
        }
    }

    // Synchronous execution (cache miss). NAN-701: sync path now also goes
    // through the admission controller — previously it bypassed the
    // per-user limit / queue / timeout entirely, so dashboard panel
    // refreshes overshot `max_concurrent_queries_for_user`.
    let start = Instant::now();
    let result = state
        .search
        .search_with_admission(request.clone(), user_id, priority, &scope)
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("piped", duration_ms, result.is_ok());

    // Cache successful results in the background, keyed under the scope the
    // query executed with.
    if let Ok(ref response) = result {
        if let Some(ref cache) = state.result_cache {
            let cache = cache.clone();
            let req = request.clone();
            let scope_for_cache = scope.clone();
            let resp = response.clone();
            tokio::spawn(async move {
                cache.set(&req, &resp, &scope_for_cache).await;
            });
        }
    }

    Ok((
        cache_status_headers(false, None),
        Json(SearchResultResponse::Sync(result?)),
    ))
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
    if !can_admin_cancel {
        let local_owner = state.search.query_tracker().get(&request_id)
            .and_then(|info| info.owner_user_id);
        let owner = if local_owner.is_some() {
            local_owner
        } else {
            match state.shared_query_owner(&request_id).await {
                Ok(owner) => owner,
                Err(error) => {
                    tracing::warn!(%error, %request_id, "Shared query ownership unavailable during cancellation");
                    None
                }
            }
        };
        if owner != Some(auth.claims.sub) {
            return Ok(Json(CancelSearchResponse { cancelled: false }));
        }
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

    // NAN-1799 FAIL-CLOSED: raw SQL cannot be AST-injected with a per-source
    // exclusion, so the service refuses outright (SqlValidationError) when the
    // caller has ANY restricted source. We pass the SOURCE deny-set only —
    // the audit gate stays handler-injected above so callers whose only
    // restriction is the audit gate keep raw SQL working exactly as before.
    let start = Instant::now();
    let result = state.search.search_sql(request, &auth.denied_sources).await;
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
    /// Per-query dataset (`logs`/`spans`/`metrics`/`risk`) so the explained SQL
    /// matches the executed source — without it, Inspect SQL shows `FROM logs`
    /// for a spans/metrics/risk query (NAN-1569, NAN-1798).
    #[serde(default)]
    pub dataset: Option<String>,
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
    Json(request): Json<ExplainRequest>,
) -> Result<Json<ExplainResponse>, SearchError> {
    // NAN-1799: pass the composed scope so "Inspect SQL" renders the exact
    // gated SQL the executed path runs for this caller.
    let scope = effective_scope(&auth);
    let start = Instant::now();
    let result = state
        .search
        .explain(
            &request.query,
            &request.time_range,
            request.table_view,
            request.dataset.as_deref(),
            &scope,
        )
        .await;
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
    // NAN-694 / NAN-1799: callers must not retrieve denied rows by direct id —
    // audit (without audit:view) or any source-scope-denied source_type. The
    // composed ScopeSet is applied at the SQL layer to match the rest of the
    // search surface.
    let scope = effective_scope(&auth);

    let start = Instant::now();
    let result = state
        .search
        .fetch_log_by_id(
            &request.id,
            request.time_range.as_ref(),
            request.source_type.as_deref(),
            &scope,
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
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<SearchRequest>,
) -> Result<(axum::http::HeaderMap, Json<PrevalenceScatterData>), SearchError> {
    // NAN-1799: the service injects the composed deny-set into the nPL path
    // itself — no more pre-rewrite of request.query here.
    let scope = effective_scope(&auth);

    // NAN-1593: the prevalence-artifacts scatter fires on every search-page
    // load / shared-link follow, separately from the main search — cache it
    // through the same Dragonfly layer so reloads don't re-extract artifacts
    // and re-run their prevalence lookups. Keyed on the raw `query` plus the
    // time range and dataset, with the caller's effective deny-set folded in
    // by `companion_key` (NAN-1799 — the scope changes the executed SQL, so
    // it is part of result identity); `request_id` is excluded since it's a
    // per-request cancellation handle, not part of result identity.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "prevart",
        &[
            request.query.as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<PrevalenceScatterData>(&cache_key).await {
                record_search_query("prevalence_artifacts_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let start = Instant::now();
    let result = state.search.get_prevalence_artifacts(&request, &scope).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("prevalence_artifacts", duration_ms, result.is_ok());

    match &result {
        Ok(_) => tracing::info!("Prevalence artifacts completed in {:.2}ms", duration_ms),
        Err(e) => tracing::error!("Prevalence artifacts failed: {:?}", e),
    }

    let response = result?;
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
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
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<FieldStatsRequest>,
) -> Result<(axum::http::HeaderMap, Json<FieldStatsResponse>), SearchError> {
    use nanosiem_core::search::QueryPriority;

    // NAN-1799: the service injects the composed deny-set into the nPL path
    // itself — no more pre-rewrite of the query here.
    let scope = effective_scope(&auth);
    let query = request.query.clone();

    let time_range = TimeRangeInput {
        start: request.start,
        end: request.end,
    };

    // NAN-1593: the field-stats panel fires on every search-page load and
    // shared-link follow, separately from the main search — cache it through
    // the same Dragonfly layer so reloads don't re-run the aggregation. Keyed
    // on the raw `query` plus the time range / column subset / dataset, with
    // the caller's effective deny-set folded in by `companion_key` (NAN-1799);
    // `request_id` is excluded since it's a per-request cancellation handle,
    // not part of result identity.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "fstats",
        &[
            query.as_bytes(),
            request.start.timestamp_micros().to_string().as_bytes(),
            request.end.timestamp_micros().to_string().as_bytes(),
            // JSON-encode (not join) so a comma in a column name can't shift the
            // boundary — ["a,b"] must not collide with ["a","b"] (NAN-1593 review).
            serde_json::to_string(&request.columns).unwrap_or_default().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<FieldStatsResponse>(&cache_key).await {
                record_search_query("field_stats_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    // NAN-1428: reserve ownership of the request_id so the cancel endpoint
    // can authorize killing the derived `{request_id}-fstats` query even
    // after the main search has completed and unregistered the id.
    if let Some(rid) = request.request_id.clone() {
        reserve_query_owner(&state, rid, auth.claims.sub).await?;
    }

    // NAN-1427: admission-gated, with the derived companion query_id and
    // per-priority CH settings. `columns` (when sent by the UI) reduces the
    // stat'd column set to what the field panel actually renders.
    let fields = state
        .search
        .get_field_stats_with_admission(
            &query,
            &time_range,
            request.columns.as_deref(),
            request.request_id.as_deref(),
            auth.claims.sub,
            QueryPriority::Interactive,
            request.dataset.as_deref(),
            &scope,
        )
        .await?;
    let total_events = fields.iter().map(|f| f.count).max().unwrap_or(0);

    let response = FieldStatsResponse {
        fields,
        total_events,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
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
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<FieldValuesRequest>,
) -> Result<(axum::http::HeaderMap, Json<FieldValuesResponse>), SearchError> {
    let start = Instant::now();

    // NAN-1799: the service injects the composed deny-set into the nPL path
    // itself — no more pre-rewrite of the query here.
    let scope = effective_scope(&auth);
    let query = request.query.clone();

    let time_range = TimeRangeInput {
        start: request.start,
        end: request.end,
    };

    // NAN-1593: drill-in field values are re-requested whenever the user
    // re-expands a field, and re-fetched on shared-link follow — cache them
    // through the same Dragonfly layer. Keyed on the raw `query` plus the
    // field, time range, limit, and dataset, with the caller's effective
    // deny-set folded in by `companion_key` (NAN-1799).
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "fvalues",
        &[
            request.field.as_bytes(),
            query.as_bytes(),
            request.start.timestamp_micros().to_string().as_bytes(),
            request.end.timestamp_micros().to_string().as_bytes(),
            request.limit.to_string().as_bytes(),
            request.dataset.as_deref().unwrap_or("logs").as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<FieldValuesResponse>(&cache_key).await {
                record_search_query("field_values_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let result = state
        .search
        .get_field_values(
            &request.field,
            &query,
            &time_range,
            request.limit,
            request.dataset.as_deref(),
            &scope,
        )
        .await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("field_values", duration_ms, result.is_ok());

    let values = result?;
    let total_count: u64 = values.iter().map(|v| v.count).sum();

    let response = FieldValuesResponse {
        field: request.field,
        values,
        total_count,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
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
    /// Per-query dataset selector (NAN-1559): `logs` (default), `spans`,
    /// `metrics`, or `risk`. Drill-in must resolve the field and base source
    /// against the same dataset the search targeted, else a spans/metrics/risk
    /// field reads the UDM `logs` table and returns nothing.
    #[serde(default)]
    pub dataset: Option<String>,
}

fn default_field_values_limit() -> usize {
    100
}

/// Response for field values
#[derive(Debug, Clone, Serialize, serde::Deserialize, utoipa::ToSchema)]
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
    /// Client request id of the originating search (NAN-1428). When set, the
    /// field-stats query runs under the derived ClickHouse query_id
    /// `{request_id}-fstats`, so `DELETE /api/search/{request_id}` cancels it
    /// together with the data query.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Optional column subset to compute stats for (NAN-1427). The stats
    /// query's I/O scales with the number of columns aggregated, so callers
    /// should send only the columns they render. Names are intersected with
    /// the live table inventory (unknown names dropped; an empty intersection
    /// falls back to the full set). Omit for the full column inventory.
    #[serde(default)]
    pub columns: Option<Vec<String>>,
    /// Per-query dataset selector (NAN-1559): `logs` (default), `spans`,
    /// `metrics`, or `risk`. The companion enumerates the dataset's columns and
    /// wraps the dataset's base SQL — without it a spans/metrics search's field
    /// panel runs the UDM column list against `otel_spans` and ClickHouse 47's.
    #[serde(default)]
    pub dataset: Option<String>,
}

/// Response for field stats
#[derive(Debug, Clone, Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct FieldStatsResponse {
    /// Field information list
    pub fields: Vec<nanosiem_core::search::FieldInfo>,
    /// Total number of events in the time range
    pub total_events: u64,
}
