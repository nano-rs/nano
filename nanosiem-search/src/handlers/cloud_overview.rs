// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud overview endpoint — single aggregate for the redesigned `| cloud`
//! landing view (NAN-394).
//!
//! Returns org-wide header, accounts grid, risky principals, cross-account
//! timeline, anomaly feed (from `signals`), service health, and top sensitive
//! changes in a single round-trip. The frontend renders each section with a
//! loading / empty state, so partial failures degrade gracefully.

use axum::{extract::State, Json};
use nanosiem_core::auth::permissions;
use nanosiem_core::search::CloudOverview;
use nanosiem_core::TimeRangeInput;
use serde::Deserialize;
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

/// Request for the cloud overview aggregate
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CloudOverviewRequest {
    /// Optional provider filter ("aws", "gcp", "azure") — omit for all
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional account scope (AWS account id or GCP project id) — omit for all
    #[serde(default)]
    pub account: Option<String>,
    /// Time window the aggregates are evaluated against
    pub time_range: TimeRangeInput,
}

#[utoipa::path(
    post,
    path = "/api/search/cloud-overview",
    tag = "search",
    request_body = CloudOverviewRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Cloud overview aggregates", body = CloudOverview),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission"),
    )
)]
pub async fn get_cloud_overview(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<CloudOverviewRequest>,
) -> Result<(axum::http::HeaderMap, Json<CloudOverview>), SearchError> {
    // NAN-1801: this endpoint was bearer-only — it runs many hand-built
    // ClickHouse aggregates over logs/signals, so gate it like every other
    // search surface (mirrors /api/search/retro).
    if !auth.claims.has_permission(permissions::SEARCH_EXECUTE) {
        return Err(SearchError::Forbidden(
            "Cloud overview queries require the search:execute permission".to_string(),
        ));
    }

    // NAN-1801: compose the effective deny-set (per-user source scope ∪ audit
    // gate) ONCE, before the cache lookup — it changes the executed SQL, so it
    // is part of result identity and MUST be folded into the cache key.
    let scope = super::search::effective_scope(&auth);

    // NAN-1593: the cloud overview landing aggregate fires on every load /
    // shared-link follow and runs many parallel ClickHouse aggregates — cache
    // it through the same Dragonfly layer. Keyed on the provider / account
    // scope, the time range, and the caller's effective source scope.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "coverview",
        &[
            request.provider.as_deref().unwrap_or("").as_bytes(),
            request.account.as_deref().unwrap_or("").as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<CloudOverview>(&cache_key).await {
                record_search_query("cloud_overview_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let start = Instant::now();

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = state
        .search
        .query_cloud_overview(
            request.provider.as_deref(),
            request.account.as_deref(),
            &time_range,
            &scope,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("cloud_overview", duration_ms, result.is_ok());

    let response = result.map_err(|e| {
        tracing::error!(error = %e, "Cloud overview query failed");
        SearchError::QueryError("Failed to fetch cloud overview".to_string())
    })?;

    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
}
