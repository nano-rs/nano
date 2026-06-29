// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC retro-hunt companion endpoint (NAN-1580).
//!
//! The initial `/api/search` response for a `ioc=… | retro` query returns a
//! lightweight marker (via the command-page short-circuit) carrying the parsed
//! retro request. The frontend then calls this endpoint to fetch the heavy
//! rollup — summary / list / pivot — shaped by [`RetroResponse`].

use axum::{Json, extract::State};
use nanosiem_core::{auth::permissions, search::RetroRequest};
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

/// Run an IOC retro-hunt rollup
///
/// POST /api/search/retro
///
/// Companion to the `/api/search` retro marker: given the parsed nPL retro
/// query (`ioc=… | retro [by asset|user]`), computes the environment-wide
/// footprint rollup. The submode (summary / list / pivot) and axis are derived
/// from the query; pagination + sort apply to the list/pivot rollups.
#[utoipa::path(
    post,
    path = "/api/search/retro",
    tag = "search",
    request_body = RetroRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Retro-hunt rollup (summary, list, or pivot)", body = nanosiem_core::search::RetroResponse),
        (status = 400, description = "Invalid retro query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn retro(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    Json(request): Json<RetroRequest>,
) -> Result<Json<nanosiem_core::search::RetroResponse>, SearchError> {
    if !auth.claims.has_permission(permissions::SEARCH_EXECUTE) {
        return Err(SearchError::Forbidden(
            "Retro-hunt queries require the search:execute permission".to_string(),
        ));
    }

    // NAN-1593: dedupe page refreshes / shared-link follows through the same
    // Dragonfly cache regular search uses. Without this, every load re-ran the
    // full environment-wide rollup (multi-second UNION scans + host denominator).
    let cache_key = retro_cache_key(&request);
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache
            .get_cached::<nanosiem_core::search::RetroResponse>(&cache_key)
            .await
        {
            record_search_query("retro_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let start = Instant::now();
    let result = state.search.build_retro_view(request.clone()).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("retro", duration_ms, result.is_ok());

    let response = result?;
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

/// Deterministic cache key for a retro request. Excludes nothing that changes
/// the rollup; pagination (`offset`/`limit`) and `sort` shape list/pivot pages.
fn retro_cache_key(request: &RetroRequest) -> String {
    crate::cache::SearchResultCache::companion_key(
        "retro",
        &[
            request.query.as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.axis.as_bytes(),
            request.offset.unwrap_or(0).to_string().as_bytes(),
            request.limit.unwrap_or(0).to_string().as_bytes(),
            request.sort.as_deref().unwrap_or("").as_bytes(),
        ],
    )
}
