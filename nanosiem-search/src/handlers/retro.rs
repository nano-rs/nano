// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC retro-hunt companion endpoint (NAN-1580).
//!
//! The initial `/api/search` response for a `ioc=… | retro` query returns a
//! lightweight marker (via the command-page short-circuit) carrying the parsed
//! retro request. The frontend then calls this endpoint to fetch the heavy
//! rollup — summary / list / pivot — shaped by [`RetroResponse`].

use axum::{extract::State, Json};
use nanosiem_core::{
    auth::permissions,
    search::{AsyncSearchResponse, RetroRequest, RetroResponse},
};
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

/// A compact single-indicator hunt completes inline. Campaign and pivot hunts
/// return a durable job handle and publish their typed result to object storage.
/// On an enterprise-shared (lean) tenant every hunt is a durable job handle
/// whose result carries a moving retention-cutoff proof.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
#[serde(untagged)]
pub enum RetroResultResponse {
    Ready(RetroResponse),
    Queued(AsyncSearchResponse),
}

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
        (status = 200, description = "Ready retro rollup or durable job handle", body = RetroResultResponse),
        (status = 400, description = "Invalid retro query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission"),
        (status = 503, description = "The tenant's lean-cell job lane or retention identity is unavailable", body = ErrorResponse),
    )
)]
pub async fn retro(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<RetroRequest>,
) -> Result<(axum::http::HeaderMap, Json<RetroResultResponse>), SearchError> {
    use crate::cache::cache_status_headers;
    if !auth.claims.has_permission(permissions::SEARCH_EXECUTE) {
        return Err(SearchError::Forbidden(
            "Retro-hunt queries require the search:execute permission".to_string(),
        ));
    }

    // NAN-1801: compose the caller's effective source scope (per-user deny-set
    // ∪ audit gate) ONCE. The retro rollup is hand-built SQL over the logs
    // table that bypasses the nPL search path — the P1 injector never sees
    // these queries — so the scope is threaded into the service (every logs
    // scan ANDs the deny predicate) AND folded into the cache key below (a
    // scoped viewer must never read an unrestricted viewer's cached rollup,
    // and vice versa).
    let scope = super::search::effective_scope(&auth);
    // NAN-3086: an enterprise-shared request is served only by the caller's
    // own lean-lake cell view (never the process singleton), and its query is
    // held to the shared nPL contract on that view.
    let search = super::product_view_search(&state, &auth)?;
    super::require_shared_npl_contract_for_view(&auth, &request.query, None, &search)?;
    // A shared tenant's retro result carries a moving retention-cutoff proof
    // that is re-checked on every read of the job artifact. An inline rollup
    // has no proof, so shared requests neither read nor write the companion
    // cache: every shared retro is a durable job handle.
    let shared = crate::is_shared_scope(auth.tenant_scope);

    // NAN-1593: dedupe page refreshes / shared-link follows through the same
    // Dragonfly cache regular search uses. Without this, every load re-ran the
    // full environment-wide rollup (multi-second UNION scans + host denominator).
    // NAN-1595: skip the read on an explicit refresh (CacheBypass), and stamp
    // x-nano-cache hit/age so the UI can show "cached Ns ago · refresh".
    let cache_key = retro_cache_key(auth.tenant_scope, &request, &scope);
    if !bypass && !shared {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache
                .get_cached::<nanosiem_core::search::RetroResponse>(&cache_key)
                .await
            {
                record_search_query("retro_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                super::require_current_shared_authority(&state, &auth).await?;
                return Ok((
                    cache_status_headers(true, age),
                    Json(RetroResultResponse::Ready(cached)),
                ));
            }
        }
    }

    if let Some(job_id) = search
        .enqueue_durable_retro_view(
            &request,
            auth.claims.sub,
            &scope,
            auth.durable_search_authority().as_ref(),
        )
        .await?
    {
        record_search_query("retro_queued", 0.0, true);
        super::require_current_shared_authority(&state, &auth).await?;
        return Ok((
            cache_status_headers(false, None),
            Json(RetroResultResponse::Queued(AsyncSearchResponse {
                job_id,
                status: "queued".to_string(),
            })),
        ));
    }

    let start = Instant::now();
    let result = search.build_retro_view(request.clone(), &scope).await;
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    record_search_query("retro", duration_ms, result.is_ok());

    let response = result?;
    if !shared {
        if let Some(cache) = state.result_cache.as_ref() {
            let cache = cache.clone();
            let resp = response.clone();
            tokio::spawn(async move {
                cache.set_cached(&cache_key, &resp).await;
            });
        }
    }

    super::require_current_shared_authority(&state, &auth).await?;
    Ok((
        cache_status_headers(false, None),
        Json(RetroResultResponse::Ready(response)),
    ))
}

/// Deterministic cache key for a retro request. Excludes nothing that changes
/// the rollup; pagination (`offset`/`limit`) and `sort` shape list/pivot pages.
/// The viewer's effective `ScopeSet` is folded in (NAN-1801) — the scope
/// changes the executed SQL, so it is part of result identity.
fn retro_cache_key(
    tenant: nanosiem_core::search::SearchTenantScope,
    request: &RetroRequest,
    scope: &nanosiem_core::auth::ScopeSet,
) -> String {
    crate::cache::SearchResultCache::companion_key_for(
        tenant,
        "retro",
        &[
            request.query.as_bytes(),
            request
                .time_range
                .start
                .timestamp_micros()
                .to_string()
                .as_bytes(),
            request
                .time_range
                .end
                .timestamp_micros()
                .to_string()
                .as_bytes(),
            request.axis.as_bytes(),
            request.offset.unwrap_or(0).to_string().as_bytes(),
            request.limit.unwrap_or(0).to_string().as_bytes(),
            request.sort.as_deref().unwrap_or("").as_bytes(),
        ],
        scope,
    )
}

#[cfg(test)]
mod tenant_cache_key_tests {
    use super::*;
    use nanosiem_core::auth::ScopeSet;
    use nanosiem_core::search::SearchTenantScope;

    fn request() -> RetroRequest {
        let end = chrono::Utc::now();
        RetroRequest {
            query: "ioc=1.2.3.4 | retro".to_string(),
            time_range: nanosiem_core::search::TimeRangeInput { start: end - chrono::Duration::hours(1), end },
            axis: "indicator".to_string(),
            offset: None,
            limit: None,
            sort: None,
        }
    }

    /// NAN-2718: the retro rollup cache identity is tenant-pinned in the
    /// hosted shared profile and byte-identical to the historical dedicated
    /// key otherwise.
    #[cfg(feature = "enterprise")]
    #[test]
    fn retro_cache_key_is_tenant_pinned() {
        let request = request();
        let scope = ScopeSet::unrestricted();
        let tenant_a = SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(1));
        let tenant_b = SearchTenantScope::EnterpriseShared(uuid::Uuid::from_u128(2));
        assert_ne!(
            retro_cache_key(tenant_a, &request, &scope),
            retro_cache_key(tenant_b, &request, &scope)
        );
        assert_ne!(
            retro_cache_key(tenant_a, &request, &scope),
            retro_cache_key(SearchTenantScope::dedicated(), &request, &scope)
        );
        let dedicated = retro_cache_key(SearchTenantScope::dedicated(), &request, &scope);
        assert!(dedicated.starts_with("retro:"), "dedicated key shape changed: {dedicated}");
    }
}
