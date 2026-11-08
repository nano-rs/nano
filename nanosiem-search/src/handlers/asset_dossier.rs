// SPDX-License-Identifier: AGPL-3.0-or-later

//! Asset dossier endpoint — single aggregate for the redesigned Asset view.
//!
//! Returns identity + timeline + processes + network + auth + files + dns in
//! one round-trip. Alerts come from `entity_context` (nanosiem-api) and
//! prevalence dots from `asset-artifacts` — both are fetched lazily alongside
//! this endpoint by the frontend.

use axum::{extract::State, Json};
use nanosiem_core::search::AssetDossier;
use nanosiem_core::TimeRangeInput;
use serde::Deserialize;
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

/// Request for the asset dossier aggregate
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetDossierRequest {
    /// Identifier field (e.g., "src_host", "src_ip", "user")
    pub identifier_field: String,
    /// Identifier value (e.g., "WIN-HR11")
    pub identifier_value: String,
    /// Resolved identities from the initial asset query (may be empty)
    #[serde(default)]
    pub identities: Vec<serde_json::Value>,
    /// Time range for the aggregates
    pub time_range: TimeRangeInput,
}

/// Build the entity dossier for the redesigned Asset view.
///
/// Runs identity, timeline, and section-card aggregates (processes, network,
/// auth, files, dns) in parallel against ClickHouse.
#[utoipa::path(
    post,
    path = "/api/search/asset-dossier",
    tag = "search",
    request_body = AssetDossierRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Asset dossier aggregates", body = AssetDossier),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn get_asset_dossier(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<AssetDossierRequest>,
) -> Result<(axum::http::HeaderMap, Json<AssetDossier>), SearchError> {
    // NAN-1801: this endpoint was bearer-only — it runs hand-built aggregates
    // over the logs table, so it needs the same execute gate as /api/search.
    if !auth
        .claims
        .has_permission(nanosiem_core::auth::permissions::SEARCH_EXECUTE)
    {
        return Err(SearchError::Forbidden(
            "Asset dossier queries require the search:execute permission".to_string(),
        ));
    }

    // NAN-1801: compose the caller's effective source-scope deny-set once —
    // it is ANDed into every dossier aggregate by the service AND folded into
    // the cache key below (the scope changes the executed SQL, so it is part
    // of result identity; two users with different scopes must not share a
    // cached dossier).
    let scope = super::search::effective_scope(&auth);

    // NAN-1593: the asset dossier fires on every Asset-view load / shared-link
    // follow and runs 8 parallel ClickHouse aggregates — cache it through the
    // same Dragonfly layer so reloads return instantly. Keyed on the
    // identifier, the resolved identities (they widen the match set), the
    // time range, and the caller's effective scope.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "adossier",
        &[
            request.identifier_field.as_bytes(),
            request.identifier_value.as_bytes(),
            serde_json::to_string(&request.identities)
                .unwrap_or_default()
                .as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<AssetDossier>(&cache_key).await {
                record_search_query("asset_dossier_cached", 0.0, true);
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
        .query_asset_dossier(
            &request.identifier_field,
            &request.identifier_value,
            &request.identities,
            &time_range,
            &scope,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("asset_dossier", duration_ms, result.is_ok());

    let response = result.map_err(|e| {
        tracing::error!(error = %e, "Asset dossier query failed");
        SearchError::QueryError("Failed to fetch asset dossier".to_string())
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
