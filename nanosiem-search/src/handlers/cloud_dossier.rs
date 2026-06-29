// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud principal dossier endpoint — single aggregate for `| cloud principal=X`
//! (NAN-395). Returns identity + risk + facets + assume-role chain + timeline
//! + regions + top actions + top resources + auth posture + error rate +
//! event stream in a single round-trip. Structurally analogous to
//! `/api/search/asset-dossier`.

use axum::{extract::State, Json};
use nanosiem_core::search::CloudDossier;
use nanosiem_core::TimeRangeInput;
use serde::Deserialize;
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CloudDossierRequest {
    /// IAM principal id (user / role / service account)
    pub principal: String,
    /// Optional account scope (AWS account id / GCP project id)
    #[serde(default)]
    pub account: Option<String>,
    /// Optional provider scope ("aws", "gcp", "azure")
    #[serde(default)]
    pub provider: Option<String>,
    /// Optional facet filters — applied to every subquery so all sections
    /// narrow in lockstep when the user toggles a facet chip in the UI.
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub regions: Vec<String>,
    #[serde(default)]
    pub accounts: Vec<String>,
    #[serde(default)]
    pub resource_types: Vec<String>,
    #[serde(default)]
    pub change_types: Vec<String>,
    /// Time window the aggregates are evaluated against
    pub time_range: TimeRangeInput,
}

#[utoipa::path(
    post,
    path = "/api/search/cloud-dossier",
    tag = "search",
    request_body = CloudDossierRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Cloud principal dossier aggregates", body = CloudDossier),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_cloud_dossier(
    State(state): State<SearchState>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<CloudDossierRequest>,
) -> Result<(axum::http::HeaderMap, Json<CloudDossier>), SearchError> {
    // NAN-1593: the cloud principal dossier fires on every load / shared-link
    // follow and runs many parallel ClickHouse aggregates — cache it through
    // the same Dragonfly layer. Every narrowing facet vec is applied to each
    // subquery, so they all change the result and MUST be part of the key
    // alongside the principal / account / provider scope and the time range.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "cdossier",
        &[
            request.principal.as_bytes(),
            request.account.as_deref().unwrap_or("").as_bytes(),
            request.provider.as_deref().unwrap_or("").as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            serde_json::to_string(&request.services)
                .unwrap_or_default()
                .as_bytes(),
            serde_json::to_string(&request.regions)
                .unwrap_or_default()
                .as_bytes(),
            serde_json::to_string(&request.accounts)
                .unwrap_or_default()
                .as_bytes(),
            serde_json::to_string(&request.resource_types)
                .unwrap_or_default()
                .as_bytes(),
            serde_json::to_string(&request.change_types)
                .unwrap_or_default()
                .as_bytes(),
        ],
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<CloudDossier>(&cache_key).await {
                record_search_query("cloud_dossier_cached", 0.0, true);
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
        .query_cloud_dossier(
            &request.principal,
            request.account.as_deref(),
            request.provider.as_deref(),
            &nanosiem_core::search::CloudDossierFacetFilters {
                services: request.services,
                regions: request.regions,
                accounts: request.accounts,
                resource_types: request.resource_types,
                change_types: request.change_types,
            },
            &time_range,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("cloud_dossier", duration_ms, result.is_ok());

    let response = result.map_err(|e| {
        tracing::error!(error = %e, "Cloud dossier query failed");
        SearchError::QueryError("Failed to fetch cloud dossier".to_string())
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
