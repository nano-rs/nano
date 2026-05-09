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
    )
)]
pub async fn get_asset_dossier(
    State(state): State<SearchState>,
    Json(request): Json<AssetDossierRequest>,
) -> Result<Json<AssetDossier>, SearchError> {
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
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("asset_dossier", duration_ms, result.is_ok());

    let dossier = result.map_err(|e| {
        tracing::error!(error = %e, "Asset dossier query failed");
        SearchError::QueryError("Failed to fetch asset dossier".to_string())
    })?;

    Ok(Json(dossier))
}
