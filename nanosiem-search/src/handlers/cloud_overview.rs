// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cloud overview endpoint — single aggregate for the redesigned `| cloud`
//! landing view (NAN-394).
//!
//! Returns org-wide header, accounts grid, risky principals, cross-account
//! timeline, anomaly feed (from `signals`), service health, and top sensitive
//! changes in a single round-trip. The frontend renders each section with a
//! loading / empty state, so partial failures degrade gracefully.

use axum::{extract::State, Json};
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
    )
)]
pub async fn get_cloud_overview(
    State(state): State<SearchState>,
    Json(request): Json<CloudOverviewRequest>,
) -> Result<Json<CloudOverview>, SearchError> {
    let start = Instant::now();

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = state
        .search
        .query_cloud_overview(
            request.provider.as_deref(),
            request.account.as_deref(),
            &time_range,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("cloud_overview", duration_ms, result.is_ok());

    let overview = result.map_err(|e| {
        tracing::error!(error = %e, "Cloud overview query failed");
        SearchError::QueryError("Failed to fetch cloud overview".to_string())
    })?;

    Ok(Json(overview))
}
