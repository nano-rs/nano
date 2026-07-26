// SPDX-License-Identifier: AGPL-3.0-or-later

//! Asset and cloud event endpoints: pagination, timeline, pivot, time range, artifacts.

use axum::{Json, extract::State};
use nanosiem_core::TimeRangeInput;
use serde::{Deserialize, Serialize};
use std::time::Instant;

// NAN-2030: asset/cloud reads hit the same log surface as POST /api/search, so
// they share the one gate defined in `handlers/mod.rs` (was a local duplicate).
use super::require_search_execute;
use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

// ============================================================================
// Asset Events Pagination
// ============================================================================

/// Request for fetching paginated asset events
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetEventsRequest {
    /// Identifier field (e.g., "src_host", "src_ip")
    pub identifier_field: String,
    /// Identifier value (e.g., "workstation-01.corp.local")
    pub identifier_value: String,
    /// Resolved identities from the initial asset query
    pub identities: Vec<serde_json::Value>,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Offset for pagination
    #[serde(default)]
    pub offset: usize,
    /// Limit for pagination (default 500)
    #[serde(default = "default_asset_limit")]
    pub limit: usize,
    /// Optional filters
    #[serde(default)]
    pub filters: Option<nanosiem_core::search::AssetEventFilters>,
}

fn default_asset_limit() -> usize {
    500
}

/// Response for paginated asset events
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetEventsResponse {
    /// The events for this page
    pub events: Vec<serde_json::Value>,
    /// Total count of matching events
    pub total_count: u64,
    /// Facet counts for filtering UI
    pub facets: nanosiem_core::search::AssetFacets,
    /// Current offset
    pub offset: usize,
    /// Page size limit
    pub limit: usize,
    /// Whether more events are available
    pub has_more: bool,
}

/// Fetch paginated asset events
///
/// Used for infinite scroll and server-side filtering in the asset view.
/// Returns a page of events plus facet counts for filtering.
#[utoipa::path(
    post,
    path = "/api/search/asset-events",
    tag = "search",
    request_body = AssetEventsRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Paginated asset events with facets", body = AssetEventsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_asset_events(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<AssetEventsRequest>,
) -> Result<(axum::http::HeaderMap, Json<AssetEventsResponse>), SearchError> {
    let start = Instant::now();
    require_search_execute(&auth)?;

    // NAN-1801: the caller's effective source scope changes the executed SQL,
    // so it is part of result identity — fold it into the cache key.
    let scope = super::search::effective_scope(&auth);
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "aevents",
        &[
            request.identifier_field.as_bytes(),
            request.identifier_value.as_bytes(),
            serde_json::to_string(&request.identities)
                .unwrap_or_default()
                .as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.offset.to_string().as_bytes(),
            request.limit.to_string().as_bytes(),
            serde_json::to_string(&request.filters)
                .unwrap_or_default()
                .as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<AssetEventsResponse>(&cache_key).await {
                record_search_query("asset_events_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    // Convert TimeRangeInput to TimeRange (the internal type)
    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = state
        .search
        .query_asset_events_paginated(
            &request.identifier_field,
            &request.identifier_value,
            &request.identities,
            &time_range,
            request.offset,
            request.limit,
            request.filters.as_ref(),
            &scope,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("asset_events", duration_ms, result.is_ok());

    let (events, total_count, facets) = result.map_err(|e| {
        tracing::error!(error = %e, "Asset events query failed");
        SearchError::QueryError("Failed to fetch asset events".to_string())
    })?;

    let has_more = request.offset + events.len() < total_count as usize;

    let response = AssetEventsResponse {
        events,
        total_count,
        facets,
        offset: request.offset,
        limit: request.limit,
        has_more,
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

// ============================================================================
// Cloud Events Pagination
// ============================================================================

/// Request for fetching paginated cloud events
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CloudEventsRequest {
    /// The original nPL query string (from _cloud_query in initial results)
    pub query: String,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Offset for pagination
    #[serde(default)]
    pub offset: usize,
    /// Limit for pagination (default 200)
    #[serde(default = "default_cloud_limit")]
    pub limit: usize,
    /// Optional filters
    #[serde(default)]
    pub filters: Option<nanosiem_core::search::CloudEventFilters>,
}

fn default_cloud_limit() -> usize {
    200
}

/// Response for paginated cloud events
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudEventsResponse {
    /// The events for this page
    pub events: Vec<serde_json::Value>,
    /// Total count of matching events
    pub total_count: u64,
    /// Facet counts for filtering UI
    pub facets: nanosiem_core::search::CloudFacets,
    /// Current offset
    pub offset: usize,
    /// Page size limit
    pub limit: usize,
    /// Whether more events are available
    pub has_more: bool,
    /// Filtered resources (only present when offset=0 and filters active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<serde_json::Value>>,
    /// Filtered user activity (only present when offset=0 and filters active)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_activity: Option<Vec<nanosiem_core::search::CloudUserActivity>>,
}

/// Fetch paginated cloud events
///
/// Used for infinite scroll and server-side filtering in the cloud view.
/// Returns a page of events plus facet counts for filtering.
#[utoipa::path(
    post,
    path = "/api/search/cloud-events",
    tag = "search",
    request_body = CloudEventsRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Paginated cloud events with facets", body = CloudEventsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_cloud_events(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<CloudEventsRequest>,
) -> Result<(axum::http::HeaderMap, Json<CloudEventsResponse>), SearchError> {
    let start = Instant::now();
    require_search_execute(&auth)?;

    let scope = super::search::effective_scope(&auth);
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "cevents",
        &[
            request.query.as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.offset.to_string().as_bytes(),
            request.limit.to_string().as_bytes(),
            serde_json::to_string(&request.filters)
                .unwrap_or_default()
                .as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache.get_cached::<CloudEventsResponse>(&cache_key).await {
                record_search_query("cloud_events_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = state
        .search
        .query_cloud_events_paginated(
            &request.query,
            &time_range,
            request.offset,
            request.limit,
            request.filters.as_ref(),
            &scope,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("cloud_events", duration_ms, result.is_ok());

    let (events, total_count, facets, resources, user_activity) = result.map_err(|e| {
        tracing::error!(error = %e, "Cloud events query failed");
        SearchError::QueryError("Failed to fetch cloud events".to_string())
    })?;

    let has_more = request.offset + events.len() < total_count as usize;

    let response = CloudEventsResponse {
        events,
        total_count,
        facets,
        offset: request.offset,
        limit: request.limit,
        has_more,
        resources,
        user_activity,
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

// ============================================================================
// Cloud User Timeline
// ============================================================================

/// Request for fetching a cloud user's activity timeline
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CloudUserTimelineRequest {
    /// The original nPL query string
    pub query: String,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// The user to get timeline for
    pub user: String,
}

/// Response for cloud user timeline
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudUserTimelineResponse {
    /// Chronological events for this user
    pub events: Vec<serde_json::Value>,
    /// Session summary with risk indicators
    pub summary: nanosiem_core::search::CloudUserSessionSummary,
}

/// Get a cloud user's activity timeline
///
/// Returns chronological events and a session summary with risk indicators
/// for a single user within the given query context.
#[utoipa::path(
    post,
    path = "/api/search/cloud-user-timeline",
    tag = "search",
    request_body = CloudUserTimelineRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "User activity timeline with session summary", body = CloudUserTimelineResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_cloud_user_timeline(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<CloudUserTimelineRequest>,
) -> Result<(axum::http::HeaderMap, Json<CloudUserTimelineResponse>), SearchError> {
    let start = Instant::now();
    require_search_execute(&auth)?;

    let scope = super::search::effective_scope(&auth);
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "cusertl",
        &[
            request.query.as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.user.as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache
                .get_cached::<CloudUserTimelineResponse>(&cache_key)
                .await
            {
                record_search_query("cloud_user_timeline_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = state
        .search
        .query_cloud_user_timeline(&request.query, &time_range, &request.user, &scope)
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("cloud_user_timeline", duration_ms, result.is_ok());

    let (events, summary) = result.map_err(|e| {
        tracing::error!(error = %e, "Cloud user timeline query failed");
        SearchError::QueryError("Failed to fetch cloud user timeline".to_string())
    })?;

    let response = CloudUserTimelineResponse { events, summary };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }
    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
}

// ============================================================================
// Cloud Entity Pivot
// ============================================================================

/// Request for fetching entity cross-references
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CloudEntityPivotRequest {
    /// The original nPL query string
    pub query: String,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Entity type: "user", "ip", or "resource"
    pub entity_type: String,
    /// Entity value to pivot on
    pub entity_value: String,
}

/// Response for entity pivot
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CloudEntityPivotResponse {
    /// Chronological events involving this entity
    pub events: Vec<serde_json::Value>,
    /// Cross-referenced related entities
    pub cross_references: Vec<nanosiem_core::search::EntityCrossReference>,
    /// Entity summary (event_count, fail_count, first/last seen, change_types, services)
    pub entity_summary: serde_json::Value,
}

/// Get entity cross-references (pivot from user/IP/resource)
///
/// Returns events for the entity, cross-referenced related entities,
/// and a summary. Enables chaining pivots in the investigation UI.
#[utoipa::path(
    post,
    path = "/api/search/cloud-entity-pivot",
    tag = "search",
    request_body = CloudEntityPivotRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Entity pivot with cross-references", body = CloudEntityPivotResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_cloud_entity_pivot(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<CloudEntityPivotRequest>,
) -> Result<(axum::http::HeaderMap, Json<CloudEntityPivotResponse>), SearchError> {
    let start = Instant::now();
    require_search_execute(&auth)?;

    let scope = super::search::effective_scope(&auth);
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "centity",
        &[
            request.query.as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.entity_type.as_bytes(),
            request.entity_value.as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache
                .get_cached::<CloudEntityPivotResponse>(&cache_key)
                .await
            {
                record_search_query("cloud_entity_pivot_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    let result = state
        .search
        .query_cloud_entity_pivot(
            &request.query,
            &time_range,
            &request.entity_type,
            &request.entity_value,
            &scope,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("cloud_entity_pivot", duration_ms, result.is_ok());

    let (events, cross_references, entity_summary) = result.map_err(|e| {
        tracing::error!(error = %e, "Cloud entity pivot query failed");
        SearchError::QueryError("Failed to fetch entity pivot".to_string())
    })?;

    let response = CloudEntityPivotResponse {
        events,
        cross_references,
        entity_summary,
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

// ============================================================================
// Asset True Time Range (lazy-loaded)
// ============================================================================

/// Request for fetching the true first/last seen timestamps for an asset
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetTrueTimeRangeRequest {
    /// Identifier field (e.g., "src_host", "src_ip")
    pub identifier_field: String,
    /// Identifier value (e.g., "workstation-01.corp.local")
    pub identifier_value: String,
    /// Resolved identities from the initial asset query
    pub identities: Vec<serde_json::Value>,
}

/// Response with first/last seen timestamps
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetTrueTimeRangeResponse {
    /// First event timestamp for this asset (across all time)
    pub first_seen: Option<String>,
    /// Last event timestamp for this asset (across all time)
    pub last_seen: Option<String>,
}

/// Fetch the true first/last seen time range for an asset
///
/// This is a potentially slow query that scans all partitions, so it is
/// separated from the main asset view to avoid blocking initial page load.
#[utoipa::path(
    post,
    path = "/api/search/asset-true-time-range",
    tag = "search",
    request_body = AssetTrueTimeRangeRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "True time range for the asset", body = AssetTrueTimeRangeResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_asset_true_time_range(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<AssetTrueTimeRangeRequest>,
) -> Result<(axum::http::HeaderMap, Json<AssetTrueTimeRangeResponse>), SearchError> {
    let start = Instant::now();
    require_search_execute(&auth)?;

    // NAN-2072: the aggregate fast path is safe only for an unrestricted
    // caller. Restricted callers are routed by the service to a scoped raw
    // scan, so the effective scope is both execution input and cache identity.
    let scope = super::search::effective_scope(&auth);
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "atruerange",
        &[
            request.identifier_field.as_bytes(),
            request.identifier_value.as_bytes(),
            serde_json::to_string(&request.identities)
                .unwrap_or_default()
                .as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache
                .get_cached::<AssetTrueTimeRangeResponse>(&cache_key)
                .await
            {
                record_search_query("asset_true_time_range_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let (first_seen, last_seen) = state
        .search
        .query_asset_true_time_range(
            &request.identifier_field,
            &request.identifier_value,
            &request.identities,
            &scope,
        )
        .await?;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("asset_true_time_range", duration_ms, true);

    let response = AssetTrueTimeRangeResponse {
        first_seen,
        last_seen,
    };
    // NAN-1593: a transient ClickHouse failure now propagates as an error from
    // `query_asset_true_time_range` (it no longer collapses into (None, None)),
    // so the `?` above means only a genuine, successful result reaches here and
    // a (None, None) legitimately means "never seen" — safe to cache like any
    // other empty-but-complete companion result.
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }
    Ok((crate::cache::cache_status_headers(false, None), Json(response)))
}

// ============================================================================
// Asset Artifacts (async, for prevalence scatter in asset mode)
// ============================================================================

/// Request for fetching artifact occurrences with server-side prevalence filtering
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssetArtifactsRequest {
    /// Identifier field (e.g., "src_host", "src_ip")
    pub identifier_field: String,
    /// Identifier value (e.g., "workstation-01.corp.local")
    pub identifier_value: String,
    /// Resolved identities from the initial asset query
    pub identities: Vec<serde_json::Value>,
    /// Time range for the search
    pub time_range: TimeRangeInput,
    /// Max host count filter (only return artifacts seen on <= this many hosts, default 100)
    #[serde(default = "default_max_host_count")]
    pub max_host_count: u64,
    /// Prevalence time window: "1h", "24h", "7d", "30d" (default "24h")
    #[serde(default = "default_prevalence_window")]
    pub prevalence_window: String,
}

fn default_max_host_count() -> u64 {
    100
}

fn default_prevalence_window() -> String {
    "24h".to_string()
}

/// A single artifact occurrence with its event timestamp
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactOccurrence {
    /// The artifact value (hash or domain)
    pub artifact: String,
    /// Event timestamp where this artifact appeared
    pub timestamp: String,
}

/// Prevalence info for a unique artifact
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactPrevalence {
    /// The artifact value
    pub artifact: String,
    /// Number of unique hosts that have seen this artifact
    pub host_count: u64,
    /// Whether this is below the rarity threshold
    pub is_rare: bool,
    /// Prevalence score (0-100)
    pub prevalence_score: u8,
    /// Total occurrences across the environment
    pub total_occurrences: u64,
    /// First seen in the environment
    pub first_seen: String,
}

/// Response with per-event occurrences and prevalence metadata
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AssetArtifactsResponse {
    /// Hash occurrences (one per event, filtered by max_host_count)
    pub hashes: Vec<ArtifactOccurrence>,
    /// Domain occurrences (one per event, filtered by max_host_count)
    pub domains: Vec<ArtifactOccurrence>,
    /// Prevalence data for ALL unique hashes (unfiltered — enables slider range calculation)
    pub hash_prevalence: Vec<ArtifactPrevalence>,
    /// Prevalence data for ALL unique domains (unfiltered)
    pub domain_prevalence: Vec<ArtifactPrevalence>,
    /// The rarity threshold from prevalence settings
    pub rarity_threshold: u64,
}

/// Fetch per-event artifact occurrences with server-side prevalence filtering
///
/// 1. Gets unique artifacts from the asset's events
/// 2. Looks up prevalence (host_count) for each
/// 3. Filters to artifacts with host_count <= max_host_count
/// 4. Returns per-event occurrences for only those artifacts + prevalence metadata
///
/// The default max_host_count=100 focuses on rare/uncommon artifacts on first load.
/// Analysts can drag the slider up to include more common artifacts.
#[utoipa::path(
    post,
    path = "/api/search/asset-artifacts",
    tag = "search",
    request_body = AssetArtifactsRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Per-event artifact occurrences with prevalence data", body = AssetArtifactsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_asset_artifacts(
    State(state): State<SearchState>,
    axum::extract::Extension(auth): axum::extract::Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<AssetArtifactsRequest>,
) -> Result<(axum::http::HeaderMap, Json<AssetArtifactsResponse>), SearchError> {
    let start = Instant::now();
    require_search_execute(&auth)?;

    let scope = super::search::effective_scope(&auth);
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "aartifacts",
        &[
            request.identifier_field.as_bytes(),
            request.identifier_value.as_bytes(),
            serde_json::to_string(&request.identities)
                .unwrap_or_default()
                .as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.max_host_count.to_string().as_bytes(),
            request.prevalence_window.as_bytes(),
        ],
        &scope,
    );
    if !bypass {
        if let Some(cache) = state.result_cache.as_ref() {
            if let Some(cached) = cache
                .get_cached::<AssetArtifactsResponse>(&cache_key)
                .await
            {
                record_search_query("asset_artifacts_cached", 0.0, true);
                let age = cache.age_secs(&cache_key).await;
                return Ok((crate::cache::cache_status_headers(true, age), Json(cached)));
            }
        }
    }

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);

    // Step 1: Get unique artifacts with pre-computed prevalence from event enrichment
    let summary = state
        .search
        .query_asset_artifact_summary(
            &request.identifier_field,
            &request.identifier_value,
            &request.identities,
            &time_range,
            &scope,
        )
        .await?;

    let rarity_threshold = state.prevalence.get_config().await.rarity_threshold;

    // Parse summary into (artifact, host_count) pairs
    struct ArtifactSummary {
        artifact: String,
        host_count: u64,
        first_seen: String,
    }
    let parse_summaries = |key: &str| -> Vec<ArtifactSummary> {
        summary
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        Some(ArtifactSummary {
                            artifact: v.get("artifact")?.as_str()?.to_string(),
                            // Handle sentinel values from dictGetOrDefault:
                            // 9999 = common/well-known (>1000 hosts, not in rare-domain dict) → keep as-is
                            // 65535 = N/A (UInt16 max, no prevalence data at all) → treat as unknown
                            host_count: match v.get("host_count")?.as_u64().unwrap_or(0) {
                                65535 => 0,
                                v => v,
                            },
                            first_seen: v.get("first_ts")?.as_str().unwrap_or_default().to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let hash_summaries = parse_summaries("hashes");
    let domain_summaries = parse_summaries("domains");

    if hash_summaries.is_empty() && domain_summaries.is_empty() {
        return Ok((
            crate::cache::cache_status_headers(false, None),
            Json(AssetArtifactsResponse {
                hashes: vec![],
                domains: vec![],
                hash_prevalence: vec![],
                domain_prevalence: vec![],
                rarity_threshold: 0,
            }),
        ));
    }

    // Step 2: Build prevalence from pre-computed values (no agg table round-trip)
    let build_prevalence = |summaries: &[ArtifactSummary]| -> Vec<ArtifactPrevalence> {
        summaries
            .iter()
            .map(|s| {
                let score = if s.host_count == 0 {
                    0
                } else {
                    (s.host_count.min(100)) as u8
                };
                ArtifactPrevalence {
                    artifact: s.artifact.clone(),
                    host_count: s.host_count,
                    // Match core's strict `<` rarity boundary (prevalence
                    // repository is_rare uses `host_count < rarity_threshold`).
                    // `<=` here over-counted: at rarity_threshold=3 it flagged an
                    // artifact seen on exactly 3 hosts as rare while core did not.
                    is_rare: s.host_count < rarity_threshold,
                    prevalence_score: score,
                    total_occurrences: 0, // per-asset occurrences filled in Step 4
                    first_seen: s.first_seen.clone(),
                }
            })
            .collect()
    };

    let all_hash_prevalence = build_prevalence(&hash_summaries);
    let all_domain_prevalence = build_prevalence(&domain_summaries);

    // Step 3: Filter to artifacts within max_host_count threshold
    let hash_filter: Vec<String> = hash_summaries
        .iter()
        .filter(|s| s.host_count <= request.max_host_count)
        .map(|s| s.artifact.clone())
        .collect();
    let domain_filter: Vec<String> = domain_summaries
        .iter()
        .filter(|s| s.host_count <= request.max_host_count)
        .map(|s| s.artifact.clone())
        .collect();

    // Step 4: Fetch per-event occurrences for only the filtered artifacts
    let raw = state
        .search
        .query_asset_artifact_occurrences(
            &request.identifier_field,
            &request.identifier_value,
            &request.identities,
            &time_range,
            Some(&hash_filter),
            Some(&domain_filter),
            &scope,
        )
        .await?;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("asset_artifacts", duration_ms, true);

    let hashes: Vec<ArtifactOccurrence> = raw
        .get("hashes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(ArtifactOccurrence {
                        artifact: v.get("artifact")?.as_str()?.to_string(),
                        timestamp: v.get("timestamp")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let domains: Vec<ArtifactOccurrence> = raw
        .get("domains")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(ArtifactOccurrence {
                        artifact: v.get("artifact")?.as_str()?.to_string(),
                        timestamp: v.get("timestamp")?.as_str()?.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    tracing::info!(
        "Asset artifacts: {} hash occurrences ({} unique), {} domain occurrences ({} unique), max_host_count={}",
        hashes.len(),
        hash_filter.len(),
        domains.len(),
        domain_filter.len(),
        request.max_host_count,
    );

    let response = AssetArtifactsResponse {
        hashes,
        domains,
        hash_prevalence: all_hash_prevalence,
        domain_prevalence: all_domain_prevalence,
        rarity_threshold: rarity_threshold,
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

#[cfg(test)]
mod true_time_range_scope_tests {
    use nanosiem_core::auth::{
        permissions::{AUDIT_VIEW, SEARCH_EXECUTE},
        types::TokenClaims,
        ApiKeyInfo, ScopeSet,
    };
    use std::collections::BTreeSet;
    use uuid::Uuid;

    fn jwt_auth(permissions: &[&str]) -> crate::AuthContext {
        crate::AuthContext::from_jwt(TokenClaims {
            iss: "test".to_string(),
            aud: "test".to_string(),
            sub: Uuid::now_v7(),
            roles: vec![],
            permissions: permissions.iter().map(|item| item.to_string()).collect(),
            exp: i64::MAX,
            iat: 0,
            jti: Uuid::now_v7(),
            purpose: "access".to_string(),
        })
    }

    fn api_key_auth(permissions: &[&str]) -> crate::AuthContext {
        crate::AuthContext::from_api_key(&ApiKeyInfo {
            id: Uuid::now_v7(),
            name: "asset-scope-test".to_string(),
            permissions: permissions.iter().map(|item| item.to_string()).collect(),
            user_id: Some(Uuid::now_v7()),
        })
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn jwt_and_api_key_principals_compose_the_same_effective_scope() {
        for mut auth in [
            jwt_auth(&[SEARCH_EXECUTE, AUDIT_VIEW]),
            api_key_auth(&[SEARCH_EXECUTE, AUDIT_VIEW]),
        ] {
            auth.denied_sources = ScopeSet::from_denied(set(&["insider_threat"]));
            assert_eq!(
                super::super::search::effective_scope(&auth).deny_set(),
                &set(&["insider_threat"])
            );
        }

        for auth in [jwt_auth(&[SEARCH_EXECUTE]), api_key_auth(&[SEARCH_EXECUTE])] {
            assert_eq!(
                super::super::search::effective_scope(&auth).deny_set(),
                &set(&["audit"]),
                "missing audit:view must force the raw scoped path for either credential type"
            );
        }
    }

    /// Wiring guard: the planner tests prove the scope decision, while this
    /// pins the HTTP surface to that decision and to a scope-separated cache.
    #[test]
    fn handler_threads_effective_scope_into_cache_and_service() {
        let source = include_str!("assets.rs");
        let marker = "pub async fn get_asset_true_time_range(";
        let start = source.find(marker).expect("true-time-range handler");
        let tail = &source[start..];
        let end = tail
            .find("// ============================================================================")
            .expect("end of true-time-range handler section");
        let handler = &tail[..end];

        assert!(handler.contains("let scope = super::search::effective_scope(&auth);"));
        assert!(
            !handler.contains("ScopeSet::unrestricted()"),
            "handler must never substitute an unscoped cache/service identity"
        );

        let cache_call = handler
            .split("SearchResultCache::companion_key")
            .nth(1)
            .expect("cache key call");
        assert!(
            cache_call.contains("&scope"),
            "effective scope must be part of the true-range cache key"
        );

        let service_call = handler
            .split(".query_asset_true_time_range(")
            .nth(1)
            .expect("service call");
        assert!(
            service_call.contains("&scope"),
            "handler must pass effective scope to the production query path"
        );
    }
}
