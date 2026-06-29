// SPDX-License-Identifier: AGPL-3.0-or-later

//! OpenTelemetry observability endpoints (NAN-1528): trace-by-id fetch (ordered
//! spans for the waterfall view) and metric time-series query.
//!
//! These read the OTLP native-storage tables (`otel_spans`, `otel_metrics`)
//! created by migrations 138/140 — NOT the UDM/OCSF logs lane. SQL is built by
//! the `nanosiem_core::query::otel` helpers (partition-pruned trace fetch,
//! bucketed metric series) and executed via the SearchService's single-SELECT
//! `query_otel_*` glue.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use nanosiem_core::TimeRangeInput;
use nanosiem_core::query::{
    InfraHostsFilters, MetricAgg, MetricQuery, MetricTagFilter, RumFilters, ServicesOverviewFilters,
    ServicesSort, TimeRange, TraceListFilters, valid_tag_key,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

// ============================================================================
// Trace by id (ordered spans for the waterfall)
// ============================================================================

/// Response for a single trace: every span, ordered by `start_time` so the
/// caller can build the waterfall directly. Spans are returned as raw JSON
/// objects (the full `otel_spans` column set incl. the `attributes` /
/// `resource_attributes` maps and the entity overlay).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TraceResponse {
    /// The trace id that was requested (lowercased hex).
    pub trace_id: String,
    /// Ordered spans (`start_time ASC`). Empty when the trace id is unknown.
    pub spans: Vec<serde_json::Value>,
    /// Number of spans returned.
    pub span_count: usize,
}

/// Fetch a distributed trace by id.
///
/// Returns every span of the trace, time-ordered (`start_time ASC`), ready for
/// the trace-waterfall view. Two-step partition-pruned fetch under the hood
/// (compact per-trace index → in-window span scan). Returns an empty span list
/// (200) when the trace id is unknown rather than 404, so the UI can render an
/// "unknown trace" state without special-casing the error path.
#[utoipa::path(
    get,
    path = "/api/search/trace/{trace_id}",
    tag = "search",
    params(
        ("trace_id" = String, Path, description = "Trace id (hex; case-insensitive — stored lowercased)")
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Ordered spans for the trace (empty if unknown)", body = TraceResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_trace(
    State(state): State<SearchState>,
    Path(trace_id): Path<String>,
) -> Result<Json<TraceResponse>, SearchError> {
    let start = Instant::now();

    // NAN-1593: the trace waterfall re-fetches on every load / shared-link
    // follow — cache it through the same Dragonfly layer as the main search.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "trace",
        &[trace_id.to_ascii_lowercase().as_bytes()],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<TraceResponse>(&cache_key).await {
            record_search_query("otel_trace_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state.search.query_otel_trace_by_id(&trace_id).await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_trace", duration_ms, result.is_ok());

    let spans = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL trace fetch failed");
        SearchError::QueryError("Failed to fetch trace".to_string())
    })?;

    let response = TraceResponse {
        trace_id: trace_id.to_ascii_lowercase(),
        span_count: spans.len(),
        spans,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Metric time series
// ============================================================================

/// A single tag/attribute equality filter for a metric query (NAN-1540).
/// Matched over the metric's `attributes` / `resource_attributes` maps.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MetricFilterInput {
    /// Tag/attribute key (validated against [`valid_tag_key`]).
    pub key: String,
    /// Exact value to match.
    pub value: String,
}

/// Request for an OTLP metric time series (NAN-1540 metrics v2).
///
/// Back-compatible with the v1 single-series request: omit `agg`/`group_by`/
/// `filters` and you get one `avg(value)` series (label `""`). Adding `agg`
/// switches the aggregate; `group_by` splits the result into one series per
/// distinct tag value; `filters` narrows by exact tag matches.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct MetricTimeseriesRequest {
    /// Metric name (OTLP `name`, e.g. `http.server.request.duration`).
    pub metric_name: String,
    /// Optional single `service.name` filter (omit / empty for all services).
    #[serde(default)]
    pub service_name: Option<String>,
    /// Time range for the series.
    pub time_range: TimeRangeInput,
    /// Bucket width in seconds (clamped to >= 1). Default 60s.
    #[serde(default = "default_step_secs")]
    pub step_secs: u64,
    /// Aggregate over each bucket: `avg`|`sum`|`min`|`max`|`count`|`rate`|
    /// `p50`|`p95`|`p99` (default `avg`). Rejected with 400 if unknown.
    #[serde(default)]
    pub agg: Option<String>,
    /// Optional tag/attribute key to split the result into one series per
    /// distinct value. `null` ⇒ a single series with label `""`. Validated
    /// against [`valid_tag_key`] (400 on reject).
    #[serde(default)]
    pub group_by: Option<String>,
    /// Optional exact-match tag/attribute filters (AND-ed together).
    #[serde(default)]
    pub filters: Vec<MetricFilterInput>,
}

fn default_step_secs() -> u64 {
    60
}

/// One labelled series of bucketed points. `key` is the `group_by` tag value
/// (`""` when there is no `group_by`); `points` is `[{t, v}]` ordered by bucket.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MetricSeries {
    /// Series label — the `group_by` tag value, or `""` for a single series.
    pub key: String,
    /// Bucketed points, ordered by bucket. Each object is `{t, v}`.
    pub points: Vec<serde_json::Value>,
}

/// Response for a metric time series: one or more labelled series (NAN-1540).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MetricTimeseriesResponse {
    /// The metric name that was queried.
    pub metric_name: String,
    /// The aggregate applied (canonical form, e.g. `avg`, `p95`).
    pub agg: String,
    /// The `group_by` tag key, if any.
    pub group_by: Option<String>,
    /// One entry per series. With no `group_by`, exactly one series (key `""`).
    pub series: Vec<serde_json::Value>,
    /// Bucket width applied (after the >= 1 clamp).
    pub step_secs: u64,
}

/// Query a metric time series.
///
/// Returns one series of `agg`-per-`step_secs`-bucket points over the time
/// range, filtered to `metric_name` (and optionally a single `service_name`
/// and exact-match tag `filters`). With `group_by` set, the result splits into
/// one series per distinct value of that tag. `agg` defaults to `avg` (safe for
/// gauges); `rate` / `p50`/`p95`/`p99` cover counter / histogram semantics.
#[utoipa::path(
    post,
    path = "/api/search/metrics/timeseries",
    tag = "search",
    request_body = MetricTimeseriesRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Labelled metric time series", body = MetricTimeseriesResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_metric_timeseries(
    State(state): State<SearchState>,
    Json(request): Json<MetricTimeseriesRequest>,
) -> Result<Json<MetricTimeseriesResponse>, SearchError> {
    let start = Instant::now();

    request.time_range.validate()?;

    let time_range =
        nanosiem_core::query::TimeRange::new(request.time_range.start, request.time_range.end);
    let service = request.service_name.as_deref().filter(|s| !s.is_empty());

    // Validate the aggregate against the allowlist (None default = avg).
    let agg = match request.agg.as_deref() {
        None => MetricAgg::default(),
        Some(s) => MetricAgg::from_str(s)
            .ok_or_else(|| SearchError::BadRequest(format!("unknown agg: {s}")))?,
    };

    // Validate group_by + every filter key at the API boundary.
    let group_by = request.group_by.as_deref().filter(|s| !s.is_empty());
    if let Some(key) = group_by {
        if !valid_tag_key(key) {
            return Err(SearchError::BadRequest(format!(
                "invalid group_by key: {key}"
            )));
        }
    }
    let mut filters: Vec<MetricTagFilter> = Vec::with_capacity(request.filters.len());
    for f in &request.filters {
        if !valid_tag_key(&f.key) {
            return Err(SearchError::BadRequest(format!(
                "invalid filter key: {}",
                f.key
            )));
        }
        filters.push(MetricTagFilter {
            key: f.key.clone(),
            value: f.value.clone(),
        });
    }

    let query = MetricQuery {
        metric_name: &request.metric_name,
        service_name: service,
        agg,
        group_by,
        filters: &filters,
        step_secs: request.step_secs,
    };

    // NAN-1593: metric panels re-query on every dashboard render / shared-link
    // follow — cache through the same Dragonfly layer. Keyed on the metric name,
    // service, time range, bucket width, canonical aggregate, group_by, and the
    // exact filter set (all of which change the series output). The filter set is
    // JSON-encoded as ordered (key, value) pairs — `MetricTagFilter` isn't
    // `Serialize`, but JSON-escaping the pairs (rather than joining on a
    // delimiter) keeps a value containing `=` or the separator from colliding a
    // single filter with two (NAN-1593 review).
    let filters_key = serde_json::to_string(
        &filters
            .iter()
            .map(|f| [f.key.as_str(), f.value.as_str()])
            .collect::<Vec<_>>(),
    )
    .unwrap_or_default();
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "mts",
        &[
            request.metric_name.as_bytes(),
            service.unwrap_or("").as_bytes(),
            request.time_range.start.timestamp_micros().to_string().as_bytes(),
            request.time_range.end.timestamp_micros().to_string().as_bytes(),
            request.step_secs.to_string().as_bytes(),
            agg.as_str().as_bytes(),
            group_by.unwrap_or("").as_bytes(),
            filters_key.as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache
            .get_cached::<MetricTimeseriesResponse>(&cache_key)
            .await
        {
            record_search_query("otel_metric_timeseries_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state
        .search
        .query_otel_metric_timeseries_v2(&query, &time_range)
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_metric_timeseries", duration_ms, result.is_ok());

    let series = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL metric timeseries query failed");
        SearchError::QueryError("Failed to fetch metric time series".to_string())
    })?;

    let response = MetricTimeseriesResponse {
        metric_name: request.metric_name,
        agg: agg.as_str().to_string(),
        group_by: group_by.map(|s| s.to_string()),
        series,
        step_secs: request.step_secs.max(1),
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Metric tags (Metrics explorer — group-by / filter pickers)
// ============================================================================

/// Query parameters for the metric-tags endpoint (NAN-1540).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct MetricTagsParams {
    /// Metric name to enumerate tags for (required).
    pub metric_name: String,
    /// When omitted, returns the distinct tag KEYS. When given, returns the
    /// distinct VALUES for that key. Validated against [`valid_tag_key`].
    pub key: Option<String>,
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 24.
    #[serde(default = "default_trace_window_hours")]
    pub window_hours: i64,
}

/// Response for the metric-tags endpoint. Exactly one of the two arrays is
/// populated per request (keys when `key` is omitted, values when given).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MetricTagsResponse {
    /// Distinct tag/attribute keys present for the metric (when `key` omitted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_keys: Option<Vec<String>>,
    /// Distinct values for the requested `key` (when `key` given).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_values: Option<Vec<String>>,
}

/// List a metric's tag keys, or the values of one tag key.
///
/// With only `metric_name`, returns the distinct attribute/resource keys
/// present for that metric (`{ tag_keys: [...] }`) — the group-by / filter
/// picker. With `key` set, returns the distinct values for that key
/// (`{ tag_values: [...] }`) — the filter-value picker. Window defaults to the
/// last 24h. Bounded by the window + internal LIMITs.
#[utoipa::path(
    get,
    path = "/api/search/metrics/tags",
    tag = "search",
    params(MetricTagsParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Tag keys (no key) or tag values (key given)", body = MetricTagsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_metric_tags(
    State(state): State<SearchState>,
    Query(params): Query<MetricTagsParams>,
) -> Result<Json<MetricTagsResponse>, SearchError> {
    let start = Instant::now();

    if params.metric_name.trim().is_empty() {
        return Err(SearchError::BadRequest(
            "metric_name must not be empty".to_string(),
        ));
    }

    let time_range = resolve_window(params.start, params.end, params.window_hours)?;

    // NAN-1593: the group-by / filter-value pickers re-fetch on every metrics
    // explorer load — cache through the same Dragonfly layer. Keyed on the
    // metric name, the optional tag key, and the resolved window.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "mtags",
        &[
            params.metric_name.as_bytes(),
            params.key.as_deref().unwrap_or("").as_bytes(),
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<MetricTagsResponse>(&cache_key).await {
            record_search_query("otel_metric_tags_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let response = match params.key.as_deref().filter(|s| !s.is_empty()) {
        None => {
            let result = state
                .search
                .list_otel_metric_tag_keys(&params.metric_name, &time_range)
                .await;
            let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            record_search_query("otel_metric_tag_keys", duration_ms, result.is_ok());
            let tag_keys = result.map_err(|e| {
                tracing::error!(error = %e, "OTEL metric tag-keys query failed");
                SearchError::QueryError("Failed to list metric tag keys".to_string())
            })?;
            MetricTagsResponse {
                tag_keys: Some(tag_keys),
                tag_values: None,
            }
        }
        Some(key) => {
            if !valid_tag_key(key) {
                return Err(SearchError::BadRequest(format!("invalid tag key: {key}")));
            }
            let result = state
                .search
                .list_otel_metric_tag_values(&params.metric_name, key, &time_range)
                .await;
            let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            record_search_query("otel_metric_tag_values", duration_ms, result.is_ok());
            let tag_values = result.map_err(|e| {
                tracing::error!(error = %e, "OTEL metric tag-values query failed");
                SearchError::QueryError("Failed to list metric tag values".to_string())
            })?;
            MetricTagsResponse {
                tag_keys: None,
                tag_values: Some(tag_values),
            }
        }
    };

    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Recent traces list (Traces explorer)
// ============================================================================

fn default_trace_window_hours() -> i64 {
    24
}

/// Query parameters for the recent-traces list (NAN-1534).
///
/// All optional. The time window defaults to the last 24h when `start`/`end`
/// are omitted; filters narrow the list and `limit` caps the row count.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ListTracesParams {
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 24.
    #[serde(default = "default_trace_window_hours")]
    pub window_hours: i64,
    /// Filter to traces whose root span belongs to this `service.name`.
    pub service: Option<String>,
    /// When true, only traces with at least one error span.
    #[serde(default)]
    pub errors_only: bool,
    /// Minimum root-span duration in nanoseconds.
    pub min_duration_ns: Option<u64>,
    /// Max traces to return (clamped to 1000 by the SQL builder; default 200).
    pub limit: Option<u32>,
    /// Keyset pagination cursor (NAN-1539, RFC3339): return only traces whose
    /// `start_time` is strictly before this instant. Pass the previous page's
    /// last `start_time` to fetch the next page (the list is most-recent-first).
    pub before: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response for the recent-traces list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ListTracesResponse {
    /// One object per trace, most-recent-first. Each carries `trace_id`,
    /// `root_service`, `root_name`, `span_count`, `error_count`, `duration_ns`,
    /// and `start_time` (the root-span duration is the trace's wall-clock span).
    pub traces: Vec<serde_json::Value>,
    /// Number of traces returned.
    pub count: usize,
}

/// List recent distributed traces.
///
/// Aggregates `otel_spans` by `trace_id` over the time window, resolving each
/// trace's root service/name/duration (the parent-less span) plus span and
/// error counts. Optional filters narrow by root `service`, errors-only, and a
/// minimum root duration. Ordered most-recent-first; bounded by `limit` (≤1000)
/// — feeds the Traces explorer table. Each row's `trace_id` links to
/// `GET /api/search/trace/{trace_id}` for the waterfall.
#[utoipa::path(
    get,
    path = "/api/search/traces",
    tag = "search",
    params(ListTracesParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Recent traces, most-recent-first", body = ListTracesResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_traces(
    State(state): State<SearchState>,
    Query(params): Query<ListTracesParams>,
) -> Result<Json<ListTracesResponse>, SearchError> {
    let start = Instant::now();

    // Resolve the time window: explicit start/end win; otherwise look back
    // `window_hours` from now (clamped to a sane 1..=720h / 30d range).
    let now = chrono::Utc::now();
    let window_hours = params.window_hours.clamp(1, 720);
    let end = params.end.unwrap_or(now);
    let begin = params
        .start
        .unwrap_or_else(|| end - chrono::Duration::hours(window_hours));
    if begin >= end {
        return Err(SearchError::BadRequest(
            "start must be before end".to_string(),
        ));
    }
    let time_range = TimeRange::new(begin, end);

    let service = params.service.as_deref().filter(|s| !s.is_empty());
    let filters = TraceListFilters {
        service,
        errors_only: params.errors_only,
        min_duration_ns: params.min_duration_ns,
        limit: params.limit,
        before: params.before,
    };

    // NAN-1593: the Traces explorer list re-fetches on every load / paging /
    // shared-link follow — cache through the same Dragonfly layer. Keyed on the
    // resolved window plus every filter + the keyset cursor that shapes the page.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "traces",
        &[
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
            service.unwrap_or("").as_bytes(),
            if params.errors_only { "e1" } else { "e0" }.as_bytes(),
            params
                .min_duration_ns
                .map(|v| v.to_string())
                .unwrap_or_default()
                .as_bytes(),
            params.limit.map(|v| v.to_string()).unwrap_or_default().as_bytes(),
            params
                .before
                .map(|t| t.timestamp_micros().to_string())
                .unwrap_or_default()
                .as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<ListTracesResponse>(&cache_key).await {
            record_search_query("otel_traces_list_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state.search.list_otel_traces(&time_range, &filters).await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_traces_list", duration_ms, result.is_ok());

    let traces = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL recent-traces query failed");
        SearchError::QueryError("Failed to list traces".to_string())
    })?;

    let response = ListTracesResponse {
        count: traces.len(),
        traces,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Metric names (Metrics explorer dropdown)
// ============================================================================

/// Query parameters for the metric-names list (NAN-1534).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct MetricNamesParams {
    /// Optional single `service.name` filter (omit / empty for all services).
    pub service: Option<String>,
}

/// Response for the metric-names list.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct MetricNamesResponse {
    /// Distinct metric names, name-ordered. Each object is `{metric_name}`.
    pub names: Vec<serde_json::Value>,
    /// Number of distinct metric names returned.
    pub count: usize,
}

/// List distinct metric names.
///
/// Returns the distinct `metric_name` values in `otel_metrics`, optionally
/// restricted to a single `service`. Name-ordered, bounded by an internal
/// `LIMIT 10000` — populates the Metrics explorer dropdown.
#[utoipa::path(
    get,
    path = "/api/search/metrics/names",
    tag = "search",
    params(MetricNamesParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Distinct metric names", body = MetricNamesResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_metric_names(
    State(state): State<SearchState>,
    Query(params): Query<MetricNamesParams>,
) -> Result<Json<MetricNamesResponse>, SearchError> {
    let start = Instant::now();

    let service = params.service.as_deref().filter(|s| !s.is_empty());

    // NAN-1593: the metrics-explorer dropdown re-fetches on every load — cache
    // through the same Dragonfly layer. Keyed on the optional service filter.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "mnames",
        &[service.unwrap_or("").as_bytes()],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<MetricNamesResponse>(&cache_key).await {
            record_search_query("otel_metric_names_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state.search.list_otel_metric_names(service).await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_metric_names", duration_ms, result.is_ok());

    let names = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL metric-names query failed");
        SearchError::QueryError("Failed to list metric names".to_string())
    })?;

    let response = MetricNamesResponse {
        count: names.len(),
        names,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Observability console — services overview + service detail (NAN-1536)
// ============================================================================

/// Default services-overview lookback window (hours) when `start` is omitted.
fn default_services_window_hours() -> i64 {
    1
}

/// Resolve an explicit `start`/`end` window, falling back to `now -
/// window_hours .. now` when `start` is omitted. Clamps `window_hours` to
/// `1..=720` (30 days) and validates `start < end`. Shared by the services
/// overview + detail handlers.
fn resolve_window(
    start: Option<chrono::DateTime<chrono::Utc>>,
    end: Option<chrono::DateTime<chrono::Utc>>,
    window_hours: i64,
) -> Result<TimeRange, SearchError> {
    let now = chrono::Utc::now();
    let window_hours = window_hours.clamp(1, 720);
    let end = end.unwrap_or(now);
    let begin = start.unwrap_or_else(|| end - chrono::Duration::hours(window_hours));
    if begin >= end {
        return Err(SearchError::BadRequest(
            "start must be before end".to_string(),
        ));
    }
    Ok(TimeRange::new(begin, end))
}

/// Pick a sane bucket width (seconds) targeting ~60 points across `time_range`,
/// clamped to a `[1, 86400]` floor/ceiling so a long window still yields a
/// reasonable bucket count.
fn step_for_window(time_range: &TimeRange) -> u64 {
    let secs = (time_range.end - time_range.start).num_seconds().max(1);
    ((secs / 60).max(1) as u64).min(86_400)
}

/// Query parameters for the services overview + detail (NAN-1536/1543).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ServicesParams {
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 1.
    #[serde(default = "default_services_window_hours")]
    pub window_hours: i64,
    /// Case-insensitive substring filter on the service name (NAN-1543).
    pub q: Option<String>,
    /// Health filter: `good` | `warn` | `bad` (NAN-1543). Applied
    /// post-aggregation; rejected with 400 if outside the allowlist.
    pub health: Option<String>,
    /// Sort key: `error_rate` | `p95` | `rate` | `name` (NAN-1543). Default
    /// `rate` (busiest first); rejected with 400 if outside the allowlist.
    pub sort: Option<String>,
    /// Max services to return after filtering (NAN-1543). Omit for all.
    pub limit: Option<u32>,
    /// Row offset for paging (NAN-1543). Default 0.
    #[serde(default)]
    pub offset: u32,
}

/// Response for the services overview: one RED summary row per service.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ServicesOverviewResponse {
    /// One object per `service` with `request_count`, `rate_per_sec`,
    /// `error_rate` (0..1), `p50_ms`/`p95_ms`/`p99_ms`, `health`
    /// (`good`|`warn`|`bad`), and a `sparkline: [{t, v}]` of per-bucket volume.
    pub services: Vec<serde_json::Value>,
    /// Total matching services AFTER the q/health filters but BEFORE the
    /// offset/limit slice (NAN-1543 — the has-more signal source).
    pub total: usize,
    /// Whether more rows exist past this page (`offset + returned < total`).
    pub has_more: bool,
}

/// List the services overview (RED metrics per service).
///
/// Aggregates `otel_spans` by `service_name` over the time window into the
/// per-service RED summary that drives the Services tab of the Observability
/// console: request count + rate, error rate, latency percentiles, a derived
/// health classification, and a request-volume sparkline. Bounded by the time
/// window + internal LIMITs (overview 1000 services, sparkline 200k points).
#[utoipa::path(
    get,
    path = "/api/search/services",
    tag = "search",
    params(ServicesParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Per-service RED overview", body = ServicesOverviewResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_services(
    State(state): State<SearchState>,
    Query(params): Query<ServicesParams>,
) -> Result<Json<ServicesOverviewResponse>, SearchError> {
    let start = Instant::now();

    let time_range = resolve_window(params.start, params.end, params.window_hours)?;
    let step = step_for_window(&time_range);

    // Validate the allowlisted enum-ish params at the boundary (400 on reject).
    let sort = match params.sort.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(s) => Some(
            ServicesSort::from_str(s)
                .ok_or_else(|| SearchError::BadRequest(format!("unknown sort: {s}")))?,
        ),
    };
    let health = match params.health.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(h) if matches!(h, "good" | "warn" | "bad") => Some(h.to_string()),
        Some(h) => {
            return Err(SearchError::BadRequest(format!("unknown health: {h}")));
        }
    };

    let filters = ServicesOverviewFilters {
        q: params.q.as_deref().filter(|s| !s.is_empty()),
        sort,
    };

    // NAN-1593: the Services tab re-fetches on every console load / filter /
    // paging — cache through the same Dragonfly layer. Keyed on the resolved
    // window, bucket width, and every filter/sort/paging param.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "svcs",
        &[
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
            step.to_string().as_bytes(),
            filters.q.unwrap_or("").as_bytes(),
            health.as_deref().unwrap_or("").as_bytes(),
            params.sort.as_deref().unwrap_or("").as_bytes(),
            params.offset.to_string().as_bytes(),
            params.limit.map(|v| v.to_string()).unwrap_or_default().as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache
            .get_cached::<ServicesOverviewResponse>(&cache_key)
            .await
        {
            record_search_query("otel_services_overview_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state
        .search
        .observability_services_overview(
            &time_range,
            step,
            &filters,
            health.as_deref(),
            params.offset,
            params.limit,
        )
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_services_overview", duration_ms, result.is_ok());

    let (services, total) = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL services-overview query failed");
        SearchError::QueryError("Failed to list services".to_string())
    })?;

    let has_more = (params.offset as usize) + services.len() < total;
    let response = ServicesOverviewResponse {
        services,
        total,
        has_more,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

/// Default exemplar sample size for the service detail.
fn default_exemplar_limit() -> u32 {
    20
}

/// Query parameters for the service detail (NAN-1536). Extends the overview
/// window params with an exemplar-sample cap.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct ServiceDetailParams {
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 1.
    #[serde(default = "default_services_window_hours")]
    pub window_hours: i64,
    /// Max exemplar trace seeds to sample (clamped `[1,200]`; default 20).
    #[serde(default = "default_exemplar_limit")]
    pub exemplar_limit: u32,
}

/// Response wrapper for the service detail. The body is the full detail object
/// (`service`, `red`, `endpoints`, `exemplars`) assembled by the core glue.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ServiceDetailResponse {
    /// Service-detail payload: `{ service, red:{rate,errors,latency},
    /// endpoints:[…], exemplars:[…] }`.
    #[serde(flatten)]
    pub detail: serde_json::Value,
}

/// Service detail (RED timeseries, per-endpoint table, trace exemplars).
///
/// For one `service`, returns the RED time series (rate / errors / latency
/// p50,p95,p99 bucketed across the window), a per-endpoint (`span_name`)
/// summary table, and a sample of exemplar trace ids (recent + errored) for
/// click-through to the trace waterfall. Bounded by the time window + internal
/// LIMITs. Drives the Service-detail drill-in of the Observability console.
#[utoipa::path(
    get,
    path = "/api/search/services/{service}",
    tag = "search",
    params(
        ("service" = String, Path, description = "service.name to detail"),
        ServiceDetailParams,
    ),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Service detail (red/endpoints/exemplars)", body = ServiceDetailResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_service_detail(
    State(state): State<SearchState>,
    Path(service): Path<String>,
    Query(params): Query<ServiceDetailParams>,
) -> Result<Json<ServiceDetailResponse>, SearchError> {
    let start = Instant::now();

    if service.trim().is_empty() {
        return Err(SearchError::BadRequest(
            "service must not be empty".to_string(),
        ));
    }

    let time_range = resolve_window(params.start, params.end, params.window_hours)?;
    let step = step_for_window(&time_range);

    // NAN-1593: the service-detail drill-in re-fetches on every open / shared-link
    // follow — cache through the same Dragonfly layer. Keyed on the service name,
    // resolved window, bucket width, and exemplar sample cap.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "svcdetail",
        &[
            service.as_bytes(),
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
            step.to_string().as_bytes(),
            params.exemplar_limit.to_string().as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<ServiceDetailResponse>(&cache_key).await {
            record_search_query("otel_service_detail_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state
        .search
        .observability_service_detail(&service, &time_range, step, Some(params.exemplar_limit))
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_service_detail", duration_ms, result.is_ok());

    let detail = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL service-detail query failed");
        SearchError::QueryError("Failed to fetch service detail".to_string())
    })?;

    let response = ServiceDetailResponse { detail };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Observability console — Infrastructure (host metrics) (NAN-1537)
// ============================================================================

/// Query parameters for the infrastructure hosts overview (NAN-1537).
///
/// Reuses the shared window resolution: explicit `start`/`end` win; otherwise a
/// `window_hours` lookback from now (default 1h).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct InfraHostsParams {
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 1.
    #[serde(default = "default_services_window_hours")]
    pub window_hours: i64,
    /// Case-insensitive substring filter on the host name (NAN-1543).
    pub q: Option<String>,
    /// Exact match on `host.group` resource attribute (NAN-1543).
    pub group: Option<String>,
    /// Exact match on `deployment.environment` resource attribute (NAN-1543).
    pub env: Option<String>,
    /// Status filter: `good` | `warn` | `bad` (NAN-1543). Applied
    /// post-aggregation; rejected with 400 if outside the allowlist.
    pub status: Option<String>,
    /// Max hosts to return after filtering (NAN-1543). Omit for all (capped at
    /// the internal LIMIT 10000).
    pub limit: Option<u32>,
    /// Row offset for paging (NAN-1543). Default 0.
    #[serde(default)]
    pub offset: u32,
}

/// Response for the infrastructure hosts overview: one row per host.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct InfraHostsResponse {
    /// One object per host with `host`, `group` (`host.group` or service
    /// fallback, nullable), the latest gauge values `cpu_pct`/`mem_pct`/`load`/
    /// `net_bytes_per_sec` (each `null` when the host emitted no such gauge), and
    /// a `status` (`good`|`warn`|`bad`) derived from the CPU/memory thresholds.
    pub hosts: Vec<serde_json::Value>,
    /// Total matching hosts AFTER the q/group/env/status filters but BEFORE the
    /// offset/limit slice (NAN-1543 — the has-more signal source).
    pub total: usize,
    /// Whether more rows exist past this page (`offset + returned < total`).
    pub has_more: bool,
}

/// Infrastructure hosts overview (latest host metrics).
///
/// Reads `otel_metrics` over the time window, keyed by host
/// (`resource_attributes['host.name']`), resolving the latest value per
/// `(host, metric_name)` via `argMax(value, timestamp)`: CPU utilization,
/// memory utilization, 1m load average, and network IO. Utilization fractions
/// are scaled to percent; a derived `status` flags hosts over the CPU/memory
/// thresholds. Bounded by the time window + internal LIMIT — drives the host
/// waffle of the Infra tab.
#[utoipa::path(
    get,
    path = "/api/search/infra/hosts",
    tag = "search",
    params(InfraHostsParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "Per-host latest-metric overview", body = InfraHostsResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_infra_hosts(
    State(state): State<SearchState>,
    Query(params): Query<InfraHostsParams>,
) -> Result<Json<InfraHostsResponse>, SearchError> {
    let start = Instant::now();

    let time_range = resolve_window(params.start, params.end, params.window_hours)?;

    // Validate the allowlisted status param at the boundary (400 on reject).
    let status = match params.status.as_deref().filter(|s| !s.is_empty()) {
        None => None,
        Some(s) if matches!(s, "good" | "warn" | "bad") => Some(s.to_string()),
        Some(s) => {
            return Err(SearchError::BadRequest(format!("unknown status: {s}")));
        }
    };

    let filters = InfraHostsFilters {
        q: params.q.as_deref().filter(|s| !s.is_empty()),
        group: params.group.as_deref().filter(|s| !s.is_empty()),
        env: params.env.as_deref().filter(|s| !s.is_empty()),
    };

    // NAN-1593: the Infra tab re-fetches on every console load / filter / paging
    // — cache through the same Dragonfly layer. Keyed on the resolved window plus
    // every filter/status/paging param.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "infra",
        &[
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
            filters.q.unwrap_or("").as_bytes(),
            filters.group.unwrap_or("").as_bytes(),
            filters.env.unwrap_or("").as_bytes(),
            status.as_deref().unwrap_or("").as_bytes(),
            params.offset.to_string().as_bytes(),
            params.limit.map(|v| v.to_string()).unwrap_or_default().as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<InfraHostsResponse>(&cache_key).await {
            record_search_query("otel_infra_hosts_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state
        .search
        .observability_infra_hosts(&time_range, &filters, status.as_deref(), params.offset, params.limit)
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_infra_hosts", duration_ms, result.is_ok());

    let (hosts, total) = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL infra-hosts query failed");
        SearchError::QueryError("Failed to list infra hosts".to_string())
    })?;

    let has_more = (params.offset as usize) + hosts.len() < total;
    let response = InfraHostsResponse {
        hosts,
        total,
        has_more,
    };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}

// ============================================================================
// Observability console — RUM (real user monitoring) (NAN-1537)
// ============================================================================

/// Query parameters for the RUM summary (NAN-1537).
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct RumParams {
    /// Window start (RFC3339). Defaults to `now - window_hours`.
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Window end (RFC3339). Defaults to `now`.
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Lookback window in hours used when `start` is omitted. Default 1.
    #[serde(default = "default_services_window_hours")]
    pub window_hours: i64,
    /// Case-insensitive substring filter on the page URL / route (NAN-1543).
    pub page: Option<String>,
    /// Exact match on the `browser.name` span attribute (NAN-1543).
    pub browser: Option<String>,
    /// Exact match on the `deployment.environment` resource attribute
    /// (NAN-1543). Also scopes the metrics-sourced web vitals.
    pub env: Option<String>,
}

/// Response wrapper for the RUM summary. The body is the full RUM object
/// assembled by the core glue.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RumSummaryResponse {
    /// RUM payload: `{ web_vitals:{lcp_ms,inp_ms,cls}, page_views,
    /// page_views_series:[{t,v}], js_errors, top_pages:[{page,views,lcp_ms}],
    /// recent_errors:[{message,page,ts}] }`.
    #[serde(flatten)]
    pub rum: serde_json::Value,
}

/// RUM (real user monitoring) summary.
///
/// Assembles the front-end-experience summary over the time window: p75 web
/// vitals (LCP/INP/CLS) from `otel_metrics`, plus page-view count + bucketed
/// series, JS-error count, busiest pages with per-page p75 LCP, and a recent
/// JS-error sample from `otel_spans`. A vital with no data points is reported
/// as `null` (distinct from a true 0). Bounded by the time window + internal
/// LIMITs — drives the RUM tab of the Observability console.
#[utoipa::path(
    get,
    path = "/api/search/rum",
    tag = "search",
    params(RumParams),
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "RUM summary (vitals/page-views/errors/top-pages)", body = RumSummaryResponse),
        (status = 400, description = "Query error", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_rum_summary(
    State(state): State<SearchState>,
    Query(params): Query<RumParams>,
) -> Result<Json<RumSummaryResponse>, SearchError> {
    let start = Instant::now();

    let time_range = resolve_window(params.start, params.end, params.window_hours)?;
    let step = step_for_window(&time_range);

    let filters = RumFilters {
        page: params.page.as_deref().filter(|s| !s.is_empty()),
        browser: params.browser.as_deref().filter(|s| !s.is_empty()),
        env: params.env.as_deref().filter(|s| !s.is_empty()),
    };

    // NAN-1593: the RUM tab re-fetches on every console load / filter / shared-link
    // follow — cache through the same Dragonfly layer. Keyed on the resolved
    // window, bucket width, and every filter param.
    let cache_key = crate::cache::SearchResultCache::companion_key(
        "rum",
        &[
            time_range.start.timestamp_micros().to_string().as_bytes(),
            time_range.end.timestamp_micros().to_string().as_bytes(),
            step.to_string().as_bytes(),
            filters.page.unwrap_or("").as_bytes(),
            filters.browser.unwrap_or("").as_bytes(),
            filters.env.unwrap_or("").as_bytes(),
        ],
    );
    if let Some(cache) = state.result_cache.as_ref() {
        if let Some(cached) = cache.get_cached::<RumSummaryResponse>(&cache_key).await {
            record_search_query("otel_rum_summary_cached", 0.0, true);
            return Ok(Json(cached));
        }
    }

    let result = state
        .search
        .observability_rum_summary(&time_range, step, &filters)
        .await;

    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;
    record_search_query("otel_rum_summary", duration_ms, result.is_ok());

    let rum = result.map_err(|e| {
        tracing::error!(error = %e, "OTEL RUM-summary query failed");
        SearchError::QueryError("Failed to fetch RUM summary".to_string())
    })?;

    let response = RumSummaryResponse { rum };
    if let Some(cache) = state.result_cache.as_ref() {
        let cache = cache.clone();
        let resp = response.clone();
        tokio::spawn(async move {
            cache.set_cached(&cache_key, &resp).await;
        });
    }

    Ok(Json(response))
}
