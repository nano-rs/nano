// SPDX-License-Identifier: AGPL-3.0-or-later

//! SSE streaming search endpoint.

use axum::{
    Json,
    extract::{Extension, State},
    response::sse::{Event, Sse},
};
use futures::stream::Stream;
use nanosiem_core::{
    SearchRequest, SearchResponse, auth::permissions, search::SearchStreamEvent,
};
use std::convert::Infallible;

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

/// NAN-704: thin shim around the canonical
/// `nanosiem_core::search::query_processing::enforce_non_audit_query`,
/// mapping its `nanosiem_core::SearchError` into this crate's local
/// `SearchError` for handler ergonomics.
fn enforce_non_audit_query(query: &str) -> Result<String, SearchError> {
    nanosiem_core::search::query_processing::enforce_non_audit_query(query).map_err(|e| {
        SearchError::QueryError(format!(
            "Query parsing failed for access control enforcement: {}",
            e
        ))
    })
}

/// Execute a streaming search via Server-Sent Events
///
/// POST /api/search/stream
///
/// Streams search results incrementally as ClickHouse returns them.
/// For non-aggregate queries, rows are sent in batches as they arrive.
/// For aggregate queries, progress is streamed and results are delivered atomically when done.
///
/// SSE event types:
/// - `started`: Search execution started (includes job_id, query_id, is_streaming flag)
/// - `progress`: Rows scanned progress update
/// - `rows`: A batch of result rows
/// - `metadata`: Query metadata (total_count, execution_time, fields, histogram, etc.)
/// - `completed`: Search finished successfully
/// - `error`: Search failed
#[utoipa::path(
    post,
    path = "/api/search/stream",
    tag = "search",
    request_body = SearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "SSE stream of search results"),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn search_stream(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    Json(mut request): Json<SearchRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, SearchError> {
    let user_id = auth.claims.sub;

    if !auth.claims.has_permission(permissions::AUDIT_VIEW) {
        request.query = enforce_non_audit_query(&request.query)?;
    }

    if let Some(request_id) = request.request_id.clone() {
        state
            .search
            .query_tracker()
            .reserve_request(request_id, user_id);
    }

    // Create event channel
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<SearchStreamEvent>(64);

    // Check search result cache (Dragonfly/Redis) — on hit, replay as SSE events via channel.
    // Rows are chunked into batches of 1000 to avoid SSE buffer overflow.
    let cache_hit = if let Some(ref cache) = state.result_cache {
        if let Some(cached) = cache.get(&request).await {
            record_search_query("stream_cached", 0.0, true);
            let tx = event_tx.clone();
            let total_row_count = cached.results.len() as u64;
            tokio::spawn(async move {
                const REPLAY_BATCH_SIZE: usize = 1000;
                let mut cumulative: u64 = 0;
                for (batch_index, chunk) in cached.results.chunks(REPLAY_BATCH_SIZE).enumerate() {
                    cumulative += chunk.len() as u64;
                    let _ = tx
                        .send(SearchStreamEvent::Rows {
                            rows: chunk.to_vec(),
                            batch_index: batch_index as u32,
                            cumulative_count: cumulative,
                        })
                        .await;
                }
                let _ = tx
                    .send(SearchStreamEvent::Metadata {
                        total_count: cached.total_count,
                        execution_time_ms: 0,
                        fields: cached.fields,
                        histogram: cached.histogram,
                        warnings: None,
                        cost_score: None,
                        display_type: cached.display_type,
                        column_order: cached.column_order,
                        generated_sql: cached.generated_sql,
                    })
                    .await;
                let _ = tx
                    .send(SearchStreamEvent::Completed {
                        total_rows_delivered: total_row_count,
                    })
                    .await;
            });
            true
        } else {
            false
        }
    } else {
        false
    };

    // On cache miss, spawn the actual search
    let cache_for_task = if cache_hit {
        None
    } else {
        state.result_cache.clone()
    };
    let request_for_cache = request.clone();
    if !cache_hit {
        let search_service = state.search.clone();
        let event_tx_clone = event_tx.clone();
        tokio::spawn(async move {
            search_service
                .search_streaming(request, event_tx_clone)
                .await;
        });
    }
    // Drop our sender so the channel closes when the spawned task finishes
    drop(event_tx);

    // Read streaming cache cap from hot-reloadable query safety settings
    let max_cache_rows: usize = state
        .search
        .query_limits()
        .read()
        .await
        .max_streaming_cache_rows as usize;

    // Build SSE stream from event channel with keepalive
    // Also collect rows + metadata for caching after completion
    let keepalive_interval = std::time::Duration::from_secs(15);
    let stream = async_stream::stream! {
        let mut interval = tokio::time::interval(keepalive_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut all_rows: Vec<serde_json::Value> = Vec::new();
        let mut cache_overflow = false;
        let mut meta_total_count: u64 = 0;
        let mut meta_fields: Vec<nanosiem_core::search::FieldInfo> = Vec::new();
        let mut meta_histogram: Option<Vec<nanosiem_core::search::HistogramBucket>> = None;
        let mut meta_display_type: Option<nanosiem_core::search::DisplayType> = None;
        let mut meta_column_order: Option<Vec<String>> = None;
        let mut meta_generated_sql: Option<String> = None;
        let mut completed_ok = false;

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    let (event_type, is_terminal) = match &event {
                        SearchStreamEvent::Queued { .. } => ("queued", false),
                        SearchStreamEvent::Started { .. } => ("started", false),
                        SearchStreamEvent::Progress { .. } => ("progress", false),
                        SearchStreamEvent::Rows { ref rows, .. } => {
                            if !cache_overflow {
                                if all_rows.len() + rows.len() > max_cache_rows {
                                    cache_overflow = true;
                                    tracing::debug!("Streaming cache: row count exceeds {}, skipping cache for this query", max_cache_rows);
                                } else {
                                    all_rows.extend(rows.iter().cloned());
                                }
                            }
                            ("rows", false)
                        }
                        SearchStreamEvent::Metadata { total_count, ref fields, ref histogram, ref display_type, ref column_order, ref generated_sql, .. } => {
                            meta_total_count = *total_count;
                            meta_fields = fields.clone();
                            meta_histogram = histogram.clone();
                            meta_display_type = display_type.clone();
                            meta_column_order = column_order.clone();
                            meta_generated_sql = generated_sql.clone();
                            ("metadata", false)
                        }
                        SearchStreamEvent::Completed { .. } => {
                            completed_ok = true;
                            ("completed", true)
                        }
                        SearchStreamEvent::Error { .. } => ("error", true),
                    };

                    let event_json = serde_json::to_string(&event).unwrap_or_default();
                    yield Ok(Event::default()
                        .event(event_type)
                        .data(event_json));

                    if is_terminal {
                        break;
                    }
                }
                _ = interval.tick() => {
                    yield Ok(Event::default().comment("keepalive"));
                }
                else => {
                    // Channel closed without terminal event
                    break;
                }
            }
        }

        // Cache the result in the background on successful completion (skip if too large)
        if completed_ok && !cache_overflow {
            if let Some(cache) = cache_for_task {
                let response = SearchResponse {
                    results: all_rows,
                    total_count: meta_total_count,
                    execution_time_ms: 0,
                    fields: meta_fields,
                    generated_sql: meta_generated_sql,
                    histogram: meta_histogram,
                    warnings: None,
                    cost_score: None,
                    display_type: meta_display_type,
                    column_order: meta_column_order,
                };
                let req = request_for_cache;
                tokio::spawn(async move {
                    cache.set(&req, &response).await;
                });
            }
        }

        // Send done event
        yield Ok(Event::default()
            .event("done")
            .data(""));
    };

    Ok(Sse::new(stream))
}
