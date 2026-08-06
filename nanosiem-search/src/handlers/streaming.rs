// SPDX-License-Identifier: AGPL-3.0-or-later

//! SSE streaming search endpoint.

use axum::{
    Json,
    extract::{Extension, State},
    response::sse::{Event, Sse},
};
use futures::stream::Stream;
use nanosiem_core::{
    SearchRequest, SearchResponse,
    search::{QueryPriority, SearchStreamEvent},
};
use std::convert::Infallible;

use crate::error::ErrorResponse;
use crate::{SearchState, error::SearchError, metrics::record_search_query};

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
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn search_stream(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    Json(request): Json<SearchRequest>,
) -> Result<(axum::http::HeaderMap, Sse<impl Stream<Item = Result<Event, Infallible>>>), SearchError>
{
    // NAN-2030: authN (a valid token) is not authZ — gate the SSE search path on
    // search:execute before any work, exactly like POST /api/search. This path
    // was authenticated but UNAUTHORIZED (a parity gap vs. the batch `search`).
    super::require_search_execute(&auth)?;

    // NAN-1799: compose the effective deny-set (per-user source scope ∪ audit
    // gate) ONCE, before the cache lookup below — the scope is folded into
    // the cache key, and the service injects the exclusion into the executed
    // SQL. This replaces the old `enforce_non_audit_query` rewrite of
    // request.query.
    let scope = super::search::effective_scope(&auth);

    if let Some(request_id) = request.request_id.clone() {
        // NAN-2100: reserve under the CREDENTIAL (api-key id, or user id for
        // an interactive session) — `cancel_search` compares the same
        // principal. Shares the batch path's helper so the two entry points
        // cannot drift on the identity they record.
        super::search::reserve_query_owner(&state, request_id, auth.credential_principal_id())
            .await?;
    }

    // NAN-2039: admission keys on the USER, not the credential principal
    // reserved above. The batch path draws the same distinction — it reserves
    // ownership under `credential_principal_id()` and then binds
    // `auth.claims.sub` for `search_with_admission` (handlers/search.rs) — and
    // the two must not drift: ownership has to match what `cancel_search`
    // compares, while the admission caps are per-user, so an analyst holding
    // several API keys shares one budget rather than one per credential.
    let user_id = auth.claims.sub;

    // Create event channel
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<SearchStreamEvent>(64);

    // Check search result cache (Dragonfly/Redis) — on hit, replay as SSE events via channel.
    // Rows are chunked into batches of 1000 to avoid SSE buffer overflow.
    // NAN-1595: skip the read on an explicit refresh (bypass), and capture the
    // entry age so the response can carry `x-nano-cache: hit` + age for the UI.
    // NAN-1799: the lookup below keys on the caller's effective deny-set
    // (composed above, BEFORE the cache read) so differently-scoped users
    // never share a cache entry.
    let mut cache_age: Option<u64> = None;
    let cache_hit = if !bypass {
        if let Some(ref cache) = state.result_cache {
            if let Some(cached) = cache.get(&request, &scope).await {
                record_search_query("stream_cached", 0.0, true);
                cache_age = cache
                    .age_secs(&crate::cache::SearchResultCache::cache_key(&request, &scope))
                    .await;
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
                        // NAN-1597: replay the original query's time so a cached
                        // view shows e.g. "230ms" (paired with the cache-age
                        // badge), not a misleading "0ms".
                        execution_time_ms: cached.execution_time_ms,
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
    let scope_for_cache = scope.clone();
    if !cache_hit {
        let search_service = state.search.clone();
        let event_tx_clone = event_tx.clone();
        let scope_for_search = scope.clone();
        // NAN-2039: route the live stream through admission control (the same
        // boundary the batch `search()` path uses via `search_with_admission`)
        // so parallel SSE searches are bounded by the per-user / global caps
        // and run with the priority's ClickHouse limits — previously
        // `search_streaming` was called directly and bypassed both. Priority is
        // derived exactly as the batch path does.
        let priority = match request.priority.as_deref() {
            Some("analytics") => QueryPriority::Analytics,
            _ => QueryPriority::Interactive,
        };
        tokio::spawn(async move {
            search_service
                .search_streaming_with_admission(
                    request,
                    event_tx_clone,
                    user_id,
                    priority,
                    &scope_for_search,
                )
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
        // NAN-1597: capture the live query's execution time from the Metadata
        // event so it can be persisted into the cached payload (and replayed on
        // a later cache hit) instead of being dropped and stored as 0.
        let mut meta_execution_time_ms: u64 = 0;
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
                        SearchStreamEvent::Metadata { total_count, execution_time_ms, ref fields, ref histogram, ref display_type, ref column_order, ref generated_sql, .. } => {
                            meta_total_count = *total_count;
                            meta_execution_time_ms = *execution_time_ms;
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
                    // NAN-1597: persist the real query time so a later cache hit
                    // replays it instead of "0ms".
                    execution_time_ms: meta_execution_time_ms,
                    fields: meta_fields,
                    generated_sql: meta_generated_sql,
                    histogram: meta_histogram,
                    warnings: None,
                    cost_score: None,
                    display_type: meta_display_type,
                    column_order: meta_column_order,
                };
                let req = request_for_cache;
                let scope = scope_for_cache;
                tokio::spawn(async move {
                    cache.set(&req, &response, &scope).await;
                });
            }
        }

        // Send done event
        yield Ok(Event::default()
            .event("done")
            .data(""));
    };

    // NAN-1595: the frontend reads the stream via fetch + getReader(), so it can
    // read these response headers — surfacing "served from cache + age" even on a
    // shared-link follow (whose client cache is cold).
    Ok((
        crate::cache::cache_status_headers(cache_hit, cache_age),
        Sse::new(stream),
    ))
}
