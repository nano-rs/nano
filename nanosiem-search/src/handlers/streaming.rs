// SPDX-License-Identifier: AGPL-3.0-or-later

//! SSE streaming search endpoint.

use axum::{
    extract::{Extension, State},
    response::sse::{Event, Sse},
    Json,
};
use futures::stream::Stream;
use nanosiem_core::{
    search::{QueryPriority, SearchStreamEvent},
    SearchRequest, SearchResponse,
};
use std::convert::Infallible;

use crate::error::ErrorResponse;
use crate::{error::SearchError, metrics::record_search_query, SearchState};

/// Dropping the HTTP body must drop the executing future, releasing admission
/// and the lake client's cancel-on-drop guards even during a slow hop.
struct StreamSearchTask(tokio::task::JoinHandle<()>);
impl StreamSearchTask { fn abort(&self) { self.0.abort(); } }
impl Drop for StreamSearchTask { fn drop(&mut self) { self.0.abort(); } }


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
/// - `progress`: Rows scanned progress update; on a lean cell, `phase: "cold_scan"`
///   with `cold_bytes_read` / `cold_bytes_total` / `queued` while it fetches
///   uncached data or waits for the reader's heavy cold-read slot
/// - `rows`: A batch of result rows
/// - `view_update`: Cumulative Lateral graph after each hop, before hostname enrichment
/// - `metadata`: Query metadata (total_count, execution_time, fields, histogram, etc.)
/// - `heartbeat`: Follow-stream liveness from the follow loop itself (no tenant data)
/// - `completed`: Search finished successfully
/// - `error`: Search failed
///
/// `x-nano-follow: true` keeps a lean cell log event stream open and emits
/// events committed in later part-log heads. Disconnect or DELETE by request ID
/// ends it. Follow streams bypass the result cache. The first head delivers one
/// page (the request's limit, at most 500); later heads re-read only a short
/// window behind the newest delivered event in shallow time-fenced
/// pages, retrying smaller after a transient refusal. A `heartbeat`
/// event is sent whenever the follow has sent nothing for 10 s. The stream
/// ends with `completed` after 30 minutes; clients reconnect.
#[utoipa::path(
    post,
    path = "/api/search/stream",
    tag = "search",
    request_body = SearchRequest,
    security(("bearer_auth" = []), ("api_key" = [])),
    responses(
        (status = 200, description = "SSE stream of search results"),
        (status = 400, description = "Invalid query", body = ErrorResponse),
        (status = 422, description = "Too large to run interactively (COLD_SCAN_TOO_LARGE): one pass would stage more uncached data than the tenant reader's cold-read ceiling (derived from its cache size). Body carries needed_bytes and ceiling_bytes, plus background_ceiling_bytes when an async search could run it. A cold read under the ceiling is never refused: it queues for the reader's heavy cold-read slot and the stream reports progress events with phase cold_scan.", body = ErrorResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing search:execute permission", body = ErrorResponse),
    )
)]
pub async fn search_stream(
    State(state): State<SearchState>,
    Extension(auth): Extension<crate::AuthContext>,
    crate::cache::CacheBypass(bypass): crate::cache::CacheBypass,
    headers: axum::http::HeaderMap,
    Json(mut request): Json<SearchRequest>,
) -> Result<
    (
        axum::http::HeaderMap,
        Sse<impl Stream<Item = Result<Event, Infallible>>>,
    ),
    SearchError,
> {
    // NAN-2030: authN (a valid token) is not authZ — gate the SSE search path on
    // search:execute before any work, exactly like POST /api/search. This path
    // was authenticated but UNAUTHORIZED (a parity gap vs. the batch `search`).
    super::require_search_execute(&auth)?;
    let follow = headers.get("x-nano-follow").is_some_and(|value| value == "true");

    // NAN-1799: compose the effective deny-set (per-user source scope ∪ audit
    // gate) ONCE, before the cache lookup below — the scope is folded into
    // the cache key, and the service injects the exclusion into the executed
    // SQL. This replaces the old `enforce_non_audit_query` rewrite of
    // request.query.
    let scope = super::search::effective_scope(&auth);
    let tenant_search = state.search_with_ai_for_auth(&auth)?;
    // NAN-3018: same tenant-bound `dataset=risk` view as POST /api/search.
    let tenant_search = state
        .bind_shared_risk_dataset(&auth, request.dataset.as_deref(), tenant_search)
        .await?;
    // Live clear state: shared risk results never use the result cache.
    let risk_uncached = tenant_search.tenant_risk_dataset_bound();
    let bypass = bypass || risk_uncached;
    // NAN-2922: the shared nPL contract is checked against the resolved view,
    // so `| ai` is admitted only when it is tenant-billed.
    super::require_shared_npl_contract_for_view(
        &auth,
        &request.query,
        request.dataset.as_deref(),
        &tenant_search,
    )?;

    if let Some(request_id) = request.request_id.clone() {
        // NAN-2100: reserve under the CREDENTIAL (api-key id, or user id for
        // an interactive session) — `cancel_search` compares the same
        // principal. Shares the batch path's helper so the two entry points
        // cannot drift on the identity they record.
        request.request_id =
            Some(super::search::reserve_query_owner(&state, request_id, &auth).await?);
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
    // NAN-2361 wave 6: shared tenants key the cache on the serving generation.
    let serving_generation = if !follow && crate::is_shared_scope(auth.tenant_scope) && state.result_cache.is_some() {
        tenant_search.serving_generation_key().await
    } else {
        None
    };
    let cache_hit = if !bypass && !follow {
        if let Some(ref cache) = state.result_cache {
            if let Some(cached) = cache
                .get_for(auth.tenant_scope, &request, &scope, serving_generation.as_ref())
                .await
            {
                record_search_query("stream_cached", 0.0, true);
                cache_age = cache
                    .age_secs(&crate::cache::SearchResultCache::cache_key_for(
                        auth.tenant_scope,
                        &request,
                        &scope,
                        serving_generation.as_ref(),
                    ))
                    .await;
                let tx = event_tx.clone();
                let total_row_count = cached.results.len() as u64;
                tokio::spawn(async move {
                    const REPLAY_BATCH_SIZE: usize = 1000;
                    let mut cumulative: u64 = 0;
                    for (batch_index, chunk) in cached.results.chunks(REPLAY_BATCH_SIZE).enumerate()
                    {
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
                            completeness: cached.completeness,
                            total_count: cached.total_count,
                            total_count_exact: cached.total_count_exact,
                            // NAN-1597: replay the original query's time so a cached
                            // view shows e.g. "230ms" (paired with the cache-age
                            // badge), not a misleading "0ms".
                            execution_time_ms: cached.execution_time_ms,
                            fields: cached.fields,
                            histogram: cached.histogram,
                            warnings: cached.warnings,
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
    let cache_for_task = if cache_hit || follow || risk_uncached {
        None
    } else {
        state.result_cache.clone()
    };
    let request_for_cache = request.clone();
    let scope_for_cache = scope.clone();
    let tenant_for_cache = auth.tenant_scope;
    let generation_for_cache = serving_generation.clone();
    let mut search_task = if !cache_hit {
        let search_service = tenant_search.clone();
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
        Some(StreamSearchTask(tokio::spawn(nanosiem_core::search::request_actor::inherit(async move {
            search_service
                .search_streaming_with_admission(
                    request,
                    event_tx_clone,
                    user_id,
                    priority,
                    &scope_for_search,
                    follow,
                )
                .await;
        }))))
    } else {
        None
    };
    // Drop our sender so the channel closes when the spawned task finishes
    drop(event_tx);

    // Read streaming cache cap from hot-reloadable query safety settings
    let max_cache_rows: usize = if follow {
        0
    } else {
        tenant_search
            .query_limits()
            .read()
            .await
            .max_streaming_cache_rows as usize
    };

    // Build SSE stream from event channel with keepalive
    // Also collect rows + metadata for caching after completion
    let keepalive_interval = std::time::Duration::from_secs(15);
    let stream_auth = auth.clone();
    let stream_auth_state = state.auth_state.clone();
    let stream = async_stream::stream! {
        let mut interval = tokio::time::interval(keepalive_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut all_rows: Vec<serde_json::Value> = Vec::new();
        let mut cache_overflow = false;
        let mut meta_total_count: u64 = 0;
        // NAN-2550: conservative until the metadata event says otherwise.
        let mut meta_total_count_exact = false;
        // NAN-1597: capture the live query's execution time from the Metadata
        // event so it can be persisted into the cached payload (and replayed on
        // a later cache hit) instead of being dropped and stored as 0.
        let mut meta_execution_time_ms: u64 = 0;
        let mut meta_fields: Vec<nanosiem_core::search::FieldInfo> = Vec::new();
        let mut meta_histogram: Option<Vec<nanosiem_core::search::HistogramBucket>> = None;
        let mut meta_display_type: Option<nanosiem_core::search::DisplayType> = None;
        let mut meta_column_order: Option<Vec<String>> = None;
        let mut meta_generated_sql: Option<String> = None;
        let mut meta_completeness = None;
        let mut meta_warnings = None;
        let mut completed_ok = false;

        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    let releases_tenant_data = matches!(
                        &event,
                        SearchStreamEvent::Rows { .. }
                            | SearchStreamEvent::ViewUpdate { .. }
                            | SearchStreamEvent::Metadata { .. }
                            | SearchStreamEvent::Completed { .. }
                    );
                    let authority = if releases_tenant_data {
                        crate::middleware::revalidate_shared_context(
                            &stream_auth_state,
                            &stream_auth,
                        )
                        .await.into_result()
                    } else {
                        Ok(())
                    };
                    if let Err(error) = authority {
                        if let Some(task) = search_task.take() {
                            task.abort();
                        }
                        let denied = SearchStreamEvent::Error {
                            code: if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                                "AUTHORITY_REVOKED"
                            } else {
                                error.code()
                            }.to_string(),
                            message: if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                                "Search authority is no longer current".to_string()
                            } else {
                                error.public_message()
                            },
                        };
                        yield Ok(Event::default()
                            .event("error")
                            .data(serde_json::to_string(&denied).unwrap_or_default()));
                        break;
                    }
                    let (event_type, is_terminal) = match &event {
                        SearchStreamEvent::Queued { .. } => ("queued", false),
                        SearchStreamEvent::Started { .. } => ("started", false),
                        SearchStreamEvent::Progress { .. } | SearchStreamEvent::ColdScanProgress { .. } => ("progress", false),
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
                        SearchStreamEvent::ViewUpdate { .. } => ("view_update", false),
                        SearchStreamEvent::Heartbeat { .. } => ("heartbeat", false),
                        SearchStreamEvent::Metadata { total_count, total_count_exact, execution_time_ms, ref fields, ref histogram, ref display_type, ref column_order, ref generated_sql, ref completeness, ref warnings, .. } => {
                            meta_total_count = *total_count;
                            meta_total_count_exact = *total_count_exact;
                            meta_execution_time_ms = *execution_time_ms;
                            meta_fields = fields.clone();
                            meta_histogram = histogram.clone();
                            meta_display_type = display_type.clone();
                            meta_column_order = column_order.clone();
                            meta_generated_sql = generated_sql.clone();
                            meta_completeness = completeness.clone();
                            meta_warnings = warnings.clone();
                            ("metadata", false)
                        }
                        SearchStreamEvent::Completed { .. } => {
                            completed_ok = true;
                            ("completed", true)
                        }
                        SearchStreamEvent::Error { .. } | SearchStreamEvent::ColdScanError { .. } => ("error", true),
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
                    if let Err(error) = crate::middleware::revalidate_shared_context(
                        &stream_auth_state,
                        &stream_auth,
                    )
                    .await.into_result()
                    {
                        if let Some(task) = search_task.take() {
                            task.abort();
                        }
                        let denied = SearchStreamEvent::Error {
                            code: if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                                "AUTHORITY_REVOKED"
                            } else {
                                error.code()
                            }.to_string(),
                            message: if error.status_code() == axum::http::StatusCode::FORBIDDEN {
                                "Search authority is no longer current".to_string()
                            } else {
                                error.public_message()
                            },
                        };
                        yield Ok(Event::default()
                            .event("error")
                            .data(serde_json::to_string(&denied).unwrap_or_default()));
                        break;
                    }
                    yield Ok(Event::default().comment("keepalive"));
                }
                else => {
                    // Channel closed without terminal event
                    break;
                }
            }
        }

        // Cache the result in the background on successful completion (skip if too large)
        if completed_ok && !cache_overflow && !follow {
            if crate::middleware::revalidate_shared_context(
                &stream_auth_state,
                &stream_auth,
            )
            .await.into_result().is_ok()
            {
              if let Some(cache) = cache_for_task {
                let response = SearchResponse {
                    server_wall_ms: None,
                    results: all_rows,
                    total_count: meta_total_count,
                    total_count_exact: meta_total_count_exact,
                    // NAN-1597: persist the real query time so a later cache hit
                    // replays it instead of "0ms".
                    execution_time_ms: meta_execution_time_ms,
                    fields: meta_fields,
                    generated_sql: meta_generated_sql,
                    histogram: meta_histogram,
                    warnings: meta_warnings,
                    cost_score: None,
                    display_type: meta_display_type,
                    column_order: meta_column_order,
                    completeness: meta_completeness,
                };
                let req = request_for_cache;
                let scope = scope_for_cache;
                let generation = generation_for_cache.clone();
                tokio::spawn(async move {
                    cache
                        .set_for(tenant_for_cache, &req, &response, &scope, generation.as_ref())
                        .await;
                });
              }
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

#[cfg(test)]
mod stream_drop_tests {
    use super::*;
    #[tokio::test]
    async fn dropping_stream_task_releases_its_running_future() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        struct Released(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Released { fn drop(&mut self) { if let Some(tx) = self.0.take() { let _ = tx.send(()); } } }
        let task = StreamSearchTask(tokio::spawn(async move {
            let _release = Released(Some(tx));
            std::future::pending::<()>().await;
        }));
        tokio::task::yield_now().await;
        drop(task);
        tokio::time::timeout(std::time::Duration::from_secs(1), rx).await.unwrap().unwrap();
    }
}
