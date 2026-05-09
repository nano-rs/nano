// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

impl SearchService {
    /// Execute a streaming search, sending events through an mpsc channel.
    ///
    /// For streamable queries (non-aggregate, no lookup/prevalence/tree/asset post-processing),
    /// rows are sent incrementally as ClickHouse returns them. For non-streamable queries,
    /// the full search is executed and all rows are delivered in a single batch.
    ///
    /// Progress events are sent periodically by polling ClickHouse system.processes.
    /// The caller receives `SearchStreamEvent` variants and should forward them as SSE events.
    pub async fn search_streaming(
        &self,
        request: SearchRequest,
        event_tx: tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
    ) {
        use crate::search::streaming::{is_query_streamable, SearchStreamEvent};

        let start_time = Instant::now();
        let query_id = request
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let job_id = uuid::Uuid::now_v7().to_string();

        // Register for cancellation
        if request.request_id.is_some() {
            self.query_tracker
                .register(request.request_id.clone().unwrap(), query_id.clone());
        }

        // Helper to send an event, returning false if receiver disconnected
        macro_rules! send_event {
            ($event:expr) => {
                if event_tx.send($event).await.is_err() {
                    tracing::info!("Streaming search: client disconnected");
                    if let Some(ref req_id) = request.request_id {
                        self.query_tracker.unregister(req_id);
                    }
                    let _ = self.cancel_query(&query_id).await;
                    return;
                }
            };
        }

        // Validate time range
        if let Err(e) = request.time_range.validate() {
            send_event!(SearchStreamEvent::Error {
                code: "VALIDATION_ERROR".to_string(),
                message: e.to_string(),
            });
            return;
        }

        // Extract time modifiers and parse query
        let (cleaned_query, earliest_offset, latest_offset) =
            extract_time_modifiers(&request.query);
        let mut adjusted_time_range = request.time_range.clone();
        if let Some(offset_secs) = earliest_offset {
            adjusted_time_range.start = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        }
        if let Some(offset_secs) = latest_offset {
            adjusted_time_range.end = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        }

        let query = match parse_query(&cleaned_query) {
            Ok(q) => q,
            Err(e) => {
                send_event!(SearchStreamEvent::Error {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("{}", e),
                });
                return;
            }
        };

        // Pre-execution guardrail: reject queries that would cause unbounded memory usage (OOM)
        if let Some(risk) = detect_oom_risk(&query) {
            send_event!(SearchStreamEvent::Error {
                code: "VALIDATION_ERROR".to_string(),
                message: risk.message(),
            });
            return;
        }

        // Analyze query for streamability
        let lookup_commands = extract_lookup_commands(&query);
        let inputlookup_commands = extract_inputlookup_commands(&query);
        let prevalence_commands = extract_prevalence_commands(&query);
        let tree_command = extract_tree_command(&query);
        let asset_command = extract_asset_command(&query);
        let cloud_command = extract_cloud_command(&query);
        let ai_command = extract_ai_command(&query);
        let lateral_command = extract_lateral_command(&query);
        let funnel_command = extract_funnel_command(&query);

        let streamable = is_query_streamable(
            &query,
            !lookup_commands.is_empty(),
            !inputlookup_commands.is_empty(),
            !prevalence_commands.is_empty(),
            tree_command.is_some(),
            asset_command.is_some(),
            cloud_command.is_some(),
            ai_command.is_some(),
            lateral_command.is_some(),
            funnel_command.is_some(),
        );

        let display_type = determine_display_type(&query);
        let column_order = get_column_order(&query);

        // Send started event
        send_event!(SearchStreamEvent::Started {
            job_id: job_id.clone(),
            query_id: query_id.clone(),
            is_streaming: streamable,
        });

        if streamable && self.backend == SearchBackend::ClickHouse && self.ch_executor.is_some() {
            // ===== STREAMING PATH: Non-aggregate queries =====
            self.execute_streaming_path(
                &request,
                &query,
                &cleaned_query,
                &adjusted_time_range,
                &query_id,
                &event_tx,
                start_time,
                display_type,
                column_order,
            )
            .await;
        } else {
            // ===== BUFFERED PATH: Aggregate / enriched queries =====
            // Execute full search and deliver all results at once
            self.execute_buffered_path(
                request.clone(),
                &query,
                &cleaned_query,
                &adjusted_time_range,
                &query_id,
                &event_tx,
                start_time,
                display_type,
                column_order,
            )
            .await;
        }

        // Unregister from tracker
        if let Some(ref req_id) = request.request_id {
            self.query_tracker.unregister(req_id);
        }
    }

    /// Spawn a background task that polls ClickHouse `system.processes` every 500ms
    /// and sends `SearchStreamEvent::Progress` through the given channel.
    /// Returns a `JoinHandle` — caller should `.abort()` it when the query finishes.
    fn spawn_progress_poller(
        ch_client: Option<clickhouse::Client>,
        query_id: &str,
        progress_tx: tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
    ) -> tokio::task::JoinHandle<()> {
        use crate::search::streaming::SearchStreamEvent;

        // Validate query_id is alphanumeric/hyphens only (UUIDs) to prevent SQL injection
        let safe_qid: String = query_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            interval.tick().await; // Skip immediate tick

            loop {
                interval.tick().await;

                if let Some(ref client) = ch_client {
                    let progress_sql = format!(
                        "SELECT read_rows, total_rows_approx, elapsed \
                         FROM system.processes WHERE query_id = '{}'",
                        safe_qid
                    );
                    if let Ok(mut cursor) = client.query(&progress_sql).fetch_bytes("JSONEachRow") {
                        let mut bytes = Vec::new();
                        while let Ok(Some(chunk)) = cursor.next().await {
                            bytes.extend_from_slice(&chunk);
                        }
                        if let Ok(text) = String::from_utf8(bytes) {
                            if let Some(line) = text.lines().next() {
                                if let Ok(row) = serde_json::from_str::<serde_json::Value>(line) {
                                    let rows_scanned =
                                        row.get("read_rows").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let rows_total = row
                                        .get("total_rows_approx")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let elapsed =
                                        row.get("elapsed").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    let percent = if rows_total > 0 {
                                        ((rows_scanned as f64 / rows_total as f64) * 100.0)
                                            .min(99.0) as u8
                                    } else {
                                        0
                                    };

                                    if progress_tx
                                        .send(SearchStreamEvent::Progress {
                                            rows_scanned,
                                            rows_total,
                                            percent,
                                            elapsed_ms: (elapsed * 1000.0) as u64,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        // Receiver dropped — stop polling
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Streaming execution path: sends result rows incrementally as ClickHouse returns them.
    ///
    /// Splits the time range into daily chunks (newest first) matching ClickHouse's
    /// `toYYYYMMDD(timestamp)` partitions. Each single-partition query sorts quickly
    /// and streams rows immediately instead of buffering the full ORDER BY across the
    /// entire time range.
    async fn execute_streaming_path(
        &self,
        request: &SearchRequest,
        query: &crate::query::Query,
        cleaned_query: &str,
        adjusted_time_range: &TimeRangeInput,
        query_id: &str,
        event_tx: &tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        start_time: Instant,
        display_type: DisplayType,
        column_order: Option<Vec<String>>,
    ) {
        use crate::query::QueryOptions;
        use crate::search::streaming::{compute_daily_chunks, SearchStreamEvent, StreamingChunk};

        let ch_executor = match self.ch_executor.as_ref() {
            Some(e) => e,
            None => {
                let _ = event_tx
                    .send(SearchStreamEvent::Error {
                        code: "CONFIG_ERROR".to_string(),
                        message: "ClickHouse not configured".to_string(),
                    })
                    .await;
                return;
            }
        };

        let is_aggregation = query_has_aggregation(query);

        let limit = if is_aggregation {
            // Aggregation output rows (GROUP BY groups) — use a high cap.
            // The CTE base stage scans all events regardless; this limits output rows only.
            1_000_000
        } else {
            request
                .limit
                .unwrap_or(self.config.default_limit)
                .min(self.config.max_limit)
        };
        let options = QueryOptions {
            use_cache: request.use_cache,
            table_view: request.table_view,
            limit: Some(limit),
        };

        let full_time_range =
            crate::query::TimeRange::new(adjusted_time_range.start, adjusted_time_range.end);

        // For non-aggregate queries, run a count query in parallel so metadata
        // reports the real total. For aggregation, the total is the row count
        // of the streamed output (number of groups).
        let count_handle = if !is_aggregation {
            let count_sql = self
                .ch_sql_generator
                .generate_with_options(query, &full_time_range, &options)
                .ok();
            let count_executor = ch_executor.clone();
            Some(tokio::spawn(async move {
                if let Some(sql) = count_sql {
                    count_executor.quick_count(&sql).await.ok()
                } else {
                    None
                }
            }))
        } else {
            None
        };

        // Start histogram query in parallel with chunk streaming — it only needs
        // the base query and full time range, so it can run independently.
        let histogram_handle = if !request.skip_histogram {
            let search_service = self.clone();
            let histogram_query = cleaned_query.to_string();
            let histogram_time_range = adjusted_time_range.clone();
            Some(tokio::spawn(async move {
                match search_service
                    .generate_histogram(&histogram_query, &histogram_time_range)
                    .await
                {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("Parallel histogram query failed: {}", e);
                        None
                    }
                }
            }))
        } else {
            None
        };

        let mut batch_index: u32 = 0;
        let mut cumulative_count: u64 = 0;
        let mut chunks_queried: usize = 0;

        // Aggregation queries run a single query across the full time range —
        // daily chunking would produce partial aggregates.
        // Non-aggregate queries split into daily chunks for partition-aligned streaming.
        let chunk_ranges: Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
            if is_aggregation {
                vec![(adjusted_time_range.start, adjusted_time_range.end)]
            } else {
                compute_daily_chunks(adjusted_time_range.start, adjusted_time_range.end)
            };

        for (chunk_idx, (chunk_start, chunk_end)) in chunk_ranges.iter().enumerate() {
            let remaining = limit.saturating_sub(cumulative_count as usize);
            if remaining == 0 {
                break;
            }
            chunks_queried += 1;

            // Generate SQL for this chunk's time range
            let chunk_time_range = crate::query::TimeRange::new(*chunk_start, *chunk_end);
            let chunk_sql = match self.ch_sql_generator.generate_with_options(
                query,
                &chunk_time_range,
                &options,
            ) {
                Ok(s) => s,
                Err(e) => {
                    let _ = event_tx
                        .send(SearchStreamEvent::Error {
                            code: "SQL_GEN_ERROR".to_string(),
                            message: e.to_string(),
                        })
                        .await;
                    return;
                }
            };

            // Inject per-chunk LIMIT with offset=0.  Streaming delivers rows
            // newest-first across partition chunks, so the global request.offset
            // is intentionally not applied here (offset-based pagination is only
            // meaningful for the non-streaming path).
            let paginated_sql = if is_aggregation {
                // Aggregation SQL already has its own structure (CTE with GROUP BY);
                // don't inject LIMIT — ClickHouse streams the grouped output directly.
                chunk_sql.clone()
            } else {
                debug_assert!(
                    request.offset.unwrap_or(0) == 0,
                    "streaming path does not support offset-based pagination"
                );
                super::execution::clickhouse_executor::inject_limit_offset(
                    &chunk_sql, remaining, 0,
                )
            };

            // Each chunk gets a unique query_id for cancellation/progress tracking
            let chunk_qid = format!("{}-chunk-{}", query_id, chunk_idx);

            // Spawn progress polling for this chunk
            let progress_handle =
                Self::spawn_progress_poller(self.ch_client.clone(), &chunk_qid, event_tx.clone());

            // Create channel for streaming chunks from executor
            let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<StreamingChunk>(32);

            // Spawn the ClickHouse streaming executor for this chunk
            let executor = ch_executor.clone();
            let sql_clone = paginated_sql.clone();
            let qid_clone = chunk_qid.clone();
            let settings = self.active_ch_settings.clone();
            let exec_handle = tokio::spawn(async move {
                executor
                    .execute_dynamic_query_streaming(
                        &sql_clone,
                        &qid_clone,
                        settings.as_ref(),
                        chunk_tx,
                    )
                    .await
            });

            // Forward streaming chunks as SSE events
            let mut chunk_errored = false;
            while let Some(chunk) = chunk_rx.recv().await {
                match chunk {
                    StreamingChunk::Rows(rows) => {
                        let count = rows.len() as u64;
                        cumulative_count += count;
                        if event_tx
                            .send(SearchStreamEvent::Rows {
                                rows,
                                batch_index,
                                cumulative_count,
                            })
                            .await
                            .is_err()
                        {
                            // Client disconnected — abort
                            progress_handle.abort();
                            exec_handle.abort();
                            let _ = ch_executor.cancel_query(&chunk_qid).await;
                            return;
                        }
                        batch_index += 1;
                    }
                    StreamingChunk::Error(msg) => {
                        let _ = event_tx
                            .send(SearchStreamEvent::Error {
                                code: "QUERY_ERROR".to_string(),
                                message: msg,
                            })
                            .await;
                        progress_handle.abort();
                        chunk_errored = true;
                        break;
                    }
                }
            }

            // Clean up this chunk's progress poller and executor
            progress_handle.abort();
            if chunk_errored {
                return;
            }
            if let Ok(Err(e)) = exec_handle.await {
                let _ = event_tx
                    .send(SearchStreamEvent::Error {
                        code: "QUERY_ERROR".to_string(),
                        message: e.to_string(),
                    })
                    .await;
                return;
            }

            // If we've hit the limit, stop querying further chunks
            if cumulative_count as usize >= limit {
                break;
            }
        }

        // Detect if we stopped early (didn't query all chunks) due to LIMIT
        let chunks_queried_all = is_aggregation || chunks_queried >= chunk_ranges.len();

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // For non-aggregate queries, use the parallel count query result.
        // For aggregation, the total is just how many groups were streamed.
        let real_total = if let Some(handle) = count_handle {
            handle
                .await
                .ok()
                .flatten()
                .unwrap_or(cumulative_count)
                .min(self.config.max_limit as u64)
        } else {
            cumulative_count
        };

        // Collect histogram from the parallel task spawned before chunk streaming
        let histogram = if let Some(handle) = histogram_handle {
            handle.await.ok().flatten()
        } else {
            None
        };

        // Analyze query cost and merge with runtime warnings
        let cost_analysis = crate::query::analyze_query_cost(query);
        let mut all_warnings: Vec<QueryWarningOutput> = cost_analysis
            .warnings
            .iter()
            .map(|w| QueryWarningOutput {
                severity: match w.severity {
                    WarningSeverity::Info => "info".to_string(),
                    WarningSeverity::Warning => "warning".to_string(),
                    WarningSeverity::Error => "error".to_string(),
                },
                code: w.code.clone(),
                message: w.message.clone(),
                suggestion: w.suggestion.clone(),
                impact: w.impact.clone(),
            })
            .collect();

        // See `should_emit_partial_time_range_warning` for rationale.
        if should_emit_partial_time_range_warning(
            chunks_queried_all,
            cumulative_count,
            self.config.max_limit,
        ) {
            let total_chunks = chunk_ranges.len();
            let oldest_covered = chunk_ranges
                .iter()
                .take(chunks_queried)
                .last()
                .map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_default();
            let requested_start = adjusted_time_range.start.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            all_warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "PARTIAL_TIME_RANGE".to_string(),
                message: format!(
                    "Query matched more than {} rows (the maximum). Scanned {} of {} daily partitions \
                     before hitting the cap. Only data from {} onward is included; the requested range \
                     started at {}.",
                    self.config.max_limit, chunks_queried, total_chunks, oldest_covered, requested_start
                ),
                suggestion: Some(
                    "Narrow the time range or add filters to scan the full requested range".to_string()
                ),
                impact: Some(
                    "Events from older days in the requested time range were not searched".to_string()
                ),
            });
        }

        let (warnings_output, cost_score) = if all_warnings.is_empty() {
            (None, None)
        } else {
            (Some(all_warnings), Some(cost_analysis.estimated_cost))
        };

        // Send metadata with real total (not just delivered rows)
        let _ = event_tx
            .send(SearchStreamEvent::Metadata {
                total_count: real_total,
                execution_time_ms,
                fields: Vec::new(), // Field stats calculated separately
                histogram,
                warnings: warnings_output,
                cost_score,
                display_type: Some(display_type),
                column_order,
                generated_sql: None,
            })
            .await;

        // Send completed
        let _ = event_tx
            .send(SearchStreamEvent::Completed {
                total_rows_delivered: cumulative_count,
            })
            .await;
    }

    /// Buffered execution path: runs the full search and delivers all results at once via SSE.
    async fn execute_buffered_path(
        &self,
        request: SearchRequest,
        _query: &crate::query::Query,
        _cleaned_query: &str,
        _adjusted_time_range: &TimeRangeInput,
        query_id: &str,
        event_tx: &tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        _start_time: Instant,
        _display_type: DisplayType,
        _column_order: Option<Vec<String>>,
    ) {
        use crate::search::streaming::SearchStreamEvent;

        // Spawn progress polling for this query too
        let progress_handle =
            Self::spawn_progress_poller(self.ch_client.clone(), query_id, event_tx.clone());

        // Execute full search
        let result = self.search(request).await;
        progress_handle.abort();

        match result {
            Ok(response) => {
                let row_count = response.results.len() as u64;

                // Send all rows in one batch
                if !response.results.is_empty() {
                    if event_tx
                        .send(SearchStreamEvent::Rows {
                            rows: response.results,
                            batch_index: 0,
                            cumulative_count: row_count,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }

                // Send metadata
                let _ = event_tx
                    .send(SearchStreamEvent::Metadata {
                        total_count: response.total_count,
                        execution_time_ms: response.execution_time_ms,
                        fields: response.fields,
                        histogram: response.histogram,
                        warnings: response.warnings,
                        cost_score: response.cost_score,
                        display_type: response.display_type,
                        column_order: response.column_order,
                        generated_sql: response.generated_sql,
                    })
                    .await;

                // Send completed
                let _ = event_tx
                    .send(SearchStreamEvent::Completed {
                        total_rows_delivered: row_count,
                    })
                    .await;
            }
            Err(e) => {
                let _ = event_tx
                    .send(SearchStreamEvent::Error {
                        code: "QUERY_ERROR".to_string(),
                        message: e.to_string(),
                    })
                    .await;
            }
        }
    }
}

/// Gate for the `PARTIAL_TIME_RANGE` warning.
///
/// The warning fires only when the scan stopped before covering every daily
/// partition *and* the row accumulator reached the global `max_limit` ceiling.
/// Early-exit that merely fills a smaller `request.limit` is not surfaced:
/// streaming reads newest partition first with `ORDER BY timestamp DESC`, so
/// the returned rows are the newest N matches in the range by definition,
/// and `total_count` metadata already reports the true total.
fn should_emit_partial_time_range_warning(
    chunks_queried_all: bool,
    cumulative_count: u64,
    max_limit: usize,
) -> bool {
    !chunks_queried_all && cumulative_count as usize >= max_limit
}

#[cfg(test)]
mod tests {
    use super::should_emit_partial_time_range_warning as gate;

    const MAX: usize = 1_000_000;

    #[test]
    fn no_warning_when_ui_page_size_filled_from_newest_partition() {
        // User asked for 50, backend stopped after today's partition had 50.
        // Not all chunks queried, but cumulative is far below max_limit.
        assert!(!gate(false, 50, MAX));
    }

    #[test]
    fn no_warning_when_all_chunks_scanned() {
        // Every partition was scanned even if cumulative happened to hit max.
        // `chunks_queried_all` is true → never truncated the range.
        assert!(!gate(true, MAX as u64, MAX));
        assert!(!gate(true, 0, MAX));
    }

    #[test]
    fn warning_when_scan_hits_max_limit_and_range_incomplete() {
        // Genuinely broad query: cap reached, older partitions skipped.
        assert!(gate(false, MAX as u64, MAX));
    }

    #[test]
    fn no_warning_just_below_max_limit() {
        // Boundary: cumulative one row short of max does not trip the gate.
        assert!(!gate(false, (MAX - 1) as u64, MAX));
    }

    #[test]
    fn warning_when_cumulative_exceeds_max_limit() {
        // Should never happen in practice (per-chunk LIMIT caps scanning),
        // but if cumulative somehow exceeds max, still fire the warning.
        assert!(gate(false, (MAX + 1) as u64, MAX));
    }

    #[test]
    fn aggregation_path_never_warns() {
        // Aggregation sets chunks_queried_all=true unconditionally
        // (see execute_streaming_path) so this branch is unreachable for it.
        assert!(!gate(true, u64::MAX, MAX));
    }
}
