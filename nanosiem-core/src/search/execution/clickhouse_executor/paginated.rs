// SPDX-License-Identifier: AGPL-3.0-or-later

//! Paginated query execution and SqlExecutor trait implementation
//!
//! High-level methods for executing paginated queries with query IDs, settings,
//! streaming support, and the SqlExecutor trait implementation.

use tokio::sync::mpsc;
use tracing::debug;

use super::super::traits::SqlExecutor;
use super::sql_helpers::{
    build_count_query, escape_question_marks_in_strings, inject_limit_offset, is_aggregation_query,
    wrap_aggregation_with_pagination, wrap_query_for_count, BoundedCountInput,
};
use super::types::ClickHouseExecutor;
use crate::search::{parse_clickhouse_error, SearchError, StreamingChunk};

/// NAN-1645 (finding 3.5): companion queries (count / histogram) only run for
/// the FIRST page of a paginated search.
///
/// The count companion re-scans the full match set and the histogram
/// re-aggregates the full window on every page flip, yet both are
/// page-invariant — page 1 already delivered the exact total and the timeline.
/// The result cache keys include the offset, so nothing absorbs the repeat
/// work. Subsequent pages return [`paged_total_estimate`] instead (mirroring
/// the long-standing `SqlExecutor::execute_sql` no-query-id path) and omit the
/// histogram; the frontend freezes the page-1 values across flips.
///
/// 43155f11's rationale (never pay the count sequentially — run it in parallel
/// with the data query) is preserved: when the companion DOES run (page 1), it
/// still runs under `tokio::join!`.
///
/// Call sites: the count gate in both paginated executor variants below, and
/// the histogram spawn gate in `service/core_search.rs`.
pub(crate) fn is_first_page(offset: usize) -> bool {
    offset == 0
}

/// Total estimate for offset>0 pages, where no count companion ran (NAN-1645).
///
/// A full page signals "there is probably more" — the estimate stays ahead of
/// what the client has so next-page fetches remain enabled. A partial page is
/// definitively the last one, so `offset + returned` is exact.
pub(crate) fn paged_total_estimate(offset: usize, returned: usize, limit: usize) -> u64 {
    if returned >= limit {
        (offset + returned + limit) as u64
    } else {
        (offset + returned) as u64
    }
}

/// Extract and remove the aggregate page's in-band window count. An empty page
/// has no row on which ClickHouse can attach the window value; callers detect
/// `None` and issue the count-only fallback in that exceptional case.
fn take_aggregation_total(results: &mut [serde_json::Value]) -> Option<u64> {
    let total_count = results
        .first()
        .and_then(|row| row.get("_total_count"))
        .and_then(serde_json::Value::as_u64);
    for row in results {
        if let Some(object) = row.as_object_mut() {
            object.remove("_total_count");
        }
    }
    total_count
}

impl ClickHouseExecutor {
    /// Execute a SQL query with a custom query_id for cancellation support
    ///
    /// The query_id is set via the ClickHouse client API (not SETTINGS clause)
    /// which allows tracking and cancellation via KILL QUERY.
    ///
    /// `bounded_count`: caller-supplied bounded input for the count companion
    /// (NAN-1635, finding 2.3) — `None` keeps the unbounded wrap.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_sql_with_query_id(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
        query_id: &str,
        bounded_count: Option<BoundedCountInput<'_>>,
        execution_limits: Option<&crate::search::SearchExecutionLimits>,
        preserve_columns: bool,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        // Check if this is an aggregation query that needs all data
        if is_aggregation_query(sql) {
            debug!(
                "Detected aggregation query with query_id {}, using full scan",
                query_id
            );

            let combined_sql = wrap_aggregation_with_pagination(sql, limit, offset);

            let mut results = if let Some(limits) = execution_limits {
                self.execute_dynamic_query_with_execution_limits(
                    &combined_sql,
                    query_id,
                    None,
                    limits,
                    preserve_columns,
                )
                .await?
            } else {
                self.execute_dynamic_query_with_query_id(&combined_sql, query_id, preserve_columns)
                    .await?
            };

            let total_count = match take_aggregation_total(&mut results) {
                Some(total_count) => total_count,
                None => {
                    // `count(*) OVER()` has nowhere to attach its value when
                    // OFFSET is past the final group. Recount only that empty
                    // exceptional page; normal aggregate pages stay one query.
                    let count_sql = wrap_query_for_count(sql);
                    let count_qid = format!("{query_id}-aggregate-count");
                    self.execute_count_query_with_options(&count_sql, Some(&count_qid), None)
                        .await?
                }
            };

            Ok((results, total_count))
        } else {
            debug!(
                "Detected raw log query with query_id {}, using optimized LIMIT injection",
                query_id
            );

            let paginated_sql = inject_limit_offset(sql, limit, offset);

            if let Some(limits) = execution_limits {
                let results = self
                    .execute_dynamic_query_with_execution_limits(
                        &paginated_sql,
                        query_id,
                        None,
                        limits,
                        preserve_columns,
                    )
                    .await?;
                let total_count = results.len() as u64;
                return Ok((results, total_count));
            }

            // NAN-1645: page flips (offset > 0) skip the count companion — the
            // exact total was already delivered with page 1.
            if !is_first_page(offset) {
                let results = self
                    .execute_dynamic_query_with_query_id(&paginated_sql, query_id, preserve_columns)
                    .await?;
                let total_count = paged_total_estimate(offset, results.len(), limit);
                return Ok((results, total_count));
            }

            // First page: run count in parallel with the data query to avoid
            // sequential latency (43155f11). For a first page with few results
            // (< limit), the count query result is discarded in favor of the
            // exact row count, but the parallel execution avoids the worst case
            // where data finishes fast and count adds 200ms+.
            //
            // NAN-1428: the companion carries the derived `{query_id}-count` id so
            // cancellation kills it together with the data query.
            let count_sql = build_count_query(sql, bounded_count);
            let count_qid = format!("{query_id}-count");
            let (results, count_result) = tokio::join!(
                self.execute_dynamic_query_with_query_id(&paginated_sql, query_id, preserve_columns),
                self.execute_count_query_with_options(&count_sql, Some(&count_qid), None)
            );
            let results = results?;
            let total_count = if results.len() < limit {
                // Got fewer results than requested on the first page — exact count known
                results.len() as u64
            } else {
                count_result.unwrap_or(results.len() as u64)
            };
            Ok((results, total_count))
        }
    }

    /// Execute a paginated SQL query with per-query ClickHouse settings
    ///
    /// `bounded_count`: caller-supplied bounded input for the count companion
    /// (NAN-1635, finding 2.3) — `None` keeps the unbounded wrap.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_sql_with_settings(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
        query_id: &str,
        settings: &crate::search::admission::ClickHouseQuerySettings,
        bounded_count: Option<BoundedCountInput<'_>>,
        execution_limits: Option<&crate::search::SearchExecutionLimits>,
        preserve_columns: bool,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        if is_aggregation_query(sql) {
            debug!("Detected aggregation query with settings, using full scan");

            let combined_sql = wrap_aggregation_with_pagination(sql, limit, offset);

            let mut results = if let Some(limits) = execution_limits {
                self.execute_dynamic_query_with_execution_limits(
                    &combined_sql,
                    query_id,
                    Some(settings),
                    limits,
                    preserve_columns,
                )
                .await?
            } else {
                self.execute_dynamic_query_with_settings(&combined_sql, query_id, settings, preserve_columns)
                    .await?
            };

            let total_count = match take_aggregation_total(&mut results) {
                Some(total_count) => total_count,
                None => {
                    let count_sql = wrap_query_for_count(sql);
                    let count_qid = format!("{query_id}-aggregate-count");
                    self.execute_count_query_with_options(
                        &count_sql,
                        Some(&count_qid),
                        Some(settings),
                    )
                    .await?
                }
            };

            Ok((results, total_count))
        } else {
            debug!("Detected raw log query with settings, using optimized LIMIT injection");

            let paginated_sql = inject_limit_offset(sql, limit, offset);

            if let Some(limits) = execution_limits {
                let results = self
                    .execute_dynamic_query_with_execution_limits(
                        &paginated_sql,
                        query_id,
                        Some(settings),
                        limits,
                        preserve_columns,
                    )
                    .await?;
                let total_count = results.len() as u64;
                return Ok((results, total_count));
            }

            // NAN-1645: page flips (offset > 0) skip the count companion — the
            // exact total was already delivered with page 1.
            if !is_first_page(offset) {
                let results = self
                    .execute_dynamic_query_with_settings(&paginated_sql, query_id, settings, preserve_columns)
                    .await?;
                let total_count = paged_total_estimate(offset, results.len(), limit);
                return Ok((results, total_count));
            }

            // First page: parallel count (43155f11).
            // NAN-1428: derived id + the same per-priority settings for the
            // count companion (settings change no result rows).
            let count_sql = build_count_query(sql, bounded_count);
            let count_qid = format!("{query_id}-count");
            let (results, count_result) = tokio::join!(
                self.execute_dynamic_query_with_settings(&paginated_sql, query_id, settings, preserve_columns),
                self.execute_count_query_with_options(&count_sql, Some(&count_qid), Some(settings))
            );
            let results = results?;
            let total_count = if results.len() < limit {
                results.len() as u64
            } else {
                count_result.unwrap_or(results.len() as u64)
            };
            Ok((results, total_count))
        }
    }

    /// Execute a ClickHouse query and stream result rows through an mpsc channel.
    ///
    /// Instead of collecting all rows in memory, this method parses JSON lines from
    /// each network chunk and sends batches of post-processed rows through the channel.
    /// Rows are batched: sent when 50 rows accumulate or 200ms elapse (whichever first).
    ///
    /// The channel sender is consumed — when all rows have been sent (or an error occurs),
    /// the method returns. The caller should monitor the receiver for `StreamingChunk` values.
    pub async fn execute_dynamic_query_streaming(
        &self,
        sql: &str,
        query_id: &str,
        settings: Option<&crate::search::admission::ClickHouseQuerySettings>,
        chunk_tx: mpsc::Sender<StreamingChunk>,
        preserve_columns: bool,
    ) -> Result<(), SearchError> {
        let escaped_sql = escape_question_marks_in_strings(sql);
        // A grouped query's columns are its answer — keep its empty group-by keys
        // instead of pruning them into a bare count (NAN-1848).
        let strip_empties = !preserve_columns;
        debug!(
            "Executing streaming ClickHouse query with query_id {}: {}",
            query_id,
            &escaped_sql[..escaped_sql.len().min(200)]
        );

        // Build the query with options
        let mut query_builder = self.client.query(&escaped_sql);
        query_builder = query_builder.with_option("query_id", query_id);

        if let Some(settings) = settings {
            query_builder = query_builder
                .with_option(
                    "max_execution_time",
                    &settings.max_execution_time.to_string(),
                )
                .with_option("max_threads", &settings.max_threads.to_string())
                .with_option("priority", &settings.priority.to_string())
                .with_option("queue_max_wait_ms", &settings.queue_max_wait_ms.to_string());
            if let Some(max_memory_usage_bytes) = settings.max_memory_usage_bytes {
                query_builder = query_builder.with_option(
                    "max_memory_usage",
                    &max_memory_usage_bytes.to_string(),
                );
            }
        }

        let mut cursor = query_builder
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // Buffer for partial JSON lines that span chunk boundaries
        let mut line_buffer = String::new();
        // Batch of parsed rows awaiting delivery
        let mut row_batch: Vec<serde_json::Value> = Vec::with_capacity(50);
        let mut last_flush = std::time::Instant::now();
        let mut total_bytes: usize = 0;
        const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024; // 100MB
        const BATCH_SIZE: usize = 50;
        const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);

        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    total_bytes += chunk.len();
                    if total_bytes > MAX_RESPONSE_SIZE {
                        let _ = chunk_tx
                            .send(StreamingChunk::Error(format!(
                                "Response exceeds {}MB limit",
                                MAX_RESPONSE_SIZE / (1024 * 1024)
                            )))
                            .await;
                        return Err(SearchError::ResponseTooLarge(
                            total_bytes,
                            MAX_RESPONSE_SIZE,
                        ));
                    }

                    // Decode chunk and append to line buffer
                    let chunk_str = match std::str::from_utf8(&chunk) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = chunk_tx
                                .send(StreamingChunk::Error(format!(
                                    "Invalid UTF-8 in response: {}",
                                    e
                                )))
                                .await;
                            return Err(SearchError::DatabaseError(sqlx::Error::Protocol(
                                format!("Invalid UTF-8 in ClickHouse response: {}", e),
                            )));
                        }
                    };

                    line_buffer.push_str(chunk_str);

                    // Parse complete lines from the buffer
                    while let Some(newline_pos) = line_buffer.find('\n') {
                        let line = &line_buffer[..newline_pos];
                        if !line.is_empty() {
                            if let Some(row) = Self::parse_and_postprocess_row(line, strip_empties) {
                                row_batch.push(row);
                            }
                        }
                        line_buffer = line_buffer[newline_pos + 1..].to_string();
                    }

                    // Flush batch if size or time threshold met
                    if row_batch.len() >= BATCH_SIZE
                        || (last_flush.elapsed() >= FLUSH_INTERVAL && !row_batch.is_empty())
                    {
                        let batch =
                            std::mem::replace(&mut row_batch, Vec::with_capacity(BATCH_SIZE));
                        if chunk_tx.send(StreamingChunk::Rows(batch)).await.is_err() {
                            // Receiver dropped — client disconnected
                            tracing::info!("Streaming search: client disconnected, aborting");
                            return Ok(());
                        }
                        last_flush = std::time::Instant::now();
                    }
                }
                Ok(None) => {
                    // End of stream — parse any remaining partial line
                    if !line_buffer.is_empty() {
                        let line = line_buffer.trim();
                        if !line.is_empty() {
                            if let Some(row) = Self::parse_and_postprocess_row(line, strip_empties) {
                                row_batch.push(row);
                            }
                        }
                    }
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    tracing::error!("Error reading streaming ClickHouse chunk: {}", error_str);
                    let _ = chunk_tx
                        .send(StreamingChunk::Error(error_str.clone()))
                        .await;
                    return Err(parse_clickhouse_error(&error_str));
                }
            }
        }

        // Flush any remaining rows
        if !row_batch.is_empty() {
            let _ = chunk_tx.send(StreamingChunk::Rows(row_batch)).await;
        }

        debug!("Streaming query complete: {} bytes total", total_bytes);
        Ok(())
    }

    /// Fetch rows for a data query, honoring the caller's column-preservation
    /// contract.
    ///
    /// `execute_sql_to_json` always prunes empty columns — right for the wide raw
    /// event rows its many callers fetch. A grouped query's rows are buckets whose
    /// (possibly empty) group-by key is their identity, so those parse through the
    /// dynamic path with pruning off (NAN-1848).
    async fn fetch_rows(
        &self,
        sql: &str,
        preserve_columns: bool,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        if preserve_columns {
            self.execute_dynamic_query(sql, true).await
        } else {
            self.execute_sql_to_json(sql).await
        }
    }
}

#[cfg(test)]
mod tests;

impl SqlExecutor for ClickHouseExecutor {
    async fn execute_sql(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
        preserve_columns: bool,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        // Check if this is an aggregation query that needs all data
        if is_aggregation_query(sql) {
            // For aggregation queries, use the traditional approach with count(*) OVER()
            // These need all data to produce correct results, so we can't optimize with early LIMIT
            debug!("Detected aggregation query, using full scan with count(*) OVER()");

            let combined_sql = wrap_aggregation_with_pagination(sql, limit, offset);

            let mut results = self.fetch_rows(&combined_sql, preserve_columns).await?;

            let total_count = match take_aggregation_total(&mut results) {
                Some(total_count) => total_count,
                None => {
                    let count_sql = wrap_query_for_count(sql);
                    self.execute_count_query(&count_sql).await?
                }
            };

            Ok((results, total_count))
        } else {
            // For non-aggregation queries (raw log browsing), inject LIMIT directly
            // This allows ClickHouse to stop reading early using the primary key index
            debug!("Detected raw log query, using optimized LIMIT injection");

            let paginated_sql = inject_limit_offset(sql, limit, offset);
            debug!("Paginated SQL: {}", paginated_sql);

            if offset == 0 {
                // First page: run data query and count query in parallel
                // This gives us exact total count while still benefiting from early LIMIT
                let count_sql = build_count_query(sql, None);
                debug!("Count SQL: {}", count_sql);

                let (data_result, count_result) = tokio::join!(
                    self.fetch_rows(&paginated_sql, preserve_columns),
                    self.execute_count_query(&count_sql)
                );

                let results = data_result?;
                let total_count = count_result.unwrap_or(results.len() as u64);

                debug!(
                    "First page: {} results, {} total",
                    results.len(),
                    total_count
                );
                Ok((results, total_count))
            } else {
                // Subsequent pages: just get data
                // The UI already has the total count from the first page
                // Return a high estimate to signal "there might be more"
                let results = self.fetch_rows(&paginated_sql, preserve_columns).await?;
                let estimated_total = paged_total_estimate(offset, results.len(), limit);

                debug!(
                    "Page at offset {}: {} results, estimated total {}",
                    offset,
                    results.len(),
                    estimated_total
                );
                Ok((results, estimated_total))
            }
        }
    }

    async fn execute_sql_to_json(&self, sql: &str) -> Result<Vec<serde_json::Value>, SearchError> {
        // Detect if this is an aggregation query (stats, timechart, etc.)
        // by checking if the SQL contains GROUP BY or aggregation functions
        let sql_upper = sql.to_uppercase();
        let is_aggregation = sql_upper.contains("GROUP BY")
            || sql_upper.contains("COUNT(")
            || sql_upper.contains("SUM(")
            || sql_upper.contains("AVG(")
            || sql_upper.contains("MIN(")
            || sql_upper.contains("MAX(")
            || sql_upper.contains("UNIQ(");

        // Detect if this is a prevalence JOIN query (has extra columns like host_count, is_rare, etc.)
        // These queries use CTEs with domain_prev and hash_prev and add computed columns
        let is_prevalence_join = sql_upper.contains("DOMAIN_PREV")
            || sql_upper.contains("HASH_PREV")
            || sql_upper.contains("HOST_COUNT")
            || sql_upper.contains("IS_RARE")
            || sql_upper.contains("PREVALENCE_SCORE");

        // Detect if this query uses date/time functions that might need all fields
        // Function filters can reference fields stored in the ext JSON column, so we need
        // dynamic parsing to ensure all fields are properly flattened and available
        let has_datetime_functions = sql_upper.contains("DAYOFWEEK(")
            || sql_upper.contains("YEAR(")
            || sql_upper.contains("MONTH(")
            || sql_upper.contains("DAY(")
            || sql_upper.contains("HOUR(")
            || sql_upper.contains("MINUTE(")
            || sql_upper.contains("SECOND(")
            || sql_upper.contains("DATE_ADD(")
            || sql_upper.contains("DATE_SUB(")
            || sql_upper.contains("NOW64(");

        if is_aggregation || is_prevalence_join || has_datetime_functions {
            // For aggregation queries, prevalence JOIN queries, or queries with date/time functions,
            // use dynamic JSON parsing to ensure all fields are properly available
            // Date/time function queries need access to all fields including those in ext JSON
            //
            // NAN-1848: callers here hand over raw SQL (the /search/sql API, OTEL
            // rollups), so there is no AST to ask — `GROUP BY` is the signal that
            // rows are keyed buckets whose (possibly empty) key must survive
            // pruning. A prevalence JOIN decorates raw events rather than grouping
            // them, so those keep the payload pruning.
            let grouped_rows = sql_upper.contains("GROUP BY") && !is_prevalence_join;
            self.execute_dynamic_query(sql, grouped_rows).await
        } else {
            // For full log queries, try the typed struct first, fall back to dynamic
            match self.execute_typed_query(sql).await {
                Ok(results) => Ok(results),
                Err(e) => {
                    // Fall back to dynamic query if typed query fails
                    // This handles cases like table command with subset of columns
                    tracing::debug!("Typed query failed, falling back to dynamic: {}", e);
                    self.execute_dynamic_query(sql, false).await
                }
            }
        }
    }
}
