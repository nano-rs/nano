// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query management: cancellation, progress tracking, and quick counts
//!
//! Methods for monitoring and controlling running ClickHouse queries.

use tracing::{debug, info};

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::ClickHouseExecutor;
use crate::search::{parse_clickhouse_error, SearchError};
use crate::sql_hygiene::escape_sql_string;

impl ClickHouseExecutor {
    /// Cancel a running query by its query_id
    ///
    /// Returns true if a query was found and killed, false if no matching query was running.
    /// Uses KILL QUERY SYNC to wait for the query to actually stop.
    pub async fn cancel_query(&self, query_id: &str) -> Result<bool, SearchError> {
        let ids = [query_id.to_string()];
        self.cancel_queries(&ids).await
    }

    /// Cancel a set of running queries by their EXACT query_ids in one round trip.
    ///
    /// NAN-1428: one search fans out to a data query plus derived companions
    /// (`{id}-count` / `{id}-hist` / `{id}-fstats`); cancel must kill all of
    /// them. Exact-match `IN` is used deliberately instead of a
    /// `LIKE '{id}%'` pattern — client-provided request ids can legitimately
    /// contain `%`/`_`, which would wildcard a LIKE and kill unrelated queries.
    ///
    /// Returns true if at least one of the queries was found running and killed.
    pub async fn cancel_queries(&self, query_ids: &[String]) -> Result<bool, SearchError> {
        if query_ids.is_empty() {
            return Ok(false);
        }

        // Escape single quotes in each id to prevent SQL injection
        let id_list = query_ids
            .iter()
            .map(|id| format!("'{}'", escape_sql_string(id)))
            .collect::<Vec<_>>()
            .join(", ");

        // Check if any of the queries are still running
        let check_sql = format!(
            "SELECT count() as cnt FROM system.processes WHERE query_id IN ({})",
            id_list
        );

        debug!("Checking if queries are running: {}", check_sql);

        let mut cursor = self
            .client
            .query(&check_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        // Propagate a mid-stream Err instead of treating it as EOF — a failed
        // check would otherwise read as "not running" and silently skip the KILL.
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => return Err(parse_clickhouse_error(&e.to_string())),
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in cancel check response: {}",
                e
            )))
        })?;

        let running_count = response_str
            .lines()
            .next()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|v| v.get("cnt")?.as_u64())
            .unwrap_or(0);

        if running_count == 0 {
            debug!("None of the queries {:?} are running", query_ids);
            return Ok(false);
        }

        // Kill all matching queries synchronously
        let kill_sql = format!("KILL QUERY WHERE query_id IN ({}) SYNC", id_list);
        info!("Killing {} running queries: {}", running_count, kill_sql);

        self.client
            .query(&kill_sql)
            .execute()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        info!("Successfully killed queries {:?}", query_ids);
        Ok(true)
    }

    /// Get progress of a running query from system.processes
    ///
    /// Returns progress info if the query is found and running, None otherwise.
    pub async fn get_query_progress(
        &self,
        query_id: &str,
    ) -> Result<Option<crate::search::jobs::SearchJobProgress>, SearchError> {
        // Escape single quotes in the query_id to prevent SQL injection
        let escaped_id = escape_sql_string(query_id);

        let sql = format!(
            "SELECT read_rows, total_rows_approx, elapsed FROM system.processes WHERE query_id = '{}'",
            escaped_id
        );

        debug!("Getting query progress: {}", sql);

        let mut cursor = self
            .client
            .query(&sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in progress response: {}",
                e
            )))
        })?;

        // Parse the first line of JSON response
        if let Some(line) = response_str.lines().next() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                let rows_scanned = v.get("read_rows").and_then(|v| v.as_u64()).unwrap_or(0);
                let rows_total = v
                    .get("total_rows_approx")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let elapsed_secs = v.get("elapsed").and_then(|v| v.as_f64()).unwrap_or(0.0);

                // Calculate percentage (avoid division by zero)
                let percent = if rows_total > 0 {
                    ((rows_scanned as f64 / rows_total as f64) * 100.0).min(100.0) as u8
                } else {
                    0
                };

                return Ok(Some(crate::search::jobs::SearchJobProgress {
                    rows_scanned,
                    rows_total,
                    percent,
                    elapsed_ms: (elapsed_secs * 1000.0) as u64,
                }));
            }
        }

        // Query not found or no results
        Ok(None)
    }

    /// Quick count query to estimate dataset size for sampling decisions
    /// Returns approximate count, or 0 on error
    ///
    /// NAN-1428: `query_id` / `settings` tag the streaming path's count
    /// companion (`{request_id}-count`) so cancel kills it and per-priority
    /// limits bound it.
    pub async fn quick_count(
        &self,
        base_sql: &str,
        query_id: Option<&str>,
        settings: Option<&crate::search::admission::ClickHouseQuerySettings>,
    ) -> Result<u64, SearchError> {
        // Extract FROM and WHERE clauses from base SQL
        let base_upper = base_sql.to_uppercase();
        let from_pos = base_upper.find(" FROM ").unwrap_or(0);
        let where_pos = base_upper
            .find(" WHERE ")
            .or_else(|| base_upper.find(" PREWHERE "))
            .unwrap_or(base_sql.len());
        let order_pos = base_upper.find(" ORDER BY ").unwrap_or(base_sql.len());
        let settings_pos = base_upper.find(" SETTINGS ").unwrap_or(base_sql.len());
        let end_pos = order_pos.min(settings_pos);

        let table_clause = &base_sql[from_pos..where_pos.min(end_pos)];
        let conditions = if where_pos < end_pos {
            &base_sql[where_pos..end_pos]
        } else {
            ""
        };

        let count_sql = format!("SELECT count(*) as cnt{}{}", table_clause, conditions);
        debug!("Quick count SQL: {}", count_sql);

        let escaped_sql = escape_question_marks_in_strings(&count_sql);
        let result =
            super::types::with_query_options(self.client.query(&escaped_sql), query_id, settings)
                .fetch_one::<u64>()
                .await
                .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        Ok(result)
    }
}
