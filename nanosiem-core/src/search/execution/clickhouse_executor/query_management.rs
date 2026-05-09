// SPDX-License-Identifier: AGPL-3.0-or-later

//! Query management: cancellation, progress tracking, and quick counts
//!
//! Methods for monitoring and controlling running ClickHouse queries.

use tracing::{debug, info};

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::ClickHouseExecutor;
use crate::search::{parse_clickhouse_error, SearchError};

impl ClickHouseExecutor {
    /// Cancel a running query by its query_id
    ///
    /// Returns true if a query was found and killed, false if no matching query was running.
    /// Uses KILL QUERY SYNC to wait for the query to actually stop.
    pub async fn cancel_query(&self, query_id: &str) -> Result<bool, SearchError> {
        // Escape single quotes in the query_id to prevent SQL injection
        let escaped_id = query_id.replace('\'', "''");

        // Check if the query is still running
        let check_sql = format!(
            "SELECT count() as cnt FROM system.processes WHERE query_id = '{}'",
            escaped_id
        );

        debug!("Checking if query is running: {}", check_sql);

        let mut cursor = self
            .client
            .query(&check_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in cancel check response: {}",
                e
            )))
        })?;

        let is_running = response_str
            .lines()
            .next()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .and_then(|v| v.get("cnt")?.as_u64())
            .unwrap_or(0)
            > 0;

        if !is_running {
            debug!("Query {} is not running", query_id);
            return Ok(false);
        }

        // Kill the query synchronously
        let kill_sql = format!("KILL QUERY WHERE query_id = '{}' SYNC", escaped_id);
        info!("Killing query: {}", kill_sql);

        self.client
            .query(&kill_sql)
            .execute()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        info!("Successfully killed query {}", query_id);
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
        let escaped_id = query_id.replace('\'', "''");

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
    pub async fn quick_count(&self, base_sql: &str) -> Result<u64, SearchError> {
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
        let result = self
            .client
            .query(&escaped_sql)
            .fetch_one::<u64>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        Ok(result)
    }
}
