// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core query execution methods for ClickHouseExecutor
//!
//! Typed and dynamic query execution, count queries, and row post-processing.

use tracing::debug;

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::{ClickHouseExecutor, CLICKHOUSE_LOG_COLUMNS};
use crate::search::evaluator::helpers::{
    clickhouse_row_to_json, convert_timestamps_to_iso8601, flatten_ext_field_in_place,
    strip_empty_values,
};
use crate::search::{parse_clickhouse_error, SearchError};

impl ClickHouseExecutor {
    /// Execute a ClickHouse query using the typed ClickHouseLogReadRow struct
    pub(crate) async fn execute_typed_query(
        &self,
        sql: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        // Replace SELECT * with explicit column list to match ClickHouseLogReadRow struct
        // This is necessary because the table has 100+ columns but our struct only has ~47
        let modified_sql = sql.replace("SELECT *", &format!("SELECT {}", CLICKHOUSE_LOG_COLUMNS));

        // Escape ? characters in string literals to prevent clickhouse-rs from
        // interpreting them as parameter placeholders (e.g., in regex patterns like (?i))
        let escaped_sql = escape_question_marks_in_strings(&modified_sql);

        debug!("Executing typed ClickHouse query: {}", escaped_sql);

        let rows: Vec<super::types::ClickHouseLogReadRow> = self
            .client
            .query(&escaped_sql)
            .fetch_all()
            .await
            .map_err(|e| {
                let error_str = e.to_string();
                debug!(
                    "Typed query failed: {} - falling back to dynamic",
                    error_str
                );
                parse_clickhouse_error(&error_str)
            })?;

        debug!("Successfully fetched {} rows from ClickHouse", rows.len());

        let results: Vec<serde_json::Value> =
            rows.iter().map(|row| clickhouse_row_to_json(row)).collect();

        Ok(results)
    }

    /// Execute a ClickHouse query with dynamic schema using JSONEachRow format
    ///
    /// This is used for aggregation queries where the result schema varies
    pub(crate) async fn execute_dynamic_query(
        &self,
        sql: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        // Escape ? characters in string literals to prevent clickhouse-rs from
        // interpreting them as parameter placeholders (e.g., in regex patterns)
        let escaped_sql = escape_question_marks_in_strings(sql);
        debug!(
            "Executing ClickHouse dynamic query with JSONEachRow format: {}",
            escaped_sql
        );

        // Use fetch_bytes with JSONEachRow format for dynamic results
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // Collect all bytes from the cursor with proper error handling
        // Limit response size to 100MB to prevent OOM
        const MAX_RESPONSE_SIZE: usize = 100 * 1024 * 1024; // 100MB
        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    if response_bytes.len() + chunk.len() > MAX_RESPONSE_SIZE {
                        return Err(SearchError::ResponseTooLarge(
                            response_bytes.len() + chunk.len(),
                            MAX_RESPONSE_SIZE,
                        ));
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    // End of stream
                    break;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    tracing::error!("Error reading ClickHouse response chunk: {}", error_str);
                    return Err(parse_clickhouse_error(&error_str));
                }
            }
        }

        tracing::debug!(
            "Received {} bytes from ClickHouse dynamic query",
            response_bytes.len()
        );

        // Parse JSONEachRow format (one JSON object per line)
        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in ClickHouse response: {}",
                e
            )))
        })?;

        let results: Vec<serde_json::Value> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let mut json: serde_json::Value = serde_json::from_str(line).ok()?;

                // Post-process: parse metadata string into JSON object if present
                if let Some(obj) = json.as_object_mut() {
                    if let Some(metadata_val) = obj.get("metadata") {
                        if let Some(metadata_str) = metadata_val.as_str() {
                            if !metadata_str.is_empty() {
                                if let Ok(parsed_metadata) =
                                    serde_json::from_str::<serde_json::Value>(metadata_str)
                                {
                                    obj.insert("metadata".to_string(), parsed_metadata);
                                }
                            }
                        }
                    }

                    // Post-process: flatten ext JSON fields into main result
                    // (NAN-1463: without clobbering promoted columns)
                    flatten_ext_field_in_place(obj);

                    // Post-process: convert timestamp to ISO 8601 with Z suffix
                    // ClickHouse returns timestamps as "YYYY-MM-DD HH:MM:SS" without timezone
                    // We need to append 'Z' to indicate UTC
                    convert_timestamps_to_iso8601(obj);

                    // Strip empty/default values to reduce response size
                    strip_empty_values(obj);
                }

                Some(json)
            })
            .collect();

        Ok(results)
    }

    /// Execute a COUNT query and return the count
    /// Used for getting total count in parallel with data queries
    pub(crate) async fn execute_count_query(&self, sql: &str) -> Result<u64, SearchError> {
        self.execute_count_query_with_options(sql, None, None).await
    }

    /// Count-companion variant carrying a derived query_id and the resolved
    /// per-priority settings (NAN-1428). The id makes the companion killable
    /// by `KILL QUERY` alongside the data query; the settings bound it by the
    /// same per-priority limits. Neither changes the returned count.
    pub(crate) async fn execute_count_query_with_options(
        &self,
        sql: &str,
        query_id: Option<&str>,
        settings: Option<&crate::search::admission::ClickHouseQuerySettings>,
    ) -> Result<u64, SearchError> {
        debug!(
            "Executing ClickHouse count query (query_id={:?}): {}",
            query_id, sql
        );

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor =
            super::types::with_query_options(self.client.query(&escaped_sql), query_id, settings)
                .fetch_bytes("JSONEachRow")
                .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // Count queries should be small, but add limit as safeguard
        const MAX_COUNT_RESPONSE_SIZE: usize = 1024 * 1024; // 1MB
        let mut response_bytes = Vec::new();
        // NAN-1160: must distinguish a stream Err from end-of-stream. The old
        // `while let Ok(Some(chunk))` treated a ClickHouse error identically to EOF, so a
        // failing count query fell through to `Ok(0)` — masking the failure and defeating the
        // caller's `count_result.unwrap_or(results.len())` fallback (total_count silently 0).
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    if response_bytes.len() + chunk.len() > MAX_COUNT_RESPONSE_SIZE {
                        return Err(SearchError::ResponseTooLarge(
                            response_bytes.len() + chunk.len(),
                            MAX_COUNT_RESPONSE_SIZE,
                        ));
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => return Err(parse_clickhouse_error(&e.to_string())),
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in count response: {}",
                e
            )))
        })?;

        // Parse the count from the first line
        if let Some(line) = response_str.lines().next() {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                // Count might be named "cnt" or "count(*)"
                if let Some(cnt) = json.get("cnt").or_else(|| json.get("count(*)")) {
                    return Ok(cnt.as_u64().unwrap_or(0));
                }
            }
        }

        // NAN-1160: a count(*) query always returns exactly one row with the count, so reaching
        // here means the response was empty/unparseable/missing the column — an error, not a
        // legitimate 0. Return Err so the caller's results.len() fallback engages instead of
        // reporting a false total_count of 0.
        Err(SearchError::DatabaseError(sqlx::Error::Protocol(
            "count query returned no parseable count column".to_string(),
        )))
    }

    /// Execute a dynamic query with a custom query_id
    pub(crate) async fn execute_dynamic_query_with_query_id(
        &self,
        sql: &str,
        query_id: &str,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let escaped_sql = escape_question_marks_in_strings(sql);
        debug!(
            "Executing ClickHouse query with query_id {}: {}",
            query_id, escaped_sql
        );

        // Use with_option to set query_id via the client API (not SETTINGS clause)
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .with_option("query_id", query_id)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    let error_str = e.to_string();
                    tracing::error!("Error reading ClickHouse response chunk: {}", error_str);
                    return Err(parse_clickhouse_error(&error_str));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in ClickHouse response: {}",
                e
            )))
        })?;

        let results: Vec<serde_json::Value> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let mut json: serde_json::Value = serde_json::from_str(line).ok()?;

                if let Some(obj) = json.as_object_mut() {
                    // Parse metadata if present
                    if let Some(metadata_val) = obj.get("metadata") {
                        if let Some(metadata_str) = metadata_val.as_str() {
                            if !metadata_str.is_empty() {
                                if let Ok(parsed) =
                                    serde_json::from_str::<serde_json::Value>(metadata_str)
                                {
                                    obj.insert("metadata".to_string(), parsed);
                                }
                            }
                        }
                    }

                    // Flatten ext JSON fields
                    flatten_ext_field_in_place(obj);

                    convert_timestamps_to_iso8601(obj);

                    // Strip empty/default values to reduce response size
                    strip_empty_values(obj);
                }

                Some(json)
            })
            .collect();

        Ok(results)
    }

    /// Execute a dynamic query with a custom query_id and per-query settings
    ///
    /// Settings are applied via `.with_option()` which maps to HTTP query params
    /// on the clickhouse-rs client. Works on both self-hosted and Cloud.
    pub(crate) async fn execute_dynamic_query_with_settings(
        &self,
        sql: &str,
        query_id: &str,
        settings: &crate::search::admission::ClickHouseQuerySettings,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let escaped_sql = escape_question_marks_in_strings(sql);
        debug!(
            "Executing ClickHouse query with query_id {} and settings (timeout={}s, mem={}B, threads={}, priority={}): {}",
            query_id, settings.max_execution_time, settings.max_memory_usage_bytes,
            settings.max_threads, settings.priority,
            &escaped_sql[..escaped_sql.len().min(200)]
        );

        let mut cursor = self
            .client
            .query(&escaped_sql)
            .with_option("query_id", query_id)
            .with_option(
                "max_execution_time",
                &settings.max_execution_time.to_string(),
            )
            .with_option(
                "max_memory_usage",
                &settings.max_memory_usage_bytes.to_string(),
            )
            .with_option("max_threads", &settings.max_threads.to_string())
            .with_option("priority", &settings.priority.to_string())
            .with_option("queue_max_wait_ms", &settings.queue_max_wait_ms.to_string())
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    let error_str = e.to_string();
                    tracing::error!("Error reading ClickHouse response chunk: {}", error_str);
                    return Err(parse_clickhouse_error(&error_str));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in ClickHouse response: {}",
                e
            )))
        })?;

        let results: Vec<serde_json::Value> = response_str
            .lines()
            .filter(|line| !line.is_empty())
            .filter_map(|line| {
                let mut json: serde_json::Value = serde_json::from_str(line).ok()?;

                if let Some(obj) = json.as_object_mut() {
                    // Parse metadata if present
                    if let Some(metadata_val) = obj.get("metadata") {
                        if let Some(metadata_str) = metadata_val.as_str() {
                            if !metadata_str.is_empty() {
                                if let Ok(parsed) =
                                    serde_json::from_str::<serde_json::Value>(metadata_str)
                                {
                                    obj.insert("metadata".to_string(), parsed);
                                }
                            }
                        }
                    }

                    // Flatten ext JSON fields
                    flatten_ext_field_in_place(obj);

                    convert_timestamps_to_iso8601(obj);
                    strip_empty_values(obj);
                }

                Some(json)
            })
            .collect();

        Ok(results)
    }

    /// Parse a single JSONEachRow line and apply post-processing (shared by streaming path).
    pub(crate) fn parse_and_postprocess_row(line: &str) -> Option<serde_json::Value> {
        let mut json: serde_json::Value = serde_json::from_str(line).ok()?;

        if let Some(obj) = json.as_object_mut() {
            // Parse metadata string into JSON object if present
            if let Some(metadata_val) = obj.get("metadata") {
                if let Some(metadata_str) = metadata_val.as_str() {
                    if !metadata_str.is_empty() {
                        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(metadata_str)
                        {
                            obj.insert("metadata".to_string(), parsed);
                        }
                    }
                }
            }

            // Flatten ext JSON fields into main result
            flatten_ext_field_in_place(obj);

            convert_timestamps_to_iso8601(obj);
            strip_empty_values(obj);
        }

        Some(json)
    }
}
