// SPDX-License-Identifier: AGPL-3.0-or-later

//! Field statistics and field value queries
//!
//! Methods for getting table columns, building/executing field stats queries,
//! and building/executing single-field value queries.

use tracing::{debug, info, warn};

use super::sql_helpers::escape_question_marks_in_strings;
use super::types::ClickHouseExecutor;
use crate::query::is_explicit_column;
use crate::search::{parse_clickhouse_error, FieldInfo, SearchError};

impl ClickHouseExecutor {
    /// Get list of queryable columns from the logs table schema
    /// Excludes arrays, maps, and internal columns (starting with _)
    pub async fn get_table_columns(&self) -> Result<Vec<String>, SearchError> {
        let sql = r#"
            SELECT name
            FROM system.columns
            WHERE database = 'nanosiem'
              AND table = 'logs'
              AND type NOT LIKE '%Array%'
              AND type NOT LIKE '%Map%'
              AND type NOT LIKE 'JSON%'
              AND name NOT LIKE '\_%'
              AND name NOT LIKE '%_search'
              AND name NOT LIKE 'prevalence_%'
              AND default_kind != 'ALIAS'
              AND name NOT IN ('ext', 'metadata', 'event_id', 'ingest_time', 'namespace')
            ORDER BY name
        "#;

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // Schema queries should be small, but add limit as safeguard
        const MAX_SCHEMA_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB
        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            if response_bytes.len() + chunk.len() > MAX_SCHEMA_RESPONSE_SIZE {
                return Err(SearchError::ResponseTooLarge(
                    response_bytes.len() + chunk.len(),
                    MAX_SCHEMA_RESPONSE_SIZE,
                ));
            }
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in columns response: {}",
                e
            )))
        })?;

        let columns: Vec<String> = response_str
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("name")?.as_str().map(|s| s.to_string()))
            })
            .collect();

        debug!("Found {} queryable columns in logs table", columns.len());
        Ok(columns)
    }

    /// Build a SQL query to get field statistics using topK
    /// Optionally uses sampling for large datasets (sample_rate < 1.0)
    /// topK is a probabilistic algorithm that's much faster than GROUP BY
    pub fn build_field_stats_sql(
        base_sql: &str,
        sample_rate: Option<f64>,
        fields: &[String],
    ) -> String {
        // Extract the FROM and WHERE clauses from the base SQL
        // We need to inject SAMPLE between FROM and WHERE
        let base_upper = base_sql.to_uppercase();

        // Find FROM clause position
        let from_pos = base_upper.find(" FROM ").unwrap_or(0);

        // Find WHERE or PREWHERE clause position
        let where_pos = base_upper
            .find(" WHERE ")
            .or_else(|| base_upper.find(" PREWHERE "))
            .unwrap_or(base_sql.len());

        // Find ORDER BY position to exclude it
        let order_pos = base_upper.find(" ORDER BY ").unwrap_or(base_sql.len());
        let settings_pos = base_upper.find(" SETTINGS ").unwrap_or(base_sql.len());
        let end_pos = order_pos.min(settings_pos);

        // Extract table name (between FROM and WHERE/PREWHERE)
        let table_clause = &base_sql[from_pos..where_pos];

        // Extract conditions (between WHERE and ORDER BY/SETTINGS)
        let conditions = if where_pos < end_pos {
            &base_sql[where_pos..end_pos]
        } else {
            ""
        };

        // Build SELECT with topK for each field
        let mut select_parts = Vec::new();
        for field in fields {
            // topK returns array of values, we also get approximate count via uniq
            select_parts.push(format!(
                "topK(100)(toString({field})) as {field}_top",
                field = field
            ));
            select_parts.push(format!(
                "uniq({field}) as {field}_cardinality",
                field = field
            ));
        }

        let select_clause = select_parts.join(",\n  ");

        // Build the query, optionally with SAMPLE for large datasets
        // SAMPLE must come right after the table name
        let sample_clause = match sample_rate {
            Some(rate) if rate < 1.0 => format!(" SAMPLE {}", rate),
            _ => String::new(),
        };

        format!(
            "SELECT\n  {}\n{}{}{}",
            select_clause,
            table_clause,
            sample_clause,
            if conditions.is_empty() {
                "".to_string()
            } else {
                format!("\n{}", conditions)
            }
        )
    }

    /// Execute a field stats query and parse the results into FieldInfo structs
    /// Returns a Vec of FieldInfo with top_values and cardinality populated
    pub async fn execute_field_stats_query(
        &self,
        sql: &str,
        field_names: &[String],
    ) -> Result<Vec<FieldInfo>, SearchError> {
        info!(
            "Executing field stats query for {} fields",
            field_names.len()
        );
        info!(
            "Field stats SQL (first 500 chars): {}",
            &sql[..sql.len().min(500)]
        );

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| {
                warn!("ClickHouse field stats query failed to start: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;

        // Limit response size to prevent OOM on large field stats
        const MAX_FIELD_STATS_SIZE: usize = 50 * 1024 * 1024; // 50MB
        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => {
                    if response_bytes.len() + chunk.len() > MAX_FIELD_STATS_SIZE {
                        return Err(SearchError::ResponseTooLarge(
                            response_bytes.len() + chunk.len(),
                            MAX_FIELD_STATS_SIZE,
                        ));
                    }
                    response_bytes.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(e) => {
                    warn!("ClickHouse field stats streaming error: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in field stats response: {}",
                e
            )))
        })?;

        debug!("Field stats response length: {} bytes", response_str.len());

        // Log response for debugging if empty or small
        if response_str.is_empty() {
            warn!("Field stats query returned empty response");
            return Ok(Vec::new());
        }
        if response_str.len() < 100 {
            debug!("Field stats response (small): {}", response_str);
        }

        // Parse the single row result
        let first_line = response_str.lines().next().unwrap_or("");
        let row: serde_json::Value = match serde_json::from_str(first_line) {
            Ok(v) => v,
            Err(e) => {
                warn!(
                    "Failed to parse field stats JSON: {} - response was: {}",
                    e,
                    if response_str.len() > 200 {
                        &response_str[..200]
                    } else {
                        &response_str
                    }
                );
                return Ok(Vec::new());
            }
        };

        let mut fields = Vec::new();

        for field_name in field_names {
            let top_key = format!("{}_top", field_name);
            let cardinality_key = format!("{}_cardinality", field_name);

            let cardinality = row
                .get(&cardinality_key)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            // Skip fields with no data
            if cardinality == 0 {
                continue;
            }

            // Parse top values array - topK returns array of values (strings)
            // Note: topK doesn't provide counts, just the most frequent values
            let top_values: Vec<(String, u64)> = row
                .get(&top_key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|val| {
                            // topK returns plain string values, not tuples
                            let value = val.as_str()?.to_string();
                            if !value.is_empty() {
                                // Count is 0 since topK doesn't provide counts
                                // The value ordering indicates relative frequency
                                Some((value, 0u64))
                            } else {
                                None
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Skip fields that only have empty/default values.
            // ClickHouse uses 0 as default for numeric columns and "" for strings.
            // When all rows have the default value, the field carries no useful info.
            if top_values.is_empty() {
                continue;
            }
            let only_defaults = cardinality <= 1
                && top_values.iter().all(|(v, _)| {
                    v.is_empty()
                        || v == "0"
                        || v == "0.0"
                        || v == "0000-00-00"
                        || v == "1970-01-01 00:00:00.000"
                        || v == "65535"
                        || v == "9999" // prevalence sentinel values
                });
            if only_defaults {
                continue;
            }

            // For topK, we don't have actual counts, use cardinality as proxy
            let total_count: u64 = cardinality;

            fields.push(FieldInfo {
                name: field_name.to_string(),
                field_type: "string".to_string(),
                count: total_count,
                top_values,
                cardinality: Some(cardinality),
            });
        }

        // Sort by total count descending (most common fields first)
        fields.sort_by(|a, b| b.count.cmp(&a.count));

        Ok(fields)
    }

    /// Get distinct ext field names from recent data.
    /// Returns field names that exist in the ext JSON column (last 24h).
    pub async fn get_ext_field_names(&self, table: &str) -> Result<Vec<String>, SearchError> {
        let sql = format!(
            "SELECT DISTINCT arrayJoin(JSONExtractKeys(ext)) AS name \
             FROM {} \
             WHERE timestamp >= now() - INTERVAL 24 HOUR \
               AND ext != '{{}}' AND ext != '' \
             LIMIT 200",
            table
        );

        debug!("Querying ext field names: {}", sql);

        let escaped_sql = escape_question_marks_in_strings(&sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let mut response_bytes = Vec::new();
        while let Ok(Some(chunk)) = cursor.next().await {
            if response_bytes.len() + chunk.len() > 1024 * 1024 {
                break; // 1MB safety limit
            }
            response_bytes.extend_from_slice(&chunk);
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in ext field names response: {}",
                e
            )))
        })?;

        let names: Vec<String> = response_str
            .lines()
            .filter_map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| v.get("name")?.as_str().map(|s| s.to_string()))
            })
            .collect();

        debug!("Found {} ext field names", names.len());
        Ok(names)
    }

    /// Build a simple SQL query to get top values for a SINGLE field
    /// This is the on-demand approach - much faster than querying all fields at once
    pub fn build_field_values_sql(&self, base_sql: &str, field: &str, limit: usize) -> String {
        // Resolve field expression: direct column vs ext JSON field
        let field_expr = if is_explicit_column(field) {
            field.to_string()
        } else {
            // Sanitize the field name for safe JSON path access
            let safe: String = field
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            format!("ext.{}", safe)
        };

        // Strip trailing ORDER BY and SETTINGS from the base SQL
        let base_upper = base_sql.to_uppercase();
        let order_pos = base_upper.rfind(" ORDER BY ").unwrap_or(base_sql.len());
        let settings_pos = base_upper.rfind(" SETTINGS ").unwrap_or(base_sql.len());
        let end_pos = order_pos.min(settings_pos);
        let base_no_order = base_sql[..end_pos].trim_end();

        // CTE queries (WITH ...) can't be wrapped in FROM (...) in ClickHouse.
        // Replace the final top-level SELECT with our field-values aggregation.
        if base_no_order
            .trim_start()
            .to_uppercase()
            .starts_with("WITH ")
        {
            // Find the last SELECT at parenthesis depth 0
            let bytes = base_no_order.as_bytes();
            let mut depth = 0i32;
            let mut last_top_select = None;
            for i in 0..bytes.len() {
                match bytes[i] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                if depth == 0
                    && i + 7 <= bytes.len()
                    && base_no_order[i..i + 7].eq_ignore_ascii_case("SELECT ")
                {
                    last_top_select = Some(i);
                }
            }
            if let Some(pos) = last_top_select {
                let cte_part = &base_no_order[..pos];
                let final_select = &base_no_order[pos..];
                // Extract the FROM source (stage name) from the final SELECT
                if let Some(from_idx) = final_select.to_uppercase().find(" FROM ") {
                    let after_from = &final_select[from_idx + 6..];
                    let source = after_from.split_whitespace().next().unwrap_or("stage_0");
                    return format!(
                        "{cte}SELECT toString({field_expr}) as value, count() as cnt FROM {source} WHERE {field_expr} IS NOT NULL AND toString({field_expr}) != '' GROUP BY value ORDER BY cnt DESC LIMIT {limit}",
                        cte = cte_part,
                        field_expr = field_expr,
                        source = source,
                        limit = limit
                    );
                }
            }
        }

        // Non-CTE: wrap as subquery
        format!(
            "SELECT toString({field_expr}) as value, count() as cnt FROM ({base}) AS _fv WHERE {field_expr} IS NOT NULL AND toString({field_expr}) != '' GROUP BY value ORDER BY cnt DESC LIMIT {limit}",
            field_expr = field_expr,
            base = base_no_order,
            limit = limit
        )
    }

    /// Execute a field values query and return the results
    pub async fn execute_field_values_query(
        &self,
        sql: &str,
    ) -> Result<Vec<crate::search::FieldValueInfo>, SearchError> {
        use crate::search::FieldValueInfo;

        debug!("Executing field values query: {}", sql);

        let escaped_sql = escape_question_marks_in_strings(sql);
        let mut cursor = self
            .client
            .query(&escaped_sql)
            .fetch_bytes("JSONEachRow")
            .map_err(|e| {
                warn!("ClickHouse field values query failed: {}", e);
                parse_clickhouse_error(&e.to_string())
            })?;

        let mut response_bytes = Vec::new();
        loop {
            match cursor.next().await {
                Ok(Some(chunk)) => response_bytes.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => {
                    warn!("ClickHouse field values streaming error: {}", e);
                    return Err(parse_clickhouse_error(&e.to_string()));
                }
            }
        }

        let response_str = String::from_utf8(response_bytes).map_err(|e| {
            SearchError::DatabaseError(sqlx::Error::Protocol(format!(
                "Invalid UTF-8 in field values response: {}",
                e
            )))
        })?;

        if response_str.is_empty() {
            return Ok(Vec::new());
        }

        // Parse results and calculate percentages
        let mut values = Vec::new();
        let mut total: u64 = 0;

        // First pass: collect values and sum total
        let rows: Vec<serde_json::Value> = response_str
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect();

        for row in &rows {
            if let Some(cnt) = row.get("cnt").and_then(|v| v.as_u64()) {
                total += cnt;
            }
        }

        // Second pass: build results with percentages
        for row in rows {
            let value = row
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let count = row.get("cnt").and_then(|v| v.as_u64()).unwrap_or(0);
            let percentage = if total > 0 {
                (count as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            if !value.is_empty() {
                values.push(FieldValueInfo {
                    value,
                    count,
                    percentage,
                });
            }
        }

        Ok(values)
    }
}
