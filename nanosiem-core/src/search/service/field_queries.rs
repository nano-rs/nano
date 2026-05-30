// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::query::MATERIALIZED_COLUMNS;

impl SearchService {
    /// Get field statistics for a query (async, separate from main search)
    ///
    /// This endpoint is designed to be called separately from the main search,
    /// allowing the UI to display search results immediately while field stats
    /// load in the background. Uses topK + uniq for efficient cardinality.
    pub async fn get_field_stats_for_query(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
    ) -> Result<Vec<FieldInfo>, SearchError> {
        // Only supported for ClickHouse backend
        if self.backend != SearchBackend::ClickHouse {
            return Ok(Vec::new());
        }

        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        // Parse and validate the query
        let parsed_query = parse_query(query).map_err(|e| convert_parse_error(e))?;

        // Extract just the base search expression (strip pipeline commands)
        let base_query = extract_base_search(&parsed_query);

        // Build time range
        let tr = TimeRange::new(time_range.start, time_range.end);

        // Generate base SQL for the query
        let base_sql = self
            .ch_sql_generator
            .generate(&base_query, &tr)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Get column list dynamically
        let columns = ch_executor.get_table_columns().await.unwrap_or_else(|e| {
            warn!(
                "Failed to get table columns for field stats, using defaults: {}",
                e
            );
            vec![
                "user",
                "src_ip",
                "dest_ip",
                "src_host",
                "dest_host",
                "action",
                "status",
                "source_type",
                "process_name",
                "file_name",
                "protocol",
                "auth_type",
                "auth_result",
                "category",
                "duration",
            ]
            .into_iter()
            .map(String::from)
            .collect()
        });

        // Build and execute field stats SQL (topK + uniq for each column)
        let field_stats_sql = ClickHouseExecutor::build_field_stats_sql(&base_sql, None, &columns);
        info!(
            "Executing async field stats query for {} columns",
            columns.len()
        );

        let stats = ch_executor
            .execute_field_stats_query(&field_stats_sql, &columns)
            .await?;
        info!(
            "Async field stats returned {} fields with data",
            stats.len()
        );

        Ok(stats)
    }

    /// Get top values for a single field (on-demand, Kibana-style).
    /// This is much more efficient than querying all fields at once.
    #[instrument(skip(self), fields(field = %field, query = %query))]
    pub async fn get_field_values(
        &self,
        field: &str,
        query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
    ) -> Result<Vec<FieldValueInfo>, SearchError> {
        // Only supported for ClickHouse backend
        if self.backend != SearchBackend::ClickHouse {
            return Ok(Vec::new());
        }

        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        // Parse and validate the query
        let parsed_query = parse_query(query).map_err(|e| convert_parse_error(e))?;

        // Extract just the base search expression, stripping ALL pipeline commands.
        // Stats/table/fields/eval all restrict or reshape columns, making field-values
        // fail with UNKNOWN_IDENTIFIER. The base search has the key filters already.
        let field_values_query = extract_base_search(&parsed_query);

        // Build time range
        let tr = TimeRange::new(time_range.start, time_range.end);

        // Generate base SQL for the query
        let base_sql = self
            .ch_sql_generator
            .generate(&field_values_query, &tr)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Build simple GROUP BY query for this single field
        let field_values_sql = ch_executor.build_field_values_sql(&base_sql, field, limit);
        info!(field = %field, "Executing field values query");
        debug!(
            "Field values SQL: {}",
            &field_values_sql[..field_values_sql.len().min(200)]
        );

        // Execute and return
        let values = ch_executor
            .execute_field_values_query(&field_values_sql)
            .await?;
        info!(field = %field, count = values.len(), "Field values query complete");

        Ok(values)
    }

    /// Fetch a single log event by ID
    ///
    /// Used for table_view mode where initial results are fetched with minimal columns,
    /// and full row data is fetched on demand when user expands a row.
    ///
    /// When `exclude_audit` is true, audit-source rows are filtered at the SQL layer so
    /// callers without `audit:view` cannot retrieve them by direct id lookup (NAN-694).
    ///
    /// NAN-1032: callers should pass `source_type` whenever known so the query can
    /// use the `(source_type, timestamp, ...)` PK index for a tight range read.
    /// Without it, S3-backed historical lookups scan every source_type's marks within
    /// the time window — measured 12–60s on cold cache vs <1s with the filter.
    /// Skips the parallel `count(*)` companion that `execute_clickhouse_sql` adds:
    /// the response carries no count, the count is bounded to {0,1} by `id` + LIMIT 1,
    /// and on S3 it doubles the I/O.
    #[instrument(skip(self))]
    pub async fn fetch_log_by_id(
        &self,
        id: &str,
        time_range: Option<&TimeRangeInput>,
        source_type: Option<&str>,
        exclude_audit: bool,
    ) -> Result<Option<serde_json::Value>, SearchError> {
        let table = self.table_names.read("logs");
        let sql = build_fetch_log_sql(&table, id, time_range, source_type, exclude_audit);

        debug!("Fetching log by ID: {}", sql);

        // Execute query
        let results = match self.backend {
            SearchBackend::ClickHouse => {
                let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
                    SearchError::DatabaseError(sqlx::Error::Configuration(
                        "ClickHouse client not configured".into(),
                    ))
                })?;
                ch_executor.execute_sql_to_json(&sql).await?
            }
            SearchBackend::PostgreSQL => {
                let (results, _) = self.execute_postgres_sql(&sql, 1, 0).await?;
                results
            }
        };

        Ok(results.into_iter().next())
    }

    /// Query logs by a specific UDM field value
    /// This searches across all log sources that have the field mapped
    #[instrument(skip(self))]
    pub async fn query_udm_field(
        &self,
        request: UdmFieldQueryRequest,
    ) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        // Validate time range
        request.time_range.validate()?;

        // Build the SQL query for the UDM field
        let sql = self.build_udm_field_query(&request)?;

        debug!("Generated UDM field query SQL: {}", sql);

        // Apply limit and offset
        let limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        let offset = request.offset.unwrap_or(0);

        // Execute the query based on backend
        let (results, total_count) = match self.backend {
            SearchBackend::ClickHouse => self.execute_clickhouse_sql(&sql, limit, offset).await?,
            SearchBackend::PostgreSQL => self.execute_postgres_sql(&sql, limit, offset).await?,
        };

        // Calculate field statistics
        let mut stats = FieldStatistics::new();
        for row in &results {
            stats.process_row(row);
        }
        let fields = stats.get_field_info(self.config.top_values_count);

        // Generate histogram for UDM field query
        let histogram = self
            .generate_histogram_for_time_range(&request.time_range)
            .await?;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // UDM field queries don't get cost analysis (they're simple field lookups)
        // Display type is always Events for UDM field queries
        Ok(SearchResponse {
            results,
            total_count,
            execution_time_ms,
            fields,
            generated_sql: if request.include_sql.unwrap_or(false) {
                Some(sql)
            } else {
                None
            },
            histogram: Some(histogram),
            warnings: None,
            cost_score: None,
            display_type: Some(DisplayType::Events),
            column_order: None, // UDM field queries don't have column order
        })
    }

    /// Get ext field names that exist in recent data (last 24h).
    /// Used by the frontend for syntax highlighting and autocomplete.
    pub async fn get_ext_field_names(&self) -> Result<Vec<String>, SearchError> {
        if self.backend != SearchBackend::ClickHouse {
            return Ok(Vec::new());
        }

        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse executor not available".into(),
            ))
        })?;

        let table = self.table_names.read("logs");
        ch_executor.get_ext_field_names(&table).await
    }

    /// Get available UDM fields with their statistics
    #[instrument(skip(self))]
    pub async fn get_udm_field_stats(
        &self,
        time_range: &TimeRangeInput,
    ) -> Result<Vec<UdmFieldStats>, SearchError> {
        time_range.validate()?;

        let mut field_stats = Vec::new();

        for field in UdmField::all() {
            let column = field.column_name();

            // Query for non-null count and distinct count (always use PostgreSQL for this)
            let sql = format!(
                r#"
                SELECT 
                    COUNT(*) FILTER (WHERE "{}" IS NOT NULL) as non_null_count,
                    COUNT(DISTINCT "{}") as distinct_count
                FROM logs
                WHERE timestamp BETWEEN $1 AND $2
                "#,
                column, column
            );

            let row = sqlx::query(&sql)
                .bind(time_range.start)
                .bind(time_range.end)
                .fetch_one(&self.pg_pool)
                .await?;

            let non_null_count: i64 = row.try_get("non_null_count").unwrap_or(0);
            let distinct_count: i64 = row.try_get("distinct_count").unwrap_or(0);

            field_stats.push(UdmFieldStats {
                field: *field,
                column_name: column.to_string(),
                category: field.category().to_string(),
                data_type: format!("{:?}", field.data_type()),
                non_null_count: non_null_count as u64,
                distinct_count: distinct_count as u64,
            });
        }

        Ok(field_stats)
    }

    /// Get top values for a specific UDM field
    #[instrument(skip(self))]
    pub async fn get_udm_field_values(
        &self,
        field: UdmField,
        time_range: &TimeRangeInput,
        limit: Option<usize>,
    ) -> Result<Vec<(String, u64)>, SearchError> {
        time_range.validate()?;

        let column = field.column_name();
        let limit = limit.unwrap_or(self.config.top_values_count);

        // Use PostgreSQL for this query
        let sql = format!(
            r#"
            SELECT "{}" as value, COUNT(*) as count
            FROM logs
            WHERE timestamp BETWEEN $1 AND $2
              AND "{}" IS NOT NULL
            GROUP BY "{}"
            ORDER BY count DESC
            LIMIT $3
            "#,
            column, column, column
        );

        let rows = sqlx::query(&sql)
            .bind(time_range.start)
            .bind(time_range.end)
            .bind(limit as i64)
            .fetch_all(&self.pg_pool)
            .await?;

        let values: Vec<(String, u64)> = rows
            .iter()
            .map(|row| {
                let value: String = row.try_get("value").unwrap_or_default();
                let count: i64 = row.try_get("count").unwrap_or(0);
                (value, count as u64)
            })
            .collect();

        Ok(values)
    }

    /// Validate a regex pattern for safety and correctness
    /// Returns an error if the pattern is too long or contains syntax errors
    fn validate_regex_pattern(pattern: &str) -> Result<(), SearchError> {
        // Limit regex length to prevent ReDoS attacks
        const MAX_REGEX_LENGTH: usize = 1000;
        if pattern.len() > MAX_REGEX_LENGTH {
            return Err(SearchError::SqlValidationError(format!(
                "Regex pattern too long ({} chars). Maximum allowed is {} characters.",
                pattern.len(),
                MAX_REGEX_LENGTH
            )));
        }

        // Try to compile the regex to catch syntax errors early
        // This provides better error messages than waiting for the database
        if let Err(e) = regex::Regex::new(pattern) {
            return Err(SearchError::SqlValidationError(format!(
                "Invalid regex pattern: {}",
                e
            )));
        }

        Ok(())
    }

    /// Build SQL query for UDM field search
    fn build_udm_field_query(&self, request: &UdmFieldQueryRequest) -> Result<String, SearchError> {
        let column = request.field.column_name();

        // Build the WHERE clause based on the operator
        let value_clause = match &request.operator {
            UdmQueryOperator::Equals => {
                format!("\"{}\" = '{}'", column, escape_sql_string(&request.value))
            }
            UdmQueryOperator::NotEquals => {
                format!("\"{}\" != '{}'", column, escape_sql_string(&request.value))
            }
            UdmQueryOperator::Contains => {
                format!(
                    "\"{}\"::text ILIKE '%{}%' ESCAPE '\\'",
                    column,
                    escape_like_pattern(&request.value)
                )
            }
            UdmQueryOperator::StartsWith => {
                format!(
                    "\"{}\"::text ILIKE '{}%' ESCAPE '\\'",
                    column,
                    escape_like_pattern(&request.value)
                )
            }
            UdmQueryOperator::EndsWith => {
                format!(
                    "\"{}\"::text ILIKE '%{}' ESCAPE '\\'",
                    column,
                    escape_like_pattern(&request.value)
                )
            }
            UdmQueryOperator::Regex => {
                Self::validate_regex_pattern(&request.value)?;
                format!(
                    "\"{}\"::text ~ '{}'",
                    column,
                    escape_sql_string(&request.value)
                )
            }
            UdmQueryOperator::GreaterThan => {
                format!("\"{}\" > '{}'", column, escape_sql_string(&request.value))
            }
            UdmQueryOperator::LessThan => {
                format!("\"{}\" < '{}'", column, escape_sql_string(&request.value))
            }
            UdmQueryOperator::IsNull => {
                format!("\"{}\" IS NULL", column)
            }
            UdmQueryOperator::IsNotNull => {
                format!("\"{}\" IS NOT NULL", column)
            }
        };

        let sql = format!(
            r#"
            SELECT * FROM logs
            WHERE timestamp BETWEEN '{}' AND '{}'
              AND {}
            ORDER BY timestamp DESC
            "#,
            request.time_range.start.format("%Y-%m-%d %H:%M:%S%.6f"),
            request.time_range.end.format("%Y-%m-%d %H:%M:%S%.6f"),
            value_clause
        );

        Ok(sql)
    }
}

/// Build the SQL for `fetch_log_by_id`.
///
/// Extracted into a free function so the audit-exclusion behavior is unit-testable
/// without a live ClickHouse/Postgres backend (NAN-694).
///
/// When `source_type` is provided it is added to the WHERE clause so the
/// `(source_type, timestamp, ...)` PK index can do a tight range read instead
/// of scanning every source_type's marks within the timestamp window (NAN-1032).
fn build_fetch_log_sql(
    table: &str,
    id: &str,
    time_range: Option<&TimeRangeInput>,
    source_type: Option<&str>,
    exclude_audit: bool,
) -> String {
    let escaped_id = id.replace('\'', "''");
    let audit_filter = if exclude_audit {
        " AND lower(source_type) != 'audit'"
    } else {
        ""
    };
    let source_type_filter = source_type
        .map(|st| format!(" AND source_type = '{}'", st.replace('\'', "''")))
        .unwrap_or_default();
    // ClickHouse's `SELECT *` excludes MATERIALIZED columns (enrichment, IOC,
    // prevalence, process-GUID, resolved-identity dict fills). The row-expand UI
    // relies on this fetch as its full-fidelity source — table_view search results
    // are field-pruned — so without re-adding them the inspector shows no
    // enrichment even though it's stored. Mirrors build_select_clause's re-add
    // off the same MATERIALIZED_COLUMNS source of truth (NAN-1147).
    let select = format!("*, {}", MATERIALIZED_COLUMNS.join(", "));
    if let Some(tr) = time_range {
        format!(
            "SELECT {} FROM {} WHERE id = '{}'{}{} AND timestamp BETWEEN '{}' AND '{}' LIMIT 1",
            select,
            table,
            escaped_id,
            source_type_filter,
            audit_filter,
            tr.start.format("%Y-%m-%d %H:%M:%S%.6f"),
            tr.end.format("%Y-%m-%d %H:%M:%S%.6f"),
        )
    } else {
        format!(
            "SELECT {} FROM {} WHERE id = '{}'{}{} LIMIT 1",
            select, table, escaped_id, source_type_filter, audit_filter,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    #[test]
    fn fetch_log_sql_without_audit_exclusion_omits_source_type_filter() {
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, false);
        assert!(sql.starts_with("SELECT *, "), "must re-add materialized cols: {sql}");
        assert!(
            sql.ends_with("FROM logs WHERE id = 'abc-123' LIMIT 1"),
            "{sql}"
        );
    }

    #[test]
    fn fetch_log_sql_reads_materialized_enrichment_columns() {
        // NAN-1147 regression: `SELECT *` excludes MATERIALIZED columns, so the
        // row-expand inspector showed no enrichment. The fetch must name them.
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, false);
        for col in [
            "user_identity_department",
            "enriched_src_country",
            "ioc_confidence",
            "prevalence_dest_ip",
        ] {
            assert!(sql.contains(col), "missing materialized column {col}: {sql}");
        }
    }

    #[test]
    fn fetch_log_sql_with_audit_exclusion_filters_audit_rows() {
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, true);
        assert!(sql.starts_with("SELECT *, "), "must re-add materialized cols: {sql}");
        assert!(
            sql.ends_with(
                "FROM logs WHERE id = 'abc-123' AND lower(source_type) != 'audit' LIMIT 1"
            ),
            "{sql}"
        );
    }

    #[test]
    fn fetch_log_sql_with_audit_exclusion_and_time_range() {
        let tr = TimeRangeInput {
            start: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 1, 2, 4, 5, 6).unwrap(),
        };
        let sql = build_fetch_log_sql("logs", "abc-123", Some(&tr), None, true);
        assert!(
            sql.contains("AND lower(source_type) != 'audit'"),
            "audit exclusion missing: {sql}"
        );
        assert!(
            sql.contains("AND timestamp BETWEEN '2026-01-02 03:04:05"),
            "time range missing: {sql}"
        );
    }

    #[test]
    fn fetch_log_sql_escapes_single_quotes_in_id() {
        let sql = build_fetch_log_sql("logs", "abc'; DROP--", None, None, true);
        assert!(
            sql.contains("WHERE id = 'abc''; DROP--'"),
            "id quotes not escaped: {sql}"
        );
    }

    #[test]
    fn fetch_log_sql_with_source_type_adds_pk_aligned_filter() {
        let tr = TimeRangeInput {
            start: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            end: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 7).unwrap(),
        };
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            Some(&tr),
            Some("windows_sysmon"),
            false,
        );
        // source_type goes immediately after the id predicate so the PK
        // (source_type, timestamp, ...) can do a tight range read on S3-backed
        // historical partitions instead of scanning every source_type's marks.
        assert!(sql.starts_with("SELECT *, "), "must re-add materialized cols: {sql}");
        assert!(
            sql.ends_with(
                "FROM logs WHERE id = 'abc-123' AND source_type = 'windows_sysmon' AND timestamp BETWEEN '2026-01-02 03:04:05.000000' AND '2026-01-02 03:04:07.000000' LIMIT 1"
            ),
            "{sql}"
        );
    }

    #[test]
    fn fetch_log_sql_escapes_single_quotes_in_source_type() {
        let sql = build_fetch_log_sql("logs", "abc-123", None, Some("evil'; DROP--"), false);
        assert!(
            sql.contains("source_type = 'evil''; DROP--'"),
            "source_type quotes not escaped: {sql}"
        );
    }
}
