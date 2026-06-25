// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::search::execution::clickhouse_executor::{
    wrap_query_for_count, wrap_query_with_pagination,
};

impl SearchService {
    /// Execute a raw SQL query (SELECT only)
    #[instrument(skip(self))]
    pub async fn search_sql(&self, request: RawSqlRequest) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        // Validate time range
        request.time_range.validate()?;

        // Validate SQL is SELECT only
        self.validate_sql(&request.sql)?;

        // Apply limit and offset
        let limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        let offset = request.offset.unwrap_or(0);
        let sql = request.sql.trim().trim_end_matches(';');

        // Execute the query
        let (results, total_count) = self.execute_clickhouse_raw_sql(sql, limit, offset).await?;

        // Calculate field statistics
        let mut stats = FieldStatistics::new();
        for row in &results {
            stats.process_row(row);
        }
        let fields = stats.get_field_info(self.config.top_values_count);

        // Generate histogram for raw SQL - use the full time range.
        // NAN-1429: degrade to histogram:null on failure instead of failing
        // the whole search (matches the piped-query path's behavior).
        let histogram = match self
            .generate_histogram_for_time_range(&request.time_range)
            .await
        {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::warn!("Raw SQL histogram query failed: {}", e);
                None
            }
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Raw SQL queries don't get cost analysis or display type (we can't parse them)
        Ok(SearchResponse {
            results,
            total_count,
            execution_time_ms,
            fields,
            generated_sql: Some(sql.to_string()),
            histogram,
            warnings: None,
            cost_score: None,
            display_type: None, // Raw SQL - let frontend determine
            column_order: None, // Raw SQL - no parsed column order
        })
    }

    /// Explain a piped query by returning the generated SQL without executing
    #[instrument(skip(self), fields(query = %query))]
    pub fn explain(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        table_view: bool,
        dataset: Option<&str>,
    ) -> Result<String, SearchError> {
        // Validate time range
        time_range.validate()?;

        // NAN-1569: resolve the per-query dataset profile so explain matches the
        // executed path — without this, "Inspect SQL" validates against and
        // renders the logs table for a spans/metrics query (misleading FROM logs).
        let query_profile = self.dataset_profile(dataset);

        // Extract time modifiers and clean the query
        let (cleaned_query, _, _) = extract_time_modifiers(query);

        // Parse the cleaned query
        let parsed = parse_query(&cleaned_query).map_err(|e| convert_parse_error(e))?;

        // NAN-1354: input-side field-name validation (defense-in-depth behind
        // codegen escaping). Keep `explain` consistent with the executed path.
        validate_query_field_names(&parsed, query_profile.as_ref())?;

        // NAN-806: keep `explain` honest — the executed query has implicit
        // top-N sorting injected after a trailing `stats … by …`, and the
        // explained SQL should reflect that.
        let (parsed, auto_sort_decision) =
            crate::search::query_processing::apply_auto_sort(parsed);

        // Extract post-prevalence commands to determine if we need to strip them
        let post_prevalence = extract_post_prevalence_commands(&parsed);

        // If there are post-prevalence commands, strip them from the query for SQL generation
        // These commands are applied as post-processing after prevalence enrichment
        let query_for_sql = if !post_prevalence.commands.is_empty() {
            strip_post_prevalence_commands(&parsed)
        } else {
            parsed
        };

        // Strip inputlookup commands — these are resolved in post-processing
        let has_inputlookup = !extract_inputlookup_commands(&query_for_sql).is_empty();
        let query_for_sql = if has_inputlookup {
            strip_inputlookup_and_after(&query_for_sql)
        } else {
            query_for_sql
        };

        // Strip AI commands — LLM enrichment happens in post-processing
        let has_ai = extract_ai_command(&query_for_sql).is_some();
        let query_for_sql = if has_ai {
            strip_ai_and_after(&query_for_sql)
        } else {
            query_for_sql
        };

        // Generate SQL based on backend
        let tr = TimeRange::new(time_range.start, time_range.end);
        let options = crate::query::QueryOptions {
            table_view,
            ..Default::default()
        };
        let mut sql = self
            .dataset_generator(dataset)
            .generate_with_options(&query_for_sql, &tr, &options)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Add a note about post-prevalence commands if any were stripped
        if !post_prevalence.commands.is_empty() {
            let cmd_descriptions: Vec<String> = post_prevalence
                .commands
                .iter()
                .map(|cmd| format!("{:?}", cmd))
                .collect();
            sql.push_str(&format!(
                "\n\n-- Note: {} post-prevalence command(s) will be applied after enrichment:\n-- {}",
                post_prevalence.commands.len(),
                cmd_descriptions.join("\n-- ")
            ));
        }

        // Add a note about inputlookup commands if any were stripped
        if has_inputlookup {
            sql.push_str("\n\n-- Note: inputlookup command(s) will be applied in post-processing");
        }

        // Add a note about AI commands if any were stripped
        if has_ai {
            sql.push_str("\n\n-- Note: | ai command will enrich results with LLM classification in post-processing");
        }

        // Disclose the implicit auto-sort so the explained SQL is self-documenting.
        match auto_sort_decision {
            crate::search::query_processing::AutoSortDecision::Applied { field } => {
                sql.push_str(&format!(
                    "\n\n-- Note: implicit `| sort -{}` injected so the outer LIMIT keeps top-N (NAN-806)",
                    field
                ));
            }
            crate::search::query_processing::AutoSortDecision::SkippedNonNumeric => {
                sql.push_str(
                    "\n\n-- Note: trailing stats has only non-numeric aggregations; result-set truncation may be arbitrary. Add `| sort` to control ordering.",
                );
            }
            _ => {}
        }

        Ok(sql)
    }

    /// Execute SQL against ClickHouse and return results with total count
    pub(crate) async fn execute_clickhouse_sql(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        self.execute_clickhouse_sql_with_query_id(sql, limit, offset, None, None)
            .await
    }

    /// Execute SQL against ClickHouse with optional query_id and per-query settings
    pub(crate) async fn execute_clickhouse_sql_with_query_id(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
        query_id: Option<&str>,
        ch_settings: Option<&super::admission::ClickHouseQuerySettings>,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        // Resolve settings: explicit parameter > active_ch_settings on self > None
        let effective_settings = ch_settings.or(self.active_ch_settings.as_ref());

        // If both query_id and settings are provided, use the settings-aware method
        if let (Some(id), Some(settings)) = (query_id, effective_settings) {
            ch_executor
                .execute_sql_with_settings(sql, limit, offset, id, settings)
                .await
        } else if let Some(id) = query_id {
            ch_executor
                .execute_sql_with_query_id(sql, limit, offset, id)
                .await
        } else {
            ch_executor.execute_sql(sql, limit, offset).await
        }
    }

    /// Execute raw SQL against ClickHouse using outer wrappers for pagination/count.
    ///
    /// Raw SQL comes from the API, so LIMIT/OFFSET enforcement must be structural and
    /// must not rely on appending clauses directly to the user-provided SQL text.
    pub(crate) async fn execute_clickhouse_raw_sql(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;

        let paginated_sql = wrap_query_with_pagination(sql, limit, offset);
        let count_sql = wrap_query_for_count(sql);

        let (results, total_count) = tokio::join!(
            ch_executor.execute_sql_to_json(&paginated_sql),
            ch_executor.execute_count_query(&count_sql)
        );

        Ok((results?, total_count?))
    }

    /// Validate that SQL is a SELECT statement only
    fn validate_sql(&self, sql: &str) -> Result<(), SearchError> {
        validate_sql_query(sql)
    }
}
