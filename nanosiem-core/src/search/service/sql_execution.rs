// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::auth::ScopeSet;
use crate::search::execution::clickhouse_executor::{
    raw_sql_needs_skip_index_guard, wrap_query_for_count, wrap_query_with_pagination,
    BoundedCountInput, ClickHouseExecutor,
};
use crate::search::query_processing::enforce_source_scope;

/// NAN-2001: which raw-SQL ClickHouse identity a caller runs as. This is the ONE
/// security decision the raw-SQL handler makes — everything else (table
/// allowlist, table-function/`system.*` denial, audit-row hiding) is enforced by
/// ClickHouse against its own semantics. Threaded EXPLICITLY from the caller's
/// `audit:view` permission — never inferred from an empty `ScopeSet` (§3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RawSqlAuditAccess {
    /// Fail-closed default: caller lacks `audit:view`. Runs as
    /// `nanosiem_rawsql_noaudit`, whose RESTRICTIVE row policy hides
    /// `source_type='audit'` rows.
    #[default]
    Hidden,
    /// Caller HAS `audit:view`. Runs as the audit-capable `nanosiem_rawsql`.
    Visible,
}

impl SearchService {
    /// NAN-2001: select the raw-SQL executor for this caller's audit access. Raw
    /// SQL always runs on a dedicated feature identity — a missing executor is a
    /// hard error, never a fallback to the broad `nanosiem` account.
    fn rawsql_executor(
        &self,
        audit: RawSqlAuditAccess,
    ) -> Result<&ClickHouseExecutor, SearchError> {
        let executor = match audit {
            RawSqlAuditAccess::Visible => self.ch_executor_rawsql.as_ref(),
            RawSqlAuditAccess::Hidden => self.ch_executor_rawsql_noaudit.as_ref(),
        };
        executor.ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "raw-SQL ClickHouse feature identity not configured (NAN-2001)".into(),
            ))
        })
    }

    /// Execute a raw SQL query (SELECT only).
    ///
    /// NAN-2001: the table allowlist and the audit-view gate are enforced by
    /// ClickHouse via `audit`-selected feature identities (grants + a RESTRICTIVE
    /// row policy), NOT by the retired in-app AST walk. `validate_sql` is now only
    /// a mandatory `system`/`information_schema` reject + friendly-error UX.
    ///
    /// NAN-1799 FAIL-CLOSED (unchanged): raw SQL cannot be AST-injected with a
    /// per-source exclusion, so a caller with ANY restricted source is refused
    /// outright (deny-when-scoped) — orthogonal to, and evaluated before, the
    /// `RawSqlAuditAccess` routing.
    #[instrument(skip(self, scope))]
    pub async fn search_sql(
        &self,
        request: RawSqlRequest,
        scope: &ScopeSet,
        audit: RawSqlAuditAccess,
    ) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        if scope.is_restricted() {
            return Err(SearchError::SqlValidationError(
                "Raw SQL search is not available for accounts with per-source access \
                 restrictions. Use the piped query language instead."
                    .to_string(),
            ));
        }

        // NAN-2001: select the executor ONCE by audit access; the main query and
        // the count companion both run on the chosen feature identity, so a
        // noaudit caller can never read audit rows (nor their volume via count).
        let executor = self.rawsql_executor(audit)?;

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

        // Execute the query on the selected raw-SQL identity.
        let (results, total_count) = self
            .execute_clickhouse_raw_sql(executor, sql, limit, offset)
            .await?;

        // Calculate field statistics
        let mut stats = FieldStatistics::new();
        for row in &results {
            stats.process_row(row);
        }
        let fields = stats.get_field_info(self.config.top_values_count);

        // NAN-2001: the raw-SQL result histogram is deliberately omitted. It was a
        // generic full-time-range logs timeline (not tied to the query) that ran
        // on the broad `ch_client` — for a noaudit caller that would leak
        // audit-event volume and bypass the feature identity. Routing it through
        // the selected identity would ripple into the field-stats histogram
        // helper; omitting is the low-risk, secure choice (the frontend already
        // handles `histogram: null`, exactly as the piped path's error degrade).
        let histogram = None;

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
    ///
    /// `scope` (NAN-1799): the caller's source-scope deny-set is injected into
    /// the query text exactly as the executed path does, so "Inspect SQL"
    /// renders the SQL that would actually run for this caller (including the
    /// scope exclusion) and the two can never diverge.
    #[instrument(skip(self, scope), fields(query = %query))]
    pub async fn explain(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        table_view: bool,
        dataset: Option<&str>,
        scope: &ScopeSet,
    ) -> Result<String, SearchError> {
        // Validate time range
        time_range.validate()?;

        // NAN-1569: resolve the per-query dataset profile so explain matches the
        // executed path — without this, "Inspect SQL" validates against and
        // renders the logs table for a spans/metrics query (misleading FROM logs).
        let query_profile = self.dataset_profile(dataset);

        // Extract time modifiers and clean the query
        let (cleaned_query, _, _) = extract_time_modifiers(query);

        // NAN-1799: same injection point as `search()` — before the parse, so
        // every explain branch below (prevalence pushdown included) renders
        // the gated query. Empty deny-set → text unchanged.
        let cleaned_query = enforce_source_scope(&cleaned_query, scope.deny_set())?;

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

        // NAN-1694: when the query would push the prevalence filter/enrich into
        // ClickHouse at execute time (`search_with_prevalence_join`), explain the REAL
        // pushdown SQL — the dictGet host_count WHERE that actually runs — instead of the
        // stale stripped base scan + "applied after enrichment" note that no longer
        // executes. Routed through the SAME gate (`prevalence_join_applies`) and the SAME
        // builder (`generate_prevalence_pushdown_sql`) as the execute path so the two can
        // never diverge. Prevalence is logs-only, so this deliberately uses the tenant
        // logs generator (`ch_sql_generator`), matching the execute path — not the
        // dataset generator.
        let prevalence_commands = extract_prevalence_commands(&parsed);
        if crate::search::query_processing::command_extraction::prevalence_join_applies(
            &parsed,
            &prevalence_commands,
            &post_prevalence.commands,
            /* is_clickhouse = */ true,
            /* has_prevalence_svc = */ self.prevalence_service.is_some(),
        )
            // Restricted execution cannot use source-less prevalence
            // dictionaries; keep Inspect SQL on the same residual path.
            // NAN-2219: the ARTIFACT half, byte-for-byte the same term the
            // execute path evaluates in `core_search` — the two must never
            // disagree or "Inspect SQL" renders a shape that does not run.
            && crate::auth::ArtifactScope::from_scope(scope).is_unrestricted()
            // NAN-1798 P2: mirror the execute path — risk-touching queries do
            // not take the prevalence pushdown (see core_search).
            && !super::touches_risk_dataset(dataset, query)
        {
            let rarity_threshold = if let Some(ref s) = self.prevalence_service {
                s.rarity_threshold().await
            } else {
                3
            };
            let tr = TimeRange::new(time_range.start, time_range.end);
            // NAN-1705: explain is SQL-only (no CH execution), so it renders the
            // pushdown WITHOUT the runtime rescue probe (empty rescue → the base
            // dict projections, byte-identical to the pre-rescue form). At execute
            // time a non-empty rescue only rewrites the `_hp/_dp/_ip_host_count`
            // projection aliases via `transform(...)`; the note keeps "Inspect
            // SQL" honest about that delta.
            let (mut sql, _num_pushed) = self.generate_prevalence_pushdown_sql(
                &parsed,
                &prevalence_commands,
                &post_prevalence.commands,
                &tr,
                rarity_threshold,
                &crate::search::service::prevalence_processing::PrevalenceRescue::default(),
            )?;
            // The rescue runs at execute time when there's a hash/domain count
            // condition OR (residual #2) an `enrich=true | where host_count < N`
            // / `| where is_rare` decorated filter.
            let has_count_conditions = prevalence_commands
                .iter()
                .any(|cmd| cmd.conditions.iter().any(|c| c.field.is_count_field()));
            let enrich_decorated_filter = prevalence_commands.iter().any(|cmd| cmd.enrich)
                && crate::search::service::prevalence_processing::decorated_filter_rescue_threshold(
                    &post_prevalence.commands,
                    rarity_threshold,
                )
                .is_some();
            if has_count_conditions || enrich_decorated_filter {
                sql.push_str(
                    "\n\n-- Note: at execute time, artifacts the prevalence dict cannot resolve (brand-new,\n-- inside the dict cache LIFETIME) are re-verified against *_prevalence_summary and, if rare,\n-- their _hp/_dp/_ip_host_count projection is transform()-rewritten to the fresh count so the\n-- filter and every decoration/`| where host_count` see the truth in-SQL (NAN-1705). The IP\n-- dimension is rescued only for the enrich+decorated-filter form; broad rules are bounded\n-- (miss-key cap) and rarest-capped with a WARN on overflow.",
                );
            }
            return Ok(sql);
        }

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

        // Strip a TERMINAL `| retro` page directive: it short-circuits to a
        // prevalence-weighted hunt-summary page view in the search service and
        // has no single SQL, so codegen rejects it (NAN-1580). Explaining the
        // base query shows the underlying observable scan instead of a 400. A
        // MID-pipeline `retro` is not stripped (the terminal command differs),
        // so it still correctly surfaces the "must be last" rejection.
        let retro_page = matches!(
            &query_for_sql,
            Query::Piped {
                command: Command::Retro { .. },
                ..
            }
        );
        let query_for_sql = if retro_page {
            match query_for_sql {
                Query::Piped { source, .. } => *source,
                other => other,
            }
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
            .dataset_generator(dataset, query, scope.deny_set())
            .await
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

        // Note the stripped retro page directive.
        if retro_page {
            sql.push_str("\n\n-- Note: `| retro` renders a prevalence-weighted hunt summary (page view); the SQL above is the underlying observable scan it sweeps.");
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
        preserve_columns: bool,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        self.execute_clickhouse_sql_with_query_id(
            sql,
            limit,
            offset,
            None,
            None,
            None,
            None,
            preserve_columns,
        )
        .await
    }

    /// Execute SQL against ClickHouse with optional query_id and per-query settings.
    ///
    /// `bounded_count` (NAN-1635, finding 2.3): caller-supplied bounded input
    /// for the raw-search count companion; `None` keeps the unbounded wrap.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute_clickhouse_sql_with_query_id(
        &self,
        sql: &str,
        limit: usize,
        offset: usize,
        query_id: Option<&str>,
        ch_settings: Option<&super::admission::ClickHouseQuerySettings>,
        bounded_count: Option<BoundedCountInput<'_>>,
        execution_limits: Option<&crate::search::SearchExecutionLimits>,
        // `preserve_columns`: keep every selected column, even when empty.
        // Grouped rows (`stats … by`, `top`, `rare`) require it — pruning an
        // empty group-by key reports the bucket as a bare count (NAN-1848).
        preserve_columns: bool,
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
                .execute_sql_with_settings(
                    sql,
                    limit,
                    offset,
                    id,
                    settings,
                    bounded_count,
                    execution_limits,
                    preserve_columns,
                )
                .await
        } else if let Some(id) = query_id {
            ch_executor
                .execute_sql_with_query_id(
                    sql,
                    limit,
                    offset,
                    id,
                    bounded_count,
                    execution_limits,
                    preserve_columns,
                )
                .await
        } else {
            ch_executor.execute_sql(sql, limit, offset, preserve_columns).await
        }
    }

    /// Execute raw SQL against ClickHouse using outer wrappers for pagination/count.
    ///
    /// Raw SQL comes from the API, so LIMIT/OFFSET enforcement must be structural and
    /// must not rely on appending clauses directly to the user-provided SQL text.
    pub(crate) async fn execute_clickhouse_raw_sql(
        &self,
        executor: &ClickHouseExecutor,
        sql: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<serde_json::Value>, u64), SearchError> {
        let mut paginated_sql = wrap_query_with_pagination(sql, limit, offset);
        let mut count_sql = wrap_query_for_count(sql);
        // NAN-2277: raw SQL bypasses the codegen-side `use_skip_indexes=0`
        // guard (NAN-2274), so a scalar-Map query submitted here can still hit
        // the CH >=26.4 unkillable planner wedge (ClickHouse#113003). Apply the
        // same guard when the text carries the map pattern; top-level SETTINGS
        // on the wrap applies to the whole query including the subquery.
        if raw_sql_needs_skip_index_guard(sql) {
            paginated_sql.push_str(" SETTINGS use_skip_indexes = 0");
            count_sql.push_str(" SETTINGS use_skip_indexes = 0");
        }

        // NAN-2001: main query + count companion both run on the selected
        // raw-SQL identity so neither the rows nor the total leak audit data.
        let (results, total_count) = tokio::join!(
            executor.execute_sql_to_json(&paginated_sql),
            executor.execute_count_query(&count_sql)
        );

        Ok((results?, total_count?))
    }

    /// Validate that SQL is a SELECT statement only
    fn validate_sql(&self, sql: &str) -> Result<(), SearchError> {
        validate_sql_query(sql)
    }
}
