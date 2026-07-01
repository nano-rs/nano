// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::sql_hygiene::escape_sql_string;

impl SearchService {
    /// Execute a search with JOIN-based prevalence filtering
    ///
    /// This generates a single SQL query that JOINs logs with prevalence tables,
    /// allowing ClickHouse to filter efficiently at the database level.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn search_with_prevalence_join(
        &self,
        query: &Query,
        prevalence_commands: &[PrevalenceCommandInfo],
        post_prevalence_commands: &[Command],
        lookup_commands: &[LookupCommandInfo],
        inputlookup_commands: &[InputLookupCommandInfo],
        post_inputlookup_commands: &[Command],
        time_range: &TimeRange,
        request: &SearchRequest,
        cleaned_query: &str,
        adjusted_time_range: &TimeRangeInput,
        limit: usize,
        offset: usize,
        start_time: Instant,
        auto_sort_decision: &crate::search::query_processing::AutoSortDecision,
    ) -> Result<SearchResponse, SearchError> {
        // Get the time window from prevalence command
        let time_window = prevalence_commands
            .first()
            .and_then(|cmd| cmd.time_window.as_ref())
            .map(|tw| ast_to_prevalence_time_window(Some(tw)))
            .unwrap_or(PrevalenceTimeWindow::ThirtyDays);

        // Strip prevalence and post-prevalence commands from query for base SQL generation
        let base_query = strip_prevalence_and_after(query);

        // Generate base SQL for the search part
        let base_sql = self
            .ch_sql_generator
            .generate(&base_query, time_range)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // NAN-362: Prior to the dict-based rewrite, this path built CTEs that aggregated the
        // full *_prevalence_agg universe and LEFT JOINed them — which OOMed ClickHouse on any
        // non-trivial base query. A count-based short-circuit used to guard that. The new path
        // only issues dictGet() calls scoped to rows in the base query, so the guard is no
        // longer needed.

        // Get rarity threshold from prevalence service config
        let rarity_threshold = if let Some(ref prev_svc) = self.prevalence_service {
            prev_svc.rarity_threshold().await
        } else {
            3 // default
        };

        // Generate the JOIN-based SQL with prevalence filtering
        // num_commands_pushed indicates how many post-prevalence commands were pushed into SQL
        // (aggregation + trailing sort/head/etc.) and should be skipped in Rust post-processing
        let (sql, num_commands_pushed) = self.generate_prevalence_join_sql(
            &base_sql,
            post_prevalence_commands,
            time_window,
            rarity_threshold,
            limit,
            offset,
        )?;

        tracing::debug!(
            "Generated JOIN-based prevalence SQL (length: {} chars)",
            sql.len()
        );
        // Log whether a WHERE clause was generated (detail at debug level)
        if let Some(where_pos) = sql.to_uppercase().rfind("\nWHERE ") {
            let where_clause = &sql[where_pos..sql.len().min(where_pos + 500)];
            tracing::debug!("Generated SQL WHERE clause: {}", where_clause);
        } else {
            tracing::warn!("No WHERE clause found in generated prevalence SQL!");
        }

        // Execute the query with timing
        let sql_start = Instant::now();
        let (mut results, total_count) = self.execute_clickhouse_sql(&sql, limit, offset).await?;
        tracing::info!(
            duration_ms = sql_start.elapsed().as_millis() as u64,
            result_count = results.len(),
            "Prevalence JOIN executed"
        );

        // Strip internal lookup fields used for SQL JOINs (these are implementation details)
        strip_internal_lookup_fields(&mut results);

        // Apply lookup enrichment if there are lookup commands
        if !lookup_commands.is_empty() {
            results =
                apply_lookup_enrichment(results, lookup_commands, self.lookup_service.as_ref())
                    .await?;
        }

        // Apply inputlookup enrichment if there are inputlookup commands.
        // Partial-failure warnings are logged but not surfaced here, matching
        // how this path treats post-processing warnings (detection path).
        if !inputlookup_commands.is_empty() {
            tracing::debug!(
                "Applying {} inputlookup commands",
                inputlookup_commands.len()
            );
            let mut enrichment_warnings: Vec<String> = Vec::new();
            results = apply_inputlookup_enrichment(
                results,
                inputlookup_commands,
                self.inputlookup_service.as_ref(),
                &mut enrichment_warnings,
            )
            .await?;
            for w in &enrichment_warnings {
                tracing::warn!("InputLookup enrichment degraded: {}", w);
            }
            tracing::debug!("After inputlookup enrichment: {} results", results.len());
        }

        // Apply post-inputlookup commands (like table, where on inputlookup_* fields)
        if !post_inputlookup_commands.is_empty() {
            tracing::debug!(
                "Applying {} post-inputlookup commands to {} results",
                post_inputlookup_commands.len(),
                results.len()
            );
            let pp = apply_post_prevalence_commands(results, post_inputlookup_commands)?;
            results = pp.results;
            // Runtime warnings from prevalence_join are not surfaced (detection path)
            tracing::debug!("After post-inputlookup commands: {} results", results.len());
        }

        // Restructure flat prevalence fields from JOIN into nested _prevalence structure
        let restructure_start = Instant::now();
        results = Self::restructure_prevalence_fields_from_join(results);
        tracing::info!(
            duration_ms = restructure_start.elapsed().as_millis() as u64,
            "Prevalence field restructure complete"
        );

        // Apply post-prevalence commands that weren't handled in SQL.
        //
        // Commands already handled in SQL generation:
        // - WHERE conditions (except those referencing _prevalence.* nested fields)
        // - EVAL expressions (computed as SQL columns)
        // - Aggregation commands pushed to SQL (Stats, Top, Rare, Timechart) + trailing
        //   Sort/Head/Tail/Table/Fields/Rename/Dedup (tracked by num_commands_pushed)
        //
        // Find which commands were pushed to SQL by re-running the partition logic
        let pushed_start_idx = post_prevalence_commands.iter().position(|cmd| {
            matches!(
                cmd,
                Command::Stats { .. }
                    | Command::Top { .. }
                    | Command::Rare { .. }
                    | Command::Timechart { .. }
            )
        });
        // num_commands_pushed is the end index (exclusive) in the command array,
        // so the pushed range is [pushed_start_idx..num_commands_pushed)
        let pushed_range = if num_commands_pushed > 0 {
            pushed_start_idx.map(|start| start..num_commands_pushed)
        } else {
            None
        };

        tracing::debug!(
            "Filtering post-prevalence commands for post-processing (total: {}, pushed to SQL: {})",
            post_prevalence_commands.len(),
            num_commands_pushed,
        );
        let post_process_commands: Vec<Command> = post_prevalence_commands
            .iter()
            .enumerate()
            .filter(|(i, cmd)| {
                // Skip commands that were pushed to SQL
                if let Some(ref range) = pushed_range {
                    if range.contains(i) {
                        tracing::debug!("Skipping command {} (pushed to SQL): {:?}", i, cmd);
                        return false;
                    }
                }
                match cmd {
                    Command::Where { condition } => {
                        // Only keep WHERE commands that reference _prevalence.* fields
                        let keep = self.condition_references_prevalence_nested_fields(condition);
                        tracing::debug!(
                            "WHERE condition {:?}: keep_for_post_process={} (refs _prevalence.*)",
                            condition,
                            keep
                        );
                        keep
                    }
                    Command::Eval { .. } => {
                        // EVAL is already computed as SQL columns in the prevalence JOIN
                        false
                    }
                    _ => true, // Keep all other non-WHERE commands
                }
            })
            .map(|(_, cmd)| cmd.clone())
            .collect();
        if !post_process_commands.is_empty() {
            tracing::debug!(
                "Applying {} post-prevalence commands (including _prevalence.* WHERE filters)",
                post_process_commands.len()
            );
            results = apply_post_prevalence_commands(results, &post_process_commands)?.results;
        }

        // NAN-366: Strip the nested `_prevalence` object from the output. It's kept only
        // long enough for post-processing WHERE filters using `_prevalence.*` dot-notation
        // (handled above). The same data is already exposed as top-level flat fields
        // (host_count, first_seen, last_seen, is_rare, prevalence_score, prevalence_type,
        // prevalence_artifact, total_occurrences), so emitting the nested copy is redundant.
        for row in &mut results {
            if let Some(obj) = row.as_object_mut() {
                obj.remove("_prevalence");
            }
        }

        // Calculate field statistics (skip if requested for detection execution)
        let fields = if request.skip_field_stats {
            Vec::new()
        } else {
            let stats_start = Instant::now();
            let mut stats = FieldStatistics::new();
            for row in &results {
                stats.process_row(row);
            }
            let fields = stats.get_field_info(self.config.top_values_count);
            tracing::info!(
                duration_ms = stats_start.elapsed().as_millis() as u64,
                "Field stats computed"
            );
            fields
        };

        // Generate histogram using cleaned query (with time modifiers removed)
        // Skip if requested for detection execution
        let histogram = if request.skip_histogram {
            None
        } else {
            let histogram_start = Instant::now();
            // NAN-1428: derived companion id so cancel kills the histogram too.
            let hist_qid = request.request_id.as_ref().map(|r| format!("{r}-hist"));
            let histogram = self
                .generate_histogram(
                    cleaned_query,
                    adjusted_time_range,
                    hist_qid.as_deref(),
                    crate::query::Dataset::from_selector(
                        request.dataset.as_deref().unwrap_or("logs"),
                    ),
                )
                .await?;
            tracing::info!(
                duration_ms = histogram_start.elapsed().as_millis() as u64,
                "Histogram generated"
            );
            Some(histogram)
        };

        // Analyze query cost and generate warnings
        let cost_analysis = analyze_query_cost(query);
        let mut warnings_output: Vec<QueryWarningOutput> = cost_analysis
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

        // NAN-806: surface the implicit auto-sort decision here too — the
        // prevalence-join path bypasses the standard merge in `search()`.
        if let Some(w) =
            crate::search::query_processing::auto_sort_warning(auto_sort_decision)
        {
            warnings_output.push(w);
        }

        let (warnings, cost_score) = if warnings_output.is_empty() {
            (None, None)
        } else {
            (Some(warnings_output), Some(cost_analysis.estimated_cost))
        };

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Determine display type from the query AST
        let display_type = determine_display_type(query);

        // Extract column order from table command if present
        let column_order = get_column_order(query);

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
            histogram,
            warnings,
            cost_score,
            display_type: Some(display_type),
            column_order,
        })
    }

    /// Generate SQL with JOINs to prevalence tables
    ///
    /// Returns (sql, num_commands_pushed_to_sql) — the caller should skip the first
    /// `num_commands_pushed_to_sql` post-prevalence commands in Rust post-processing
    /// since they have already been executed in ClickHouse.
    fn generate_prevalence_join_sql(
        &self,
        base_sql: &str,
        post_prevalence_commands: &[Command],
        time_window: PrevalenceTimeWindow,
        rarity_threshold: u64,
        limit: usize,
        offset: usize,
    ) -> Result<(String, usize), SearchError> {
        tracing::debug!(
            "generate_prevalence_join_sql: {} post-prevalence commands",
            post_prevalence_commands.len()
        );
        for (i, cmd) in post_prevalence_commands.iter().enumerate() {
            tracing::debug!("  Post-prevalence command {}: {:?}", i, cmd);
        }

        // NAN-364: per-window sibling dicts (_1d/_7d) were rolled back — their source queries
        // did unbounded `uniqMerge GROUP BY entity` over prevalence_agg before the host_count
        // filter, reproducing the same OOM at dict-refresh time that NAN-362 tried to kill
        // at query time. We now use the single 30d dict for all windows and mask entries
        // whose `last_seen` is older than the requested window to the 9999 sentinel. 1h is
        // still rejected — dict refresh is 5–10 min, so sub-day granularity isn't meaningful.
        let window_cutoff_sql: &str = match time_window {
            PrevalenceTimeWindow::OneHour => {
                return Err(SearchError::SqlGenError(
                    "prevalence window=1h is not supported; use 24h, 7d, or 30d".to_string(),
                ));
            }
            PrevalenceTimeWindow::TwentyFourHours => "now() - INTERVAL 1 DAY",
            PrevalenceTimeWindow::SevenDays => "now() - INTERVAL 7 DAY",
            // 30d: use epoch-0 so the mask is a no-op (dict already windowed to 30d).
            PrevalenceTimeWindow::ThirtyDays => "toDateTime64(0, 6)",
        };
        // Prevalence summary dicts are SCHEMA-AGNOSTIC (clickhouse/ocsf/init.sql:697-823):
        // OCSF reuses the exact same `nanosiem.{hash,domain,ip}_prevalence_dict`, keyed by the
        // canonical hash/domain/ip string. So the dict names are identical for UDM and OCSF —
        // no profile branching needed here.
        let domain_dict = "nanosiem.domain_prevalence_dict".to_string();
        let ip_dict = "nanosiem.ip_prevalence_dict".to_string();
        let hash_dict = "nanosiem.hash_prevalence_dict".to_string();

        // NAN-1241: resolve the UDM-semantic lookup columns to the active schema's physical
        // columns. UDM returns the same bare literal (byte-identical output); OCSF returns the
        // promoted dotted column (e.g. `"dst_endpoint.hostname"`). `None` => the schema has no
        // column for that concept, so that lookup branch is dropped rather than referencing a
        // missing column (which would 500 on OCSF).
        let profile = self.active_profile.as_ref();
        let dest_host_col = profile.udm_column_sql("dest_host");
        let src_host_col = profile.udm_column_sql("src_host");
        let query_col = profile.udm_column_sql("query");
        let dest_ip_col = profile.udm_column_sql("dest_ip");
        let src_ip_col = profile.udm_column_sql("src_ip");
        let file_hash_col = profile.udm_column_sql("file_hash");
        let process_hash_col = profile.udm_column_sql("process_hash");

        // Domain lookup key: first non-empty non-IP domain field. Skip any branch whose column
        // is unmapped; if no domain column maps at all, emit NULL (dictGet then falls through to
        // the 9999 sentinel — i.e. "not tracked").
        let domain_lookup_expr = {
            let mut branches: Vec<String> = Vec::new();
            if let Some(c) = &dest_host_col {
                branches.push(format!("nullIf(CASE WHEN {c} != '' AND match({c}, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+$') = 0 THEN lower({c}) ELSE '' END, '')"));
            }
            if let Some(c) = &src_host_col {
                branches.push(format!("nullIf(CASE WHEN {c} != '' AND match({c}, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+$') = 0 THEN lower({c}) ELSE '' END, '')"));
            }
            if let Some(c) = &query_col {
                branches.push(format!("nullIf(lower({c}), '')"));
            }
            if branches.is_empty() {
                "NULL".to_string()
            } else {
                format!("COALESCE(\n            {}\n        )", branches.join(",\n            "))
            }
        };

        // IP lookup key: first non-empty IP field (or dest_host when it's an IP literal).
        let ip_lookup_expr = {
            let mut branches: Vec<String> = Vec::new();
            if let Some(c) = &dest_ip_col {
                branches.push(format!("nullIf({c}, '')"));
            }
            if let Some(c) = &src_ip_col {
                branches.push(format!("nullIf({c}, '')"));
            }
            if let Some(c) = &dest_host_col {
                branches.push(format!("nullIf(CASE WHEN match({c}, '^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+$') THEN {c} ELSE '' END, '')"));
            }
            if branches.is_empty() {
                "NULL".to_string()
            } else {
                format!("COALESCE(\n            {}\n        )", branches.join(",\n            "))
            }
        };

        // Hash lookup key: first non-empty hash field, lowercased for case-insensitive match.
        let hash_lookup_expr = {
            let mut branches: Vec<String> = Vec::new();
            if let Some(c) = &file_hash_col {
                branches.push(format!("nullIf({c}, '')"));
            }
            if let Some(c) = &process_hash_col {
                branches.push(format!("nullIf({c}, '')"));
            }
            if branches.is_empty() {
                "NULL".to_string()
            } else {
                format!(
                    "lower(COALESCE(\n            {}\n        ))",
                    branches.join(",\n            ")
                )
            }
        };

        // `prevalence_artifact` CASE arms project the human-facing artifact value per winning
        // entity type from whichever columns the schema maps.
        //
        // `udm_column_sql` returns a bare column for UDM, but for some OCSF fields
        // (e.g. process_hash) a class-spanning EXPRESSION like
        // `if(`process.file.hashes.sha256` != '', …, `actor.…`)`. A bare column is
        // `l.`-qualified against `FROM base_logs l`; an expression must NOT be —
        // `l.if(…)` is a bogus function call (CH: "Function `l.if` does not exist",
        // NAN-1291). Its inner column refs resolve unqualified against the single
        // source table. UDM (always a bare column) is byte-identical.
        let artifact_col = |c: &str| -> String {
            if c.contains('(') {
                format!("nullIf({c}, '')")
            } else {
                format!("nullIf(l.{c}, '')")
            }
        };
        let domain_artifact_expr = {
            let mut parts: Vec<String> = Vec::new();
            if let Some(c) = &dest_host_col {
                parts.push(artifact_col(c));
            }
            if let Some(c) = &src_host_col {
                parts.push(artifact_col(c));
            }
            if let Some(c) = &query_col {
                parts.push(artifact_col(c));
            }
            parts.push("''".to_string());
            format!("COALESCE({})", parts.join(", "))
        };
        let ip_artifact_expr = {
            let mut parts: Vec<String> = Vec::new();
            if let Some(c) = &dest_ip_col {
                parts.push(artifact_col(c));
            }
            if let Some(c) = &src_ip_col {
                parts.push(artifact_col(c));
            }
            if let Some(c) = &dest_host_col {
                parts.push(artifact_col(c));
            }
            parts.push("''".to_string());
            format!("COALESCE({})", parts.join(", "))
        };
        let hash_artifact_expr = {
            let mut parts: Vec<String> = Vec::new();
            if let Some(c) = &file_hash_col {
                parts.push(artifact_col(c));
            }
            if let Some(c) = &process_hash_col {
                parts.push(artifact_col(c));
            }
            parts.push("''".to_string());
            format!("COALESCE({})", parts.join(", "))
        };

        // Build the WHERE clause and EVAL expressions from post-prevalence commands
        // EVAL expressions must be processed first so WHERE can reference them
        let mut where_conditions = Vec::new();
        let mut eval_expressions: Vec<(String, String)> = Vec::new(); // (field_name, sql_expression)
        let mut eval_field_names: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut other_commands = Vec::new();

        // First pass: collect EVAL expressions
        // Use prevalence context to properly qualify ambiguous field names like first_seen
        for cmd in post_prevalence_commands {
            if let Command::Eval { assignments } = cmd {
                for assignment in assignments {
                    let field_name = assignment.field.clone();
                    // Pass true for in_prevalence_context to resolve ambiguous fields
                    let expr_sql = self.eval_expression_to_clickhouse_sql_with_context(
                        &assignment.expression,
                        true,
                    )?;
                    eval_expressions.push((field_name.clone(), expr_sql));
                    eval_field_names.insert(field_name);
                }
            }
        }

        // Second pass: collect WHERE conditions and other commands
        // Skip WHERE conditions that reference _prevalence.* nested fields - those must be
        // handled in post-processing since they don't exist until after restructure_prevalence_fields_from_join
        for cmd in post_prevalence_commands {
            match cmd {
                Command::Where { condition } => {
                    // Check if this condition references _prevalence.* nested fields
                    if self.condition_references_prevalence_nested_fields(condition) {
                        tracing::debug!(
                            "Skipping WHERE condition for SQL (references _prevalence.*): {:?}",
                            condition
                        );
                        // This will be handled in post-processing
                        other_commands.push(cmd);
                    } else {
                        // Convert the condition to SQL, passing eval field names for proper reference
                        let condition_sql = self.prevalence_condition_to_sql_with_eval(
                            condition,
                            &eval_field_names,
                            rarity_threshold,
                        )?;
                        tracing::debug!("Adding WHERE condition to SQL: {}", condition_sql);
                        where_conditions.push(condition_sql);
                    }
                }
                Command::Eval { .. } => {
                    // Already processed in first pass
                }
                _ => {
                    other_commands.push(cmd);
                }
            }
        }

        // Strip ORDER BY and LIMIT from base SQL since we'll add our own
        let base_sql_clean = base_sql.trim().trim_end_matches(';');

        // Remove ORDER BY clause if present (case insensitive)
        let base_sql_no_order =
            if let Some(order_pos) = base_sql_clean.to_lowercase().rfind(" order by ") {
                &base_sql_clean[..order_pos]
            } else {
                base_sql_clean
            };

        // Build eval columns string for the SELECT clause
        let eval_columns = if eval_expressions.is_empty() {
            String::new()
        } else {
            let cols: Vec<String> = eval_expressions
                .iter()
                .map(|(name, expr)| format!("    ({}) AS {}", expr, name))
                .collect();
            format!(",\n{}", cols.join(",\n"))
        };

        // Build is_rare and prevalence_score SQL using configurable rarity threshold.
        // NAN-366: "winner" = the entity with the LOWEST host_count (rarest entity wins).
        // Previous logic picked domain first, which hid rare IPs/hashes behind common domains
        // (e.g. a row with IP host_count=1 but domain host_count=2 failed `where host_count < 2`).
        // The sentinel 9999 stands in for "not tracked" — least() handles it naturally since
        // a real rare count is always less than 9999.
        let rt = rarity_threshold.max(1);
        // `_min_host_count` is the effective flattened host_count (still 9999 if none matched).
        // Defined here as an SQL fragment so downstream CASEs reuse the same winner selection.
        let min_host_count = "least(_dp_host_count, _ip_host_count, _hp_host_count)";
        let is_rare_sql = format!(
            r#"CASE
        WHEN {m} < 9999 THEN {m} < {rt}
        ELSE false
    END"#,
            m = min_host_count,
            rt = rt,
        );
        let prevalence_score_sql = format!(
            r#"CASE
        WHEN {m} >= 9999 THEN 0
        WHEN {m} = 0 THEN 0
        WHEN {m} < {t} THEN toUInt8(round(least(toFloat64({m}) / {t} * 20, 20)))
        WHEN {m} < {t} * 2 THEN toUInt8(round(20 + (toFloat64({m}) - {t}) / {t} * 30))
        WHEN {m} < {t} * 10 THEN toUInt8(round(50 + (toFloat64({m}) - {t} * 2) / ({t} * 8) * 30))
        ELSE toUInt8(round(80 + least((toFloat64({m}) - {t} * 10) / ({t} * 90) * 20, 20)))
    END"#,
            m = min_host_count,
            t = rt,
        );

        // Build the final SQL using dictGet() against precomputed per-window prevalence dicts.
        // NAN-362: Replaces the old CTE + LEFT JOIN path which aggregated the entire
        // *_prevalence_agg universe before joining (O(universe) memory — OOM on any
        // non-trivial time window). Dict lookups are O(rows-in-result) instead.
        // Priority for convenience fields: domain > IP > hash
        // Sentinel value 9999 = "common or not tracked" (dicts only load entities with
        // host_count < 1000).
        let sql = format!(
            r#"WITH raw_logs AS (
    SELECT * FROM (
        {base_sql}
    )
),
logs_with_keys AS (
    SELECT *,
        -- Domain lookup: first non-empty domain field (exclude IPs)
        {domain_lookup_expr} AS _domain_lookup,
        -- IP lookup: first non-empty IP field (or dest_host if it's an IP)
        {ip_lookup_expr} AS _ip_lookup,
        -- Hash lookup: first non-empty hash field (lowercased for case-insensitive matching)
        {hash_lookup_expr} AS _hash_lookup
    FROM raw_logs
),
base_logs AS (
    SELECT *,
        -- Mask host_count to 9999 (sentinel) when last_seen is outside the requested window.
        -- This is how NAN-364 serves sub-30d windows from the 30d dict without per-window dicts.
        if(dictGetOrDefault('{domain_dict}', 'last_seen', ifNull(_domain_lookup, ''), toDateTime64(0, 6)) >= {window_cutoff_sql},
           dictGetOrDefault('{domain_dict}', 'host_count', ifNull(_domain_lookup, ''), toUInt16(9999)),
           toUInt16(9999)) AS _dp_host_count,
        dictGetOrDefault('{domain_dict}', 'first_seen', ifNull(_domain_lookup, ''), toDateTime64(0, 6)) AS _dp_first_seen,
        dictGetOrDefault('{domain_dict}', 'last_seen', ifNull(_domain_lookup, ''), toDateTime64(0, 6)) AS _dp_last_seen,
        dictGetOrDefault('{domain_dict}', 'total_occurrences', ifNull(_domain_lookup, ''), toUInt64(0)) AS _dp_total_occurrences,
        if(dictGetOrDefault('{ip_dict}', 'last_seen', ifNull(_ip_lookup, ''), toDateTime64(0, 6)) >= {window_cutoff_sql},
           dictGetOrDefault('{ip_dict}', 'host_count', ifNull(_ip_lookup, ''), toUInt16(9999)),
           toUInt16(9999)) AS _ip_host_count,
        dictGetOrDefault('{ip_dict}', 'first_seen', ifNull(_ip_lookup, ''), toDateTime64(0, 6)) AS _ip_first_seen,
        dictGetOrDefault('{ip_dict}', 'last_seen', ifNull(_ip_lookup, ''), toDateTime64(0, 6)) AS _ip_last_seen,
        dictGetOrDefault('{ip_dict}', 'total_occurrences', ifNull(_ip_lookup, ''), toUInt64(0)) AS _ip_total_occurrences,
        if(dictGetOrDefault('{hash_dict}', 'last_seen', _hash_lookup, toDateTime64(0, 6)) >= {window_cutoff_sql},
           dictGetOrDefault('{hash_dict}', 'host_count', _hash_lookup, toUInt16(9999)),
           toUInt16(9999)) AS _hp_host_count,
        dictGetOrDefault('{hash_dict}', 'first_seen', _hash_lookup, toDateTime64(0, 6)) AS _hp_first_seen,
        dictGetOrDefault('{hash_dict}', 'last_seen', _hash_lookup, toDateTime64(0, 6)) AS _hp_last_seen,
        dictGetOrDefault('{hash_dict}', 'total_occurrences', _hash_lookup, toUInt64(0)) AS _hp_total_occurrences
    FROM logs_with_keys
)
SELECT
    l.*,
    -- NAN-366: winner = rarest entity (lowest host_count). Ties break domain → ip → hash
    -- only as a last resort, after the min has been established, so "rare IP + common domain"
    -- no longer hides behind the domain.
    CASE
        WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) >= 9999 THEN NULL
        ELSE least(_dp_host_count, _ip_host_count, _hp_host_count)
    END AS host_count,
    CASE
        WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_first_seen
        WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_first_seen
        WHEN _hp_host_count < 9999 THEN _hp_first_seen
        ELSE NULL
    END AS prevalence_first_seen,
    CASE
        WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_last_seen
        WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_last_seen
        WHEN _hp_host_count < 9999 THEN _hp_last_seen
        ELSE NULL
    END AS prevalence_last_seen,
    CASE
        WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_total_occurrences
        WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_total_occurrences
        WHEN _hp_host_count < 9999 THEN _hp_total_occurrences
        ELSE NULL
    END AS total_occurrences,
    {is_rare_sql} AS is_rare,
    {prevalence_score_sql} AS prevalence_score,
    CASE
        WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN 'domain'
        WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN 'ip'
        WHEN _hp_host_count < 9999 THEN 'hash'
        ELSE NULL
    END AS prevalence_type,
    CASE
        WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count
            THEN {domain_artifact_expr}
        WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count
            THEN {ip_artifact_expr}
        WHEN _hp_host_count < 9999
            THEN {hash_artifact_expr}
        ELSE NULL
    END AS prevalence_artifact{eval_columns}
FROM base_logs l{extra_where}
ORDER BY l.timestamp DESC"#,
            base_sql = base_sql_no_order,
            domain_dict = domain_dict,
            ip_dict = ip_dict,
            hash_dict = hash_dict,
            window_cutoff_sql = window_cutoff_sql,
            is_rare_sql = is_rare_sql,
            prevalence_score_sql = prevalence_score_sql,
            domain_lookup_expr = domain_lookup_expr,
            ip_lookup_expr = ip_lookup_expr,
            hash_lookup_expr = hash_lookup_expr,
            domain_artifact_expr = domain_artifact_expr,
            ip_artifact_expr = ip_artifact_expr,
            hash_artifact_expr = hash_artifact_expr,
            eval_columns = eval_columns,
            extra_where = if where_conditions.is_empty() {
                tracing::debug!("No WHERE conditions to add to prevalence SQL");
                String::new()
            } else {
                let where_clause = format!("\nWHERE {}", where_conditions.join(" AND "));
                tracing::debug!("Adding WHERE clause to prevalence SQL: {}", where_clause);
                where_clause
            },
        );

        // Partition remaining post-prevalence commands (those not already handled as WHERE/EVAL)
        // into SQL-pushable aggregations and the rest.
        // We look for an aggregation command (Stats, Top, Rare, Timechart) and any commands
        // that follow it (Sort, Head, Tail, Table, Fields, Rename) which can also be chained in SQL.
        let (sql_pushable, num_commands_pushed) =
            partition_sql_pushable_commands(post_prevalence_commands);

        let mut sql = sql;
        if !sql_pushable.is_empty() {
            // Wrap the prevalence JOIN SQL as a CTE and chain SQL-pushable commands
            tracing::debug!(
                "Pushing {} commands to SQL (aggregation push-down)",
                sql_pushable.len()
            );
            let mut cte_sql = format!("WITH prevalence_results AS (\n{}\n)", sql);
            let mut current_source = "prevalence_results".to_string();

            for (i, cmd) in sql_pushable.iter().enumerate() {
                let stage_name = format!("stage_{}", i);
                let cmd_sql = self
                    .ch_sql_generator
                    .generate_command_sql(&current_source, cmd)
                    .map_err(|e| SearchError::SqlGenError(e.to_string()))?;
                cte_sql = format!("{},\n{} AS (\n{}\n)", cte_sql, stage_name, cmd_sql);
                current_source = stage_name;
            }

            sql = format!("{}\nSELECT * FROM {}", cte_sql, current_source);
        } else {
            // No aggregation push-down — apply LIMIT/OFFSET to bound the result set
            sql = format!("{}\nLIMIT {} OFFSET {}", sql, limit, offset);
        }

        tracing::debug!(
            "Generated prevalence SQL (first 2000 chars): {}",
            &sql[..sql.len().min(2000)]
        );
        Ok((sql, num_commands_pushed))
    }

    /// Convert a prevalence-related condition to SQL, with support for eval-created fields
    ///
    /// Similar to `prevalence_condition_to_sql`, but also recognizes fields created by
    /// EVAL commands that appear before the WHERE in post-prevalence processing.
    fn prevalence_condition_to_sql_with_eval(
        &self,
        condition: &crate::query::SearchExpr,
        eval_field_names: &std::collections::HashSet<String>,
        rarity_threshold: u64,
    ) -> Result<String, SearchError> {
        use crate::query::{Comparator, EvalExpression, SearchExpr, Value};

        match condition {
            SearchExpr::FieldFilter { field, op, value } => {
                // Normalize field name (e.g., command_line -> process)
                let field = Self::normalize_prevalence_field(field);
                let field_name = field.as_ref().to_string();
                // Check if the field is an eval-created field
                let (sql_field, needs_null_check): (std::borrow::Cow<'_, str>, bool) =
                    if eval_field_names.contains(field.as_ref()) {
                        // Eval-created field - reference directly
                        (field.into_owned().into(), false)
                    } else {
                        // Use prevalence field mapping
                        match field.as_ref() {
                        // NAN-366: WHERE-side expressions mirror the SELECT side's rarest-wins
                        // semantics so `| where host_count < N` returns rows where ANY entity
                        // is rare, not just rows whose domain is rare.
                        "host_count" => ("CASE WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) >= 9999 THEN NULL ELSE least(_dp_host_count, _ip_host_count, _hp_host_count) END".into(), true),
                        "is_rare" => {
                            let rt = rarity_threshold.max(1);
                            (format!("CASE WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < 9999 THEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {rt} ELSE false END", rt = rt).into(), false)
                        }
                        "prevalence_score" => {
                            let rt = rarity_threshold.max(1);
                            (format!(
                                "CASE WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) >= 9999 THEN 0 WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) = 0 THEN 0 WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {t} THEN toUInt8(round(least(toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) / {t} * 20, 20))) WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {t} * 2 THEN toUInt8(round(20 + (toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) - {t}) / {t} * 30)) WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {t} * 10 THEN toUInt8(round(50 + (toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) - {t} * 2) / ({t} * 8) * 30)) ELSE toUInt8(round(80 + least((toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) - {t} * 10) / ({t} * 90) * 20, 20))) END",
                                t = rt,
                            ).into(), false)
                        }
                        "first_seen" | "prevalence_first_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_first_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_first_seen WHEN _hp_host_count < 9999 THEN _hp_first_seen ELSE NULL END".into(), true),
                        "last_seen" | "prevalence_last_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_last_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_last_seen WHEN _hp_host_count < 9999 THEN _hp_last_seen ELSE NULL END".into(), true),
                        "total_occurrences" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_total_occurrences WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_total_occurrences WHEN _hp_host_count < 9999 THEN _hp_total_occurrences ELSE NULL END".into(), true),
                        other => (format!("l.{}", other).into(), false),
                    }
                    };

                let condition = match op {
                    Comparator::Eq
                    | Comparator::Ne
                    | Comparator::Lt
                    | Comparator::Lte
                    | Comparator::Gt
                    | Comparator::Gte => {
                        let sql_op = match op {
                            Comparator::Eq => "=",
                            Comparator::Ne => "!=",
                            Comparator::Lt => "<",
                            Comparator::Lte => "<=",
                            Comparator::Gt => ">",
                            Comparator::Gte => ">=",
                            _ => unreachable!(),
                        };
                        let sql_value = match value {
                            Value::Number(n) => n.to_string(),
                            Value::String(s) => {
                                // Boolean coercion: "true"/"false" → 1/0 for known boolean fields only
                                // Only is_rare is a computed UInt8 boolean in the prevalence JOIN
                                let lower = s.to_lowercase();
                                if (lower == "true" || lower == "false") && field_name == "is_rare"
                                {
                                    if lower == "true" {
                                        "1".to_string()
                                    } else {
                                        "0".to_string()
                                    }
                                } else {
                                    format!("'{}'", escape_sql_string(s))
                                }
                            }
                            Value::Bool(b) => if *b { "1" } else { "0" }.to_string(),
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "Unsupported value type".to_string(),
                                ))
                            }
                        };
                        format!("{} {} {}", sql_field, sql_op, sql_value)
                    }
                    Comparator::Contains | Comparator::NotContains => {
                        let negate = matches!(op, Comparator::NotContains);
                        match value {
                            Value::String(s) => {
                                let escaped = escape_sql_string(s).to_lowercase();
                                let like_op = if negate { "NOT iLike" } else { "iLike" };
                                format!(
                                    "lower(toString({})) {} '%{}%'",
                                    sql_field, like_op, escaped
                                )
                            }
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "Contains requires string value".to_string(),
                                ))
                            }
                        }
                    }
                    Comparator::StartsWith | Comparator::NotStartsWith => {
                        let negate = matches!(op, Comparator::NotStartsWith);
                        match value {
                            Value::String(s) => {
                                let escaped = escape_sql_string(s).to_lowercase();
                                let like_op = if negate { "NOT iLike" } else { "iLike" };
                                format!("lower(toString({})) {} '{}%'", sql_field, like_op, escaped)
                            }
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "StartsWith requires string value".to_string(),
                                ))
                            }
                        }
                    }
                    Comparator::EndsWith | Comparator::NotEndsWith => {
                        let negate = matches!(op, Comparator::NotEndsWith);
                        match value {
                            Value::String(s) => {
                                let escaped = escape_sql_string(s).to_lowercase();
                                let like_op = if negate { "NOT iLike" } else { "iLike" };
                                format!("lower(toString({})) {} '%{}'", sql_field, like_op, escaped)
                            }
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "EndsWith requires string value".to_string(),
                                ))
                            }
                        }
                    }
                    Comparator::Like | Comparator::NotLike => {
                        let like_op = if matches!(op, Comparator::NotLike) {
                            "NOT iLike"
                        } else {
                            "iLike"
                        };
                        match value {
                            Value::String(s) => format!(
                                "toString({}) {} '{}'",
                                sql_field,
                                like_op,
                                escape_sql_string(s)
                            ),
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "Like requires string value".to_string(),
                                ))
                            }
                        }
                    }
                    Comparator::Regex | Comparator::NotRegex => {
                        let negate = matches!(op, Comparator::NotRegex);
                        let pattern = match value {
                            Value::Regex(p) | Value::String(p) => escape_sql_string(p),
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "Regex requires string/regex value".to_string(),
                                ))
                            }
                        };
                        let not_str = if negate { "NOT " } else { "" };
                        format!(
                            "{}match(toString({}), '(?i){}')",
                            not_str, sql_field, pattern
                        )
                    }
                };

                if needs_null_check {
                    Ok(format!("({} IS NOT NULL AND {})", sql_field, condition))
                } else {
                    Ok(condition)
                }
            }
            SearchExpr::FieldFunctionFilter {
                field,
                op,
                function,
            } => {
                // Normalize field name (e.g., command_line -> process)
                let field = Self::normalize_prevalence_field(field);
                // Check if the field is an eval-created field
                let (sql_field, needs_null_check): (std::borrow::Cow<'_, str>, bool) =
                    if eval_field_names.contains(field.as_ref()) {
                        (field.into_owned().into(), false)
                    } else {
                        match field.as_ref() {
                        // NAN-366: match SELECT-side rarest-wins semantics.
                        "host_count" => ("CASE WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) >= 9999 THEN NULL ELSE least(_dp_host_count, _ip_host_count, _hp_host_count) END".into(), true),
                        "first_seen" | "prevalence_first_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_first_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_first_seen WHEN _hp_host_count < 9999 THEN _hp_first_seen ELSE NULL END".into(), true),
                        "last_seen" | "prevalence_last_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_last_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_last_seen WHEN _hp_host_count < 9999 THEN _hp_last_seen ELSE NULL END".into(), true),
                        other => (format!("l.{}", other).into(), false),
                    }
                    };

                let sql_op = match op {
                    Comparator::Eq => "=",
                    Comparator::Ne => "!=",
                    Comparator::Lt => "<",
                    Comparator::Lte => "<=",
                    Comparator::Gt => ">",
                    Comparator::Gte => ">=",
                    _ => {
                        return Err(SearchError::SqlGenError(format!(
                            "Unsupported operator: {:?}",
                            op
                        )))
                    }
                };

                // Convert the function expression to SQL
                // If it's a field reference and that field is an eval-created field, use it directly
                let func_sql = match function {
                    EvalExpression::Field(name) if eval_field_names.contains(name) => {
                        // Eval-created field reference - use directly
                        name.clone()
                    }
                    _ => self.eval_expression_to_clickhouse_sql(function)?,
                };

                if needs_null_check {
                    Ok(format!(
                        "({} IS NOT NULL AND {} {} {})",
                        sql_field, sql_field, sql_op, func_sql
                    ))
                } else {
                    Ok(format!("{} {} {}", sql_field, sql_op, func_sql))
                }
            }
            SearchExpr::And(left, right) => {
                let left_sql = self.prevalence_condition_to_sql_with_eval(
                    left,
                    eval_field_names,
                    rarity_threshold,
                )?;
                let right_sql = self.prevalence_condition_to_sql_with_eval(
                    right,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("({} AND {})", left_sql, right_sql))
            }
            SearchExpr::Or(left, right) => {
                let left_sql = self.prevalence_condition_to_sql_with_eval(
                    left,
                    eval_field_names,
                    rarity_threshold,
                )?;
                let right_sql = self.prevalence_condition_to_sql_with_eval(
                    right,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("({} OR {})", left_sql, right_sql))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = self.prevalence_condition_to_sql_with_eval(
                    inner,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("NOT ({})", inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = self.prevalence_condition_to_sql_with_eval(
                    inner,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("({})", inner_sql))
            }
            SearchExpr::InList {
                field,
                values,
                negated,
            } => {
                let field = Self::normalize_prevalence_field(field);
                let sql_field: std::borrow::Cow<'_, str> =
                    if eval_field_names.contains(field.as_ref()) {
                        field.into_owned().into()
                    } else {
                        format!("l.{}", field).into()
                    };
                let op = if *negated { "NOT IN" } else { "IN" };
                let all_strings = values.iter().all(|v| matches!(v, Value::String(_)));
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => {
                            if all_strings {
                                format!("'{}'", escape_sql_string(s).to_lowercase())
                            } else {
                                format!("'{}'", escape_sql_string(s))
                            }
                        }
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => if *b { "true" } else { "false" }.to_string(),
                        _ => format!("'{}'", escape_sql_string(format!("{:?}", v))),
                    })
                    .collect();
                let values_list = values_sql.join(", ");
                if all_strings {
                    Ok(format!(
                        "lower(toString({})) {} ({})",
                        sql_field, op, values_list
                    ))
                } else {
                    Ok(format!("{} {} ({})", sql_field, op, values_list))
                }
            }
            SearchExpr::Keyword(kw) => {
                // Keyword search in prevalence context - search message field
                let escaped = escape_sql_string(kw).to_lowercase();
                Ok(format!("lower(toString(l.message)) iLike '%{}%'", escaped))
            }
            _ => Err(SearchError::SqlGenError(format!(
                "Unsupported expression type: {:?}",
                condition
            ))),
        }
    }

    /// Normalize field names for prevalence SQL (mirrors clickhouse_sql_gen::normalize_field_name)
    fn normalize_prevalence_field(field: &str) -> std::borrow::Cow<'_, str> {
        match field {
            "process" => "command_line".into(),
            "parent_process" => "parent_command_line".into(),
            "sourcetype" => "source_type".into(),
            "hostname" => "host".into(),
            "dest_hostname" => "dest_host".into(),
            "src_hostname" => "src_host".into(),
            "username" => "user".into(),
            "source_ip" => "src_ip".into(),
            "destination_ip" => "dest_ip".into(),
            "source_port" => "src_port".into(),
            "destination_port" => "dest_port".into(),
            _ => field.into(),
        }
    }

    /// Convert eval expression to ClickHouse SQL for function calls in search service
    fn eval_expression_to_clickhouse_sql(
        &self,
        expr: &crate::query::EvalExpression,
    ) -> Result<String, SearchError> {
        self.eval_expression_to_clickhouse_sql_with_context(expr, false)
    }

    /// Convert eval expression to ClickHouse SQL, with optional prevalence context
    /// When in_prevalence_context is true, ambiguous field names are replaced with
    /// their properly qualified CASE expressions to avoid ClickHouse identifier errors.
    fn eval_expression_to_clickhouse_sql_with_context(
        &self,
        expr: &crate::query::EvalExpression,
        in_prevalence_context: bool,
    ) -> Result<String, SearchError> {
        use crate::query::EvalExpression;

        match expr {
            EvalExpression::Field(field) => {
                // When in prevalence context, certain field names are ambiguous because
                // they exist in multiple JOINed CTEs (domain_prev, ip_prev, hash_prev)
                // Replace them with the properly qualified CASE expression
                if in_prevalence_context {
                    match field.as_str() {
                        "first_seen" => Ok("(CASE WHEN _dp_host_count < 9999 THEN _dp_first_seen WHEN _ip_host_count < 9999 THEN _ip_first_seen WHEN _hp_host_count < 9999 THEN _hp_first_seen ELSE NULL END)".to_string()),
                        "last_seen" => Ok("(CASE WHEN _dp_host_count < 9999 THEN _dp_last_seen WHEN _ip_host_count < 9999 THEN _ip_last_seen WHEN _hp_host_count < 9999 THEN _hp_last_seen ELSE NULL END)".to_string()),
                        // host_count and total_occurrences are also defined in the SELECT,
                        // but reference them from the already-selected alias would cause ordering issues
                        // Use the CASE expression for consistency
                        _ => Ok(field.clone()),
                    }
                } else {
                    Ok(field.clone())
                }
            }
            EvalExpression::Literal(value) => {
                match value {
                    crate::query::Value::String(s) => Ok(format!("'{}'", escape_sql_string(s))),
                    crate::query::Value::Number(n) => Ok(n.to_string()),
                    crate::query::Value::Bool(b) => Ok(if *b { "1" } else { "0" }.to_string()),
                    crate::query::Value::Interval(duration, unit) => {
                        // Convert interval to ClickHouse INTERVAL syntax
                        // The duration stores the total seconds, we need to convert back to the original unit
                        let secs = duration.as_secs();
                        let (value, unit_str) = match unit {
                            crate::query::IntervalUnit::Microsecond => {
                                (secs * 1_000_000, "MICROSECOND")
                            }
                            crate::query::IntervalUnit::Millisecond => {
                                (secs * 1_000, "MILLISECOND")
                            }
                            crate::query::IntervalUnit::Second => (secs, "SECOND"),
                            crate::query::IntervalUnit::Minute => (secs / 60, "MINUTE"),
                            crate::query::IntervalUnit::Hour => (secs / 3600, "HOUR"),
                            crate::query::IntervalUnit::Day => (secs / 86400, "DAY"),
                            crate::query::IntervalUnit::Week => (secs / 604800, "WEEK"),
                            crate::query::IntervalUnit::Month => (secs / 2592000, "MONTH"),
                            crate::query::IntervalUnit::Year => (secs / 31536000, "YEAR"),
                        };
                        Ok(format!("INTERVAL {} {}", value, unit_str))
                    }
                    _ => Err(SearchError::SqlGenError(
                        "Unsupported literal type in function".to_string(),
                    )),
                }
            }
            EvalExpression::FunctionCall { name, args } => {
                let arg_sqls: Result<Vec<String>, _> = args
                    .iter()
                    .map(|arg| {
                        self.eval_expression_to_clickhouse_sql_with_context(
                            arg,
                            in_prevalence_context,
                        )
                    })
                    .collect();
                let arg_sqls = arg_sqls?;

                // Map function names to ClickHouse equivalents
                let clickhouse_func = match name.as_str() {
                    // Date/time functions
                    "now" => "now64(6)",
                    "year" => "toYear",
                    "month" => "toMonth",
                    "day" => "toDayOfMonth",
                    "hour" => "toHour",
                    "minute" => "toMinute",
                    "second" => "toSecond",
                    "dayofweek" => "toDayOfWeek",
                    "dayofyear" => "toDayOfYear",
                    "weekofyear" => "toWeek",
                    "date_add" => "addInterval",
                    "date_sub" => "subtractInterval",
                    "date_format" => "formatDateTime",
                    "date_trunc" => "date_trunc",
                    "unix_timestamp" => "toUnixTimestamp",
                    "from_unixtime" => "fromUnixTimestamp",

                    // String functions
                    "upper" => "upper",
                    "lower" => "lower",
                    "length" => "length",
                    "substr" => "substring",
                    "substring" => "substring",
                    "concat" => "concat",
                    "replace" => "replaceAll",
                    "trim" => "trim",
                    "ltrim" => "trimLeft",
                    "rtrim" => "trimRight",

                    // Math functions
                    "abs" => "abs",
                    "ceil" => "ceil",
                    "floor" => "floor",
                    "round" => "round",
                    "sqrt" => "sqrt",
                    "pow" => "pow",

                    // Conditional functions
                    "if" => "if",
                    "case" => "multiIf",
                    "coalesce" => "coalesce",
                    "nullif" => "nullIf",

                    // Type conversion
                    "tostring" => "toString",
                    "tonumber" => "toFloat64OrNull",
                    "toint" => "toInt64OrNull",

                    // Pass through unknown functions (might be ClickHouse-specific)
                    other => other,
                };

                if arg_sqls.is_empty() && clickhouse_func == "now64(6)" {
                    Ok(clickhouse_func.to_string())
                } else {
                    Ok(format!("{}({})", clickhouse_func, arg_sqls.join(", ")))
                }
            }
            EvalExpression::BinaryOp { left, op, right } => {
                let left_sql = self
                    .eval_expression_to_clickhouse_sql_with_context(left, in_prevalence_context)?;
                let right_sql = self
                    .eval_expression_to_clickhouse_sql_with_context(right, in_prevalence_context)?;
                let op_sql = match op {
                    crate::query::BinaryOperator::Add => "+",
                    crate::query::BinaryOperator::Sub => "-",
                    crate::query::BinaryOperator::Mul => "*",
                    crate::query::BinaryOperator::Div => "/",
                    crate::query::BinaryOperator::Mod => "%",
                    crate::query::BinaryOperator::Concat => "||",
                    crate::query::BinaryOperator::Eq => "=",
                    crate::query::BinaryOperator::Ne => "!=",
                    crate::query::BinaryOperator::Lt => "<",
                    crate::query::BinaryOperator::Lte => "<=",
                    crate::query::BinaryOperator::Gt => ">",
                    crate::query::BinaryOperator::Gte => ">=",
                    crate::query::BinaryOperator::And => "AND",
                    crate::query::BinaryOperator::Or => "OR",
                    crate::query::BinaryOperator::Contains | crate::query::BinaryOperator::Like => {
                        ""
                    }
                };
                match op {
                    crate::query::BinaryOperator::Contains => {
                        Ok(format!("(position({}, {}) > 0)", left_sql, right_sql))
                    }
                    crate::query::BinaryOperator::Like => {
                        Ok(format!("({} LIKE {})", left_sql, right_sql))
                    }
                    _ => Ok(format!("({} {} {})", left_sql, op_sql, right_sql)),
                }
            }
        }
    }
}
