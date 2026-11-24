// SPDX-License-Identifier: AGPL-3.0-or-later

use super::prevalence_processing::{
    rescue_index_sql, rescue_value_sql, PrevalenceRescue, RescueAttr,
};
use super::*;
use crate::query::clickhouse_sql_gen::{ch_lower, ci_like, escape_like_pattern};
use crate::search::companion_query_id::CompanionQuery;
use crate::sql_hygiene::escape_sql_string;
use super::prevalence_scan::{
    output_row_columns_sql, plan_prevalence_scan, PrevalenceScanPlan, ResultWindow,
};

/// The decoration columns the pushdown's `prevalence_results` CTE adds to
/// every row (its final SELECT), which the pushed-down stages read as plain
/// columns (NAN-5632).
pub(super) const PREVALENCE_RESULT_COLUMNS: &[&str] = &[
    "host_count",
    "prevalence_first_seen",
    "prevalence_last_seen",
    "total_occurrences",
    "is_rare",
    "prevalence_score",
    "prevalence_type",
    "prevalence_artifact",
];

/// Schema-resolved artifact lookup-key expressions (`_domain_lookup` /
/// `_ip_lookup` / `_hash_lookup`), shared between the pushdown SQL build and
/// the NAN-1705 rescue probe. "NULL" means the active schema maps no column
/// for that concept (the branch is dropped / never probed).
pub(crate) struct PrevalenceLookupExprs {
    pub domain: String,
    pub ip: String,
    pub hash: String,
}

/// Static shape of one NAN-1705 rescue probe: which lookup expression to
/// DISTINCT over the base scan, which dict identifies the blind keys, and
/// which summary table/columns re-resolve them.
struct RescueProbeSpec<'a> {
    /// NAN-5723: the probe's derived query id (cancel kills it).
    probe_id: String,
    lookup_expr: &'a str,
    dict: &'static str,
    summary_table: String,
    key_col: &'static str,
    state_col: &'static str,
    /// Extra summary predicate (must end ` AND ` if non-empty). `is_private = 0 `
    /// for IP (mirrors the ip dict source), empty for hash/domain.
    extra_summary_filter: &'static str,
}

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
        scope: &crate::auth::ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        // NAN-5793 review: every generation below (base, count, rescue probe,
        // pushdown) is under the caller's deny-set, so `| resolve_identity`
        // and `[dataset=risk …]` before `| prevalence` stay scoped.
        let gscope = crate::query::GeneratorScope::viewer(scope);
        // Get rarity threshold from prevalence service config
        let rarity_threshold = if let Some(ref prev_svc) = self.prevalence_service {
            prev_svc.rarity_threshold().await
        } else {
            3 // default
        };

        // NAN-5660: the caller reads `[offset, offset + limit)` of the result.
        // When the plan cannot push that window into the base scan and keeps
        // the newest-1M full-width sort, admit it like the other row-preserving
        // buffers (NAN-5635) instead of letting it hit Code 241.
        let window = ResultWindow { limit, offset };
        let scan = self.prevalence_scan_plan(query, prevalence_commands, post_prevalence_commands, Some(window));
        let query_id = request
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        if scan.is_wide_newest_scan() {
            self.admit_prevalence_scan(query, adjusted_time_range, &query_id, scope)
                .await
                .map_err(SearchError::SqlValidationError)?;
        }

        // NAN-1705 (D4b): before building the pushdown SQL, re-resolve the
        // window's dict-blind artifacts (negative-cached misses / stale window
        // masks) against the real-time summary. The rescued sets override the
        // dict projections in-SQL (NAN-5565: keys once, every artifact); an
        // empty rescue (the steady state) leaves the SQL byte-identical to the
        // rescue-free build. The
        // probe fails OPEN to an empty rescue — a probe error must degrade to
        // today's behavior, never fail the search.
        let mut rescue = self
            .compute_prevalence_rescue(
                query,
                prevalence_commands,
                post_prevalence_commands,
                time_range,
                &query_id,
                gscope,
            )
            .await;

        // NAN-1694: the entire pushdown SQL build (window pick + base scan + dictGet
        // JOIN) is now the shared sync `generate_prevalence_pushdown_sql`, so the
        // explain path renders byte-identical SQL. Only the async rarity_threshold
        // fetch above stays here (and the rescue probe, which explain skips — its
        // shape and bounds are spelled out in the explain note instead).
        // NAN-5565: the rendered text must fit the executor's max_query_size
        // ceiling; past it the least-rare rescued artifacts are left out.
        let (sql, num_commands_pushed, aggregation) = render_within_query_size_ceiling(
            &mut rescue,
            crate::search::execution::clickhouse_executor::MAX_QUERY_SIZE_CEILING,
            |rescue| {
                self.generate_prevalence_pushdown_sql_with_shape(
                    query,
                    prevalence_commands,
                    post_prevalence_commands,
                    time_range,
                    rarity_threshold,
                    rescue,
                    Some(window),
                    gscope,
                )
            },
        )?;
        // NAN-5565: anything left out (key-byte cap or query-size ceiling) is
        // loud: a WARN, a metric, a PARTIAL note that the scheduler records on
        // the rule run, and a response warning (below) on the search.
        report_partial_rescue(&rescue);

        tracing::debug!(
            "Generated JOIN-based prevalence SQL (length: {} chars)",
            sql.len()
        );
        // NAN-5565: a rescued query's size is the one number that says how
        // close it runs to ClickHouse's max_query_size; log it with the set.
        if !rescue.is_empty() {
            tracing::info!(
                sql_bytes = sql.len(),
                lifted_max_query_size = ?crate::search::execution::clickhouse_executor::max_query_size_for(sql.len()),
                rescued_hashes = rescue.hashes.len(),
                rescued_domains = rescue.domains.len(),
                rescued_ips = rescue.ips.len(),
                "Prevalence pushdown SQL carries a dict-blind rescue"
            );
        }
        // NAN-5824: the base scan must carry its time-bounded WHERE (single
        // WHERE, NAN-1412); without it the pushdown scans every partition.
        if let Some(where_clause) = base_scan_time_where(&sql) {
            tracing::debug!("Generated SQL WHERE clause: {}", where_clause);
        } else {
            tracing::warn!("No time-bounded WHERE found in generated prevalence SQL!");
        }

        // Execute the query with timing.
        //
        // NAN-1848: the pushdown can carry an aggregation into SQL — either from
        // the query itself or from the post-prevalence commands it pushed — and a
        // grouped row's (possibly empty) key must not be pruned away into a bare
        // count. Ask about exactly the commands that made it into this SQL.
        let grouped_output = query_produces_grouped_rows(query)
            || post_prevalence_commands
                .iter()
                .take(num_commands_pushed)
                .any(command_groups_rows);
        let sql_start = Instant::now();
        // NAN-5660: with the result window pushed, the SQL holds only the rows
        // the page reads, so its count companion would report the window, not
        // the total. The first page counts the base instead: decoration keeps
        // every row, so the total is the base count under the same 1M cap the
        // unpushed `raw_logs` applied. Later pages keep the executor estimate.
        let window_total = scan.window_pushed
            && crate::search::execution::clickhouse_executor::is_first_page(offset);
        // NAN-5565: generated SQL: the executor lifts `max_query_size` when the
        // rescue needs it and takes the aggregation decision from the
        // rescue-free rendering.
        // NAN-5751: when the SQL ends in an aggregation and nothing runs after
        // it in Rust, `limit` (the 1M input ceiling of an aggregation query)
        // would read up to 1M groups; the caller's page is the groups it reads.
        let limit = if self.prevalence_aggregation_is_final(
            post_prevalence_commands,
            num_commands_pushed,
            lookup_commands,
            inputlookup_commands,
        ) {
            limit.min(request.limit.unwrap_or(self.config.default_limit).min(self.config.max_limit))
        } else {
            limit
        };
        let data = self.execute_generated_clickhouse_sql(&sql, aggregation, limit, offset, &query_id, grouped_output);
        let (mut results, total_count) = if window_total {
            let (data, base_total) =
                tokio::join!(data, self.prevalence_base_total(query, time_range, &query_id, gscope));
            let (results, _window_total) = data?;
            let total_count = match base_total {
                Ok(total) => total.max(results.len() as u64),
                Err(e) => {
                    // The windowed SQL's own count is at most the window; keep
                    // a full page signalling "more" so paging stays enabled.
                    tracing::warn!(error = %e, "prevalence base count failed; estimating the total from the page");
                    crate::search::execution::clickhouse_executor::paged_total_estimate(
                        offset,
                        results.len(),
                        limit,
                    )
                }
            };
            (results, total_count)
        } else {
            data.await?
        };
        tracing::info!(
            duration_ms = sql_start.elapsed().as_millis() as u64,
            result_count = results.len(),
            "Prevalence JOIN executed"
        );

        // NAN-1705 (D4b): rescued rows already carry their TRUE prevalence
        // decoration — the `_hp/_dp_host_count` projection aliases were rewritten
        // in-SQL via `transform(...)` (see `generate_prevalence_join_sql`), so the
        // host_count / is_rare / first_seen / … CASEs, the pushed predicate, AND
        // any downstream `| where host_count < N` all saw the real count in
        // ClickHouse. No post-query decoration patch is needed.

        // NAN-5718: a plain decorating `enrich=true` has no in-SQL rescue (the
        // NAN-1705 rescue above is driven by filter conditions), so the rows it
        // returned are re-checked here, BEFORE the per-dimension columns are
        // stripped: true dict misses on these rows only, one combined probe.
        let mut page_rescue_dropped = 0usize;
        if super::prevalence_page_rescue::page_rescue_applies(
            prevalence_commands,
            post_prevalence_commands,
            &scan,
            rarity_threshold,
        ) {
            let time_window = Self::resolve_prevalence_window(prevalence_commands)?;
            // Past-the-cap misses are reported (WARN, metric, PARTIAL note)
            // inside, and surfaced as a PREVALENCE_RESCUE_PARTIAL warning below.
            page_rescue_dropped = self
                .rescue_page_prevalence(&mut results, time_window, rarity_threshold, &query_id)
                .await;
        }

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
        // Skip if requested for detection execution.
        // NAN-1645: also skip on page flips (offset > 0) — the histogram is
        // page-invariant and the frontend freezes the page-1 timeline.
        let histogram = if request.skip_histogram
            || !crate::search::execution::clickhouse_executor::is_first_page(offset)
        {
            None
        } else {
            let histogram_start = Instant::now();
            // NAN-1428: derived companion id so cancel kills the histogram too.
            let hist_qid = request.request_id.as_ref().map(|r| CompanionQuery::Hist.query_id(r));
            let histogram = self
                .generate_histogram(
                    cleaned_query,
                    adjusted_time_range,
                    hist_qid.as_deref(),
                    crate::query::Dataset::from_selector(
                        request.dataset.as_deref().unwrap_or("logs"),
                    ),
                    scope.deny_set(),
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

        // NAN-5565: a rescue cut at the key-byte cap left artifacts out.
        if rescue.dropped > 0 {
            warnings_output.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "PREVALENCE_RESCUE_PARTIAL".to_string(),
                message: prevalence_rescue_partial_message(rescue.dropped),
                suggestion: Some("Narrow the time range or the search so fewer brand-new artifacts need re-checking.".to_string()),
                impact: Some("Results can miss rare artifacts the prevalence dictionaries have not loaded yet.".to_string()),
            });
        }
        // NAN-5718: dict-missed artifacts past the page rescue's cap.
        if page_rescue_dropped > 0 {
            warnings_output.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "PREVALENCE_RESCUE_PARTIAL".to_string(),
                message: super::prevalence_page_rescue::page_rescue_partial_message(page_rescue_dropped),
                suggestion: Some("Narrow the time range or lower the page size so fewer brand-new artifacts need re-checking.".to_string()),
                impact: Some("Rows can show no prevalence for artifacts the prevalence dictionaries have not loaded yet.".to_string()),
            });
        }

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
            server_wall_ms: None,
            queue_wait_ms: None,
            fields,
            generated_sql: if request.include_sql.unwrap_or(false) {
                // NAN-5043: never echo the caller's deny list.
                Some(crate::search::display_sql::DisplaySql::for_scope(sql, scope))
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

    /// Map the prevalence window to the dict `last_seen` mask cutoff.
    ///
    /// NAN-364: per-window sibling dicts (_1d/_7d) were rolled back — their source queries
    /// did unbounded `uniqMerge GROUP BY entity` over prevalence_agg before the host_count
    /// filter, reproducing the same OOM at dict-refresh time that NAN-362 tried to kill
    /// at query time. We now use the single 30d dict for all windows and mask entries
    /// whose `last_seen` is older than the requested window to the 9999 sentinel. 1h is
    /// still rejected — dict refresh is 5–10 min, so sub-day granularity isn't meaningful.
    pub(crate) fn prevalence_window_cutoff_sql(
        time_window: PrevalenceTimeWindow,
    ) -> Result<&'static str, SearchError> {
        match time_window {
            PrevalenceTimeWindow::OneHour => {
                // NAN-1689: SqlValidationError → clean 400 carrying the real
                // message (error.rs maps it to QueryError without masking).
                // Previously SqlGenError, which was masked to "Query processing
                // failed". Matches the dict-fallback rejection in service/mod.rs.
                Err(SearchError::SqlValidationError(
                    "prevalence window=1h is not supported; use 24h, 7d, or 30d".to_string(),
                ))
            }
            PrevalenceTimeWindow::TwentyFourHours => Ok("now() - INTERVAL 1 DAY"),
            PrevalenceTimeWindow::SevenDays => Ok("now() - INTERVAL 7 DAY"),
            // 30d: use epoch-0 so the mask is a no-op (dict already windowed to 30d).
            PrevalenceTimeWindow::ThirtyDays => Ok("toDateTime64(0, 6)"),
        }
    }

    /// Resolve the single prevalence time window shared by every `| prevalence`
    /// command in the query. All conditions are flattened into ONE dictGet mask
    /// (a single window_cutoff_sql), so mixed windows across multiple
    /// `| prevalence` commands can't be honored per-command. Reject that rather
    /// than silently applying the first command's window to every condition
    /// (NAN-1691 Codex review) — the old in-memory path evaluated each
    /// command's window independently.
    fn resolve_prevalence_window(
        prevalence_commands: &[PrevalenceCommandInfo],
    ) -> Result<PrevalenceTimeWindow, SearchError> {
        let mut time_window: Option<PrevalenceTimeWindow> = None;
        for cmd in prevalence_commands {
            if let Some(tw) = cmd.time_window.as_ref() {
                let tw = ast_to_prevalence_time_window(Some(tw))?;
                if let Some(existing) = time_window {
                    if existing != tw {
                        return Err(SearchError::SqlValidationError(
                            "multiple `| prevalence` commands with different windows are not \
                             supported in one query; use a single window".to_string(),
                        ));
                    }
                }
                time_window = Some(tw);
            }
        }
        Ok(time_window.unwrap_or(PrevalenceTimeWindow::ThirtyDays))
    }

    /// NAN-5751: whether the pushdown SQL produces the final rows, so the
    /// caller's page may bound it: it carries a pushed aggregation, every
    /// command from there on ran in SQL, and every command before the
    /// aggregation is one the pushdown inlines (`eval`, or a `where` not on
    /// `_prevalence.*`). Anything else before it (`dedup`, `head`, `rex`, …)
    /// is replayed in Rust AFTER the SQL rows arrive, so they must not be cut.
    fn prevalence_aggregation_is_final(
        &self,
        post_prevalence_commands: &[Command],
        num_commands_pushed: usize,
        lookup_commands: &[LookupCommandInfo],
        inputlookup_commands: &[InputLookupCommandInfo],
    ) -> bool {
        let is_aggregation = |c: &Command| {
            matches!(c, Command::Stats { .. } | Command::Top { .. } | Command::Rare { .. } | Command::Timechart { .. })
        };
        let Some(agg_idx) = post_prevalence_commands.iter().position(is_aggregation) else {
            return false;
        };
        agg_idx < num_commands_pushed
            && num_commands_pushed == post_prevalence_commands.len()
            && lookup_commands.is_empty()
            && inputlookup_commands.is_empty()
            && post_prevalence_commands[..agg_idx].iter().all(|c| match c {
                Command::Eval { .. } => true,
                Command::Where { condition } => !self.condition_references_prevalence_nested_fields(condition),
                _ => false,
            })
    }

    /// Generate the base SQL for the search part (the query with prevalence and
    /// everything after it stripped). Shared by the pushdown build and the
    /// NAN-1705 rescue probe so both scan the identical base.
    ///
    /// NAN-1635: `limit: None` — the prevalence wrapper owns the result
    /// bound (generate_prevalence_join_sql appends its own LIMIT) and the
    /// ORDER-BY-anchored stripper below only removes a trailing
    /// `ORDER BY … [LIMIT …]`. With the CTE tail now applying the default
    /// safety limit (finding 3.6), a projected base (`… | fields - x |
    /// prevalence`) ends in a bare `LIMIT 1000000 SETTINGS …` the stripper
    /// would miss, silently truncating the prevalence base set. Emitting no
    /// generator LIMIT reproduces the pre-3.6 base byte-for-byte after the
    /// strip. The implicit trailing ORDER BY is kept (NOT `unordered`): the
    /// stripper anchors on the LAST ` order by `, and removing the final
    /// one would make it truncate mid-CTE at an internal stage's ORDER BY
    /// (e.g. dedup's `ORDER BY … LIMIT 1 BY …`).
    fn generate_prevalence_base_sql(
        &self,
        query: &Query,
        time_range: &TimeRange,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<String, SearchError> {
        self.generate_prevalence_base_sql_with_limit(query, time_range, None, gscope)
    }

    /// [`Self::generate_prevalence_base_sql`] with the generator's own result
    /// LIMIT (NAN-5660: the pushed result window). With a limit the base keeps
    /// its trailing `ORDER BY timestamp DESC LIMIT n` and no SETTINGS clause
    /// (the unlimited base loses its trailing SETTINGS to the ORDER BY strip
    /// the same way), so the top-N runs directly on the table, where
    /// ClickHouse reads only the sort column for the rows it drops.
    fn generate_prevalence_base_sql_with_limit(
        &self,
        query: &Query,
        time_range: &TimeRange,
        limit: Option<usize>,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<String, SearchError> {
        let base_query = strip_prevalence_and_after(query);
        let base_options = crate::query::QueryOptions {
            limit,
            omit_settings: limit.is_some(),
            ..Default::default()
        };
        self.sql_generator(gscope)
            .generate_with_options(&base_query, time_range, &base_options)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))
    }

    /// NAN-5660: total rows of an enrich-only pushdown whose result window was
    /// pushed: the base search's count, capped at the 1M the unpushed
    /// `raw_logs` kept. A filtered base stops counting one row past the cap; a
    /// filter-free one is served from part metadata (NAN-1635).
    /// The count carries the derived `{query_id}-base-count` id (cancel kills
    /// it with the data query) and the request's ClickHouse settings.
    async fn prevalence_base_total(
        &self,
        query: &Query,
        time_range: &TimeRange,
        query_id: &str,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<u64, SearchError> {
        let count_sql = self.prevalence_base_count_sql(query, time_range, gscope)?;
        let executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse client not configured".into(),
            ))
        })?;
        let count_qid = CompanionQuery::BaseCount.query_id(query_id);
        let total = executor
            .execute_count_query_with_options(&count_sql, Some(&count_qid), self.active_ch_settings.as_ref())
            .await?;
        Ok(total.min(crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT as u64))
    }

    /// The count SQL behind [`Self::prevalence_base_total`].
    pub(crate) fn prevalence_base_count_sql(&self, query: &Query, time_range: &TimeRange, gscope: crate::query::GeneratorScope<'_>) -> Result<String, SearchError> {
        use crate::search::execution::clickhouse_executor::{build_count_query, BoundedCountInput};
        let cap = crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT;
        let base_query = strip_prevalence_and_after(query);
        let options = crate::query::QueryOptions {
            limit: None,
            unordered: true,
            ..Default::default()
        };
        let sql = self
            .sql_generator(gscope)
            .generate_with_options(&base_query, time_range, &options)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;
        let bounded = crate::search::query_processing::query_has_per_row_filters(&base_query)
            .then_some(BoundedCountInput { sql: &sql, limit: cap });
        Ok(build_count_query(&sql, bounded))
    }

    /// Build the schema-resolved artifact lookup-key expressions the prevalence
    /// pushdown computes per row (`_domain_lookup` / `_ip_lookup` /
    /// `_hash_lookup`). Shared by `generate_prevalence_join_sql` and the
    /// NAN-1705 rescue probe so both key off byte-identical expressions.
    ///
    /// NAN-5293: every key derives from the canonical artifact column list
    /// (`prevalence::artifact_fields`), the same list the query-artifacts
    /// endpoint, the in-memory path, the drawer and the scatter read. The
    /// pre-5293 keys resolved UDM concepts one by one, so the domain key fell
    /// back to `src_host` (`device.hostname` on OCSF) before ever reaching
    /// `query.hostname` and keyed every Sysmon DNS row on the workstation.
    /// `"NULL"` => the schema has no column for that class (dictGet then
    /// falls through to the 9999 "not tracked" sentinel).
    fn prevalence_lookup_exprs(&self) -> PrevalenceLookupExprs {
        use crate::prevalence::artifact_fields::{ArtifactColumns, ArtifactKind};
        let cols = ArtifactColumns::resolve(self.active_profile.as_ref());
        let key = |kind| cols.lookup_key_sql(kind).unwrap_or_else(|| "NULL".to_string());
        PrevalenceLookupExprs {
            domain: key(ArtifactKind::Domain),
            ip: key(ArtifactKind::Ip),
            hash: key(ArtifactKind::Hash),
        }
    }

    /// NAN-1705 (D4b): re-resolve dict-blind artifacts against the real-time
    /// summary before the pushdown SQL is built.
    ///
    /// The prevalence CACHE dicts negative-cache a brand-new artifact's absence
    /// for LIFETIME(900–1800s) — poisoned at ingest by the `logs.prevalence_*`
    /// MATERIALIZED-column lookups that run before the same insert block's
    /// summary-MV rows land. A rarity rule riding the `< 9999` presence guard is
    /// therefore blind to an artifact for the first 15–30 minutes of its life —
    /// exactly the artifacts it exists to catch. The probe finds the window's
    /// dict-missed keys and re-checks them against `*_prevalence_summary` (the
    /// dict's own real-time source) under the dict source's exact contract; see
    /// `build_prevalence_rescue_probe_sql`.
    ///
    /// Fail-open BY DESIGN: any probe failure returns an empty rescue and the
    /// generated SQL is byte-identical to the pre-NAN-1705 build — the rescue
    /// can only ADD rows the dict path wrongly dropped, never remove or block.
    /// Skipped entirely (zero cost) unless a pushable count condition exists OR
    /// (NAN-1705 residual #2) `enrich=true` is paired with a downstream
    /// rare-direction filter on a decorated column (`| where host_count < N`,
    /// `| where is_rare`). Pure-decorate `enrich=true` (no such filter) triggers
    /// NO probe and stays byte-identical.
    pub(crate) async fn compute_prevalence_rescue(
        &self,
        query: &Query,
        prevalence_commands: &[PrevalenceCommandInfo],
        post_prevalence_commands: &[Command],
        time_range: &TimeRange,
        query_id: &str,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> PrevalenceRescue {
        use crate::query::{
            PrevalenceCondition, PrevalenceField, PrevalenceOperator, PrevalenceThreshold,
        };

        let mut rescue = PrevalenceRescue::default();

        // Explicit `| prevalence <field> <op> N` count conditions (hash/domain only).
        let conditions: Vec<PrevalenceCondition> = prevalence_commands
            .iter()
            .flat_map(|cmd| cmd.conditions.iter().cloned())
            .collect();
        // NAN-4372: a first_seen condition also drives its entity's probe. A
        // brand-new artifact (exactly what `domain_first_seen > now() - 24h`
        // hunts) is the one the dict negative-caches; without the rescue the
        // pushed `_dp_first_seen` predicate could never see it.
        // `filter_rescued_artifacts` enforces only the count conditions, so the
        // rescued set is a superset the in-SQL predicate narrows.
        let entity_conds = |fields: [PrevalenceField; 2]| -> Vec<PrevalenceCondition> {
            conditions
                .iter()
                .filter(|c| fields.contains(&c.field))
                .cloned()
                .collect()
        };
        let mut hash_conds =
            entity_conds([PrevalenceField::HashPrevalence, PrevalenceField::HashFirstSeen]);
        let mut domain_conds =
            entity_conds([PrevalenceField::DomainPrevalence, PrevalenceField::DomainFirstSeen]);
        let mut ip_conds: Vec<PrevalenceCondition> = Vec::new();

        // NAN-1705 residual #2: `enrich=true | where <decorated> …`. The
        // decorated `host_count = least(_dp, _ip, _hp)` includes IP (the ONLY way
        // to reach IP rarity — there is no `ip_prevalence` filter field), so a
        // synthetic `<= threshold` condition drives ALL THREE dimensions. The
        // threshold only BOUNDS the rescue set; the in-SQL `| where` filters
        // exactly once the aliases are transform-corrected.
        let enrich = prevalence_commands.iter().any(|cmd| cmd.enrich);
        if enrich {
            let rarity_threshold = if let Some(ref s) = self.prevalence_service {
                s.rarity_threshold().await
            } else {
                3
            };
            if let Some(threshold) =
                super::prevalence_processing::decorated_filter_rescue_threshold(
                    post_prevalence_commands,
                    rarity_threshold,
                )
            {
                let syn = |field: PrevalenceField| PrevalenceCondition {
                    field,
                    operator: PrevalenceOperator::Lte,
                    threshold: PrevalenceThreshold::Count(threshold),
                };
                hash_conds.push(syn(PrevalenceField::HashPrevalence));
                domain_conds.push(syn(PrevalenceField::DomainPrevalence));
                // IP reuses HashPrevalence as a placeholder field —
                // `filter_rescued_artifacts` only reads operator+threshold, never
                // the field, so the placeholder is inert.
                ip_conds.push(syn(PrevalenceField::HashPrevalence));
            }
        }

        if hash_conds.is_empty() && domain_conds.is_empty() && ip_conds.is_empty() {
            // No count condition and no enrich+decorated-filter: nothing to
            // rescue. Zero probe cost; SQL stays byte-identical.
            return rescue;
        }
        if self.ch_executor.is_none() {
            return rescue;
        }

        // Window / base-SQL failures are NOT reported here — the pushdown build
        // right after this will surface the identical error to the user.
        let Ok(time_window) = Self::resolve_prevalence_window(prevalence_commands) else {
            return rescue;
        };
        let Ok(window_cutoff_sql) = Self::prevalence_window_cutoff_sql(time_window) else {
            return rescue;
        };
        let Ok(base_sql) = self.generate_prevalence_base_sql(query, time_range, gscope) else {
            return rescue;
        };
        let base_sql_clean = base_sql.trim().trim_end_matches(';');
        let base_no_order =
            if let Some(order_pos) = base_sql_clean.to_ascii_lowercase().rfind(" order by ") {
                &base_sql_clean[..order_pos]
            } else {
                base_sql_clean
            };
        let exprs = self.prevalence_lookup_exprs();

        // One probe per entity type that has conditions AND a mapped lookup
        // column ("NULL" ⇒ the active schema has nothing to key on).
        let hash_refs: Vec<&PrevalenceCondition> = hash_conds.iter().collect();
        let domain_refs: Vec<&PrevalenceCondition> = domain_conds.iter().collect();
        let ip_refs: Vec<&PrevalenceCondition> = ip_conds.iter().collect();
        if !hash_conds.is_empty() && exprs.hash != "NULL" {
            rescue.hashes = self
                .run_prevalence_rescue_probe(
                    base_no_order,
                    window_cutoff_sql,
                    RescueProbeSpec {
                        probe_id: CompanionQuery::RescueProbeHash.query_id(query_id),
                        lookup_expr: &exprs.hash,
                        dict: "nanosiem.hash_prevalence_dict",
                        summary_table: self.table_names.read("hash_prevalence_summary"),
                        key_col: "file_hash",
                        state_col: "host_count",
                        extra_summary_filter: "",
                    },
                    &hash_refs,
                )
                .await;
        }
        if !domain_conds.is_empty() && exprs.domain != "NULL" {
            rescue.domains = self
                .run_prevalence_rescue_probe(
                    base_no_order,
                    window_cutoff_sql,
                    RescueProbeSpec {
                        probe_id: CompanionQuery::RescueProbeDomain.query_id(query_id),
                        lookup_expr: &exprs.domain,
                        dict: "nanosiem.domain_prevalence_dict",
                        summary_table: self.table_names.read("domain_prevalence_summary"),
                        key_col: "domain",
                        state_col: "source_host_count",
                        extra_summary_filter: "",
                    },
                    &domain_refs,
                )
                .await;
        }
        // IP: enrich-only dimension. The ip summary key is RAW (not lowercased),
        // and the ip dict source is `WHERE is_private = 0`, so the summary probe
        // mirrors that. Broad rules (Saturn: 133k distinct IPs / 1h `*|`) are
        // bounded by the miss-key cap (~17s, no OOM) and the rarest-first
        // artifact cap + WARN; narrow rules are ~0.3s.
        if !ip_conds.is_empty() && exprs.ip != "NULL" {
            rescue.ips = self
                .run_prevalence_rescue_probe(
                    base_no_order,
                    window_cutoff_sql,
                    RescueProbeSpec {
                        probe_id: CompanionQuery::RescueProbeIp.query_id(query_id),
                        lookup_expr: &exprs.ip,
                        dict: "nanosiem.ip_prevalence_dict",
                        summary_table: self.table_names.read("ip_prevalence_summary"),
                        key_col: "ip",
                        state_col: "source_host_count",
                        extra_summary_filter: "is_private = 0 AND ",
                    },
                    &ip_refs,
                )
                .await;
        }

        // NAN-5565: bound the inlined keys. What is left out is counted in
        // `rescue.dropped` and reported loudly by the caller
        // (`report_partial_rescue`).
        rescue.cap_key_bytes(super::prevalence_processing::PREVALENCE_RESCUE_KEY_BYTE_CAP);

        rescue
    }

    /// Execute one rescue probe (see [`Self::compute_prevalence_rescue`]).
    /// Fail-open: any error yields an empty rescued set with a WARN.
    async fn run_prevalence_rescue_probe(
        &self,
        base_no_order: &str,
        window_cutoff_sql: &str,
        spec: RescueProbeSpec<'_>,
        conds: &[&crate::query::PrevalenceCondition],
    ) -> Vec<super::prevalence_processing::RescuedArtifact> {
        let Some(ch_executor) = self.ch_executor.as_ref() else {
            return Vec::new();
        };
        let probe_sql = super::prevalence_processing::build_prevalence_rescue_probe_sql(
            base_no_order,
            spec.lookup_expr,
            spec.dict,
            &spec.summary_table,
            spec.key_col,
            spec.state_col,
            window_cutoff_sql,
            spec.extra_summary_filter,
        );
        let probe_start = Instant::now();
        match self.execute_companion_dynamic(ch_executor, &probe_sql, &spec.probe_id).await {
            Ok(rows) => {
                let rescued = super::prevalence_processing::filter_rescued_artifacts(rows, conds);
                if !rescued.is_empty() {
                    tracing::info!(
                        entity = spec.key_col,
                        rescued = rescued.len(),
                        duration_ms = probe_start.elapsed().as_millis() as u64,
                        "Prevalence rescue: dict-blind artifacts re-verified rare against the real-time summary"
                    );
                }
                rescued
            }
            Err(e) => {
                // Fail OPEN to an empty rescue: the main query then behaves
                // exactly as before NAN-1705 (dict-blind rows stay dropped).
                tracing::warn!(
                    entity = spec.key_col,
                    error = %e,
                    "Prevalence rescue probe failed; dict-blind artifacts will not be rescued this cycle"
                );
                Vec::new()
            }
        }
    }

    /// Build the JOIN-based prevalence pushdown SQL (window pick + base scan +
    /// dictGet host_count JOIN), WITHOUT executing it or fetching config.
    ///
    /// NAN-1694: extracted from `search_with_prevalence_join` so the explain path
    /// (`SearchService::explain`) renders the SAME SQL that actually executes. Kept
    /// SYNC — the async dependencies (`rarity_threshold`, and the NAN-1705 rescue
    /// probe result) are passed in by the caller; explain passes an empty rescue
    /// and appends `prevalence_rescue_explain_note` (the rescue adds per-entity
    /// index columns and value arrays). Returns
    /// `(sql, num_commands_pushed_to_sql)`.
    pub(crate) fn generate_prevalence_pushdown_sql(
        &self,
        query: &Query,
        prevalence_commands: &[PrevalenceCommandInfo],
        post_prevalence_commands: &[Command],
        time_range: &TimeRange,
        rarity_threshold: u64,
        rescue: &PrevalenceRescue,
        window: Option<ResultWindow>,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<(String, usize), SearchError> {
        self.generate_prevalence_pushdown_sql_with_shape(
            query,
            prevalence_commands,
            post_prevalence_commands,
            time_range,
            rarity_threshold,
            rescue,
            window,
            gscope,
        )
        .map(|(sql, pushed, _)| (sql, pushed))
    }

    /// [`Self::generate_prevalence_pushdown_sql`] plus whether the SQL is an
    /// aggregation for the executor's paginated paths.
    ///
    /// NAN-5565: both the tripwire and the aggregation decision look at the
    /// RESCUE-FREE rendering. The rescue only adds escaped, event-derived
    /// literals (keys) and integers, so the shape is identical; but a key such
    /// as `sum(` would flip text sniffing into the full-window `count(*) OVER
    /// ()` path, and a large rescue would push the text past the tripwire's
    /// size limit, so it would no longer be observed at all.
    pub(crate) fn generate_prevalence_pushdown_sql_with_shape(
        &self,
        query: &Query,
        prevalence_commands: &[PrevalenceCommandInfo],
        post_prevalence_commands: &[Command],
        time_range: &TimeRange,
        rarity_threshold: u64,
        rescue: &PrevalenceRescue,
        window: Option<ResultWindow>,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<(String, usize, bool), SearchError> {
        let render = |rescue: &PrevalenceRescue| {
            self.generate_prevalence_pushdown_sql_unobserved(
                query,
                prevalence_commands,
                post_prevalence_commands,
                time_range,
                rarity_threshold,
                rescue,
                window,
                gscope,
            )
        };
        let (sql, pushed) = render(rescue)?;
        let rescue_free = if rescue.is_empty() {
            None
        } else {
            Some(render(&PrevalenceRescue::default())?.0)
        };
        let shape_sql = rescue_free.as_deref().unwrap_or(&sql);
        // Security review 2026-11-08 (layer 2): this template is a second SQL
        // generator, so its output gets the same log-only tripwire.
        crate::query::generated_sql_tripwire::observe(shape_sql, "prevalence_pushdown");
        let aggregation =
            crate::search::execution::clickhouse_executor::is_aggregation_query(shape_sql);
        Ok((sql, pushed, aggregation))
    }

    fn generate_prevalence_pushdown_sql_unobserved(
        &self,
        query: &Query,
        prevalence_commands: &[PrevalenceCommandInfo],
        post_prevalence_commands: &[Command],
        time_range: &TimeRange,
        rarity_threshold: u64,
        rescue: &PrevalenceRescue,
        window: Option<ResultWindow>,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<(String, usize), SearchError> {
        let time_window = Self::resolve_prevalence_window(prevalence_commands)?;

        // NAN-5660: how much of the base `raw_logs` keeps (and which columns
        // the final SELECT reads).
        let scan = self.prevalence_scan_plan(query, prevalence_commands, post_prevalence_commands, window);
        // A pushed window goes INTO the base (`… ORDER BY timestamp DESC
        // LIMIT n`): a LIMIT on the `SELECT * FROM (<base>)` wrapper reads
        // every column of every row before the top-N (measured: 2.6 GiB read
        // and Code 241 at 1 GiB for 2M OCSF rows, vs 35 MiB / 41 MiB directly
        // on the table). The plan only pushes over a base in natural time
        // order; should the generator end it otherwise, the wrapper bound
        // keeps the result correct.
        let windowed_base = match (scan.window_pushed, scan.raw_logs_limit) {
            (true, Some(n)) => {
                let sql = self.generate_prevalence_base_sql_with_limit(query, time_range, Some(n), gscope)?;
                let ends_in_window = sql
                    .trim_end()
                    .ends_with(&format!("ORDER BY timestamp DESC LIMIT {n}"));
                if !ends_in_window {
                    tracing::warn!("prevalence window base does not end in its top-N; bounding the wrapper");
                }
                ends_in_window.then_some(sql)
            }
            _ => None,
        };
        let base_windowed = windowed_base.is_some();
        let base_sql = match windowed_base {
            Some(sql) => sql,
            None => self.generate_prevalence_base_sql(query, time_range, gscope)?,
        };

        // NAN-362: Prior to the dict-based rewrite, this path built CTEs that aggregated the
        // full *_prevalence_agg universe and LEFT JOINed them — which OOMed ClickHouse on any
        // non-trivial base query. A count-based short-circuit used to guard that. The new path
        // only issues dictGet() calls scoped to rows in the base query, so the guard is no
        // longer needed.

        // Generate the JOIN-based SQL with prevalence filtering
        // num_commands_pushed indicates how many post-prevalence commands were pushed into SQL
        // (aggregation + trailing sort/head/etc.) and should be skipped in Rust post-processing
        // Pagination is owned by `execute_clickhouse_sql` below — the generator
        // no longer takes limit/offset. NAN-1691 (P1-B): enrich-only / filter-only
        // prevalence SQL is 1:1 row decoration (host_count / is_rare /
        // prevalence_score columns), NOT an aggregation, so it now takes the
        // executor's raw-event branch (inject_limit_offset + a bounded count
        // companion). Only when a real aggregation is pushed down (`… | stats …`)
        // does the SQL trip `is_aggregation_query` and get the count(*) OVER ()
        // full-window wrap.
        // NAN-1691: the filter form carries its predicate INSIDE the prevalence command
        // (conditions), not as a post-prevalence WHERE. Push those into the dictGet WHERE
        // over the windowed host-count aliases so the filter runs in ClickHouse instead of
        // the 1M-row in-memory fetch.
        let filter_conditions: Vec<crate::query::PrevalenceCondition> = prevalence_commands
            .iter()
            .flat_map(|cmd| cmd.conditions.iter().cloned())
            .collect();

        self.generate_prevalence_join_sql(
            &base_sql,
            base_windowed,
            post_prevalence_commands,
            &filter_conditions,
            time_window,
            rarity_threshold,
            rescue,
            &scan,
            gscope,
        )
    }

    /// NAN-5660: the scan plan for this pushdown, under the tenant profile the
    /// lookups and the base scan use.
    pub(crate) fn prevalence_scan_plan(
        &self,
        query: &Query,
        prevalence_commands: &[PrevalenceCommandInfo],
        post_prevalence_commands: &[Command],
        window: Option<ResultWindow>,
    ) -> PrevalenceScanPlan {
        plan_prevalence_scan(
            query,
            prevalence_commands,
            post_prevalence_commands,
            window,
            self.active_profile.as_ref(),
        )
    }

    /// Generate SQL with JOINs to prevalence tables
    ///
    /// Returns (sql, num_commands_pushed_to_sql) — the caller should skip the first
    /// `num_commands_pushed_to_sql` post-prevalence commands in Rust post-processing
    /// since they have already been executed in ClickHouse.
    #[allow(clippy::too_many_arguments)]
    fn generate_prevalence_join_sql(
        &self,
        base_sql: &str,
        base_windowed: bool,
        post_prevalence_commands: &[Command],
        filter_conditions: &[crate::query::PrevalenceCondition],
        time_window: PrevalenceTimeWindow,
        rarity_threshold: u64,
        rescue: &PrevalenceRescue,
        scan: &PrevalenceScanPlan,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<(String, usize), SearchError> {
        tracing::debug!(
            "generate_prevalence_join_sql: {} post-prevalence commands",
            post_prevalence_commands.len()
        );
        for (i, cmd) in post_prevalence_commands.iter().enumerate() {
            tracing::debug!("  Post-prevalence command {}: {:?}", i, cmd);
        }

        let window_cutoff_sql: &str = Self::prevalence_window_cutoff_sql(time_window)?;
        // Prevalence summary dicts are SCHEMA-AGNOSTIC (clickhouse/ocsf/init.sql:697-823):
        // OCSF reuses the exact same `nanosiem.{hash,domain,ip}_prevalence_dict`, keyed by the
        // canonical hash/domain/ip string. So the dict names are identical for UDM and OCSF —
        // no profile branching needed here.
        let domain_dict = "nanosiem.domain_prevalence_dict".to_string();
        let ip_dict = "nanosiem.ip_prevalence_dict".to_string();
        let hash_dict = "nanosiem.hash_prevalence_dict".to_string();

        // The lookup keys come from the canonical artifact list (see
        // `prevalence_lookup_exprs` — shared with the NAN-1705 rescue probe so
        // both key off byte-identical expressions).
        let PrevalenceLookupExprs {
            domain: domain_lookup_expr,
            ip: ip_lookup_expr,
            hash: hash_lookup_expr,
        } = self.prevalence_lookup_exprs();

        // NAN-5293: `prevalence_artifact` is the lookup key that won, so the
        // artifact shown is exactly the one whose prevalence was read (before,
        // a separate COALESCE could name a different column than the key).
        let domain_artifact_expr = "l._domain_lookup";
        let ip_artifact_expr = "l._ip_lookup";
        let hash_artifact_expr = "l._hash_lookup";

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
                    let expr_sql = self
                        .eval_expression_to_clickhouse_sql_with_context_and_eval_fields(
                            &assignment.expression,
                            true,
                            &eval_field_names,
                            rarity_threshold,
                            gscope,
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
                            gscope,
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

        // NAN-1691: filter-form conditions → dictGet WHERE over the windowed host-count
        // aliases the base_logs CTE already computes. Miss / out-of-window → 9999 → the
        // `< 9999` presence guard drops the row for EVERY operator, exactly matching the
        // in-memory `prevalence_passes_filter` (None → false). These AND together with any
        // post-prevalence WHEREs above, mirroring the in-memory per-condition AND loop.
        // NAN-1705 (D4b): the predicate is UNCHANGED — the `_hp/_dp_host_count`
        // aliases below are transform-rewritten to the rescued rows' true counts,
        // so `{alias} < 9999 AND {alias} op N` matches them directly here.
        for cond in filter_conditions {
            where_conditions.push(
                super::prevalence_processing::prevalence_filter_condition_to_sql(cond)?,
            );
        }

        // Strip ORDER BY and LIMIT from base SQL since we'll add our own
        let base_sql_clean = base_sql.trim().trim_end_matches(';');

        // Remove ORDER BY clause if present (case insensitive)
        // NAN-5660: a windowed base keeps its own `ORDER BY … LIMIT n`.
        let base_sql_no_order = if base_windowed {
            base_sql_clean
        } else if let Some(order_pos) = base_sql_clean.to_ascii_lowercase().rfind(" order by ") {
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
                .map(|(name, expr)| {
                    // Security review 2026-11-08 (NAN-5009): the eval target is an
                    // OUTPUT alias the parser accepts with arbitrary quoted text, so
                    // it is quoted exactly like `commands.rs` quotes the same alias.
                    format!("    {}", crate::sql_hygiene::alias_expr(&format!("({})", expr), name))
                })
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
        // NAN-5718: `floor(0.5 + x)`, not `round(x)`: ClickHouse rounds halves
        // to even (52.5 → 52) while the Prevalence API's
        // `calculate_prevalence_score` rounds them away from zero (→ 53). The
        // score is never negative, so the two agree exactly.
        let prevalence_score_sql = format!(
            r#"CASE
        WHEN {m} >= 9999 THEN 0
        WHEN {m} = 0 THEN 0
        WHEN {m} < {t} THEN toUInt8(floor(0.5 + least(toFloat64({m}) / {t} * 20, 20)))
        WHEN {m} < {t} * 2 THEN toUInt8(floor(0.5 + 20 + (toFloat64({m}) - {t}) / {t} * 30))
        WHEN {m} < {t} * 10 THEN toUInt8(floor(0.5 + 50 + (toFloat64({m}) - {t} * 2) / ({t} * 8) * 30))
        ELSE toUInt8(floor(0.5 + 80 + least((toFloat64({m}) - {t} * 10) / ({t} * 90) * 20, 20)))
    END"#,
            m = min_host_count,
            t = rt,
        );

        // NAN-1691 (P1-B): enrich-only prevalence is 1:1 row decoration. Cap the rows that
        // flow into the dictGet projections at DEFAULT_RESULT_LIMIT (the standard safety cap
        // applied to every other raw-event query) so an unbounded window scan can no longer
        // OOM the shared pod. `ORDER BY timestamp DESC` picks the newest N — matching the
        // final `ORDER BY l.timestamp DESC` at the outer SELECT — and the bound lands where
        // the ORDER-BY stripper cannot delete it and where the executor sees a ` LIMIT `
        // (forcing the structural pagination wrap instead of SETTINGS string-surgery).
        //
        // A downstream aggregation (pushed to a SQL GROUP BY below) needs its full input
        // set, and the FILTER form's dictGet predicate must run over the full window (rare
        // rows earlier in the window must not be missed), so both stay unbounded.
        //
        // NAN-5660: when nothing after the prevalence stage(s) filters, reorders or
        // aggregates, the bound is the caller's result window instead of the 1M cap, and a
        // `table`/`fields` output names its columns instead of `l.*`; see `prevalence_scan`.
        let raw_logs_bound = match scan.raw_logs_limit {
            None => String::new(),
            Some(_) if base_windowed => String::new(),
            Some(n) => format!("\n    ORDER BY timestamp DESC\n    LIMIT {n}"),
        };
        let output_row_columns = output_row_columns_sql(scan);

        // NAN-1705 (D4b): build the domain/hash/IP base_logs projection aliases,
        // each `rescue_value_sql`-wrapped so a rescued dict-blind key resolves
        // to its FRESH summary value IN ClickHouse. Because the alias itself
        // now carries the truth, the pushed predicate, the decoration CASEs
        // below, AND any downstream `| where host_count < N` all see the
        // rescued host_count — closing the "downstream reference re-reads 9999"
        // gap without an OR-branch or post-query patch. Empty rescue →
        // `rescue_value_sql` returns the base dict expression verbatim and no
        // index column is emitted, so the whole query stays byte-identical to
        // the pre-NAN-1705 form. IP is rescued ONLY for the `enrich=true |
        // where host_count < N` form (residual #2) — its `rescue.ips` is empty
        // otherwise, so the IP projection is byte-identical for the filter form.
        //
        // NAN-5565: each entity's rescued keys are written ONCE, as a
        // `transform(key, [...], range(1, n + 1), 0)` index column in
        // `logs_with_keys` (`_dp/_ip/_hp_rescue_idx`); the four projections read
        // typed value arrays by that index. The index columns are dropped from
        // `base_logs` with `* EXCEPT` so they never reach the output rows. No
        // artifact is dropped for size: the executor lifts `max_query_size`
        // for a query whose text needs it (`ClickHouseExecutor::sized_query`).
        //
        // Byte-for-byte reproduction of the historical inline expressions (dict
        // key differs: domain/ip use `ifNull(_x_lookup, '')`, hash uses
        // `_hash_lookup` bare). The rescue match-key always `ifNull(..)`s so
        // an empty/NULL lookup can never collide with a rescued (non-empty) key.
        let build_projection =
            |dict: &str, dict_key: &str, idx_alias: &str, rescued: &[_]| {
                let host_count_base = format!(
                    "if(dictGetOrDefault('{dict}', 'last_seen', {dict_key}, toDateTime64(0, 6)) >= {w},\n           dictGetOrDefault('{dict}', 'host_count', {dict_key}, toUInt16(9999)),\n           toUInt16(9999))",
                    w = window_cutoff_sql,
                );
                let first_seen_base = format!(
                    "dictGetOrDefault('{dict}', 'first_seen', {dict_key}, toDateTime64(0, 6))"
                );
                let last_seen_base = format!(
                    "dictGetOrDefault('{dict}', 'last_seen', {dict_key}, toDateTime64(0, 6))"
                );
                let total_occ_base = format!(
                    "dictGetOrDefault('{dict}', 'total_occurrences', {dict_key}, toUInt64(0))"
                );
                (
                    rescue_value_sql(&host_count_base, idx_alias, rescued, RescueAttr::HostCount),
                    rescue_value_sql(&first_seen_base, idx_alias, rescued, RescueAttr::FirstSeen),
                    rescue_value_sql(&last_seen_base, idx_alias, rescued, RescueAttr::LastSeen),
                    rescue_value_sql(
                        &total_occ_base,
                        idx_alias,
                        rescued,
                        RescueAttr::TotalOccurrences,
                    ),
                )
            };
        let (
            dp_host_count_expr,
            dp_first_seen_expr,
            dp_last_seen_expr,
            dp_total_occurrences_expr,
        ) = build_projection(
            &domain_dict,
            "ifNull(_domain_lookup, '')",
            "_dp_rescue_idx",
            &rescue.domains,
        );
        let (
            hp_host_count_expr,
            hp_first_seen_expr,
            hp_last_seen_expr,
            hp_total_occurrences_expr,
        ) = build_projection(&hash_dict, "_hash_lookup", "_hp_rescue_idx", &rescue.hashes);
        let (
            ip_host_count_expr,
            ip_first_seen_expr,
            ip_last_seen_expr,
            ip_total_occurrences_expr,
        ) = build_projection(&ip_dict, "ifNull(_ip_lookup, '')", "_ip_rescue_idx", &rescue.ips);

        // NAN-5565: the once-per-entity rescue index columns (empty rescue →
        // none, and `base_logs` keeps its plain `SELECT *`).
        let rescue_index_cols: Vec<(String, &str)> = [
            ("ifNull(_domain_lookup, '')", "_dp_rescue_idx", &rescue.domains),
            ("ifNull(_ip_lookup, '')", "_ip_rescue_idx", &rescue.ips),
            ("ifNull(_hash_lookup, '')", "_hp_rescue_idx", &rescue.hashes),
        ]
        .into_iter()
        .filter_map(|(match_key, alias, rescued)| {
            rescue_index_sql(match_key, rescued).map(|sql| (sql, alias))
        })
        .collect();
        let rescue_index_columns: String = rescue_index_cols
            .iter()
            .map(|(sql, alias)| format!(",\n        {sql} AS {alias}"))
            .collect();
        let base_logs_star = if rescue_index_cols.is_empty() {
            "*".to_string()
        } else {
            format!(
                "* EXCEPT ({})",
                rescue_index_cols
                    .iter()
                    .map(|(_, alias)| *alias)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };

        // Build the final SQL using dictGet() against precomputed per-window prevalence dicts.
        // NAN-362: Replaces the old CTE + LEFT JOIN path which aggregated the entire
        // *_prevalence_agg universe before joining (O(universe) memory — OOM on any
        // non-trivial time window). Dict lookups are O(rows-in-result) instead.
        // Priority for convenience fields: domain > IP > hash
        // Sentinel value 9999 = "common or not tracked" (dicts only load entities with
        // host_count < 1000).
        //
        // Template notes (kept here, not as SQL comments: generated SQL carries no
        // comments so the layer-2 tripwire can treat any comment as suspicious,
        // security review 2026-11-08):
        // - `_domain_lookup`: first non-empty domain field (IPs excluded).
        // - `_ip_lookup`: first non-empty IP field (or dest_host if it is an IP).
        // - `_hash_lookup`: first non-empty hash field, lowercased.
        // - `_*_host_count` is masked to 9999 when last_seen is outside the window;
        //   this is how NAN-364 serves sub-30d windows from the 30d dict.
        // - NAN-366: `host_count` is the rarest entity (lowest count). Ties break
        //   domain → ip → hash only after the minimum is established, so a rare IP
        //   is not hidden behind a common domain.
        let sql = format!(
            r#"WITH raw_logs AS (
    SELECT * FROM (
        {base_sql}
    ){raw_logs_bound}
),
logs_with_keys AS (
    SELECT *,
        {domain_lookup_expr} AS _domain_lookup,
        {ip_lookup_expr} AS _ip_lookup,
        {hash_lookup_expr} AS _hash_lookup{rescue_index_columns}
    FROM raw_logs
),
base_logs AS (
    SELECT {base_logs_star},
        {dp_host_count_expr} AS _dp_host_count,
        {dp_first_seen_expr} AS _dp_first_seen,
        {dp_last_seen_expr} AS _dp_last_seen,
        {dp_total_occurrences_expr} AS _dp_total_occurrences,
        {ip_host_count_expr} AS _ip_host_count,
        {ip_first_seen_expr} AS _ip_first_seen,
        {ip_last_seen_expr} AS _ip_last_seen,
        {ip_total_occurrences_expr} AS _ip_total_occurrences,
        {hp_host_count_expr} AS _hp_host_count,
        {hp_first_seen_expr} AS _hp_first_seen,
        {hp_last_seen_expr} AS _hp_last_seen,
        {hp_total_occurrences_expr} AS _hp_total_occurrences
    FROM logs_with_keys
)
SELECT
    {output_row_columns},
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
            raw_logs_bound = raw_logs_bound,
            output_row_columns = output_row_columns,
            // NAN-1705 (D4b): all three dimensions' projections are pre-built
            // (rescue-aware); the dict names AND the window_cutoff mask are baked
            // into those exprs, so `{domain_dict}` / `{ip_dict}` / `{hash_dict}` /
            // `{window_cutoff_sql}` no longer appear in the template.
            dp_host_count_expr = dp_host_count_expr,
            dp_first_seen_expr = dp_first_seen_expr,
            dp_last_seen_expr = dp_last_seen_expr,
            dp_total_occurrences_expr = dp_total_occurrences_expr,
            ip_host_count_expr = ip_host_count_expr,
            ip_first_seen_expr = ip_first_seen_expr,
            ip_last_seen_expr = ip_last_seen_expr,
            ip_total_occurrences_expr = ip_total_occurrences_expr,
            hp_host_count_expr = hp_host_count_expr,
            hp_first_seen_expr = hp_first_seen_expr,
            hp_last_seen_expr = hp_last_seen_expr,
            hp_total_occurrences_expr = hp_total_occurrences_expr,
            is_rare_sql = is_rare_sql,
            prevalence_score_sql = prevalence_score_sql,
            domain_lookup_expr = domain_lookup_expr,
            ip_lookup_expr = ip_lookup_expr,
            hash_lookup_expr = hash_lookup_expr,
            rescue_index_columns = rescue_index_columns,
            base_logs_star = base_logs_star,
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

            // NAN-5632: the stages are generated as ONE chain so a column an
            // earlier stage produces (`time_bucket`, `count`, a by-field
            // alias) and the columns `prevalence_results` adds (the
            // decorations, eval outputs) resolve as plain columns, not as
            // unknown event fields (`unmapped."time_bucket"` on OCSF).
            let mut source_columns: std::collections::HashSet<String> =
                PREVALENCE_RESULT_COLUMNS.iter().map(|c| (*c).to_string()).collect();
            source_columns.extend(eval_field_names.iter().cloned());
            // NAN-5628: not `stage_<i>`: the base pipeline nested in
            // `raw_logs` carries its own `WITH stage_0, …`, and reusing
            // those names here made ClickHouse resolve these outer stages
            // against the inner CTEs (Code 60 UNKNOWN_TABLE).
            let stages = self
                .sql_generator(gscope)
                .generate_command_chain_sql(&current_source, &sql_pushable, "pv_stage_", &source_columns)
                .map_err(|e| SearchError::SqlGenError(e.to_string()))?;
            for (stage_name, cmd_sql) in stages {
                cte_sql = format!("{},\n{} AS (\n{}\n)", cte_sql, stage_name, cmd_sql);
                current_source = stage_name;
            }

            sql = format!("{}\nSELECT * FROM {}", cte_sql, current_source);
        }
        // NAN-366 pagination fix: do NOT append `LIMIT {limit} OFFSET {offset}` here.
        // The executor (`execute_sql_with_query_id`) owns pagination + the pre-pagination
        // total in BOTH of its branches, so appending it here would double-paginate.
        // NAN-1691 (P1-B): enrich-only / filter-only prevalence SQL is 1:1 row decoration
        // (host_count / is_rare / prevalence_score), NOT an aggregation, so it now takes the
        // raw-event branch — `inject_limit_offset` slices the page and a bounded count
        // companion reports the total. Only when a real aggregation is pushed down
        // (`… | stats …`) does the SQL match `is_aggregation_query` and get the
        // `SELECT *, count(*) OVER () AS _total_count FROM (<sql>) LIMIT {limit} OFFSET {offset}`
        // wrap. Either way, appending LIMIT/OFFSET here too double-paginated: page 1's
        // `count(*) OVER ()` ran AFTER the inner LIMIT so the reported total was capped at
        // the page size, and page 2+ came back EMPTY because the outer OFFSET slid past the
        // already-offset inner window. Leaving the query unbounded (the base CTE still
        // carries its own safety LIMIT) lets the executor slice the page and report the real
        // total. The push-down branch above already relied on this — it never appended
        // pagination either.

        tracing::debug!(
            "Generated prevalence SQL (first 2000 chars): {}",
            crate::text_bounds::prefix_at_most(&sql, 2000)
        );
        Ok((sql, num_commands_pushed))
    }

    /// Convert a prevalence-related condition to SQL (see [`prevalence_condition_sql`]).
    fn prevalence_condition_to_sql_with_eval(
        &self,
        condition: &crate::query::SearchExpr,
        eval_field_names: &std::collections::HashSet<String>,
        rarity_threshold: u64,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<String, SearchError> {
        prevalence_condition_sql(&self.sql_generator(gscope), condition, eval_field_names, rarity_threshold)
    }

    fn eval_expression_to_clickhouse_sql_with_context_and_eval_fields(
        &self,
        expr: &crate::query::EvalExpression,
        in_prevalence_context: bool,
        eval_field_names: &std::collections::HashSet<String>,
        rarity_threshold: u64,
        gscope: crate::query::GeneratorScope<'_>,
    ) -> Result<String, SearchError> {
        prevalence_eval_sql(
            &self.sql_generator(gscope),
            expr,
            in_prevalence_context,
            eval_field_names,
            rarity_threshold,
        )
    }
}

/// NAN-4943: the `WHERE` SQL a post-`| prevalence` predicate is pushed down to
/// (over the joined `l` row alias), for parity tests that run it on real
/// ClickHouse next to the canonical generator and the post-stage evaluator.
#[doc(hidden)]
pub fn prevalence_where_sql(
    gen: &crate::query::ClickHouseSqlGenerator,
    condition: &crate::query::SearchExpr,
) -> Result<String, SearchError> {
    prevalence_condition_sql(gen, condition, &std::collections::HashSet::new(), 3)
}

/// Convert a prevalence-related condition to SQL, with support for eval-created fields.
///
/// NAN-4943: string predicates use the canonical generator's helpers
/// (`ci_like`, `ch_lower`, `regex_predicate_sql`, `keyword_predicate`), so a
/// predicate means the same thing before and after `| prevalence`.
    /// Convert a prevalence-related condition to SQL, with support for eval-created fields
    ///
    /// Similar to `prevalence_condition_to_sql`, but also recognizes fields created by
    /// EVAL commands that appear before the WHERE in post-prevalence processing.
pub(crate) fn prevalence_condition_sql(
        gen: &crate::query::ClickHouseSqlGenerator,
        condition: &crate::query::SearchExpr,
        eval_field_names: &std::collections::HashSet<String>,
        rarity_threshold: u64,
    ) -> Result<String, SearchError> {
        use crate::query::{Comparator, EvalExpression, SearchExpr, Value};

        match condition {
            SearchExpr::FieldFilter { field, op, value } => {
                // Normalize field name (e.g., command_line -> process)
                let field = normalize_prevalence_field(field);
                let field_name = field.as_ref().to_string();
                // Check if the field is an eval-created field
                let (sql_field, needs_null_check): (std::borrow::Cow<'_, str>, bool) =
                    if eval_field_names.contains(field.as_ref()) {
                        // Eval-created field: reference the quoted alias (NAN-5009).
                        (crate::sql_hygiene::quote_identifier(field.as_ref()).into(), false)
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
                                "CASE WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) >= 9999 THEN 0 WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) = 0 THEN 0 WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {t} THEN toUInt8(floor(0.5 + least(toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) / {t} * 20, 20))) WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {t} * 2 THEN toUInt8(floor(0.5 + 20 + (toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) - {t}) / {t} * 30)) WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) < {t} * 10 THEN toUInt8(floor(0.5 + 50 + (toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) - {t} * 2) / ({t} * 8) * 30)) ELSE toUInt8(floor(0.5 + 80 + least((toFloat64(least(_dp_host_count, _ip_host_count, _hp_host_count)) - {t} * 10) / ({t} * 90) * 20, 20))) END",
                                t = rt,
                            ).into(), false)
                        }
                        "first_seen" | "prevalence_first_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_first_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_first_seen WHEN _hp_host_count < 9999 THEN _hp_first_seen ELSE NULL END".into(), true),
                        "last_seen" | "prevalence_last_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_last_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_last_seen WHEN _hp_host_count < 9999 THEN _hp_last_seen ELSE NULL END".into(), true),
                        "total_occurrences" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_total_occurrences WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_total_occurrences WHEN _hp_host_count < 9999 THEN _hp_total_occurrences ELSE NULL END".into(), true),
                        other => (crate::sql_hygiene::qualified_column("l", other).into(), false),
                    }
                    };

                // NAN-4943: an array column is element membership, through
                // the canonical array predicate (`has` / `arrayExists`).
                if !needs_null_check && !eval_field_names.contains(&field_name) {
                    if let Some(sql) = gen
                        .array_field_predicate_sql(&field_name, &sql_field, op, value)
                        .map_err(|e| SearchError::SqlGenError(e.to_string()))?
                    {
                        return Ok(sql);
                    }
                }
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
                        // NAN-4943: string equality on a row column is the nPL
                        // lowercase match (`lower(toString(col)) = '<ch_lower>'`),
                        // exactly the canonical generator's; numeric literals and
                        // the computed prevalence fields stay typed.
                        if let Value::String(text) = value {
                            let is_bool_literal = matches!(text.to_ascii_lowercase().as_str(), "true" | "false");
                            let computed = needs_null_check
                                || matches!(field_name.as_str(), "is_rare" | "prevalence_score");
                            if matches!(op, Comparator::Eq | Comparator::Ne)
                                && !computed
                                && !(is_bool_literal && field_name == "is_rare")
                                && !gen.is_profile_numeric_field(&field_name)
                            {
                                return Ok(format!(
                                    "lower(toString({sql_field})) {sql_op} '{}'",
                                    escape_sql_string(&ch_lower(text))
                                ));
                            }
                        }
                        let sql_value = match value {
                            Value::Number(n) => n.to_string(),
                            Value::String(s) => {
                                // Boolean coercion: "true"/"false" → 1/0 for known boolean fields only
                                // Only is_rare is a computed UInt8 boolean in the prevalence JOIN
                                let lower = s.to_ascii_lowercase();
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
                                // NAN-4943: the single nPL lowercase match, with
                                // `%`/`_`/`\` in the value matched literally.
                                let escaped = escape_like_pattern(&escape_sql_string(&ch_lower(s)));
                                ci_like(&format!("toString({})", sql_field), &format!("%{escaped}%"), negate)
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
                                let escaped = escape_like_pattern(&escape_sql_string(&ch_lower(s)));
                                ci_like(&format!("toString({})", sql_field), &format!("{escaped}%"), negate)
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
                                let escaped = escape_like_pattern(&escape_sql_string(&ch_lower(s)));
                                ci_like(&format!("toString({})", sql_field), &format!("%{escaped}"), negate)
                            }
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "EndsWith requires string value".to_string(),
                                ))
                            }
                        }
                    }
                    Comparator::Like | Comparator::NotLike => {
                        let negate = matches!(op, Comparator::NotLike);
                        match value {
                            // Explicit LIKE: the user's `%`/`_` are the wildcards.
                            Value::String(s) => ci_like(
                                &format!("toString({})", sql_field),
                                &escape_sql_string(&ch_lower(s)),
                                negate,
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
                            Value::Regex(p) | Value::String(p) => p,
                            _ => {
                                return Err(SearchError::SqlGenError(
                                    "Regex requires string/regex value".to_string(),
                                ))
                            }
                        };
                        // NAN-4943: the canonical regex classification — a literal
                        // regex is the lowercase match, anything else RE2.
                        crate::query::clickhouse_sql_gen::search_expr::regex_predicate_sql(
                            &format!("toString({})", sql_field),
                            pattern,
                            negate,
                        )
                        .map_err(|e| SearchError::SqlGenError(e.to_string()))?
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
                let field = normalize_prevalence_field(field);
                let field_name = field.as_ref().to_string();
                // Check if the field is an eval-created field
                let (sql_field, needs_null_check): (std::borrow::Cow<'_, str>, bool) =
                    if eval_field_names.contains(field.as_ref()) {
                        (crate::sql_hygiene::quote_identifier(field.as_ref()).into(), false)
                    } else {
                        match field.as_ref() {
                        // NAN-366: match SELECT-side rarest-wins semantics.
                        "host_count" => ("CASE WHEN least(_dp_host_count, _ip_host_count, _hp_host_count) >= 9999 THEN NULL ELSE least(_dp_host_count, _ip_host_count, _hp_host_count) END".into(), true),
                        "first_seen" | "prevalence_first_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_first_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_first_seen WHEN _hp_host_count < 9999 THEN _hp_first_seen ELSE NULL END".into(), true),
                        "last_seen" | "prevalence_last_seen" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_last_seen WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_last_seen WHEN _hp_host_count < 9999 THEN _hp_last_seen ELSE NULL END".into(), true),
                        // NAN-5568: same as the plain FieldFilter arm.
                        "total_occurrences" => ("CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_total_occurrences WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_total_occurrences WHEN _hp_host_count < 9999 THEN _hp_total_occurrences ELSE NULL END".into(), true),
                        other => (crate::sql_hygiene::qualified_column("l", other).into(), false),
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
                        // Eval-created field reference: the quoted alias (NAN-5009).
                        crate::sql_hygiene::quote_identifier(name)
                    }
                    // NAN-5568: the function side resolves decorated
                    // prevalence fields too (`host_count`, `first_seen`, …).
                    _ => prevalence_eval_sql(
                        gen,
                        function,
                        true,
                        eval_field_names,
                        rarity_threshold,
                    )?,
                };

                if needs_null_check {
                    Ok(format!(
                        "({} IS NOT NULL AND {} {} {})",
                        sql_field, sql_field, sql_op, func_sql
                    ))
                } else if matches!(op, Comparator::Eq | Comparator::Ne)
                    && !gen.is_profile_numeric_field(&field_name)
                {
                    // NAN-4943: string equality against a function folds both
                    // sides with ClickHouse `lower()`, as the canonical
                    // generator's `field = lower(func)` form does.
                    Ok(format!(
                        "lower(toString({})) {} lower(toString({}))",
                        sql_field, sql_op, func_sql
                    ))
                } else {
                    Ok(format!("{} {} {}", sql_field, sql_op, func_sql))
                }
            }
            SearchExpr::And(left, right) => {
                let left_sql = prevalence_condition_sql(
                    gen,
                    left,
                    eval_field_names,
                    rarity_threshold,
                )?;
                let right_sql = prevalence_condition_sql(
                    gen,
                    right,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("({} AND {})", left_sql, right_sql))
            }
            SearchExpr::Or(left, right) => {
                let left_sql = prevalence_condition_sql(
                    gen,
                    left,
                    eval_field_names,
                    rarity_threshold,
                )?;
                let right_sql = prevalence_condition_sql(
                    gen,
                    right,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("({} OR {})", left_sql, right_sql))
            }
            SearchExpr::Not(inner) => {
                let inner_sql = prevalence_condition_sql(
                    gen,
                    inner,
                    eval_field_names,
                    rarity_threshold,
                )?;
                Ok(format!("NOT ({})", inner_sql))
            }
            SearchExpr::Group(inner) => {
                let inner_sql = prevalence_condition_sql(
                    gen,
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
                let field = normalize_prevalence_field(field);
                let field_name = field.as_ref().to_string();
                let is_eval_field = eval_field_names.contains(field.as_ref());
                // Security review 2026-11-08: both forms are quoted. A quoted
                // eval/rename name made before `| prevalence` is "derived", so it
                // skips field-name validation and must not reach SQL raw.
                let sql_field: std::borrow::Cow<'_, str> = if is_eval_field {
                    crate::sql_hygiene::quote_identifier(field.as_ref()).into()
                } else {
                    crate::sql_hygiene::qualified_column("l", field.as_ref()).into()
                };
                if !is_eval_field {
                    if let Some(sql) = gen
                        .array_in_list_sql(&field_name, &sql_field, values, *negated)
                        .map_err(|e| SearchError::SqlGenError(e.to_string()))?
                    {
                        return Ok(sql);
                    }
                }
                let op = if *negated { "NOT IN" } else { "IN" };
                let all_strings = values.iter().all(|v| matches!(v, Value::String(_)));
                let values_sql: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => {
                            if all_strings {
                                // NAN-4943: ClickHouse `lower()` semantics.
                                format!("'{}'", escape_sql_string(&ch_lower(s)))
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
                // NAN-4943: the canonical keyword predicate (token search; term
                // boundaries for one-sided wildcards) over the profile's body
                // columns of the joined row.
                let cols: Vec<String> =
                    // sql-lint: allow(profile column constants)
                    gen.keyword_search_columns().iter().map(|c| format!("l.{c}")).collect();
                let cols: Vec<&str> = cols.iter().map(String::as_str).collect();
                Ok(crate::query::clickhouse_sql_gen::keyword_predicate(kw, &cols))
            }
            // NAN-2336: arithmetic `where` predicates (NAN-2331) used to fall
            // into the catch-all below and fail the query at RUNTIME with
            // "Unsupported expression type", which is how the shape the
            // feature most obviously exists for —
            // `| prevalence enrich=true | where (last_seen - first_seen) >= 300`
            // — never worked.
            //
            // `in_prevalence_context = true` is the load-bearing argument: it
            // rewrites `first_seen`/`last_seen` into the rarest-wins CASE
            // expressions over the dict-derived `_dp_*`/`_ip_*`/`_hp_*`
            // aliases. They are logical prevalence fields, not columns of the
            // scanned table, so without the rewrite the emitted SQL names
            // something that does not resolve. Validated against live
            // ClickHouse: the rewritten predicate parses and selects the
            // rarest artifact's timestamps.
            SearchExpr::EvalPredicate(expression) => {
                prevalence_eval_sql(gen, expression, true, eval_field_names, rarity_threshold)
            }
            // NAN-4943: a standalone boolean function (`like(f, "…")`,
            // `isnull(f)`, `cidrmatch(…)`) lowers through the same typed eval
            // path as the canonical generator; it failed the whole query with
            // "Unsupported expression type" after `| prevalence`.
            SearchExpr::BooleanFunction(function) => {
                prevalence_eval_sql(gen, function, true, eval_field_names, rarity_threshold)
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


    /// Route prevalence evals through the same typed, profile-aware lowering as
    /// ordinary nPL. Only names created by an earlier eval and the logical
    /// prevalence timestamp fields override normal schema resolution.
fn prevalence_eval_sql(
        gen: &crate::query::ClickHouseSqlGenerator,
        expr: &crate::query::EvalExpression,
        in_prevalence_context: bool,
        eval_field_names: &std::collections::HashSet<String>,
        rarity_threshold: u64,
    ) -> Result<String, SearchError> {
        let override_field = |field: &str, _numeric_context: bool| {
            if eval_field_names.contains(field) {
                return Some(crate::query::clickhouse_sql_gen::escape_identifier(field));
            }
            if !in_prevalence_context {
                return None;
            }
            decorated_prevalence_field_sql(field, rarity_threshold)
        };

        crate::query::clickhouse_sql_gen::typed_eval_expression_to_sql_with_field_override(
            gen,
            expr,
            &override_field,
        )
        .map_err(|error| SearchError::SqlGenError(error.to_string()))
    }

/// NAN-5568: the SQL for a decorated `| prevalence` output field (host_count,
/// first/last_seen, total_occurrences, is_rare, prevalence_score,
/// prevalence_type, prevalence_artifact) when an eval
/// or a `where` expression after `| prevalence` reads it.
///
/// These fields are SELECT aliases of the pushdown (`host_count`,
/// `prevalence_first_seen`, …), not columns of the scanned table, so normal
/// schema resolution sent them to the unmapped/`ext` fallback
/// (`unmapped."host_count"` on OCSF), which is always empty: `eval
/// very_rare=(host_count < 3)` was never true. Each one resolves to the same
/// rarest-wins expression the SELECT and the `where` field filter use.
fn decorated_prevalence_field_sql(field: &str, rarity_threshold: u64) -> Option<String> {
    const LEAST: &str = "least(_dp_host_count, _ip_host_count, _hp_host_count)";
    let rarest = |suffix: &str| {
        format!(
            "(CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN _dp_{suffix} WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN _ip_{suffix} WHEN _hp_host_count < 9999 THEN _hp_{suffix} ELSE NULL END)"
        )
    };
    // The winning entity's value, as the SELECT's prevalence_type /
    // prevalence_artifact CASEs pick it.
    let rarest_pick = |domain: &str, ip: &str, hash: &str| {
        format!(
            "(CASE WHEN _dp_host_count < 9999 AND _dp_host_count <= _ip_host_count AND _dp_host_count <= _hp_host_count THEN {domain} WHEN _ip_host_count < 9999 AND _ip_host_count <= _hp_host_count THEN {ip} WHEN _hp_host_count < 9999 THEN {hash} ELSE NULL END)"
        )
    };
    let rt = rarity_threshold.max(1);
    Some(match field {
        "first_seen" | "prevalence_first_seen" => rarest("first_seen"),
        "last_seen" | "prevalence_last_seen" => rarest("last_seen"),
        "total_occurrences" => rarest("total_occurrences"),
        "host_count" => format!("(CASE WHEN {LEAST} >= 9999 THEN NULL ELSE {LEAST} END)"),
        "is_rare" => format!("(CASE WHEN {LEAST} < 9999 THEN {LEAST} < {rt} ELSE false END)"),
        "prevalence_score" => format!(
            "(CASE WHEN {m} >= 9999 THEN 0 WHEN {m} = 0 THEN 0 WHEN {m} < {t} THEN toUInt8(floor(0.5 + least(toFloat64({m}) / {t} * 20, 20))) WHEN {m} < {t} * 2 THEN toUInt8(floor(0.5 + 20 + (toFloat64({m}) - {t}) / {t} * 30)) WHEN {m} < {t} * 10 THEN toUInt8(floor(0.5 + 50 + (toFloat64({m}) - {t} * 2) / ({t} * 8) * 30)) ELSE toUInt8(floor(0.5 + 80 + least((toFloat64({m}) - {t} * 10) / ({t} * 90) * 20, 20))) END)",
            m = LEAST,
            t = rt,
        ),
        "prevalence_type" => rarest_pick("'domain'", "'ip'", "'hash'"),
        "prevalence_artifact" => rarest_pick("l._domain_lookup", "l._ip_lookup", "l._hash_lookup"),
        _ => return None,
    })
}

/// NAN-5565: what a run whose rescue was cut at the key-byte cap reports.
pub(crate) fn prevalence_rescue_partial_message(dropped: usize) -> String {
    format!(
        "prevalence rescue left out {dropped} dict-blind artifact(s) (the least rare) to stay within the {} MiB inlined-key cap / {} MiB query-size ceiling; they were not evaluated",
        super::prevalence_processing::PREVALENCE_RESCUE_KEY_BYTE_CAP / (1024 * 1024),
        crate::search::execution::clickhouse_executor::MAX_QUERY_SIZE_CEILING / (1024 * 1024),
    )
}

/// NAN-5565: render the pushdown so its text fits `ceiling` (the executor's
/// `max_query_size` ceiling, less the headroom it adds). While it does not,
/// halve the rescue's key bytes, dropping the least-rare artifacts (counted in
/// `rescue.dropped`), and render again. A rescue-free query that still does
/// not fit is returned as is: ClickHouse refuses it with code 62, which is
/// classified as a size failure, so it fails loudly rather than silently.
pub(crate) fn render_within_query_size_ceiling<F>(
    rescue: &mut PrevalenceRescue,
    ceiling: usize,
    mut render: F,
) -> Result<(String, usize, bool), SearchError>
where
    F: FnMut(&PrevalenceRescue) -> Result<(String, usize, bool), SearchError>,
{
    loop {
        let rendered = render(rescue)?;
        let fits = rendered.0.len()
            + crate::search::execution::clickhouse_executor::MAX_QUERY_SIZE_HEADROOM
            <= ceiling;
        if fits || rescue.is_empty() {
            return Ok(rendered);
        }
        let target = rescue.key_bytes() / 2;
        if rescue.cap_key_bytes(target) == 0 {
            // Nothing left to drop below the target: drop everything.
            rescue.dropped += rescue.len();
            rescue.hashes.clear();
            rescue.domains.clear();
            rescue.ips.clear();
        }
    }
}

/// NAN-5565: make a rescue that left artifacts out loud: WARN, metric, and a
/// PARTIAL note the detection scheduler records on the rule run. (The search
/// response carries a `PREVALENCE_RESCUE_PARTIAL` warning too.)
pub(crate) fn report_partial_rescue(rescue: &PrevalenceRescue) {
    if rescue.dropped == 0 {
        return;
    }
    tracing::warn!(
        dropped = rescue.dropped,
        kept = rescue.len(),
        "Prevalence rescue left out its least-rare dict-blind artifacts; this run evaluated only part of its input (PARTIAL)"
    );
    metrics::counter!("nanosiem_prevalence_rescue_dropped_artifacts_total")
        .increment(rescue.dropped as u64);
    crate::search::partial_run::note(prevalence_rescue_partial_message(rescue.dropped));
}

/// The base scan's time-bounded WHERE clause in generated prevalence SQL, up to
/// 500 bytes of it for the debug log, or `None` when the SQL has none.
///
/// NAN-5824: the pushdown emits that WHERE mid-line inside the `raw_logs` CTE
/// (`FROM ocsf_logs WHERE timestamp >= …`), so the old newline-prefixed
/// `"\nWHERE "` lookup never matched and warned on every prevalence search.
/// This looks only at the base scan (the `raw_logs` CTE, before
/// `logs_with_keys AS (`), outside string literals, for the `WHERE` keyword
/// followed by the `timestamp` column itself (not `timestamp_ms`), so a
/// later filter or a search term cannot stand in for a missing bound.
fn base_scan_time_where(sql: &str) -> Option<&str> {
    let scan_end = sql.find("logs_with_keys AS (").unwrap_or(sql.len());
    let bytes = sql.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0;
    let mut start = None;
    while i < scan_end {
        match bytes[i] {
            // Skip a '…' literal: '' and \' are escaped quotes in ClickHouse.
            b'\'' => {
                i += 1;
                while i < scan_end {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'\'' if bytes.get(i + 1) == Some(&b'\'') => i += 2,
                        b'\'' => break,
                        _ => i += 1,
                    }
                }
                i += 1;
            }
            b'W' | b'w'
                if bytes.len() >= i + 5
                    && bytes[i..i + 5].eq_ignore_ascii_case(b"WHERE")
                    && i > 0
                    && bytes[i - 1].is_ascii_whitespace()
                    && bytes.get(i + 5).is_some_and(u8::is_ascii_whitespace) =>
            {
                let rest = sql[i + 5..].trim_start();
                let column = rest.get(..9).is_some_and(|c| c.eq_ignore_ascii_case("timestamp"));
                if column && !rest.as_bytes().get(9).copied().is_some_and(is_word) {
                    start = Some(i);
                    break;
                }
                i += 5;
            }
            _ => i += 1,
        }
    }
    let start = start?;
    let mut end = sql.len().min(start + 500);
    while !sql.is_char_boundary(end) {
        end -= 1;
    }
    Some(&sql[start..end])
}

#[cfg(test)]
mod base_scan_where_tests {
    use super::base_scan_time_where;
    use crate::auth::ScopeSet;
    use crate::search::service::npl_golden_corpus_tests::sql_only_service;
    use crate::search::TimeRangeInput;

    fn range() -> TimeRangeInput {
        TimeRangeInput::new(
            chrono::DateTime::parse_from_rfc3339("2026-11-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2026-11-02T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
    }

    /// NAN-5824: the e2e searches that logged the false warning all render a
    /// time-bounded base scan, under both schemas.
    #[tokio::test]
    async fn prevalence_pushdown_sql_has_a_time_bounded_where() {
        for schema in ["ocsf", "udm"] {
            let svc = sql_only_service(schema);
            for q in [
                r#"source_type="deep_proc" "rare-é.exe" | prevalence enrich=true"#,
                r#"source_type="deep_dns" "c2.badexample.net" | prevalence enrich=true"#,
                r#"source_type="deep_proc" | prevalence enrich=true | head 50"#,
                r#"source_type="deep_proc" | prevalence enrich=true window=24h | head 50"#,
                r#"* | prevalence enrich=true | where host_count < 3"#,
            ] {
                let sql = svc
                    .explain(q, &range(), false, None, &ScopeSet::unrestricted())
                    .await
                    .unwrap_or_else(|e| panic!("{schema} {q}: {e}"));
                assert!(sql.contains("prevalence_dict"), "{schema} {q}: not a pushdown:\n{sql}");
                assert!(!sql.to_ascii_uppercase().contains("PREWHERE"), "{schema} {q}: {sql}");
                let clause = base_scan_time_where(&sql)
                    .unwrap_or_else(|| panic!("{schema} {q}: no time-bounded WHERE:\n{sql}"));
                assert!(clause.contains("timestamp <"), "{schema} {q}: {clause}");
            }
        }
    }

    #[test]
    fn detects_only_a_time_bounded_where_keyword() {
        assert!(base_scan_time_where("SELECT * FROM logs WHERE timestamp >= 1").is_some());
        assert!(base_scan_time_where("SELECT *\nFROM logs\nWHERE timestamp >= 1").is_some());
        assert!(base_scan_time_where("SELECT * FROM logs").is_none());
        assert!(base_scan_time_where("SELECT * FROM logs WHERE user = 'x'").is_none());
        assert!(base_scan_time_where("SELECT nowhere_timestamp FROM logs").is_none());
        // The 500-byte debug excerpt never splits a multibyte character: the
        // 31-byte ASCII prefix before the 2-byte 'é's puts byte 500 inside
        // one, so the excerpt must back off to 499 (the old slice panicked).
        let sql = format!("SELECT 1 FROM logs WHERE timestamp >= 1 AND mm = '{}'", "é".repeat(400));
        let clause = base_scan_time_where(&sql).unwrap();
        assert_eq!("WHERE timestamp >= 1 AND mm = '".len(), 31);
        assert_eq!(clause.len(), 499);
        assert!(clause.starts_with("WHERE timestamp"));
    }

    /// Review cases: a column that only starts with `timestamp`, a search term
    /// quoting the shape, or a WHERE after the base scan is not the bound.
    #[test]
    fn only_the_base_scan_time_bound_counts() {
        assert!(base_scan_time_where("SELECT * FROM logs WHERE timestamp_ms >= 1").is_none());
        assert!(base_scan_time_where("SELECT * FROM logs WHERE timestamped = 1").is_none());
        assert!(base_scan_time_where(
            "SELECT * FROM logs WHERE lower(message) = 'x WHERE timestamp >= 1'"
        )
        .is_none());
        assert!(base_scan_time_where("SELECT * FROM logs WHERE m = 'it''s WHERE timestamp >= 1'").is_none());
        assert!(base_scan_time_where("SELECT * FROM logs WHERE m = 'a\\' WHERE timestamp >= 1'").is_none());
        let pushdown = |raw: &str| {
            format!("WITH raw_logs AS (\n    SELECT * FROM ocsf_logs {raw}\n),\nlogs_with_keys AS (\n    SELECT * FROM raw_logs WHERE timestamp >= 1\n)\nSELECT * FROM logs_with_keys")
        };
        assert!(base_scan_time_where(&pushdown("WHERE user = 'a'")).is_none());
        assert!(base_scan_time_where(&pushdown("WHERE timestamp >= 1 AND timestamp < 2")).is_some());
        assert!(base_scan_time_where("SELECT * FROM logs WHERE timestamp>=1").is_some());
        assert!(base_scan_time_where("SELECT * FROM logs\n  where TIMESTAMP between 1 and 2").is_some());
        // A multibyte character right after a 'W' is not sliced into.
        assert!(base_scan_time_where("SELECT 'é' AS Wé FROM logs WHERE timestamp >= 1").is_some());
    }
}

