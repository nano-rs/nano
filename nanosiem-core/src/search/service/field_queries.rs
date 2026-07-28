// SPDX-License-Identifier: AGPL-3.0-or-later

use super::lateral::source_scope_sql_predicate;
use super::*;
use crate::auth::ScopeSet;
use crate::query::escape_identifier;
use crate::search::query_processing::enforce_source_scope;
use crate::sql_hygiene::escape_sql_string;
use std::collections::BTreeSet;
// `MATERIALIZED_COLUMNS` is only referenced by the unit tests below (the UDM
// materialized set passed to `build_fetch_log_sql`); production callers pass the
// active profile's columns. Scoped to test builds to avoid an unused-import warning.
#[cfg(test)]
use crate::query::MATERIALIZED_COLUMNS;

impl SearchService {
    /// Get field statistics for a query, gated by the admission controller
    /// (NAN-1427).
    ///
    /// The field-stats companion is the heaviest query a search fans out to
    /// (measured 8.4x the data query's read bytes for the full ~90-column
    /// set), and the `/api/search/field-stats` endpoint fires after every
    /// Search-page search — previously with no admission permit, no query_id,
    /// and no per-priority settings. This wrapper:
    ///
    /// 1. Acquires an admission permit (N analysts no longer means N
    ///    concurrent unbounded all-column scans),
    /// 2. Applies the priority's `ClickHouseQuerySettings`,
    /// 3. Runs the stats query under the derived `{request_id}-fstats` id so
    ///    `DELETE /api/search/{request_id}` cancels it (NAN-1428).
    pub async fn get_field_stats_with_admission(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        requested_columns: Option<&[String]>,
        request_id: Option<&str>,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        dataset: Option<&str>,
        scope: &ScopeSet,
    ) -> Result<Vec<FieldInfo>, SearchError> {
        let derived_qid = request_id.map(|r| format!("{r}-fstats"));

        // No controller wired up → no gating, run directly (tests,
        // single-tenant deployments) — mirrors `search_with_admission`.
        let Some(controller) = self.admission_controller.clone() else {
            return self
                .get_field_stats_for_query(
                    query,
                    time_range,
                    requested_columns,
                    derived_qid.as_deref(),
                    dataset,
                    scope,
                )
                .await;
        };

        let job_id = uuid::Uuid::now_v7().to_string();
        let _permit = controller
            .acquire(&job_id, user_id, priority)
            .await
            .map_err(|e| SearchError::AdmissionDenied(e.to_string()))?;

        let mut service = self.clone();
        service.active_ch_settings = Some(priority.to_ch_settings());
        // _permit drops at end of scope, freeing the slot.
        service
            .get_field_stats_for_query(
                query,
                time_range,
                requested_columns,
                derived_qid.as_deref(),
                dataset,
                scope,
            )
            .await
    }

    /// Get field statistics for a query (async, separate from main search)
    ///
    /// This endpoint is designed to be called separately from the main search,
    /// allowing the UI to display search results immediately while field stats
    /// load in the background. Uses topK + uniq for efficient cardinality.
    ///
    /// `requested_columns` (NAN-1427) restricts the stat'd column set: the
    /// companion's read bytes scale with the number of columns aggregated
    /// (topK+uniq per column), so computing stats over only the columns the
    /// caller actually renders is the effective I/O lever (measured 50x on
    /// the audit dataset). Requested names are intersected with the live
    /// table inventory — unknown names are dropped, and an empty intersection
    /// falls back to the full inventory so a stale client column list cannot
    /// blank the field panel. `None` keeps today's full-inventory behavior.
    pub async fn get_field_stats_for_query(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        requested_columns: Option<&[String]>,
        query_id: Option<&str>,
        dataset: Option<&str>,
        scope: &ScopeSet,
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

        // NAN-1799: inject the caller's source-scope exclusion before the
        // parse — the companion aggregates over the base search's WHERE, so
        // an ungated text here would leak denied sources' values into the
        // field panel. Empty deny-set → text unchanged.
        let query = enforce_source_scope(query, scope.deny_set())?;

        // Parse and validate the query
        let parsed_query = parse_query(&query).map_err(|e| convert_parse_error(e))?;

        // Extract just the base search expression (strip pipeline commands)
        let base_query = extract_base_search(&parsed_query);

        // Build time range
        let tr = TimeRange::new(time_range.start, time_range.end);

        // Generate base SQL for the query, retargeted to the per-query dataset's
        // OTLP table (NAN-1559) — without this the spans/metrics base SQL was
        // generated against `logs` and the companion enumerated UDM columns,
        // producing ClickHouse 47 `Unknown expression identifier`. Logs unchanged.
        let base_sql = self
            .dataset_generator(dataset, &query, scope.deny_set())
            .await
            .generate(&base_query, &tr)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Enumerate the columns of the per-query DATASET's table, not a hardcoded
        // `logs`. `system.columns` reflects the underlying local MergeTree, so
        // pass the bare local table name (UDM `logs` / OCSF `ocsf_logs` /
        // `otel_spans` / `otel_metrics`) — never the `_distributed` read alias
        // (NAN-1241/NAN-1559).
        let profile = self.dataset_profile(dataset);
        // NAN-1798 P2: the risk dataset's base is a DERIVED subquery — there is
        // no physical table to introspect, and enumerating the underlying
        // `logs` inventory would wrap UDM columns around the 15-column entity
        // grain (guaranteed CH 47 per column). Its column universe IS the
        // derived projection.
        let columns = if profile.id() == crate::schema::SchemaId::Risk {
            Self::field_stats_fallback_columns(dataset)
        } else {
            // Enumerate the columns of the per-query DATASET's table, not a
            // hardcoded `logs`. `system.columns` reflects the underlying local
            // MergeTree, so pass the bare local table name (UDM `logs` / OCSF
            // `ocsf_logs` / `otel_spans` / `otel_metrics`) — never the
            // `_distributed` read alias (NAN-1241/NAN-1559). The profile's
            // materialized re-add list scopes the inventory to columns
            // resolvable inside a CTE wrap and keeps internal bookkeeping
            // (e.g. OCSF `event_bytes`) out of the field panel (NAN-1397).
            let logs_table = crate::schema::logs_table_for(profile.id());
            ch_executor
                .get_table_columns(
                    logs_table,
                    profile.materialized_columns(),
                    profile.default_view_renames(),
                )
                .await
                .unwrap_or_else(|e| {
                    // NAN-1559: dataset-correct fallback — a UDM list here over an
                    // `otel_spans`/`otel_metrics` base would re-trigger CH 47.
                    warn!(
                        "Failed to get table columns for field stats, using dataset defaults: {}",
                        e
                    );
                    Self::field_stats_fallback_columns(dataset)
                })
        };

        // NAN-1427: reduce the column set to what the caller requested
        // (intersected with the live inventory). Falls back to the full
        // inventory when nothing is requested or nothing intersects.
        let inventory_len = columns.len();
        let columns = select_field_stats_columns(columns, requested_columns);
        if columns.len() < inventory_len {
            info!(
                "Field stats column set reduced to {} of {} inventory columns",
                columns.len(),
                inventory_len
            );
        }

        // Build and execute field stats SQL (topK + uniq for each column).
        // NAN-1506: bound the scan to FIELD_STATS_ROW_CAP rows. topK/uniq over
        // many columns is a full-window scan otherwise (12.6s for 20 cols / 24h /
        // 22M rows on Saturn; timeout for the full inventory). Tight windows
        // (≤ cap matching rows) stay exact; large windows become a fast
        // PK-order sample. Per-field drill-in stays exact + unbounded.
        //
        // NAN-1591: a requested column can exist in the local-table inventory yet
        // be unresolvable in the query's actual target — an ALIAS column
        // (computed, not on the Distributed wrapper) or a column that drifted off
        // the wrapper (span_id/tags/trace_id before a cluster re-sync). The field
        // panel is best-effort, so a single bad column must NOT 400 the whole
        // request: drop the offender ClickHouse names and retry, rather than
        // failing every other column's stats. Bounded by the column count.
        let mut columns = columns;
        loop {
            let field_stats_sql = ClickHouseExecutor::build_field_stats_sql(
                &base_sql,
                None,
                &columns,
                Some(FIELD_STATS_ROW_CAP),
            );
            info!(
                "Executing async field stats query for {} columns",
                columns.len()
            );
            match ch_executor
                .execute_field_stats_query(
                    &field_stats_sql,
                    &columns,
                    query_id,
                    self.active_ch_settings.as_ref(),
                )
                .await
            {
                Ok(stats) => {
                    info!("Async field stats returned {} fields with data", stats.len());
                    return Ok(stats);
                }
                Err(SearchError::FieldNotFound { field, .. })
                    if columns.iter().any(|c| c == &field) =>
                {
                    warn!(
                        "Field-stats: column '{}' not resolvable in the query target \
                         (alias/schema drift); dropping it and retrying",
                        field
                    );
                    columns.retain(|c| c != &field);
                    if columns.is_empty() {
                        return Ok(Vec::new());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Get top values for a single field (on-demand, Kibana-style).
    /// This is much more efficient than querying all fields at once.
    #[instrument(skip(self, scope), fields(field = %field, query = %query))]
    pub async fn get_field_values(
        &self,
        field: &str,
        query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
        dataset: Option<&str>,
        scope: &ScopeSet,
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

        // NAN-1799: gate the drill-in the same way as the search it belongs
        // to — inject the scope exclusion into the text before the parse.
        let query = enforce_source_scope(query, scope.deny_set())?;

        // Parse and validate the query
        let parsed_query = parse_query(&query).map_err(|e| convert_parse_error(e))?;

        // Extract just the base search expression, stripping ALL pipeline commands.
        // Stats/table/fields/eval all restrict or reshape columns, making field-values
        // fail with UNKNOWN_IDENTIFIER. The base search has the key filters already.
        let field_values_query = extract_base_search(&parsed_query);

        // Build time range
        let tr = TimeRange::new(time_range.start, time_range.end);

        // Per-query dataset generator (NAN-1559): retargets the base SQL to
        // `otel_spans`/`otel_metrics` AND resolves the field-access expression
        // against the dataset profile (e.g. spans `attributes['k']` MapKey), so a
        // sidebar field drill-in on a spans/metrics search reads the right table
        // and column. Logs unchanged.
        let generator = self
            .dataset_generator(dataset, &query, scope.deny_set())
            .await;

        // Generate base SQL for the query
        let base_sql = generator
            .generate(&field_values_query, &tr)
            .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

        // Resolve the value returned to the endpoint through the per-query
        // dataset profile. In addition to normal promoted/tail access
        // (NAN-1241/NAN-1559), NAN-2149 makes this the shared display seam for
        // both field-values endpoints: OCSF class-split concepts group on their
        // indexed unified value, and numeric enums display their human label
        // column/table. UDM has neither feature, so its expression — and thus its
        // complete SQL — stays byte-identical.
        let field_expr = generator.field_values_display_expr(field);

        // Build simple GROUP BY query for this single field
        let field_values_sql = ch_executor.build_field_values_sql(&base_sql, &field_expr, limit);
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
    /// `scope` (NAN-1799, replaces the old `exclude_audit: bool`): every
    /// source_type in the caller's deny-set is filtered at the SQL layer so a
    /// scoped caller cannot retrieve a denied row by direct id lookup. The
    /// handler unions `audit` into the deny-set for callers without
    /// `audit:view`, preserving the NAN-694 behavior byte-identically
    /// (`lower(source_type) != 'audit'`).
    ///
    /// NAN-1032: callers should pass `source_type` whenever known so the query can
    /// use the `(source_type, timestamp, ...)` PK index for a tight range read.
    /// Without it, S3-backed historical lookups scan every source_type's marks within
    /// the time window — measured 12–60s on cold cache vs <1s with the filter.
    /// Skips the parallel `count(*)` companion that `execute_clickhouse_sql` adds:
    /// the response carries no count, the count is bounded to {0,1} by `id` + LIMIT 1,
    /// and on S3 it doubles the I/O.
    #[instrument(skip(self, scope))]
    pub async fn fetch_log_by_id(
        &self,
        id: &str,
        time_range: Option<&TimeRangeInput>,
        source_type: Option<&str>,
        scope: &ScopeSet,
    ) -> Result<Option<serde_json::Value>, SearchError> {
        // Profile-aware (NAN-1241): resolve the active schema's logs table
        // (`ocsf_logs` under OCSF) and re-add that profile's materialized columns,
        // not the UDM set. UDM behavior is unchanged (same key, same columns).
        let table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        // NAN-1443: `unmapped` (the OCSF spill) is a MATERIALIZED column excluded
        // from `SELECT *`, and it is NOT in the manifest-derived materialized
        // re-add list — so the row-expand inspector would miss spill fields. The
        // full OCSF `event` is EPHEMERAL, so the promoted columns + `message` +
        // `unmapped` ARE the complete stored record; append `unmapped` for the
        // OCSF row-expand fetch only. It is intentionally NOT added to
        // `materialized_columns()` (which also drives the search-results CTE
        // re-add — every result row would then carry the spill blob).
        let mut mat_cols: Vec<&str> = self.active_profile.materialized_columns().to_vec();
        if self.active_profile.id() == crate::schema::SchemaId::Ocsf {
            mat_cols.push("unmapped");
        }
        let sql = build_fetch_log_sql(
            &table,
            id,
            time_range,
            source_type,
            scope.deny_set(),
            &mat_cols,
            self.active_profile.default_view_renames(),
        );

        debug!("Fetching log by ID: {}", sql);

        // Execute query
        let results = {
            let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
                SearchError::DatabaseError(sqlx::Error::Configuration(
                    "ClickHouse client not configured".into(),
                ))
            })?;
            ch_executor.execute_sql_to_json(&sql).await?
        };

        Ok(results.into_iter().next())
    }

    /// Query logs by a specific UDM field value
    /// This searches across all log sources that have the field mapped
    ///
    /// NAN-1799: the hand-built SQL ANDs the caller's source-scope deny-set
    /// into the WHERE (see `build_udm_field_query`).
    #[instrument(skip(self, scope))]
    pub async fn query_udm_field(
        &self,
        request: UdmFieldQueryRequest,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        // Validate time range
        request.time_range.validate()?;

        // Build the SQL query for the UDM field
        let sql = self.build_udm_field_query(&request, scope.deny_set())?;

        debug!("Generated UDM field query SQL: {}", sql);

        // Apply limit and offset
        let limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        let offset = request.offset.unwrap_or(0);

        // Execute the query
        let (results, total_count) = self
            .execute_clickhouse_sql(&sql, limit, offset, false)
            .await?;

        // Calculate field statistics
        let mut stats = FieldStatistics::new();
        for row in &results {
            stats.process_row(row);
        }
        let fields = stats.get_field_info(self.config.top_values_count);

        // Generate histogram for UDM field query.
        // NAN-1429: degrade to histogram:null on failure instead of failing
        // the whole query (matches the piped-query path's behavior).
        //
        // NAN-1799: `generate_histogram_for_time_range` counts EVERY source in
        // the window (no per-source filter), so for a scoped caller it would
        // leak denied sources' event volumes into the timeline. Fail closed to
        // no histogram for restricted callers; unrestricted behavior unchanged.
        let histogram = if scope.is_restricted() {
            None
        } else {
            match self
                .generate_histogram_for_time_range(&request.time_range)
                .await
            {
                Ok(h) => Some(h),
                Err(e) => {
                    tracing::warn!("UDM field query histogram failed: {}", e);
                    None
                }
            }
        };

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
            histogram,
            warnings: None,
            cost_score: None,
            display_type: Some(DisplayType::Events),
            column_order: None, // UDM field queries don't have column order
        })
    }

    /// Get ext field names that exist in the data, scoped to the active search.
    ///
    /// NAN-1510: when `query` + `time_range` are given, enumeration is scoped to
    /// the SAME predicate (time bounds + base filter) the per-field value fetch
    /// (`get_field_values`) uses — so every key listed has values an expand can
    /// actually return. Previously enumeration was time-window-only (NAN-1505),
    /// so a filtered search listed ext keys from other source types in the window
    /// that then expanded empty ("Values loaded on demand", no entries).
    /// Fallbacks: time-only when no query (historical window), `now()-3h` when
    /// neither (the context-free syntax-highlighter path).
    /// `scope` (NAN-1799): the deny-set exclusion is ANDed into EVERY branch of
    /// the scan predicate below — including the time-only and `now()-3h`
    /// fallbacks, which previously applied NO source gate at all, leaking
    /// audit/denied sources' ext keys to any caller.
    pub async fn get_ext_field_names(
        &self,
        query: Option<&str>,
        time_range: Option<&TimeRangeInput>,
        scope: &ScopeSet,
    ) -> Result<Vec<String>, SearchError> {
        if self.backend != SearchBackend::ClickHouse {
            return Ok(Vec::new());
        }

        let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
            SearchError::DatabaseError(sqlx::Error::Configuration(
                "ClickHouse executor not available".into(),
            ))
        })?;

        // NAN-1241/1443: enumerate the active table's dynamic-JSON tail column —
        // `ext` under UDM, the `unmapped` spill under OCSF (was the full `event`,
        // now EPHEMERAL). Promoted/known fields are surfaced from the schema
        // separately; this discovers the spill-only tail leaf paths.
        let profile = self.active_profile.as_ref();
        let table = self.table_names.read(Self::logs_table_key(profile));
        // The OCSF spill is still nested, so the enumerator returns full leaf
        // paths rather than collapsing to the top-level segment (which is correct
        // for UDM's effectively-flat `ext`).
        let is_ocsf = profile.id() == crate::schema::SchemaId::Ocsf;
        let json_col = profile.json_tail_column();

        let time_only = |tr: &TimeRangeInput| {
            format!(
                "timestamp BETWEEN '{}' AND '{}'",
                crate::sql_hygiene::format_ch_bound_micros(&tr.start),
                crate::sql_hygiene::format_ch_bound_micros(&tr.end),
            )
        };
        // Build the scan predicate.
        //
        // The query path builds it STRUCTURALLY — `time_only` + the base search's
        // generated filter (`generate_search_expr`) — i.e. exactly what the data
        // query and the per-field value fetch emit as their WHERE. We deliberately
        // do NOT slice the WHERE out of a fully-generated SQL string: that scan
        // isn't quote/paren aware, so a literal containing `ORDER BY`/`LIMIT` or a
        // subsearch's own inner `LIMIT` would truncate the predicate into malformed
        // SQL (codex review, NAN-1510). A provided-but-unparseable/ungenerable query
        // returns an empty list rather than broadening to the time-only window
        // (which would re-list the cross-source-type keys this fix removes); a query
        // that already ran for the search will parse + generate here too.
        let where_predicate = match (query.map(str::trim).filter(|q| !q.is_empty()), time_range) {
            (Some(q), Some(tr)) => {
                let Ok(parsed) = parse_query(q) else {
                    return Ok(Vec::new());
                };
                match extract_base_search(&parsed) {
                    Query::Search(expr) => match self.ch_sql_generator.generate_search_expr(&expr) {
                        Ok(filter) => format!("{} AND ({})", time_only(tr), filter),
                        Err(_) => return Ok(Vec::new()),
                    },
                    // extract_base_search always yields Query::Search; defensively
                    // fall back to the window scope rather than erroring.
                    _ => time_only(tr),
                }
            }
            (_, Some(tr)) => time_only(tr),
            _ => "timestamp >= now() - INTERVAL 3 HOUR".to_string(),
        };

        // NAN-1799: append the caller's source-scope exclusion to whichever
        // branch built the predicate (query-scoped, time-only, or the 3h
        // fallback). Empty deny-set → predicate unchanged (byte-identical).
        let where_predicate =
            match source_scope_sql_predicate("source_type", scope.deny_set()) {
                Some(pred) => format!("{where_predicate} AND {pred}"),
                None => where_predicate,
            };

        ch_executor
            .get_ext_field_names(&table, json_col, is_ocsf, &where_predicate)
            .await
    }

    /// Get top values for a specific UDM field
    ///
    /// NAN-2146: top-values for a UDM field over the time window.
    ///
    /// Logs live only in ClickHouse; the PG-only log fallback was removed by
    /// NAN-800, so the previous hand-built `FROM logs` PostgreSQL query 500'd
    /// (`relation "logs" does not exist`) for every legitimate caller. Delegate
    /// to the canonical ClickHouse field-values path ([`get_field_values`]) with
    /// a match-all (`*`) query. That path resolves the field to its physical
    /// column via the active schema profile, applies the NAN-1799 source-scope
    /// deny-set, excludes empty ClickHouse defaults, and applies the top-N limit
    /// inside the aggregate — none of which the removed PG query did. UDM is
    /// exact; NAN-2149's shared display expression makes OCSF class-split concepts
    /// and enum labels exact through this same delegation as well.
    #[instrument(skip(self, scope))]
    pub async fn get_udm_field_values(
        &self,
        field: UdmField,
        time_range: &TimeRangeInput,
        limit: Option<usize>,
        scope: &ScopeSet,
    ) -> Result<Vec<(String, u64)>, SearchError> {
        time_range.validate()?;
        let limit = limit.unwrap_or(self.config.top_values_count);

        let values = self
            .get_field_values(field.column_name(), "*", time_range, limit, None, scope)
            .await?;

        Ok(values.into_iter().map(|v| (v.value, v.count)).collect())
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
    ///
    /// `deny_set` (NAN-1799): the caller's source-scope deny-set, ANDed into
    /// the WHERE. Empty set emits nothing (byte-identical to the old SQL).
    fn build_udm_field_query(
        &self,
        request: &UdmFieldQueryRequest,
        deny_set: &BTreeSet<String>,
    ) -> Result<String, SearchError> {
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

        // NAN-1799: the caller's source-scope exclusion. Empty → "" (SQL
        // byte-identical to the pre-scoping form).
        let scope_clause = source_scope_sql_predicate("source_type", deny_set)
            .map(|pred| format!("\n              AND {pred}"))
            .unwrap_or_default();

        let sql = format!(
            r#"
            SELECT * FROM logs
            WHERE timestamp BETWEEN '{}' AND '{}'
              AND {}{}
            ORDER BY timestamp DESC
            "#,
            crate::sql_hygiene::format_ch_bound_micros(&request.time_range.start),
            crate::sql_hygiene::format_ch_bound_micros(&request.time_range.end),
            value_clause,
            scope_clause
        );

        Ok(sql)
    }
}

/// Select the column set for a field-stats query (NAN-1427).
///
/// - `requested = None` → the full table inventory (today's behavior — API
///   callers that don't send `columns` are unchanged).
/// - `requested = Some(set)` → the inventory restricted to the requested
///   names (exact match; inventory order preserved). Unknown names (ext-JSON
///   keys, typos) are dropped — only enumerated table columns ever reach the
///   generated SQL, so a client cannot inject identifiers.
/// - An empty intersection falls back to the FULL inventory: a stale client
///   column list must not silently blank the field panel.
fn select_field_stats_columns(
    inventory: Vec<String>,
    requested: Option<&[String]>,
) -> Vec<String> {
    let Some(requested) = requested else {
        return inventory;
    };
    let requested_set: std::collections::HashSet<&str> =
        requested.iter().map(|s| s.as_str()).collect();
    let reduced: Vec<String> = inventory
        .iter()
        .filter(|c| requested_set.contains(c.as_str()))
        .cloned()
        .collect();
    if reduced.is_empty() {
        warn!(
            "Requested field-stats columns ({}) matched no table columns; \
             falling back to full inventory",
            requested.len()
        );
        inventory
    } else {
        reduced
    }
}

/// Build the SQL for `fetch_log_by_id`.
///
/// Extracted into a free function so the audit-exclusion behavior is unit-testable
/// without a live ClickHouse/Postgres backend (NAN-694).
///
/// `deny_set` (NAN-1799, replaces the old `exclude_audit: bool`): the caller's
/// full source-scope deny-set, rendered via [`source_scope_sql_predicate`].
/// A `{"audit"}` set emits the legacy ` AND lower(source_type) != 'audit'`
/// byte-identically; an empty set emits nothing.
///
/// When `source_type` is provided it is added to the WHERE clause so the
/// `(source_type, timestamp, ...)` PK index can do a tight range read instead
/// of scanning every source_type's marks within the timestamp window (NAN-1032).
///
/// `default_view_renames` is the active profile's `(column, alias)` rewrite list
/// (NAN-2208). ClickHouse's `SELECT *` drops ALIAS columns, so a bare `*` here
/// returned the *physical* `action` while search results — which project
/// `* EXCEPT (action), action AS event_type` — returned the canonical
/// `event_type`. The row-expand inspector merges both payloads, so the same
/// column surfaced under two different names in one view, and the field index
/// only ever showed the legacy one. Applying the same rewrite makes this fetch
/// agree with search. UDM passes `[("action", "event_type")]`; OCSF passes `[]`
/// and keeps a bare `*` (byte-identical to the previous behavior).
fn build_fetch_log_sql(
    table: &str,
    id: &str,
    time_range: Option<&TimeRangeInput>,
    source_type: Option<&str>,
    deny_set: &BTreeSet<String>,
    materialized_cols: &[&str],
    default_view_renames: &[(&str, &str)],
) -> String {
    let escaped_id = escape_sql_string(id);
    let audit_filter = source_scope_sql_predicate("source_type", deny_set)
        .map(|pred| format!(" AND {pred}"))
        .unwrap_or_default();
    let source_type_filter = source_type
        .map(|st| format!(" AND source_type = '{}'", escape_sql_string(st)))
        .unwrap_or_default();
    // ClickHouse's `SELECT *` excludes MATERIALIZED columns (enrichment, IOC,
    // prevalence, process-GUID, resolved-identity dict fills for UDM; the promoted
    // OCSF columns for OCSF). The row-expand UI relies on this fetch as its
    // full-fidelity source — table_view search results are field-pruned — so
    // without re-adding them the inspector shows no enrichment even though it's
    // stored. Mirrors build_select_clause's re-add off the active profile's
    // materialized-column source of truth (NAN-1147; OCSF profile-awareness
    // NAN-1241). UDM names are bare snake_case (escape is a no-op → byte-identical);
    // OCSF names are dotted (`src_endpoint.ip`) and MUST be quoted or ClickHouse
    // parses them as tuple/sub-column access.
    // Wildcard first: `* EXCEPT (action)` when the profile renames columns, so the
    // physical name does not also land in the row alongside its canonical alias
    // (mirrors `build_default_view_base`). Empty renames → bare `*`.
    let mut select_parts: Vec<String> = Vec::with_capacity(1 + materialized_cols.len());
    if default_view_renames.is_empty() {
        select_parts.push("*".to_string());
    } else {
        let except_cols = default_view_renames
            .iter()
            .map(|(col, _)| escape_identifier(col))
            .collect::<Vec<_>>()
            .join(", ");
        select_parts.push(format!("* EXCEPT ({})", except_cols));
        for (col, alias) in default_view_renames {
            select_parts.push(format!(
                "{} AS {}",
                escape_identifier(col),
                escape_identifier(alias)
            ));
        }
    }
    select_parts.extend(materialized_cols.iter().map(|c| escape_identifier(c)));
    let select = select_parts.join(", ");
    if let Some(tr) = time_range {
        format!(
            "SELECT {} FROM {} WHERE id = '{}'{}{} AND timestamp BETWEEN '{}' AND '{}' LIMIT 1",
            select,
            table,
            escaped_id,
            source_type_filter,
            audit_filter,
            crate::sql_hygiene::format_ch_bound_micros(&tr.start),
            crate::sql_hygiene::format_ch_bound_micros(&tr.end),
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

    /// The UDM profile's `default_view_renames` (NAN-2208). Kept as a literal
    /// rather than reaching for the profile so these stay pure SQL-shape tests;
    /// `udm_view_renames_match_the_profile` pins it to the real profile value.
    const UDM_VIEW_RENAMES: &[(&str, &str)] = &[("action", "event_type")];

    fn inv(cols: &[&str]) -> Vec<String> {
        cols.iter().map(|s| s.to_string()).collect()
    }

    /// Unrestricted caller — no source gate (the old `exclude_audit: false`).
    fn no_scope() -> BTreeSet<String> {
        BTreeSet::new()
    }

    /// The handler-composed deny-set for a caller without `audit:view`
    /// (the old `exclude_audit: true`).
    fn audit_scope() -> BTreeSet<String> {
        std::iter::once("audit".to_string()).collect()
    }

    fn field_values_sql(
        generator: &ClickHouseSqlGenerator,
        table: &str,
        field: &str,
    ) -> String {
        let executor = ClickHouseExecutor::new(clickhouse::Client::default());
        let base_sql = format!(
            "SELECT * FROM {table} ORDER BY timestamp DESC SETTINGS optimize_read_in_order=1"
        );
        executor.build_field_values_sql(
            &base_sql,
            &generator.field_values_display_expr(field),
            25,
        )
    }

    /// NAN-2149 endpoint-path snapshot: both POST /api/search/field-values and
    /// GET /api/fields/{name}/values reach this shared SQL builder. An OCSF UDM
    /// alias must aggregate the indexed class-spanning value, not `user.name`.
    #[test]
    fn ocsf_field_values_sql_groups_class_split_user_on_unified_value() {
        let generator = ClickHouseSqlGenerator::new().with_profile(std::sync::Arc::new(
            crate::schema::OcsfProfile::new(),
        ));
        assert_eq!(
            field_values_sql(&generator, "ocsf_logs", "user"),
            "SELECT toString(user_unified) as value, count() as cnt FROM \
             (SELECT * FROM ocsf_logs) AS _fv WHERE user_unified IS NOT NULL AND \
             toString(user_unified) != '' GROUP BY value ORDER BY cnt DESC LIMIT 25"
        );
    }

    /// NAN-2149 endpoint-path snapshot: class-scoped activity IDs group on the
    /// human sibling label. The already-native label spelling is identical.
    #[test]
    fn ocsf_field_values_sql_groups_event_type_and_activity_on_label() {
        let generator = ClickHouseSqlGenerator::new().with_profile(std::sync::Arc::new(
            crate::schema::OcsfProfile::new(),
        ));
        let expected = "SELECT toString(activity) as value, count() as cnt FROM \
                        (SELECT * FROM ocsf_logs) AS _fv WHERE activity IS NOT NULL AND \
                        toString(activity) != '' GROUP BY value ORDER BY cnt DESC LIMIT 25";
        assert_eq!(
            field_values_sql(&generator, "ocsf_logs", "event_type"),
            expected
        );
        assert_eq!(
            field_values_sql(&generator, "ocsf_logs", "activity"),
            expected
        );
    }

    /// NAN-2149 endpoint-path snapshot: a fixed numeric enum is decoded before
    /// projection, filtering, and grouping, so callers receive labels and counts
    /// are combined by the returned display value.
    #[test]
    fn ocsf_field_values_sql_groups_severity_ids_on_labels() {
        let generator = ClickHouseSqlGenerator::new().with_profile(std::sync::Arc::new(
            crate::schema::OcsfProfile::new(),
        ));
        let transform = "transform(severity_id, [0, 1, 2, 3, 4, 5, 6, 99], \
                         ['unknown', 'informational', 'low', 'medium', 'high', \
                         'critical', 'fatal', 'other'], toString(severity_id))";
        assert_eq!(
            field_values_sql(&generator, "ocsf_logs", "severity_id"),
            format!(
                "SELECT toString({transform}) as value, count() as cnt FROM \
                 (SELECT * FROM ocsf_logs) AS _fv WHERE {transform} IS NOT NULL AND \
                 toString({transform}) != '' GROUP BY value ORDER BY cnt DESC LIMIT 25"
            )
        );
    }

    /// NAN-2149 UDM parity snapshot: the shared display seam must not alter even
    /// one byte of the complete field-values aggregate under the default profile.
    #[test]
    fn udm_field_values_sql_remains_byte_identical() {
        assert_eq!(
            field_values_sql(&ClickHouseSqlGenerator::new(), "logs", "user"),
            "SELECT toString(\"user\") as value, count() as cnt FROM \
             (SELECT * FROM logs) AS _fv WHERE \"user\" IS NOT NULL AND \
             toString(\"user\") != '' GROUP BY value ORDER BY cnt DESC LIMIT 25"
        );
    }

    /// NAN-1427: requested-columns reduction — exact-match intersection with
    /// the live inventory, inventory order preserved.
    #[test]
    fn field_stats_columns_intersect_requested_with_inventory() {
        let inventory = inv(&["action", "dest_ip", "src_ip", "user"]);
        let requested = inv(&["user", "src_ip", "not_a_column"]);
        assert_eq!(
            select_field_stats_columns(inventory, Some(&requested)),
            inv(&["src_ip", "user"]),
        );
    }

    /// No requested set → full inventory (existing API callers unchanged).
    #[test]
    fn field_stats_columns_default_to_full_inventory() {
        let inventory = inv(&["action", "src_ip"]);
        assert_eq!(
            select_field_stats_columns(inventory.clone(), None),
            inventory
        );
    }

    /// A requested set matching nothing must NOT blank the field panel —
    /// fall back to the full inventory.
    #[test]
    fn field_stats_columns_empty_intersection_falls_back_to_full() {
        let inventory = inv(&["action", "src_ip"]);
        let requested = inv(&["ext_only_key", "typo_column"]);
        assert_eq!(
            select_field_stats_columns(inventory.clone(), Some(&requested)),
            inventory
        );
    }

    /// OCSF dotted column names intersect exactly (no normalization).
    #[test]
    fn field_stats_columns_dotted_ocsf_names_match_exactly() {
        let inventory = inv(&["class_uid", "src_endpoint.ip", "user.name"]);
        let requested = inv(&["src_endpoint.ip", "user.name"]);
        assert_eq!(
            select_field_stats_columns(inventory, Some(&requested)),
            inv(&["src_endpoint.ip", "user.name"]),
        );
    }

    #[test]
    fn fetch_log_sql_without_audit_exclusion_omits_source_type_filter() {
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, &no_scope(), MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
        assert!(
            sql.starts_with("SELECT * EXCEPT (action), action AS event_type, "),
            "must rewrite action->event_type and re-add materialized cols: {sql}"
        );
        assert!(
            sql.ends_with("FROM logs WHERE id = 'abc-123' LIMIT 1"),
            "{sql}"
        );
    }

    /// NAN-1620: backslash-bearing values embedded in a CH string literal must
    /// be escaped (`\` → `\\`), otherwise the literal is corrupted/broken. A
    /// Windows-path-style id and the source_type filter both go into `'…'`.
    #[test]
    fn fetch_log_sql_escapes_backslashes_in_string_literals() {
        let sql = build_fetch_log_sql(
            "logs",
            r"C:\Users\admin",
            None,
            Some(r"win\evtx"),
            &no_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
        assert!(
            sql.contains(r"WHERE id = 'C:\\Users\\admin'"),
            "id backslashes must be doubled: {sql}"
        );
        assert!(
            sql.contains(r"AND source_type = 'win\\evtx'"),
            "source_type backslashes must be doubled: {sql}"
        );
    }

    #[test]
    fn fetch_log_sql_reads_materialized_enrichment_columns() {
        // NAN-1147 regression: `SELECT *` excludes MATERIALIZED columns, so the
        // row-expand inspector showed no enrichment. The fetch must name them.
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, &no_scope(), MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
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
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, &audit_scope(), MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
        assert!(
            sql.starts_with("SELECT * EXCEPT (action), action AS event_type, "),
            "must rewrite action->event_type and re-add materialized cols: {sql}"
        );
        assert!(
            sql.ends_with(
                "FROM logs WHERE id = 'abc-123' AND lower(source_type) != 'audit' LIMIT 1"
            ),
            "{sql}"
        );
    }

    /// NAN-1799: a multi-source deny-set renders the negated IN form — a
    /// scoped caller cannot retrieve a denied row by direct id lookup.
    #[test]
    fn fetch_log_sql_with_multi_source_deny_set_renders_not_in() {
        let deny: BTreeSet<String> = ["audit", "windows_sysmon"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let sql =
            build_fetch_log_sql("logs", "abc-123", None, None, &deny, MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
        assert!(
            sql.ends_with(
                "FROM logs WHERE id = 'abc-123' AND lower(source_type) NOT IN \
                 ('audit', 'windows_sysmon') LIMIT 1"
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
        let sql = build_fetch_log_sql("logs", "abc-123", Some(&tr), None, &audit_scope(), MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
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
        let sql = build_fetch_log_sql("logs", "abc'; DROP--", None, None, &audit_scope(), MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
        assert!(
            sql.contains("WHERE id = 'abc''; DROP--'"),
            "id quotes not escaped: {sql}"
        );
    }

    #[test]
    fn fetch_log_sql_quotes_dotted_ocsf_materialized_columns() {
        // OCSF profile-awareness (NAN-1241): the fetch re-adds the active
        // profile's materialized columns, which for OCSF are dotted promoted
        // paths. They MUST be double-quoted or ClickHouse reads `src_endpoint.ip`
        // as tuple sub-column access. `WHERE id =` is unchanged — OCSF now has a
        // real `id` UUID column too.
        let ocsf_cols: &[&str] = &["src_endpoint.ip", "http_response.code", "class_uid"];
        let sql = build_fetch_log_sql("ocsf_logs", "abc-123", None, None, &no_scope(), ocsf_cols, &[]);
        assert!(
            sql.contains("\"src_endpoint.ip\""),
            "dotted col must be quoted: {sql}"
        );
        assert!(
            sql.contains("\"http_response.code\""),
            "dotted col must be quoted: {sql}"
        );
        // Bare names stay bare (no needless quoting).
        assert!(sql.contains(", class_uid"), "bare col stays bare: {sql}");
        assert!(
            sql.ends_with("FROM ocsf_logs WHERE id = 'abc-123' LIMIT 1"),
            "{sql}"
        );
    }

    #[test]
    fn fetch_log_sql_with_empty_materialized_cols_emits_bare_star() {
        // Defensive: a profile with no materialized columns must not produce the
        // dangling `SELECT *, ` (trailing comma → syntax error).
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, &no_scope(), &[], &[]);
        assert!(
            sql.starts_with("SELECT * FROM logs WHERE id = 'abc-123'"),
            "{sql}"
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
            &no_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
        // source_type goes immediately after the id predicate so the PK
        // (source_type, timestamp, ...) can do a tight range read on S3-backed
        // historical partitions instead of scanning every source_type's marks.
        assert!(
            sql.starts_with("SELECT * EXCEPT (action), action AS event_type, "),
            "must rewrite action->event_type and re-add materialized cols: {sql}"
        );
        assert!(
            sql.ends_with(
                "FROM logs WHERE id = 'abc-123' AND source_type = 'windows_sysmon' AND timestamp BETWEEN '2026-01-02 03:04:05.000000' AND '2026-01-02 03:04:07.000000' LIMIT 1"
            ),
            "{sql}"
        );
    }

    /// NAN-2208: the row-expand fetch must project the profile's canonical
    /// alias, not the physical column. Before this, search returned
    /// `event_type` and this fetch returned `action` for the same column — the
    /// inspector merges both payloads, so one column surfaced under two names.
    #[test]
    fn fetch_log_sql_projects_canonical_event_type_and_drops_physical_action() {
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            None,
            None,
            &no_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
        assert!(
            sql.starts_with("SELECT * EXCEPT (action), action AS event_type, "),
            "canonical alias must replace the physical column: {sql}"
        );
        // `action` must appear ONLY inside the EXCEPT and the alias expression —
        // never as a bare projected column that would duplicate `event_type`.
        let select_list = sql
            .strip_prefix("SELECT ")
            .and_then(|s| s.split(" FROM ").next())
            .expect("select list");
        assert!(
            !select_list.split(", ").any(|c| c.trim() == "action"),
            "physical `action` must not be projected alongside its alias: {sql}"
        );
    }

    /// The renamed projection must match what a bare search emits, or the two
    /// payloads disagree again the moment either side changes.
    #[test]
    fn fetch_log_sql_rename_shape_matches_default_view_base() {
        let sql = build_fetch_log_sql("logs", "abc-123", None, None, &no_scope(), &[], UDM_VIEW_RENAMES);
        assert_eq!(
            sql,
            "SELECT * EXCEPT (action), action AS event_type FROM logs WHERE id = 'abc-123' LIMIT 1",
            "must mirror build_default_view_base's `* EXCEPT (col), col AS alias`"
        );
    }

    /// OCSF has no `action` column — applying the UDM rewrite would reference a
    /// nonexistent column and fail every row-expand. Empty renames → bare `*`.
    #[test]
    fn fetch_log_sql_ocsf_no_renames_keeps_bare_star() {
        let ocsf_cols: &[&str] = &["src_endpoint.ip", "class_uid"];
        let sql = build_fetch_log_sql("ocsf_logs", "abc-123", None, None, &no_scope(), ocsf_cols, &[]);
        assert!(sql.starts_with("SELECT *, "), "{sql}");
        assert!(!sql.contains("EXCEPT"), "OCSF must not emit EXCEPT: {sql}");
        assert!(!sql.contains("event_type"), "OCSF must not emit UDM names: {sql}");
    }

    /// Pins the literal used above to the real UDM profile, so a profile change
    /// cannot silently drift away from what these tests assert.
    #[test]
    fn udm_view_renames_match_the_profile() {
        use crate::schema::SchemaProfile;
        let udm = crate::schema::UdmProfile::new();
        assert_eq!(udm.default_view_renames(), UDM_VIEW_RENAMES);
    }

    #[test]
    fn fetch_log_sql_escapes_single_quotes_in_source_type() {
        let sql =
            build_fetch_log_sql("logs", "abc-123", None, Some("evil'; DROP--"), &no_scope(), MATERIALIZED_COLUMNS, UDM_VIEW_RENAMES);
        assert!(
            sql.contains("source_type = 'evil''; DROP--'"),
            "source_type quotes not escaped: {sql}"
        );
    }
}
