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

/// The base the field sidebar plans its rollup decision on (NAN-3166): the
/// text the drill-in's searches plan on once `search` has injected the
/// caller's lake source-scope gate and NAN-3163 has removed it again for the
/// count rollups. For an empty deny set that is `base_query` itself; for a
/// strippable deny set (`{audit}`) it is `base_query` round-tripped; for a
/// deny set naming Unattributed the gate stays, so the decision matches the
/// gated scan those searches run instead of the rollup.
fn lake_field_values_planning_base(base_query: &str, deny_set: &BTreeSet<String>) -> String {
    let Ok(gated) = crate::search::query_processing::enforce_source_scope_with_field(
        base_query,
        deny_set,
        crate::search::query_processing::LAKE_SOURCE_FIELD,
    ) else {
        return base_query.to_string();
    };
    parse_query(&gated)
        .ok()
        .and_then(|parsed| {
            crate::search::query_processing::strip_lake_source_scope_gate(&parsed, deny_set)
        })
        .map(|stripped| stripped.pretty_print())
        .unwrap_or(gated)
}

fn lake_field_values_sampled_window(
    profile: &dyn crate::schema::SchemaProfile,
    base_query: &str,
    field: &str,
    time_range: &TimeRangeInput,
    allow_sample: bool,
    deny_set: &BTreeSet<String>,
) -> Option<TimeRangeInput> {
    (allow_sample
        && (time_range.end - time_range.start).num_seconds()
            > SearchService::LAKE_FIELD_VALUES_EXACT_WINDOW_SECS
        && (profile.is_string_array_field(field)
            || !super::core_search::lake_field_values_rollup_served(
                profile,
                &lake_field_values_planning_base(base_query, deny_set),
                field,
            )))
        .then(|| TimeRangeInput {
            start: time_range.end
                - chrono::Duration::seconds(SearchService::LAKE_FIELD_VALUES_EXACT_WINDOW_SECS),
            end: time_range.end,
        })
}

/// NAN-3566: the base a field's value list is counted over. `F=*` grouped by
/// `F` lists exactly the values `*` grouped by `F` lists once empty values are
/// dropped (which every caller does), and `*` is served by the exact count
/// rollups while `F=*` is not: without this, `metadata.log_source=*` over a
/// 12h window was counted over its newest hour only and hid a source whose
/// only event was older. `None` when the base is anything else.
fn lake_field_values_presence_base(base_query: &str, field: &str) -> Option<&'static str> {
    use crate::query::{Comparator, SearchExpr, Value};
    match parse_query(base_query).ok()? {
        Query::Search(SearchExpr::FieldFilter {
            field: filtered,
            op: Comparator::Eq,
            value: Value::String(value),
            ..
        }) if filtered == field && value == "*" => Some("*"),
        _ => None,
    }
}

/// NAN-3566: low-cardinality fields the lake field list counts exactly over
/// the whole window (from the count rollups, memoized per part on the worker)
/// instead of from the newest-rows sample, so a low-volume value — a rare log
/// source, a rare class — is never missing from the rail. Every field here
/// is a scalar count-rollup field (`LAKE_COUNT_ROLLUP_FIELDS`).
const LAKE_EXACT_FIELD_LIST_FIELDS: &[&str] = &[
    "metadata.log_source",
    "metadata.product.name",
    "metadata.product.vendor_name",
    "class_uid",
    "class_name",
    "category_name",
    "activity_name",
    "severity",
    "status",
];

/// Values kept per exact field: the drill-in's own bound (`limit: 100`).
const LAKE_EXACT_FIELD_LIST_LIMIT: usize = 100;

/// How long the field-stats answer waits for one exact field before keeping
/// its sampled values (flagged as sampled). The exact reads run beside the
/// row sample, so on a warm worker they add nothing; this caps a cold
/// rollup read on a large tenant.
const LAKE_EXACT_FIELD_LIST_BUDGET: std::time::Duration = std::time::Duration::from_millis(1_500);

/// Merge exact per-field values into a lake field-stats sample: an exact
/// field replaces its sampled entry (or is added when the sample never saw
/// it); every other field is flagged with the sample size.
fn merge_exact_field_values(
    sampled: Vec<FieldInfo>,
    exact: Vec<(String, Vec<(String, u64)>)>,
    sampled_rows: u64,
) -> Vec<FieldInfo> {
    let mut fields: Vec<FieldInfo> = sampled
        .into_iter()
        .map(|mut field| {
            field.sampled_rows = Some(sampled_rows);
            field
        })
        .collect();
    for (name, values) in exact {
        if values.is_empty() {
            // No event in the window carries the field: nothing to list.
            fields.retain(|field| field.name != name);
            continue;
        }
        let field_type = fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.field_type.clone())
            .unwrap_or_else(|| {
                if values.iter().all(|(value, _)| value.parse::<i64>().is_ok()) {
                    "number".to_string()
                } else {
                    "string".to_string()
                }
            });
        let info = FieldInfo {
            count: values.iter().map(|(_, count)| *count).sum(),
            cardinality: Some(values.len() as u64),
            top_values: values,
            sampled_rows: None,
            ..FieldInfo::new(name.clone(), field_type)
        };
        match fields.iter_mut().find(|field| field.name == name) {
            Some(field) => *field = info,
            None => fields.push(info),
        }
    }
    fields
}

impl SearchService {
    /// Row bound for the primary lake's field-stats sample. The lake has no
    /// column inventory to aggregate over, so field stats are computed from
    /// up to this many recent matching rows, for every request: with no
    /// `columns` (the web's "Show all fields" / "Index all fields", pivt
    /// inventory reads) over full rows, and with `columns` projected to the
    /// requested canonical fields when they are all known (NAN-2771).
    /// NAN-3216: a `columns` request used to return an empty answer unless it
    /// opted in with `sample_columns`; that silent empty was indistinguishable
    /// from "no data" and left the web Search page's field rail (which always
    /// sends `columns`) and every API caller with no field stats on a shared
    /// tenant. The projected sample is cheap (sub-second live) and cached by
    /// the search service's companion cache. Transferring ClickHouse's
    /// 100k-row field-stat bound across the worker boundary would dwarf the
    /// visible result payload; per-field expansion stays exact over the full
    /// window.
    const LAKE_FIELD_STATS_SAMPLE_ROWS: usize = 1_000;

    /// Get field statistics for a query, gated by the admission controller
    ///
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
    ///    `DELETE /api/search/{request_id}` cancels it.
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
    ) -> Result<FieldStatsResult, SearchError> {
        let derived_qid = request_id.map(|r| format!("{r}-fstats"));

        // No controller wired up → no gating, run directly (tests,
        // single-tenant deployments) — mirrors `search_with_admission`.
        let Some(controller) = self.required_admission_controller()? else {
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
        let _permit = self
            .acquire_auxiliary_search_admission(&controller, &job_id, user_id, priority)
            .await
            .map_err(SearchError::from)?;

        let mut service = self.clone();
        service.active_ch_settings = Some(service.ch_settings_for_priority(priority));
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
    ///
    /// On the primary lake every request runs the bounded sample (see
    /// [`Self::LAKE_FIELD_STATS_SAMPLE_ROWS`]). [`FieldStatsResult::sampled_rows`]
    /// carries the lake sample's row count so `total_events` never depends on
    /// which columns were requested; ClickHouse leaves it `None`.
    pub async fn get_field_stats_for_query(
        &self,
        query: &str,
        time_range: &TimeRangeInput,
        requested_columns: Option<&[String]>,
        query_id: Option<&str>,
        dataset: Option<&str>,
        scope: &ScopeSet,
    ) -> Result<FieldStatsResult, SearchError> {
        let Some(retention_time_range) =
            self.retention_bound_input_range(time_range, chrono::Utc::now())?
        else {
            return Ok(FieldStatsResult::default());
        };
        let time_range = &retention_time_range;

        // The primary lake has no column inventory to aggregate over: field
        // stats come from a bounded row sample (`LAKE_FIELD_STATS_SAMPLE_ROWS`)
        // whose rows flatten to canonical dotted OCSF paths
        // (`metadata.log_source`, `src_endpoint.ip`, ...).
        //
        // A `columns` request is projected to exactly those fields when every
        // name is a known canonical field (otherwise full rows, so
        // unknown/unmapped names keep the ClickHouse contract: dropped, empty
        // intersection = full sample). NAN-3216: never answer a `columns`
        // request with an empty list — that read as "no fields" on a window
        // carrying ~1.4M events/hour.
        let is_log_request = crate::query::Dataset::from_selector(dataset.unwrap_or("logs"))
            == crate::query::Dataset::Logs;
        if self.lake_query.mode == LakeQueryMode::Primary && is_log_request {
            let parsed_query = parse_query(query).map_err(convert_parse_error)?;
            let base_query = extract_base_search(&parsed_query).pretty_print();
            let profile = self.dataset_profile(Some("logs"));
            let projection = requested_columns
                .and_then(|columns| lake_field_stats_projection(columns, profile.as_ref()));
            let sample_query = match &projection {
                Some(columns) => format!("{base_query} | table {}", columns.join(", ")),
                None => base_query.clone(),
            };
            let request = SearchRequest {
                query: sample_query,
                time_range: time_range.clone(),
                limit: Some(Self::LAKE_FIELD_STATS_SAMPLE_ROWS),
                offset: Some(0),
                include_sql: Some(false),
                skip_histogram: true,
                skip_field_stats: true,
                use_cache: true,
                table_view: false,
                request_id: query_id.map(ToOwned::to_owned),
                async_mode: false,
                priority: None,
                dataset: Some("logs".to_string()),
            };
            // NAN-3566: the low-cardinality fields are counted exactly beside
            // the sample (each bounded by its own budget), so a rare value is
            // never lost to the newest-rows sample.
            let exact_columns = requested_columns.filter(|columns| {
                columns.iter().any(|column| profile.is_known_field(column))
            });
            let exact_fields: Vec<&str> = LAKE_EXACT_FIELD_LIST_FIELDS
                .iter()
                .copied()
                .filter(|field| {
                    exact_columns
                        .is_none_or(|columns| columns.iter().any(|column| column == field))
                })
                .collect();
            let base_query = base_query.as_str();
            let exact_reads = futures::future::join_all(exact_fields.iter().map(|&field| {
                async move {
                    let read = self.lake_exact_field_values(field, base_query, time_range, scope);
                    match tokio::time::timeout(LAKE_EXACT_FIELD_LIST_BUDGET, read).await {
                        Ok(Ok(Some(values))) => Some((field.to_string(), values)),
                        Ok(Ok(None)) => None,
                        Ok(Err(error)) => {
                            warn!(%error, field, "exact field-list values failed; keeping the sample");
                            None
                        }
                        Err(_) => {
                            info!(field, "exact field-list values over budget; keeping the sample");
                            None
                        }
                    }
                }
            }));
            // Search futures are large; keep concurrent companions on the heap
            // instead of multiplying the caller's stack frame.
            let (response, exact) = tokio::join!(Box::pin(self.search(request, scope)), exact_reads);
            let response = response?;
            let exact: Vec<_> = exact.into_iter().flatten().collect();
            let sampled_rows = u64::try_from(response.results.len()).unwrap_or(u64::MAX);
            let sampled = if projection.is_some() {
                // A projection emits every requested column on every row, null
                // where the event lacks it; count only populated values so a
                // sparse field's count matches the full-row sample.
                let mut statistics = FieldStatistics::new();
                for row in &response.results {
                    statistics.process_row(&strip_null_fields(row));
                }
                statistics.get_field_info(self.config.top_values_count)
            } else {
                response.fields
            };
            return Ok(FieldStatsResult {
                fields: merge_exact_field_values(
                    select_lake_field_stats(sampled, requested_columns),
                    exact,
                    sampled_rows,
                ),
                sampled_rows: Some(sampled_rows),
            });
        }
        if self.backend != SearchBackend::ClickHouse {
            return Ok(FieldStatsResult::default());
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
                    info!(
                        "Async field stats returned {} fields with data",
                        stats.len()
                    );
                    return Ok(FieldStatsResult { fields: stats, sampled_rows: None });
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
                        return Ok(FieldStatsResult::default());
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Widest window whose field-sidebar drill-in scans every raw row when
    /// the parts' count rollups cannot answer it (NAN-3093). A wider window is
    /// answered from its newest slice this long and flagged as a sample.
    pub const LAKE_FIELD_VALUES_EXACT_WINDOW_SECS: i64 = 3_600;

    /// Get top values for a single field (on-demand, Kibana-style).
    /// This is much more efficient than querying all fields at once.
    /// Always exact over the whole window.
    pub async fn get_field_values(
        &self,
        field: &str,
        query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
        dataset: Option<&str>,
        scope: &ScopeSet,
    ) -> Result<Vec<FieldValueInfo>, SearchError> {
        Ok(self
            .field_values_inner(field, query, time_range, limit, dataset, scope, false)
            .await?
            .values)
    }

    /// NAN-3566: `field`'s values over the whole window, exactly, when the
    /// count rollups answer `base_query` grouped by `field`; `None` when they
    /// do not (the caller keeps its sample rather than scan the window).
    /// One rollup read with no full-window scan fallback; the worker counts
    /// ragged time-window edges exactly and memoizes per-part rollups.
    async fn lake_exact_field_values(
        &self,
        field: &str,
        base_query: &str,
        time_range: &TimeRangeInput,
        scope: &ScopeSet,
    ) -> Result<Option<Vec<(String, u64)>>, SearchError> {
        let profile = self.active_profile.as_ref();
        if !profile.is_known_field(field)
            || profile.is_string_array_field(field)
            || crate::search::lake::lake_count_rollup_field_multi_value(field) != Some(false)
        {
            return Ok(None);
        }
        let base_query = lake_field_values_presence_base(base_query, field).unwrap_or(base_query);
        let planning_base = lake_field_values_planning_base(base_query, scope.deny_set());
        let Some(rows) = self
            .lake_field_list_rollup_rows(&planning_base, field, time_range, scope)
            .await?
        else {
            return Ok(None);
        };
        let mut values = Vec::with_capacity(rows.len());
        for row in &rows {
            let Some(value) = row.get(field).and_then(lake_field_value_string) else {
                return Err(SearchError::SqlValidationError(
                    "field-list rollup omitted its grouped value".to_string(),
                ));
            };
            if value.is_empty() {
                continue;
            }
            let count = row
                .get("count")
                .and_then(|value| {
                    value.as_u64().or_else(|| value.as_str().and_then(|v| v.parse().ok()))
                })
                .ok_or_else(|| SearchError::SqlValidationError(
                    "field-list rollup omitted its UInt64 count".to_string(),
                ))?;
            values.push((value, count));
        }
        // A capped list cannot supply an exact count or cardinality. Unusual
        // metadata with more values keeps the explicitly marked row sample.
        if values.len() > LAKE_EXACT_FIELD_LIST_LIMIT {
            return Ok(None);
        }
        values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        Ok(Some(values))
    }

    /// The field sidebar's drill-in (NAN-3093). On the primary lake a window
    /// wider than [`Self::LAKE_FIELD_VALUES_EXACT_WINDOW_SECS`] that the count
    /// rollups cannot answer (a non-rollup field, a repeated field, a base with
    /// row-level filters) is sampled: counted over its newest slice of that
    /// length, and the result names the slice so the panel can say so.
    /// Everything else is exact, as [`Self::get_field_values`].
    pub async fn get_field_values_for_panel(
        &self,
        field: &str,
        query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
        dataset: Option<&str>,
        scope: &ScopeSet,
    ) -> Result<FieldValuesResult, SearchError> {
        self.field_values_inner(field, query, time_range, limit, dataset, scope, true)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(skip(self, scope, query), fields(field = %field, query = %crate::inputlookup::storage_policy::redact_url_credentials(query)))]
    async fn field_values_inner(
        &self,
        field: &str,
        query: &str,
        time_range: &TimeRangeInput,
        limit: usize,
        dataset: Option<&str>,
        scope: &ScopeSet,
        allow_sample: bool,
    ) -> Result<FieldValuesResult, SearchError> {
        let Some(retention_time_range) =
            self.retention_bound_input_range(time_range, chrono::Utc::now())?
        else {
            return Ok(FieldValuesResult::default());
        };
        let time_range = &retention_time_range;

        let is_log_request = crate::query::Dataset::from_selector(dataset.unwrap_or("logs"))
            == crate::query::Dataset::Logs;
        if self.lake_query.mode == LakeQueryMode::Primary && is_log_request {
            let safe_field = field.split('.').all(|segment| {
                !segment.is_empty()
                    && segment
                        .chars()
                        .next()
                        .is_some_and(|value| value == '_' || value.is_ascii_alphabetic())
                    && segment
                        .chars()
                        .all(|value| value == '_' || value.is_ascii_alphanumeric())
            });
            if !safe_field || !self.active_profile.is_known_field(field) {
                return Err(SearchError::FieldNotFound {
                    field: field.to_string(),
                    suggestions: Vec::new(),
                    message: "field values require a canonical OCSF or explicit unmapped path"
                        .to_string(),
                });
            }
            let parsed_query = parse_query(query).map_err(convert_parse_error)?;
            let base_query = extract_base_search(&parsed_query).pretty_print();
            // NAN-3566: `F=*` lists F's values as `*` does, from the rollups.
            // Keep repeated-field presence/percentage semantics unchanged:
            // summing expanded value counts can count an event more than once.
            let repeated = self.active_profile.is_string_array_field(field);
            let presence_base = (!repeated)
                .then(|| lake_field_values_presence_base(&base_query, field))
                .flatten();
            let base_query = presence_base.map(str::to_string).unwrap_or(base_query);
            let field_values_query = lake_field_values_query(&base_query, field, limit, repeated);
            let sampled_window = lake_field_values_sampled_window(
                self.active_profile.as_ref(), &base_query, field, time_range, allow_sample,
                scope.deny_set(),
            );
            let request = SearchRequest {
                query: field_values_query,
                time_range: sampled_window.clone().unwrap_or_else(|| time_range.clone()),
                limit: Some(limit),
                offset: None,
                include_sql: Some(false),
                skip_histogram: true,
                skip_field_stats: true,
                use_cache: true,
                table_view: false,
                request_id: None,
                async_mode: false,
                priority: None,
                dataset: Some("logs".to_string()),
            };
            // The percentage is "share of all matching events" (the UI's
            // contract, FieldsPanel.tsx). The top-N rows alone only give the
            // share of the returned values (audit #14: 10.7% for a value
            // that is 0.09% of the events). The base count runs beside the
            // values query and is rollup-served when the base allows it.
            let total_request = SearchRequest {
                query: format!("{base_query} | stats count() as count"),
                limit: Some(1),
                ..request.clone()
            };
            let (response, total) = tokio::join!(
                Box::pin(self.search(request, scope)),
                Box::pin(self.search(total_request, scope))
            );
            let response = response?;
            let matching_events = match total {
                Ok(total) => total
                    .results
                    .first()
                    .and_then(|row| row.get("count"))
                    .and_then(|value| value.as_u64().or_else(|| value.as_f64().map(|v| v as u64))),
                Err(error) => {
                    tracing::warn!(%error, field, "lake field-values total failed; percentages are relative to the returned values");
                    None
                }
            };
            let mut values = Vec::with_capacity(response.results.len());
            for row in response.results {
                let Some(value) = row.get(field).and_then(lake_field_value_string) else {
                    continue;
                };
                if value.is_empty() {
                    continue;
                }
                let count = row
                    .get("count")
                    .and_then(|value| value.as_u64().or_else(|| value.as_f64().map(|v| v as u64)))
                    .unwrap_or(0);
                values.push(FieldValueInfo {
                    value,
                    count,
                    percentage: 0.0,
                });
            }
            // Under the presence rewrite the matching events are the rows
            // that carry a value: all of them are listed below the limit.
            let matching_events = if presence_base.is_some() && values.len() < limit {
                Some(values.iter().map(|value| value.count).sum())
            } else {
                matching_events
            };
            apply_field_value_percentages(&mut values, matching_events);
            return Ok(FieldValuesResult { values, sampled_window });
        }
        if self.backend != SearchBackend::ClickHouse {
            return Ok(FieldValuesResult::default());
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

        Ok(FieldValuesResult { values, sampled_window: None })
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
        let (retention_time_range, fully_expired) =
            self.retention_bound_optional_input_range(time_range, chrono::Utc::now())?;
        if fully_expired {
            return Ok(None);
        }
        let time_range = retention_time_range.as_ref();

        if self.lake_query.mode == LakeQueryMode::Primary {
            let client = self.lake_query.client.as_ref().ok_or_else(|| {
                SearchError::SqlValidationError(
                    "lake query backend is enabled without a worker client".to_string(),
                )
            })?;
            return client
                .fetch_log_by_id(id, time_range, source_type, scope.deny_set())
                .await;
        }

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

        // NAN-3245: the expanded row is the event's populated fields; the
        // explicit-column table pads every unset UDM/OCSF column with
        // null/"". `raw_data` is kept verbatim; a JSON-string `unmapped`/`ext`
        // is a non-empty value and is kept as is (NAN-3458).
        Ok(results.into_iter().next().map(|mut row| {
            crate::search::sparse_event::sparse_full_event(&mut row);
            row
        }))
    }

    /// Query logs by a specific UDM field value
    /// This searches across all log sources that have the field mapped
    ///
    /// NAN-1799: the hand-built SQL ANDs the caller's source-scope deny-set
    /// into the WHERE (see `build_udm_field_query`).
    #[instrument(skip(self, scope))]
    pub async fn query_udm_field(
        &self,
        mut request: UdmFieldQueryRequest,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        // Validate time range
        request.time_range.validate()?;
        let Some(retention_time_range) =
            self.retention_bound_input_range(&request.time_range, chrono::Utc::now())?
        else {
            return Ok(SearchResponse::empty());
        };
        request.time_range = retention_time_range;

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
            server_wall_ms: None,
            results,
            total_count,
            // Field lookups run their own exact count companion.
            total_count_exact: true,
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
            completeness: None,
        })
    }

    /// Discovery window for the context-free ext-key enumeration (NAN-2174).
    /// See the fallback branch in [`Self::get_ext_field_names`] for why this is
    /// the real bound on the scan and why it must stay small.
    pub(crate) const EXT_FIELD_NAMES_DISCOVERY_WINDOW_MINUTES: u32 = 15;

    /// Get ext field names that exist in the data, scoped to the active search.
    ///
    /// NAN-1510: when `query` + `time_range` are given, enumeration is scoped to
    /// the SAME predicate (time bounds + base filter) the per-field value fetch
    /// (`get_field_values`) uses — so every key listed has values an expand can
    /// actually return. Previously enumeration was time-window-only (NAN-1505),
    /// so a filtered search listed ext keys from other source types in the window
    /// that then expanded empty ("Values loaded on demand", no entries).
    /// Fallbacks: time-only when no query (historical window), a short recent
    /// window (NAN-2174) when neither — the context-free syntax-highlighter path.
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
        let (retention_time_range, fully_expired) =
            self.retention_bound_optional_input_range(time_range, chrono::Utc::now())?;
        if fully_expired {
            return Ok(Vec::new());
        }
        let time_range = retention_time_range.as_ref();

        if self.lake_query.mode == LakeQueryMode::Primary {
            // Strict OCSF has no `ext` namespace. The route name remains for
            // the existing frontend transport. The worker's immutable source
            // manifest describes POSSIBLE `unmapped.*` paths, not paths with a
            // non-null value in this search. It is useful for context-free
            // query autocomplete, but must not populate a query-scoped field
            // rail with empty schema placeholders. Populated spill leaves in a
            // search are discovered from the same sampled rows as other nested
            // OCSF leaves and remain available for exact per-field expansion.
            if query.is_some() || time_range.is_some() {
                return Ok(Vec::new());
            }
            // Serving objects can mix sources, and the current manifest does
            // not attribute each sparse path to a source. Returning the union
            // to a restricted caller would disclose fields that exist only in
            // denied/audit sources, so fail closed until the manifest carries
            // per-source path coverage.
            if !lake_unmapped_field_discovery_allowed(scope) {
                return Ok(Vec::new());
            }
            return self.lake_unmapped_field_names().await;
        }
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
                    Query::Search(expr) => {
                        match self.ch_sql_generator.generate_search_expr(&expr) {
                            Ok(filter) => format!("{} AND ({})", time_only(tr), filter),
                            Err(_) => return Ok(Vec::new()),
                        }
                    }
                    // extract_base_search always yields Query::Search; defensively
                    // fall back to the window scope rather than erroring.
                    _ => time_only(tr),
                }
            }
            (_, Some(tr)) => time_only(tr),
            // NAN-2174: the context-free highlighter path (no query, no range)
            // is what a bare `/search` mount hits. This window is the ONLY thing
            // bounding the read — the executor's per-source slice caps what gets
            // aggregated, not what gets scanned — so it must stay narrow.
            //
            // Was 3h, which on Saturn is 2.44M rows / 903 MiB of `ext` and 500'd
            // on `max_execution_time`. 15 minutes reads 187k rows / 256 MiB there
            // (1.07s) and returns the IDENTICAL key set — verified by
            // set-differencing the 3h and 15m results both ways, both empty.
            //
            // Trade-off: a source emitting less than ~1 row per 15 minutes may
            // not contribute keys here. That is a soft miss on a best-effort
            // prefetch (the frontend `.catch`es this, and results-driven
            // `availableFields` also feeds highlighting), and strictly better
            // than the hard 500 that returned no keys at all.
            _ => format!(
                "timestamp >= now() - INTERVAL {} MINUTE",
                Self::EXT_FIELD_NAMES_DISCOVERY_WINDOW_MINUTES
            ),
        };

        // NAN-1799: append the caller's source-scope exclusion to whichever
        // branch built the predicate (query-scoped, time-only, or the 3h
        // fallback). Empty deny-set → predicate unchanged (byte-identical).
        let where_predicate = match source_scope_sql_predicate("source_type", scope.deny_set()) {
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

fn lake_unmapped_field_discovery_allowed(scope: &ScopeSet) -> bool {
    !scope.is_restricted()
}

fn lake_field_value_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::Null => None,
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            serde_json::to_string(value).ok()
        }
    }
}

/// Build the primary-lake on-demand value query at the same logical grain the
/// event inspector renders. Repeated OCSF objects are stored as parallel array
/// leaves (`enrichments.data.detector`, hashes, resources, ...). Grouping the
/// physical leaf directly groups whole array combinations and leaks JSON such
/// as `["dga_entropy","suspicious_tld"]` into the filter rail. Expand only
/// schema-declared array leaves first so each displayed/filterable scalar gets
/// its own count. Scalar fields keep the existing byte shape.
///
/// The maximum `usize` is deliberate: this internal companion must not silently
/// sample a user's result window at the normal interactive `mvexpand` row cap.
/// The worker's scan, time, and memory admission fences still apply, so an
/// oversized drill-in fails explicitly instead of returning plausible partial
/// counts.
/// Percent of all matching events. Falls back to the returned values' sum
/// when the base count is unavailable, and never below it (a stale count must
/// not produce shares above 100%).
fn apply_field_value_percentages(values: &mut [FieldValueInfo], matching_events: Option<u64>) {
    let returned_total: u64 = values.iter().map(|item| item.count).sum();
    let denominator = matching_events.unwrap_or(0).max(returned_total);
    if denominator > 0 {
        for item in values.iter_mut() {
            item.percentage = item.count as f64 * 100.0 / denominator as f64;
        }
    }
}

fn lake_field_values_query(base_query: &str, field: &str, limit: usize, repeated: bool) -> String {
    let expand = repeated
        .then(|| format!(" | mvexpand {field} limit={}", usize::MAX))
        .unwrap_or_default();
    format!("{base_query}{expand} | stats count() as count by {field} | sort -count | head {limit}")
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
fn select_field_stats_columns(inventory: Vec<String>, requested: Option<&[String]>) -> Vec<String> {
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

/// Top values of one field (NAN-3093): exact over the requested window, or
/// counted over `sampled_window` only (see
/// [`SearchService::get_field_values_for_panel`]).
#[derive(Debug, Clone, Default)]
pub struct FieldValuesResult {
    pub values: Vec<FieldValueInfo>,
    /// The slice of the window the values were counted over, when sampled.
    pub sampled_window: Option<TimeRangeInput>,
}

/// Field statistics plus, on the primary lake, the size of the row sample
/// they were computed from (NAN-2771). `sampled_rows` is independent of the
/// requested columns, so it is the honest `total_events` for a sample;
/// ClickHouse aggregates over the window and leaves it `None`.
#[derive(Debug, Clone, Default)]
pub struct FieldStatsResult {
    pub fields: Vec<FieldInfo>,
    pub sampled_rows: Option<u64>,
}

/// NAN-2771: the canonical fields to project a lake field-stats sample to, or
/// `None` to sample full rows. Projection happens only when the profile
/// enforces canonical fields and EVERY requested name is a known scalar
/// field of it; any unknown/unmapped/array name keeps the full-row sample so
/// the selection contract (drop unknown, empty intersection = full) holds.
fn lake_field_stats_projection(
    requested: &[String],
    profile: &dyn crate::schema::SchemaProfile,
) -> Option<Vec<String>> {
    if requested.is_empty() || !profile.uses_strict_canonical_fields() {
        return None;
    }
    let mut columns: Vec<String> = Vec::with_capacity(requested.len());
    for name in requested {
        if !profile.is_known_field(name) || profile.is_string_array_field(name) {
            return None;
        }
        if !columns.contains(name) {
            columns.push(name.clone());
        }
    }
    Some(columns)
}

/// Drop null-valued keys (recursively through objects) from a projected row.
fn strip_null_fields(row: &serde_json::Value) -> serde_json::Value {
    match row {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .filter(|(_, value)| !value.is_null())
                .map(|(key, value)| (key.clone(), strip_null_fields(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// NAN-2771: reduce a lake field-stats sample to the requested canonical
/// names, mirroring [`select_field_stats_columns`] (exact-name intersection;
/// an empty intersection keeps the full sample so a stale client column list
/// cannot blank the field panel). Sample order is preserved.
fn select_lake_field_stats(sampled: Vec<FieldInfo>, requested: Option<&[String]>) -> Vec<FieldInfo> {
    let Some(requested) = requested else {
        return sampled;
    };
    let requested: std::collections::HashSet<&str> = requested.iter().map(String::as_str).collect();
    if !sampled.iter().any(|field| requested.contains(field.name.as_str())) {
        if !requested.is_empty() {
            warn!(
                "Requested lake field-stats columns ({}) matched no sampled field; \
                 returning the full sample inventory",
                requested.len()
            );
        }
        return sampled;
    }
    sampled
        .into_iter()
        .filter(|field| requested.contains(field.name.as_str()))
        .collect()
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
    #[test]
    fn lake_field_values_rollup_served_contract() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        for (base, field, expected) in [
            ("metadata.log_source=windows_sysmon", "src_endpoint.hostname", true),
            ("*", "actor.user.name", true),
            ("*", "src_endpoint.ip", false),
            ("*", "unmapped.custom_field", false),
            ("*", "enrichments.data.detector", false),
        ] {
            assert_eq!(super::super::core_search::lake_field_values_rollup_served(
                &profile, base, field,
            ), expected, "{base}: {field}");
        }
    }

    #[test]
    fn lake_field_values_panel_samples_only_wide_non_rollup_windows() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let end = Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap();
        let wide = TimeRangeInput { start: end - chrono::Duration::hours(24), end };
        for field in ["src_endpoint.ip", "unmapped.custom_field", "enrichments.data.detector"] {
            let sampled = lake_field_values_sampled_window(&profile, "*", field, &wide, true, &BTreeSet::new()).unwrap();
            assert_eq!(sampled.start, end - chrono::Duration::hours(1));
            assert_eq!(sampled.end, end);
            assert!(lake_field_values_sampled_window(&profile, "*", field, &wide, false, &BTreeSet::new()).is_none());
            let exact = TimeRangeInput { start: sampled.start, end };
            assert!(lake_field_values_sampled_window(&profile, "*", field, &exact, true, &BTreeSet::new()).is_none());
        }
        assert!(lake_field_values_sampled_window(&profile, "*", "actor.user.name", &wide, true, &BTreeSet::new()).is_none());
        assert!(lake_field_values_sampled_window(&profile, "metadata.log_source=windows_sysmon", "src_endpoint.hostname", &wide, true, &BTreeSet::new()).is_none());
    }

    /// NAN-3166: a scoped caller's sidebar makes the same exact-vs-sampled
    /// decision as an unrestricted one, because the drill-in's searches plan
    /// their rollups without the injected gate and carry the deny set to the
    /// worker. A deny set naming Unattributed keeps the gated (scanning)
    /// plan, so its wide windows are sampled rather than scanned in full.
    #[test]
    fn scoped_field_values_panel_decides_like_an_unrestricted_one() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let end = Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap();
        let wide = TimeRangeInput { start: end - chrono::Duration::hours(24), end };
        let set = |items: &[&str]| items.iter().map(|item| item.to_string()).collect::<BTreeSet<_>>();
        let cases = [
            ("*", "actor.user.name"),
            ("*", "device.hostname"),
            ("metadata.log_source=windows_sysmon", "src_endpoint.hostname"),
            (r#"device.hostname="ws-hr-132.corp.local""#, "metadata.log_source"),
            ("*", "src_endpoint.ip"),
            ("*", "unmapped.custom_field"),
            ("powershell", "actor.user.name"),
        ];
        for deny in [&["audit"][..], &["windows_sysmon"], &["audit", "conduit_proxy"]] {
            for (base, field) in cases {
                let window = |deny: &BTreeSet<String>| {
                    lake_field_values_sampled_window(&profile, base, field, &wide, true, deny)
                        .map(|window| (window.start, window.end))
                };
                assert_eq!(
                    window(&set(deny)),
                    window(&BTreeSet::new()),
                    "{deny:?} {base}: {field}"
                );
                // The planning base is the user's base, user-written source
                // filters included; only the injected gate is gone.
                assert_eq!(
                    parse_query(&lake_field_values_planning_base(base, &set(deny))).unwrap(),
                    parse_query(&parse_query(base).unwrap().pretty_print()).unwrap(),
                    "{deny:?} {base}"
                );
            }
        }
        // The rollup-served cases really are exact for the scoped caller.
        assert!(lake_field_values_sampled_window(&profile, "*", "actor.user.name", &wide, true, &set(&["audit"])).is_none());
        // A user-written exclusion of a denied source is not stripped.
        let user = r#"metadata.log_source!="audit" device.hostname="h1""#;
        assert_eq!(
            parse_query(&lake_field_values_planning_base(user, &set(&["audit"]))).unwrap(),
            parse_query(&parse_query(user).unwrap().pretty_print()).unwrap()
        );
        // Unattributed deny sets keep the gate: the decision follows the
        // gated scan, which the rollups cannot answer.
        for deny in [&["default"][..], &["unknown"], &["audit", "Default"]] {
            let planning = lake_field_values_planning_base("*", &set(deny));
            assert!(planning.contains("metadata.log_source"), "{deny:?} {planning}");
            assert!(
                lake_field_values_sampled_window(&profile, "*", "actor.user.name", &wide, true, &set(deny)).is_some(),
                "{deny:?}"
            );
        }
    }

    /// Audit #14: shares are of all matching events, not of the top-N sum.
    #[test]
    fn lake_field_value_percentages_use_the_matching_event_count() {
        use super::FieldValueInfo;
        let value = |count| FieldValueInfo { value: format!("v{count}"), count, percentage: 0.0 };
        let mut values = vec![value(44), value(300), value(68)];
        super::apply_field_value_percentages(&mut values, Some(50_588));
        assert!((values[0].percentage - 44.0 * 100.0 / 50_588.0).abs() < 1e-9);
        // No count: relative to the returned values (the old behaviour).
        let mut values = vec![value(1), value(3)];
        super::apply_field_value_percentages(&mut values, None);
        assert_eq!(values[1].percentage, 75.0);
        // A stale/short count never yields shares above 100%.
        let mut values = vec![value(10)];
        super::apply_field_value_percentages(&mut values, Some(4));
        assert_eq!(values[0].percentage, 100.0);
    }

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

    #[test]
    fn lake_unmapped_discovery_fails_closed_for_restricted_callers() {
        assert!(lake_unmapped_field_discovery_allowed(
            &ScopeSet::unrestricted()
        ));
        assert!(!lake_unmapped_field_discovery_allowed(
            &ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]))
        ));
    }

    #[test]
    fn lake_field_values_expand_repeated_ocsf_leaves_before_grouping() {
        assert_eq!(
            lake_field_values_query(
                "metadata.log_source=conduit_proxy",
                "enrichments.data.detector",
                100,
                true,
            ),
            format!(
                "metadata.log_source=conduit_proxy | mvexpand enrichments.data.detector \
                 limit={} | stats count() as count by enrichments.data.detector | sort \
                 -count | head 100",
                usize::MAX
            )
        );
    }

    #[test]
    fn lake_field_values_leave_scalar_fields_unexpanded() {
        assert_eq!(
            lake_field_values_query("metadata.log_source=windows_sysmon", "action", 25, false,),
            "metadata.log_source=windows_sysmon | stats count() as count by action | sort -count | head 25"
        );
    }

    /// The handler-composed deny-set for a caller without `audit:view`
    /// (the old `exclude_audit: true`).
    fn audit_scope() -> BTreeSet<String> {
        std::iter::once("audit".to_string()).collect()
    }

    fn field_values_sql(generator: &ClickHouseSqlGenerator, table: &str, field: &str) -> String {
        let executor = ClickHouseExecutor::new(clickhouse::Client::default());
        let base_sql = format!(
            "SELECT * FROM {table} ORDER BY timestamp DESC SETTINGS optimize_read_in_order=1"
        );
        executor.build_field_values_sql(&base_sql, &generator.field_values_display_expr(field), 25)
    }

    /// NAN-2149 endpoint-path snapshot: both POST /api/search/field-values and
    /// GET /api/fields/{name}/values reach this shared SQL builder. An OCSF UDM
    /// alias must aggregate the indexed class-spanning value, not `user.name`.
    #[test]
    fn ocsf_field_values_sql_groups_class_split_user_on_unified_value() {
        let generator = ClickHouseSqlGenerator::new()
            .with_profile(std::sync::Arc::new(crate::schema::OcsfProfile::new()));
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
        let generator = ClickHouseSqlGenerator::new()
            .with_profile(std::sync::Arc::new(crate::schema::OcsfProfile::new()));
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
        let generator = ClickHouseSqlGenerator::new()
            .with_profile(std::sync::Arc::new(crate::schema::OcsfProfile::new()));
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
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            None,
            None,
            &no_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
        for col in [
            "user_identity_department",
            "enriched_src_country",
            "ioc_confidence",
            "prevalence_dest_ip",
        ] {
            assert!(
                sql.contains(col),
                "missing materialized column {col}: {sql}"
            );
        }
    }

    #[test]
    fn fetch_log_sql_with_audit_exclusion_filters_audit_rows() {
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            None,
            None,
            &audit_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
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
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            None,
            None,
            &deny,
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
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
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            Some(&tr),
            None,
            &audit_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
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
        let sql = build_fetch_log_sql(
            "logs",
            "abc'; DROP--",
            None,
            None,
            &audit_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
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
        let sql = build_fetch_log_sql(
            "ocsf_logs",
            "abc-123",
            None,
            None,
            &no_scope(),
            ocsf_cols,
            &[],
        );
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
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            None,
            None,
            &no_scope(),
            &[],
            UDM_VIEW_RENAMES,
        );
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
        let sql = build_fetch_log_sql(
            "ocsf_logs",
            "abc-123",
            None,
            None,
            &no_scope(),
            ocsf_cols,
            &[],
        );
        assert!(sql.starts_with("SELECT *, "), "{sql}");
        assert!(!sql.contains("EXCEPT"), "OCSF must not emit EXCEPT: {sql}");
        assert!(
            !sql.contains("event_type"),
            "OCSF must not emit UDM names: {sql}"
        );
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
        let sql = build_fetch_log_sql(
            "logs",
            "abc-123",
            None,
            Some("evil'; DROP--"),
            &no_scope(),
            MATERIALIZED_COLUMNS,
            UDM_VIEW_RENAMES,
        );
        assert!(
            sql.contains("source_type = 'evil''; DROP--'"),
            "source_type quotes not escaped: {sql}"
        );
    }

    // ── NAN-2771: lake field-stats honor a requested column subset ─────────

    /// A lake worker double that echoes the request/tenant/route binding the
    /// client validates, and answers every `/v1/query` with fixed OCSF rows.
    struct EchoLakeWorker {
        tenant: String,
        rows: serde_json::Value,
    }

    impl wiremock::Respond for EchoLakeWorker {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "ok": true,
                    "tenant_id": self.tenant,
                    "request_id": body["request_id"],
                    "route": body["route"],
                    "result": {
                        "rows": self.rows,
                        "result_rows": self.rows.as_array().map(|rows| rows.len()),
                        "page_has_more": false,
                    },
                }))
                .insert_header("x-nano-worker-assignment-id", "field-stats-worker")
                .insert_header("x-nano-worker-assignment-revision", "1")
        }
    }

    #[cfg(feature = "enterprise")]
    async fn lake_tenant_view(
        server: &wiremock::MockServer,
        tenant: uuid::Uuid,
        dir: &std::path::Path,
    ) -> SearchService {
        let credential = dir.join("worker-token");
        std::fs::write(&credential, "field-stats-worker-token-0123456789abcdef").unwrap();
        let assignment = crate::search::SharedLakeWorkerAssignment {
            tenant_id: tenant,
            internal_endpoint: server.uri(),
            credential_file: credential,
            expected_worker_identity: "field-stats-worker".to_string(),
            expected_worker_revision: 1,
            timeout_secs: 10,
            prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots {
                one_hour: "p1".into(),
                twenty_four_hours: "p24".into(),
                seven_days: "p7".into(),
                thirty_days: "p30".into(),
            },
            prevalence_rarity_threshold: 3,
            prevalence_timeout_secs: 10,
            enrichment_coordinator: None,
            otel_ingest: None,
            erasure_executor: None,
        };
        // Never connects: a request that escaped the lake into PostgreSQL or
        // ClickHouse would fail rather than silently succeed.
        let dual_pool = crate::db::DualPool::new_lake_control_plane(
            &crate::db::DualPoolConfig::with_auth(
                "postgres://fixture:fixture@127.0.0.1:1/never_connect",
                "http://127.0.0.1:1",
                "fixture",
                "fixture",
                "fixture",
            ),
        )
        .await
        .unwrap();
        // The lake's strict canonical OCSF 1.9 profile, as shared deployments run.
        SearchService::with_dual_pool_and_profile_unrouted(
            &dual_pool,
            std::sync::Arc::new(crate::schema::OcsfProfile::lake_1_9()),
        )
            .enterprise_shared_tenant_view(
                &assignment,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                std::sync::Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap()
    }

    fn ocsf_rows() -> serde_json::Value {
        serde_json::json!([
            {"time": "2026-09-24T10:00:00Z", "class_uid": 4002, "metadata": {"log_source": "conduit_proxy", "product": {"name": "conduit"}}, "src_endpoint": {"ip": "10.0.0.1"}, "http_request": {"url": {"hostname": "a.example"}}},
            {"time": "2026-09-24T10:01:00Z", "class_uid": 4002, "metadata": {"log_source": "conduit_proxy", "product": {"name": "conduit"}}, "src_endpoint": {"ip": "10.0.0.2"}, "http_request": {"url": {"hostname": "b.example"}}},
            {"time": "2026-09-24T10:02:00Z", "class_uid": 1007, "metadata": {"log_source": "windows_sysmon", "product": {"name": "sysmon"}}, "src_endpoint": {"ip": "10.0.0.1"}}
        ])
    }

    #[test]
    fn lake_field_stats_selection_keeps_sample_order_and_exact_names() {
        let sample: Vec<FieldInfo> = ["class_uid", "metadata.log_source", "metadata.log_source_uid", "src_endpoint.ip"]
            .iter()
            .map(|name| FieldInfo::new(name.to_string(), "string".into()))
            .collect();
        let names = |fields: Vec<FieldInfo>| fields.into_iter().map(|f| f.name).collect::<Vec<_>>();
        assert_eq!(names(select_lake_field_stats(sample.clone(), None)).len(), 4);
        // Exact dotted-path match only: `metadata.log_source` is not a prefix
        // selector for `metadata.log_source_uid`.
        assert_eq!(
            names(select_lake_field_stats(sample.clone(), Some(&["src_endpoint.ip".to_string(), "metadata.log_source".to_string()][..]))),
            vec!["metadata.log_source", "src_endpoint.ip"]
        );
        // No intersection (or an empty list) keeps the full sample.
        assert_eq!(names(select_lake_field_stats(sample.clone(), Some(&["src_ip".to_string()][..]))).len(), 4);
        assert_eq!(names(select_lake_field_stats(sample, Some(&[][..]))).len(), 4);
    }

    fn ocsf_window() -> TimeRangeInput {
        let now = chrono::Utc::now();
        TimeRangeInput::new(now - chrono::Duration::hours(1), now)
    }

    async fn mounted_worker(tenant: uuid::Uuid) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/query"))
            .respond_with(EchoLakeWorker { tenant: tenant.to_string(), rows: ocsf_rows() })
            .mount(&server)
            .await;
        server
    }

    async fn worker_queries(server: &wiremock::MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            // NAN-3566: exact field-list reads go to the count route.
            .filter(|request| request.url.path().ends_with("/v1/query"))
            .map(|request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                body["query"].as_str().unwrap().to_string()
            })
            .collect()
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3216 regression: the web Search page (and every API caller) sends
    /// `columns` without any opt-in. On a data-bearing lake window that must
    /// answer with real, projected field stats — never the silent
    /// `{"fields":[],"total_events":0}` that blanked the field rail on shared.
    #[tokio::test]
    async fn lake_field_stats_columns_request_is_never_empty_for_a_data_bearing_window() {
        let tenant = uuid::Uuid::from_u128(0x3216);
        let server = mounted_worker(tenant).await;
        let dir = tempfile::tempdir().unwrap();
        let view = lake_tenant_view(&server, tenant, dir.path()).await;
        // The web's reduced request: pinned + visible-row canonical columns.
        let requested = vec!["metadata.log_source".to_string(), "class_uid".to_string()];
        let result = view
            .get_field_stats_for_query("*", &ocsf_window(), Some(&requested), None, None, &ScopeSet::unrestricted())
            .await
            .unwrap();
        let names: BTreeSet<&str> = result.fields.iter().map(|field| field.name.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["metadata.log_source", "class_uid"]));
        assert!(result.fields.iter().all(|field| field.count > 0 && !field.top_values.is_empty()));
        assert_eq!(result.sampled_rows, Some(3));
        let queries = worker_queries(&server).await;
        assert_eq!(queries.len(), 1, "one projected sample scan");
        assert!(queries[0].ends_with("| table metadata.log_source, class_uid"), "{}", queries[0]);
    }

    #[cfg(feature = "enterprise")]
    /// The live repro (`columns` of canonical dotted OCSF paths returned
    /// `{"fields":[],"total_events":0}`), now answered by default (NAN-3216): real
    /// counts, projected to exactly the requested fields.
    #[tokio::test]
    async fn lake_field_stats_opt_in_counts_requested_columns() {
        let tenant = uuid::Uuid::from_u128(0x2771);
        let server = mounted_worker(tenant).await;
        let dir = tempfile::tempdir().unwrap();
        let view = lake_tenant_view(&server, tenant, dir.path()).await;
        let scope = ScopeSet::unrestricted();

        let full = view
            .get_field_stats_for_query("*", &ocsf_window(), None, None, None, &scope)
            .await
            .unwrap();
        assert_eq!(full.sampled_rows, Some(3));
        let full_log_source = full
            .fields
            .iter()
            .find(|field| field.name == "metadata.log_source")
            .expect("full inventory carries the canonical OCSF leaf")
            .clone();

        let requested = vec![
            "metadata.log_source".to_string(),
            "src_endpoint.ip".to_string(),
            "class_uid".to_string(),
        ];
        let reduced = view
            .get_field_stats_for_query("*", &ocsf_window(), Some(&requested), None, None, &scope)
            .await
            .unwrap();
        let names: BTreeSet<&str> = reduced.fields.iter().map(|field| field.name.as_str()).collect();
        assert_eq!(names, BTreeSet::from(["metadata.log_source", "src_endpoint.ip", "class_uid"]));
        let log_source = reduced.fields.iter().find(|field| field.name == "metadata.log_source").unwrap();
        assert_eq!(log_source.count, full_log_source.count);
        assert_eq!(log_source.top_values, full_log_source.top_values);
        assert_eq!(reduced.sampled_rows, Some(3));

        // Known canonical fields are projected at the worker, not fetched as
        // full rows.
        let queries = worker_queries(&server).await;
        assert_eq!(queries.len(), 2);
        assert!(!queries[0].contains("| table"), "{}", queries[0]);
        assert!(
            queries[1].ends_with("| table metadata.log_source, src_endpoint.ip, class_uid"),
            "{}",
            queries[1]
        );
    }

    /// NAN-3566 worker: the newest-rows sample holds only source A; the
    /// exact grouped count (whichever route search plans it on) holds A and
    /// the one event of source B.
    struct RareSourceWorker {
        tenant: String,
    }

    const RARE_SOURCE_A_EVENTS: u64 = 1_500;

    #[cfg(feature = "enterprise")]
    async fn rare_source_cell_view(
        server: &wiremock::MockServer,
        tenant: uuid::Uuid,
        dir: &std::path::Path,
    ) -> SearchService {
        let token_file = dir.join("router.token");
        std::fs::write(&token_file, "nan3566-fixture-router-token-1234567890").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool = crate::db::DualPool::new_lake_control_plane(
            &crate::db::DualPoolConfig::with_auth(
                "postgres://fixture:fixture@127.0.0.1:1/never_connect",
                "http://127.0.0.1:1", "fixture", "fixture", "fixture",
            ),
        ).await.unwrap();
        SearchService::with_dual_pool_and_profile_unrouted(
            &pool, std::sync::Arc::new(crate::schema::OcsfProfile::lake_1_9()),
        ).enterprise_shared_cell_tenant_view(
            &crate::search::LakeCellRoute {
                tenant_id: tenant, assignment_generation: 1, part_log_writer_epoch: 1,
                worker_revision: 1, assignment_fenced: true, cell_origin: server.uri(),
                query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
                router_token_file: token_file,
            },
            crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap(),
            std::sync::Arc::new(crate::search::InMemoryJobStore::new()),
        ).unwrap()
    }

    fn rare_source_counts() -> serde_json::Value {
        serde_json::json!([
            {"metadata.log_source": "audit", "count": RARE_SOURCE_A_EVENTS},
            {"metadata.log_source": "otlp_log", "count": 1}
        ])
    }

    impl wiremock::Respond for RareSourceWorker {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let query = body["query"].as_str().unwrap_or_default();
            let count_route = request.url.path().ends_with("/v1/aggregate/count");
            let rows = if body["group_field"] == "class_uid"
                || query.contains("stats count() as count by class_uid")
            {
                serde_json::json!([{"class_uid": 6003, "count": RARE_SOURCE_A_EVENTS + 1}])
            } else if (count_route && body["group_results"] == true)
                || query.contains("stats count() as count by metadata.log_source")
            {
                rare_source_counts()
            } else if count_route || query.contains("stats count() as count") {
                serde_json::json!([{"count": RARE_SOURCE_A_EVENTS + 1}])
            } else {
                // The newest 1,000 rows: all source A.
                serde_json::Value::Array(
                    (0..1_000)
                        .map(|i| serde_json::json!({"time": "2026-09-24T10:00:00Z", "class_uid": 6003,
                            "metadata": {"uid": format!("a-{i}"), "log_source": "audit"}}))
                        .collect(),
                )
            };
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "ok": true,
                    "tenant_id": self.tenant,
                    "request_id": body["request_id"],
                    "route": body["route"].as_str().unwrap_or(if count_route { "count_aggregate" } else { "broad_npl" }),
                    "source_mode": "parts",
                    "log_head": {"seq": 1, "sha256": "ab".repeat(32)},
                    "generation_id": "nan3566",
                    "snapshot_id": "1",
                    "result": {
                        "rows": rows,
                        "result_rows": rows.as_array().map(|rows| rows.len()),
                        "page_has_more": false,
                    },
                }))
                .insert_header("x-nano-worker-assignment-id", "field-stats-worker")
                .insert_header("x-nano-worker-assignment-revision", "1")
        }
    }

    fn twelve_hours() -> TimeRangeInput {
        let now = chrono::Utc::now();
        TimeRangeInput::new(now - chrono::Duration::hours(12), now)
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3566 regression: N events of source A and one of source B in a
    /// 12h window. The field rail's `metadata.log_source` lists both and is
    /// exact, though the row sample saw only A; every other field is
    /// flagged with the sample size.
    #[tokio::test]
    async fn lake_field_list_lists_a_one_event_source_beside_a_large_one() {
        let tenant = uuid::Uuid::from_u128(0x3566);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(RareSourceWorker { tenant: tenant.to_string() })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = rare_source_cell_view(&server, tenant, dir.path()).await;
        let requested = vec!["metadata.log_source".to_string(), "class_uid".to_string()];
        for query in ["*", "metadata.log_source=*"] {
            let result = view
                .get_field_stats_for_query(query, &twelve_hours(), Some(&requested), None, None, &ScopeSet::unrestricted())
                .await
                .unwrap();
            let source = result.fields.iter().find(|field| field.name == "metadata.log_source").unwrap();
            assert_eq!(
                source.top_values,
                vec![("audit".to_string(), RARE_SOURCE_A_EVENTS), ("otlp_log".to_string(), 1)],
                "{query}"
            );
            assert_eq!(source.cardinality, Some(2), "{query}");
            assert_eq!(source.count, RARE_SOURCE_A_EVENTS + 1, "{query}");
            assert_eq!(source.sampled_rows, None, "{query}: exact");
            assert_eq!(result.sampled_rows, Some(1_000));
            if query == "*" {
                let class = result.fields.iter().find(|field| field.name == "class_uid").unwrap();
                assert_eq!(class.top_values, vec![("6003".to_string(), RARE_SOURCE_A_EVENTS + 1)]);
                assert_eq!(class.sampled_rows, None);
            }
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3566: the drill-in for `F=*` grouped by F is the exact rollup
    /// read of `*`, never the newest-hour sample.
    #[tokio::test]
    async fn lake_field_values_presence_base_is_exact_over_the_whole_window() {
        let tenant = uuid::Uuid::from_u128(0x3567);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(RareSourceWorker { tenant: tenant.to_string() })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = rare_source_cell_view(&server, tenant, dir.path()).await;
        let result = view
            .get_field_values_for_panel(
                "metadata.log_source",
                "metadata.log_source=*",
                &twelve_hours(),
                100,
                None,
                &ScopeSet::unrestricted(),
            )
            .await
            .unwrap();
        assert!(result.sampled_window.is_none(), "exact, not the newest-hour slice");
        let values: Vec<(String, u64)> =
            result.values.iter().map(|value| (value.value.clone(), value.count)).collect();
        assert_eq!(values, vec![("audit".to_string(), RARE_SOURCE_A_EVENTS), ("otlp_log".to_string(), 1)]);
        let otlp = &result.values[1];
        assert!((otlp.percentage - 100.0 / (RARE_SOURCE_A_EVENTS + 1) as f64).abs() < 1e-9);
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3716: both field-value drill-ins (`get_field_values`, which
    /// backs `/api/fields/{name}/values`, and the sidebar's
    /// `get_field_values_for_panel`) are retention-bound on the shared lake.
    /// A wholly expired window answers empty without reaching the worker; a
    /// window straddling the cutoff reaches it only with `start >= cutoff`.
    /// On the lake the guarantee holds at two layers: `field_values_inner`'s
    /// own clamp (pinned by the search-retention static contract) and the
    /// clamped `search` it delegates to, so this proves the end-to-end
    /// behavior, not one layer alone.
    #[tokio::test]
    async fn field_values_never_read_past_the_tenant_retention_cutoff() {
        let tenant = uuid::Uuid::from_u128(0x3716);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(RareSourceWorker { tenant: tenant.to_string() })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        // Fixture retention: 90 days.
        let view = rare_source_cell_view(&server, tenant, dir.path()).await;
        let now = chrono::Utc::now();
        let cutoff = view.retention_cutoff_at(now).unwrap().expect("shared view is retained");
        assert!(cutoff < now - chrono::Duration::days(89) && cutoff > now - chrono::Duration::days(91));

        let expired = TimeRangeInput::new(now - chrono::Duration::days(200), now - chrono::Duration::days(100));
        let values = view
            .get_field_values("metadata.log_source", "*", &expired, 100, None, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert!(values.is_empty(), "expired window must answer empty");
        let panel = view
            .get_field_values_for_panel("metadata.log_source", "*", &expired, 100, None, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert!(panel.values.is_empty() && panel.sampled_window.is_none());
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "an expired field-values window must not reach the lake worker"
        );

        let straddling = TimeRangeInput::new(now - chrono::Duration::days(120), now);
        view.get_field_values("metadata.log_source", "*", &straddling, 100, None, &ScopeSet::unrestricted())
            .await
            .unwrap();
        view.get_field_values_for_panel("metadata.log_source", "*", &straddling, 100, None, &ScopeSet::unrestricted())
            .await
            .unwrap();
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.is_empty(), "a live window reaches the worker");
        for request in &requests {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            // `/v1/query` nests the window; `/v1/aggregate/count` flattens it.
            let start = body["time_range"]["start"]
                .as_str()
                .or_else(|| body["start"].as_str())
                .unwrap_or_else(|| panic!("worker request without a start bound: {body}"));
            let start = chrono::DateTime::parse_from_rfc3339(start).unwrap().with_timezone(&chrono::Utc);
            assert!(
                start >= cutoff - chrono::Duration::seconds(1),
                "{} read from {start}, before the retention cutoff {cutoff}",
                request.url.path()
            );
        }
    }

    /// NAN-4763: the debug `search` poll frames measured ~1.9 MiB under gdb
    /// on this path. `search` now boxes its inner future, so these tests fit
    /// in about 1.5 MiB. The field-list join + timeout cases are the deepest
    /// callers, so they also run on an explicit stack (not RUST_MIN_STACK)
    /// and stay clear of the default 2 MiB test thread as the search future
    /// grows.
    #[cfg(feature = "enterprise")]
    fn on_big_stack<F: std::future::Future<Output = ()> + Send + 'static>(case: F) {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(case)
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn exact_field_list_refuses_another_tenants_rollup() {
        on_big_stack(exact_field_list_refuses_another_tenants_rollup_case());
    }

    #[cfg(feature = "enterprise")]
    async fn exact_field_list_refuses_another_tenants_rollup_case() {
        let tenant = uuid::Uuid::from_u128(0x3568);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(RareSourceWorker { tenant: tenant.to_string() })
            .mount(&server).await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!("/v1/tenants/{tenant}/query/v1/aggregate/count")))
            .respond_with(RareSourceWorker { tenant: uuid::Uuid::from_u128(0x356a).to_string() })
            .expect(1).mount(&server).await;
        let dir = tempfile::tempdir().unwrap();
        let view = rare_source_cell_view(&server, tenant, dir.path()).await;
        let requested = vec!["metadata.log_source".to_string()];
        let result = view.get_field_stats_for_query(
            "*", &twelve_hours(), Some(&requested), None, None, &ScopeSet::unrestricted(),
        ).await.unwrap();
        let source = &result.fields[0];
        assert_eq!(source.sampled_rows, Some(1000));
        assert_eq!(source.top_values, vec![("audit".to_string(), 1000)]);
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn exact_field_list_timeout_keeps_the_marked_sample() {
        on_big_stack(exact_field_list_timeout_keeps_the_marked_sample_case());
    }

    #[cfg(feature = "enterprise")]
    async fn exact_field_list_timeout_keeps_the_marked_sample_case() {
        let tenant = uuid::Uuid::from_u128(0x3569);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(RareSourceWorker { tenant: tenant.to_string() })
            .mount(&server).await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path(format!("/v1/tenants/{tenant}/query/v1/aggregate/count")))
            .respond_with(wiremock::ResponseTemplate::new(500)
                .set_delay(std::time::Duration::from_secs(5)))
            .expect(2).mount(&server).await;
        let dir = tempfile::tempdir().unwrap();
        let view = rare_source_cell_view(&server, tenant, dir.path()).await;
        let requested = vec!["metadata.log_source".to_string(), "class_uid".to_string()];
        let result = tokio::time::timeout(std::time::Duration::from_secs(3),
            view.get_field_stats_for_query(
                "*", &twelve_hours(), Some(&requested), None, None, &ScopeSet::unrestricted(),
            )).await.expect("concurrent rollup timeouts must not add up").unwrap();
        assert_eq!(result.fields.len(), 2);
        assert!(result.fields.iter().all(|field| field.sampled_rows == Some(1000)));
    }

    #[test]
    fn presence_base_rewrites_only_the_grouped_fields_wildcard() {
        assert_eq!(lake_field_values_presence_base("metadata.log_source=*", "metadata.log_source"), Some("*"));
        assert_eq!(lake_field_values_presence_base("metadata.log_source=\"*\"", "metadata.log_source"), Some("*"));
        assert_eq!(lake_field_values_presence_base("class_uid=*", "metadata.log_source"), None);
        assert_eq!(lake_field_values_presence_base("metadata.log_source=audit*", "metadata.log_source"), None);
        assert_eq!(lake_field_values_presence_base("metadata.log_source!=*", "metadata.log_source"), None);
        assert_eq!(lake_field_values_presence_base("metadata.log_source=* user.name=bob", "metadata.log_source"), None);
        assert_eq!(lake_field_values_presence_base("*", "metadata.log_source"), None);
    }

    #[test]
    fn exact_values_replace_the_sample_and_the_rest_are_flagged_sampled() {
        let mut source = FieldInfo::new("metadata.log_source".into(), "string".into());
        source.count = 1_000;
        source.top_values = vec![("audit".into(), 1_000)];
        source.cardinality = Some(1);
        let mut user = FieldInfo::new("user.name".into(), "string".into());
        user.count = 10;
        user.top_values = vec![("bob".into(), 10)];
        let merged = merge_exact_field_values(
            vec![source, user],
            vec![
                ("metadata.log_source".into(), vec![("audit".into(), 1_500), ("otlp_log".into(), 1)]),
                ("class_uid".into(), vec![("6003".into(), 1_501)]),
                ("status".into(), vec![]),
            ],
            1_000,
        );
        let by_name = |name: &str| merged.iter().find(|field| field.name == name).unwrap();
        assert_eq!(by_name("metadata.log_source").top_values.len(), 2);
        assert_eq!(by_name("metadata.log_source").count, 1_501);
        assert_eq!(by_name("metadata.log_source").cardinality, Some(2));
        assert_eq!(by_name("metadata.log_source").sampled_rows, None);
        assert_eq!(by_name("class_uid").field_type, "number");
        assert_eq!(by_name("class_uid").sampled_rows, None);
        assert_eq!(by_name("user.name").sampled_rows, Some(1_000));
        assert!(merged.iter().all(|field| field.name != "status"));
    }

    #[cfg(feature = "enterprise")]
    /// `total_events` must not depend on which columns were requested: a
    /// sparse field present on 2 of 3 sampled rows still reports 3 rows.
    #[tokio::test]
    async fn lake_field_stats_sample_size_is_independent_of_sparse_columns() {
        let tenant = uuid::Uuid::from_u128(0x2773);
        let server = mounted_worker(tenant).await;
        let dir = tempfile::tempdir().unwrap();
        let view = lake_tenant_view(&server, tenant, dir.path()).await;
        let sparse = vec!["http_request.url.hostname".to_string()];
        let result = view
            .get_field_stats_for_query("*", &ocsf_window(), Some(&sparse), None, None, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert_eq!(result.fields.len(), 1);
        assert_eq!(result.fields[0].name, "http_request.url.hostname");
        assert_eq!(result.fields[0].count, 2, "only populated rows count");
        assert_eq!(result.sampled_rows, Some(3), "sample size, not the sparse field's count");
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn lake_field_stats_unknown_columns_fall_back_to_full_inventory() {
        let tenant = uuid::Uuid::from_u128(0x2772);
        let server = mounted_worker(tenant).await;
        let dir = tempfile::tempdir().unwrap();
        let view = lake_tenant_view(&server, tenant, dir.path()).await;
        let scope = ScopeSet::unrestricted();
        let full = view
            .get_field_stats_for_query("*", &ocsf_window(), None, None, None, &scope)
            .await
            .unwrap();
        // Same contract as the ClickHouse path: a stale client column list that
        // intersects nothing must not blank the field panel. Unknown names are
        // never projected, so the sample is full rows.
        let stale = vec!["src_ip".to_string(), "no_such_field".to_string()];
        let fallback = view
            .get_field_stats_for_query("*", &ocsf_window(), Some(&stale), None, None, &scope)
            .await
            .unwrap();
        // The sample inventory's order is not stable across runs (hash-map
        // backed), so compare the name sets.
        let full_names: BTreeSet<&str> = full.fields.iter().map(|field| field.name.as_str()).collect();
        let fallback_names: BTreeSet<&str> = fallback.fields.iter().map(|field| field.name.as_str()).collect();
        assert!(!fallback_names.is_empty());
        assert_eq!(fallback_names, full_names);
        assert!(worker_queries(&server).await.iter().all(|query| !query.contains("| table")));
    }

    #[test]
    fn lake_projection_requires_every_name_to_be_a_known_canonical_field() {
        let lake = crate::schema::OcsfProfile::lake_1_9();
        let cols = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(
            lake_field_stats_projection(&cols(&["metadata.log_source", "src_endpoint.ip", "metadata.log_source"]), &lake),
            Some(cols(&["metadata.log_source", "src_endpoint.ip"]))
        );
        assert_eq!(lake_field_stats_projection(&cols(&["metadata.log_source", "no_such_field"]), &lake), None);
        assert_eq!(lake_field_stats_projection(&[], &lake), None);
        assert_eq!(
            lake_field_stats_projection(&cols(&["src_ip"]), &crate::schema::UdmProfile::new()),
            None,
            "legacy profiles never project"
        );
    }

    // ── NAN-3458: open core's full events drop union-padded struct members ──

    /// The CT 106 conduit_proxy row: the lake `unmapped` struct carries the
    /// union of every key the tenant ever stored, null except the event's 4.
    fn padded_conduit_rows() -> serde_json::Value {
        serde_json::json!([{
            "time": "2026-10-09T12:00:00.000000Z",
            "class_uid": 4002,
            "severity_id": 0,
            "metadata": {"uid": "evt-3458", "log_source": "conduit_proxy", "labels": []},
            "raw_data": "{\"user\":\"alice\"}",
            "ext": {"note": null},
            "enrichments": [{"name": "geo", "value": null}],
            "unmapped": {
                "_timestamp": null, "foo": null, "Image": null,
                "winlog.event_data.TargetFilename": null,
                "winlog": {"event_data": {"Image": null}, "channel": null},
                "bytes_out": "1824", "status": "200", "url": "https://a.example/login", "user": "alice",
            },
        }])
    }

    fn sparse_conduit_row() -> serde_json::Value {
        serde_json::json!({
            "time": "2026-10-09T12:00:00.000000Z",
            "class_uid": 4002,
            "severity_id": 0,
            "metadata": {"uid": "evt-3458", "log_source": "conduit_proxy"},
            "raw_data": "{\"user\":\"alice\"}",
            "enrichments": [{"name": "geo"}],
            "unmapped": {"bytes_out": "1824", "status": "200", "url": "https://a.example/login", "user": "alice"},
        })
    }

    #[cfg(feature = "enterprise")]
    /// Open core's search process: a DEDICATED (non-shared) SearchService
    /// whose log reads are the primary lake (`NANO_LOG_QUERY_BACKEND=lake`,
    /// served by the generation manager's query worker).
    async fn open_core_dedicated_lake_view(server: &wiremock::MockServer, dir: &std::path::Path) -> SearchService {
        let tenant = uuid::Uuid::from_u128(0x3458);
        let credential = dir.join("worker-token");
        std::fs::write(&credential, "field-stats-worker-token-0123456789abcdef").unwrap();
        let assignment = crate::search::SharedLakeWorkerAssignment {
            tenant_id: tenant,
            internal_endpoint: server.uri(),
            credential_file: credential,
            expected_worker_identity: "field-stats-worker".to_string(),
            expected_worker_revision: 1,
            timeout_secs: 10,
            prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots {
                one_hour: "p1".into(),
                twenty_four_hours: "p24".into(),
                seven_days: "p7".into(),
                thirty_days: "p30".into(),
            },
            prevalence_rarity_threshold: 3,
            prevalence_timeout_secs: 10,
            enrichment_coordinator: None,
            otel_ingest: None,
            erasure_executor: None,
        };
        let dual_pool = crate::db::DualPool::new_lake_control_plane(
            &crate::db::DualPoolConfig::with_auth(
                "postgres://fixture:fixture@127.0.0.1:1/never_connect",
                "http://127.0.0.1:1",
                "fixture",
                "fixture",
                "fixture",
            ),
        )
        .await
        .unwrap();
        let mut service = SearchService::with_dual_pool_and_profile_unrouted(
            &dual_pool,
            std::sync::Arc::new(crate::schema::OcsfProfile::lake_1_9()),
        );
        service.lake_query =
            crate::search::lake::LakeQueryRuntime::from_enterprise_shared_assignment(&assignment).unwrap();
        server
            .register(
                wiremock::Mock::given(wiremock::matchers::method("POST"))
                    .and(wiremock::matchers::path("/v1/query"))
                    .respond_with(EchoLakeWorker { tenant: tenant.to_string(), rows: padded_conduit_rows() }),
            )
            .await;
        service
    }

    #[cfg(feature = "enterprise")]
    /// `POST /api/search/log` -> `fetch_log_by_id` on open core.
    #[tokio::test]
    async fn open_core_expanded_full_event_drops_padded_unmapped_members() {
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let service = open_core_dedicated_lake_view(&server, dir.path()).await;
        let event = service
            .fetch_log_by_id("evt-3458", Some(&ocsf_window()), Some("conduit_proxy"), &ScopeSet::unrestricted())
            .await
            .unwrap()
            .expect("one event");
        assert_eq!(event, sparse_conduit_row());
    }

    #[cfg(feature = "enterprise")]
    /// Non-table-view `POST /api/search` -> `search_with_admission` on open
    /// core: the rows the web marks `fullEvent` and shows in the inspector.
    /// Table-view rows keep their shape. Run on a 32 MiB stack: the debug
    /// `search` future outgrows the 2 MiB test thread.
    #[test]
    fn open_core_full_event_result_rows_drop_padded_unmapped_members() {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(open_core_full_event_result_rows_case())
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "enterprise")]
    async fn open_core_full_event_result_rows_case() {
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let service = open_core_dedicated_lake_view(&server, dir.path()).await;
        let mut request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "user=alice",
            "time_range": {"start": chrono::Utc::now() - chrono::Duration::hours(1), "end": chrono::Utc::now()},
            "skip_histogram": true,
            "skip_field_stats": true,
            "table_view": false,
        }))
        .unwrap();
        let response = service
            .search_with_admission(request.clone(), uuid::Uuid::nil(), crate::search::QueryPriority::Interactive, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert_eq!(response.results, vec![sparse_conduit_row()]);

        request.table_view = true;
        let response = service
            .search_with_admission(request, uuid::Uuid::nil(), crate::search::QueryPriority::Interactive, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert_eq!(serde_json::Value::Array(response.results), padded_conduit_rows());
    }
}
