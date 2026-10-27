// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::auth::ScopeSet;
use crate::query::{
    Comparator, EvalAssignment, EvalExpression, PrettyPrint, SearchExpr, TableField, Value,
};
use crate::search::lake::LakeCountPredicate;
use crate::search::query_processing::{
    apply_profile_product_semantics, enforce_source_scope, enforce_source_scope_with_field,
    strip_lake_source_scope_gate,
};
use base64::Engine;
use std::collections::{BTreeMap, BTreeSet};

/// NAN-4291 (F6): the query an expired window runs instead of returning no
/// rows, or `None` when no rows is already the query's answer. An ungrouped
/// `stats` / `chart` returns one row over zero input rows, so a pipeline of
/// row-local commands around one is kept with its search ANDed with `NOT *`
/// (matches nothing) and the engine computes exactly what it would over an
/// empty window. Pipelines with a subsearch (join, append, `IN [search …]`) or
/// any other command keep the empty answer: their other inputs are windowed
/// too and would read the substituted window.
fn expired_window_aggregate_query(query: &Query) -> Option<Query> {
    fn has_subsearch(expr: &SearchExpr) -> bool {
        match expr {
            SearchExpr::InSubsearch { .. } => true,
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                has_subsearch(left) || has_subsearch(right)
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => has_subsearch(inner),
            _ => false,
        }
    }
    let mut ungrouped = false;
    let mut cursor = query;
    let base = loop {
        match cursor {
            Query::Search(expr) => break expr,
            Query::Piped { source, command } => {
                match command {
                    Command::Stats { group_by, .. } | Command::Chart { group_by, .. } => {
                        ungrouped |= group_by.as_ref().is_none_or(|fields| fields.is_empty());
                    }
                    Command::Where { condition } if !has_subsearch(condition) => {}
                    Command::Eval { .. }
                    | Command::Sort { .. }
                    | Command::Head { .. }
                    | Command::Tail { .. }
                    | Command::Table { .. }
                    | Command::Fields { .. }
                    | Command::Rename { .. }
                    | Command::Fillnull { .. }
                    | Command::Rex { .. }
                    | Command::Dedup { .. }
                    | Command::Bin { .. }
                    | Command::Spath { .. }
                    | Command::Mvexpand { .. }
                    | Command::Reverse
                    | Command::Top { .. }
                    | Command::Rare { .. }
                    | Command::EventStats { .. }
                    | Command::StreamStats { .. } => {}
                    _ => return None,
                }
                cursor = source;
            }
        }
    };
    if !ungrouped || has_subsearch(base) {
        return None;
    }
    let mut rewritten = query.clone();
    let mut cursor = &mut rewritten;
    loop {
        match cursor {
            Query::Search(expr) => {
                let matched = std::mem::replace(expr, SearchExpr::Keyword("*".to_string()));
                *expr = SearchExpr::And(
                    Box::new(SearchExpr::Group(Box::new(matched))),
                    Box::new(SearchExpr::Not(Box::new(SearchExpr::Keyword("*".to_string())))),
                );
                return Some(rewritten);
            }
            Query::Piped { source, .. } => cursor = source,
        }
    }
}

fn command_page_marker(query: &Query) -> Result<serde_json::Value, SearchError> {
    let marker = match get_semantic_terminal_command(query) {
        Some(Command::Services) => serde_json::json!({
            "_display_type": "services",
        }),
        Some(Command::Service { name }) => serde_json::json!({
            "_display_type": "service",
            "_service": name,
        }),
        Some(Command::Trace { trace_id }) => serde_json::json!({
            "_display_type": "trace",
            "_trace_id": trace_id,
        }),
        Some(Command::Metric { name, service }) => serde_json::json!({
            "_display_type": "metric",
            "_metric": name,
            "_metric_service": service.clone().unwrap_or_default(),
        }),
        Some(Command::Retro { .. }) => match super::retro::extract_retro_plan(query) {
            Some(plan) => super::retro::build_retro_marker(&plan),
            None => {
                return Err(SearchError::SqlValidationError(
                    "`retro` needs a leading `ioc` term — e.g. \
                     `ioc=\"1.2.3.4\" | retro` or `ioc in threatfox(\"apt29\") | \
                     retro by asset`."
                        .to_string(),
                ));
            }
        },
        _ => serde_json::json!({ "_display_type": "events" }),
    };
    Ok(marker)
}

/// The asset view is a single synthetic row carrying the real event total in
/// `_asset_pagination.total_count`. Lift it so `SearchResponse.total_count`
/// (and therefore the footer "N hits") reflects the true count instead of the
/// placeholder `1` / the initial-scan count (NAN-1601). Returns `None` when the
/// results aren't an asset view.
fn asset_view_total_count(results: &[serde_json::Value]) -> Option<u64> {
    results
        .first()
        .and_then(|r| r.get("_asset_pagination"))
        .and_then(|p| p.get("total_count"))
        .and_then(|v| v.as_u64())
}

/// A lake event page intentionally fetches only `limit + 1` rows, but its
/// histogram already counts the complete base predicate over the same time
/// range. Use that exact companion count instead of exposing the page sentinel
/// as "51 hits". This is valid only for the direct event path, before any Rust
/// post-processing can change membership.
pub(super) fn attach_lake_histogram(
    response: &mut SearchResponse,
    histogram: Vec<HistogramBucket>,
    counts_result_rows: bool,
) {
    if counts_result_rows {
        response.total_count = histogram.iter().map(|bucket| bucket.count).sum();
        // NAN-2550: the histogram counts the complete base predicate, so this
        // response now carries an exact total. Flipping the flag is the whole
        // correction -- there is no warning left to strip.
        response.total_count_exact = true;
    }
    // Otherwise (`where`/`dedup`/… after the base search) the histogram is
    // the base events' timeline, and its sum is not this result's size.
    response.histogram = Some(histogram);
}

/// One lake histogram companion: the base-search text (its part before the
/// first pipe is what `generate_histogram` counts), the window, the derived
/// `{query_id}-hist` id, and the scope deny set.
type LakeHistogramPlan = (
    String,
    TimeRangeInput,
    String,
    std::collections::BTreeSet<String>,
);

/// The histogram companion for a primary-lake log search, or `None` when the
/// request skips it, is not a first page, or the UI never renders the
/// timeline for this pipeline (see `lake_histogram_applies`).
fn lake_histogram_plan(
    request: &SearchRequest,
    request_dataset: crate::query::Dataset,
    parsed: &Query,
    query_id: &str,
    scope: &ScopeSet,
    histogram_only: bool,
) -> Option<LakeHistogramPlan> {
    (!request.skip_histogram
        // Event tables get their exact total from the standalone companion.
        && (histogram_only
            || !request.table_view
            || !super::lake_histogram_counts_result_rows(parsed))
        && request_dataset == crate::query::Dataset::Logs
        && crate::search::execution::clickhouse_executor::is_first_page(
            request.offset.unwrap_or(0),
        )
        && super::lake_histogram_applies(parsed))
    .then(|| {
        (
            parsed.pretty_print(),
            request.time_range.clone(),
            format!("{query_id}-hist"),
            scope.deny_set().clone(),
        )
    })
}

/// Attach a finished histogram companion (or log its failure). A failed
/// companion never fails the search: the timeline is simply absent.
fn attach_lake_histogram_result(
    response: &mut SearchResponse,
    histogram: Option<Result<Vec<HistogramBucket>, SearchError>>,
    counts_result_rows: bool,
) {
    match histogram {
        Some(Ok(histogram)) => attach_lake_histogram(response, histogram, counts_result_rows),
        Some(Err(error)) => tracing::warn!(%error, "lake histogram query failed"),
        None => {}
    }
}

/// NAN-3093: the answer of a histogram-only view ([`SearchService::histogram_only`]):
/// no rows, the timeline (absent when the search renders none), and the
/// exact total only when the histogram's sum is the result's row count.
fn histogram_only_response(
    histogram: Option<Result<Vec<HistogramBucket>, SearchError>>,
    counts_result_rows: bool,
    display_type: DisplayType,
    start_time: Instant,
) -> Result<SearchResponse, SearchError> {
    let mut response = SearchResponse::empty();
    response.total_count_exact = false;
    match histogram {
        Some(Ok(histogram)) => attach_lake_histogram(&mut response, histogram, counts_result_rows),
        // The standalone endpoint has nothing else to show, so a failed
        // companion is the caller's error rather than a silent blank.
        Some(Err(error)) => return Err(error),
        None => {}
    }
    response.display_type = Some(display_type);
    response.execution_time_ms = start_time.elapsed().as_millis() as u64;
    Ok(response)
}

/// NAN-1691 interim safety: any prevalence FILTER that still falls to the in-memory
/// fetch-then-filter path (aggregation-before-prevalence, first_seen conditions, or a
/// non-ClickHouse backend) is hard-capped to this many pre-filter rows. Far below what
/// fits in the 2Gi search pod, so a missed pushdown degrades to approximate results
/// instead of OOM-killing the shared pod. The primary path (use_prevalence_join) pushes
/// the filter into SQL and never hits this.
const IN_MEMORY_PREVALENCE_FETCH_CAP: usize = 50_000;
use super::lake_identity::LAKE_IDENTITY_BATCH_CAP;
// The existing envelope bounds pagination; the worker enforces scan, memory,
// and execution budgets. Keep in-process async searches within one day.
const LAKE_INTERACTIVE_WINDOW_HOURS: i64 = 24;
/// Rows per query[T] page when a lean-cell raw-event result is paged
/// (NAN-3046); a page is halved on a memory refusal.
pub(crate) const LAKE_PAGE_ROWS: usize = 2_000;
/// Raw JSON a synchronous (non-streamed) paged answer may gather in this
/// process; past it the request is escalated to a durable job.
const LAKE_PAGED_SYNC_MAX_BYTES: usize = 256 * 1024 * 1024;

tokio::task_local! {
    /// Installed by the SSE path: paged lean-cell rows are sent here as they
    /// arrive instead of being gathered into the response.
    pub(crate) static LAKE_ROW_SINK: tokio::sync::mpsc::Sender<Vec<serde_json::Value>>;
}
const LAKE_LOOKUP_MEMBERSHIP_PUSHDOWN_MAX: usize = 4_096;
const LAKE_INLINE_LOOKUP_MAX_ROWS: i64 = 100;
/// NAN-4287: the supported way to hunt a lookup/IOC list on the lake, named
/// by every refusal of a nested lookup shape.
pub const LAKE_LOOKUP_ALTERNATIVE: &str = "To match events against a lookup or IOC list, use it in the outer pipeline: `<search> | lookup <table> <key> AS <event field> OUTPUT <column> | where isnotnull(<column>)` (lists up to 4,096 keys are pushed into the scan), or search the IOC fields stamped at ingest.";
const LAKE_INLINE_LOOKUP_MAX_QUERY_BYTES: usize = 192 * 1_024;
const LAKE_DASHBOARD_BREAKDOWN_FIELD: &str = "__nano.dashboard_breakdown";
/// The log-source column every count rollup row is keyed by.
const LAKE_SOURCE_FIELD: &str = "metadata.log_source";
/// NAN-3153: a lean cell answers a grouped `stats count by …` page from the
/// count rollups only up to this many complete groups; a larger answer is
/// refused by the worker and the bounded compiled page (NAN-3077) runs
/// instead, so a wide group set is never materialized and transferred.
const LAKE_CELL_ROLLUP_PAGE_MAX_GROUPS: usize = 10_000;
const LAKE_DASHBOARD_BREAKDOWN_COMPONENTS: &[&str] =
    &["severity", "class_name", "metadata.log_source"];

fn interactive_lake_eligible(
    request: &SearchRequest,
    priority: super::admission::QueryPriority,
    max_limit: usize,
) -> bool {
    let duration = request.time_range.end - request.time_range.start;
    let Ok((_, earliest, latest)) = extract_time_bounds(&request.query) else { return false; };
    matches!(
        priority,
        super::admission::QueryPriority::Interactive | super::admission::QueryPriority::Analytics
    ) && duration > chrono::Duration::zero()
        && duration <= chrono::Duration::hours(LAKE_INTERACTIVE_WINDOW_HOURS)
        && request
            .offset
            .unwrap_or(0)
            .saturating_add(request.limit.unwrap_or(100))
            <= max_limit
        && earliest.is_none()
        && latest.is_none()
        && !request.query.split('|').any(|part| {
            matches!(
                part.trim().split_whitespace().next(),
                Some("export" | "retro")
            )
        })
}

fn interactive_lake_fallback(error: &SearchError) -> bool {
    matches!(
        error,
        SearchError::ResourceExhausted(_)
            | SearchError::ServiceUnavailable(_)
            | SearchError::LakeWorkerNotReady(_)
            | SearchError::Timeout(_)
            | SearchError::TenantLakePublicationDegraded(_)
            | SearchError::SearchAdmissionUnavailable(_)
    )
}

/// A durable lake search currently publishes the query worker's SQL result
/// directly as Parquet. It cannot run the Nano-side suffix that the
/// interactive path applies after the lake read. Reject that shape before a
/// job is admitted so resource escalation never turns a correct interactive
/// query into a silently incomplete durable result.
pub(super) fn validate_durable_lake_sql_only_query(query_text: &str) -> Result<(), SearchError> {
    let parsed = parse_query(query_text).map_err(convert_parse_error)?;
    if !contains_lake_post_processing_anywhere(&parsed) {
        return Ok(());
    }
    Err(SearchError::SqlValidationError(
        DURABLE_LANE_POST_PROCESSING_REFUSAL.to_string(),
    ))
}

/// The durable lane's refusal of a query with Nano-side stages.
pub const DURABLE_LANE_POST_PROCESSING_REFUSAL: &str =
    "this query contains Nano-side enrichment or state that the durable SQL-only lane cannot preserve yet; it was not queued";

/// NAN-3071: whether `error` is the durable lane refusing a query because it
/// has Nano-side stages. An escalation that ends here must not replace the
/// interactive lane's real failure (the budget it exhausted) with this text.
pub fn is_durable_lane_post_processing_refusal(error: &SearchError) -> bool {
    matches!(error, SearchError::SqlValidationError(message) if message == DURABLE_LANE_POST_PROCESSING_REFUSAL)
}

/// A Nano-side stage nested below a subsearch boundary cannot be lifted into
/// the outer interactive suffix without changing append/join/membership
/// semantics. Refuse the shape instead of letting the SQL generator's legacy
/// pass-through behavior produce a plausible but incomplete answer.
fn validate_lake_nested_post_processing(query: &Query) -> Result<(), SearchError> {
    // NAN-3311: every command after the first Nano-side stage runs in the Rust
    // evaluator. Refuse one it cannot run BEFORE the worker scan, instead of
    // dropping it and answering 200 with rows the query did not ask for.
    let (_, suffix) = split_lake_post_processing(query);
    if let Some(command) = suffix.iter().find(|command| {
        !crate::search::processing::post_processing::is_supported_post_processing_command(command)
    }) {
        return Err(SearchError::SqlValidationError(
            crate::search::processing::post_processing::unsupported_post_processing_command_message(
                command,
            ),
        ));
    }
    if !contains_nested_lake_post_processing(query) {
        return Ok(());
    }
    Err(SearchError::SqlValidationError(format!(
        "Nano-side lookup, prevalence, inputlookup, identity, or AI stages are not supported inside lake subsearches; move the stage to the outer pipeline or run the subsearch separately. {LAKE_LOOKUP_ALTERNATIVE}"
    )))
}

/// Whether a Nano-side suffix must see a bounded candidate set before caller
/// pagination is applied. Enrichment and row-local projection commute with
/// pagination; membership, ordering, cardinality and aggregate stages do not.
///
/// The old `post_commands.len() > 1` shortcut classified even
/// `lookup | rename` and two enrich-only prevalence stages as global work. In
/// primary-lake mode that expanded a 50-row page into 50,000 complete OCSF
/// events, producing multi-gigabyte native result buffers for a row-local
/// operation.
fn lake_post_processing_needs_candidate_set(commands: &[Command]) -> bool {
    commands.iter().any(|command| match command {
        Command::Prevalence { conditions, .. } => !conditions.is_empty(),
        Command::Lookup { .. }
        | Command::ResolveIdentity { .. }
        | Command::Ai { .. }
        | Command::Rename { .. }
        | Command::Eval { .. }
        | Command::Rex { .. }
        | Command::Fields { .. }
        | Command::Table { .. }
        | Command::Fillnull { .. }
        | Command::Spath { .. }
        | Command::Bin { .. }
        | Command::Risk { .. }
        | Command::Output { .. } => false,
        Command::InputLookup { key_field, .. } => key_field.is_none(),
        Command::Where { .. }
        | Command::Sort { .. }
        | Command::Head { .. }
        | Command::Tail { .. }
        | Command::Stats { .. }
        | Command::Chart { .. }
        | Command::StreamStats { .. }
        | Command::Timechart { .. }
        | Command::Dedup { .. }
        | Command::Top { .. }
        | Command::Rare { .. }
        | Command::Transaction { .. }
        | Command::Mvexpand { .. }
        | Command::Append { .. }
        | Command::Join { .. }
        | Command::Format { .. }
        | Command::Return { .. }
        | Command::Sample { .. }
        | Command::Reverse
        | Command::EventStats { .. }
        | Command::Sequence { .. }
        | Command::Funnel { .. }
        | Command::Anomaly { .. }
        | Command::Tree { .. }
        | Command::Asset { .. }
        | Command::Cloud { .. }
        | Command::Lateral { .. }
        | Command::Services
        | Command::Service { .. }
        | Command::Trace { .. }
        | Command::Metric { .. }
        | Command::Retro { .. }
        | Command::Baseline { .. } => true,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LookupMembershipPushdown {
    table_name: String,
    event_field: String,
    key_field: String,
    case_insensitive: bool,
}

/// Recognize the exact SPL membership shape
/// `| lookup table event AS key | where isnotnull(output)`.
///
/// The suffix still runs after the lake read and therefore preserves all
/// enrichment columns. Resolving the lookup keys ahead of the read only adds
/// an equivalent event-field membership predicate, which prevents a small IOC
/// table from forcing a 50k raw-event candidate materialization.
fn lookup_membership_pushdown(query: &Query) -> Option<LookupMembershipPushdown> {
    fn commands<'a>(query: &'a Query, output: &mut Vec<&'a Command>) {
        if let Query::Piped { source, command } = query {
            commands(source, output);
            output.push(command);
        }
    }

    fn is_not_null_field(condition: &SearchExpr) -> Option<&str> {
        let SearchExpr::BooleanFunction(EvalExpression::FunctionCall { name, args }) = condition
        else {
            return None;
        };
        if !matches!(
            name.to_ascii_lowercase().as_str(),
            "isnotnull" | "is_not_null"
        ) {
            return None;
        }
        match args.as_slice() {
            [EvalExpression::Field(field)] => Some(field),
            _ => None,
        }
    }

    let mut pipeline = Vec::new();
    commands(query, &mut pipeline);
    pipeline.windows(2).find_map(|pair| {
        let Command::Lookup {
            table_name,
            event_field,
            key_field,
            output_fields,
            output_renames,
            output_new,
            case_insensitive,
        } = pair[0]
        else {
            return None;
        };
        let Command::Where { condition } = pair[1] else {
            return None;
        };
        if *output_new || !output_renames.is_empty() {
            return None;
        }
        let tested_field = is_not_null_field(condition)?;
        if output_fields
            .as_ref()
            .is_some_and(|fields| !fields.iter().any(|field| field == tested_field))
        {
            return None;
        }
        Some(LookupMembershipPushdown {
            table_name: table_name.clone(),
            event_field: event_field.clone(),
            key_field: key_field.clone(),
            case_insensitive: *case_insensitive,
        })
    })
}

fn inject_lake_base_membership(query: &mut Query, field: String, values: Vec<Value>) {
    match query {
        Query::Search(expression) => {
            *expression = SearchExpr::And(
                Box::new(expression.clone()),
                Box::new(SearchExpr::InList {
                    field,
                    values,
                    negated: false,
                }),
            );
        }
        Query::Piped { source, .. } => inject_lake_base_membership(source, field, values),
    }
}

async fn push_down_lake_lookup_membership(
    query: &mut Query,
    lookup_service: Option<&crate::lookup::LookupService>,
) -> Result<bool, SearchError> {
    let Some(pushdown) = lookup_membership_pushdown(query) else {
        return Ok(false);
    };
    let Some(lookup_service) = lookup_service else {
        return Ok(false);
    };
    let rows = match lookup_service.read_all_rows(&pushdown.table_name).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::warn!(
                table = %pushdown.table_name,
                error = %error,
                "lookup membership pushdown could not read the lookup snapshot"
            );
            return Ok(false);
        }
    };
    if rows.len() > LAKE_LOOKUP_MEMBERSHIP_PUSHDOWN_MAX {
        return Ok(false);
    }
    let mut seen = std::collections::HashSet::new();
    let mut values = Vec::new();
    for row in rows {
        let Some(raw) = row.get(&pushdown.key_field) else {
            continue;
        };
        let value = match raw {
            serde_json::Value::String(value) => {
                let value = value.trim();
                if value.is_empty() {
                    continue;
                }
                Value::String(if pushdown.case_insensitive {
                    value.to_ascii_lowercase()
                } else {
                    value.to_string()
                })
            }
            serde_json::Value::Number(value) => {
                let Some(value) = value.as_f64() else {
                    continue;
                };
                Value::Number(value)
            }
            serde_json::Value::Bool(value) => Value::Bool(*value),
            _ => continue,
        };
        let identity = value.to_string().to_ascii_lowercase();
        if seen.insert(identity) {
            values.push(value);
        }
    }
    if values.is_empty() {
        return Ok(false);
    }
    inject_lake_base_membership(query, pushdown.event_field, values);
    Ok(true)
}

/// NAN-3466: orient every `| lookup` against its table's real columns.
///
/// The parser cannot see the table, so for `lookup <a> AS <b>` it guesses
/// which side is the event field with the UDM profile: `user` is a UDM
/// column, so `lookup users user AS u` (after `eval u=user.name`) became
/// "table column `u`, event field `user`" and failed with "does not contain
/// key column 'u'" on OCSF. Once the table is known the answer is exact: when
/// the parsed key is not a table column but the parsed event field is, the
/// two sides are swapped. Every other pair (both or neither are columns, or
/// an unreadable registry) keeps the parsed order and its existing errors.
async fn orient_lookup_keys(
    query: &mut Query,
    lookup_service: Option<&crate::lookup::LookupService>,
) {
    fn visit_expr(expr: &mut SearchExpr, f: &mut dyn FnMut(&mut Command)) {
        match expr {
            SearchExpr::InSubsearch { subsearch, .. } => visit(subsearch, f),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                visit_expr(left, f);
                visit_expr(right, f);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => visit_expr(inner, f),
            _ => {}
        }
    }
    fn visit(query: &mut Query, f: &mut dyn FnMut(&mut Command)) {
        match query {
            Query::Search(expr) => visit_expr(expr, f),
            Query::Piped { source, command } => {
                visit(source, f);
                match command {
                    Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
                        visit(subsearch, f)
                    }
                    Command::Where { condition } => visit_expr(condition, f),
                    _ => {}
                }
                f(command);
            }
        }
    }

    let Some(lookup_service) = lookup_service else {
        return;
    };
    let mut tables = std::collections::BTreeSet::new();
    visit(query, &mut |command| {
        if let Command::Lookup { table_name, .. } = command {
            tables.insert(table_name.clone());
        }
    });
    let mut columns = std::collections::HashMap::new();
    for table_name in tables {
        // A missing table keeps the parsed order; `validate_lookup_tables`
        // reports it with the available table names.
        if let Ok(table) = lookup_service.get_table(&table_name).await {
            columns.insert(
                table_name,
                table
                    .columns
                    .into_iter()
                    .map(|column| column.name)
                    .collect::<std::collections::HashSet<_>>(),
            );
        }
    }
    visit(query, &mut |command| {
        if let Command::Lookup {
            table_name,
            event_field,
            key_field,
            ..
        } = command
        {
            if let Some(columns) = columns.get(table_name.as_str()) {
                orient_lookup_pair(columns, key_field, event_field);
            }
        }
    });
}

/// Swap a parsed `(key_field, event_field)` pair when only the event side
/// names a column of the lookup table (see [`orient_lookup_keys`]).
fn orient_lookup_pair(
    columns: &std::collections::HashSet<String>,
    key_field: &mut String,
    event_field: &mut String,
) {
    if !columns.contains(key_field.as_str()) && columns.contains(event_field.as_str()) {
        std::mem::swap(key_field, event_field);
    }
}

/// Replace small, scalar lookup-table joins with worker-native `eval case(...)`
/// assignments. This lets every downstream `where`/`stats`/`sort` stage run in
/// chDB over the complete lake input instead of applying Nano's 50k candidate
/// envelope after the scan.
///
/// The lookup registry remains authoritative in PostgreSQL. Only a bounded,
/// already-validated snapshot is embedded in the tenant-pinned query. Larger
/// tables, repeated event fields, heterogeneous JSON values, duplicate keys,
/// or a query that would approach the worker text fence retain the existing
/// Nano-side path and its explicit approximation warning.
async fn inline_small_lake_lookups(
    query: &mut Query,
    lookup_service: Option<&crate::lookup::LookupService>,
    profile: &dyn crate::schema::SchemaProfile,
) -> Result<usize, SearchError> {
    fn collect_expr(expr: &SearchExpr, commands: &mut Vec<Command>) {
        match expr {
            SearchExpr::InSubsearch { subsearch, .. } => collect(subsearch, commands),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                collect_expr(left, commands);
                collect_expr(right, commands);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => collect_expr(inner, commands),
            _ => {}
        }
    }

    fn collect_nested(command: &Command, commands: &mut Vec<Command>) {
        match command {
            Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
                collect(subsearch, commands)
            }
            Command::Where { condition } => collect_expr(condition, commands),
            Command::Transaction { startswith, endswith, .. } => {
                if let Some(expr) = startswith { collect_expr(expr, commands); }
                if let Some(expr) = endswith { collect_expr(expr, commands); }
            }
            Command::Sequence { conditions, .. } => {
                for expr in conditions { collect_expr(expr, commands); }
            }
            Command::Funnel { steps, .. } => {
                for (_, expr) in steps { collect_expr(expr, commands); }
            }
            _ => {}
        }
    }

    fn collect(query: &Query, commands: &mut Vec<Command>) {
        match query {
            Query::Search(expr) => collect_expr(expr, commands),
            Query::Piped { source, command } => {
                collect(source, commands);
                collect_nested(command, commands);
                if matches!(command, Command::Lookup { .. }) {
                    commands.push(command.clone());
                }
            }
        }
    }

    fn replace_expr(
        expr: &mut SearchExpr,
        replacements: &mut std::collections::VecDeque<Option<Vec<EvalAssignment>>>,
    ) {
        match expr {
            SearchExpr::InSubsearch { subsearch, .. } => replace(subsearch, replacements),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                replace_expr(left, replacements);
                replace_expr(right, replacements);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => replace_expr(inner, replacements),
            _ => {}
        }
    }

    fn replace_nested(
        command: &mut Command,
        replacements: &mut std::collections::VecDeque<Option<Vec<EvalAssignment>>>,
    ) {
        match command {
            Command::Join { subsearch, .. } | Command::Append { subsearch, .. } => {
                replace(subsearch, replacements)
            }
            Command::Where { condition } => replace_expr(condition, replacements),
            Command::Transaction { startswith, endswith, .. } => {
                if let Some(expr) = startswith { replace_expr(expr, replacements); }
                if let Some(expr) = endswith { replace_expr(expr, replacements); }
            }
            Command::Sequence { conditions, .. } => {
                for expr in conditions { replace_expr(expr, replacements); }
            }
            Command::Funnel { steps, .. } => {
                for (_, expr) in steps { replace_expr(expr, replacements); }
            }
            _ => {}
        }
    }

    fn replace(
        query: &mut Query,
        replacements: &mut std::collections::VecDeque<Option<Vec<EvalAssignment>>>,
    ) {
        match query {
            Query::Search(expr) => replace_expr(expr, replacements),
            Query::Piped { source, command } => {
                replace(source, replacements);
                replace_nested(command, replacements);
                if matches!(command, Command::Lookup { .. }) {
                    if let Some(Some(assignments)) = replacements.pop_front() {
                        *command = Command::Eval { assignments };
                    }
                }
            }
        }
    }

    let Some(lookup_service) = lookup_service else {
        return Ok(0);
    };
    let mut commands = Vec::new();
    collect(query, &mut commands);
    if commands.is_empty() {
        return Ok(0);
    }

    let mut replacements = std::collections::VecDeque::with_capacity(commands.len());
    let mut replacement_count = 0_usize;
    for command in commands {
        let Command::Lookup {
            table_name,
            event_field,
            key_field,
            output_fields,
            output_renames,
            output_new,
            case_insensitive,
        } = command
        else {
            unreachable!("collector only returns lookup commands");
        };

        if output_new || !output_renames.is_empty() || profile.is_string_array_field(&event_field) {
            replacements.push_back(None);
            continue;
        }
        let table = match lookup_service.get_table(&table_name).await {
            Ok(table) => table,
            Err(error) => {
                tracing::warn!(
                    table = %table_name,
                    error = %error,
                    "small lake lookup could not read registry metadata"
                );
                replacements.push_back(None);
                continue;
            }
        };
        let page = match lookup_service
            .list_rows(&table_name, 1, LAKE_INLINE_LOOKUP_MAX_ROWS)
            .await
        {
            Ok(page) => page,
            Err(error) => {
                tracing::warn!(
                    table = %table_name,
                    error = %error,
                    "small lake lookup could not read its bounded snapshot"
                );
                replacements.push_back(None);
                continue;
            }
        };
        if page.total < 0
            || page.total > LAKE_INLINE_LOOKUP_MAX_ROWS
            || page.rows.len() != usize::try_from(page.total).unwrap_or(usize::MAX)
        {
            replacements.push_back(None);
            continue;
        }

        if let Some(assignments) = build_inline_lookup_assignments(
            &table,
            &event_field,
            &key_field,
            output_fields.as_deref(),
            case_insensitive,
            page.rows,
        ) {
            replacement_count = replacement_count.saturating_add(1);
            replacements.push_back(Some(assignments));
        } else {
            replacements.push_back(None);
        }
    }

    if replacement_count == 0 {
        return Ok(0);
    }
    let mut candidate = query.clone();
    replace(&mut candidate, &mut replacements);
    let rendered = candidate.pretty_print();
    if rendered.len() > LAKE_INLINE_LOOKUP_MAX_QUERY_BYTES {
        return Ok(0);
    }
    let reparsed = parse_query(&rendered).map_err(convert_parse_error)?;
    if reparsed != candidate {
        tracing::warn!(
            "small lake lookup rewrite did not round-trip byte-exactly; retaining Nano-side execution"
        );
        return Ok(0);
    }
    *query = reparsed;
    Ok(replacement_count)
}

fn null_eval_expression() -> EvalExpression {
    EvalExpression::FunctionCall {
        name: "null".to_string(),
        args: Vec::new(),
    }
}

/// Nano's post-inputlookup stats use their Rust default alias (`Count`) rather
/// than the SQL generator's default (`count`). Carry that output spelling into
/// downstream cell-native aggregations after an internal snapshot is inlined.
fn align_stats_aliases_expr(expr: &mut SearchExpr) -> bool {
    match expr {
        SearchExpr::InSubsearch { subsearch, .. } => align_stats_aliases(subsearch),
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            let left = align_stats_aliases_expr(left);
            align_stats_aliases_expr(right) || left
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => align_stats_aliases_expr(inner),
        _ => false,
    }
}
fn align_stats_aliases(query: &mut Query) -> bool {
    match query {
        Query::Search(expr) => align_stats_aliases_expr(expr),
        Query::Piped { source, command } => {
            let mut contains_inline = align_stats_aliases(source);
            contains_inline |= match command {
                Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
                    align_stats_aliases(subsearch)
                }
                Command::Where { condition } => align_stats_aliases_expr(condition),
                Command::Transaction {
                    startswith,
                    endswith,
                    ..
                } => {
                    let start = startswith.as_mut().is_some_and(align_stats_aliases_expr);
                    endswith.as_mut().is_some_and(align_stats_aliases_expr) || start
                }
                Command::Sequence { conditions, .. } => conditions
                    .iter_mut()
                    .fold(false, |found, expr| align_stats_aliases_expr(expr) || found),
                Command::Funnel { steps, .. } => {
                    steps.iter_mut().fold(false, |found, (_, expr)| {
                        align_stats_aliases_expr(expr) || found
                    })
                }
                _ => false,
            };
            if let Command::Eval { assignments } = command {
                contains_inline |= assignments
                    .iter()
                    .any(|assignment| assignment.field.starts_with("__nano_il_match_"));
            }
            if contains_inline {
                if let Command::Stats { aggregations, .. } | Command::Chart { aggregations, .. } =
                    command
                {
                    for aggregation in aggregations {
                        if aggregation.alias.is_none() {
                            aggregation.alias = Some(
                                aggregation
                                    .field
                                    .clone()
                                    .unwrap_or_else(|| format!("{:?}", aggregation.func)),
                            );
                        }
                    }
                }
            }
            contains_inline
        }
    }
}

/// Inline a bounded tenant lookup snapshot before sending a nested subsearch to
/// query[T]. The intermediate names are unique to this rewrite, so a source
/// event's pre-existing `inputlookup_*` fields remain available for the merge.
async fn inline_nested_lake_inputlookups(
    query: &mut Query,
    lookup_service: Option<&crate::lookup::LookupService>,
    profile: &dyn crate::schema::SchemaProfile,
) -> Result<usize, SearchError> {
    fn source_keeps_physical_fields(query: &Query) -> bool {
        match query {
            Query::Search(_) => true,
            Query::Piped { source, command } => {
                matches!(
                    command,
                    Command::Where { .. }
                        | Command::Sort { .. }
                        | Command::Head { .. }
                        | Command::Tail { .. }
                        | Command::Dedup { .. }
                        | Command::Sample { .. }
                        | Command::Reverse
                ) && source_keeps_physical_fields(source)
            }
        }
    }
    fn collect_expr(expr: &SearchExpr, commands: &mut Vec<Command>) {
        match expr {
            SearchExpr::InSubsearch { subsearch, .. } => collect(subsearch, commands, true),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                collect_expr(left, commands);
                collect_expr(right, commands);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => collect_expr(inner, commands),
            _ => {}
        }
    }
    fn collect(query: &Query, commands: &mut Vec<Command>, nested: bool) {
        match query {
            Query::Search(expr) => collect_expr(expr, commands),
            Query::Piped { source, command } => {
                collect(source, commands, nested);
                match command {
                    Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
                        collect(subsearch, commands, true)
                    }
                    Command::Where { condition } => collect_expr(condition, commands),
                    Command::Transaction {
                        startswith,
                        endswith,
                        ..
                    } => {
                        if let Some(expr) = startswith {
                            collect_expr(expr, commands);
                        }
                        if let Some(expr) = endswith {
                            collect_expr(expr, commands);
                        }
                    }
                    Command::Sequence { conditions, .. } => {
                        for expr in conditions {
                            collect_expr(expr, commands);
                        }
                    }
                    Command::Funnel { steps, .. } => {
                        for (_, expr) in steps {
                            collect_expr(expr, commands);
                        }
                    }
                    _ => {}
                }
                if nested
                    && matches!(command, Command::InputLookup { .. })
                    && source_keeps_physical_fields(source)
                {
                    commands.push(command.clone());
                }
            }
        }
    }
    fn replace_expr(
        expr: &mut SearchExpr,
        replacements: &mut std::collections::VecDeque<Option<Vec<Command>>>,
    ) {
        match expr {
            SearchExpr::InSubsearch { subsearch, .. } => replace(subsearch, replacements, true),
            SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
                replace_expr(left, replacements);
                replace_expr(right, replacements);
            }
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => replace_expr(inner, replacements),
            _ => {}
        }
    }
    fn replace(
        query: &mut Query,
        replacements: &mut std::collections::VecDeque<Option<Vec<Command>>>,
        nested: bool,
    ) {
        match query {
            Query::Search(expr) => replace_expr(expr, replacements),
            Query::Piped { source, command } => {
                replace(source, replacements, nested);
                match command {
                    Command::Append { subsearch, .. } | Command::Join { subsearch, .. } => {
                        replace(subsearch, replacements, true)
                    }
                    Command::Where { condition } => replace_expr(condition, replacements),
                    Command::Transaction {
                        startswith,
                        endswith,
                        ..
                    } => {
                        if let Some(expr) = startswith {
                            replace_expr(expr, replacements);
                        }
                        if let Some(expr) = endswith {
                            replace_expr(expr, replacements);
                        }
                    }
                    Command::Sequence { conditions, .. } => {
                        for expr in conditions {
                            replace_expr(expr, replacements);
                        }
                    }
                    Command::Funnel { steps, .. } => {
                        for (_, expr) in steps {
                            replace_expr(expr, replacements);
                        }
                    }
                    _ => {}
                }
                if nested
                    && matches!(command, Command::InputLookup { .. })
                    && source_keeps_physical_fields(source)
                {
                    if let Some(Some(commands)) = replacements.pop_front() {
                        let mut rewritten = *source.clone();
                        for command in commands {
                            rewritten = Query::Piped {
                                source: Box::new(rewritten),
                                command,
                            };
                        }
                        *query = rewritten;
                    }
                }
            }
        }
    }

    let Some(service) = lookup_service else {
        return Ok(0);
    };
    let mut commands = Vec::new();
    collect(query, &mut commands, false);
    let mut replacements = std::collections::VecDeque::with_capacity(commands.len());
    let mut count = 0;
    for command in commands {
        let Command::InputLookup { url, key_field, .. } = command else {
            unreachable!()
        };
        let Some(table_name) = url.template.strip_prefix("lookup://") else {
            replacements.push_back(None);
            continue;
        };
        let Some(key_field) = key_field else {
            replacements.push_back(None);
            continue;
        };
        if profile.field_type(&key_field) != Some(crate::schema::FieldType::String)
            || profile.is_string_array_field(&key_field)
        {
            replacements.push_back(None);
            continue;
        }
        let table = service.get_table(table_name).await.map_err(|error| {
            SearchError::SqlValidationError(format!("inputlookup table '{table_name}': {error}"))
        })?;
        let page = service
            .list_rows(table_name, 1, LAKE_INLINE_LOOKUP_MAX_ROWS)
            .await
            .map_err(|error| {
                SearchError::SqlValidationError(format!(
                    "inputlookup table '{table_name}': {error}"
                ))
            })?;
        if page.total < 0
            || page.total > LAKE_INLINE_LOOKUP_MAX_ROWS
            || page.rows.len() != usize::try_from(page.total).unwrap_or(usize::MAX)
        {
            replacements.push_back(None);
            continue;
        }
        let Some(native) =
            build_inline_inputlookup_commands(&table, &key_field, page.rows, profile)
        else {
            replacements.push_back(None);
            continue;
        };
        count += 1;
        replacements.push_back(Some(native));
    }
    if count == 0 {
        return Ok(0);
    }
    let mut candidate = query.clone();
    replace(&mut candidate, &mut replacements, false);
    align_stats_aliases(&mut candidate);
    let rendered = candidate.pretty_print();
    if rendered.len() > LAKE_INLINE_LOOKUP_MAX_QUERY_BYTES {
        return Ok(0);
    }
    let reparsed = parse_query(&rendered).map_err(convert_parse_error)?;
    if reparsed != candidate {
        return Ok(0);
    }
    *query = reparsed;
    Ok(count)
}

fn build_inline_inputlookup_commands(
    table: &crate::lookup::LookupTable,
    key_field: &str,
    rows: Vec<std::collections::HashMap<String, serde_json::Value>>,
    profile: &dyn crate::schema::SchemaProfile,
) -> Option<Vec<Command>> {
    let output_names = table
        .columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<Vec<_>>();
    if output_names.is_empty()
        || output_names
            .iter()
            .any(|name| name.chars().any(char::is_control))
    {
        return None;
    }
    let fallback_key = output_names.iter().min()?;
    let mut seen = std::collections::HashSet::new();
    let mut keyed_rows = Vec::new();
    for row in rows {
        let key = row.get(key_field).or_else(|| row.get(*fallback_key))?;
        if !key.is_string() {
            return None;
        }
        let key_expr = json_scalar_eval_expression(key)?;
        if !seen.insert(json_lookup_identity(key)?) {
            continue;
        }
        keyed_rows.push((row, key_expr));
    }
    let nonce = uuid::Uuid::now_v7().simple().to_string();
    let match_alias = format!("__nano_il_match_{nonce}");
    let mut projection = Vec::new();
    let mut merges = Vec::new();
    let mut temporary = vec![match_alias.clone()];
    let mut predicates = Vec::new();
    for (_, key) in &keyed_rows {
        predicates.push(EvalExpression::BinaryOp {
            left: Box::new(EvalExpression::Field(key_field.to_string())),
            op: crate::query::BinaryOperator::Eq,
            right: Box::new(key.clone()),
        });
    }
    let mut match_args = Vec::new();
    for predicate in &predicates {
        match_args.push(predicate.clone());
        match_args.push(EvalExpression::Literal(Value::Bool(true)));
    }
    match_args.push(EvalExpression::Literal(Value::Bool(false)));
    projection.push(EvalAssignment {
        field: match_alias.clone(),
        expression: if keyed_rows.is_empty() {
            EvalExpression::Literal(Value::Bool(false))
        } else {
            EvalExpression::FunctionCall {
                name: "case".into(),
                args: match_args,
            }
        },
    });
    for (index, output_name) in output_names.iter().enumerate() {
        let alias = format!("__nano_il_value_{nonce}_{index}");
        temporary.push(alias.clone());
        let mut args = Vec::new();
        for ((row, _), predicate) in keyed_rows.iter().zip(&predicates) {
            args.push(predicate.clone());
            args.push(json_scalar_eval_expression(row.get(*output_name)?)?);
        }
        args.push(null_eval_expression());
        projection.push(EvalAssignment {
            field: alias.clone(),
            expression: if keyed_rows.is_empty() {
                null_eval_expression()
            } else {
                EvalExpression::FunctionCall {
                    name: "case".into(),
                    args,
                }
            },
        });
        let target = format!("inputlookup_{output_name}");
        let mut merge_args = vec![
            EvalExpression::Field(match_alias.clone()),
            EvalExpression::Field(alias),
        ];
        if profile.field_type(&target).is_some() {
            merge_args.push(EvalExpression::Field(target.clone()));
        } else {
            merge_args.push(null_eval_expression());
        }
        merges.push(EvalAssignment {
            field: target,
            expression: EvalExpression::FunctionCall {
                name: "case".into(),
                args: merge_args,
            },
        });
    }
    Some(vec![
        Command::Eval {
            assignments: projection,
        },
        Command::Eval {
            assignments: merges,
        },
        Command::Fields {
            fields: temporary,
            keep: false,
        },
    ])
}

fn build_inline_lookup_assignments(
    table: &crate::lookup::LookupTable,
    event_field: &str,
    command_key_field: &str,
    requested_outputs: Option<&[String]>,
    case_insensitive: bool,
    rows: Vec<std::collections::HashMap<String, serde_json::Value>>,
) -> Option<Vec<EvalAssignment>> {
    let lookup_key = table.primary_key.as_deref().unwrap_or(command_key_field);
    let mut output_names = requested_outputs.map_or_else(
        || {
            table
                .columns
                .iter()
                .map(|column| column.name.clone())
                .collect()
        },
        |outputs| outputs.to_vec(),
    );
    if !output_names.iter().any(|name| name == lookup_key) {
        output_names.push(lookup_key.to_string());
    }
    // NAN-3466: an implicit output named after the event field's parent
    // object (table key `user` for event field `user.name`) becomes
    // `… AS user` in the worker SQL, which shadows every `user.*` path
    // downstream (chDB: "Unknown expression identifier 'user.name'"), and
    // would overwrite the nested object Nano-side. Only an explicit OUTPUT
    // of that name keeps it.
    output_names.retain(|name| {
        !crate::search::processing::enrichment::lookup_output_shadows_event_field(event_field, name)
            || requested_outputs.is_some_and(|outputs| outputs.iter().any(|output| output == name))
    });
    output_names.sort();
    output_names.dedup();
    if output_names.iter().any(|name| {
        !table.columns.iter().any(|column| column.name == *name)
            || name.chars().any(char::is_control)
    }) {
        return None;
    }

    let mut seen_keys = std::collections::HashSet::new();
    let mut keyed_rows = Vec::with_capacity(rows.len());
    for row in rows {
        let key = row.get(lookup_key)?;
        let key_expression = json_scalar_eval_expression(key)?;
        let identity = if case_insensitive {
            json_lookup_identity(key)?.to_lowercase()
        } else {
            json_lookup_identity(key)?
        };
        if !seen_keys.insert(identity) {
            return None;
        }
        keyed_rows.push((row, key_expression));
    }

    let mut assignments = Vec::with_capacity(output_names.len());
    for output_name in output_names {
        let mut args = Vec::with_capacity(keyed_rows.len().saturating_mul(2));
        for (row, key_expression) in &keyed_rows {
            let output_expression = row
                .get(&output_name)
                .and_then(json_scalar_eval_expression)?;
            let (field_expression, key_expression) = if case_insensitive {
                let EvalExpression::Literal(Value::String(key)) = key_expression else {
                    return None;
                };
                (
                    EvalExpression::FunctionCall {
                        name: "lower".to_string(),
                        args: vec![EvalExpression::Field(event_field.to_string())],
                    },
                    EvalExpression::Literal(Value::String(key.to_lowercase())),
                )
            } else {
                (
                    EvalExpression::Field(event_field.to_string()),
                    key_expression.clone(),
                )
            };
            args.push(EvalExpression::BinaryOp {
                left: Box::new(field_expression),
                op: crate::query::BinaryOperator::Eq,
                right: Box::new(key_expression),
            });
            args.push(output_expression);
        }
        let expression = if args.is_empty() {
            null_eval_expression()
        } else {
            // An even number of case arguments intentionally omits the
            // default; both evaluators supply NULL for an unmatched key.
            EvalExpression::FunctionCall {
                name: "case".to_string(),
                args,
            }
        };
        assignments.push(EvalAssignment {
            field: output_name,
            expression,
        });
    }
    Some(assignments)
}

fn json_scalar_eval_expression(value: &serde_json::Value) -> Option<EvalExpression> {
    let value = match value {
        serde_json::Value::Null => return Some(null_eval_expression()),
        serde_json::Value::String(value) => {
            if value.contains('\n')
                || value.contains('\r')
                || value.contains('"') && value.contains('\'')
            {
                return None;
            }
            Value::String(value.clone())
        }
        serde_json::Value::Number(value) => {
            // nPL numeric literals are represented as f64. Refuse integers
            // outside its exact range instead of changing a lookup key or
            // value while compiling the bounded snapshot into the query.
            const MAX_EXACT_F64_INTEGER: u64 = 9_007_199_254_740_991;
            if let Some(integer) = value.as_i64() {
                if integer.unsigned_abs() > MAX_EXACT_F64_INTEGER {
                    return None;
                }
            } else if let Some(integer) = value.as_u64() {
                if integer > MAX_EXACT_F64_INTEGER {
                    return None;
                }
            }
            Value::Number(value.as_f64().filter(|v| v.is_finite())?)
        }
        serde_json::Value::Bool(value) => Value::Bool(*value),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => return None,
    };
    Some(EvalExpression::Literal(value))
}

fn json_lookup_identity(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

/// Return the first `head` that can be moved in front of Nano-side enrichment
/// without changing which rows it observes. The commands accepted before the
/// bound preserve both row cardinality and order. Once that exact prefix is
/// bounded, every later suffix command can run over the complete input set
/// without expanding the worker fetch to the 50k global-processing cap.
///
/// This matters for common analyst pipelines such as
/// `ip=... | lookup assets ... | table ... | head 20`: treating the final
/// `head` as a global stage turns a selective page lookup into a wide scan.
fn lake_safe_post_processing_head_bound(commands: &[Command]) -> Option<usize> {
    for command in commands {
        match command {
            Command::Head { count } => return (1..=10_000).contains(count).then_some(*count),
            Command::Lookup { .. }
            | Command::ResolveIdentity { .. }
            | Command::Ai { .. }
            | Command::Rename { .. }
            | Command::Eval { .. }
            | Command::Rex { .. }
            | Command::Fields { .. }
            | Command::Table { .. }
            | Command::Fillnull { .. }
            | Command::Spath { .. }
            | Command::Bin { .. }
            | Command::Risk { .. }
            | Command::Output { .. } => {}
            Command::Prevalence { conditions, .. } if conditions.is_empty() => {}
            Command::InputLookup {
                key_field: Some(_), ..
            } => {}
            _ => return None,
        }
    }
    None
}

/// The worker query and row bound for a lake query with a Nano-side suffix.
/// A `head N` left inside the worker query runs once per progressive time
/// chunk (`… | head 5 | lookup …` returned 3x5 rows), so it is pulled out of
/// the base exactly as the no-suffix head page does and the request limit
/// carries N; the suffix then sees the global newest N rows.
fn lake_post_processing_worker_query(
    base_query: &Query,
    post_commands: &[Command],
) -> (String, Option<usize>) {
    let base_head_page = lake_head_page_plan(base_query);
    let bound = match (
        base_head_page.as_ref().map(|page| page.head_count),
        lake_safe_post_processing_head_bound(post_commands),
    ) {
        (Some(base), Some(suffix)) => Some(base.min(suffix)),
        (base, suffix) => base.or(suffix),
    };
    let query = base_head_page
        .map_or_else(|| base_query.pretty_print(), |page| page.query_without_head.pretty_print());
    (query, bound)
}

/// NAN-3078: how a lake query with a Nano-side suffix splits between the
/// worker (an SQL-only candidate prefix) and Nano. The interactive lane and
/// durable post-processed jobs both plan through [`plan_lake_post_processing`]
/// so the candidate set a job materializes is exactly the one the interactive
/// lane would have fetched.
#[derive(Debug, Clone)]
pub(crate) struct LakePostProcessingPlan {
    pub(crate) base_query: Query,
    pub(crate) post_commands: Vec<Command>,
    pub(crate) tree_command: Option<crate::search::query_processing::TreeCommandInfo>,
    pub(crate) funnel_command: Option<crate::search::query_processing::FunnelCommandInfo>,
    /// The base query with any pulled-out `head` removed.
    pub(crate) worker_query: String,
    pub(crate) safe_head_bound: Option<usize>,
    pub(crate) needs_candidate_set: bool,
    pub(crate) has_identity: bool,
}

pub(crate) fn plan_lake_post_processing(parsed: &Query) -> LakePostProcessingPlan {
    let tree_command = extract_tree_command(parsed);
    let funnel_command = extract_funnel_command(parsed);
    let (base_query, post_commands) = split_lake_post_processing(parsed);
    // A `head N` inside the worker query runs once per progressive time
    // chunk (`… | head 5 | lookup …` returned 3x5 rows). Pull it out of
    // the base exactly as the no-suffix head page does, and let the
    // request limit carry N: the post-processing suffix then sees the
    // global newest N rows.
    let (worker_query, safe_head_bound) =
        lake_post_processing_worker_query(&base_query, &post_commands);
    let has_identity = post_commands
        .iter()
        .any(|command| matches!(command, Command::ResolveIdentity { .. }));
    // Only membership/order/cardinality stages need a pre-pagination
    // candidate set. Pure enrichment and row-local projection operate on
    // the requested page, matching the established ClickHouse path.
    let needs_candidate_set =
        safe_head_bound.is_none() && lake_post_processing_needs_candidate_set(&post_commands);
    LakePostProcessingPlan {
        base_query,
        post_commands,
        tree_command,
        funnel_command,
        worker_query,
        safe_head_bound,
        needs_candidate_set,
        has_identity,
    }
}

impl LakePostProcessingPlan {
    /// Row bound of the worker fetch (always at offset 0). `None` is the page
    /// case: the suffix is row-local, so the caller's own page is fetched.
    pub(crate) fn candidate_limit(&self) -> Option<usize> {
        if let Some(count) = self.safe_head_bound {
            // The request limit, rather than an nPL `head`, controls the
            // worker's progressive stop target. Putting `head 20` into each
            // time slice while asking for a 100-row page would make every
            // slice return 20 rows and continue scanning older ranges.
            Some(count)
        } else if self.tree_command.is_some() {
            // The tree builder needs the relationship set, not a UI page. The
            // established product cap is 10k nodes.
            Some(crate::search::query_processing::LAKE_TREE_CANDIDATE_CAP)
        } else if self.needs_candidate_set {
            Some(if self.has_identity {
                LAKE_IDENTITY_BATCH_CAP
            } else {
                IN_MEMORY_PREVALENCE_FETCH_CAP
            })
        } else {
            None
        }
    }

    /// The worker query text, projected to the referenced fields for a large
    /// candidate fetch over strict canonical logs.
    pub(crate) fn candidate_query(
        &self,
        parsed: &Query,
        generator: &ClickHouseSqlGenerator,
        profile: &dyn crate::schema::SchemaProfile,
        strict_logs: bool,
    ) -> String {
        // NAN-3257: a terminal tree reads a narrow, edge-only projection
        // instead of `SELECT *` over the whole window.
        if strict_logs && self.post_commands.is_empty() && self.tree_command.is_some() {
            if let Some(projected) =
                crate::search::query_processing::lake_tree_candidate_query(&self.base_query, profile)
            {
                return projected.pretty_print();
            }
        }
        if self.needs_candidate_set && strict_logs {
            if let Some(projected) = project_lake_candidate_query(
                &self.base_query,
                parsed,
                &self.post_commands,
                generator,
                profile,
            ) {
                tracing::debug!(
                    query = %crate::inputlookup::storage_policy::redact_url_credentials(&projected.pretty_print()),
                    "projecting primary-lake Nano-side candidate rows"
                );
                return projected.pretty_print();
            }
        }
        self.worker_query.clone()
    }
}

/// Whether a durable search must run as `SearchNplPostV1`: its SQL-only
/// candidate prefix is materialized and the Nano-side suffix applied on read.
/// NAN-3257: a terminal `| tree` is assembled Nano-side too. Queued as a plain
/// SQL-only job, its completed result carried no tree marker, so the paged
/// tree view rendered "No tree nodes returned" after a full-window scan.
pub(crate) fn durable_search_needs_post_processing(parsed: &Query) -> bool {
    contains_lake_post_processing_anywhere(parsed) || extract_tree_command(parsed).is_some()
}

/// Append one sentence to a tree marker's `_tree_note`, keeping what an
/// earlier stage (the builder's empty-tree / fallback note) already said.
pub(crate) fn append_tree_note(marker: &mut serde_json::Map<String, serde_json::Value>, note: &str) {
    let combined = match marker.get("_tree_note").and_then(serde_json::Value::as_str) {
        Some(existing) if !existing.is_empty() && !existing.contains(note) => format!("{existing} {note}"),
        Some(existing) if !existing.is_empty() => existing.to_string(),
        _ => note.to_string(),
    };
    marker.insert("_tree_note".to_string(), serde_json::Value::String(combined));
}

/// NAN-3294: a `tree web` whose host could not be widened to its IPs says
/// so, in the tree note and as a response warning.
fn attach_lake_tree_identity_problems(response: &mut SearchResponse, problems: Vec<String>) {
    if problems.is_empty() {
        return;
    }
    if let Some(marker) = response
        .results
        .first_mut()
        .and_then(serde_json::Value::as_object_mut)
        .filter(|marker| marker.get("_display_type").and_then(serde_json::Value::as_str) == Some("tree"))
    {
        for problem in &problems {
            append_tree_note(marker, problem);
        }
    }
    response.warnings.get_or_insert_with(Vec::new).extend(problems.into_iter().map(|message| QueryWarningOutput {
        severity: "warning".to_string(),
        code: "TREE_HOST_IDENTITY_UNRESOLVED".to_string(),
        message,
        suggestion: Some("Filter by the host's IP (src_endpoint.ip) instead, or widen the time range.".to_string()),
        impact: Some("Events that name the host only by IP are missing from the tree.".to_string()),
    }));
}

/// NAN-3257: the analyst-facing note for a tree built from a candidate fetch
/// that stopped at its row cap (or reported more matching events than it
/// returned). `None` when the tree saw every matching edge.
pub(crate) fn lake_tree_bound_note(
    fetched: usize,
    base_total: u64,
) -> Option<String> {
    let cap = crate::search::query_processing::LAKE_TREE_CANDIDATE_CAP;
    (fetched >= cap || base_total > fetched as u64).then(|| {
        format!(
            "Tree built from {fetched} parent/child events; more matched, so the tree is partial. Narrow the search or time range for the full tree."
        )
    })
}

/// Caller-side inputs of [`SearchService::finish_lake_post_processing`].
pub(crate) struct LakePostProcessingContext<'a> {
    pub(crate) parsed: &'a Query,
    pub(crate) display_type: DisplayType,
    pub(crate) requested_limit: usize,
    pub(crate) requested_offset: usize,
    pub(crate) skip_field_stats: bool,
    pub(crate) fallback_reference_time: chrono::DateTime<chrono::Utc>,
    pub(crate) scope: &'a ScopeSet,
    pub(crate) max_post_processing_groups: usize,
    pub(crate) start_time: Instant,
}

/// True when the suffix eventually replaces the raw event shape with a bounded
/// set of explicitly referenced columns. Such queries can safely project the
/// worker candidate rows before Nano-side processing.
fn lake_suffix_has_narrow_result(commands: &[Command]) -> bool {
    commands.iter().any(|command| {
        matches!(
            command,
            Command::Stats { .. }
                | Command::Chart { .. }
                | Command::Timechart { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::Table { .. }
                | Command::Fields { keep: true, .. }
        )
    })
}

/// The internal projection is deliberately limited to a raw-event prefix with
/// row-selection stages. A prefix that created dynamic columns (eval/rex/bin)
/// or already changed shape must retain its own projection contract.
fn lake_base_accepts_candidate_projection(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            lake_base_accepts_candidate_projection(source)
                && matches!(
                    command,
                    Command::Where { .. }
                        | Command::Sort { .. }
                        | Command::Head { .. }
                        | Command::Tail { .. }
                        | Command::Dedup { .. }
                        | Command::Sample { .. }
                        | Command::Reverse
                        | Command::Eval { .. }
                        | Command::Rex { .. }
                        | Command::Fillnull { .. }
                        | Command::Spath { .. }
                        | Command::Bin { .. }
                )
        }
    }
}

/// Add an internal `table` stage for a large Nano-side candidate fetch. The
/// full parsed query supplies every physical field referenced before and after
/// the stateful boundary; lookup-produced aliases are discarded because they
/// do not exist in the event snapshot yet.
fn project_lake_candidate_query(
    base_query: &Query,
    full_query: &Query,
    post_commands: &[Command],
    generator: &ClickHouseSqlGenerator,
    profile: &dyn crate::schema::SchemaProfile,
) -> Option<Query> {
    if !lake_base_accepts_candidate_projection(base_query)
        || !lake_suffix_has_narrow_result(post_commands)
    {
        return None;
    }

    let derived = crate::query::collect_derived_fields(full_query);
    let referenced = generator.referenced_fields_for_query(full_query);
    let fields = referenced
        .into_iter()
        .filter(|field| {
            let lower = field.to_ascii_lowercase();
            let is_derived = derived.contains(&lower)
                || lower
                    .strip_prefix("ext.")
                    .is_some_and(|name| derived.contains(name));
            !is_derived
                || !matches!(
                    profile.resolve(field),
                    crate::schema::FieldResolution::Unknown
                )
        })
        .map(|field| profile.canonicalize(&field).into_owned())
        .filter(|field| {
            !matches!(
                profile.resolve(field),
                crate::schema::FieldResolution::Unknown
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    if fields.is_empty() {
        return None;
    }

    // NAN-2373: a prevalence stage reads artifact columns that the query text
    // never mentions (`file.hashes[].value`, `dst_endpoint.hostname`, …). If
    // the internal projection narrows the candidate rows to the referenced
    // fields alone, the stage sees no artifact and emits none of its output
    // columns — the same silent no-op, reintroduced one stage later. Pin the
    // artifact paths the active schema actually has.
    let mut fields = fields;
    if post_commands
        .iter()
        .any(|command| matches!(command, Command::Prevalence { .. }))
    {
        for path in crate::search::service::prevalence_processing::lake_prevalence_artifact_paths()
        {
            if !matches!(
                profile.resolve(path),
                crate::schema::FieldResolution::Unknown
            ) {
                fields.insert(path.to_string());
            }
        }
    }

    Some(Query::Piped {
        source: Box::new(base_query.clone()),
        command: Command::Table {
            fields: fields
                .into_iter()
                .map(|name| TableField { name, alias: None })
                .collect(),
        },
    })
}

fn lake_row_string<'a>(row: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    if let Some(value) = row.get(field).and_then(serde_json::Value::as_str) {
        return Some(value);
    }
    let mut value = row;
    for segment in field.split('.') {
        value = value.get(segment)?;
    }
    value.as_str()
}

/// NAN-3294: the OCSF identity paths `| resolve_identity` accepts on the
/// lake, whatever entity typing the profile's field catalog carries for them
/// (`device.ip` is untyped there). Other fields fall back to the profile.
fn lake_identity_entity_type(field: &str) -> Option<crate::schema::EntityType> {
    use crate::schema::EntityType;
    match field {
        "src_endpoint.ip" | "dst_endpoint.ip" | "device.ip" => Some(EntityType::Ip),
        "src_endpoint.hostname" | "dst_endpoint.hostname" | "device.hostname" => Some(EntityType::Host),
        "user.name" | "actor.user.name" => Some(EntityType::User),
        _ => None,
    }
}

/// One lean identity answer, as the `identity_*` columns and OCSF fills
/// [`SearchService::apply_lake_identity_batch`] writes (NAN-3294).
#[derive(Debug, Clone, Default)]
struct LakeIdentityAnswerColumns {
    ip: String,
    hostname: String,
    user: String,
    mac: String,
    source: String,
    observed_at: String,
    fqdn: String,
}

/// NAN-3294: the explicit `| resolve_identity` output columns on a lean row.
/// Flat keys, like every other Nano-side decoration column; empty values are
/// left out so a partial answer never shows as a resolved blank.
pub(super) fn set_lake_identity_columns(row: &mut serde_json::Value, columns: &[(&str, &str)]) {
    let Some(object) = row.as_object_mut() else { return };
    for (name, value) in columns {
        if !value.is_empty() {
            object.insert((*name).to_string(), serde_json::Value::String((*value).to_string()));
        }
    }
}

/// NAN-3294: `| resolve_identity` over rows that never carry its field must
/// say so instead of returning the rows unchanged.
pub(super) fn lake_identity_absent_field_warning(field: &str, rows: usize) -> String {
    format!(
        "resolve_identity: none of the {rows} rows carry {field}, so nothing was resolved. \
         Resolve a field these events carry (proxy and network events carry src_endpoint.ip; \
         endpoint events carry device.hostname)."
    )
}

/// NAN-3294: `| resolve_identity` that found no identity for any value.
pub(super) fn lake_identity_unresolved_warning(
    field: &str,
    distinct_values: usize,
    stale_rows: usize,
    max_age: &std::time::Duration,
) -> String {
    let stale = if stale_rows > 0 {
        format!(" {stale_rows} rows matched an identity older than max_age={}s.", max_age.as_secs())
    } else {
        String::new()
    };
    format!(
        "resolve_identity: no identity was found for any of the {distinct_values} distinct {field} values at their event times.{stale} \
         The tenant's identity index only learns hosts and users from events that name them (endpoint, auth and DHCP logs)."
    )
}

/// Add query-time identity context using canonical OCSF paths. Existing
/// observed event values always win over derived identity state; the
/// resolution itself is always visible in the `identity_*` columns
/// ([`set_lake_identity_columns`]).
pub(super) fn set_lake_ocsf_value_if_empty(row: &mut serde_json::Value, path: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    let segments = path.split('.').collect::<Vec<_>>();
    let mut current = row;
    for (index, segment) in segments.iter().enumerate() {
        let is_leaf = index + 1 == segments.len();
        let Some(object) = current.as_object_mut() else {
            return;
        };
        if is_leaf {
            let should_set = object
                .get(*segment)
                .map(|existing| existing.is_null() || existing.as_str() == Some(""))
                .unwrap_or(true);
            if should_set {
                object.insert((*segment).to_string(), value.into());
            }
            return;
        }
        current = object
            .entry((*segment).to_string())
            .or_insert_with(|| serde_json::json!({}));
    }
}

pub(super) fn parse_lake_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|timestamp| timestamp.and_utc())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SqlLimitPlan {
    generator_limit: Option<usize>,
    execution_limit: usize,
    execution_offset: usize,
    page_after_post_processing: bool,
}

/// Separate an SQL query's input/result-shape limit from its returned-page
/// limit. Raw rows and SQL aggregations are paginated by the executor; other
/// paths keep their internal fetch cap in generated SQL.
fn sql_limit_plan(
    is_raw_event_query: bool,
    sql_has_aggregation: bool,
    sql_aggregation_has_rust_suffix: bool,
    aggregation_deferred_to_rust: bool,
    internal_limit: usize,
    page_limit: usize,
    request_offset: usize,
) -> SqlLimitPlan {
    if sql_has_aggregation && sql_aggregation_has_rust_suffix {
        SqlLimitPlan {
            generator_limit: Some(AGGREGATE_OUTPUT_CAP),
            execution_limit: AGGREGATE_OUTPUT_CAP,
            execution_offset: 0,
            page_after_post_processing: true,
        }
    } else if sql_has_aggregation {
        SqlLimitPlan {
            generator_limit: Some(AGGREGATE_OUTPUT_CAP),
            execution_limit: page_limit,
            execution_offset: request_offset,
            page_after_post_processing: false,
        }
    } else if is_raw_event_query {
        SqlLimitPlan {
            generator_limit: None,
            execution_limit: internal_limit,
            execution_offset: request_offset,
            page_after_post_processing: false,
        }
    } else if aggregation_deferred_to_rust {
        SqlLimitPlan {
            generator_limit: Some(internal_limit),
            execution_limit: internal_limit,
            execution_offset: 0,
            page_after_post_processing: true,
        }
    } else {
        SqlLimitPlan {
            generator_limit: Some(internal_limit),
            execution_limit: internal_limit,
            execution_offset: request_offset,
            page_after_post_processing: false,
        }
    }
}

/// Whether one of the Rust-only pipeline stages occurs after an aggregation.
/// Stripping that suffix leaves a real SQL aggregation whose complete bounded
/// output must reach Rust before request pagination is applied.
fn has_rust_only_suffix_after_aggregation(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            let is_rust_only = matches!(
                command,
                Command::Prevalence { .. }
                    | Command::InputLookup { .. }
                    | Command::Lateral { .. }
                    | Command::Ai { .. }
            );
            (is_rust_only && query_has_aggregation(source))
                || has_rust_only_suffix_after_aggregation(source)
        }
    }
}

/// Apply request pagination after a Rust-side aggregation/transform has seen
/// its complete fetched input. The returned count describes the full
/// post-processed result, before this page is sliced.
fn paginate_post_processed_results(
    mut results: Vec<serde_json::Value>,
    offset: usize,
    limit: usize,
    preserve_display_metadata: bool,
) -> (Vec<serde_json::Value>, u64) {
    let metadata = preserve_display_metadata
        .then(|| {
            results
                .iter()
                .position(|row| row.get("_display_type").is_some())
                .map(|index| results.remove(index))
        })
        .flatten();
    let total_count = u64::try_from(results.len()).unwrap_or(u64::MAX);
    let mut page: Vec<_> = results.into_iter().skip(offset).take(limit).collect();
    if let Some(metadata) = metadata {
        page.insert(0, metadata);
    }
    (page, total_count)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LakeCountStatsPlan {
    group_by: Vec<String>,
    count_alias: String,
    rollup_field: Option<String>,
    rollup_predicate: Option<LakeCountPredicate>,
    rollup_source_filter: Option<String>,
    rollup_union: Option<LakeCountUnionPlan>,
    /// NAN-3153: `rollup_field`/`rollup_predicate` select the rows, which are
    /// grouped by `metadata.log_source` (`F=v | stats count by metadata.log_source`).
    rollup_group_by_source: bool,
    /// NAN-3153: `A=v OR B=w` over two different rollup fields.
    rollup_field_union: Option<LakeFieldUnionPlan>,
    bucket_span_us: Option<i64>,
    /// NAN-3883: the caller's stats command was planned in its rollup
    /// spelling (see [`lake_rollup_planning_stats`]); rollup rows are put
    /// back into the caller's spelling before they are used.
    output_spelling: Option<LakeRollupOutputSpelling>,
}

/// NAN-3883: how a stats command planned in its rollup spelling maps back
/// to the caller's output columns.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LakeRollupOutputSpelling {
    /// The group column as the rollups key it (`metadata.log_source`).
    rollup_group: String,
    /// The group column as the caller wrote it (`source_type`).
    caller_group: String,
    /// `count(F) by F` planned as `count() by F`. Identical for every group
    /// except a NULL `F`, where `count(F)` is 0 but the rollup counts the
    /// group's rows; a rollup answer carrying a NULL group is not used.
    counts_group_field: bool,
}

/// `left_field <left_predicate> OR right_field <right_predicate>`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LakeFieldUnionPlan {
    left_field: String,
    left_predicate: LakeCountPredicate,
    right_field: String,
    right_predicate: LakeCountPredicate,
}

#[derive(Clone, Debug, PartialEq)]
struct LakeCountPipelinePlan {
    aggregate: LakeCountStatsPlan,
    aggregate_query: Query,
    post_commands: Vec<Command>,
}

#[derive(Clone, Debug, PartialEq)]
struct LakeHeadPagePlan {
    query_without_head: Query,
    head_count: usize,
}

#[derive(Clone, Debug, PartialEq)]
struct LakeDistinctPipelinePlan {
    group_by: Vec<String>,
    output_alias: String,
    values_output_alias: Option<String>,
    count_output_alias: Option<String>,
    values_alias: String,
    aggregate_query: Query,
    post_commands: Vec<Command>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LakeCountMetric {
    alias: String,
    field: String,
    predicate: Option<LakeCountPredicate>,
    source_filter: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LakeCountMetricsPlan {
    metrics: Vec<LakeCountMetric>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LakeCountUnionPlan {
    source: String,
    field: String,
    predicate: LakeCountPredicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LakeRollupSearch {
    All,
    Source(String),
    Predicate {
        field: String,
        predicate: LakeCountPredicate,
        source: Option<String>,
    },
    SourcePredicateUnion(LakeCountUnionPlan),
    FieldUnion(LakeFieldUnionPlan),
}

fn lake_count_value(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Ip(value) => Some(value.to_string()),
        Value::Regex(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn lake_count_field_predicate(
    field: &str,
    op: Comparator,
    value: &Value,
) -> Option<LakeCountPredicate> {
    let value = lake_count_value(value)?;
    let kind = match op {
        Comparator::Eq if value == "*" => return None,
        Comparator::Eq if !value.contains(['*', '?']) => "eq",
        Comparator::Ne if !value.contains(['*', '?']) => "ne",
        Comparator::Contains => "contains",
        Comparator::NotContains => "not_contains",
        Comparator::Regex => {
            if let Some(token) =
                crate::query::clickhouse_sql_gen::extract_simple_regex_token(&value)
            {
                return Some(LakeCountPredicate {
                    kind: "contains",
                    values: vec![token],
                });
            }
            "regex"
        }
        Comparator::NotRegex => {
            if let Some(token) =
                crate::query::clickhouse_sql_gen::extract_simple_regex_token(&value)
            {
                return Some(LakeCountPredicate {
                    kind: "not_contains",
                    values: vec![token],
                });
            }
            "not_regex"
        }
        Comparator::StartsWith => "starts_with",
        Comparator::NotStartsWith => "not_starts_with",
        Comparator::EndsWith => "ends_with",
        Comparator::NotEndsWith => "not_ends_with",
        _ => return None,
    };
    (!field.is_empty()).then_some(LakeCountPredicate {
        kind,
        values: vec![value],
    })
}

fn lake_count_boolean_predicate(expr: &EvalExpression) -> Option<(String, LakeCountPredicate)> {
    let EvalExpression::FunctionCall { name, args } = expr else {
        return None;
    };
    let name = name.to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "isnull" | "is_null" | "isnotnull" | "is_not_null"
    ) {
        let [EvalExpression::Field(field)] = args.as_slice() else {
            return None;
        };
        return Some((
            field.clone(),
            LakeCountPredicate {
                kind: if matches!(name.as_str(), "isnull" | "is_null") {
                    "is_null"
                } else {
                    "is_not_null"
                },
                values: Vec::new(),
            },
        ));
    }
    if !matches!(name.as_str(), "cidrmatch" | "cidr_match") || args.len() != 2 {
        return None;
    }
    let (field, cidr) = match (&args[0], &args[1]) {
        (EvalExpression::Field(field), EvalExpression::Literal(value))
        | (EvalExpression::Literal(value), EvalExpression::Field(field)) => {
            (field.clone(), lake_count_value(value)?)
        }
        _ => return None,
    };
    Some((
        field,
        LakeCountPredicate {
            kind: "cidr_in",
            values: vec![cidr],
        },
    ))
}

fn lake_count_rollup_search(expr: &SearchExpr) -> Option<LakeRollupSearch> {
    match expr {
        SearchExpr::Keyword(value) if value == "*" => Some(LakeRollupSearch::All),
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Eq,
            value: Value::String(value),
            ..
        } if field == "metadata.log_source" && !value.contains(['*', '?']) => {
            Some(LakeRollupSearch::Source(value.clone()))
        }
        SearchExpr::FieldFilter {
            field, op, value, ..
        } => lake_count_field_predicate(field, *op, value).map(|predicate| {
            LakeRollupSearch::Predicate {
                field: field.clone(),
                predicate,
                source: None,
            }
        }),
        SearchExpr::InList {
            field,
            values,
            negated,
        } => {
            let values = values
                .iter()
                .map(lake_count_value)
                .collect::<Option<Vec<_>>>()?;
            (!values.is_empty() && values.len() <= 64).then(|| LakeRollupSearch::Predicate {
                field: field.clone(),
                predicate: LakeCountPredicate {
                    kind: if *negated { "not_in" } else { "in" },
                    values,
                },
                source: None,
            })
        }
        SearchExpr::BooleanFunction(expr) => {
            lake_count_boolean_predicate(expr).map(|(field, predicate)| {
                LakeRollupSearch::Predicate {
                    field,
                    predicate,
                    source: None,
                }
            })
        }
        SearchExpr::And(left, right) => {
            match (
                lake_count_rollup_search(left),
                lake_count_rollup_search(right),
            ) {
                (
                    Some(LakeRollupSearch::Source(source)),
                    Some(LakeRollupSearch::Predicate {
                        field,
                        predicate,
                        source: None,
                    }),
                )
                | (
                    Some(LakeRollupSearch::Predicate {
                        field,
                        predicate,
                        source: None,
                    }),
                    Some(LakeRollupSearch::Source(source)),
                ) if field != "metadata.log_source" => Some(LakeRollupSearch::Predicate {
                    field,
                    predicate,
                    source: Some(source),
                }),
                _ => None,
            }
        }
        SearchExpr::Or(left, right) => {
            match (
                lake_count_rollup_search(left),
                lake_count_rollup_search(right),
            ) {
                (
                    Some(LakeRollupSearch::Source(source)),
                    Some(LakeRollupSearch::Predicate {
                        field,
                        predicate,
                        source: None,
                    }),
                )
                | (
                    Some(LakeRollupSearch::Predicate {
                        field,
                        predicate,
                        source: None,
                    }),
                    Some(LakeRollupSearch::Source(source)),
                ) if field != "metadata.log_source" => {
                    Some(LakeRollupSearch::SourcePredicateUnion(LakeCountUnionPlan {
                        source,
                        field,
                        predicate,
                    }))
                }
                (
                    Some(LakeRollupSearch::Predicate {
                        field: left_field,
                        predicate: left_predicate,
                        source: None,
                    }),
                    Some(LakeRollupSearch::Predicate {
                        field: right_field,
                        predicate: right_predicate,
                        source: None,
                    }),
                ) if left_field != right_field
                    && left_field != LAKE_SOURCE_FIELD
                    && right_field != LAKE_SOURCE_FIELD =>
                {
                    Some(LakeRollupSearch::FieldUnion(LakeFieldUnionPlan {
                        left_field,
                        left_predicate,
                        right_field,
                        right_predicate,
                    }))
                }
                _ => None,
            }
        }
        SearchExpr::Group(inner) => lake_count_rollup_search(inner),
        _ => None,
    }
}

/// NAN-3780: the count-rollup spelling of `field` when the lake profile
/// compiles it to a different, rollup-covered field (`source_type` and
/// `sourcetype` → `metadata.log_source`, `process_name` → `process.name`,
/// …). The profile resolves both spellings to the same column, so a rollup
/// keyed by the canonical spelling answers exactly what the raw scan of the
/// original text answers. `None`: keep the field as written.
fn lake_rollup_field_spelling(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
) -> Option<String> {
    if !profile.uses_strict_canonical_fields()
        || crate::search::lake::lake_count_rollup_field_multi_value(field).is_some()
    {
        return None;
    }
    let canonical = profile.canonicalize(field);
    (canonical.as_ref() != field
        && crate::search::lake::lake_count_rollup_field_multi_value(canonical.as_ref()).is_some())
    .then(|| canonical.into_owned())
}

fn lake_rollup_planning_search(profile: &dyn crate::schema::SchemaProfile, expr: &mut SearchExpr) {
    let rename = |field: &mut String| {
        if let Some(canonical) = lake_rollup_field_spelling(profile, field) {
            *field = canonical;
        }
    };
    match expr {
        SearchExpr::FieldFilter { field, .. } | SearchExpr::InList { field, .. } => rename(field),
        SearchExpr::BooleanFunction(EvalExpression::FunctionCall { args, .. }) => {
            for arg in args {
                if let EvalExpression::Field(field) = arg {
                    rename(field);
                }
            }
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            lake_rollup_planning_search(profile, left);
            lake_rollup_planning_search(profile, right);
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => {
            lake_rollup_planning_search(profile, inner)
        }
        _ => {}
    }
}

/// NAN-3780: `query` with every base-search field spelled the way the count
/// rollups key it (see [`lake_rollup_field_spelling`]). For PLANNING only:
/// the rollup classifiers match field names literally, so before this
/// `source_type IN (…) | stats count` asked the worker for a rollup on
/// `source_type`, which it refused, and every such count paid an error
/// round-trip before its raw scan. Pipeline commands (group-by names,
/// output columns) are untouched; anything executed as query text keeps
/// the caller's spelling.
pub(super) fn lake_rollup_planning_query(
    profile: &dyn crate::schema::SchemaProfile,
    query: &Query,
) -> Query {
    let mut planning = query.clone();
    let mut base = &mut planning;
    while let Query::Piped { source, .. } = base {
        base = source.as_mut();
    }
    if let Query::Search(search) = base {
        lake_rollup_planning_search(profile, search);
    }
    planning
}

/// NAN-3883: the stats half of [`lake_rollup_planning_query`]. Rewrites, in
/// place, the single-count `stats` directly over the base search into its
/// rollup spelling, so the rollup classifiers (which match names literally)
/// see what the count rollups key:
///
/// - a group field the profile compiles to a rollup field
///   (`by source_type` → `by metadata.log_source`);
/// - `count(F) by F` → `count() by F`: counting the group field itself
///   counts every row of every non-NULL group.
///
/// The returned spelling maps rollup rows back to the caller's columns; the
/// caller's text is still what any scan executes. `None`: nothing to rewrite.
fn lake_rollup_planning_stats(
    profile: &dyn crate::schema::SchemaProfile,
    query: &mut Query,
) -> Option<LakeRollupOutputSpelling> {
    let Query::Piped { source, command } = query else {
        return None;
    };
    if !matches!(source.as_ref(), Query::Search(_)) {
        return lake_rollup_planning_stats(profile, source);
    }
    let Command::Stats {
        aggregations,
        group_by: Some(group_by),
    } = command
    else {
        return None;
    };
    let ([aggregation], [group]) = (aggregations.as_mut_slice(), group_by.as_mut_slice()) else {
        return None;
    };
    if aggregation.func != AggFunc::Count
        || aggregation.condition.is_some()
        || aggregation.field_expr.is_some()
    {
        return None;
    }
    let spelled = |field: &str| lake_rollup_field_spelling(profile, field).unwrap_or_else(|| field.to_string());
    let rollup_group = spelled(group);
    // Scalar rollup fields only: a multi-valued field's group semantics are
    // the scan's to decide.
    let counts_group_field = aggregation.field.as_deref().is_some_and(|field| spelled(field) == rollup_group)
        && crate::search::lake::lake_count_rollup_field_multi_value(&rollup_group) == Some(false);
    if rollup_group == *group && !counts_group_field {
        return None;
    }
    if counts_group_field {
        // `count(F)` and `count()` both name their column `count` unless
        // aliased; keep the caller's column name either way.
        aggregation.alias = Some(aggregation.output_alias());
        aggregation.field = None;
    }
    let caller_group = std::mem::replace(group, rollup_group.clone());
    Some(LakeRollupOutputSpelling { rollup_group, caller_group, counts_group_field })
}

/// NAN-3883: put rollup `rows` into the caller's spelling (see
/// [`lake_rollup_planning_stats`]). `false`: the rollup answer is not the
/// caller's answer (a NULL group under `count(F) by F`); scan instead.
fn lake_apply_rollup_output_spelling(
    rows: &mut [serde_json::Value],
    spelling: &LakeRollupOutputSpelling,
) -> bool {
    for row in rows.iter_mut() {
        let Some(object) = row.as_object_mut() else {
            return false;
        };
        if spelling.rollup_group != spelling.caller_group {
            if let Some(value) = object.remove(&spelling.rollup_group) {
                object.insert(spelling.caller_group.clone(), value);
            }
        }
        if spelling.counts_group_field
            && object.get(&spelling.caller_group).is_none_or(serde_json::Value::is_null)
        {
            return false;
        }
    }
    true
}

/// Whether the worker's count rollups cover `field` at all (the contract
/// mirror [`crate::search::lake::LAKE_COUNT_ROLLUP_FIELDS`]). NAN-3780: a
/// request for any other field is refused by the worker as invalid, so it is
/// never sent; the caller scans directly.
fn lake_rollup_covers(field: &str) -> bool {
    crate::search::lake::lake_count_rollup_field_multi_value(field).is_some()
}

/// Whether the worker accepts `span_us` as a count-rollup bucket span: a
/// whole number of [`LAKE_COUNT_ROLLUP_BUCKET_US`] (the worker's
/// `validate_shape` refuses anything else as invalid).
fn lake_rollup_span_supported(span_us: Option<i64>) -> bool {
    span_us.is_none_or(|span| span >= LAKE_COUNT_ROLLUP_BUCKET_US && span % LAKE_COUNT_ROLLUP_BUCKET_US == 0)
}

/// The single-field rollup request (`field`, exact predicate) for `plan`, or
/// `None` when the rollups cannot answer it (uncovered field, a predicate
/// the rollup cannot express exactly, or a bucket span finer than or not
/// aligned to the rollup bucket).
///
/// NAN-4664: before the span check, `class_uid=4001 | timechart span=1m
/// count` sent a `-count-rollup` request with a 60 s span on every search;
/// the worker refused it as invalid and the search then ran its raw scan,
/// so each such hunt paid a wasted worker round-trip first.
fn lake_count_rollup_request<'a>(
    profile: &dyn crate::schema::SchemaProfile,
    plan: &'a LakeCountStatsPlan,
) -> Option<(&'a str, Option<LakeCountPredicate>)> {
    if !lake_rollup_span_supported(plan.bucket_span_us) {
        return None;
    }
    let field = plan.rollup_field.as_deref().filter(|field| lake_rollup_covers(field))?;
    lake_rollup_exact_predicate(profile, field, plan.rollup_predicate.as_ref())
        .map(|predicate| (field, predicate))
}

/// Identify the first distributed aggregation contract supported by the lake
/// path. A single `count()` over raw filtered events is algebraically exact:
/// each disjoint time slice can aggregate independently and Nano can sum equal
/// groups. More complex pipelines stay on the normal worker path until their
/// merge states are explicit; guessing would silently change query semantics.
/// The exact count-rollup request that answers a search histogram
/// (`<base> | timechart span=<s> count() as count`), when one exists.
///
/// NAN-2996: the histogram companion ran as a second full-window raw scan of
/// every data file for every UI search. When the base is a rollup-expressible
/// predicate (`*`, a source, a field equality/IN/CIDR, a source AND a field)
/// and the span is whole rollup buckets, the worker's `count_aggregate`
/// answers it from the parts' rollup partials (and raw-scans only the partial
/// edge buckets). The same routing already serves user `timechart count`
/// through [`lake_count_stats_plan`]; this only lets the companion use it.
pub(super) struct LakeHistogramRollupPlan {
    pub field: String,
    pub predicate: Option<LakeCountPredicate>,
    pub source_filter: Option<String>,
    pub bucket_span_us: i64,
}

pub(super) fn lake_histogram_rollup_plan(query: &Query) -> Option<LakeHistogramRollupPlan> {
    let plan = lake_count_stats_plan(query)?;
    let bucket_span_us = plan.bucket_span_us?;
    // The worker's rollup bucket (`nanosiem-lake-worker` `COUNT_ROLLUP_BUCKET_US`, 5 min);
    // it rejects any other span as invalid rather than guessing.
    let rollup_bucket_us: i64 = 300_000_000;
    if !plan.group_by.is_empty()
        || plan.rollup_union.is_some()
        || plan.count_alias != "count"
        || bucket_span_us < rollup_bucket_us
        || bucket_span_us % rollup_bucket_us != 0
    {
        return None;
    }
    Some(LakeHistogramRollupPlan {
        // NAN-3780: never ask the worker for a field its rollups refuse.
        field: plan.rollup_field.filter(|field| lake_rollup_covers(field))?,
        predicate: plan.rollup_predicate,
        source_filter: plan.rollup_source_filter,
        bucket_span_us,
    })
}

/// The count-rollup predicate that means exactly what the search means on
/// `field`, or `None` when the rollup cannot express it (the caller scans).
///
/// The rollup compares values case-insensitively and exactly (NAN-3093). The
/// search differs in three places the rollup must not paper over:
/// - a dotless equality on a host field matches the name and its FQDNs
///   (`hostname_equality_expands`): a single `=` is sent as `host_eq`, which
///   the worker evaluates as `lower(v) = h OR startsWith(lower(v), 'h.')`
///   (NAN-3153); `!=`/`IN` forms of it keep the raw path;
/// - an IP field compared to `a.b.c.d/n` is a CIDR range, not a value;
/// - an empty literal is an emptiness test, not a value.
pub(super) fn lake_rollup_exact_predicate(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
    predicate: Option<&LakeCountPredicate>,
) -> Option<Option<LakeCountPredicate>> {
    let Some(predicate) = predicate else {
        return Some(None);
    };
    if !matches!(predicate.kind, "eq" | "ne" | "in" | "not_in") {
        return Some(Some(predicate.clone()));
    }
    let is_ip = profile.entity_type(field) == Some(crate::schema::EntityType::Ip)
        || profile.field_type(field) == Some(crate::schema::FieldType::IpAddress)
        || field.ends_with(".ip");
    if predicate
        .values
        .iter()
        .any(|value| value.is_empty() || (is_ip && value.contains('/')))
    {
        return None;
    }
    if !predicate
        .values
        .iter()
        .any(|value| crate::query::hostname_equality_expands(profile, field, value))
    {
        return Some(Some(predicate.clone()));
    }
    (predicate.kind == "eq" && predicate.values.len() == 1).then(|| {
        Some(LakeCountPredicate {
            kind: "host_eq",
            values: predicate.values.clone(),
        })
    })
}

/// Whether some exact count-rollup predicate means what the search means
/// (see [`lake_rollup_exact_predicate`]).
pub(super) fn lake_rollup_predicate_is_exact(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
    predicate: Option<&LakeCountPredicate>,
) -> bool {
    lake_rollup_exact_predicate(profile, field, predicate).is_some()
}

/// The exact rollup predicate for one side of a [`LakeFieldUnionPlan`],
/// when the worker can count that side by log source.
fn lake_rollup_union_side(
    profile: &dyn crate::schema::SchemaProfile,
    field: &str,
    predicate: &LakeCountPredicate,
) -> Option<LakeCountPredicate> {
    let predicate = lake_rollup_exact_predicate(profile, field, Some(predicate))??;
    // Scalar fields only: a multi-value rollup counts a row once per distinct
    // value, so `eq` could count a row holding two case variants twice.
    let multi_value = crate::search::lake::lake_count_rollup_field_multi_value(field)?;
    (field != LAKE_SOURCE_FIELD
        && field != LAKE_DASHBOARD_BREAKDOWN_FIELD
        && !multi_value)
        .then_some(predicate)
}

/// Rollup fields whose values are close to unique per event (addresses,
/// ports, command lines, URLs, paths, ids, hashes). Their rollup holds about
/// one row per event per 5-minute bucket, so a grouped page over them reads
/// and folds more rollup rows than the compiled page scans (lab, NAN-3153:
/// `source=conduit_proxy | stats count by src_endpoint.ip` 1.07 s warm from
/// rollups vs 0.08 s compiled); such pages keep the compiled page.
fn lake_rollup_group_field_is_wide(field: &str) -> bool {
    [".ip", ".port", ".mac", ".uid", ".path", "cmd_line", "url_string", "hashes.value", "answers.rdata"]
        .iter()
        .any(|suffix| field.ends_with(suffix))
}

/// Whether the count rollups answer `plan` exactly as the compiled scan
/// would (NAN-3153). Lean cells route a grouped `stats count by …` page here
/// instead of the compiled page when this holds.
fn lake_count_plan_rollup_exact(
    profile: &dyn crate::schema::SchemaProfile,
    plan: &LakeCountStatsPlan,
) -> bool {
    if let Some(union) = &plan.rollup_field_union {
        return plan.bucket_span_us.is_none()
            && (plan.group_by.is_empty() || plan.group_by == [LAKE_SOURCE_FIELD])
            && lake_rollup_union_side(profile, &union.left_field, &union.left_predicate).is_some()
            && lake_rollup_union_side(profile, &union.right_field, &union.right_predicate).is_some();
    }
    if plan.rollup_union.is_some() {
        // NAN-4664: the union answers window totals only (see
        // `lake_count_rollup_rows`), never a bucketed series.
        return plan.bucket_span_us.is_none()
            && plan.group_by.is_empty()
            && plan.rollup_union.as_ref().is_some_and(|union| {
                lake_rollup_predicate_is_exact(profile, &union.field, Some(&union.predicate))
            });
    }
    let Some(field) = plan.rollup_field.as_deref() else {
        return false;
    };
    let Some(multi_value) = crate::search::lake::lake_count_rollup_field_multi_value(field) else {
        return false;
    };
    let Some(predicate) = lake_rollup_exact_predicate(profile, field, plan.rollup_predicate.as_ref())
    else {
        return false;
    };
    // A multi-value rollup counts a row once per distinct value: exact for
    // grouped pages only on scalar fields (the ungrouped `eq` route is
    // unchanged and never a page).
    let grouped_by_value = !plan.group_by.is_empty() && !plan.rollup_group_by_source;
    !(grouped_by_value && lake_rollup_group_field_is_wide(field))
        && (!multi_value
            || (plan.group_by.is_empty()
                && predicate.as_ref().is_some_and(|predicate| predicate.kind == "eq")))
}

/// `metadata.log_source → count` from source-grouped count rows (a NULL
/// source is its own key).
fn lake_source_counts(
    rows: &[serde_json::Value],
    count_alias: &str,
) -> Result<BTreeMap<Option<String>, u64>, SearchError> {
    let mut counts = BTreeMap::new();
    for row in rows {
        let malformed =
            || SearchError::SqlValidationError("source-grouped count row is malformed".to_string());
        let object = row.as_object().ok_or_else(malformed)?;
        let source = match object.get(LAKE_SOURCE_FIELD) {
            None | Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(source)) => Some(source.clone()),
            Some(_) => return Err(malformed()),
        };
        let count = object
            .get(count_alias)
            .and_then(|value| value.as_u64().or_else(|| value.as_str().and_then(|value| value.parse().ok())))
            .ok_or_else(malformed)?;
        let entry: &mut u64 = counts.entry(source).or_default();
        *entry = entry.checked_add(count).ok_or_else(malformed)?;
    }
    Ok(counts)
}

/// Per-source union counts that the two sides' rollup counts determine
/// exactly, and the sources where both sides match (whose intersection only
/// a scan can count). `None` when a NULL source matches both sides (it
/// cannot be narrowed to by a source filter).
#[derive(Debug, PartialEq, Eq)]
struct LakeFieldUnionCombination {
    disjoint: BTreeMap<Option<String>, u64>,
    overlap: BTreeSet<String>,
}

fn lake_field_union_combination(
    left: &BTreeMap<Option<String>, u64>,
    right: &BTreeMap<Option<String>, u64>,
) -> Option<LakeFieldUnionCombination> {
    let mut disjoint = BTreeMap::new();
    let mut overlap = BTreeSet::new();
    for source in left.keys().chain(right.keys()).collect::<BTreeSet<_>>() {
        let left = left.get(source).copied().unwrap_or(0);
        let right = right.get(source).copied().unwrap_or(0);
        if left > 0 && right > 0 {
            overlap.insert(source.clone()?);
        } else if left + right > 0 {
            disjoint.insert(source.clone(), left + right);
        }
    }
    Some(LakeFieldUnionCombination { disjoint, overlap })
}

/// Shape per-source union counts as the count route's rows: grouped by
/// `metadata.log_source` (count descending, then key) or one total row.
fn lake_field_union_rows(
    by_source: BTreeMap<Option<String>, u64>,
    grouped: bool,
    count_alias: &str,
) -> Result<Vec<serde_json::Value>, SearchError> {
    if !grouped {
        let total = by_source.values().try_fold(0_u64, |total, count| total.checked_add(*count)).ok_or_else(|| {
            SearchError::SqlValidationError("two-field count union overflowed UInt64".to_string())
        })?;
        return Ok(vec![serde_json::json!({ count_alias: total })]);
    }
    let mut rows = by_source
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(source, count)| {
            let mut row = serde_json::Map::new();
            row.insert(LAKE_SOURCE_FIELD.to_string(), source.map_or(serde_json::Value::Null, serde_json::Value::String));
            row.insert(count_alias.to_string(), serde_json::Value::from(count));
            (count, serde_json::Value::Object(row))
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right.0.cmp(&left.0).then_with(|| {
            serde_json::to_string(&left.1)
                .unwrap_or_default()
                .cmp(&serde_json::to_string(&right.1).unwrap_or_default())
        })
    });
    Ok(rows.into_iter().map(|(_, row)| row).collect())
}

/// Whether the field sidebar's drill-in (`<base> | stats count() as count
/// by <field> | sort -count | head N`) is answered from the parts' exact
/// count rollups rather than a raw scan of the window (NAN-3093).
pub(super) fn lake_field_values_rollup_served(
    profile: &dyn crate::schema::SchemaProfile,
    base_query: &str,
    field: &str,
) -> bool {
    let Ok(parsed) = parse_query(&format!("{base_query} | stats count() as count by {field}")) else {
        return false;
    };
    let Some(plan) = lake_count_stats_plan(&lake_rollup_planning_query(profile, &parsed)) else {
        return false;
    };
    let Some(rollup_field) = plan.rollup_field.as_deref() else {
        return false;
    };
    // The broad IP top-N runs as a compiled scan (see `lake_count_pipeline_plan`).
    let broad_ip_top_n = rollup_field == "src_endpoint.ip"
        && plan.rollup_predicate.is_none()
        && plan.rollup_source_filter.is_none();
    plan.rollup_union.is_none()
        && !broad_ip_top_n
        // A grouped rollup read serves scalar fields only.
        && crate::search::lake::lake_count_rollup_field_multi_value(rollup_field) == Some(false)
        && lake_rollup_predicate_is_exact(profile, rollup_field, plan.rollup_predicate.as_ref())
}

impl SearchService {
    /// Field-list companion reads must stay on the rollups: unlike a normal
    /// search, an unavailable rollup keeps the sidebar's sample instead of
    /// falling back to a scan of the whole window.
    pub(super) async fn lake_field_list_rollup_rows(
        &self,
        base_query: &str,
        field: &str,
        time_range: &TimeRangeInput,
        scope: &ScopeSet,
    ) -> Result<Option<Vec<serde_json::Value>>, SearchError> {
        let profile = self.active_profile.as_ref();
        if !lake_field_values_rollup_served(profile, base_query, field) {
            return Ok(None);
        }
        let Some(plan) = parse_query(&format!("{base_query} | stats count() as count by {field}"))
            .ok()
            .and_then(|query| lake_count_stats_plan(&lake_rollup_planning_query(profile, &query)))
        else {
            return Ok(None);
        };
        let Some(rollup_field) = plan.rollup_field.as_deref() else {
            return Ok(None);
        };
        let Some(predicate) =
            lake_rollup_exact_predicate(profile, rollup_field, plan.rollup_predicate.as_ref())
        else {
            return Ok(None);
        };
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError("lake field list requires a worker client".to_string())
        })?;
        let max_groups = self.query_limits.read().await.max_post_processing_groups as usize;
        client
            .count_aggregate_grouped(
                &format!("field-list-{}", uuid::Uuid::new_v4()),
                rollup_field,
                !plan.rollup_group_by_source,
                plan.rollup_group_by_source,
                predicate.as_ref(),
                None,
                &plan.count_alias,
                time_range,
                plan.rollup_source_filter.as_deref(),
                scope.deny_set(),
                max_groups,
            )
            .await
            .map(Some)
    }
}

fn lake_count_stats_plan(query: &Query) -> Option<LakeCountStatsPlan> {
    let Query::Piped { source, command } = query else {
        return None;
    };
    let Query::Search(search) = source.as_ref() else {
        return None;
    };
    let (aggregations, group_by, bucket_span_us) = match command {
        Command::Stats {
            aggregations,
            group_by,
        }
        | Command::Chart {
            aggregations,
            group_by,
        } => (aggregations, group_by.clone().unwrap_or_default(), None),
        Command::Timechart {
            span,
            aggregations,
            split_by,
            ..
        } => (
            aggregations,
            split_by.clone(),
            i64::try_from(span.as_micros()).ok(),
        ),
        _ => return None,
    };
    let [aggregation] = aggregations.as_slice() else {
        return None;
    };
    if aggregation.func != AggFunc::Count {
        return None;
    }
    let group_by = group_by.clone();
    let rollup_search = lake_count_rollup_search(search);
    // NAN-2361: ONLY a bare `count()` may take the typed count fast path.
    //
    // This path executes through the worker's `count_aggregate` RPC, whose
    // contract is "count rows matching a typed field/predicate" — it has no way
    // to carry an nPL `eval` condition, a field expression, or a counted field.
    // The guard above admits any `AggFunc::Count`, so `count(eval(<predicate>))`
    // was routed here and the CONDITION WAS SILENTLY DISCARDED: the aggregate
    // returned the plain row count. Measured live on 2,345 proxy events,
    // `count(eval(query.hostname=<value>))` returned 2,345 for a column NULL on
    // every one of them, while the identical predicate in `| where` returned 0.
    // The compiler was never at fault — it emits correct `countIf(...)`; that
    // SQL simply never ran, because routing bypassed it.
    //
    // Returning None here falls through to the general compiled-SQL path, which
    // already generates `countIf`/`sumIf`/`avgIf` correctly. `raw_count` was
    // already computing exactly this predicate — it just gated which rollup
    // shape to use rather than whether the fast path was legal at all.
    let raw_count = aggregation.condition.is_none()
        && aggregation.field_expr.is_none()
        && aggregation.field.is_none();
    // Reject ONLY the shape the typed RPC cannot express: an `eval` predicate.
    // `count(<field>)` and `count(<expr>)` keep their existing routing — this
    // guard is deliberately narrower than `raw_count` (which also gates the
    // rollup shapes below), because widening it silently changed behaviour for
    // field-carrying counts that this path has always served.
    if aggregation.condition.is_some() {
        return None;
    }
    let mut rollup_group_by_source = false;
    let mut rollup_field_union = None;
    let (rollup_field, rollup_predicate, rollup_source_filter, rollup_union) = if raw_count {
        match (group_by.as_slice(), rollup_search) {
            (groups, Some(LakeRollupSearch::All))
                if groups
                    .iter()
                    .map(String::as_str)
                    .eq(LAKE_DASHBOARD_BREAKDOWN_COMPONENTS.iter().copied()) =>
            {
                (
                    Some(LAKE_DASHBOARD_BREAKDOWN_FIELD.to_string()),
                    None,
                    None,
                    None,
                )
            }
            (groups, Some(LakeRollupSearch::Source(source)))
                if groups
                    .iter()
                    .map(String::as_str)
                    .eq(LAKE_DASHBOARD_BREAKDOWN_COMPONENTS.iter().copied()) =>
            {
                (
                    Some(LAKE_DASHBOARD_BREAKDOWN_FIELD.to_string()),
                    None,
                    Some(source),
                    None,
                )
            }
            ([group], Some(LakeRollupSearch::All)) => (Some(group.clone()), None, None, None),
            ([group], Some(LakeRollupSearch::Source(source))) => {
                (Some(group.clone()), None, Some(source), None)
            }
            (
                [group],
                Some(LakeRollupSearch::Predicate {
                    field,
                    predicate,
                    source,
                }),
            ) if field == *group => (Some(group.clone()), Some(predicate), source, None),
            // NAN-3153: the entity pivot `F=v | stats count by metadata.log_source`.
            (
                [group],
                Some(LakeRollupSearch::Predicate {
                    field,
                    predicate,
                    source,
                }),
            ) if group == LAKE_SOURCE_FIELD
                && field != LAKE_SOURCE_FIELD
                && field != LAKE_DASHBOARD_BREAKDOWN_FIELD =>
            {
                rollup_group_by_source = true;
                (Some(field), Some(predicate), source, None)
            }
            (groups, Some(LakeRollupSearch::FieldUnion(union)))
                if bucket_span_us.is_none()
                    && (groups.is_empty() || groups == [LAKE_SOURCE_FIELD]) =>
            {
                rollup_field_union = Some(union);
                (None, None, None, None)
            }
            ([], Some(LakeRollupSearch::All)) => {
                (Some("metadata.log_source".to_string()), None, None, None)
            }
            ([], Some(LakeRollupSearch::Source(source))) => (
                Some("metadata.log_source".to_string()),
                Some(LakeCountPredicate {
                    kind: "eq",
                    values: vec![source],
                }),
                None,
                None,
            ),
            (
                [],
                Some(LakeRollupSearch::Predicate {
                    field,
                    predicate,
                    source,
                }),
            ) => (Some(field), Some(predicate), source, None),
            ([], Some(LakeRollupSearch::SourcePredicateUnion(union))) => {
                (None, None, None, Some(union))
            }
            _ => (None, None, None, None),
        }
    } else {
        (None, None, None, None)
    };
    Some(LakeCountStatsPlan {
        group_by,
        count_alias: aggregation.output_alias(),
        rollup_field,
        rollup_predicate,
        rollup_source_filter,
        rollup_union,
        rollup_group_by_source,
        rollup_field_union,
        bucket_span_us,
        output_spelling: None,
    })
}

/// NAN-3173: the exact count-rollup plan that answers a split timechart's
/// whole long-form series set (`<base> | timechart span=<s> count by <f>`)
/// in one bucketed, grouped rollup read, or `None` when the rollups cannot
/// answer it exactly (the caller keeps the ranking + bucket scans).
///
/// `planning_source` must already be free of the caller's injected scope
/// gate (see [`SearchService::lake_timechart_inner_source`]); the rollup
/// request enforces the deny set itself as `deny_source_types`.
fn lake_timechart_rollup_plan(
    profile: &dyn crate::schema::SchemaProfile,
    planning_source: &Query,
    span: std::time::Duration,
    aggregation: &crate::query::Aggregation,
    fields: &[String],
) -> Option<LakeCountStatsPlan> {
    // The worker's rollup bucket (`COUNT_ROLLUP_BUCKET_US`, 5 min): any other
    // span is rejected by the worker rather than guessed.
    const ROLLUP_BUCKET_US: i64 = 300_000_000;
    if fields.is_empty() {
        return None;
    }
    let query = Query::Piped {
        source: Box::new(lake_rollup_planning_query(profile, planning_source)),
        command: Command::Timechart {
            span,
            bins: None,
            aggregations: vec![aggregation.clone()],
            split_by: fields.to_vec(),
            limit: None,
            cont: false,
            useother: true,
        },
    };
    let plan = lake_count_stats_plan(&query)?;
    let bucket_span_us = plan.bucket_span_us?;
    (plan.rollup_field.is_some()
        && plan.rollup_union.is_none()
        && plan.rollup_field_union.is_none()
        && plan.group_by == fields
        && bucket_span_us >= ROLLUP_BUCKET_US
        && bucket_span_us % ROLLUP_BUCKET_US == 0
        && lake_count_plan_rollup_exact(profile, &plan))
    .then_some(plan)
}

impl SearchService {
    /// NAN-3173: the base search a timechart builds its inner fetches from.
    ///
    /// `complete_timechart` receives the base AFTER the caller's lake source
    /// gate was injected, and every inner fetch goes back through
    /// [`SearchService::search`], which injects the same gate again. The
    /// doubled gate (`((base) AND gate) AND gate`) is invisible to the
    /// NAN-3163 planning strip, which removes exactly one injected conjunct,
    /// so every scoped timechart lost its count rollup. Here the outer gate
    /// is removed for exactly the requests the inner search re-gates (primary
    /// lake, logs dataset), so each inner fetch carries the gate once. When
    /// the gate cannot be stripped (e.g. an Unattributed deny) this returns
    /// `None` and the caller keeps the base: doubly gated, slower, correct.
    pub(super) fn lake_timechart_inner_source(
        &self,
        source: &Query,
        request: &SearchRequest,
        scope: &ScopeSet,
    ) -> Option<Query> {
        let dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
        if self.lake_query.mode != LakeQueryMode::Primary || dataset != crate::query::Dataset::Logs {
            return None;
        }
        strip_lake_source_scope_gate(source, scope.deny_set())
    }

    /// NAN-3173: the complete long-form rows (`time_bucket`, the split
    /// fields, the count) of a split count timechart from ONE bucketed,
    /// grouped count-rollup request, or `None` when no exact rollup answer
    /// exists (the caller then runs the ranking + bucket fetches).
    ///
    /// `planning_source` is the gate-free base (see
    /// [`Self::lake_timechart_inner_source`]), or the base itself for an
    /// unrestricted caller; `gated_source` is the base as the caller may
    /// execute it. The deny set rides on the rollup request.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn lake_timechart_rollup_rows(
        &self,
        request: &SearchRequest,
        scope: &ScopeSet,
        planning_source: &Query,
        gated_source: &Query,
        span: std::time::Duration,
        aggregation: &crate::query::Aggregation,
        fields: &[String],
    ) -> Option<Vec<serde_json::Value>> {
        let dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
        if self.lake_query.mode != LakeQueryMode::Primary
            || dataset != crate::query::Dataset::Logs
            || self.lake_query.client.is_none()
        {
            return None;
        }
        // A deny set whose gate cannot be stripped (Unattributed) keeps the
        // gated scans: never plan a rollup from a base that still carries it.
        if !scope.deny_set().is_empty()
            && strip_lake_source_scope_gate(gated_source, scope.deny_set()).is_none()
        {
            return None;
        }
        let plan = lake_timechart_rollup_plan(
            self.active_profile.as_ref(),
            planning_source,
            span,
            aggregation,
            fields,
        )?;
        let aggregate_query = Query::Piped {
            source: Box::new(gated_source.clone()),
            command: Command::Timechart {
                span,
                bins: None,
                aggregations: vec![aggregation.clone()],
                split_by: fields.to_vec(),
                limit: None,
                cont: false,
                useother: true,
            },
        };
        let query_id = request
            .request_id
            .clone()
            .unwrap_or_else(|| super::background_request::generated_query_id(uuid::Uuid::now_v7()));
        let max_groups = self.query_limits.read().await.max_post_processing_groups as usize;
        match self
            .lake_count_rollup_rows(request, &query_id, scope, &plan, &aggregate_query, max_groups)
            .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(
                    request_id = %query_id,
                    error = %error,
                    "timechart count rollup unavailable; running the series scans"
                );
                None
            }
        }
    }
}

/// Split a pipeline after its first exact count aggregation. The storage
/// worker executes only the aggregation prefix; bounded row transformations
/// run over that compact result in Rust. This keeps harmless suffixes such as
/// `sort`, `head`, `where`, `eval`, and a second `stats` stage from turning a
/// count-cube lookup back into a raw Parquet scan.
fn lake_count_pipeline_plan(query: &Query) -> Option<LakeCountPipelinePlan> {
    if let Some(aggregate) = lake_count_stats_plan(query) {
        return Some(LakeCountPipelinePlan {
            aggregate,
            aggregate_query: query.clone(),
            post_commands: Vec::new(),
        });
    }

    let Query::Piped { source, command } = query else {
        return None;
    };
    let supported = matches!(
        command,
        Command::Stats { .. }
            | Command::Where { .. }
            | Command::Head { .. }
            | Command::Tail { .. }
            | Command::Sort { .. }
            | Command::Table { .. }
            | Command::Dedup { .. }
            | Command::Rename { .. }
            | Command::Fields { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
            | Command::Fillnull { .. }
            | Command::Eval { .. }
            | Command::Timechart { .. }
            | Command::Rex { .. }
            | Command::Risk { .. }
    );
    if !supported {
        return None;
    }
    let mut plan = lake_count_pipeline_plan(source)?;
    plan.post_commands.push(command.clone());
    // The broad IP top-N shape can have millions of distinct groups even
    // though the final page is tiny. The count RPC materializes every group
    // before enforcing its one-million-group bound, then the caller scans the
    // same data again. Run the compiled top-N directly for this shape.
    if matches!(command, Command::Head { count } if *count <= 100)
        && plan.aggregate.group_by.len() == 1
        && plan.aggregate.group_by[0] == "src_endpoint.ip"
        && plan.aggregate.rollup_predicate.is_none()
        && plan.aggregate.rollup_source_filter.is_none()
        && plan.aggregate.bucket_span_us.is_none()
    {
        return None;
    }
    Some(plan)
}

/// [`lake_count_pipeline_plan`] for a search whose text carries the caller's
/// injected source-scope gate (NAN-3163). The gate is one more conjunct the
/// rollup classifier cannot express, so planning the gated query dropped every
/// count rollup (and every NAN-3153 rollup page) for any caller with a
/// non-empty deny set, including everyone without `audit:view`. The rollup
/// part of the plan comes from the query with that exact gate removed: every
/// rollup request carries the same deny set as `deny_source_types`, which the
/// worker applies to the rollup rows and the raw edges. Everything that
/// executes as a query stays gated: `aggregate_query` (the raw fallback and
/// the field-union overlap scan) is the gated query's aggregate prefix.
fn lake_count_pipeline_plan_scoped(
    gated: &Query,
    deny_set: &BTreeSet<String>,
) -> Option<LakeCountPipelinePlan> {
    let Some(mut plan) = strip_lake_source_scope_gate(gated, deny_set)
        .as_ref()
        .and_then(lake_count_pipeline_plan)
    else {
        return lake_count_pipeline_plan(gated);
    };
    // Stripping touches only the base scan, so the gated query has the same
    // commands: its aggregate prefix is it minus the post commands.
    let mut aggregate_query = gated;
    for _ in &plan.post_commands {
        let Query::Piped { source, .. } = aggregate_query else {
            return lake_count_pipeline_plan(gated);
        };
        aggregate_query = source;
    }
    plan.aggregate_query = aggregate_query.clone();
    Some(plan)
}

/// [`lake_count_pipeline_plan_scoped`] planned from the rollup spelling of
/// the base search's fields (NAN-3780, [`lake_rollup_planning_query`]), so
/// `source_type IN (…) | stats count` is served by the `metadata.log_source`
/// rollup. The plan's `aggregate_query` (executed by the raw fallback and the
/// field-union overlap scan) stays the caller's own gated text.
fn lake_count_pipeline_plan_for(
    profile: &dyn crate::schema::SchemaProfile,
    gated: &Query,
    deny_set: &BTreeSet<String>,
) -> Option<LakeCountPipelinePlan> {
    // NAN-4295: `count by <array leaf>` (any element type; the compiler's own
    // predicate) groups by EACH element. The worker's
    // typed count groups by `toString(<array>)` (whole-array keys such as
    // `['T1110']`, and `[null]` for a repeated object's leaf), and its rollups
    // serve scalar groups only, so such a plan always takes the compiled
    // page, which joins the elements.
    lake_count_pipeline_plan_for_inner(profile, gated, deny_set).filter(|plan| {
        !plan
            .aggregate
            .group_by
            .iter()
            .any(|field| crate::query::clickhouse_sql_gen::search_expr::stats_by_schema_field_is_array(profile, field))
    })
}

fn lake_count_pipeline_plan_for_inner(
    profile: &dyn crate::schema::SchemaProfile,
    gated: &Query,
    deny_set: &BTreeSet<String>,
) -> Option<LakeCountPipelinePlan> {
    let mut planning = lake_rollup_planning_query(profile, gated);
    // NAN-3883: the stats command too (`count(source_type) by source_type`).
    let output_spelling = lake_rollup_planning_stats(profile, &mut planning);
    if planning == *gated {
        return lake_count_pipeline_plan_scoped(gated, deny_set);
    }
    let Some(mut plan) = lake_count_pipeline_plan_scoped(&planning, deny_set) else {
        return lake_count_pipeline_plan_scoped(gated, deny_set);
    };
    if let Some(spelling) = output_spelling {
        // Rows reach every consumer (validation, post commands, the raw
        // fallback's own output) under the caller's group column.
        for group in &mut plan.aggregate.group_by {
            if *group == spelling.rollup_group {
                *group = spelling.caller_group.clone();
            }
        }
        plan.aggregate.output_spelling = Some(spelling);
    }
    // The rewrite touches only the base search, so both texts have the same
    // commands: the caller's aggregate prefix is it minus the post commands.
    let mut aggregate_query = gated;
    for _ in &plan.post_commands {
        let Query::Piped { source, .. } = aggregate_query else {
            return lake_count_pipeline_plan_scoped(gated, deny_set);
        };
        aggregate_query = source;
    }
    plan.aggregate_query = aggregate_query.clone();
    Some(plan)
}

/// Preserve the small source/dashboard count cubes: paging must not turn a
/// cheap rollup lookup into a raw-event scan. Unbounded entity groups use SQL.
fn lake_stats_uses_compiled_page(query: &Query, count: Option<&LakeCountPipelinePlan>) -> bool {
    crate::query::stats_page::eligible(query)
        && !count.is_some_and(|plan| matches!(plan.aggregate.rollup_field.as_deref(),
            Some("metadata.log_source") | Some(LAKE_DASHBOARD_BREAKDOWN_FIELD)))
}

/// The worker's count-rollup bucket (`nanosiem-lake-worker`
/// `COUNT_ROLLUP_BUCKET_US`). The worker refuses a bucketed count request
/// whose span is not a whole number of these.
const LAKE_COUNT_ROLLUP_BUCKET_US: i64 = 300_000_000;

/// NAN-4184: whether the lean cell answers `query` from its 5-minute count
/// rollups without scanning events. It uses the same plan the service sends
/// to the worker's `/v1/aggregate/count`
/// ([`lake_count_pipeline_plan_for`] + [`lake_count_plan_rollup_exact`]).
/// Typical matches are `* | stats count by metadata.log_source`, the
/// `class_uid` / `source_type` inventories, and a timechart count over whole
/// rollup buckets. Any suffix the count pipeline runs over the compact
/// rollup rows (sort, head, where on count, ...) is allowed. Planned for an
/// unrestricted caller: a caller's source-scope gate is stripped from rollup
/// planning anyway ([`lake_count_pipeline_plan_scoped`]).
pub fn lake_count_rollup_answers(profile: &dyn crate::schema::SchemaProfile, query: &Query) -> bool {
    let Some(plan) = lake_count_pipeline_plan_for(profile, query, &BTreeSet::new()) else {
        return false;
    };
    lake_count_plan_rollup_exact(profile, &plan.aggregate)
        && lake_rollup_span_supported(plan.aggregate.bucket_span_us)
}

/// How a lean cell answers a raw-search aggregation (NAN-3153).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LakeCellStatsRoute {
    /// Not a bounded grouped page: the count route (rollups when exact,
    /// else a raw count scan) or the general path, as before.
    Default,
    /// A grouped page every predicate and group of which the count rollups
    /// answer exactly: try them (up to [`LAKE_CELL_ROLLUP_PAGE_MAX_GROUPS`]
    /// groups), and run the bounded compiled page only if they cannot.
    RollupThenCompiledPage,
    /// A grouped page the rollups cannot answer exactly: compiled page.
    CompiledPage,
}

/// NAN-3077 sent every grouped `stats count by …` page on a lean cell to the
/// compiled page so a high-cardinality group set is never materialized whole,
/// which also forced a full scan for entity pivots the rollups answer in
/// milliseconds (`host=h | stats count by metadata.log_source`). The rollup
/// answer is exact and complete, so it is tried first when it exists; the
/// group bound keeps the NAN-3077 guarantee.
fn lake_cell_stats_route(
    profile: &dyn crate::schema::SchemaProfile,
    query: &Query,
    count: Option<&LakeCountPipelinePlan>,
) -> LakeCellStatsRoute {
    if !lake_stats_uses_compiled_page(query, count) {
        return LakeCellStatsRoute::Default;
    }
    if count.is_some_and(|plan| lake_count_plan_rollup_exact(profile, &plan.aggregate)) {
        LakeCellStatsRoute::RollupThenCompiledPage
    } else {
        LakeCellStatsRoute::CompiledPage
    }
}

/// `sort -time` (single descending event-time key): the lake's implicit
/// event order, so it commutes with a newest-first `head`.
fn is_newest_first_time_sort(fields: &[crate::query::SortField]) -> bool {
    matches!(fields, [field] if field.descending
        && matches!(field.field.as_str(), "time" | "timestamp" | "_time"))
}

/// NAN-3466: the caller's page over a `head N` that was pulled out of the
/// worker query and fetched as one complete N-row set at offset 0.
#[derive(Debug, Clone, Copy)]
struct LakeHeadWindow {
    head_count: usize,
    requested_limit: usize,
    requested_offset: usize,
}

impl LakeHeadWindow {
    /// Cut the fetched set to N, then page it. The N-row set was fetched
    /// whole, so its size is the exact total (as on the head page path).
    fn apply(&self, response: &mut SearchResponse) {
        response.results.truncate(self.head_count);
        response.total_count = response.results.len() as u64;
        response.total_count_exact = true;
        let results = std::mem::take(&mut response.results);
        response.results = results
            .into_iter()
            .skip(self.requested_offset)
            .take(self.requested_limit)
            .collect();
    }
}

/// Pull a bounded `head` out of an otherwise row/order-preserving event
/// pipeline. The compiler can then prove the remaining projection is a
/// newest-first timeline and the worker can stop after the newest source
/// chunks. Moving `head` across these commands is exact because none changes
/// row membership or order.
fn lake_head_page_plan(query: &Query) -> Option<LakeHeadPagePlan> {
    fn recurse(query: &Query) -> Option<(Query, Option<usize>)> {
        match query {
            Query::Search(search) => Some((Query::Search(search.clone()), None)),
            Query::Piped { source, command } => {
                let (source, head_count) = recurse(source)?;
                match command {
                    Command::Head { count } => Some((
                        source,
                        Some(head_count.map_or(*count, |old| old.min(*count))),
                    )),
                    Command::Table { .. }
                    | Command::Fields { .. }
                    | Command::Rename { .. }
                    | Command::Fillnull { .. }
                    | Command::Eval { .. }
                    | Command::Rex { .. } => Some((
                        Query::Piped {
                            source: Box::new(source),
                            command: command.clone(),
                        },
                        head_count,
                    )),
                    // An explicit `sort -time` restates the implicit
                    // newest-first event order, so `| sort -time | head N`
                    // (and `| head N | sort -time`) is the same global top-N
                    // page. Without this the head stayed inside the compiled
                    // query, the worker ran it per progressive time chunk,
                    // and concatenated k*N rows up to the page limit.
                    Command::Sort { fields, limit } if is_newest_first_time_sort(fields) => {
                        let head_count = match (head_count, limit) {
                            (Some(head), Some(limit)) => Some(head.min(*limit)),
                            (head, limit) => head.or(*limit),
                        };
                        Some((
                            Query::Piped {
                                source: Box::new(source),
                                command: Command::Sort {
                                    fields: fields.clone(),
                                    limit: None,
                                },
                            },
                            head_count,
                        ))
                    }
                    _ => None,
                }
            }
        }
    }

    let (query_without_head, head_count) = recurse(query)?;
    let head_count = head_count?;
    (head_count <= 10_000).then_some(LakeHeadPagePlan {
        query_without_head,
        head_count,
    })
}

fn lake_distinct_pipeline_plan(query: &Query) -> Option<LakeDistinctPipelinePlan> {
    fn delimiter_safe_state_field(field: &str) -> bool {
        matches!(
            field,
            "src_endpoint.ip"
                | "dst_endpoint.ip"
                | "src_endpoint.hostname"
                | "dst_endpoint.hostname"
                | "device.hostname"
                | "user.name"
                | "user.uid"
                | "actor.user.name"
                | "actor.user.uid"
                | "process.uid"
                | "actor.process.uid"
                | "src_endpoint.port"
                | "dst_endpoint.port"
                | "file.hashes.value"
                | "process.file.hashes.value"
                | "actor.process.file.hashes.value"
        )
    }

    fn raw_prefix(query: &Query) -> bool {
        match query {
            Query::Search(_) => true,
            Query::Piped { source, command } => {
                raw_prefix(source)
                    && matches!(
                        command,
                        Command::Where { .. }
                            | Command::Eval { .. }
                            | Command::Rex { .. }
                            | Command::Fillnull { .. }
                    )
            }
        }
    }

    fn recurse(query: &Query) -> Option<LakeDistinctPipelinePlan> {
        if let Query::Piped { source, command } = query {
            if raw_prefix(source) {
                if let Command::Stats {
                    aggregations,
                    group_by,
                } = command
                {
                    let distinct = aggregations.iter().find(|aggregation| {
                        aggregation.func == AggFunc::Dc
                            && aggregation.condition.is_none()
                            && aggregation.field_expr.is_none()
                    })?;
                    let distinct_field = distinct.field.clone()?;
                    let values = aggregations.iter().find(|aggregation| {
                        aggregation.func == AggFunc::Values
                            && aggregation.condition.is_none()
                            && aggregation.field_expr.is_none()
                            && aggregation.field.as_deref() == Some(distinct_field.as_str())
                    });
                    let count = aggregations.iter().find(|aggregation| {
                        aggregation.func == AggFunc::Count
                            && aggregation.condition.is_none()
                            && aggregation.field_expr.is_none()
                            && aggregation.field.is_none()
                    });
                    let supported_count =
                        usize::from(values.is_some()) + usize::from(count.is_some()) + 1;
                    if supported_count != aggregations.len() {
                        return None;
                    }
                    if !delimiter_safe_state_field(&distinct_field) {
                        return None;
                    }
                    let group_by = group_by.clone().unwrap_or_default();
                    if group_by.len() > 2 {
                        return None;
                    }
                    let encoded_alias = "__nano_distinct_token".to_string();
                    let values_alias = "__nano_distinct_values".to_string();
                    let merge_source = Query::Piped {
                        source: source.clone(),
                        command: Command::Eval {
                            assignments: vec![EvalAssignment {
                                field: encoded_alias.clone(),
                                expression: EvalExpression::FunctionCall {
                                    name: "base64_encode".to_string(),
                                    // Ports and other numeric OCSF leaves are
                                    // valid dc()/values() inputs, while chDB's
                                    // base64Encode accepts only strings. The
                                    // distributed state is textual by design,
                                    // so normalize every supported leaf before
                                    // encoding instead of special-casing types.
                                    args: vec![EvalExpression::FunctionCall {
                                        name: "tostring".to_string(),
                                        args: vec![EvalExpression::Field(distinct_field)],
                                    }],
                                },
                            }],
                        },
                    };
                    let mut merge_aggregations = vec![crate::query::Aggregation::with_alias(
                        AggFunc::Values,
                        Some(encoded_alias),
                        values_alias.clone(),
                    )];
                    if let Some(count) = count {
                        merge_aggregations.push(count.clone());
                    }
                    let aggregate_query = Query::Piped {
                        source: Box::new(merge_source),
                        command: Command::Stats {
                            aggregations: merge_aggregations,
                            group_by: (!group_by.is_empty()).then_some(group_by.clone()),
                        },
                    };
                    return Some(LakeDistinctPipelinePlan {
                        group_by,
                        output_alias: distinct.output_alias(),
                        values_output_alias: values.map(crate::query::Aggregation::output_alias),
                        count_output_alias: count.map(crate::query::Aggregation::output_alias),
                        values_alias,
                        aggregate_query,
                        post_commands: Vec::new(),
                    });
                }
            }
            let supported = matches!(
                command,
                Command::Stats { .. }
                    | Command::Where { .. }
                    | Command::Head { .. }
                    | Command::Tail { .. }
                    | Command::Sort { .. }
                    | Command::Table { .. }
                    | Command::Dedup { .. }
                    | Command::Rename { .. }
                    | Command::Fields { .. }
                    | Command::Top { .. }
                    | Command::Rare { .. }
                    | Command::Fillnull { .. }
                    | Command::Eval { .. }
                    | Command::Timechart { .. }
                    | Command::Rex { .. }
                    | Command::Risk { .. }
            );
            if supported {
                let mut plan = recurse(source)?;
                plan.post_commands.push(command.clone());
                return Some(plan);
            }
        }
        None
    }

    recurse(query)
}

fn lake_eval_count_predicate(expression: &EvalExpression) -> Option<(String, LakeCountPredicate)> {
    if let Some(predicate) = lake_count_boolean_predicate(expression) {
        return Some(predicate);
    }
    let EvalExpression::BinaryOp { left, op, right } = expression else {
        return None;
    };
    let (field, value, comparator) = match (left.as_ref(), op, right.as_ref()) {
        (
            EvalExpression::Field(field),
            crate::query::BinaryOperator::Eq,
            EvalExpression::Literal(value),
        ) => (field, value, Comparator::Eq),
        (
            EvalExpression::Field(field),
            crate::query::BinaryOperator::Ne,
            EvalExpression::Literal(value),
        ) => (field, value, Comparator::Ne),
        (
            EvalExpression::Field(field),
            crate::query::BinaryOperator::Contains,
            EvalExpression::Literal(value),
        ) => (field, value, Comparator::Contains),
        _ => return None,
    };
    Some((
        field.clone(),
        lake_count_field_predicate(field, comparator, value)?,
    ))
}

fn lake_count_metrics_plan(query: &Query) -> Option<LakeCountMetricsPlan> {
    let Query::Piped { source, command } = query else {
        return None;
    };
    let Command::Stats {
        aggregations,
        group_by,
    } = command
    else {
        return None;
    };
    if group_by.as_ref().is_some_and(|groups| !groups.is_empty())
        || aggregations.len() < 2
        || aggregations.len() > 16
    {
        return None;
    }
    let (search, assignments) = match source.as_ref() {
        Query::Search(search) => (search, &[][..]),
        Query::Piped {
            source,
            command: Command::Eval { assignments },
        } => {
            let Query::Search(search) = source.as_ref() else {
                return None;
            };
            (search, assignments.as_slice())
        }
        _ => return None,
    };
    let source_filter = match lake_count_rollup_search(search)? {
        LakeRollupSearch::All => None,
        LakeRollupSearch::Source(source) => Some(source),
        _ => return None,
    };
    let mut metrics = Vec::with_capacity(aggregations.len());
    for aggregation in aggregations {
        let metric = if aggregation.func == AggFunc::Count
            && aggregation.field.is_none()
            && aggregation.field_expr.is_none()
            && aggregation.condition.is_none()
        {
            match source_filter.as_ref() {
                Some(source) => LakeCountMetric {
                    alias: aggregation.output_alias(),
                    field: "metadata.log_source".to_string(),
                    predicate: Some(LakeCountPredicate {
                        kind: "eq",
                        values: vec![source.clone()],
                    }),
                    source_filter: None,
                },
                None => LakeCountMetric {
                    alias: aggregation.output_alias(),
                    field: "metadata.log_source".to_string(),
                    predicate: None,
                    source_filter: None,
                },
            }
        } else if aggregation.func == AggFunc::Count {
            let condition = aggregation.condition.as_ref()?;
            let (field, predicate) = lake_eval_count_predicate(condition)?;
            LakeCountMetric {
                alias: aggregation.output_alias(),
                field,
                predicate: Some(predicate),
                source_filter: source_filter.clone(),
            }
        } else if aggregation.func == AggFunc::Sum {
            let assignment_field = aggregation.field.as_ref()?;
            let assignment = assignments
                .iter()
                .find(|assignment| assignment.field == *assignment_field)?;
            let EvalExpression::FunctionCall { name, args } = &assignment.expression else {
                return None;
            };
            if !name.eq_ignore_ascii_case("if") || args.len() != 3 {
                return None;
            }
            let (
                EvalExpression::Literal(Value::Number(when_true)),
                EvalExpression::Literal(Value::Number(when_false)),
            ) = (&args[1], &args[2])
            else {
                return None;
            };
            if *when_true != 1.0 || *when_false != 0.0 {
                return None;
            }
            let (field, predicate) = lake_eval_count_predicate(&args[0])?;
            LakeCountMetric {
                alias: aggregation.output_alias(),
                field,
                predicate: Some(predicate),
                source_filter: source_filter.clone(),
            }
        } else {
            return None;
        };
        // NAN-3780: every metric is a `count_aggregate` request, which the
        // worker refuses for a field its rollups do not cover; such a
        // metrics query takes the general path instead of failing.
        if !lake_rollup_covers(&metric.field) {
            return None;
        }
        metrics.push(metric);
    }
    Some(LakeCountMetricsPlan { metrics })
}

/// [`lake_count_metrics_plan`] for a search whose text carries the caller's
/// injected source-scope gate (NAN-3166, after NAN-3163). The gate is a
/// conjunct `lake_count_rollup_search` cannot express, so planning the gated
/// text dropped the exact count-metrics route for every scoped caller. The
/// plan is made from the query with that exact gate removed: it is executed
/// only as `count_aggregate` requests, each carrying the same deny set as
/// `deny_source_types`, which the worker applies to the rollup rows and to
/// the raw edge fragments. No query text is executed from it. Deny sets
/// naming Unattributed are never stripped (see
/// [`strip_lake_source_scope_gate`]) and keep the gated plan.
fn lake_count_metrics_plan_scoped(
    gated: &Query,
    deny_set: &BTreeSet<String>,
) -> Option<LakeCountMetricsPlan> {
    match strip_lake_source_scope_gate(gated, deny_set) {
        Some(stripped) => lake_count_metrics_plan(&stripped),
        None => lake_count_metrics_plan(gated),
    }
}

fn lake_single_count(rows: &[serde_json::Value], alias: &str) -> Result<u64, SearchError> {
    let [row] = rows else {
        return Err(SearchError::SqlValidationError(
            "count rollup did not return exactly one row".to_string(),
        ));
    };
    row.get(alias)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .ok_or_else(|| {
            SearchError::SqlValidationError("count rollup omitted its UInt64 count".to_string())
        })
}

const LAKE_MAX_DISTRIBUTED_AGGREGATE_CHUNKS: usize = 4_096;

pub fn is_lake_scan_budget_rejection(error: &SearchError) -> bool {
    match error {
        // Current workers return a typed 422 that the lake client maps to the
        // resource kind. Keep the older text form for archived workers during
        // a rolling upgrade. Only this physical fence can justify trying
        // smaller time slices; LakeSliceRetries bounds that recovery.
        SearchError::ResourceExhausted(kind) => kind == "scan" || kind.starts_with("scan;"),
        SearchError::SqlValidationError(message) => message.contains("query scan budget rejected"),
        _ => false,
    }
}

const LAKE_MAX_SLICE_ATTEMPTS: usize = 64;

/// Per-row bound of the exact values state the lake compiler emits for
/// distributed `dc()`/`values()` (`INTERNAL_DISTINCT_VALUES_LIMIT` in
/// `bin/lake_query_compile.rs`, `groupUniqArray(10001)`). A state this full
/// may be truncated.
const LAKE_DISTINCT_STATE_CAP: usize = 10_001;

fn lake_distinct_state_len(state: &serde_json::Value) -> usize {
    match state {
        serde_json::Value::Array(values) => values.iter().filter(|value| !value.is_null()).count(),
        serde_json::Value::String(values) => {
            values.split(", ").filter(|value| !value.is_empty()).count()
        }
        serde_json::Value::Null => 0,
        _ => 1,
    }
}

/// Preserve exact byte counts across the worker/client boundary. Archived
/// workers used the planner's text diagnostic instead of structured fields.
fn lake_scan_budget_bytes(error: &SearchError) -> Option<(u64, u64)> {
    let message = match error {
        SearchError::ResourceExhausted(message) | SearchError::SqlValidationError(message) => {
            message
        }
        _ => return None,
    };
    if let Some(rest) = message.strip_prefix("scan; estimated_bytes=") {
        let (estimated, budget) = rest.split_once("; budget_bytes=")?;
        return Some((estimated.parse().ok()?, budget.parse().ok()?));
    }
    let (_, rest) = message.split_once("query scan budget rejected ")?;
    let (estimated, budget) = rest.split_once(" bytes above ")?;
    Some((
        estimated.parse().ok()?,
        budget.split_whitespace().next()?.parse().ok()?,
    ))
}

pub(super) struct LakeSliceRetries {
    scheduled: usize,
    rejected: std::collections::HashMap<String, Option<(u64, u64)>>,
}

impl LakeSliceRetries {
    pub(super) fn new() -> Self {
        Self {
            scheduled: 1,
            rejected: Default::default(),
        }
    }

    pub(super) fn split(
        &mut self,
        path: &str,
        range: &TimeRangeInput,
        error: SearchError,
        query: &str,
    ) -> Result<(TimeRangeInput, TimeRangeInput), SearchError> {
        let bytes = lake_scan_budget_bytes(&error);
        let parent = path
            .get(..path.len().saturating_sub(1))
            .and_then(|parent| self.rejected.get(parent));
        let stalled = parent.is_some_and(|parent| match (*parent, bytes) {
            (Some((previous, _)), Some((current, _))) => {
                u128::from(current) * 4 > u128::from(previous) * 3
            }
            // Legacy workers omit estimates. The attempt cap and minute
            // floor still bound recovery; do not stop after just one split.
            _ => false,
        });
        let stop = stalled
            || (range.end - range.start) < chrono::Duration::minutes(1)
            || self.scheduled + 2 > LAKE_MAX_SLICE_ATTEMPTS
            || self.scheduled + 2 > LAKE_MAX_DISTRIBUTED_AGGREGATE_CHUNKS;
        if stop {
            let message = if let Some((estimated, budget)) = bytes {
                format!(
                    "scan slice needs {:.2} MB, budget {:.2} MB (estimated_bytes={estimated}, budget_bytes={budget}); stopped after scheduling {} slice attempts",
                    estimated as f64 / 1_000_000.0,
                    budget as f64 / 1_000_000.0,
                    self.scheduled
                )
            } else {
                format!(
                    "scan slice exceeds the worker budget (byte estimate unavailable); stopped after scheduling {} slice attempts",
                    self.scheduled
                )
            };
            // Only the exact original nPL may be promoted to the SQL-only
            // durable lane. Nano-side suffixes must fail without losing work.
            return Err(if validate_durable_lake_sql_only_query(query).is_ok() {
                SearchError::ResourceExhausted(message)
            } else {
                SearchError::SqlValidationError(message)
            });
        }
        let split = split_lake_aggregate_range(range).ok_or(error)?;
        self.scheduled += 2;
        self.rejected.insert(path.to_string(), bytes);
        Ok(split)
    }
}

/// Bisect one half-open `[start, end)` event-time range without overlap
/// (NAN-4280): the halves share `right_start`, which belongs to the right
/// half only. (With the old inclusive `BETWEEN` bound the left side had to
/// end one microsecond earlier.)
fn split_lake_aggregate_range(
    time_range: &TimeRangeInput,
) -> Option<(TimeRangeInput, TimeRangeInput)> {
    let width_us = (time_range.end - time_range.start).num_microseconds()?;
    if width_us < 2 {
        return None;
    }
    let right_start = time_range.start + chrono::Duration::microseconds(width_us / 2);
    Some((
        TimeRangeInput {
            start: time_range.start,
            end: right_start,
        },
        TimeRangeInput {
            start: right_start,
            end: time_range.end,
        },
    ))
}

/// Execute a bounded event candidate fetch without weakening the worker's
/// physical byte fence. Wide windows are split newest-first only after the
/// trusted worker rejects a slice, and successful disjoint slices are merged
/// until the caller's existing in-memory candidate cap is full.
async fn search_lake_rows_with_budget_slices(
    client: &crate::search::lake::LakeQueryClient,
    request: &SearchRequest,
    query_id: &str,
    risk_config: Option<&crate::risk::clickhouse_sql::RiskQueryConfig>,
    deny_source_types: &std::collections::BTreeSet<String>,
) -> Result<SearchResponse, SearchError> {
    let target = request.limit.unwrap_or(100).max(1);
    let mut pending = vec![("0".to_string(), request.time_range.clone())];
    let mut retries = LakeSliceRetries::new();
    let mut completed_slices = 0;
    let mut template = None;
    let mut results = Vec::new();
    let mut total_count = 0_u64;
    let mut warnings = Vec::new();
    let mut sliced = false;
    let mut incomplete = false;

    while let Some((path, range)) = pending.pop() {
        if results.len() >= target {
            incomplete = true;
            break;
        }
        let mut slice_request = request.clone();
        slice_request.time_range = range.clone();
        slice_request.limit = Some(target - results.len());
        slice_request.offset = Some(0);
        let slice_query_id = format!("{query_id}-rows-{path}");
        slice_request.request_id = Some(slice_query_id.clone());
        match client
            .search(
                &slice_request,
                &slice_query_id,
                risk_config,
                deny_source_types,
            )
            .await
        {
            Ok(mut response) => {
                completed_slices += 1;
                total_count = total_count.saturating_add(response.total_count);
                incomplete |= !response.total_count_exact;
                if let Some(mut slice_warnings) = response.warnings.take() {
                    warnings.append(&mut slice_warnings);
                }
                results.append(&mut response.results);
                template.get_or_insert(response);
            }
            Err(error) if is_lake_scan_budget_rejection(&error) => {
                let (older, newer) = retries.split(&path, &range, error, &request.query)?;
                sliced = true;
                // Stack order is deliberate: pop and scan the newer half first.
                pending.push((format!("{path}l"), older));
                pending.push((format!("{path}r"), newer));
            }
            Err(error) => return Err(error),
        }
    }

    let mut response = template.ok_or_else(|| {
        SearchError::SqlValidationError(
            "scan-budgeted lake row fetch produced no executable slice".to_string(),
        )
    })?;
    results.truncate(target);
    incomplete |= !pending.is_empty() || total_count > results.len() as u64;
    response.results = results;
    // NAN-2550: report the bound AS a bound. The old `+ incomplete as u64` made a
    // 50-row incomplete page claim 51 hits; `total_count_exact` says the same
    // thing without inventing a row.
    response.total_count = total_count.max(response.results.len() as u64);
    response.total_count_exact = !incomplete;
    if sliced {
        warnings.push(QueryWarningOutput {
            severity: "info".to_string(),
            code: "LAKE_SCAN_BUDGET_SLICED".to_string(),
            message: format!(
                "The event candidate fetch was executed as {completed_slices} byte-fenced time slices"
            ),
            suggestion: None,
            impact: None,
        });
    }
    response.warnings = (!warnings.is_empty()).then_some(warnings);
    Ok(response)
}

impl SearchService {
    /// Kill an evaluator-owned set of exact ClickHouse query IDs in one
    /// cluster-aware round trip. Autonomous replay owns every ID up front, so
    /// timeout/error cleanup does not depend on local request tracking.
    pub(crate) async fn cancel_exact_queries(
        &self,
        query_ids: &[String],
    ) -> Result<bool, SearchError> {
        let Some(executor) = &self.ch_executor else {
            for query_id in query_ids {
                self.query_tracker.unregister(query_id);
            }
            tracing::warn!(
                "Exact query cancellation is unavailable for the PostgreSQL search backend"
            );
            return Ok(false);
        };
        let result = executor.cancel_queries(query_ids).await;
        for query_id in query_ids {
            self.query_tracker.unregister(query_id);
        }
        result
    }

    /// Cancel a running query by its request ID
    ///
    /// Stateless cancellation: the frontend request_id IS used as the ClickHouse
    /// query_id (see search() below), so we can issue KILL QUERY directly without
    /// needing to look up the mapping on the correct instance.
    ///
    /// NAN-1728 (H2): `KILL QUERY` is in fact **node-local** — it only kills
    /// queries initiated on the connected ClickHouse node, NOT global to the
    /// cluster as this comment previously (incorrectly) claimed. On a clustered
    /// deployment the cancel connection is load-balanced and can land on a
    /// different node than the search's initiator, so a node-local kill would
    /// no-op and the query would run on unstopped. `cancel_queries` therefore
    /// fans the kill out with `KILL QUERY ON CLUSTER` (and reads
    /// `clusterAllReplicas(system.processes)`) when clustered; on single-node it
    /// emits the exact pre-cluster node-local SQL.
    ///
    /// The local QueryTracker is still maintained for metrics/debugging but is not
    /// required for correctness.
    pub async fn cancel_query(&self, request_id: &str) -> Result<bool, SearchError> {
        if let Some(cancel) = self.follow_cancellations.get(request_id) {
            let _ = cancel.send(true);
            self.query_tracker.unregister(request_id);
            return Ok(true);
        }
        if self.lake_query.mode == LakeQueryMode::Primary {
            let client = self.lake_query.client.as_ref().ok_or_else(|| {
                SearchError::SqlValidationError(
                    "lake query backend is enabled without a worker client".to_string(),
                )
            })?;
            // Primary lake mode is deliberately hybrid while native span and
            // metric datasets remain on ClickHouse. The public DELETE route
            // carries only a request ID, not the dataset that owns it, so fan
            // the exact ID set to both backends. This avoids making a CH OTEL
            // query uncancellable merely because log Search uses the lake.
            let lake_cancel = client.cancel(request_id);
            let clickhouse_cancel = async {
                match &self.ch_executor {
                    Some(executor) => executor.cancel_queries(&all_query_ids(request_id)).await,
                    None => Ok(false),
                }
            };
            let (lake_result, clickhouse_result) = tokio::join!(lake_cancel, clickhouse_cancel);
            self.query_tracker.unregister(request_id);
            return match (lake_result, clickhouse_result) {
                (Ok(lake), Ok(clickhouse)) => Ok(lake || clickhouse),
                (Ok(true), Err(error)) => {
                    tracing::warn!(error = %error, "ClickHouse cancellation failed after the lake query was cancelled");
                    Ok(true)
                }
                (Err(error), Ok(true)) => {
                    tracing::warn!(error = %error, "lake cancellation failed after the ClickHouse query was cancelled");
                    Ok(true)
                }
                (Ok(false), Err(error)) | (Err(error), Ok(false)) => Err(error),
                (Err(lake_error), Err(clickhouse_error)) => {
                    tracing::warn!(error = %clickhouse_error, "ClickHouse cancellation also failed");
                    Err(lake_error)
                }
            };
        }

        // Only ClickHouse supports query cancellation
        let ch_executor = match &self.ch_executor {
            Some(executor) => executor,
            None => {
                tracing::warn!("Query cancellation not supported for PostgreSQL backend");
                return Ok(false);
            }
        };

        // Issue KILL QUERY directly using the request_id as query_id.
        // This works regardless of which instance started the query.
        //
        // NAN-1428: one search fans out to the data query plus companion
        // queries (count / histogram / field-stats) carrying derived ids —
        // the companions are ~90% of the fan-out's I/O, so cancel must kill
        // all of them, not just the data query. Exact derived ids, never
        // LIKE patterns (client ids can contain %/_).
        let cancelled = ch_executor
            .cancel_queries(&all_query_ids(request_id))
            .await?;

        // Clean up local tracker if this instance happened to be tracking it
        self.query_tracker.unregister(request_id);

        if cancelled {
            tracing::info!("Cancelled query via KILL QUERY: request_id={}", request_id);
        } else {
            tracing::debug!(
                "No running query found for request_id: {} (may have already completed)",
                request_id
            );
        }

        Ok(cancelled)
    }

    // =========================================================================
    // Async Search Job Methods
    // =========================================================================

    /// Execute a search asynchronously, returning a job ID immediately
    ///
    /// The search runs in the background. Use get_job_status() to poll for
    /// completion and retrieve results.
    ///
    /// `scope` (NAN-1799): the caller's source-scope deny-set, enforced inside
    /// [`SearchService::search`]. REQUIRED — pass [`ScopeSet::unrestricted`]
    /// only for SYSTEM callers.
    pub async fn search_async(
        &self,
        request: SearchRequest,
        scope: &ScopeSet,
    ) -> Result<String, SearchError> {
        self.require_dedicated_retention_surface("async search jobs")?;
        if self.backend() == crate::search::SearchBackend::Lake {
            return Err(SearchError::ServiceUnavailable(
                "native async searches require durable job admission".into(),
            ));
        }

        // Create job in store
        // NAN-2096: the execution scope is stamped on the job in the creating
        // write, so the poll path can re-decide visibility against the caller's
        // CURRENT scope instead of trusting submission-time authorization.
        let job_id = self
            .job_store
            .create(request.clone(), scope)
            .await
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "Maximum concurrent async jobs limit reached. Try again later.".to_string(),
                )
            })?;

        // Generate ClickHouse query_id for this job
        let query_id = uuid::Uuid::now_v7().to_string();
        self.job_store.set_query_id(&job_id, query_id.clone()).await;

        // Clone what we need for the spawned task
        let service = self.clone();
        let job_id_clone = job_id.clone();
        let scope = scope.clone();

        // Modify request to use our query_id for progress tracking
        let mut request_with_id = request;
        request_with_id.request_id = Some(query_id);

        // Spawn background task to execute the search
        tokio::spawn(super::super::request_actor::inherit(async move {
            tracing::info!("Async job {} starting search execution", job_id_clone);

            // Execute the search (reuse existing search logic)
            let result = service.search(request_with_id, &scope).await;

            // Update job with result
            match result {
                Ok(response) => {
                    tracing::info!(
                        "Async job {} completed: {} results, {} histogram buckets",
                        job_id_clone,
                        response.results.len(),
                        response.histogram.as_ref().map(|h| h.len()).unwrap_or(0)
                    );
                    service.job_store.complete(&job_id_clone, response).await;
                }
                Err(e) => {
                    tracing::error!("Async job {} failed: {}", job_id_clone, e);
                    service.job_store.fail(&job_id_clone, e.to_string()).await;
                }
            }
        }));

        tracing::info!("Started async search job: {}", job_id);
        Ok(job_id)
    }

    /// Execute a search asynchronously with admission control.
    ///
    /// Creates a job in Queued state, then spawns a background task that:
    /// 1. Acquires an admission permit (may wait in queue)
    /// 2. Transitions job to Running
    /// 3. Executes the search with per-priority CH settings
    /// 4. Completes or fails the job
    /// 5. Drops the permit (freeing the slot for the next queued search)
    pub async fn search_async_with_admission(
        &self,
        request: SearchRequest,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        self.search_async_with_task(request, user_id, priority, scope, authority,
            crate::search::DurableLakeTask::SearchNplV1).await
    }

    pub async fn search_async_with_task(
        &self,
        mut request: SearchRequest,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
        task: crate::search::DurableLakeTask,
    ) -> Result<String, SearchError> {
        let dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
        if self.lake_query.mode == LakeQueryMode::Primary
            && matches!(dataset, crate::query::Dataset::Logs)
        {
            if self.serves_lake_cell() && !self.has_cell_job_runner() {
                return Err(SearchError::ServiceUnavailable(
                    "hosted cell job runner is not configured for this tenant".into(),
                ));
            }
            if let Some(id) = self.try_enqueue_durable_lateral(&request, user_id, scope, authority).await? {
                return Ok(id);
            }
            // NAN-3078: a `| baseline` escalates to its typed durable job.
            if let Some(job_id) = self
                .try_enqueue_durable_baseline(&request, user_id, scope, authority)
                .await?
            {
                return Ok(job_id);
            }
            // NAN-4288 (F16): the durable lane honours in-query
            // earliest=/latest= exactly as the interactive one does.
            let (_, earliest, latest) = extract_time_bounds(&request.query)?;
            request.time_range = apply_time_bounds(&request.time_range, earliest, latest)?;
            request.time_range = self
                .retention_bound_input_range(&request.time_range, chrono::Utc::now())?
                .ok_or(SearchError::InvalidTimeRange)?;
            let query_profile = self.dataset_profile(request.dataset.as_deref());
            let mut parsed = parse_query(&request.query).map_err(convert_parse_error)?;
            // NAN-3385: the durable worker compiles the re-printed query.
            crate::query::resolve_timechart_bins(
            &mut parsed,
            &crate::query::TimeRange { start: request.time_range.start, end: request.time_range.end },
        );
            if query_profile.uses_strict_canonical_fields() {
                apply_profile_product_semantics(&mut parsed, query_profile.as_ref());
            }
            validate_query_field_names(&parsed, query_profile.as_ref())?;
            // NAN-2922: the durable lane compiles the pretty-printed query in
            // the worker, which cannot resolve IOC sources. Resolve them here
            // through the same (tenant-pinned on shared) readers as the
            // interactive path; an unresolved lookup source would otherwise
            // compile to a silent never-match. A retro marker keeps its
            // sources for `build_retro_view`, exactly as on the interactive path.
            let is_retro_query = matches!(
                get_semantic_terminal_command(&parsed),
                Some(Command::Retro { .. })
            );
            let mut ioc_warnings = Vec::new();
            if !is_retro_query && ioc_lookup_resolve::query_has_ioc_lookup(&parsed) {
                ioc_lookup_resolve::resolve_ioc_lookup_sources(
                    &mut parsed,
                    self.lookup_service.as_ref(),
                    &mut ioc_warnings,
                )
                .await?;
            }
            if !is_retro_query && ioc_lookup_resolve::query_has_ioc_feed(&parsed) {
                let tenant_ioc = self.shared_retro_feed_client("IOC feed search")?;
                ioc_lookup_resolve::resolve_ioc_feed_sources(
                    &mut parsed,
                    tenant_ioc,
                    &mut ioc_warnings,
                )
                .await?;
            }
            for warning in &ioc_warnings {
                tracing::info!(warning = %warning, "durable lake IOC source resolution");
            }
            inline_nested_lake_inputlookups(
                &mut parsed, self.lookup_service.as_ref(), query_profile.as_ref(),
            ).await?;
            validate_lake_nested_post_processing(&parsed)?;
            orient_lookup_keys(&mut parsed, self.lookup_service.as_ref()).await;
            let lookup_commands = extract_lookup_commands(&parsed);
            validate_lookup_tables(&lookup_commands, self.lookup_service.as_ref()).await?;
            let _ =
                push_down_lake_lookup_membership(&mut parsed, self.lookup_service.as_ref()).await?;
            let inlined = inline_small_lake_lookups(
                &mut parsed,
                self.lookup_service.as_ref(),
                query_profile.as_ref(),
            )
            .await?;
            if inlined > 0 {
                tracing::debug!(
                    inlined,
                    "inlined bounded lookup snapshots for durable lake admission"
                );
            }
            validate_lake_nested_post_processing(&parsed)?;
            // NAN-3078: a search task whose top-level pipeline keeps Nano-side
            // stages runs its SQL-only candidate prefix durably; the suffix is
            // applied when the verified result is read.
            // NAN-3257: a terminal tree is assembled Nano-side too. As a plain
            // SQL-only job its result carried no tree marker, so the paged tree
            // view of a completed job rendered "No tree nodes returned".
            // NAN-3294: the same host → IP widening the interactive tree
            // preview applies, so the exact tree job scans the same events.
            if task.is_search()
                && crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"))
                    == crate::query::Dataset::Logs
                && query_profile.uses_strict_canonical_fields()
            {
                for problem in self
                    .expand_lake_tree_web_query(&mut parsed, request.time_range.start, request.time_range.end, scope)
                    .await
                {
                    tracing::info!(problem = %problem, "durable tree web host → IP expansion");
                }
            }
            let task = if task.is_search() && durable_search_needs_post_processing(&parsed) {
                self.plan_durable_post_processing(&mut request, parsed, &task).await?
            } else {
                request.query = parsed.pretty_print();
                task
            };
            validate_durable_lake_sql_only_query(&request.query)?;
            let client = self.lake_query.client.as_ref().ok_or_else(|| {
                SearchError::SqlValidationError(
                    "lake query backend is enabled without a worker client".to_string(),
                )
            })?;
            let (generation_pin, _worker_ready) = client.admission_generation().await?;
            // Native results must retain the worker's expiry/revocation fence.
            // Interactive job stores retain naked responses; use the durable
            // worker result path, whose pages revalidate authority at return.
            let job_id = self
                .job_control()
                .create_durable_queued(
                    request,
                    &task,
                    user_id,
                    priority,
                    scope,
                    &generation_pin,
                    authority,
                )
                .await
                .map_err(|error| {
                    SearchError::SqlValidationError(format!(
                        "durable lake job admission failed: {error}"
                    ))
                })?;
            tracing::info!(
                job_id = %job_id,
                user_id = %user_id,
                priority = %priority,
                generation_id = %generation_pin.generation_id,
                snapshot_id = generation_pin.snapshot_id,
                "created durable lake search job"
            );
            return Ok(job_id);
        }

        // Non-lake async jobs still store a frozen response body in Redis and
        // do not yet carry the durable lake result's moving-cutoff receipt.
        self.require_dedicated_retention_surface("async search jobs")?;

        // Shared views must never turn a missing cell controller into an
        // unbounded legacy execution path. Dedicated/open-core services retain
        // the historical `None` fallback.
        let admission_controller = self.required_admission_controller()?;

        // Create job in Queued state. NAN-2096: stamp the execution scope in the
        // same write (see `search_async`).
        let job_id = self
            .job_store
            .create_queued(request.clone(), user_id, priority, scope)
            .await
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "Maximum concurrent async jobs limit reached. Try again later.".to_string(),
                )
            })?;

        // Generate ClickHouse query_id for this job
        let query_id = uuid::Uuid::now_v7().to_string();
        self.job_store.set_query_id(&job_id, query_id.clone()).await;

        let mut service = self.clone();
        // Set per-query ClickHouse settings based on priority
        service.active_ch_settings = Some(service.ch_settings_for_priority(priority));
        let job_id_clone = job_id.clone();
        let scope = scope.clone();

        let mut request_with_id = request;
        request_with_id.request_id = Some(query_id);

        // NAN-4664: a background job outlives its request; it waits for
        // admission up to the configured queue timeout, not the HTTP budget.
        tokio::spawn(super::super::request_actor::inherit(crate::search::admission::without_wait_budget(async move {
            // Step 1: Acquire admission permit
            let _permit = if let Some(ref controller) = admission_controller {
                match service
                    .acquire_search_admission(controller, &job_id_clone, user_id, priority)
                    .await
                {
                    Ok(permit) => Some(permit),
                    Err(e) => {
                        tracing::warn!("Job {} admission denied: {}", job_id_clone, e);
                        service.job_store.fail(&job_id_clone, e.to_string()).await;
                        return;
                    }
                }
            } else {
                None
            };

            // Step 2: Transition to Running
            service.job_store.start(&job_id_clone).await;
            tracing::info!(
                "Async job {} starting search execution (priority={})",
                job_id_clone,
                priority
            );

            // Step 3: Execute search
            let result = service.search(request_with_id, &scope).await;

            // Step 4: Complete or fail
            match result {
                Ok(response) => {
                    let result_count = response.results.len();
                    tracing::info!(
                        "Async job {} completed: {} results",
                        job_id_clone,
                        result_count,
                    );
                    service.job_store.complete(&job_id_clone, response).await;
                }
                Err(e) => {
                    let error_msg = e.to_string();
                    tracing::error!("Async job {} failed: {}", job_id_clone, error_msg);
                    service.job_store.fail(&job_id_clone, error_msg).await;
                }
            }
            // Step 5: _permit drops here, freeing the admission slot
        })));

        tracing::info!(
            "Created admission-controlled async search job: {} (user={}, priority={})",
            job_id,
            user_id,
            priority
        );
        Ok(job_id)
    }

    /// NAN-3809: a finished durable search job of this caller that answers
    /// exactly `request` and may be re-served through its result pages
    /// instead of re-running the search (a pasted absolute-range URL).
    ///
    /// The index is a bounded process-local exact-request hint (a cold miss runs);
    /// the data fence is the reuse marker the cell wrote next to the job's
    /// result pages in the tenant's R2 result prefix, which the cell checks
    /// against its current part set. Returns `None` on any doubt; a lookup
    /// failure is a miss, never an error. The caller must still re-check the
    /// current search authority before answering.
    pub async fn settled_durable_job_for_reuse(
        &self,
        request: &SearchRequest,
        user_id: uuid::Uuid,
        scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Option<super::jobs::SearchJob> {
        use crate::search::settled_reuse;
        let lookup_started = std::time::Instant::now();
        let now = chrono::Utc::now();
        if !request.use_cache
            || !settled_reuse::is_settled_end(request.time_range.end, now)
            || !settled_reuse::query_allows_settled_reuse(&request.query)
        {
            return None;
        }
        let canonical = self.durable_plain_search_canonical(request, now)?;
        let client = self.lake_query.client.as_ref()?;
        let control = self.job_control();
        // One exact candidate, one tenant-pinned metadata read, one cell check.
        // This hint survives completion independently of the in-flight index.
        let key = crate::search::recent_reuse_jobs::key(request, &canonical, user_id, scope, authority)?;
        let job_id = crate::search::recent_reuse_jobs::RecentReuseJobs::global().candidate(key)?;
        let caller = settled_reuse::ReuseCaller { user_id, deny: scope.deny_set(), authority };
        {
            let Ok(Some(job)) = control.get_checked(&job_id).await else { return None };
            if !settled_reuse::job_matches_reuse_request(&job, request, &canonical, &caller) {
                return None;
            }
            let Some(reference) = job.result_ref.clone() else { return None };
            match client.settled_job_reuse_check(&job.id, &reference).await {
                Ok(true) => {
                    tracing::info!(job_id = %job.id, reuse_lookup_ms = lookup_started.elapsed().as_millis() as u64, "re-serving a settled durable search job");
                    return Some(job);
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::debug!(job_id = %job.id, %error, "settled search reuse check failed; running the search");
                    return None;
                }
            }
        }
        None
    }

    /// The query text the durable lane submits for `request` as a plain
    /// `search_npl_v1` job, or `None` when such a job could not answer it
    /// (another dataset or lane, an explicit async request, a retention-
    /// clipped range, or Nano-side post-processing).
    fn durable_plain_search_canonical(&self, request: &SearchRequest, now: chrono::DateTime<chrono::Utc>) -> Option<String> {
        let dataset = request.dataset.as_deref().unwrap_or("logs");
        if request.async_mode
            || dataset != "logs"
            || self.lake_query.mode != LakeQueryMode::Primary
            || !self.serves_lake_cell()
            || !self.has_cell_job_runner()
        {
            return None;
        }
        // A range the retention frontier clips is not the range a job stored.
        let bounded = self.retention_bound_input_range(&request.time_range, now).ok()??;
        if bounded.start != request.time_range.start || bounded.end != request.time_range.end {
            return None;
        }
        let mut parsed = parse_query(&request.query).ok()?;
        crate::query::resolve_timechart_bins(
            &mut parsed,
            &crate::query::TimeRange { start: request.time_range.start, end: request.time_range.end },
        );
        let query_profile = self.dataset_profile(request.dataset.as_deref());
        if query_profile.uses_strict_canonical_fields() {
            apply_profile_product_semantics(&mut parsed, query_profile.as_ref());
        }
        if durable_search_needs_post_processing(&parsed) {
            return None;
        }
        Some(parsed.pretty_print())
    }

    /// NAN-3883: a queued or running durable search job of this caller that
    /// is already computing exactly `request` (same canonical query, absolute
    /// window, page, scope and authority). A second escalation of the same
    /// search, a reload or a reopened history entry attaches to it instead of
    /// starting the same long scan again. Returns `None` on any doubt; a
    /// lookup failure is a miss. The caller must still re-check the current
    /// search authority and the job's visibility before answering.
    /// NAN-4277: `point` decides whether a still-queued job is followed.
    pub async fn in_flight_durable_job_for_attach(
        &self,
        request: &SearchRequest,
        user_id: uuid::Uuid,
        scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
        point: crate::search::settled_reuse::AttachPoint,
    ) -> Option<super::jobs::SearchJob> {
        use crate::search::{in_flight_jobs::InFlightJobs, settled_reuse};
        crate::request_timing::timed(crate::request_timing::Phase::Attach, async {
            // NAN-3920: only the jobs this process started for this caller
            // over this exact window are candidates. Listing every job the
            // caller ever ran cost ~2 s on every search.
            let jobs = InFlightJobs::global();
            let candidates = jobs.candidates(user_id, request.time_range.start, request.time_range.end);
            if candidates.is_empty() {
                return None;
            }
            let canonical = self.durable_plain_search_canonical(request, chrono::Utc::now())?;
            let control = self.job_control();
            let caller = settled_reuse::ReuseCaller { user_id, deny: scope.deny_set(), authority };
            for job_id in candidates {
                let job = match control.get_checked(&job_id).await {
                    Ok(Some(job)) => job,
                    // Not this tenant's job (a user can belong to several
                    // tenants): skip it, never forget it; the TTL ages it out.
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::debug!(%error, "in-flight search attach: job read unavailable; running the search");
                        return None;
                    }
                };
                if !matches!(job.status, super::jobs::SearchJobStatus::Queued | super::jobs::SearchJobStatus::Running) {
                    jobs.forget(&job_id);
                    continue;
                }
                if settled_reuse::job_matches_attach_request(&job, request, &canonical, &caller, point) {
                    tracing::info!(job_id = %job.id, "attaching to an in-flight durable search job");
                    return Some(job);
                }
            }
            None
        })
        .await
    }

    async fn start_interactive_lake(
        &self,
        request: SearchRequest,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        scope: &ScopeSet,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
        pin: &crate::search::DurableLakeGenerationPin,
    ) -> Result<String, SearchError> {
        let controller = self.required_admission_controller()?;
        let id = self
            .job_control()
            .create_interactive_lake(request.clone(), user_id, priority, scope, pin, authority)
            .await
            .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
        let query_id = uuid::Uuid::now_v7().to_string();
        self.job_store.set_query_id(&id, query_id.clone()).await;
        let mut request = request;
        request.request_id = Some(query_id);
        let service = self.clone();
        let job_id = id.clone();
        let scope = scope.clone();
        // NAN-4664: as above, the job's admission is not bound by the HTTP budget.
        tokio::spawn(super::super::request_actor::inherit(crate::search::admission::without_wait_budget(async move {
            let result = async {
                let _permit = match controller {
                    Some(ref controller) => Some(
                        service
                            .acquire_search_admission(controller, &job_id, user_id, priority)
                            .await
                            .map_err(SearchError::from)?,
                    ),
                    None => None,
                };
                let job = service
                    .job_store
                    .get_checked(&job_id)
                    .await
                    .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
                if !job.is_some_and(|job| job.status == super::jobs::SearchJobStatus::Running) {
                    return Err(SearchError::Cancelled);
                }
                service.search(request, &scope).await
            };
            let result = tokio::time::timeout(std::time::Duration::from_secs(300), result)
                .await
                .unwrap_or(Err(SearchError::Timeout(300_000)));
            service
                .finish_interactive_lake(&job_id, &scope, result)
                .await;
        })));
        tracing::info!(job_id = %id, "started interactive lake search job");
        Ok(id)
    }

    async fn finish_interactive_lake(
        &self,
        job_id: &str,
        scope: &ScopeSet,
        result: Result<SearchResponse, SearchError>,
    ) {
        match result {
            Ok(response) => {
                if let Err(error) = self
                    .job_store
                    .complete_interactive_lake(job_id, response)
                    .await
                {
                    tracing::error!(job_id, %error, "interactive lake completion failed");
                    let _ = self
                        .job_store
                        .fail_interactive_lake(job_id, &error.to_string())
                        .await;
                }
            }
            Err(error) if interactive_lake_fallback(&error) => {
                tracing::info!(job_id, %error, "promoting interactive lake query to durable execution");
                let mut promotion = self
                    .job_control()
                    .promote_interactive_lake(job_id, scope)
                    .await;
                if matches!(
                    promotion,
                    Err(super::jobs::DurableJobStoreError::Unavailable(_))
                ) {
                    promotion = self
                        .job_control()
                        .promote_interactive_lake(job_id, scope)
                        .await;
                }
                if let Err(error) = promotion {
                    tracing::warn!(job_id, %error, "interactive lake promotion failed");
                    let _ = self
                        .job_store
                        .fail_interactive_lake(job_id, &error.to_string())
                        .await;
                }
            }
            Err(error) => {
                let _ = self
                    .job_store
                    .fail_interactive_lake(job_id, &error.to_string())
                    .await;
            }
        }
    }

    /// Execute a search synchronously, gated by the admission controller.
    ///
    /// NAN-701: Sibling of `search_async_with_admission` for callers that
    /// need the response inline (search handler sync path, dashboard panel
    /// queries) instead of a job_id to poll. Acquires an admission permit
    /// (waiting in queue if needed), runs `search`, and releases the permit
    /// on return via RAII drop.
    ///
    /// When `admission_controller` is `None` (e.g. tests, single-tenant
    /// deployments), behaves identically to `search`.
    pub async fn search_with_admission(
        &self,
        request: SearchRequest,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        // NAN-709: lower-priority requests yield briefly before claiming a
        // slot. Without this, the initial admit burst when a dashboard fires
        // all panels simultaneously is a network-timing race — 1-2 Analytics
        // panels can sneak into the per-user cap alongside Interactive ones.
        // The delay (a few hundred ms, see `admit_delay`) gives Interactive
        // requests a deterministic head start so cheap panels render first.
        // Detection/NRT priorities bypass admission entirely and never reach
        // here.
        if let Some(delay) = priority.admit_delay() {
            tokio::time::sleep(delay).await;
        }

        // No controller wired up → no gating, run directly. Preserves the
        // pre-NAN-701 behavior for code paths that haven't been migrated.
        let Some(controller) = self.required_admission_controller()? else {
            return self.search(request, scope).await;
        };

        let job_id = uuid::Uuid::now_v7().to_string();
        let waited = Instant::now();
        let _permit = self
            .acquire_search_admission(&controller, &job_id, user_id, priority)
            .await
            .map_err(SearchError::from)?;
        crate::search::lake_debug::phase("admission_wait", waited.elapsed());

        let mut service = self.clone();
        service.active_ch_settings = Some(service.ch_settings_for_priority(priority));
        // _permit drops at end of scope, freeing the slot.
        service.search(request, scope).await
    }

    /// Get the status of an async search job
    ///
    /// Returns job status, progress (if running), results (if completed),
    /// or error (if failed). When queued, includes queue position and estimated wait.
    pub async fn get_job_status(
        &self,
        job_id: &str,
    ) -> Option<super::jobs::SearchJobStatusResponse> {
        match self.get_job_status_checked(job_id).await {
            Ok(status) => status,
            Err(error) => {
                tracing::warn!(job_id, error = %error, "Failed to read async search job status");
                None
            }
        }
    }

    /// Get async search status without treating a durable state-store outage
    /// as a missing job. Public HTTP handlers use this variant so callers can
    /// retry a temporary Dragonfly/Redis failure safely.
    pub async fn get_job_status_checked(
        &self,
        job_id: &str,
    ) -> Result<Option<super::jobs::SearchJobStatusResponse>, super::jobs::DurableJobStoreError>
    {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, crate::search::tenant::SearchTenantScope::Dedicated);
        if shared_scope {
            let Some(job) = self.job_control().get_checked(job_id).await? else {
                return Ok(None);
            };
            if job.backend != super::jobs::SearchJobBackend::LakeDurable {
                job.verify_interactive_retention(self.admission_scope, chrono::Utc::now())?;
                return self.job_control().get_status_checked(job_id).await;
            }
            if job.status == super::jobs::SearchJobStatus::Completed {
                job.result_ref
                    .as_ref()
                    .ok_or_else(|| {
                        super::jobs::DurableJobStoreError::Invalid(
                            "completed durable job has no result reference".to_string(),
                        )
                    })?
                    .verify_retention_for_range(
                        self.admission_scope,
                        &job.request.time_range,
                        chrono::Utc::now(),
                    )?;
            }
        }
        // Get basic status from store
        let Some(mut status) = self.job_control().get_status_checked(job_id).await? else {
            return Ok(None);
        };

        tracing::debug!("Job {} status: {:?}", job_id, status.status);
        if self.durable_job_control.is_some() {
            return Ok(Some(status));
        }

        // If job is queued, populate queue position and estimated wait
        if status.status == super::jobs::SearchJobStatus::Queued {
            if let Some(ref controller) = self.admission_controller {
                if let Some(position) = controller
                    .queue_position_for_scope(job_id, self.admission_scope)
                    .await
                {
                    status.queue_position = Some(position);
                    // Estimate wait: ~5 seconds per position (rough heuristic)
                    status.estimated_wait_seconds = Some(position * 5);
                    self.job_store.set_queue_position(job_id, position).await;
                }
            }
        }

        // If job is running, fetch progress from ClickHouse
        if status.status == super::jobs::SearchJobStatus::Running {
            if let Some(query_id) = self.job_store.get_query_id(job_id).await {
                tracing::debug!("Fetching progress for query_id: {}", query_id);
                if let Some(progress) = self.get_query_progress(&query_id).await {
                    tracing::debug!(
                        "Got progress: {}% ({} of {} rows)",
                        progress.percent,
                        progress.rows_scanned,
                        progress.rows_total
                    );
                    status.progress = Some(progress);
                } else {
                    tracing::debug!("No progress found for query_id: {}", query_id);
                }
            } else {
                tracing::debug!("No query_id found for job: {}", job_id);
            }
        }

        Ok(Some(status))
    }

    /// Read one manifest-fenced durable result page through the assigned lake
    /// worker. Public handlers perform ownership, capability, and current
    /// source-scope authorization before calling this storage-facing method.
    pub async fn get_durable_job_result_page(
        &self,
        job_id: &str,
        reference: &super::jobs::SearchJobResultRef,
        page: usize,
    ) -> Result<super::jobs::SearchJobResultPage, SearchError> {
        reference
            .verify_retention_at(self.admission_scope, chrono::Utc::now())
            .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;

        if self.lake_query.mode != LakeQueryMode::Primary {
            return Err(SearchError::SqlValidationError(
                "durable lake result pages require the primary lake backend".to_string(),
            ));
        }
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        client.result_page(self.admission_scope, job_id, reference, page).await
    }

    /// Cancel an async search job
    ///
    /// Returns Ok(true) if the job was found and cancelled.
    /// Works for both queued and running jobs.
    /// Stateless: issues KILL QUERY directly using the job's query_id,
    /// so it works from any instance in an active/active deployment.
    pub async fn cancel_job(&self, job_id: &str) -> Result<bool, SearchError> {
        if self.durable_job_control.is_some() {
            let job = self
                .job_control()
                .get_checked(job_id)
                .await
                .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
            let cancelled = self
                .job_control()
                .cancel_checked(job_id)
                .await
                .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
            if cancelled {
                if let Some(job) =
                    job.filter(|job| job.backend == super::jobs::SearchJobBackend::Inline)
                {
                    if let Some(controller) = &self.admission_controller {
                        controller
                            .cancel_queued_for_scope(job_id, self.admission_scope)
                            .await;
                    }
                    if let Some(client) = &self.lake_query.client {
                        let _ = client.cancel(&job.query_id).await;
                    }
                }
            }
            return Ok(cancelled);
        }
        // Get the job to check status and get query_id
        let job = match self.job_store.get(job_id).await {
            Some(j) => j,
            None => return Ok(false),
        };

        // Cancel queued jobs by removing from admission queue
        if job.status == super::jobs::SearchJobStatus::Queued {
            if let Some(ref controller) = self.admission_controller {
                controller
                    .cancel_queued_for_scope(job_id, self.admission_scope)
                    .await;
            }
            self.job_store.cancel(job_id).await;
            tracing::info!("Cancelled queued search job: {}", job_id);
            return Ok(true);
        }

        // Only cancel if still running
        if job.status != super::jobs::SearchJobStatus::Running {
            return Ok(false);
        }

        if self.lake_query.mode == LakeQueryMode::Primary {
            if let Some(client) = self.lake_query.client.as_ref() {
                let _ = client.cancel(&job.query_id).await;
            }
        }

        // Kill the ClickHouse query — works from any instance.
        // NAN-1428: include the derived companion ids (count/hist/fstats).
        if let Some(ref executor) = self.ch_executor {
            let _ = executor.cancel_queries(&all_query_ids(&job.query_id)).await;
        }

        // Mark as cancelled in the (potentially Redis-backed) store
        self.job_store.cancel(job_id).await;

        tracing::info!("Cancelled async search job: {}", job_id);
        Ok(true)
    }

    /// Get query progress from ClickHouse system.processes
    async fn get_query_progress(&self, query_id: &str) -> Option<super::jobs::SearchJobProgress> {
        let ch_executor = self.ch_executor.as_ref()?;

        match ch_executor.get_query_progress(query_id).await {
            Ok(progress) => progress,
            Err(e) => {
                tracing::debug!("Failed to get query progress: {}", e);
                None
            }
        }
    }

    /// nPL `| resolve_identity` on the lake (NAN-3058): fill the row's
    /// missing identity paths from the tenant's identity resolution. IP
    /// fields go through [`Self::resolve_lake_identity_ips`] (the observation
    /// index, or the bounded event scan while it backfills); host and user
    /// fields need the index itself. Fails closed: any resolution failure is
    /// the search's error, never rows silently left unresolved.
    ///
    /// NAN-3294: every resolved row also carries the explicit `identity_*`
    /// columns (`identity_ip`, `identity_hostname`, `identity_fqdn`,
    /// `identity_user`, `identity_mac`, `identity_source`,
    /// `identity_observed_at`). The in-place OCSF fill alone was invisible
    /// whenever the event already carried the path, so the command looked
    /// like a no-op. A run that resolves nothing says so in `warnings`.
    async fn apply_lake_identity_batch(
        &self,
        mut rows: Vec<serde_json::Value>,
        field: &str,
        max_age: &std::time::Duration,
        fallback_reference_time: chrono::DateTime<chrono::Utc>,
        scope: &ScopeSet,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let entity_type = match lake_identity_entity_type(field)
            .or_else(|| self.active_profile.entity_type(field))
        {
            Some(crate::schema::EntityType::Ip) => "ip",
            Some(crate::schema::EntityType::Host) => "host",
            Some(crate::schema::EntityType::User) => "user",
            _ => {
                return Err(SearchError::SqlValidationError(format!(
                    "lake resolve_identity requires a canonical OCSF IP, host, or user field; got {field}"
                )));
            }
        };
        let endpoint = match entity_type {
            "ip" => Some(field.strip_suffix(".ip").ok_or_else(|| {
                SearchError::SqlValidationError(format!(
                    "lake resolve_identity requires an OCSF IP path ending in .ip; got {field}"
                ))
            })?),
            "host" => Some(field.strip_suffix(".hostname").ok_or_else(|| {
                SearchError::SqlValidationError(format!(
                    "lake resolve_identity requires an OCSF host path ending in .hostname; got {field}"
                ))
            })?),
            _ => None,
        };
        let mut row_indices = Vec::new();
        let mut keys = Vec::new();
        let mut event_times = Vec::new();
        for (row_index, row) in rows.iter().enumerate() {
            let Some(value) = lake_row_string(row, field).filter(|value| !value.is_empty()) else {
                continue;
            };
            let key = match entity_type {
                "ip" => match value.trim().parse::<std::net::IpAddr>() {
                    Ok(ip) => ip.to_string(),
                    Err(_) => continue,
                },
                _ => value.trim().to_ascii_lowercase(),
            };
            let event_time = lake_row_string(row, self.active_profile.timestamp_expr())
                .and_then(parse_lake_timestamp)
                .unwrap_or(fallback_reference_time);
            row_indices.push(row_index);
            keys.push(key);
            event_times.push(event_time);
        }
        if keys.is_empty() {
            if !rows.is_empty() {
                warnings.push(lake_identity_absent_field_warning(field, rows.len()));
            }
            return Ok(rows);
        }
        let distinct_keys = keys.iter().collect::<std::collections::BTreeSet<_>>().len();
        let mut resolved_rows = 0usize;
        let mut stale_rows = 0usize;
        // (ip, hostname, user, mac, source, observed_at, fqdn) per resolved item.
        let mut resolved: Vec<Option<LakeIdentityAnswerColumns>> = vec![None; keys.len()];
        if entity_type == "ip" {
            let items = keys
                .iter()
                .zip(&event_times)
                .map(|(key, at)| (key.parse::<std::net::IpAddr>().expect("canonical IP"), *at))
                .collect::<Vec<_>>();
            for (slot, answer) in resolved.iter_mut().zip(self.resolve_lake_identity_ips(&items, scope.deny_set()).await?) {
                *slot = answer.map(|o| LakeIdentityAnswerColumns {
                    ip: String::new(),
                    hostname: o.hostname,
                    user: o.user,
                    mac: o.mac,
                    source: o.source,
                    observed_at: o.observed_at,
                    fqdn: o.fqdn,
                });
            }
        } else {
            let client = self.lake_query.client.as_ref().ok_or_else(|| {
                SearchError::SqlValidationError("lake identity client is unavailable".to_string())
            })?;
            for (batch_index, batch) in keys.chunks(LAKE_IDENTITY_BATCH_CAP).enumerate() {
                let base = batch_index.saturating_mul(LAKE_IDENTITY_BATCH_CAP);
                let items = batch
                    .iter()
                    .enumerate()
                    .map(|(offset, key)| crate::search::lake::LakeIdentityEntityBatchItem {
                        value: key.clone(),
                        reference_time: event_times[base + offset].to_rfc3339(),
                    })
                    .collect::<Vec<_>>();
                let answer = client.resolve_identity_entity_batch(entity_type, &items, scope.deny_set()).await?;
                if !answer.complete {
                    return Err(SearchError::ServiceUnavailable(format!(
                        "resolve_identity by {entity_type} needs the tenant's identity observation index, which is still backfilling; resolve by an IP field meanwhile"
                    )));
                }
                for observation in answer.rows {
                    let Some(item) = items.get(observation.ordinal) else {
                        return Err(SearchError::SqlValidationError(
                            "lake identity worker returned an out-of-range ordinal".to_string(),
                        ));
                    };
                    if observation.value != item.value {
                        return Err(SearchError::SqlValidationError(
                            "lake identity worker substituted an entity binding".to_string(),
                        ));
                    }
                    resolved[base + observation.ordinal] = Some(LakeIdentityAnswerColumns {
                        ip: observation.ip,
                        hostname: observation.hostname,
                        user: observation.user,
                        mac: observation.mac,
                        source: observation.source,
                        observed_at: observation.observed_at,
                        fqdn: observation.fqdn,
                    });
                }
            }
        }
        for (item_index, answer) in resolved.into_iter().enumerate() {
            let Some(answer) = answer else { continue };
            let LakeIdentityAnswerColumns { ip, hostname, user, mac, source, observed_at: observed_at_text, fqdn } = answer;
            let observed_at = observed_at_text.as_str();
            let row_index = row_indices[item_index];
            let observed_at = parse_lake_timestamp(observed_at).ok_or_else(|| {
                SearchError::SqlValidationError("lake identity answer has an invalid observation time".to_string())
            })?;
            // The index answers at or before the event; the event scan of a
            // batch answers at the batch's latest event, so its observation
            // may follow an earlier row by at most the batch span.
            let age = event_times[item_index].signed_duration_since(observed_at).abs();
            if age.num_seconds() as u64 > max_age.as_secs() {
                stale_rows += 1;
                continue;
            }
            resolved_rows += 1;
            let row = &mut rows[row_index];
            // The resolved address: the answer's own IP for a host/user
            // lookup, the event's key for an IP lookup.
            let identity_ip = if entity_type == "ip" { keys[item_index].as_str() } else { ip.as_str() };
            set_lake_identity_columns(
                row,
                &[
                    ("identity_ip", identity_ip),
                    ("identity_hostname", hostname.as_str()),
                    ("identity_fqdn", if fqdn.is_empty() { hostname.as_str() } else { fqdn.as_str() }),
                    ("identity_user", user.as_str()),
                    ("identity_mac", mac.as_str()),
                    ("identity_source", source.as_str()),
                    ("identity_observed_at", &observed_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
                ],
            );
            match (entity_type, endpoint) {
                ("ip", Some(endpoint)) => {
                    set_lake_ocsf_value_if_empty(row, &format!("{endpoint}.hostname"), &hostname);
                    set_lake_ocsf_value_if_empty(row, &format!("{endpoint}.mac"), &mac);
                    set_lake_ocsf_value_if_empty(row, "user.name", &user);
                }
                ("host", Some(endpoint)) => {
                    set_lake_ocsf_value_if_empty(row, &format!("{endpoint}.ip"), &ip);
                    set_lake_ocsf_value_if_empty(row, &format!("{endpoint}.mac"), &mac);
                    set_lake_ocsf_value_if_empty(row, "user.name", &user);
                }
                _ => {
                    set_lake_ocsf_value_if_empty(row, "src_endpoint.ip", &ip);
                    set_lake_ocsf_value_if_empty(row, "src_endpoint.hostname", &hostname);
                    set_lake_ocsf_value_if_empty(row, "src_endpoint.mac", &mac);
                }
            }
            tracing::debug!(
                identity_source = %source,
                identity_observed_at = %observed_at,
                event_field = field,
                identity_entity_type = entity_type,
                "Applied lake identity context to canonical OCSF paths"
            );
        }
        if resolved_rows == 0 {
            warnings.push(lake_identity_unresolved_warning(field, distinct_keys, stale_rows, max_age));
        }
        Ok(rows)
    }

    fn finish_primary_lake_count_stats(
        &self,
        request: &SearchRequest,
        start_time: Instant,
        parsed: &Query,
        mut complete: Vec<serde_json::Value>,
        post_commands: &[Command],
        max_groups: usize,
    ) -> Result<SearchResponse, SearchError> {
        let mut runtime_warnings = Vec::new();
        if !post_commands.is_empty() {
            let processed =
                apply_post_prevalence_commands_with_limit(complete, post_commands, max_groups)?;
            complete = processed.results;
            runtime_warnings = processed.warnings;
        }

        let total_count = u64::try_from(complete.len()).unwrap_or(u64::MAX);
        let offset = request.offset.unwrap_or(0);
        let limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        let results = complete
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        let mut statistics = FieldStatistics::new();
        for row in &results {
            statistics.process_row(row);
        }
        Ok(SearchResponse {
            server_wall_ms: None,
            results,
            total_count,
            // `complete` is the whole grouped output; the count is its length.
            total_count_exact: true,
            execution_time_ms: start_time.elapsed().as_millis() as u64,
            fields: if request.skip_field_stats {
                Vec::new()
            } else {
                statistics.get_field_info(self.config.top_values_count)
            },
            generated_sql: None,
            histogram: None,
            warnings: (!runtime_warnings.is_empty()).then(|| {
                runtime_warnings
                    .into_iter()
                    .map(|message| QueryWarningOutput {
                        severity: "warning".to_string(),
                        code: "LAKE_COUNT_POST_PROCESSING".to_string(),
                        message,
                        suggestion: None,
                        impact: None,
                    })
                    .collect()
            }),
            cost_score: None,
            display_type: Some(determine_display_type(parsed)),
            column_order: get_column_order(parsed),
            completeness: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn search_primary_lake_count_stats(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &LakeCountStatsPlan,
        aggregate_query: &Query,
        post_commands: &[Command],
        max_groups: usize,
        start_time: Instant,
        parsed: &Query,
    ) -> Result<SearchResponse, SearchError> {
        let complete = match self
            .lake_count_rollup_rows(request, query_id, scope, plan, aggregate_query, max_groups)
            .await?
        {
            Some(complete) => complete,
            None => {
                self.lake_count_raw_rows(request, query_id, scope, plan, aggregate_query, max_groups)
                    .await?
            }
        };
        self.finish_primary_lake_count_stats(
            request,
            start_time,
            parsed,
            complete,
            post_commands,
            max_groups,
        )
    }

    /// The complete grouped rows of an exact count `plan` answered from the
    /// count rollups, or `None` when no exact rollup answer is available (the
    /// caller then scans). Every rollup answer is exact: rollup-aligned
    /// buckets come from the parts' rollup partials and the ragged window
    /// edges from a raw scan inside the worker (`count_aggregate`).
    async fn lake_count_rollup_rows(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &LakeCountStatsPlan,
        aggregate_query: &Query,
        max_groups: usize,
    ) -> Result<Option<Vec<serde_json::Value>>, SearchError> {
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        // The union counts are three window totals: they answer an
        // ungrouped, unbucketed count only (never a timechart's series).
        if let Some((union, union_predicate)) = plan
            .rollup_union
            .as_ref()
            .filter(|_| plan.bucket_span_us.is_none() && plan.group_by.is_empty())
            .filter(|union| lake_rollup_covers(&union.field))
            .and_then(|union| {
                lake_rollup_exact_predicate(
                    self.active_profile.as_ref(),
                    &union.field,
                    Some(&union.predicate),
                )
                .flatten()
                .map(|predicate| (union, predicate))
            })
        {
            let source_predicate = LakeCountPredicate {
                kind: "eq",
                values: vec![union.source.clone()],
            };
            let source_request_id = format!("{query_id}-count-union-source");
            let predicate_request_id = format!("{query_id}-count-union-predicate");
            let intersection_request_id = format!("{query_id}-count-union-intersection");
            let source_count = client.count_aggregate(
                &source_request_id,
                "metadata.log_source",
                false,
                Some(&source_predicate),
                None,
                &plan.count_alias,
                &request.time_range,
                None,
                scope.deny_set(),
                1,
            );
            let predicate_count = client.count_aggregate(
                &predicate_request_id,
                &union.field,
                false,
                Some(&union_predicate),
                None,
                &plan.count_alias,
                &request.time_range,
                None,
                scope.deny_set(),
                1,
            );
            let intersection_count = client.count_aggregate(
                &intersection_request_id,
                &union.field,
                false,
                Some(&union_predicate),
                None,
                &plan.count_alias,
                &request.time_range,
                Some(&union.source),
                scope.deny_set(),
                1,
            );
            match tokio::join!(source_count, predicate_count, intersection_count) {
                (Ok(source), Ok(predicate), Ok(intersection)) => {
                    let source = lake_single_count(&source, &plan.count_alias)?;
                    let predicate = lake_single_count(&predicate, &plan.count_alias)?;
                    let intersection = lake_single_count(&intersection, &plan.count_alias)?;
                    let count = source
                        .checked_add(predicate)
                        .and_then(|value| value.checked_sub(intersection))
                        .ok_or_else(|| {
                            SearchError::SqlValidationError(
                                "count rollup union overflowed or violated set inclusion"
                                    .to_string(),
                            )
                        })?;
                    let results = vec![serde_json::Value::Object(
                        [(plan.count_alias.clone(), serde_json::Value::from(count))]
                            .into_iter()
                            .collect(),
                    )];
                    return Ok(Some(results));
                }
                (source, predicate, intersection) => tracing::warn!(
                    request_id = %query_id,
                    source_error = ?source.err(),
                    predicate_error = ?predicate.err(),
                    intersection_error = ?intersection.err(),
                    "exact count union rollup unavailable; falling back to raw aggregation"
                ),
            }
        }
        if let Some(union) = plan.rollup_field_union.as_ref() {
            match self
                .lake_count_field_union_rows(
                    request, query_id, scope, plan, union, aggregate_query, max_groups,
                )
                .await
            {
                Ok(Some(rows)) => return Ok(Some(rows)),
                Ok(None) => {}
                Err(error) => tracing::warn!(
                    request_id = %query_id,
                    error = %error,
                    "exact two-field count union unavailable; falling back to raw aggregation"
                ),
            }
        }
        if let Some((rollup_field, rollup_predicate)) =
            lake_count_rollup_request(self.active_profile.as_ref(), plan)
        {
            let group_results = !plan.group_by.is_empty() && !plan.rollup_group_by_source;
            let rollup_group_limit = if group_results || plan.rollup_group_by_source || plan.bucket_span_us.is_some() {
                max_groups
            } else {
                1
            };
            match client
                .count_aggregate_grouped(
                    &format!("{query_id}-count-rollup"),
                    rollup_field,
                    group_results,
                    plan.rollup_group_by_source,
                    rollup_predicate.as_ref(),
                    plan.bucket_span_us,
                    &plan.count_alias,
                    &request.time_range,
                    plan.rollup_source_filter.as_deref(),
                    scope.deny_set(),
                    rollup_group_limit,
                )
                .await
            {
                Ok(mut complete) => {
                    if let Some(spelling) = plan.output_spelling.as_ref() {
                        if !lake_apply_rollup_output_spelling(&mut complete, spelling) {
                            tracing::info!(
                                request_id = %query_id,
                                group_field = %spelling.caller_group,
                                "count(F) by F rollup has a NULL group; running the scan"
                            );
                            return Ok(None);
                        }
                    }
                    for row in &complete {
                        let object = row.as_object().ok_or_else(|| {
                            SearchError::SqlValidationError(
                                "count rollup returned a non-object row".to_string(),
                            )
                        })?;
                        if (!plan.group_by.is_empty()
                            && !plan.group_by.iter().all(|field| object.contains_key(field)))
                            || (plan.bucket_span_us.is_some()
                                && !object.contains_key("time_bucket"))
                            || object
                                .get(&plan.count_alias)
                                .and_then(|value| {
                                    value.as_u64().or_else(|| {
                                        value.as_str().and_then(|value| value.parse().ok())
                                    })
                                })
                                .is_none()
                        {
                            return Err(SearchError::SqlValidationError(
                                "count rollup omitted its group or UInt64 count".to_string(),
                            ));
                        }
                    }
                    complete.sort_by(|left, right| {
                        if plan.bucket_span_us.is_some() {
                            return left
                                .get("time_bucket")
                                .and_then(serde_json::Value::as_str)
                                .cmp(&right.get("time_bucket").and_then(serde_json::Value::as_str))
                                .then_with(|| {
                                    serde_json::to_string(left)
                                        .unwrap_or_default()
                                        .cmp(&serde_json::to_string(right).unwrap_or_default())
                                });
                        }
                        let count = |row: &serde_json::Value| {
                            row.get(&plan.count_alias)
                                .and_then(|value| {
                                    value.as_u64().or_else(|| {
                                        value.as_str().and_then(|value| value.parse().ok())
                                    })
                                })
                                .unwrap_or_default()
                        };
                        count(right).cmp(&count(left)).then_with(|| {
                            serde_json::to_string(left)
                                .unwrap_or_default()
                                .cmp(&serde_json::to_string(right).unwrap_or_default())
                        })
                    });
                    return Ok(Some(complete));
                }
                Err(error) => tracing::warn!(
                    request_id = %query_id,
                    group_field = %rollup_field,
                    error = %error,
                    "exact count rollup unavailable; falling back to scan-budgeted raw aggregation"
                ),
            }
        }
        Ok(None)
    }

    /// NAN-3153: `A=v OR B=w | stats count [by metadata.log_source]` for two
    /// different rollup fields, exactly. Per log source `s`,
    /// `|A ∪ B|(s) = |A|(s) + |B|(s) - |A ∩ B|(s)`, and `|A ∩ B|(s) = 0`
    /// whenever either side has no row in `s`. Both per-source counts come
    /// from the rollups; only the sources where BOTH sides match are counted
    /// again by a raw scan of the original predicate narrowed to exactly
    /// those sources (usually none: the two fields rarely co-occur in one
    /// source for one value). `None`: not exactly answerable here.
    #[allow(clippy::too_many_arguments)]
    async fn lake_count_field_union_rows(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &LakeCountStatsPlan,
        union: &LakeFieldUnionPlan,
        aggregate_query: &Query,
        max_groups: usize,
    ) -> Result<Option<Vec<serde_json::Value>>, SearchError> {
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let grouped = match plan.group_by.as_slice() {
            [] => false,
            [group] if group == LAKE_SOURCE_FIELD => true,
            _ => return Ok(None),
        };
        if plan.bucket_span_us.is_some() || plan.rollup_union.is_some() {
            return Ok(None);
        }
        let profile = self.active_profile.as_ref();
        let Some(sides) = [
            (&union.left_field, &union.left_predicate),
            (&union.right_field, &union.right_predicate),
        ]
        .into_iter()
        .map(|(field, predicate)| {
            lake_rollup_union_side(profile, field, predicate).map(|predicate| (field.clone(), predicate))
        })
        .collect::<Option<Vec<_>>>() else {
            return Ok(None);
        };
        let Query::Piped {
            source,
            command:
                Command::Stats { aggregations, .. } | Command::Chart { aggregations, .. },
        } = aggregate_query
        else {
            return Ok(None);
        };
        let Query::Search(search) = source.as_ref() else {
            return Ok(None);
        };
        let side_ids = [
            format!("{query_id}-count-field-union-0"),
            format!("{query_id}-count-field-union-1"),
        ];
        let side_request = |index: usize| {
            let (field, predicate) = &sides[index];
            client.count_aggregate_grouped(
                &side_ids[index],
                field,
                false,
                true,
                Some(predicate),
                None,
                &plan.count_alias,
                &request.time_range,
                None,
                scope.deny_set(),
                max_groups,
            )
        };
        let (left, right) = tokio::join!(side_request(0), side_request(1));
        let left = lake_source_counts(&left?, &plan.count_alias)?;
        let right = lake_source_counts(&right?, &plan.count_alias)?;
        let Some(combination) = lake_field_union_combination(&left, &right) else {
            return Ok(None);
        };
        let mut by_source = combination.disjoint;
        if !combination.overlap.is_empty() {
            let narrowed = Query::Piped {
                source: Box::new(Query::Search(SearchExpr::And(
                    Box::new(SearchExpr::Group(Box::new(search.clone()))),
                    Box::new(SearchExpr::InList {
                        field: LAKE_SOURCE_FIELD.to_string(),
                        values: combination
                            .overlap
                            .iter()
                            .map(|source| Value::String(source.clone()))
                            .collect(),
                        negated: false,
                    }),
                ))),
                command: Command::Stats {
                    aggregations: aggregations.clone(),
                    group_by: Some(vec![LAKE_SOURCE_FIELD.to_string()]),
                },
            };
            let narrowed_plan = LakeCountStatsPlan {
                group_by: vec![LAKE_SOURCE_FIELD.to_string()],
                count_alias: plan.count_alias.clone(),
                rollup_field: None,
                rollup_predicate: None,
                rollup_source_filter: None,
                rollup_union: None,
                rollup_group_by_source: false,
                rollup_field_union: None,
                bucket_span_us: None,
                output_spelling: None,
            };
            let scanned = self
                .lake_count_raw_rows(
                    request,
                    &format!("{query_id}-field-union-overlap"),
                    scope,
                    &narrowed_plan,
                    &narrowed,
                    max_groups,
                )
                .await?;
            let scanned = lake_source_counts(&scanned, &plan.count_alias)?;
            for source in &combination.overlap {
                // Each overlap source matches both sides, so its union count
                // is positive and the scan must report it.
                let Some(count) = scanned.get(&Some(source.clone())).copied().filter(|count| *count > 0) else {
                    return Err(SearchError::SqlValidationError(
                        "two-field count union overlap scan omitted a matching source".to_string(),
                    ));
                };
                by_source.insert(Some(source.clone()), count);
            }
        }
        Ok(Some(lake_field_union_rows(by_source, grouped, &plan.count_alias)?))
    }

    /// The complete grouped rows of `aggregate_query` (an exact count) from
    /// raw scans: the whole range first, bisected only on a planner-confirmed
    /// scan-budget rejection, then merged by group.
    async fn lake_count_raw_rows(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &LakeCountStatsPlan,
        aggregate_query: &Query,
        max_groups: usize,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        use futures::StreamExt;

        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let chunk_limit = max_groups.clamp(1, self.config.max_limit);
        let mut pending = vec![("0".to_string(), request.time_range.clone())];
        let mut chunks = Vec::new();
        let mut retries = LakeSliceRetries::new();

        // Try the whole range first. Only a planner-confirmed scan-budget
        // rejection causes bisection, so ordinary datasets pay one query, the
        // current 288 MB validation corpus pays two half-range scans, and a
        // larger/skewed tenants split while estimates improve within the
        // attempt cap. Successful siblings are retained when only one side
        // is oversized.
        while !pending.is_empty() {
            let attempts = futures::stream::iter(pending.drain(..).map(|(path, range)| {
                let client = client.clone();
                let mut chunk_request = request.clone();
                let chunk_query_id = format!("{query_id}-stats-{path}");
                let deny_source_types = scope.deny_set().clone();
                async move {
                    chunk_request.time_range = range.clone();
                    chunk_request.limit = Some(chunk_limit);
                    chunk_request.offset = Some(0);
                    chunk_request.skip_histogram = true;
                    chunk_request.skip_field_stats = true;
                    chunk_request.table_view = false;
                    chunk_request.request_id = Some(chunk_query_id.clone());
                    chunk_request.query = aggregate_query.pretty_print();
                    let response = client
                        .search(&chunk_request, &chunk_query_id, None, &deny_source_types)
                        .await;
                    (path, range, response)
                }
            }))
            .buffer_unordered(2)
            .collect::<Vec<_>>()
            .await;

            for (path, range, response) in attempts {
                match response {
                    Ok(response) => {
                        if !response.total_count_exact
                            || response.total_count > response.results.len() as u64
                        {
                            return Err(SearchError::ResourceExhausted(format!(
                                "distributed stats exceeded the per-slice group bound of {chunk_limit}"
                            )));
                        }
                        chunks.push(response.results);
                    }
                    Err(error) if is_lake_scan_budget_rejection(&error) => {
                        let (left, right) = retries.split(&path, &range, error, &request.query)?;
                        pending.push((format!("{path}l"), left));
                        pending.push((format!("{path}r"), right));
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        let mut merged = std::collections::BTreeMap::<String, (Vec<serde_json::Value>, u64)>::new();
        for row in chunks.into_iter().flatten() {
            let object = row.as_object().ok_or_else(|| {
                SearchError::SqlValidationError(
                    "distributed stats worker returned a non-object row".to_string(),
                )
            })?;
            let merge_fields = plan
                .bucket_span_us
                .map(|_| "time_bucket")
                .into_iter()
                .chain(plan.group_by.iter().map(String::as_str))
                .collect::<Vec<_>>();
            let values = merge_fields
                .iter()
                .map(|field| {
                    object
                        .get(*field)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                })
                .collect::<Vec<_>>();
            let key = serde_json::to_string(&values).map_err(|error| {
                SearchError::SqlValidationError(format!(
                    "distributed stats group key could not be encoded: {error}"
                ))
            })?;
            let count = object
                .get(&plan.count_alias)
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                })
                .ok_or_else(|| {
                    SearchError::SqlValidationError(format!(
                        "distributed stats worker omitted numeric {}",
                        plan.count_alias
                    ))
                })?;
            let entry = merged.entry(key).or_insert((values, 0));
            entry.1 = entry.1.checked_add(count).ok_or_else(|| {
                SearchError::SqlValidationError(
                    "distributed stats count overflowed UInt64".to_string(),
                )
            })?;
        }
        if merged.len() > max_groups {
            return Err(SearchError::ResourceExhausted(format!(
                "distributed stats produced {} groups above the configured bound of {max_groups}",
                merged.len()
            )));
        }

        let mut complete = merged
            .into_iter()
            .map(|(key, (values, count))| {
                let mut row = serde_json::Map::new();
                let merge_fields = plan
                    .bucket_span_us
                    .map(|_| "time_bucket")
                    .into_iter()
                    .chain(plan.group_by.iter().map(String::as_str));
                for (field, value) in merge_fields.zip(values) {
                    row.insert(field.to_string(), value);
                }
                row.insert(
                    plan.count_alias.clone(),
                    serde_json::Value::Number(serde_json::Number::from(count)),
                );
                (key, count, serde_json::Value::Object(row))
            })
            .collect::<Vec<_>>();
        if plan.bucket_span_us.is_some() {
            complete.sort_by(|left, right| left.0.cmp(&right.0));
        } else {
            complete.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        }

        let complete = complete
            .into_iter()
            .map(|(_, _, row)| row)
            .collect::<Vec<_>>();
        Ok(complete)
    }

    /// Recover a scan-budget-rejected `stats` by running it as bisected
    /// event-time slices and merging the per-slice groups exactly
    /// (`lake_stats_merge`). The rejected full range is never re-sent; the
    /// Rust suffix (`sort`, `head`, ...) runs over the merged set.
    #[allow(clippy::too_many_arguments)]
    async fn search_primary_lake_sliced_stats(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &super::lake_stats_merge::LakeMergeableStatsPlan,
        rejection: SearchError,
        max_groups: usize,
        start_time: Instant,
        parsed: &Query,
    ) -> Result<SearchResponse, SearchError> {
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let chunk_limit = max_groups.clamp(1, self.config.max_limit);
        let aggregate_query = plan.aggregate_query.pretty_print();
        let deny_source_types = scope.deny_set();
        let slices = super::lake_stats_merge::run_lake_stats_slices(
            &request.time_range,
            rejection,
            &request.query,
            |path, range| {
                let mut chunk_request = request.clone();
                let chunk_query_id = format!("{query_id}-sliced-stats-{path}");
                chunk_request.query = aggregate_query.clone();
                chunk_request.time_range = range;
                chunk_request.limit = Some(chunk_limit);
                chunk_request.offset = Some(0);
                chunk_request.skip_histogram = true;
                chunk_request.skip_field_stats = true;
                chunk_request.table_view = false;
                chunk_request.request_id = Some(chunk_query_id.clone());
                async move {
                    let response = client
                        .search(&chunk_request, &chunk_query_id, None, deny_source_types)
                        .await?;
                    if !response.total_count_exact
                        || response.total_count > response.results.len() as u64
                    {
                        return Err(SearchError::ResourceExhausted(format!(
                            "sliced stats exceeded the per-slice group bound of {chunk_limit}"
                        )));
                    }
                    Ok(response.results)
                }
            },
        )
        .await?;
        let slice_count = slices.len();
        let merged = super::lake_stats_merge::merge_lake_stats_slices(plan, slices, max_groups)?;
        tracing::info!(
            request_id = %query_id,
            slices = slice_count,
            groups = merged.len(),
            "scan-budget-rejected stats completed as exact time slices"
        );
        let mut response = self.finish_primary_lake_count_stats(
            request,
            start_time,
            parsed,
            merged,
            &plan.post_commands,
            max_groups,
        )?;
        response
            .warnings
            .get_or_insert_with(Vec::new)
            .push(QueryWarningOutput {
                severity: "info".to_string(),
                code: "LAKE_SCAN_BUDGET_SLICED".to_string(),
                message: format!(
                    "The aggregation exceeded the worker scan budget and was executed as {slice_count} byte-fenced time slices, merged exactly"
                ),
                suggestion: None,
                impact: None,
            });
        Ok(response)
    }

    async fn search_primary_lake_distinct_stats(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &LakeDistinctPipelinePlan,
        max_groups: usize,
        start_time: Instant,
        parsed: &Query,
    ) -> Result<SearchResponse, SearchError> {
        use futures::StreamExt;

        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let chunk_limit = max_groups.clamp(1, self.config.max_limit);
        let mut pending = vec![("0".to_string(), request.time_range.clone())];
        let mut chunks = Vec::new();
        let mut retries = LakeSliceRetries::new();
        let mut truncation_splits = 0_usize;
        while !pending.is_empty() {
            let attempts = futures::stream::iter(pending.drain(..).map(|(path, range)| {
                let client = client.clone();
                let mut chunk_request = request.clone();
                let chunk_query_id = format!("{query_id}-dc-{path}");
                let deny_source_types = scope.deny_set().clone();
                let query = plan.aggregate_query.pretty_print();
                async move {
                    chunk_request.query = query;
                    chunk_request.time_range = range.clone();
                    chunk_request.limit = Some(chunk_limit);
                    chunk_request.offset = Some(0);
                    chunk_request.skip_histogram = true;
                    chunk_request.skip_field_stats = true;
                    chunk_request.table_view = false;
                    chunk_request.request_id = Some(chunk_query_id.clone());
                    let response = client
                        .search(&chunk_request, &chunk_query_id, None, &deny_source_types)
                        .await;
                    (path, range, response)
                }
            }))
            .buffer_unordered(2)
            .collect::<Vec<_>>()
            .await;

            for (path, range, response) in attempts {
                match response {
                    Ok(response) => {
                        if !response.total_count_exact
                            || response.total_count > response.results.len() as u64
                        {
                            return Err(SearchError::ResourceExhausted(format!(
                                "distributed distinct count exceeded the per-slice group bound of {chunk_limit}"
                            )));
                        }
                        // The compiler bounds each slice's values state at
                        // LAKE_DISTINCT_STATE_CAP; a full state is truncated
                        // (`dc()` answered exactly 10001 for 27,970 IPs).
                        // Bisect the slice until every state is complete, or
                        // fail rather than report a silent undercount.
                        if response.results.iter().any(|row| {
                            row.get(&plan.values_alias)
                                .is_some_and(|state| lake_distinct_state_len(state) >= LAKE_DISTINCT_STATE_CAP)
                        }) {
                            let split = (truncation_splits < LAKE_MAX_SLICE_ATTEMPTS)
                                .then(|| split_lake_aggregate_range(&range))
                                .flatten()
                                .ok_or_else(|| {
                                    SearchError::ResourceExhausted(format!(
                                        "distinct count needs more than {LAKE_DISTINCT_STATE_CAP} values per time slice; narrow the time range for an exact dc()/values()"
                                    ))
                                })?;
                            truncation_splits += 1;
                            pending.push((format!("{path}l"), split.0));
                            pending.push((format!("{path}r"), split.1));
                            continue;
                        }
                        chunks.push(response.results);
                    }
                    Err(error) if is_lake_scan_budget_rejection(&error) => {
                        let (left, right) = retries.split(&path, &range, error, &request.query)?;
                        pending.push((format!("{path}l"), left));
                        pending.push((format!("{path}r"), right));
                    }
                    Err(error) => return Err(error),
                }
            }
        }

        let mut merged = std::collections::BTreeMap::<
            String,
            (
                Vec<serde_json::Value>,
                std::collections::BTreeSet<String>,
                u64,
            ),
        >::new();
        for row in chunks.into_iter().flatten() {
            let object = row.as_object().ok_or_else(|| {
                SearchError::SqlValidationError(
                    "distributed distinct worker returned a non-object row".to_string(),
                )
            })?;
            let groups = plan
                .group_by
                .iter()
                .map(|field| {
                    object
                        .get(field)
                        .cloned()
                        .unwrap_or(serde_json::Value::Null)
                })
                .collect::<Vec<_>>();
            let key = serde_json::to_string(&groups).map_err(|error| {
                SearchError::SqlValidationError(format!(
                    "distributed distinct group key could not be encoded: {error}"
                ))
            })?;
            let values = object.get(&plan.values_alias).ok_or_else(|| {
                SearchError::SqlValidationError(
                    "distributed distinct worker omitted its values state".to_string(),
                )
            })?;
            let entry = merged
                .entry(key)
                .or_insert_with(|| (groups, std::collections::BTreeSet::new(), 0));
            let serialized = match values {
                serde_json::Value::Array(values) => values
                    .iter()
                    .filter(|value| !value.is_null())
                    .map(serde_json::Value::to_string)
                    .collect::<Vec<_>>(),
                serde_json::Value::String(values) => values
                    .split(", ")
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
                    .collect(),
                value if !value.is_null() => vec![value.to_string()],
                _ => Vec::new(),
            };
            for value in serialized {
                entry.1.insert(value);
            }
            if let Some(alias) = plan.count_output_alias.as_deref() {
                let count = object
                    .get(alias)
                    .and_then(|value| {
                        value
                            .as_u64()
                            .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                    })
                    .ok_or_else(|| {
                        SearchError::SqlValidationError(format!(
                            "distributed distinct worker omitted numeric {alias}"
                        ))
                    })?;
                entry.2 = entry.2.checked_add(count).ok_or_else(|| {
                    SearchError::SqlValidationError(
                        "distributed distinct companion count overflowed UInt64".to_string(),
                    )
                })?;
            }
            if entry.1.len() >= max_groups {
                return Err(SearchError::ResourceExhausted(format!(
                    "distributed distinct state reached the configured bound of {max_groups}; exact completeness cannot be proven"
                )));
            }
        }
        if merged.len() > max_groups {
            return Err(SearchError::ResourceExhausted(format!(
                "distributed distinct produced {} groups above the configured bound of {max_groups}",
                merged.len()
            )));
        }
        let mut complete = merged
            .into_iter()
            .map(
                |(key, (groups, values, raw_count))| -> Result<_, SearchError> {
                    let mut row = serde_json::Map::new();
                    for (field, value) in plan.group_by.iter().zip(groups) {
                        row.insert(field.clone(), value);
                    }
                    let count = values.len() as u64;
                    row.insert(plan.output_alias.clone(), serde_json::Value::from(count));
                    if let Some(alias) = plan.values_output_alias.as_deref() {
                        let values = values
                            .iter()
                            .map(|value| {
                                let bytes = base64::engine::general_purpose::STANDARD
                                    .decode(value)
                                    .map_err(|error| {
                                        SearchError::SqlValidationError(format!(
                                        "distributed distinct state was not valid base64: {error}"
                                    ))
                                    })?;
                                let value = String::from_utf8(bytes).map_err(|error| {
                                    SearchError::SqlValidationError(format!(
                                        "distributed distinct state was not UTF-8: {error}"
                                    ))
                                })?;
                                Ok(value)
                            })
                            .collect::<Result<Vec<_>, SearchError>>()?;
                        // Keep the public nPL contract identical to ClickHouse and
                        // post-processing: values(field) is a comma-separated
                        // String, not an implementation-specific JSON array. The
                        // BTreeSet above also makes the distributed merge stable.
                        // NAN-4291 (F6): like the compiled ungrouped
                        // aggregate, `values` over no rows is null, not "".
                        // (A grouped row exists only for a group with rows.)
                        let state = if values.is_empty() && plan.group_by.is_empty() {
                            serde_json::Value::Null
                        } else {
                            serde_json::Value::String(values.join(", "))
                        };
                        row.insert(alias.to_string(), state);
                    }
                    if let Some(alias) = plan.count_output_alias.as_deref() {
                        row.insert(alias.to_string(), serde_json::Value::from(raw_count));
                    }
                    let sort_count = plan
                        .count_output_alias
                        .as_ref()
                        .map_or(count, |_| raw_count);
                    Ok((key, sort_count, serde_json::Value::Object(row)))
                },
            )
            .collect::<Result<Vec<_>, SearchError>>()?;
        complete.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        self.finish_primary_lake_count_stats(
            request,
            start_time,
            parsed,
            complete.into_iter().map(|(_, _, row)| row).collect(),
            &plan.post_commands,
            max_groups,
        )
    }

    async fn search_primary_lake_count_metrics(
        &self,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        plan: &LakeCountMetricsPlan,
        start_time: Instant,
        parsed: &Query,
    ) -> Result<SearchResponse, SearchError> {
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let requests = plan.metrics.iter().enumerate().map(|(index, metric)| {
            let request_id = format!("{query_id}-metric-{index}");
            async move {
                let rows = client
                    .count_aggregate(
                        &request_id,
                        &metric.field,
                        false,
                        metric.predicate.as_ref(),
                        None,
                        &metric.alias,
                        &request.time_range,
                        metric.source_filter.as_deref(),
                        scope.deny_set(),
                        1,
                    )
                    .await?;
                Ok::<_, SearchError>((
                    metric.alias.clone(),
                    lake_single_count(&rows, &metric.alias)?,
                ))
            }
        });
        let values = futures::future::try_join_all(requests).await?;
        let results = vec![serde_json::Value::Object(
            values
                .into_iter()
                .map(|(alias, value)| (alias, serde_json::Value::from(value)))
                .collect(),
        )];
        self.finish_primary_lake_count_stats(request, start_time, parsed, results, &[], 1)
    }

    /// Execute a primary-lake query, retaining Nano's prevalence semantics in
    /// the Rust service. The lake worker receives the pre-prevalence nPL only;
    /// immutable point state is fetched through the separately pinned
    /// [`PrevalenceLookup`] contract and all filtering/decorating happens here.
    /// Page a lean-cell raw-event search (see [`LAKE_PAGE_ROWS`]). `None`:
    /// not cursor-continuable, run the ordinary single request.
    async fn search_lake_cell_paged(
        &self,
        client: &crate::search::lake::LakeQueryClient,
        request: &SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
    ) -> Result<Option<SearchResponse>, SearchError> {
        let sink = LAKE_ROW_SINK.try_with(Clone::clone).ok();
        let gathered = std::sync::Mutex::new((Vec::new(), 0_usize));
        let over_budget = std::sync::atomic::AtomicBool::new(false);
        let paged = client
            .search_paged(request, query_id, scope.deny_set(), LAKE_PAGE_ROWS, |rows| {
                let sink = sink.clone();
                let gathered = &gathered;
                let over_budget = &over_budget;
                async move {
                    match sink {
                        Some(sink) => sink.send(rows).await.is_ok(),
                        None => {
                            let bytes: usize = rows.iter().map(|row| row.to_string().len()).sum();
                            let mut gathered = gathered.lock().expect("paged rows");
                            gathered.1 += bytes;
                            if gathered.1 > LAKE_PAGED_SYNC_MAX_BYTES {
                                over_budget.store(true, std::sync::atomic::Ordering::Relaxed);
                                return false;
                            }
                            gathered.0.extend(rows);
                            true
                        }
                    }
                }
            })
            .await?;
        let Some(paged) = paged else { return Ok(None) };
        if over_budget.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(SearchError::ResourceExhausted("memory".to_string()));
        }
        // NAN-4593: the row consumer went away mid-read, so the rows gathered
        // here are a prefix. Never hand that back as a complete answer.
        if paged.stopped {
            return Err(SearchError::Cancelled);
        }
        let mut response = paged.first.ok_or_else(|| {
            SearchError::SqlValidationError("paged lake search returned no first page".to_string())
        })?;
        response.results = gathered.into_inner().expect("paged rows").0;
        response.total_count = paged.delivered as u64;
        response.total_count_exact = !paged.truncated;
        tracing::debug!(pages = paged.pages, rows = paged.delivered, streamed = sink.is_some(), "paged lean-cell search");
        Ok(Some(response))
    }

    /// Run one bounded lake histogram companion, if planned.
    async fn lake_histogram_companion(
        &self,
        plan: Option<&LakeHistogramPlan>,
    ) -> Option<Result<Vec<HistogramBucket>, SearchError>> {
        let (query, time_range, id, deny) = plan?;
        Some(
            self.generate_histogram(query, time_range, Some(id), crate::query::Dataset::Logs, deny)
                .await,
        )
    }

    /// Run an aggregate lake search beside its base-search histogram
    /// companion (NAN-3062). Both calls are bounded and joined, so no detached
    /// companion keeps scanning after the search returns; the companion is
    /// one count-by-bucket pass over the base predicate (usually the
    /// count rollup), never a second run of the aggregation.
    async fn with_lake_histogram(
        &self,
        plan: Option<&LakeHistogramPlan>,
        counts_result_rows: bool,
        search: impl std::future::Future<Output = Result<SearchResponse, SearchError>>,
    ) -> Result<SearchResponse, SearchError> {
        let (response, histogram) = tokio::join!(search, self.lake_histogram_companion(plan));
        let mut response = response?;
        attach_lake_histogram_result(&mut response, histogram, counts_result_rows);
        Ok(response)
    }

    /// NAN-3078: plan a durable search whose top-level pipeline keeps
    /// Nano-side stages. The job's `request` becomes the SQL-only candidate
    /// prefix — the same prefix, row bound and projection the interactive lane
    /// fetches ([`plan_lake_post_processing`]) — and the returned
    /// `SearchNplPostV1` task carries the complete query whose suffix Search
    /// applies to the verified result.
    ///
    /// Still refused with [`DURABLE_LANE_POST_PROCESSING_REFUSAL`]: `| ai`
    /// (a per-row model call must not rerun on every result read), a
    /// source-replacing `inputlookup` (it scans nothing, so it has no durable
    /// work), and a candidate page too large to post-process in one read.
    pub(super) async fn plan_durable_post_processing(
        &self,
        request: &mut SearchRequest,
        parsed: Query,
        task: &crate::search::DurableLakeTask,
    ) -> Result<crate::search::DurableLakeTask, SearchError> {
        let refusal =
            || SearchError::SqlValidationError(DURABLE_LANE_POST_PROCESSING_REFUSAL.to_string());
        let (parsed, _) = apply_auto_sort(parsed);
        let plan = plan_lake_post_processing(&parsed);
        if plan
            .post_commands
            .iter()
            .any(|command| matches!(command, Command::Ai { .. }))
            || lake_post_processing_replaces_source(&plan.post_commands)
        {
            return Err(refusal());
        }
        self.require_lake_prevalence_configuration(&parsed)?;
        let requested_limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit)
            .max(1);
        let requested_offset = request.offset.unwrap_or(0);
        let (limit, offset) = plan
            .candidate_limit()
            .map_or((requested_limit, requested_offset), |limit| (limit, 0));
        if offset.saturating_add(limit) > IN_MEMORY_PREVALENCE_FETCH_CAP {
            return Err(refusal());
        }
        let post_query = parsed.pretty_print();
        if post_query.len() > crate::search::MAX_DURABLE_POST_QUERY_BYTES {
            return Err(refusal());
        }
        let query_profile = self.dataset_profile(request.dataset.as_deref());
        request.query = plan.candidate_query(
            &parsed,
            &self.ch_sql_generator,
            query_profile.as_ref(),
            query_profile.uses_strict_canonical_fields(),
        );
        request.limit = Some(limit);
        request.offset = Some(offset);
        request.table_view = false;
        Ok(crate::search::DurableLakeTask::SearchNplPostV1 {
            post_query,
            requested_limit,
            requested_offset,
            required_scan_bytes: task.required_scan_bytes(),
        })
    }

    /// NAN-3078: the answer of a completed `SearchNplPostV1` job. Every
    /// candidate page is read through [`Self::get_durable_job_result_page`],
    /// which re-verifies the result's moving retention proof, and the query's
    /// Nano-side suffix is applied exactly as the interactive lane applies it.
    /// Callers must have authorized the job (owner, source scope, retention)
    /// first; the raw candidate pages never leave this method.
    pub async fn durable_post_processed_result(
        &self,
        job: &crate::search::SearchJob,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        crate::inputlookup::shared::with_fetch_search_id(
            crate::inputlookup::shared::audit_search_id(&job.id),
            self.durable_post_processed_result_with_fetch_audit(job, scope),
        )
        .await
    }

    async fn durable_post_processed_result_with_fetch_audit(
        &self,
        job: &crate::search::SearchJob,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();
        let Some(crate::search::DurableLakeTask::SearchNplPostV1 {
            post_query,
            requested_limit,
            requested_offset,
            ..
        }) = job.task.as_ref()
        else {
            return Err(SearchError::SqlValidationError(
                "job is not a post-processed durable search".to_string(),
            ));
        };
        let reference = job.result_ref.as_ref().ok_or_else(|| {
            SearchError::ServiceUnavailable(
                "completed durable job has no result reference".to_string(),
            )
        })?;
        reference
            .verify_retention_for_range(
                self.admission_scope,
                &job.request.time_range,
                chrono::Utc::now(),
            )
            .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
        let candidate_rows = usize::try_from(reference.rows).unwrap_or(usize::MAX);
        if candidate_rows > IN_MEMORY_PREVALENCE_FETCH_CAP {
            return Err(SearchError::SqlValidationError(
                "durable post-processing candidate set exceeds its envelope".to_string(),
            ));
        }
        let mut rows = Vec::with_capacity(candidate_rows);
        for page in 0..reference.parts {
            rows.extend(
                self.get_durable_job_result_page(&job.id, reference, page)
                    .await?
                    .rows,
            );
        }
        if rows.len() != candidate_rows {
            return Err(SearchError::SqlValidationError(
                "durable post-processing candidate pages differ from their manifest".to_string(),
            ));
        }
        let mut parsed = parse_query(post_query).map_err(convert_parse_error)?;
        // NAN-3257: the stored post query is pretty-printed nPL, which keeps a
        // preset by NAME (`tree process`). Resolve it against this tenant's
        // profile exactly as admission did, or the suffix reads UDM field
        // names off canonical OCSF candidate rows and finds nothing.
        let query_profile = self.dataset_profile(job.request.dataset.as_deref());
        if crate::query::Dataset::from_selector(job.request.dataset.as_deref().unwrap_or("logs"))
            == crate::query::Dataset::Logs
            && query_profile.uses_strict_canonical_fields()
        {
            apply_profile_product_semantics(&mut parsed, query_profile.as_ref());
        }
        let plan = plan_lake_post_processing(&parsed);
        let display_type = determine_display_type(&parsed);
        let base_offset = if plan.candidate_limit().is_some() {
            0
        } else {
            *requested_offset as u64
        };
        let response = SearchResponse {
            server_wall_ms: None,
            total_count: base_offset + rows.len() as u64 + u64::from(reference.has_more),
            // A filled candidate envelope stopped early; more events matched.
            total_count_exact: !reference.has_more,
            results: rows,
            execution_time_ms: 0,
            fields: Vec::new(),
            generated_sql: None,
            histogram: None,
            warnings: None,
            cost_score: None,
            display_type: None,
            column_order: None,
            completeness: None,
        };
        let max_post_processing_groups =
            self.query_limits.read().await.max_post_processing_groups as usize;
        self.finish_lake_post_processing(
            plan,
            response,
            LakePostProcessingContext {
                parsed: &parsed,
                display_type,
                requested_limit: *requested_limit,
                requested_offset: *requested_offset,
                skip_field_stats: job.request.skip_field_stats,
                fallback_reference_time: job.request.time_range.end,
                scope,
                max_post_processing_groups,
                start_time,
            },
        )
        .await
    }

    /// Lake prevalence stages need immutable snapshot IDs and valid windows.
    pub(super) fn require_lake_prevalence_configuration(
        &self,
        parsed: &Query,
    ) -> Result<(), SearchError> {
        let prevalence_commands = extract_prevalence_commands(parsed);
        if self.prevalence_lookup.is_none() && !prevalence_commands.is_empty() {
            return Err(SearchError::PrevalenceError(
                "lake prevalence is not configured with immutable snapshot IDs".to_string(),
            ));
        }
        for command in &prevalence_commands {
            ast_to_prevalence_time_window(command.time_window.as_ref())?;
        }
        Ok(())
    }

    /// NAN-3078: apply a lake query's Nano-side suffix to its fetched
    /// candidate rows. Shared by the interactive lane (rows straight from the
    /// worker) and durable post-processed jobs (rows from verified result
    /// pages), so both lanes answer the same query identically.
    pub(super) async fn finish_lake_post_processing(
        &self,
        plan: LakePostProcessingPlan,
        mut response: SearchResponse,
        context: LakePostProcessingContext<'_>,
    ) -> Result<SearchResponse, SearchError> {
        let LakePostProcessingPlan {
            post_commands,
            tree_command,
            funnel_command,
            safe_head_bound,
            needs_candidate_set,
            ..
        } = plan;
        let LakePostProcessingContext {
            parsed,
            display_type,
            requested_limit,
            requested_offset,
            skip_field_stats,
            fallback_reference_time,
            scope,
            max_post_processing_groups,
            start_time,
        } = context;
        let fetched_count = response.results.len();
        let base_total_count = response.total_count;
        let base_total_exact = response.total_count_exact;
        let prevalence_scope = crate::auth::ArtifactScope::from_scope(scope);
        let mut results = response.results;
        let mut runtime_warnings = Vec::new();
        // NAN-2373: a Nano-side decoration stage that emits NONE of its declared
        // output columns must say so. Without this, `| prevalence enrich=true |
        // where host_count < 10` returns 200 with zero rows and no signal that
        // the threshold column never existed.
        let mut output_column_warnings: Vec<String> = Vec::new();
        // NAN-3294: `| resolve_identity` that resolved nothing says so.
        let mut identity_warnings: Vec<String> = Vec::new();
        let mut ordinary_commands = Vec::new();

        for command in post_commands {
            let declared = output_column_guard::declared_output_columns(&command);
            let is_stateful = matches!(
                &command,
                Command::Prevalence { .. }
                    | Command::Lookup { .. }
                    | Command::InputLookup { .. }
                    | Command::ResolveIdentity { .. }
                    | Command::Ai { .. }
            );
            if is_stateful && !ordinary_commands.is_empty() {
                let processed = apply_post_prevalence_commands_with_limit(
                    results,
                    &ordinary_commands,
                    max_post_processing_groups,
                )?;
                results = processed.results;
                runtime_warnings.extend(processed.warnings);
                ordinary_commands.clear();
            }

            match command {
                Command::Prevalence {
                    artifact_fields,
                    conditions,
                    time_window,
                    enrich,
                } => {
                    let info = PrevalenceCommandInfo {
                        artifact_fields,
                        conditions,
                        time_window,
                        enrich,
                    };
                    results = self
                        .apply_prevalence_processing(results, &[info], &prevalence_scope)
                        .await?;
                }
                Command::Lookup {
                    table_name,
                    event_field,
                    key_field,
                    output_fields,
                    output_renames,
                    output_new,
                    case_insensitive,
                } => {
                    let info = LookupCommandInfo {
                        table_name,
                        event_field,
                        key_field,
                        output_fields,
                        output_renames,
                        output_new,
                        case_insensitive,
                    };
                    results =
                        apply_lookup_enrichment(results, &[info], self.lookup_service.as_ref())
                            .await?;
                }
                Command::InputLookup {
                    url,
                    format,
                    key_field,
                    timeout_secs,
                    max_rows,
                    cache_ttl_secs,
                } => {
                    let info = InputLookupCommandInfo {
                        url,
                        format,
                        key_field,
                        timeout_secs,
                        max_rows,
                        cache_ttl_secs,
                    };
                    results = apply_inputlookup_enrichment(
                        results,
                        &[info],
                        self.inputlookup_service.as_ref(),
                        &mut runtime_warnings,
                    )
                    .await?;
                }
                Command::ResolveIdentity { field, max_age, .. } => {
                    results = self
                        .apply_lake_identity_batch(
                            results,
                            &field,
                            &max_age,
                            fallback_reference_time,
                            scope,
                            &mut identity_warnings,
                        )
                        .await?;
                }
                Command::Ai { prompt, max_rows } => {
                    // NAN-3190: bounded below the edge timeout; failures
                    // become per-row ERROR verdicts instead of a hang.
                    results = super::ai_pipe_deadline::enrich_rows_with_deadline(
                        self.ai_client.as_ref(),
                        results,
                        &prompt,
                        max_rows,
                        super::ai_pipe_deadline::AI_PIPE_DEADLINE,
                    )
                    .await;
                }
                ordinary => ordinary_commands.push(ordinary),
            }

            if let Some((stage, columns)) = declared {
                let missing = output_column_guard::missing_declared_columns(&results, &columns);
                if !missing.is_empty() {
                    output_column_warnings.push(
                        output_column_guard::missing_output_column_warning(stage, &missing),
                    );
                }
            }
        }
        if !ordinary_commands.is_empty() {
            let processed = apply_post_prevalence_commands_with_limit(
                results,
                &ordinary_commands,
                max_post_processing_groups,
            )?;
            results = processed.results;
            runtime_warnings.extend(processed.warnings);
        }
        // Match the established residual ClickHouse path: the nested object is
        // available to suffix filters, then removed because the same values are
        // exposed through the stable flat fields.
        for row in &mut results {
            if let Some(object) = row.as_object_mut() {
                object.remove("_prevalence");
            }
        }

        let mut tree_bound_warning = None;
        if let Some(ref tree_info) = tree_command {
            results = self.build_tree_visualization(results, tree_info).await?;
            // NAN-3294: name the host → IP identities a widened `tree web`
            // matched by (read back from the query, so both lanes agree).
            let bindings = super::lake_host_identity::lake_tree_identity_bindings(parsed);
            if let (Some(note), Some(marker)) = (
                super::lake_host_identity::lake_host_binding_note(&bindings),
                results.first_mut().and_then(serde_json::Value::as_object_mut),
            ) {
                append_tree_note(marker, &note);
                marker.insert(
                    "_tree_identities".to_string(),
                    serde_json::Value::Array(
                        bindings
                            .iter()
                            .map(|binding| {
                                serde_json::json!({
                                    "host": binding.host,
                                    "ip": binding.ip.to_string(),
                                    "start": binding.start,
                                    "end": binding.end,
                                })
                            })
                            .collect(),
                    ),
                );
            }
            // NAN-3257: a tree built from a filled candidate envelope is
            // partial. Say so instead of presenting it as the whole window.
            if let Some(note) = lake_tree_bound_note(fetched_count, base_total_count) {
                if let Some(marker) = results.first_mut().and_then(serde_json::Value::as_object_mut) {
                    marker.insert("_tree_truncated".to_string(), serde_json::Value::Bool(true));
                    append_tree_note(marker, &note);
                }
                tree_bound_warning = Some(note);
            }
        }
        if let Some(ref funnel_info) = funnel_command {
            results = self.build_funnel_view(results, funnel_info);
        }

        let total_count = if needs_candidate_set || safe_head_bound.is_some() {
            let completed_count = results.len() as u64;
            results = results
                .into_iter()
                .skip(requested_offset)
                .take(requested_limit)
                .collect();
            if needs_candidate_set && base_total_count > fetched_count as u64 {
                runtime_warnings.push(format!(
                    "Lake post-processing examined the newest {} candidate events out of {}; results are approximate. Narrow the search or time range for an exact result.",
                    fetched_count, base_total_count
                ));
            } else if needs_candidate_set && !base_total_exact {
                // NAN-3078: a durable candidate envelope that filled up has no
                // exact base total, only the fact that more events matched.
                runtime_warnings.push(format!(
                    "Lake post-processing examined the newest {fetched_count} candidate events; more events matched, so results are approximate. Narrow the search or time range for an exact result."
                ));
            }
            completed_count
        } else {
            base_total_count
        };

        response.results = results;
        response.total_count = total_count;
        // NAN-2550: a bounded `| head N` was satisfied in full, so the count is
        // exact even though the underlying lake page reported a bound.
        if safe_head_bound.is_some() {
            response.total_count_exact = true;
        }
        response.execution_time_ms = start_time.elapsed().as_millis() as u64;
        response.display_type = Some(display_type);
        response.column_order = get_column_order(parsed);
        response.fields = if skip_field_stats {
            Vec::new()
        } else {
            let mut statistics = FieldStatistics::new();
            for row in &response.results {
                statistics.process_row(row);
            }
            statistics.get_field_info(self.config.top_values_count)
        };
        if !output_column_warnings.is_empty() {
            let warnings = response.warnings.get_or_insert_with(Vec::new);
            warnings.extend(
                output_column_warnings
                    .into_iter()
                    .map(|message| QueryWarningOutput {
                        severity: "warning".to_string(),
                        code: "MISSING_OUTPUT_COLUMN".to_string(),
                        message,
                        suggestion: Some(
                            "Check that the events carry the fields this stage reads, or remove the downstream reference to its output columns."
                                .to_string(),
                        ),
                        impact: Some(
                            "Filters on the missing column match nothing, so this query can silently return zero rows."
                                .to_string(),
                        ),
                    }),
            );
        }
        if !identity_warnings.is_empty() {
            response.warnings.get_or_insert_with(Vec::new).extend(identity_warnings.into_iter().map(|message| {
                QueryWarningOutput {
                    severity: "warning".to_string(),
                    code: "IDENTITY_UNRESOLVED".to_string(),
                    message,
                    suggestion: Some(
                        "Check the field name, widen max_age, or resolve the opposite direction (host or user to IP).".to_string(),
                    ),
                    impact: Some("No identity_* columns were added.".to_string()),
                }
            }));
        }
        if let Some(message) = tree_bound_warning {
            response.warnings.get_or_insert_with(Vec::new).push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "TREE_CANDIDATE_BOUND".to_string(),
                message,
                suggestion: Some("Narrow the base search or time range, or root the tree with root=<pattern>.".to_string()),
                impact: Some("Some edges are not in the tree; ancestry beyond the fetched edges is unknown.".to_string()),
            });
        }
        if !runtime_warnings.is_empty() {
            let warnings = response.warnings.get_or_insert_with(Vec::new);
            warnings.extend(
                runtime_warnings
                    .into_iter()
                    .map(|message| QueryWarningOutput {
                        severity: "warning".to_string(),
                        code: "LAKE_POST_PROCESSING_CANDIDATE_BOUND".to_string(),
                        message,
                        suggestion: Some("Narrow the base query or time range.".to_string()),
                        impact: Some(
                            "The returned prevalence-filtered set may be incomplete.".to_string(),
                        ),
                    }),
            );
        }
        Ok(response)
    }

    async fn search_primary_lake(
        &self,
        mut request: SearchRequest,
        query_id: &str,
        scope: &ScopeSet,
        max_post_processing_groups: usize,
        start_time: Instant,
    ) -> Result<SearchResponse, SearchError> {
        let request_dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
        let query_profile = self.dataset_profile(request.dataset.as_deref());
        let mut parsed = parse_query(&request.query).map_err(convert_parse_error)?;
        // NAN-3385: `timechart bins=N` → a real span before rollup routing,
        // count plans and the presentation wrapper read it.
        crate::query::resolve_timechart_bins(
            &mut parsed,
            &crate::query::TimeRange { start: request.time_range.start, end: request.time_range.end },
        );
        if request_dataset == crate::query::Dataset::Logs
            && query_profile.uses_strict_canonical_fields()
        {
            apply_profile_product_semantics(&mut parsed, query_profile.as_ref());
        }
        validate_query_field_names(&parsed, query_profile.as_ref())?;
        let count_pipeline =
            lake_count_pipeline_plan_for(self.active_profile.as_ref(), &parsed, scope.deny_set());
        let cell_route = if self.lake_query.client.as_ref().is_some_and(|client| client.is_lake_cell()) {
            lake_cell_stats_route(self.active_profile.as_ref(), &parsed, count_pipeline.as_ref())
        } else {
            LakeCellStatsRoute::Default
        };
        let (distributed_count_stats, rollup_first_page) = match cell_route {
            LakeCellStatsRoute::Default => (count_pipeline, None),
            LakeCellStatsRoute::RollupThenCompiledPage => (None, count_pipeline),
            LakeCellStatsRoute::CompiledPage => (None, None),
        };
        // Executed only as `count_aggregate` requests: planned from the
        // rollup spelling of the base search's fields (NAN-3780).
        let distributed_count_metrics = lake_count_metrics_plan_scoped(
            &lake_rollup_planning_query(self.active_profile.as_ref(), &parsed),
            scope.deny_set(),
        );
        // NAN-3166: the distinct plan stays on the gated text. It accepts any
        // base search, so the gate does not change its route, and its
        // `aggregate_query` is executed as a query and must keep the gate.
        let distributed_distinct_stats = lake_distinct_pipeline_plan(&parsed);
        let progressive_head_page = lake_head_page_plan(&parsed);
        let (mut parsed, _) = apply_auto_sort(parsed);
        let display_type = determine_display_type(&parsed);
        if let Some(risk) = detect_oom_risk(&parsed) {
            return Err(SearchError::SqlValidationError(risk.message()));
        }
        // NAN-3062: the aggregate fast paths below (count cube, distinct
        // state, count metrics) return before the general histogram plan, so
        // they get the base-search timeline from this plan.
        let aggregate_histogram_plan =
            lake_histogram_plan(
                &request, request_dataset, &parsed, query_id, scope, self.histogram_only,
            );
        let histogram_counts_rows = super::lake_histogram_counts_result_rows(&parsed);
        // NAN-3093: a histogram-only view of a search that renders no
        // timeline (page markers, product views, aggregates the UI charts,
        // later pages, `skip_histogram`) has nothing to answer.
        if self.histogram_only && aggregate_histogram_plan.is_none() {
            return histogram_only_response(None, false, display_type, start_time);
        }

        // Page directives are storage-independent and must not scan the lake.
        // Keep this inside the primary branch so the log backend selection
        // cannot bypass the established marker contract.
        if is_command_page_marker(display_type) {
            return Ok(SearchResponse {
                server_wall_ms: None,
                results: vec![command_page_marker(&parsed)?],
                total_count: 1,
                // A page marker is exactly one synthetic row.
                total_count_exact: true,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: None,
                cost_score: None,
                display_type: Some(display_type),
                column_order: None,
                completeness: None,
            });
        }

        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;

        if display_type == DisplayType::Asset {
            let asset = extract_asset_command(&parsed).ok_or_else(|| {
                SearchError::SqlValidationError(
                    "asset display was selected without an asset command".to_string(),
                )
            })?;
            let time_range = TimeRange::new(request.time_range.start, request.time_range.end);
            let results = self
                .build_lake_asset_view(&parsed, &asset, &time_range, scope)
                .await?;
            let total_count = asset_view_total_count(&results).unwrap_or(1);
            return Ok(SearchResponse {
                server_wall_ms: None,
                results,
                total_count,
                // The asset marker carries the real event total, not a page bound.
                total_count_exact: true,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: None,
                cost_score: None,
                display_type: Some(DisplayType::Asset),
                column_order: get_column_order(&parsed),
                completeness: None,
            });
        }

        if display_type == DisplayType::Cloud {
            let cloud = extract_cloud_command(&parsed).ok_or_else(|| {
                SearchError::SqlValidationError(
                    "cloud display was selected without a cloud command".to_string(),
                )
            })?;
            let time_range = TimeRange::new(request.time_range.start, request.time_range.end);
            let results = self
                .build_lake_cloud_view(&parsed, &cloud, &time_range, scope)
                .await?;
            let total_count = results
                .first()
                .and_then(|row| row.pointer("/_cloud_pagination/total_count"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            return Ok(SearchResponse {
                server_wall_ms: None,
                results,
                total_count,
                // The cloud marker carries the real event total, not a page bound.
                total_count_exact: true,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: None,
                cost_score: None,
                display_type: Some(DisplayType::Cloud),
                column_order: get_column_order(&parsed),
                completeness: None,
            });
        }

        if display_type == DisplayType::Lateral {
            if request.time_range.end - request.time_range.start > chrono::Duration::hours(24) {
                return Err(SearchError::ResourceExhausted("Lateral windows beyond 24h require a durable job".into()));
            }
            let lateral = extract_lateral_command(&parsed).ok_or_else(|| {
                SearchError::SqlValidationError(
                    "lateral display was selected without a lateral command".to_string(),
                )
            })?;
            let post_lateral = extract_post_lateral_commands(&parsed);
            let requested_limit = request
                .limit
                .unwrap_or(self.config.default_limit)
                .min(self.config.max_limit);
            let requested_offset = request.offset.unwrap_or(0);
            let base_query = strip_lateral_and_after(&parsed);
            let seed_request_id = format!("{query_id}-lateral-seed");
            request.query = base_query.pretty_print();
            request.limit = Some(10);
            request.offset = Some(0);
            request.table_view = false;
            request.skip_histogram = true;
            request.skip_field_stats = true;
            request.request_id = Some(seed_request_id.clone());
            let explicit_seed = extract_lake_lateral_identifier_from_query(&base_query, &lateral);
            let seed_results = if explicit_seed.is_some() {
                Vec::new()
            } else {
                client
                    .search(&request, &seed_request_id, None, scope.deny_set())
                    .await?
                    .results
            };
            let time_range = TimeRange::new(request.time_range.start, request.time_range.end);
            // Queries with stages after lateral retain atomic post-processing.
            let defer = crate::search::streaming::DEFER_LATERAL_VIEW.try_with(|value| *value).unwrap_or(false)
                && post_lateral.is_empty();
            let mut results = crate::search::streaming::DEFER_LATERAL_VIEW.scope(defer,
                self.build_lake_lateral_view(seed_results, &lateral, explicit_seed, &time_range, scope)).await?;
            let pending = results.first().is_some_and(|row| row.get("_lateral_pending").and_then(serde_json::Value::as_bool) == Some(true));
            let trace_complete = !pending && results.first().and_then(|row| row.get("_lateral_config"))
                .and_then(|config| config.get("time_truncated_at_hop")).is_none_or(serde_json::Value::is_null);
            let mut warnings = Vec::new();
            if !post_lateral.is_empty() {
                let metadata = results
                    .iter()
                    .position(|row| row.get("_display_type").is_some())
                    .map(|index| results.remove(index));
                let processed = apply_post_prevalence_commands_with_limit(
                    results,
                    &post_lateral,
                    max_post_processing_groups,
                )?;
                results = processed.results;
                warnings.extend(processed.warnings);
                if let Some(metadata) = metadata {
                    results.insert(0, metadata);
                }
            }
            let (results, total_count) =
                paginate_post_processed_results(results, requested_offset, requested_limit, true);
            return Ok(SearchResponse {
                server_wall_ms: None,
                results,
                total_count,
                // Post-processing ran over the complete candidate set.
                total_count_exact: trace_complete,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: (!warnings.is_empty()).then(|| {
                    warnings
                        .into_iter()
                        .map(|message| QueryWarningOutput {
                            severity: "warning".to_string(),
                            code: "LAKE_LATERAL_POST_PROCESSING".to_string(),
                            message,
                            suggestion: None,
                            impact: None,
                        })
                        .collect()
                }),
                cost_score: None,
                display_type: Some(DisplayType::Lateral),
                column_order: get_column_order(&parsed),
                completeness: None,
            });
        }

        if display_type == DisplayType::Baseline {
            let baseline = extract_baseline_command(&parsed).ok_or_else(|| {
                SearchError::SqlValidationError(
                    "baseline display was selected without a baseline command".to_string(),
                )
            })?;
            let entity = crate::search::query_processing::resolve_baseline_entity(
                &parsed,
                &baseline,
            )
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "| baseline could not determine an entity; use host=, user=, or ip=, or lead with an exact canonical OCSF entity filter"
                        .to_string(),
                )
            })?;
            let requested_limit = request
                .limit
                .unwrap_or(self.config.default_limit)
                .min(self.config.max_limit);
            let requested_offset = request.offset.unwrap_or(0);
            let mut start = request.time_range.start;
            let end = request.time_range.end;
            let mut warnings = None;
            if end - start > chrono::Duration::days(super::baseline::MAX_BASELINE_CURRENT_DAYS) {
                start = end - chrono::Duration::days(super::baseline::MAX_BASELINE_CURRENT_DAYS);
                warnings = Some(vec![QueryWarningOutput {
                    severity: "warning".to_string(),
                    code: "BASELINE_WINDOW_CLAMPED".to_string(),
                    message: format!(
                        "Baseline current window was clamped to the newest {} days",
                        super::baseline::MAX_BASELINE_CURRENT_DAYS
                    ),
                    suggestion: Some("Narrow the time picker for a focused baseline".to_string()),
                    impact: Some(
                        "Older events in the requested current window were not analyzed"
                            .to_string(),
                    ),
                }]);
            }
            let time_range = TimeRange::new(start, end);
            let results = self
                .build_lake_baseline_view(&baseline, entity, &time_range, scope)
                .await?;
            let (results, total_count) =
                paginate_post_processed_results(results, requested_offset, requested_limit, false);
            return Ok(SearchResponse {
                server_wall_ms: None,
                results,
                total_count,
                // Post-processing ran over the complete candidate set.
                total_count_exact: true,
                execution_time_ms: start_time.elapsed().as_millis() as u64,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings,
                cost_score: None,
                display_type: Some(DisplayType::Baseline),
                column_order: get_column_order(&parsed),
                completeness: None,
            });
        }

        if request_dataset == crate::query::Dataset::Logs {
            let histogram_plan = aggregate_histogram_plan.as_ref();
            if self.histogram_only {
                // The same timeline each fast path below attaches beside its
                // aggregate, or none where the bounded head page skips it.
                if distributed_count_metrics.is_some()
                    || distributed_count_stats.is_some()
                    || distributed_distinct_stats.is_some()
                {
                    return histogram_only_response(
                        self.lake_histogram_companion(histogram_plan).await,
                        histogram_counts_rows,
                        display_type,
                        start_time,
                    );
                }
                if progressive_head_page.is_some() {
                    return histogram_only_response(None, false, display_type, start_time);
                }
            }
            if let Some(plan) = distributed_count_metrics.as_ref() {
                return self
                    .with_lake_histogram(
                        histogram_plan,
                        histogram_counts_rows,
                        self.search_primary_lake_count_metrics(
                            &request, query_id, scope, plan, start_time, &parsed,
                        ),
                    )
                    .await;
            }
            if let Some(pipeline) = rollup_first_page.as_ref().filter(|_| !self.histogram_only) {
                let rows = match self
                    .lake_count_rollup_rows(
                        &request,
                        query_id,
                        scope,
                        &pipeline.aggregate,
                        &pipeline.aggregate_query,
                        max_post_processing_groups.min(LAKE_CELL_ROLLUP_PAGE_MAX_GROUPS),
                    )
                    .await
                {
                    Ok(rows) => rows,
                    Err(error) => {
                        tracing::warn!(
                            request_id = %query_id,
                            error = %error,
                            "exact rollup page unavailable; running the compiled page"
                        );
                        None
                    }
                };
                if let Some(rows) = rows {
                    let finished = self.finish_primary_lake_count_stats(
                        &request,
                        start_time,
                        &parsed,
                        rows,
                        &pipeline.post_commands,
                        max_post_processing_groups,
                    );
                    return self
                        .with_lake_histogram(histogram_plan, histogram_counts_rows, async { finished })
                        .await;
                }
            }
            if let Some(pipeline) = distributed_count_stats.as_ref() {
                return self
                    .with_lake_histogram(
                        histogram_plan,
                        histogram_counts_rows,
                        self.search_primary_lake_count_stats(
                            &request,
                            query_id,
                            scope,
                            &pipeline.aggregate,
                            &pipeline.aggregate_query,
                            &pipeline.post_commands,
                            max_post_processing_groups,
                            start_time,
                            &parsed,
                        ),
                    )
                    .await;
            }
            if let Some(pipeline) = distributed_distinct_stats.as_ref() {
                return self
                    .with_lake_histogram(
                        histogram_plan,
                        histogram_counts_rows,
                        self.search_primary_lake_distinct_stats(
                            &request,
                            query_id,
                            scope,
                            pipeline,
                            max_post_processing_groups,
                            start_time,
                            &parsed,
                        ),
                    )
                    .await;
            }
            if let Some(page) = progressive_head_page.as_ref() {
                let requested_limit = request
                    .limit
                    .unwrap_or(self.config.default_limit)
                    .min(self.config.max_limit);
                let requested_offset = request.offset.unwrap_or(0);
                request.query = page.query_without_head.pretty_print();
                request.limit = Some(page.head_count);
                request.offset = Some(0);
                request.skip_histogram = true;
                request.request_id = Some(query_id.to_string());
                let mut response = client
                    .search(&request, query_id, None, scope.deny_set())
                    .await?;
                response.results.truncate(page.head_count);
                let complete_count = response.results.len() as u64;
                response.results = response
                    .results
                    .into_iter()
                    .skip(requested_offset)
                    .take(requested_limit)
                    .collect();
                response.total_count = complete_count;
                // NAN-2550: the head page fetched the complete `head_count` set,
                // so this total is exact regardless of what the page reported.
                response.total_count_exact = true;
                response.display_type = Some(display_type);
                response.column_order = get_column_order(&parsed);
                response.execution_time_ms = start_time.elapsed().as_millis() as u64;
                return Ok(response);
            }
        }

        if request_dataset == crate::query::Dataset::Logs {
            orient_lookup_keys(&mut parsed, self.lookup_service.as_ref()).await;
            if contains_nested_lake_post_processing(&parsed) {
                let inlined = inline_small_lake_lookups(
                    &mut parsed,
                    self.lookup_service.as_ref(),
                    query_profile.as_ref(),
                )
                .await?;
                if inlined > 0 {
                    tracing::debug!(inlined, "inlined tenant lookup snapshots in lake subsearches");
                }
            }
            inline_nested_lake_inputlookups(
                &mut parsed, self.lookup_service.as_ref(), query_profile.as_ref(),
            ).await?;
            validate_lake_nested_post_processing(&parsed)?;
            let lookup_commands = extract_lookup_commands(&parsed);
            validate_lookup_tables(&lookup_commands, self.lookup_service.as_ref()).await?;
            if push_down_lake_lookup_membership(&mut parsed, self.lookup_service.as_ref()).await? {
                tracing::debug!(
                    "pushed bounded lookup membership into the primary-lake event predicate"
                );
            }
            let (_, prospective_suffix) = split_lake_post_processing(&parsed);
            if lake_post_processing_needs_candidate_set(&prospective_suffix) {
                let inlined = inline_small_lake_lookups(
                    &mut parsed,
                    self.lookup_service.as_ref(),
                    query_profile.as_ref(),
                )
                .await?;
                if inlined > 0 {
                    tracing::debug!(
                        inlined,
                        "inlined bounded lookup snapshots into the primary-lake query"
                    );
                }
            }
        }

        let histogram_plan =
            lake_histogram_plan(
                &request, request_dataset, &parsed, query_id, scope, self.histogram_only,
            );

        // Non-log lake datasets cannot carry lookup/prevalence/identity today,
        // but keep the structural fence exhaustive if that changes later.
        validate_lake_nested_post_processing(&parsed)?;
        if self.histogram_only {
            // Every row-producing branch below attaches exactly this
            // companion; the histogram-only view runs it alone.
            return histogram_only_response(
                self.lake_histogram_companion(histogram_plan.as_ref()).await,
                super::lake_histogram_counts_result_rows(&parsed),
                display_type,
                start_time,
            );
        }

        // NAN-3294: `<host> | tree web` also matches the host's proxy and
        // network events, which carry only its IP at the time.
        let tree_identity_problems = if request_dataset == crate::query::Dataset::Logs
            && query_profile.uses_strict_canonical_fields()
        {
            self.expand_lake_tree_web_query(
                &mut parsed,
                request.time_range.start,
                request.time_range.end,
                scope,
            )
            .await
        } else {
            Vec::new()
        };
        let plan = plan_lake_post_processing(&parsed);
        request.query = plan.worker_query.clone();
        let risk_config = if request_dataset == crate::query::Dataset::Risk {
            Some(self.risk_query_config.resolve().await)
        } else {
            None
        };
        if plan.post_commands.is_empty()
            && plan.tree_command.is_none()
            && plan.funnel_command.is_none()
        {
            // NAN-3466: `plan.worker_query` has its `head N` pulled out (a
            // head left in the compiled query runs once per progressive time
            // chunk). The pre-inlining head page above could not see it when
            // the head followed a `| lookup` that was only later inlined into
            // an `eval`, so this branch must carry N in the request limit
            // itself — it read the default page instead (`| lookup … | head
            // 1` returned 20 rows).
            let head_window = plan.safe_head_bound.map(|head_count| {
                let window = LakeHeadWindow {
                    head_count,
                    requested_limit: request
                        .limit
                        .unwrap_or(self.config.default_limit)
                        .min(self.config.max_limit),
                    requested_offset: request.offset.unwrap_or(0),
                };
                request.limit = Some(head_count);
                request.offset = Some(0);
                window
            });
            // NAN-3046: a large raw-event page is read from a lean cell in
            // bounded cursor pages, so query[T] never holds (and never
            // refuses) the whole result. With a stream sink installed the
            // pages go straight to the client; otherwise they are gathered
            // here up to LAKE_PAGED_SYNC_MAX_BYTES.
            let paged_eligible = client.is_lake_cell()
                && !query_has_aggregation(&parsed)
                && request_dataset == crate::query::Dataset::Logs
                && risk_config.is_none()
                && request.offset.unwrap_or(0) == 0
                // A streamed head page cannot skip the caller's offset.
                && head_window.is_none_or(|window| window.requested_offset == 0)
                && request.limit.unwrap_or(self.config.default_limit) > LAKE_PAGE_ROWS;
            if paged_eligible {
                if let Some(mut response) = self
                    .search_lake_cell_paged(client, &request, query_id, scope)
                    .await?
                {
                    let histogram = self.lake_histogram_companion(histogram_plan.as_ref()).await;
                    attach_lake_histogram_result(
                        &mut response,
                        histogram,
                        super::lake_histogram_counts_result_rows(&parsed),
                    );
                    response.display_type = Some(display_type);
                    if response.column_order.is_none() {
                        response.column_order = get_column_order(&parsed);
                    }
                    if let Some(window) = head_window.as_ref() {
                        window.apply(&mut response);
                    }
                    return Ok(response);
                }
            }
            let rows = client.search(&request, query_id, risk_config.as_ref(), scope.deny_set());
            let histogram = self.lake_histogram_companion(histogram_plan.as_ref());
            // Join both bounded calls before promotion so no detached companion
            // keeps scanning after the foreground query enters the durable lane.
            let (rows, histogram) = tokio::join!(rows, histogram);
            let mut response = match rows {
                // NAN-2361: a scan-budget rejection of a `stats` whose
                // aggregations merge exactly over disjoint time slices
                // (count / earliest / latest / first / last; NAN-4313: sum,
                // avg, numeric min / max) is recovered by bisection instead
                // of failing closed. Only the rejection takes this path, so
                // every query that fits is unchanged. Any other rejection
                // (percentiles, median, dc, values) is returned as the
                // `ResourceExhausted` the search handler escalates to a
                // durable job.
                Err(error)
                    if request_dataset == crate::query::Dataset::Logs
                        && is_lake_scan_budget_rejection(&error) =>
                {
                    let Some(plan) = super::lake_stats_merge::lake_mergeable_stats_plan(
                        &parsed,
                        &|field: &str| self.active_profile.is_numeric_field(field),
                    )
                    else {
                        return Err(error);
                    };
                    let mut response = self
                        .search_primary_lake_sliced_stats(
                            &request,
                            query_id,
                            scope,
                            &plan,
                            error,
                            max_post_processing_groups,
                            start_time,
                            &parsed,
                        )
                        .await?;
                    // The companion already ran beside the rejected scan.
                    attach_lake_histogram_result(
                        &mut response,
                        histogram,
                        super::lake_histogram_counts_result_rows(&parsed),
                    );
                    return Ok(response);
                }
                rows => rows?,
            };
            attach_lake_histogram_result(
                &mut response,
                histogram,
                super::lake_histogram_counts_result_rows(&parsed),
            );
            // The worker envelope carries no presentation metadata; every
            // other lake exit sets it (audit #10: `top`/`rare` and
            // `eval|stats` answered `display_type: null`).
            response.display_type = Some(display_type);
            if response.column_order.is_none() {
                response.column_order = get_column_order(&parsed);
            }
            if let Some(window) = head_window.as_ref() {
                window.apply(&mut response);
            }
            return Ok(response);
        }
        self.require_lake_prevalence_configuration(&parsed)?;

        let requested_limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        let requested_offset = request.offset.unwrap_or(0);
        let skip_field_stats = request.skip_field_stats;
        let fallback_reference_time = request.time_range.end;
        request.table_view = false;
        request.request_id = Some(query_id.to_string());
        request.skip_field_stats = true;
        if let Some(limit) = plan.candidate_limit() {
            request.limit = Some(limit);
            request.offset = Some(0);
        }
        request.query = plan.candidate_query(
            &parsed,
            &self.ch_sql_generator,
            query_profile.as_ref(),
            request_dataset == crate::query::Dataset::Logs
                && query_profile.uses_strict_canonical_fields(),
        );

        let response = if lake_post_processing_replaces_source(&plan.post_commands) {
            // Data-source inputlookup replaces its input stream. Avoid scanning
            // the lake for rows that the very next stage is required to ignore.
            SearchResponse {
                server_wall_ms: None,
                results: Vec::new(),
                total_count: 0,
                // Placeholder template: the lookup stage replaces every field below.
                total_count_exact: true,
                execution_time_ms: 0,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: None,
                cost_score: None,
                display_type: None,
                column_order: None,
                completeness: None,
            }
        } else {
            search_lake_rows_with_budget_slices(
                client,
                &request,
                query_id,
                risk_config.as_ref(),
                scope.deny_set(),
            )
            .await?
        };
        let mut response = self
            .finish_lake_post_processing(
                plan,
                response,
                LakePostProcessingContext {
                    parsed: &parsed,
                    display_type,
                    requested_limit,
                    requested_offset,
                    skip_field_stats,
                    fallback_reference_time,
                    scope,
                    max_post_processing_groups,
                    start_time,
                },
            )
            .await?;
        attach_lake_tree_identity_problems(&mut response, tree_identity_problems);
        if let Some((query, time_range, histogram_query_id, deny_source_types)) =
            histogram_plan.as_ref()
        {
            match self
                .generate_histogram(
                    query,
                    time_range,
                    Some(histogram_query_id),
                    crate::query::Dataset::Logs,
                    deny_source_types,
                )
                .await
            {
                Ok(histogram) => response.histogram = Some(histogram),
                Err(error) => {
                    tracing::warn!("Sequential lake histogram query failed: {}", error);
                }
            }
        }
        Ok(response)
    }

    /// Execute a piped query and return structured results
    ///
    /// `scope` (NAN-1799): the caller's source-scope deny-set (audit gate
    /// already unioned in by the handler). Enforced structurally on the query
    /// text BEFORE SQL generation and before any companion (histogram /
    /// count / field-stats / view builder) sees the query, so every derived
    /// scan carries the same exclusion. An empty deny-set leaves the query
    /// byte-identical (zero-restricted-sources back-compat).
    #[instrument(skip(self, scope, request), fields(query = %crate::inputlookup::storage_policy::redact_url_credentials(&request.query)))]
    pub async fn search(
        &self,
        request: SearchRequest,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        let id = request
            .request_id
            .as_deref()
            .map(crate::inputlookup::shared::audit_search_id)
            .unwrap_or_else(uuid::Uuid::now_v7);
        crate::inputlookup::shared::with_fetch_search_id(
            id,
            self.search_with_fetch_audit(request, scope),
        )
        .await
    }

    async fn search_with_fetch_audit(
        &self,
        request: SearchRequest,
        scope: &ScopeSet,
    ) -> Result<SearchResponse, SearchError> {
        let start_time = Instant::now();

        let retention_cutoff = self.retention_cutoff_at(chrono::Utc::now())?;

        // Read query safety limits (hot-reloadable from DB settings)
        let query_limits = self.query_limits.read().await.clone();

        // Generate query_id for cancellation support
        // Use request_id if provided (from frontend), otherwise generate a new UUID
        let query_id = request
            .request_id
            .clone()
            .unwrap_or_else(|| {
                // NAN-4193: `detect-`-prefixed inside a detection scope.
                super::background_request::generated_query_id(
                    crate::inputlookup::shared::fetch_search_id()
                        .unwrap_or_else(uuid::Uuid::now_v7),
                )
            });

        // Register with tracker for cancellation support (if request_id was provided)
        // Note: We don't unregister on error - stale entries are harmless since cancel_query
        // checks ClickHouse directly if the query is still running
        if request.request_id.is_some() {
            self.query_tracker
                .register(request.request_id.clone().unwrap(), query_id.clone());
        }

        // Validate time range
        request.time_range.validate()?;

        // Extract time modifiers (earliest=-24h, latest=now, etc.) and clean the query
        let (cleaned_query, earliest_offset, latest_offset) =
            extract_time_bounds(&request.query)?;

        // NAN-1799: inject the caller's source-scope exclusion into the query
        // TEXT before anything downstream touches it — the parse below, SQL
        // generation, the histogram companion, the prevalence-join path and
        // the cloud view builder all derive from `cleaned_query`, so a single
        // injection here gates every scan this search fans out to. Empty
        // deny-set returns the text unchanged (byte-identical).
        let request_dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
        let is_log_request = request_dataset == crate::query::Dataset::Logs;
        let is_risk_request = request_dataset == crate::query::Dataset::Risk;
        let is_otel_request = matches!(
            request_dataset,
            crate::query::Dataset::Spans | crate::query::Dataset::Metrics
        );
        let is_primary_lake_request =
            self.lake_query.mode == LakeQueryMode::Primary && (is_log_request || is_risk_request);
        let is_primary_otel_request =
            self.lake_query.mode == LakeQueryMode::Primary && is_otel_request;
        let cleaned_query = if self.lake_query.mode == LakeQueryMode::Primary && is_log_request {
            enforce_source_scope_with_field(
                &cleaned_query,
                scope.deny_set(),
                "metadata.log_source",
            )?
        } else if is_primary_lake_request {
            // The risk grain has no log-source column. Its worker builds the
            // grain from the immutable findings ledger and applies this same
            // deny-set before aggregation.
            cleaned_query
        } else {
            enforce_source_scope(&cleaned_query, scope.deny_set())?
        };

        // Adjust time range based on modifiers (NAN-4288: SPL semantics)
        let mut adjusted_time_range = match apply_time_bounds(
            &request.time_range,
            earliest_offset,
            latest_offset,
        ) {
            Ok(range) => range,
            Err(error) => {
                if let Some(ref request_id) = request.request_id {
                    self.query_tracker.unregister(request_id);
                }
                return Err(error);
            }
        };
        let mut expired_window_cutoff = None;
        if let Some(cutoff) = retention_cutoff {
            if adjusted_time_range.end <= cutoff {
                expired_window_cutoff = Some(cutoff);
            } else if adjusted_time_range.start < cutoff {
                adjusted_time_range.start = cutoff;
            }
        }

        // Cost analysis is part of the public query contract, not a property of
        // the legacy ClickHouse executor. Parse and analyze before choosing a
        // backend so lake searches surface the same semantic-cap advisories
        // (`values/list`, `mvexpand`, join/append) and honor the same blocking
        // policy. Previously the primary-lake return below bypassed this entire
        // section and could make a capped result look complete.
        let mut query = match parse_query(&cleaned_query) {
            Ok(query) => query,
            Err(error) => return Err(convert_parse_error(error)),
        };
        // An expired window reads no backend. NAN-4291 (F6): an ungrouped
        // `stats` still answers it with its one row (count 0, the other
        // aggregates null), so that pipeline runs over a search that matches
        // nothing in a 1 ms in-retention window; anything else is empty.
        let mut cleaned_query = cleaned_query;
        if let Some(cutoff) = expired_window_cutoff {
            match expired_window_aggregate_query(&query) {
                Some(empty_query) => {
                    query = empty_query;
                    // Every later reader of the text (timeline, cloud view)
                    // sees the same matches-nothing search.
                    cleaned_query = query.pretty_print();
                    adjusted_time_range.start = cutoff;
                    adjusted_time_range.end = cutoff + chrono::Duration::milliseconds(1);
                }
                None => {
                    if let Some(ref request_id) = request.request_id {
                        self.query_tracker.unregister(request_id);
                    }
                    return Ok(SearchResponse::empty());
                }
            }
        }
        // NAN-3466: lookup key orientation needs the table's columns.
        orient_lookup_keys(&mut query, self.lookup_service.as_ref()).await;
        // NAN-3385: resolve `timechart bins=N` against the effective window.
        crate::query::resolve_timechart_bins(
            &mut query,
            &crate::query::TimeRange { start: adjusted_time_range.start, end: adjusted_time_range.end },
        );
        let cost_analysis = analyze_query_cost(&query);
        if query_limits.block_on_cost_errors && cost_analysis.has_errors() {
            let error_messages = cost_analysis
                .warnings
                .iter()
                .filter(|warning| warning.severity == WarningSeverity::Error)
                .map(|warning| {
                    let mut message = format!("[{}] {}", warning.code, warning.message);
                    if let Some(suggestion) = &warning.suggestion {
                        message.push_str(&format!(" — {suggestion}"));
                    }
                    message
                })
                .collect::<Vec<_>>();
            return Err(SearchError::SqlValidationError(format!(
                "Query blocked by cost analysis: {}",
                error_messages.join("; ")
            )));
        }

        // NAN-4289 (F25): a tail that addresses the pivoted series columns runs
        // after the pivot, in memory, exactly like a terminal timechart plus
        // the in-memory evaluator.
        if let (false, Some((source, Command::Timechart { span, aggregations, split_by, limit, useother, .. }, tail))) =
            (self.histogram_only, super::timechart::split_pivot_tail(&query))
        {
            let mut chart_request = request.clone();
            chart_request.time_range = adjusted_time_range.clone();
            let mut response = Box::pin(self.complete_timechart(
                chart_request, scope, source, *span, aggregations, split_by, *limit, *useother,
            ))
            .await?;
            let processed = apply_post_prevalence_commands_with_limit(
                std::mem::take(&mut response.results),
                &tail,
                query_limits.max_post_processing_groups as usize,
            )?;
            response.results = processed.results;
            response.total_count = response.results.len() as u64;
            response.column_order = response.results.first().and_then(|r| r.as_object()).map(|r| {
                r.keys().filter(|k| k.as_str() != "_timechart").cloned().collect()
            });
            let mut warnings = response.warnings.take().unwrap_or_default();
            warnings.extend(processed.warnings.into_iter().map(|message| QueryWarningOutput {
                severity: "warning".to_string(),
                code: "TIMECHART_POST_PROCESSING".to_string(),
                message,
                suggestion: None,
                impact: None,
            }));
            response.warnings = (!warnings.is_empty()).then_some(warnings);
            return Ok(response);
        }

        if let (false, Query::Piped {
            source,
            command: Command::Timechart { span, aggregations, split_by, limit, useother, .. },
        }) = (self.histogram_only, &query)
        {
            let mut chart_request = request.clone();
            chart_request.time_range = adjusted_time_range.clone();
            // Boxed: the timechart re-enters `search` for its inner fetches.
            return Box::pin(self.complete_timechart(
                chart_request, scope, source, *span, aggregations, split_by, *limit, *useother,
            ))
            .await;
        }

        // Primary-lake requests return to the worker before the legacy SQL
        // generation section below. Resolve product-owned IOC sources here so
        // the worker receives the same literal, indexable observable set as the
        // legacy executor. Retro is intentionally excluded: its marker retains
        // source identity and the companion durable task resolves the snapshot.
        let is_retro_query = matches!(
            get_semantic_terminal_command(&query),
            Some(Command::Retro { .. })
        );
        let mut primary_lake_ioc_warnings = Vec::new();
        if is_primary_lake_request && is_log_request && !is_retro_query {
            if ioc_lookup_resolve::query_has_ioc_lookup(&query) {
                ioc_lookup_resolve::resolve_ioc_lookup_sources(
                    &mut query,
                    self.lookup_service.as_ref(),
                    &mut primary_lake_ioc_warnings,
                )
                .await?;
            }
            if ioc_lookup_resolve::query_has_ioc_feed(&query) {
                let tenant_ioc = self.shared_retro_feed_client("IOC feed search")?;
                ioc_lookup_resolve::resolve_ioc_feed_sources(
                    &mut query,
                    tenant_ioc,
                    &mut primary_lake_ioc_warnings,
                )
                .await?;
            }
        }

        if is_primary_otel_request {
            let profile = self.dataset_profile(request.dataset.as_deref());
            validate_query_field_names(&query, profile.as_ref())?;
            let (query, auto_sort_decision) = apply_auto_sort(query);
            if let Some(risk) = detect_oom_risk(&query) {
                return Err(SearchError::SqlValidationError(risk.message()));
            }
            let display_type = determine_display_type(&query);
            if is_command_page_marker(display_type) {
                let marker = command_page_marker(&query)?;
                if let Some(ref request_id) = request.request_id {
                    self.query_tracker.unregister(request_id);
                }
                return Ok(SearchResponse {
                    server_wall_ms: None,
                    results: vec![marker],
                    total_count: 1,
                    total_count_exact: true,
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    fields: Vec::new(),
                    generated_sql: None,
                    histogram: None,
                    warnings: None,
                    cost_score: None,
                    display_type: Some(display_type),
                    column_order: None,
                    completeness: None,
                });
            }
            let dataset = match request_dataset {
                crate::query::Dataset::Spans => "spans",
                crate::query::Dataset::Metrics => "metrics",
                _ => unreachable!("native OTLP branch is spans/metrics only"),
            };
            // NAN-2361 wave 8: the OTLP half of the one `metadata.log_source`
            // row filter. The native spans / metrics tables carry no per-row
            // source column and every row of a dataset arrived through
            // exactly one route slug (`otlp_trace` / `otlp_metric`), so a
            // caller denied that slug sees the dataset as empty — the same
            // answer a row filter would give, never an error that reveals
            // the dataset has data.
            if crate::search::query_processing::otlp_dataset_denied(dataset, scope.deny_set()) {
                if let Some(ref request_id) = request.request_id {
                    self.query_tracker.unregister(request_id);
                }
                return Ok(SearchResponse {
                    server_wall_ms: None,
                    results: Vec::new(),
                    total_count: 0,
                    total_count_exact: true,
                    execution_time_ms: start_time.elapsed().as_millis() as u64,
                    fields: Vec::new(),
                    generated_sql: None,
                    histogram: None,
                    warnings: None,
                    cost_score: None,
                    display_type: Some(display_type),
                    column_order: None,
                    completeness: None,
                });
            }
            let limit = request
                .limit
                .unwrap_or(self.config.default_limit)
                .clamp(1, self.config.max_limit);
            let offset = request.offset.unwrap_or_default();
            let evaluator = self.otel_lake.as_ref().ok_or_else(|| {
                SearchError::ServiceUnavailable(
                    "native OTLP lake query service is not configured".to_string(),
                )
            })?;
            let native = evaluator
                .npl_query(
                    dataset,
                    &query.pretty_print(),
                    &TimeRange::new(adjusted_time_range.start, adjusted_time_range.end),
                    offset,
                    limit,
                )
                .await
                .map_err(|error| match error {
                    crate::search::otel_lake::OtelNplQueryError::Invalid(message) => {
                        SearchError::SqlValidationError(message)
                    }
                    crate::search::otel_lake::OtelNplQueryError::ResourceExhausted(message) => {
                        SearchError::ResourceExhausted(message)
                    }
                    crate::search::otel_lake::OtelNplQueryError::Unavailable(message) => {
                        SearchError::ServiceUnavailable(message)
                    }
                })?;
            if native.has_more && self.active_execution_limits.is_some() {
                return Err(SearchError::ResourceExhausted(
                    "native OTLP detection result-row".to_string(),
                ));
            }
            tracing::debug!(
                dataset,
                storage_rows_read = native.storage_rows_read,
                storage_bytes_read = native.storage_bytes_read,
                "native OTLP nPL query completed"
            );
            let total_count = (offset + native.results.len() + usize::from(native.has_more)) as u64;
            let mut warnings = cost_analysis
                .warnings
                .iter()
                .map(|warning| QueryWarningOutput {
                    severity: match warning.severity {
                        WarningSeverity::Info => "info".to_string(),
                        WarningSeverity::Warning => "warning".to_string(),
                        WarningSeverity::Error => "error".to_string(),
                    },
                    code: warning.code.clone(),
                    message: warning.message.clone(),
                    suggestion: warning.suggestion.clone(),
                    impact: warning.impact.clone(),
                })
                .collect::<Vec<_>>();
            if let Some(warning) =
                crate::search::query_processing::auto_sort_warning(&auto_sort_decision)
            {
                warnings.push(warning);
            }
            if native.has_more {
                warnings.push(QueryWarningOutput {
                    severity: "info".to_string(),
                    code: "OTEL_RESULT_PAGE_BOUND".to_string(),
                    message: "More native telemetry rows match this query.".to_string(),
                    suggestion: Some("Page forward or narrow the time range.".to_string()),
                    impact: Some("The displayed hit count is a lower bound.".to_string()),
                });
            }
            if let Some(ref request_id) = request.request_id {
                self.query_tracker.unregister(request_id);
            }
            return Ok(SearchResponse {
                server_wall_ms: None,
                results: native.results,
                total_count,
                // NAN-2550: the same page-bound shape as the lake. `has_more`
                // means `total_count` is a lower bound, not a total.
                total_count_exact: !native.has_more,
                execution_time_ms: native.execution_time_ms,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: (!warnings.is_empty()).then_some(warnings),
                cost_score: Some(cost_analysis.estimated_cost),
                display_type: Some(display_type),
                column_order: get_column_order(&query),
                completeness: None,
            });
        }

        if is_primary_lake_request {
            let mut lake_request = request.clone();
            lake_request.query = query.pretty_print();
            lake_request.time_range = adjusted_time_range;
            lake_request.request_id = Some(query_id.clone());
            let mut result = self
                .search_primary_lake(
                    lake_request,
                    &query_id,
                    scope,
                    query_limits.max_post_processing_groups as usize,
                    start_time,
                )
                .await;
            if let Ok(response) = &mut result {
                let cost_warnings = cost_analysis
                    .warnings
                    .iter()
                    .map(|warning| QueryWarningOutput {
                        severity: match warning.severity {
                            WarningSeverity::Info => "info".to_string(),
                            WarningSeverity::Warning => "warning".to_string(),
                            WarningSeverity::Error => "error".to_string(),
                        },
                        code: warning.code.clone(),
                        message: warning.message.clone(),
                        suggestion: warning.suggestion.clone(),
                        impact: warning.impact.clone(),
                    })
                    .collect::<Vec<_>>();
                if !cost_warnings.is_empty() {
                    response
                        .warnings
                        .get_or_insert_with(Vec::new)
                        .extend(cost_warnings);
                    response.cost_score = Some(cost_analysis.estimated_cost);
                }
                if !primary_lake_ioc_warnings.is_empty() {
                    response
                        .warnings
                        .get_or_insert_with(Vec::new)
                        .extend(primary_lake_ioc_warnings.iter().map(|message| {
                            QueryWarningOutput {
                                severity: "warning".to_string(),
                                code: "IOC_SOURCE_EMPTY".to_string(),
                                message: message.clone(),
                                suggestion: Some(
                                    "Verify the selected IOC feed or lookup contains current indicators."
                                        .to_string(),
                                ),
                                impact: Some(
                                    "This IOC term matches no events until the source contains indicators."
                                        .to_string(),
                                ),
                            }
                        }));
                }
            }
            if let Some(ref request_id) = request.request_id {
                self.query_tracker.unregister(request_id);
            }
            return result;
        }
        // NAN-1581 Phase 6: pre-resolve `ioc in lookup("table")` sources to
        // concrete indicator values BEFORE SQL generation. This is backend-
        // agnostic (works whether lookups are PG- or CH-backed) and keeps the
        // SQL generator unaware of lookup tables — once substituted, the existing
        // OCSF/UDM-aware observable matchset handles column resolution. An unknown
        // lookup errors here (clear 400); an empty lookup yields a never-match
        // term plus a warning surfaced in the response below.
        // A `… | retro` query short-circuits to a marker below and resolves its
        // lookup/feed sources inside `build_retro_view` (which re-parses the raw
        // query). Skip pre-resolution here so the retro marker keeps the lookup
        // source visible and we don't resolve twice.
        let is_retro_query = matches!(
            get_semantic_terminal_command(&query),
            Some(Command::Retro { .. })
        );
        let mut ioc_resolution_warnings: Vec<String> = Vec::new();
        if !is_retro_query && ioc_lookup_resolve::query_has_ioc_lookup(&query) {
            ioc_lookup_resolve::resolve_ioc_lookup_sources(
                &mut query,
                self.lookup_service.as_ref(),
                &mut ioc_resolution_warnings,
            )
            .await?;
        }
        // In primary-lake mode feed-backed IOC terms must resolve through the
        // same immutable enrichment snapshot used by ingest and retro hunts.
        // Leaving the source attached would make SQL generation emit the legacy
        // ClickHouse `custom_enrichment_results` subquery, which is neither
        // available nor part of the OCSF lake contract.
        if !is_retro_query
            && self.backend() == crate::search::config::SearchBackend::Lake
            && ioc_lookup_resolve::query_has_ioc_feed(&query)
        {
            let tenant_ioc = self.shared_retro_feed_client("IOC feed search")?;
            ioc_lookup_resolve::resolve_ioc_feed_sources(
                &mut query,
                tenant_ioc,
                &mut ioc_resolution_warnings,
            )
            .await?;
        }

        // NAN-1354: input-side field-name validation (defense-in-depth behind
        // codegen escaping). Reject malformed / typo'd field references early.
        // NAN-1557: validate against the active DATASET's profile — spans/metrics
        // carry their own field universe (`duration_ns`/`span_name`/`span_kind`/
        // `value`/… are real columns there), so a legitimate span/metric field is
        // not 400'd as a typo against the UDM/logs schema. Logs keep the tenant
        // profile (unchanged).
        // NAN-1559: this per-query profile also scopes the field-stats companion's
        // column enumeration below — the companion wraps the DATASET's base SQL
        // (`otel_spans`/`otel_metrics`), so it must enumerate that dataset's
        // columns, not `self.active_profile`'s UDM/logs set (else ClickHouse 47:
        // `Unknown expression identifier 'action'`).
        let query_profile = self.dataset_profile(request.dataset.as_deref());
        validate_query_field_names(&query, query_profile.as_ref())?;

        // NAN-806: a bare `… | stats count by x` runs aggregation over the full
        // event set but the executor's outer `LIMIT N` would trim the GROUP BY
        // result in ClickHouse hash-bucket order — analysts would see a random
        // slice of groups instead of the largest ones. Inject an implicit
        // `| sort -<first-numeric-agg>` after the trailing stats/chart so the
        // outer LIMIT keeps the actual top-N.
        let (query, auto_sort_decision) = apply_auto_sort(query);

        // Determine the display type once, up front — it gates the histogram
        // companion below (NAN-1429) and is reported in the response.
        let display_type = determine_display_type(&query);

        // Pre-execution guardrail: reject queries that would cause unbounded memory usage (OOM)
        // Covers: eventstats/streamstats, dedup, reverse, transaction, values()/list(), high-cardinality GROUP BY
        if let Some(risk) = detect_oom_risk(&query) {
            return Err(SearchError::SqlValidationError(risk.message()));
        }

        // ── Command-page short-circuit (NAN-1560) ─────────────────────────
        // `| service|trace|metric|services` are PAGE directives, not data
        // transforms. The entity is carried in the AST itself, so we emit a
        // synthetic single-row marker and let the frontend reuse the curated
        // ServiceDetail / TraceWaterfall / MetricsExplorer / ServicesTab
        // components. NO ClickHouse scan, NO count companion, NO histogram, NO
        // field stats — mirrors the asset fast-path early-return below.
        //
        // Placement is load-bearing: this MUST sit after the OOM guard but
        // BEFORE any extraction / limit / count fan-out, or these pages
        // silently scan logs (the count companion is NOT display-type-gated).
        if is_command_page_marker(display_type) {
            let marker = command_page_marker(&query)?;

            let execution_time_ms = start_time.elapsed().as_millis() as u64;
            if let Some(ref req_id) = request.request_id {
                self.query_tracker.unregister(req_id);
            }
            return Ok(SearchResponse {
                server_wall_ms: None,
                results: vec![marker],
                total_count: 1,
                total_count_exact: true,
                execution_time_ms,
                fields: Vec::new(),
                generated_sql: None,
                histogram: None,
                warnings: None,
                cost_score: None,
                display_type: Some(display_type),
                column_order: None,
                completeness: None,
            });
        }

        // Extract lookup commands for post-processing
        let lookup_commands = extract_lookup_commands(&query);

        // NAN-1389: pre-validate lookup table existence so a typo'd or missing
        // `| lookup <table>` surfaces as an actionable 400 naming the table
        // (and listing the available ones) instead of a masked failure.
        if !lookup_commands.is_empty() {
            validate_lookup_tables(&lookup_commands, self.lookup_service.as_ref()).await?;
        }

        // Extract inputlookup commands for URL-based enrichment
        let inputlookup_commands = extract_inputlookup_commands(&query);

        // Extract commands that come after inputlookup (need post-processing)
        let post_inputlookup_commands = extract_post_inputlookup_commands(&query);
        let has_inputlookup = !inputlookup_commands.is_empty();

        // Extract prevalence commands for post-processing
        let prevalence_commands = extract_prevalence_commands(&query);

        // P2 (audit): validate EVERY prevalence command's window up front —
        // before the JOIN-vs-fallback dispatch and the prevalence-service check
        // below. The JOIN path only reads the first command's window and the
        // fallback early-returns when no service is wired, so a later command's
        // `window=1h` (e.g. `… | prevalence enrich=true | prevalence host_count < 5
        // window=1h`) would otherwise slip past one of those paths. Rejecting
        // here makes the `window=1h` contract path-independent (1h isn't
        // meaningful — the prevalence dicts refresh every 5–10min).
        for cmd in &prevalence_commands {
            ast_to_prevalence_time_window(cmd.time_window.as_ref())?;
        }

        // Extract commands that come after prevalence enrichment
        let post_prevalence = extract_post_prevalence_commands(&query);

        // Check if we can use JOIN-based prevalence filtering (ClickHouse only)
        // This is more efficient than post-processing for large datasets.
        //
        // NAN-701: Previously also required `has_prevalence_field_filter` —
        // i.e. the JOIN path only engaged when the user had a `WHERE` on a
        // prevalence field like `host_count`. Pure-enrich queries (sort by
        // host_count + head, no WHERE) silently fell through to the slow
        // post-processing path. With dict-based enrichment now handling both
        // paths, JOIN is strictly cheaper for any `enrich=true` query, so the
        // field-filter gate is dropped.
        let is_clickhouse = self.backend == SearchBackend::ClickHouse;
        let has_prevalence_svc = self.prevalence_service.is_some();
        let has_prevalence_cmds = !prevalence_commands.is_empty();
        let has_enrich = prevalence_commands.iter().any(|cmd| cmd.enrich);
        // NAN-2219: prevalence rows are DERIVED ARTIFACTS, so this reads the
        // scope's per-source RBAC half, not its row-filter half. The log rows
        // this query returns are still filtered by the full row-filter deny set
        // (injected into the query TEXT above), audit gate included — only the
        // `_prevalence` host-counts attached to them come from the artifact
        // half. Reading the row-filter half here made every caller without
        // `audit:view` take the source-attributed residual path over tables
        // migration 170 never backfilled, so `| prevalence` reported every
        // artifact as rare and first-seen-now.
        let prevalence_scope = crate::auth::ArtifactScope::from_scope(scope);

        // Check if there's aggregation (stats, timechart, etc.) before prevalence
        // If so, we can't use JOIN-based prevalence because the result structure is different
        let has_aggregation_before = has_aggregation_before_prevalence(&query);

        // Check if post-prevalence commands are safe for JOIN optimization.
        // Only simple commands (where, sort, head, tail, table, fields, dedup, rename) are safe.
        // Complex commands (stats, eval, rex, lookup, etc.) create new fields that won't exist
        // in the JOIN query, causing "identifier cannot be resolved" errors.
        let safe_post_commands =
            has_only_simple_post_prevalence_commands(&post_prevalence.commands);

        tracing::debug!(
            "Prevalence JOIN check: clickhouse={}, prevalence_svc={}, prevalence_cmds={}, enrich={}, has_aggregation_before={}, safe_post_commands={}",
            is_clickhouse,
            has_prevalence_svc,
            has_prevalence_cmds,
            has_enrich,
            has_aggregation_before,
            safe_post_commands
        );
        tracing::debug!(
            "Post-prevalence commands count: {}",
            post_prevalence.commands.len()
        );
        tracing::debug!("Post-prevalence commands: {:?}", post_prevalence.commands);
        tracing::debug!("Prevalence commands: {:?}", prevalence_commands);

        // NAN-1694: ONE shared routing decision — the execute path and the explain
        // path both call `prevalence_join_applies` so "Inspect SQL" can never render a
        // shape that no longer executes. (Empty prevalence_commands returns false, so
        // this subsumes the old `has_prevalence_cmds` term.)
        let use_prevalence_join =
            crate::search::query_processing::command_extraction::prevalence_join_applies(
            &query,
            &prevalence_commands,
            &post_prevalence.commands,
            is_clickhouse,
            has_prevalence_svc,
        )
            // The dictionary-backed JOIN has no source dimension. Restricted
            // viewers must take the residual path, whose source-attributed
            // repository query filters contributors before aggregation.
            && prevalence_scope.is_unrestricted()
            // NAN-1798 P2: the pushdown builds its base scan from the tenant
            // LOGS generator, sync and without the per-request risk config —
            // on a `dataset=risk` request it would scan raw logs instead of
            // the derived grain, and a `[dataset=risk …]` bracket would render
            // with default decay/cleared values. Any risk-touching query takes
            // the post-processing prevalence path instead (correct results;
            // only the pushdown optimization is skipped). The explain path
            // applies the SAME condition so "Inspect SQL" matches execution.
            && !super::touches_risk_dataset(request.dataset.as_deref(), &request.query);

        // NAN-1798 P2: prevalence is a logs-artifact concept (hash/domain/ip
        // host-counts). The derived risk grain has no artifact columns, so the
        // post-processing fallback would silently pass every entity through
        // the filter and decorate nothing — reject loudly instead.
        if !prevalence_commands.is_empty()
            && crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"))
                == crate::query::Dataset::Risk
        {
            return Err(SearchError::PrevalenceError(
                "prevalence operates on log artifacts (hashes, domains, IPs) and is not                  supported on dataset=risk. Query the findings stream instead, e.g.                  `source_type=findings | prevalence ...`"
                    .to_string(),
            ));
        }

        // Check if this is a tree visualization query BEFORE setting limit
        // Tree queries need ALL events to properly build parent-child relationships
        let tree_command = extract_tree_command(&query);
        let is_tree_query = tree_command.is_some();

        // Check if this is an asset view query
        // Asset queries need events to build identity resolution and activity aggregation
        let asset_command = extract_asset_command(&query);
        let is_asset_query = asset_command.is_some();

        // Check if this is a baseline query (NAN-1868). Like asset, the initial
        // fetch is a throwaway (entity detection); build_baseline_view re-queries.
        let baseline_command = extract_baseline_command(&query);
        let is_baseline_query = baseline_command.is_some();

        // Check if this is a cloud investigation query
        // Cloud queries re-query ClickHouse for facets, resources, and paginated events
        let cloud_command = extract_cloud_command(&query);
        let is_cloud_query = cloud_command.is_some();

        // Check if this is a funnel query — captured early so post-processing
        // can convert the `_droppers_<field>` sample arrays emitted by
        // generate_funnel_sql into top-K dropper attribution.
        let funnel_command = extract_funnel_command(&query);

        // Check if this is a lateral movement query
        let lateral_command = extract_lateral_command(&query);
        let post_lateral_commands = extract_post_lateral_commands(&query);
        let is_lateral_query = lateral_command.is_some();

        // Check if this is an AI pipe query
        // AI queries send results to an LLM for inline classification
        let ai_command = extract_ai_command(&query);
        let post_ai_commands = extract_post_ai_commands(&query);
        let has_ai = ai_command.is_some();

        // Check if query has aggregations (stats, timechart, top, rare, etc.)
        // Aggregations need all data to produce correct results
        let is_aggregation_query = query_has_aggregation(&query);

        // Check if query has prevalence filtering commands - these need all data for proper filtering
        // Enrich-only prevalence (no conditions) just decorates existing results, so normal limits apply
        let has_prevalence_filtering = prevalence_commands
            .iter()
            .any(|cmd| !cmd.conditions.is_empty());

        // Apply limit and offset
        // For queries that transform/aggregate data, use higher limits since they need more events.
        // Only simple event listing queries should use pagination limits.
        // - Tree: needs events for parent-child relationship building (but cap at 10k for performance)
        // - Asset: needs events for identity resolution and activity aggregation (cap at 100k)
        // - Stats/Timechart/Top/Rare: needs all events for accurate counts
        // - Prevalence: needs all events to properly filter by prevalence scores
        let page_limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        let limit = if is_tree_query {
            // Tree visualizations cap at 10k events - more than this makes the tree unusable anyway
            // and causes performance issues with tree building algorithm
            10_000
        } else if is_asset_query || is_cloud_query || is_lateral_query || is_baseline_query {
            // Asset/cloud/lateral initial fetch is only used for identifier detection (first 10 rows).
            // build_*_view re-queries ClickHouse for the actual data.
            10
        } else if is_aggregation_query {
            // This is an input-fetch cap only when aggregation is deferred to
            // Rust post-processing. SQL aggregations replace it with
            // `page_limit` below, after `query_for_sql` is known.
            1_000_000
        } else if has_prevalence_filtering && !use_prevalence_join {
            // NAN-1691: residual in-memory prevalence filter (aggregation-before,
            // first_seen conditions, or non-ClickHouse backend). Filtering happens in
            // Rust AFTER the fetch, so a small limit truncates the candidate set — but
            // 1M full-width rows OOM the 2Gi pod. Fetch a bounded superset and flag the
            // result approximate downstream.
            IN_MEMORY_PREVALENCE_FETCH_CAP
        } else if has_prevalence_filtering {
            // NAN-1691: filter pushed into SQL (use_prevalence_join) — the JOIN wrapper
            // returns only the already-rare set and the executor paginates it. Use the
            // normal page limit, honoring the user's `| head N` / request.limit, instead
            // of materializing 1M rows.
            page_limit
        } else {
            page_limit
        };
        let offset = request.offset.unwrap_or(0);

        // Raw deep-page callers must not be silently rewritten onto the final
        // allowed page. That returned duplicate rows while claiming to honor
        // the requested offset. Lake product views use stable cursors; generic
        // deep traversal belongs in the durable export path.
        let is_raw_event_query = !is_aggregation_query
            && !is_tree_query
            && !is_asset_query
            && !is_baseline_query
            && !is_cloud_query
            && !is_lateral_query
            && !has_prevalence_filtering;
        if is_raw_event_query && offset >= self.config.max_limit {
            return Err(SearchError::ResourceExhausted(format!(
                "raw event offset {offset} exceeds the interactive pagination envelope; use a durable search/export instead"
            )));
        }

        let time_range = TimeRange::new(adjusted_time_range.start, adjusted_time_range.end);

        // Asset and Cloud are exact product queries. Never silently replace a
        // requested window with its newest six hours; their lake readers raise
        // ResourceExhausted and the API promotes that exact request to a typed
        // durable job. Baseline retains its documented semantic window until
        // its own resumable task exists.
        let (time_range, window_clamp_warning) = if is_baseline_query {
            super::window_clamp::clamp_with_warning(
                &time_range,
                chrono::Duration::days(super::baseline::MAX_BASELINE_CURRENT_DAYS),
                "baseline",
                &format!("{}d", super::baseline::MAX_BASELINE_CURRENT_DAYS),
            )
        } else {
            (time_range, None)
        };

        // Fast path: if this is an asset query and the identifier is directly in the search
        // expression (e.g. `src_host="workstation03" | asset`), skip the initial SQL query
        // entirely and call build_asset_view directly with the pre-extracted identifier.
        if let Some(ref asset_info) = asset_command {
            if let Some(pre_id) = extract_asset_identifier_from_query(&query, asset_info) {
                tracing::info!(
                    "Asset fast path: extracted identifier {}={} from query AST, skipping initial search",
                    pre_id.0,
                    pre_id.1
                );
                let results = self
                    .build_asset_view(Vec::new(), asset_info, &time_range, Some(pre_id), scope)
                    .await?;
                let execution_time_ms = start_time.elapsed().as_millis() as u64;
                let column_order = get_column_order(&query);

                if let Some(ref req_id) = request.request_id {
                    self.query_tracker.unregister(req_id);
                }

                // Asset view is a single result containing nested _asset_pagination with the real count
                let total_count = asset_view_total_count(&results).unwrap_or(1);
                return Ok(SearchResponse {
                    server_wall_ms: None,
                    results,
                    total_count,
                    // The asset marker carries the real event total.
                    total_count_exact: true,
                    execution_time_ms,
                    fields: Vec::new(),
                    generated_sql: None,
                    histogram: None,
                    // NAN-2022: surface the window-clamp warning on the asset fast path too.
                    warnings: window_clamp_warning.map(|w| vec![w]),
                    cost_score: None,
                    display_type: Some(display_type),
                    column_order,
                    completeness: None,
                });
            }
        }

        // Use JOIN-based approach for prevalence filtering when possible
        if use_prevalence_join {
            tracing::debug!("Using JOIN-based prevalence filtering for efficiency");
            return self
                .search_with_prevalence_join(
                    &query,
                    &prevalence_commands,
                    &post_prevalence.commands,
                    &lookup_commands,
                    &inputlookup_commands,
                    &post_inputlookup_commands,
                    &time_range,
                    &request,
                    &cleaned_query,
                    &adjusted_time_range,
                    limit,
                    offset,
                    start_time,
                    &auto_sort_decision,
                )
                .await;
        }

        // Strip commands that need post-processing from the query for SQL generation
        // This includes: post-prevalence commands and inputlookup + post-inputlookup commands
        let query_for_sql = {
            let mut q = query.clone();

            // Strip prevalence and post-prevalence commands from SQL generation
            // Prevalence is handled entirely in Rust post-processing (enrichment/filtering),
            // so the SQL generator's no-op `SELECT * FROM source` wrapper is unnecessary
            if has_prevalence_cmds {
                tracing::debug!(
                    "Stripping prevalence command and {} post-prevalence commands for post-processing",
                    post_prevalence.commands.len()
                );
                q = strip_prevalence_and_after(&q);
            }

            // Strip inputlookup and post-inputlookup commands if any
            if has_inputlookup {
                tracing::debug!(
                    "Found {} inputlookup commands and {} post-inputlookup commands",
                    inputlookup_commands.len(),
                    post_inputlookup_commands.len()
                );
                q = strip_inputlookup_and_after(&q);
            }

            // Strip lateral and post-lateral commands if any (movement tracing happens in post-processing)
            if is_lateral_query {
                q = strip_lateral_and_after(&q);
            }

            // Strip ai and post-ai commands if any (LLM enrichment happens in post-processing)
            if has_ai {
                q = strip_ai_and_after(&q);
            }

            q
        };

        // NAN-1848: the rows ClickHouse returns are grouped buckets keyed by the
        // `by` fields, so the executor must not prune those keys when empty — an
        // empty bucket would arrive as a bare `{"count": N}` that reads as a grand
        // total, and a grouping field that exists nowhere yields exactly one such
        // bucket. Decided from `query_for_sql`, NOT the original query: when
        // prevalence/inputlookup/lateral/AI post-processing strips the aggregation
        // out of the SQL, ClickHouse really does return raw events, and those must
        // keep their pruning or a 1M-row fetch arrives with every empty UDM column.
        let grouped_output = query_produces_grouped_rows(&query_for_sql);
        // NAN-2344: a caller limit on a SQL aggregation pages the rows/groups
        // the aggregation PRODUCES; it must never become a LIMIT on the SQL
        // feeding that aggregation. Aggregations stripped for Rust-side
        // processing retain the large input fetch above.
        let sql_has_aggregation = query_has_aggregation(&query_for_sql);
        let sql_aggregation_has_rust_suffix =
            sql_has_aggregation && has_rust_only_suffix_after_aggregation(&query);
        let aggregation_deferred_to_rust = is_aggregation_query && !sql_has_aggregation;
        let sql_limit_plan = sql_limit_plan(
            is_raw_event_query,
            sql_has_aggregation,
            sql_aggregation_has_rust_suffix,
            aggregation_deferred_to_rust,
            limit,
            page_limit,
            offset,
        );

        // The dataset this request targets (NAN-1534). Shared by the SQL-gen
        // block, the histogram spawn, and the field-stats gate below.
        let request_dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));

        // NAN-1798 P2: resolve the cached decay-factor + cleared-boundary config
        // whenever this request can reach the derived risk dataset — either
        // directly (`dataset=risk`) or through a `[dataset=risk …]` subsearch
        // bracket (cheap textual pre-filter; a false positive only attaches an
        // unused, output-neutral config). Resolved OUTSIDE the sync SQL-gen
        // block; served from the provider's 60s cache on the hot path. This is
        // what makes `dataset=risk` scores equal the Risk page / leaderboard:
        // the generator inlines the SAME values the enterprise repository binds.
        let risk_config = if super::touches_risk_dataset(request.dataset.as_deref(), &request.query)
        {
            Some(self.risk_query_config.resolve().await)
        } else {
            None
        };

        // Generate SQL
        let (sql, bounded_count_sql) = {
            use crate::query::QueryOptions;
            let options = QueryOptions {
                use_cache: request.use_cache,
                table_view: request.table_view,
                // Raw event queries are paginated by the executor, which
                // injects LIMIT/OFFSET itself. Baking the page-size limit into
                // the SQL here made that injection a silent no-op (page N
                // re-served page 1's rows) and capped the count companion's
                // total_count at the page size (NAN-1410). SQL aggregation
                // pagination is likewise executor-owned: its outer wrapper
                // applies request.limit only after GROUP BY/window processing.
                // Tree/asset/prevalence and Rust-side transformations retain
                // their explicit input caps.
                limit: sql_limit_plan.generator_limit,
                unordered: false,
            };
            // Apply current query safety limits to the SQL generator.
            let mut ch_gen = self
                .ch_sql_generator
                .clone()
                // NAN-2009 (F20/F21): resolve_identity's ASOF join to
                // identity_observations is a SEPARATE dataset the nPL-text gate
                // (enforce_source_scope) does not cover. Carry the caller's
                // source-scope deny-set so generate_resolve_identity_sql filters
                // the join's build side. Empty deny-set = byte-identical SQL.
                .with_source_scope_deny(scope.deny_set().clone())
                .with_max_group_array_size(query_limits.max_group_array_size as usize)
                .with_max_mvexpand_rows(query_limits.max_mvexpand_rows as usize);
            // NAN-1798 P2: attach the resolved risk config BEFORE any dataset
            // swap so both a `dataset=risk` request and a `[dataset=risk …]`
            // subsearch clone build the derived base source from the real
            // per-request decay/cleared values. Output-neutral for every
            // non-risk generation path.
            if let Some(cfg) = risk_config.clone() {
                ch_gen = ch_gen.with_risk_config(cfg);
            }
            // NAN-1534: retarget to the spans/metrics OTLP table for this request.
            // `Dataset::Logs` is left UNTOUCHED so the generator keeps the
            // tenant-aware logs table resolved by `with_table` (UDM `logs` /
            // OCSF `ocsf_logs` / tenant-prefixed) — applying `with_dataset(Logs)`
            // would clobber that back to the literal `"logs"`.
            let dataset = request_dataset;
            if dataset != crate::query::Dataset::Logs {
                ch_gen = ch_gen.with_dataset(dataset);
            }
            // NAN-1555 resolution routing: a wide-window metric AGGREGATE over only
            // the rollup's keys reads the pre-aggregated `otel_metrics_1m/_1h`
            // (migration 144) instead of scanning raw points. Conservative — any
            // tag/value/keyword predicate, multi-stage pipe, or narrow window keeps
            // the query on raw `otel_metrics` (always correct). See
            // [`metrics_routing`](super::metrics_routing).
            if dataset == crate::query::Dataset::Metrics {
                if let Some(grain) =
                    super::metrics_routing::metrics_rollup_grain(&query_for_sql, &time_range)
                {
                    ch_gen = ch_gen.with_metrics_rollup(grain);
                }
            }
            let sql = ch_gen
                .generate_with_options(&query_for_sql, &time_range, &options)
                .map_err(|e| SearchError::SqlGenError(e.to_string()))?;

            // NAN-1635 (finding 2.3): the count companion's total is clamped
            // at max_limit below, so when the WHERE carries per-row filters the
            // count scan can stop at max_limit+1 matches instead of scanning
            // the full match set (Saturn: 9.5x read_rows / 8.5x read_bytes on
            // a broad keyword). Filter-free counts stay unbounded — ClickHouse
            // serves them from part metadata and the bounded form measured
            // 12.8x MORE expensive there, so the bound is conditional. The
            // count input is REGENERATED with `unordered` rather than
            // string-stripped (NAN-1160): a trailing ORDER BY under the count's
            // inner LIMIT is a semantic top-N that defeats early termination.
            let bounded_count_sql =
                if is_raw_event_query && query_has_per_row_filters(&query_for_sql) {
                    ch_gen
                        .generate_with_options(
                            &query_for_sql,
                            &time_range,
                            &QueryOptions {
                                unordered: true,
                                ..options
                            },
                        )
                        .ok()
                } else {
                    None
                };
            (sql, bounded_count_sql)
        };

        debug!("Generated SQL (backend={:?}): {}", self.backend, sql);

        // One past the consumer clamp (`total_count.min(max_limit)` below), so
        // "exactly max_limit" and "more than max_limit" stay distinguishable.
        let bounded_count = bounded_count_sql.as_deref().map(|count_sql| {
            crate::search::execution::clickhouse_executor::BoundedCountInput {
                sql: count_sql,
                limit: self.config.max_limit.saturating_add(1),
            }
        });

        // Start histogram query in parallel with data execution — it only needs
        // the base search expression and time range, independent of data results.
        //
        // NAN-1429: skip it entirely when the UI never renders the timeline for
        // this display type (timechart/ranked_bar/flow/tree/asset/cloud/lateral)
        // — for those, the companion's full-window scan was computed and then
        // discarded (an exact 2x window read for `| timechart`).
        //
        // NAN-1428: the companion carries the derived `{query_id}-hist` id (and
        // the resolved per-priority settings via the cloned service) so cancel
        // kills it together with the data query.
        //
        // NAN-1645 (finding 3.5): page flips (offset > 0) skip the spawn — the
        // histogram is page-invariant, so re-aggregating the full window on
        // every page was pure repeat work. The frontend freezes the page-1
        // timeline across flips; `histogram: None` in the response leaves it
        // untouched (same shape `skip_histogram` already produces).
        // NAN-1798 P2: the risk dataset has no meaningful time axis at entity
        // grain (fixed trailing 24h/7d windows; one row per entity), so the
        // timeline companion is skipped entirely — mirroring the marker-page
        // special-casing. `histogram: None` leaves the frontend timeline
        // untouched, same shape `skip_histogram` produces.
        let histogram_handle = if !request.skip_histogram
            && request_dataset != crate::query::Dataset::Risk
            && crate::search::execution::clickhouse_executor::is_first_page(offset)
            && !is_tree_query
            && !is_asset_query
            && !is_baseline_query
            && display_type_renders_timeline(display_type)
        {
            let search_service = self.clone();
            let histogram_query = cleaned_query.clone();
            let histogram_time_range = adjusted_time_range.clone();
            let hist_qid = format!("{query_id}-hist");
            // NAN-1557: the timeline reads the same dataset as the results.
            let histogram_dataset =
                crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
            let histogram_deny_source_types = scope.deny_set().clone();
            Some(tokio::spawn(super::super::request_actor::inherit(async move {
                match search_service
                    .generate_histogram(
                        &histogram_query,
                        &histogram_time_range,
                        Some(&hist_qid),
                        histogram_dataset,
                        &histogram_deny_source_types,
                    )
                    .await
                {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("Parallel histogram query failed: {}", e);
                        None
                    }
                }
            })))
        } else {
            None
        };

        // Execute the query based on backend
        // For ClickHouse non-aggregation queries, also run field stats query in parallel
        //
        // NAN-1395: the companion aggregates topK/uniq over the BASE table's
        // column inventory, which is only resolvable while the pipeline output
        // is still wide (`SELECT *`-shaped: filters/sort/head/eval/...).
        // Transformative pipelines (funnel/sequence/table/chart/...) project a
        // new column set containing none of the base columns — the companion
        // was a guaranteed Code 47 + a wasted CH round-trip before falling
        // back. Statically non-wide (or unmodeled → Unknown) output shapes go
        // straight to the client-side fallback, which computes exact stats
        // over the (small) transformed result set the response already carries.
        // NAN-1798 P2: skip the server-side companion for the risk dataset —
        // its base source is a derived subquery with no `system.columns`
        // inventory to enumerate; the client-side fallback computes exact
        // stats over the (entity-cardinality) result set instead.
        let should_run_server_field_stats = self.backend == SearchBackend::ClickHouse
            && !is_aggregation_query
            && !is_tree_query
            && !is_asset_query
            && !is_baseline_query
            && !request.skip_field_stats
            && request_dataset != crate::query::Dataset::Risk
            && self
                .ch_sql_generator
                .pipeline_output_is_wide(&query_for_sql);

        let (mut results, total_count, server_field_stats) = {
            if should_run_server_field_stats {
                let ch_executor = self.ch_executor.as_ref().ok_or_else(|| {
                    SearchError::DatabaseError(sqlx::Error::Configuration(
                        "ClickHouse client not configured".into(),
                    ))
                })?;

                // Get column list dynamically (run in parallel with data query)
                // for the per-query DATASET's table (UDM `logs` / OCSF
                // `ocsf_logs` / `otel_spans` / `otel_metrics`), so OCSF
                // deployments enumerate OCSF columns rather than a hardcoded
                // `logs` (NAN-1241) and spans/metrics searches enumerate their
                // own columns rather than the UDM set (NAN-1559 — the companion
                // wraps the dataset's base SQL, so a UDM column list against an
                // `otel_spans` base 47'd `Unknown expression identifier`). The
                // profile's materialized re-add list scopes the inventory to
                // columns that actually resolve inside the companion's CTE wrap
                // (NAN-1397: excludes bookkeeping like `event_bytes`).
                //
                // NAN-1559: use `logs_table_for(id)` (the physical READ table)
                // rather than `logs_table_key` here — the latter intentionally
                // collapses Spans/Metrics → "logs" because it is the generator's
                // `table_names` REGISTRY key (the dataset FROM is applied
                // separately via `with_dataset`). For `system.columns`
                // enumeration we need the actual local table name. Byte-identical
                // for UDM (`logs`) / OCSF (`ocsf_logs`).
                let logs_table = crate::schema::logs_table_for(query_profile.id());
                let columns = ch_executor
                    .get_table_columns(
                        logs_table,
                        query_profile.materialized_columns(),
                        query_profile.default_view_renames(),
                    )
                    .await
                    .unwrap_or_else(|e| {
                        // NAN-1559: dataset-correct fallback — a UDM list here over an
                        // `otel_spans`/`otel_metrics` base would re-trigger CH 47.
                        warn!("Failed to get table columns, using dataset defaults: {}", e);
                        Self::field_stats_fallback_columns(request.dataset.as_deref())
                    });

                // Run data query and field stats query in parallel.
                // NAN-1428: the companion carries the derived
                // `{query_id}-fstats` id and the resolved per-priority
                // settings so it is cancellable and admission-bounded.
                // NAN-1506: bound the inline companion scan too (same cap as
                // the standalone /field-stats path) — see FIELD_STATS_ROW_CAP.
                let field_stats_sql = ClickHouseExecutor::build_field_stats_sql(
                    &sql,
                    None,
                    &columns,
                    Some(FIELD_STATS_ROW_CAP),
                );
                debug!("Generated field stats SQL: {}", field_stats_sql);
                let fstats_qid = format!("{query_id}-fstats");

                let (data_result, field_stats_result) = tokio::join!(
                    self.execute_clickhouse_sql_with_query_id(
                        &sql,
                        sql_limit_plan.execution_limit,
                        sql_limit_plan.execution_offset,
                        Some(&query_id),
                        None,
                        bounded_count,
                        self.active_execution_limits.as_ref(),
                        grouped_output,
                    ),
                    ch_executor.execute_field_stats_query(
                        &field_stats_sql,
                        &columns,
                        Some(&fstats_qid),
                        self.active_ch_settings.as_ref()
                    )
                );

                let (results, total_count) = data_result?;
                let field_stats = match field_stats_result {
                    Ok(stats) => {
                        debug!("Server field stats returned {} fields", stats.len());
                        Some(stats)
                    }
                    Err(e) => {
                        // Graceful degradation: log warning and fall back to client-side stats
                        warn!(
                            "Field stats query failed, falling back to client-side: {}",
                            e
                        );
                        None
                    }
                };

                (results, total_count, field_stats)
            } else {
                let (results, total_count) = self
                    .execute_clickhouse_sql_with_query_id(
                        &sql,
                        sql_limit_plan.execution_limit,
                        sql_limit_plan.execution_offset,
                        Some(&query_id),
                        None,
                        bounded_count,
                        self.active_execution_limits.as_ref(),
                        grouped_output,
                    )
                    .await?;
                (results, total_count, None)
            }
        };

        tracing::debug!(
            "Initial SQL query returned {} results (total_count={})",
            results.len(),
            total_count
        );
        // NAN-2550: capture page fullness BEFORE any Rust post-processing can
        // shrink the row set. On a page flip the count companion did not run
        // (NAN-1645) and `paged_total_estimate` is exact only when the raw page
        // came back short, which is what proves the end of the result set.
        let raw_page_proved_end = results.len() < sql_limit_plan.execution_limit;
        // Mirrors `clickhouse_executor::paginated::is_first_page` (that module is
        // private to the executor).
        let count_companion_ran = sql_limit_plan.execution_offset == 0;

        // Collect runtime warnings from post-processing (e.g. group cap reached).
        // These get the `POST_PROCESSING_TRUNCATED` warning code at merge time —
        // the auto-sort warning has its own code and is emitted separately at
        // the merge point below to keep the labelling honest.
        let mut runtime_warnings: Vec<String> = Vec::new();

        // NAN-1581 Phase 6: surface any empty-`ioc in lookup(...)` warnings raised
        // during pre-resolution (a 0-row lookup yields a never-match term).
        runtime_warnings.extend(ioc_resolution_warnings.drain(..));

        // Enrichment degradation warnings (e.g. a subset of inputlookup fetches
        // failed) get their own `ENRICHMENT_DEGRADED` code — they are not
        // truncation events (NAN-1389).
        let mut enrichment_warnings: Vec<String> = Vec::new();

        // Strip internal lookup fields used for SQL JOINs (these are implementation details)
        strip_internal_lookup_fields(&mut results);

        // Apply lookup enrichment if there are lookup commands
        if !lookup_commands.is_empty() {
            results =
                apply_lookup_enrichment(results, &lookup_commands, self.lookup_service.as_ref())
                    .await?;
        }

        // Apply inputlookup enrichment if there are inputlookup commands
        if !inputlookup_commands.is_empty() {
            tracing::debug!(
                "Applying {} inputlookup commands (service configured: {})",
                inputlookup_commands.len(),
                self.inputlookup_service.is_some()
            );
            results = apply_inputlookup_enrichment(
                results,
                &inputlookup_commands,
                self.inputlookup_service.as_ref(),
                &mut enrichment_warnings,
            )
            .await?;
            tracing::debug!("After inputlookup enrichment: {} results", results.len());
        }

        // Apply post-inputlookup commands (like table, where on inputlookup_* fields)
        if !post_inputlookup_commands.is_empty() {
            tracing::debug!(
                "Applying {} post-inputlookup commands to {} results",
                post_inputlookup_commands.len(),
                results.len()
            );
            let pp = apply_post_prevalence_commands_with_limit(
                results,
                &post_inputlookup_commands,
                query_limits.max_post_processing_groups as usize,
            )?;
            results = pp.results;
            runtime_warnings.extend(pp.warnings);
            tracing::debug!("After post-inputlookup commands: {} results", results.len());
        }

        // NAN-1691: warn when the residual in-memory prevalence filter truncated its input.
        if has_prevalence_filtering
            && !use_prevalence_join
            && results.len() >= IN_MEMORY_PREVALENCE_FETCH_CAP
        {
            runtime_warnings.push(format!(
                "Prevalence filter applied to the first {} events only; results are approximate. \
                 Narrow the search or time range for exact rarity filtering.",
                IN_MEMORY_PREVALENCE_FETCH_CAP
            ));
        }

        // Apply prevalence filtering and enrichment if there are prevalence commands
        let mut output_column_warnings: Vec<String> = Vec::new();
        if !prevalence_commands.is_empty() {
            tracing::debug!("Applying {} prevalence commands", prevalence_commands.len());
            results = self
                .apply_prevalence_processing(results, &prevalence_commands, &prevalence_scope)
                .await?;
            tracing::debug!("After prevalence processing: {} results", results.len());
            // NAN-2373: same materialization guard the primary-lake lane runs.
            // The JOIN pushdown projects these columns in SQL, but this residual
            // in-memory lane decorates in Rust and can silently emit none of
            // them; a downstream threshold would then drop every row without a
            // word.
            if prevalence_commands.iter().any(|cmd| cmd.enrich) {
                let declared = ["host_count", "is_rare", "prevalence_score"]
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect::<Vec<_>>();
                let missing = output_column_guard::missing_declared_columns(&results, &declared);
                if !missing.is_empty() {
                    output_column_warnings.push(
                        output_column_guard::missing_output_column_warning("prevalence", &missing),
                    );
                }
            }
        }

        // Apply post-prevalence commands (like where clauses on enriched fields)
        if !post_prevalence.commands.is_empty() {
            tracing::debug!(
                "Applying {} post-prevalence commands to {} results",
                post_prevalence.commands.len(),
                results.len()
            );
            let pp = apply_post_prevalence_commands_with_limit(
                results,
                &post_prevalence.commands,
                query_limits.max_post_processing_groups as usize,
            )?;
            results = pp.results;
            runtime_warnings.extend(pp.warnings);
            tracing::debug!("After post-prevalence commands: {} results", results.len());
        }

        // NAN-366: Strip the nested `_prevalence` object from enriched results (legacy path).
        // Top-level flat fields (host_count, first_seen, ...) already expose the same data.
        if !prevalence_commands.is_empty() {
            for row in &mut results {
                if let Some(obj) = row.as_object_mut() {
                    obj.remove("_prevalence");
                }
            }
        }

        // Build tree visualization if this is a tree query (tree_command extracted earlier)
        if let Some(ref tree_info) = tree_command {
            tracing::debug!(
                "Building tree structure with config: parent={}, child={}, label={}",
                tree_info.parent_field,
                tree_info.child_field,
                tree_info.label_field
            );
            results = self.build_tree_visualization(results, tree_info).await?;
            tracing::debug!("After tree building: {} top-level results", results.len());
        }

        // Build funnel view if this is a funnel query. Converts the raw
        // `_droppers_<field>` arrays emitted by the SQL layer into a compact
        // `dropper_top_attrs` JSON structure per stage row.
        if let Some(ref funnel_info) = funnel_command {
            tracing::debug!(
                "Building funnel view: group_by={:?}, step_count={}",
                funnel_info.group_by,
                funnel_info.step_count
            );
            results = self.build_funnel_view(results, funnel_info);
            tracing::debug!("After funnel view building: {} stage rows", results.len());
        }

        // Build asset view if this is an asset query (asset_command extracted earlier)
        if let Some(ref asset_info) = asset_command {
            tracing::debug!(
                "Building asset view with config: identifier_field={:?}, sections={:?}",
                asset_info.identifier_field,
                asset_info.sections
            );
            results = self
                .build_asset_view(results, asset_info, &time_range, None, scope)
                .await?;
            tracing::debug!("After asset view building: {} results", results.len());
        }

        // Build baseline view if this is a baseline query (NAN-1868). The entity
        // is explicit (`host=…`) or inferred from the leading filter
        // (`src_host="X" | baseline`); the initial `results` fetch is discarded.
        if let Some(ref baseline_info) = baseline_command {
            let entity =
                crate::search::query_processing::resolve_baseline_entity(&query, baseline_info)
                    .ok_or_else(|| {
                        SearchError::SqlValidationError(
                    "| baseline could not determine the entity — add host=/user=/ip=\"…\" or a \
                     src_host / src_ip / user filter to the search."
                        .to_string(),
                )
                    })?;
            results = self
                .build_baseline_view(baseline_info, entity, &time_range, scope)
                .await?;
            tracing::debug!("After baseline view building: {} results", results.len());
        }

        // Build cloud investigation view if this is a cloud query
        if let Some(ref cloud_info) = cloud_command {
            tracing::debug!(
                "Building cloud view with config: group_by={:?}, show_mfa={}",
                cloud_info.group_by,
                cloud_info.show_mfa
            );
            results = self
                .build_cloud_view(results, cloud_info, &time_range, &cleaned_query, scope)
                .await?;
            tracing::debug!("After cloud view building: {} results", results.len());
        }

        // Build lateral movement view if this is a lateral query
        if let Some(ref lateral_info) = lateral_command {
            tracing::debug!(
                "Building lateral movement view: seed_type={:?}, max_hops={}",
                lateral_info.seed_type,
                lateral_info.max_hops
            );
            results = self
                .build_lateral_view(results, lateral_info, &time_range, scope)
                .await?;
            tracing::debug!("After lateral view building: {} results", results.len());

            // Apply post-lateral commands (e.g., | where method_detail="rdp" | stats count by dest_host)
            // Preserve the metadata row (first row with _display_type) — only filter edge rows.
            if !post_lateral_commands.is_empty() {
                tracing::debug!(
                    "Applying {} post-lateral commands",
                    post_lateral_commands.len()
                );
                let metadata_row = results
                    .iter()
                    .position(|r| r.get("_display_type").is_some())
                    .map(|i| results.remove(i));
                let pp = apply_post_prevalence_commands_with_limit(
                    results,
                    &post_lateral_commands,
                    query_limits.max_post_processing_groups as usize,
                )?;
                results = pp.results;
                runtime_warnings.extend(pp.warnings);
                if let Some(meta) = metadata_row {
                    results.insert(0, meta);
                }
            }
        }

        // AI pipe enrichment: send results to LLM for inline classification.
        // The `ai_client` is always present — open-core builds wire
        // `NoopAiClient`, which tags overflow / disabled rows with
        // `ai_verdict = "SKIPPED"` so the table shape is preserved.
        if let Some(ref ai_info) = ai_command {
            tracing::debug!(
                "Running AI pipe enrichment: prompt={}, max_rows={}",
                ai_info.prompt,
                ai_info.max_rows
            );
            // NAN-3190: bounded below the edge timeout; failures become
            // per-row ERROR verdicts instead of a hang.
            results = super::ai_pipe_deadline::enrich_rows_with_deadline(
                self.ai_client.as_ref(),
                results,
                &ai_info.prompt,
                ai_info.max_rows,
                super::ai_pipe_deadline::AI_PIPE_DEADLINE,
            )
            .await;
            // Apply post-ai commands (e.g., | where ai_verdict="TP")
            if !post_ai_commands.is_empty() {
                tracing::debug!("Applying {} post-ai commands", post_ai_commands.len());
                let pp = apply_post_prevalence_commands_with_limit(
                    results,
                    &post_ai_commands,
                    query_limits.max_post_processing_groups as usize,
                )?;
                results = pp.results;
                runtime_warnings.extend(pp.warnings);
            }
        }

        // NAN-2344: when an aggregation was stripped from SQL (prevalence,
        // inputlookup, lateral, or AI post-processing), the SQL fetch started
        // at offset 0 and supplied the capped input set to Rust. Page only now,
        // after every Rust command (including explicit sort/head) has run, and
        // report the number of completed groups before request pagination.
        let total_count = if sql_limit_plan.page_after_post_processing {
            let (paged_results, grouped_total_count) =
                paginate_post_processed_results(results, offset, page_limit, is_lateral_query);
            results = paged_results;
            grouped_total_count
        } else {
            total_count
        };

        // Calculate field statistics (after enrichment so lookup fields are included)
        // Skip for tree/asset/cloud queries (visualization is the data) or if explicitly requested
        // Prefer server-side stats (computed across ALL matching events) over client-side stats (from sampled results)
        let fields = if request.skip_field_stats
            || is_tree_query
            || is_asset_query
            || is_baseline_query
            || is_cloud_query
            || is_lateral_query
        {
            Vec::new()
        } else if let Some(stats) = server_field_stats {
            // Use server-side field stats (topK across all matching events)
            debug!("Using server-side field stats ({} fields)", stats.len());
            stats
        } else {
            // Fall back to client-side stats from sampled results
            debug!(
                "Using client-side field stats from {} results",
                results.len()
            );
            let mut stats = FieldStatistics::new();
            for row in &results {
                stats.process_row(row);
            }
            stats.get_field_info(self.config.top_values_count)
        };

        // Collect histogram from the parallel task spawned before data execution.
        // The histogram runs the base filter independently — no dependency on data results.
        let histogram = if let Some(handle) = histogram_handle {
            handle.await.ok().flatten()
        } else {
            None
        };

        // Merge cost analysis warnings with runtime post-processing warnings
        let mut all_warnings: Vec<QueryWarningOutput> = cost_analysis
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

        // NAN-806: surface the implicit auto-sort decision with its own code
        // so the UI can label it correctly (it isn't a truncation event).
        if let Some(w) = crate::search::query_processing::auto_sort_warning(&auto_sort_decision) {
            all_warnings.push(w);
        }

        // NAN-2373: a decoration stage whose declared output columns never
        // materialized. Its own code so the UI does not read it as truncation.
        for msg in &output_column_warnings {
            all_warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "MISSING_OUTPUT_COLUMN".to_string(),
                message: msg.clone(),
                suggestion: Some(
                    "Check that the events carry the fields this stage reads, or remove the downstream reference to its output columns."
                        .to_string(),
                ),
                impact: Some(
                    "Filters on the missing column match nothing, so this query can silently return zero rows."
                        .to_string(),
                ),
            });
        }

        // Add runtime warnings (e.g. stats group cap reached)
        for msg in &runtime_warnings {
            all_warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "POST_PROCESSING_TRUNCATED".to_string(),
                message: msg.clone(),
                suggestion: Some(
                    "Add filters or reduce the time range to lower cardinality".to_string(),
                ),
                impact: Some("Some results may be missing from the output".to_string()),
            });
        }

        // Add enrichment degradation warnings (e.g. partial inputlookup fetch
        // failures) with their own code so the UI doesn't label them as
        // truncation (NAN-1389)
        for msg in &enrichment_warnings {
            all_warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "ENRICHMENT_DEGRADED".to_string(),
                message: msg.clone(),
                suggestion: Some(
                    "Verify the inputlookup URL is reachable and returns the expected format"
                        .to_string(),
                ),
                impact: Some("Some rows are missing enrichment fields".to_string()),
            });
        }

        // NAN-1388 (G14): under the legacy ClickHouse OCSF profile, `ext.foo`
        // predicates are strip-and-remapped
        // to the OCSF spill location `unmapped.foo` (OcsfProfile::resolve) so
        // UDM-era saved searches keep working. UDM `ext` and OCSF `unmapped` key
        // layouts are not guaranteed to coincide though — when a remapped
        // predicate produced an empty result set, say so honestly instead of
        // leaving a silent zero. Info severity: the remap itself is correct
        // behavior, the note just explains the empty result.
        if results.is_empty()
            && self.active_profile.id() == crate::schema::SchemaId::Ocsf
            && !self.active_profile.uses_strict_canonical_fields()
        {
            let ext_fields = collect_ext_prefixed_predicate_fields(&query);
            if !ext_fields.is_empty() {
                let remapped: Vec<String> = ext_fields
                    .iter()
                    .map(|f| format!("{f} → unmapped.{}", &f["ext.".len()..]))
                    .collect();
                all_warnings.push(QueryWarningOutput {
                    severity: "info".to_string(),
                    code: "OCSF_EXT_REMAPPED".to_string(),
                    message: format!(
                        "No rows matched. UDM-style ext.* fields were remapped to the OCSF \
                         unmapped.* spill location: {}",
                        remapped.join(", ")
                    ),
                    suggestion: Some(
                        "OCSF stores unconverted source fields under unmapped.*; the key may \
                         have a different name there than under UDM ext.*"
                            .to_string(),
                    ),
                    impact: None,
                });
            }
        }

        let (mut warnings, cost_score) = if all_warnings.is_empty() {
            (None, None)
        } else {
            (Some(all_warnings), Some(cost_analysis.estimated_cost))
        };

        // NAN-2022: attach the window-clamp warning (if the range was clamped). Kept
        // separate from the tuple above so it never spuriously sets `cost_score`, which
        // reflects cost analysis only.
        if let Some(w) = window_clamp_warning {
            warnings.get_or_insert_with(Vec::new).push(w);
        }

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Extract column order from table command if present
        let column_order = get_column_order(&query);

        // Unregister from tracker now that query is complete
        if let Some(ref req_id) = request.request_id {
            self.query_tracker.unregister(req_id);
        }

        // Cap reported total_count at max_limit for raw event queries so the
        // frontend knows pagination stops there. Aggregation queries report the
        // real count since their output is already grouped/reduced.
        let count_was_clamped = is_raw_event_query && total_count > self.config.max_limit as u64;
        let capped_total = if is_raw_event_query {
            total_count.min(self.config.max_limit as u64)
        } else {
            total_count
        };
        // NAN-1601: for an asset view, report the real event total from the
        // marker's _asset_pagination, not the initial-scan count.
        let asset_total = asset_view_total_count(&results);
        let capped_total = asset_total.unwrap_or(capped_total);

        // NAN-2550: `total_count` is exact only when the number actually counts
        // the whole match set. Three ways it does not: the raw-event clamp above
        // turned "more than max_limit" into exactly max_limit; the count
        // companion was skipped on a page flip and the raw page came back full;
        // or both. An asset marker and a post-processed grouped total are
        // complete by construction.
        let total_count_exact = if asset_total.is_some() || sql_limit_plan.page_after_post_processing
        {
            true
        } else {
            !count_was_clamped && (count_companion_ran || raw_page_proved_end)
        };

        Ok(SearchResponse {
            server_wall_ms: None,
            results,
            total_count: capped_total,
            total_count_exact,
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
            completeness: None,
        })
    }
}

/// Collect `ext.`-prefixed field names referenced by predicates in the query —
/// base search terms and `| where` conditions (NAN-1388 / G14).
///
/// Best-effort by design: it feeds the `OCSF_EXT_REMAPPED` empty-result note
/// only, so it deliberately covers the surfaces where an analyst types a
/// filtering predicate (the demo trap is `ext.error_code=0`). Non-predicate
/// references (`| stats by ext.foo`, `| table ext.foo`) project empty values
/// rather than filtering to zero rows, so they are out of scope here. BTreeSet
/// keeps the note's field list deterministic.
fn collect_ext_prefixed_predicate_fields(query: &Query) -> std::collections::BTreeSet<String> {
    fn from_expr(expr: &crate::query::SearchExpr, out: &mut std::collections::BTreeSet<String>) {
        use crate::query::SearchExpr as E;
        match expr {
            E::FieldFilter { field, .. }
            | E::FieldFunctionFilter { field, .. }
            | E::InList { field, .. } => {
                if field.starts_with("ext.") {
                    out.insert(field.clone());
                }
            }
            E::And(left, right) | E::Or(left, right) => {
                from_expr(left, out);
                from_expr(right, out);
            }
            E::Not(inner) | E::Group(inner) => from_expr(inner, out),
            _ => {}
        }
    }
    fn walk(query: &Query, out: &mut std::collections::BTreeSet<String>) {
        match query {
            Query::Search(expr) => from_expr(expr, out),
            Query::Piped { source, command } => {
                walk(source, out);
                if let Command::Where { condition } = command {
                    from_expr(condition, out);
                }
            }
        }
    }
    let mut out = std::collections::BTreeSet::new();
    walk(query, &mut out);
    out
}

#[cfg(test)]
mod ext_remap_note_tests {
    use super::*;
    use crate::lookup::{LookupColumn, LookupTable};
    use crate::query::parse_query;
    use crate::schema::OcsfProfile;
    use std::collections::HashMap;

    #[test]
    fn stats_page_routing_preserves_small_count_cubes_and_complete_suffixes() {
        for (text, expected) in [
            ("* | stats count by metadata.log_source", false),
            ("* | stats count by src_endpoint.ip", true),
            ("metadata.log_source=windows_sysmon category_name=\"Network Activity\" | stats count by dst_endpoint.ip, actor.process.name", true),
            ("* | stats count by src_endpoint.ip | where count > 10", false),
        ] {
            let query = parse_query(text).unwrap();
            let count = lake_count_pipeline_plan(&query);
            assert_eq!(lake_stats_uses_compiled_page(&query, count.as_ref()), expected, "{text}");
        }
    }

    #[test]
    fn interactive_lake_envelope_excludes_long_deep_and_export_requests() {
        let now = chrono::Utc::now();
        let mut request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "metadata.log_source = windows_sysmon",
            "time_range": { "start": now - chrono::Duration::hours(1), "end": now }
        }))
        .unwrap();
        let priority = super::super::admission::QueryPriority::Interactive;
        assert!(interactive_lake_eligible(&request, priority, 1000));
        request.offset = Some(1000);
        assert!(!interactive_lake_eligible(&request, priority, 1000));
        request.offset = None;
        request.query.push_str(" | export");
        assert!(!interactive_lake_eligible(&request, priority, 1000));
        request.query = "*".into();
        request.time_range.start = now - chrono::Duration::days(2);
        assert!(!interactive_lake_eligible(&request, priority, 1000));
        assert!(interactive_lake_fallback(&SearchError::ResourceExhausted(
            "scan".into()
        )));
        assert!(interactive_lake_fallback(&SearchError::ServiceUnavailable(
            "worker".into()
        )));
        assert!(!interactive_lake_fallback(&SearchError::Cancelled));
        assert!(!interactive_lake_fallback(&SearchError::InvalidTimeRange));
    }

    fn inline_lookup_table() -> LookupTable {
        LookupTable {
            id: uuid::Uuid::now_v7(),
            name: "asset_inventory".to_string(),
            description: None,
            table_name: "lookup_asset_inventory".to_string(),
            columns: vec![
                LookupColumn::text("ip", false),
                LookupColumn::text("department", true),
                LookupColumn::integer("criticality", true),
            ],
            primary_key: Some("ip".to_string()),
            row_count: 2,
            size_bytes: 256,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: None,
        }
    }

    #[test]
    fn small_scalar_lookup_compiles_to_worker_native_eval() {
        let rows = vec![
            HashMap::from([
                ("ip".to_string(), serde_json::json!("198.51.100.25")),
                ("department".to_string(), serde_json::json!("Engineering")),
                ("criticality".to_string(), serde_json::json!(90)),
            ]),
            HashMap::from([
                ("ip".to_string(), serde_json::json!("203.0.113.7")),
                ("department".to_string(), serde_json::Value::Null),
                ("criticality".to_string(), serde_json::json!(40)),
            ]),
        ];
        let assignments = build_inline_lookup_assignments(
            &inline_lookup_table(),
            "src_endpoint.ip",
            "ip",
            Some(&["department".to_string(), "criticality".to_string()]),
            false,
            rows,
        )
        .expect("bounded scalar lookup should inline");
        let query = Query::Piped {
            source: Box::new(parse_query("src_endpoint.ip=*").unwrap()),
            command: Command::Eval { assignments },
        };
        let rendered = query.pretty_print();
        let reparsed = parse_query(&rendered).expect("generated eval must reparse");

        assert_eq!(reparsed, query);
        assert!(rendered.contains("eval criticality = case("));
        assert!(rendered.contains("department = case("));
        assert!(rendered.contains("ip = case("));
        assert!(rendered.contains("null()"));
        assert!(!contains_lake_post_processing_anywhere(&query));
    }

    #[test]
    fn ambiguous_or_non_scalar_lookup_keeps_nano_side_execution() {
        let duplicate_casefolded = vec![
            HashMap::from([
                ("ip".to_string(), serde_json::json!("Example.COM")),
                ("department".to_string(), serde_json::json!("A")),
                ("criticality".to_string(), serde_json::json!(1)),
            ]),
            HashMap::from([
                ("ip".to_string(), serde_json::json!("example.com")),
                ("department".to_string(), serde_json::json!("B")),
                ("criticality".to_string(), serde_json::json!(2)),
            ]),
        ];
        assert!(build_inline_lookup_assignments(
            &inline_lookup_table(),
            "src_endpoint.ip",
            "ip",
            Some(&["department".to_string()]),
            true,
            duplicate_casefolded,
        )
        .is_none());

        let json_value = vec![HashMap::from([
            ("ip".to_string(), serde_json::json!("198.51.100.25")),
            (
                "department".to_string(),
                serde_json::json!({"nested": true}),
            ),
            ("criticality".to_string(), serde_json::json!(90)),
        ])];
        assert!(build_inline_lookup_assignments(
            &inline_lookup_table(),
            "src_endpoint.ip",
            "ip",
            Some(&["department".to_string()]),
            false,
            json_value,
        )
        .is_none());

        let inexact_integer = vec![HashMap::from([
            (
                "ip".to_string(),
                serde_json::json!(9_007_199_254_740_992_u64),
            ),
            ("department".to_string(), serde_json::json!("Finance")),
            ("criticality".to_string(), serde_json::json!(90)),
        ])];
        assert!(
            build_inline_lookup_assignments(
                &inline_lookup_table(),
                "src_endpoint.ip",
                "ip",
                Some(&["department".to_string()]),
                false,
                inexact_integer,
            )
            .is_none(),
            "integers that cannot round-trip through nPL f64 literals must stay Nano-side"
        );
    }

    #[test]
    fn row_local_lake_suffixes_keep_request_pagination() {
        let query = parse_query(
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence | rename confidence as intel_confidence | table time, src_endpoint.ip, intel_confidence"#,
        )
        .unwrap();
        let (_, suffix) = split_lake_post_processing(&query);

        assert!(!lake_post_processing_needs_candidate_set(&suffix));

        let prevalence =
            parse_query("* | prevalence enrich=true | prevalence enrich=true").unwrap();
        let (_, suffix) = split_lake_post_processing(&prevalence);
        assert!(!lake_post_processing_needs_candidate_set(&suffix));
    }

    #[test]
    fn durable_lake_sql_only_gate_rejects_nano_side_suffixes() {
        for query in [
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence"#,
            r#"metadata.log_source="windows_sysmon" | prevalence hash_prevalence < 5"#,
            r#"metadata.log_source="windows_sysmon" | resolve_identity field=src_endpoint.ip"#,
            r#"metadata.log_source="windows_sysmon" | inputlookup url="https://example.test/{src_endpoint.ip}" key=src_endpoint.ip"#,
            r#"metadata.log_source="windows_sysmon" | ai "classify these events""#,
            r#"* | append [* | lookup iocs src_endpoint.ip OUTPUT confidence]"#,
            r#"* | join src_endpoint.ip [* | prevalence enrich=true]"#,
            r#"* | where src_endpoint.ip IN [* | resolve_identity field=src_endpoint.ip | return src_endpoint.ip]"#,
        ] {
            let error = validate_durable_lake_sql_only_query(query)
                .expect_err("Nano-side suffix must not enter SQL-only durable execution");
            assert!(matches!(error, SearchError::SqlValidationError(_)));
        }

        validate_durable_lake_sql_only_query(
            r#"metadata.log_source="windows_sysmon" | stats count by process.name"#,
        )
        .expect("worker-native pipeline should remain durable-compatible");
    }

    /// NAN-3311: a suffix command the Nano-side evaluator cannot run is
    /// refused before the worker scan instead of being dropped.
    #[test]
    fn nan3311_lake_refuses_unsupported_commands_after_nano_side_stage() {
        for query in [
            "metadata.log_source=windows_sysmon | head 3 | prevalence enrich=true | streamstats count as n | table time, n",
            "* | lookup iocs src_endpoint.ip OUTPUT confidence | eventstats count by confidence",
            "* | prevalence enrich=true | bin span=1h | stats count by time_bucket",
        ] {
            let parsed = parse_query(query).unwrap();
            let error = validate_lake_nested_post_processing(&parsed)
                .expect_err("unsupported suffix command must be refused");
            assert!(
                matches!(&error, SearchError::SqlValidationError(m) if m.contains("cannot run after")),
                "{query}: {error:?}"
            );
        }
        for query in [
            "metadata.log_source=windows_sysmon | head 3 | prevalence enrich=true | reverse | table time",
            "* | streamstats count as n | prevalence enrich=true | where n > 1",
        ] {
            validate_lake_nested_post_processing(&parse_query(query).unwrap())
                .unwrap_or_else(|e| panic!("{query}: {e:?}"));
        }
    }

    #[test]
    fn interactive_lake_rejects_only_nested_nano_side_stages() {
        let top_level = parse_query(
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence"#,
        )
        .unwrap();
        validate_lake_nested_post_processing(&top_level)
            .expect("outer Nano-side suffix remains supported interactively");

        for query in [
            r#"* | append [* | lookup iocs src_endpoint.ip OUTPUT confidence]"#,
            r#"* | join src_endpoint.ip [* | prevalence enrich=true]"#,
            r#"* | where src_endpoint.ip IN [* | resolve_identity field=src_endpoint.ip | return src_endpoint.ip]"#,
        ] {
            let parsed = parse_query(query).unwrap();
            let error = validate_lake_nested_post_processing(&parsed)
                .expect_err("nested Nano-side stage must fail closed");
            // NAN-4287: the refusal names the supported IOC-hunting shape.
            assert!(
                matches!(&error, SearchError::SqlValidationError(m) if m.contains(LAKE_LOOKUP_ALTERNATIVE)),
                "{error:?}"
            );
        }
        assert!(LAKE_LOOKUP_ALTERNATIVE.contains("up to 4,096 keys"));
        assert_eq!(LAKE_LOOKUP_MEMBERSHIP_PUSHDOWN_MAX, 4_096);

        let native =
            parse_query(r#"* | append [* | stats count by process.name] | stats count"#).unwrap();
        validate_lake_nested_post_processing(&native)
            .expect("worker-native nested pipeline should remain supported");
    }

    #[tokio::test]
    async fn nested_internal_inputlookup_with_post_processing_is_cell_native() {
        use crate::inputlookup::{
            FakeStore, InputLookupConfig, InputLookupParams, InputLookupService,
        };
        use crate::lookup::LookupService;
        use crate::schema::FieldType;
        use std::{collections::BTreeMap, sync::Arc};

        let rows = vec![HashMap::from([
            ("host".to_string(), serde_json::json!("web01")),
            ("owner".to_string(), serde_json::json!("alice")),
            ("_row_id".to_string(), serde_json::json!(1)),
        ])];
        let lookup = Arc::new(LookupService::from_store(Arc::new(FakeStore {
            tables: HashMap::from([("asset_inventory".to_string(), rows)]),
        })));
        let service = InputLookupService::new(InputLookupConfig::default())
            .with_lookup_service(lookup.clone());
        let source_rows = vec![
            serde_json::json!({"host": "web01", "inputlookup_owner": "old"}),
            serde_json::json!({"host": "web99", "inputlookup_owner": "prior"}),
        ];
        let expected = service
            .execute(
                source_rows.clone(),
                &InputLookupParams {
                    url: crate::query::UrlTemplate::new("lookup://asset_inventory"),
                    format: crate::query::InputLookupFormat::Json,
                    key_field: Some("host".into()),
                    timeout_secs: 30,
                    max_rows: 100,
                    cache_ttl_secs: 0,
                },
            )
            .await
            .unwrap()
            .results;
        assert_eq!(expected[0]["inputlookup_owner"], serde_json::json!("alice"));
        assert_eq!(expected[1]["inputlookup_owner"], serde_json::json!("prior"));

        let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::from([
            ("inputlookup_owner".into(), FieldType::String),
            ("host".into(), FieldType::String),
        ]))
        .unwrap();
        let mut query = parse_query(
            r#"host=never | table host, inputlookup_owner | append [* | inputlookup asset_inventory key=host | eval score = 1 | where score > 0 | table host, inputlookup_owner] | stats count by inputlookup_owner"#,
        ).unwrap();
        validate_query_field_names(&query, &profile).unwrap();
        assert!(validate_lake_nested_post_processing(&query).is_err());
        assert_eq!(
            inline_nested_lake_inputlookups(&mut query, Some(&lookup), &profile)
                .await
                .unwrap(),
            1
        );
        validate_lake_nested_post_processing(&query).unwrap();
        validate_query_field_names(&query, &profile).unwrap();
        let rendered = query.pretty_print();
        assert!(rendered.contains("eval score"), "{rendered}");
        assert!(rendered.contains("where score"), "{rendered}");
        assert!(
            rendered.contains("stats count() as Count by inputlookup_owner"),
            "{rendered}"
        );
        let Query::Piped {
            source: append_source,
            command: outer_stats @ Command::Stats { .. },
        } = &query
        else {
            panic!("expected outer stats");
        };
        let Query::Piped {
            command: Command::Append { subsearch, .. },
            ..
        } = append_source.as_ref()
        else {
            panic!("expected append subsearch");
        };
        fn pipeline_commands(query: &Query, out: &mut Vec<Command>) {
            if let Query::Piped { source, command } = query {
                pipeline_commands(source, out);
                out.push(command.clone());
            }
        }
        let mut commands = Vec::new();
        pipeline_commands(subsearch, &mut commands);
        assert_eq!(commands.len(), 6);
        let native_rows = apply_post_prevalence_commands(source_rows.clone(), &commands[..3])
            .unwrap()
            .results;
        assert_eq!(
            native_rows[0]["inputlookup_owner"],
            serde_json::json!("alice")
        );
        assert_eq!(
            native_rows[1]["inputlookup_owner"],
            serde_json::json!("prior")
        );
        let mut actual = apply_post_prevalence_commands(source_rows, &commands)
            .unwrap()
            .results;
        let mut expected = apply_post_prevalence_commands(expected, &commands[3..])
            .unwrap()
            .results;
        actual = apply_post_prevalence_commands(actual, &[outer_stats.clone()])
            .unwrap()
            .results;
        expected = apply_post_prevalence_commands(expected, &[outer_stats.clone()])
            .unwrap()
            .results;
        actual.sort_by_key(|row| {
            row["inputlookup_owner"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        });
        expected.sort_by_key(|row| {
            row["inputlookup_owner"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        });
        assert_eq!(
            actual, expected,
            "cell-native rewrite must match InputLookupService after post-processing"
        );
        let mut projected =
            parse_query("* | append [* | table host | inputlookup asset_inventory key=host]")
                .unwrap();
        assert_eq!(
            inline_nested_lake_inputlookups(&mut projected, Some(&lookup), &profile)
                .await
                .unwrap(),
            0
        );
        assert!(validate_lake_nested_post_processing(&projected).is_err());
        let generator = crate::query::ClickHouseSqlGenerator::with_table("__tenant_parts")
            .with_profile(Arc::new(profile));
        let now = chrono::Utc::now();
        let sql = generator
            .generate_with_options(
                &query,
                &crate::query::TimeRange::new(now - chrono::Duration::hours(1), now),
                &crate::query::QueryOptions {
                    use_cache: false,
                    table_view: false,
                    limit: Some(100),
                    unordered: false,
                },
            )
            .unwrap();
        assert!(
            sql.contains("REPLACE("),
            "existing prefixed field must have one physical projection: {sql}"
        );
        assert!(sql.contains("__nano_il_value_"));
        assert!(sql.contains("SELECT * EXCEPT (__nano_il_"));
    }

    #[tokio::test]
    async fn bounded_tenant_lookup_runs_inside_lake_subsearch() {
        use super::super::ioc_lookup_resolve::tests::service_with;

        for original in [
            r#"* | append [src_endpoint.ip=* | lookup asset_inventory src_endpoint.ip AS ip OUTPUT department | where department="Engineering"]"#,
            r#"* | join src_endpoint.ip [src_endpoint.ip=* | lookup asset_inventory src_endpoint.ip AS ip OUTPUT department]"#,
            r#"* | where src_endpoint.ip IN [src_endpoint.ip=* | lookup asset_inventory src_endpoint.ip AS ip OUTPUT department | return src_endpoint.ip]"#,
        ] {
            let mut renderings = Vec::new();
            for department in ["Engineering", "Finance"] {
                let row = HashMap::from([
                    ("ip".to_string(), serde_json::json!("198.51.100.25")),
                    ("department".to_string(), serde_json::json!(department)),
                ]);
                let service = service_with(inline_lookup_table(), vec![row]);
                let mut query = parse_query(original).unwrap();
                assert!(validate_lake_nested_post_processing(&query).is_err());
                assert_eq!(inline_small_lake_lookups(
                    &mut query,
                    Some(&service),
                    &OcsfProfile::lake_1_9(),
                ).await.unwrap(), 1);
                validate_lake_nested_post_processing(&query).unwrap();
                let rendered = query.pretty_print();
                assert_eq!(parse_query(&rendered).unwrap(), query);
                assert!(rendered.contains(department));
                assert!(!rendered.contains("lookup asset_inventory"));
                renderings.push(rendered);
            }
            assert_ne!(renderings[0], renderings[1], "the two tenant snapshots must not share lookup rows");
        }
    }

    fn oc_sweep_users() -> (LookupTable, Vec<HashMap<String, serde_json::Value>>) {
        let table = LookupTable {
            id: uuid::Uuid::now_v7(),
            name: "oc_sweep_users".to_string(),
            description: None,
            table_name: "lookup_oc_sweep_users".to_string(),
            columns: vec![
                LookupColumn::text("user", false),
                LookupColumn::text("dept", true),
                LookupColumn::text("vip", true),
            ],
            primary_key: Some("user".to_string()),
            row_count: 1,
            size_bytes: 64,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: None,
        };
        let rows = vec![HashMap::from([
            ("user".to_string(), serde_json::json!("oc-sweep-alice")),
            ("dept".to_string(), serde_json::json!("finance")),
            ("vip".to_string(), serde_json::json!("yes")),
        ])];
        (table, rows)
    }

    fn first_lookup(query: &Query) -> (String, String) {
        match query {
            Query::Piped { command: Command::Lookup { key_field, event_field, .. }, .. } => {
                (key_field.clone(), event_field.clone())
            }
            Query::Piped { source, .. } => first_lookup(source),
            Query::Search(_) => panic!("no lookup in {query:?}"),
        }
    }

    /// NAN-3466 (a): the table key `user` was always added to the inlined
    /// outputs, so the worker SQL carried `case(…) AS user`, which shadows
    /// `user.name` in chDB ("Unknown expression identifier 'user.name' in
    /// scope stage_2") — with or without `OUTPUT dept, vip`.
    #[tokio::test]
    async fn inlined_lookup_on_a_dotted_key_keeps_the_event_field() {
        use super::super::ioc_lookup_resolve::tests::service_with;
        for original in [
            r#"metadata.product.name="oc-sweep" class_uid=3002 | lookup oc_sweep_users user as user.name | stats count by user.name"#,
            r#"metadata.product.name="oc-sweep" class_uid=3002 | lookup oc_sweep_users user as user.name OUTPUT dept, vip | stats count by user.name"#,
            r#"metadata.product.name="oc-sweep" class_uid=3002 | lookup oc_sweep_users user as user.name | table user.name, dept"#,
        ] {
            let (table, rows) = oc_sweep_users();
            let service = service_with(table, rows);
            let mut query = parse_query(original).unwrap();
            assert_eq!(
                inline_small_lake_lookups(&mut query, Some(&service), &OcsfProfile::lake_1_9())
                    .await
                    .unwrap(),
                1,
                "{original}"
            );
            let rendered = query.pretty_print();
            assert!(rendered.contains("dept = case("), "{rendered}");
            assert!(!rendered.contains(" user = case("), "{rendered}");
            assert!(!rendered.contains("eval user = case("), "{rendered}");
        }
        // An explicit OUTPUT of the key still emits it.
        let (table, rows) = oc_sweep_users();
        let assignments = build_inline_lookup_assignments(
            &table,
            "user.name",
            "user",
            Some(&["dept".to_string(), "user".to_string()]),
            false,
            rows,
        )
        .unwrap();
        assert!(assignments.iter().any(|assignment| assignment.field == "user"));
    }

    /// NAN-3466 (b): `| lookup … | head 1` returned the default page. The
    /// lookup was inlined into an `eval` after the head page was planned, the
    /// worker query had the head pulled out, and the no-suffix branch never
    /// applied the bound.
    #[tokio::test]
    async fn head_after_an_inlined_lookup_bounds_the_page() {
        use super::super::ioc_lookup_resolve::tests::service_with;
        let (table, rows) = oc_sweep_users();
        let service = service_with(table, rows);
        let mut query = parse_query(
            r#"metadata.product.name="oc-sweep" class_uid=3002 | lookup oc_sweep_users user as user.name | head 1"#,
        )
        .unwrap();
        assert!(lake_head_page_plan(&query).is_none(), "the lookup hides the head from the early plan");
        assert_eq!(
            inline_small_lake_lookups(&mut query, Some(&service), &OcsfProfile::lake_1_9())
                .await
                .unwrap(),
            1
        );
        let plan = plan_lake_post_processing(&query);
        assert!(plan.post_commands.is_empty());
        assert_eq!(plan.safe_head_bound, Some(1));
        assert!(!plan.worker_query.contains("head"), "{}", plan.worker_query);

        let row = |n: u64| serde_json::json!({"n": n});
        let mut response = SearchResponse {
            server_wall_ms: None,
            results: (0..20).map(row).collect(),
            total_count: 20,
            total_count_exact: false,
            execution_time_ms: 0,
            fields: Vec::new(),
            generated_sql: None,
            histogram: None,
            warnings: None,
            cost_score: None,
            display_type: None,
            column_order: None,
            completeness: None,
        };
        LakeHeadWindow { head_count: 1, requested_limit: 20, requested_offset: 0 }.apply(&mut response);
        assert_eq!(response.results, vec![row(0)]);
        assert_eq!((response.total_count, response.total_count_exact), (1, true));

        response.results = (0..5).map(row).collect();
        LakeHeadWindow { head_count: 3, requested_limit: 1, requested_offset: 1 }.apply(&mut response);
        assert_eq!(response.results, vec![row(1)]);
        assert_eq!(response.total_count, 3);
    }

    /// NAN-3466 (c): the parser picks the event side with the UDM profile,
    /// where `user` is a column, so a lookup keyed on an eval'd field asked
    /// the table for column `u`. The table's own columns now decide.
    #[tokio::test]
    async fn lookup_on_an_evald_field_orients_against_the_table_columns() {
        use super::super::ioc_lookup_resolve::tests::service_with;
        for original in [
            r#"class_uid=3002 | eval u=user.name | lookup oc_sweep_users user as u | stats count by dept"#,
            r#"class_uid=3002 | eval u=user.name | lookup oc_sweep_users u as user | stats count by dept"#,
            r#"class_uid=3002 | eval u=user.name | append [class_uid=3002 | eval u=user.name | lookup oc_sweep_users user as u]"#,
        ] {
            let (table, rows) = oc_sweep_users();
            let service = service_with(table, rows);
            let mut query = parse_query(original).unwrap();
            orient_lookup_keys(&mut query, Some(&service)).await;
            let lookups = crate::search::query_processing::extract_lookup_commands(&query);
            for lookup in &lookups {
                assert_eq!((lookup.key_field.as_str(), lookup.event_field.as_str()), ("user", "u"), "{original}");
            }
            if lookups.is_empty() {
                // The appended subsearch's lookup.
                let rendered = query.pretty_print();
                assert!(rendered.contains("lookup oc_sweep_users user AS u"), "{rendered}");
            }
        }
        // The correctly-ordered dotted form and an unknown table keep the parse.
        let (table, rows) = oc_sweep_users();
        let service = service_with(table, rows);
        let mut query = parse_query("* | lookup oc_sweep_users user as user.name").unwrap();
        orient_lookup_keys(&mut query, Some(&service)).await;
        assert_eq!(first_lookup(&query), ("user".to_string(), "user.name".to_string()));
        let mut query = parse_query("* | lookup missing_table user as u").unwrap();
        let before = first_lookup(&query);
        orient_lookup_keys(&mut query, Some(&service)).await;
        assert_eq!(first_lookup(&query), before);
    }

    #[test]
    fn membership_and_aggregation_suffixes_need_candidate_set() {
        let query = parse_query(
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence | where confidence > 50 | stats count by dst_endpoint.ip"#,
        )
        .unwrap();
        let (_, suffix) = split_lake_post_processing(&query);

        assert!(lake_post_processing_needs_candidate_set(&suffix));
    }

    #[test]
    fn lookup_isnotnull_membership_is_safe_to_push_into_the_base_search() {
        let mut query = parse_query(
            r#"metadata.log_source="windows_sysmon" | lookup threat_intel src_endpoint.ip AS src_ip | where isnotnull(threat_type)"#,
        )
        .unwrap();
        let pushdown = lookup_membership_pushdown(&query).expect("membership pushdown");
        assert_eq!(pushdown.table_name, "threat_intel");
        assert_eq!(pushdown.event_field, "src_endpoint.ip");
        assert_eq!(pushdown.key_field, "src_ip");

        inject_lake_base_membership(
            &mut query,
            pushdown.event_field,
            vec![Value::String("203.0.113.7".to_string())],
        );
        let rendered = query.pretty_print();
        assert!(rendered.contains(r#"src_endpoint.ip IN ("203.0.113.7")"#));
        assert!(rendered.contains("lookup threat_intel"));
        assert!(rendered.contains("where isnotnull(threat_type)"));
    }

    #[test]
    fn lookup_membership_does_not_rewrite_unrelated_suffix_filters() {
        let query = parse_query(
            r#"metadata.log_source="windows_sysmon" | lookup threat_intel src_endpoint.ip AS src_ip | where confidence >= 80"#,
        )
        .unwrap();
        assert!(lookup_membership_pushdown(&query).is_none());
    }

    #[test]
    fn row_preserving_enrichment_can_push_a_head_bound_to_storage() {
        let query = parse_query(
            r#"src_endpoint.ip="198.51.100.25" | lookup asset_inventory src_endpoint.ip AS ip OUTPUT hostname, criticality | table src_endpoint.ip, hostname, criticality | head 20"#,
        )
        .unwrap();
        let (base, suffix) = split_lake_post_processing(&query);

        assert_eq!(lake_safe_post_processing_head_bound(&suffix), Some(20));
        assert!(
            !(lake_safe_post_processing_head_bound(&suffix).is_none()
                && lake_post_processing_needs_candidate_set(&suffix))
        );
        assert_eq!(base.pretty_print(), r#"src_endpoint.ip="198.51.100.25""#);
    }

    #[test]
    fn filtering_on_enrichment_output_prevents_head_pushdown() {
        let query = parse_query(
            r#"src_endpoint.ip=* | lookup iocs src_endpoint.ip OUTPUT confidence | where confidence > 50 | head 20"#,
        )
        .unwrap();
        let (_, suffix) = split_lake_post_processing(&query);

        assert_eq!(lake_safe_post_processing_head_bound(&suffix), None);
        assert!(lake_post_processing_needs_candidate_set(&suffix));
    }

    #[test]
    fn a_safe_head_bounds_later_global_processing_exactly() {
        let query = parse_query(
            r#"src_endpoint.ip=* | lookup iocs src_endpoint.ip OUTPUT confidence | head 20 | stats count() as events by confidence"#,
        )
        .unwrap();
        let (_, suffix) = split_lake_post_processing(&query);

        assert_eq!(lake_safe_post_processing_head_bound(&suffix), Some(20));
    }

    #[test]
    fn global_lake_suffix_projects_only_referenced_ocsf_fields() {
        let profile = OcsfProfile::lake_1_9();
        let generator =
            ClickHouseSqlGenerator::new().with_profile(std::sync::Arc::new(profile.clone()));
        let query = parse_query(
            // `confidence` is itself an OCSF 1.9 leaf (NAN-2994), and a derived
            // name that is also a real column is deliberately projected, so the
            // lookup output here is a name no schema owns.
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT feed_confidence | where feed_confidence > 50 | stats count by dst_endpoint.ip"#,
        )
        .unwrap();
        let (base, suffix) = split_lake_post_processing(&query);

        let projected =
            project_lake_candidate_query(&base, &query, &suffix, &generator, &profile).unwrap();
        let text = projected.pretty_print();

        assert!(text.contains("dst_endpoint.ip"));
        assert!(text.contains("metadata.log_source"));
        assert!(text.contains("src_endpoint.ip"));
        assert!(!text.contains("feed_confidence"));
        assert!(!text.contains("raw_data"));
    }

    #[test]
    fn full_event_suffix_does_not_add_internal_projection() {
        let profile = OcsfProfile::lake_1_9();
        let generator =
            ClickHouseSqlGenerator::new().with_profile(std::sync::Arc::new(profile.clone()));
        let query = parse_query(
            r#"metadata.log_source="windows_sysmon" | lookup iocs src_endpoint.ip OUTPUT confidence | where confidence > 50"#,
        )
        .unwrap();
        let (base, suffix) = split_lake_post_processing(&query);

        assert!(
            project_lake_candidate_query(&base, &query, &suffix, &generator, &profile).is_none()
        );
    }

    #[test]
    fn candidate_projection_does_not_resolve_derived_names_as_unmapped_fields() {
        let profile = OcsfProfile::lake_1_9();
        let generator =
            ClickHouseSqlGenerator::new().with_profile(std::sync::Arc::new(profile.clone()));
        let full_query = parse_query(
            r#"metadata.log_source="windows_sysmon" | anomaly sum(raw_data_size) by src_endpoint.ip threshold=3 | where anomaly_score > 3 | table src_endpoint.ip, sum_raw_data_size, expected, anomaly_score"#,
        )
        .unwrap();
        let base = parse_query(r#"metadata.log_source="windows_sysmon""#).unwrap();
        let suffix = vec![
            Command::Anomaly {
                field: "sum(raw_data_size)".to_string(),
                by_fields: vec!["src_endpoint.ip".to_string()],
                threshold: 3.0,
                method: crate::query::AnomalyMethod::ZScore,
            },
            Command::Table {
                fields: [
                    "src_endpoint.ip",
                    "sum_raw_data_size",
                    "expected",
                    "anomaly_score",
                ]
                .into_iter()
                .map(|name| TableField {
                    name: name.to_string(),
                    alias: None,
                })
                .collect(),
            },
        ];

        let projected =
            project_lake_candidate_query(&base, &full_query, &suffix, &generator, &profile)
                .unwrap()
                .pretty_print();

        assert!(projected.contains("metadata.log_source"));
        assert!(projected.contains("raw_data_size"));
        assert!(projected.contains("src_endpoint.ip"));
        assert!(!projected.contains("expected"));
        assert!(!projected.contains("anomaly_score"));
        assert!(!projected.contains("sum_raw_data_size"));
    }

    #[test]
    fn lake_histogram_replaces_page_sentinel_with_exact_count() {
        let mut response = SearchResponse {
            server_wall_ms: None,
            results: vec![serde_json::json!({"time": "2026-08-12 00:00:00"})],
            // NAN-2550: 50 rows and "more exist" -- a lower bound, reported as
            // one, not as the old fabricated 51.
            total_count: 50,
            total_count_exact: false,
            execution_time_ms: 125,
            fields: Vec::new(),
            generated_sql: None,
            histogram: None,
            warnings: None,
            cost_score: None,
            display_type: None,
            column_order: None,
            completeness: None,
        };
        let histogram = vec![
            HistogramBucket {
                time: chrono::Utc::now(),
                count: 70,
            },
            HistogramBucket {
                time: chrono::Utc::now(),
                count: 29,
            },
        ];

        attach_lake_histogram(&mut response, histogram, true);

        assert_eq!(response.total_count, 99);
        assert_eq!(response.histogram.as_ref().unwrap().len(), 2);
        assert!(response.warnings.is_none());
        // The histogram companion counted the complete base predicate, so the
        // result is no longer a lower bound.
        assert!(response.total_count_exact);
    }

    #[test]
    fn lake_event_table_returns_rows_without_an_exact_count_companion() {
        let scope = ScopeSet::unrestricted();
        for query in ["*", "device.hostname=\"ws-support-115.corp.local\"", "src_endpoint.ip=\"10.0.0.1\" AND user.name=\"alice\""] {
            let parsed = parse_query(query).unwrap();
            let request: SearchRequest = serde_json::from_value(serde_json::json!({
                "query": query,
                "time_range": {"start": "2026-09-28T00:00:00Z", "end": "2026-09-29T00:00:00Z"},
                "table_view": true
            })).unwrap();
            let logs = crate::query::Dataset::Logs;
            assert!(lake_histogram_plan(&request, logs, &parsed, "rows", &scope, false).is_none());
            assert!(lake_histogram_plan(&request, logs, &parsed, "hist", &scope, true).is_some());
        }
    }

    /// Stats requests, including the standalone histogram route, perform
    /// no companion scan and leave the aggregation's row count untouched.
    #[test]
    fn lake_stats_search_skips_base_histogram() {
        let query = r#"metadata.log_source="windows_sysmon" category_name="Network Activity" actor.process.name="SpeechModelDownload.exe" | stats count by dst_endpoint.ip, actor.process.name"#;
        let parsed = parse_query(query).unwrap();
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": query,
            "time_range": {"start": "2026-09-28T00:00:00Z", "end": "2026-09-29T00:00:00Z"},
        })).unwrap();
        let scope = ScopeSet::unrestricted();
        for histogram_only in [false, true] {
            assert!(lake_histogram_plan(&request, crate::query::Dataset::Logs,
                &parsed, "q1", &scope, histogram_only).is_none());
        }
        assert!(!super::super::lake_histogram_counts_result_rows(&parsed));
    }

    /// NAN-2996: the search histogram companion takes the exact count-rollup
    /// route only for rollup-expressible bases and whole 5-minute spans.
    #[test]
    fn lake_histogram_rollup_plan_is_exact_or_absent() {
        let plan = |query: &str| lake_histogram_rollup_plan(&parse_query(query).unwrap());
        let all = plan("* | timechart span=5m count() as count").expect("match-all");
        assert_eq!((all.field.as_str(), all.bucket_span_us), ("metadata.log_source", 300_000_000));
        assert!(all.predicate.is_none() && all.source_filter.is_none());
        let source = plan("metadata.log_source=conduit_proxy | timechart span=1h count() as count")
            .expect("source");
        assert_eq!(source.field, "metadata.log_source");
        assert_eq!(source.predicate.as_ref().map(|p| p.values.clone()), Some(vec!["conduit_proxy".to_string()]));
        // Keyword bases are not in the rollups; sub-bucket spans cannot be exact.
        assert!(plan("powershell | timechart span=5m count() as count").is_none());
        assert!(plan("* | timechart span=1m count() as count").is_none());
        assert!(plan("* | timechart span=7m count() as count").is_none());
        // A split timechart is not a histogram.
        assert!(plan("* | timechart span=5m count() as count by metadata.log_source").is_none());
    }

    #[test]
    fn lake_distributed_stats_accepts_only_exact_raw_count() {
        let count =
            parse_query(r#"metadata.log_source="windows_sysmon" | stats count by process.name"#)
                .unwrap();
        assert_eq!(
            lake_count_stats_plan(&count),
            Some(LakeCountStatsPlan {
                group_by: vec!["process.name".to_string()],
                count_alias: "count".to_string(),
                rollup_field: Some("process.name".to_string()),
                rollup_predicate: None,
                rollup_source_filter: Some("windows_sysmon".to_string()),
                rollup_union: None,
                rollup_group_by_source: false,
                rollup_field_union: None,
                bucket_span_us: None,
                output_spelling: None,
            })
        );

        let populated = parse_query(
            r#"metadata.log_source="windows_sysmon" | stats count(process.name) as populated by device.hostname"#,
        )
        .unwrap();
        assert_eq!(
            lake_count_stats_plan(&populated),
            Some(LakeCountStatsPlan {
                group_by: vec!["device.hostname".to_string()],
                count_alias: "populated".to_string(),
                rollup_field: None,
                rollup_predicate: None,
                rollup_source_filter: None,
                rollup_union: None,
                rollup_group_by_source: false,
                rollup_field_union: None,
                bucket_span_us: None,
                output_spelling: None,
            })
        );

        let sum = parse_query(
            r#"metadata.log_source="windows_sysmon" | stats sum(raw_data_size) by process.name"#,
        )
        .unwrap();
        assert!(lake_count_stats_plan(&sum).is_none());

        let post_filter = parse_query(
            r#"metadata.log_source="windows_sysmon" | stats count by process.name | where count > 2"#,
        )
        .unwrap();
        assert!(lake_count_stats_plan(&post_filter).is_none());
        let pipeline = lake_count_pipeline_plan(&post_filter).unwrap();
        assert_eq!(pipeline.aggregate.group_by, vec!["process.name"]);
        assert_eq!(pipeline.post_commands.len(), 1);
        assert!(matches!(
            pipeline.post_commands.first(),
            Some(Command::Where { .. })
        ));
    }

    #[test]
    fn lake_count_pipeline_keeps_safe_suffixes_off_raw_parquet() {
        let parsed = parse_query(
            r#"metadata.log_source="windows_sysmon" | stats count as events by process.name | where events > 2 | sort -events | head 10 | table process.name, events"#,
        )
        .unwrap();
        let pipeline = lake_count_pipeline_plan(&parsed).unwrap();
        assert_eq!(
            pipeline.aggregate_query.pretty_print(),
            r#"metadata.log_source="windows_sysmon" | stats count() as events by process.name"#
        );
        assert_eq!(pipeline.post_commands.len(), 4);
        assert!(matches!(pipeline.post_commands[0], Command::Where { .. }));
        assert!(matches!(pipeline.post_commands[1], Command::Sort { .. }));
        assert!(matches!(
            pipeline.post_commands[2],
            Command::Head { count: 10 }
        ));
        assert!(matches!(pipeline.post_commands[3], Command::Table { .. }));
    }

    #[test]
    fn lake_count_pipeline_supports_bounded_second_aggregation() {
        let parsed = parse_query(
            r#"* | stats count as events by process.name | eval bucket = case(events>100,"hi",1=1,"lo") | stats count by bucket"#,
        )
        .unwrap();
        let pipeline = lake_count_pipeline_plan(&parsed).unwrap();
        assert_eq!(pipeline.aggregate.group_by, vec!["process.name"]);
        assert_eq!(pipeline.post_commands.len(), 2);
        assert!(matches!(pipeline.post_commands[0], Command::Eval { .. }));
        assert!(matches!(pipeline.post_commands[1], Command::Stats { .. }));
    }

    #[test]
    fn lake_head_page_moves_only_bounded_head_across_row_preserving_commands() {
        let parsed =
            parse_query("* | head 10 | table time, src_endpoint.ip, process.cmd_line").unwrap();
        let plan = lake_head_page_plan(&parsed).unwrap();
        assert_eq!(plan.head_count, 10);
        assert_eq!(
            plan.query_without_head.pretty_print(),
            "* | table time, src_endpoint.ip, process.cmd_line"
        );

        let membership_changing =
            parse_query("* | where isnotnull(src_endpoint.ip) | head 10").unwrap();
        assert!(lake_head_page_plan(&membership_changing).is_none());
        let unbounded = parse_query("* | head 10001").unwrap();
        assert!(lake_head_page_plan(&unbounded).is_none());
    }

    /// gen1-vs-lean audit: `dc()` answered exactly 10001 for 27,970 IPs. A
    /// values state at the compiler's cap is recognised as truncated.
    #[test]
    fn lake_distinct_state_len_detects_a_full_state() {
        let full: Vec<serde_json::Value> =
            (0..LAKE_DISTINCT_STATE_CAP).map(|i| serde_json::json!(format!("v{i}"))).collect();
        assert_eq!(lake_distinct_state_len(&serde_json::Value::Array(full)), LAKE_DISTINCT_STATE_CAP);
        assert_eq!(lake_distinct_state_len(&serde_json::json!(["a", null, "b"])), 2);
        assert_eq!(lake_distinct_state_len(&serde_json::json!("a, b, c")), 3);
        assert_eq!(lake_distinct_state_len(&serde_json::Value::Null), 0);
        // The cap must track the compiler's INTERNAL_DISTINCT_VALUES_LIMIT.
        let compiler = include_str!("../../bin/lake_query_compile.rs");
        assert!(
            compiler.contains(&format!("const INTERNAL_DISTINCT_VALUES_LIMIT: usize = {};",
                LAKE_DISTINCT_STATE_CAP.to_string().as_bytes().rchunks(3).rev()
                    .map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("_"))),
            "LAKE_DISTINCT_STATE_CAP drifted from the compiler"
        );
    }

    /// Detection audit: `… | head N | lookup …` returned 3xN rows on lean;
    /// the base head was left inside the per-chunk worker query.
    #[test]
    fn lake_suffix_pulls_the_base_head_into_the_request_bound() {
        for (query, worker, bound) in [
            ("host=\"h\" | head 5 | lookup assets src_endpoint.ip OUTPUT owner", "host=\"h\"", Some(5)),
            ("host=\"h\" | sort -time | head 5 | lookup assets src_endpoint.ip OUTPUT owner | head 3", "host=\"h\" | sort -time", Some(3)),
            ("host=\"h\" | lookup assets src_endpoint.ip OUTPUT owner | head 4", "host=\"h\"", Some(4)),
        ] {
            let parsed = parse_query(query).unwrap();
            let (base, post) = split_lake_post_processing(&parsed);
            assert!(!post.is_empty(), "{query}");
            let (worker_query, head) = lake_post_processing_worker_query(&base, &post);
            assert_eq!(worker_query, worker, "{query}");
            assert_eq!(head, bound, "{query}");
        }
        // A membership-changing base keeps its head (never paged per chunk:
        // the compiler does not prove it newest-first).
        let parsed = parse_query("host=\"h\" | where isnotnull(user.name) | head 5 | lookup assets src_endpoint.ip OUTPUT owner").unwrap();
        let (base, post) = split_lake_post_processing(&parsed);
        let (worker_query, head) = lake_post_processing_worker_query(&base, &post);
        assert!(worker_query.ends_with("| head 5"), "{worker_query}");
        assert_eq!(head, None);
    }

    /// Audit #3: `| sort -time | head N` must be a global top-N page, not a
    /// per-chunk head. The head leaves the worker query (the request limit
    /// becomes N) and the `sort -time` stays.
    #[test]
    fn lake_head_page_moves_head_across_newest_first_time_sort() {
        for (query, expected, count) in [
            ("host=\"h\" | sort -time | head 7", "host=\"h\" | sort -time", 7),
            ("host=\"h\" | head 7 | sort -time", "host=\"h\" | sort -time", 7),
            ("host=\"h\" | sort -_time | head 50", "host=\"h\" | sort -_time", 50),
            ("host=\"h\" | sort -time | head 9 | table time | head 4", "host=\"h\" | sort -time | table time", 4),
        ] {
            let plan = lake_head_page_plan(&parse_query(query).unwrap())
                .unwrap_or_else(|| panic!("{query} must take the head page"));
            assert_eq!(plan.head_count, count, "{query}");
            assert_eq!(plan.query_without_head.pretty_print(), expected, "{query}");
        }
        for query in [
            "host=\"h\" | sort time | head 7",
            "host=\"h\" | sort -count | head 7",
            "host=\"h\" | sort -time, host | head 7",
        ] {
            assert!(lake_head_page_plan(&parse_query(query).unwrap()).is_none(), "{query}");
        }
    }

    #[test]
    fn lake_distinct_pipeline_uses_mergeable_values_state() {
        let parsed = parse_query(
            "* | where src_endpoint.ip!=\"\" | stats dc(dst_endpoint.ip) as peers by src_endpoint.ip | where peers>1 | sort -peers | head 10",
        )
        .unwrap();
        let plan = lake_distinct_pipeline_plan(&parsed).unwrap();
        assert_eq!(plan.group_by, vec!["src_endpoint.ip"]);
        assert_eq!(plan.output_alias, "peers");
        assert_eq!(plan.post_commands.len(), 3);
        assert!(plan
            .aggregate_query
            .pretty_print()
            .contains("eval __nano_distinct_token = base64_encode(tostring(dst_endpoint.ip))"));
        assert!(plan
            .aggregate_query
            .pretty_print()
            .contains("values(__nano_distinct_token) as __nano_distinct_values"));
    }

    #[test]
    fn lake_distinct_pipeline_merges_count_dc_and_values_together() {
        let parsed = parse_query(
            r#"failed password OR login failed | stats count() as failures, dc(user.name) as targeted_users, values(user.name) as user_list by src_endpoint.ip | where failures > 20 | sort -failures | head 10"#,
        )
        .unwrap();
        let plan = lake_distinct_pipeline_plan(&parsed).unwrap();
        assert_eq!(plan.group_by, vec!["src_endpoint.ip"]);
        assert_eq!(plan.output_alias, "targeted_users");
        assert_eq!(plan.values_output_alias.as_deref(), Some("user_list"));
        assert_eq!(plan.count_output_alias.as_deref(), Some("failures"));
        let aggregate = plan.aggregate_query.pretty_print();
        assert!(
            aggregate.contains("eval __nano_distinct_token = base64_encode(tostring(user.name))")
        );
        assert!(aggregate.contains("values(__nano_distinct_token) as __nano_distinct_values"));
        assert!(aggregate.contains("count() as failures"));
        assert_eq!(plan.post_commands.len(), 3);
    }

    #[test]
    fn lake_count_metrics_reduce_boolean_eval_sum_to_exact_cube_counts() {
        let parsed = parse_query(
            "metadata.log_source=\"conduit_proxy\" | eval is_int = if(src_endpoint.ip != \"\", 1, 0) | stats sum(is_int) as internal, count() as total",
        )
        .unwrap();
        let plan = lake_count_metrics_plan(&parsed).unwrap();
        assert_eq!(plan.metrics.len(), 2);
        assert_eq!(plan.metrics[0].alias, "internal");
        assert_eq!(plan.metrics[0].field, "src_endpoint.ip");
        assert_eq!(plan.metrics[0].predicate.as_ref().unwrap().kind, "ne");
        assert_eq!(
            plan.metrics[0].source_filter.as_deref(),
            Some("conduit_proxy")
        );
        assert_eq!(plan.metrics[1].alias, "total");
        assert_eq!(plan.metrics[1].field, "metadata.log_source");
        assert!(plan.metrics[1].source_filter.is_none());
    }

    #[test]
    fn high_cardinality_ip_top_talkers_use_the_compiled_query_once() {
        let query = parse_query("* | stats count by src_endpoint.ip | sort -count | head 10").unwrap();
        assert!(lake_count_pipeline_plan(&query).is_none());
        let unbounded = parse_query("* | stats count by src_endpoint.ip").unwrap();
        assert!(lake_count_pipeline_plan(&unbounded).is_some());
    }

    #[test]
    fn lake_count_rollup_recognizes_structured_benchmark_predicates() {
        let cases = [
            (
                r#"process.cmd_line contains "powershell" | stats count"#,
                "process.cmd_line",
                "contains",
                vec!["powershell"],
                None,
            ),
            (
                r#"actor.process.name=/^ngen[.]exe$/i | stats count"#,
                "actor.process.name",
                "regex",
                vec!["(?i)^ngen[.]exe$"],
                None,
            ),
            (
                r#"metadata.log_source="windows_sysmon" actor.process.name="ngen.exe" | stats count"#,
                "actor.process.name",
                "eq",
                vec!["ngen.exe"],
                Some("windows_sysmon"),
            ),
            (
                r#"metadata.log_source IN ("findings", "audit") | stats count"#,
                "metadata.log_source",
                "in",
                vec!["findings", "audit"],
                None,
            ),
            (
                r#"isnull(device.hostname) | stats count"#,
                "device.hostname",
                "is_null",
                Vec::new(),
                None,
            ),
        ];
        for (query, field, kind, values, source) in cases {
            let parsed = parse_query(query).unwrap_or_else(|error| panic!("{query}: {error}"));
            let plan = lake_count_stats_plan(&parsed).unwrap_or_else(|| panic!("{query}"));
            assert!(plan.group_by.is_empty(), "{query}");
            assert_eq!(plan.rollup_field.as_deref(), Some(field), "{query}");
            let predicate = plan
                .rollup_predicate
                .as_ref()
                .unwrap_or_else(|| panic!("{query}"));
            assert_eq!(predicate.kind, kind, "{query}");
            assert_eq!(predicate.values, values, "{query}");
            assert_eq!(plan.rollup_source_filter.as_deref(), source, "{query}");
        }
    }

    #[test]
    fn lake_count_rollup_recognizes_dashboard_breakdown_cube() {
        let parsed =
            parse_query("* | stats count as events by severity, class_name, metadata.log_source")
                .unwrap();
        let plan = lake_count_stats_plan(&parsed).unwrap();
        assert_eq!(
            plan.group_by,
            vec!["severity", "class_name", "metadata.log_source"]
        );
        assert_eq!(
            plan.rollup_field.as_deref(),
            Some(LAKE_DASHBOARD_BREAKDOWN_FIELD)
        );
        assert!(plan.rollup_predicate.is_none());
        assert!(plan.rollup_source_filter.is_none());
        assert!(plan.bucket_span_us.is_none());
    }

    #[test]
    fn lake_count_rollup_recognizes_source_timechart() {
        let parsed = parse_query("* | timechart span=1h count by metadata.log_source").unwrap();
        let plan = lake_count_stats_plan(&parsed).unwrap();
        assert_eq!(plan.group_by, vec!["metadata.log_source"]);
        assert_eq!(plan.rollup_field.as_deref(), Some("metadata.log_source"));
        assert_eq!(plan.bucket_span_us, Some(3_600_000_000));
    }

    /// NAN-3173: a scoped split timechart plans its one-request rollup from
    /// the gate-free base; the doubly gated base (what the inner fetches used
    /// to carry) never plans one, and inexact shapes keep the scans.
    #[test]
    fn lake_timechart_rollup_plan_reads_through_the_scope_gate() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let deny = ["audit".to_string()].into_iter().collect::<BTreeSet<_>>();
        let timechart_parts = |query: &str| {
            let Query::Piped {
                source,
                command:
                    Command::Timechart {
                        span,
                        aggregations,
                        split_by,
                        ..
                    },
            } = lake_gated_query(query, &["audit"])
            else {
                panic!("{query}")
            };
            (*source, span, aggregations[0].clone(), split_by)
        };
        for (query, group_field, by_source) in [
            ("* | timechart span=1h count by metadata.log_source", "metadata.log_source", false),
            (
                r#"device.hostname="ws-1.corp.local" | timechart span=1h count by metadata.log_source"#,
                "device.hostname",
                true,
            ),
            ("* | timechart span=30m count by device.hostname", "device.hostname", false),
        ] {
            let (gated, span, aggregation, fields) = timechart_parts(query);
            assert!(
                lake_timechart_rollup_plan(&profile, &gated, span, &aggregation, &fields).is_none(),
                "the gate hides the rollup: {query}"
            );
            let stripped = strip_lake_source_scope_gate(&gated, &deny).unwrap();
            let plan = lake_timechart_rollup_plan(&profile, &stripped, span, &aggregation, &fields)
                .unwrap_or_else(|| panic!("{query}"));
            assert_eq!(plan.rollup_field.as_deref(), Some(group_field), "{query}");
            assert_eq!(plan.rollup_group_by_source, by_source, "{query}");
            assert_eq!(plan.bucket_span_us, Some(i64::try_from(span.as_micros()).unwrap()));

            // The inner fetch re-gates its text: built from the gated base
            // it carries the gate twice and the strip cannot see through.
            let regated = |base: &Query| {
                let text = Query::Piped {
                    source: Box::new(base.clone()),
                    command: Command::Stats {
                        aggregations: vec![aggregation.clone()],
                        group_by: Some(fields.clone()),
                    },
                }
                .pretty_print();
                lake_gated_query(&text, &["audit"])
            };
            let rollup_field = |query: &Query| {
                lake_count_pipeline_plan_scoped(query, &deny)
                    .and_then(|plan| plan.aggregate.rollup_field)
            };
            assert_eq!(rollup_field(&regated(&gated)), None, "{query}");
            assert_eq!(rollup_field(&regated(&stripped)).as_deref(), Some(group_field), "{query}");
        }
        for query in [
            // Sub-rollup and unaligned spans.
            "* | timechart span=1m count by metadata.log_source",
            "* | timechart span=7m count by metadata.log_source",
            // Not a bare count.
            "* | timechart span=1h sum(traffic.bytes) by metadata.log_source",
            // A free-text base has no rollup predicate.
            "powershell | timechart span=1h count by metadata.log_source",
            // A near-unique group field reads more rollup rows than it saves.
            "* | timechart span=1h count by src_endpoint.ip",
        ] {
            let (gated, span, aggregation, fields) = timechart_parts(query);
            let stripped = strip_lake_source_scope_gate(&gated, &deny).unwrap();
            assert!(
                lake_timechart_rollup_plan(&profile, &stripped, span, &aggregation, &fields).is_none(),
                "{query}"
            );
        }
    }

    /// NAN-3153: the Q6 entity pivots map onto exact rollup shapes.
    #[test]
    fn lake_count_rollup_recognizes_entity_pivots_by_source() {
        let plan = |query: &str| lake_count_stats_plan(&parse_query(query).unwrap()).unwrap();
        let host = plan(r#"device.hostname="ws-legal-096.corp.local" | stats count by metadata.log_source"#);
        assert_eq!(host.rollup_field.as_deref(), Some("device.hostname"));
        assert!(host.rollup_group_by_source);
        assert_eq!(host.rollup_predicate.as_ref().unwrap().kind, "eq");
        assert_eq!(host.group_by, vec![LAKE_SOURCE_FIELD.to_string()]);
        // Source-scoped: the source filter narrows the rows, grouping stays by source.
        let scoped = plan(r#"metadata.log_source=windows_sysmon device.hostname="h1" | stats count by metadata.log_source"#);
        assert!(scoped.rollup_group_by_source);
        assert_eq!(scoped.rollup_source_filter.as_deref(), Some("windows_sysmon"));
        let trend = plan(r#"user.name="svc_db" | timechart span=1h count by metadata.log_source"#);
        assert!(trend.rollup_group_by_source);
        assert_eq!(trend.bucket_span_us, Some(3_600_000_000));
        for query in [
            r#"user.name="svc_db" OR actor.user.name="svc_db" | stats count by metadata.log_source"#,
            r#"src_endpoint.ip="10.1.3.147" OR dst_endpoint.ip="10.1.3.147" | stats count"#,
        ] {
            let union = plan(query);
            assert!(union.rollup_field.is_none(), "{query}");
            let union = union.rollup_field_union.expect(query);
            assert_ne!(union.left_field, union.right_field);
        }
        // Not exact or not a rollup shape: no rollup routing at all.
        for query in [
            r#"user.name="a" OR actor.user.name="a" | timechart span=1h count"#,
            r#"user.name="a" OR actor.user.name="a" | stats count by device.hostname"#,
            r#"user.name="a" OR user.name="b" OR actor.user.name="a" | stats count"#,
            r#"user.name="a" | stats count by device.hostname"#,
            r#"aa8d33751db6b0f228b42de63ca96014f340b32f94369d818b8095ebe5deb263 | stats count by metadata.log_source"#,
        ] {
            let plan = plan(query);
            assert!(
                plan.rollup_field.is_none() && plan.rollup_field_union.is_none() && !plan.rollup_group_by_source,
                "{query}: {plan:?}"
            );
        }
    }

    #[test]
    fn lake_rollup_exact_predicate_keeps_search_semantics() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let predicate = |kind: &'static str, values: &[&str]| LakeCountPredicate {
            kind,
            values: values.iter().map(|value| value.to_string()).collect(),
        };
        let exact = |field: &str, predicate: LakeCountPredicate| {
            lake_rollup_exact_predicate(&profile, field, Some(&predicate))
        };
        // Dotless host equality expands to the FQDN-inclusive form.
        assert_eq!(
            exact("device.hostname", predicate("eq", &["WS-1"])),
            Some(Some(predicate("host_eq", &["WS-1"])))
        );
        assert_eq!(
            exact("device.hostname", predicate("eq", &["ws-1.corp.local"])),
            Some(Some(predicate("eq", &["ws-1.corp.local"])))
        );
        // Its negated/set forms have no exact rollup form.
        assert_eq!(exact("device.hostname", predicate("ne", &["ws-1"])), None);
        assert_eq!(exact("device.hostname", predicate("in", &["ws-1", "ws-2.corp"])), None);
        // CIDR literals on IP fields are ranges; empty literals are emptiness tests.
        assert_eq!(exact("src_endpoint.ip", predicate("eq", &["10.0.0.0/8"])), None);
        assert_eq!(exact("user.name", predicate("eq", &[""])), None);
        assert_eq!(
            exact("src_endpoint.ip", predicate("eq", &["10.1.3.147"])),
            Some(Some(predicate("eq", &["10.1.3.147"])))
        );
        assert_eq!(
            exact("device.hostname", predicate("contains", &["ws"])),
            Some(Some(predicate("contains", &["ws"])))
        );
        assert_eq!(lake_rollup_exact_predicate(&profile, "device.hostname", None), Some(None));
        assert!(!lake_rollup_predicate_is_exact(&profile, "device.hostname", Some(&predicate("ne", &["ws-1"]))));
    }

    /// NAN-3153 routing on a lean cell: grouped pages go to the rollups only
    /// when every predicate and group is rollup-covered and exact.
    #[test]
    fn lake_cell_stats_route_uses_rollups_only_when_exact() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let route = |query: &str| {
            let parsed = parse_query(query).unwrap();
            lake_cell_stats_route(&profile, &parsed, lake_count_pipeline_plan(&parsed).as_ref())
        };
        for (query, expected) in lake_cell_stats_route_cases() {
            assert_eq!(route(query), expected, "{query}");
        }
    }

    /// The NAN-3153 lean-cell routing table (query, route) for an
    /// unrestricted caller.
    fn lake_cell_stats_route_cases() -> Vec<(&'static str, LakeCellStatsRoute)> {
        use LakeCellStatsRoute::*;
        vec![
            // Q6 steps 3 and 5 keep the existing count route.
            ("* | stats count by metadata.log_source", Default),
            ("* | timechart span=1h count by metadata.log_source", Default),
            (r#"device.hostname="ws-1" | timechart span=10m count"#, Default),
            (r#"user.name="svc_db" | stats count"#, Default),
            // Q6 steps 7, 10, 12 (and 31-33), and low-cardinality value groups.
            ("* | stats count by device.hostname | sort -count | head 10", RollupThenCompiledPage),
            ("metadata.log_source=windows_sysmon | stats count by process.name", RollupThenCompiledPage),
            (r#"user.name="svc_db" OR actor.user.name="svc_db" | stats count by metadata.log_source"#, RollupThenCompiledPage),
            (r#"device.hostname="ws-legal-096.corp.local" | stats count by metadata.log_source"#, RollupThenCompiledPage),
            (r#"device.hostname="ws-legal-096" | stats count by metadata.log_source"#, RollupThenCompiledPage),
            (r#"src_endpoint.ip="10.1.3.147" OR dst_endpoint.ip="10.1.3.147" | stats count by metadata.log_source"#, RollupThenCompiledPage),
            ("* | stats count by user.name | sort -count | head 20", RollupThenCompiledPage),
            (r#"file.hashes.value="abc" | stats count by metadata.log_source"#, CompiledPage),
            // Q6 step 34: a bare keyword is not in the rollups.
            ("aa8d33751db6b0f228b42de63ca96014f340b32f94369d818b8095ebe5deb263 | stats count by metadata.log_source", CompiledPage),
            // Broad IP top-N, inexact predicates, multi-value groups,
            // non-count aggregates and unknown fields keep the compiled page.
            ("* | stats count by src_endpoint.ip | sort -count | head 10", CompiledPage),
            // Q6 step 4 and other near-unique groups: the compiled page is cheaper.
            ("metadata.log_source=conduit_proxy | stats count by src_endpoint.ip | sort -count | head 10", CompiledPage),
            ("* | stats count by process.cmd_line", CompiledPage),
            ("* | stats count by dst_endpoint.port", CompiledPage),
            (r#"device.hostname!="ws-1" | stats count by metadata.log_source"#, CompiledPage),
            (r#"src_endpoint.ip="10.0.0.0/8" | stats count by metadata.log_source"#, CompiledPage),
            (r#"user.name="a" OR device.hostname!="ws-1" | stats count by metadata.log_source"#, CompiledPage),
            ("* | stats count by resources.hostname", CompiledPage),
            ("* | stats count by enrichments.value", CompiledPage),
            ("* | stats count by unmapped.custom_field", CompiledPage),
            (r#"user.name="a" | stats count, dc(device.hostname) by metadata.log_source"#, CompiledPage),
            (r#"user.name="a" | stats count by device.hostname"#, CompiledPage),
        ]
    }

    /// The query `search_primary_lake` plans for `query` from a caller whose
    /// deny set is `deny`: the source-scope gate injected into the text, then
    /// the text round trip `search_with_fetch_audit` makes before the call.
    fn lake_gated_query(query: &str, deny: &[&str]) -> Query {
        let deny = deny
            .iter()
            .map(|source| source.to_string())
            .collect::<BTreeSet<_>>();
        let gated = enforce_source_scope_with_field(query, &deny, LAKE_SOURCE_FIELD).unwrap();
        parse_query(&parse_query(&gated).unwrap().pretty_print()).unwrap()
    }

    /// NAN-3163: a caller with a non-empty deny set (everyone without
    /// `audit:view`) routes exactly like an unrestricted one. The injected
    /// gate used to hide every count rollup, so these searches fell to the
    /// compiled page or a raw count scan.
    #[test]
    fn lake_cell_stats_route_ignores_the_injected_source_scope_gate() {
        let profile = crate::schema::OcsfProfile::lake_1_9();
        for deny in [
            &["audit"][..],
            &["windows_sysmon"],
            &["audit", "conduit_proxy"],
        ] {
            let deny_set = deny
                .iter()
                .map(|source| source.to_string())
                .collect::<BTreeSet<_>>();
            for (query, expected) in lake_cell_stats_route_cases() {
                let gated = lake_gated_query(query, deny);
                assert_ne!(
                    gated,
                    parse_query(query).unwrap(),
                    "{query}: the gate is injected"
                );
                let scoped = lake_count_pipeline_plan_scoped(&gated, &deny_set);
                assert_eq!(
                    lake_cell_stats_route(&profile, &gated, scoped.as_ref()),
                    expected,
                    "{deny:?} {query}"
                );
                let unscoped = lake_count_pipeline_plan(&parse_query(query).unwrap());
                assert_eq!(
                    scoped.as_ref().map(|plan| &plan.aggregate),
                    unscoped.as_ref().map(|plan| &plan.aggregate),
                    "{deny:?} {query}"
                );
                // Everything executed stays gated: the aggregate query is the
                // unrestricted one plus exactly this caller's gate.
                if let (Some(scoped), Some(unscoped)) = (scoped.as_ref(), unscoped.as_ref()) {
                    assert_ne!(
                        scoped.aggregate_query, unscoped.aggregate_query,
                        "{deny:?} {query}"
                    );
                    assert_eq!(
                        strip_lake_source_scope_gate(&scoped.aggregate_query, &deny_set).as_ref(),
                        Some(&unscoped.aggregate_query),
                        "{deny:?} {query}"
                    );
                    assert_eq!(
                        scoped.post_commands, unscoped.post_commands,
                        "{deny:?} {query}"
                    );
                }
            }
        }
        // The live NAN-3163 probe.
        let probe =
            r#"device.hostname="ws-hr-132.corp.local" | stats count by metadata.log_source"#;
        let gated = lake_gated_query(probe, &["audit"]);
        let audit = BTreeSet::from(["audit".to_string()]);
        let plan = lake_count_pipeline_plan_scoped(&gated, &audit).unwrap();
        assert_eq!(
            plan.aggregate.rollup_field.as_deref(),
            Some("device.hostname")
        );
        assert!(plan.aggregate.rollup_group_by_source);
        assert_eq!(
            lake_cell_stats_route(&profile, &gated, Some(&plan)),
            LakeCellStatsRoute::RollupThenCompiledPage
        );
        // Unpatched planning of the same gated text lost the rollup.
        assert_eq!(
            lake_cell_stats_route(&profile, &gated, lake_count_pipeline_plan(&gated).as_ref()),
            LakeCellStatsRoute::CompiledPage
        );
    }

    /// NAN-3163: only the gate injected for THIS deny set is removed; a
    /// user-written `metadata.log_source` exclusion (even one shaped exactly
    /// like a gate) and a gate for another deny set stay.
    #[test]
    fn strip_lake_source_scope_gate_removes_only_the_injected_conjunct() {
        let set = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<BTreeSet<_>>()
        };
        let base = r#"device.hostname="h1" | stats count by metadata.log_source"#;
        // No deny set: nothing was injected, nothing is stripped.
        assert_eq!(
            strip_lake_source_scope_gate(&parse_query(base).unwrap(), &set(&[])),
            None
        );
        // A gate for another deny set is not this caller's gate.
        assert_eq!(
            strip_lake_source_scope_gate(&lake_gated_query(base, &["a"]), &set(&["b"])),
            None
        );
        assert_eq!(
            strip_lake_source_scope_gate(
                &lake_gated_query(base, &["audit"]),
                &set(&["a", "audit"])
            ),
            None
        );
        // A deny set naming Unattributed keeps the gated plan (NULL / empty
        // sources are excluded by the scan gate, not by a rollup filter).
        for deny in [&["default"][..], &["unknown"], &["audit", "Default"]] {
            assert_eq!(
                strip_lake_source_scope_gate(&lake_gated_query(base, deny), &set(deny)),
                None,
                "{deny:?}"
            );
        }
        // User-written source exclusions survive, whether or not they look
        // like the gate; only the outer injected conjunct goes.
        for user in [
            r#"device.hostname="h1" metadata.log_source NOT IN ("windows_sysmon") | stats count by metadata.log_source"#,
            r#"(device.hostname="h1") metadata.log_source NOT IN ("windows_sysmon") | stats count by metadata.log_source"#,
            r#"(device.hostname="h1") metadata.log_source!="audit" | stats count by metadata.log_source"#,
        ] {
            for deny in [&["audit"][..], &["windows_sysmon"]] {
                let stripped =
                    strip_lake_source_scope_gate(&lake_gated_query(user, deny), &set(deny))
                        .unwrap();
                assert_eq!(
                    stripped,
                    parse_query(&parse_query(user).unwrap().pretty_print()).unwrap(),
                    "{deny:?} {user}"
                );
                // ...so they keep the route they have unrestricted.
                let profile = crate::schema::OcsfProfile::lake_1_9();
                let unrestricted = parse_query(user).unwrap();
                assert_eq!(
                    lake_cell_stats_route(
                        &profile,
                        &lake_gated_query(user, deny),
                        lake_count_pipeline_plan_scoped(&lake_gated_query(user, deny), &set(deny))
                            .as_ref()
                    ),
                    lake_cell_stats_route(
                        &profile,
                        &unrestricted,
                        lake_count_pipeline_plan(&unrestricted).as_ref()
                    ),
                    "{deny:?} {user}"
                );
            }
        }
    }

    /// NAN-3166: the exact count-metrics route ignores the injected gate for
    /// the caller's own deny set, so a scoped caller plans exactly like an
    /// unrestricted one; user-written source filters stay in the plan, and
    /// deny sets naming Unattributed keep the gated plan.
    #[test]
    fn lake_count_metrics_plan_ignores_the_injected_source_scope_gate() {
        let set = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<BTreeSet<_>>()
        };
        let served = [
            r#"* | eval is_int = if(src_endpoint.ip != "", 1, 0) | stats sum(is_int) as internal, count() as total"#,
            r#"metadata.log_source="conduit_proxy" | eval is_int = if(src_endpoint.ip != "", 1, 0) | stats sum(is_int) as internal, count() as total"#,
            r#"metadata.log_source=audit | eval is_int = if(src_endpoint.ip != "", 1, 0) | stats sum(is_int) as internal, count() as total"#,
        ];
        let unserved = [
            // A user-written source exclusion is a row filter the metrics
            // cannot express; it is not mistaken for the gate.
            r#"metadata.log_source!="audit" | eval is_int = if(src_endpoint.ip != "", 1, 0) | stats sum(is_int) as internal, count() as total"#,
            r#"powershell | eval is_int = if(src_endpoint.ip != "", 1, 0) | stats sum(is_int) as internal, count() as total"#,
            "* | stats count() as total",
        ];
        for deny in [
            &["audit"][..],
            &["windows_sysmon"],
            &["audit", "conduit_proxy"],
        ] {
            for query in served.iter().chain(unserved.iter()) {
                let gated = lake_gated_query(query, deny);
                assert_ne!(gated, parse_query(query).unwrap(), "{query}: the gate is injected");
                let scoped = lake_count_metrics_plan_scoped(&gated, &set(deny));
                let unrestricted = lake_count_metrics_plan(&parse_query(query).unwrap());
                assert_eq!(scoped, unrestricted, "{deny:?} {query}");
                assert_eq!(scoped.is_some(), served.contains(query), "{deny:?} {query}");
            }
            // Unpatched planning of the gated text lost the route.
            for query in served {
                assert!(lake_count_metrics_plan(&lake_gated_query(query, deny)).is_none(), "{query}");
            }
        }
        // The user's own source filter rides in the plan.
        let plan = lake_count_metrics_plan_scoped(
            &lake_gated_query(served[1], &["audit"]),
            &set(&["audit"]),
        )
        .unwrap();
        assert_eq!(plan.metrics[0].source_filter.as_deref(), Some("conduit_proxy"));
        assert_eq!(
            plan.metrics[1].predicate.as_ref().map(|predicate| predicate.values.clone()),
            Some(vec!["conduit_proxy".to_string()])
        );
        // Unattributed deny sets are never stripped: the gated plan stands.
        for deny in [&["default"][..], &["unknown"], &["audit", "Default"]] {
            for query in served {
                let gated = lake_gated_query(query, deny);
                assert_eq!(
                    lake_count_metrics_plan_scoped(&gated, &set(deny)),
                    lake_count_metrics_plan(&gated),
                    "{deny:?} {query}"
                );
                assert!(lake_count_metrics_plan_scoped(&gated, &set(deny)).is_none());
            }
        }
    }

    /// NAN-4295: `count by <array leaf>` must group by each element. The
    /// worker's typed count groups by the whole array (`['T1110']`, `[null]`)
    /// and the multi-value rollups never serve grouped results, so such a
    /// plan is refused and the compiled page (arrayJoin) answers. Ungrouped
    /// and scalar-grouped counts keep their plans.
    #[test]
    fn lake_count_plan_refuses_array_group_by() {
        let profile = OcsfProfile::lake_1_9();
        let none = BTreeSet::new();
        let plan = |query: &str| lake_count_pipeline_plan_for(&profile, &parse_query(query).unwrap(), &none);
        assert_eq!(
            crate::schema::SchemaProfile::field_type(&profile, "module.file.signatures.algorithm_id"),
            Some(crate::schema::FieldType::Array)
        );
        for query in [
            "* | stats count by privileges",
            "* | stats count by file.hashes.value",
            "* | stats count by finding_info.attacks.technique.uid",
            // A non-string repeated leaf (integer_t under a repeated object).
            "* | stats count by module.file.signatures.algorithm_id",
            "source_type=windows_sysmon | stats count by metadata.log_source, resources.hostname",
        ] {
            assert!(plan(query).is_none(), "{query}");
        }
        for query in [
            "* | stats count by src_endpoint.ip",
            "* | stats count by metadata.log_source",
            "file.hashes.value=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 | stats count",
        ] {
            assert!(plan(query).is_some(), "{query}");
        }
    }

    /// NAN-3883: `* | stats count(source_type) by source_type` (and
    /// `count by source_type`) scanned 30 days (177 s, escalated) while the
    /// same counts by `metadata.log_source` came from the rollups in 0.2 s.
    /// The stats command is now planned in its rollup spelling too, and the
    /// rollup rows are renamed back to the caller's column.
    #[test]
    fn lake_rollup_plans_stats_by_source_type_and_count_of_the_group_field() {
        let profile = OcsfProfile::lake_1_9();
        let none = BTreeSet::new();
        let planned = |query: &str| {
            let parsed = parse_query(query).unwrap();
            let plan = lake_count_pipeline_plan_for(&profile, &parsed, &none)
                .unwrap_or_else(|| panic!("{query}"));
            // The raw fallback runs the caller's text up to the stats command;
            // post commands are split off into `post_commands`.
            let mut stats_text = parsed;
            for _ in 0..plan.post_commands.len() {
                let Query::Piped { source, .. } = stats_text else { panic!("{query}") };
                stats_text = *source;
            }
            assert_eq!(plan.aggregate_query, stats_text, "the raw fallback runs the caller's text: {query}");
            plan
        };
        for (query, group, alias, counts_group_field) in [
            ("* | stats count by source_type", "source_type", "count", false),
            ("* | stats count(source_type) by source_type", "source_type", "count", true),
            ("* | stats count(source_type) as n by source_type", "source_type", "n", true),
            ("* | stats count(sourcetype) by source_type", "source_type", "count", true),
            ("* | stats count(metadata.log_source) by metadata.log_source", "metadata.log_source", "count", true),
        ] {
            let plan = planned(query);
            assert_eq!(plan.aggregate.group_by, vec![group.to_string()], "{query}");
            assert_eq!(plan.aggregate.count_alias, alias, "{query}");
            let (field, predicate) = lake_count_rollup_request(&profile, &plan.aggregate)
                .unwrap_or_else(|| panic!("{query} must be a rollup request"));
            assert_eq!(field, "metadata.log_source", "{query}");
            assert!(predicate.is_none(), "{query}");
            let spelling = plan.aggregate.output_spelling.as_ref().unwrap();
            assert_eq!(spelling.rollup_group, "metadata.log_source", "{query}");
            assert_eq!(spelling.caller_group, group, "{query}");
            assert_eq!(spelling.counts_group_field, counts_group_field, "{query}");
        }

        // Post commands still see the caller's column.
        let sorted = planned("* | stats count(source_type) by source_type | sort -count | head 5");
        assert_eq!(sorted.aggregate.group_by, vec!["source_type".to_string()]);
        assert_eq!(sorted.post_commands.len(), 2);

        // Already the rollup spelling: unchanged plan, no renaming.
        let canonical = planned("* | stats count by metadata.log_source");
        assert!(canonical.aggregate.output_spelling.is_none());

        // A scoped caller plans the same rollup; the gate stays in the text.
        let deny = ["audit".to_string()].into_iter().collect::<BTreeSet<_>>();
        let gated = lake_gated_query("* | stats count(source_type) by source_type", &["audit"]);
        let scoped = lake_count_pipeline_plan_for(&profile, &gated, &deny).unwrap();
        assert_eq!(scoped.aggregate, planned("* | stats count(source_type) by source_type").aggregate);
        assert_eq!(scoped.aggregate_query, gated);

        // Counting a different field than the group is not a row count.
        for query in [
            "* | stats count(process.name) by source_type",
            "* | stats count(eval(severity_id > 3)) by source_type",
            "* | stats dc(source_type) by source_type",
        ] {
            let parsed = parse_query(query).unwrap();
            if let Some(plan) = lake_count_pipeline_plan_for(&profile, &parsed, &none) {
                assert_eq!(plan.aggregate_query, parsed, "{query}");
                assert!(lake_count_rollup_request(&profile, &plan.aggregate).is_none(), "{query}");
            }
        }
    }

    #[test]
    fn lake_rollup_output_spelling_renames_rows_and_refuses_a_null_count_group() {
        let spelling = LakeRollupOutputSpelling {
            rollup_group: "metadata.log_source".to_string(),
            caller_group: "source_type".to_string(),
            counts_group_field: false,
        };
        let mut rows = vec![
            serde_json::json!({"metadata.log_source": "windows_sysmon", "count": 7}),
            serde_json::json!({"metadata.log_source": null, "count": 2}),
        ];
        assert!(lake_apply_rollup_output_spelling(&mut rows, &spelling));
        assert_eq!(rows[0], serde_json::json!({"source_type": "windows_sysmon", "count": 7}));
        // `count by F` counts a NULL group's rows like the scan does.
        assert_eq!(rows[1], serde_json::json!({"source_type": null, "count": 2}));

        // `count(F) by F`: a NULL group counts 0 in the scan, so the rollup
        // answer is refused (the caller scans) rather than guessed.
        let counted = LakeRollupOutputSpelling { counts_group_field: true, ..spelling };
        let mut rows = vec![
            serde_json::json!({"metadata.log_source": "windows_sysmon", "count": 7}),
            serde_json::json!({"metadata.log_source": null, "count": 2}),
        ];
        assert!(!lake_apply_rollup_output_spelling(&mut rows, &counted));
        let mut rows = vec![serde_json::json!({"metadata.log_source": "apache_access", "count": 3})];
        assert!(lake_apply_rollup_output_spelling(&mut rows, &counted));
        assert_eq!(rows[0], serde_json::json!({"source_type": "apache_access", "count": 3}));
    }

    /// NAN-3780: `source_type IN (…) | stats count` (a CT 106 steady-state
    /// probe, and any lean user typing the UDM spelling) asked the worker for
    /// a count rollup on `source_type`, which the rollups do not key by; the
    /// worker refused it, the lake cell logged `outcome=error`, and search
    /// warned and scanned. The lake profile compiles `source_type` to
    /// `metadata.log_source`, which every rollup row carries (field 0), so
    /// the plan now asks for that rollup; a field the rollups do not cover
    /// is never sent at all.
    #[test]
    fn lake_rollup_plans_source_type_as_the_log_source_rollup() {
        let profile = OcsfProfile::lake_1_9();
        let none = BTreeSet::new();
        let query = "source_type IN (windows_sysmon, windows_event, conduit_proxy, apache_access) | stats count";
        let parsed = parse_query(query).unwrap();
        let plan = lake_count_pipeline_plan_for(&profile, &parsed, &none).unwrap();
        assert_eq!(plan.aggregate_query, parsed, "the raw fallback runs the caller's own text");
        assert!(plan.aggregate.group_by.is_empty());
        let (field, predicate) = lake_count_rollup_request(&profile, &plan.aggregate).unwrap();
        assert_eq!(field, "metadata.log_source");
        let predicate = predicate.expect("the IN list rides as the rollup predicate");
        assert_eq!(predicate.kind, "in");
        assert_eq!(
            predicate.values,
            ["windows_sysmon", "windows_event", "conduit_proxy", "apache_access"]
        );
        // Unpatched planning named the uncovered `source_type` rollup...
        let unpatched = lake_count_pipeline_plan_scoped(&parsed, &none).unwrap();
        assert_eq!(unpatched.aggregate.rollup_field.as_deref(), Some("source_type"));
        // ...which is now never requested: the caller scans directly.
        assert!(lake_count_rollup_request(&profile, &unpatched.aggregate).is_none());

        // A scoped caller plans the same rollup; the gate stays in the text.
        let deny = ["audit".to_string()].into_iter().collect::<BTreeSet<_>>();
        let gated = lake_gated_query(query, &["audit"]);
        let scoped = lake_count_pipeline_plan_for(&profile, &gated, &deny).unwrap();
        assert_eq!(scoped.aggregate, plan.aggregate);
        assert_eq!(scoped.aggregate_query, gated);

        // Other spellings and shapes of the same pivot.
        for (query, field, kind, source) in [
            ("sourcetype=windows_sysmon | stats count", "metadata.log_source", Some("eq"), None),
            ("source_type!=audit | stats count", "metadata.log_source", Some("ne"), None),
            (
                "source_type=windows_sysmon | stats count by metadata.log_source",
                "metadata.log_source",
                None,
                Some("windows_sysmon"),
            ),
            (
                "source_type=windows_sysmon src_ip=10.0.0.5 | stats count",
                "src_endpoint.ip",
                Some("eq"),
                Some("windows_sysmon"),
            ),
        ] {
            let parsed = parse_query(query).unwrap();
            let plan = lake_count_pipeline_plan_for(&profile, &parsed, &none)
                .unwrap_or_else(|| panic!("{query}"));
            assert_eq!(plan.aggregate_query, parsed, "{query}");
            let (rollup_field, predicate) = lake_count_rollup_request(&profile, &plan.aggregate)
                .unwrap_or_else(|| panic!("{query}"));
            assert_eq!(rollup_field, field, "{query}");
            assert_eq!(predicate.map(|predicate| predicate.kind), kind, "{query}");
            assert_eq!(plan.aggregate.rollup_source_filter.as_deref(), source, "{query}");
        }

        // An uncovered field is never a rollup request. A class-split alias
        // (`process_name` = `process.name` OR `actor.process.name` by class)
        // is not one rollup field, so it keeps its spelling and scans.
        // (NAN-3883: `by source_type` IS the log-source rollup now, renamed
        // back to the caller's column; see the test below.)
        for query in [
            "source_type=windows_sysmon process_name=cmd.exe | stats count",
            "not_a_rollup_field=1 | stats count",
            "source_type=windows_sysmon | stats count by not_a_rollup_field",
        ] {
            let parsed = parse_query(query).unwrap();
            if let Some(plan) = lake_count_pipeline_plan_for(&profile, &parsed, &none) {
                assert_eq!(plan.aggregate_query, parsed, "{query}");
                assert!(lake_count_rollup_request(&profile, &plan.aggregate).is_none(), "{query}");
            }
        }

        // Count metrics whose field the rollups refuse take the general path.
        assert!(lake_count_metrics_plan(
            &parse_query(r#"* | eval hit = if(not_a_rollup_field != "", 1, 0) | stats sum(hit) as hits, count() as total"#)
                .unwrap()
        )
        .is_none());

        // The histogram companion of the same search uses the rollup too.
        let histogram = |query: &str| {
            lake_histogram_rollup_plan(&lake_rollup_planning_query(
                &profile,
                &parse_query(query).unwrap(),
            ))
        };
        let companion = histogram(
            "source_type IN (windows_sysmon, apache_access) | timechart span=5m count() as count",
        )
        .unwrap();
        assert_eq!(companion.field, "metadata.log_source");
        assert_eq!(companion.predicate.map(|predicate| predicate.kind), Some("in"));
        assert!(lake_histogram_rollup_plan(
            &parse_query("source_type IN (windows_sysmon) | timechart span=5m count() as count")
                .unwrap()
        )
        .is_none());

        // Only the lake profile rewrites; ClickHouse keeps the text.
        assert_eq!(lake_rollup_planning_query(&OcsfProfile::new(), &parsed), parsed);
    }

    /// NAN-3166: the distinct-state route is planned on the gated text and
    /// stays gated. It accepts any base search, so the gate never changes
    /// its route; its aggregate query is executed and must keep the gate,
    /// for every deny set (Unattributed included).
    #[test]
    fn lake_distinct_pipeline_plan_routes_the_gated_query_unchanged() {
        let set = |items: &[&str]| {
            items
                .iter()
                .map(|item| item.to_string())
                .collect::<BTreeSet<_>>()
        };
        let queries = [
            r#"* | where src_endpoint.ip!="" | stats dc(dst_endpoint.ip) as peers by src_endpoint.ip | where peers>1 | sort -peers | head 10"#,
            r#"user.name="a" | stats dc(device.hostname) as hosts, values(device.hostname), count() as n by user.name"#,
            r#"metadata.log_source=windows_sysmon | stats dc(device.hostname) as hosts"#,
            r#"metadata.log_source!="audit" | stats dc(device.hostname) as hosts by user.name"#,
            r#"* | stats dc(process.cmd_line) as cmds"#,
        ];
        for deny in [
            &["audit"][..],
            &["windows_sysmon"],
            &["audit", "conduit_proxy"],
            &["default"],
        ] {
            for query in queries {
                let gated = lake_gated_query(query, deny);
                let scoped = lake_distinct_pipeline_plan(&gated);
                let unrestricted = lake_distinct_pipeline_plan(&parse_query(query).unwrap());
                assert_eq!(scoped.is_some(), unrestricted.is_some(), "{deny:?} {query}");
                let (Some(scoped), Some(unrestricted)) = (scoped, unrestricted) else {
                    continue;
                };
                assert_eq!(scoped.group_by, unrestricted.group_by, "{deny:?} {query}");
                assert_eq!(scoped.output_alias, unrestricted.output_alias);
                assert_eq!(scoped.values_output_alias, unrestricted.values_output_alias);
                assert_eq!(scoped.count_output_alias, unrestricted.count_output_alias);
                assert_eq!(scoped.post_commands, unrestricted.post_commands);
                // The executed query keeps exactly this caller's gate, so a
                // denied source can never be counted.
                assert_ne!(scoped.aggregate_query, unrestricted.aggregate_query);
                assert!(
                    scoped
                        .aggregate_query
                        .pretty_print()
                        .contains("metadata.log_source"),
                    "{deny:?} {}",
                    scoped.aggregate_query.pretty_print()
                );
                if deny != &["default"][..] {
                    assert_eq!(
                        strip_lake_source_scope_gate(&scoped.aggregate_query, &set(deny)).as_ref(),
                        Some(&unrestricted.aggregate_query),
                        "{deny:?} {query}"
                    );
                }
            }
        }
    }

    #[test]
    fn lake_field_union_combination_is_exact_per_source() {
        let counts = |pairs: &[(Option<&str>, u64)]| {
            pairs
                .iter()
                .map(|(source, count)| (source.map(str::to_string), *count))
                .collect::<BTreeMap<_, _>>()
        };
        let left = counts(&[(Some("proxy"), 5), (Some("sysmon"), 2), (None, 1)]);
        let right = counts(&[(Some("proxy"), 3), (Some("cloudtrail"), 4)]);
        let combination = lake_field_union_combination(&left, &right).unwrap();
        // Disjoint sources sum exactly; a source matched by both sides needs a scan.
        assert_eq!(combination.disjoint, counts(&[(Some("sysmon"), 2), (Some("cloudtrail"), 4), (None, 1)]));
        assert_eq!(combination.overlap, BTreeSet::from(["proxy".to_string()]));
        // A NULL source on both sides cannot be narrowed to: no exact answer.
        assert!(lake_field_union_combination(&counts(&[(None, 1)]), &counts(&[(None, 2)])).is_none());
        let mut by_source = combination.disjoint;
        by_source.insert(Some("proxy".to_string()), 6);
        let rows = lake_field_union_rows(by_source.clone(), true, "count").unwrap();
        assert_eq!(
            rows,
            vec![
                serde_json::json!({"count": 6, "metadata.log_source": "proxy"}),
                serde_json::json!({"count": 4, "metadata.log_source": "cloudtrail"}),
                serde_json::json!({"count": 2, "metadata.log_source": "sysmon"}),
                serde_json::json!({"count": 1, "metadata.log_source": null}),
            ]
        );
        assert_eq!(lake_field_union_rows(by_source, false, "n").unwrap(), vec![serde_json::json!({"n": 13})]);
        assert_eq!(lake_field_union_rows(BTreeMap::new(), false, "count").unwrap(), vec![serde_json::json!({"count": 0})]);
        assert!(lake_field_union_rows(BTreeMap::new(), true, "count").unwrap().is_empty());
        assert_eq!(
            lake_source_counts(&rows_from(&[("proxy", "7"), ("proxy", "1")]), "count").unwrap(),
            counts(&[(Some("proxy"), 8)])
        );
        assert!(lake_source_counts(&[serde_json::json!({"metadata.log_source": 3, "count": 1})], "count").is_err());

        fn rows_from(pairs: &[(&str, &str)]) -> Vec<serde_json::Value> {
            pairs.iter().map(|(source, count)| serde_json::json!({"metadata.log_source": source, "count": count})).collect()
        }
    }

    /// The overlap scan's narrowed query must survive the wire (pretty-print
    /// then re-parse) with the original predicate intact.
    #[test]
    fn lake_field_union_overlap_query_round_trips() {
        let original = parse_query(
            r#"src_endpoint.ip="10.1.3.147" OR dst_endpoint.ip="10.1.3.147" | stats count by metadata.log_source"#,
        )
        .unwrap();
        let Query::Piped { source, command: Command::Stats { aggregations, .. } } = &original else {
            panic!("stats pipeline");
        };
        let Query::Search(search) = source.as_ref() else { panic!("search") };
        let narrowed = Query::Piped {
            source: Box::new(Query::Search(SearchExpr::And(
                Box::new(SearchExpr::Group(Box::new(search.clone()))),
                Box::new(SearchExpr::InList {
                    field: LAKE_SOURCE_FIELD.to_string(),
                    values: vec![Value::String("conduit_proxy".into()), Value::String("edr".into())],
                    negated: false,
                }),
            ))),
            command: Command::Stats {
                aggregations: aggregations.clone(),
                group_by: Some(vec![LAKE_SOURCE_FIELD.to_string()]),
            },
        };
        let printed = narrowed.pretty_print();
        let reparsed = parse_query(&printed).unwrap();
        assert_eq!(reparsed.pretty_print(), printed, "{printed}");
        let Query::Piped { source, .. } = &reparsed else { panic!("{printed}") };
        let Query::Search(SearchExpr::And(left, right)) = source.as_ref() else { panic!("{printed}") };
        assert!(matches!(right.as_ref(), SearchExpr::InList { field, negated: false, .. } if field == LAKE_SOURCE_FIELD), "{printed}");
        let mut inner = left.as_ref();
        while let SearchExpr::Group(group) = inner {
            inner = group.as_ref();
        }
        assert!(matches!(inner, SearchExpr::Or(..)), "{printed}");
    }

    #[test]
    fn lake_count_rollup_recognizes_source_predicate_union() {
        let parsed = parse_query(
            r#"metadata.log_source="audit" OR file.hashes.value="02580eb1cc489f0359e3008b62c8dee14183b9252c81bf638ed4d911fe624ae2" | stats count as events"#,
        )
        .unwrap();
        let plan = lake_count_stats_plan(&parsed).unwrap();
        assert!(plan.rollup_field.is_none());
        assert_eq!(
            plan.rollup_union,
            Some(LakeCountUnionPlan {
                source: "audit".to_string(),
                field: "file.hashes.value".to_string(),
                predicate: LakeCountPredicate {
                    kind: "eq",
                    values: vec![
                        "02580eb1cc489f0359e3008b62c8dee14183b9252c81bf638ed4d911fe624ae2"
                            .to_string(),
                    ],
                },
            })
        );
    }

    fn rejected_scan(estimated: u64) -> SearchError {
        SearchError::ResourceExhausted(format!(
            "scan; estimated_bytes={estimated}; budget_bytes=100000000"
        ))
    }

    #[test]
    fn lake_slice_retries_stop_constant_estimates_within_three_attempts() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-08-11T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let range = TimeRangeInput {
            start,
            end: start + chrono::Duration::days(1),
        };
        for query in [
            "* | stats count by src_endpoint.ip",
            "* | stats dc(user.name)",
            "*",
        ] {
            let mut retries = LakeSliceRetries::new();
            let (left, _) = retries
                .split("0", &range, rejected_scan(720_000_000), query)
                .unwrap();
            let error = retries
                .split("0l", &left, rejected_scan(720_000_000), query)
                .unwrap_err();
            assert_eq!(retries.scheduled, 3);
            assert!(
                error
                    .to_string()
                    .contains("slice needs 720.00 MB, budget 100.00 MB")
            );
            assert!(interactive_lake_fallback(&error));
        }
    }

    #[test]
    fn lake_slice_stop_does_not_promote_nano_side_suffixes() {
        let start = chrono::Utc::now();
        let range = TimeRangeInput {
            start,
            end: start + chrono::Duration::seconds(30),
        };
        let error = LakeSliceRetries::new().split("0", &range, rejected_scan(720_000_000),
            "* | stats count by src_endpoint.ip | lookup iocs src_endpoint.ip OUTPUT confidence").unwrap_err();
        assert!(!interactive_lake_fallback(&error));
        assert!(
            error
                .to_string()
                .contains("slice needs 720.00 MB, budget 100.00 MB")
        );
    }

    #[test]
    fn lake_slice_retries_require_quarter_reduction_and_minute_window() {
        let start = chrono::Utc::now();
        let range = TimeRangeInput {
            start,
            end: start + chrono::Duration::hours(1),
        };
        let mut retries = LakeSliceRetries::new();
        let (left, _) = retries
            .split("0", &range, rejected_scan(800_000_000), "*")
            .unwrap();
        let (left, _) = retries
            .split("0l", &left, rejected_scan(600_000_000), "*")
            .unwrap();
        assert!(
            retries
                .split("0ll", &left, rejected_scan(450_000_001), "*")
                .is_err()
        );
        let mut retries = LakeSliceRetries::new();
        let short = TimeRangeInput {
            start,
            end: start + chrono::Duration::seconds(59),
        };
        assert!(
            retries
                .split("0", &short, rejected_scan(800_000_000), "*")
                .is_err()
        );
        assert_eq!(retries.scheduled, 1);
    }

    #[test]
    fn lake_slice_retries_cap_total_attempts_and_legacy_workers() {
        let start = chrono::Utc::now();
        let range = TimeRangeInput {
            start,
            end: start + chrono::Duration::days(1),
        };
        let mut retries = LakeSliceRetries::new();
        let mut pending =
            std::collections::VecDeque::from([("0".to_string(), range.clone(), 1_u64 << 60)]);
        let mut attempts = 0;
        while let Some((path, range, bytes)) = pending.pop_front() {
            attempts += 1;
            match retries.split(&path, &range, rejected_scan(bytes), "*") {
                Ok((left, right)) => {
                    pending.push_back((format!("{path}l"), left, bytes / 2));
                    pending.push_back((format!("{path}r"), right, bytes / 2));
                }
                Err(_) => break,
            }
        }
        assert!(attempts <= 64);
        assert_eq!(retries.scheduled, 63);
        let mut retries = LakeSliceRetries::new();
        let legacy = || SearchError::ResourceExhausted("scan".into());
        let (left, _) = retries.split("0", &range, legacy(), "*").unwrap();
        assert!(retries.split("0l", &left, legacy(), "*").is_ok());
        assert_eq!(
            lake_scan_budget_bytes(&SearchError::SqlValidationError(
                "query scan budget rejected 720 bytes above 100".into()
            )),
            Some((720, 100))
        );
    }

    #[test]
    fn legacy_scan_recovery_splits_a_thirty_day_identity_window() {
        let start = chrono::Utc::now();
        let mut retries = LakeSliceRetries::new();
        let mut pending = vec![("0".to_string(), TimeRangeInput { start, end: start + chrono::Duration::days(30) })];
        let mut completed = 0;
        while let Some((path, range)) = pending.pop() {
            if range.end - range.start <= chrono::Duration::days(1) {
                completed += 1;
            } else {
                let (left, right) = retries.split(&path, &range, SearchError::ResourceExhausted("scan".into()), "*").unwrap();
                pending.push((format!("{path}l"), left));
                pending.push((format!("{path}r"), right));
            }
        }
        assert_eq!(completed, 32);
        assert_eq!(retries.scheduled, 63);
    }

    #[test]
    fn lake_distributed_stats_bisection_is_disjoint() {
        let start = chrono::DateTime::parse_from_rfc3339("2026-08-11T18:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let end = chrono::DateTime::parse_from_rfc3339("2026-08-12T18:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let (left, right) = split_lake_aggregate_range(&TimeRangeInput { start, end }).unwrap();
        assert_eq!(left.start, start);
        // NAN-4280: half-open halves share the split instant.
        assert_eq!(left.end, right.start);
        assert_eq!(right.end, end);
    }

    #[test]
    fn lake_distributed_stats_only_retries_scan_budget_rejections() {
        assert!(is_lake_scan_budget_rejection(
            &SearchError::ResourceExhausted("scan".to_string())
        ));
        assert!(is_lake_scan_budget_rejection(
            &SearchError::SqlValidationError(
                "lake query rejected: request is invalid: query scan budget rejected 288293407 bytes above 268435456"
                    .to_string(),
            )
        ));
        assert!(!is_lake_scan_budget_rejection(
            &SearchError::SqlValidationError("lake query rejected: invalid field".to_string())
        ));
        assert!(!is_lake_scan_budget_rejection(
            &SearchError::ResourceExhausted("memory".to_string())
        ));
    }

    #[test]
    fn lake_identity_context_writes_canonical_ocsf_and_preserves_observed_values() {
        let mut event = serde_json::json!({
            "src_endpoint": {"ip": "10.1.1.1", "hostname": "observed-host"},
            "user": {"name": ""}
        });

        set_lake_ocsf_value_if_empty(&mut event, "src_endpoint.hostname", "derived-host");
        set_lake_ocsf_value_if_empty(&mut event, "src_endpoint.mac", "00:11:22:33:44:55");
        set_lake_ocsf_value_if_empty(&mut event, "user.name", "jsmith");

        assert_eq!(event["src_endpoint"]["hostname"], "observed-host");
        assert_eq!(event["src_endpoint"]["mac"], "00:11:22:33:44:55");
        assert_eq!(event["user"]["name"], "jsmith");
        assert!(event.get("identity_name").is_none());
        assert!(event.get("identity_hostname").is_none());
    }

    #[test]
    fn strict_tree_presets_use_canonical_ocsf_and_accept_product_aliases() {
        let mut process = parse_query("error | tree process root=\"cmd.exe\"").unwrap();
        assert_eq!(
            process.pretty_print(),
            "error | tree process root=\"cmd.exe\""
        );
        apply_profile_product_semantics(&mut process, &OcsfProfile::lake_1_9());
        let info = extract_tree_command(&process).unwrap();
        assert_eq!(info.parent_field, "actor.process.uid");
        assert_eq!(info.child_field, "process.uid");
        assert_eq!(info.label_field, "process.name");
        assert_eq!(info.detail_field.as_deref(), Some("process.cmd_line"));
        assert_eq!(
            info.prevalence_field.as_deref(),
            Some("process.file.hashes.value")
        );
        validate_query_field_names(&process, &OcsfProfile::lake_1_9()).unwrap();

        let mut web = parse_query("error | tree web").unwrap();
        apply_profile_product_semantics(&mut web, &OcsfProfile::lake_1_9());
        let info = extract_tree_command(&web).unwrap();
        assert_eq!(info.parent_field, "http_request.referrer");
        assert_eq!(info.child_field, "http_request.url.url_string");
        assert_eq!(info.label_field, "http_request.url.hostname");

        let mut explicit_udm = parse_query(
            "error | tree parent=parent_process_guid child=process_guid label=process_name \
             detail=command_line prevalence=process_hash",
        )
        .unwrap();
        apply_profile_product_semantics(&mut explicit_udm, &OcsfProfile::lake_1_9());
        let info = extract_tree_command(&explicit_udm).unwrap();
        assert_eq!(info.parent_field, "parent_process_guid");
        // NAN-2447: explicit product aliases resolve through the lake profile.
        validate_query_field_names(&explicit_udm, &OcsfProfile::lake_1_9()).unwrap();
    }

    #[test]
    fn strict_identity_default_is_canonical_and_explicit_product_alias_is_accepted() {
        let mut default = parse_query("error | resolve_identity").unwrap();
        apply_profile_product_semantics(&mut default, &OcsfProfile::lake_1_9());
        assert_eq!(default.pretty_print(), "error | resolve_identity");
        assert!(matches!(
            get_semantic_terminal_command(&default),
            Some(Command::ResolveIdentity {
                field,
                field_is_default: true,
                ..
            }) if field == "src_endpoint.ip"
        ));
        validate_query_field_names(&default, &OcsfProfile::lake_1_9()).unwrap();

        let mut explicit = parse_query("error | resolve_identity field=src_ip").unwrap();
        apply_profile_product_semantics(&mut explicit, &OcsfProfile::lake_1_9());
        assert!(matches!(
            get_semantic_terminal_command(&explicit),
            Some(Command::ResolveIdentity {
                field,
                field_is_default: false,
                ..
            }) if field == "src_ip"
        ));
        // NAN-2447: explicit product aliases are valid without rewriting the AST.
        validate_query_field_names(&explicit, &OcsfProfile::lake_1_9()).unwrap();
    }

    #[test]
    fn command_page_marker_is_storage_independent() {
        let services = parse_query("error | services").unwrap();
        assert_eq!(
            command_page_marker(&services).unwrap(),
            serde_json::json!({ "_display_type": "services" })
        );

        let service = parse_query("error | service checkout-api").unwrap();
        assert_eq!(
            command_page_marker(&service).unwrap(),
            serde_json::json!({
                "_display_type": "service",
                "_service": "checkout-api"
            })
        );
    }

    /// NAN-2344: a stats request with `limit=60` keeps the independent 1M
    /// aggregate-output guard and pages only its completed output.
    #[test]
    fn aggregation_limit_plan_pages_output_not_input() {
        let plan = sql_limit_plan(false, true, false, false, 1_000_000, 60, 120);
        assert_eq!(
            plan,
            SqlLimitPlan {
                generator_limit: Some(AGGREGATE_OUTPUT_CAP),
                execution_limit: 60,
                execution_offset: 120,
                page_after_post_processing: false,
            }
        );

        // Raw pagination remains executor-owned.
        assert_eq!(
            sql_limit_plan(true, false, false, false, 60, 60, 120),
            SqlLimitPlan {
                generator_limit: None,
                execution_limit: 60,
                execution_offset: 120,
                page_after_post_processing: false,
            }
        );
    }

    /// An aggregation stripped from SQL must fetch raw input from offset zero,
    /// retain its internal safety cap, and defer request pagination until Rust
    /// has completed grouping/sorting/head semantics.
    #[test]
    fn deferred_aggregation_limit_plan_pages_after_rust_processing() {
        assert_eq!(
            sql_limit_plan(false, false, false, true, 1_000_000, 60, 120),
            SqlLimitPlan {
                generator_limit: Some(1_000_000),
                execution_limit: 1_000_000,
                execution_offset: 0,
                page_after_post_processing: true,
            }
        );
    }

    #[test]
    fn sql_aggregation_before_rust_suffix_fetches_cap_then_pages_in_rust() {
        assert_eq!(
            sql_limit_plan(false, true, true, false, 10, 60, 120),
            SqlLimitPlan {
                generator_limit: Some(AGGREGATE_OUTPUT_CAP),
                execution_limit: AGGREGATE_OUTPUT_CAP,
                execution_offset: 0,
                page_after_post_processing: true,
            }
        );

        for query in [
            "* | stats count by dest_ip | prevalence enrich=true",
            r#"* | stats count by dest_ip | inputlookup url="https://example.com/{dest_ip}" key=dest_ip"#,
            "* | stats count by src_host | lateral entity=src_host",
            r#"* | stats count by dest_ip | ai prompt="classify""#,
        ] {
            let parsed = parse_query(query)
                .unwrap_or_else(|error| panic!("test query must parse ({query}): {error}"));
            assert!(
                has_rust_only_suffix_after_aggregation(&parsed),
                "missed Rust-only suffix after SQL aggregation: {query}"
            );
        }

        let suffix_before_aggregation =
            parse_query("* | prevalence enrich=true | stats count by dest_ip").unwrap();
        assert!(
            !has_rust_only_suffix_after_aggregation(&suffix_before_aggregation),
            "a Rust stage before aggregation must use deferred-aggregation planning"
        );
    }

    #[test]
    fn post_processed_pagination_reports_pre_page_group_count() {
        let rows: Vec<serde_json::Value> = (0..100)
            .map(|i| serde_json::json!({ "group": i }))
            .collect();
        let (page, total_count) = paginate_post_processed_results(rows, 60, 25, false);

        assert_eq!(total_count, 100);
        assert_eq!(page.len(), 25);
        assert_eq!(page.first().unwrap().get("group").unwrap(), 60);
        assert_eq!(page.last().unwrap().get("group").unwrap(), 84);

        let rows: Vec<serde_json::Value> =
            (0..3).map(|i| serde_json::json!({ "group": i })).collect();
        let (page, total_count) = paginate_post_processed_results(rows, 10, 60, false);
        assert!(page.is_empty());
        assert_eq!(total_count, 3);
    }

    #[test]
    fn lateral_metadata_is_outside_data_pagination() {
        let rows = vec![
            serde_json::json!({ "_display_type": "lateral" }),
            serde_json::json!({ "edge": 0 }),
            serde_json::json!({ "edge": 1 }),
            serde_json::json!({ "edge": 2 }),
        ];
        let (page, total_count) = paginate_post_processed_results(rows, 1, 1, true);

        assert_eq!(total_count, 3, "metadata is not a data row");
        assert_eq!(page.len(), 2, "metadata does not consume request.limit");
        assert_eq!(
            page[0].get("_display_type").and_then(|v| v.as_str()),
            Some("lateral")
        );
        assert_eq!(page[1].get("edge").and_then(|v| v.as_i64()), Some(1));

        let rows = vec![
            serde_json::json!({ "_display_type": "lateral" }),
            serde_json::json!({ "edge": 0 }),
        ];
        let (page, total_count) = paginate_post_processed_results(rows, 10, 10, true);
        assert_eq!(total_count, 1);
        assert_eq!(
            page,
            vec![serde_json::json!({ "_display_type": "lateral" })]
        );
    }

    /// NAN-1388: the OCSF empty-result note collects `ext.*` predicate fields
    /// from base search terms and `| where` stages — and nothing else.
    #[test]
    fn collects_ext_predicates_from_search_and_where() {
        let q = parse_query(
            r#"ext.error_code=5 AND NOT ext.cache_status="hit" | where ext.threat_tier!="low" | stats count by ext.category"#,
        )
        .unwrap();
        let fields = collect_ext_prefixed_predicate_fields(&q);
        let got: Vec<&str> = fields.iter().map(|s| s.as_str()).collect();
        // stats-by ext.category is a projection, not a predicate — excluded.
        assert_eq!(
            got,
            vec!["ext.cache_status", "ext.error_code", "ext.threat_tier"],
        );
    }

    #[test]
    fn ignores_non_ext_fields() {
        let q = parse_query(r#"src_ip="10.0.0.1" | where unmapped.foo="x""#).unwrap();
        assert!(collect_ext_prefixed_predicate_fields(&q).is_empty());
    }
}

#[cfg(test)]
mod nan3078_durable_post_processing_tests {
    use super::*;
    use crate::search::{
        DurableLakeTask, DurableResultRetentionProof, SearchJob, SearchJobBackend,
        SearchJobResultRef, SearchJobStatus, SearchTenantScope,
    };

    const WORKER: &str = "post-processing-worker";

    #[cfg(feature = "enterprise")]
    fn tenant_scope(tenant: uuid::Uuid) -> SearchTenantScope {
        SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0).unwrap()
    }

    /// A gen1-style lake worker double answering `/v1/jobs/result-page` with
    /// one page of fixed candidate rows, echoing the request binding.
    struct ResultPageWorker {
        tenant: String,
        rows: serde_json::Value,
    }

    impl wiremock::Respond for ResultPageWorker {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let rows = self.rows.as_array().unwrap().len();
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "ok": true,
                    "request_id": body["request_id"],
                    "tenant_id": self.tenant,
                    "route": "result_page",
                    "result": {
                        "page": body["page"],
                        "pages": 1,
                        "total_rows": rows,
                        "row_offset": 0,
                        "rows": self.rows,
                    },
                }))
                .insert_header("x-nano-worker-assignment-id", WORKER)
                .insert_header("x-nano-worker-assignment-revision", "1")
        }
    }

    #[cfg(feature = "enterprise")]
    async fn tenant_view(
        server: &wiremock::MockServer,
        tenant: uuid::Uuid,
        dir: &std::path::Path,
    ) -> SearchService {
        let credential = dir.join("worker-token");
        std::fs::write(&credential, "post-processing-worker-token-0123456789").unwrap();
        let assignment = crate::search::SharedLakeWorkerAssignment {
            tenant_id: tenant,
            internal_endpoint: server.uri(),
            credential_file: credential,
            expected_worker_identity: WORKER.to_string(),
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
        // Never connects: anything escaping the lake into PG/CH fails loudly.
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
        SearchService::with_dual_pool_and_profile_unrouted(
            &dual_pool,
            std::sync::Arc::new(crate::schema::OcsfProfile::lake_1_9()),
        )
        .enterprise_shared_tenant_view(
            &assignment,
            tenant_scope(tenant),
            std::sync::Arc::new(crate::search::InMemoryJobStore::new()),
        )
        .unwrap()
    }

    fn request(query: &str, limit: usize) -> SearchRequest {
        let now = chrono::Utc::now();
        serde_json::from_value(serde_json::json!({
            "query": query,
            "time_range": { "start": now - chrono::Duration::hours(1), "end": now },
            "limit": limit,
        }))
        .unwrap()
    }

    fn parsed(query: &str) -> Query {
        parse_query(query).unwrap()
    }

    #[test]
    fn the_planner_bounds_candidates_exactly_like_the_interactive_lane() {
        let filter = plan_lake_post_processing(&parsed(
            r#"class_uid=4002 | prevalence enrich=true | where class_uid=4002"#,
        ));
        assert_eq!(filter.worker_query, parsed("class_uid=4002").pretty_print());
        assert!(filter.needs_candidate_set);
        assert_eq!(filter.candidate_limit(), Some(IN_MEMORY_PREVALENCE_FETCH_CAP));

        let identity = plan_lake_post_processing(&parsed(
            r#"class_uid=3002 | resolve_identity src_endpoint.ip | where class_uid=3002"#,
        ));
        assert!(identity.has_identity);
        assert_eq!(identity.candidate_limit(), Some(LAKE_IDENTITY_BATCH_CAP));

        // Row-local enrichment keeps the caller's page.
        let enrich = plan_lake_post_processing(&parsed("class_uid=4002 | prevalence enrich=true"));
        assert!(!enrich.needs_candidate_set);
        assert_eq!(enrich.candidate_limit(), None);

        // A head before the stage is pulled out and becomes the row bound.
        let head = plan_lake_post_processing(&parsed(
            "class_uid=4002 | head 20 | prevalence enrich=true | where class_uid=4002",
        ));
        assert_eq!(head.candidate_limit(), Some(20));
        assert_eq!(head.worker_query, parsed("class_uid=4002").pretty_print());
    }

    #[test]
    fn post_task_validates_its_query_and_page_bounds() {
        let task = |post_query: &str, limit: usize, offset: usize| DurableLakeTask::SearchNplPostV1 {
            post_query: post_query.to_string(),
            requested_limit: limit,
            requested_offset: offset,
            required_scan_bytes: 0,
        };
        let valid = task("* | prevalence enrich=true\n| head 5", 100, 0);
        valid.validate().unwrap();
        assert_eq!(valid.kind(), "search_npl_post_v1");
        assert!(valid.is_search());
        let wire = serde_json::to_string(&valid).unwrap();
        assert_eq!(serde_json::from_str::<DurableLakeTask>(&wire).unwrap(), valid);
        for invalid in [
            task("", 100, 0),
            task("  ", 100, 0),
            task("* | prevalence enrich=true\u{0}", 100, 0),
            task(&"x".repeat(crate::search::MAX_DURABLE_POST_QUERY_BYTES + 1), 100, 0),
            task("* | prevalence enrich=true", 0, 0),
            task("* | prevalence enrich=true", 10, crate::search::MAX_DURABLE_POST_PAGE_ROWS),
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
        assert!(!DurableLakeTask::PrevalenceExportV1 {
            window: "24h".into(),
            artifact_type: None,
            max_prevalence: 1,
            format: "csv".into(),
        }
        .is_search());
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn prevalence_and_identity_suffixes_queue_their_sql_only_prefix() {
        let tenant = uuid::Uuid::from_u128(0x3078);
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        let shed = DurableLakeTask::SearchNplShedV1 { estimated_bytes: 8 << 30, budget_bytes: 4 << 30 };
        for (query, limit) in [
            ("class_uid=4002 | prevalence enrich=true | where class_uid=4002", IN_MEMORY_PREVALENCE_FETCH_CAP),
            ("class_uid=3002 | resolve_identity src_endpoint.ip | where class_uid=3002", LAKE_IDENTITY_BATCH_CAP),
        ] {
            let mut job_request = request(query, 100);
            let (full, _) = apply_auto_sort(parsed(query));
            let plan = plan_lake_post_processing(&full);
            let task = view
                .plan_durable_post_processing(&mut job_request, parsed(query), &shed)
                .await
                .unwrap();
            // The job fetches exactly the interactive candidate envelope.
            let profile = view.dataset_profile(None);
            assert_eq!(
                job_request.query,
                plan.candidate_query(&full, &view.ch_sql_generator, profile.as_ref(), true)
            );
            assert_eq!(job_request.limit, Some(limit));
            assert_eq!(job_request.offset, Some(0));
            validate_durable_lake_sql_only_query(&job_request.query).unwrap();
            let DurableLakeTask::SearchNplPostV1 {
                post_query,
                requested_limit,
                requested_offset,
                required_scan_bytes,
            } = task
            else {
                panic!("expected a post-processed task");
            };
            assert_eq!(post_query, full.pretty_print());
            assert_eq!((requested_limit, requested_offset), (100, 0));
            assert_eq!(required_scan_bytes, 8 << 30, "the shed envelope carries over");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[test]
    fn tree_searches_queue_as_post_processed_jobs() {
        // NAN-3257 repro: before the fix this was false, so a tree job ran as
        // a SQL-only `SearchNplV1` whose result had no tree marker.
        assert!(durable_search_needs_post_processing(&parsed(
            "device.hostname=\"ws1\" | tree process"
        )));
        assert!(durable_search_needs_post_processing(&parsed(
            "http_request.http_method=GET | tree web"
        )));
        assert!(!durable_search_needs_post_processing(&parsed("class_uid=1007 | head 5")));
    }

    #[test]
    fn tree_bound_note_only_for_a_filled_envelope() {
        let cap = crate::search::query_processing::LAKE_TREE_CANDIDATE_CAP;
        assert!(lake_tree_bound_note(cap, cap as u64).is_some());
        assert!(lake_tree_bound_note(10, 11).is_some());
        assert!(lake_tree_bound_note(10, 10).is_none());
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn tree_jobs_fetch_a_narrow_edge_candidate_set() {
        let tenant = uuid::Uuid::from_u128(0x3257);
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        for (query, expected) in [
            (
                "device.hostname=\"ws1\" | tree process",
                ["process.uid", "actor.process.uid", "process.parent_process.uid", "process.name"],
            ),
            (
                "http_request.http_method=GET | tree web",
                ["http_request.url.url_string", "http_request.referrer", "http_request.url.hostname", "dst_endpoint.hostname"],
            ),
        ] {
            let mut job_request = request(query, 1);
            let mut query = parsed(query);
            apply_profile_product_semantics(&mut query, view.dataset_profile(None).as_ref());
            let task = view
                .plan_durable_post_processing(&mut job_request, query, &DurableLakeTask::SearchNplV1)
                .await
                .unwrap();
            assert!(matches!(task, DurableLakeTask::SearchNplPostV1 { .. }), "{task:?}");
            assert_eq!(job_request.limit, Some(crate::search::query_processing::LAKE_TREE_CANDIDATE_CAP));
            let candidate = parsed(&job_request.query);
            let Query::Piped { command: Command::Table { fields }, .. } = &candidate else {
                panic!("tree candidate must be a narrow table: {}", job_request.query);
            };
            let names = fields.iter().map(|field| field.name.as_str()).collect::<Vec<_>>();
            for field in expected {
                assert!(names.contains(&field), "{field} missing from {names:?}");
            }
            assert!(!job_request.query.contains("tree"), "{}", job_request.query);
            validate_durable_lake_sql_only_query(&job_request.query).unwrap();
        }
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn a_completed_tree_job_answers_with_tree_nodes() {
        let tenant = uuid::Uuid::from_u128(0x3258);
        let server = wiremock::MockServer::start().await;
        // A non-Sysmon endpoint shape: the parent is nested under the process
        // (`process.parent_process.uid`), no `actor.process.*`.
        let rows = serde_json::json!([
            {"time": "2026-09-30T10:00:00Z", "process.uid": "c1", "process.parent_process.uid": "p1",
             "process.name": "curl", "process.parent_process.name": "bash", "process.cmd_line": "curl x"},
            {"time": "2026-09-30T09:59:00Z", "process.uid": "c2", "process.parent_process.uid": "p1",
             "process.name": "ls", "process.parent_process.name": "bash"},
            {"time": "2026-09-30T09:58:00Z", "process.uid": "p1", "process.parent_process.uid": "init",
             "process.name": "bash", "process.parent_process.name": "systemd"},
        ]);
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/jobs/result-page"))
            .respond_with(ResultPageWorker { tenant: tenant.to_string(), rows })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        let now = chrono::Utc::now();
        let job = completed_post_job(
            tenant,
            "device.hostname=\"ws1\" | tree process",
            now,
            TimeRangeInput::new(now - chrono::Duration::hours(1), now),
        );
        let response = view
            .durable_post_processed_result(&job, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert_eq!(response.results.len(), 1);
        let marker = &response.results[0];
        assert_eq!(marker["_display_type"], "tree");
        let roots = marker["_tree_nodes"].as_array().unwrap();
        assert_eq!(roots.len(), 1, "{roots:?}");
        assert_eq!(roots[0]["id"], "init");
        assert_eq!(roots[0]["label"], "systemd");
        let bash = &roots[0]["children"][0];
        assert_eq!(bash["id"], "p1");
        assert_eq!(bash["children"].as_array().unwrap().len(), 2);
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn ai_and_oversized_pages_stay_refused() {
        let tenant = uuid::Uuid::from_u128(0x3079);
        let server = wiremock::MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        for (query, limit) in [
            (r#"class_uid=4002 | ai prompt="is this malicious?""#, 100),
            // Row-local enrichment fetches the caller's page; over the
            // post-processing envelope it cannot be read back in one pass.
            ("class_uid=4002 | prevalence enrich=true", IN_MEMORY_PREVALENCE_FETCH_CAP + 1),
        ] {
            let error = view
                .plan_durable_post_processing(
                    &mut request(query, limit),
                    parsed(query),
                    &DurableLakeTask::SearchNplV1,
                )
                .await
                .unwrap_err();
            assert!(is_durable_lane_post_processing_refusal(&error), "{query}: {error:?}");
        }
    }

    #[cfg(feature = "enterprise")]
    fn completed_post_job(
        tenant: uuid::Uuid,
        post_query: &str,
        evaluated_at: chrono::DateTime<chrono::Utc>,
        range: TimeRangeInput,
    ) -> SearchJob {
        let mut request = request("class_uid=4002", IN_MEMORY_PREVALENCE_FETCH_CAP);
        request.time_range = range.clone();
        let mut job = SearchJob::new_for_tenant(
            tenant_scope(tenant),
            "job-3078".into(),
            request,
            &ScopeSet::unrestricted(),
        );
        job.status = SearchJobStatus::Completed;
        job.backend = SearchJobBackend::LakeDurable;
        job.task = Some(DurableLakeTask::SearchNplPostV1 {
            post_query: post_query.to_string(),
            requested_limit: 100,
            requested_offset: 0,
            required_scan_bytes: 0,
        });
        job.result_ref = Some(SearchJobResultRef {
            tenant_id: Some(tenant),
            manifest_uri: "s3://results/job-3078/manifest.json".into(),
            manifest_sha256: "a".repeat(64),
            rows: 3,
            parts: 1,
            has_more: false,
            page_rows: 10_000,
            retention_proof: Some(
                DurableResultRetentionProof::from_shared_job(
                    tenant_scope(tenant),
                    evaluated_at,
                    &range,
                )
                .unwrap(),
            ),
        });
        job
    }

    fn candidate_rows() -> serde_json::Value {
        serde_json::json!([
            {"time": "2026-09-30T10:00:00Z", "class_uid": 4002, "metadata": {"log_source": "proxy"}},
            {"time": "2026-09-30T09:59:00Z", "class_uid": 1007, "metadata": {"log_source": "sysmon"}},
            {"time": "2026-09-30T09:58:00Z", "class_uid": 4002, "metadata": {"log_source": "proxy"}},
        ])
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn a_completed_job_answers_with_the_suffix_applied_never_the_raw_candidates() {
        let tenant = uuid::Uuid::from_u128(0x307a);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/jobs/result-page"))
            .respond_with(ResultPageWorker { tenant: tenant.to_string(), rows: candidate_rows() })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        let now = chrono::Utc::now();
        let job = completed_post_job(
            tenant,
            "class_uid=4002 | prevalence enrich=true | where class_uid=4002",
            now,
            TimeRangeInput::new(now - chrono::Duration::hours(1), now),
        );
        let response = view
            .durable_post_processed_result(&job, &ScopeSet::unrestricted())
            .await
            .unwrap();
        assert_eq!(response.results.len(), 2, "{:?}", response.results);
        assert!(response
            .results
            .iter()
            .all(|row| row["class_uid"] == serde_json::json!(4002)));
        assert_eq!(response.total_count, 2);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// The gen1 worker's `/v1/prevalence/lookup`: answers every requested
    /// artifact with the first_seen from `first_seen`, echoing the binding.
    /// Snapshots are per-window, like the lake's: outside the 30d snapshot an
    /// artifact's first_seen is only its earliest sighting inside the window
    /// (here: within the last hour, for every artifact seen today).
    struct PrevalenceLookupWorker {
        tenant: String,
        first_seen: std::collections::BTreeMap<&'static str, String>,
    }

    impl wiremock::Respond for PrevalenceLookupWorker {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let results: Vec<serde_json::Value> = body["artifacts"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|name| {
                    let name = name.as_str().unwrap();
                    let first_seen = self.first_seen.get(name)?;
                    let first_seen = if body["window"] == "30d" {
                        first_seen.clone()
                    } else {
                        let in_window = chrono::Utc::now() - chrono::Duration::hours(1);
                        chrono::DateTime::parse_from_rfc3339(first_seen)
                            .unwrap()
                            .with_timezone(&chrono::Utc)
                            .max(in_window)
                            .to_rfc3339()
                    };
                    Some(serde_json::json!({
                        "artifact": name, "artifact_type": "domain", "host_count": 2,
                        "total_occurrences": 4, "first_seen": first_seen,
                        "last_seen": chrono::Utc::now().to_rfc3339(), "is_rare": true,
                        "prevalence_score": 10,
                    }))
                })
                .collect();
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "ok": true, "tenant_id": self.tenant, "snapshot_id": body["snapshot_id"],
                    "results": results,
                }))
                .insert_header("x-nano-worker-assignment-id", WORKER)
                .insert_header("x-nano-worker-assignment-revision", "1")
        }
    }

    /// NAN-4372: `| prevalence domain_first_seen > now() - 24h` returned every
    /// candidate row on the lake (the in-memory filter `return Ok(results)`
    /// for first_seen fields). Through the production tenant view and the
    /// shared lake post-processing path, only the row whose domain was first
    /// seen inside the window survives; an old domain, a domain the backend
    /// does not know, and a row with no domain are all excluded. The same
    /// condition with `enrich=true` filters too (it used to skip conditions).
    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn nan4372_first_seen_filter_keeps_only_new_artifacts_on_the_lake() {
        let tenant = uuid::Uuid::from_u128(0x4372);
        let server = wiremock::MockServer::start().await;
        let now = chrono::Utc::now();
        let rows = serde_json::json!([
            {"time": "2026-09-30T10:00:00Z", "class_uid": 4002, "metadata": {"uid": "fresh"},
             "dst_endpoint": {"hostname": "fresh.example"}},
            {"time": "2026-09-30T09:59:00Z", "class_uid": 4002, "metadata": {"uid": "old"},
             "dst_endpoint": {"hostname": "old.example"}},
            {"time": "2026-09-30T09:58:00Z", "class_uid": 4002, "metadata": {"uid": "unknown"},
             "dst_endpoint": {"hostname": "unknown.example"}},
            {"time": "2026-09-30T09:57:00Z", "class_uid": 4002, "metadata": {"uid": "nodomain"}},
        ]);
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/jobs/result-page"))
            .respond_with(ResultPageWorker { tenant: tenant.to_string(), rows })
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/prevalence/lookup"))
            .respond_with(PrevalenceLookupWorker {
                tenant: tenant.to_string(),
                first_seen: [
                    ("fresh.example", (now - chrono::Duration::hours(2)).to_rfc3339()),
                    ("old.example", (now - chrono::Duration::days(20)).to_rfc3339()),
                ]
                .into_iter()
                .collect(),
            })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        let uids = |response: &SearchResponse| -> Vec<String> {
            response
                .results
                .iter()
                .map(|row| row["metadata"]["uid"].as_str().unwrap_or_default().to_string())
                .collect()
        };
        for (query, expected) in [
            ("class_uid=4002 | prevalence domain_first_seen > now() - 24h", vec!["fresh"]),
            ("class_uid=4002 | prevalence domain_first_seen > now() - 24h enrich=true", vec!["fresh"]),
            ("class_uid=4002 | prevalence domain_first_seen < now() - 7d", vec!["old"]),
            // NAN-4372 review: `window=` scopes the host count only. A domain
            // first seen 20 days ago is not new in the last 24h even though
            // the 24h snapshot's earliest sighting of it is an hour old:
            // first_seen always reads the 30d snapshot.
            (
                "class_uid=4002 | prevalence domain_prevalence < 10 domain_first_seen > now() - 24h window=24h",
                vec!["fresh"],
            ),
            ("class_uid=4002 | prevalence domain_first_seen > now() - 24h window=7d", vec!["fresh"]),
        ] {
            let mut job = completed_post_job(
                tenant,
                query,
                now,
                TimeRangeInput::new(now - chrono::Duration::hours(1), now),
            );
            job.result_ref.as_mut().unwrap().rows = 4;
            let response = view
                .durable_post_processed_result(&job, &ScopeSet::unrestricted())
                .await
                .unwrap_or_else(|error| panic!("{query}: {error:?}"));
            assert_eq!(uids(&response), expected, "{query}");
        }
    }

    /// NAN-4291 (F6): an expired window still answers an ungrouped `stats`
    /// the way the engine answers any empty window (one row: count 0, the
    /// other aggregates null), by running it over a matches-nothing search
    /// in a 1 ms in-retention window. Everything else (grouped stats, raw
    /// events, a subsearch) answers empty without reaching the worker. Run
    /// on a 32 MiB stack: the debug `search` future outgrows the 2 MiB test
    /// thread.
    #[cfg(feature = "enterprise")]
    #[test]
    fn an_expired_window_runs_only_an_ungrouped_aggregate_over_no_rows() {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(expired_window_aggregate_case())
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "enterprise")]
    async fn expired_window_aggregate_case() {
        let tenant = uuid::Uuid::from_u128(0x4291);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(wiremock::ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        let now = chrono::Utc::now();
        let cutoff = view.retention_cutoff_at(now).unwrap().expect("shared view is retained");
        let expired = |query: &str| -> SearchRequest {
            serde_json::from_value(serde_json::json!({
                "query": query,
                "time_range": {
                    "start": now - chrono::Duration::days(200),
                    "end": now - chrono::Duration::days(150),
                },
                "limit": 100,
            }))
            .unwrap()
        };

        for query in [
            "class_uid=4002",
            "class_uid=4002 | stats count by actor.user.name",
            "class_uid=4002 | stats count by actor.user.name | sort -count | head 5",
            "class_uid=4002 | join type=left actor.user.name [search class_uid=3002 | stats count by actor.user.name] | stats count",
            "class_uid=4002 | timechart span=1h count",
        ] {
            let response = view.search(expired(query), &ScopeSet::unrestricted()).await.unwrap();
            assert!(response.results.is_empty(), "{query}");
        }
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "only an ungrouped aggregate reads an expired window"
        );

        let _ = view
            .search(
                expired("class_uid=4002 | stats count, max(time) as mt, values(actor.user.name) as v | eval n=count"),
                &ScopeSet::unrestricted(),
            )
            .await;
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.is_empty(), "the ungrouped aggregate runs");
        for request in &requests {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let text = body.to_string();
            assert!(text.contains("NOT *"), "the search matches nothing: {text}");
            let start = body["start"].as_str().unwrap_or_else(|| panic!("{text}"));
            let end = body["end"].as_str().unwrap_or_else(|| panic!("{text}"));
            let start = chrono::DateTime::parse_from_rfc3339(start).unwrap().with_timezone(&chrono::Utc);
            let end = chrono::DateTime::parse_from_rfc3339(end).unwrap().with_timezone(&chrono::Utc);
            assert!(start >= cutoff && end - start <= chrono::Duration::milliseconds(1), "{text}");
        }
    }

    /// One fixture event: time, `actor.user.name`, `dst_endpoint.port`.
    #[cfg(feature = "enterprise")]
    type SliceEvent = (chrono::DateTime<chrono::Utc>, &'static str, i64);

    /// What the compiled statement answers over `events` (one window, no
    /// slicing): ungrouped, one row with count 0 and every other state null
    /// over no rows (NAN-4291); grouped by user, one row per user seen. The
    /// row carries every state any test query names (`s`, `a`, `lo`, `hi`,
    /// the avg partials `__nano_avg_sum_N` / `__nano_avg_count_N`, …); the
    /// merge reads only its own. UInt64 counts arrive quoted, as from a cell.
    #[cfg(feature = "enterprise")]
    fn slice_statement_rows(query: &str, events: &[&SliceEvent]) -> Vec<serde_json::Value> {
        use base64::Engine as _;
        let fmt = |at: &chrono::DateTime<chrono::Utc>| at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let state = |rows: &[&SliceEvent]| {
            let ports = rows.iter().map(|(_, _, port)| *port).collect::<Vec<_>>();
            let some = !ports.is_empty();
            let sum = some.then(|| ports.iter().sum::<i64>());
            let mut row = serde_json::json!({
                "count": rows.len().to_string(),
                "first_seen": rows.first().map(|(at, _, _)| fmt(at)),
                "last_seen": rows.last().map(|(at, _, _)| fmt(at)),
                "first_user": rows.first().map(|(_, user, _)| user),
                "last_user": rows.last().map(|(_, user, _)| user),
                "s": sum,
                "a": some.then(|| sum.unwrap() as f64 / ports.len() as f64),
                "lo": ports.iter().min(),
                "hi": ports.iter().max(),
                "__nano_distinct_values": some.then(|| rows.iter()
                    .map(|(_, user, _)| base64::engine::general_purpose::STANDARD.encode(user))
                    .collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join(", ")),
            });
            for index in 0..8 {
                row[format!("__nano_avg_sum_{index}")] = serde_json::json!(sum);
                row[format!("__nano_avg_count_{index}")] = serde_json::json!(ports.len().to_string());
            }
            row
        };
        if query.contains(" by actor.user.name") {
            let mut users = BTreeMap::<&str, Vec<&SliceEvent>>::new();
            for event in events {
                users.entry(event.1).or_default().push(event);
            }
            users
                .into_iter()
                .map(|(user, rows)| {
                    let mut row = state(&rows);
                    row["actor.user.name"] = serde_json::json!(user);
                    row
                })
                .collect()
        } else {
            vec![state(events)]
        }
    }

    /// A worker whose scan budget refuses any window wider than `max_width`
    /// (413 `scan_budget_exhausted`, as a cell does), so the sliced-stats and
    /// distinct-state paths bisect. Each slice is answered by
    /// [`slice_statement_rows`], the compiled statement's shape (pinned
    /// natively by `ungrouped_stats_over_no_rows_is_count_zero_and_null_aggregates`).
    #[cfg(feature = "enterprise")]
    struct SlicingAggregateWorker {
        tenant: String,
        max_width: chrono::Duration,
        events: Vec<SliceEvent>,
    }

    #[cfg(feature = "enterprise")]
    impl wiremock::Respond for SlicingAggregateWorker {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let bound = |key: &str| {
                chrono::DateTime::parse_from_rfc3339(body[key].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc)
            };
            let (start, end) = (bound("start"), bound("end"));
            if end - start > self.max_width {
                return wiremock::ResponseTemplate::new(413).set_body_json(serde_json::json!({
                    "ok": false, "error_code": "RESOURCE_EXHAUSTED", "reason": "scan_budget_exhausted",
                    "error": "query scan budget rejected",
                }))
                .insert_header("x-nano-worker-assignment-id", WORKER)
                .insert_header("x-nano-worker-assignment-revision", "1");
            }
            let mut events: Vec<_> = self.events.iter().filter(|(at, _, _)| *at >= start && *at <= end).collect();
            events.sort();
            let rows = slice_statement_rows(body["query"].as_str().unwrap(), &events);
            wiremock::ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "ok": true, "tenant_id": self.tenant, "request_id": body["request_id"],
                    "route": "broad_npl", "source_mode": "parts",
                    "log_head": {"seq": 1, "sha256": "ab".repeat(32)},
                    "generation_id": "nan4291", "snapshot_id": "1",
                    "result": {"rows": rows, "result_rows": rows.len(), "page_has_more": false},
                }))
                .insert_header("x-nano-worker-assignment-id", WORKER)
                .insert_header("x-nano-worker-assignment-revision", "1")
        }
    }

    /// NAN-4291 / NAN-4313: the per-slice merges read an empty slice (the
    /// ungrouped statement's count-0-and-null row, or a grouped slice's
    /// missing group) as "no rows". Over four slices, two of them empty in
    /// the middle, every merged aggregate equals the unsliced statement:
    /// counts, earliest/latest, first/last, dc/values, and (NAN-4313) sum,
    /// avg (Σsum/Σcount), numeric min/max, ungrouped and by user (bob's rows
    /// sit in both non-empty slices). Percentiles and medians have no exact
    /// merge and are never sliced: one request, the budget rejection, which
    /// the search handler escalates to a durable job.
    #[cfg(feature = "enterprise")]
    #[test]
    fn sliced_ungrouped_merges_skip_empty_slices() {
        std::thread::Builder::new()
            .stack_size(32 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(sliced_ungrouped_merge_case())
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "enterprise")]
    async fn sliced_ungrouped_merge_case() {
        let tenant = uuid::Uuid::from_u128(0x4292);
        // The worker reports event times at microsecond precision.
        let now = chrono::SubsecRound::trunc_subsecs(chrono::Utc::now(), 6);
        let start = now - chrono::Duration::hours(4);
        let at = |minutes: i64| start + chrono::Duration::minutes(minutes);
        // Quarter slices: events only in the first and the last, a distinct
        // port on each.
        let events: Vec<SliceEvent> =
            vec![(at(10), "alice", 443), (at(20), "bob", 22), (at(200), "bob", 8080), (at(230), "carol", 3389)];
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(SlicingAggregateWorker {
                tenant: tenant.to_string(),
                max_width: chrono::Duration::minutes(61),
                events: events.clone(),
            })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        let search = |query: &str, start: chrono::DateTime<chrono::Utc>| {
            let request: SearchRequest = serde_json::from_value(serde_json::json!({
                "query": query,
                "time_range": {"start": start, "end": start + chrono::Duration::hours(4)},
                "limit": 100,
            }))
            .unwrap();
            let view = &view;
            async move {
                view.search(request, &ScopeSet::unrestricted()).await.unwrap_or_else(|error| panic!("{error}")).results
            }
        };
        let number = |value: &serde_json::Value| {
            value.as_f64().or_else(|| value.as_str().and_then(|s| s.parse().ok())).unwrap_or_else(|| panic!("{value}"))
        };
        let instant = |value: &serde_json::Value| {
            chrono::DateTime::parse_from_rfc3339(value.as_str().unwrap_or_else(|| panic!("{value}"))).unwrap()
        };

        let sliced = "metadata.log_source=aws_cloudtrail | stats count, earliest(time) as first_seen, \
                      latest(time) as last_seen, first(actor.user.name) as first_user, last(actor.user.name) as last_user";
        let distinct = "metadata.log_source=aws_cloudtrail | stats dc(actor.user.name) as users, values(actor.user.name) as v, count";
        let requests_before = server.received_requests().await.unwrap().len();
        let row = search(sliced, start).await.remove(0);
        assert!(server.received_requests().await.unwrap().len() - requests_before >= 4, "the window was sliced");
        assert_eq!(number(&row["count"]), 4.0, "{row}");
        assert_eq!(instant(&row["first_seen"]), at(10), "{row}");
        assert_eq!(instant(&row["last_seen"]), at(230), "{row}");
        assert_eq!(row["first_user"], "alice", "{row}");
        assert_eq!(row["last_user"], "carol", "{row}");
        let row = search(distinct, start).await.remove(0);
        assert_eq!(number(&row["users"]), 3.0, "{row}");
        let mut users = row["v"].as_str().unwrap_or_else(|| panic!("{row}")).split(", ").collect::<Vec<_>>();
        users.sort_unstable();
        assert_eq!(users, ["alice", "bob", "carol"], "{row}");
        assert_eq!(number(&row["count"]), 4.0, "{row}");

        // NAN-4313: sum / avg / numeric min / max slice and merge exactly,
        // equal to the unsliced statement over the whole window.
        let numeric = "count, sum(dst_endpoint.port) as s, avg(dst_endpoint.port) as a, \
                       min(dst_endpoint.port) as lo, max(dst_endpoint.port) as hi";
        let all: Vec<&SliceEvent> = events.iter().collect();
        for tail in ["", " by actor.user.name"] {
            let query = format!("metadata.log_source=aws_cloudtrail | stats {numeric}{tail}");
            let before = server.received_requests().await.unwrap().len();
            let mut rows = search(&query, start).await;
            assert!(server.received_requests().await.unwrap().len() - before >= 4, "{query} was sliced");
            let mut unsliced = slice_statement_rows(&query, &all);
            let key = |row: &serde_json::Value| row["actor.user.name"].to_string();
            rows.sort_by_key(key);
            unsliced.sort_by_key(key);
            assert_eq!(rows.len(), unsliced.len(), "{query}: {rows:?}");
            for (row, expected) in rows.iter().zip(&unsliced) {
                for state in ["count", "s", "a", "lo", "hi"] {
                    assert_eq!(number(&row[state]), number(&expected[state]), "{query}: {state} in {row} vs {expected}");
                }
            }
        }
        let row = search(&format!("metadata.log_source=aws_cloudtrail | stats {numeric}"), start).await.remove(0);
        assert_eq!((number(&row["s"]), number(&row["a"])), (11_934.0, 2_983.5), "{row}");
        assert_eq!((number(&row["lo"]), number(&row["hi"])), (22.0, 8_080.0), "{row}");
        let bob = search(&format!("metadata.log_source=aws_cloudtrail | stats {numeric} by actor.user.name"), start)
            .await
            .into_iter()
            .find(|row| row["actor.user.name"] == "bob")
            .unwrap();
        assert_eq!(
            [number(&bob["count"]), number(&bob["s"]), number(&bob["a"]), number(&bob["lo"]), number(&bob["hi"])],
            [2.0, 8_102.0, 4_051.0, 22.0, 8_080.0],
            "bob's rows sit in both non-empty slices: {bob}"
        );

        // Percentiles and medians have no exact merge from partials: never
        // sliced, one request, the budget rejection (escalated to a durable
        // job by the search handler).
        for aggregate in [
            "perc95(dst_endpoint.port) as p95",
            "median(dst_endpoint.port) as med",
            "count, sum(dst_endpoint.port) as s, median(dst_endpoint.port) as med",
        ] {
            let query = format!("metadata.log_source=aws_cloudtrail | stats {aggregate}");
            let before = server.received_requests().await.unwrap().len();
            let request: SearchRequest = serde_json::from_value(serde_json::json!({
                "query": query,
                "time_range": {"start": start, "end": start + chrono::Duration::hours(4)},
                "limit": 100,
            }))
            .unwrap();
            let error = view.search(request, &ScopeSet::unrestricted()).await.expect_err(&query);
            assert!(
                matches!(error, SearchError::ResourceExhausted(_)) && is_lake_scan_budget_rejection(&error),
                "{query}: {error}"
            );
            assert_eq!(server.received_requests().await.unwrap().len() - before, 1, "{query} was sliced");
        }

        // Every slice empty.
        let empty = now - chrono::Duration::days(10);
        let row = search(sliced, empty).await.remove(0);
        assert_eq!(number(&row["count"]), 0.0, "{row}");
        for null in ["first_seen", "last_seen", "first_user", "last_user"] {
            assert!(row.get(null).is_some_and(serde_json::Value::is_null), "{null}: {row}");
        }
        let row = search(distinct, empty).await.remove(0);
        assert_eq!(number(&row["users"]), 0.0, "{row}");
        assert_eq!(number(&row["count"]), 0.0, "{row}");
        assert!(row.get("v").is_some_and(serde_json::Value::is_null), "values over no rows is null: {row}");
        let row = search(&format!("metadata.log_source=aws_cloudtrail | stats {numeric}"), empty).await.remove(0);
        assert_eq!(number(&row["count"]), 0.0, "{row}");
        for null in ["s", "a", "lo", "hi"] {
            assert!(row.get(null).is_some_and(serde_json::Value::is_null), "{null}: {row}");
        }
        assert!(
            search(&format!("metadata.log_source=aws_cloudtrail | stats {numeric} by actor.user.name"), empty)
                .await
                .is_empty(),
            "grouped stats over no rows have no rows"
        );
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn a_result_past_the_retention_cutoff_is_never_read() {
        let tenant = uuid::Uuid::from_u128(0x307b);
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/v1/jobs/result-page"))
            .respond_with(ResultPageWorker { tenant: tenant.to_string(), rows: candidate_rows() })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let view = tenant_view(&server, tenant, dir.path()).await;
        // Admitted 100 days ago over a range that has since crossed the
        // tenant's 90-day cutoff.
        let evaluated = chrono::Utc::now() - chrono::Duration::days(100);
        let job = completed_post_job(
            tenant,
            "class_uid=4002 | prevalence enrich=true | where class_uid=4002",
            evaluated,
            TimeRangeInput::new(evaluated - chrono::Duration::hours(1), evaluated),
        );
        assert!(view
            .durable_post_processed_result(&job, &ScopeSet::unrestricted())
            .await
            .is_err());
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "no candidate page is read once the proof crossed the cutoff"
        );
    }
}

#[cfg(all(test, feature = "enterprise"))]
#[path = "nan4664_rollup_sibling_tests.rs"]
mod nan4664_rollup_sibling_tests;
