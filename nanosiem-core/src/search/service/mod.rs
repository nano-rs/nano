// SPDX-License-Identifier: AGPL-3.0-or-later

//! Search execution service
//!
//! This module provides the SearchService which:
//! - Executes piped queries by parsing and generating SQL
//! - Executes raw SQL queries (SELECT only)
//! - Calculates field statistics from results
//! - Supports UDM field querying across sources
//! - Enriches results with lookup table data
//! - Executes log search on ClickHouse (PostgreSQL is metadata-only)
//! - Supports prevalence filtering and enrichment

use std::time::Instant;
use tracing::{debug, info, instrument, warn};

use crate::db::dual_pool::TableNames;
use crate::db::DualPool;
use crate::extensions::{AiClient, CloudRiskProvider, NoopAiClient, NoopCloudRiskProvider};
use crate::lookup::LookupService;
use crate::prevalence::{
    LakePrevalenceClient, PrevalenceData, PrevalenceLookup, PrevalenceService,
    TimeWindow as PrevalenceTimeWindow,
};
use crate::query::{
    analyze_query_cost, parse_query, AggFunc, BinSpan, ClickHouseSqlGenerator, Command, ParseError,
    PrettyPrint, PrevalenceField, PrevalenceOperator, PrevalenceThreshold,
    PrevalenceTimeWindow as AstTimeWindow, Query, TimeRange, WarningSeverity, WindowType,
};
use crate::udm::UdmField;

use super::config::{SearchBackend, SearchConfig};
use super::evaluator::helpers::{escape_like_pattern, escape_sql_string};
use super::execution::{
    escape_question_marks_in_strings, validate_sql_query, ClickHouseExecutor, SqlExecutor,
};
use super::lake::{LakeQueryMode, LakeQueryRuntime};
use super::processing::{
    apply_inputlookup_enrichment, apply_lookup_enrichment, apply_post_prevalence_commands,
    apply_post_prevalence_commands_with_limit, validate_lookup_tables,
};
use super::query_processing::{
    apply_auto_sort, contains_lake_post_processing_anywhere, contains_nested_lake_post_processing,
    detect_oom_risk, extract_ai_command, extract_asset_command,
    extract_asset_identifier_from_query, extract_base_query, extract_baseline_command,
    extract_cloud_command, extract_funnel_command, extract_inputlookup_commands,
    extract_lake_lateral_identifier_from_query, extract_lateral_command, extract_lookup_commands,
    extract_post_ai_commands, extract_post_inputlookup_commands, extract_post_lateral_commands,
    extract_post_prevalence_commands, extract_prevalence_commands, extract_tree_command,
    has_aggregation_before_prevalence, has_only_simple_post_prevalence_commands,
    lake_post_processing_replaces_source, query_has_aggregation, query_has_per_row_filters,
    split_lake_post_processing, strip_ai_and_after, strip_inputlookup_and_after,
    strip_lateral_and_after, strip_post_prevalence_commands, strip_prevalence_and_after,
    AssetCommandInfo, CloudCommandInfo, FunnelCommandInfo, InputLookupCommandInfo,
    LookupCommandInfo, PrevalenceCommandInfo, TreeCommandInfo,
};
use super::types::*;
use crate::inputlookup::InputLookupService;

// Re-export parent sibling modules so submodules can access them via `super::`
// Note: `streaming` is not re-exported here because it conflicts with our local `streaming` submodule.
// Submodules that need search::streaming types should use `crate::search::streaming::*` directly.
pub(super) use super::admission;
pub(super) use super::execution;
pub(super) use super::jobs;

mod ai_pipe_deadline;
mod asset;
pub use asset::{DimensionFirst, EntityActivityBucket};
pub mod asset_dossier;
mod baseline;
pub use baseline::{run_lake_baseline, LakeBaselineOutcome, LakeBaselinePlan, LAKE_BASELINE_BUDGET_EXHAUSTED};
mod cloud;
pub mod cloud_dossier;
pub mod cloud_overview;
mod core_search;
mod timechart;
mod field_queries;
pub use field_queries::{FieldStatsResult, FieldValuesResult};
mod funnel_view;
mod lake_asset;
pub use lake_asset::{LakeAssetCardRead, LakeAssetCards};
mod lake_cloud;
pub use lake_cloud::CloudDossierAccumulator;
mod lake_identity;
mod lake_host_identity;
mod lake_stats_merge;

/// NAN-1506: row cap for the bulk field-stats scan (shared by the standalone
/// `/api/search/field-stats` companion and the inline parallel companion in
/// `core_search`). topK/uniq over many columns is a full-window scan otherwise
/// (Saturn: 12.6s for 20 columns over a 24h / 22M-row window; timeout for the
/// full inventory). 100k rows brings it to ~0.1s. Windows with ≤ this many
/// matching rows are byte-identical (the LIMIT doesn't truncate), so tight
/// searches stay exact; larger windows become a fast PK-order sample. Per-field
/// drill-in (`get_field_values`) stays exact and unbounded.
pub(crate) const FIELD_STATS_ROW_CAP: usize = 100_000;

/// Hard ceiling for rows produced by an SQL aggregation before caller-facing
/// pagination. This is deliberately separate from `SearchRequest.limit`: the
/// former bounds high-cardinality grouped output, while the latter selects a
/// page from within that bounded output.
pub(super) const AGGREGATE_OUTPUT_CAP: usize = 1_000_000;
/// Hosted tenant-pinned service views and their tenant-bound setters.
#[cfg(feature = "enterprise")]
mod enterprise_shared_views;
mod histogram;
pub use histogram::SearchHistogramResult;
mod ioc_lookup_resolve;
mod lake_views;
mod lake_view_cache;
pub(crate) use lake_views::lake_product_cursor as lake_product_cursor_for_row;
pub(crate) mod lateral;
mod lateral_graph;
/// NAN-3088: Prevalence export and the rare list as durable lean-cell jobs.
pub mod lean_prevalence;
mod metrics_routing;
mod otel;
mod output_column_guard;
mod prevalence_join;
mod prevalence_processing;
mod retro;
mod sql_execution;
pub use sql_execution::RawSqlAuditAccess;
/// NAN-2564: the shared detection runtime classifies scan-budget refusals.
pub use core_search::is_lake_scan_budget_rejection;
pub use core_search::{is_durable_lane_post_processing_refusal, DURABLE_LANE_POST_PROCESSING_REFUSAL};
mod streaming;
mod tree_view;
pub(crate) use tree_view::{derived_parent_label_field, TREE_PREVALENCE_FIELDS};
mod window_clamp;

/// Crate-public re-export of the ONE source-scope SQL predicate builder
/// (NAN-1801, P3). The hand-built "side-door" SQL paths in other crates
/// (identity API, prevalence, telemetry, AI) render a caller's deny-set with
/// THIS function so their gate stays byte-identical to the nPL injector's
/// negated-`InList` shape — never a re-derived copy. Reachable as
/// `nanosiem_core::search::service::source_scope_sql_predicate` (requires
/// `search::service` to be a `pub mod`).
pub use lateral::source_scope_sql_predicate;

/// Determine the display type for a query based on its commands
///
/// This inspects the AST to determine the appropriate display type:
/// - Visualization commands (timechart, top, rare, etc.) set their specific type
/// - Aggregation commands (stats, chart) result in Table display
/// - Formatting commands (sort, head, tail) after aggregation still show Table
/// - Raw event queries show Events display
fn determine_display_type(query: &Query) -> DisplayType {
    // First, find the "semantic" terminal command - the command that determines
    // what kind of data we're displaying, ignoring formatting commands like sort/head/tail
    let semantic_command = get_semantic_terminal_command(query);

    match semantic_command {
        Some(Command::Timechart { .. }) => DisplayType::Timechart,
        Some(Command::Top { .. }) | Some(Command::Rare { .. }) => DisplayType::RankedBar,
        Some(Command::Transaction { .. }) => DisplayType::Transaction,
        Some(Command::Sequence { .. }) | Some(Command::Funnel { .. }) => DisplayType::Flow,
        Some(Command::Tree { .. }) => DisplayType::Tree,
        Some(Command::Asset { .. }) => DisplayType::Asset,
        Some(Command::Cloud { .. }) => DisplayType::Cloud,
        Some(Command::Lateral { .. }) => DisplayType::Lateral,
        Some(Command::Services) => DisplayType::Services,
        Some(Command::Service { .. }) => DisplayType::Service,
        Some(Command::Trace { .. }) => DisplayType::Trace,
        Some(Command::Metric { .. }) => DisplayType::Metric,
        Some(Command::Retro { .. }) => DisplayType::Retro,
        Some(Command::Baseline { .. }) => DisplayType::Baseline,
        Some(Command::Stats { .. })
        | Some(Command::Chart { .. })
        | Some(Command::EventStats { .. })
        | Some(Command::Anomaly { .. }) => DisplayType::Table,
        Some(Command::Table { .. }) => {
            // `| table` explicitly requests tabular display regardless of aggregation
            DisplayType::Table
        }
        _ => {
            // Check if there's any aggregation in the query - if so, show as Table
            // This handles cases like `| stats ... | sort ...` where terminal is sort
            if has_aggregation_in_query(query) {
                DisplayType::Table
            } else {
                DisplayType::Events
            }
        }
    }
}

/// Derived ClickHouse query_ids for the companion queries fanned out by one
/// search request (NAN-1428): count, histogram, and field-stats.
///
/// Cancellation must kill the data query plus exactly these ids. They are
/// always matched EXACTLY (never via `LIKE '{id}%'`) because client-provided
/// request ids can legitimately contain `%`/`_` LIKE metacharacters.
pub(crate) fn companion_query_ids(query_id: &str) -> [String; 3] {
    [
        format!("{query_id}-count"),
        format!("{query_id}-hist"),
        format!("{query_id}-fstats"),
    ]
}

/// The data query id plus all derived companion ids — the full kill set for
/// one search request (NAN-1428).
pub(crate) fn all_query_ids(query_id: &str) -> Vec<String> {
    let mut ids = Vec::with_capacity(4);
    ids.push(query_id.to_string());
    ids.extend(companion_query_ids(query_id));
    ids
}

/// Whether the UI renders the histogram timeline for this display type
/// (NAN-1429).
///
/// Mirrors the gate in `nanosiem-web/src/pages/Search.tsx` (the
/// `<TimelineVisualization>` render condition): tree, asset, cloud, and
/// lateral views ship their own visualizations; timechart / ranked_bar / flow
/// render their own charts. For those, the histogram companion's full-window
/// scan was computed and then discarded — so the backend skips it entirely.
/// Events and Transaction render the timeline; lake stats tables omit it.
/// Lake stats pipelines omit the base-event timeline (NAN-3077). A second
/// full-window scan competes with the aggregation for tenant CPU and reads
/// the same files again. Inspect the AST so quoted pipes and downstream
/// sorting/filtering cannot accidentally re-enable the companion.
pub(super) fn lake_histogram_applies(query: &Query) -> bool {
    fn contains_stats(query: &Query) -> bool {
        match query {
            Query::Search(_) => false,
            Query::Piped { source, command } => {
                matches!(command, Command::Stats { .. }) || contains_stats(source)
            }
        }
    }
    display_type_renders_timeline(determine_display_type(query)) && !contains_stats(query)
}

/// Whether the base-search histogram's sum is the result's row count: true
/// only when every pipe stage keeps each base event as exactly one row.
/// Row-reducing stages (`where`, `dedup`, `head`, `search`, …) keep the
/// histogram for the timeline but not its sum as the total.
pub(super) fn lake_histogram_counts_result_rows(query: &Query) -> bool {
    match query {
        Query::Search(_) => true,
        Query::Piped { source, command } => {
            matches!(
                command,
                Command::Table { .. }
                    | Command::Fields { .. }
                    | Command::Rename { .. }
                    | Command::Fillnull { .. }
                    | Command::Eval { .. }
                    | Command::Rex { .. }
                    | Command::Sort { limit: None, .. }
                    | Command::Reverse
            ) && lake_histogram_counts_result_rows(source)
        }
    }
}

fn display_type_renders_timeline(display_type: DisplayType) -> bool {
    matches!(
        display_type,
        DisplayType::Events | DisplayType::Table | DisplayType::Transaction
    )
}

/// Page directives that emit a synthetic single-row marker (no ClickHouse scan)
/// and let the frontend fetch detail from a companion endpoint. This is the ONE
/// list — referenced by both the `core_search` short-circuit (which builds the
/// marker) and the streaming router (which keeps these off the incremental-row
/// path). Add a new marker page here only.
///
/// NAN-1580: `retro` originally slipped through the streaming path because these
/// two sites hand-rolled this list independently and only one was updated.
/// (Asset/cloud/lateral/tree are deliberately NOT here — they render richer
/// dossier fast-paths, detected via their own `extract_*_command` flags.)
pub(super) fn is_command_page_marker(display_type: DisplayType) -> bool {
    matches!(
        display_type,
        DisplayType::Services
            | DisplayType::Service
            | DisplayType::Trace
            | DisplayType::Metric
            | DisplayType::Retro
    )
}

/// Whether a search request can touch the derived `risk` dataset (NAN-1798
/// P2) — directly (`dataset=risk`) or through a `[dataset=risk …]` subsearch
/// bracket. The bracket check is a cheap textual pre-filter (the parser only
/// accepts the literal `dataset=` token form); a false positive — e.g. the
/// text inside a quoted string — only costs an optimization (prevalence
/// pushdown skip / an unused risk config attach), never correctness.
pub(super) fn touches_risk_dataset(dataset: Option<&str>, raw_query: &str) -> bool {
    crate::query::Dataset::from_selector(dataset.unwrap_or("logs")) == crate::query::Dataset::Risk
        || raw_query.to_ascii_lowercase().contains("dataset=risk")
}

/// Input-side field-name validation for the nPL request path (NAN-1354).
///
/// Runs after parse and before SQL generation so a malformed or typo'd field
/// reference is rejected with guidance instead of reaching codegen (which escapes
/// it anyway) or ClickHouse (which fails opaquely). This is the second line of
/// defense behind the generators' escaping — a defense-in-depth gate, not the
/// sole protection.
///
/// Permissive by design: unknown ext-JSON fields and OCSF-dotted names pass;
/// only names that closely resemble a UDM field (likely typos) or that fail the
/// safe-format check are rejected. Output aliases (eval/rename/spath targets) are
/// not format-checked here — codegen escaping owns their safety.
///
/// Profile-aware (NAN-1380): the active schema profile is consulted so a real
/// column of the active schema (e.g. a promoted OCSF dotted column one edit
/// away from a UDM name, `user.name` vs `user_name`) is never flagged as a typo.
pub(crate) fn validate_query_field_names(
    query: &Query,
    profile: &dyn crate::schema::SchemaProfile,
) -> Result<(), SearchError> {
    // NAN-2019: reject a zero timechart span / bin span / bin hop here — this runs
    // on every search path (core_search / streaming / explain), so all paths get a
    // clean 400 instead of the SQL-pushdown path emitting `INTERVAL 0` and coming
    // back as a ClickHouse 500. The bin-hop codegen guard (NAN-2010/F22) and the
    // timechart in-memory guard (F28) stay as defense-in-depth for non-search
    // codegen paths (saved rules, dashboards).
    validate_time_spans(query)?;

    // NAN-2373: a filter on a column that no upstream stage produces is a query
    // error, not a legitimate empty result set.
    output_column_guard::validate_declared_output_column_references(query)?;

    if let Some(err) =
        crate::query::validation::validate_query_fields_with_profile(query, Some(profile))
            .into_iter()
            .next()
    {
        return Err(SearchError::FieldNotFound {
            field: err.field_name,
            suggestions: err.suggestions,
            message: err.message,
        });
    }
    Ok(())
}

/// Reject non-positive `timechart` / `bin` spans and `bin` hop advances before
/// they reach SQL generation or ClickHouse (NAN-2019). A zero span becomes
/// `INTERVAL 0` / a divide-by-zero — a clean validation error is far better than
/// a ClickHouse 500 or a panic. Walks the piped command chain.
fn validate_time_spans(query: &Query) -> Result<(), SearchError> {
    let err = |m: &str| Err(SearchError::SqlValidationError(m.to_string()));
    let mut node = query;
    while let Query::Piped { source, command } = node {
        match command {
            Command::Timechart { span, .. } if span.is_zero() => {
                return err("timechart span must be greater than 0");
            }
            Command::Bin {
                span, window_type, ..
            } => {
                match span {
                    BinSpan::Time(d) if d.is_zero() => {
                        return err("bin span must be greater than 0");
                    }
                    BinSpan::Numeric(n) if *n <= 0.0 => {
                        return err("bin span must be greater than 0");
                    }
                    BinSpan::Bins(0) => {
                        return err("bin bins must be greater than 0");
                    }
                    _ => {}
                }
                if let WindowType::Hop { advance } = window_type {
                    if advance.is_zero() {
                        return err("bin hop must be greater than 0");
                    }
                }
            }
            _ => {}
        }
        node = source;
    }
    Ok(())
}

/// Get the semantic terminal command, skipping formatting commands like sort/head/tail
/// This finds the command that determines what kind of data we're displaying
pub(super) fn get_semantic_terminal_command(query: &Query) -> Option<&Command> {
    match query {
        Query::Search(_) => None,
        Query::Piped { command, source } => {
            // If the terminal command is a formatting command, look at the source
            if is_formatting_command(command) {
                get_semantic_terminal_command(source)
            } else {
                Some(command)
            }
        }
    }
}

/// Check if a command is a "formatting" command that doesn't change the data type
/// These commands modify display/order but don't change whether we're showing
/// events, aggregated table, chart, etc.
fn is_formatting_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Sort { .. } |
        Command::Head { .. } |
        Command::Tail { .. } |
        Command::Reverse |
        Command::Dedup { .. } |
        Command::Rename { .. } |
        Command::Fields { .. } |
        Command::Where { .. } |  // Row filtering doesn't change display type
        Command::Eval { .. } |   // Adding computed columns doesn't change display type
        Command::Ai { .. } // AI enrichment doesn't change display type
    )
}

/// Normalize field name for column order (matches clickhouse_sql_gen::normalize_field_name)
fn normalize_column_name(field: &str) -> &str {
    match field {
        "_time" => "timestamp",
        "sourcetype" => "source_type",
        _ => field,
    }
}

/// Extract column order from the table command if present
fn get_column_order(query: &Query) -> Option<Vec<String>> {
    // Walk the full pipeline to collect columns from stats + eval + table commands
    let mut columns: Vec<String> = Vec::new();
    collect_column_order_recursive(query, &mut columns);

    if columns.is_empty() {
        return None;
    }
    Some(columns)
}

/// Recursively collect column order from the query pipeline.
/// Stats/Chart produce group_by fields + aggregation aliases.
/// Eval adds computed fields. Table overrides everything.
fn collect_column_order_recursive(query: &Query, columns: &mut Vec<String>) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            collect_column_order_recursive(source, columns);
            match command {
                Command::Table { fields } => {
                    // Table overrides all previous columns
                    columns.clear();
                    columns.extend(fields.iter().map(|f| {
                        f.alias
                            .clone()
                            .unwrap_or_else(|| normalize_column_name(&f.name).to_string())
                    }));
                }
                Command::Stats {
                    aggregations,
                    group_by,
                }
                | Command::Chart {
                    aggregations,
                    group_by,
                } => {
                    // Stats resets columns to: group_by fields + aggregation result names
                    columns.clear();
                    if let Some(gb) = group_by {
                        columns.extend(gb.iter().cloned());
                    }
                    for agg in aggregations {
                        let name = if let Some(a) = agg.alias.as_ref() {
                            a.clone()
                        } else if agg.field.is_none() && agg.func == AggFunc::Count {
                            "count".to_string()
                        } else if matches!(agg.func, AggFunc::Values | AggFunc::List) {
                            if let Some(field) = agg.field.as_ref() {
                                format!("{}_{}", agg.func.as_str(), field)
                            } else {
                                agg.func.as_str().to_string()
                            }
                        } else {
                            agg.func.as_str().to_string()
                        };
                        columns.push(name);
                    }
                }
                Command::Top {
                    field,
                    by_fields,
                    show_count,
                    show_percent,
                    ..
                }
                | Command::Rare {
                    field,
                    by_fields,
                    show_count,
                    show_percent,
                    ..
                } => {
                    // top/rare replace the row shape (`stats … | top f`
                    // listed the stats columns).
                    columns.clear();
                    columns.extend(by_fields.iter().cloned());
                    columns.push(field.clone());
                    if *show_count {
                        columns.push("count".to_string());
                    }
                    if *show_percent {
                        columns.push("percent".to_string());
                    }
                }
                Command::Eval { assignments } => {
                    // Eval adds new computed columns (if not already present)
                    for assignment in assignments {
                        if !columns.contains(&assignment.field) {
                            columns.push(assignment.field.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Whether the query's result rows are grouped buckets — one row per distinct
/// value of the grouping dimensions, as produced by `stats`/`chart`/`timechart`
/// `by …`, or by `top`/`rare`.
///
/// Those dimension columns carry each row's identity, so they must survive
/// result serialization even when empty. The executor otherwise prunes empty
/// columns to keep payloads small, which is right for a raw event — most of the
/// 75+ UDM columns are empty on any given event — but on a grouped row it
/// deletes the group-by key itself. The "no user" bucket of `stats count by
/// user` arrives as a bare `{"count": 634}`, indistinguishable from a grand
/// total; and grouping by a field that exists nowhere yields exactly one such
/// bucket, so a meaningless query answers with a confident number and no error
/// (NAN-1848).
///
/// Deliberately an AST question, not a SQL-text one. `eventstats … by user`
/// groups in a subquery but returns wide raw events through it, and `dedup`
/// likewise — sniffing the generated SQL for `GROUP BY` would stop pruning
/// those, bloating every row with all 75+ mostly-empty UDM columns.
///
/// True as soon as *any* command in the pipeline groups, not just the terminal
/// one: nothing downstream can un-aggregate those buckets back into raw events,
/// so `stats count by user | table user, count` and `… | rename user as who`
/// still deliver buckets, and their keys must survive. Because this only decides
/// whether to prune — never what to name anything — it needs no knowledge of how
/// a later command reshapes the columns.
pub(super) fn query_produces_grouped_rows(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            command_groups_rows(command) || query_produces_grouped_rows(source)
        }
    }
}

/// Whether this single command turns rows into buckets keyed by a dimension.
/// See [`query_produces_grouped_rows`], which is this over a whole pipeline —
/// and the prevalence-join path, which pushes a *slice* of post-prevalence
/// commands into SQL and so must ask the question per command.
pub(super) fn command_groups_rows(command: &Command) -> bool {
    matches!(
        command,
        Command::Stats { .. }
            | Command::Chart { .. }
            | Command::Timechart { .. }
            | Command::Top { .. }
            | Command::Rare { .. }
    )
}

/// Check if the query has any aggregation command before the terminal command
fn has_aggregation_in_query(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            // Check if current command is an aggregation
            let is_agg = matches!(
                command,
                Command::Stats { .. }
                    | Command::Chart { .. }
                    | Command::Timechart { .. }
                    | Command::Top { .. }
                    | Command::Rare { .. }
                    | Command::EventStats { .. }
                    | Command::Transaction { .. }
            );
            is_agg || has_aggregation_in_query(source)
        }
    }
}

/// Convert a ParseError to a SearchError with structured information
fn convert_parse_error(parse_error: ParseError) -> SearchError {
    SearchError::StructuredParseError {
        message: parse_error.message.clone(),
        position: parse_error.position,
        line: parse_error.line,
        column: parse_error.column,
        token: parse_error.token.clone(),
        expected: parse_error.expected.clone(),
        suggestions: parse_error
            .suggestions
            .iter()
            .map(|s| ErrorSuggestion {
                description: s.description.clone(),
                replacement: s.replacement.clone(),
            })
            .collect(),
        formatted: format!("{}", parse_error),
    }
}

// Static regex for time modifiers - compiled once at startup
// Pattern to match earliest=-24h, earliest=-1d, latest=now, etc.
// Group 1: modifier (earliest/latest)
// Group 2: number (optional, for -24, -7, etc.)
// Group 3: unit (optional, for h, d, m, etc.)
// Group 4: "now" (optional, alternative to number+unit)
static TIME_MODIFIER_PATTERN: once_cell::sync::Lazy<regex::Regex> =
    once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?i)\b(earliest|latest)=(?:(-?\d+)([smhdwMy])|(now))\b").unwrap()
    });

/// Extract and parse time modifiers (earliest/latest) from the query
/// Returns the cleaned query and optional time offset in seconds
///
/// NAN-3377: comments are stripped FIRST, with the parser's own
/// `strip_comments` (quote-aware, so `url="http://x"` survives). The tidy-up
/// below flattens newlines, and a `//` comment ends at a newline: flattening
/// first turned `base\n// note\n| where x=1` into one line whose comment
/// swallowed the `| where`. Stripping first also means an `earliest=` written
/// inside a comment no longer sets the search range — exactly what the parser
/// sees, since it strips comments before anything else.
fn extract_time_modifiers(query: &str) -> (String, Option<i64>, Option<i64>) {
    tracing::debug!(
        "extract_time_modifiers called with query: {}",
        crate::inputlookup::storage_policy::redact_url_credentials(query)
    );

    let without_comments = crate::query::strip_comments(query);
    let query = without_comments.as_str();

    let time_pattern = &*TIME_MODIFIER_PATTERN;

    let mut earliest_offset: Option<i64> = None;
    let mut latest_offset: Option<i64> = None;
    // NAN-3337: a modifier inside a `[...]` subsearch never sets the OUTER
    // range. It stays in the query text, where `parse_query` rejects it.
    let depths = crate::query::subsearch_depths(query);
    // `x.latest=-1h` is a field filter, as in the parser's scan.
    let top_level = |m: &regex::Match<'_>| {
        depths.get(m.start()).copied().unwrap_or(0) == 0
            && (m.start() == 0 || query.as_bytes()[m.start() - 1] != b'.')
    };

    for cap in time_pattern.captures_iter(query) {
        if !cap.get(0).is_some_and(|m| top_level(&m)) {
            continue;
        }
        let modifier = cap
            .get(1)
            .map(|m| m.as_str().to_lowercase())
            .unwrap_or_default();

        // Check if it's "now" (group 4)
        if cap.get(4).is_some() {
            tracing::debug!("Time modifier: {}=now", modifier);
            if modifier == "latest" {
                latest_offset = Some(0); // now = 0 offset
            }
            continue;
        }

        // Otherwise it's number+unit (groups 2 and 3)
        let value_str = cap.get(2).map(|m| m.as_str()).unwrap_or("0");
        let unit = cap.get(3).map(|m| m.as_str()).unwrap_or("");

        let value: i64 = value_str.parse().unwrap_or(0);

        // Convert to seconds
        let seconds = match unit {
            "s" => value,
            "m" => value * 60,
            "h" => value * 3600,
            "d" => value * 86400,
            "w" => value * 604800,
            "M" => value * 2592000,  // ~30 days
            "y" => value * 31536000, // ~365 days
            _ => value,
        };

        tracing::debug!(
            "Time modifier: {}={}{} -> {} seconds",
            modifier,
            value,
            unit,
            seconds
        );

        if modifier == "earliest" {
            earliest_offset = Some(seconds);
        } else if modifier == "latest" {
            latest_offset = Some(seconds);
        }
    }

    // Remove the time modifiers from the query
    let cleaned = time_pattern
        .replace_all(query, |cap: &regex::Captures<'_>| {
            let whole = cap.get(0).expect("match");
            if top_level(&whole) {
                String::new()
            } else {
                whole.as_str().to_string()
            }
        })
        .to_string();
    // Clean up any double spaces
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    tracing::debug!(
        "Cleaned query: {}, earliest: {:?}, latest: {:?}",
        crate::inputlookup::storage_policy::redact_url_credentials(&cleaned),
        earliest_offset,
        latest_offset
    );

    (cleaned, earliest_offset, latest_offset)
}

/// Convert an AST time window to the prevalence-service time window.
///
/// Rejects `window=1h` on EVERY prevalence path (audit P2). The JOIN builder
/// already errored on `OneHour`, but the dict-fallback path silently coerced it
/// to 24h — so the same `| prevalence window=1h` returned different truth
/// depending on which path the query shape selected. 1h prevalence isn't
/// meaningful (the dictionaries refresh every 5–10min), so both paths now
/// reject it identically. Threading this through the single converter both
/// search paths call keeps the contract path-independent.
fn ast_to_prevalence_time_window(
    ast_tw: Option<&AstTimeWindow>,
) -> Result<PrevalenceTimeWindow, SearchError> {
    match ast_tw {
        // NAN-1689: SqlValidationError (not PrevalenceError) so this
        // user-actionable guidance surfaces as a clean 400 carrying the real
        // message. PrevalenceError also wraps operational ClickHouse failures
        // (prevalence_processing.rs) that must stay masked as 500 — so it can't
        // be blanket-mapped to 400.
        Some(AstTimeWindow::OneHour) => Err(SearchError::SqlValidationError(
            "prevalence window=1h is not supported; use 24h, 7d, or 30d".to_string(),
        )),
        Some(AstTimeWindow::TwentyFourHours) => Ok(PrevalenceTimeWindow::TwentyFourHours),
        Some(AstTimeWindow::SevenDays) => Ok(PrevalenceTimeWindow::SevenDays),
        Some(AstTimeWindow::ThirtyDays) => Ok(PrevalenceTimeWindow::ThirtyDays),
        None => Ok(PrevalenceTimeWindow::ThirtyDays), // Default: match dictionary 30-day window
    }
}

/// Partition post-prevalence commands into SQL-pushable and remaining.
///
/// Scans the command list for an aggregation command (Stats, Top, Rare, Timechart).
/// Once found, that command and all subsequent commands that can be chained in SQL
/// (Sort, Head, Tail, Table, Fields, Rename, Dedup) are collected as SQL-pushable.
///
/// Returns (sql_pushable_commands, total_count_of_commands_consumed).
/// `total_count_of_commands_consumed` includes WHERE and EVAL commands that are
/// handled inline in the prevalence SQL, plus the SQL-pushable aggregation chain.
/// The caller uses this count to skip those commands in Rust post-processing.
fn partition_sql_pushable_commands(commands: &[Command]) -> (Vec<Command>, usize) {
    // Find the index of the first aggregation command
    let agg_index = commands.iter().position(|cmd| {
        matches!(
            cmd,
            Command::Stats { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::Timechart { .. }
        )
    });

    let Some(agg_idx) = agg_index else {
        return (Vec::new(), 0);
    };

    // Collect the aggregation command and all following SQL-chainable commands
    let mut sql_pushable = vec![commands[agg_idx].clone()];
    let mut end_idx = agg_idx + 1;

    for cmd in &commands[agg_idx + 1..] {
        if matches!(
            cmd,
            Command::Sort { .. }
                | Command::Head { .. }
                | Command::Tail { .. }
                | Command::Table { .. }
                | Command::Fields { .. }
                | Command::Rename { .. }
                | Command::Dedup { .. }
        ) {
            sql_pushable.push(cmd.clone());
            end_idx += 1;
        } else {
            break;
        }
    }

    // The number of commands consumed = everything from the start through end_idx.
    // Commands before the aggregation (WHERE, EVAL) are handled inline in prevalence SQL,
    // so we consume the entire range.
    (sql_pushable, end_idx)
}

/// Extract just the base search expression from a query, stripping ALL pipeline commands.
/// Used by field-values endpoint which needs access to all raw columns.
/// Stats, table, fields, etc. all restrict columns making field-values fail.
/// The base search expression already contains the key filters (source_type, src_ip, etc.)
/// so the field-values results remain properly scoped.
fn extract_base_search(query: &Query) -> Query {
    match query {
        Query::Search(_) => query.clone(),
        Query::Piped { source, .. } => extract_base_search(source),
    }
}

/// Strip internal lookup fields from search results
///
/// These fields (_domain_lookup, _hash_lookup, _ip_lookup) are used internally
/// for efficient SQL JOINs during prevalence enrichment and should not be
/// exposed to users.
fn strip_internal_lookup_fields(results: &mut Vec<serde_json::Value>) {
    const INTERNAL_FIELDS: &[&str] = &[
        "_domain_lookup",
        "_hash_lookup",
        "_ip_lookup",
        // NAN-362 dict-lookup scratch columns used in prevalence SQL
        "_dp_host_count",
        "_dp_first_seen",
        "_dp_last_seen",
        "_dp_total_occurrences",
        "_ip_host_count",
        "_ip_first_seen",
        "_ip_last_seen",
        "_ip_total_occurrences",
        "_hp_host_count",
        "_hp_first_seen",
        "_hp_last_seen",
        "_hp_total_occurrences",
    ];

    for row in results.iter_mut() {
        if let Some(obj) = row.as_object_mut() {
            for field in INTERNAL_FIELDS {
                obj.remove(*field);
            }
        }
    }
}

/// Search execution service
///
/// Supports both PostgreSQL and ClickHouse backends for log queries.
/// PostgreSQL is always used for lookup table enrichment.
#[derive(Clone)]
pub struct SearchService {
    /// ClickHouse client (for log queries)
    ch_client: Option<clickhouse::Client>,
    /// PostgreSQL control-plane metadata used by storage-neutral lake surfaces
    /// such as the retro-hunt feed catalog.
    metadata_pool: Option<sqlx::PgPool>,
    /// Service configuration
    config: SearchConfig,
    /// ClickHouse SQL generator
    ch_sql_generator: ClickHouseSqlGenerator,
    /// Lookup service for enrichment (uses PostgreSQL)
    lookup_service: Option<LookupService>,
    /// Prevalence service for filtering and enrichment (uses ClickHouse)
    prevalence_service: Option<PrevalenceService>,
    /// Storage-neutral point lookup used by search and scheduled rule
    /// decoration. In primary lake mode this is a tenant/snapshot-pinned
    /// worker client; it never falls back to ClickHouse prevalence state.
    prevalence_lookup: Option<std::sync::Arc<dyn PrevalenceLookup>>,
    /// NAN-2361 wave 6: the tenant-pinned IOC snapshot reader installed by
    /// `shared_tenant_view` from the SAME assignment as the query
    /// runtime (retro-hunt feed candidates on the shared lake). Always `None`
    /// on the process singleton and on dedicated services, which keep the
    /// `NANO_LAKE_*` process-pinned client.
    shared_ioc_client: Option<crate::enrichment::ioc::LakeIocClient>,
    /// InputLookup service for URL-based enrichment
    inputlookup_service: Option<InputLookupService>,
    /// Backend to use for log queries
    backend: SearchBackend,
    /// Optional tenant-pinned lake worker. Shadow mode retains ClickHouse as
    /// the response source; primary mode routes log queries to this client.
    lake_query: LakeQueryRuntime,
    /// Native OTLP Iceberg reader for API-local unattended evaluators such as
    /// metric monitors and SLOs. Interactive observability routes use the same
    /// service through nanosiem-search.
    otel_lake: Option<super::otel_lake::OtelLakeEvaluator>,
    /// ClickHouse executor (if configured)
    ch_executor: Option<ClickHouseExecutor>,
    /// NAN-2001: raw-SQL executors backed by the two dedicated ClickHouse
    /// feature identities. `search_sql` selects between them by the caller's
    /// `RawSqlAuditAccess` so the table allowlist + audit-row hiding are enforced
    /// by ClickHouse (grants + row policy), not by the retired AST walk. Kept
    /// distinct from `ch_executor` (the broad `nanosiem` account) — raw SQL never
    /// runs on the broad account.
    ch_executor_rawsql: Option<ClickHouseExecutor>,
    ch_executor_rawsql_noaudit: Option<ClickHouseExecutor>,
    /// Query tracker for cancellation support (local instance monitoring)
    query_tracker: super::query_tracking::QueryTracker,
    /// Live cell SSE cancellation survives per-request tenant-view cloning.
    follow_cancellations: std::sync::Arc<dashmap::DashMap<String, tokio::sync::watch::Sender<bool>>>,
    /// Job store for async search support (pluggable: in-memory or Redis)
    job_store: std::sync::Arc<dyn super::jobs::SearchJobStore>,
    durable_job_control: Option<std::sync::Arc<dyn super::job_control_store::DurableJobControlStore>>,
    /// Admission controller for search query concurrency limits
    admission_controller: Option<std::sync::Arc<super::admission::AdmissionController>>,
    /// Server-owned identity namespace for admission counters. Dedicated and
    /// open-core services retain their historical user-only keyspace. A shared
    /// tenant view binds the immutable tenant UUID here before any query can
    /// acquire from the process/cell controller.
    admission_scope: super::tenant::SearchTenantScope,
    /// Per-query ClickHouse settings (set by admission-controlled path, consumed by execute)
    active_ch_settings: Option<super::admission::ClickHouseQuerySettings>,
    /// NAN-3093: a request-local view that answers only the search's
    /// timeline (`POST /api/search/histogram`). The primary lake runs the
    /// same preparation as a full search (scope, IOC resolution, lookup
    /// push-down) and then the histogram companion alone, so rows paint
    /// without waiting for it. Set through [`SearchService::histogram_only`].
    histogram_only: bool,
    /// Deployment-sized ceiling for per-query ClickHouse memory overrides.
    /// Priority tiers may ask for less, but never more than this value.
    query_memory_ceiling_bytes: Option<u64>,
    /// Internal server-side output limits for unattended execution. Presence
    /// also suppresses the interactive count companion when the caller does
    /// not consume `total_count`.
    active_execution_limits: Option<super::types::SearchExecutionLimits>,
    /// AI client for inline LLM classification in queries (`| ai` pipe).
    /// Open-core builds wire `NoopAiClient`; enterprise builds inject the
    /// `AiPipeAgent`-backed implementation via `set_ai_client`.
    ai_client: std::sync::Arc<dyn AiClient>,
    /// NAN-2922: true only when `ai_client` was installed by
    /// [`SearchService::set_tenant_ai_client`] on an enterprise-shared view,
    /// i.e. it is bound to the tenant's billing authority. Every tenant-view
    /// constructor resets it; the shared Search gate admits `| ai` only when set.
    ai_pipe_tenant_bound: bool,
    /// Cloud risk analytics provider for cloud_overview / cloud_dossier risk
    /// fan-out. Open-core builds wire `NoopCloudRiskProvider`; enterprise
    /// builds inject the `RiskAnalyticsService`-backed implementation via
    /// `set_cloud_risk`.
    cloud_risk: std::sync::Arc<dyn CloudRiskProvider>,
    /// Table name resolver for clustered/standalone ClickHouse deployments
    table_names: TableNames,
    /// Hot-reloadable query safety limits (read at query time, updated by config polling)
    query_limits: std::sync::Arc<tokio::sync::RwLock<crate::settings::SearchQueryLimitsConfig>>,
    /// Active schema profile (OCSF Phase 3a, NAN-1241). Defaults to
    /// [`UdmProfile`](crate::schema::UdmProfile); an OCSF deployment injects an
    /// `OcsfProfile` via [`with_profile`](SearchService::with_profile). It is
    /// passed to the SQL generator at construction so default-view projection,
    /// field resolution, and the FROM table follow the active schema.
    active_profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    /// Cached decay-factor + cleared-boundary provider for the derived
    /// `dataset=risk` base source (NAN-1798 P2). Resolves the SAME values the
    /// enterprise `RiskRepository` binds (60s cache; open-core schema degrades
    /// to the shipped defaults) so risk-dataset scores equal the Risk page /
    /// leaderboard numbers.
    risk_query_config: std::sync::Arc<crate::risk::config_provider::RiskQueryConfigProvider>,
    /// Process-lifetime memo of the baseline-agg MV activation watermark
    /// (`baseline_agg_meta.active_since`, NAN-1895). Migration 167 writes it
    /// ONCE and it never changes, so it is read lazily on the first `| baseline`
    /// query and cached for the life of the service. A CH read ERROR is NOT
    /// cached (the next query retries); a missing row caches `None` (the agg
    /// fast path stays off — fail-safe to the raw scan). Shared across clones
    /// via `Arc` so the memo survives the per-request service clones.
    baseline_agg_active_since:
        std::sync::Arc<tokio::sync::OnceCell<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl SearchService {
    /// Test-only: point this service's lake backend, prevalence and IOC reads
    /// at one lean-lake cell route (the open build's analogue of the hosted
    /// tenant view, without changing the admission scope).
    #[cfg(all(test, not(feature = "enterprise")))]
    pub(crate) fn pinned_to_cell_route_for_test(
        &self,
        route: &crate::search::lake_cell::LakeCellRoute,
        store: std::sync::Arc<dyn crate::search::jobs::SearchJobStore>,
    ) -> Result<Self, SearchError> {
        let timeout =
            std::time::Duration::from_secs(crate::search::lake::DEFAULT_LAKE_CELL_TIMEOUT_SECS);
        let mut service = self.clone();
        service.lake_query = LakeQueryRuntime::from_lake_cell_route(route, timeout)
            .map_err(SearchError::ServiceUnavailable)?;
        service.prevalence_lookup = Some(std::sync::Arc::new(
            LakePrevalenceClient::from_lake_cell_route(
                route,
                crate::search::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD,
                timeout,
            )
            .map_err(SearchError::ServiceUnavailable)?,
        ));
        service.shared_ioc_client = Some(
            crate::enrichment::ioc::LakeIocClient::from_lake_cell_route(route)
                .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?,
        );
        service.job_store = store;
        Ok(service)
    }
}

impl SearchService {
    fn prevalence_lookup_for_runtime(
        lake_query: &LakeQueryRuntime,
        clickhouse_fallback: Option<&PrevalenceService>,
    ) -> Option<std::sync::Arc<dyn PrevalenceLookup>> {
        if lake_query.mode == LakeQueryMode::Primary {
            // NAN-3451: the Settings rarity threshold drives the lake client
            // (the hot-reloaded service's live value); the env threshold is
            // only its fallback.
            return LakePrevalenceClient::from_env()
                .unwrap_or_else(|error| panic!("invalid lake prevalence configuration: {error}"))
                .map(|client| match clickhouse_fallback {
                    Some(service) => client.with_rarity_setting(service.rarity_setting()),
                    None => client,
                })
                .map(|client| std::sync::Arc::new(client) as std::sync::Arc<dyn PrevalenceLookup>);
        }
        clickhouse_fallback.map(|service| {
            std::sync::Arc::new(service.clone()) as std::sync::Arc<dyn PrevalenceLookup>
        })
    }

    fn lake_runtime_for_profile(profile: &dyn crate::schema::SchemaProfile) -> LakeQueryRuntime {
        LakeQueryRuntime::from_env(profile.id())
            .unwrap_or_else(|error| panic!("invalid lake query configuration: {error}"))
    }

    /// The tenant-aware `table_names` registry key for the active profile's logs
    /// table. UDM → `"logs"` (byte-identical to today); OCSF → `"ocsf_logs"`.
    ///
    /// Derived from the profile's fully-qualified `table_name()` by stripping the
    /// `nanosiem.` database prefix, so cluster/tenant prefixing still flows
    /// through the same registry (`ocsf_logs` is registered in
    /// `DISTRIBUTED_TABLE_SET`) rather than being hardcoded here.
    fn logs_table_key(profile: &dyn crate::schema::SchemaProfile) -> &'static str {
        match profile.id() {
            crate::schema::SchemaId::Ocsf => "ocsf_logs",
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics
            | crate::schema::SchemaId::Risk => "logs",
        }
    }

    /// Registry key for the active profile's `| baseline` first-seen day agg
    /// (NAN-1888). TWIN tables, one per schema lane, keyed exactly like
    /// [`logs_table_key`](Self::logs_table_key): the agg-served
    /// `entity_dimension_firsts` must see precisely what the profile's raw scan
    /// over its logs table would see — a shared target (the
    /// `entity_time_range_agg` pattern) would double-count every event under
    /// Vector's transitional dual-write and break raw/agg parity.
    fn dimension_agg_table_key(profile: &dyn crate::schema::SchemaProfile) -> &'static str {
        match profile.id() {
            crate::schema::SchemaId::Ocsf => "ocsf_entity_dimension_day_agg",
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics
            | crate::schema::SchemaId::Risk => "entity_dimension_day_agg",
        }
    }

    /// The active profile's lane label in
    /// `entity_dimension_day_agg_backfill_progress` (`'udm'` | `'ocsf'`,
    /// NAN-1895). Matches the `lane` the backfill script writes; used by the
    /// baseline agg's backfill-extension gate to check pre-activation days.
    fn dimension_agg_lane(profile: &dyn crate::schema::SchemaProfile) -> &'static str {
        match profile.id() {
            crate::schema::SchemaId::Ocsf => "ocsf",
            crate::schema::SchemaId::Udm
            | crate::schema::SchemaId::Spans
            | crate::schema::SchemaId::Metrics
            | crate::schema::SchemaId::Risk => "udm",
        }
    }

    /// Resolve the per-query DATASET profile (NAN-1559). Spans/Metrics carry their
    /// own field universe and physical table (`otel_spans`/`otel_metrics`); Logs
    /// keeps the active tenant profile (UDM/OCSF) unchanged. Used by the
    /// field-stats / field-values companions to scope column enumeration and field
    /// resolution to the dataset the search actually targets — otherwise an
    /// `otel_spans` base SQL is wrapped with the UDM column list and ClickHouse
    /// 47's `Unknown expression identifier 'action'`.
    fn dataset_profile(
        &self,
        dataset: Option<&str>,
    ) -> std::sync::Arc<dyn crate::schema::SchemaProfile> {
        match crate::query::Dataset::from_selector(dataset.unwrap_or("logs")) {
            crate::query::Dataset::Spans => {
                crate::schema::profile_for_id(crate::schema::SchemaId::Spans)
            }
            crate::query::Dataset::Metrics => {
                crate::schema::profile_for_id(crate::schema::SchemaId::Metrics)
            }
            // NAN-1798 P2: the derived risk grain's 15-column profile.
            crate::query::Dataset::Risk => {
                crate::schema::profile_for_id(crate::schema::SchemaId::Risk)
            }
            crate::query::Dataset::Logs => self.active_profile.clone(),
        }
    }

    /// Clone the SQL generator and retarget it to the per-query dataset's OTLP
    /// table (NAN-1559). `Dataset::Logs` is left UNTOUCHED so the generator keeps
    /// the tenant-aware logs table resolved by `with_table` (UDM `logs` / OCSF
    /// `ocsf_logs` / tenant-prefixed) — mirrors the data-query path in
    /// `core_search`; applying `with_dataset(Logs)` would clobber it to the
    /// literal `"logs"`.
    /// Async since NAN-1798 P2: when the request can touch the risk dataset —
    /// `dataset=risk`, or a LOGS query carrying a `[dataset=risk …]` bracket
    /// (judged from `raw_query`) — the cached decay/cleared config is resolved
    /// and attached BEFORE any dataset swap, so the derived base source (and
    /// therefore explain / field-values SQL) matches the executed data path.
    async fn dataset_generator(
        &self,
        dataset: Option<&str>,
        raw_query: &str,
        deny_set: &std::collections::BTreeSet<String>,
    ) -> ClickHouseSqlGenerator {
        let ds = crate::query::Dataset::from_selector(dataset.unwrap_or("logs"));
        // NAN-2009 (F20/F21): carry the caller's source-scope deny-set so the
        // resolve_identity ASOF join to identity_observations (reached via the
        // explain and field-values paths, which build their generator here)
        // filters its build side. Empty deny-set = byte-identical SQL.
        let mut generator = self
            .ch_sql_generator
            .clone()
            .with_source_scope_deny(deny_set.clone());
        if touches_risk_dataset(dataset, raw_query) {
            generator = generator.with_risk_config(self.risk_query_config.resolve().await);
        }
        match ds {
            crate::query::Dataset::Logs => generator,
            _ => generator.with_dataset(ds),
        }
    }

    /// Fallback field-stats column inventory used ONLY when `system.columns`
    /// introspection fails (NAN-1559). It must be dataset-correct: a hardcoded
    /// UDM list wrapped around an `otel_spans`/`otel_metrics` base SQL reintroduces
    /// the exact ClickHouse 47 `Unknown expression identifier` this fix removes.
    /// For spans/metrics the dataset's promoted columns are the safe minimum (they
    /// are guaranteed to exist on the table); logs keep the curated high-value UDM
    /// subset. Associated fn (no `self`) — depends only on the selector.
    fn field_stats_fallback_columns(dataset: Option<&str>) -> Vec<String> {
        let ds = crate::query::Dataset::from_selector(dataset.unwrap_or("logs"));
        match ds {
            crate::query::Dataset::Spans
            | crate::query::Dataset::Metrics
            // NAN-1798 P2: the risk dataset's columns ARE its derived
            // projection — the guaranteed-correct inventory.
            | crate::query::Dataset::Risk => {
                ds.columns().iter().map(|c| c.to_string()).collect()
            }
            crate::query::Dataset::Logs => [
                "user",
                "src_ip",
                "dest_ip",
                "src_host",
                "dest_host",
                // NAN-2208: canonical name, matching what `get_table_columns`
                // now returns. The physical column is still `action`; the alias
                // resolves in every scope the stats query runs in.
                "event_type",
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
            .collect(),
        }
    }

    /// Build a ClickHouse SQL generator using the appropriate table from DualPool
    /// and the active schema profile. The generator's FROM table is resolved
    /// through the tenant-aware `table_names` registry for the profile's logs
    /// table key, and the profile is injected so resolution/typing/default-view
    /// projection follow the active schema.
    fn ch_generator_for_pool(
        dual_pool: &DualPool,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) -> ClickHouseSqlGenerator {
        let table = dual_pool
            .table_names()
            .read_bare(Self::logs_table_key(profile.as_ref()));
        // NAN-1728: propagate cluster mode so non-logs dataset lanes (otel spans/
        // metrics, identity ASOF join) route their FROM to the `_distributed`
        // wrapper too — the logs lane is already routed via `read_bare` above.
        // No-op on single-shard (flag false → bare local table names).
        ClickHouseSqlGenerator::with_table(table)
            .with_profile(profile)
            .with_cluster_routing(dual_pool.table_names().is_clustered())
    }

    /// Create a new search service with DualPool (ClickHouse for logs, PostgreSQL
    /// for lookups). Uses the default [`UdmProfile`](crate::schema::UdmProfile),
    /// so behavior is unchanged for existing call sites.
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        Self::with_dual_pool_and_profile(
            dual_pool,
            std::sync::Arc::new(crate::schema::UdmProfile::new()),
        )
    }

    /// Create a new search service with DualPool and an explicit active schema
    /// profile. The profile selects the FROM logs table (UDM `logs` vs OCSF
    /// `ocsf_logs`, both through the tenant-aware registry) and is injected into
    /// the SQL generator so resolution / default-view projection follow it.
    pub fn with_dual_pool_and_profile(
        dual_pool: &DualPool,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) -> Self {
        let lake_query = Self::lake_runtime_for_profile(profile.as_ref());
        Self::with_dual_pool_profile_and_lake(dual_pool, profile, lake_query)
    }

    /// [`with_dual_pool_and_profile`](Self::with_dual_pool_and_profile) for a
    /// base service that has no process-wide lake route: the lake lane is
    /// selected but every request must go through a tenant view
    /// (`shared_tenant_view` / the lake-cell view), which binds its
    /// own tenant-pinned route — exactly the enterprise-shared base service.
    /// Reads no lake-route environment (NAN-3491).
    pub fn with_dual_pool_and_profile_unrouted(
        dual_pool: &DualPool,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) -> Self {
        let lake_query = LakeQueryRuntime {
            mode: LakeQueryMode::Primary,
            client: None,
        };
        Self::with_dual_pool_profile_and_lake(dual_pool, profile, lake_query)
    }

    fn with_dual_pool_profile_and_lake(
        dual_pool: &DualPool,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
        lake_query: LakeQueryRuntime,
    ) -> Self {
        let otel_lake = super::otel_lake::OtelLakeEvaluator::from_env()
            .unwrap_or_else(|error| panic!("invalid native OTLP lake configuration: {error}"));
        // `backend` is the executor for surfaces that have not moved to the
        // object lake (risk, telemetry, field helpers, and raw SQL). The lake
        // runtime is deliberately a logs-only routing decision in `search()`.
        let backend = SearchBackend::ClickHouse;
        let prevalence_lookup = Self::prevalence_lookup_for_runtime(&lake_query, None);
        let ch_executor = Some(ClickHouseExecutor::new(dual_pool.clickhouse().clone()));
        // NAN-2001: raw-SQL executors on the two dedicated feature identities.
        let ch_executor_rawsql = Some(ClickHouseExecutor::new(
            dual_pool.clickhouse_rawsql().clone(),
        ));
        let ch_executor_rawsql_noaudit = Some(ClickHouseExecutor::new(
            dual_pool.clickhouse_rawsql_noaudit().clone(),
        ));
        Self {
            ch_client: Some(dual_pool.clickhouse().clone()),
            metadata_pool: Some(dual_pool.postgres().clone()),
            config: SearchConfig::default(),
            ch_sql_generator: Self::ch_generator_for_pool(dual_pool, profile.clone()),
            lookup_service: None,
            prevalence_service: None,
            prevalence_lookup,
            shared_ioc_client: None,
            inputlookup_service: None,
            backend,
            lake_query,
            otel_lake,
            ch_executor,
            ch_executor_rawsql,
            ch_executor_rawsql_noaudit,
            query_tracker: super::query_tracking::QueryTracker::new(),
            follow_cancellations: std::sync::Arc::new(dashmap::DashMap::new()),
            job_store: std::sync::Arc::new(super::jobs::InMemoryJobStore::new()),
            durable_job_control: None,
            admission_controller: None,
            admission_scope: super::tenant::SearchTenantScope::dedicated(),
            active_ch_settings: None,
            histogram_only: false,
            query_memory_ceiling_bytes: super::admission::query_memory_ceiling_from_env(),
            active_execution_limits: None,
            ai_client: std::sync::Arc::new(NoopAiClient),
            ai_pipe_tenant_bound: false,
            cloud_risk: std::sync::Arc::new(NoopCloudRiskProvider),
            table_names: dual_pool.table_names(),
            query_limits: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::settings::SearchQueryLimitsConfig::default(),
            )),
            active_profile: profile,
            risk_query_config: std::sync::Arc::new(
                crate::risk::config_provider::RiskQueryConfigProvider::new(
                    dual_pool.postgres().clone(),
                ),
            ),
            baseline_agg_active_since: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        }
    }
    /// Create a new search service with DualPool, lookup, and prevalence support.
    /// Uses the default [`UdmProfile`](crate::schema::UdmProfile) — existing call
    /// sites keep today's behavior unchanged.
    pub fn with_dual_pool_lookup_and_prevalence(
        dual_pool: &DualPool,
        lookup_service: LookupService,
        prevalence_service: PrevalenceService,
    ) -> Self {
        Self::with_dual_pool_lookup_and_prevalence_and_profile(
            dual_pool,
            lookup_service,
            prevalence_service,
            std::sync::Arc::new(crate::schema::UdmProfile::new()),
        )
    }

    /// Profile-aware variant of [`with_dual_pool_lookup_and_prevalence`]. The
    /// active schema profile selects the FROM logs table (UDM `logs` vs OCSF
    /// `ocsf_logs`, both through the tenant-aware registry) and is injected into
    /// the SQL generator so resolution / default-view projection follow it. App
    /// boot passes the profile resolved from `NANO_SCHEMA_PROFILE`.
    ///
    /// [`with_dual_pool_lookup_and_prevalence`]: SearchService::with_dual_pool_lookup_and_prevalence
    pub fn with_dual_pool_lookup_and_prevalence_and_profile(
        dual_pool: &DualPool,
        lookup_service: LookupService,
        prevalence_service: PrevalenceService,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) -> Self {
        let lake_query = Self::lake_runtime_for_profile(profile.as_ref());
        let otel_lake = super::otel_lake::OtelLakeEvaluator::from_env()
            .unwrap_or_else(|error| panic!("invalid native OTLP lake configuration: {error}"));
        // Keep ClickHouse available for non-log datasets while the OCSF logs
        // lane is served by the tenant-pinned lake worker.
        let backend = SearchBackend::ClickHouse;
        let prevalence_lookup =
            Self::prevalence_lookup_for_runtime(&lake_query, Some(&prevalence_service));
        let ch_executor = Some(ClickHouseExecutor::new(dual_pool.clickhouse().clone()));
        // NAN-2001: raw-SQL executors on the two dedicated feature identities.
        let ch_executor_rawsql = Some(ClickHouseExecutor::new(
            dual_pool.clickhouse_rawsql().clone(),
        ));
        let ch_executor_rawsql_noaudit = Some(ClickHouseExecutor::new(
            dual_pool.clickhouse_rawsql_noaudit().clone(),
        ));
        Self {
            ch_client: Some(dual_pool.clickhouse().clone()),
            metadata_pool: Some(dual_pool.postgres().clone()),
            config: SearchConfig::default(),
            ch_sql_generator: Self::ch_generator_for_pool(dual_pool, profile.clone()),
            lookup_service: Some(lookup_service),
            prevalence_service: Some(prevalence_service),
            prevalence_lookup,
            shared_ioc_client: None,
            inputlookup_service: None,
            backend,
            lake_query,
            otel_lake,
            ch_executor,
            ch_executor_rawsql,
            ch_executor_rawsql_noaudit,
            query_tracker: super::query_tracking::QueryTracker::new(),
            follow_cancellations: std::sync::Arc::new(dashmap::DashMap::new()),
            job_store: std::sync::Arc::new(super::jobs::InMemoryJobStore::new()),
            durable_job_control: None,
            admission_controller: None,
            admission_scope: super::tenant::SearchTenantScope::dedicated(),
            active_ch_settings: None,
            histogram_only: false,
            query_memory_ceiling_bytes: super::admission::query_memory_ceiling_from_env(),
            active_execution_limits: None,
            ai_client: std::sync::Arc::new(NoopAiClient),
            ai_pipe_tenant_bound: false,
            cloud_risk: std::sync::Arc::new(NoopCloudRiskProvider),
            table_names: dual_pool.table_names(),
            query_limits: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::settings::SearchQueryLimitsConfig::default(),
            )),
            active_profile: profile,
            risk_query_config: std::sync::Arc::new(
                crate::risk::config_provider::RiskQueryConfigProvider::new(
                    dual_pool.postgres().clone(),
                ),
            ),
            baseline_agg_active_since: std::sync::Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// The active schema profile this service queries under.
    pub fn active_profile(&self) -> &std::sync::Arc<dyn crate::schema::SchemaProfile> {
        &self.active_profile
    }

    /// A copy of this service re-pinned to `profile`; every other dependency
    /// is shared. NAN-3492: a dedicated Search follows the worker-served
    /// schema this way after the field set changes.
    pub fn with_active_profile(
        &self,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) -> Self {
        let mut service = self.clone();
        service.set_active_profile(profile);
        service
    }

    /// Re-pin this service (and its SQL generator) to a schema profile. Used by
    /// the enterprise-shared tenant view to bind a tenant's own inventory.
    pub(crate) fn set_active_profile(
        &mut self,
        profile: std::sync::Arc<dyn crate::schema::SchemaProfile>,
    ) {
        self.ch_sql_generator = self.ch_sql_generator.clone().with_profile(profile.clone());
        self.active_profile = profile;
    }
    /// Get the current backend type
    pub fn backend(&self) -> SearchBackend {
        if self.lake_query.mode == LakeQueryMode::Primary {
            SearchBackend::Lake
        } else {
            self.backend
        }
    }

    /// Server-assigned tenant carried by the active lake client. Dedicated and
    /// legacy services remain tenantless. Shared resolvers use this as a final
    /// structural assertion after replacing a process-global service's worker.
    pub fn assigned_tenant_id(&self) -> Option<uuid::Uuid> {
        self.lake_query
            .assigned_tenant_id()
            .and_then(|tenant| uuid::Uuid::parse_str(tenant).ok())
    }

    /// The serving generation of the tenant-pinned primary-lake worker, as a
    /// result-cache identity (NAN-2361 wave 6). `None` off the primary lake
    /// or when the worker cannot report one stable generation; a shared
    /// tenant is then simply not served from cache.
    pub async fn serving_generation_key(&self) -> Option<crate::search::ServingGenerationKey> {
        if self.lake_query.mode != LakeQueryMode::Primary {
            return None;
        }
        let client = self.lake_query.client.as_ref()?;
        let pin = client.generation_pin().await.ok()?;
        Some(crate::search::ServingGenerationKey {
            generation_id: pin.generation_id,
            snapshot_id: pin.snapshot_id,
        })
    }

    /// Deep readiness for the tenant-pinned primary-lake worker. Legacy and
    /// shadow modes do not make the worker a serving dependency.
    pub async fn lake_worker_ready(&self) -> bool {
        if self.lake_query.mode != LakeQueryMode::Primary {
            return true;
        }
        let Some(client) = self.lake_query.client.as_ref() else {
            return false;
        };
        client.health().await.is_ok()
    }

    /// Enqueue a complete Prevalence export on the same generation-pinned,
    /// isolated job lane as heavy Search, Asset, and Cloud work. The handler
    /// supplies only semantic filters; the archived worker config owns every
    /// snapshot and object-store coordinate.
    pub async fn enqueue_durable_prevalence_export(
        &self,
        window: PrevalenceTimeWindow,
        artifact_type: Option<&str>,
        max_prevalence: u64,
        format: &str,
        scope: &crate::auth::ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        self.require_dedicated_retention_surface("durable Prevalence exports")?;
        if self.lake_query.mode != LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Prevalence exports require the primary lake backend".to_string(),
            ));
        }
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::ServiceUnavailable(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        let generation_pin = client.generation_pin().await?;
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::hours(window.hours());
        let task = crate::search::DurableLakeTask::PrevalenceExportV1 {
            window: window.to_string(),
            artifact_type: artifact_type.map(str::to_string),
            max_prevalence,
            format: format.to_string(),
        };
        let request = SearchRequest {
            query: format!("prevalence export window={window} format={format}"),
            time_range: TimeRangeInput::new(start, end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &task,
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Prevalence export admission failed: {error}"
                ))
            })
    }

    /// Return strict `unmapped.*` schema paths from the worker's pinned source
    /// manifest. These are stable schema names, not values sampled from rows.
    pub async fn lake_unmapped_field_names(&self) -> Result<Vec<String>, SearchError> {
        if self.lake_query.mode != LakeQueryMode::Primary {
            return Ok(Vec::new());
        }
        self.lake_query
            .client
            .as_ref()
            .ok_or_else(|| {
                SearchError::SqlValidationError(
                    "lake query backend is enabled without a worker client".to_string(),
                )
            })?
            .unmapped_field_names()
            .await
    }

    /// Install hard ClickHouse output limits on a one-shot cloned service.
    pub(crate) fn with_execution_limits(
        mut self,
        limits: super::types::SearchExecutionLimits,
    ) -> Self {
        self.active_execution_limits = Some(limits);
        self
    }
    /// Set the prevalence service
    pub fn set_prevalence_service(&mut self, prevalence_service: PrevalenceService) {
        if self.lake_query.mode != LakeQueryMode::Primary {
            self.prevalence_lookup = Some(std::sync::Arc::new(prevalence_service.clone()));
        }
        self.prevalence_service = Some(prevalence_service);
    }

    /// Override the point-serving backend without changing discovery/explorer
    /// surfaces. Primarily used by tenant-pinned lake deployments and focused
    /// contract tests.
    pub fn set_prevalence_lookup(
        &mut self,
        prevalence_lookup: std::sync::Arc<dyn PrevalenceLookup>,
    ) {
        self.prevalence_lookup = Some(prevalence_lookup);
    }

    /// The point-serving prevalence backend this view answers from: the
    /// tenant's lake client (gen1 snapshots or a lean cell's query[T]) on a
    /// lake view, the ClickHouse service otherwise. NAN-3451: hunt evidence
    /// measures lake prevalence through it.
    pub fn prevalence_lookup(&self) -> Option<std::sync::Arc<dyn PrevalenceLookup>> {
        self.prevalence_lookup.clone()
    }

    /// Set the inputlookup service
    pub fn set_inputlookup_service(&mut self, inputlookup_service: InputLookupService) {
        tracing::info!("InputLookup service configured successfully");
        self.inputlookup_service = Some(inputlookup_service);
    }

    pub fn storage_lookup_tenant_bound(&self) -> bool {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        shared_scope && self.assigned_tenant_id().is_some()
            && self.inputlookup_service.as_ref().and_then(InputLookupService::shared_storage_tenant) == self.assigned_tenant_id()
    }

    /// Set the AI client used by the `| ai` pipe operator. Enterprise builds
    /// inject an `AiPipeAgent`-backed implementation; open-core builds keep
    /// the default `NoopAiClient` which tags rows `ai_verdict = "SKIPPED"`.
    pub fn set_ai_client(&mut self, client: std::sync::Arc<dyn AiClient>) {
        self.ai_client = client;
        self.ai_pipe_tenant_bound = false;
    }

    /// Install an `| ai` client bound to this enterprise-shared view's tenant
    /// billing authority (NAN-2922, #4668). Refuses any view that is not a
    /// tenant-pinned shared view, so the flag cannot be set on the process
    /// singleton.
    pub fn set_tenant_ai_client(
        &mut self,
        client: std::sync::Arc<dyn AiClient>,
        tenant_id: uuid::Uuid,
    ) -> Result<(), SearchError> {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        if !shared_scope
            || tenant_id.is_nil()
            || self.assigned_tenant_id() != Some(tenant_id)
        {
            return Err(SearchError::ServiceUnavailable(
                "tenant AI client does not match the tenant view".into(),
            ));
        }
        self.ai_client = client;
        self.ai_pipe_tenant_bound = true;
        Ok(())
    }

    /// Whether `| ai` on this view is billed to its tenant (NAN-2922).
    pub fn ai_pipe_tenant_bound(&self) -> bool {
        self.ai_pipe_tenant_bound
    }

    /// Bind the `dataset=risk` decay / clear state of this enterprise-shared
    /// lean-lake cell view to its tenant, read by the caller in that tenant's
    /// signed transaction. Refuses the process singleton, a gen1 view, and a
    /// view pinned to any other tenant, so a risk search can only ever send
    /// the cell the requesting tenant's own clear boundaries.
    #[cfg(feature = "enterprise")]
    pub fn set_tenant_risk_config(
        &mut self,
        tenant_id: uuid::Uuid,
        decay: crate::risk::RiskDecayConfig,
        clear: &crate::enterprise_shared_risk::TenantRiskClearState,
    ) -> Result<(), SearchError> {
        if !self.admission_scope.is_enterprise_shared()
            || tenant_id.is_nil()
            || self.admission_scope.tenant_id() != Some(tenant_id)
            || self.assigned_tenant_id() != Some(tenant_id)
            || !self.serves_lake_cell()
        {
            return Err(SearchError::ServiceUnavailable(
                "tenant risk configuration does not match the tenant cell view".into(),
            ));
        }
        let provider = crate::risk::config_provider::RiskQueryConfigProvider::for_tenant(
            tenant_id, decay, clear,
        )
        .map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
        self.risk_query_config = std::sync::Arc::new(provider);
        Ok(())
    }

    /// Whether this view may serve `dataset=risk` for an enterprise-shared
    /// tenant: a lean-lake cell view whose risk state is bound to the same
    /// tenant the cell route and admission scope are pinned to.
    pub fn tenant_risk_dataset_bound(&self) -> bool {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        let tenant = self.assigned_tenant_id();
        shared_scope
            && self.serves_lake_cell()
            && tenant.is_some()
            && self.admission_scope.tenant_id() == tenant
            && self.risk_query_config.bound_tenant_id() == tenant
    }

    /// Set the cloud risk analytics provider used by the cloud overview /
    /// dossier surfaces. Enterprise builds inject the `RiskAnalyticsService`-
    /// backed implementation; open-core builds keep the default
    /// `NoopCloudRiskProvider` which returns empty risk data.
    pub fn set_cloud_risk(&mut self, provider: std::sync::Arc<dyn CloudRiskProvider>) {
        self.cloud_risk = provider;
    }

    /// Set the job store (e.g., RedisJobStore for active/active deployments)
    pub fn set_job_store(&mut self, store: std::sync::Arc<dyn super::jobs::SearchJobStore>) {
        self.job_store = store;
        self.durable_job_control = None;
    }

    /// The hosted job control attached to this tenant view, if any. Cached
    /// views compare it by pointer with the process's current producer so a
    /// dropped or re-attested producer is never served from a stale view
    /// (NAN-3531 N2a).
    pub fn durable_job_control(&self) -> Option<&std::sync::Arc<dyn super::job_control_store::DurableJobControlStore>> {
        self.durable_job_control.as_ref()
    }

    pub fn job_control(&self)->super::job_control_store::JobControlView<'_> {
        super::job_control_store::JobControlView {legacy:self.job_store.as_ref(),hosted:self.durable_job_control.as_deref()}
    }

    /// Attach only to an already tenant-pinned service view, never its process
    /// singleton. Backend failure is not permission to consult the legacy store.
    pub fn set_durable_job_control(&mut self,store:std::sync::Arc<dyn super::job_control_store::DurableJobControlStore>,
        assignment:super::job_coordinator_client::HostedAssignment)->Result<(),SearchError> {
        // Both gen1 and cell views must be structurally tenant-pinned before
        // the hosted coordinator can admit work.
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        if !shared_scope || self.lake_query.mode!=LakeQueryMode::Primary
            || !store.matches_binding(self.admission_scope,assignment) {
            return Err(SearchError::ServiceUnavailable("hosted job control identity does not match the tenant view".into()));
        }
        self.durable_job_control=Some(store);Ok(())
    }

    /// The tenant query[T] prefix this view talks to, when it is a lean-lake
    /// cell view. Cached views compare it with the current route so a moved
    /// tenant is never served from its old cell.
    pub fn lake_cell_query_base(&self) -> Option<&str> {
        self.lake_query
            .client
            .as_ref()
            .and_then(|client| client.lake_cell_query_base())
    }

    /// Scheduled detection RPCs have their own read-only cell process and
    /// cgroup. The tenant scope and authenticated route remain pinned.
    pub fn detection_lane_view(&self) -> Result<Self, SearchError> {
        let mut view = self.clone();
        view.lake_query = self.lake_query.detection_lane().map_err(SearchError::ServiceUnavailable)?;
        if let Some((base, tenant, token)) = view.lake_query.detection_prevalence_parts() {
            view.prevalence_lookup = Some(std::sync::Arc::new(LakePrevalenceClient::from_cell_detection_parts(
                base, tenant, token, super::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD,
                detection_prevalence_timeout(),
            ).map_err(SearchError::ServiceUnavailable)?));
        }
        Ok(view)
    }

    /// Whether this view's lake backend is a lean-lake cell (NAN-2891).
    pub fn serves_lake_cell(&self) -> bool {
        self.lake_query.mode == LakeQueryMode::Primary
            && self
                .lake_query
                .client
                .as_ref()
                .is_some_and(|client| client.is_lake_cell())
    }

    /// query[T]'s detection gate for one rule window (NAN-2891). `Ok(None)`
    /// off a lean-lake cell: gen1 detections run every window as before.
    pub async fn lake_cell_detection_plan(
        &self,
        rule_id: &str,
        window_start_us: i64,
        window_end_us: i64,
        grid_us: Option<i64>,
    ) -> Result<Option<super::LakeDetectionPlan>, SearchError> {
        if !self.serves_lake_cell() {
            return Ok(None);
        }
        match self.lake_query.client.as_ref() {
            Some(client) => {
                client
                    .detection_plan(rule_id, window_start_us, window_end_us, grid_us)
                    .await
            }
            None => Ok(None),
        }
    }

    /// A detached handle that records completed rule windows with query[T]'s
    /// detection gate (NAN-2891), so the caller can commit without holding
    /// its executor slot. `None` off a lean-lake cell.
    pub fn lake_cell_detection_committer(&self) -> Option<LakeCellDetectionCommitter> {
        if !self.serves_lake_cell() {
            return None;
        }
        self.lake_query
            .client
            .clone()
            .map(|client| LakeCellDetectionCommitter { client })
    }

    /// Resolve the event-time retention frontier for this service identity.
    ///
    /// A tenant-only shared scope is historical decoding state, never query
    /// authority. Keeping this check on `SearchService` gives every hand-built
    /// lake/ClickHouse companion one fail-closed seam instead of relying on the
    /// main nPL search path to have run first.
    pub(crate) fn retention_cutoff_at(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, SearchError> {
        match self.admission_scope {
            super::tenant::SearchTenantScope::Dedicated => Ok(None),
            super::tenant::SearchTenantScope::EnterpriseShared(_) => {
                Err(SearchError::ServiceUnavailable(
                    "enterprise-shared query has no current retention policy identity".to_string(),
                ))
            }
            retained @ super::tenant::SearchTenantScope::EnterpriseSharedRetained { .. } => {
                retained.event_time_cutoff(now).map(Some).ok_or_else(|| {
                    SearchError::ServiceUnavailable(
                        "enterprise-shared query retention policy is invalid".to_string(),
                    )
                })
            }
        }
    }

    /// Intersect a required search request range with the exact current
    /// event-time retention frontier. `None` means the entire requested window
    /// is expired and callers must return an empty result without touching a
    /// data backend.
    pub(crate) fn retention_bound_input_range(
        &self,
        range: &TimeRangeInput,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<TimeRangeInput>, SearchError> {
        let Some(cutoff) = self.retention_cutoff_at(now)? else {
            return Ok(Some(range.clone()));
        };
        if range.end < cutoff {
            return Ok(None);
        }
        Ok(Some(TimeRangeInput::new(
            range.start.max(cutoff),
            range.end,
        )))
    }

    /// Retention-bind an optional row-lookup range. Shared callers that omit a
    /// range receive the exact `cutoff..now` window; dedicated callers preserve
    /// the historical unbounded lookup. The boolean is true only when a
    /// caller-supplied window is wholly expired.
    pub(crate) fn retention_bound_optional_input_range(
        &self,
        range: Option<&TimeRangeInput>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(Option<TimeRangeInput>, bool), SearchError> {
        let Some(cutoff) = self.retention_cutoff_at(now)? else {
            return Ok((range.cloned(), false));
        };
        let Some(range) = range else {
            return Ok((Some(TimeRangeInput::new(cutoff, now)), false));
        };
        match self.retention_bound_input_range(range, now)? {
            Some(bound) => Ok((Some(bound), false)),
            None => Ok((None, true)),
        }
    }

    /// Intersect a hand-built query range with retention. This is the query
    /// generator's `TimeRange`, distinct from the API `TimeRangeInput` above.
    pub(crate) fn retention_bound_query_range(
        &self,
        range: &TimeRange,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<TimeRange>, SearchError> {
        let Some(cutoff) = self.retention_cutoff_at(now)? else {
            return Ok(Some(range.clone()));
        };
        if range.end <= cutoff {
            return Ok(None);
        }
        Ok(Some(TimeRange::new(range.start.max(cutoff), range.end)))
    }

    /// Variant for aggregate companions whose return shape has no unambiguous
    /// empty representation. A wholly expired range is rejected before backend
    /// access; callers may translate it to their ordinary empty response.
    pub(crate) fn retention_require_query_range(
        &self,
        range: &TimeRange,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TimeRange, SearchError> {
        self.retention_bound_query_range(range, now)?
            .ok_or(SearchError::InvalidTimeRange)
    }

    /// Release-close an event-bearing surface that does not yet carry a
    /// moving-cutoff proof. This is intentionally stricter than merely binding
    /// the retention revision: a cached aggregate or durable result can age
    /// across the cutoff while the revision remains unchanged.
    pub(crate) fn require_dedicated_retention_surface(
        &self,
        surface: &str,
    ) -> Result<(), SearchError> {
        match self.admission_scope {
            super::tenant::SearchTenantScope::Dedicated => Ok(()),
            super::tenant::SearchTenantScope::EnterpriseShared(_)
            | super::tenant::SearchTenantScope::EnterpriseSharedRetained { .. } => {
                Err(SearchError::ServiceUnavailable(format!(
                    "enterprise-shared {surface} is release-closed until its result carries a moving retention-cutoff proof"
                )))
            }
        }
    }

    /// Whether durable jobs for this cell tenant have a runner: the tenant's
    /// hosted producer (`durable_job_control`). NAN-3492: the explicitly
    /// trusted-local install (`NANO_TRUSTED_LOCAL`, never hosted) keeps its
    /// own Redis job store, which `lake_job_runner --cell-only --trusted-local`
    /// claims, so its dedicated cell needs no hosted producer.
    pub(crate) fn has_cell_job_runner(&self) -> bool {
        self.durable_job_control.is_some() || self.serves_trusted_local_cell()
    }

    /// NAN-3492: this service reads the explicitly trusted-local install's
    /// dedicated cell (see [`super::lake_cell::trusted_local_from_env`]).
    /// Never true under a shared scope or for a route without the flag.
    pub(crate) fn serves_trusted_local_cell(&self) -> bool {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        !shared_scope
            && self.serves_lake_cell()
            && self.lake_query.client.as_ref().is_some_and(|client| client.is_trusted_local())
    }

    /// NAN-3078: whether a typed product view that exceeds its interactive
    /// budget can escalate to a durable job on this service: a lean cell with
    /// its hosted job runner. The runner binds the job to the tenant's
    /// retention cutoff and query[T] enforces it.
    pub fn has_durable_view_lane(&self) -> bool {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        self.serves_lake_cell()
            && self.has_cell_job_runner()
            && (!shared_scope
                || self.admission_scope.require_retention_identity().is_ok())
    }

    /// NAN-3078: views whose durable assembler materializes the whole event
    /// set (Cloud user timeline, Cloud entity pivot) have no
    /// lean durable lane. Refuse with the interactive budget error so the
    /// caller is told to narrow the window instead of seeing a 503.
    pub(crate) fn require_materializing_view_lane(&self, surface: &str) -> Result<(), SearchError> {
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        if shared_scope || self.serves_lake_cell() {
            return Err(SearchError::ResourceExhausted(format!(
                "{surface} exceed the interactive event envelope and have no background-job lane on this tenant yet; narrow the time range or add filters"
            )));
        }
        Ok(())
    }

    /// NAN-3078: admit a typed durable product view (Cloud, Asset, baseline).
    /// Replaces the old shared-tenant release close: the durable result now
    /// carries a moving retention-cutoff proof end to end.
    ///
    /// * the admitted range is bound to the tenant's retention cutoff here;
    /// * the runner re-binds it at dispatch and signs a proof over it;
    /// * query[T] clamps every read to the proof's current cutoff and refuses
    ///   a compiled window outside the admitted range;
    /// * every read of the result re-checks the proof against the moving
    ///   cutoff and hides the result once the cutoff crosses its start.
    ///
    /// Returns the generation pin and the retention-bound range.
    pub(crate) async fn durable_view_admission(
        &self,
        surface: &str,
        range: &TimeRange,
    ) -> Result<(super::jobs::DurableLakeGenerationPin, TimeRange), SearchError> {
        if self.lake_query.mode != LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(format!(
                "{surface} require the primary lake backend"
            )));
        }
        let client = self.lake_query.client.as_ref().ok_or_else(|| {
            SearchError::ServiceUnavailable(
                "lake query backend is enabled without a worker client".to_string(),
            )
        })?;
        #[cfg(feature = "enterprise")]
        let shared_scope = self.admission_scope.is_enterprise_shared();
        #[cfg(not(feature = "enterprise"))]
        let shared_scope = !matches!(self.admission_scope, super::tenant::SearchTenantScope::Dedicated);
        if shared_scope && !self.has_durable_view_lane() {
            return Err(SearchError::ServiceUnavailable(format!(
                "enterprise-shared {surface} need the tenant's lean cell job runner and its current retention identity"
            )));
        }
        let bound = self
            .retention_bound_input_range(
                &TimeRangeInput::new(range.start, range.end),
                chrono::Utc::now(),
            )?
            .ok_or_else(|| {
                SearchError::SqlValidationError(format!(
                    "{surface}: the requested window is entirely past the tenant's retention"
                ))
            })?;
        let generation_pin = if client.is_lake_cell() {
            client.admission_generation().await?.0
        } else {
            client.generation_pin().await?
        };
        Ok((generation_pin, TimeRange::new(bound.start, bound.end)))
    }

    /// Get a reference to the job store
    pub fn job_store(&self) -> &dyn super::jobs::SearchJobStore {
        &*self.job_store
    }

    /// Set the admission controller for search query concurrency limits
    pub fn set_admission_controller(
        &mut self,
        controller: std::sync::Arc<super::admission::AdmissionController>,
    ) {
        self.admission_controller = Some(controller);
    }

    /// Get a reference to the admission controller
    pub fn admission_controller(
        &self,
    ) -> Option<&std::sync::Arc<super::admission::AdmissionController>> {
        self.admission_controller.as_ref()
    }

    /// Resolve the controller for an admission-gated path. Dedicated/open-core
    /// services preserve their historical direct fallback when no controller
    /// is wired. Enterprise-shared views never do: losing this cell boundary
    /// is a service outage, not permission to execute unbounded work.
    pub(super) fn required_admission_controller(
        &self,
    ) -> Result<Option<std::sync::Arc<super::admission::AdmissionController>>, SearchError> {
        match (&self.admission_controller, self.admission_scope) {
            (Some(controller), _) => Ok(Some(std::sync::Arc::clone(controller))),
            (None, super::tenant::SearchTenantScope::Dedicated) => Ok(None),
            (
                None,
                super::tenant::SearchTenantScope::EnterpriseShared(_)
                | super::tenant::SearchTenantScope::EnterpriseSharedRetained { .. },
            ) => Err(SearchError::SearchAdmissionUnavailable(
                "distributed search admission (Redis) is not configured for this deployment".to_string(),
            )),
        }
    }

    pub(super) async fn acquire_search_admission(
        &self,
        controller: &super::admission::AdmissionController,
        job_id: &str,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
    ) -> Result<super::admission::AdmissionPermit, super::admission::AdmissionError> {
        controller
            .acquire_for_scope(job_id, self.admission_scope, user_id, priority)
            .await
    }

    /// Admission for a companion of a rows search (histogram, field stats).
    /// NAN-3299: companions are capped below the per-user limit and queue
    /// behind rows searches, so one run's companions never starve its rows.
    pub(super) async fn acquire_auxiliary_search_admission(
        &self,
        controller: &super::admission::AdmissionController,
        job_id: &str,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
    ) -> Result<super::admission::AdmissionPermit, super::admission::AdmissionError> {
        controller
            .acquire_for_scope_in_lane(
                job_id,
                self.admission_scope,
                user_id,
                priority,
                super::admission::AdmissionLane::Auxiliary,
            )
            .await
    }

    fn ch_settings_for_priority(
        &self,
        priority: super::admission::QueryPriority,
    ) -> super::admission::ClickHouseQuerySettings {
        priority.to_ch_settings_with_memory_ceiling(self.query_memory_ceiling_bytes)
    }

    /// Get a shared reference to the query limits for use in config polling
    pub fn query_limits(
        &self,
    ) -> std::sync::Arc<tokio::sync::RwLock<crate::settings::SearchQueryLimitsConfig>> {
        self.query_limits.clone()
    }

    /// Update query safety limits (called by config polling loop).
    /// Updates the shared RwLock so all in-flight queries pick up the new values.
    pub async fn update_query_limits(&self, config: crate::settings::SearchQueryLimitsConfig) {
        let mut limits = self.query_limits.write().await;
        if *limits != config {
            tracing::info!(
                "Query safety limits updated: max_group_array_size={}, max_mvexpand_rows={}, block_on_cost_errors={}",
                config.max_group_array_size,
                config.max_mvexpand_rows,
                config.block_on_cost_errors
            );
            *limits = config;
        }
    }

    /// Get a reference to the query tracker
    pub fn query_tracker(&self) -> &super::query_tracking::QueryTracker {
        &self.query_tracker
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit #10: transforming pipelines on the lake skip the base-search
    /// histogram, and only row-preserving pipelines take its sum as total.
    #[test]
    fn lake_histogram_gate_and_total_follow_the_pipeline_shape() {
        let parsed = |q: &str| crate::query::parse_query(q).unwrap();
        for query in [
            "powershell",
            "* | table time, user.name",
            "* | where status=1",
            "* | dedup user.name",
            r#"message="literal | stats count""#,
        ] {
            assert!(lake_histogram_applies(&parsed(query)), "{query}");
        }
        for query in [
            "* | rex field=url \"(?<tld>[a-z]+)$\" | stats count by tld",
            "* | eval p=is_private_ip(src_endpoint.ip) | stats count by p",
            "* | dedup user.name | stats count by user.name",
            "* | where cidr_match(\"10.0.0.0/8\", src_endpoint.ip) | stats count",
            "metadata.log_source=\"windows_sysmon\" | stats count by device.hostname",
            "* | stats count by user.name | sort -count | head 10",
            "* | stats count by user.name | where count > 1 | table user.name, count",
            "* | top 10 http_request.url.hostname",
            "* | rare user.name",
            "* | timechart span=1h count",
        ] {
            assert!(!lake_histogram_applies(&parsed(query)), "{query}");
        }
        for query in [
            "* | stats count by user.name",
            "* | eval p=is_private_ip(src_endpoint.ip) | stats count by p",
        ] {
            // The histogram is not the aggregate's row count.
            assert!(!lake_histogram_counts_result_rows(&parsed(query)), "{query}");
        }
        for (query, counts_rows) in [
            ("powershell", true),
            ("* | eval x=1 | table time, x | sort -time", true),
            ("* | where status=1", false),
            ("* | dedup user.name", false),
            ("* | sort 10 -time", false),
        ] {
            assert_eq!(lake_histogram_counts_result_rows(&parsed(query)), counts_rows, "{query}");
        }
        assert_eq!(determine_display_type(&parsed("* | top 10 user.name")), DisplayType::RankedBar);
        assert_eq!(
            determine_display_type(&parsed("* | rex field=url \"(?<tld>[a-z]+)$\" | stats count by tld")),
            DisplayType::Table
        );
    }

    /// NAN-2019: a zero timechart span / bin span / bin hop must be rejected at
    /// validation (a clean 400) rather than reaching ClickHouse as `INTERVAL 0`
    /// (a 500) or a divide-by-zero. Legit spans/hops still validate.
    #[test]
    fn validate_time_spans_rejects_zero_span_and_hop() {
        for q in [
            "* | timechart span=0s count",
            "error | bin span=0s",
            "error | bin span=1h hop=0s",
            "* | bin bytes_out span=0",
            "* | prevalence src_ip | timechart span=0s count",
        ] {
            let parsed = parse_query(q).unwrap_or_else(|e| panic!("{q} should parse: {e:?}"));
            assert!(
                validate_time_spans(&parsed).is_err(),
                "{q} must be rejected"
            );
        }
        for q in [
            "* | timechart span=1h count",
            "error | bin span=10m",
            "error | bin span=1h hop=5m",
            "* | bin bytes_out span=5000",
            "* | stats count by src_ip",
        ] {
            let parsed = parse_query(q).unwrap_or_else(|e| panic!("{q} should parse: {e:?}"));
            assert!(validate_time_spans(&parsed).is_ok(), "{q} must be allowed");
        }
    }

    /// NAN-1428: the companion id scheme is fixed — cancel derives these
    /// exact ids; changing the suffixes breaks kill coverage for in-flight
    /// searches during a rolling deploy.
    #[test]
    fn companion_ids_are_exact_derived_suffixes() {
        assert_eq!(
            companion_query_ids("req-1"),
            [
                "req-1-count".to_string(),
                "req-1-hist".to_string(),
                "req-1-fstats".to_string()
            ]
        );
        assert_eq!(
            all_query_ids("req-1"),
            vec!["req-1", "req-1-count", "req-1-hist", "req-1-fstats"]
        );
        // Ids with LIKE metacharacters stay literal — derivation is plain
        // concatenation, matching is exact (never LIKE).
        assert_eq!(
            all_query_ids("a%b_c")[1..],
            ["a%b_c-count", "a%b_c-hist", "a%b_c-fstats"]
        );
    }

    /// NAN-1429: histogram companion is skipped server-side exactly for the
    /// display types whose UI never renders the timeline. This pins the list
    /// against `Search.tsx`'s `<TimelineVisualization>` render gate.
    #[test]
    fn histogram_skip_list_matches_ui_timeline_gate() {
        // Skipped: the UI renders its own chart / no per-bucket density.
        for (query, expected) in [
            ("* | timechart span=1h count", DisplayType::Timechart),
            ("* | top src_ip", DisplayType::RankedBar),
            ("* | rare user", DisplayType::RankedBar),
            (
                r#"* | sequence by user [action="login"] [action="delete"]"#,
                DisplayType::Flow,
            ),
            (
                "* | tree parent=ppid child=pid label=process_name",
                DisplayType::Tree,
            ),
            ("src_host=\"web01\" | asset", DisplayType::Asset),
            ("* | cloud", DisplayType::Cloud),
            ("* | lateral", DisplayType::Lateral),
            // Command-page directives (NAN-1560) render their own curated views.
            ("* | services", DisplayType::Services),
            ("* | service checkout", DisplayType::Service),
            ("* | trace deadbeef", DisplayType::Trace),
            ("* | metric http.server.duration", DisplayType::Metric),
        ] {
            let q = parse_query(query).unwrap();
            let dt = determine_display_type(&q);
            assert_eq!(dt, expected, "display type drifted for {query}");
            assert!(
                !display_type_renders_timeline(dt),
                "histogram must be skipped for {query} ({dt:?})"
            );
        }

        // Kept: the timeline IS rendered next to these results.
        for (query, expected) in [
            ("error", DisplayType::Events),
            ("* | stats count by src_ip", DisplayType::Table),
            ("* | table src_ip, user", DisplayType::Table),
            ("* | transaction session_id", DisplayType::Transaction),
            // Prevalence enrich keeps Events — the empty-state UX explains
            // filtered-out results by pointing at the histogram.
            (
                "* | prevalence enrich=true | where host_count < 3",
                DisplayType::Events,
            ),
        ] {
            let q = parse_query(query).unwrap();
            let dt = determine_display_type(&q);
            assert_eq!(dt, expected, "display type drifted for {query}");
            assert!(
                display_type_renders_timeline(dt),
                "histogram must be kept for {query} ({dt:?})"
            );
        }
    }

    #[test]
    fn test_explain_query() {
        let sql_generator = ClickHouseSqlGenerator::new();
        let time_range = TimeRange::new(
            "2024-01-01T00:00:00Z".parse().unwrap(),
            "2024-01-02T00:00:00Z".parse().unwrap(),
        );

        let query = parse_query("error").unwrap();
        let sql = sql_generator.generate(&query, &time_range).unwrap();
        assert!(sql.contains("SELECT"));
        // ClickHouse generator uses lower(message) for keyword searches
        assert!(sql.contains("lower(message)") || sql.contains("error"));
    }

    /// NAN-1635 (finding 2.2): the histogram companion's base options must
    /// produce an unbounded FLAT scan — no trailing ORDER BY, no LIMIT — like
    /// the raw-SQL time-range histogram. The old `QueryOptions::default()`
    /// base baked `ORDER BY timestamp DESC LIMIT 1000000`, forcing a top-1M
    /// sort on every broad search (Saturn: 2x wall, ~2750x memory) and
    /// silently truncating the timeline to the newest 1M events (17 buckets
    /// shown vs 289 real ones over a 21.77M-event day).
    #[test]
    fn histogram_base_options_emit_unbounded_flat_scan() {
        let sql_generator = ClickHouseSqlGenerator::new();
        let time_range = TimeRange::new(
            "2024-01-01T00:00:00Z".parse().unwrap(),
            "2024-01-02T00:00:00Z".parse().unwrap(),
        );
        let options = SearchService::histogram_base_options();
        assert!(options.limit.is_none(), "histogram base must be unbounded");
        assert!(options.unordered, "histogram base must be flat (no sort)");

        for q in ["*", "error", "src_ip=\"10.0.0.1\""] {
            let base_sql = sql_generator
                .generate_with_options(&parse_query(q).unwrap(), &time_range, &options)
                .unwrap();
            assert!(
                !base_sql.contains("ORDER BY"),
                "`{q}` histogram base must carry no sort, got:\n{base_sql}"
            );
            assert!(
                !base_sql.to_uppercase().contains(" LIMIT "),
                "`{q}` histogram base must carry no LIMIT (the old top-1M \
                 truncated the timeline), got:\n{base_sql}"
            );
        }
    }

    #[test]
    fn test_escape_sql_string() {
        assert_eq!(escape_sql_string("hello"), "hello");
        assert_eq!(escape_sql_string("it's"), "it''s");
        assert_eq!(escape_sql_string("a'b'c"), "a''b''c");
    }

    #[test]
    fn test_ast_to_prevalence_time_window() {
        assert_eq!(
            ast_to_prevalence_time_window(None).unwrap(),
            PrevalenceTimeWindow::ThirtyDays
        );
        // P2: 1h is rejected on every prevalence path (no silent 24h coercion).
        // NAN-1689: rejection is now a SqlValidationError (clean 400 with the real
        // message), not a PrevalenceError (which stays masked as a 500 for operational
        // ClickHouse failures).
        assert!(matches!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::OneHour)),
            Err(SearchError::SqlValidationError(_))
        ));
        assert_eq!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::TwentyFourHours)).unwrap(),
            PrevalenceTimeWindow::TwentyFourHours
        );
        assert_eq!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::SevenDays)).unwrap(),
            PrevalenceTimeWindow::SevenDays
        );
        assert_eq!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::ThirtyDays)).unwrap(),
            PrevalenceTimeWindow::ThirtyDays
        );
    }

    #[test]
    fn test_extract_post_prevalence_commands() {
        // Query with where after prevalence enrich
        let query =
            parse_query("source_type=squid_proxy | prevalence enrich=true | where host_count < 3")
                .unwrap();
        let post_cmds = extract_post_prevalence_commands(&query);
        assert_eq!(
            post_cmds.commands.len(),
            1,
            "Should extract 1 post-prevalence command"
        );
        assert!(
            matches!(post_cmds.commands[0], Command::Where { .. }),
            "Should be a Where command"
        );
    }

    #[test]
    fn test_strip_post_prevalence_commands() {
        // Query with where after prevalence enrich
        let query =
            parse_query("source_type=squid_proxy | prevalence enrich=true | where host_count < 3")
                .unwrap();
        let stripped = strip_post_prevalence_commands(&query);

        // The stripped query should only have the prevalence command, not the where
        match stripped {
            Query::Piped { source: _, command } => {
                assert!(
                    matches!(command, Command::Prevalence { enrich: true, .. }),
                    "Stripped query should end with prevalence command, got {:?}",
                    command
                );
            }
            _ => panic!("Expected Piped query"),
        }
    }

    #[test]
    fn test_no_post_prevalence_commands_without_enrich() {
        // Query with prevalence filtering (not enrichment) followed by where
        let query = parse_query(
            "source_type=squid_proxy | prevalence hash_prevalence < 5 | where status=200",
        )
        .unwrap();
        let post_cmds = extract_post_prevalence_commands(&query);
        assert_eq!(
            post_cmds.commands.len(),
            1,
            "Should not extract commands after non-enrich prevalence"
        );
    }

    #[test]
    fn subsearch_time_modifiers_never_set_the_outer_range_nan3337() {
        let query = "class_uid=3002 | stats count as main | append [search class_uid=3002 earliest=-3h latest=-2h | stats count as sub]";
        let (cleaned, earliest, latest) = extract_time_modifiers(query);
        assert_eq!((earliest, latest), (None, None), "outer range took the subsearch's modifiers");
        assert!(cleaned.contains("earliest=-3h") && cleaned.contains("latest=-2h"), "{cleaned}");
        let err = parse_query(&cleaned).expect_err("subsearch modifiers must be rejected");
        assert!(err.message.contains("subsearch"), "{}", err.message);

        // Outer modifiers still apply next to a plain subsearch.
        let (cleaned, earliest, _) =
            extract_time_modifiers("a earliest=-1h | append [search b | stats count]");
        assert_eq!(earliest, Some(-3600));
        assert!(parse_query(&cleaned).is_ok(), "{cleaned}");
        // Word boundaries and escapes: neither of these is a modifier.
        for query in [
            "a | append [search b is_latest=true | stats count]",
            "a | append [search b x.earliest=-1h | stats count]",
        ] {
            let (cleaned, earliest, latest) = extract_time_modifiers(query);
            assert_eq!((earliest, latest), (None, None), "{query}");
            assert!(parse_query(&cleaned).is_ok(), "{query} must parse");
        }
        let (_, earliest, _) = extract_time_modifiers(r"a \[ earliest=-1h");
        assert_eq!(earliest, Some(-3600), "an escaped bracket opens no subsearch");
        assert!(crate::query::subsearch_depths(r"a \[ b").iter().all(|d| *d == 0));
        // A whole-query `[search …]` wrapper is not a subsearch.
        let (_, earliest, _) = extract_time_modifiers("[search a earliest=-1h]");
        assert_eq!(earliest, Some(-3600));
    }

    #[test]
    fn test_extract_time_modifiers() {
        // Test earliest with hours
        let (cleaned, earliest, latest) =
            extract_time_modifiers("source_type=squid_proxy earliest=-24h");
        assert_eq!(cleaned, "source_type=squid_proxy");
        assert_eq!(earliest, Some(-24 * 3600)); // -24 hours in seconds
        assert_eq!(latest, None);

        // Test earliest with days
        let (cleaned, earliest, latest) =
            extract_time_modifiers("source_type=test earliest=-7d | stats count");
        assert_eq!(cleaned, "source_type=test | stats count");
        assert_eq!(earliest, Some(-7 * 86400)); // -7 days in seconds
        assert_eq!(latest, None);

        // Test latest=now (with fixed regex pattern)
        let (cleaned, earliest, latest) =
            extract_time_modifiers("source_type=test earliest=-1h latest=now");
        assert_eq!(cleaned, "source_type=test");
        assert_eq!(earliest, Some(-1 * 3600)); // -1 hour in seconds
        assert_eq!(latest, Some(0)); // now = 0 offset

        // Test no time modifiers
        let (cleaned, earliest, latest) = extract_time_modifiers("source_type=test | stats count");
        assert_eq!(cleaned, "source_type=test | stats count");
        assert_eq!(earliest, None);
        assert_eq!(latest, None);

        // Test with minutes
        let (cleaned, earliest, _) = extract_time_modifiers("error earliest=-30m");
        assert_eq!(cleaned, "error");
        assert_eq!(earliest, Some(-30 * 60)); // -30 minutes in seconds

        // Test with weeks
        let (cleaned, earliest, _) = extract_time_modifiers("error earliest=-2w");
        assert_eq!(cleaned, "error");
        assert_eq!(earliest, Some(-2 * 604800)); // -2 weeks in seconds

        // Test just latest=now
        let (cleaned, earliest, latest) = extract_time_modifiers("source_type=test latest=now");
        assert_eq!(cleaned, "source_type=test");
        assert_eq!(earliest, None);
        assert_eq!(latest, Some(0));
    }

    #[test]
    fn own_line_comments_keep_the_rest_of_the_query_nan3377() {
        // A `//` comment on its own line used to swallow every later line:
        // the whitespace tidy flattened newlines before the parser's comment
        // stripper (which ends `//` at a newline) ever saw the query.
        let (cleaned, earliest, latest) = extract_time_modifiers("base\n// note\n| where x=1");
        assert_eq!(cleaned, "base | where x=1");
        assert_eq!((earliest, latest), (None, None));
        assert_eq!(
            parse_query(&cleaned).unwrap(),
            parse_query("base | where x=1").unwrap()
        );

        // A leading comment line used to leave an empty query (400).
        let (cleaned, _, _) = extract_time_modifiers("// c\nbase");
        assert_eq!(cleaned, "base");
        assert_eq!(parse_query(&cleaned).unwrap(), parse_query("base").unwrap());

        // Time modifiers are still extracted around a comment line.
        let (cleaned, earliest, latest) =
            extract_time_modifiers("earliest=-2h base\n// c\n| head 5");
        assert_eq!(cleaned, "base | head 5");
        assert_eq!((earliest, latest), (Some(-2 * 3600), None));

        // Block comments spanning lines, CRLF line endings and trailing
        // comments all reduce to the same query.
        for query in [
            "base\r\n// note\r\n| where x=1",
            "base /* one\ntwo */\n| where x=1",
            "base // trailing\n| where x=1",
        ] {
            let (cleaned, _, _) = extract_time_modifiers(query);
            assert_eq!(cleaned, "base | where x=1", "{query:?}");
        }

        // An `earliest=` written inside a comment is commentary, not the range
        // (the parser never sees it either).
        let (cleaned, earliest, _) =
            extract_time_modifiers("base // earliest=-30d was too slow\n| head 5");
        assert_eq!(cleaned, "base | head 5");
        assert_eq!(earliest, None);

        // `//` inside a quoted value is not a comment.
        let (cleaned, _, _) = extract_time_modifiers("url=\"http://x/y\"\n// note\n| head 5");
        assert_eq!(cleaned, "url=\"http://x/y\" | head 5");
    }

    // NAN-1453: full-chain guard. A non-audit-view user's query is rewritten by
    // `enforce_non_audit_query` before it reaches `search()`, where
    // `extract_time_modifiers` reads the time window. If the rewrite drops
    // `earliest=`/`latest=` (the original bug — parse + pretty-print strips
    // them), the offsets vanish and the search/timeline silently scope to the
    // picker window. This pins the whole chain end-to-end.
    #[test]
    fn test_enforce_non_audit_preserves_time_window_end_to_end() {
        let enforced = crate::search::query_processing::enforce_non_audit_query(
            "error earliest=-12h latest=now",
        )
        .unwrap();
        let (_cleaned, earliest, latest) = extract_time_modifiers(&enforced);
        assert_eq!(
            earliest,
            Some(-12 * 3600),
            "earliest= lost through audit enforcement: {enforced}"
        );
        assert_eq!(
            latest,
            Some(0),
            "latest= lost through audit enforcement: {enforced}"
        );
    }

    // === NAN-1848: which queries return grouped buckets ===

    fn grouped(query: &str) -> bool {
        query_produces_grouped_rows(&parse_query(query).unwrap())
    }

    #[test]
    fn grouping_commands_produce_keyed_buckets() {
        assert!(grouped("* | stats count by source_type"));
        assert!(grouped("* | chart count by user"));
        assert!(grouped("* | top user"));
        assert!(grouped("* | rare dest_port"));
        assert!(grouped("* | timechart span=1h count by source_type"));

        // Formatting commands don't change the row shape — this is the reported
        // query, whose empty bucket must keep its key.
        assert!(grouped(
            "* | stats count by source_type | sort -count | head 25"
        ));

        // A grouping command with no `by` still returns one summary row; keeping
        // its columns costs nothing and stays consistent.
        assert!(grouped("* | stats count"));

        // Nothing downstream can un-aggregate buckets back into raw events, so a
        // reshaping command after the grouping does not forfeit the keys.
        assert!(grouped("* | stats count by user | table user, count"));
        assert!(grouped("* | stats count by user | rename user as who"));
        assert!(grouped("* | stats count by user | eval x = count + 1"));
    }

    #[test]
    fn event_shaped_queries_keep_their_payload_pruning() {
        // The regression to avoid. `eventstats` GROUPS in a subquery but returns
        // wide raw events through it, so a SQL-text "does it contain GROUP BY"
        // check would wrongly stop pruning and bloat every row with all 75+
        // mostly-empty UDM columns. The row shape is an AST question, not a
        // SQL-text one.
        assert!(!grouped("* | eventstats avg(bytes_out) by src_ip"));
        assert!(!grouped("* | dedup src_ip"));

        // Plain event searches and projections keep pruning too.
        assert!(!grouped("error"));
        assert!(!grouped("error | head 10"));
        assert!(!grouped("* | table src_ip, user"));
    }
}

/// NAN-2961: the committed part-log head of one lean-lake tenant, read from
/// its detect[T] leaf (`GET …/detect/v1/status`, which also catches the
/// detect process up with the log). Tenant-pinned by the route: the status
/// report must name exactly this tenant or the probe fails.
#[derive(Clone)]
pub struct LakeCellDetectHeadProbe {
    client: super::lake::LakeQueryClient,
    route_base: String,
}

impl LakeCellDetectHeadProbe {
    /// Build a probe for `route`'s detect leaf.
    pub fn for_route(route: &super::lake_cell::LakeCellRoute) -> Result<Self, String> {
        let runtime = super::lake::LakeQueryRuntime::from_lake_cell_route(
            route,
            std::time::Duration::from_secs(5),
        )?
        .detection_lane()?;
        let client = runtime
            .client
            .ok_or_else(|| "lean-lake detect probe has no client".to_string())?;
        Ok(Self { client, route_base: route.query_base_url.clone() })
    }

    /// Whether this probe was built for `route` (a moved tenant rebuilds it).
    pub fn serves(&self, route: &super::lake_cell::LakeCellRoute) -> bool {
        self.route_base == route.query_base_url
    }

    /// `(seq, sha256)` of the tenant's committed head, `None` before genesis.
    pub async fn head(&self) -> Result<Option<(u64, String)>, SearchError> {
        self.client.lake_cell_part_log_head().await
    }
}

/// Records completed rule windows with one lean-lake tenant's query[T]
/// detection gate (NAN-2891). Bounded by its own short timeout.
#[derive(Clone)]
pub struct LakeCellDetectionCommitter {
    client: super::lake::LakeQueryClient,
}

impl LakeCellDetectionCommitter {
    pub async fn commit(
        &self,
        rule_id: &str,
        log_seq: u64,
        evaluated_through_us: i64,
    ) -> Result<bool, SearchError> {
        self.client
            .detection_commit(rule_id, log_seq, evaluated_through_us)
            .await
    }
}

/// NAN-3080: per-request ceiling on a scheduled detection's prevalence lookup
/// (`NANOSIEM_DETECTION_PREVALENCE_TIMEOUT_SECS`, default 30, clamped
/// 5..=120). A rule that needs prevalence the tenant cannot serve fails with
/// `prevalence_unavailable` in well under the detection search deadline
/// (180 s) instead of spending the interactive 130 s per lookup; a healthy
/// lookup (one statement per request since NAN-3068) takes about a second.
pub(crate) fn detection_prevalence_timeout() -> std::time::Duration {
    static TIMEOUT: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        std::time::Duration::from_secs(parse_detection_prevalence_timeout(
            std::env::var("NANOSIEM_DETECTION_PREVALENCE_TIMEOUT_SECS").ok().as_deref(),
        ))
    })
}

fn parse_detection_prevalence_timeout(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok()).unwrap_or(30).clamp(5, 120)
}

#[cfg(test)]
mod nan3080_detection_prevalence_timeout_tests {
    #[test]
    fn detection_prevalence_timeout_defaults_to_30s_and_is_clamped() {
        use super::parse_detection_prevalence_timeout as parse;
        assert_eq!(parse(None), 30);
        assert_eq!(parse(Some("garbage")), 30);
        assert_eq!(parse(Some("1")), 5);
        assert_eq!(parse(Some("600")), 120);
        assert_eq!(parse(Some(" 45 ")), 45);
        assert!(super::detection_prevalence_timeout() < std::time::Duration::from_secs(180));
    }
}

#[cfg(test)]
mod signed_url_trace_tests {
    use super::extract_time_modifiers;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn time_modifier_traces_do_not_disclose_signed_url_credentials() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let capture = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .without_time()
            .with_writer(move || capture.clone())
            .finish();
        let query = "| inputlookup url=\"https://storage.googleapis.com/bucket/x?sig=TEST_CREDENTIAL\" earliest=-1h";
        tracing::subscriber::with_default(subscriber, || {
            let (cleaned, earliest, _) = extract_time_modifiers(query);
            assert!(
                cleaned.contains("sig=TEST_CREDENTIAL"),
                "execution retains credentials"
            );
            assert_eq!(earliest, Some(-3600));
        });
        let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("Cleaned query"),
            "capture must observe the real traces"
        );
        assert!(
            !output.contains("TEST_CREDENTIAL"),
            "signed URL leaked to debug traces"
        );
    }
}
