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

use sqlx::{PgPool, Row};
use std::time::Instant;
use tracing::{debug, info, instrument, warn};

use crate::db::dual_pool::TableNames;
use crate::db::DualPool;
use crate::extensions::{AiClient, CloudRiskProvider, NoopAiClient, NoopCloudRiskProvider};
use crate::lookup::LookupService;
use crate::prevalence::{PrevalenceData, PrevalenceService, TimeWindow as PrevalenceTimeWindow};
use crate::query::{
    analyze_query_cost, parse_query, AggFunc, ClickHouseSqlGenerator, Command, ParseError, PrevalenceField,
    PrevalenceOperator, PrevalenceThreshold, PrevalenceTimeWindow as AstTimeWindow, Query,
    TimeRange, WarningSeverity,
};
use crate::udm::UdmField;

use super::config::{SearchBackend, SearchConfig};
use super::evaluator::helpers::{escape_like_pattern, escape_sql_string};
use super::execution::{
    escape_question_marks_in_strings, validate_sql_query, ClickHouseExecutor, SqlExecutor,
};
use super::processing::{
    apply_inputlookup_enrichment, apply_lookup_enrichment, apply_post_prevalence_commands,
    apply_post_prevalence_commands_with_limit, validate_lookup_tables,
};
use super::query_processing::{
    apply_auto_sort, detect_oom_risk, extract_ai_command, extract_asset_command,
    extract_baseline_command, extract_asset_identifier_from_query, extract_base_query,
    extract_cloud_command,
    extract_inputlookup_commands, extract_lateral_command, extract_lookup_commands,
    extract_post_ai_commands, extract_post_inputlookup_commands, extract_post_lateral_commands,
    extract_funnel_command, extract_post_prevalence_commands, extract_prevalence_commands,
    extract_tree_command, has_aggregation_before_prevalence,
    has_only_simple_post_prevalence_commands, query_has_aggregation, query_has_per_row_filters,
    strip_ai_and_after, strip_inputlookup_and_after, strip_lateral_and_after,
    strip_post_prevalence_commands,
    strip_prevalence_and_after, AssetCommandInfo, CloudCommandInfo, FunnelCommandInfo,
    InputLookupCommandInfo, LookupCommandInfo, PrevalenceCommandInfo, TreeCommandInfo,
};
use super::types::*;
use crate::inputlookup::InputLookupService;

// Re-export parent sibling modules so submodules can access them via `super::`
// Note: `streaming` is not re-exported here because it conflicts with our local `streaming` submodule.
// Submodules that need search::streaming types should use `crate::search::streaming::*` directly.
pub(super) use super::admission;
pub(super) use super::execution;
pub(super) use super::jobs;

mod asset;
pub use asset::{DimensionFirst, EntityActivityBucket};
mod baseline;
pub mod asset_dossier;
mod cloud;
pub mod cloud_dossier;
pub mod cloud_overview;
mod core_search;
mod field_queries;
mod funnel_view;

/// NAN-1506: row cap for the bulk field-stats scan (shared by the standalone
/// `/api/search/field-stats` companion and the inline parallel companion in
/// `core_search`). topK/uniq over many columns is a full-window scan otherwise
/// (Saturn: 12.6s for 20 columns over a 24h / 22M-row window; timeout for the
/// full inventory). 100k rows brings it to ~0.1s. Windows with ≤ this many
/// matching rows are byte-identical (the LIMIT doesn't truncate), so tight
/// searches stay exact; larger windows become a fast PK-order sample. Per-field
/// drill-in (`get_field_values`) stays exact and unbounded.
pub(crate) const FIELD_STATS_ROW_CAP: usize = 100_000;
mod histogram;
mod ioc_lookup_resolve;
mod lateral;
mod metrics_routing;
mod lateral_graph;
mod otel;
mod prevalence_join;
mod prevalence_processing;
mod retro;
mod sql_execution;
mod streaming;
mod tree_view;

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
/// Events, Table (trailing `stats`), and Transaction DO render the timeline.
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
                Command::Stats { aggregations, group_by }
                | Command::Chart { aggregations, group_by } => {
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
fn extract_time_modifiers(query: &str) -> (String, Option<i64>, Option<i64>) {
    tracing::debug!("extract_time_modifiers called with query: {}", query);

    let time_pattern = &*TIME_MODIFIER_PATTERN;

    let mut earliest_offset: Option<i64> = None;
    let mut latest_offset: Option<i64> = None;

    for cap in time_pattern.captures_iter(query) {
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
    let cleaned = time_pattern.replace_all(query, "").to_string();
    // Clean up any double spaces
    let cleaned = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");

    tracing::debug!(
        "Cleaned query: {}, earliest: {:?}, latest: {:?}",
        cleaned,
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
    /// PostgreSQL pool (for lookups and legacy queries)
    pg_pool: PgPool,
    /// ClickHouse client (for log queries)
    ch_client: Option<clickhouse::Client>,
    /// Service configuration
    config: SearchConfig,
    /// ClickHouse SQL generator
    ch_sql_generator: ClickHouseSqlGenerator,
    /// Lookup service for enrichment (uses PostgreSQL)
    lookup_service: Option<LookupService>,
    /// Prevalence service for filtering and enrichment (uses ClickHouse)
    prevalence_service: Option<PrevalenceService>,
    /// InputLookup service for URL-based enrichment
    inputlookup_service: Option<InputLookupService>,
    /// Backend to use for log queries
    backend: SearchBackend,
    /// ClickHouse executor (if configured)
    ch_executor: Option<ClickHouseExecutor>,
    /// Query tracker for cancellation support (local instance monitoring)
    query_tracker: super::query_tracking::QueryTracker,
    /// Job store for async search support (pluggable: in-memory or Redis)
    job_store: std::sync::Arc<dyn super::jobs::SearchJobStore>,
    /// Admission controller for search query concurrency limits
    admission_controller: Option<std::sync::Arc<super::admission::AdmissionController>>,
    /// Per-query ClickHouse settings (set by admission-controlled path, consumed by execute)
    active_ch_settings: Option<super::admission::ClickHouseQuerySettings>,
    /// Internal server-side output limits for unattended execution. Presence
    /// also suppresses the interactive count companion when the caller does
    /// not consume `total_count`.
    active_execution_limits: Option<super::types::SearchExecutionLimits>,
    /// AI client for inline LLM classification in queries (`| ai` pipe).
    /// Open-core builds wire `NoopAiClient`; enterprise builds inject the
    /// `AiPipeAgent`-backed implementation via `set_ai_client`.
    ai_client: std::sync::Arc<dyn AiClient>,
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
    ) -> ClickHouseSqlGenerator {
        let ds = crate::query::Dataset::from_selector(dataset.unwrap_or("logs"));
        let mut generator = self.ch_sql_generator.clone();
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
        let ch_executor = Some(ClickHouseExecutor::new(dual_pool.clickhouse().clone()));
        Self {
            pg_pool: dual_pool.postgres().clone(),
            ch_client: Some(dual_pool.clickhouse().clone()),
            config: SearchConfig::default(),
            ch_sql_generator: Self::ch_generator_for_pool(dual_pool, profile.clone()),
            lookup_service: None,
            prevalence_service: None,
            inputlookup_service: None,
            backend: SearchBackend::ClickHouse,
            ch_executor,
            query_tracker: super::query_tracking::QueryTracker::new(),
            job_store: std::sync::Arc::new(super::jobs::InMemoryJobStore::new()),
            admission_controller: None,
            active_ch_settings: None,
            active_execution_limits: None,
            ai_client: std::sync::Arc::new(NoopAiClient),
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
        let ch_executor = Some(ClickHouseExecutor::new(dual_pool.clickhouse().clone()));
        Self {
            pg_pool: dual_pool.postgres().clone(),
            ch_client: Some(dual_pool.clickhouse().clone()),
            config: SearchConfig::default(),
            ch_sql_generator: Self::ch_generator_for_pool(dual_pool, profile.clone()),
            lookup_service: Some(lookup_service),
            prevalence_service: Some(prevalence_service),
            inputlookup_service: None,
            backend: SearchBackend::ClickHouse,
            ch_executor,
            query_tracker: super::query_tracking::QueryTracker::new(),
            job_store: std::sync::Arc::new(super::jobs::InMemoryJobStore::new()),
            admission_controller: None,
            active_ch_settings: None,
            active_execution_limits: None,
            ai_client: std::sync::Arc::new(NoopAiClient),
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
    /// Get the current backend type
    pub fn backend(&self) -> SearchBackend {
        self.backend
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
        self.prevalence_service = Some(prevalence_service);
    }

    /// Set the inputlookup service
    pub fn set_inputlookup_service(&mut self, inputlookup_service: InputLookupService) {
        tracing::info!("InputLookup service configured successfully");
        self.inputlookup_service = Some(inputlookup_service);
    }

    /// Set the AI client used by the `| ai` pipe operator. Enterprise builds
    /// inject an `AiPipeAgent`-backed implementation; open-core builds keep
    /// the default `NoopAiClient` which tags rows `ai_verdict = "SKIPPED"`.
    pub fn set_ai_client(&mut self, client: std::sync::Arc<dyn AiClient>) {
        self.ai_client = client;
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
                config.max_group_array_size, config.max_mvexpand_rows, config.block_on_cost_errors
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

    // NAN-1453: full-chain guard. A non-audit-view user's query is rewritten by
    // `enforce_non_audit_query` before it reaches `search()`, where
    // `extract_time_modifiers` reads the time window. If the rewrite drops
    // `earliest=`/`latest=` (the original bug — parse + pretty-print strips
    // them), the offsets vanish and the search/timeline silently scope to the
    // picker window. This pins the whole chain end-to-end.
    #[test]
    fn test_enforce_non_audit_preserves_time_window_end_to_end() {
        let enforced =
            crate::search::query_processing::enforce_non_audit_query("error earliest=-12h latest=now")
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
        assert!(grouped("* | stats count by source_type | sort -count | head 25"));

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
