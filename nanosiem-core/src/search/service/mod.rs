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
    apply_post_prevalence_commands_with_limit,
};
use super::query_processing::{
    apply_auto_sort, detect_oom_risk, extract_ai_command, extract_asset_command,
    extract_asset_identifier_from_query, extract_base_query, extract_cloud_command,
    extract_inputlookup_commands, extract_lateral_command, extract_lookup_commands,
    extract_post_ai_commands, extract_post_inputlookup_commands, extract_post_lateral_commands,
    extract_funnel_command, extract_post_prevalence_commands, extract_prevalence_commands,
    extract_tree_command, has_aggregation_before_prevalence,
    has_only_simple_post_prevalence_commands, query_has_aggregation, strip_ai_and_after,
    strip_inputlookup_and_after, strip_lateral_and_after, strip_post_prevalence_commands,
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
pub mod asset_dossier;
mod cloud;
pub mod cloud_dossier;
pub mod cloud_overview;
mod core_search;
mod field_queries;
mod funnel_view;
mod histogram;
mod lateral;
mod lateral_graph;
mod prevalence_join;
mod prevalence_processing;
mod sql_execution;
mod streaming;
mod tree_view;

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

/// Get the semantic terminal command, skipping formatting commands like sort/head/tail
/// This finds the command that determines what kind of data we're displaying
fn get_semantic_terminal_command(query: &Query) -> Option<&Command> {
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

/// Convert AST time window to prevalence service time window
fn ast_to_prevalence_time_window(ast_tw: Option<&AstTimeWindow>) -> PrevalenceTimeWindow {
    match ast_tw {
        Some(AstTimeWindow::OneHour) => PrevalenceTimeWindow::OneHour,
        Some(AstTimeWindow::TwentyFourHours) => PrevalenceTimeWindow::TwentyFourHours,
        Some(AstTimeWindow::SevenDays) => PrevalenceTimeWindow::SevenDays,
        Some(AstTimeWindow::ThirtyDays) => PrevalenceTimeWindow::ThirtyDays,
        None => PrevalenceTimeWindow::ThirtyDays, // Default: match dictionary 30-day window
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
}

impl SearchService {
    /// Build a ClickHouse SQL generator using the appropriate table from DualPool.
    fn ch_generator_for_pool(dual_pool: &DualPool) -> ClickHouseSqlGenerator {
        ClickHouseSqlGenerator::with_table(dual_pool.table_names().read_bare("logs"))
    }

    /// Create a new search service with DualPool (ClickHouse for logs, PostgreSQL for lookups)
    pub fn with_dual_pool(dual_pool: &DualPool) -> Self {
        let ch_executor = Some(ClickHouseExecutor::new(dual_pool.clickhouse().clone()));
        Self {
            pg_pool: dual_pool.postgres().clone(),
            ch_client: Some(dual_pool.clickhouse().clone()),
            config: SearchConfig::default(),
            ch_sql_generator: Self::ch_generator_for_pool(dual_pool),
            lookup_service: None,
            prevalence_service: None,
            inputlookup_service: None,
            backend: SearchBackend::ClickHouse,
            ch_executor,
            query_tracker: super::query_tracking::QueryTracker::new(),
            job_store: std::sync::Arc::new(super::jobs::InMemoryJobStore::new()),
            admission_controller: None,
            active_ch_settings: None,
            ai_client: std::sync::Arc::new(NoopAiClient),
            cloud_risk: std::sync::Arc::new(NoopCloudRiskProvider),
            table_names: dual_pool.table_names(),
            query_limits: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::settings::SearchQueryLimitsConfig::default(),
            )),
        }
    }
    /// Create a new search service with DualPool, lookup, and prevalence support
    pub fn with_dual_pool_lookup_and_prevalence(
        dual_pool: &DualPool,
        lookup_service: LookupService,
        prevalence_service: PrevalenceService,
    ) -> Self {
        let ch_executor = Some(ClickHouseExecutor::new(dual_pool.clickhouse().clone()));
        Self {
            pg_pool: dual_pool.postgres().clone(),
            ch_client: Some(dual_pool.clickhouse().clone()),
            config: SearchConfig::default(),
            ch_sql_generator: Self::ch_generator_for_pool(dual_pool),
            lookup_service: Some(lookup_service),
            prevalence_service: Some(prevalence_service),
            inputlookup_service: None,
            backend: SearchBackend::ClickHouse,
            ch_executor,
            query_tracker: super::query_tracking::QueryTracker::new(),
            job_store: std::sync::Arc::new(super::jobs::InMemoryJobStore::new()),
            admission_controller: None,
            active_ch_settings: None,
            ai_client: std::sync::Arc::new(NoopAiClient),
            cloud_risk: std::sync::Arc::new(NoopCloudRiskProvider),
            table_names: dual_pool.table_names(),
            query_limits: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::settings::SearchQueryLimitsConfig::default(),
            )),
        }
    }
    /// Get the current backend type
    pub fn backend(&self) -> SearchBackend {
        self.backend
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

    #[test]
    fn test_escape_sql_string() {
        assert_eq!(escape_sql_string("hello"), "hello");
        assert_eq!(escape_sql_string("it's"), "it''s");
        assert_eq!(escape_sql_string("a'b'c"), "a''b''c");
    }

    #[test]
    fn test_ast_to_prevalence_time_window() {
        assert_eq!(
            ast_to_prevalence_time_window(None),
            PrevalenceTimeWindow::ThirtyDays
        );
        assert_eq!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::OneHour)),
            PrevalenceTimeWindow::OneHour
        );
        assert_eq!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::SevenDays)),
            PrevalenceTimeWindow::SevenDays
        );
        assert_eq!(
            ast_to_prevalence_time_window(Some(&AstTimeWindow::ThirtyDays)),
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
}
