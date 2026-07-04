// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command extraction utilities for parsed queries
//!
//! This module provides functions to extract and analyze commands from parsed query ASTs.

use crate::query::{
    AggFunc, Command, Comparator, InputLookupFormat, PrevalenceCondition,
    PrevalenceTimeWindow as AstTimeWindow, Query, SearchExpr, UrlTemplate, Value,
};

/// Extract the base query (before any pipe commands) from a piped query string.
/// This is careful not to split on | inside regex patterns (/.../) or quoted strings ("...").
pub fn extract_base_query(query: &str) -> &str {
    let mut in_regex = false;
    let mut in_quote = false;
    let mut escape_next = false;

    for (i, c) in query.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }

        match c {
            '\\' => escape_next = true,
            '"' if !in_regex => in_quote = !in_quote,
            '/' if !in_quote => {
                // Check if this is a regex delimiter
                // A regex starts with = or != followed by /
                if !in_regex {
                    // Look back to see if preceded by = or !=
                    let before = query[..i].trim_end();
                    if before.ends_with('=') || before.ends_with("!=") {
                        in_regex = true;
                    }
                } else {
                    // End of regex
                    in_regex = false;
                }
            }
            '|' if !in_regex && !in_quote => {
                // Found a pipe outside of regex and quotes - this is a command separator
                return query[..i].trim();
            }
            _ => {}
        }
    }

    // No pipe found, return the whole query
    query.trim()
}

/// Information about a lookup command extracted from a query
#[derive(Debug, Clone)]
pub struct LookupCommandInfo {
    /// Name of the lookup table
    pub table_name: String,
    /// Field in the log results to match against the lookup table's key
    pub key_field: String,
    /// Optional list of fields to output from the lookup table
    pub output_fields: Option<Vec<String>>,
    /// Whether to perform case-insensitive matching
    pub case_insensitive: bool,
}

/// Extract all lookup commands from a parsed query
pub fn extract_lookup_commands(query: &Query) -> Vec<LookupCommandInfo> {
    let mut lookups = Vec::new();
    extract_lookup_commands_recursive(query, &mut lookups);
    lookups
}

/// Recursively extract lookup commands from a query
fn extract_lookup_commands_recursive(query: &Query, lookups: &mut Vec<LookupCommandInfo>) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // First process the source
            extract_lookup_commands_recursive(source, lookups);

            // Then check if this command is a lookup
            if let Command::Lookup {
                table_name,
                key_field,
                output_fields,
                case_insensitive,
            } = command
            {
                lookups.push(LookupCommandInfo {
                    table_name: table_name.clone(),
                    key_field: key_field.clone(),
                    output_fields: output_fields.clone(),
                    case_insensitive: *case_insensitive,
                });
            }
        }
    }
}

/// Information about a prevalence command extracted from a query
#[derive(Debug, Clone)]
pub struct PrevalenceCommandInfo {
    /// Filter conditions (can have multiple, all must be satisfied)
    pub conditions: Vec<PrevalenceCondition>,
    /// Time window for prevalence calculation
    pub time_window: Option<AstTimeWindow>,
    /// Whether to enrich results with prevalence data
    pub enrich: bool,
}

/// Information about post-prevalence commands that need to be applied after enrichment
#[derive(Debug, Clone)]
pub struct PostPrevalenceCommands {
    /// Commands to apply after prevalence enrichment
    pub commands: Vec<Command>,
}

/// Extract all prevalence commands from a parsed query
pub fn extract_prevalence_commands(query: &Query) -> Vec<PrevalenceCommandInfo> {
    let mut prevalence_cmds = Vec::new();
    extract_prevalence_commands_recursive(query, &mut prevalence_cmds);
    prevalence_cmds
}

/// Recursively extract prevalence commands from a query
fn extract_prevalence_commands_recursive(query: &Query, cmds: &mut Vec<PrevalenceCommandInfo>) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // First process the source
            extract_prevalence_commands_recursive(source, cmds);

            // Then check if this command is a prevalence command
            if let Command::Prevalence {
                conditions,
                time_window,
                enrich,
            } = command
            {
                cmds.push(PrevalenceCommandInfo {
                    conditions: conditions.clone(),
                    time_window: *time_window,
                    enrich: *enrich,
                });
            }
        }
    }
}

/// Extract commands that come after prevalence enrichment
/// These need to be applied as post-processing, not SQL
pub fn extract_post_prevalence_commands(query: &Query) -> PostPrevalenceCommands {
    let mut commands = Vec::new();
    let mut found_enrich = false;
    extract_post_prevalence_recursive(query, &mut commands, &mut found_enrich);
    PostPrevalenceCommands { commands }
}

/// Recursively extract commands after any prevalence command
fn extract_post_prevalence_recursive(
    query: &Query,
    cmds: &mut Vec<Command>,
    found_prevalence: &mut bool,
) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // First process the source
            extract_post_prevalence_recursive(source, cmds, found_prevalence);

            // Check if this is any prevalence command (enrich or filter-only)
            if matches!(command, Command::Prevalence { .. }) {
                *found_prevalence = true;
            } else if *found_prevalence {
                // This command comes after prevalence, collect it
                cmds.push(command.clone());
            }
        }
    }
}

/// Check if the query has aggregation commands (stats, timechart, top, rare, streamstats)
/// before the prevalence command. This is used to determine if JOIN-based prevalence
/// can be used (it can't when aggregation changes the result structure).
pub fn has_aggregation_before_prevalence(query: &Query) -> bool {
    // First, collect all commands in pipeline order (source to end)
    let mut commands = Vec::new();
    collect_commands_in_order(query, &mut commands);

    // Now check if any aggregation appears before prevalence
    let mut seen_aggregation = false;
    for cmd in commands {
        let is_aggregation = matches!(
            cmd,
            Command::Stats { .. }
                | Command::Timechart { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::StreamStats { .. }
        );

        if is_aggregation {
            seen_aggregation = true;
        }

        if matches!(cmd, Command::Prevalence { .. }) {
            return seen_aggregation;
        }
    }

    false
}

/// Author-time prevalence-pushdown eligibility (NAN-1691 / P1-C).
///
/// A `| prevalence <field> <op> N` FILTER is only memory-safe when the search
/// router can push the dictGet threshold into the ClickHouse WHERE
/// (`search_with_prevalence_join`). When the shape blocks that push — an
/// aggregation *before* the prevalence command, or a transforming command
/// *after* it — the filter falls back to loading a bounded candidate set into
/// the pod and filtering in Rust, which is capped but returns approximate
/// results and, on the 1Gi jobs pod, wastes memory on every scheduled tick.
/// Enrich-only prevalence (no conditions) just decorates an already-bounded
/// result set and is always safe.
///
/// This predicate MUST stay in lock-step with the `use_prevalence_join` gate in
/// `core_search.rs` (minus the deploy-invariant `is_clickhouse` /
/// `has_prevalence_svc` terms, assumed true at author time) — the same
/// lock-step contract NAN-1688 holds between `check_query_realtime_eligible`
/// and the MV DDL path.
///
/// Returns `Ok(())` when the query has no prevalence FILTER, or has one that
/// will push down. Returns `Err(reason)` (user-facing) otherwise.
///
/// NAN-1691: only a COUNT-field filter (`hash_prevalence`/`domain_prevalence`)
/// pushes down, so the eligibility term mirrors the router's
/// `has_pushable_prevalence_filter` exactly — `!conditions.is_empty()` AND every
/// condition is a count field. A timestamp-field filter (`hash_first_seen`, …)
/// has no command-form SQL predicate and no-ops on the bounded in-memory path
/// today, so it never pushes AND never OOMs — it is classified like "no filter"
/// (Ok) by both this gate and the router, not rejected.
pub fn check_prevalence_pushdown_eligible(query: &Query) -> Result<(), String> {
    let has_filter = extract_prevalence_commands(query).iter().any(|c| {
        !c.conditions.is_empty() && c.conditions.iter().all(|cond| cond.field.is_count_field())
    });
    if !has_filter {
        return Ok(());
    }
    if has_aggregation_before_prevalence(query) {
        return Err(
            "A prevalence filter placed after an aggregation (stats/timechart/top/rare) can't be \
             pushed into ClickHouse and would load the full result set into memory. Put the \
             prevalence filter before the aggregation, or filter an enriched prevalence field \
             with `| where`."
                .to_string(),
        );
    }
    let post = extract_post_prevalence_commands(query);
    if !has_only_simple_post_prevalence_commands(&post.commands) {
        return Err(
            "A prevalence filter followed by a command that re-queries or reshapes the result \
             (lookup, join, transaction, append, streamstats, …) can't be pushed into ClickHouse \
             and would load the full result set into memory. Keep only in-pipeline commands \
             (where, sort, head, table, fields, dedup, rename, stats, eval, rex) after \
             `| prevalence`, or move that command before it."
                .to_string(),
        );
    }
    Ok(())
}

/// Describes why a query poses an OOM risk, enabling specific error messages.
#[derive(Debug, Clone, PartialEq)]
pub enum OomRisk {
    /// eventstats/streamstats without filters
    UnboundedWindowFunction,
    /// dedup without filters — materializes full dataset to deduplicate
    UnboundedDedup,
    /// reverse without a preceding head/tail — loads entire result set
    UnboundedReverse,
    /// transaction without filters — holds all events in memory
    UnboundedTransaction,
    /// anomaly without filters — scores every row in the window (NAN-1648)
    UnboundedAnomaly,
    /// values()/list() aggregation without filters — collects unbounded arrays
    UnboundedCollectAggregation,
    /// GROUP BY on a high-cardinality string field without filters
    HighCardinalityGroupBy { field: String },
}

impl OomRisk {
    /// Human-readable error message for this risk.
    pub fn message(&self) -> String {
        match self {
            OomRisk::UnboundedWindowFunction => {
                "eventstats/streamstats requires search filters to avoid unbounded memory usage. \
                 Add a source_type filter or other search terms before the command."
                    .to_string()
            }
            OomRisk::UnboundedDedup => "dedup on an unfiltered search can exhaust memory (OOM). \
                 Add a source_type filter, search terms, or a | head before | dedup."
                .to_string(),
            OomRisk::UnboundedReverse => {
                "reverse on an unfiltered search loads the entire result set into memory. \
                 Add a | head or search filters before | reverse."
                    .to_string()
            }
            OomRisk::UnboundedTransaction => {
                "transaction on an unfiltered search can exhaust memory (OOM). \
                 Add a source_type filter or other search terms before | transaction."
                    .to_string()
            }
            OomRisk::UnboundedAnomaly => {
                "anomaly on an unfiltered search scores every event in the time range. \
                 Add a source_type filter or other search terms before | anomaly."
                    .to_string()
            }
            OomRisk::UnboundedCollectAggregation => {
                "values()/list() on an unfiltered search collects unbounded data per group. \
                 Add search filters or use dc() (distinct count) instead."
                    .to_string()
            }
            OomRisk::HighCardinalityGroupBy { field } => {
                format!(
                    "stats ... by {field} on an unfiltered search groups by a high-cardinality field, \
                     causing unbounded memory usage. Add search filters or group by a lower-cardinality field."
                )
            }
        }
    }
}

/// Known high-cardinality fields that are essentially unique per row.
/// GROUP BY on these without filters causes unbounded memory.
const HIGH_CARDINALITY_FIELDS: &[&str] = &[
    "message",
    "command_line",
    "parent_command_line",
    "id",
    "process",
    "url",
    "file_path",
    "raw",
];

/// Detect OOM risks in a query. Returns the first risk found, or None if safe.
pub fn detect_oom_risk(query: &Query) -> Option<OomRisk> {
    let mut commands = Vec::new();
    collect_commands_in_order(query, &mut commands);

    let has_filter = search_has_meaningful_filter(query);

    // Check if there's a row-bounding limit preceding a given command index.
    // `sample N` emits `ORDER BY … LIMIT N` just like head/tail, so it bounds
    // the downstream row set identically (NAN-1648).
    let has_limit_before = |target_idx: usize| -> bool {
        commands[..target_idx].iter().any(|cmd| {
            matches!(
                cmd,
                Command::Head { .. } | Command::Tail { .. } | Command::Sample { .. }
            )
        })
    };

    for (i, cmd) in commands.iter().enumerate() {
        match cmd {
            // 1. eventstats/streamstats without filters (existing NAN-224 guardrail)
            Command::EventStats { .. } | Command::StreamStats { .. } => {
                if !has_filter && !has_limit_before(i) {
                    return Some(OomRisk::UnboundedWindowFunction);
                }
            }
            // 2. dedup without filters — materializes full dataset
            Command::Dedup { .. } => {
                if !has_filter && !has_limit_before(i) {
                    return Some(OomRisk::UnboundedDedup);
                }
            }
            // 3. reverse without filters or preceding limit
            Command::Reverse => {
                if !has_filter && !has_limit_before(i) {
                    return Some(OomRisk::UnboundedReverse);
                }
            }
            // 4. transaction without filters
            Command::Transaction { .. } => {
                if !has_filter && !has_limit_before(i) {
                    return Some(OomRisk::UnboundedTransaction);
                }
            }
            // 5. anomaly without filters — scores every row in the window; the
            //    same filters-required rule as eventstats (NAN-1648: this arm was
            //    missing, so `* | anomaly …` ran unbounded while eventstats/dedup
            //    were rejected; pre-NAN-1642 emissions also buffered whole
            //    partitions and OOMed). Aggregation-first anomaly
            //    (`… | stats count by user | anomaly count`) is a first-class
            //    mode operating on already-collapsed groups, not raw rows —
            //    a preceding aggregation bounds it, so it stays allowed.
            Command::Anomaly { .. } => {
                let has_agg_before = commands[..i].iter().any(|c| {
                    matches!(
                        c,
                        Command::Stats { .. } | Command::Chart { .. } | Command::Timechart { .. }
                    )
                });
                if !has_filter && !has_limit_before(i) && !has_agg_before {
                    return Some(OomRisk::UnboundedAnomaly);
                }
            }
            // 6. stats with values()/list() or high-cardinality GROUP BY without filters
            Command::Stats {
                aggregations,
                group_by,
            }
            | Command::Chart {
                aggregations,
                group_by,
            } => {
                if !has_filter && !has_limit_before(i) {
                    // Check for values()/list() aggregations
                    let has_collect = aggregations
                        .iter()
                        .any(|agg| matches!(agg.func, AggFunc::Values | AggFunc::List));
                    if has_collect {
                        return Some(OomRisk::UnboundedCollectAggregation);
                    }

                    // Check for high-cardinality GROUP BY fields
                    if let Some(group_fields) = group_by {
                        for field in group_fields {
                            let lower = field.to_lowercase();
                            if HIGH_CARDINALITY_FIELDS.iter().any(|&hc| hc == lower) {
                                return Some(OomRisk::HighCardinalityGroupBy {
                                    field: field.clone(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Executable nested pipelines get their own SCOPED pass (NAN-1649):
    // append/join subsearches generate full command chains as CTEs, so an
    // unfiltered dedup/eventstats/anomaly inside one runs for real — and the
    // parent's filters/limits/aggregations bound only the parent's rows, never
    // the subsearch's, so nothing from this scope may exempt it (the recursion
    // re-derives has_filter from the SUBSEARCH's own search stage).
    // `field IN [search … | return f]` subsearches are deliberately NOT
    // scanned: `generate_in_subsearch_filter` extracts only the search
    // expression and return field, so commands inside them never execute.
    for cmd in &commands {
        if let Command::Append { subsearch, .. } | Command::Join { subsearch, .. } = cmd {
            if let Some(risk) = detect_oom_risk(subsearch) {
                return Some(risk);
            }
        }
    }

    None
}

/// Check if the query's search expression has meaningful filters
/// (field filters, keywords other than *, etc.)
fn search_has_meaningful_filter(query: &Query) -> bool {
    match query {
        Query::Search(expr) => search_expr_has_filter(expr),
        Query::Piped { source, .. } => search_has_meaningful_filter(source),
    }
}

fn search_expr_has_filter(expr: &SearchExpr) -> bool {
    match expr {
        SearchExpr::Keyword(kw) => kw != "*",
        SearchExpr::FieldFilter { op, .. } => {
            // Negation operators (!=, NOT LIKE, etc.) don't meaningfully narrow the dataset —
            // e.g., source_type!="audit" still scans essentially everything.
            // Only positive/equality filters count as meaningful.
            !matches!(
                op,
                Comparator::Ne
                    | Comparator::NotRegex
                    | Comparator::NotLike
                    | Comparator::NotContains
                    | Comparator::NotStartsWith
                    | Comparator::NotEndsWith
            )
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            search_expr_has_filter(left) || search_expr_has_filter(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => search_expr_has_filter(inner),
        SearchExpr::BooleanFunction { .. } => true,
        _ => false,
    }
}

/// Check if the query contains any aggregation commands (stats, timechart, top, rare, streamstats)
/// These queries need all data to produce correct results, so limits should not be applied.
pub fn query_has_aggregation(query: &Query) -> bool {
    let mut commands = Vec::new();
    collect_commands_in_order(query, &mut commands);

    commands.iter().any(|cmd| {
        matches!(
            cmd,
            Command::Stats { .. }
                | Command::Timechart { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::StreamStats { .. }
                | Command::Anomaly { .. }
        )
    })
}

/// NAN-1635 (finding 2.3): does the query's WHERE carry per-row filters beyond
/// the time bounds and the injected `source_type != "<internal>"` exclusion?
///
/// Drives the count companion's conditional bound: a filtered count can stop
/// scanning at `max_limit + 1` matches (Saturn: 9.5x fewer rows read on a broad
/// keyword), but a filter-free count is served from part metadata and the
/// bounded row-reading form measured 12.8x MORE expensive — so the bound must
/// only apply when this returns true. Row-reducing pipe commands (`where`,
/// `dedup`, `sample`) count as filters too.
///
/// Conservative by construction: anything not recognized as the match-all
/// baseline is treated as filtered. Misclassification is a perf tradeoff, never
/// a correctness one — both count forms clamp to the same reported total.
pub fn query_has_per_row_filters(query: &Query) -> bool {
    fn is_match_all_baseline(expr: &SearchExpr) -> bool {
        match expr {
            SearchExpr::Keyword(kw) => kw == "*",
            SearchExpr::Group(inner) => is_match_all_baseline(inner),
            // The audit-gate wrap injected by `enforce_source_type_exclusion`:
            // `(<expr>) AND source_type != "audit"`. source_type leads the sort
            // key, so the exclusion prunes at the granule level and the count
            // stays metadata-served — it is part of the filter-free baseline.
            SearchExpr::And(left, right) => {
                is_match_all_baseline(left) && is_match_all_baseline(right)
            }
            SearchExpr::FieldFilter {
                field,
                op: Comparator::Ne,
                ..
            } => field == "source_type" || field == "sourcetype",
            _ => false,
        }
    }
    match query {
        Query::Search(expr) => !is_match_all_baseline(expr),
        Query::Piped { source, command } => {
            query_has_per_row_filters(source)
                || matches!(
                    command,
                    Command::Where { .. } | Command::Dedup { .. } | Command::Sample { .. }
                )
        }
    }
}

/// Check if post-prevalence commands are safe for JOIN-based prevalence optimization.
///
/// Only simple filtering/ordering commands are safe. Commands that create new fields
/// (eval, rex, stats, etc.) are NOT safe because WHERE clauses after them would reference
/// fields that don't exist in the JOIN query.
///
/// Safe commands: where, sort, head, tail, table, fields, dedup, rename, eval,
///                stats, top, rare, timechart, risk, rex, fillnull
/// Unsafe commands: lookup, transaction, join, append, etc.
pub fn has_only_simple_post_prevalence_commands(commands: &[Command]) -> bool {
    commands.iter().all(|cmd| {
        matches!(
            cmd,
            Command::Where { .. }
                | Command::Sort { .. }
                | Command::Head { .. }
                | Command::Tail { .. }
                | Command::Table { .. }
                | Command::Fields { .. }
                | Command::Dedup { .. }
                | Command::Rename { .. }
                | Command::Stats { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::Timechart { .. }
                | Command::Eval { .. }
                | Command::Risk { .. }
                | Command::Rex { .. }
                | Command::Fillnull { .. }
        )
    })
}

/// Collect commands in pipeline order (from source to end)
fn collect_commands_in_order<'a>(query: &'a Query, commands: &mut Vec<&'a Command>) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // First collect from source (earlier in pipeline)
            collect_commands_in_order(source, commands);
            // Then add this command
            commands.push(command);
        }
    }
}

/// Information about an inputlookup command extracted from a query
#[derive(Debug, Clone)]
pub struct InputLookupCommandInfo {
    /// URL template with optional {field} placeholders
    pub url: UrlTemplate,
    /// Response format (json or csv)
    pub format: InputLookupFormat,
    /// Field to join on (enables enrichment mode when set)
    pub key_field: Option<String>,
    /// Request timeout in seconds
    pub timeout_secs: u32,
    /// Maximum rows to return
    pub max_rows: usize,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u32,
}

/// Extract all inputlookup commands from a parsed query
pub fn extract_inputlookup_commands(query: &Query) -> Vec<InputLookupCommandInfo> {
    let mut lookups = Vec::new();
    extract_inputlookup_commands_recursive(query, &mut lookups);
    lookups
}

/// Recursively extract inputlookup commands from a query
fn extract_inputlookup_commands_recursive(
    query: &Query,
    lookups: &mut Vec<InputLookupCommandInfo>,
) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // First process the source
            extract_inputlookup_commands_recursive(source, lookups);

            // Then check if this command is an inputlookup
            if let Command::InputLookup {
                url,
                format,
                key_field,
                timeout_secs,
                max_rows,
                cache_ttl_secs,
            } = command
            {
                lookups.push(InputLookupCommandInfo {
                    url: url.clone(),
                    format: *format,
                    key_field: key_field.clone(),
                    timeout_secs: *timeout_secs,
                    max_rows: *max_rows,
                    cache_ttl_secs: *cache_ttl_secs,
                });
            }
        }
    }
}

/// Extract commands that come after inputlookup (need post-processing)
pub fn extract_post_inputlookup_commands(query: &Query) -> Vec<Command> {
    let mut commands = Vec::new();
    extract_post_inputlookup_recursive(query, &mut commands, false);
    commands
}

fn extract_post_inputlookup_recursive(
    query: &Query,
    cmds: &mut Vec<Command>,
    found_inputlookup: bool,
) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            // Check if source contains inputlookup
            let source_has_inputlookup = found_inputlookup || query_has_inputlookup(source);
            extract_post_inputlookup_recursive(source, cmds, found_inputlookup);

            // If we've found inputlookup, collect subsequent commands
            if source_has_inputlookup && !matches!(command, Command::InputLookup { .. }) {
                cmds.push(command.clone());
            }
        }
    }
}

/// Check if a query contains an inputlookup command
pub fn query_has_inputlookup(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(command, Command::InputLookup { .. }) || query_has_inputlookup(source)
        }
    }
}

/// Information about a tree command extracted from a query
#[derive(Debug, Clone)]
pub struct TreeCommandInfo {
    /// Field containing parent identifier (e.g., parent_process_id, referrer)
    pub parent_field: String,
    /// Field containing child identifier (e.g., process_id, url)
    pub child_field: String,
    /// Field to display as node label (e.g., process_name, dest_host)
    pub label_field: String,
    /// Optional field for detail text (e.g., process, file_name)
    pub detail_field: Option<String>,
    /// Optional field to enrich with prevalence (e.g., file_hash, domain)
    pub prevalence_field: Option<String>,
    /// Optional root filter - show only subtree(s) rooted at nodes matching this pattern
    pub root_filter: Option<String>,
}

/// Extract tree command from a parsed query (only one tree command is supported per query)
pub fn extract_tree_command(query: &Query) -> Option<TreeCommandInfo> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            // First check the source
            if let Some(info) = extract_tree_command(source) {
                return Some(info);
            }

            // Then check this command
            if let Command::Tree {
                parent_field,
                child_field,
                label_field,
                detail_field,
                prevalence_field,
                root_filter,
            } = command
            {
                return Some(TreeCommandInfo {
                    parent_field: parent_field.clone(),
                    child_field: child_field.clone(),
                    label_field: label_field.clone(),
                    detail_field: detail_field.clone(),
                    prevalence_field: prevalence_field.clone(),
                    root_filter: root_filter.clone(),
                });
            }

            None
        }
    }
}

/// Canonical list of UDM field names used for funnel dropper attribution.
///
/// Used by BOTH the SQL generator (`generate_funnel_sql` emits one
/// `argMaxIf(..)`/`groupArraySampleIf(..)` per entry) and the post-processor
/// (`build_funnel_view` reads one `_droppers_<field>` array per entry and
/// turns it into top-K `{field, value, count, pct}` entries).
///
/// Kept in a single const so the two sides can't drift. Adding a field here
/// still requires matching `argMax` expressions in the SQL generator's local
/// field table (for per-field casts like `toString(dest_port)`), but the name
/// set is canonical here.
pub const FUNNEL_DROPPER_FIELDS: &[&str] = &[
    "process_name",
    "src_host",
    "dest_host",
    "dest_ip",
    "dest_port",
    "user",
    "action",
];

/// Information about a funnel command extracted from a query.
///
/// Used to drive post-processing of dropper attribution rows emitted by
/// `generate_funnel_sql` — specifically, turning per-stage sampled value
/// arrays into top-K `{field, value, count, pct}` attributes.
#[derive(Debug, Clone)]
pub struct FunnelCommandInfo {
    /// Fields to partition/group by (e.g., user, src_ip)
    pub group_by: Vec<String>,
    /// Number of declared stages (one row emitted per stage)
    pub step_count: usize,
}

/// Extract funnel command from a parsed query (only one funnel command is supported per query)
pub fn extract_funnel_command(query: &Query) -> Option<FunnelCommandInfo> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            if let Some(info) = extract_funnel_command(source) {
                return Some(info);
            }
            if let Command::Funnel {
                group_by, steps, ..
            } = command
            {
                return Some(FunnelCommandInfo {
                    group_by: group_by.clone(),
                    step_count: steps.len(),
                });
            }
            None
        }
    }
}

/// Information about an asset command extracted from a query
#[derive(Debug, Clone)]
pub struct AssetCommandInfo {
    /// Field containing the asset identifier (auto-detected if not specified)
    pub identifier_field: Option<String>,
    /// Sections to include in asset details (None = all sections)
    pub sections: Option<Vec<crate::query::AssetSection>>,
    /// Maximum age of identity observations to use
    pub max_identity_age: std::time::Duration,
}

/// Extract asset command from a parsed query (only one asset command is supported per query)
pub fn extract_asset_command(query: &Query) -> Option<AssetCommandInfo> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            // First check the source
            if let Some(info) = extract_asset_command(source) {
                return Some(info);
            }

            // Then check this command
            if let Command::Asset {
                identifier_field,
                sections,
                max_identity_age,
            } = command
            {
                return Some(AssetCommandInfo {
                    identifier_field: identifier_field.clone(),
                    sections: sections.clone(),
                    max_identity_age: *max_identity_age,
                });
            }

            None
        }
    }
}

/// Information about a cloud investigation command extracted from a query
#[derive(Debug, Clone)]
pub struct CloudCommandInfo {
    /// Primary grouping dimension
    pub group_by: crate::query::CloudGroupBy,
    /// Whether to include MFA usage analysis panel
    pub show_mfa: bool,
    /// Principal scope — when Some, the frontend renders the dossier view (NAN-395)
    pub principal: Option<String>,
    /// Optional account scope (AWS account id / GCP project id)
    pub account: Option<String>,
}

/// Extract cloud command from a parsed query
pub fn extract_cloud_command(query: &Query) -> Option<CloudCommandInfo> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            if let Some(info) = extract_cloud_command(source) {
                return Some(info);
            }
            if let Command::Cloud {
                group_by,
                show_mfa,
                principal,
                account,
            } = command
            {
                return Some(CloudCommandInfo {
                    group_by: *group_by,
                    show_mfa: *show_mfa,
                    principal: principal.clone(),
                    account: account.clone(),
                });
            }
            None
        }
    }
}

/// Information about an AI command extracted from a query
#[derive(Debug, Clone)]
pub struct AiCommandInfo {
    /// The analyst's prompt instruction
    pub prompt: String,
    /// Maximum rows to send to LLM
    pub max_rows: usize,
}

/// Extract ai command from a parsed query
pub fn extract_ai_command(query: &Query) -> Option<AiCommandInfo> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            if let Some(info) = extract_ai_command(source) {
                return Some(info);
            }
            if let Command::Ai { prompt, max_rows } = command {
                return Some(AiCommandInfo {
                    prompt: prompt.clone(),
                    max_rows: *max_rows,
                });
            }
            None
        }
    }
}

/// Extract commands that come after the `| ai` command in the pipeline.
/// These will be applied as post-processing after AI enrichment.
pub fn extract_post_ai_commands(query: &Query) -> Vec<Command> {
    let mut commands = Vec::new();
    extract_post_ai_recursive(query, &mut commands, false);
    commands
}

fn extract_post_ai_recursive(query: &Query, cmds: &mut Vec<Command>, found_ai: bool) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            let source_has_ai = found_ai || query_has_ai(source);
            extract_post_ai_recursive(source, cmds, found_ai);

            // If we've found ai, collect subsequent commands
            if source_has_ai && !matches!(command, Command::Ai { .. }) {
                cmds.push(command.clone());
            }
        }
    }
}

/// Check if a query contains an ai command
fn query_has_ai(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(command, Command::Ai { .. }) || query_has_ai(source)
        }
    }
}

/// Information about a lateral command extracted from a query
#[derive(Debug, Clone)]
pub struct LateralCommandInfo {
    /// How to identify the seed entity
    pub seed_type: crate::query::LateralSeedType,
    /// Specific field to use as seed entity
    pub entity_field: Option<String>,
    /// Maximum number of hops to trace
    pub max_hops: u32,
    /// Time window override (None = use query time range)
    pub time_window: Option<std::time::Duration>,
    /// Categories of lateral movement evidence to search
    pub methods: Vec<crate::query::LateralMethod>,
}

/// Extract lateral command from a parsed query
pub fn extract_lateral_command(query: &Query) -> Option<LateralCommandInfo> {
    match query {
        Query::Search(_) => None,
        Query::Piped { source, command } => {
            if let Some(info) = extract_lateral_command(source) {
                return Some(info);
            }
            if let Command::Lateral {
                seed_type,
                entity_field,
                max_hops,
                time_window,
                methods,
            } = command
            {
                return Some(LateralCommandInfo {
                    seed_type: *seed_type,
                    entity_field: entity_field.clone(),
                    max_hops: *max_hops,
                    time_window: *time_window,
                    methods: methods.clone(),
                });
            }
            None
        }
    }
}

/// Extract commands that come after the `| lateral` command in the pipeline.
/// These will be applied as post-processing after lateral movement tracing.
pub fn extract_post_lateral_commands(query: &Query) -> Vec<Command> {
    let mut commands = Vec::new();
    extract_post_lateral_recursive(query, &mut commands, false);
    commands
}

fn extract_post_lateral_recursive(query: &Query, cmds: &mut Vec<Command>, found_lateral: bool) {
    match query {
        Query::Search(_) => {}
        Query::Piped { source, command } => {
            let source_has_lateral = found_lateral || query_has_lateral(source);
            extract_post_lateral_recursive(source, cmds, found_lateral);

            if source_has_lateral && !matches!(command, Command::Lateral { .. }) {
                cmds.push(command.clone());
            }
        }
    }
}

/// Check if a query contains a lateral command
fn query_has_lateral(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(command, Command::Lateral { .. }) || query_has_lateral(source)
        }
    }
}

/// Known asset identifier fields in priority order
const ASSET_IDENTIFIER_FIELDS: &[&str] =
    &["src_host", "dest_host", "src_ip", "dest_ip", "user", "mac"];

/// Extract an asset identifier directly from the query AST, avoiding the need to execute
/// the initial search query. Returns `Some((field, value))` if the search expression contains
/// a simple equality filter (e.g. `src_host="workstation03"`) on a known identifier field.
///
/// Only works for exact equality — wildcards, regex, and complex boolean expressions are skipped.
pub fn extract_asset_identifier_from_query(
    query: &Query,
    asset_info: &AssetCommandInfo,
) -> Option<(String, String)> {
    // Get the root search expression from the query
    let search_expr = get_root_search_expr(query)?;
    // If asset command specifies an identifier_field, only look for that field
    if let Some(ref target_field) = asset_info.identifier_field {
        return extract_eq_field_value(search_expr, Some(target_field));
    }
    // Otherwise try known identifier fields
    extract_eq_field_value(search_expr, None)
}

/// Walk the Query AST down to the root Search expression
fn get_root_search_expr(query: &Query) -> Option<&SearchExpr> {
    match query {
        Query::Search(expr) => Some(expr),
        Query::Piped { source, .. } => get_root_search_expr(source),
    }
}

/// Extract `(field, value)` from a SearchExpr if it's a simple equality on a known identifier field.
/// If `target_field` is Some, only match that specific field.
fn extract_eq_field_value(
    expr: &SearchExpr,
    target_field: Option<&str>,
) -> Option<(String, String)> {
    match expr {
        SearchExpr::FieldFilter {
            field,
            op: Comparator::Eq,
            value,
        } => {
            let is_target = match target_field {
                Some(t) => field == t,
                None => ASSET_IDENTIFIER_FIELDS.contains(&field.as_str()),
            };
            if !is_target {
                return None;
            }
            // Extract the string value, skip wildcards
            let str_val = match value {
                Value::String(s) => s.clone(),
                Value::Ip(ip) => ip.to_string(),
                _ => return None,
            };
            if str_val.contains('*') || str_val.contains('?') {
                return None;
            }
            Some((field.clone(), str_val))
        }
        // Walk through AND — both sides might have it, take first match
        SearchExpr::And(left, right) => extract_eq_field_value(left, target_field)
            .or_else(|| extract_eq_field_value(right, target_field)),
        // Walk through Group
        SearchExpr::Group(inner) => extract_eq_field_value(inner, target_field),
        // Everything else: OR, NOT, keywords, regex, etc. — skip
        _ => None,
    }
}

/// Threshold at which a time range alone is considered heavy enough to warrant
/// the slow lane. Picked to match the existing "wide range" intuition — most
/// dashboards default to 24h or 7d, anything beyond that scans many partitions
/// even with the best index pruning.
pub const HEAVY_TIME_RANGE_DAYS: i64 = 7;

/// Reject panel queries that combine `| prevalence` with no narrowing filter.
///
/// NAN-712: even with NAN-701/706/707/708/709 making prevalence cheap when
/// CH cooperates, an unscoped prevalence query
/// (`source_host=* user=* | prevalence`) scans the entire dataset for
/// rarity — the worst-case shape regardless of dict caching. In practice
/// analysts almost never *want* this on a dashboard; they want "rare X for
/// THIS host". The wildcard pattern is an artifact of the AI agent (or a
/// manual author) defaulting variables to `*` for cheap-command UX and not
/// realizing prevalence has a different cost profile.
///
/// "Effectively unscoped" means: the search expression has zero narrowing
/// components — no `Keyword` other than bare `*`, no `FieldFilter` with a
/// non-wildcard value. At least one narrowing component → allow.
///
/// Returns `Err(Vec<String>)` with the deduped list of `field=*` clauses
/// found, so the caller can name the specific fields the user should narrow
/// ("set source_host or user to a specific value").
pub fn validate_panel_query_unscoped_prevalence(query: &Query) -> Result<(), Vec<String>> {
    if extract_prevalence_commands(query).is_empty() {
        return Ok(());
    }

    // Walk to the base search expression (before any pipe).
    let mut base = query;
    while let Query::Piped { source, .. } = base {
        base = source;
    }
    let Query::Search(expr) = base else {
        return Ok(());
    };

    let mut wildcard_fields: Vec<String> = Vec::new();
    if narrows(expr, &mut wildcard_fields) {
        Ok(())
    } else {
        wildcard_fields.sort();
        wildcard_fields.dedup();
        Err(wildcard_fields)
    }
}

/// Returns true if the expression contains at least one filter that
/// genuinely narrows the dataset. Side effect: pushes any wildcard
/// `FieldFilter` field names into `wildcard_fields` for the error message.
fn narrows(expr: &SearchExpr, wildcard_fields: &mut Vec<String>) -> bool {
    match expr {
        // Bare `*` keyword is the canonical "unscoped" search; any other
        // free-text term or prefix pattern actively narrows.
        SearchExpr::Keyword(k) => k != "*",
        SearchExpr::FieldFilter { field, value, .. } => match value {
            Value::String(s) if s == "*" => {
                wildcard_fields.push(field.clone());
                false
            }
            _ => true,
        },
        // AND: any narrowing branch is enough — `source_type=foo source_host=*`
        // is bounded by the source_type filter regardless of the wildcard.
        // Walk both sides so the wildcard_fields list is fully populated for
        // the error message even when the result is "narrows".
        SearchExpr::And(left, right) => {
            let l = narrows(left, wildcard_fields);
            let r = narrows(right, wildcard_fields);
            l || r
        }
        // OR: BOTH branches must narrow, otherwise the wildcard branch
        // dominates the union and the result is "everything." Bitwise `&`
        // (not short-circuit `&&`) so both sides still walk into
        // wildcard_fields for the error message.
        SearchExpr::Or(left, right) => {
            narrows(left, wildcard_fields) & narrows(right, wildcard_fields)
        }
        SearchExpr::Group(inner) | SearchExpr::Not(inner) => narrows(inner, wildcard_fields),
        // Anything else (InList, FunctionFilter, FieldFunctionFilter,
        // BooleanFunction, LiteralComparison, InSubsearch) is more
        // specific than a bare wildcard — treat as narrowing.
        _ => true,
    }
}

/// Commands whose output shape is bound to a dedicated nanosiem surface
/// (asset dossier, cloud dossier, tree visualization, lateral-movement graph,
/// funnel attribution, AI inline classification) and which therefore should
/// never run inside a generic dashboard panel. NAN-708 rejects them at the
/// panel_query handler and instructs the AI dashboard agent to never emit
/// them. See `validate_panel_query_commands`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelBlockedCommand {
    Tree,
    Asset,
    Cloud,
    Ai,
    Lateral,
    Funnel,
}

impl PanelBlockedCommand {
    /// Short keyword that appears in nPL pipelines (without the leading `|`).
    pub fn keyword(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Asset => "asset",
            Self::Cloud => "cloud",
            Self::Ai => "ai",
            Self::Lateral => "lateral",
            Self::Funnel => "funnel",
        }
    }

    /// One-line user-facing redirect explaining where the dedicated UI lives.
    pub fn redirect_hint(self) -> &'static str {
        match self {
            Self::Tree => "use the dedicated tree view from the search page",
            Self::Asset => "use the asset dossier from the assets page",
            Self::Cloud => "use the cloud dossier from the cloud page",
            Self::Ai => "AI inline classification isn't supported in dashboards",
            Self::Lateral => "use the lateral-movement graph from the search page",
            Self::Funnel => "use the funnel view from the search page",
        }
    }
}

/// Reject panel queries whose pipeline contains one of the surface-bound
/// commands enumerated by `PanelBlockedCommand`. Callers should map this to
/// HTTP 400 with the returned redirect hint.
///
/// NAN-708: even before the cost classifier kicks in, these commands have
/// custom output shapes (e.g., `_asset_pagination`, hierarchical trees,
/// per-row LLM classifications) that don't render meaningfully in a generic
/// dashboard panel. Better to fail fast with a redirect than to render
/// garbage or stall the cluster.
pub fn validate_panel_query_commands(query: &Query) -> Result<(), PanelBlockedCommand> {
    if extract_tree_command(query).is_some() {
        return Err(PanelBlockedCommand::Tree);
    }
    if extract_asset_command(query).is_some() {
        return Err(PanelBlockedCommand::Asset);
    }
    if extract_cloud_command(query).is_some() {
        return Err(PanelBlockedCommand::Cloud);
    }
    if extract_ai_command(query).is_some() {
        return Err(PanelBlockedCommand::Ai);
    }
    if extract_lateral_command(query).is_some() {
        return Err(PanelBlockedCommand::Lateral);
    }
    if extract_funnel_command(query).is_some() {
        return Err(PanelBlockedCommand::Funnel);
    }
    Ok(())
}

/// Classify a parsed query + its time range into the right `QueryPriority` for
/// admission gating.
///
/// NAN-708: dashboards mix cheap panels (raw event search, narrow time, no
/// enrichment) with expensive ones (`| prevalence`, `| lookup`, wide ranges).
/// Without classification all of them share `QueryPriority::Interactive` and
/// queue FIFO behind whichever expensive panel got there first — so the user
/// sees N spinners until the slow one releases its slot. With classification,
/// expensive panels get `QueryPriority::Analytics`. The admission heap is
/// priority-aware (see `admission::QueuedSearch::cmp`), so Interactive panels
/// jump the queue and the dashboard fills in cheap-to-expensive: same total
/// wallclock, materially faster perceived response.
///
/// Heavy = `prevalence` (dict fan-out), `lookup`/`inputlookup` (per-row HTTP
/// enrichment), or any time range > `HEAVY_TIME_RANGE_DAYS`. Surface-bound
/// commands (tree/asset/cloud/ai/lateral/funnel) are rejected upstream by
/// `validate_panel_query_commands` and never reach this classifier.
/// Detection rules bypass admission entirely (`QueryPriority::Detection`),
/// also unaffected.
pub fn classify_query_cost(
    query: &Query,
    time_range: &crate::search::TimeRangeInput,
) -> crate::search::admission::QueryPriority {
    let span_days = (time_range.end - time_range.start).num_days();
    let wide_time = span_days > HEAVY_TIME_RANGE_DAYS;

    let has_lookup = !extract_lookup_commands(query).is_empty();
    let has_inputlookup = !extract_inputlookup_commands(query).is_empty();
    let has_prevalence = !extract_prevalence_commands(query).is_empty();

    let heavy = wide_time || has_lookup || has_inputlookup || has_prevalence;

    if heavy {
        crate::search::admission::QueryPriority::Analytics
    } else {
        crate::search::admission::QueryPriority::Interactive
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{parse_query, PrevalenceField, PrevalenceOperator, PrevalenceThreshold};

    #[test]
    fn test_extract_base_query() {
        assert_eq!(extract_base_query("error"), "error");
        assert_eq!(extract_base_query("error | stats count"), "error");
        assert_eq!(
            extract_base_query("src_ip=192.168.1.1 | head 10"),
            "src_ip=192.168.1.1"
        );
        assert_eq!(
            extract_base_query("action=/login.*/ | stats count"),
            "action=/login.*/"
        );
        assert_eq!(
            extract_base_query("message=\"hello | world\" | head 10"),
            "message=\"hello | world\""
        );
    }

    /// NAN-1179: a leading-pipe query has no base filter, so `extract_base_query`
    /// returns the empty string. The histogram path must treat this as match-all
    /// rather than parsing "" (which fails with "Empty query" and drops the
    /// timeline). This locks the trigger condition and verifies the wildcard
    /// substitute generates valid SQL — exactly what `generate_histogram` does.
    #[test]
    fn test_leading_pipe_base_query_falls_back_to_wildcard() {
        use crate::query::{ClickHouseSqlGenerator, Query, SearchExpr, TimeRange};

        for q in ["| stats count by src_ip", "| timechart span=1h count"] {
            assert_eq!(extract_base_query(q), "", "leading-pipe base must be empty: {q}");
        }

        // The match-all substitute the histogram path uses for an empty base.
        let parsed = Query::Search(SearchExpr::Keyword("*".to_string()));
        let time_range = TimeRange {
            start: "2024-01-01T00:00:00Z".parse().unwrap(),
            end: "2024-01-02T00:00:00Z".parse().unwrap(),
        };
        let sql = ClickHouseSqlGenerator::new()
            .generate(&parsed, &time_range)
            .expect("wildcard match-all must generate valid SQL");
        assert!(!sql.trim().is_empty(), "wildcard SQL must not be empty");
    }

    #[test]
    fn test_extract_prevalence_commands_enrichment() {
        let query = parse_query("error | prevalence enrich=true").unwrap();
        let cmds = extract_prevalence_commands(&query);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].enrich);
        assert!(cmds[0].conditions.is_empty());
    }

    #[test]
    fn test_extract_prevalence_commands_filtering() {
        let query = parse_query("error | prevalence hash_prevalence < 5 window=24h").unwrap();
        let cmds = extract_prevalence_commands(&query);
        assert_eq!(cmds.len(), 1);
        assert!(!cmds[0].enrich);
        assert_eq!(cmds[0].conditions.len(), 1);
        assert_eq!(cmds[0].conditions[0].field, PrevalenceField::HashPrevalence);
        assert_eq!(cmds[0].conditions[0].operator, PrevalenceOperator::Lt);
        assert_eq!(
            cmds[0].conditions[0].threshold,
            PrevalenceThreshold::Count(5)
        );
        assert_eq!(cmds[0].time_window, Some(AstTimeWindow::TwentyFourHours));
    }

    #[test]
    fn test_extract_prevalence_commands_multiple_conditions() {
        let query = parse_query(
            "error | prevalence domain_prevalence < 10 domain_first_seen > now()-86400 window=24h",
        )
        .unwrap();
        let cmds = extract_prevalence_commands(&query);
        assert_eq!(cmds.len(), 1);
        assert!(!cmds[0].enrich);
        assert_eq!(cmds[0].conditions.len(), 2);
        assert_eq!(
            cmds[0].conditions[0].field,
            PrevalenceField::DomainPrevalence
        );
        assert_eq!(cmds[0].conditions[0].operator, PrevalenceOperator::Lt);
        assert_eq!(
            cmds[0].conditions[1].field,
            PrevalenceField::DomainFirstSeen
        );
        assert_eq!(cmds[0].conditions[1].operator, PrevalenceOperator::Gt);
        assert_eq!(cmds[0].time_window, Some(AstTimeWindow::TwentyFourHours));
    }

    #[test]
    fn test_extract_prevalence_commands_multiple_pipes() {
        let query =
            parse_query("error | prevalence enrich=true | prevalence hash_prevalence < 3").unwrap();
        let cmds = extract_prevalence_commands(&query);
        assert_eq!(cmds.len(), 2);
        assert!(cmds[0].enrich);
        assert!(!cmds[1].enrich);
        assert_eq!(cmds[1].conditions.len(), 1);
    }

    #[test]
    fn test_has_aggregation_before_prevalence_with_stats() {
        // Stats before prevalence - should return true
        let query = parse_query("error | stats count by src_ip | prevalence enrich=true").unwrap();
        assert!(has_aggregation_before_prevalence(&query));
    }

    #[test]
    fn test_has_aggregation_before_prevalence_without_stats() {
        // No stats before prevalence - should return false
        let query = parse_query("error | prevalence enrich=true | where host_count < 5").unwrap();
        assert!(!has_aggregation_before_prevalence(&query));
    }

    #[test]
    fn test_has_aggregation_before_prevalence_with_streamstats() {
        // Streamstats before prevalence - should return true
        let query =
            parse_query("error | streamstats count by src_ip | prevalence enrich=true").unwrap();
        assert!(has_aggregation_before_prevalence(&query));
    }

    #[test]
    fn test_has_aggregation_before_prevalence_with_timechart() {
        // Timechart before prevalence - should return true
        let query =
            parse_query("error | timechart span=1h count | prevalence enrich=true").unwrap();
        assert!(has_aggregation_before_prevalence(&query));
    }

    #[test]
    fn test_prevalence_pushdown_eligible_ok_cases() {
        // No prevalence at all → eligible.
        assert!(check_prevalence_pushdown_eligible(&parse_query("error | head 10").unwrap()).is_ok());
        // Enrich-only (no conditions) → decorates an already-bounded set → eligible.
        assert!(check_prevalence_pushdown_eligible(
            &parse_query("error | prevalence enrich=true").unwrap()
        )
        .is_ok());
        // Filter that pushes down → eligible.
        assert!(check_prevalence_pushdown_eligible(
            &parse_query("error | prevalence hash_prevalence <= 5 window=7d").unwrap()
        )
        .is_ok());
        // Filter + only simple post-commands → still pushes down.
        assert!(check_prevalence_pushdown_eligible(
            &parse_query(
                "error | prevalence domain_prevalence < 3 | where x>1 | sort -count | head 20 | table a,b"
            )
            .unwrap()
        )
        .is_ok());
    }

    #[test]
    fn test_prevalence_pushdown_ineligible_aggregation_before() {
        let query =
            parse_query("error | stats count by user | prevalence hash_prevalence <= 5").unwrap();
        assert!(check_prevalence_pushdown_eligible(&query).is_err());
    }

    #[test]
    fn test_prevalence_pushdown_eligible_inpipeline_post() {
        // stats/eval after the filter push down over the already-rare set, so
        // the router routes them through the JOIN — they must stay eligible,
        // matching `has_only_simple_post_prevalence_commands`.
        let query =
            parse_query("error | prevalence hash_prevalence <= 5 | stats count by src_ip").unwrap();
        assert!(check_prevalence_pushdown_eligible(&query).is_ok());
        let query2 = parse_query("error | prevalence hash_prevalence <= 5 | eval y=1").unwrap();
        assert!(check_prevalence_pushdown_eligible(&query2).is_ok());
    }

    #[test]
    fn test_prevalence_pushdown_ineligible_requerying_post() {
        // streamstats is NOT in the JOIN-safe post-command set, so the router
        // falls to the in-memory path — the gate must reject it.
        let query =
            parse_query("error | prevalence hash_prevalence <= 5 | streamstats count").unwrap();
        assert!(check_prevalence_pushdown_eligible(&query).is_err());
    }

    /// Lock-step guard: the author-time gate must agree with the boolean the
    /// search router (`use_prevalence_join`) computes for the same query shape,
    /// minus the deploy-invariant `is_clickhouse`/`has_prevalence_svc` terms.
    /// Mirrors NAN-1688's `test_realtime_eligible_matches_ddl_acceptance`.
    #[test]
    fn test_prevalence_pushdown_matches_router_gate() {
        let corpus = [
            "error | head 10",
            "error | prevalence enrich=true",
            "error | prevalence hash_prevalence <= 5 window=7d",
            "error | prevalence domain_prevalence < 3 | where x>1 | sort -count",
            "error | stats count by user | prevalence hash_prevalence <= 5",
            "error | prevalence hash_prevalence <= 5 | stats count by src_ip",
            "error | prevalence hash_prevalence <= 5 | eval y=1",
            "error | prevalence hash_prevalence <= 5 | streamstats count",
            // NAN-1691: a timestamp-field (first_seen) filter is NOT a count-field
            // filter — it never pushes down and no-ops in memory, so both the gate
            // and the router-model below must treat it like "no filter" (Ok), even
            // when it sits after an aggregation. This is the blind spot the earlier
            // `router_ok` model (missing the is_count_field term) papered over.
            "error | prevalence hash_first_seen > now() - 24h",
            "error | stats count by user | prevalence hash_first_seen > now() - 24h",
        ];
        for q in corpus {
            let query = parse_query(q).unwrap();
            let gate_ok = check_prevalence_pushdown_eligible(&query).is_ok();
            // Mirror the router's `has_pushable_prevalence_filter`: a filter is
            // pushable only when every condition is a count field. A timestamp-field
            // (first_seen) filter is not pushable and no-ops in memory, so it counts
            // as "no filter" here.
            let has_filter = extract_prevalence_commands(&query).iter().any(|c| {
                !c.conditions.is_empty()
                    && c.conditions.iter().all(|cond| cond.field.is_count_field())
            });
            // The router pushdown predicate for the FILTER form (excluding the
            // deploy-invariant terms). No pushable filter → always safe (gate returns Ok).
            let router_ok = if has_filter {
                !has_aggregation_before_prevalence(&query)
                    && has_only_simple_post_prevalence_commands(
                        &extract_post_prevalence_commands(&query).commands,
                    )
            } else {
                true
            };
            assert_eq!(gate_ok, router_ok, "gate/router divergence on: {q}");
        }
    }

    #[test]
    fn test_extract_ai_command() {
        let query =
            parse_query(r#"error | ai prompt="Classify these events" max_rows=50"#).unwrap();
        let ai = extract_ai_command(&query);
        assert!(ai.is_some());
        let ai = ai.unwrap();
        assert_eq!(ai.prompt, "Classify these events");
        assert_eq!(ai.max_rows, 50);
    }

    #[test]
    fn test_extract_ai_command_defaults() {
        let query = parse_query(r#"* | ai prompt="Score""#).unwrap();
        let ai = extract_ai_command(&query).unwrap();
        assert_eq!(ai.max_rows, 100); // default
    }

    #[test]
    fn test_extract_ai_command_none_when_absent() {
        let query = parse_query("error | head 10").unwrap();
        assert!(extract_ai_command(&query).is_none());
    }

    #[test]
    fn test_extract_post_ai_commands() {
        let query =
            parse_query(r#"error | ai prompt="Classify" | where ai_verdict="TP" | head 10"#)
                .unwrap();
        let post = extract_post_ai_commands(&query);
        assert_eq!(post.len(), 2); // where + head
    }

    #[test]
    fn test_extract_post_ai_commands_none() {
        let query = parse_query(r#"error | ai prompt="Classify""#).unwrap();
        let post = extract_post_ai_commands(&query);
        assert_eq!(post.len(), 0);
    }

    // === OOM guardrail tests ===

    #[test]
    fn test_oom_eventstats_unfiltered() {
        let query = parse_query("* | eventstats count by src_ip").unwrap();
        assert_eq!(
            detect_oom_risk(&query),
            Some(OomRisk::UnboundedWindowFunction)
        );
    }

    #[test]
    fn test_oom_eventstats_with_filter() {
        let query = parse_query("source_type=firewall | eventstats count by src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_eventstats_with_head_before() {
        let query = parse_query("* | head 1000 | eventstats count by src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_dedup_unfiltered() {
        let query = parse_query("* | dedup src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedDedup));
    }

    #[test]
    fn test_oom_dedup_with_filter() {
        let query = parse_query("source_type=firewall | dedup src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_dedup_with_head_before() {
        let query = parse_query("* | head 1000 | dedup src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_anomaly_unfiltered() {
        let query = parse_query("* | anomaly bytes_out by src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedAnomaly));
    }

    #[test]
    fn test_oom_anomaly_with_filter() {
        let query = parse_query("source_type=firewall | anomaly bytes_out by src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_anomaly_with_head_before() {
        let query = parse_query("* | head 1000 | anomaly bytes_out").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_append_subsearch_scanned() {
        // NAN-1649: the appended pipeline executes for real — a parent filter
        // must not exempt an unfiltered command inside it
        let query =
            parse_query("source_type=firewall | append [search * | anomaly bytes_out]").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedAnomaly));
        let query =
            parse_query("source_type=firewall | append [search * | dedup src_ip]").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedDedup));
    }

    #[test]
    fn test_oom_append_subsearch_with_own_filter_allowed() {
        let query = parse_query(
            "source_type=firewall | append [search source_type=proxy | dedup src_ip]",
        )
        .unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_parent_head_does_not_exempt_subsearch() {
        // parent's head bounds the PARENT rows only
        let query = parse_query("* | head 10 | append [search * | dedup src_ip]").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedDedup));
    }

    #[test]
    fn test_oom_subsearch_own_head_exempts() {
        let query =
            parse_query("source_type=firewall | append [search * | head 100 | dedup src_ip]")
                .unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_join_subsearch_scanned() {
        let query = parse_query(
            "source_type=firewall | join src_ip [search * | eventstats count by src_ip]",
        )
        .unwrap();
        assert_eq!(
            detect_oom_risk(&query),
            Some(OomRisk::UnboundedWindowFunction)
        );
    }

    #[test]
    fn test_oom_nested_append_recursed() {
        let query = parse_query(
            "source_type=firewall | append [search source_type=proxy | append [search * | dedup src_ip]]",
        )
        .unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedDedup));
    }

    #[test]
    fn test_oom_in_subsearch_not_scanned() {
        // IN-subsearches only codegen search + return; other commands never
        // execute, so they must not be guarded
        let query = parse_query("src_ip IN [search error | return src_ip]").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_sample_bounds_downstream_commands() {
        // sample emits ORDER BY … LIMIT N — bounds rows exactly like head
        let query = parse_query("* | sample 1000 | anomaly bytes_out").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
        let query = parse_query("* | sample 1000 | dedup src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_anomaly_aggregation_first_allowed() {
        // aggregation-first anomaly operates on collapsed groups, not raw rows
        let query = parse_query("* | stats count by \"user\" | anomaly count").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_reverse_unfiltered() {
        let query = parse_query("* | reverse").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedReverse));
    }

    #[test]
    fn test_oom_reverse_with_head_before() {
        let query = parse_query("* | head 100 | reverse").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_reverse_with_filter() {
        let query = parse_query("error | reverse").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_transaction_unfiltered() {
        let query = parse_query("* | transaction src_ip maxspan=30m").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedTransaction));
    }

    #[test]
    fn test_oom_transaction_with_filter() {
        let query = parse_query("source_type=proxy | transaction src_ip maxspan=30m").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_values_unfiltered() {
        let query = parse_query("* | stats values(message) by src_ip").unwrap();
        assert_eq!(
            detect_oom_risk(&query),
            Some(OomRisk::UnboundedCollectAggregation)
        );
    }

    #[test]
    fn test_oom_list_unfiltered() {
        let query = parse_query("* | stats list(message) by src_ip").unwrap();
        assert_eq!(
            detect_oom_risk(&query),
            Some(OomRisk::UnboundedCollectAggregation)
        );
    }

    #[test]
    fn test_oom_values_with_filter() {
        let query = parse_query("source_type=firewall | stats values(message) by src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_high_cardinality_group_by_message() {
        let query = parse_query("* | stats count by message").unwrap();
        let risk = detect_oom_risk(&query);
        assert!(
            matches!(risk, Some(OomRisk::HighCardinalityGroupBy { ref field }) if field == "message")
        );
    }

    #[test]
    fn test_oom_high_cardinality_group_by_command_line() {
        let query = parse_query("* | stats count by command_line").unwrap();
        let risk = detect_oom_risk(&query);
        assert!(
            matches!(risk, Some(OomRisk::HighCardinalityGroupBy { ref field }) if field == "command_line")
        );
    }

    #[test]
    fn test_oom_high_cardinality_group_by_with_filter() {
        let query = parse_query("source_type=edr | stats count by message").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_safe_stats_count_by_src_ip() {
        // src_ip is not high-cardinality, count is not values/list — safe even unfiltered
        let query = parse_query("* | stats count by src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_safe_sort() {
        let query = parse_query("* | sort -bytes_out").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_safe_top() {
        let query = parse_query("* | top process_name").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_safe_rare() {
        let query = parse_query("* | rare process_name").unwrap();
        assert_eq!(detect_oom_risk(&query), None);
    }

    #[test]
    fn test_oom_negation_filter_not_meaningful() {
        // Negation filters don't narrow the dataset — should still be caught
        let query = parse_query("source_type!=audit | dedup src_ip").unwrap();
        assert_eq!(detect_oom_risk(&query), Some(OomRisk::UnboundedDedup));
    }

    // ----- NAN-708: panel command validation + cost classification -----

    fn one_day_range() -> crate::search::TimeRangeInput {
        use chrono::{Duration, Utc};
        let end = Utc::now();
        crate::search::TimeRangeInput {
            start: end - Duration::days(1),
            end,
        }
    }

    fn thirty_day_range() -> crate::search::TimeRangeInput {
        use chrono::{Duration, Utc};
        let end = Utc::now();
        crate::search::TimeRangeInput {
            start: end - Duration::days(30),
            end,
        }
    }

    #[test]
    fn classify_cheap_query_is_interactive() {
        let q = parse_query("source_type=foo | head 25").unwrap();
        assert_eq!(
            classify_query_cost(&q, &one_day_range()),
            crate::search::admission::QueryPriority::Interactive
        );
    }

    #[test]
    fn classify_prevalence_is_analytics() {
        let q = parse_query(
            "source_type=windows_sysmon action=network_connection \
             | prevalence enrich=true window=7d | where host_count < 3 | head 25",
        )
        .unwrap();
        assert_eq!(
            classify_query_cost(&q, &one_day_range()),
            crate::search::admission::QueryPriority::Analytics
        );
    }

    #[test]
    fn classify_lookup_is_analytics() {
        let q = parse_query(
            "source_type=foo | lookup threats src_ip OUTPUT threat_score",
        )
        .unwrap();
        assert_eq!(
            classify_query_cost(&q, &one_day_range()),
            crate::search::admission::QueryPriority::Analytics
        );
    }

    #[test]
    fn classify_wide_time_range_alone_is_analytics() {
        // Cheap query body, wide range — still demoted because partition scan
        // is the bottleneck regardless of post-processing.
        let q = parse_query("source_type=foo | head 25").unwrap();
        assert_eq!(
            classify_query_cost(&q, &thirty_day_range()),
            crate::search::admission::QueryPriority::Analytics
        );
    }

    #[test]
    fn validate_blocks_each_surface_bound_command() {
        // Real syntaxes pulled from `nanosiem-core/tests/docs_query_tests.rs`.
        let cases = [
            (
                "source_type=edr | tree parent=ppid child=pid label=process_name",
                PanelBlockedCommand::Tree,
            ),
            (
                "src_host=\"server-01\" | asset field=src_host",
                PanelBlockedCommand::Asset,
            ),
            ("* | cloud by=provider", PanelBlockedCommand::Cloud),
            (
                "* | stats count by src_ip | ai prompt=\"flag scan\"",
                PanelBlockedCommand::Ai,
            ),
            (
                "src_host=\"DC01\" | lateral entity=src_host",
                PanelBlockedCommand::Lateral,
            ),
            (
                "* | funnel by user window=1h step1=(action=\"login\") step2=(action=\"file_access\")",
                PanelBlockedCommand::Funnel,
            ),
        ];
        for (query_str, want) in &cases {
            let q = parse_query(query_str)
                .unwrap_or_else(|e| panic!("failed to parse: {query_str}: {e}"));
            assert_eq!(
                validate_panel_query_commands(&q),
                Err(*want),
                "expected block for: {query_str}"
            );
        }
    }

    #[test]
    fn validate_allows_cheap_and_heavy_but_non_blocked() {
        // Cheap raw search — allowed.
        let q = parse_query("source_type=foo | head 25").unwrap();
        assert!(validate_panel_query_commands(&q).is_ok());

        // Heavy but allowed (prevalence).
        let q = parse_query("* | prevalence enrich=true window=7d").unwrap();
        assert!(validate_panel_query_commands(&q).is_ok());

        // Stats aggregation — allowed.
        let q = parse_query("* | stats count by src_ip | head 25").unwrap();
        assert!(validate_panel_query_commands(&q).is_ok());
    }

    // ----- NAN-712: unscoped prevalence rejection -----

    #[test]
    fn unscoped_prevalence_rejects_bare_wildcard() {
        let q = parse_query("* | prevalence enrich=true window=7d").unwrap();
        let result = validate_panel_query_unscoped_prevalence(&q);
        assert!(matches!(result, Err(ref fields) if fields.is_empty()));
    }

    #[test]
    fn unscoped_prevalence_rejects_all_wildcard_filters() {
        let q = parse_query(
            "source_host=* user=* | prevalence enrich=true window=7d | where host_count<3",
        )
        .unwrap();
        let result = validate_panel_query_unscoped_prevalence(&q);
        match result {
            Err(fields) => {
                assert_eq!(fields, vec!["source_host".to_string(), "user".to_string()]);
            }
            Ok(_) => panic!("expected reject"),
        }
    }

    #[test]
    fn unscoped_prevalence_allows_one_narrowing_filter() {
        // Even though source_host=* is a wildcard, source_type=windows_sysmon
        // narrows the dataset enough to make prevalence tractable.
        let q = parse_query(
            "source_type=windows_sysmon source_host=* | prevalence enrich=true window=7d",
        )
        .unwrap();
        assert!(validate_panel_query_unscoped_prevalence(&q).is_ok());
    }

    #[test]
    fn unscoped_prevalence_allows_keyword_search() {
        // A free-text keyword (not bare `*`) narrows.
        let q = parse_query("powershell | prevalence enrich=true window=7d").unwrap();
        assert!(validate_panel_query_unscoped_prevalence(&q).is_ok());
    }

    #[test]
    fn unscoped_prevalence_allows_action_filter() {
        // Real saturn pattern: source_type + action + wildcard host filter →
        // narrow enough.
        let q = parse_query(
            "source_type=windows_sysmon action=image_load file_hash=* | prevalence enrich=true window=30d",
        )
        .unwrap();
        assert!(validate_panel_query_unscoped_prevalence(&q).is_ok());
    }

    #[test]
    fn unscoped_prevalence_skips_non_prevalence_queries() {
        // Bare wildcard is fine for cheap commands.
        let q = parse_query("* | head 25").unwrap();
        assert!(validate_panel_query_unscoped_prevalence(&q).is_ok());

        let q = parse_query("source_host=* user=* | stats count by src_ip").unwrap();
        assert!(validate_panel_query_unscoped_prevalence(&q).is_ok());
    }

    /// NAN-712 (P1 from code review): `(narrow OR wildcard)` does NOT narrow
    /// — the union with the wildcard branch matches everything. The walker's
    /// OR arm must require BOTH branches narrow, not either.
    #[test]
    fn unscoped_prevalence_rejects_or_with_wildcard_branch() {
        let q = parse_query(
            "source_host=server01 OR user=* | prevalence enrich=true window=7d",
        )
        .unwrap();
        let result = validate_panel_query_unscoped_prevalence(&q);
        assert!(
            matches!(&result, Err(fields) if fields.contains(&"user".to_string())),
            "expected OR with wildcard branch to be rejected, got: {:?}",
            result
        );
    }

    #[test]
    fn unscoped_prevalence_allows_or_with_both_narrowing() {
        let q = parse_query(
            "severity=high OR severity=critical | prevalence enrich=true window=7d",
        )
        .unwrap();
        assert!(validate_panel_query_unscoped_prevalence(&q).is_ok());
    }

    /// NAN-1635 (finding 2.3): the per-row-filter boundary drives whether the
    /// count companion gets a LIMIT bound. Filter-free = match-all `*` plus the
    /// injected `source_type != "audit"` gate plus non-filtering pipes — those
    /// counts are metadata-served and the bound made them 12.8x MORE expensive.
    /// Everything else must classify as filtered (9.5x fewer rows read bounded).
    #[test]
    fn per_row_filter_boundary_for_bounded_count() {
        use super::super::enforce_source_type_exclusion;

        // Filter-free baseline: unbounded count stays.
        for q in ["*", "* | head 100", "* | sort -timestamp", "* | table src_ip, user"] {
            assert!(
                !query_has_per_row_filters(&parse_query(q).unwrap()),
                "`{q}` must classify as filter-free"
            );
        }
        // The audit-gate wrap every non-audit-view search carries:
        // `(<expr>) AND source_type != "audit"` — still filter-free.
        let audit_gated = enforce_source_type_exclusion(&parse_query("*").unwrap(), "audit");
        assert!(
            !query_has_per_row_filters(&audit_gated),
            "audit-gated match-all must stay filter-free"
        );

        // Per-row filters: bounded count engages.
        for q in [
            "error",
            "src_ip=\"1.2.3.4\"",
            "user!=\"bob\"", // non-source_type negation still reads rows
            "* | where status_code=500",
            "* | dedup src_ip",
            "error | head 100",
        ] {
            assert!(
                query_has_per_row_filters(&parse_query(q).unwrap()),
                "`{q}` must classify as filtered"
            );
        }
        let audit_gated_filtered =
            enforce_source_type_exclusion(&parse_query("error").unwrap(), "audit");
        assert!(
            query_has_per_row_filters(&audit_gated_filtered),
            "audit-gated keyword search must classify as filtered"
        );
    }
}
