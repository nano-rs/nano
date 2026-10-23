// SPDX-License-Identifier: AGPL-3.0-or-later

//! Post-processing functions for search results
//!
//! This module provides functions to apply post-processing commands to search results.
//! These commands are applied after the initial SQL query execution and include:
//! - Filtering (where)
//! - Sorting (sort)
//! - Field selection (table, fields)
//! - Aggregation (stats)
//! - Deduplication (dedup)
//! - Field renaming (rename)
//! - Top/rare analysis (top, rare)
//! - Expression evaluation (eval)
//! - Null filling (fillnull)
//! - Risk scoring (risk)
//!
//! # Submodules
//! - [`helpers`] - Shared utility functions (nested field access, JSON conversion)
//! - [`stats`] - Stats aggregation, top/rare analysis, and timechart
//! - [`eval`] - Expression evaluation (arithmetic, functions, type conversion)
//! - [`condition`] - Search condition evaluation on JSON rows
//! - [`rex`] - Regex extraction and substitution

pub mod condition;
pub mod eval;
#[cfg(test)]
mod eval_parity_tests;
mod helpers;
mod rex;
pub mod stats;

pub(crate) use helpers::{get_nested_value, get_nested_values, project_nested_value};

use tracing;

use crate::query::{Command, RiskScoreExpr};
use crate::search::evaluator::helpers::compare_json_values;
use crate::search::SearchError;

use self::condition::evaluate_condition_on_json;
use self::eval::evaluate_eval_expression;
use self::helpers::get_nested_map_value;
use self::rex::apply_rex_post_processing;
use self::stats::{
    apply_stats_post_processing_with_limit, apply_timechart_post_processing,
    apply_top_rare_post_processing,
};

use crate::search::field_utils::normalize_field_alias;

// ============================================================================
// Main Post-Processing Orchestrator
// ============================================================================

/// Result of post-processing, including any runtime warnings (e.g. group cap reached)
pub struct PostProcessingResult {
    pub results: Vec<serde_json::Value>,
    /// Runtime warnings to surface to the client (e.g. "groups capped at 1M")
    pub warnings: Vec<String>,
}

/// Apply post-processing commands to results
///
/// This function applies a series of commands to the results in order.
/// Commands include filtering, sorting, field selection, aggregation, etc.
///
/// # Arguments
/// * `results` - The search results to process
/// * `commands` - The commands to apply
///
/// # Returns
/// * `Ok(PostProcessingResult)` - The processed results and any warnings
/// * `Err(SearchError)` - If processing fails
pub fn apply_post_prevalence_commands(
    results: Vec<serde_json::Value>,
    commands: &[Command],
) -> Result<PostProcessingResult, SearchError> {
    apply_post_prevalence_commands_with_limit(results, commands, 1_000_000)
}

/// Apply post-prevalence commands with a configurable group limit for stats/top/rare
pub fn apply_post_prevalence_commands_with_limit(
    mut results: Vec<serde_json::Value>,
    commands: &[Command],
    max_post_processing_groups: usize,
) -> Result<PostProcessingResult, SearchError> {
    let mut runtime_warnings: Vec<String> = Vec::new();

    tracing::debug!(
        "Applying {} post-prevalence commands to {} results",
        commands.len(),
        results.len()
    );

    // NAN-2711: a second `| risk` pipe ACCUMULATES onto the first, exactly like
    // the ClickHouse generator's `has_prior_risk` branch (score summed and
    // clamped 0-100, factors concatenated, `raw_risk_score` = this pipe's own
    // score, entity = this pipe's entity or `unknown`). The lake search path
    // runs `| risk` here, so without this an RBA rule scored differently on
    // the hosted lake than on a dedicated deployment.
    if let Some(function) = commands.iter().find_map(unsupported_function_in_command) {
        return Err(SearchError::SqlGenError(format!(
            "eval function '{function}' is not supported after a prevalence, lookup, identity or ai \
             stage. Compute it before that stage (it will run in the query engine), or use a \
             supported function."
        )));
    }

    // NAN-3311: a command this evaluator cannot run used to hit the `_` arm,
    // log a warning and be DROPPED — a 200 with plausible but wrong rows.
    // Refuse the whole query before touching any row instead.
    if let Some(command) = commands.iter().find(|c| !is_supported_post_processing_command(c)) {
        return Err(SearchError::SqlValidationError(
            unsupported_post_processing_command_message(command),
        ));
    }

    let mut prior_risk = false;
    for command in commands {
        match command {
            Command::Where { condition } => {
                let original_count = results.len();

                // Log a sample of what we're filtering on
                if let Some(first) = results.first() {
                    if let Some(obj) = first.as_object() {
                        let host_count = obj
                            .get("host_count")
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "MISSING".to_string());
                        tracing::debug!(
                            "Post-prevalence where: sample host_count value = {}",
                            host_count
                        );
                    }
                }

                results = results
                    .into_iter()
                    .filter(|row| evaluate_condition_on_json(condition, row))
                    .collect();
                tracing::debug!(
                    "Post-prevalence where filter: {} -> {} results (condition: {:?})",
                    original_count,
                    results.len(),
                    condition
                );
            }
            Command::Head { count } => {
                results.truncate(*count);
            }
            Command::Tail { count } => {
                let len = results.len();
                if len > *count {
                    results = results.split_off(len - *count);
                }
            }
            Command::Sort { fields, limit } => {
                results.sort_by(|a, b| {
                    for sf in fields {
                        let cmp = sort_compare(
                            get_nested_value(a, &sf.field),
                            get_nested_value(b, &sf.field),
                            sf.descending,
                        );
                        if cmp != std::cmp::Ordering::Equal {
                            return cmp;
                        }
                    }
                    std::cmp::Ordering::Equal
                });
                if let Some(n) = limit {
                    results.truncate(*n);
                }
            }
            Command::Table { fields } => {
                // Check for wildcard - if present, keep all fields
                if fields.len() == 1 && fields[0].name == "*" {
                    // No filtering needed - keep all fields
                    continue;
                }

                // Filter to only include specified fields
                results = results
                    .into_iter()
                    .map(|row| {
                        if row.is_object() {
                            let mut new_obj = serde_json::Map::new();
                            for table_field in fields {
                                let field_name = &table_field.name;
                                // NAN-3333: `table identity_*` / `table src_endpoint.*`
                                // expand against the row (a Nano-side stage such as
                                // `resolve_identity` adds columns SQL never saw).
                                if field_name.contains('*') {
                                    expand_table_wildcard(&row, field_name, &mut new_obj);
                                    continue;
                                }
                                // Normalize common aliases so _time finds "timestamp", etc.
                                let canonical = normalize_field_alias(field_name);
                                let output_name =
                                    table_field.alias.as_deref().unwrap_or(field_name);
                                // Try canonical name first, then raw name as fallback
                                let val = project_nested_value(&row, canonical)
                                    .or_else(|| project_nested_value(&row, field_name));
                                if let Some(val) = val {
                                    new_obj.insert(output_name.to_string(), val);
                                }
                            }
                            serde_json::Value::Object(new_obj)
                        } else {
                            row
                        }
                    })
                    .collect();
            }
            Command::Stats {
                aggregations,
                group_by,
            } => {
                // Skip post-processing for ClickHouse backend - stats are already in SQL
                // Only apply post-processing for PostgreSQL or when stats come after other commands
                // that can't be expressed in SQL
                let (stats_results, groups_capped) = apply_stats_post_processing_with_limit(
                    &results,
                    aggregations,
                    group_by.as_ref(),
                    max_post_processing_groups,
                )?;
                results = stats_results;
                if groups_capped {
                    runtime_warnings.push(format!(
                        "Results grouped by high-cardinality field were capped at {} groups. Some groups may be missing from the output.",
                        max_post_processing_groups
                    ));
                }
            }
            Command::Dedup { fields, keep_first } => {
                let mut seen = std::collections::HashSet::new();
                let mut deduped = Vec::new();

                let iter: Box<dyn Iterator<Item = serde_json::Value>> = if *keep_first {
                    Box::new(results.into_iter())
                } else {
                    Box::new(results.into_iter().rev())
                };

                for row in iter {
                    let key = fields
                        .iter()
                        .map(|f| {
                            get_nested_value(&row, f)
                                .map(|v| v.to_string())
                                .unwrap_or_default()
                        })
                        .collect::<Vec<_>>()
                        .join("|");
                    if seen.insert(key) {
                        deduped.push(row);
                    }
                }

                results = if *keep_first {
                    deduped
                } else {
                    deduped.into_iter().rev().collect()
                };
            }
            Command::Rename { mappings } => {
                results = results
                    .into_iter()
                    .map(|row| {
                        if let Some(mut obj) = row.as_object().cloned() {
                            for mapping in mappings {
                                if let Some(val) = obj.remove(&mapping.from) {
                                    obj.insert(mapping.to.clone(), val);
                                }
                            }
                            serde_json::Value::Object(obj)
                        } else {
                            row
                        }
                    })
                    .collect();
            }
            Command::Fields { fields, keep } => {
                results = results
                    .into_iter()
                    .map(|row| {
                        if let Some(obj) = row.as_object() {
                            let mut new_obj = serde_json::Map::new();
                            if *keep {
                                // Keep only specified fields
                                for field in fields {
                                    if let Some(val) = project_nested_value(&row, field) {
                                        new_obj.insert(field.clone(), val);
                                    }
                                }
                            } else {
                                // Remove specified fields
                                for (k, v) in obj {
                                    if !fields.contains(k) {
                                        new_obj.insert(k.clone(), v.clone());
                                    }
                                }
                            }
                            serde_json::Value::Object(new_obj)
                        } else {
                            row
                        }
                    })
                    .collect();
            }
            // `inject_bounds` (NAN-1711 / audit D15) is intentionally ignored on
            // this in-memory path: the SQL pushdown is the detection path; here
            // the rows simply fall back to content-hash finding dedup (the
            // pre-enrichment behavior — safe, never an error).
            Command::Top {
                field,
                limit,
                by_fields,
                show_count,
                show_percent,
                ..
            } => {
                let (top_results, capped) = apply_top_rare_post_processing(
                    &results,
                    field,
                    *limit,
                    by_fields,
                    *show_count,
                    *show_percent,
                    false,
                )?;
                results = top_results;
                if capped {
                    runtime_warnings.push(format!(
                        "Unique value count for '{}' was capped at {} during top analysis. Some values may be missing.",
                        field, max_post_processing_groups
                    ));
                }
            }
            Command::Rare {
                field,
                limit,
                by_fields,
                show_count,
                show_percent,
                ..
            } => {
                let (rare_results, capped) = apply_top_rare_post_processing(
                    &results,
                    field,
                    *limit,
                    by_fields,
                    *show_count,
                    *show_percent,
                    true,
                )?;
                results = rare_results;
                if capped {
                    runtime_warnings.push(format!(
                        "Unique value count for '{}' was capped at {} during rare analysis. Some values may be missing.",
                        field, max_post_processing_groups
                    ));
                }
            }
            Command::Fillnull {
                value,
                fields: fill_fields,
            } => {
                results = results
                    .into_iter()
                    .map(|row| {
                        if let Some(mut obj) = row.as_object().cloned() {
                            let fields_to_check: Vec<String> = fill_fields
                                .clone()
                                .unwrap_or_else(|| obj.keys().cloned().collect());
                            for field in fields_to_check {
                                if obj.get(&field).map(|v| v.is_null()).unwrap_or(true) {
                                    obj.insert(field, serde_json::Value::String(value.clone()));
                                }
                            }
                            serde_json::Value::Object(obj)
                        } else {
                            row
                        }
                    })
                    .collect();
            }
            Command::Eval { assignments } => {
                results = results
                    .into_iter()
                    .map(|row| {
                        if let Some(mut obj) = row.as_object().cloned() {
                            // SQL `expr AS field`: a NULL result is still a
                            // (NULL) column, and it replaces any earlier value.
                            for assignment in assignments {
                                let val = evaluate_eval_expression(&assignment.expression, &obj)
                                    .unwrap_or(serde_json::Value::Null);
                                obj.insert(assignment.field.clone(), val);
                            }
                            serde_json::Value::Object(obj)
                        } else {
                            row
                        }
                    })
                    .collect();
            }
            Command::Timechart {
                span,
                aggregations,
                split_by,
                ..
            } => {
                results = apply_timechart_post_processing(&results, *span, aggregations, split_by)?;
            }
            Command::Rex {
                field,
                pattern,
                mode,
            } => {
                results = apply_rex_post_processing(results, field.as_deref(), pattern, mode)?;
            }
            Command::Risk {
                score,
                entity_field,
                factor,
                weight,
            } => {
                let pipe_is_prior = prior_risk;
                results = results
                    .into_iter()
                    .map(|row| {
                        let serde_json::Value::Object(mut obj) = row else {
                            return row;
                        };
                        // A `| risk` that ran in SQL before the Nano-side stage
                        // (`… | risk … | prevalence … | risk …`) left its columns
                        // on the row; this pipe accumulates onto it exactly as a
                        // second SQL pipe would.
                        let prior = pipe_is_prior || row_carries_risk_pipe(&obj);
                        apply_risk_pipe(
                            &mut obj,
                            score,
                            entity_field.as_deref(),
                            factor.as_ref(),
                            *weight,
                            prior,
                        );
                        serde_json::Value::Object(obj)
                    })
                    .collect();
                tracing::debug!(
                    "Post-prevalence risk: applied score={:?} entity={:?} factor={:?} to {} results",
                    score, entity_field, factor, results.len()
                );
                prior_risk = true;
            }
            Command::Reverse => results.reverse(),
            // Applied by the caller (the tree view, and the Nano-side stages
            // each search path dispatches itself); nothing to do here.
            Command::Tree { .. }
            | Command::Prevalence { .. }
            | Command::Lookup { .. }
            | Command::InputLookup { .. }
            | Command::ResolveIdentity { .. }
            | Command::Ai { .. } => {}
            other => {
                // Unreachable: the support gate above refused the query.
                return Err(SearchError::SqlValidationError(
                    unsupported_post_processing_command_message(other),
                ));
            }
        }
    }
    Ok(PostProcessingResult {
        results,
        warnings: runtime_warnings,
    })
}

/// Whether the in-memory evaluator implements `command` (NAN-3311). Keep in
/// lockstep with the match arms of [`apply_post_prevalence_commands_with_limit`].
pub fn is_supported_post_processing_command(command: &Command) -> bool {
    matches!(
        command,
        Command::Where { .. }
            | Command::Head { .. }
            | Command::Tail { .. }
            | Command::Sort { .. }
            | Command::Table { .. }
            | Command::Stats { .. }
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
            | Command::Reverse
            | Command::Tree { .. }
            | Command::Prevalence { .. }
            | Command::Lookup { .. }
            | Command::InputLookup { .. }
            | Command::ResolveIdentity { .. }
            | Command::Ai { .. }
    )
}

/// The error for a command that cannot run after a Nano-side stage.
pub fn unsupported_post_processing_command_message(command: &Command) -> String {
    use crate::query::PrettyPrint;
    let printed = command.pretty_print();
    let name = printed.split_whitespace().next().unwrap_or("command");
    format!(
        "`{name}` cannot run after a lookup, prevalence, inputlookup, resolve_identity, ai or \
         lateral stage: those stages run in Nano, and only where, head, tail, sort, table, \
         fields, stats, dedup, rename, top, rare, fillnull, eval, timechart, rex, risk, reverse \
         and tree can follow them. Move `{name}` before that stage."
    )
}

/// The first eval function in `command` the Rust evaluator does not implement.
fn unsupported_function_in_command(command: &Command) -> Option<String> {
    use self::eval::unsupported_post_processing_function as unsupported;
    match command {
        Command::Eval { assignments } => assignments
            .iter()
            .find_map(|assignment| unsupported(&assignment.expression)),
        Command::Risk { score, factor, .. } => {
            let score = match score {
                RiskScoreExpr::Dynamic(expr) => unsupported(expr),
                RiskScoreExpr::Literal(_) => None,
            };
            score.or_else(|| factor.as_ref().and_then(unsupported))
        }
        Command::Where { condition } => unsupported_in_condition(condition),
        _ => None,
    }
}

fn unsupported_in_condition(expr: &crate::query::SearchExpr) -> Option<String> {
    use self::eval::unsupported_post_processing_function as unsupported;
    use crate::query::SearchExpr;
    match expr {
        SearchExpr::FunctionFilter { function, .. }
        | SearchExpr::FieldFunctionFilter { function, .. } => unsupported(function),
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            unsupported_in_condition(left).or_else(|| unsupported_in_condition(right))
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => unsupported_in_condition(inner),
        SearchExpr::BooleanFunction(function) | SearchExpr::EvalPredicate(function) => {
            unsupported(function)
        }
        _ => None,
    }
}

/// Whether a row already carries the columns a `| risk` pipe emits.
fn row_carries_risk_pipe(row: &serde_json::Map<String, serde_json::Value>) -> bool {
    row.contains_key("raw_risk_score")
        && row
            .get("risk_factors")
            .is_some_and(serde_json::Value::is_array)
}

/// One `| risk` pipe over a row, with the SQL generator's semantics
/// (`clickhouse_sql_gen::commands`, `Command::Risk`):
///
/// - `risk_score` accumulates across pipes (sum, clamped 0-100), and
///   `raw_risk_score` carries the same accumulated, unweighted score — it is
///   what the detection calculator scores the finding from.
/// - `entity=` sets `risk_entity` (`unknown` when the field is empty); a pipe
///   without `entity=` inherits the previous pipe's entity, and only a first
///   pipe without one defaults to `unknown`.
/// - factors append; a dynamic factor that evaluates to NULL is a NULL entry
///   (dropped by the calculator), an omitted factor is `risk_assigned`.
/// - a dynamic score that evaluates to NULL makes the score NULL.
fn apply_risk_pipe(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    score: &RiskScoreExpr,
    entity_field: Option<&str>,
    factor: Option<&crate::query::EvalExpression>,
    weight: Option<f64>,
    prior: bool,
) {
    let own_score = match score {
        RiskScoreExpr::Literal(s) => Some(i64::from((*s).clamp(0, 100))),
        RiskScoreExpr::Dynamic(expr) => evaluate_eval_expression(expr, obj)
            .as_ref()
            .and_then(eval::numeric_value)
            .map(|v| (v.trunc() as i64).clamp(0, 100)),
    };
    let accumulated = if prior {
        own_score.and_then(|own| {
            obj.get("risk_score")
                .and_then(eval::numeric_value)
                .map(|prior| (prior as i64 + own).clamp(0, 100))
        })
    } else {
        own_score
    };
    let score_json = accumulated.map_or(serde_json::Value::Null, |v| serde_json::json!(v));
    obj.insert("raw_risk_score".to_string(), score_json.clone());
    obj.insert("risk_score".to_string(), score_json);

    let entity = match entity_field {
        Some(field) => Some(
            get_nested_map_value(obj, field)
                .and_then(eval::clickhouse_text)
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        None if prior => None, // inherit the previous pipe's entity
        None => Some("unknown".to_string()),
    };
    if let Some(entity) = entity {
        obj.insert("risk_entity".to_string(), serde_json::Value::String(entity));
    } else if !obj.contains_key("risk_entity") {
        obj.insert(
            "risk_entity".to_string(),
            serde_json::Value::String("unknown".into()),
        );
    }

    let factor_value = match factor {
        None => serde_json::Value::String("risk_assigned".to_string()),
        Some(expr) => evaluate_eval_expression(expr, obj)
            .as_ref()
            .and_then(eval::clickhouse_text)
            .map_or(serde_json::Value::Null, serde_json::Value::String),
    };
    let mut factors = if prior {
        obj.get("risk_factors")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    factors.push(factor_value);
    obj.insert(
        "risk_factors".to_string(),
        serde_json::Value::Array(factors),
    );
    if let Some(w) = weight {
        obj.insert("risk_weight".to_string(), serde_json::json!(w));
    }
}

/// `*` glob match (any run of characters, including none and dots).
fn table_glob_matches(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if parts.len() == 1 {
        return pattern == text;
    }
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

/// Copy every column of `row` whose dotted name matches `pattern` into `out`
/// under that dotted name. A matching key keeps its whole value; otherwise
/// objects are descended so `src_endpoint.*` reaches `src_endpoint.ip`.
fn expand_table_wildcard(
    row: &serde_json::Value,
    pattern: &str,
    out: &mut serde_json::Map<String, serde_json::Value>,
) {
    fn walk(
        value: &serde_json::Value,
        prefix: &str,
        pattern: &str,
        out: &mut serde_json::Map<String, serde_json::Value>,
    ) {
        let Some(object) = value.as_object() else { return };
        for (key, child) in object {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            if table_glob_matches(pattern, &path) {
                out.entry(path).or_insert_with(|| child.clone());
            } else if child.is_object() {
                walk(child, &path, pattern, out);
            }
        }
    }
    walk(row, "", pattern, out);
}

#[cfg(test)]
mod tests {

    /// NAN-3333: `resolve_identity | table time, identity_*` dropped every
    /// `identity_*` column: the post-processing table looked the glob up as a
    /// literal field name.
    #[test]
    fn table_wildcards_expand_against_row_columns_nan3333() {
        let rows = vec![serde_json::json!({
            "time": "2026-10-08 16:30:27",
            "identity_user": "mtaylor",
            "identity_hostname": "ws-it-083",
            "src_endpoint": {"ip": "10.1.7.249", "port": 5555},
            "user": {"name": "x"},
        })];
        let query = crate::query::parse_query("* | table time, identity_*, src_endpoint.*").unwrap();
        let crate::query::Query::Piped { command, .. } = query else { panic!() };
        let out = apply_post_prevalence_commands(rows, &[command]).unwrap().results;
        let row = out[0].as_object().unwrap();
        let mut keys: Vec<&String> = row.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["identity_hostname", "identity_user", "src_endpoint.ip", "src_endpoint.port", "time"],
            "{row:?}"
        );
        assert!(table_glob_matches("a*b*c", "a-x-b-y-c") && !table_glob_matches("a*b", "ab-c"));
    }

    use super::*;
    use crate::query::{AggFunc, Aggregation, TableField};

    /// The pipe commands of `* | <suffix>`, as the lake splits them off.
    fn suffix(pipeline: &str) -> Vec<Command> {
        fn collect(query: &crate::query::Query, out: &mut Vec<Command>) {
            if let crate::query::Query::Piped { source, command } = query {
                collect(source, out);
                out.push(command.clone());
            }
        }
        let mut commands = Vec::new();
        collect(
            &crate::query::parse_query(&format!("* | {pipeline}")).unwrap(),
            &mut commands,
        );
        commands
    }

    fn run(rows: Vec<serde_json::Value>, pipeline: &str) -> Vec<serde_json::Value> {
        apply_post_prevalence_commands(rows, &suffix(pipeline))
            .unwrap()
            .results
    }

    /// NAN-3311: a command the evaluator cannot run is refused, never
    /// silently dropped; `reverse` now runs.
    #[test]
    fn nan3311_unsupported_suffix_command_is_refused_not_skipped() {
        let rows = vec![
            serde_json::json!({"time": 3}),
            serde_json::json!({"time": 2}),
            serde_json::json!({"time": 1}),
        ];
        for pipeline in [
            "streamstats count as n | table time, n",
            "eventstats count",
            "bin span=1h",
            "mvexpand x",
            "head 2 | chart count by time",
        ] {
            let error = apply_post_prevalence_commands(rows.clone(), &suffix(pipeline))
                .err()
                .unwrap_or_else(|| panic!("{pipeline}: dropped silently"));
            let message = error.to_string();
            assert!(message.contains("cannot run after"), "{pipeline}: {message}");
        }
        let out = run(rows.clone(), "reverse | table time");
        assert_eq!(
            out,
            vec![
                serde_json::json!({"time": 1}),
                serde_json::json!({"time": 2}),
                serde_json::json!({"time": 3}),
            ]
        );
        // Stages the callers dispatch themselves stay accepted.
        assert!(apply_post_prevalence_commands(rows, &suffix("prevalence enrich=true | head 1")).is_ok());
    }

    /// gen1-vs-lean audit: a Nano-side `stats` names its columns exactly as
    /// the SQL generator does (`Aggregation::output_alias`).
    #[test]
    fn nano_side_stats_after_stats_uses_sql_column_names() {
        let groups = vec![
            serde_json::json!({"src": "a", "count": 3}),
            serde_json::json!({"src": "b", "count": 5}),
        ];
        let out = run(groups.clone(), "stats count");
        assert_eq!(out, vec![serde_json::json!({"count": 2})]);
        let out = run(groups.clone(), "stats avg(count), max(count), sum(count)");
        assert_eq!(out.len(), 1);
        let row = out[0].as_object().unwrap();
        assert_eq!(
            row.get("avg").and_then(|v| v.as_f64()),
            Some(4.0),
            "{row:?}"
        );
        assert_eq!(
            row.get("max").and_then(|v| v.as_f64()),
            Some(5.0),
            "{row:?}"
        );
        assert_eq!(
            row.get("sum").and_then(|v| v.as_f64()),
            Some(8.0),
            "{row:?}"
        );
        assert!(!row.contains_key("count"), "{row:?}");
        let out = run(groups, "stats sum(count) as total");
        assert!(out[0].get("total").is_some(), "{out:?}");
    }

    /// gen1-vs-lean audit: Nano-side top/rare keep value types (number, null)
    /// and round `percent` like the SQL path.
    #[test]
    fn nano_side_top_keeps_value_types_and_rounds_percent() {
        let mut rows: Vec<serde_json::Value> =
            (0..12).map(|_| serde_json::json!({"code": 200})).collect();
        rows.push(serde_json::json!({"code": null}));
        let out = run(rows, "top code");
        assert_eq!(out[0]["code"], serde_json::json!(200));
        assert_eq!(out[0]["count"], serde_json::json!(12));
        assert_eq!(out[0]["percent"], serde_json::json!(92.31));
        assert_eq!(out[1]["code"], serde_json::Value::Null);
        assert_eq!(out[1]["percent"], serde_json::json!(7.69));
    }

    /// gen1-vs-lean audit: `sort` puts NULL/missing last in both directions.
    #[test]
    fn nano_side_sort_puts_nulls_last_both_directions() {
        let rows = vec![
            serde_json::json!({"code": null, "count": 9}),
            serde_json::json!({"code": 404, "count": 2}),
            serde_json::json!({"count": 1}),
            serde_json::json!({"code": 200, "count": 7}),
        ];
        let codes = |out: Vec<serde_json::Value>| -> Vec<serde_json::Value> {
            out.iter()
                .map(|row| row.get("code").cloned().unwrap_or(serde_json::Value::Null))
                .collect()
        };
        let asc = codes(run(rows.clone(), "sort code"));
        assert_eq!(&asc[..2], &[serde_json::json!(200), serde_json::json!(404)]);
        assert!(asc[2..].iter().all(|v| v.is_null()));
        let desc = codes(run(rows, "sort -code"));
        assert_eq!(
            &desc[..2],
            &[serde_json::json!(404), serde_json::json!(200)]
        );
        assert!(desc[2..].iter().all(|v| v.is_null()));
    }

    #[test]
    fn canonical_ocsf_nested_fields_survive_table_and_stats() {
        let rows = vec![
            serde_json::json!({"src_endpoint": {"ip": "203.0.113.50"}, "owner": "edge"}),
            serde_json::json!({"src_endpoint": {"ip": "203.0.113.50"}, "owner": "edge"}),
        ];
        let table = Command::Table {
            fields: vec![
                TableField {
                    name: "src_endpoint.ip".to_string(),
                    alias: None,
                },
                TableField {
                    name: "owner".to_string(),
                    alias: None,
                },
            ],
        };
        let tabled = apply_post_prevalence_commands(rows.clone(), &[table])
            .expect("nested table should work")
            .results;
        assert_eq!(tabled[0]["src_endpoint.ip"], "203.0.113.50");
        assert_eq!(tabled[0]["owner"], "edge");

        let stats = Command::Stats {
            aggregations: vec![Aggregation {
                func: AggFunc::Count,
                field: None,
                alias: Some("events".to_string()),
                condition: None,
                field_expr: None,
            }],
            group_by: Some(vec!["src_endpoint.ip".to_string()]),
        };
        let grouped = apply_post_prevalence_commands(rows, &[stats])
            .expect("nested stats should work")
            .results;
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0]["src_endpoint.ip"], "203.0.113.50");
        assert_eq!(grouped[0]["events"], 2);
    }

    fn pipeline(query: &str) -> Vec<Command> {
        let mut commands = Vec::new();
        let mut node = crate::query::parse_query(query).expect("query parses");
        while let crate::query::Query::Piped { source, command } = node {
            commands.push(command);
            node = *source;
        }
        commands.reverse();
        commands
    }

    /// NAN-2711: the lake search path evaluates `| risk` here. Two risk pipes
    /// must accumulate exactly like the ClickHouse generator (sum clamped to
    /// 100, factors concatenated, raw = the accumulated score, entity
    /// inherited by an entity-less pipe), and a row scores only from its own
    /// fields.
    #[test]
    fn stacked_risk_pipes_accumulate_like_the_sql_generator() {
        let rows = vec![
            serde_json::json!({"device.hostname": "h1", "process.cmd_line": "x.exe"}),
            serde_json::json!({"device.hostname": "h2", "process.cmd_line": "y.exe"}),
        ];
        let commands = pipeline(
            "* | risk score=80 entity=device.hostname factor=\"Certutil file download\" \
             | risk score=90 factor=\"Executable download\"",
        );
        let scored = apply_post_prevalence_commands(rows, &commands)
            .unwrap()
            .results;
        for (row, host) in scored.iter().zip(["h1", "h2"]) {
            assert_eq!(row["risk_score"], 100, "80 + 90 clamps to 100");
            assert_eq!(row["raw_risk_score"], 100, "raw is the accumulated score");
            assert_eq!(
                row["risk_factors"],
                serde_json::json!(["Certutil file download", "Executable download"])
            );
            assert_eq!(
                row["risk_entity"], host,
                "the entity-less pipe inherits it, as in SQL"
            );
            assert_eq!(row["device.hostname"], host);
        }

        let single = apply_post_prevalence_commands(
            vec![serde_json::json!({"user": "alice", "risk_score": 42})],
            &pipeline("* | risk score=30 entity=user weight=0.5"),
        )
        .unwrap()
        .results;
        assert_eq!(
            single[0]["risk_score"], 30,
            "a pre-existing field is not a prior risk pipe"
        );
        assert_eq!(single[0]["risk_entity"], "alice");
        assert_eq!(single[0]["risk_weight"], 0.5);
        assert_eq!(
            single[0]["risk_factors"],
            serde_json::json!(["risk_assigned"])
        );
    }

    /// `… | risk score=45 entity=h … | prevalence … | risk score=20 …`: the
    /// first pipe ran in SQL, the second runs here. It must accumulate onto
    /// the SQL pipe's columns and keep its entity, exactly as a second SQL
    /// pipe would (dns_over_https scored 65 against `unknown` / 0 before).
    #[test]
    fn nano_side_risk_accumulates_onto_a_sql_side_risk() {
        let rows = vec![serde_json::json!({
            "src_endpoint": {"hostname": "ws-1"},
            "raw_risk_score": 45, "risk_score": 45, "risk_entity": "ws-1",
            "risk_factors": ["DNS-over-HTTPS detected"], "host_count": 3,
        })];
        let scored = apply_post_prevalence_commands(
            rows,
            &pipeline("* | where host_count < 10 | risk score=20 factor=\"Uncommon DoH usage\""),
        )
        .unwrap()
        .results;
        assert_eq!(scored[0]["risk_score"], 65);
        assert_eq!(
            scored[0]["raw_risk_score"], 65,
            "the calculator reads the accumulated score"
        );
        assert_eq!(scored[0]["risk_entity"], "ws-1");
        assert_eq!(
            scored[0]["risk_factors"],
            serde_json::json!(["DNS-over-HTTPS detected", "Uncommon DoH usage"])
        );
    }

    /// The reported shape: escalation flags computed after `prevalence` with
    /// `match()` / `is_private_ip()` on a row missing one of the fields. The
    /// flags are false, the score is the base plus the true escalations.
    #[test]
    fn escalation_flags_after_prevalence_do_not_null_the_score() {
        let rows = vec![serde_json::json!({
            "device": {"hostname": "h1"},
            "dst_endpoint": {"ip": "10.1.2.3", "port": 8443},
            "process": {"cmd_line": "certutil -urlcache -f http://x"},
        })];
        let scored = apply_post_prevalence_commands(
            rows,
            &pipeline(
                "* | eval esc_private=is_private_ip(dst_endpoint.ip) \
                 | eval esc_dga=match(dst_endpoint.hostname, \"^[a-z0-9]{16,}\\.\") \
                 | eval esc_urlcache=match(process.cmd_line, \"(?i)-urlcache\") \
                 | risk score=min(100, 50 + if(esc_private, 10, 0) + if(esc_dga, 20, 0) + if(esc_urlcache, 25, 0)) \
                   entity=device.hostname factor=concat(\"base\", if(esc_urlcache, \"; urlcache\", \"\"))",
            ),
        )
        .unwrap()
        .results;
        assert_eq!(scored[0]["esc_private"], true);
        assert_eq!(
            scored[0]["esc_dga"],
            serde_json::Value::Null,
            "missing field: NULL flag"
        );
        assert_eq!(scored[0]["raw_risk_score"], 85);
        assert_eq!(scored[0]["risk_entity"], "h1");
        assert_eq!(
            scored[0]["risk_factors"],
            serde_json::json!(["base; urlcache"])
        );
    }

    /// A function the Nano-side evaluator does not implement is a clear
    /// query error, never a silent NULL.
    #[test]
    fn unsupported_function_after_prevalence_is_an_error() {
        let error = apply_post_prevalence_commands(
            vec![serde_json::json!({"d": "a.example.com"})],
            &pipeline("* | eval x=extract_root_domain(d)"),
        )
        .err()
        .expect("unsupported function must fail");
        assert!(error.to_string().contains("extract_root_domain"), "{error}");
        assert!(apply_post_prevalence_commands(
            Vec::new(),
            &pipeline("* | risk score=if(typeof(d) = \"String\", 10, 0)"),
        )
        .is_err());
    }
}

/// `sort` ordering with SQL semantics: missing/NULL values sort LAST in both
/// directions (ClickHouse's default `NULLS LAST`), and values of different
/// JSON types get a fixed type order instead of comparing Equal. The old
/// comparator put the NULL group of `stats count by f | sort -f` first for
/// both `sort f` and `sort -f`, and was not a total order over mixed rows.
fn sort_compare(
    a: Option<&serde_json::Value>,
    b: Option<&serde_json::Value>,
    descending: bool,
) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let a = a.filter(|value| !value.is_null());
    let b = b.filter(|value| !value.is_null());
    let (a, b) = match (a, b) {
        (None, None) => return Ordering::Equal,
        (None, Some(_)) => return Ordering::Greater,
        (Some(_), None) => return Ordering::Less,
        (Some(a), Some(b)) => (a, b),
    };
    let rank = |value: &serde_json::Value| match value {
        serde_json::Value::Number(_) => 0,
        serde_json::Value::String(_) => 1,
        serde_json::Value::Bool(_) => 2,
        _ => 3,
    };
    let cmp = compare_json_values(Some(a), Some(b)).then_with(|| rank(a).cmp(&rank(b)));
    if descending {
        cmp.reverse()
    } else {
        cmp
    }
}

#[cfg(test)]
mod risk_match_envelope_tests {

    #[test]
    fn risk_eval_alias_survives_table_projection_in_match_envelope() {
        use crate::query::parse_query;
        use super::apply_post_prevalence_commands;
        use crate::detection::normalize_match_events_for_query;
        use serde_json::json;

        // The ops rule keeps its eval alias in table, but drops risk_entity.
        for alias in ["account", "subject_alias", "arbitrary_column"] {
            let query = format!("* | eval {alias}=coalesce(user.uid, actor.user.uid) | risk score=60 entity={alias} | table {alias}, risk_score");
            let ast = parse_query(&query).unwrap();
            let mut commands = Vec::new();
            let mut node = &ast;
            while let crate::query::Query::Piped { source, command } = node {
                commands.push(command.clone());
                node = source;
            }
            commands.reverse();
            let mut rows = apply_post_prevalence_commands(
                vec![json!({"actor.user.uid": "usr_example"})], &commands,
            ).unwrap().results;
            assert!(rows[0].get("risk_entity").is_none());
            normalize_match_events_for_query(&mut rows, &query);
            assert_eq!(rows[0]["_match_entity"], "usr_example");
            assert_eq!(rows[0]["_match_entity_type"], "user");
        }
    }

}
