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
mod helpers;
mod rex;
pub mod stats;

use tracing;

use crate::query::{Command, RiskScoreExpr};
use crate::search::evaluator::helpers::compare_json_values;
use crate::search::SearchError;

use self::condition::evaluate_condition_on_json;
use self::eval::evaluate_eval_expression;
use self::stats::{
    apply_stats_post_processing_with_limit, apply_timechart_post_processing,
    apply_top_rare_post_processing,
};
use self::rex::apply_rex_post_processing;

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
    // NAN-3055: a later `| risk` pipe accumulates onto an earlier one, like the
    // SQL generator's `has_prior_risk` branch.
    let mut prior_risk = false;

    tracing::debug!(
        "Applying {} post-prevalence commands to {} results",
        commands.len(),
        results.len()
    );

    // NAN-3311: a command this evaluator cannot run used to hit the `_` arm,
    // log a warning and be DROPPED — a 200 with plausible but wrong rows.
    // Refuse the whole query before touching any row instead.
    if let Some(command) = commands.iter().find(|c| !is_supported_post_processing_command(c)) {
        return Err(SearchError::SqlValidationError(
            unsupported_post_processing_command_message(command),
        ));
    }

    for command in commands {
        match command {
            Command::Where { condition } => {
                condition::validate_post_stage_condition(condition)?;
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
                        let a_val = a.get(&sf.field);
                        let b_val = b.get(&sf.field);
                        let cmp = compare_json_values(a_val, b_val);
                        let cmp = if sf.descending { cmp.reverse() } else { cmp };
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
                        if let Some(obj) = row.as_object() {
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
                                let val = obj.get(canonical).or_else(|| obj.get(field_name));
                                if let Some(val) = val {
                                    new_obj.insert(output_name.to_string(), val.clone());
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
                        .map(|f| row.get(f).map(|v| v.to_string()).unwrap_or_default())
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
                                    if let Some(val) = obj.get(field) {
                                        new_obj.insert(field.clone(), val.clone());
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
                // NAN-4902: functions are checked against the capability table
                // up front (as for `where`), so a NULL result below is a real
                // SQL NULL, never an unsupported call.
                for assignment in assignments {
                    condition::validate_post_stage_expression(&assignment.expression)?;
                }
                results = results
                    .into_iter()
                    .map(|row| {
                        if let Some(mut obj) = row.as_object().cloned() {
                            for assignment in assignments {
                                // `eval x=<expr>` always replaces `x`, as the SQL
                                // alias does; a NULL result is an explicit null.
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
                        // second SQL pipe would (NAN-3055).
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
            | Command::Lateral { .. }
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
            | Command::Lateral { .. }
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

/// True when an earlier (SQL-side) `| risk` pipe already scored this row.
fn row_carries_risk_pipe(row: &serde_json::Map<String, serde_json::Value>) -> bool {
    row.contains_key("raw_risk_score")
        && row
            .get("risk_factors")
            .is_some_and(serde_json::Value::is_array)
}

/// A score operand as a number: JSON numbers, and numeric text.
fn risk_number(value: &serde_json::Value) -> Option<f64> {
    match value {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// One `| risk` pipe over a row, with the SQL generator's semantics
/// (`clickhouse_sql_gen::commands`, `Command::Risk`; NAN-3055, Splunk RBA):
///
/// - `risk_score` accumulates across pipes (sum, clamped 0-100), and
///   `raw_risk_score` carries the same accumulated, unweighted score — it is
///   what the detection calculator scores the finding from.
/// - `entity=` sets `risk_entity` (`unknown` when the field is missing); a pipe
///   without `entity=` inherits the previous pipe's entity, and only a first
///   pipe without one defaults to `unknown`.
/// - `risk_factors` appends this pipe's factor.
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
            .and_then(risk_number)
            .map(|v| (v.trunc() as i64).clamp(0, 100)),
    };
    let accumulated = if prior {
        own_score.and_then(|own| {
            obj.get("risk_score")
                .and_then(risk_number)
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
            obj.get(field)
                .and_then(eval::json_scalar_string)
                .unwrap_or_else(|| "unknown".to_string()),
        ),
        None if prior => None, // inherit the previous pipe's entity
        None => Some("unknown".to_string()),
    };
    if let Some(entity) = entity {
        obj.insert("risk_entity".to_string(), serde_json::Value::String(entity));
    } else if !obj.contains_key("risk_entity") {
        obj.insert("risk_entity".to_string(), serde_json::Value::String("unknown".into()));
    }

    let factor_value = match factor {
        None => serde_json::Value::String("risk_assigned".to_string()),
        Some(expr) => evaluate_eval_expression(expr, obj)
            .as_ref()
            .and_then(eval::json_scalar_string)
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
    obj.insert("risk_factors".to_string(), serde_json::Value::Array(factors));
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
mod ch_semantics_tests;
#[cfg(test)]
mod post_stage_predicate_tests;
#[cfg(test)]
mod eval_capability_tests;
#[cfg(test)]
mod three_valued_ch_tests;
#[cfg(test)]
mod eval_not_tests;
#[cfg(test)]
mod eval_literal_predicate_tests;
#[cfg(test)]
mod risk_chain_tests;
#[cfg(test)]
mod unsupported_command_tests;
#[cfg(test)]
mod table_glob_tests;
#[cfg(test)]
mod datetime_arith_tests;
#[cfg(test)]
mod deep_expression_stack_tests;
#[cfg(test)]
mod cidr_membership_tests;
#[cfg(test)]
mod string_plus_tests;
#[cfg(test)]
mod dc_missing_value_tests;
