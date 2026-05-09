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
// apply_stats_post_processing (no limit param) is available via apply_post_prevalence_commands default path
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

    tracing::debug!(
        "Applying {} post-prevalence commands to {} results",
        commands.len(),
        results.len()
    );

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
            Command::Top {
                field,
                limit,
                by_fields,
                show_count,
                show_percent,
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
                            for assignment in assignments {
                                if let Some(val) =
                                    evaluate_eval_expression(&assignment.expression, &obj)
                                {
                                    obj.insert(assignment.field.clone(), val);
                                }
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
                results = results
                    .into_iter()
                    .map(|row| {
                        if let Some(mut obj) = row.as_object().cloned() {
                            // Evaluate the score (literal or dynamic expression)
                            let raw_score = match score {
                                RiskScoreExpr::Literal(s) => Some((*s).clamp(0, 100) as f64),
                                RiskScoreExpr::Dynamic(expr) => {
                                    evaluate_eval_expression(expr, &obj)
                                        .and_then(|v| v.as_f64())
                                        .map(|v| v.clamp(0.0, 100.0))
                                }
                            };

                            if let Some(score_val) = raw_score {
                                let score_int = score_val as i64;
                                obj.insert(
                                    "raw_risk_score".to_string(),
                                    serde_json::json!(score_int),
                                );
                                obj.insert("risk_score".to_string(), serde_json::json!(score_int));

                                // Entity field - extract value or default to "unknown"
                                let entity = entity_field
                                    .as_ref()
                                    .and_then(|f| obj.get(f))
                                    .and_then(|v| match v {
                                        serde_json::Value::String(s) => Some(s.clone()),
                                        serde_json::Value::Number(n) => Some(n.to_string()),
                                        _ => None,
                                    })
                                    .unwrap_or_else(|| "unknown".to_string());
                                obj.insert(
                                    "risk_entity".to_string(),
                                    serde_json::Value::String(entity),
                                );

                                // Risk factors array - evaluate expression or use default
                                let factor_str = factor
                                    .as_ref()
                                    .and_then(|expr| evaluate_eval_expression(expr, &obj))
                                    .and_then(|v| match v {
                                        serde_json::Value::String(s) => Some(s),
                                        other => Some(other.to_string()),
                                    })
                                    .unwrap_or_else(|| "risk_assigned".to_string());
                                obj.insert(
                                    "risk_factors".to_string(),
                                    serde_json::json!([factor_str]),
                                );

                                // Optional weight
                                if let Some(w) = weight {
                                    obj.insert("risk_weight".to_string(), serde_json::json!(w));
                                }
                            }

                            serde_json::Value::Object(obj)
                        } else {
                            row
                        }
                    })
                    .collect();
                tracing::debug!(
                    "Post-prevalence risk: applied score={:?} entity={:?} factor={:?} to {} results",
                    score, entity_field, factor, results.len()
                );
            }
            _ => {
                // Other commands not yet supported in post-processing
                tracing::warn!("Post-prevalence command {:?} not yet supported", command);
            }
        }
    }
    Ok(PostProcessingResult {
        results,
        warnings: runtime_warnings,
    })
}
