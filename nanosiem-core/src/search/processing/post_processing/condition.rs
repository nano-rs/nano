// SPDX-License-Identifier: AGPL-3.0-or-later

//! Condition evaluation for post-processing
//!
//! This module provides functions to evaluate search conditions on JSON rows:
//! - Field comparisons (string, number, boolean)
//! - Function-based filters (e.g., dayofweek)
//! - Field-function comparisons (datetime arithmetic)
//! - Logical operators (AND, OR, NOT)
//! - Keyword search, IN lists, literal comparisons

use chrono::Datelike;

use crate::query::{BinaryOperator, Comparator, EvalExpression, SearchExpr, Value};
use crate::search::evaluator::helpers::parse_datetime_flexible;

use super::helpers::get_nested_value;

// ============================================================================
// Condition Evaluation
// ============================================================================

/// Evaluate a search condition on a JSON row
///
/// # Arguments
/// * `condition` - The condition to evaluate
/// * `row` - The row data to evaluate against
///
/// # Returns
/// * `true` - If the condition is satisfied
/// * `false` - If the condition is not satisfied
pub fn evaluate_condition_on_json(condition: &SearchExpr, row: &serde_json::Value) -> bool {
    match condition {
        SearchExpr::FieldFilter { field, op, value } => {
            // Use get_nested_value to support dot-notation for nested fields like _prevalence.hash.artifact
            let row_value = get_nested_value(row, field);

            // Debug logging for prevalence field filtering
            if field == "host_count" || field == "is_rare" || field.starts_with("_prevalence") {
                tracing::debug!(
                    "evaluate_condition_on_json: field={}, row_value={:?}, target_value={:?}, op={:?}",
                    field, row_value, value, op
                );
            }

            match (row_value, value) {
                (Some(serde_json::Value::Number(n)), Value::Number(target)) => {
                    let row_num = n.as_f64().unwrap_or(0.0);
                    let result = match op {
                        Comparator::Eq => (row_num - target).abs() < f64::EPSILON,
                        Comparator::Ne => (row_num - target).abs() >= f64::EPSILON,
                        Comparator::Lt => row_num < *target,
                        Comparator::Lte => row_num <= *target,
                        Comparator::Gt => row_num > *target,
                        Comparator::Gte => row_num >= *target,
                        _ => false,
                    };
                    if field == "host_count" {
                        tracing::debug!(
                            "Number comparison: {} {:?} {} = {} (row_num={}, target={})",
                            field,
                            op,
                            target,
                            result,
                            row_num,
                            target
                        );
                    }
                    result
                }
                (Some(serde_json::Value::String(s)), Value::String(target)) => match op {
                    Comparator::Eq => s == target,
                    Comparator::Ne => s != target,
                    Comparator::Contains => s.contains(target),
                    Comparator::NotContains => !s.contains(target),
                    Comparator::StartsWith => s.starts_with(target),
                    Comparator::NotStartsWith => !s.starts_with(target),
                    Comparator::EndsWith => s.ends_with(target),
                    Comparator::NotEndsWith => !s.ends_with(target),
                    _ => false,
                },
                (Some(serde_json::Value::Bool(b)), Value::Bool(target)) => match op {
                    Comparator::Eq => b == target,
                    Comparator::Ne => b != target,
                    _ => false,
                },
                (None, _) => {
                    // Field doesn't exist - treat as false for most comparisons
                    matches!(op, Comparator::Ne)
                }
                _ => false,
            }
        }
        SearchExpr::FunctionFilter {
            function,
            op,
            value,
        } => {
            // For function filters, we need to evaluate the function on the JSON data
            // This is a simplified implementation - in practice, we'd need a full expression evaluator
            match function {
                EvalExpression::FunctionCall { name, args } => {
                    match name.as_str() {
                        "dayofweek" => {
                            // Extract timestamp field from args and evaluate dayofweek
                            if let Some(EvalExpression::Field(field)) = args.first() {
                                if let Some(timestamp_val) = row.get(field) {
                                    if let Some(timestamp_str) = timestamp_val.as_str() {
                                        // Parse timestamp and get day of week (1=Sunday, 7=Saturday)
                                        if let Ok(dt) =
                                            chrono::DateTime::parse_from_rfc3339(timestamp_str)
                                        {
                                            let dow = dt.weekday().number_from_sunday() as f64;
                                            if let Value::Number(target) = value {
                                                match op {
                                                    Comparator::Eq => {
                                                        (dow - target).abs() < f64::EPSILON
                                                    }
                                                    Comparator::Ne => {
                                                        (dow - target).abs() >= f64::EPSILON
                                                    }
                                                    Comparator::Lt => dow < *target,
                                                    Comparator::Lte => dow <= *target,
                                                    Comparator::Gt => dow > *target,
                                                    Comparator::Gte => dow >= *target,
                                                    _ => false,
                                                }
                                            } else {
                                                false
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        }
                        _ => {
                            // For other functions, return false for now
                            // In a full implementation, we'd evaluate all supported functions
                            false
                        }
                    }
                }
                _ => false, // Other expression types not supported yet
            }
        }
        SearchExpr::FieldFunctionFilter {
            field,
            op,
            function,
        } => {
            // For field function filters (field op function(args)), we need to evaluate the function
            // and compare it with the field value
            // Use get_nested_value to support dot-notation for nested fields
            let row_value = get_nested_value(row, field);

            // Evaluate the function expression to get a value
            let func_value = evaluate_expression_on_json(function, row);

            // Debug logging for datetime comparisons
            if field == "first_seen" || field == "last_seen" {
                tracing::debug!(
                    field = %field,
                    row_value = ?row_value,
                    func_value = ?func_value,
                    "FieldFunctionFilter datetime comparison"
                );
            }

            match (row_value, func_value) {
                (Some(serde_json::Value::String(field_str)), Some(target_val)) => {
                    // Try to parse as datetime for comparison using flexible parser
                    if let Some(field_dt) = parse_datetime_flexible(field_str) {
                        // Try to parse target as datetime
                        if let Some(target_str) = target_val.as_str() {
                            if let Some(target_dt) = parse_datetime_flexible(target_str) {
                                let result = match op {
                                    Comparator::Eq => field_dt == target_dt,
                                    Comparator::Ne => field_dt != target_dt,
                                    Comparator::Lt => field_dt < target_dt,
                                    Comparator::Lte => field_dt <= target_dt,
                                    Comparator::Gt => field_dt > target_dt,
                                    Comparator::Gte => field_dt >= target_dt,
                                    _ => false,
                                };
                                if field == "first_seen" || field == "last_seen" {
                                    tracing::debug!(
                                        field_dt = %field_dt,
                                        target_dt = %target_dt,
                                        op = ?op,
                                        result = result,
                                        "Datetime comparison result"
                                    );
                                }
                                result
                            } else {
                                tracing::warn!(target_str = %target_str, "Failed to parse target datetime");
                                false
                            }
                        } else if let Some(target_num) = target_val.as_f64() {
                            // Target is a number (unix timestamp?)
                            let field_ts = field_dt.timestamp() as f64;
                            match op {
                                Comparator::Eq => (field_ts - target_num).abs() < 1.0,
                                Comparator::Ne => (field_ts - target_num).abs() >= 1.0,
                                Comparator::Lt => field_ts < target_num,
                                Comparator::Lte => field_ts <= target_num,
                                Comparator::Gt => field_ts > target_num,
                                Comparator::Gte => field_ts >= target_num,
                                _ => false,
                            }
                        } else {
                            tracing::warn!(target_val = ?target_val, "Target is neither string nor number");
                            false
                        }
                    } else {
                        tracing::warn!(field_str = %field_str, "Failed to parse field datetime");
                        // Not a datetime, try string comparison
                        if let Some(target_str) = target_val.as_str() {
                            match op {
                                Comparator::Eq => field_str == target_str,
                                Comparator::Ne => field_str != target_str,
                                Comparator::Lt => field_str.as_str() < target_str,
                                Comparator::Lte => field_str.as_str() <= target_str,
                                Comparator::Gt => field_str.as_str() > target_str,
                                Comparator::Gte => field_str.as_str() >= target_str,
                                _ => false,
                            }
                        } else {
                            false
                        }
                    }
                }
                (Some(serde_json::Value::Number(n)), Some(target_val)) => {
                    let row_num = n.as_f64().unwrap_or(0.0);
                    if let Some(target_num) = target_val.as_f64() {
                        match op {
                            Comparator::Eq => (row_num - target_num).abs() < f64::EPSILON,
                            Comparator::Ne => (row_num - target_num).abs() >= f64::EPSILON,
                            Comparator::Lt => row_num < target_num,
                            Comparator::Lte => row_num <= target_num,
                            Comparator::Gt => row_num > target_num,
                            Comparator::Gte => row_num >= target_num,
                            _ => false,
                        }
                    } else {
                        false
                    }
                }
                (None, _) => {
                    tracing::debug!(field = %field, "Field not found in row");
                    false
                }
                (_, None) => {
                    tracing::debug!(field = %field, "Function evaluation returned None");
                    false
                }
                _ => false,
            }
        }
        SearchExpr::And(left, right) => {
            evaluate_condition_on_json(left, row) && evaluate_condition_on_json(right, row)
        }
        SearchExpr::Or(left, right) => {
            evaluate_condition_on_json(left, row) || evaluate_condition_on_json(right, row)
        }
        SearchExpr::Not(inner) => !evaluate_condition_on_json(inner, row),
        SearchExpr::Group(inner) => evaluate_condition_on_json(inner, row),
        SearchExpr::Keyword(kw) => {
            // Check if keyword appears in any string field
            if let Some(obj) = row.as_object() {
                obj.values().any(|v| {
                    if let Some(s) = v.as_str() {
                        s.to_lowercase().contains(&kw.to_lowercase())
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        }
        SearchExpr::InList {
            field,
            values,
            negated,
        } => {
            // Use get_nested_value to support dot-notation for nested fields
            let row_value = get_nested_value(row, field);
            let matches = values.iter().any(|v| match (row_value, v) {
                (Some(serde_json::Value::String(s)), Value::String(target)) => s == target,
                (Some(serde_json::Value::Number(n)), Value::Number(target)) => n
                    .as_f64()
                    .map(|nf| (nf - target).abs() < f64::EPSILON)
                    .unwrap_or(false),
                _ => false,
            });
            if *negated {
                !matches
            } else {
                matches
            }
        }
        SearchExpr::BooleanFunction(_) => {
            // Standalone boolean function predicate (e.g., isnull(field))
            // Would need full eval engine for post-processing evaluation
            false
        }
        SearchExpr::LiteralComparison { left, op, right } => {
            // Compare two literal strings - used for parameter expansion checks
            let right_str = match right {
                Value::String(s) => s.as_str(),
                _ => return false,
            };
            match op {
                Comparator::Eq => left == right_str,
                Comparator::Ne => left != right_str,
                _ => false, // Other operators not typically used for literal comparisons
            }
        }
        SearchExpr::InSubsearch { .. } => {
            // Subsearch conditions cannot be evaluated in post-processing
            false
        }
    }
}

/// Evaluate an eval expression on a JSON row and return the result as a JSON value
///
/// # Arguments
/// * `expr` - The expression to evaluate
/// * `row` - The row data to evaluate against
///
/// # Returns
/// * `Some(serde_json::Value)` - The evaluated value
/// * `None` - If evaluation fails
pub fn evaluate_expression_on_json(
    expr: &EvalExpression,
    row: &serde_json::Value,
) -> Option<serde_json::Value> {
    match expr {
        EvalExpression::Field(field) => {
            // Use get_nested_value to support dot-notation for nested fields
            get_nested_value(row, field).cloned()
        }
        EvalExpression::Literal(value) => {
            match value {
                Value::String(s) => Some(serde_json::Value::String(s.clone())),
                Value::Number(n) => Some(serde_json::json!(*n)),
                Value::Bool(b) => Some(serde_json::Value::Bool(*b)),
                Value::Interval(duration, _unit) => {
                    // Return interval as seconds for arithmetic
                    Some(serde_json::json!(duration.as_secs() as f64))
                }
                _ => None,
            }
        }
        EvalExpression::FunctionCall { name, args } => {
            match name.as_str() {
                "now" => {
                    // Return current time as ISO string
                    let now = chrono::Utc::now();
                    Some(serde_json::Value::String(now.to_rfc3339()))
                }
                "dayofweek" => {
                    if let Some(arg) = args.first() {
                        if let Some(val) = evaluate_expression_on_json(arg, row) {
                            if let Some(ts_str) = val.as_str() {
                                if let Some(dt) = parse_datetime_flexible(ts_str) {
                                    return Some(serde_json::json!(dt
                                        .weekday()
                                        .number_from_sunday()));
                                }
                            }
                        }
                    }
                    None
                }
                _ => None, // Other functions not yet implemented
            }
        }
        EvalExpression::BinaryOp { left, op, right } => {
            let left_val = evaluate_expression_on_json(left, row)?;
            let right_val = evaluate_expression_on_json(right, row)?;

            match op {
                BinaryOperator::Sub => {
                    // Handle datetime - interval
                    if let Some(left_str) = left_val.as_str() {
                        if let Some(dt) = parse_datetime_flexible(left_str) {
                            if let Some(secs) = right_val.as_f64() {
                                let new_dt = dt - chrono::Duration::seconds(secs as i64);
                                return Some(serde_json::Value::String(new_dt.to_rfc3339()));
                            }
                        }
                    }
                    // Handle numeric subtraction
                    if let (Some(l), Some(r)) = (left_val.as_f64(), right_val.as_f64()) {
                        return Some(serde_json::json!(l - r));
                    }
                    None
                }
                BinaryOperator::Add => {
                    // Handle datetime + interval
                    if let Some(left_str) = left_val.as_str() {
                        if let Some(dt) = parse_datetime_flexible(left_str) {
                            if let Some(secs) = right_val.as_f64() {
                                let new_dt = dt + chrono::Duration::seconds(secs as i64);
                                return Some(serde_json::Value::String(new_dt.to_rfc3339()));
                            }
                        }
                    }
                    // Handle numeric addition
                    if let (Some(l), Some(r)) = (left_val.as_f64(), right_val.as_f64()) {
                        return Some(serde_json::json!(l + r));
                    }
                    None
                }
                BinaryOperator::Mul => {
                    if let (Some(l), Some(r)) = (left_val.as_f64(), right_val.as_f64()) {
                        return Some(serde_json::json!(l * r));
                    }
                    None
                }
                BinaryOperator::Div => {
                    if let (Some(l), Some(r)) = (left_val.as_f64(), right_val.as_f64()) {
                        if r != 0.0 {
                            return Some(serde_json::json!(l / r));
                        }
                    }
                    None
                }
                _ => None,
            }
        }
    }
}
