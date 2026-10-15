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

/// Render a JSON scalar as a string for regex matching. Objects/arrays never
/// match a scalar regex, which is the same choice the SQL path makes.
fn json_to_haystack(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Compile a pattern, honouring the `(?i)` inline flag the SQL path emits.
/// Compilation is cheap relative to a network round trip and these predicates
/// run over a bounded post-processing page, so no cache is warranted yet.
fn regex_cache(pattern: &str) -> Option<regex::Regex> {
    regex::Regex::new(pattern).ok()
}

/// Compare an evaluated function result against the predicate's literal.
/// Mirrors the numeric/string/bool semantics used elsewhere in this module.
fn compare_json_to_value(result: &serde_json::Value, op: &Comparator, value: &Value) -> bool {
    match (result, value) {
        (serde_json::Value::Bool(b), Value::Bool(t)) => match op {
            Comparator::Eq => b == t,
            Comparator::Ne => b != t,
            _ => false,
        },
        // `| where is_private_ip(x)` parses as a bare truthy predicate; the
        // generator compares against boolean true.
        (serde_json::Value::Bool(b), _) => *b,
        (serde_json::Value::Number(n), Value::Number(t)) => {
            let l = n.as_f64().unwrap_or(0.0);
            match op {
                Comparator::Eq => (l - t).abs() < f64::EPSILON,
                Comparator::Ne => (l - t).abs() >= f64::EPSILON,
                Comparator::Lt => l < *t,
                Comparator::Lte => l <= *t,
                Comparator::Gt => l > *t,
                Comparator::Gte => l >= *t,
                _ => false,
            }
        }
        (serde_json::Value::String(s), Value::String(t)) => match op {
            Comparator::Eq => s.eq_ignore_ascii_case(t),
            Comparator::Ne => !s.eq_ignore_ascii_case(t),
            Comparator::Contains => s.to_lowercase().contains(&t.to_lowercase()),
            Comparator::NotContains => !s.to_lowercase().contains(&t.to_lowercase()),
            _ => false,
        },
        (serde_json::Value::String(s), Value::Regex(p)) => match regex_cache(p) {
            Some(re) => {
                let hit = re.is_match(s);
                if matches!(op, Comparator::NotRegex) {
                    !hit
                } else {
                    hit
                }
            }
            None => false,
        },
        _ => false,
    }
}

pub fn evaluate_condition_on_json(condition: &SearchExpr, row: &serde_json::Value) -> bool {
    match condition {
        SearchExpr::FieldFilter {
            field, op, value, ..
        } => {
            // Use get_nested_value to support dot-notation for nested fields like _prevalence.hash.artifact
            let row_value = get_nested_value(row, field);

            // Debug logging for prevalence field filtering
            if field == "host_count" || field == "is_rare" || field.starts_with("_prevalence") {
                tracing::debug!(
                    "evaluate_condition_on_json: field={}, row_value={:?}, target_value={:?}, op={:?}",
                    field, row_value, value, op
                );
            }

            // NAN-2361: `Value::Regex` had NO arm here, so it fell through to
            // `false` — every regex predicate evaluated Nano-side (i.e. after a
            // `| prevalence` / `| risk` stage) silently matched nothing. A rule
            // whose escalation is `| where dest_host=/(\d{3,})/ | risk score=95`
            // simply never escalated. Verified live: `/^10\./` after
            // `| prevalence` returned 0 rows; the same predicate without it
            // returned 5, on data where every value starts `10.`.
            if let Value::Regex(pattern) = value {
                let Some(haystack) = row_value.as_ref().and_then(|v| json_to_haystack(v)) else {
                    return matches!(op, Comparator::NotRegex);
                };
                return match regex_cache(pattern) {
                    Some(re) => {
                        let hit = re.is_match(&haystack);
                        if matches!(op, Comparator::NotRegex) {
                            !hit
                        } else {
                            hit
                        }
                    }
                    // An uncompilable pattern must not silently match everything
                    // or nothing in one direction only.
                    None => false,
                };
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
            // Delegate to the post-processing eval evaluator, which implements the
            // full nPL function set (38 functions), instead of the hand-rolled
            // whitelist below.
            //
            // NAN-2361: that whitelist covered only min/max/now/dayofweek, and
            // every other function fell through to `false`. Because these
            // predicates are evaluated Nano-side AFTER a stage like
            // `| prevalence`, the consequence was silent and inverted: a rule
            // ending `| prevalence … | where NOT is_private_ip(src_endpoint.ip)`
            // had its RFC1918 exclusion evaluate to NOT(false) = TRUE for every
            // row, so the filter never applied. Measured on a live lake:
            // `is_private_ip` after `| prevalence` returned 0 rows where the
            // same predicate without it returned 5, on data that is entirely
            // RFC1918.
            if let EvalExpression::FunctionCall { name, .. } = function {
                if !matches!(name.as_str(), "min" | "max" | "now" | "dayofweek") {
                    if let Some(obj) = row.as_object() {
                        if let Some(result) = super::eval::evaluate_eval_expression(function, obj) {
                            return compare_json_to_value(&result, op, value);
                        }
                    }
                    // The function is real but produced nothing for this row —
                    // treat as non-matching rather than pretending it matched.
                    return false;
                }
            }
            match function {
                EvalExpression::FunctionCall { name, args } => {
                    match name.as_str() {
                        "dayofweek" => {
                            // Extract timestamp field from args and evaluate dayofweek
                            if let Some(EvalExpression::Field(field)) = args.first() {
                                if let Some(timestamp_val) = get_nested_value(row, field) {
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
            // A wildcard keyword (`*svchost*`, `svch*`) mirrors the SQL
            // `iLike` over the whole value (NAN-3034: `*kw*` is now a Keyword,
            // not a message regex); a plain keyword is a substring test.
            let wildcard = (kw.contains(['*', '?'])).then(|| {
                let mut pattern = String::from("(?is)^");
                for c in kw.chars() {
                    match c {
                        '*' => pattern.push_str(".*"),
                        '?' => pattern.push('.'),
                        other => pattern.push_str(&regex::escape(&other.to_string())),
                    }
                }
                pattern.push('$');
                regex_cache(&pattern)
            });
            let needle = kw.to_lowercase();
            // Check if keyword appears in any string field
            if let Some(obj) = row.as_object() {
                obj.values().any(|v| {
                    let Some(s) = v.as_str() else { return false };
                    match &wildcard {
                        Some(Some(re)) => re.is_match(s),
                        Some(None) => false,
                        None => s.to_lowercase().contains(&needle),
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
        SearchExpr::BooleanFunction(function) => {
            // NAN-2361: this used to be a hardcoded `false` — "would need full
            // eval engine for post-processing evaluation" — but that engine is
            // this module's sibling, `super::eval`, with the full 38-function
            // set. Returning false made every standalone boolean predicate
            // evaluated Nano-side (i.e. after `| prevalence` / `| risk`) fail
            // shut, and its NEGATION fail OPEN: a rule ending
            // `| prevalence … | where NOT is_private_ip(src_endpoint.ip)`
            // evaluated NOT(false) = true for every row, so the RFC1918
            // exclusion silently never applied. Measured live: `is_private_ip`
            // after `| prevalence` matched 0 of 5 rows that are all RFC1918,
            // while the same predicate without prevalence matched all 5.
            //
            // A function that genuinely yields nothing for a row stays false —
            // an absent value is not a match — but that is now a real answer
            // rather than a stub.
            row.as_object()
                .and_then(|obj| super::eval::evaluate_eval_expression(function, obj))
                .map(|v| match v {
                    serde_json::Value::Bool(b) => b,
                    serde_json::Value::Null => false,
                    serde_json::Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
                    serde_json::Value::String(ref s) => {
                        !s.is_empty() && !s.eq_ignore_ascii_case("false")
                    }
                    _ => false,
                })
                .unwrap_or(false)
        }
        // The timestamp-aware evaluator first (epoch arithmetic over stats
        // aliases), then the full eval function set: a predicate such as
        // `(is_private_ip(ip) AND port > 1024)` must not fail shut Nano-side.
        SearchExpr::EvalPredicate(expression) => evaluate_expression_on_json(expression, row)
            .or_else(|| {
                row.as_object()
                    .and_then(|obj| super::eval::evaluate_eval_expression(expression, obj))
            })
            .map(|value| match value {
                serde_json::Value::Bool(b) => b,
                serde_json::Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
                _ => false,
            })
            .unwrap_or(false),
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
        SearchExpr::IocMatch { .. } => {
            // NAN-1580: the ioc retro-hunt term is resolved in SQL/at the retro
            // endpoint, not in JSON post-processing — treat as non-matching here.
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
            let normalized_name = name.to_ascii_lowercase();
            match normalized_name.as_str() {
                "min" | "max" => {
                    let mut values = args.iter().map(|arg| evaluate_expression_on_json(arg, row));
                    let first = values.next()??;
                    values.try_fold(first, |best, candidate| {
                        let candidate = candidate?;
                        let ordering = match (best.as_f64(), candidate.as_f64()) {
                            (Some(left), Some(right)) => left.partial_cmp(&right),
                            _ => match (best.as_str(), candidate.as_str()) {
                                (Some(left), Some(right)) => Some(left.cmp(right)),
                                _ => None,
                            },
                        }?;
                        let take_candidate = if normalized_name == "min" {
                            ordering.is_gt()
                        } else {
                            ordering.is_lt()
                        };
                        Some(if take_candidate { candidate } else { best })
                    })
                }
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
                    // SPL timestamps are numeric epoch values. Preserve those
                    // semantics when aggregate aliases arrive as ISO strings.
                    if let (Some(left_str), Some(right_str)) =
                        (left_val.as_str(), right_val.as_str())
                    {
                        if let (Some(left_dt), Some(right_dt)) = (
                            parse_datetime_flexible(left_str),
                            parse_datetime_flexible(right_str),
                        ) {
                            return Some(serde_json::json!(
                                left_dt.signed_duration_since(right_dt).num_milliseconds() as f64
                                    / 1000.0
                            ));
                        }
                    }
                    // Handle datetime - interval
                    if let Some(left_str) = left_val.as_str() {
                        if let Some(dt) = parse_datetime_flexible(left_str) {
                            if let Some(secs) = right_val.as_f64() {
                                // NAN-3080: checked. An out-of-range delta
                                // (a huge INTERVAL) used to panic here and,
                                // under a release panic=abort, kill the jobs
                                // process. It evaluates to null instead.
                                return Some(
                                    shift_datetime(dt, -secs)
                                        .map(|new_dt| serde_json::Value::String(new_dt.to_rfc3339()))
                                        .unwrap_or(serde_json::Value::Null),
                                );
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
                                // NAN-3080: checked. An out-of-range delta
                                // (a huge INTERVAL) used to panic here and,
                                // under a release panic=abort, kill the jobs
                                // process. It evaluates to null instead.
                                return Some(
                                    shift_datetime(dt, secs)
                                        .map(|new_dt| serde_json::Value::String(new_dt.to_rfc3339()))
                                        .unwrap_or(serde_json::Value::Null),
                                );
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
                BinaryOperator::Eq => Some(serde_json::Value::Bool(left_val == right_val)),
                BinaryOperator::Ne => Some(serde_json::Value::Bool(left_val != right_val)),
                BinaryOperator::Gt
                | BinaryOperator::Lt
                | BinaryOperator::Gte
                | BinaryOperator::Lte => {
                    let ordering = match (left_val.as_f64(), right_val.as_f64()) {
                        (Some(left), Some(right)) => left.partial_cmp(&right),
                        _ => match (left_val.as_str(), right_val.as_str()) {
                            (Some(left), Some(right)) => Some(left.cmp(right)),
                            _ => None,
                        },
                    }?;
                    Some(serde_json::Value::Bool(match op {
                        BinaryOperator::Gt => ordering.is_gt(),
                        BinaryOperator::Lt => ordering.is_lt(),
                        BinaryOperator::Gte => ordering.is_ge(),
                        BinaryOperator::Lte => ordering.is_le(),
                        _ => unreachable!(),
                    }))
                }
                BinaryOperator::Mod => {
                    let left = left_val.as_f64()?;
                    let right = right_val.as_f64()?;
                    (right != 0.0).then(|| serde_json::json!(left % right))
                }
                BinaryOperator::And
                | BinaryOperator::Or
                | BinaryOperator::Concat
                | BinaryOperator::Contains
                | BinaryOperator::Like => None,
            }
        }
    }
}

#[cfg(test)]
mod nan2331_where_arithmetic_tests {
    use super::*;
    use crate::query::{parse_query, Command, Query};

    fn where_condition(npl: &str) -> SearchExpr {
        match parse_query(npl).unwrap() {
            Query::Piped {
                command: Command::Where { condition },
                ..
            } => condition,
            other => panic!("expected piped where query, got {other:?}"),
        }
    }

    #[test]
    fn evaluates_numeric_stats_alias_arithmetic() {
        let condition =
            where_condition("* | where event_count > 5 AND (last_seen - first_seen) >= 300");

        assert!(evaluate_condition_on_json(
            &condition,
            &serde_json::json!({
                "event_count": 6,
                "first_seen": 100,
                "last_seen": 450
            })
        ));
        assert!(!evaluate_condition_on_json(
            &condition,
            &serde_json::json!({
                "event_count": 6,
                "first_seen": 300,
                "last_seen": 450
            })
        ));
    }

    #[test]
    fn evaluates_datetime_alias_subtraction_and_case_insensitive_min_max() {
        let condition = where_condition("* | where (MAX(last_seen) - MIN(first_seen)) >= 300");
        let row = serde_json::json!({
            "first_seen": "2026-08-05T10:00:00Z",
            "last_seen": "2026-08-05T10:10:00Z"
        });

        assert!(evaluate_condition_on_json(&condition, &row));
    }

    /// NAN-3080: the live crash. A `where ... > now() - INTERVAL <huge>` after
    /// a Rust-side stage (prevalence) panicked with `DateTime - TimeDelta
    /// overflowed` and took the jobs process down. It must evaluate cleanly.
    #[test]
    fn huge_interval_arithmetic_does_not_panic() {
        let row = serde_json::json!({"host_count": 1, "prevalence_first_seen": "2026-09-29T10:00:00Z"});
        for npl in [
            "* | where host_count < 5 AND prevalence_first_seen > now() - INTERVAL 86400 HOURS",
            "* | where prevalence_first_seen > now() - INTERVAL 311040000 HOURS",
            "* | where prevalence_first_seen < now() + INTERVAL 9999999999 YEARS",
            "* | where prevalence_first_seen > now() - INTERVAL 24 HOUR",
        ] {
            let condition = where_condition(npl);
            let _ = evaluate_condition_on_json(&condition, &row);
        }
        assert!(evaluate_condition_on_json(
            &where_condition("* | where prevalence_first_seen > now() - INTERVAL 100000 DAYS"),
            &row
        ));
    }
}

#[cfg(test)]
mod nan2361_post_stage_predicate_tests {
    use super::*;
    use crate::query::parse_query;

    /// Pull the `| where` condition out of a parsed pipeline so these tests
    /// exercise the real AST the product builds, not a hand-made one.
    fn where_condition(npl: &str) -> SearchExpr {
        fn find(q: &crate::query::Query) -> Option<SearchExpr> {
            match q {
                crate::query::Query::Piped { source, command } => {
                    if let crate::query::Command::Where { condition } = command {
                        return Some(condition.clone());
                    }
                    find(source)
                }
                _ => None,
            }
        }
        find(&parse_query(npl).expect("parses")).expect("has a where stage")
    }

    fn row(json: serde_json::Value) -> serde_json::Value {
        json
    }

    /// A `| where` after a Nano-side stage (prevalence/risk) is evaluated in
    /// Rust, not SQL. `Value::Regex` had no arm here, so EVERY such regex
    /// matched nothing — a risk escalation gated on a regex simply never fired,
    /// silently.
    #[test]
    fn regex_predicate_is_evaluated_not_silently_false() {
        let cond = where_condition(r#"* | where src_endpoint.ip=/^10\./"#);
        assert!(
            evaluate_condition_on_json(
                &cond,
                &row(serde_json::json!({"src_endpoint.ip": "10.1.5.1"}))
            ),
            "a regex that matches must match; before the fix this was always false"
        );
        assert!(
            !evaluate_condition_on_json(
                &cond,
                &row(serde_json::json!({"src_endpoint.ip": "203.0.113.9"}))
            ),
            "a regex that does not match must not match"
        );
    }

    #[test]
    fn negated_regex_predicate_is_evaluated() {
        let cond = where_condition(r#"* | where src_endpoint.ip!=/^10\./"#);
        assert!(!evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"src_endpoint.ip": "10.1.5.1"}))
        ));
        assert!(evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"src_endpoint.ip": "203.0.113.9"}))
        ));
    }

    /// The dangerous one: the evaluator knew only min/max/now/dayofweek, so
    /// `is_private_ip(...)` was false for every row — and its NEGATION was
    /// therefore true for every row. A rule ending
    /// `| prevalence … | where NOT is_private_ip(x)` had no RFC1918 exclusion
    /// at all, while looking perfectly healthy.
    #[test]
    fn function_predicate_uses_the_real_evaluator() {
        let cond = where_condition("* | where is_private_ip(src_endpoint.ip)");
        assert!(
            evaluate_condition_on_json(
                &cond,
                &row(serde_json::json!({"src_endpoint.ip": "10.1.5.1"}))
            ),
            "10.1.5.1 is RFC1918; before the fix this was false"
        );
        assert!(
            !evaluate_condition_on_json(
                &cond,
                &row(serde_json::json!({"src_endpoint.ip": "203.0.113.9"}))
            ),
            "203.0.113.9 is public"
        );
    }

    /// The inversion that made it dangerous rather than merely broken.
    #[test]
    fn negated_function_predicate_does_not_pass_everything() {
        let cond = where_condition("* | where NOT is_private_ip(src_endpoint.ip)");
        assert!(
            !evaluate_condition_on_json(
                &cond,
                &row(serde_json::json!({"src_endpoint.ip": "10.1.5.1"}))
            ),
            "an RFC1918 address must NOT survive a NOT is_private_ip filter — \
             before the fix every row survived, so the exclusion never applied"
        );
        assert!(evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"src_endpoint.ip": "203.0.113.9"}))
        ));
    }

    /// Guard the shapes that already worked, so the delegation does not regress
    /// them: numeric thresholds on prevalence output columns are how every
    /// rarity rule is written.
    #[test]
    fn numeric_thresholds_on_decoration_columns_still_work() {
        let cond = where_condition("* | where host_count < 10");
        assert!(evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"host_count": 2}))
        ));
        assert!(!evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"host_count": 40}))
        ));
    }

    #[test]
    fn string_equality_still_works() {
        let cond = where_condition(r#"* | where severity = "Informational""#);
        assert!(evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"severity": "Informational"}))
        ));
        assert!(!evaluate_condition_on_json(
            &cond,
            &row(serde_json::json!({"severity": "High"}))
        ));
    }
}

/// `dt + secs` seconds, or `None` when the delta or the result is outside
/// chrono's range (never panics; NAN-3080).
pub(crate) fn shift_datetime<Tz: chrono::TimeZone>(
    dt: chrono::DateTime<Tz>,
    secs: f64,
) -> Option<chrono::DateTime<Tz>> {
    if !secs.is_finite() || secs.abs() >= i64::MAX as f64 {
        return None;
    }
    let delta = chrono::TimeDelta::try_seconds(secs as i64)?;
    dt.checked_add_signed(delta)
}

#[cfg(test)]
mod nan3080_datetime_overflow_tests {
    use super::shift_datetime;

    #[test]
    fn huge_or_invalid_deltas_do_not_panic() {
        let now = chrono::Utc::now();
        // `INTERVAL 86400 HOURS` re-parsed: 311,040,000 hours in seconds.
        assert!(shift_datetime(now, -(86_400.0 * 3_600.0 * 3_600.0)).is_some());
        assert!(shift_datetime(now, -1.0e15).is_none(), "beyond chrono's range");
        assert!(shift_datetime(now, 1.0e19).is_none(), "beyond i64");
        assert!(shift_datetime(now, f64::NAN).is_none());
        assert!(shift_datetime(now, f64::NEG_INFINITY).is_none());
        assert_eq!(shift_datetime(now, -86_400.0), Some(now - chrono::Duration::days(1)));
    }
}
