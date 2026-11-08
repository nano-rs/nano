// SPDX-License-Identifier: AGPL-3.0-or-later

//! Condition evaluation for post-processing
//!
//! This module provides functions to evaluate search conditions on JSON rows:
//! - Field comparisons (string, number, boolean)
//! - Function-based filters (e.g., dayofweek)
//! - Field-function comparisons (datetime arithmetic)
//! - Logical operators (AND, OR, NOT)
//! - Keyword search, IN lists, literal comparisons


use crate::query::{BinaryOperator, Comparator, EvalExpression, SearchExpr, Value};
use crate::search::evaluator::helpers::parse_datetime_flexible;

use super::eval::ip_in_cidr;
use super::helpers::get_nested_value;

/// A literal that is an actual CIDR (`a.b.c.d/n`, `x::/n`), not just any
/// slash-containing text such as a URL or a path (NAN-4285 review).
fn is_cidr_literal(text: &str) -> bool {
    text.contains('/') && super::eval::is_valid_cidr(text.trim())
}

/// The row's value as an IP address, if it is one.
fn row_ip(value: Option<&serde_json::Value>) -> Option<std::net::IpAddr> {
    value?.as_str()?.trim().parse().ok()
}

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

/// RE2's Perl classes and word boundaries are ASCII; Rust's default classes are Unicode.
/// Keep Unicode literal folding while spelling those classes explicitly for the Rust matcher.
fn clickhouse_regex_pattern(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    let mut in_class = false;
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else { out.push(ch); break; };
            let replacement = match escaped {
                'd' => Some("[0-9]"), 'D' => Some("[^0-9]"),
                'w' => Some("[A-Za-z0-9_]"), 'W' => Some("[^A-Za-z0-9_]"),
                's' => Some(r"[\t\n\f\r ]"), 'S' => Some(r"[^\t\n\f\r ]"),
                'b' if !in_class => Some(r"(?-u:\b)"),
                'B' if !in_class => Some(r"(?-u:\B)"),
                _ => None,
            };
            if let Some(replacement) = replacement { out.push_str(replacement); }
            else { out.push(ch); out.push(escaped); }
        } else {
            if ch == '[' { in_class = true; } else if ch == ']' { in_class = false; }
            out.push(ch);
        }
    }
    out
}

/// ClickHouse `match(haystack, pattern)` semantics: RE2, case-SENSITIVE, dot-all.
/// Shares the bounded compile cache; `(?-i)` overrides the cache's case-folding default.
pub(super) fn compile_case_sensitive_regex(pattern: &str) -> Option<regex::Regex> {
    compile_predicate_regex(&format!("(?-i){pattern}"))
}

/// Match ClickHouse's case-insensitive, dot-all RE2 defaults. Cache bounded compiled patterns (including errors)
/// because this predicate is called for every row in a post-processing page.
fn compile_predicate_regex(pattern: &str) -> Option<regex::Regex> {
    use std::{collections::VecDeque, sync::{Mutex, OnceLock}};
    type Cache = VecDeque<(String, Option<regex::Regex>)>;
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    const MAX_PATTERNS: usize = 32;
    if pattern.len() > 4096 { return None; }
    let cache = CACHE.get_or_init(|| Mutex::new(VecDeque::new()));
    {
        let mut entries = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = entries.iter().position(|(key, _)| key == pattern) {
            let found = entries.remove(index).expect("index exists");
            let compiled = found.1.clone();
            entries.push_back(found);
            return compiled;
        }
    }
    let compiled = regex::RegexBuilder::new(&clickhouse_regex_pattern(pattern))
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build().ok();
    let mut entries = cache.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if entries.len() == MAX_PATTERNS { entries.pop_front(); }
    entries.push_back((pattern.to_owned(), compiled.clone()));
    compiled
}

/// Reject invalid/unsupported regexes once per stage, including beneath NOT and on empty pages.
/// A per-row false cannot represent a query error: NOT(false) would admit every row.
pub(super) fn validate_post_stage_condition(condition: &SearchExpr) -> Result<(), crate::search::SearchError> {
    match condition {
        SearchExpr::FieldFilter { value: Value::Regex(pattern), .. } => {
            if compile_predicate_regex(pattern).is_none() {
                return Err(post_stage_error("Invalid or unsupported post-processing regex".to_owned()));
            }
        }
        SearchExpr::FunctionFilter { function, value, .. } => {
            if let Value::Regex(pattern) = value {
                if compile_predicate_regex(pattern).is_none() {
                    return Err(post_stage_error("Invalid or unsupported post-processing regex".to_owned()));
                }
            }
            validate_post_stage_expression(function)?;
        }
        SearchExpr::BooleanFunction(expression)
        | SearchExpr::EvalPredicate(expression)
        | SearchExpr::FieldFunctionFilter { function: expression, .. } => {
            validate_post_stage_expression(expression)?;
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            validate_post_stage_condition(left)?;
            validate_post_stage_condition(right)?;
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => validate_post_stage_condition(inner)?,
        _ => {}
    }
    Ok(())
}

fn post_stage_error(message: String) -> crate::search::SearchError {
    crate::search::SearchError::SqlGenError(message)
}

/// NAN-4902: every function in a post-stage predicate must be in the
/// capability table (`super::eval::FUNCTIONS`) with a valid argument count, and
/// literal regex / CIDR arguments must compile. Otherwise it is a query error:
/// evaluating it to null and filtering on that drops every row, and under `NOT`
/// admits every row, while the same predicate in ClickHouse SQL errors or works.
pub(super) fn validate_post_stage_expression(expr: &EvalExpression) -> Result<(), crate::search::SearchError> {
    let (name, args) = match expr {
        EvalExpression::FunctionCall { name, args } => (name, args),
        EvalExpression::BinaryOp { left, right, .. } => {
            validate_post_stage_expression(left)?;
            return validate_post_stage_expression(right);
        }
        EvalExpression::Field(_) | EvalExpression::Literal(_) => return Ok(()),
    };
    let spec = super::eval::lookup_function(name).ok_or_else(|| {
        post_stage_error(format!(
            "Function '{name}' is not supported after a post-processing stage (e.g. prevalence, risk)"
        ))
    })?;
    if !spec.accepts(args.len()) {
        return Err(post_stage_error(spec.arity_message(name)));
    }
    let literal = |arg: &EvalExpression| match arg {
        EvalExpression::Literal(Value::String(s) | Value::Regex(s)) => Some(s.clone()),
        _ => None,
    };
    match spec.canonical {
        "match" => {
            if let Some(pattern) = literal(&args[1]) {
                if compile_case_sensitive_regex(&pattern).is_none() {
                    return Err(post_stage_error(format!("Invalid or unsupported regex in {name}()")));
                }
            }
        }
        "cidr_match" => {
            let first_is_cidr = args.len() == 2
                && literal(&args[0]).is_some_and(|a| a.contains('/'))
                && !literal(&args[1]).is_some_and(|a| a.contains('/'));
            let cidr_args: &[EvalExpression] = if first_is_cidr { &args[..1] } else { &args[1..] };
            for cidr in cidr_args.iter().filter_map(literal) {
                if !super::eval::is_valid_cidr(&cidr) {
                    return Err(post_stage_error(format!("Invalid CIDR '{cidr}' in {name}()")));
                }
            }
        }
        _ => {}
    }
    args.iter().try_for_each(validate_post_stage_expression)
}

pub(super) fn sql_like(haystack: &str, pattern: &str) -> bool {
    let mut regex = String::from("(?-i)^(?:");
    let mut chars = pattern.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '%' => regex.push_str(".*"), '_' => regex.push('.'),
            '\\' => regex.push_str(&regex::escape(&chars.next().unwrap_or('\\').to_string())),
            _ => regex.push_str(&regex::escape(&ch.to_string())),
        }
    }
    regex.push_str(")$");
    compile_predicate_regex(&regex).is_some_and(|compiled| compiled.is_match(haystack))
}

/// Compare an evaluated function result against the predicate's literal.
/// Mirrors the numeric/string/bool semantics used elsewhere in this module.
fn compare_json_to_value(result: &serde_json::Value, op: &Comparator, value: &Value) -> bool {
    match (result, value) {
        (serde_json::Value::Bool(b), Value::Bool(t)) => match op {
            Comparator::Eq => b == t,
            Comparator::Ne => b != t,
            Comparator::Lt => u8::from(*b) < u8::from(*t), Comparator::Lte => u8::from(*b) <= u8::from(*t),
            Comparator::Gt => u8::from(*b) > u8::from(*t), Comparator::Gte => u8::from(*b) >= u8::from(*t),
            _ => false,
        },
        // ClickHouse boolean functions return UInt8 and accept numeric comparisons, e.g. is_private_ip(x) = 0.
        (serde_json::Value::Bool(b), Value::Number(target)) => {
            let actual = f64::from(u8::from(*b));
            match op {
                Comparator::Eq => actual == *target, Comparator::Ne => actual != *target,
                Comparator::Lt => actual < *target, Comparator::Lte => actual <= *target,
                Comparator::Gt => actual > *target, Comparator::Gte => actual >= *target,
                _ => false,
            }
        },
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
        // NAN-4943: the SQL side is `lower(f) = / LIKE '<ch_lower(t)>'`, and
        // ClickHouse lower() folds ASCII only — so both sides fold ASCII only.
        (serde_json::Value::String(s), Value::String(t)) => {
            let (ls, lt) = (s.to_ascii_lowercase(), t.to_ascii_lowercase());
            match op {
                Comparator::Eq => ls == lt,
                Comparator::Ne => ls != lt,
                Comparator::Lt => s < t, Comparator::Lte => s <= t, Comparator::Gt => s > t, Comparator::Gte => s >= t,
                Comparator::Contains => ls.contains(&lt),
                Comparator::NotContains => !ls.contains(&lt),
                Comparator::StartsWith => ls.starts_with(&lt),
                Comparator::NotStartsWith => !ls.starts_with(&lt),
                Comparator::EndsWith => ls.ends_with(&lt),
                Comparator::NotEndsWith => !ls.ends_with(&lt),
                Comparator::Like => sql_like(&ls, &lt), Comparator::NotLike => !sql_like(&ls, &lt),
                _ => false,
            }
        }
        (serde_json::Value::String(s), Value::Regex(p)) => match regex_filter_hit(p, s) {
            Some(hit) => if matches!(op, Comparator::NotRegex | Comparator::Ne) { !hit } else { hit },
            None => false,
        },
        _ => false,
    }
}

/// NAN-4943: an nPL field regex on one value, with the SAME classification
/// the SQL generators use ([`regex_plan`]): a literal regex is the lowercase
/// match (ASCII-only fold), anything else a case-insensitive RE2-style match.
/// `None` when the pattern does not compile.
///
/// [`regex_plan`]: crate::query::clickhouse_sql_gen::regex_plan
pub(super) fn regex_filter_hit(pattern: &str, haystack: &str) -> Option<bool> {
    use crate::query::clickhouse_sql_gen::{regex_plan, RegexPlan};
    let folded = || haystack.to_ascii_lowercase();
    Some(match regex_plan(pattern) {
        RegexPlan::Contains(t) => folded().contains(&t),
        RegexPlan::Prefix(p) => folded().starts_with(&p),
        RegexPlan::Suffix(x) => folded().ends_with(&x),
        RegexPlan::AnyContains(list) => {
            let h = folded();
            list.iter().any(|t| h.contains(t.as_str()))
        }
        RegexPlan::Match => compile_predicate_regex(pattern)?.is_match(haystack),
    })
}

/// NAN-4943: the nPL lowercase match on two strings (ClickHouse `lower()`,
/// ASCII-only fold on both sides) for the equality / substring operators.
fn ascii_fold_string_compare(s: &str, op: &Comparator, target: &str) -> bool {
    let (s, t) = (s.to_ascii_lowercase(), target.to_ascii_lowercase());
    match op {
        Comparator::Eq => s == t,
        Comparator::Ne => s != t,
        Comparator::Contains => s.contains(&t),
        Comparator::NotContains => !s.contains(&t),
        Comparator::StartsWith => s.starts_with(&t),
        Comparator::NotStartsWith => !s.starts_with(&t),
        Comparator::EndsWith => s.ends_with(&t),
        Comparator::NotEndsWith => !s.ends_with(&t),
        _ => false,
    }
}

/// Whether `row` passes `condition` as a `WHERE` would: UNKNOWN (NULL) rejects.
pub fn evaluate_condition_on_json(condition: &SearchExpr, row: &serde_json::Value) -> bool {
    evaluate_condition_tri(condition, row).unwrap_or(false)
}

/// NAN-4902: the SQL three-valued truth of `condition` on `row` — `None` is
/// UNKNOWN. A NULL operand stays UNKNOWN through `NOT`, and `AND` / `OR`
/// follow the SQL truth tables, so a post-stage `where` answers exactly as
/// ClickHouse would for the same predicate.
pub(crate) fn evaluate_condition_tri(condition: &SearchExpr, row: &serde_json::Value) -> Option<bool> {
    // NAN-4917: guarded recursion point.
    crate::query::complexity::ensure_sufficient_stack(|| evaluate_condition_tri_unguarded(condition, row))
}

/// Truth of an evaluated predicate value: NULL / no value is UNKNOWN.
fn predicate_truth(value: Option<serde_json::Value>) -> Option<bool> {
    super::eval::sql_truth(value.as_ref())
}

fn evaluate_condition_tri_unguarded(condition: &SearchExpr, row: &serde_json::Value) -> Option<bool> {
    match condition {
        SearchExpr::And(left, right) => {
            return super::eval::sql_logic(
                &BinaryOperator::And,
                evaluate_condition_tri(left, row),
                evaluate_condition_tri(right, row),
            )
        }
        SearchExpr::Or(left, right) => {
            return super::eval::sql_logic(
                &BinaryOperator::Or,
                evaluate_condition_tri(left, row),
                evaluate_condition_tri(right, row),
            )
        }
        SearchExpr::Not(inner) => return super::eval::sql_not(evaluate_condition_tri(inner, row)),
        SearchExpr::Group(inner) => return evaluate_condition_tri(inner, row),
        // A comparison against a NULL value is UNKNOWN (the `field=*`
        // existence test is not a comparison and stays two-valued).
        SearchExpr::FieldFilter { field, value, .. }
            if !matches!(value, Value::String(s) if s == "*")
                && matches!(get_nested_value(row, field), Some(serde_json::Value::Null)) =>
        {
            return None
        }
        SearchExpr::InList { field, .. } | SearchExpr::FieldFunctionFilter { field, .. }
            if matches!(get_nested_value(row, field), Some(serde_json::Value::Null)) =>
        {
            return None
        }
        // NAN-2361: function predicates delegate to the sibling eval engine
        // (they were a hardcoded `false`, so `NOT is_private_ip(x)` admitted
        // every row). NAN-4902: a function that yields NULL is UNKNOWN, not
        // false, so NOT cannot turn it into a match.
        SearchExpr::FunctionFilter { function, op, value } => {
            let result = evaluate_expression_on_json(function, row).filter(|v| !v.is_null())?;
            return Some(compare_json_to_value(&result, op, value));
        }
        SearchExpr::FieldFunctionFilter { function, .. }
            if evaluate_expression_on_json(function, row).is_none_or(|v| v.is_null()) =>
        {
            return None
        }
        SearchExpr::BooleanFunction(function) | SearchExpr::EvalPredicate(function) => {
            return predicate_truth(evaluate_expression_on_json(function, row))
        }
        _ => {}
    }
    Some(evaluate_condition_two_valued(condition, row))
}

/// The leaf predicates that never yield UNKNOWN (after the NULL checks in
/// `evaluate_condition_tri_unguarded`).
fn evaluate_condition_two_valued(condition: &SearchExpr, row: &serde_json::Value) -> bool {
    match condition {
        SearchExpr::FieldFilter {
            field, op, value, ..
        } => {
            // Use get_nested_value to support dot-notation for nested fields like _prevalence.hash.artifact
            let row_value = get_nested_value(row, field);

            // The residual path must use the same existence semantics as SQL.
            // In particular, zero/false are present, while null and empty arrays
            // or strings are absent. Literal equality against "*" drops every
            // ordinary value when a where stage runs after enrichment.
            if matches!(value, Value::String(s) if s == "*")
                && matches!(op, Comparator::Eq | Comparator::Ne)
            {
                let present = match row_value {
                    None | Some(serde_json::Value::Null) => false,
                    Some(serde_json::Value::String(s)) => !s.is_empty(),
                    Some(serde_json::Value::Array(a)) => !a.is_empty(),
                    Some(_) => true,
                };
                return if *op == Comparator::Eq { present } else { !present };
            }

            // NAN-4285: `ip=10.0.0.0/8` / `ip!=…` is network membership, as
            // the SQL path emits; `!=` only matches a row carrying an IP.
            if let (Value::String(cidr), Comparator::Eq | Comparator::Ne) = (value, op) {
                if is_cidr_literal(cidr) {
                    if let Some(ip) = row_ip(row_value) {
                        return ip_in_cidr(ip, cidr.trim()).is_some_and(|hit| hit == (*op == Comparator::Eq));
                    }
                }
            }

            // NAN-4933: `LIKE` / `NOT LIKE` (the piped `| search f=val*`
            // lowering, and `where f LIKE "…"`) compile to the case-insensitive
            // SQL LIKE. They had no arm here and fell through to `false`, so
            // `| prevalence … | search actor.user.name=adm*` returned nothing.
            // An array matches when any element does (NOT LIKE: no element).
            if let (Comparator::Like | Comparator::NotLike, Value::String(pattern)) = (op, value) {
                let pattern = pattern.to_ascii_lowercase();
                let element_matches = |v: &serde_json::Value| {
                    super::eval::json_scalar_string(v)
                        .is_some_and(|text| sql_like(&text.to_ascii_lowercase(), &pattern))
                };
                let hit = match row_value {
                    None | Some(serde_json::Value::Null) => return false,
                    Some(serde_json::Value::Array(items)) => items.iter().any(element_matches),
                    Some(other) => element_matches(other),
                };
                return if *op == Comparator::Like { hit } else { !hit };
            }

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
                // NAN-4943: an array matches when any element does (NOT: none),
                // as `arrayExists` does in SQL.
                if let Some(serde_json::Value::Array(items)) = row_value {
                    let mut hit = false;
                    for item in items {
                        let Some(text) = super::eval::json_scalar_string(item) else { continue };
                        match regex_filter_hit(pattern, &text) {
                            Some(true) => {
                                hit = true;
                                break;
                            }
                            Some(false) => {}
                            None => return false,
                        }
                    }
                    return if matches!(op, Comparator::NotRegex | Comparator::Ne) { !hit } else { hit };
                }
                let Some(haystack) = row_value.as_ref().and_then(|v| json_to_haystack(v)) else {
                    return matches!(op, Comparator::NotRegex);
                };
                return match regex_filter_hit(pattern, &haystack) {
                    Some(hit) => {
                        if matches!(op, Comparator::NotRegex | Comparator::Ne) { !hit } else { hit }
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
                // NAN-4943: the SQL side is the nPL lowercase match
                // (`lower(col) = / LIKE '<ch_lower(v)>'`, ASCII-only fold), so
                // the post-stage compare folds ASCII on both sides too. It was
                // case-SENSITIVE: `| prevalence | where user CONTAINS "Admin"`
                // missed `admin` rows the same predicate found before the pipe.
                (Some(serde_json::Value::String(s)), Value::String(target))
                    if matches!(
                        op,
                        Comparator::Eq | Comparator::Ne | Comparator::Contains | Comparator::NotContains
                            | Comparator::StartsWith | Comparator::NotStartsWith
                            | Comparator::EndsWith | Comparator::NotEndsWith
                    ) =>
                {
                    ascii_fold_string_compare(s, op, target)
                }
                // An array matches when any element does; a negated operator
                // when none does (`arrayExists` / `NOT arrayExists` in SQL).
                (Some(serde_json::Value::Array(items)), Value::String(target))
                    if matches!(
                        op,
                        Comparator::Eq | Comparator::Ne | Comparator::Contains | Comparator::NotContains
                            | Comparator::StartsWith | Comparator::NotStartsWith
                            | Comparator::EndsWith | Comparator::NotEndsWith
                    ) =>
                {
                    let positive = match op {
                        Comparator::Ne => Comparator::Eq,
                        Comparator::NotContains => Comparator::Contains,
                        Comparator::NotStartsWith => Comparator::StartsWith,
                        Comparator::NotEndsWith => Comparator::EndsWith,
                        other => *other,
                    };
                    let hit = items.iter().any(|item| {
                        super::eval::json_scalar_string(item)
                            .is_some_and(|text| ascii_fold_string_compare(&text, &positive, target))
                    });
                    if positive == *op { hit } else { !hit }
                }
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
                                // NAN-4943: `lower(field) = lower(func)` in SQL.
                                Comparator::Eq => field_str.eq_ignore_ascii_case(target_str),
                                Comparator::Ne => !field_str.eq_ignore_ascii_case(target_str),
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
        // Logical connectives and function predicates are evaluated
        // three-valued by `evaluate_condition_tri_unguarded`.
        SearchExpr::And(..)
        | SearchExpr::Or(..)
        | SearchExpr::Not(..)
        | SearchExpr::Group(..)
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_) => evaluate_condition_on_json(condition, row),
        SearchExpr::Keyword(kw) => {
            // NAN-4943: the canonical keyword semantics (token search for a
            // bare term, term boundaries for one-sided wildcards, whole-value
            // substring for `*kw*`) over the free-text body columns the SQL
            // searches (`message`, and OCSF `raw_data`), ASCII-folded.
            ["message", "raw_data"].iter().any(|col| {
                get_nested_value(row, col)
                    .and_then(|v| v.as_str())
                    .is_some_and(|text| crate::query::clickhouse_sql_gen::keyword_matches(kw, text))
            })
        }
        SearchExpr::InList {
            field,
            values,
            negated,
        } => {
            // Use get_nested_value to support dot-notation for nested fields
            let row_value = get_nested_value(row, field);
            // NAN-4285: a CIDR entry is network membership on an IP-valued
            // operand; `NOT IN` with one only matches a row carrying the
            // field, as the SQL path does. Anything else -- a URL or path
            // literal, or a non-IP value -- keeps exact IN / NOT IN.
            let has_cidr = values.iter().any(|v| matches!(v, Value::String(t) if is_cidr_literal(t)));
            if has_cidr && *negated && row_value.and_then(|v| v.as_str()).is_none_or(str::is_empty) {
                return false;
            }
            let ip = has_cidr.then(|| row_ip(row_value)).flatten();
            // NAN-4943: string membership is the nPL lowercase match
            // (`lower(col) IN ('<ch_lower>', …)`): ASCII-fold both sides. An
            // array matches when any element is a member (`arrayExists`).
            let scalar_member = |s: &str| {
                values.iter().any(|v| match v {
                    Value::String(target) => s.eq_ignore_ascii_case(target),
                    Value::Number(target) => s.trim().parse::<f64>().is_ok_and(|n| (n - target).abs() < f64::EPSILON),
                    _ => false,
                })
            };
            let matches = values.iter().any(|v| match (row_value, v) {
                (Some(serde_json::Value::String(_)), Value::String(target))
                    if ip.is_some() && is_cidr_literal(target) =>
                {
                    ip.is_some_and(|ip| ip_in_cidr(ip, target.trim()) == Some(true))
                }
                (Some(serde_json::Value::String(s)), Value::String(target)) => s.eq_ignore_ascii_case(target),
                (Some(serde_json::Value::Number(n)), Value::Number(target)) => n
                    .as_f64()
                    .map(|nf| (nf - target).abs() < f64::EPSILON)
                    .unwrap_or(false),
                (Some(serde_json::Value::Array(items)), _) => items.iter().any(|item| {
                    super::eval::json_scalar_string(item).is_some_and(|text| scalar_member(&text))
                }),
                _ => false,
            });
            if *negated {
                !matches
            } else {
                matches
            }
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
    // NAN-4917: guarded recursion point.
    crate::query::complexity::ensure_sufficient_stack(|| evaluate_expression_on_json_unguarded(expr, row))
}

fn evaluate_expression_on_json_unguarded(
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
                Value::Regex(r) => Some(serde_json::Value::String(r.clone())),
                Value::Ip(ip) => Some(serde_json::Value::String(ip.to_string())),
            }
        }
        // NAN-4933: searchmatch reads the whole row and isbool its argument's
        // field NAME (schema typing), which the scratch-row dispatch below
        // hides; evaluate them against the row itself.
        EvalExpression::FunctionCall { name, .. }
            if name.eq_ignore_ascii_case("searchmatch") || name.eq_ignore_ascii_case("isbool") =>
        {
            super::eval::evaluate_eval_expression(expr, row.as_object()?)
        }
        EvalExpression::FunctionCall { name, args } => {
            // NAN-4902: one function engine. Arguments are evaluated here (so
            // they keep dot-notation field access and datetime arithmetic),
            // then the call is dispatched through the capability table in
            // `super::eval` via a scratch row of the evaluated values. An
            // argument that evaluated to nothing stays absent, exactly as a
            // missing field would.
            let mut scratch = serde_json::Map::with_capacity(args.len());
            let slots = args
                .iter()
                .enumerate()
                .map(|(index, arg)| {
                    let key = format!("\u{0}arg{index}");
                    if let Some(value) = evaluate_expression_on_json(arg, row) {
                        scratch.insert(key.clone(), value);
                    }
                    EvalExpression::Field(key)
                })
                .collect();
            let call = EvalExpression::FunctionCall { name: name.clone(), args: slots };
            super::eval::evaluate_eval_expression(&call, &scratch)
        }
        EvalExpression::BinaryOp { left, op, right } => {
            let left_val = evaluate_expression_on_json(left, row);
            let right_val = evaluate_expression_on_json(right, row);
            // NAN-4902: AND / OR are three-valued (a NULL operand does not
            // force NULL when the other side decides); every other operator
            // propagates NULL, as in ClickHouse.
            if matches!(op, BinaryOperator::And | BinaryOperator::Or) {
                return super::eval::sql_logic(
                    op,
                    super::eval::sql_truth(left_val.as_ref()),
                    super::eval::sql_truth(right_val.as_ref()),
                )
                .map(serde_json::Value::Bool);
            }
            let left_val = left_val.filter(|v| !v.is_null())?;
            let right_val = right_val.filter(|v| !v.is_null())?;

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
                // NAN-4303: a string operand concatenates (`"a" + "b"`).
                BinaryOperator::Add if left_val.is_string() || right_val.is_string() => {
                    let text = super::eval::plus_text;
                    // A datetime + interval keeps its shift below.
                    let shifted_datetime = left_val.as_str().is_some_and(|s| parse_datetime_flexible(s).is_some())
                        && right_val.as_f64().is_some();
                    if !shifted_datetime {
                        return Some(serde_json::Value::String(format!("{}{}", text(&left_val)?, text(&right_val)?)));
                    }
                    let dt = parse_datetime_flexible(left_val.as_str()?)?;
                    Some(
                        shift_datetime(dt, right_val.as_f64()?)
                            .map(|new_dt| serde_json::Value::String(new_dt.to_rfc3339()))
                            .unwrap_or(serde_json::Value::Null),
                    )
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
                // Numbers compare by value: a row's integer 90 equals a literal 90.0.
                BinaryOperator::Eq | BinaryOperator::Ne => {
                    let equal = match (left_val.as_f64(), right_val.as_f64()) {
                        (Some(l), Some(r)) => l == r,
                        _ => left_val == right_val,
                    };
                    Some(serde_json::Value::Bool(equal == matches!(op, BinaryOperator::Eq)))
                }
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
                | BinaryOperator::Or => None, // handled above
                BinaryOperator::Concat
                | BinaryOperator::Contains
                | BinaryOperator::Like => super::eval::apply_binary_op(op, left_val, right_val),
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


#[cfg(test)]
mod existence_tests {
    use super::*;
    use crate::query::{parse_query, Command, Query};

    #[test]
    fn residual_where_existence_keeps_zero_false_and_typed_arrays() {
        for field in ["answer", "metadata.answer"] {
            for (value, present) in [
                (serde_json::json!(null), false),
                (serde_json::json!(""), false),
                (serde_json::json!([]), false),
                (serde_json::json!([""]), true),
                (serde_json::json!("[]"), true),
                (serde_json::json!("*"), true),
                (serde_json::json!(0), true),
                (serde_json::json!(false), true),
            ] {
                let row = if field.contains('.') {
                    serde_json::json!({"metadata": {"answer": value}})
                } else {
                    serde_json::json!({"answer": value})
                };
                for (op, expected) in [("=", present), ("!=", !present)] {
                    let Query::Piped { command: Command::Where { condition }, .. } =
                        parse_query(&format!("* | where {field}{op}*")).unwrap()
                    else { panic!("expected where") };
                    assert_eq!(evaluate_condition_on_json(&condition, &row), expected, "{field}{op}*: {row}");
                    assert_eq!(evaluate_condition_on_json(&condition, &serde_json::json!({})), op == "!=");
                }
            }
        }
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

    fn row(json: serde_json::Value) -> serde_json::Value { json }

    /// A `| where` after a Nano-side stage (prevalence/risk) is evaluated in
    /// Rust, not SQL. `Value::Regex` had no arm here, so EVERY such regex
    /// matched nothing — a risk escalation gated on a regex simply never fired,
    /// silently.
    #[test]
    fn regex_predicate_is_evaluated_not_silently_false() {
        let cond = where_condition(r#"* | where src_ip=/^10\./"#);
        assert!(
            evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "10.1.5.1"}))),
            "a regex that matches must match; before the fix this was always false"
        );
        assert!(
            !evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "203.0.113.9"}))),
            "a regex that does not match must not match"
        );
    }

    /// The SQL path is case-insensitive (`(?i)` prefix); post-processing must
    /// agree or the same rule changes answer depending on pipeline shape.
    #[test]
    fn regex_predicate_is_case_insensitive_like_the_sql_path() {
        let cond = where_condition(r#"* | where src_host=/^ws-/"#);
        assert!(evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_host": "WS-SALES-131"}))));
    }

    #[test]
    fn negated_regex_predicate_is_evaluated() {
        let cond = where_condition(r#"* | where src_ip!=/^10\./"#);
        assert!(!evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "10.1.5.1"}))));
        assert!(evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "203.0.113.9"}))));
    }

    /// The dangerous one: the evaluator knew only min/max/now/dayofweek, so
    /// `is_private_ip(...)` was false for every row — and its NEGATION was
    /// therefore true for every row. A rule ending
    /// `| prevalence … | where NOT is_private_ip(x)` had no RFC1918 exclusion
    /// at all, while looking perfectly healthy.
    #[test]
    fn function_predicate_uses_the_real_evaluator() {
        let cond = where_condition("* | where is_private_ip(src_ip)");
        assert!(
            evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "10.1.5.1"}))),
            "10.1.5.1 is RFC1918; before the fix this was false"
        );
        assert!(
            !evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "203.0.113.9"}))),
            "203.0.113.9 is public"
        );
    }

    /// The inversion that made it dangerous rather than merely broken.
    #[test]
    fn negated_function_predicate_does_not_pass_everything() {
        let cond = where_condition("* | where NOT is_private_ip(src_ip)");
        assert!(
            !evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "10.1.5.1"}))),
            "an RFC1918 address must NOT survive a NOT is_private_ip filter — \
             before the fix every row survived, so the exclusion never applied"
        );
        assert!(evaluate_condition_on_json(&cond, &row(serde_json::json!({"src_ip": "203.0.113.9"}))));
    }

    /// Guard the shapes that already worked, so the delegation does not regress
    /// them: numeric thresholds on prevalence output columns are how every
    /// rarity rule is written.
    #[test]
    fn numeric_thresholds_on_decoration_columns_still_work() {
        let cond = where_condition("* | where host_count < 10");
        assert!(evaluate_condition_on_json(&cond, &row(serde_json::json!({"host_count": 2}))));
        assert!(!evaluate_condition_on_json(&cond, &row(serde_json::json!({"host_count": 40}))));
    }

    #[test]
    fn string_equality_still_works() {
        let cond = where_condition(r#"* | where severity = "Informational""#);
        assert!(evaluate_condition_on_json(&cond, &row(serde_json::json!({"severity": "Informational"}))));
        assert!(!evaluate_condition_on_json(&cond, &row(serde_json::json!({"severity": "High"}))));
    }
}
