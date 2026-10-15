// SPDX-License-Identifier: AGPL-3.0-or-later

//! Expression evaluation for post-processing
//!
//! Commands after a Nano-side stage (`prevalence`, `lookup`, identity, `ai`)
//! run here, in Rust, over JSON rows instead of in ClickHouse / chDB. The same
//! rule text must score the same on both sides of that boundary, so this
//! evaluator mirrors the SQL generator (`clickhouse_sql_gen::eval_functions`)
//! function by function, including ClickHouse's NULL semantics:
//!
//! - A missing field is NULL. Most functions return NULL for a NULL input.
//! - `if(NULL, a, b)` is `b`, `case()` skips a NULL condition, and
//!   `AND`/`OR` are three-valued (`NULL AND false` is false, `NULL OR true`
//!   is true), so one missing field no longer nulls a whole risk score.
//! - Booleans are numbers in arithmetic and comparisons (`true` is 1).
//! - `toString` of a number drops a trailing `.0`, as ClickHouse does.
//! - An array compared with a scalar matches when ANY element matches
//!   (`!=` / `NOT` when NO element matches), as `| where` does.
//!
//! A function the SQL generator supports but this evaluator does not is
//! reported up front by [`unsupported_post_processing_function`], so a query
//! fails with a clear message instead of silently evaluating to NULL.

use super::helpers::get_nested_map_value;
use crate::query::{BinaryOperator, EvalExpression, Value};
use chrono::{DateTime, Datelike, NaiveDate, NaiveDateTime, TimeZone, Timelike, Utc};
use serde_json::Value as Json;

/// Functions the Rust evaluator implements with the SQL generator's
/// semantics. Anything else that the SQL generator accepts is rejected on the
/// post-processing path by [`unsupported_post_processing_function`].
const SUPPORTED_FUNCTIONS: &[&str] = &[
    // strings
    "lower",
    "tolower",
    "upper",
    "toupper",
    "len",
    "length",
    "substr",
    "substring",
    "replace",
    "trim",
    "ltrim",
    "rtrim",
    "reverse",
    "split",
    "concat",
    // encoding
    "base64_encode",
    "base64encode",
    "base64_decode",
    "base64decode",
    "hex_encode",
    "hexencode",
    "tohex",
    "hex_decode",
    "hexdecode",
    "fromhex",
    "url_encode",
    "urlencode",
    "url_decode",
    "urldecode",
    // hashing
    "md5",
    "sha1",
    "sha256",
    // ip
    "cidr_match",
    "cidrmatch",
    "is_private_ip",
    "isprivateip",
    "is_rfc1918",
    "is_public_ip",
    "ispublicip",
    "is_loopback",
    "isloopback",
    "ipv4_to_int",
    "ip_to_int",
    "int_to_ipv4",
    "int_to_ip",
    "ip_version",
    // url / domain
    "extract_domain",
    "extractdomain",
    "extract_tld",
    "extracttld",
    "extract_path",
    "extractpath",
    "extract_protocol",
    "extractprotocol",
    "extract_query_string",
    "extractquerystring",
    "domain_depth",
    "subdomain_count",
    // security
    "defang",
    "refang",
    "entropy",
    // time
    "now",
    "today",
    "yesterday",
    "strftime",
    "to_char",
    "epoch",
    "to_epoch",
    "from_epoch",
    "fromepoch",
    "date_diff",
    "datediff",
    "date_trunc",
    "datetrunc",
    "date_part",
    "datepart",
    "year",
    "month",
    "day",
    "dayofmonth",
    "hour",
    "minute",
    "second",
    "dayofweek",
    "dow",
    "dayofyear",
    "doy",
    "week",
    "weekofyear",
    "quarter",
    "age",
    "earliest",
    "latest",
    "start_of_hour",
    "startofhour",
    "start_of_day",
    "startofday",
    "start_of_week",
    "startofweek",
    "start_of_month",
    "startofmonth",
    "start_of_quarter",
    "startofquarter",
    "start_of_year",
    "startofyear",
    // conversion
    "tonumber",
    "to_number",
    "tostring",
    "to_string",
    "toint",
    "to_int",
    "tolong",
    "exact",
    // conditional
    "in",
    "not",
    "if",
    "iif",
    "coalesce",
    "nvl",
    "nullif",
    "isnull",
    "is_null",
    "isnotnull",
    "is_not_null",
    "case",
    "null",
    "true",
    "false",
    // math
    "min",
    "max",
    "abs",
    "ceil",
    "ceiling",
    "floor",
    "round",
    "log",
    "ln",
    "log10",
    "pow",
    "power",
    "sqrt",
    // regex
    "like",
    "match",
    "regex_match",
    "regex_extract",
    "extract_regex",
    "extract",
    "regex_replace",
    "regex_replace_all",
    // similarity
    "levenshtein",
    "levenshtein_distance",
    "edit_distance",
    "levenshtein_normalized",
    "edit_distance_normalized",
    // arrays
    "array_length",
    "arraylength",
    "array_join",
    "arrayjoin",
    "array_contains",
    "arraycontains",
    "has",
    "mvjoin",
    "mvfind",
    "mvcount",
    "mvindex",
    "mvdedup",
    "mvsort",
    "mvappend",
    "mvzip",
    "mvrange",
];

/// The first eval function in `expr` that the post-processing evaluator does
/// not implement, if any. Callers turn it into a query error: evaluating it to
/// NULL would silently drop a risk score or an escalation.
pub fn unsupported_post_processing_function(expr: &EvalExpression) -> Option<String> {
    match expr {
        EvalExpression::Field(_) | EvalExpression::Literal(_) => None,
        EvalExpression::BinaryOp { left, right, .. } => unsupported_post_processing_function(left)
            .or_else(|| unsupported_post_processing_function(right)),
        EvalExpression::FunctionCall { name, args } => {
            let lower = name.to_ascii_lowercase();
            if !SUPPORTED_FUNCTIONS.contains(&lower.as_str()) {
                return Some(name.clone());
            }
            args.iter().find_map(unsupported_post_processing_function)
        }
    }
}

type Row = serde_json::Map<String, Json>;

/// Evaluate an eval expression on a row.
///
/// Returns `None` for SQL NULL (a missing field, a NULL-propagating function,
/// an unparseable input).
pub fn evaluate_eval_expression(expr: &EvalExpression, row: &Row) -> Option<Json> {
    match expr {
        EvalExpression::Field(name) => field_value(row, name),
        EvalExpression::Literal(val) => Some(match val {
            Value::String(s) => Json::String(s.clone()),
            Value::Number(n) => serde_json::json!(n),
            Value::Bool(b) => Json::Bool(*b),
            Value::Regex(r) => Json::String(r.clone()),
            Value::Ip(ip) => Json::String(ip.to_string()),
            Value::Interval(duration, unit) => Json::String(format!(
                "INTERVAL {} {}",
                duration.as_secs(),
                unit.as_str().to_uppercase()
            )),
        }),
        EvalExpression::BinaryOp { left, op, right } => evaluate_binary(left, *op, right, row),
        EvalExpression::FunctionCall { name, args } => evaluate_function_call(name, args, row),
    }
}

/// A field's value on a Nano-side row: a flat key (`"dst_endpoint.ip"`, SQL
/// aliases) or a path into native OCSF JSON. A path that crosses a repeated
/// object (`module.file.signatures[].state`) yields the array of its leaves,
/// the same `Array(T)` the query engine reads for that path.
fn field_value(row: &Row, name: &str) -> Option<Json> {
    if let Some(value) = get_nested_map_value(row, name) {
        return Some(value.clone()).filter(|value| !value.is_null());
    }
    let mut segments = name.split('.');
    let root = row.get(segments.next()?)?;
    let mut current = vec![root];
    let mut crossed_array = false;
    for segment in segments {
        let mut next = Vec::new();
        for value in current {
            match value {
                Json::Object(object) => next.extend(object.get(segment)),
                Json::Array(items) => {
                    crossed_array = true;
                    next.extend(items.iter().filter_map(|item| item.get(segment)));
                }
                _ => {}
            }
        }
        current = next;
    }
    if !crossed_array {
        return current
            .first()
            .map(|value| (*value).clone())
            .filter(|value| !value.is_null());
    }
    let mut leaves = Vec::new();
    for value in current {
        match value {
            Json::Array(items) => leaves.extend(items.iter().cloned()),
            other => leaves.push(other.clone()),
        }
    }
    Some(Json::Array(leaves))
}

// ============================================================================
// Value coercions (ClickHouse semantics)
// ============================================================================

/// `toFloat64OrNull(toString(x))`: numbers, booleans (1/0) and numeric text.
fn num(value: &Json) -> Option<f64> {
    match value {
        Json::Number(n) => n.as_f64(),
        Json::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Json::String(s) => s.parse::<f64>().ok().filter(|n| n.is_finite()),
        _ => None,
    }
}

/// `toFloat64OrNull(toString(x))` for the risk pipe.
pub(super) fn numeric_value(value: &Json) -> Option<f64> {
    num(value)
}

/// ClickHouse `toString(x)` for the risk pipe; `None` for NULL.
pub(super) fn clickhouse_text(value: &Json) -> Option<String> {
    ch_string(value)
}

/// A condition's truth value; `None` is SQL NULL.
fn truth(value: Option<&Json>) -> Option<bool> {
    match value? {
        Json::Bool(b) => Some(*b),
        Json::Number(n) => n.as_f64().map(|n| n != 0.0),
        Json::String(s) => Some(!s.is_empty()),
        Json::Null => None,
        _ => None,
    }
}

/// ClickHouse number rendering: integral floats print without `.0`.
fn number_text(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

/// ClickHouse `toString(x)`; `None` for NULL.
fn ch_string(value: &Json) -> Option<String> {
    match value {
        Json::Null => None,
        Json::String(s) => Some(s.clone()),
        Json::Number(n) => Some(n.as_f64().map_or_else(|| n.to_string(), number_text)),
        Json::Bool(b) => Some(b.to_string()),
        Json::Array(items) => Some(format!(
            "[{}]",
            items
                .iter()
                .map(|item| match item {
                    Json::String(s) =>
                        format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
                    Json::Null => "NULL".to_string(),
                    other => ch_string(other).unwrap_or_default(),
                })
                .collect::<Vec<_>>()
                .join(",")
        )),
        Json::Object(_) => Some(value.to_string()),
    }
}

fn json_number(n: f64) -> Option<Json> {
    serde_json::Number::from_f64(n).map(Json::Number)
}

fn bool_json(b: bool) -> Json {
    Json::Bool(b)
}

/// A regex literal's matcher: case-insensitive with or without `/i`, bounded
/// like the SQL-side validation.
fn case_insensitive_regex(pattern: &str) -> Option<regex::Regex> {
    let pattern = if pattern.starts_with("(?i)") {
        pattern.to_string()
    } else {
        format!("(?i){pattern}")
    };
    bounded_regex(&pattern)
}

fn bounded_regex(pattern: &str) -> Option<regex::Regex> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .build()
        .ok()
}

/// `iLike` pattern (`%` / `_`), case-insensitive.
fn ilike_regex(pattern: &str) -> Option<regex::Regex> {
    let mut regex = String::from("(?is)^");
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(escaped) = chars.next() {
                    regex.push_str(&regex::escape(&escaped.to_string()));
                }
            }
            '%' => regex.push_str(".*"),
            '_' => regex.push('.'),
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
    }
    regex.push('$');
    bounded_regex(&regex)
}

// ============================================================================
// Binary operators
// ============================================================================

/// Scalar equality with the SQL generator's rules: case-insensitive against a
/// quoted string literal, numeric between numbers/booleans, exact otherwise.
fn scalar_equal(left: &Json, right: &Json, literal_string: bool) -> bool {
    if literal_string {
        return match (ch_string(left), ch_string(right)) {
            (Some(l), Some(r)) => l.to_lowercase() == r.to_lowercase(),
            _ => false,
        };
    }
    let numeric_like = |v: &Json| matches!(v, Json::Number(_) | Json::Bool(_));
    if numeric_like(left) || numeric_like(right) {
        if let (Some(l), Some(r)) = (num(left), num(right)) {
            return l == r;
        }
    }
    left == right
}

fn evaluate_binary(
    left: &EvalExpression,
    op: BinaryOperator,
    right: &EvalExpression,
    row: &Row,
) -> Option<Json> {
    // Three-valued AND / OR: a NULL side does not decide the result when the
    // other side does (`NULL AND false` is false, `NULL OR true` is true).
    if matches!(op, BinaryOperator::And | BinaryOperator::Or) {
        let l = truth(evaluate_eval_expression(left, row).as_ref());
        let r = truth(evaluate_eval_expression(right, row).as_ref());
        return match (op, l, r) {
            (BinaryOperator::And, Some(false), _) | (BinaryOperator::And, _, Some(false)) => {
                Some(bool_json(false))
            }
            (BinaryOperator::And, Some(true), Some(true)) => Some(bool_json(true)),
            (BinaryOperator::Or, Some(true), _) | (BinaryOperator::Or, _, Some(true)) => {
                Some(bool_json(true))
            }
            (BinaryOperator::Or, Some(false), Some(false)) => Some(bool_json(false)),
            _ => None,
        };
    }

    if let Some(result) = datetime_arithmetic(left, op, right, row) {
        return result;
    }

    // `f = /re/[i]` / `f != /re/`: case-insensitive regex match.
    if matches!(op, BinaryOperator::Eq | BinaryOperator::Ne) {
        let regex_side = match (left, right) {
            (subject, EvalExpression::Literal(Value::Regex(pattern)))
            | (EvalExpression::Literal(Value::Regex(pattern)), subject) => Some((subject, pattern)),
            _ => None,
        };
        if let Some((subject, pattern)) = regex_side {
            let regex = case_insensitive_regex(pattern)?;
            let value = evaluate_eval_expression(subject, row)?;
            let matched = match &value {
                Json::Array(items) => items
                    .iter()
                    .filter_map(ch_string)
                    .any(|text| regex.is_match(&text)),
                other => regex.is_match(&ch_string(other)?),
            };
            return Some(bool_json(matched == (op == BinaryOperator::Eq)));
        }
    }

    let left_val = evaluate_eval_expression(left, row);
    let right_val = evaluate_eval_expression(right, row);

    // Multivalue semantics: an array against a scalar matches when ANY
    // element matches; `!=` is true when NO element equals the scalar.
    let array_side = match (&left_val, &right_val) {
        (Some(Json::Array(items)), Some(other)) if !other.is_array() => {
            Some((items.clone(), other.clone(), true))
        }
        (Some(other), Some(Json::Array(items)))
            if !other.is_array() && matches!(op, BinaryOperator::Eq | BinaryOperator::Ne) =>
        {
            Some((items.clone(), other.clone(), false))
        }
        _ => None,
    };
    if let Some((items, scalar, array_on_left)) = array_side {
        let literal_string = matches!(
            if array_on_left { right } else { left },
            EvalExpression::Literal(Value::String(_))
        );
        let any = |predicate: &dyn Fn(&Json) -> bool| {
            items.iter().filter(|item| !item.is_null()).any(predicate)
        };
        return match op {
            BinaryOperator::Eq => Some(bool_json(any(&|item| {
                scalar_equal(item, &scalar, literal_string || scalar.is_string())
            }))),
            BinaryOperator::Ne => Some(bool_json(!any(&|item| {
                scalar_equal(item, &scalar, literal_string || scalar.is_string())
            }))),
            BinaryOperator::Contains => {
                let needle = ch_string(&scalar)?.to_lowercase();
                Some(bool_json(any(&|item| {
                    ch_string(item).is_some_and(|text| text.to_lowercase().contains(&needle))
                })))
            }
            BinaryOperator::Like => {
                let regex = ilike_regex(&ch_string(&scalar)?)?;
                Some(bool_json(any(&|item| {
                    ch_string(item).is_some_and(|text| regex.is_match(&text))
                })))
            }
            BinaryOperator::Gt | BinaryOperator::Lt | BinaryOperator::Gte | BinaryOperator::Lte => {
                let r = num(&scalar)?;
                Some(bool_json(any(&|item| {
                    num(item).is_some_and(|l| compare_numbers(op, l, r))
                })))
            }
            _ => None,
        };
    }

    let left_val = left_val?;
    let right_val = right_val?;
    match op {
        BinaryOperator::Add | BinaryOperator::Sub | BinaryOperator::Mul => {
            let (l, r) = (num(&left_val)?, num(&right_val)?);
            json_number(match op {
                BinaryOperator::Add => l + r,
                BinaryOperator::Sub => l - r,
                _ => l * r,
            })
        }
        BinaryOperator::Div => {
            let (l, r) = (num(&left_val)?, num(&right_val)?);
            // ClickHouse: x / 0 is ±inf / nan, which JSON renders as null.
            if r == 0.0 {
                None
            } else {
                json_number(l / r)
            }
        }
        BinaryOperator::Mod => {
            let (l, r) = (num(&left_val)?, num(&right_val)?);
            if r == 0.0 {
                None
            } else {
                json_number(l % r)
            }
        }
        BinaryOperator::Concat => Some(Json::String(format!(
            "{}{}",
            ch_string(&left_val)?,
            ch_string(&right_val)?
        ))),
        BinaryOperator::Eq | BinaryOperator::Ne => {
            let literal_string = matches!(left, EvalExpression::Literal(Value::String(_)))
                || matches!(right, EvalExpression::Literal(Value::String(_)));
            let equal = scalar_equal(&left_val, &right_val, literal_string);
            Some(bool_json(equal == (op == BinaryOperator::Eq)))
        }
        BinaryOperator::Gt | BinaryOperator::Lt | BinaryOperator::Gte | BinaryOperator::Lte => {
            let (l, r) = (num(&left_val)?, num(&right_val)?);
            Some(bool_json(compare_numbers(op, l, r)))
        }
        BinaryOperator::Contains => {
            let (l, r) = (ch_string(&left_val)?, ch_string(&right_val)?);
            Some(bool_json(l.to_lowercase().contains(&r.to_lowercase())))
        }
        BinaryOperator::Like => {
            let text = ch_string(&left_val)?;
            let regex = ilike_regex(&ch_string(&right_val)?)?;
            Some(bool_json(regex.is_match(&text)))
        }
        BinaryOperator::And | BinaryOperator::Or => unreachable!("handled above"),
    }
}

// ============================================================================
// Datetime arithmetic (NAN-3329 / NAN-3382), mirroring the SQL generator
// ============================================================================

/// Field names that are the event time: the lean `time` column and its
/// `_time` / `timestamp` aliases, which the SQL generator resolves to it.
const EVENT_TIME_FIELDS: [&str; 3] = ["time", "_time", "timestamp"];

/// Functions whose value is a date/datetime (the SQL generator's
/// `is_datetime_function`, restricted to the ones evaluated here).
fn is_datetime_function(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "now" | "today" | "from_epoch" | "fromepoch" | "date_trunc" | "datetrunc"
    )
}

/// The datetime value of a statically datetime-typed expression: the event
/// time (or one of its aliases), a datetime function, or `<datetime> ±
/// INTERVAL`. The outer `None` means the expression is not datetime-typed;
/// `Some(None)` is a datetime-typed NULL (missing or unparseable time).
fn datetime_value(expr: &EvalExpression, row: &Row) -> Option<Option<DateTime<Utc>>> {
    match expr {
        EvalExpression::Field(name) if EVENT_TIME_FIELDS.contains(&name.as_str()) => Some(
            std::iter::once(name.as_str())
                .chain(EVENT_TIME_FIELDS)
                .find_map(|key| field_value(row, key))
                .and_then(|value| parse_time(&value)),
        ),
        EvalExpression::FunctionCall { name, args } if is_datetime_function(name) => {
            Some(evaluate_function_call(name, args, row).and_then(|value| parse_time(&value)))
        }
        EvalExpression::BinaryOp {
            left,
            op: op @ (BinaryOperator::Add | BinaryOperator::Sub),
            right,
        } => match &**right {
            EvalExpression::Literal(Value::Interval(duration, unit)) => {
                let base = datetime_value(left, row)?;
                Some(base.and_then(|dt| shift_by_interval(dt, *op, duration, unit)))
            }
            _ => None,
        },
        _ => None,
    }
}

/// `<datetime> ± INTERVAL n unit`: calendar months/years like ClickHouse,
/// fixed seconds otherwise (the interval literal carries whole seconds).
fn shift_by_interval(
    dt: DateTime<Utc>,
    op: BinaryOperator,
    duration: &std::time::Duration,
    unit: &crate::query::IntervalUnit,
) -> Option<DateTime<Utc>> {
    use crate::query::IntervalUnit;
    let seconds = duration.as_secs();
    let months = match unit {
        IntervalUnit::Month => Some(seconds / 2_592_000),
        IntervalUnit::Year => Some(seconds / 31_536_000 * 12),
        _ => None,
    };
    let add = op == BinaryOperator::Add;
    match months {
        Some(months) => {
            let months = chrono::Months::new(u32::try_from(months).ok()?);
            if add {
                dt.checked_add_months(months)
            } else {
                dt.checked_sub_months(months)
            }
        }
        None => {
            let delta = chrono::Duration::seconds(i64::try_from(seconds).ok()?);
            if add {
                dt.checked_add_signed(delta)
            } else {
                dt.checked_sub_signed(delta)
            }
        }
    }
}

fn epoch_seconds(dt: &DateTime<Utc>) -> f64 {
    dt.timestamp_millis() as f64 / 1000.0
}

/// Arithmetic and ordering with a datetime operand, or `None` when neither
/// side is datetime-typed. As in SQL: `<datetime> - <datetime>` is whole
/// elapsed seconds (floor of the millisecond difference), `<datetime> ±
/// INTERVAL` is a datetime, and any other datetime operand is epoch seconds
/// with the millisecond fraction.
fn datetime_arithmetic(
    left: &EvalExpression,
    op: BinaryOperator,
    right: &EvalExpression,
    row: &Row,
) -> Option<Option<Json>> {
    if !matches!(
        op,
        BinaryOperator::Add
            | BinaryOperator::Sub
            | BinaryOperator::Mul
            | BinaryOperator::Div
            | BinaryOperator::Mod
            | BinaryOperator::Gt
            | BinaryOperator::Lt
            | BinaryOperator::Gte
            | BinaryOperator::Lte
    ) {
        return None;
    }
    if matches!(op, BinaryOperator::Add | BinaryOperator::Sub)
        && matches!(right, EvalExpression::Literal(Value::Interval(..)))
    {
        let shifted = datetime_value(
            &EvalExpression::BinaryOp {
                left: Box::new(left.clone()),
                op,
                right: Box::new(right.clone()),
            },
            row,
        )?;
        return Some(shifted.map(|dt| Json::String(datetime_text(&dt))));
    }
    let left_dt = datetime_value(left, row);
    let right_dt = datetime_value(right, row);
    if left_dt.is_none() && right_dt.is_none() {
        return None;
    }
    if op == BinaryOperator::Sub {
        if let (Some(l), Some(r)) = (left_dt, right_dt) {
            return Some((|| {
                let millis = l?.timestamp_millis() - r?.timestamp_millis();
                Some(Json::from(millis.div_euclid(1000)))
            })());
        }
    }
    let operand = |dt: Option<Option<DateTime<Utc>>>, expr: &EvalExpression| match dt {
        Some(dt) => dt.map(|dt| epoch_seconds(&dt)),
        None => num(&evaluate_eval_expression(expr, row)?),
    };
    Some((|| {
        let (l, r) = (operand(left_dt, left)?, operand(right_dt, right)?);
        match op {
            BinaryOperator::Add => json_number(l + r),
            BinaryOperator::Sub => json_number(l - r),
            BinaryOperator::Mul => json_number(l * r),
            BinaryOperator::Div if r != 0.0 => json_number(l / r),
            BinaryOperator::Mod if r != 0.0 => json_number(l % r),
            BinaryOperator::Div | BinaryOperator::Mod => None,
            _ => Some(bool_json(compare_numbers(op, l, r))),
        }
    })())
}

fn compare_numbers(op: BinaryOperator, l: f64, r: f64) -> bool {
    match op {
        BinaryOperator::Gt => l > r,
        BinaryOperator::Lt => l < r,
        BinaryOperator::Gte => l >= r,
        _ => l <= r,
    }
}

// ============================================================================
// Time helpers
// ============================================================================

/// Parse an event timestamp the way the lake / ClickHouse lanes hand it back:
/// `YYYY-MM-DD HH:MM:SS[.ffffff]`, RFC 3339, a date, or epoch seconds /
/// milliseconds.
fn parse_time(value: &Json) -> Option<DateTime<Utc>> {
    match value {
        Json::String(s) => {
            let s = s.trim();
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                return Some(dt.with_timezone(&Utc));
            }
            for format in [
                "%Y-%m-%d %H:%M:%S%.f",
                "%Y-%m-%dT%H:%M:%S%.f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
            ] {
                if let Ok(naive) = NaiveDateTime::parse_from_str(s.trim_end_matches('Z'), format) {
                    return Some(Utc.from_utc_datetime(&naive));
                }
            }
            if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
                return Some(Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0)?));
            }
            s.parse::<f64>()
                .ok()
                .and_then(|n| parse_time(&serde_json::json!(n)))
        }
        Json::Number(n) => {
            let n = n.as_f64()?;
            let (secs, nanos) = if n.abs() >= 1e12 {
                ((n / 1000.0).floor(), ((n % 1000.0) * 1e6) as u32)
            } else {
                (n.floor(), ((n - n.floor()) * 1e9) as u32)
            };
            Utc.timestamp_opt(secs as i64, nanos).single()
        }
        _ => None,
    }
}

fn datetime_text(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn date_text(date: NaiveDate) -> String {
    date.format("%Y-%m-%d").to_string()
}

/// ClickHouse `toWeek(x)` (mode 0): Sunday-first, days before the first
/// Sunday are week 0.
fn week_mode0(dt: &DateTime<Utc>) -> u32 {
    dt.format("%U").to_string().parse().unwrap_or(0)
}

/// `strftime`-style formatting with the SQL generator's accepted codes.
/// `None` for a format chrono cannot render (never panics).
fn strftime(dt: &DateTime<Utc>, format: &str) -> Option<String> {
    use chrono::format::{Item, StrftimeItems};
    let items = StrftimeItems::new(format).collect::<Vec<_>>();
    if items.iter().any(|item| matches!(item, Item::Error)) {
        return None;
    }
    let mut out = String::new();
    use std::fmt::Write;
    write!(out, "{}", dt.format_with_items(items.into_iter())).ok()?;
    Some(out)
}

fn start_of(unit: &str, dt: &DateTime<Utc>) -> Option<String> {
    let date = dt.date_naive();
    Some(match unit {
        "second" => format!("{}.000000", datetime_text(dt)),
        "minute" => format!("{}:00", dt.format("%Y-%m-%d %H:%M")),
        "hour" => format!("{}:00:00", dt.format("%Y-%m-%d %H")),
        "day" => format!("{} 00:00:00", date_text(date)),
        "week" => {
            date_text(date - chrono::Duration::days(dt.weekday().num_days_from_sunday() as i64))
        }
        "month" => date_text(NaiveDate::from_ymd_opt(dt.year(), dt.month(), 1)?),
        "quarter" => date_text(NaiveDate::from_ymd_opt(
            dt.year(),
            (dt.month() - 1) / 3 * 3 + 1,
            1,
        )?),
        "year" => date_text(NaiveDate::from_ymd_opt(dt.year(), 1, 1)?),
        _ => return None,
    })
}

/// ClickHouse `dateDiff(unit, start, end)`: the number of unit boundaries
/// crossed between the two instants.
fn date_diff(unit: &str, start: &DateTime<Utc>, end: &DateTime<Utc>) -> Option<i64> {
    let months = |dt: &DateTime<Utc>| dt.year() as i64 * 12 + dt.month0() as i64;
    let day_number = |dt: &DateTime<Utc>| dt.date_naive().num_days_from_ce() as i64;
    Some(match unit {
        "second" | "seconds" | "ss" | "s" => end.timestamp() - start.timestamp(),
        "minute" | "minutes" | "mi" | "n" => {
            end.timestamp().div_euclid(60) - start.timestamp().div_euclid(60)
        }
        "hour" | "hours" | "hh" | "h" => {
            end.timestamp().div_euclid(3600) - start.timestamp().div_euclid(3600)
        }
        "day" | "days" | "dd" | "d" => day_number(end) - day_number(start),
        "week" | "weeks" | "wk" | "ww" => {
            // Monday-based week boundaries (toRelativeWeekNum).
            let week = |dt: &DateTime<Utc>| (day_number(dt) + 6).div_euclid(7);
            week(end) - week(start)
        }
        "month" | "months" | "mm" | "m" => months(end) - months(start),
        "quarter" | "quarters" | "qq" | "q" => {
            months(end).div_euclid(3) - months(start).div_euclid(3)
        }
        "year" | "years" | "yyyy" | "yy" => end.year() as i64 - start.year() as i64,
        _ => return None,
    })
}

// ============================================================================
// IP / URL helpers
// ============================================================================

fn parse_ip(value: &Json) -> Option<std::net::IpAddr> {
    ch_string(value)?.trim().parse().ok()
}

fn ip_in_cidr(ip: std::net::IpAddr, cidr: &str) -> bool {
    use std::net::IpAddr;
    let Some((network, bits)) = cidr.trim().split_once('/') else {
        return cidr
            .trim()
            .parse::<IpAddr>()
            .is_ok_and(|single| single == ip);
    };
    let (Ok(network), Ok(bits)) = (network.parse::<IpAddr>(), bits.parse::<u32>()) else {
        return false;
    };
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) if bits <= 32 => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) if bits <= 128 => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

const PRIVATE_V4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// ClickHouse `domain(url)`: host without scheme, user info or port.
fn url_domain(url: &str) -> String {
    let rest = match url.find("://") {
        Some(index)
            if url[..index]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c)) =>
        {
            &url[index + 3..]
        }
        _ => url.strip_prefix("//").unwrap_or(url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    if host.starts_with('[') {
        return host
            .split(']')
            .next()
            .map(|h| format!("{h}]"))
            .unwrap_or_default();
    }
    host.split(':').next().unwrap_or("").to_string()
}

/// The part of a URL after its authority (`/path?query#fragment`).
fn url_after_authority(url: &str) -> &str {
    let rest = match url.find("://") {
        Some(index) => &url[index + 3..],
        None => url.strip_prefix("//").unwrap_or(url),
    };
    match rest.find(['/', '?', '#']) {
        Some(index) => &rest[index..],
        None => "",
    }
}

fn shannon_entropy(text: &str) -> f64 {
    let chars = text.chars().filter(|c| *c != '\n').collect::<Vec<_>>();
    if chars.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in &chars {
        *counts.entry(*c).or_insert(0usize) += 1;
    }
    let total = chars.len() as f64;
    counts
        .values()
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn byte_levenshtein(a: &[u8], b: &[u8]) -> usize {
    let mut previous = (0..=b.len()).collect::<Vec<_>>();
    for (i, ca) in a.iter().enumerate() {
        let mut current = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            current[j + 1] = (previous[j] + cost)
                .min(previous[j + 1] + 1)
                .min(current[j] + 1);
        }
        previous = current;
    }
    previous[b.len()]
}

/// ClickHouse replacement syntax (`\1`, `\\`) to the regex crate's (`${1}`).
fn ch_replacement(replacement: &str) -> String {
    let mut out = String::new();
    let mut chars = replacement.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(d) if d.is_ascii_digit() => out.push_str(&format!("${{{d}}}")),
                Some(other) => out.push(other),
                None => out.push('\\'),
            },
            '$' => out.push_str("$$"),
            other => out.push(other),
        }
    }
    out
}

/// ClickHouse `extract(s, re)`: the first capture group when the pattern has
/// one, else the whole match; `''` when nothing matches.
fn regex_extract_first(text: &str, regex: &regex::Regex) -> String {
    regex
        .captures(text)
        .and_then(|caps| caps.get(if regex.captures_len() > 1 { 1 } else { 0 }))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default()
}

// ============================================================================
// Functions
// ============================================================================

fn evaluate_function_call(name: &str, args: &[EvalExpression], row: &Row) -> Option<Json> {
    let arg = |index: usize| {
        args.get(index)
            .and_then(|a| evaluate_eval_expression(a, row))
    };
    let text = |index: usize| arg(index).as_ref().and_then(ch_string);
    let number = |index: usize| arg(index).as_ref().and_then(num);
    let time = |index: usize| arg(index).as_ref().and_then(parse_time);
    let string = |s: String| Some(Json::String(s));

    match name.to_lowercase().as_str() {
        // ---------------------------------------------------------- strings
        "lower" | "tolower" => string(text(0)?.to_lowercase()),
        "upper" | "toupper" => string(text(0)?.to_uppercase()),
        "len" | "length" | "array_length" | "arraylength" | "mvcount" => match arg(0)? {
            Json::Array(items) => json_number(items.len() as f64),
            other => json_number(ch_string(&other)?.len() as f64),
        },
        "trim" => string(text(0)?.trim_matches(' ').to_string()),
        "ltrim" => string(text(0)?.trim_start_matches(' ').to_string()),
        "rtrim" => string(text(0)?.trim_end_matches(' ').to_string()),
        "reverse" => string(text(0)?.chars().rev().collect()),
        "substr" | "substring" => {
            let s = text(0)?;
            let start = number(1)?.max(0.0) as usize;
            let tail = s.chars().skip(start);
            if args.len() >= 3 {
                string(tail.take(number(2)?.max(0.0) as usize).collect())
            } else {
                string(tail.collect())
            }
        }
        "replace" => {
            let (s, from, to) = (text(0)?, text(1)?, text(2)?);
            if from.is_empty() {
                return string(s);
            }
            string(s.replace(&from, &to))
        }
        // ClickHouse `concat` is NULL when any argument is NULL.
        "concat" => {
            let mut out = String::new();
            for index in 0..args.len() {
                out.push_str(&text(index)?);
            }
            string(out)
        }
        // `split(NULL, d)` is `[]` (ClickHouse cannot hold a NULL array).
        "split" => {
            let Some(s) = text(0) else {
                return Some(Json::Array(Vec::new()));
            };
            let delimiter = text(1)?;
            let parts: Vec<Json> = if delimiter.is_empty() {
                s.chars().map(|c| Json::String(c.to_string())).collect()
            } else {
                s.split(delimiter.as_str())
                    .map(|p| Json::String(p.to_string()))
                    .collect()
            };
            Some(Json::Array(parts))
        }

        // --------------------------------------------------------- encoding
        "base64_encode" | "base64encode" => {
            use base64::Engine;
            string(base64::engine::general_purpose::STANDARD.encode(text(0)?.as_bytes()))
        }
        "base64_decode" | "base64decode" => {
            use base64::Engine;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(text(0)?)
                .ok()?;
            string(String::from_utf8_lossy(&decoded).into_owned())
        }
        "hex_encode" | "hexencode" | "tohex" => string(hex::encode_upper(text(0)?.as_bytes())),
        "hex_decode" | "hexdecode" | "fromhex" => {
            let decoded = hex::decode(text(0)?).ok()?;
            string(String::from_utf8_lossy(&decoded).into_owned())
        }
        "url_encode" | "urlencode" => string(urlencoding::encode(&text(0)?).into_owned()),
        "url_decode" | "urldecode" => string(urlencoding::decode(&text(0)?).ok()?.into_owned()),

        // ---------------------------------------------------------- hashing
        "md5" => {
            use md5::{Digest, Md5};
            string(hex::encode(Md5::digest(text(0)?.as_bytes())))
        }
        "sha1" => {
            use sha1::{Digest, Sha1};
            string(hex::encode(Sha1::digest(text(0)?.as_bytes())))
        }
        "sha256" => {
            use sha2::{Digest, Sha256};
            string(hex::encode(Sha256::digest(text(0)?.as_bytes())))
        }

        // --------------------------------------------------------------- IP
        // IP predicates are false (never NULL, never an error) for a missing
        // or non-IP value, exactly like the SQL lowering.
        "is_private_ip" | "isprivateip" | "is_rfc1918" => {
            Some(bool_json(arg(0).as_ref().and_then(parse_ip).is_some_and(
                |ip| PRIVATE_V4.iter().any(|cidr| ip_in_cidr(ip, cidr)),
            )))
        }
        "is_public_ip" | "ispublicip" => Some(bool_json(
            arg(0).as_ref().and_then(parse_ip).is_some_and(|ip| {
                !PRIVATE_V4
                    .iter()
                    .chain(["127.0.0.0/8"].iter())
                    .any(|cidr| ip_in_cidr(ip, cidr))
            }),
        )),
        "is_loopback" | "isloopback" => Some(bool_json(
            arg(0)
                .as_ref()
                .and_then(parse_ip)
                .is_some_and(|ip| ip_in_cidr(ip, "127.0.0.0/8")),
        )),
        "cidr_match" | "cidrmatch" => {
            if args.len() < 2 {
                return None;
            }
            let values = (0..args.len()).map(text).collect::<Vec<_>>();
            let (ip, cidrs): (Option<String>, Vec<Option<String>>) = if args.len() == 2
                && values[0].as_deref().is_some_and(|v| v.contains('/'))
                && !values[1].as_deref().is_some_and(|v| v.contains('/'))
            {
                (values[1].clone(), vec![values[0].clone()])
            } else {
                (values[0].clone(), values[1..].to_vec())
            };
            let ip = ip.and_then(|ip| ip.trim().parse::<std::net::IpAddr>().ok());
            Some(bool_json(ip.is_some_and(|ip| {
                cidrs.iter().flatten().any(|cidr| ip_in_cidr(ip, cidr))
            })))
        }
        "ipv4_to_int" | "ip_to_int" => json_number(
            text(0)?
                .trim()
                .parse::<std::net::Ipv4Addr>()
                .map(u32::from)
                .unwrap_or(0) as f64,
        ),
        "int_to_ipv4" | "int_to_ip" => {
            string(std::net::Ipv4Addr::from(number(0)? as u32).to_string())
        }
        "ip_version" => json_number(match text(0)?.trim().parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(_)) => 4.0,
            Ok(std::net::IpAddr::V6(_)) => 6.0,
            Err(_) => 0.0,
        }),

        // ------------------------------------------------------ URL / domain
        "extract_domain" | "extractdomain" => string(url_domain(&text(0)?)),
        "extract_tld" | "extracttld" => {
            let domain = url_domain(&text(0)?);
            string(domain.rsplit('.').next().unwrap_or("").to_string())
        }
        "extract_path" | "extractpath" => {
            let url = text(0)?;
            let after = url_after_authority(&url);
            string(after.split(['?', '#']).next().unwrap_or("").to_string())
        }
        "extract_protocol" | "extractprotocol" => {
            let url = text(0)?;
            string(match url.find("://") {
                Some(index) => url[..index].to_string(),
                None => String::new(),
            })
        }
        "extract_query_string" | "extractquerystring" => {
            let url = text(0)?;
            let after = url_after_authority(&url);
            string(match after.split_once('?') {
                Some((_, query)) => query.split('#').next().unwrap_or("").to_string(),
                None => String::new(),
            })
        }
        "domain_depth" | "subdomain_count" => {
            let domain = url_domain(&text(0)?);
            let domain = domain.strip_prefix("www.").unwrap_or(&domain);
            json_number(domain.split('.').count() as f64)
        }

        // --------------------------------------------------------- security
        "defang" => string(
            text(0)?
                .replace("http", "hxxp")
                .replace('.', "[.]")
                .replace("://", "[://]"),
        ),
        "refang" => string(
            text(0)?
                .replace("hxxp", "http")
                .replace("[.]", ".")
                .replace("[://]", "://"),
        ),
        "entropy" => json_number(shannon_entropy(&text(0)?)),

        // ------------------------------------------------------------- time
        "now" => string(datetime_text(&Utc::now())),
        "today" => string(date_text(Utc::now().date_naive())),
        "yesterday" => string(date_text(
            Utc::now().date_naive() - chrono::Duration::days(1),
        )),
        "strftime" | "to_char" => string(strftime(&time(0)?, &text(1)?)?),
        "epoch" | "to_epoch" => json_number(time(0)?.timestamp() as f64),
        "from_epoch" | "fromepoch" => string(datetime_text(
            &Utc.timestamp_opt(number(0)? as i64, 0).single()?,
        )),
        "year" => json_number(time(0)?.year() as f64),
        "month" => json_number(time(0)?.month() as f64),
        "day" | "dayofmonth" => json_number(time(0)?.day() as f64),
        "hour" => json_number(time(0)?.hour() as f64),
        "minute" => json_number(time(0)?.minute() as f64),
        "second" => json_number(time(0)?.second() as f64),
        "dayofweek" | "dow" => json_number(time(0)?.weekday().number_from_monday() as f64),
        "dayofyear" | "doy" => json_number(time(0)?.ordinal() as f64),
        "week" | "weekofyear" => json_number(week_mode0(&time(0)?) as f64),
        "quarter" => json_number(((time(0)?.month() - 1) / 3 + 1) as f64),
        "date_part" | "datepart" => {
            let EvalExpression::Literal(Value::String(part)) = args.first()? else {
                return None;
            };
            let dt = time(1)?;
            json_number(match part.to_lowercase().as_str() {
                "hour" => dt.hour() as f64,
                "minute" => dt.minute() as f64,
                "second" => dt.second() as f64,
                "day" => dt.day() as f64,
                "month" => dt.month() as f64,
                "year" => dt.year() as f64,
                "week" => dt.iso_week().week() as f64,
                "dayofweek" => dt.weekday().number_from_monday() as f64,
                "dayofyear" => dt.ordinal() as f64,
                _ => return None,
            })
        }
        "date_diff" | "datediff" => match args.len() {
            2 => json_number(date_diff("second", &time(1)?, &time(0)?)? as f64),
            3 => json_number(date_diff(&text(0)?.to_lowercase(), &time(1)?, &time(2)?)? as f64),
            _ => None,
        },
        "age" => match args.len() {
            1 => json_number(date_diff("second", &time(0)?, &Utc::now())? as f64),
            2 => json_number(date_diff("second", &time(1)?, &time(0)?)? as f64),
            _ => None,
        },
        "date_trunc" | "datetrunc" => string(start_of(&text(0)?.to_lowercase(), &time(1)?)?),
        "start_of_hour" | "startofhour" => string(start_of("hour", &time(0)?)?),
        "start_of_day" | "startofday" => string(start_of("day", &time(0)?)?),
        "start_of_week" | "startofweek" => string(start_of("week", &time(0)?)?),
        "start_of_month" | "startofmonth" => string(start_of("month", &time(0)?)?),
        "start_of_quarter" | "startofquarter" => string(start_of("quarter", &time(0)?)?),
        "start_of_year" | "startofyear" => string(start_of("year", &time(0)?)?),
        "earliest" | "latest" => {
            let times = (0..args.len())
                .filter_map(|index| arg(index))
                .filter_map(|value| parse_time(&value).map(|dt| (dt, value)))
                .collect::<Vec<_>>();
            let pick = if name.eq_ignore_ascii_case("earliest") {
                times.into_iter().min_by_key(|(dt, _)| *dt)
            } else {
                times.into_iter().max_by_key(|(dt, _)| *dt)
            };
            pick.map(|(_, value)| value)
        }

        // ------------------------------------------------------- conversion
        // `toFloat64OrZero(toString(x))`: unparseable text is 0, NULL stays NULL.
        "tonumber" | "to_number" => {
            let value = arg(0)?;
            json_number(num(&value).unwrap_or(0.0))
        }
        "tostring" | "to_string" => match text(1) {
            Some(format) if format.contains('%') => string(strftime(&time(0)?, &format)?),
            _ => string(text(0)?),
        },
        // `toInt64OrZero(x)`.
        "toint" | "to_int" => json_number(match arg(0)? {
            Json::String(s) => s.trim().parse::<i64>().unwrap_or(0) as f64,
            other => num(&other)?.trunc(),
        }),
        // `toInt64OrNull(toString(x))`.
        "tolong" => json_number(text(0)?.trim().parse::<i64>().ok()? as f64),
        "exact" => arg(0),

        // ------------------------------------------------------ conditional
        // `in(x, a, b)` / `x IN (a, b)`: string members compare
        // case-insensitively, numbers as numbers; an array subject matches
        // when any element is a member.
        "in" => {
            let subject = arg(0)?;
            let members = (1..args.len())
                .filter_map(|index| arg(index))
                .collect::<Vec<_>>();
            let is_member = |value: &Json| {
                members.iter().any(|member| match (member, value) {
                    (Json::Number(_), _) => {
                        num(value).zip(num(member)).is_some_and(|(l, r)| l == r)
                    }
                    _ => match (ch_string(value), ch_string(member)) {
                        (Some(l), Some(r)) => l.to_lowercase() == r.to_lowercase(),
                        _ => false,
                    },
                })
            };
            Some(bool_json(match &subject {
                Json::Array(items) => items.iter().any(is_member),
                other => is_member(other),
            }))
        }
        // `NOT <predicate>` / `not(x)`: a NULL predicate is not satisfied, so
        // its negation is true (search `NOT` semantics).
        "not" => Some(bool_json(!truth(arg(0).as_ref()).unwrap_or(false))),
        "null" => None,
        "true" => json_number(1.0),
        "false" => json_number(0.0),
        // `match(x, re)` is the explicit, case-SENSITIVE regex (as in SQL).
        "match" | "regex_match" => {
            let regex = bounded_regex(&text(1)?)?;
            Some(bool_json(regex.is_match(&text(0)?)))
        }
        "like" => {
            let regex = ilike_regex(&text(1)?)?;
            Some(bool_json(regex.is_match(&text(0)?)))
        }
        "coalesce" | "nvl" => (0..args.len()).find_map(|index| arg(index)),
        "nullif" => {
            let (value, other) = (arg(0)?, arg(1));
            match other {
                Some(other) if scalar_equal(&value, &other, false) => None,
                _ => Some(value),
            }
        }
        // ClickHouse `if(NULL, a, b)` is `b`.
        "if" | "iif" => {
            if args.len() != 3 {
                return None;
            }
            if truth(arg(0).as_ref()).unwrap_or(false) {
                arg(1)
            } else {
                arg(2)
            }
        }
        "case" => {
            if args.is_empty() {
                return None;
            }
            let pair_end = args.len() - (args.len() % 2);
            for index in (0..pair_end).step_by(2) {
                if truth(arg(index).as_ref()).unwrap_or(false) {
                    return arg(index + 1);
                }
            }
            if args.len() % 2 == 1 {
                arg(args.len() - 1)
            } else {
                None
            }
        }
        "isnull" | "is_null" => Some(bool_json(arg(0).is_none())),
        "isnotnull" | "is_not_null" => Some(bool_json(arg(0).is_some())),

        // ------------------------------------------------------------- math
        // `least`/`greatest` ignore NULL arguments (ClickHouse 26).
        "min" | "max" => {
            let values = (0..args.len())
                .filter_map(|index| arg(index))
                .collect::<Vec<_>>();
            let is_min = name.eq_ignore_ascii_case("min");
            let mut best: Option<Json> = None;
            for candidate in values {
                best = Some(match best {
                    None => candidate,
                    Some(current) => {
                        let ordering = match (num(&current), num(&candidate)) {
                            (Some(l), Some(r)) => l.partial_cmp(&r)?,
                            _ => ch_string(&current)?.cmp(&ch_string(&candidate)?),
                        };
                        let take = if is_min {
                            ordering.is_gt()
                        } else {
                            ordering.is_lt()
                        };
                        if take {
                            candidate
                        } else {
                            current
                        }
                    }
                });
            }
            best
        }
        "abs" => json_number(number(0)?.abs()),
        "ceil" | "ceiling" => json_number(number(0)?.ceil()),
        "floor" => json_number(number(0)?.floor()),
        // ClickHouse rounds floats half to even.
        "round" => {
            let n = number(0)?;
            if args.len() >= 2 {
                let factor = 10_f64.powi(number(1)? as i32);
                json_number((n * factor).round_ties_even() / factor)
            } else {
                json_number(n.round_ties_even())
            }
        }
        "sqrt" => json_number(number(0)?.sqrt()),
        "pow" | "power" => json_number(number(0)?.powf(number(1)?)),
        "log" | "ln" => json_number(number(0)?.ln()),
        "log10" => json_number(number(0)?.log10()),

        // ------------------------------------------------------------ regex
        "regex_extract" | "extract_regex" | "extract" => {
            let (s, regex) = (text(0)?, bounded_regex(&text(1)?)?);
            if args.len() >= 3 {
                let group = number(2)? as usize;
                let value = regex
                    .captures(&s)
                    .and_then(|caps| if group == 0 { None } else { caps.get(group) })
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();
                string(value)
            } else {
                string(regex_extract_first(&s, &regex))
            }
        }
        "regex_replace" => {
            let (s, regex, replacement) = (text(0)?, bounded_regex(&text(1)?)?, text(2)?);
            string(
                regex
                    .replace(&s, ch_replacement(&replacement).as_str())
                    .into_owned(),
            )
        }
        "regex_replace_all" => {
            let (s, regex, replacement) = (text(0)?, bounded_regex(&text(1)?)?, text(2)?);
            string(
                regex
                    .replace_all(&s, ch_replacement(&replacement).as_str())
                    .into_owned(),
            )
        }

        // ------------------------------------------------------- similarity
        "levenshtein" | "levenshtein_distance" | "edit_distance" => {
            json_number(byte_levenshtein(text(0)?.as_bytes(), text(1)?.as_bytes()) as f64)
        }
        "levenshtein_normalized" | "edit_distance_normalized" => {
            let (a, b) = (text(0)?, text(1)?);
            let distance = byte_levenshtein(a.as_bytes(), b.as_bytes()) as f64;
            json_number(distance / a.len().max(b.len()).max(1) as f64)
        }

        // ----------------------------------------------------------- arrays
        "array_join" | "arrayjoin" | "mvjoin" => {
            let Json::Array(items) = arg(0)? else {
                return None;
            };
            let separator = if args.len() >= 2 {
                text(1)?
            } else {
                ",".to_string()
            };
            string(
                items
                    .iter()
                    .filter_map(ch_string)
                    .collect::<Vec<_>>()
                    .join(&separator),
            )
        }
        "array_contains" | "arraycontains" | "has" => match arg(0)? {
            Json::Array(items) => {
                let needle = text(1)?.to_lowercase();
                Some(bool_json(items.iter().any(|item| {
                    ch_string(item).unwrap_or_default().to_lowercase() == needle
                })))
            }
            // A string-backed field: `positionCaseInsensitive(toString(a), b)`.
            other => {
                let haystack = ch_string(&other)?.to_lowercase();
                let needle = text(1)?.to_lowercase();
                json_number(haystack.find(&needle).map_or(0, |index| index + 1) as f64)
            }
        },
        "mvfind" => {
            let Json::Array(items) = arg(0)? else {
                return None;
            };
            let regex = bounded_regex(&text(1)?)?;
            json_number(
                items
                    .iter()
                    .position(|item| ch_string(item).is_some_and(|t| regex.is_match(&t)))
                    .map_or(0, |index| index + 1) as f64,
            )
        }
        "mvindex" => {
            let Json::Array(items) = arg(0)? else {
                return None;
            };
            let position = number(1)? as i64 + 1;
            let len = items.len() as i64;
            let index = if position > 0 {
                position - 1
            } else {
                len + position
            };
            match (position != 0 && index >= 0 && index < len, items.first()) {
                (true, _) => Some(items[index as usize].clone()),
                (false, Some(Json::Number(_))) => json_number(0.0),
                (false, _) => string(String::new()),
            }
        }
        "mvdedup" => {
            let Json::Array(items) = arg(0)? else {
                return None;
            };
            let mut seen = Vec::new();
            for item in items {
                if !seen.contains(&item) {
                    seen.push(item);
                }
            }
            Some(Json::Array(seen))
        }
        "mvsort" => {
            let Json::Array(mut items) = arg(0)? else {
                return None;
            };
            items.sort_by(|a, b| match (a, b) {
                (Json::Number(_), Json::Number(_)) => num(a)
                    .partial_cmp(&num(b))
                    .unwrap_or(std::cmp::Ordering::Equal),
                _ => ch_string(a).cmp(&ch_string(b)),
            });
            Some(Json::Array(items))
        }
        "mvappend" => Some(Json::Array(
            (0..args.len()).filter_map(|index| arg(index)).collect(),
        )),
        "mvzip" => {
            let (Json::Array(left), Json::Array(right)) = (arg(0)?, arg(1)?) else {
                return None;
            };
            if left.len() != right.len() {
                return None;
            }
            let delimiter = if args.len() > 2 {
                text(2)?
            } else {
                ",".to_string()
            };
            Some(Json::Array(
                left.iter()
                    .zip(&right)
                    .map(|(l, r)| {
                        Json::String(format!(
                            "{}{}{}",
                            ch_string(l).unwrap_or_default(),
                            delimiter,
                            ch_string(r).unwrap_or_default()
                        ))
                    })
                    .collect(),
            ))
        }
        "mvrange" => {
            let (start, end) = (number(0)? as i64, number(1)? as i64);
            let step = if args.len() > 2 { number(2)? as i64 } else { 1 };
            if step <= 0 || end.saturating_sub(start) > 1_000_000 {
                return None;
            }
            Some(Json::Array(
                (start..end)
                    .step_by(step as usize)
                    .filter_map(|n| json_number(n as f64))
                    .collect(),
            ))
        }

        _ => None,
    }
}

#[cfg(test)]
mod nan2331_scalar_min_max_tests {
    use super::*;

    #[test]
    fn evaluates_case_insensitive_scalar_min_max() {
        let row = serde_json::Map::new();
        let expression = EvalExpression::FunctionCall {
            name: "MAX".to_string(),
            args: vec![
                EvalExpression::Literal(Value::Number(1.0)),
                EvalExpression::Literal(Value::Number(3.0)),
                EvalExpression::Literal(Value::Number(2.0)),
            ],
        };

        assert_eq!(
            evaluate_eval_expression(&expression, &row),
            Some(serde_json::json!(3.0))
        );
    }
}

#[cfg(test)]
mod lake_count_pipeline_eval_tests {
    use super::*;

    #[test]
    fn evaluates_case_pairs_and_default_over_aggregate_rows() {
        let row = serde_json::json!({"events": 120})
            .as_object()
            .unwrap()
            .clone();
        let expression = EvalExpression::FunctionCall {
            name: "case".to_string(),
            args: vec![
                EvalExpression::BinaryOp {
                    left: Box::new(EvalExpression::Field("events".to_string())),
                    op: BinaryOperator::Gt,
                    right: Box::new(EvalExpression::Literal(Value::Number(100.0))),
                },
                EvalExpression::Literal(Value::String("hi".to_string())),
                EvalExpression::Literal(Value::Bool(true)),
                EvalExpression::Literal(Value::String("lo".to_string())),
            ],
        };

        assert_eq!(
            evaluate_eval_expression(&expression, &row),
            Some(serde_json::json!("hi"))
        );
    }
}

#[cfg(test)]
mod nan3041_eval_parity_tests {
    use super::*;
    use crate::query::{parse_query, Command, Query};

    fn eval_expr(npl: &str) -> EvalExpression {
        match parse_query(npl).unwrap() {
            Query::Piped {
                command: Command::Eval { mut assignments },
                ..
            } => assignments.remove(0).expression,
            other => panic!("expected eval, got {other:?}"),
        }
    }

    fn eval(npl: &str, row: serde_json::Value) -> Option<serde_json::Value> {
        evaluate_eval_expression(&eval_expr(npl), row.as_object().unwrap())
    }

    #[test]
    fn regex_literal_in_and_not_evaluate_like_sql() {
        let row = serde_json::json!({"p": "MicrosoftEdgeUpdate.exe", "port": 443});
        assert_eq!(
            eval(r#"* | eval x=if(p=/edge.*update/i, 1, 0)"#, row.clone()),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(p=/EDGE/, 1, 0)"#, row.clone()),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(p!=/edge/, 1, 0)"#, row.clone()),
            Some(serde_json::json!(0.0))
        );
        assert_eq!(
            eval(
                r#"* | eval x=if(p CONTAINS "EDGEUPDATE", 1, 0)"#,
                row.clone()
            ),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(
                r#"* | eval x=if(p IN ("microsoftedgeupdate.exe", "b"), 1, 0)"#,
                row.clone()
            ),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(in(port, 80, 443), 1, 0)"#, row.clone()),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(p NOT IN ("a"), 1, 0)"#, row.clone()),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(
                r#"* | eval x=if(NOT p="MicrosoftEdgeUpdate.exe", 1, 0)"#,
                row.clone()
            ),
            Some(serde_json::json!(0.0))
        );
        assert_eq!(
            eval(
                r#"* | eval x=if(p="MICROSOFTEDGEUPDATE.EXE", 1, 0)"#,
                row.clone()
            ),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(
                r#"* | eval x=if(p!="microsoftedgeupdate.exe", 1, 0)"#,
                row.clone()
            ),
            Some(serde_json::json!(0.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(port="443", 1, 0)"#, row.clone()),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(like(p, "%edge%"), 1, 0)"#, row.clone()),
            Some(serde_json::json!(1.0))
        );
        assert_eq!(
            eval(r#"* | eval x=if(match(p, "edge"), 1, 0)"#, row.clone()),
            Some(serde_json::json!(0.0))
        );
        // ClickHouse `if(NULL, 1, 0)` is 0: a missing field's predicate is
        // NULL, and a NULL condition takes the else branch.
        assert_eq!(
            eval(r#"* | eval x=if(missing IN ("a"), 1, 0)"#, row),
            Some(serde_json::json!(0.0))
        );
    }
}

/// NAN-3382: after a Nano-side stage (`| prevalence`, lookup, identity, ai)
/// eval runs here, and `now() - time` was NULL: both operands are datetime
/// text, which `toFloat64OrNull` semantics read as NULL. The SQL generator
/// reads a datetime operand of arithmetic as epoch seconds (NAN-3329) and a
/// datetime minus a datetime as whole elapsed seconds; this evaluator must
/// agree.
#[cfg(test)]
mod nan3382_datetime_arithmetic_tests {
    use super::*;
    use crate::query::{parse_query, Command, Query};

    fn eval(npl: &str, row: serde_json::Value) -> Option<Json> {
        let expression = match parse_query(npl).unwrap() {
            Query::Piped {
                command: Command::Eval { mut assignments },
                ..
            } => assignments.remove(0).expression,
            other => panic!("expected eval, got {other:?}"),
        };
        evaluate_eval_expression(&expression, row.as_object().unwrap())
    }

    fn lean_time(dt: DateTime<Utc>) -> String {
        dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    }

    fn whole_seconds(value: Option<Json>) -> i64 {
        let value = value.expect("age must not be NULL");
        assert!(value.is_i64(), "age must be integer seconds, got {value}");
        value.as_i64().unwrap()
    }

    #[test]
    fn now_minus_event_time_is_whole_seconds() {
        // `now()` is whole seconds (ClickHouse DateTime), the event 100.5 s
        // old with millisecond precision: floor(100.5 - fraction) is 99 or
        // 100, plus one if the clock ticks between here and the evaluator.
        let event = Utc::now() - chrono::Duration::milliseconds(100_500);
        for (npl, key) in [
            ("* | eval age=now()-time", "time"),
            ("* | eval age=now() - _time", "time"),
            ("* | eval age=now()-timestamp", "time"),
            ("* | eval age=now()-timestamp", "timestamp"),
            ("* | eval age=now()-_time", "_time"),
        ] {
            let age = whole_seconds(eval(npl, serde_json::json!({ key: lean_time(event) })));
            assert!((99..=101).contains(&age), "{npl} on {key}: {age}");
        }
    }

    #[test]
    fn datetime_minus_datetime_is_whole_seconds() {
        let row = serde_json::json!({"time": "2026-09-27 05:04:03.250000"});
        assert_eq!(
            whole_seconds(eval("* | eval d=time - time", row.clone())),
            0
        );
        assert_eq!(
            whole_seconds(eval(
                "* | eval d=time - (time - INTERVAL 1 HOUR)",
                row.clone()
            )),
            3600
        );
        // `<datetime> - INTERVAL` alone stays a datetime, as in SQL.
        assert_eq!(
            eval("* | eval t=time - INTERVAL 1 HOUR", row),
            Some(serde_json::json!("2026-09-27 04:04:03"))
        );
    }

    #[test]
    fn datetime_minus_number_is_epoch_seconds() {
        let row = serde_json::json!({"time": "2026-09-27 05:04:03.250000"});
        let epoch = Utc
            .with_ymd_and_hms(2026, 9, 27, 5, 4, 3)
            .unwrap()
            .timestamp() as f64
            + 0.25;
        let d = eval("* | eval d=time - 1000", row).expect("time - 1000 must not be NULL");
        assert_eq!(d.as_f64(), Some(epoch - 1000.0), "{d}");
    }

    #[test]
    fn event_time_compares_with_now_minus_interval() {
        let recent =
            serde_json::json!({ "time": lean_time(Utc::now() - chrono::Duration::minutes(5)) });
        let old = serde_json::json!({ "time": lean_time(Utc::now() - chrono::Duration::hours(2)) });
        let npl = "* | eval recent=if(time > now() - INTERVAL 1 HOUR, 1, 0)";
        assert_eq!(eval(npl, recent).and_then(|v| v.as_f64()), Some(1.0));
        assert_eq!(eval(npl, old).and_then(|v| v.as_f64()), Some(0.0));
    }

    #[test]
    fn a_missing_event_time_stays_null() {
        assert_eq!(
            eval("* | eval age=now()-time", serde_json::json!({"x": 1})),
            None
        );
    }
}
