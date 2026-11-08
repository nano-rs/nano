// SPDX-License-Identifier: AGPL-3.0-or-later

//! Expression evaluation for post-processing
//!
//! This module provides eval expression evaluation functions including:
//! - Binary operations (arithmetic, comparison, logical)
//! - Function calls (string, encoding, hashing, IP/network, domain/URL, security, conditional, math, type conversion)

use crate::query::{BinaryOperator, EvalExpression, Value};

/// Evaluate an eval expression on a row
///
/// # Arguments
/// * `expr` - The expression to evaluate
/// * `row` - The row data to evaluate against
///
/// # Returns
/// * `Some(serde_json::Value)` - The evaluated value
/// * `None` - If evaluation fails or produces null
pub fn evaluate_eval_expression(
    expr: &EvalExpression,
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    // NAN-4917: guarded recursion point (cheap stack-pointer check per node).
    crate::query::complexity::ensure_sufficient_stack(|| evaluate_eval_expression_unguarded(expr, row))
}

fn evaluate_eval_expression_unguarded(
    expr: &EvalExpression,
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    match expr {
        EvalExpression::Field(name) => row.get(name).cloned(),
        EvalExpression::Literal(val) => Some(match val {
            Value::String(s) => serde_json::Value::String(s.clone()),
            Value::Number(n) => serde_json::json!(n),
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Regex(r) => serde_json::Value::String(r.clone()),
            Value::Ip(ip) => serde_json::Value::String(ip.to_string()),
            Value::Interval(duration, unit) => {
                // Convert interval to a string representation
                serde_json::Value::String(format!(
                    "INTERVAL {} {}",
                    duration.as_secs(),
                    unit.as_str().to_uppercase()
                ))
            }
        }),
        EvalExpression::BinaryOp { left, op, right } => {
            if let Some(result) = array_predicate(left, op, right, row) {
                return result;
            }
            if let Some(result) = literal_predicate(left, op, right, row) {
                return result;
            }
            let left_val = evaluate_eval_expression(left, row);
            let right_val = evaluate_eval_expression(right, row);
            if matches!(op, BinaryOperator::And | BinaryOperator::Or) {
                return sql_logic(op, sql_truth(left_val.as_ref()), sql_truth(right_val.as_ref()))
                    .map(serde_json::Value::Bool);
            }
            // Every other operator propagates NULL, as in ClickHouse.
            let left_val = left_val.filter(|v| !v.is_null())?;
            let right_val = right_val.filter(|v| !v.is_null())?;
            // NAN-3329: a datetime operand of arithmetic or an ordering
            // comparison is epoch seconds, as in the SQL generator, and
            // `<datetime> - <datetime>` is whole seconds. `now()` and the time
            // column are datetime TEXT here, so `now() - time` was NULL.
            if is_numeric_operator(op) {
                let l_ms = datetime_operand_millis(left, &left_val);
                let r_ms = datetime_operand_millis(right, &right_val);
                if let (Some(l), Some(r), BinaryOperator::Sub) = (l_ms, r_ms, op) {
                    return Some(serde_json::json!((l - r).div_euclid(1000)));
                }
                let as_seconds = |ms: Option<i64>, v: serde_json::Value| {
                    ms.map_or(v, |ms| serde_json::json!(ms as f64 / 1000.0))
                };
                return apply_binary_op(op, as_seconds(l_ms, left_val), as_seconds(r_ms, right_val));
            }
            apply_binary_op(op, left_val, right_val)
        }
        EvalExpression::FunctionCall { name, args } => evaluate_function_call(name, args, row),
    }
}

/// NAN-4902: a value as a SQL truth value — `Some(bool)`, or `None` for
/// UNKNOWN (NULL / absent / a non-boolean, non-numeric value). Numbers are
/// truthy when non-zero, like ClickHouse UInt8 booleans.
pub(super) fn sql_truth(value: Option<&serde_json::Value>) -> Option<bool> {
    match value? {
        serde_json::Value::Bool(b) => Some(*b),
        serde_json::Value::Number(n) => Some(n.as_f64()? != 0.0),
        _ => None,
    }
}

/// NAN-4902: SQL three-valued AND / OR (`None` = UNKNOWN): `false AND x` is
/// false and `true OR x` is true even when `x` is NULL; otherwise any UNKNOWN
/// operand makes the result UNKNOWN.
pub(super) fn sql_logic(op: &BinaryOperator, left: Option<bool>, right: Option<bool>) -> Option<bool> {
    match op {
        BinaryOperator::And => match (left, right) {
            (Some(false), _) | (_, Some(false)) => Some(false),
            (Some(true), Some(true)) => Some(true),
            _ => None,
        },
        BinaryOperator::Or => match (left, right) {
            (Some(true), _) | (_, Some(true)) => Some(true),
            (Some(false), Some(false)) => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// NAN-4902: SQL NOT — NOT UNKNOWN is UNKNOWN.
pub(super) fn sql_not(value: Option<bool>) -> Option<bool> {
    value.map(|b| !b)
}

/// Apply a binary operator to two already-evaluated values.
pub(super) fn apply_binary_op(
    op: &BinaryOperator,
    left_val: serde_json::Value,
    right_val: serde_json::Value,
) -> Option<serde_json::Value> {
    {
            match op {
                // NAN-4303: a string operand concatenates (`"a" + "b"`), as the
                // SQL generator does for a string-typed operand.
                BinaryOperator::Add if left_val.is_string() || right_val.is_string() => {
                    Some(serde_json::Value::String(format!(
                        "{}{}",
                        plus_text(&left_val)?,
                        plus_text(&right_val)?
                    )))
                }
                BinaryOperator::Add => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l + r))
                }
                BinaryOperator::Sub => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l - r))
                }
                BinaryOperator::Mul => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l * r))
                }
                BinaryOperator::Div => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    if r != 0.0 {
                        Some(serde_json::json!(l / r))
                    } else {
                        None
                    }
                }
                BinaryOperator::Mod => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    if r != 0.0 {
                        Some(serde_json::json!(l % r))
                    } else {
                        None
                    }
                }
                BinaryOperator::Concat => {
                    // String concatenation
                    let l = left_val
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| left_val.to_string());
                    let r = right_val
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| right_val.to_string());
                    Some(serde_json::Value::String(format!("{}{}", l, r)))
                }
                BinaryOperator::Eq => Some(serde_json::json!(left_val == right_val)),
                BinaryOperator::Ne => Some(serde_json::json!(left_val != right_val)),
                BinaryOperator::Gt => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l > r))
                }
                BinaryOperator::Lt => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l < r))
                }
                BinaryOperator::Gte => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l >= r))
                }
                BinaryOperator::Lte => {
                    let l = left_val.as_f64()?;
                    let r = right_val.as_f64()?;
                    Some(serde_json::json!(l <= r))
                }
                BinaryOperator::And => {
                    let l = left_val.as_bool()?;
                    let r = right_val.as_bool()?;
                    Some(serde_json::json!(l && r))
                }
                BinaryOperator::Or => {
                    let l = left_val.as_bool()?;
                    let r = right_val.as_bool()?;
                    Some(serde_json::json!(l || r))
                }
                BinaryOperator::Contains => {
                    let l = left_val.as_str()?;
                    let r = right_val.as_str()?;
                    // NAN-4943: the nPL lowercase match (ClickHouse lower(), ASCII).
                    Some(serde_json::json!(l
                        .to_ascii_lowercase()
                        .contains(&r.to_ascii_lowercase())))
                }
                BinaryOperator::Like => {
                    // NAN-4943: `lower(l) LIKE lower(r)` — `%`/`_` wildcards,
                    // `\` escapes, every other character literal.
                    let l = left_val.as_str()?.to_ascii_lowercase();
                    let r = right_val.as_str()?.to_ascii_lowercase();
                    Some(serde_json::json!(super::condition::sql_like(&l, &r)))
                }
            }
    }
}

/// Arithmetic and ordering operators: the ones whose datetime operands the SQL
/// generator lowers to epoch seconds (NAN-3329).
fn is_numeric_operator(op: &BinaryOperator) -> bool {
    matches!(
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
    )
}

/// Epoch milliseconds of a DATETIME operand: `now()` or the event time column
/// (`timestamp` / `time` / `_time`) whose value parses as a datetime.
fn datetime_operand_millis(expr: &EvalExpression, value: &serde_json::Value) -> Option<i64> {
    let is_datetime_expr = match expr {
        EvalExpression::FunctionCall { name, args } => name.eq_ignore_ascii_case("now") && args.is_empty(),
        EvalExpression::Field(name) => matches!(name.as_str(), "timestamp" | "time" | "_time"),
        _ => false,
    };
    if !is_datetime_expr {
        return None;
    }
    crate::search::evaluator::helpers::parse_datetime_flexible(value.as_str()?)
        .map(|dt| dt.timestamp_millis())
}

/// NAN-4933 (codex P1): an array value against a scalar in eval / if() /
/// risk uses the SQL generator's multivalue semantics
/// (`array_field_predicate`): `=`, CONTAINS, LIKE, regex and the ordered
/// comparisons hold when ANY element does; `!=` when NO element is equal.
/// Before, the array went through `json_scalar_string` (None) and the whole
/// predicate was NULL, so a flag computed after `| prevalence` never matched.
fn array_predicate(
    left: &EvalExpression,
    op: &BinaryOperator,
    right: &EvalExpression,
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<Option<serde_json::Value>> {
    if !matches!(
        op,
        BinaryOperator::Eq
            | BinaryOperator::Ne
            | BinaryOperator::Contains
            | BinaryOperator::Like
            | BinaryOperator::Gt
            | BinaryOperator::Lt
            | BinaryOperator::Gte
            | BinaryOperator::Lte
    ) {
        return None;
    }
    let as_array = |expr: &EvalExpression| match expr {
        EvalExpression::Literal(_) => None,
        _ => match evaluate_eval_expression(expr, row) {
            Some(serde_json::Value::Array(items)) => Some(items),
            _ => None,
        },
    };
    let symmetric = matches!(op, BinaryOperator::Eq | BinaryOperator::Ne);
    let (items, scalar) = match (as_array(left), as_array(right)) {
        (Some(_), Some(_)) => return None,
        (Some(items), None) => (items, right),
        (None, Some(items)) if symmetric => (items, left),
        _ => return None,
    };
    let text = |v: &serde_json::Value| json_scalar_string(v).map(|t| t.to_ascii_lowercase());
    let element_hit: Box<dyn Fn(&serde_json::Value) -> bool> = match (op, scalar) {
        (BinaryOperator::Eq | BinaryOperator::Ne, EvalExpression::Literal(Value::Regex(pattern))) => {
            // NAN-4943: the canonical regex classification (`regex_plan`).
            if super::condition::regex_filter_hit(pattern, "").is_none() {
                return Some(None);
            }
            let pattern = pattern.clone();
            Box::new(move |v| {
                json_scalar_string(v)
                    .is_some_and(|t| super::condition::regex_filter_hit(&pattern, &t) == Some(true))
            })
        }
        _ => {
            let needle = match evaluate_eval_expression(scalar, row) {
                None | Some(serde_json::Value::Null) => return Some(None),
                Some(v) => v,
            };
            match op {
                BinaryOperator::Eq | BinaryOperator::Ne => {
                    let needle = text(&needle)?;
                    Box::new(move |v| text(v).is_some_and(|t| t == needle))
                }
                BinaryOperator::Contains => {
                    let needle = text(&needle)?;
                    Box::new(move |v| text(v).is_some_and(|t| t.contains(&needle)))
                }
                BinaryOperator::Like => {
                    let pattern = text(&needle)?;
                    Box::new(move |v| text(v).is_some_and(|t| super::condition::sql_like(&t, &pattern)))
                }
                _ => {
                    let bound = needle.as_f64().or_else(|| json_scalar_string(&needle)?.trim().parse().ok())?;
                    let op = *op;
                    Box::new(move |v| {
                        let n = v.as_f64().or_else(|| json_scalar_string(v).and_then(|t| t.trim().parse().ok()));
                        n.is_some_and(|n| match op {
                            BinaryOperator::Gt => n > bound,
                            BinaryOperator::Lt => n < bound,
                            BinaryOperator::Gte => n >= bound,
                            _ => n <= bound,
                        })
                    })
                }
            }
        }
    };
    let any = items.iter().any(|v| element_hit(v));
    Some(Some(serde_json::Value::Bool(if *op == BinaryOperator::Ne { !any } else { any })))
}

/// NAN-3041: `=` / `!=` against a regex or quoted-string literal mean what they
/// mean in `| where` and in the SQL generator: `f=/re/` is a case-insensitive
/// regex match, and `f="x"` is a case-insensitive string comparison. Returns
/// `None` when the operands are not that shape (the generic operator applies).
/// A NULL / absent subject propagates NULL, as in ClickHouse.
fn literal_predicate(
    left: &EvalExpression,
    op: &BinaryOperator,
    right: &EvalExpression,
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<Option<serde_json::Value>> {
    if !matches!(op, BinaryOperator::Eq | BinaryOperator::Ne) {
        return None;
    }
    let negate = |b: bool| Some(serde_json::Value::Bool(if *op == BinaryOperator::Eq { b } else { !b }));
    let subject_text = |subject: &EvalExpression| -> Option<String> {
        match evaluate_eval_expression(subject, row)? {
            serde_json::Value::Null => None,
            other => json_scalar_string(&other),
        }
    };
    match (left, right) {
        (subject, EvalExpression::Literal(Value::Regex(pattern)))
        | (EvalExpression::Literal(Value::Regex(pattern)), subject) => {
            let Some(text) = subject_text(subject) else { return Some(None) };
            // NAN-4943: the canonical regex classification (`regex_plan`).
            let Some(hit) = super::condition::regex_filter_hit(pattern, &text) else {
                return Some(None);
            };
            Some(negate(hit))
        }
        (subject, EvalExpression::Literal(Value::String(literal)))
        | (EvalExpression::Literal(Value::String(literal)), subject)
            if !matches!(subject, EvalExpression::Literal(_)) =>
        {
            let Some(text) = subject_text(subject) else { return Some(None) };
            Some(negate(text.to_ascii_lowercase() == literal.to_ascii_lowercase()))
        }
        _ => None,
    }
}

const PRIVATE_V4_RANGES: [&str; 3] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];

/// One post-processing function: its canonical name (the dispatch key in
/// `evaluate_function_call`), accepted aliases, and argument count. Arity
/// mirrors the ClickHouse SQL generator's checks, tightened to the arguments the
/// Rust evaluator actually honours (e.g. `tostring(x, fmt)` is rejected rather
/// than silently ignoring the format).
#[derive(Debug)]
pub(super) struct FunctionSpec {
    pub canonical: &'static str,
    pub aliases: &'static [&'static str],
    pub min_args: usize,
    pub max_args: Option<usize>,
}

impl FunctionSpec {
    pub(super) fn accepts(&self, count: usize) -> bool {
        count >= self.min_args && self.max_args.map_or(true, |max| count <= max)
    }

    pub(super) fn arity_message(&self, name: &str) -> String {
        let plural = |n: usize| if n == 1 { "argument" } else { "arguments" };
        match self.max_args {
            Some(max) if max == self.min_args => format!("{name}() requires {max} {}", plural(max)),
            Some(max) => format!("{name}() requires {} to {max} arguments", self.min_args),
            None => format!("{name}() requires at least {} {}", self.min_args, plural(self.min_args)),
        }
    }
}

const fn spec(canonical: &'static str, aliases: &'static [&'static str], min_args: usize, max_args: Option<usize>) -> FunctionSpec {
    FunctionSpec { canonical, aliases, min_args, max_args }
}

/// NAN-4902 capability table: the ONLY functions a post-processing stage can
/// evaluate. Validation rejects anything else (and wrong arity) as a query
/// error; dispatch looks names up here, so the two cannot drift apart.
/// `capability_table_tests` asserts every entry and alias really evaluates.
pub(super) const FUNCTIONS: &[FunctionSpec] = &[
    // String
    spec("lower", &["tolower"], 1, Some(1)),
    spec("upper", &["toupper"], 1, Some(1)),
    spec("len", &["length"], 1, Some(1)),
    spec("trim", &[], 1, Some(1)),
    spec("ltrim", &[], 1, Some(1)),
    spec("rtrim", &[], 1, Some(1)),
    spec("reverse", &[], 1, Some(1)),
    spec("substr", &["substring"], 2, Some(3)),
    spec("replace", &[], 3, Some(3)),
    spec("concat", &[], 1, None),
    spec("split", &[], 2, Some(2)),
    // Encoding / hashing
    spec("base64_encode", &["base64encode"], 1, Some(1)),
    spec("base64_decode", &["base64decode"], 1, Some(1)),
    spec("hex_encode", &["hexencode", "tohex"], 1, Some(1)),
    spec("hex_decode", &["hexdecode", "fromhex"], 1, Some(1)),
    spec("url_encode", &["urlencode"], 1, Some(1)),
    spec("url_decode", &["urldecode"], 1, Some(1)),
    spec("md5", &[], 1, Some(1)),
    spec("sha1", &[], 1, Some(1)),
    spec("sha256", &[], 1, Some(1)),
    // IP / network
    spec("is_private_ip", &["isprivateip", "is_rfc1918"], 1, Some(1)),
    spec("is_public_ip", &["ispublicip"], 1, Some(1)),
    spec("is_loopback", &["isloopback"], 1, Some(1)),
    spec("cidr_match", &["cidrmatch"], 2, None),
    // Pattern matching
    spec("match", &["regex_match"], 2, Some(2)),
    spec("like", &[], 2, Some(2)),
    spec("array_contains", &["arraycontains", "has"], 2, Some(2)),
    // Domain / URL / security
    spec("extract_domain", &["extractdomain"], 1, Some(1)),
    spec("extract_tld", &["extracttld"], 1, Some(1)),
    spec("extract_path", &["extractpath"], 1, Some(1)),
    spec("defang", &[], 1, Some(1)),
    spec("refang", &[], 1, Some(1)),
    // Conditional / null
    spec("coalesce", &["nvl"], 1, None),
    spec("if", &["iif"], 3, Some(3)),
    spec("in", &[], 2, None),
    // NAN-4933: type tests and searchmatch, as in the SQL generator.
    spec("isnum", &[], 1, Some(1)),
    spec("isint", &[], 1, Some(1)),
    spec("isstr", &[], 1, Some(1)),
    spec("isbool", &[], 1, Some(1)),
    spec("searchmatch", &[], 1, Some(1)),
    spec("not", &[], 1, Some(1)),
    spec("isnull", &["is_null"], 1, Some(1)),
    spec("isnotnull", &["is_not_null"], 1, Some(1)),
    // Math
    spec("min", &[], 1, None),
    spec("max", &[], 1, None),
    spec("abs", &[], 1, Some(1)),
    spec("ceil", &["ceiling"], 1, Some(1)),
    spec("floor", &[], 1, Some(1)),
    spec("round", &[], 1, Some(2)),
    spec("sqrt", &[], 1, Some(1)),
    spec("pow", &["power"], 2, Some(2)),
    spec("log", &["ln"], 1, Some(1)),
    spec("log10", &[], 1, Some(1)),
    // Type conversion
    spec("tonumber", &["to_number"], 1, Some(1)),
    spec("toint", &["to_int"], 1, Some(1)),
    spec("tostring", &["to_string"], 1, Some(1)),
    // Time
    spec("now", &[], 0, Some(0)),
    spec("dayofweek", &["dow"], 1, Some(1)),
];

/// Case-insensitive lookup by canonical name or alias.
pub(super) fn lookup_function(name: &str) -> Option<&'static FunctionSpec> {
    let lower = name.to_ascii_lowercase();
    FUNCTIONS
        .iter()
        .find(|f| f.canonical == lower || f.aliases.contains(&lower.as_str()))
}

/// Render a JSON scalar the way ClickHouse's toString would for matching.
/// nPL numeric literals evaluate to f64, and serde renders `443.0` as "443.0";
/// ClickHouse's `toString(443.0)` is "443", so an integral float is rendered
/// without the fraction (otherwise `has(dst_ports, 443)` never matches 443).
pub(super) fn json_scalar_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(match n.as_f64() {
            Some(f) if n.is_f64() && f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 => {
                format!("{}", f as i64)
            }
            _ => n.to_string(),
        }),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Parse an address; IPv4-mapped IPv6 is folded to IPv4 like ClickHouse does.
fn parse_ip(s: &str) -> Option<std::net::IpAddr> {
    let ip: std::net::IpAddr = s.trim().parse().ok()?;
    Some(match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(std::net::IpAddr::V4)
            .unwrap_or(ip),
        v4 => v4,
    })
}

/// Evaluate the first argument as an IP: `None` = the arg itself is absent (null
/// result), `Some(None)` = present but empty/malformed (never in any range).
fn ip_arg(
    args: &[EvalExpression],
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<Option<std::net::IpAddr>> {
    let arg = args.first().and_then(|a| evaluate_eval_expression(a, row))?;
    Some(arg.as_str().and_then(parse_ip))
}

/// Parse `net/bits`, rejecting a prefix length beyond the address family.
fn parse_cidr(cidr: &str) -> Option<(std::net::IpAddr, u32)> {
    let (net, bits) = cidr.trim().split_once('/')?;
    let net = parse_ip(net)?;
    let bits: u32 = bits.parse().ok()?;
    let max = if net.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((net, bits))
}

/// `Some(bool)` for a valid CIDR (family mismatch = false), `None` if the CIDR is invalid.
pub(super) fn ip_in_cidr(ip: std::net::IpAddr, cidr: &str) -> Option<bool> {
    let (net, bits) = parse_cidr(cidr)?;
    Some(match (ip, net) {
        (std::net::IpAddr::V4(ip), std::net::IpAddr::V4(net)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            u32::from(ip) & mask == u32::from(net) & mask
        }
        (std::net::IpAddr::V6(ip), std::net::IpAddr::V6(net)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            u128::from(ip) & mask == u128::from(net) & mask
        }
        _ => false,
    })
}

/// Validate a literal CIDR argument up front (ClickHouse rejects a bad prefix).
pub(super) fn is_valid_cidr(cidr: &str) -> bool {
    parse_cidr(cidr).is_some()
}

/// Evaluate a function call in an eval expression
///
/// # Arguments
/// * `name` - The function name
/// * `args` - The function arguments
/// * `row` - The row data to evaluate against
///
/// # Returns
/// * `Some(serde_json::Value)` - The function result
/// * `None` - If evaluation fails
fn evaluate_function_call(
    name: &str,
    args: &[EvalExpression],
    row: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    // NAN-4902: dispatch only through the capability table, so a name the
    // validator accepts is exactly a name this function evaluates.
    let spec = lookup_function(name)?;
    if !spec.accepts(args.len()) {
        return None;
    }
    match spec.canonical {
        // ============================================================
        // String Functions
        // ============================================================
        "lower" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(arg.as_str()?.to_ascii_lowercase()))
        }
        "upper" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(arg.as_str()?.to_ascii_uppercase()))
        }
        "len" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::json!(arg.as_str()?.len()))
        }
        "trim" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(arg.as_str()?.trim().to_string()))
        }
        "ltrim" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                arg.as_str()?.trim_start().to_string(),
            ))
        }
        "rtrim" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                arg.as_str()?.trim_end().to_string(),
            ))
        }
        "reverse" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                arg.as_str()?.chars().rev().collect(),
            ))
        }
        "substr" => {
            let s = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let start = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            let s_str = s.as_str()?;
            let start_idx = start.as_f64()?.max(0.0) as usize;
            if args.len() >= 3 {
                let len = args.get(2).and_then(|a| evaluate_eval_expression(a, row))?;
                let len_val = len.as_f64()?.max(0.0) as usize;
                Some(serde_json::Value::String(
                    s_str.chars().skip(start_idx).take(len_val).collect(),
                ))
            } else {
                Some(serde_json::Value::String(
                    s_str.chars().skip(start_idx).collect(),
                ))
            }
        }
        "replace" => {
            let s = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let from = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            let to = args.get(2).and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(
                s.as_str()?.replace(from.as_str()?, to.as_str()?),
            ))
        }
        "concat" => {
            let parts: Vec<String> = args
                .iter()
                .filter_map(|a| evaluate_eval_expression(a, row))
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            Some(serde_json::Value::String(parts.join("")))
        }
        "split" => {
            let s = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let delim = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            let parts: Vec<serde_json::Value> = s
                .as_str()?
                .split(delim.as_str()?)
                .map(|p| serde_json::Value::String(p.to_string()))
                .collect();
            Some(serde_json::Value::Array(parts))
        }

        // ============================================================
        // Encoding/Decoding Functions (Security Essential)
        // ============================================================
        "base64_encode" => {
            use base64::Engine;
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(arg.as_str()?.as_bytes());
            Some(serde_json::Value::String(encoded))
        }
        "base64_decode" => {
            use base64::Engine;
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(arg.as_str()?)
                .ok()?;
            let decoded_str = String::from_utf8(decoded).ok()?;
            Some(serde_json::Value::String(decoded_str))
        }
        "hex_encode" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let encoded = hex::encode(arg.as_str()?.as_bytes());
            Some(serde_json::Value::String(encoded))
        }
        "hex_decode" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let decoded = hex::decode(arg.as_str()?).ok()?;
            let decoded_str = String::from_utf8(decoded).ok()?;
            Some(serde_json::Value::String(decoded_str))
        }
        "url_encode" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let encoded = urlencoding::encode(arg.as_str()?);
            Some(serde_json::Value::String(encoded.into_owned()))
        }
        "url_decode" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let decoded = urlencoding::decode(arg.as_str()?).ok()?;
            Some(serde_json::Value::String(decoded.into_owned()))
        }

        // ============================================================
        // Hashing Functions (Security Essential)
        // ============================================================
        "md5" => {
            use md5::{Digest, Md5};
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let mut hasher = Md5::new();
            hasher.update(arg.as_str()?.as_bytes());
            let result = hasher.finalize();
            Some(serde_json::Value::String(hex::encode(result)))
        }
        "sha1" => {
            use sha1::{Digest, Sha1};
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let mut hasher = Sha1::new();
            hasher.update(arg.as_str()?.as_bytes());
            let result = hasher.finalize();
            Some(serde_json::Value::String(hex::encode(result)))
        }
        "sha256" => {
            use sha2::{Digest, Sha256};
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let mut hasher = Sha256::new();
            hasher.update(arg.as_str()?.as_bytes());
            let result = hasher.finalize();
            Some(serde_json::Value::String(hex::encode(result)))
        }

        // ============================================================
        // IP/Network Functions (Security Essential)
        // ============================================================
        // NAN-4902: these mirror the SQL generator's
        // `length(x) > 0 AND isIPAddressInRange(...)` forms, so an empty or
        // malformed address is never private, public or loopback. The old
        // prefix checks made `is_public_ip("")` TRUE after a post-processing
        // stage while the same predicate in ClickHouse was FALSE.
        "is_private_ip" => {
            let ip = ip_arg(args, row)?;
            Some(serde_json::Value::Bool(ip.is_some_and(|ip| {
                PRIVATE_V4_RANGES.iter().any(|cidr| ip_in_cidr(ip, cidr) == Some(true))
            })))
        }
        "is_public_ip" => {
            let ip = ip_arg(args, row)?;
            Some(serde_json::Value::Bool(ip.is_some_and(|ip| {
                !PRIVATE_V4_RANGES
                    .iter()
                    .chain(std::iter::once(&"127.0.0.0/8"))
                    .any(|cidr| ip_in_cidr(ip, cidr) == Some(true))
            })))
        }
        "is_loopback" => {
            let ip = ip_arg(args, row)?;
            Some(serde_json::Value::Bool(
                ip.is_some_and(|ip| ip_in_cidr(ip, "127.0.0.0/8") == Some(true)),
            ))
        }
        "cidr_match" => {
            // Same argument resolution as the SQL generator (NAN-2020): with two
            // args the CIDR is the one containing '/', defaulting to (ip, cidr);
            // with more, the first arg is the IP and the rest are CIDRs (OR).
            let values = args
                .iter()
                .map(|a| evaluate_eval_expression(a, row).and_then(|v| json_scalar_string(&v)))
                .collect::<Option<Vec<String>>>()?;
            if values.len() < 2 {
                return None;
            }
            let (ip, cidrs): (&String, Vec<&String>) = if values.len() == 2
                && values[0].contains('/')
                && !values[1].contains('/')
            {
                (&values[1], vec![&values[0]])
            } else {
                (&values[0], values[1..].iter().collect())
            };
            let Some(ip) = parse_ip(ip) else {
                return Some(serde_json::Value::Bool(false));
            };
            let mut hit = false;
            for cidr in cidrs {
                // An unparseable CIDR is a query error in ClickHouse; literal
                // CIDRs are rejected before filtering, a computed one yields null.
                hit |= ip_in_cidr(ip, cidr)?;
            }
            Some(serde_json::Value::Bool(hit))
        }
        "match" => {
            // ClickHouse match(): case-SENSITIVE RE2 (the `(?i)` prefix only
            // applies to `field=/re/` filters), dot matches newline.
            let [haystack, pattern] = args else { return None };
            let haystack = json_scalar_string(&evaluate_eval_expression(haystack, row)?)?;
            let pattern = json_scalar_string(&evaluate_eval_expression(pattern, row)?)?;
            let re = super::condition::compile_case_sensitive_regex(&pattern)?;
            Some(serde_json::Value::Bool(re.is_match(&haystack)))
        }
        "like" => {
            // NAN-3041: like() compiles to ClickHouse `iLike` (as the `where`
            // LIKE comparator): case-insensitive, `%`/`_` wildcards, `\` escape.
            let [haystack, pattern] = args else { return None };
            let haystack = json_scalar_string(&evaluate_eval_expression(haystack, row)?)?.to_ascii_lowercase();
            let pattern = json_scalar_string(&evaluate_eval_expression(pattern, row)?)?.to_ascii_lowercase();
            Some(serde_json::Value::Bool(super::condition::sql_like(&haystack, &pattern)))
        }
        "array_contains" => {
            // SQL: positionCaseInsensitive(toString(arr), needle) > 0 — an
            // ASCII-case-insensitive substring test over the rendered value.
            let [haystack, needle] = args else { return None };
            let haystack = evaluate_eval_expression(haystack, row)?;
            let needle = json_scalar_string(&evaluate_eval_expression(needle, row)?)?
                .to_ascii_lowercase();
            let contains = |v: &serde_json::Value| {
                json_scalar_string(v).is_some_and(|s| s.to_ascii_lowercase().contains(&needle))
            };
            Some(serde_json::Value::Bool(match &haystack {
                serde_json::Value::Array(items) => items.iter().any(contains),
                serde_json::Value::Null => false,
                other => contains(other),
            }))
        }

        // ============================================================
        // Domain/URL Extraction Functions (Security Essential)
        // ============================================================
        "extract_domain" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let url = arg.as_str()?;
            // Remove protocol
            let without_protocol = url
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("ftp://");
            // Get domain (before first /)
            let domain = without_protocol
                .split('/')
                .next()
                .unwrap_or(without_protocol);
            // Remove port if present
            let domain = domain.split(':').next().unwrap_or(domain);
            Some(serde_json::Value::String(domain.to_string()))
        }
        "extract_tld" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let url = arg.as_str()?;
            let without_protocol = url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let domain = without_protocol
                .split('/')
                .next()
                .unwrap_or(without_protocol);
            let domain = domain.split(':').next().unwrap_or(domain);
            let tld = domain.rsplit('.').next().unwrap_or("");
            Some(serde_json::Value::String(tld.to_string()))
        }
        "extract_path" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let url = arg.as_str()?;
            let without_protocol = url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let path = without_protocol
                .find('/')
                .map(|i| &without_protocol[i..])
                .unwrap_or("/");
            Some(serde_json::Value::String(path.to_string()))
        }

        // ============================================================
        // Security-Specific Functions
        // ============================================================
        "defang" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let defanged = arg
                .as_str()?
                .replace("http", "hxxp")
                .replace(".", "[.]")
                .replace("://", "[://]");
            Some(serde_json::Value::String(defanged))
        }
        "refang" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let refanged = arg
                .as_str()?
                .replace("hxxp", "http")
                .replace("[.]", ".")
                .replace("[://]", "://");
            Some(serde_json::Value::String(refanged))
        }

        // ============================================================
        // Conditional Functions
        // ============================================================
        "coalesce" => {
            for arg in args {
                if let Some(val) = evaluate_eval_expression(arg, row) {
                    if !val.is_null() {
                        return Some(val);
                    }
                }
            }
            None
        }
        "if" => {
            if args.len() >= 3 {
                // ClickHouse `if(NULL, a, b)` takes the else branch.
                let cond = evaluate_eval_expression(&args[0], row).unwrap_or(serde_json::Value::Null);
                let is_true = match cond {
                    serde_json::Value::Bool(b) => b,
                    serde_json::Value::Number(n) => n.as_f64().map(|v| v != 0.0).unwrap_or(false),
                    serde_json::Value::String(s) => !s.is_empty(),
                    _ => false,
                };
                if is_true {
                    evaluate_eval_expression(&args[1], row)
                } else {
                    evaluate_eval_expression(&args[2], row)
                }
            } else {
                None
            }
        }
        // NAN-4933: type tests with the SQL generator's semantics. NULL /
        // absent is false. isnum / isint read the value's text
        // (`toFloat64OrNull(toString(x))`), so "5" counts; isstr / isbool are
        // type tests ("5" is a string, 5 is not).
        "isnum" => {
            let v = evaluate_eval_expression(args.first()?, row);
            Some(serde_json::Value::Bool(v.as_ref().is_some_and(|v| match v {
                serde_json::Value::Number(_) => true,
                serde_json::Value::String(s) => s.trim().parse::<f64>().is_ok(),
                _ => false,
            })))
        }
        "isint" => {
            let v = evaluate_eval_expression(args.first()?, row);
            Some(serde_json::Value::Bool(v.as_ref().is_some_and(|v| match v {
                serde_json::Value::Number(n) => n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.fract() == 0.0),
                serde_json::Value::String(s) => s.trim().parse::<i64>().is_ok(),
                _ => false,
            })))
        }
        "isstr" => {
            let v = evaluate_eval_expression(args.first()?, row);
            Some(serde_json::Value::Bool(matches!(v, Some(serde_json::Value::String(_)))))
        }
        "isbool" => {
            // A JSON boolean, or a schema boolean stored as UInt8 (UDM).
            let v = evaluate_eval_expression(args.first()?, row);
            let schema_bool = match args.first() {
                Some(EvalExpression::Field(name)) => {
                    use crate::schema::SchemaProfile;
                    crate::schema::UdmProfile::new().field_type(name)
                        == Some(crate::schema::FieldType::Boolean)
                }
                _ => false,
            };
            Some(serde_json::Value::Bool(match v {
                Some(serde_json::Value::Bool(_)) => true,
                Some(serde_json::Value::Number(_)) => schema_bool,
                _ => false,
            }))
        }
        "searchmatch" => {
            let call = EvalExpression::FunctionCall { name: "searchmatch".into(), args: args.to_vec() };
            // Base-search semantics: `f=adm*` is a wildcard (LIKE), as in SQL.
            let search = crate::query::search_wildcards_to_like(
                crate::query::searchmatch_search_expr(&call)?,
            );
            Some(serde_json::Value::Bool(super::condition::evaluate_condition_on_json(
                &search,
                &serde_json::Value::Object(row.clone()),
            )))
        }
        // NAN-3041: `in(x, a, b)` / `x IN (a, b)`: numbers compare as numbers,
        // anything else as case-insensitive text (as `| where x IN (…)`).
        // NULL subject is NULL, as in ClickHouse.
        "in" => {
            let subject = evaluate_eval_expression(args.first()?, row).filter(|v| !v.is_null())?;
            // An array subject is a member when any element is (as in SQL).
            if let serde_json::Value::Array(items) = &subject {
                let members: Vec<serde_json::Value> =
                    args[1..].iter().filter_map(|m| evaluate_eval_expression(m, row)).collect();
                let hit = items.iter().any(|item| {
                    members.iter().any(|m| match (item.as_f64(), m.as_f64()) {
                        (Some(l), Some(r)) => l == r,
                        _ => matches!((json_scalar_string(item), json_scalar_string(m)),
                            (Some(l), Some(r)) if l.to_ascii_lowercase() == r.to_ascii_lowercase()),
                    })
                });
                return Some(serde_json::Value::Bool(hit));
            }
            let found = args[1..].iter().any(|member| {
                let Some(member) = evaluate_eval_expression(member, row) else { return false };
                match (subject.as_f64(), member.as_f64()) {
                    (Some(l), Some(r)) => l == r,
                    _ => match (json_scalar_string(&subject), json_scalar_string(&member)) {
                        (Some(l), Some(r)) => l.to_ascii_lowercase() == r.to_ascii_lowercase(),
                        _ => false,
                    },
                }
            });
            Some(serde_json::Value::Bool(found))
        }
        "not" => {
            // Unary `NOT expr` (parser lowers it to `not(expr)`). Mirrors
            // ClickHouse: NOT NULL is NULL (None), NOT of a number is
            // `n == 0`, and a non-boolean, non-numeric operand (a string,
            // where ClickHouse raises) yields no value.
            let arg = args.first().and_then(|a| evaluate_eval_expression(a, row));
            sql_not(sql_truth(arg.as_ref())).map(serde_json::Value::Bool)
        }
        "isnull" => {
            let arg = args.first().and_then(|a| evaluate_eval_expression(a, row));
            Some(serde_json::Value::Bool(
                arg.is_none() || arg.as_ref().map(|v| v.is_null()).unwrap_or(true),
            ))
        }
        "isnotnull" => {
            let arg = args.first().and_then(|a| evaluate_eval_expression(a, row));
            Some(serde_json::Value::Bool(
                arg.is_some() && !arg.as_ref().map(|v| v.is_null()).unwrap_or(true),
            ))
        }

        // ============================================================
        // Math Functions
        // ============================================================
        "min" | "max" => {
            let mut values = args.iter().map(|arg| evaluate_eval_expression(arg, row));
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
                let take_candidate = if spec.canonical == "min" {
                    ordering.is_gt()
                } else {
                    ordering.is_lt()
                };
                Some(if take_candidate { candidate } else { best })
            })
        }
        "abs" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.abs()))
        }
        "ceil" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.ceil()))
        }
        "floor" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.floor()))
        }
        "round" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            if args.len() >= 2 {
                let decimals = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
                let d = decimals.as_f64()? as i32;
                let factor = 10_f64.powi(d);
                Some(serde_json::json!((n * factor).round() / factor))
            } else {
                Some(serde_json::json!(n.round()))
            }
        }
        "sqrt" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.sqrt()))
        }
        "pow" => {
            let base = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let exp = args.get(1).and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::json!(base.as_f64()?.powf(exp.as_f64()?)))
        }
        "log" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.ln()))
        }
        "log10" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            let n = arg.as_f64()?;
            Some(serde_json::json!(n.log10()))
        }

        // ============================================================
        // Type Conversion Functions
        // ============================================================
        "tonumber" => {
            // SQL: toFloat64OrZero(toString(x)) — unparseable is 0, not null.
            let arg = evaluate_eval_expression(&args[0], row)?;
            let parsed = match &arg {
                serde_json::Value::Number(n) => n.as_f64(),
                serde_json::Value::String(s) => s.trim().parse::<f64>().ok(),
                serde_json::Value::Bool(b) => Some(f64::from(u8::from(*b))),
                _ => None,
            };
            Some(serde_json::json!(parsed.unwrap_or(0.0)))
        }
        "toint" => {
            // SQL: toInt64OrZero(x) — integer text only, anything else is 0.
            let arg = evaluate_eval_expression(&args[0], row)?;
            let parsed = match &arg {
                serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
                serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
                serde_json::Value::Bool(b) => Some(i64::from(*b)),
                _ => None,
            };
            Some(serde_json::json!(parsed.unwrap_or(0)))
        }
        "now" => Some(serde_json::Value::String(chrono::Utc::now().to_rfc3339())),
        "dayofweek" => {
            // SQL: toDayOfWeek(ts) — ISO numbering, Monday = 1 … Sunday = 7.
            use chrono::Datelike;
            let arg = evaluate_eval_expression(&args[0], row)?;
            let dt = crate::search::evaluator::helpers::parse_datetime_flexible(arg.as_str()?)?;
            Some(serde_json::json!(dt.weekday().number_from_monday()))
        }
        "tostring" => {
            let arg = args
                .first()
                .and_then(|a| evaluate_eval_expression(a, row))?;
            Some(serde_json::Value::String(match arg {
                serde_json::Value::String(s) => s,
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                _ => arg.to_string(),
            }))
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

/// NAN-4303: one `+` operand as the text ClickHouse `toString` gives it
/// (integral numbers without a fraction); NULL makes the result NULL.
pub(super) fn plus_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() < 1e15 => format!("{}", f as i64),
            _ => n.to_string(),
        }),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}
