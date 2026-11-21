// SPDX-License-Identifier: AGPL-3.0-or-later

//! The static SQL → nPL translation: one guarded SELECT in, nPL text out, or
//! a structured [`Unsupported`]. It never guesses: a construct it does not
//! know is refused with the span it sits at, and the caller may then try the
//! AI path.

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use sqlparser::ast::{
    BinaryOperator, DuplicateTreatment, Expr, FunctionArg, FunctionArgExpr, FunctionArguments, GroupByExpr, InTarget,
    LimitClause, ObjectName, ObjectNamePart, OrderByKind, OrderBySort, Query, Select, SelectItem, SetExpr,
    Spanned, Statement, TableFactor, UnaryOperator, Value,
};
use sqlparser::dialect::ClickHouseDialect;
use sqlparser::parser::Parser;

use crate::query::Dataset;

use super::{
    ConvertContext, TimeBound, Unsupported, EVENTS_TABLE_PLACEHOLDER, MAX_SQL_BYTES, SIGNALS_TABLE_PLACEHOLDER,
    WINDOW_END_PARAM, WINDOW_START_PARAM,
};

/// Same-shape identifiers the placeholders are swapped for before parsing,
/// padded to the placeholder's length so sqlparser's spans stay accurate.
pub(super) const EARLIEST_SENTINEL: &str = "__nano_window_earliest";
pub(super) const LATEST_SENTINEL: &str = "__nano_window_latest";
pub(super) const EVENTS_SENTINEL: &str = "__events";
pub(super) const SIGNALS_SENTINEL: &str = "__signals";

/// The column every events table is partitioned and bounded by.
pub(super) const TIME_COLUMN: &str = "timestamp";

static NPL_FIELD: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$").expect("static regex"));
static READS_SIGNALS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(from|join)\s+(`?\w+`?\.)?`?(__signals|signals(_distributed|_local)?)`?\b").expect("static regex")
});
/// NAN-5612: Search reads detections as `dataset=signals`, one dataset per
/// query. SQL that correlates events with detections in one statement (the
/// playbook's `id IN (SELECT matched_log_id FROM {signals} …)`) has no exact
/// nPL form.
const MIXED_SIGNALS_REASON: &str = "the query correlates events with signals (detections that fired); nPL \
     correlates them only through an `IN [dataset=signals …]` subsearch filter";
/// A shard-local `signals_local` table reads one shard's detections only.
const SIGNALS_LOCAL_REASON: &str =
    "the shard-local `signals_local` table reads one shard only; dataset=signals reads every shard";
/// `LIMIT n BY …` (NAN-5614).
static LIMIT_BY: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)\bLIMIT\s+\d+\s+BY\b").expect("static regex"));
const LIMIT_BY_REASON: &str = "LIMIT n BY … (the first n rows per key): nPL `dedup` keeps one row per key, in its own \
     order, and takes no count, so it has no exact nPL form";
static NPL_ALIAS: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").expect("static regex"));

fn padded(sentinel: &str, placeholder: &str) -> String {
    format!("{sentinel:_<width$}", width = placeholder.len())
}

/// Trim, drop one trailing `;`, cap the size, and swap the Agent Lane
/// placeholders for parseable identifiers.
pub(super) fn preprocess(sql: &str) -> Result<String, Unsupported> {
    let trimmed = sql.trim();
    let query = trimmed.strip_suffix(';').unwrap_or(trimmed).trim();
    if query.is_empty() {
        return Err(Unsupported::new("the query is empty"));
    }
    if query.len() > MAX_SQL_BYTES {
        return Err(Unsupported::new("the query is longer than 16 KiB"));
    }
    let out = query
        .replace(WINDOW_START_PARAM, &padded(EARLIEST_SENTINEL, WINDOW_START_PARAM))
        .replace(WINDOW_END_PARAM, &padded(LATEST_SENTINEL, WINDOW_END_PARAM))
        .replace(EVENTS_TABLE_PLACEHOLDER, &padded(EVENTS_SENTINEL, EVENTS_TABLE_PLACEHOLDER))
        .replace(SIGNALS_TABLE_PLACEHOLDER, &padded(SIGNALS_SENTINEL, SIGNALS_TABLE_PLACEHOLDER));
    if let Some(at) = brace_outside_literals(&out) {
        return Err(Unsupported::new(format!(
            "query parameter at byte {at}: only the run window placeholders can be converted"
        )));
    }
    Ok(out)
}

/// The byte offset of the first `{` outside a single-quoted literal.
fn brace_outside_literals(sql: &str) -> Option<usize> {
    let mut in_str = false;
    let mut chars = sql.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if in_str => {
                chars.next();
            }
            '\'' if in_str && chars.peek().map(|p| p.1) == Some('\'') => {
                chars.next();
            }
            '\'' => in_str = !in_str,
            '{' if !in_str => return Some(i),
            _ => {}
        }
    }
    None
}

/// Parse exactly one statement and return its query.
pub(super) fn parse_one(sql: &str) -> Result<Box<Query>, Unsupported> {
    let mut statements = Parser::parse_sql(&ClickHouseDialect {}, sql)
        .map_err(|e| Unsupported::new(format!("the SQL does not parse: {e}")))?;
    if statements.len() != 1 {
        return Err(Unsupported::new("exactly one statement can be converted"));
    }
    match statements.remove(0) {
        Statement::Query(q) => Ok(q),
        _ => Err(Unsupported::new("only a SELECT can be converted")),
    }
}

/// What a FROM target is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TableKind {
    Events,
    /// The playbook's `{signals}` placeholder: every detection that fired
    /// (real-time signals plus scheduled findings), exactly what
    /// `dataset=signals` reads.
    Signals,
    /// The physical `signals` table (or its `_distributed` twin): real-time
    /// detections only. `dataset=signals` also reads scheduled detections.
    SignalsTable,
    Other(String),
}

/// The last identifier of a table name, without the `_distributed` /
/// `_local` twin suffix.
pub(super) fn table_base(name: &ObjectName) -> String {
    let parts: Vec<&str> = name.0.iter().filter_map(ObjectNamePart::as_ident).map(|i| i.value.as_str()).collect();
    if parts.len() > 1 && !parts[0].eq_ignore_ascii_case("default") {
        // Another database's table, whatever its name.
        return name.to_string();
    }
    let last = name
        .0
        .last()
        .and_then(ObjectNamePart::as_ident)
        .map(|i| i.value.clone())
        .unwrap_or_default();
    // The cluster-wide twin reads the same rows; a shard-local `_local`
    // table does not.
    last.strip_suffix("_distributed").map(str::to_string).unwrap_or(last)
}

pub(super) fn table_kind(base: &str, ctx: &ConvertContext) -> TableKind {
    if base == EVENTS_SENTINEL || base == ctx.events_table() {
        TableKind::Events
    } else if base == SIGNALS_SENTINEL {
        TableKind::Signals
    } else if base == "signals" {
        TableKind::SignalsTable
    } else {
        TableKind::Other(base.to_string())
    }
}

/// Is `name` an aggregate function the converter or comparator knows?
pub(super) fn is_aggregate_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "count"
            | "sum"
            | "avg"
            | "min"
            | "max"
            | "any"
            | "anylast"
            | "argmin"
            | "argmax"
            | "median"
            | "grouparray"
            | "groupuniqarray"
            | "topk"
            | "stddevpop"
            | "stddevsamp"
            | "varpop"
            | "varsamp"
    ) || n.starts_with("uniq")
        || n.starts_with("quantile")
        || n.ends_with("if") && is_aggregate_name(&n[..n.len() - 2])
}

pub(super) fn function_name(f: &sqlparser::ast::Function) -> String {
    f.name
        .0
        .last()
        .and_then(ObjectNamePart::as_ident)
        .map(|i| i.value.clone())
        .unwrap_or_default()
}

/// Does `expr` contain an aggregate call anywhere?
pub(super) fn contains_aggregate(expr: &Expr) -> bool {
    match expr {
        Expr::Function(f) => {
            is_aggregate_name(&function_name(f))
                || function_args(f).iter().any(|a| matches!(a, Arg::Expr(e) if contains_aggregate(e)))
        }
        Expr::BinaryOp { left, right, .. } => contains_aggregate(left) || contains_aggregate(right),
        Expr::UnaryOp { expr, .. } | Expr::Nested(expr) => contains_aggregate(expr),
        _ => false,
    }
}

/// A function argument as the converter sees it.
pub(super) enum Arg<'a> {
    Expr(&'a Expr),
    Star,
    Other,
}

pub(super) fn function_args(f: &sqlparser::ast::Function) -> Vec<Arg<'_>> {
    match &f.args {
        FunctionArguments::None => Vec::new(),
        FunctionArguments::Subquery(_) => vec![Arg::Other],
        FunctionArguments::List(list) => list
            .args
            .iter()
            .map(|a| match a {
                FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) => Arg::Expr(e),
                FunctionArg::Unnamed(FunctionArgExpr::Wildcard) => Arg::Star,
                _ => Arg::Other,
            })
            .collect(),
    }
}

pub(super) fn is_distinct_call(f: &sqlparser::ast::Function) -> bool {
    matches!(&f.args, FunctionArguments::List(l) if l.duplicate_treatment == Some(DuplicateTreatment::Distinct))
}

/// Parse a literal timestamp the way ClickHouse would read it.
pub(super) fn parse_instant(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d"] {
        if let Ok(n) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&n));
        }
        if fmt == "%Y-%m-%d" {
            if let Ok(d) = chrono::NaiveDate::parse_from_str(s, fmt) {
                return d.and_hms_opt(0, 0, 0).map(|n| Utc.from_utc_datetime(&n));
            }
        }
    }
    None
}

pub(super) fn string_literal(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) | Value::EscapedStringLiteral(s) => Some(s.as_str()),
            _ => None,
        },
        Expr::Nested(e) => string_literal(e),
        _ => None,
    }
}

pub(super) fn sentinel_of(expr: &Expr) -> Option<&'static str> {
    sentinel_name(expr)
}

fn sentinel_name(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::Identifier(i) if i.value.starts_with(EARLIEST_SENTINEL) => Some(EARLIEST_SENTINEL),
        Expr::Identifier(i) if i.value.starts_with(LATEST_SENTINEL) => Some(LATEST_SENTINEL),
        Expr::Nested(e) => sentinel_name(e),
        _ => None,
    }
}

/// A time-bound operand: the window placeholder, a literal, or a literal
/// wrapped in a conversion function.
fn time_bound_value(expr: &Expr) -> Option<TimeBound> {
    match sentinel_of(expr) {
        Some(EARLIEST_SENTINEL) => return Some(TimeBound::WindowStart),
        Some(_) => return Some(TimeBound::WindowEnd),
        None => {}
    }
    if let Some(s) = string_literal(expr) {
        return parse_instant(s).map(TimeBound::At);
    }
    if let Expr::Function(f) = expr {
        let name = function_name(f).to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "todatetime" | "todatetime64" | "parsedatetimebesteffort" | "parsedatetime64besteffort"
        ) {
            // One argument only: a second one is a timezone (or a scale
            // the literal then depends on), which would shift the instant.
            let args = function_args(f);
            let only_scale = name == "todatetime64" && args.len() == 2;
            if args.len() == 1 || only_scale {
                if let Some(Arg::Expr(first)) = args.first() {
                    return time_bound_value(first);
                }
            }
        }
    }
    None
}

/// The table qualifiers a column may be prefixed with in this SELECT.
struct Scope<'a> {
    qualifiers: Vec<String>,
    /// SELECT aliases that rename something: ClickHouse resolves them inside
    /// WHERE too, so a filter naming one is not filtering the column.
    shadowed: Vec<String>,
    /// What an `IN (SELECT …)` filter needs (NAN-5614): the context, the
    /// dataset this SELECT reads, and its time window. `None` where a
    /// subquery cannot appear (HAVING, eval conditions).
    sub: Option<SubContext<'a>>,
}

#[derive(Clone)]
struct SubContext<'a> {
    ctx: &'a ConvertContext,
    dataset: Dataset,
    earliest: Option<TimeBound>,
    latest: Option<TimeBound>,
}

impl Scope<'_> {
    fn plain(qualifiers: Vec<String>) -> Scope<'static> {
        Scope { qualifiers, shadowed: Vec::new(), sub: None }
    }
    /// The column a reference names, as nPL spells it.
    fn field(&self, expr: &Expr) -> Option<String> {
        match expr {
            Expr::Identifier(i) => {
                if i.value.starts_with("__nano_window_") {
                    None
                } else {
                    Some(i.value.clone())
                }
            }
            Expr::CompoundIdentifier(parts) => {
                let names: Vec<&str> = parts.iter().map(|p| p.value.as_str()).collect();
                let names = if names.len() > 1 && self.qualifiers.iter().any(|q| q == names[0]) {
                    &names[1..]
                } else {
                    &names[..]
                };
                Some(names.join("."))
            }
            Expr::Nested(e) => self.field(e),
            _ => None,
        }
    }
}

fn npl_field(name: &str, span: sqlparser::tokenizer::Span) -> Result<String, Unsupported> {
    if NPL_FIELD.is_match(name) {
        Ok(name.to_string())
    } else {
        Err(Unsupported::at(format!("the field `{name}` cannot be written in nPL"), span))
    }
}

/// An nPL string literal for `s`. Double-quoted unless it holds a `"`; a
/// value with both quote kinds has no nPL spelling. Backslashes are doubled
/// because the parser collapses `\\` to `\` (NAN-1157).
fn npl_string(s: &str, span: sqlparser::tokenizer::Span) -> Result<String, Unsupported> {
    let body = s.replace('\\', "\\\\");
    if !s.contains('"') {
        Ok(format!("\"{body}\""))
    } else if !s.contains('\'') {
        Ok(format!("'{body}'"))
    } else {
        Err(Unsupported::at("a value with both quote kinds has no nPL spelling", span))
    }
}

/// An nPL literal for a SQL literal operand.
fn npl_literal(expr: &Expr) -> Result<Option<String>, Unsupported> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::SingleQuotedString(s) | Value::EscapedStringLiteral(s) => npl_string(s, expr.span()).map(Some),
            Value::Number(n, _) => {
                if n.parse::<f64>().is_ok() {
                    Ok(Some(n.to_string()))
                } else {
                    Err(Unsupported::at(format!("the number `{n}`"), expr.span()))
                }
            }
            Value::Boolean(b) => Ok(Some(b.to_string())),
            _ => Ok(None),
        },
        Expr::UnaryOp { op: UnaryOperator::Minus, expr: inner } => {
            Ok(npl_literal(inner)?.filter(|n| n.parse::<f64>().is_ok()).map(|n| format!("-{n}")))
        }
        Expr::Nested(e) => npl_literal(e),
        _ => Ok(None),
    }
}

/// A translated filter: nPL text, and whether it only parses inside
/// `| where` (boolean functions such as `isnull(…)`).
#[derive(Debug, Clone)]
enum Filter {
    Atom { text: String, where_only: bool },
    And(Vec<Filter>),
    Or(Vec<Filter>),
    Not(Box<Filter>),
}

impl Filter {
    fn where_only(&self) -> bool {
        match self {
            Filter::Atom { where_only, .. } => *where_only,
            Filter::And(v) | Filter::Or(v) => v.iter().any(Filter::where_only),
            Filter::Not(f) => f.where_only(),
        }
    }

    fn render(&self) -> String {
        match self {
            Filter::Atom { text, .. } => text.clone(),
            Filter::And(v) => v.iter().map(|f| f.render_operand()).collect::<Vec<_>>().join(" AND "),
            Filter::Or(v) => v.iter().map(|f| f.render_operand()).collect::<Vec<_>>().join(" OR "),
            Filter::Not(f) => format!("NOT {}", f.render_operand()),
        }
    }

    fn render_operand(&self) -> String {
        match self {
            Filter::Atom { .. } | Filter::Not(_) => self.render(),
            _ => format!("({})", self.render()),
        }
    }
}

fn atom(text: String) -> Filter {
    Filter::Atom { text, where_only: false }
}

fn where_atom(text: String) -> Filter {
    Filter::Atom { text, where_only: true }
}

fn flip(op: &BinaryOperator) -> Option<BinaryOperator> {
    Some(match op {
        BinaryOperator::Eq => BinaryOperator::Eq,
        BinaryOperator::NotEq => BinaryOperator::NotEq,
        BinaryOperator::Gt => BinaryOperator::Lt,
        BinaryOperator::Lt => BinaryOperator::Gt,
        BinaryOperator::GtEq => BinaryOperator::LtEq,
        BinaryOperator::LtEq => BinaryOperator::GtEq,
        _ => return None,
    })
}

fn op_text(op: &BinaryOperator) -> Option<&'static str> {
    Some(match op {
        BinaryOperator::Eq => "=",
        BinaryOperator::NotEq => "!=",
        BinaryOperator::Gt => ">",
        BinaryOperator::Lt => "<",
        BinaryOperator::GtEq => ">=",
        BinaryOperator::LtEq => "<=",
        _ => return None,
    })
}

/// How a filter's column reference reads: the field, through any
/// `lower(…)` / `toString(…)` wrapper (nPL string matching is already
/// case-insensitive; the comparator reports where that broadens the SQL).
fn filter_field(scope: &Scope, expr: &Expr) -> Result<Option<String>, Unsupported> {
    if let Some(f) = scope.field(expr) {
        if scope.shadowed.contains(&f) {
            return Err(Unsupported::at(
                format!("the filter names `{f}`, a SELECT alias that ClickHouse resolves to the aliased expression"),
                expr.span(),
            ));
        }
        return npl_field(&f, expr.span()).map(Some);
    }
    if let Expr::Function(func) = expr {
        let name = function_name(func).to_ascii_lowercase();
        if matches!(name.as_str(), "lower" | "lowerutf8" | "tostring") {
            if let [Arg::Expr(inner)] = function_args(func).as_slice() {
                return filter_field(scope, inner);
            }
        }
    }
    Ok(None)
}

/// Escape-free LIKE body: no `%`, `_` or `\` inside.
fn plain(s: &str) -> bool {
    !s.is_empty() && !s.contains(['%', '_', '\\'])
}

fn like_filter(field: &str, pattern: &str, negated: bool, span: sqlparser::tokenizer::Span) -> Result<Filter, Unsupported> {
    let not = if negated { "NOT " } else { "" };
    let (op, value) = if let Some(inner) = pattern.strip_prefix('%').and_then(|p| p.strip_suffix('%')).filter(|p| plain(p)) {
        ("CONTAINS", inner)
    } else if let Some(inner) = pattern.strip_suffix('%').filter(|p| plain(p)) {
        ("STARTSWITH", inner)
    } else if let Some(inner) = pattern.strip_prefix('%').filter(|p| plain(p)) {
        ("ENDSWITH", inner)
    } else {
        ("LIKE", pattern)
    };
    Ok(atom(format!("{field} {not}{op} {}", npl_string(value, span)?)))
}

/// `lower(col)` / `lowerUTF8(col)`.
fn is_lowered(expr: &Expr) -> bool {
    match expr {
        Expr::Nested(e) => is_lowered(e),
        Expr::Function(f) => matches!(function_name(f).to_ascii_lowercase().as_str(), "lower" | "lowerutf8"),
        _ => false,
    }
}

fn has_upper(expr: &Expr) -> bool {
    string_literal(expr).is_some_and(|s| s != s.to_lowercase())
}

/// `lower(col) = 'Admin'` (or IN / LIKE with an uppercase literal) never
/// matches as written; nPL would fold the value and match rows the agent
/// never saw.
fn lowered_against_upper(expr: &Expr) -> bool {
    match expr {
        Expr::BinaryOp { left, op: BinaryOperator::Eq | BinaryOperator::NotEq, right } => {
            (is_lowered(left) && has_upper(right)) || (is_lowered(right) && has_upper(left))
        }
        Expr::In { expr, target: InTarget::List(list), .. } => is_lowered(expr) && list.iter().any(has_upper),
        Expr::Like { expr, pattern, .. } => is_lowered(expr) && has_upper(pattern),
        _ => false,
    }
}

fn translate_filter(scope: &Scope, expr: &Expr) -> Result<Option<Filter>, Unsupported> {
    let unsupported = |what: &str| Unsupported::at(format!("{what} cannot be converted: `{expr}`"), expr.span());
    if lowered_against_upper(expr) {
        return Err(Unsupported::at(
            format!("`{expr}` compares lower() with a value holding uppercase letters, so the SQL never matches it"),
            expr.span(),
        ));
    }
    Ok(Some(match expr {
        Expr::Nested(e) => return translate_filter(scope, e),
        Expr::Value(v) if matches!(&v.value, Value::Boolean(true)) => return Ok(None),
        Expr::Value(v) if matches!(&v.value, Value::Number(n, _) if n == "1") => return Ok(None),
        Expr::BinaryOp { left, op: BinaryOperator::And, right } => {
            let parts: Vec<Filter> = [left, right]
                .into_iter()
                .filter_map(|e| translate_filter(scope, e).transpose())
                .collect::<Result<_, _>>()?;
            match parts.len() {
                0 => return Ok(None),
                1 => parts.into_iter().next().expect("one"),
                _ => Filter::And(parts),
            }
        }
        Expr::BinaryOp { left, op: BinaryOperator::Or, right } => {
            let l = translate_filter(scope, left)?;
            let r = translate_filter(scope, right)?;
            match (l, r) {
                (Some(l), Some(r)) => Filter::Or(vec![l, r]),
                // `x OR true` is always true.
                _ => return Ok(None),
            }
        }
        Expr::UnaryOp { op: UnaryOperator::Not, expr: inner } => match translate_filter(scope, inner)? {
            Some(f) => Filter::Not(Box::new(f)),
            None => return Err(unsupported("`NOT true`")),
        },
        // NAN-5630: `positionCaseInsensitive(x, 'n') > 0` is a substring
        // match (`position` a case-sensitive one, which nPL matches broader).
        Expr::BinaryOp { left, op, right } if position_test(left, op, right).is_some() => {
            let (hay, needle, negated) = position_test(left, op, right).expect("checked");
            let field = filter_field(scope, hay)?.ok_or_else(|| unsupported("this position()"))?;
            like_filter(&field, &format!("%{needle}%"), negated, expr.span())?
        }
        Expr::BinaryOp { left, op, right } => {
            let (field_side, lit_side, op) = if filter_field(scope, left)?.is_some() {
                (left, right, op.clone())
            } else {
                (right, left, flip(op).ok_or_else(|| unsupported("this operator"))?)
            };
            let field = filter_field(scope, field_side)?.ok_or_else(|| unsupported("this comparison"))?;
            let op = op_text(&op).ok_or_else(|| unsupported("this operator"))?;
            match npl_literal(lit_side)? {
                Some(v) => atom(format!("{field}{op}{v}")),
                None if matches!(lit_side.as_ref(), Expr::Value(v) if matches!(v.value, Value::Null)) => {
                    return Err(unsupported("a comparison with NULL"))
                }
                None => return Err(unsupported("a comparison that is not with a literal")),
            }
        }
        Expr::In { expr: inner, target: InTarget::List(list), negated, .. } => {
            let field = filter_field(scope, inner)?.ok_or_else(|| unsupported("this IN"))?;
            let values = list
                .iter()
                .map(|v| npl_literal(v)?.ok_or_else(|| unsupported("an IN list with a non-literal")))
                .collect::<Result<Vec<_>, _>>()?;
            let not = if *negated { "NOT " } else { "" };
            atom(format!("{field} {not}IN ({})", values.join(", ")))
        }
        Expr::Like { negated, any: false, expr: inner, pattern, escape_char: None }
        | Expr::ILike { negated, any: false, expr: inner, pattern, escape_char: None } => {
            let field = filter_field(scope, inner)?.ok_or_else(|| unsupported("this LIKE"))?;
            let pat = string_literal(pattern).ok_or_else(|| unsupported("a LIKE without a literal pattern"))?;
            like_filter(&field, pat, *negated, expr.span())?
        }
        Expr::IsNull(inner) => {
            let field = filter_field(scope, inner)?.ok_or_else(|| unsupported("this IS NULL"))?;
            where_atom(format!("isnull({field})"))
        }
        Expr::IsNotNull(inner) => {
            let field = filter_field(scope, inner)?.ok_or_else(|| unsupported("this IS NOT NULL"))?;
            where_atom(format!("isnotnull({field})"))
        }
        Expr::Between { expr: inner, negated: false, low, high } => {
            let field = filter_field(scope, inner)?.ok_or_else(|| unsupported("this BETWEEN"))?;
            let low = npl_literal(low)?.ok_or_else(|| unsupported("a BETWEEN without literal bounds"))?;
            let high = npl_literal(high)?.ok_or_else(|| unsupported("a BETWEEN without literal bounds"))?;
            Filter::And(vec![atom(format!("{field}>={low}")), atom(format!("{field}<={high}"))])
        }
        Expr::Function(f) => {
            let name = function_name(f).to_ascii_lowercase();
            let args = function_args(f);
            match (name.as_str(), args.as_slice()) {
                ("isnull", [Arg::Expr(e)]) | ("isnotnull", [Arg::Expr(e)]) => {
                    let field = filter_field(scope, e)?.ok_or_else(|| unsupported("this function"))?;
                    where_atom(format!("{name}({field})"))
                }
                ("match", [Arg::Expr(e), Arg::Expr(p)]) => {
                    let field = filter_field(scope, e)?.ok_or_else(|| unsupported("this function"))?;
                    let pat = string_literal(p).ok_or_else(|| unsupported("a match() without a literal pattern"))?;
                    where_atom(format!("match({field}, {})", npl_string(pat, p.span())?))
                }
                ("startswith", [Arg::Expr(e), Arg::Expr(p)]) | ("endswith", [Arg::Expr(e), Arg::Expr(p)]) => {
                    let field = filter_field(scope, e)?.ok_or_else(|| unsupported("this function"))?;
                    let v = string_literal(p).ok_or_else(|| unsupported("this function"))?;
                    let op = if name == "startswith" { "STARTSWITH" } else { "ENDSWITH" };
                    atom(format!("{field} {op} {}", npl_string(v, p.span())?))
                }
                _ => return Err(Unsupported::at(format!("the function `{}`", function_name(f)), expr.span())),
            }
        }
        Expr::In { expr: inner, target: InTarget::Subquery(subquery), negated, global } => {
            if *global {
                return Err(Unsupported::at("GLOBAL IN", expr.span()));
            }
            subsearch_filter(scope, inner, subquery, *negated, expr.span())?
        }
        Expr::Subquery(_) | Expr::Exists { .. } => {
            return Err(Unsupported::at("a subquery", expr.span()))
        }
        _ => return Err(unsupported("this expression")),
    }))
}

/// What an nPL `IN [ ]` subsearch can carry: the generator applies only its
/// search terms and its `return` field (every other stage is ignored), over
/// the search's own time range.
const SUBSEARCH_SHAPE: &str = "an nPL `IN [ ]` subsearch applies only its search terms and its `return` field \
     (no stats, where, sort or head), so it has no exact nPL form";

/// `col IN (SELECT ret FROM t WHERE <window> AND …)` →
/// `col IN [dataset=… … | return ret]` (NAN-5614). Only a plain filtering
/// subquery over the same window converts; the comparator then proves it.
fn subsearch_filter(
    scope: &Scope,
    outer: &Expr,
    query: &Query,
    negated: bool,
    span: sqlparser::tokenizer::Span,
) -> Result<Filter, Unsupported> {
    let Some(sub) = scope.sub.as_ref() else {
        return Err(Unsupported::at("a subquery in this clause", span));
    };
    let refuse = |what: &str| Unsupported::at(format!("{what}: {SUBSEARCH_SHAPE}"), span);
    let field = match scope.field(outer) {
        Some(f) if !scope.shadowed.contains(&f) => npl_field(&f, outer.span())?,
        _ => {
            return Err(Unsupported::at(
                format!("`{outer} IN (SELECT …)`: only a plain column can be matched against a subquery in nPL"),
                outer.span(),
            ))
        }
    };
    if query.with.is_some()
        || query.fetch.is_some()
        || query.settings.is_some()
        || query.format_clause.is_some()
        || !query.locks.is_empty()
        || !query.pipe_operators.is_empty()
        || query.for_clause.is_some()
    {
        return Err(refuse("the subquery has a WITH / SETTINGS / FORMAT clause"));
    }
    if query.order_by.is_some() || query.limit_clause.is_some() {
        return Err(refuse("the subquery keeps only some of its rows (ORDER BY / LIMIT)"));
    }
    let SetExpr::Select(select) = query.body.as_ref() else {
        return Err(refuse("the subquery is a set operation"));
    };
    // DISTINCT does not change what IN matches.
    check_select_shape(select, true)?;
    let [from] = select.from.as_slice() else {
        return Err(refuse("the subquery reads more than one table"));
    };
    if !from.joins.is_empty() {
        return Err(refuse("the subquery has a JOIN"));
    }
    let (name, alias) = match &from.relation {
        TableFactor::Table { name, alias, args: None, sample: None, .. } => (name, alias),
        _ => return Err(refuse("the subquery reads a derived table or a table function")),
    };
    let base = table_base(name);
    let sub_dataset = match table_kind(&base, sub.ctx) {
        TableKind::Events => Dataset::Logs,
        TableKind::Signals | TableKind::SignalsTable => Dataset::Signals,
        TableKind::Other(t) => {
            return Err(Unsupported::at(format!("the subquery reads `{t}`, which Search has no dataset for"), from.relation.span())
                .no_dataset())
        }
    };
    let grouped = !matches!(&select.group_by, GroupByExpr::Expressions(e, m) if e.is_empty() && m.is_empty());
    let aggregates = select.projection.iter().any(|i| match i {
        SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => contains_aggregate(e),
        _ => false,
    });
    if grouped || aggregates || select.having.is_some() {
        return Err(refuse("the subquery aggregates (GROUP BY / HAVING)"));
    }
    let mut qualifiers = vec![base.clone(), sub.ctx.events_table().to_string(), "signals".to_string(), name.to_string()];
    if let Some(a) = alias {
        qualifiers.push(a.name.value.clone());
    }
    let ret_expr = match select.projection.as_slice() {
        [SelectItem::UnnamedExpr(e)] | [SelectItem::ExprWithAlias { expr: e, .. }] => e,
        _ => return Err(refuse("the subquery does not return exactly one column")),
    };
    let ret = match Scope::plain(qualifiers.clone()).field(ret_expr) {
        Some(f) => npl_field(&f, ret_expr.span())?,
        None => return Err(refuse(&format!("the subquery returns `{ret_expr}`, not a plain column"))),
    };

    let window_scope = Scope::plain(qualifiers.clone());
    let mut window = Window::default();
    let mut rest = Vec::new();
    for clause in [select.prewhere.as_ref(), select.selection.as_ref()].into_iter().flatten() {
        for c in conjuncts(clause) {
            if !window.take(&window_scope, c)? {
                rest.push(c);
            }
        }
    }
    if window.earliest != sub.earliest || window.latest != sub.latest {
        return Err(Unsupported::at(
            "the subquery's time window differs from the outer query's; an nPL subsearch runs over the search's own \
             time range",
            span,
        ));
    }
    let inner = Scope {
        qualifiers,
        shadowed: Vec::new(),
        sub: Some(SubContext { ctx: sub.ctx, dataset: sub_dataset, earliest: window.earliest, latest: window.latest }),
    };
    let mut terms = Vec::new();
    for c in rest {
        if let Some(f) = translate_filter(&inner, c)? {
            if f.where_only() {
                return Err(refuse(&format!("the subquery filter `{c}` needs `| where`")));
            }
            terms.push(f.render());
        }
    }
    if terms.is_empty() {
        terms.push("*".into());
    }
    let token = if sub_dataset != sub.dataset { format!("dataset={} ", sub_dataset.selector()) } else { String::new() };
    let not = if negated { "NOT " } else { "" };
    Ok(atom(format!("{field} {not}IN [{token}{} | return {ret}]", terms.join(" "))))
}

/// Split a WHERE into its top-level conjuncts.
pub(super) fn conjuncts(expr: &Expr) -> Vec<&Expr> {
    match expr {
        Expr::BinaryOp { left, op: BinaryOperator::And, right } => {
            let mut v = conjuncts(left);
            v.extend(conjuncts(right));
            v
        }
        Expr::Nested(e) if matches!(e.as_ref(), Expr::BinaryOp { op: BinaryOperator::And, .. }) => conjuncts(e),
        _ => vec![expr],
    }
}

#[derive(Default)]
struct Window {
    earliest: Option<TimeBound>,
    latest: Option<TimeBound>,
}

impl Window {
    /// Take `conjunct` as a time bound. `Ok(false)` when it is not one.
    fn take(&mut self, scope: &Scope, conjunct: &Expr) -> Result<bool, Unsupported> {
        let is_time = |e: &Expr| scope.field(e).as_deref() == Some(TIME_COLUMN);
        let (low, high) = match conjunct {
            Expr::Nested(e) => return self.take(scope, e),
            Expr::Between { expr, negated: false, low, high } if is_time(expr) => {
                (Some(low.as_ref()), Some(high.as_ref()))
            }
            Expr::BinaryOp { left, op, right } if is_time(left) || is_time(right) => {
                let (op, other) = if is_time(left) { (op.clone(), right) } else { (flip(op).unwrap_or(op.clone()), left) };
                match op {
                    BinaryOperator::Gt | BinaryOperator::GtEq => (Some(other.as_ref()), None),
                    BinaryOperator::Lt | BinaryOperator::LtEq => (None, Some(other.as_ref())),
                    _ => return Ok(false),
                }
            }
            _ => return Ok(false),
        };
        for (slot, bound, which) in [(&mut self.earliest, low, "lower"), (&mut self.latest, high, "upper")] {
            let Some(bound) = bound else { continue };
            let value = time_bound_value(bound).ok_or_else(|| {
                Unsupported::at(
                    format!("the {which} time bound `{bound}`: only the window placeholders or literal instants convert"),
                    bound.span(),
                )
            })?;
            // NAN-5630: a second bound next to the window (the hunt prompt
            // teaches `timestamp >= '2026-11-17 12:37:50'` to narrow it): the
            // tighter of the two is the Search range, once both are known.
            *slot = Some(match slot.take() {
                None => value,
                Some(TimeBound::Tightest { lower, mut bounds }) => {
                    bounds.push(value);
                    TimeBound::Tightest { lower, bounds }
                }
                Some(prev) => TimeBound::Tightest { lower: which == "lower", bounds: vec![prev, value] },
            });
        }
        Ok(true)
    }
}

/// One aggregate in the stats list.
struct Agg {
    /// The SQL expression, for ORDER BY / HAVING matching.
    sql: String,
    /// `count() as n`.
    npl: String,
    /// The output name.
    alias: String,
}

fn agg_call(scope: &Scope, expr: &Expr) -> Result<(String, String), Unsupported> {
    let unsupported = || Unsupported::at(format!("the aggregate `{expr}`"), expr.span());
    let Expr::Function(f) = expr else { return Err(unsupported()) };
    if f.over.is_some() {
        return Err(Unsupported::at("a window function", expr.span()));
    }
    if f.filter.is_some() || !f.within_group.is_empty() {
        return Err(unsupported());
    }
    let name = function_name(f).to_ascii_lowercase();
    let args = function_args(f);
    // A parametric aggregate: only `groupUniqArray(N)(x)` has an nPL
    // reading (`values(x)`, whose own cap and format the comparator reports).
    if !matches!(f.parameters, sqlparser::ast::FunctionArguments::None) {
        let capped = name == "groupuniqarray"
            && matches!(&f.parameters, FunctionArguments::List(l) if l.args.len() == 1);
        if !capped {
            return Err(unsupported());
        }
    }
    let field = |a: &Arg| -> Result<String, Unsupported> {
        match a {
            Arg::Expr(e) => scope.field(e).ok_or_else(unsupported).and_then(|f| npl_field(&f, e.span())),
            _ => Err(unsupported()),
        }
    };
    let slug = |f: &str| f.replace('.', "_");
    match (name.as_str(), args.as_slice()) {
        ("count", []) | ("count", [Arg::Star]) => Ok(("count()".into(), "count".into())),
        ("count", [a]) if is_distinct_call(f) => {
            let f = field(a)?;
            Ok((format!("dc({f})"), format!("dc_{}", slug(&f))))
        }
        ("count", [a]) => {
            let f = field(a)?;
            Ok((format!("count({f})"), format!("count_{}", slug(&f))))
        }
        ("uniqexact", [a]) if !is_distinct_call(f) => {
            let f = field(a)?;
            Ok((format!("dc({f})"), format!("dc_{}", slug(&f))))
        }
        // NAN-5657: an approximate distinct count converts to nPL's
        // approximate estdc, never to the exact dc.
        ("uniq" | "uniqcombined" | "uniqcombined64" | "uniqhll12", [a]) if !is_distinct_call(f) => {
            let f = field(a)?;
            Ok((format!("estdc({f})"), format!("estdc_{}", slug(&f))))
        }
        ("sum" | "avg" | "min" | "max", [a]) if !is_distinct_call(f) => {
            let f = field(a)?;
            Ok((format!("{name}({f})"), format!("{name}_{}", slug(&f))))
        }
        ("groupuniqarray", [a]) => {
            let f = field(a)?;
            Ok((format!("values({f})"), format!("values_{}", slug(&f))))
        }
        // NAN-5614: conditional aggregates. `count(eval(c))` compiles to
        // `countIf(c)`; `sum(if(c, x, 0))` sums the same rows `sumIf(x, c)`
        // does. The condition is rendered as an nPL eval expression and the
        // comparator checks what it compiles to.
        ("countif", [Arg::Expr(cond)]) => {
            let c = any_condition(scope, cond)?;
            Ok((format!("count(eval({c}))"), "count_if".into()))
        }
        ("sumif", [a, Arg::Expr(cond)]) => {
            let f = field(a)?;
            let c = any_condition(scope, cond)?;
            Ok((format!("sum(if({c}, {f}, 0))"), format!("sum_{}", slug(&f))))
        }
        // `last(x)` / `first(x)` are `argMax(x, timestamp)` / `argMin(x, timestamp)`.
        ("argmax" | "argmin", [a, Arg::Expr(by)]) if !is_distinct_call(f) => {
            if scope.field(by).as_deref() != Some(TIME_COLUMN) {
                return Err(Unsupported::at(
                    format!("`{expr}`: nPL first() / last() pick by timestamp only"),
                    expr.span(),
                ));
            }
            let f = field(a)?;
            let func = if name == "argmax" { "last" } else { "first" };
            Ok((format!("{func}({f})"), format!("{func}_{}", slug(&f))))
        }
        // `any(x)` is an arbitrary row's value; `first(x)` is one such value
        // (the earliest). The comparator reports the difference.
        ("any", [a]) if !is_distinct_call(f) => {
            let f = field(a)?;
            Ok((format!("first({f})"), format!("first_{}", slug(&f))))
        }
        (n, _) if n.starts_with("uniq") && n.ends_with("if") => Err(Unsupported::at(
            format!("`{expr}`: nPL dc() takes no condition, so a conditional distinct count has no nPL form"),
            expr.span(),
        )),
        _ => Err(unsupported()),
    }
}

/// An aggregate condition as an nPL eval expression (comparisons with
/// literals, IN lists, null tests, AND / OR / NOT). Anything else, and any
/// bound that names the run window (`{latest} - INTERVAL 1 DAY`), has no
/// nPL spelling.
fn eval_condition(scope: &Scope, expr: &Expr) -> Result<String, Unsupported> {
    let unsupported = |what: &str| Unsupported::at(format!("{what} in an aggregate condition: `{expr}`"), expr.span());
    if contains_subquery(expr) {
        return Err(unsupported("a subquery (nPL aggregates take no subsearch)"));
    }
    if mentions_window(expr) {
        return Err(Unsupported::at(
            format!("the aggregate condition `{expr}` is relative to the run window, which nPL cannot reference"),
            expr.span(),
        ));
    }
    if lowered_against_upper(expr) {
        return Err(unsupported("lower() against a value holding uppercase letters"));
    }
    let field = |e: &Expr| -> Result<String, Unsupported> {
        match filter_field(scope, e)? {
            Some(f) => Ok(f),
            None => Err(unsupported("a non-column operand")),
        }
    };
    Ok(match expr {
        Expr::Nested(e) => return eval_condition(scope, e),
        Expr::BinaryOp { left, op: op @ (BinaryOperator::And | BinaryOperator::Or), right } => {
            let word = if matches!(op, BinaryOperator::And) { "AND" } else { "OR" };
            format!("({}) {word} ({})", eval_condition(scope, left)?, eval_condition(scope, right)?)
        }
        Expr::UnaryOp { op: UnaryOperator::Not, expr: inner } => format!("NOT ({})", eval_condition(scope, inner)?),
        Expr::BinaryOp { left, op, right } => {
            let (field_side, lit_side, op) = if filter_field(scope, left)?.is_some() {
                (left, right, op.clone())
            } else {
                (right, left, flip(op).ok_or_else(|| unsupported("this operator"))?)
            };
            let f = field(field_side)?;
            let op = op_text(&op).ok_or_else(|| unsupported("this operator"))?;
            let v = npl_literal(lit_side)?.ok_or_else(|| unsupported("a comparison that is not with a literal"))?;
            format!("{f}{op}{v}")
        }
        Expr::In { expr: inner, target: InTarget::List(list), negated, .. } => {
            let f = field(inner)?;
            let values = list
                .iter()
                .map(|v| npl_literal(v)?.ok_or_else(|| unsupported("an IN list with a non-literal")))
                .collect::<Result<Vec<_>, _>>()?;
            let not = if *negated { "NOT " } else { "" };
            format!("{f} {not}IN ({})", values.join(", "))
        }
        Expr::IsNull(inner) => format!("isnull({})", field(inner)?),
        Expr::IsNotNull(inner) => format!("isnotnull({})", field(inner)?),
        _ => return Err(unsupported("this expression")),
    })
}

/// An aggregate condition: the column comparisons [`eval_condition`] reads,
/// else (NAN-5630) any condition an nPL eval expression can say
/// (`countIf(length(x) > 100)`).
fn any_condition(scope: &Scope, cond: &Expr) -> Result<String, Unsupported> {
    eval_condition(scope, cond).or_else(|e| {
        if contains_subquery(cond) || mentions_window(cond) {
            return Err(e);
        }
        let names = std::collections::HashMap::new();
        Ev { scope, names: &names, aggs: None }.cond(cond).map_err(|_| e)
    })
}

/// Does `expr` hold a subquery anywhere?
fn contains_subquery(expr: &Expr) -> bool {
    match expr {
        Expr::Subquery(_) | Expr::Exists { .. } => true,
        Expr::In { target: InTarget::Subquery(_), .. } => true,
        Expr::In { expr, target: InTarget::List(list), .. } => contains_subquery(expr) || list.iter().any(contains_subquery),
        Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } | Expr::IsNull(e) | Expr::IsNotNull(e) => contains_subquery(e),
        Expr::BinaryOp { left, right, .. } => contains_subquery(left) || contains_subquery(right),
        Expr::Function(f) => {
            matches!(f.args, FunctionArguments::Subquery(_))
                || function_args(f).iter().any(|a| matches!(a, Arg::Expr(e) if contains_subquery(e)))
        }
        _ => false,
    }
}

/// Does `expr` name a run-window placeholder anywhere?
fn mentions_window(expr: &Expr) -> bool {
    expr.to_string().contains("__nano_window_")
}

/// The converted query.
pub(super) struct Converted {
    pub npl: String,
    /// The Search dataset the nPL runs on (`logs`, or `signals` for SQL over
    /// the detections).
    pub dataset: Dataset,
    pub earliest: Option<TimeBound>,
    pub latest: Option<TimeBound>,
}

pub(super) fn convert(sql: &str, ctx: &ConvertContext) -> Result<Converted, Unsupported> {
    let pre = preprocess(sql)?;
    let query = parse_one(&pre).map_err(|u| {
        // sqlparser does not read ClickHouse's `LIMIT n BY … LIMIT m`; name
        // the construct rather than a parse error.
        if LIMIT_BY.is_match(&pre) {
            Unsupported::new(LIMIT_BY_REASON)
        } else {
            u
        }
    })?;
    let (query, cap) = unwrap_row_cap(&query)?;
    // NAN-5612 / NAN-5614: a query that reads the detections next to events
    // converts only when the detections sit in a plain `IN (SELECT …)` filter
    // (an nPL `[dataset=signals …]` subsearch). Any other correlation (a JOIN,
    // a derived table, a subquery in the SELECT list, an aggregating
    // subquery) has no nPL form, AI-written or not.
    let mixed = READS_SIGNALS.is_match(&pre) && !top_level_reads_signals(query, ctx);
    convert_query(query, cap, ctx).map_err(|u| {
        if mixed {
            Unsupported { reason: format!("{} ({MIXED_SIGNALS_REASON})", u.reason), ..u }.no_dataset()
        } else {
            u
        }
    })
}

/// The outer SELECT reads exactly one table, and it is the detections.
fn top_level_reads_signals(query: &Query, ctx: &ConvertContext) -> bool {
    let SetExpr::Select(select) = query.body.as_ref() else { return false };
    let [from] = select.from.as_slice() else { return false };
    if !from.joins.is_empty() {
        return false;
    }
    match &from.relation {
        TableFactor::Table { name, .. } => {
            let base = table_base(name);
            base == "signals_local" || matches!(table_kind(&base, ctx), TableKind::Signals | TableKind::SignalsTable)
        }
        _ => false,
    }
}

/// The Agent Lane runner wraps every guarded query as
/// `SELECT * FROM (<query>) LIMIT n` (`limit_wrapped`), and the query audit
/// records it that way. Read through the wrapper: its LIMIT caps the inner
/// query's rows.
fn unwrap_row_cap(query: &Query) -> Result<(&Query, Option<u64>), Unsupported> {
    let SetExpr::Select(select) = query.body.as_ref() else { return Ok((query, None)) };
    let plain_star = matches!(select.projection.as_slice(), [SelectItem::Wildcard(o)]
        if o.opt_exclude.is_none() && o.opt_except.is_none() && o.opt_replace.is_none() && o.opt_rename.is_none() && o.opt_ilike.is_none());
    let [from] = select.from.as_slice() else { return Ok((query, None)) };
    let TableFactor::Derived { subquery, sample: None, .. } = &from.relation else { return Ok((query, None)) };
    let bare = plain_star
        && check_select_shape(select, false).is_ok()
        && select.distinct.is_none()
        && from.joins.is_empty()
        && select.selection.is_none()
        && select.prewhere.is_none()
        && select.having.is_none()
        && matches!(&select.group_by, GroupByExpr::Expressions(e, m) if e.is_empty() && m.is_empty())
        && query.order_by.is_none()
        && query.with.is_none();
    if !bare {
        return Ok((query, None));
    }
    let cap = match &query.limit_clause {
        None => None,
        Some(LimitClause::LimitOffset { limit: Some(l), offset: None, limit_by }) if limit_by.is_empty() => {
            Some(positive_limit(l)?)
        }
        _ => return Ok((query, None)),
    };
    let (inner, inner_cap) = unwrap_row_cap(subquery)?;
    let cap = match (cap, inner_cap) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    Ok((inner, cap))
}

fn positive_limit(l: &Expr) -> Result<u64, Unsupported> {
    match l {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse::<u64>().ok(),
            _ => None,
        },
        _ => None,
    }
    .filter(|n| *n > 0)
    .ok_or_else(|| Unsupported::at("a LIMIT that is not a positive integer", l.span()))
}

fn convert_query(query: &Query, cap: Option<u64>, ctx: &ConvertContext) -> Result<Converted, Unsupported> {
    if query.with.is_some() {
        return Err(Unsupported::new("a WITH clause (common table expression)"));
    }
    if query.fetch.is_some() || !query.locks.is_empty() || query.settings.is_some() || query.format_clause.is_some()
        || !query.pipe_operators.is_empty() || query.for_clause.is_some()
    {
        return Err(Unsupported::new("a FETCH / SETTINGS / FORMAT / FOR clause"));
    }
    let select: &Select = match query.body.as_ref() {
        SetExpr::Select(s) => s,
        SetExpr::Query(_) => return Err(Unsupported::new("a parenthesized query")),
        _ => return Err(Unsupported::new("a UNION or other set operation")),
    };
    check_select_shape(select, false)?;

    // FROM: exactly the events table.
    let [from] = select.from.as_slice() else {
        return Err(Unsupported::new("a query over more than one table (or none)"));
    };
    if let Some(j) = from.joins.first() {
        return Err(Unsupported::at("a JOIN", j.relation.span()));
    }
    let (base, alias) = match &from.relation {
        TableFactor::Table { name, alias, args: None, sample: None, .. } => (table_base(name), alias.clone()),
        TableFactor::Derived { .. } => return Err(Unsupported::at("a subquery in FROM", from.relation.span())),
        other => return Err(Unsupported::at("this FROM target (a table function or sample)", other.span())),
    };
    let dataset = match table_kind(&base, ctx) {
        TableKind::Events => Dataset::Logs,
        // NAN-5612: the detections convert to the Search signals dataset.
        TableKind::Signals | TableKind::SignalsTable => Dataset::Signals,
        TableKind::Other(t) if t == "signals_local" => {
            return Err(Unsupported::at(SIGNALS_LOCAL_REASON, from.relation.span()).no_dataset())
        }
        TableKind::Other(t) => {
            return Err(Unsupported::at(
                format!("the table `{t}`: Search reads only the events table `{}`", ctx.events_table()),
                from.relation.span(),
            )
            .no_dataset())
        }
    };
    let mut qualifiers = vec![base.clone(), ctx.events_table().to_string(), "signals".to_string()];
    if let TableFactor::Table { name, .. } = &from.relation {
        qualifiers.push(name.to_string());
    }
    if let Some(a) = alias {
        qualifiers.push(a.name.value.clone());
    }
    let shadowed: Vec<String> = select
        .projection
        .iter()
        .filter_map(|item| match item {
            SelectItem::ExprWithAlias { expr, alias } => {
                let source = Scope::plain(qualifiers.clone()).field(expr);
                (source.as_deref() != Some(alias.value.as_str())).then(|| alias.value.clone())
            }
            _ => None,
        })
        .collect();
    // WHERE (and any explicit PREWHERE): time bounds out, the rest to nPL.
    // The window is read first: an `IN (SELECT …)` filter must run over it.
    let mut window = Window::default();
    let mut rest = Vec::new();
    {
        let window_scope = Scope::plain(qualifiers.clone());
        for clause in [select.prewhere.as_ref(), select.selection.as_ref()].into_iter().flatten() {
            for c in conjuncts(clause) {
                if !window.take(&window_scope, c)? {
                    rest.push(c);
                }
            }
        }
    }
    let scope = Scope {
        qualifiers,
        shadowed,
        sub: Some(SubContext { ctx, dataset, earliest: window.earliest.clone(), latest: window.latest.clone() }),
    };
    // NAN-5630: the projection first. A computed column (`expr AS name`)
    // becomes an nPL `eval` (or a `bin` for a time bucket) before `stats` /
    // `table`; WHERE, GROUP BY, HAVING and ORDER BY may name it (ClickHouse
    // resolves a SELECT alias in every clause of its SELECT).
    let mut plan = Plan::default();
    plan.taken = select
        .projection
        .iter()
        .filter_map(|i| match i {
            SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.clone()),
            _ => None,
        })
        .collect();
    for item in &select.projection {
        if let SelectItem::ExprWithAlias { expr, alias } = item {
            if !contains_aggregate(expr) {
                if let Some(f) = scope.field(expr) {
                    if f != alias.value {
                        plan.names.insert(alias.value.clone(), npl_field(&f, expr.span())?);
                    }
                }
            }
        }
    }
    let mut star = false;
    // The SELECT items in order, as nPL output names.
    let mut items: Vec<Item> = Vec::new();
    let mut columns: Vec<(String, Option<String>)> = Vec::new(); // (field, alias)
    let mut aggs: Vec<Agg> = Vec::new();
    // Computed columns: (nPL name, SQL expression), in SELECT order.
    let mut computed: Vec<(String, &Expr)> = Vec::new();
    // Expressions over aggregates (`countIf(c) / count() AS ratio`).
    let mut post_items: Vec<(String, &Expr)> = Vec::new();
    for item in &select.projection {
        let (expr, alias) = match item {
            SelectItem::Wildcard(opts) => {
                if opts.opt_exclude.is_some() || opts.opt_except.is_some() || opts.opt_replace.is_some()
                    || opts.opt_rename.is_some() || opts.opt_ilike.is_some()
                {
                    return Err(Unsupported::new("a `*` with EXCEPT / REPLACE"));
                }
                star = true;
                items.push(Item::Star);
                continue;
            }
            SelectItem::UnnamedExpr(e) => (e, None),
            SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias.value.clone())),
            other => return Err(Unsupported::at("this select item", other.span())),
        };
        if contains_aggregate(expr) {
            if is_aggregate_call(expr) {
                let hoisted = hoist_agg_args(&scope, &mut plan, expr)?;
                let (npl, default_alias) = agg_call(&scope, &hoisted)?;
                let alias = alias.unwrap_or(default_alias);
                if !NPL_ALIAS.is_match(&alias) {
                    return Err(Unsupported::at(format!("the output name `{alias}`"), expr.span()));
                }
                items.push(Item::Named(alias.clone()));
                aggs.push(Agg { sql: expr.to_string(), npl, alias });
            } else {
                let name = alias.ok_or_else(|| {
                    Unsupported::at(format!("the unnamed expression over aggregates `{expr}` (name it with AS)"), expr.span())
                })?;
                if !NPL_ALIAS.is_match(&name) {
                    return Err(Unsupported::at(format!("the output name `{name}`"), expr.span()));
                }
                items.push(Item::Named(name.clone()));
                post_items.push((name, expr));
            }
        } else if let Some(f) = scope.field(expr) {
            let field = npl_field(&f, expr.span())?;
            items.push(Item::Named(alias.clone().unwrap_or_else(|| field.clone())));
            columns.push((field, alias));
        } else {
            let name = match alias {
                Some(a) => a,
                None => plan.fresh_visible(expr),
            };
            if !NPL_ALIAS.is_match(&name) {
                return Err(Unsupported::at(format!("the output name `{name}`"), expr.span()));
            }
            if computed.iter().any(|(n, _)| *n == name) {
                return Err(Unsupported::at(format!("two SELECT items named `{name}`"), expr.span()));
            }
            plan.names.insert(name.clone(), name.clone());
            plan.computed.push((expr.to_string(), name.clone()));
            items.push(Item::Named(name.clone()));
            computed.push((name, expr));
        }
    }
    let computed_names: Vec<String> = computed.iter().map(|(n, _)| n.clone()).collect();

    // WHERE: plain filters stay search terms; a filter on a computed column,
    // or one that only an eval expression can say (`length(x) > 1000`), runs
    // as `| where` after the evals.
    let mut head: Vec<Filter> = Vec::new();
    let mut wheres: Vec<Filter> = Vec::new();
    let mut late_wheres: Vec<String> = Vec::new();
    for c in rest {
        if mentions_any(c, &computed_names) {
            late_wheres.push(plan.ev(&scope).cond(c)?);
            continue;
        }
        let f = match translate_filter(&scope, c) {
            Ok(f) => f,
            Err(e) => match plan.ev(&scope).cond(c) {
                Ok(text) => {
                    late_wheres.push(text);
                    continue;
                }
                Err(_) => return Err(e),
            },
        };
        if let Some(f) = f {
            if f.where_only() {
                wheres.push(f);
            } else {
                head.push(f);
            }
        }
    }

    let group_exprs: Vec<&Expr> = match &select.group_by {
        GroupByExpr::Expressions(exprs, modifiers) => {
            if !modifiers.is_empty() {
                return Err(Unsupported::new("GROUP BY … WITH ROLLUP / CUBE / TOTALS"));
            }
            exprs.iter().collect()
        }
        GroupByExpr::All(_) => return Err(Unsupported::new("GROUP BY ALL")),
    };
    let grouped = !aggs.is_empty() || !post_items.is_empty() || !group_exprs.is_empty();

    let mut npl = String::new();
    let mut search: Vec<String> = head.iter().map(Filter::render).collect();
    if search.is_empty() {
        search.push("*".into());
    }
    npl.push_str(&search.join(" "));
    if !wheres.is_empty() {
        npl.push_str(" | where ");
        npl.push_str(&wheres.iter().map(Filter::render_operand).collect::<Vec<_>>().join(" AND "));
    }

    // Output names a later clause may reference, mapped to how nPL names them.
    let mut outputs: Vec<(String, String)> = Vec::new(); // (sql name, npl name)
    // Evals after `stats`.
    let mut post: Vec<(String, String)> = Vec::new(); // (name, nPL expression)
    let mut keys: Vec<String> = Vec::new();
    let mut having: Option<String> = None;
    if grouped {
        for g in &group_exprs {
            let key = if let Some(n) = super::canon::positional(g) {
                match items.get(n - 1) {
                    Some(Item::Named(name)) => match columns.iter().find(|(f, a)| a.as_deref().unwrap_or(f) == name) {
                        Some((f, _)) => f.clone(),
                        None => name.clone(),
                    },
                    _ => return Err(Unsupported::at(format!("`GROUP BY {g}` names no SELECT item"), g.span())),
                }
            } else if let Some(name) = scope.field(g) {
                columns
                    .iter()
                    .find(|(_, alias)| alias.as_deref() == Some(name.as_str()))
                    .map(|(f, _)| f.clone())
                    .unwrap_or(name)
            } else if let Some((_, name)) = plan.computed.iter().find(|(sql, _)| *sql == g.to_string()) {
                name.clone()
            } else if contains_aggregate(g) {
                return Err(Unsupported::at(format!("the GROUP BY expression `{g}`"), g.span()));
            } else {
                // A key the SELECT does not return: computed, then dropped.
                let name = plan.fresh("_g");
                plan.pre_hidden(&scope, &name, g)?;
                plan.drop.push(name.clone());
                name
            };
            keys.push(npl_field(&key, g.span())?);
        }
        if star {
            return Err(Unsupported::new("`*` in an aggregating query"));
        }
        for (field, alias) in &columns {
            if !keys.contains(field) {
                return Err(Unsupported::new(format!("the column `{field}` is neither grouped nor aggregated")));
            }
            outputs.push((alias.clone().unwrap_or_else(|| field.clone()), field.clone()));
            outputs.push((field.clone(), field.clone()));
        }
        // A computed key is an eval before `stats`; any other computed
        // column is computed from the keys after it (and before it as well
        // when WHERE filters on it).
        for (name, expr) in &computed {
            let filtered = select.selection.iter().chain(select.prewhere.iter()).any(|w| mentions_any(w, &[name.clone()]));
            if keys.contains(name) || filtered || plan.needed.contains(name) {
                plan.pre_computed(&scope, name, expr)?;
            }
            if !keys.contains(name) {
                post.push((name.clone(), plan.ev(&scope).expr(expr)?));
            }
            outputs.push((name.clone(), name.clone()));
        }
        for k in &keys {
            outputs.push((k.clone(), k.clone()));
        }
        for a in &aggs {
            outputs.push((a.alias.clone(), a.alias.clone()));
        }
        // Expressions over aggregates: every aggregate in them gets an
        // output name (a projected one, else a hidden one), then an eval
        // after `stats` computes the item.
        for (name, expr) in &post_items {
            let names = plan.name_aggregates(&scope, &mut aggs, expr)?;
            let text = plan.ev(&scope).with_aggs(&names).expr(expr)?;
            post.push((name.clone(), text));
            outputs.push((name.clone(), name.clone()));
        }
        // HAVING: aggregates it names that the SELECT does not return are
        // computed too, then dropped.
        if let Some(h) = &select.having {
            let names = plan.name_aggregates(&scope, &mut aggs, h)?;
            let rewritten = rewrite_outputs(h, &names);
            let post_scope = Scope::plain(Vec::new());
            having = match translate_filter(&post_scope, &rewritten) {
                Ok(f) => f.map(|f| f.render()),
                Err(e) => Some(plan.ev(&post_scope).cond(&rewritten).map_err(|_| e)?),
            };
        }
        // ORDER BY may name aggregates the SELECT does not return.
        if let Some(order) = &query.order_by {
            if let OrderByKind::Expressions(order_items) = &order.kind {
                for item in order_items {
                    if contains_aggregate(&item.expr) && super::canon::positional(&item.expr).is_none() {
                        plan.name_aggregates(&scope, &mut aggs, &item.expr)?;
                    }
                }
            }
        }
        if aggs.is_empty() {
            return Err(Unsupported::new("GROUP BY without an aggregate (a DISTINCT)"));
        }
        for a in &aggs {
            outputs.push((a.alias.clone(), a.alias.clone()));
        }
    } else {
        if select.having.is_some() {
            return Err(Unsupported::new("HAVING without an aggregate"));
        }
        for (field, alias) in &columns {
            outputs.push((field.clone(), field.clone()));
            if let Some(a) = alias {
                outputs.push((a.clone(), field.clone()));
            }
        }
        for (name, expr) in &computed {
            plan.pre_computed(&scope, name, expr)?;
            outputs.push((name.clone(), name.clone()));
        }
    }

    // ORDER BY → sort.
    let mut sort_text = String::new();
    if let Some(order) = &query.order_by {
        if order.interpolate.is_some() {
            return Err(Unsupported::new("ORDER BY … INTERPOLATE"));
        }
        let OrderByKind::Expressions(order_items) = &order.kind else {
            return Err(Unsupported::new("ORDER BY ALL"));
        };
        let mut sort_keys = Vec::new();
        for item in order_items {
            if item.with_fill.is_some() || item.options.nulls_first.is_some() {
                return Err(Unsupported::at("ORDER BY … WITH FILL / NULLS FIRST|LAST", item.expr.span()));
            }
            let name = match order_name(&scope, &item.expr, &aggs, &outputs, grouped, &items, &plan) {
                Some(n) => n,
                // An expression: computed into a hidden column to sort by.
                None if !contains_aggregate(&item.expr) && !grouped => {
                    let name = plan.fresh("_o");
                    plan.pre_hidden(&scope, &name, &item.expr)?;
                    if star {
                        plan.drop.push(name.clone());
                    }
                    name
                }
                None if grouped => {
                    let names = plan.name_aggregates(&scope, &mut aggs, &item.expr)?;
                    let text = plan.ev(&scope).with_aggs(&names).expr(&item.expr).map_err(|_| {
                        Unsupported::at(
                            format!("the ORDER BY key `{}`: nPL sorts by fields and stats outputs only", item.expr),
                            item.expr.span(),
                        )
                    })?;
                    let name = plan.fresh("_o");
                    post.push((name.clone(), text));
                    plan.drop.push(name.clone());
                    name
                }
                None => {
                    return Err(Unsupported::at(
                        format!("the ORDER BY key `{}`: nPL sorts by fields and stats outputs only", item.expr),
                        item.expr.span(),
                    ))
                }
            };
            let desc = matches!(item.options.sort, Some(OrderBySort::Desc));
            sort_keys.push(if desc { format!("-{name}") } else { name });
        }
        sort_text.push_str(" | sort ");
        sort_text.push_str(&sort_keys.join(", "));
    }

    // The evals before `stats` / `table`, then the filters on them.
    npl.push_str(&plan.render_pre());
    if !late_wheres.is_empty() {
        npl.push_str(" | where ");
        npl.push_str(
            &late_wheres.iter().map(|w| if late_wheres.len() > 1 { format!("({w})") } else { w.clone() }).collect::<Vec<_>>().join(" AND "),
        );
    }
    if grouped {
        // Aggregates HAVING / ORDER BY need were added as they were met:
        // the stats list is written from the final set.
        npl.push_str(" | stats ");
        npl.push_str(&aggs.iter().map(|a| format!("{} as {}", a.npl, a.alias)).collect::<Vec<_>>().join(", "));
        if !keys.is_empty() {
            npl.push_str(" by ");
            npl.push_str(&keys.join(", "));
        }
        if !post.is_empty() {
            npl.push_str(" | eval ");
            npl.push_str(&post.iter().map(|(n, e)| format!("{n}={e}")).collect::<Vec<_>>().join(", "));
        }
        if let Some(h) = &having {
            npl.push_str(" | where ");
            npl.push_str(h);
        }
    }
    npl.push_str(&sort_text);

    // LIMIT (and any runner row cap around the query) → head.
    let limit = match &query.limit_clause {
        None => None,
        Some(LimitClause::LimitOffset { limit, offset, limit_by }) => {
            if offset.is_some() {
                return Err(Unsupported::new("LIMIT … OFFSET"));
            }
            if !limit_by.is_empty() {
                return Err(Unsupported::new(LIMIT_BY_REASON));
            }
            limit.as_ref().map(positive_limit).transpose()?
        }
        Some(_) => return Err(Unsupported::new("LIMIT offset, count")),
    };
    let limit = match (limit, cap) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    if let Some(n) = limit {
        npl.push_str(&format!(" | head {n}"));
    }

    if !plan.drop.is_empty() && (grouped || star) {
        npl.push_str(" | fields - ");
        npl.push_str(&plan.drop.join(", "));
    }
    if !grouped && !star {
        let visible: Vec<String> = items
            .iter()
            .filter_map(|i| match i {
                Item::Named(n) => Some(
                    columns
                        .iter()
                        .find(|(f, a)| a.as_deref().unwrap_or(f) == n)
                        .map(|(f, _)| f.clone())
                        .unwrap_or_else(|| n.clone()),
                ),
                Item::Star => None,
            })
            .collect();
        if !visible.is_empty() {
            npl.push_str(" | table ");
            npl.push_str(&visible.join(", "));
        }
    }

    Ok(Converted { npl, dataset, earliest: window.earliest, latest: window.latest })
}

/// A SELECT item as nPL names it.
enum Item {
    Named(String),
    Star,
}

/// A stage before `stats` / `table`.
enum Stage {
    /// `name=<nPL eval expression>`.
    Eval(String, String),
    /// `bin timestamp span=<span> as name`.
    Bin(String, String),
}

impl Stage {
    fn name(&self) -> &str {
        match self {
            Stage::Eval(n, _) | Stage::Bin(n, _) => n,
        }
    }
}

/// NAN-5630: what the nPL computes on the way. Computed SELECT columns and
/// hidden helpers (an aggregate's computed argument, a GROUP BY / ORDER BY
/// expression the SELECT does not return) are evals before `stats`;
/// aggregates only HAVING / ORDER BY / an expression over aggregates need
/// are extra `stats` outputs; hidden names are dropped at the end.
#[derive(Default)]
struct Plan {
    /// A SQL name an expression may use → the nPL name: a renaming alias
    /// (`device.hostname AS host`) and every computed column.
    names: std::collections::HashMap<String, String>,
    /// (SQL text, nPL name) of each computed SELECT column.
    computed: Vec<(String, String)>,
    /// Computed columns a pre-`stats` stage needs even when they are not keys.
    needed: std::collections::HashSet<String>,
    /// Computed columns' stages, then the hidden ones.
    pre: Vec<Stage>,
    hidden: Vec<Stage>,
    /// Hidden output names to drop at the end.
    drop: Vec<String>,
    counter: usize,
    /// Every name the SQL or the plan already uses (no hidden name may
    /// collide with one).
    taken: std::collections::HashSet<String>,
}

impl Plan {
    fn ev<'a>(&'a self, scope: &'a Scope<'a>) -> Ev<'a> {
        Ev { scope, names: &self.names, aggs: None }
    }

    /// A fresh hidden name.
    fn fresh(&mut self, prefix: &str) -> String {
        loop {
            self.counter += 1;
            let name = format!("{prefix}{}", self.counter);
            if !self.taken.contains(&name) && !self.names.contains_key(&name) {
                self.taken.insert(name.clone());
                return name;
            }
        }
    }

    /// A visible name for an unnamed computed column (its SQL text, as a
    /// field name: `toStartOfHour(timestamp)` → `tostartofhour_timestamp`).
    fn fresh_visible(&mut self, expr: &Expr) -> String {
        let mut slug = String::new();
        for c in expr.to_string().chars() {
            if c.is_ascii_alphanumeric() {
                slug.push(c.to_ascii_lowercase());
            } else if !slug.ends_with('_') {
                slug.push('_');
            }
        }
        let mut slug: String = slug.trim_matches('_').chars().take(40).collect();
        slug = slug.trim_end_matches('_').to_string();
        if !slug.starts_with(|c: char| c.is_ascii_alphabetic()) {
            slug = format!("e_{slug}");
        }
        let taken = |s: &str| self.names.contains_key(s) || self.taken.contains(s);
        if !taken(&slug) {
            return slug;
        }
        let mut n = 2;
        while taken(&format!("{slug}_{n}")) {
            n += 1;
        }
        format!("{slug}_{n}")
    }

    fn stage(&self, scope: &Scope, name: &str, expr: &Expr) -> Result<Stage, Unsupported> {
        Ok(match bucket_span(scope, expr) {
            Some(span) => Stage::Bin(name.to_string(), span),
            None => Stage::Eval(name.to_string(), self.ev(scope).expr(expr)?),
        })
    }

    /// The pre-`stats` stage of a computed SELECT column (once).
    fn pre_computed(&mut self, scope: &Scope, name: &str, expr: &Expr) -> Result<(), Unsupported> {
        if self.pre.iter().any(|s| s.name() == name) {
            return Ok(());
        }
        let stage = self.stage(scope, name, expr)?;
        self.pre.push(stage);
        Ok(())
    }

    /// A hidden pre-`stats` value.
    fn pre_hidden(&mut self, scope: &Scope, name: &str, expr: &Expr) -> Result<(), Unsupported> {
        let stage = self.stage(scope, name, expr)?;
        self.hidden.push(stage);
        Ok(())
    }

    /// Every aggregate call in `expr` gets a `stats` output: a projected
    /// one if the SELECT computes it, else a hidden one. Returns every
    /// (SQL text, output name) pair.
    fn name_aggregates(
        &mut self,
        scope: &Scope,
        aggs: &mut Vec<Agg>,
        expr: &Expr,
    ) -> Result<Vec<(String, String)>, Unsupported> {
        let mut calls = Vec::new();
        aggregate_calls(expr, &mut calls);
        for call in calls {
            let text = call.to_string();
            if aggs.iter().any(|a| a.sql == text) {
                continue;
            }
            let hoisted = hoist_agg_args(scope, self, call)?;
            let (npl, _) = agg_call(scope, &hoisted)?;
            let alias = self.fresh("_a");
            self.drop.push(alias.clone());
            aggs.push(Agg { sql: text, npl, alias });
        }
        Ok(aggs.iter().map(|a| (a.sql.clone(), a.alias.clone())).collect())
    }

    /// The pre-`stats` stages as nPL: consecutive evals share one `eval`
    /// unless one reads a name another in it defines.
    fn render_pre(&self) -> String {
        let mut out = String::new();
        let mut group: Vec<(&str, &str)> = Vec::new();
        let flush = |group: &mut Vec<(&str, &str)>, out: &mut String| {
            if !group.is_empty() {
                out.push_str(" | eval ");
                out.push_str(&group.iter().map(|(n, e)| format!("{n}={e}")).collect::<Vec<_>>().join(", "));
                group.clear();
            }
        };
        for stage in self.pre.iter().chain(self.hidden.iter()) {
            match stage {
                Stage::Eval(name, expr) => {
                    if group.iter().any(|(n, _)| mentions_word(expr, n) || *n == name.as_str()) {
                        flush(&mut group, &mut out);
                    }
                    group.push((name, expr));
                }
                Stage::Bin(name, span) => {
                    flush(&mut group, &mut out);
                    out.push_str(&format!(" | bin {TIME_COLUMN} span={span} as {name}"));
                }
            }
        }
        flush(&mut group, &mut out);
        out
    }
}

/// Does `text` hold `word` as a whole word (an nPL field reference)?
fn mentions_word(text: &str, word: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.';
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

/// Does `expr` name any of `names` (a SELECT alias)? Conservative: a
/// construct it does not look into counts as naming one.
fn mentions_any(expr: &Expr, names: &[String]) -> bool {
    if names.is_empty() {
        return false;
    }
    let any = |e: &Expr| mentions_any(e, names);
    match expr {
        Expr::Identifier(i) => names.contains(&i.value),
        Expr::CompoundIdentifier(_) | Expr::Value(_) => false,
        Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } | Expr::IsNull(e) | Expr::IsNotNull(e) => any(e),
        Expr::BinaryOp { left, right, .. } => any(left) || any(right),
        Expr::Between { expr, low, high, .. } => any(expr) || any(low) || any(high),
        Expr::In { expr, target: InTarget::List(list), .. } => any(expr) || list.iter().any(any),
        // A subquery's names are its own table's, not this SELECT's aliases.
        Expr::In { expr, target: InTarget::Subquery(_), .. } => any(expr),
        Expr::Cast { expr, .. } => any(expr),
        Expr::Like { expr, pattern, .. } | Expr::ILike { expr, pattern, .. } => any(expr) || any(pattern),
        Expr::Function(f) => function_args(f).iter().any(|a| match a {
            Arg::Expr(e) => any(e),
            _ => true,
        }),
        Expr::Case { operand, conditions, else_result, .. } => {
            operand.as_deref().is_some_and(any)
                || conditions.iter().any(|w| any(&w.condition) || any(&w.result))
                || else_result.as_deref().is_some_and(any)
        }
        Expr::CompoundFieldAccess { root, .. } => any(root),
        Expr::Interval(i) => any(&i.value),
        _ => true,
    }
}

/// The aggregate calls inside `expr` (not looking inside them).
fn aggregate_calls<'e>(expr: &'e Expr, out: &mut Vec<&'e Expr>) {
    match expr {
        Expr::Function(f) if is_aggregate_name(&function_name(f)) => out.push(expr),
        Expr::Function(f) => {
            for a in function_args(f) {
                if let Arg::Expr(e) = a {
                    aggregate_calls(e, out);
                }
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            aggregate_calls(left, out);
            aggregate_calls(right, out);
        }
        Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } => aggregate_calls(e, out),
        _ => {}
    }
}

/// Is `expr` one aggregate call (`count()`, `uniq(x)`, …)?
fn is_aggregate_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Function(f) if is_aggregate_name(&function_name(f)))
}

/// `avg(length(x))`: an aggregate whose value argument is computed. The
/// argument becomes a hidden eval before `stats` (or the computed SELECT
/// column with the same expression), and the aggregate reads that field.
fn hoist_agg_args(scope: &Scope, plan: &mut Plan, expr: &Expr) -> Result<Expr, Unsupported> {
    let Expr::Function(f) = expr else { return Ok(expr.clone()) };
    let name = function_name(f).to_ascii_lowercase();
    // A condition argument (countIf) stays a condition; argMax's `by`
    // stays the timestamp.
    if name == "countif" || f.over.is_some() {
        return Ok(expr.clone());
    }
    let FunctionArguments::List(list) = &f.args else { return Ok(expr.clone()) };
    let Some(FunctionArg::Unnamed(FunctionArgExpr::Expr(first))) = list.args.first() else { return Ok(expr.clone()) };
    if scope.field(first).is_some() || contains_aggregate(first) {
        return Ok(expr.clone());
    }
    let field = match plan.computed.iter().find(|(sql, _)| *sql == first.to_string()) {
        Some((_, n)) => {
            let n = n.clone();
            plan.needed.insert(n.clone());
            n
        }
        None => {
            // One hidden field per distinct expression.
            let stage = plan.stage(scope, "_", first)?;
            let same = plan.hidden.iter().find(|s| match (s, &stage) {
                (Stage::Eval(_, a), Stage::Eval(_, b)) | (Stage::Bin(_, a), Stage::Bin(_, b)) => a == b,
                _ => false,
            });
            match same {
                Some(s) => s.name().to_string(),
                None => {
                    let n = plan.fresh("_x");
                    plan.pre_hidden(scope, &n, first)?;
                    n
                }
            }
        }
    };
    let mut f = f.clone();
    if let FunctionArguments::List(list) = &mut f.args {
        list.args[0] = FunctionArg::Unnamed(FunctionArgExpr::Expr(Expr::Identifier(sqlparser::ast::Ident::new(field))));
    }
    Ok(Expr::Function(f))
}

/// A time bucket over the time column, as an nPL `bin` span:
/// `toStartOfHour(timestamp)` → `1h`, `toStartOfInterval(timestamp,
/// INTERVAL 5 MINUTE)` → `5m`. The comparator proves what the generator's
/// bucket function is.
fn bucket_span(scope: &Scope, expr: &Expr) -> Option<String> {
    let Expr::Function(f) = expr else { return None };
    if f.over.is_some() || !matches!(f.parameters, FunctionArguments::None) {
        return None;
    }
    let name = function_name(f).to_ascii_lowercase();
    let args = function_args(f);
    let Some(Arg::Expr(ts)) = args.first() else { return None };
    if scope.field(ts).as_deref() != Some(TIME_COLUMN) {
        return None;
    }
    let secs: u64 = match (name.as_str(), args.len()) {
        ("tostartofminute", 1) => 60,
        ("tostartoffiveminutes", 1) => 300,
        ("tostartoftenminutes", 1) => 600,
        ("tostartoffifteenminutes", 1) => 900,
        ("tostartofhour", 1) => 3600,
        ("tostartofday", 1) => 86_400,
        ("tostartofinterval", 2) => {
            let Arg::Expr(width) = &args[1] else { return None };
            interval_seconds(width)?
        }
        _ => return None,
    };
    Some(if secs % 86_400 == 0 {
        format!("{}d", secs / 86_400)
    } else if secs % 3600 == 0 {
        format!("{}h", secs / 3600)
    } else if secs % 60 == 0 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    })
}

/// `INTERVAL n unit` / `toIntervalUnit(n)` in seconds (second to day).
fn interval_seconds(expr: &Expr) -> Option<u64> {
    let unit_secs = |u: &str| -> Option<u64> {
        let u = u.to_ascii_lowercase();
        Some(match u.strip_suffix('s').unwrap_or(&u) {
            "second" => 1,
            "minute" => 60,
            "hour" => 3600,
            "day" => 86_400,
            _ => return None,
        })
    };
    let number = |e: &Expr| match e {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse::<u64>().ok().filter(|n| *n > 0),
            _ => None,
        },
        _ => None,
    };
    match expr {
        Expr::Interval(i) if i.last_field.is_none() => {
            number(&i.value)?.checked_mul(unit_secs(&i.leading_field.as_ref()?.to_string())?)
        }
        Expr::Function(f) => {
            let unit = function_name(f).to_ascii_lowercase();
            let unit = unit.strip_prefix("tointerval")?;
            match function_args(f).as_slice() {
                [Arg::Expr(n)] => number(n)?.checked_mul(unit_secs(unit)?),
                _ => None,
            }
        }
        _ => None,
    }
}

/// NAN-5630: a SQL expression as an nPL eval expression. Only functions
/// whose nPL counterpart the comparator can prove (or report) convert.
struct Ev<'a> {
    scope: &'a Scope<'a>,
    names: &'a std::collections::HashMap<String, String>,
    /// After `stats`: an aggregate call → its output name.
    aggs: Option<&'a [(String, String)]>,
}

impl<'a> Ev<'a> {
    fn with_aggs(self, aggs: &'a [(String, String)]) -> Ev<'a> {
        Ev { aggs: Some(aggs), ..self }
    }

    fn refuse(e: &Expr, what: &str) -> Unsupported {
        Unsupported::at(format!("{what} has no nPL eval form: `{e}`"), e.span())
    }

    fn field(&self, e: &Expr) -> Result<String, Unsupported> {
        let f = self.scope.field(e).ok_or_else(|| Self::refuse(e, "this reference"))?;
        let qualified =
            matches!(e, Expr::CompoundIdentifier(p) if p.len() > 1 && self.scope.qualifiers.iter().any(|q| *q == p[0].value));
        if qualified && self.names.contains_key(&f) {
            // `t.col` is the table's column, but a SELECT alias of that
            // name is what nPL's field holds by then.
            return Err(Unsupported::at(
                format!("`{e}` names a column a SELECT alias of the same name shadows"),
                e.span(),
            ));
        }
        if let Some(n) = self.names.get(&f) {
            return Ok(n.clone());
        }
        npl_field(&f, e.span())
    }

    fn expr(&self, e: &Expr) -> Result<String, Unsupported> {
        if let Some(aggs) = self.aggs {
            let text = e.to_string();
            if let Some((_, n)) = aggs.iter().find(|(s, _)| *s == text) {
                return Ok(n.clone());
            }
        }
        if is_aggregate_call(e) {
            return Err(Self::refuse(e, "an aggregate inside an expression"));
        }
        if mentions_window(e) {
            return Err(Unsupported::at(
                format!("`{e}` is relative to the run window, which nPL cannot reference"),
                e.span(),
            ));
        }
        match e {
            Expr::Nested(inner) => Ok(format!("({})", self.expr(inner)?)),
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => self.field(e),
            Expr::Value(v) if matches!(v.value, Value::Null) => Err(Self::refuse(e, "NULL")),
            Expr::Value(_) => npl_literal(e)?.ok_or_else(|| Self::refuse(e, "this literal")),
            Expr::UnaryOp { op: UnaryOperator::Minus, .. } => {
                npl_literal(e)?.ok_or_else(|| Self::refuse(e, "a negated expression"))
            }
            Expr::UnaryOp { op: UnaryOperator::Not, .. } => self.cond(e),
            Expr::BinaryOp { left, op, right } => {
                let arith = match op {
                    BinaryOperator::Plus => "+",
                    BinaryOperator::Minus => "-",
                    BinaryOperator::Multiply => "*",
                    BinaryOperator::Divide => "/",
                    _ => return self.cond(e),
                };
                Ok(format!("({} {arith} {})", self.expr(left)?, self.expr(right)?))
            }
            Expr::In { .. } | Expr::Like { .. } | Expr::ILike { .. } | Expr::IsNull(_) | Expr::IsNotNull(_) => {
                self.cond(e)
            }
            Expr::Case { operand: None, conditions, else_result, .. } => {
                let mut parts = Vec::new();
                for w in conditions {
                    parts.push(format!("{}, {}", self.cond(&w.condition)?, self.expr(&w.result)?));
                }
                if let Some(other) = else_result {
                    parts.push(format!("true, {}", self.expr(other)?));
                }
                Ok(format!("case({})", parts.join(", ")))
            }
            Expr::CompoundFieldAccess { root, access_chain } => match access_chain.as_slice() {
                [sqlparser::ast::AccessExpr::Subscript(sqlparser::ast::Subscript::Index { index })] => {
                    let i = super::canon::positional(index).ok_or_else(|| Self::refuse(e, "a non-literal subscript"))?;
                    Ok(format!("mvindex({}, {})", self.expr(root)?, i - 1))
                }
                _ => Err(Self::refuse(e, "this access")),
            },
            Expr::Function(f) => self.function(f, e),
            _ => Err(Self::refuse(e, "this expression")),
        }
    }

    fn function(&self, f: &sqlparser::ast::Function, e: &Expr) -> Result<String, Unsupported> {
        let refuse = || Self::refuse(e, &format!("the function `{}`", function_name(f)));
        if f.over.is_some()
            || f.filter.is_some()
            || !f.within_group.is_empty()
            || !matches!(f.parameters, FunctionArguments::None)
            || is_distinct_call(f)
        {
            return Err(refuse());
        }
        let name = function_name(f).to_ascii_lowercase();
        let args: Vec<&Expr> = function_args(f)
            .into_iter()
            .map(|a| match a {
                Arg::Expr(e) => Ok(e),
                _ => Err(refuse()),
            })
            .collect::<Result<_, _>>()?;
        let call = |npl: &str, arity: std::ops::RangeInclusive<usize>| -> Result<String, Unsupported> {
            if !arity.contains(&args.len()) {
                return Err(refuse());
            }
            let parts = args.iter().map(|a| self.expr(a)).collect::<Result<Vec<_>, _>>()?;
            Ok(format!("{npl}({})", parts.join(", ")))
        };
        match name.as_str() {
            // lowerUTF8 / upperUTF8 / lengthUTF8 fold or count characters;
            // nPL's lower() / upper() / len() fold ASCII and count bytes.
            "lower" | "lcase" => call("lower", 1..=1),
            "upper" | "ucase" => call("upper", 1..=1),
            "length" => call("len", 1..=1),
            "concat" => call("concat", 1..=64),
            "tostring" => call("tostring", 1..=1),
            "domain" => call("extract_domain", 1..=1),
            "cuttofirstsignificantsubdomain" => call("extract_root_domain", 1..=1),
            "topleveldomain" => call("extract_tld", 1..=1),
            "path" => call("extract_path", 1..=1),
            "protocol" => call("extract_protocol", 1..=1),
            "ipv4numtostring" => call("int_to_ipv4", 1..=1),
            "replaceall" | "replace" => call("replace", 3..=3),
            "trimboth" | "trim" => call("trim", 1..=1),
            "trimleft" => call("ltrim", 1..=1),
            "trimright" => call("rtrim", 1..=1),
            "abs" => call("abs", 1..=1),
            "floor" => call("floor", 1..=1),
            "ceil" | "ceiling" => call("ceil", 1..=1),
            "round" => call("round", 1..=2),
            "tohour" => call("hour", 1..=1),
            "tominute" => call("minute", 1..=1),
            "tosecond" => call("second", 1..=1),
            "toyear" => call("year", 1..=1),
            "tomonth" => call("month", 1..=1),
            "todayofmonth" => call("day", 1..=1),
            "todayofweek" => call("dayofweek", 1..=1),
            "todate" => call("to_date", 1..=1),
            "tostartofhour" => call("start_of_hour", 1..=1),
            "tostartofday" => call("start_of_day", 1..=1),
            "tostartofminute" if args.len() == 1 => Ok(format!("date_trunc(\"minute\", {})", self.expr(args[0])?)),
            "splitbychar" | "splitbystring" if args.len() == 2 => {
                Ok(format!("split({}, {})", self.expr(args[1])?, self.expr(args[0])?))
            }
            "if" if args.len() == 3 => {
                Ok(format!("if({}, {}, {})", self.cond(args[0])?, self.expr(args[1])?, self.expr(args[2])?))
            }
            "multiif" if args.len() >= 3 && args.len() % 2 == 1 => {
                let mut parts = Vec::new();
                for pair in args[..args.len() - 1].chunks(2) {
                    parts.push(format!("{}, {}", self.cond(pair[0])?, self.expr(pair[1])?));
                }
                parts.push(format!("true, {}", self.expr(args[args.len() - 1])?));
                Ok(format!("case({})", parts.join(", ")))
            }
            // A condition as a value: only the forms `cond` reads itself
            // (never back through here, which would not terminate).
            "isnull" | "isnotnull" if args.len() == 1 => self.cond(e),
            "match" if args.len() == 2 => self.cond(e),
            _ => Err(refuse()),
        }
    }

    /// A comparison operand: a plain column through `lower()` reads as the
    /// column (nPL compares strings case-insensitively).
    fn operand(&self, e: &Expr) -> Result<String, Unsupported> {
        if let Expr::Function(f) = e {
            if function_name(f).eq_ignore_ascii_case("lower") {
                if let [Arg::Expr(inner)] = function_args(f).as_slice() {
                    if self.scope.field(inner).is_some() {
                        return self.field(inner);
                    }
                }
            }
        }
        self.expr(e)
    }

    /// A condition, as nPL writes one in `eval` / `where`.
    fn cond(&self, e: &Expr) -> Result<String, Unsupported> {
        let refuse = |what: &str| Unsupported::at(format!("{what} in an nPL condition: `{e}`"), e.span());
        if contains_subquery(e) {
            return Err(refuse("a subquery (only a plain `col IN (SELECT …)` filter is an nPL subsearch)"));
        }
        if lowered_against_upper(e) {
            return Err(Unsupported::at(
                format!("`{e}` compares lower() with a value holding uppercase letters, so the SQL never matches it"),
                e.span(),
            ));
        }
        if mentions_window(e) {
            return Err(Unsupported::at(
                format!("the condition `{e}` is relative to the run window, which nPL cannot reference"),
                e.span(),
            ));
        }
        Ok(match e {
            Expr::Nested(inner) => self.cond(inner)?,
            Expr::BinaryOp { left, op: op @ (BinaryOperator::And | BinaryOperator::Or), right } => {
                let word = if matches!(op, BinaryOperator::And) { "AND" } else { "OR" };
                format!("({}) {word} ({})", self.cond(left)?, self.cond(right)?)
            }
            Expr::UnaryOp { op: UnaryOperator::Not, expr: inner } => format!("NOT ({})", self.cond(inner)?),
            Expr::BinaryOp { left, op, right } => {
                if let Some(text) = self.position_like(left, op, right)? {
                    return Ok(text);
                }
                let op = op_text(op).ok_or_else(|| refuse("this operator"))?;
                if [left, right].iter().any(|s| matches!(s.as_ref(), Expr::Value(v) if matches!(v.value, Value::Null))) {
                    return Err(refuse("a comparison with NULL"));
                }
                format!("{}{op}{}", self.operand(left)?, self.operand(right)?)
            }
            Expr::In { expr: inner, target: InTarget::List(list), negated, .. } => {
                let values = list
                    .iter()
                    .map(|v| npl_literal(v)?.ok_or_else(|| refuse("an IN list with a non-literal")))
                    .collect::<Result<Vec<_>, _>>()?;
                let not = if *negated { "NOT " } else { "" };
                format!("{} {not}IN ({})", self.operand(inner)?, values.join(", "))
            }
            Expr::Like { negated, any: false, expr: inner, pattern, escape_char: None }
            | Expr::ILike { negated, any: false, expr: inner, pattern, escape_char: None } => {
                let pat = string_literal(pattern).ok_or_else(|| refuse("a LIKE without a literal pattern"))?;
                let text = format!("like({}, {})", self.operand(inner)?, npl_string(pat, pattern.span())?);
                if *negated {
                    format!("NOT ({text})")
                } else {
                    text
                }
            }
            Expr::IsNull(inner) => format!("isnull({})", self.operand(inner)?),
            Expr::IsNotNull(inner) => format!("isnotnull({})", self.operand(inner)?),
            Expr::Between { expr: inner, negated: false, low, high } => {
                let x = self.operand(inner)?;
                format!("({x}>={}) AND ({x}<={})", self.expr(low)?, self.expr(high)?)
            }
            Expr::Value(v) if matches!(&v.value, Value::Boolean(true)) => "true".into(),
            Expr::Function(f) => {
                let name = function_name(f).to_ascii_lowercase();
                let args = function_args(f);
                match (name.as_str(), args.as_slice()) {
                    ("isnull" | "isnotnull", [Arg::Expr(x)]) => format!("{name}({})", self.operand(x)?),
                    ("match", [Arg::Expr(x), Arg::Expr(p)]) => {
                        let pat = string_literal(p).ok_or_else(|| refuse("a match() without a literal pattern"))?;
                        format!("match({}, {})", self.operand(x)?, npl_string(pat, p.span())?)
                    }
                    ("isnull" | "isnotnull" | "match" | "position" | "positioncaseinsensitive", _) => {
                        return Err(refuse("this form of the function"))
                    }
                    _ => self.function(f, e)?,
                }
            }
            Expr::Identifier(_) | Expr::CompoundIdentifier(_) => self.field(e)?,
            _ => return Err(refuse("this expression")),
        })
    }

    /// `position(x, 'n') > 0` (and `positionCaseInsensitive`): a substring
    /// test, `like(x, "%n%")`.
    fn position_like(&self, left: &Expr, op: &BinaryOperator, right: &Expr) -> Result<Option<String>, Unsupported> {
        let Some((field, needle, negated)) = position_test(left, op, right) else { return Ok(None) };
        let text = format!("like({}, {})", self.operand(field)?, npl_string(&format!("%{needle}%"), left.span())?);
        Ok(Some(if negated { format!("NOT ({text})") } else { text }))
    }
}

/// `position(x, 'needle') > 0` / `positionCaseInsensitive(…) >= 1` / `!= 0`
/// (`= 0` negated), with a plain ASCII needle (no LIKE wildcard in it):
/// (x, needle, negated).
fn position_test<'e>(left: &'e Expr, op: &BinaryOperator, right: &Expr) -> Option<(&'e Expr, String, bool)> {
    let Expr::Function(f) = left else { return None };
    let name = function_name(f).to_ascii_lowercase();
    if !matches!(name.as_str(), "position" | "positioncaseinsensitive")
        || f.over.is_some()
        || !matches!(f.parameters, FunctionArguments::None)
    {
        return None;
    }
    let args = function_args(f);
    let [Arg::Expr(hay), Arg::Expr(needle)] = args.as_slice() else { return None };
    let needle = string_literal(needle)?;
    if !needle.is_ascii() || !plain(needle) {
        return None;
    }
    let k = match right {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.clone(),
            _ => return None,
        },
        _ => return None,
    };
    let negated = match (op, k.as_str()) {
        (BinaryOperator::Gt, "0") | (BinaryOperator::GtEq, "1") | (BinaryOperator::NotEq, "0") => false,
        (BinaryOperator::Eq, "0") | (BinaryOperator::LtEq, "0") | (BinaryOperator::Lt, "1") => true,
        _ => return None,
    };
    Some((hay, needle.to_string(), negated))
}

/// Refuse SELECT modifiers the subset does not cover.
/// `allow_distinct`: a plain `SELECT DISTINCT` is harmless where only the set
/// of values matters (the subquery of an `IN`).
fn check_select_shape(s: &Select, allow_distinct: bool) -> Result<(), Unsupported> {
    let refuse = |what: &str| Err(Unsupported::new(what.to_string()));
    match &s.distinct {
        Some(sqlparser::ast::Distinct::Distinct) if !allow_distinct => return refuse("SELECT DISTINCT"),
        Some(sqlparser::ast::Distinct::On(_)) => return refuse("SELECT DISTINCT ON"),
        _ => {}
    }
    if s.top.is_some() {
        return refuse("SELECT TOP");
    }
    if s.into.is_some() {
        return refuse("SELECT INTO");
    }
    if !s.lateral_views.is_empty() || !s.connect_by.is_empty() {
        return refuse("LATERAL VIEW / CONNECT BY");
    }
    if !s.cluster_by.is_empty() || !s.distribute_by.is_empty() || !s.sort_by.is_empty() {
        return refuse("CLUSTER / DISTRIBUTE / SORT BY");
    }
    if !s.named_window.is_empty() || s.qualify.is_some() {
        return refuse("a WINDOW / QUALIFY clause");
    }
    if s.exclude.is_some() || s.value_table_mode.is_some() {
        return refuse("this SELECT form");
    }
    Ok(())
}

/// HAVING / ORDER BY may repeat an aggregate instead of naming its alias:
/// swap each aggregate for its output name.
fn rewrite_outputs(expr: &Expr, names: &[(String, String)]) -> Expr {
    let text = expr.to_string();
    if let Some((_, n)) = names.iter().find(|(s, _)| *s == text) {
        return Expr::Identifier(sqlparser::ast::Ident::new(n.clone()));
    }
    match expr {
        Expr::BinaryOp { left, op, right } => Expr::BinaryOp {
            left: Box::new(rewrite_outputs(left, names)),
            op: op.clone(),
            right: Box::new(rewrite_outputs(right, names)),
        },
        Expr::Nested(e) => Expr::Nested(Box::new(rewrite_outputs(e, names))),
        Expr::UnaryOp { op, expr: e } => Expr::UnaryOp { op: *op, expr: Box::new(rewrite_outputs(e, names)) },
        Expr::Function(f) if !is_aggregate_name(&function_name(f)) => {
            let mut f = f.clone();
            if let FunctionArguments::List(list) = &mut f.args {
                for a in list.args.iter_mut() {
                    if let FunctionArg::Unnamed(FunctionArgExpr::Expr(e)) = a {
                        *e = rewrite_outputs(e, names);
                    }
                }
            }
            Expr::Function(f)
        }
        other => other.clone(),
    }
}

fn order_name(
    scope: &Scope,
    expr: &Expr,
    aggs: &[Agg],
    outputs: &[(String, String)],
    grouped: bool,
    items: &[Item],
    plan: &Plan,
) -> Option<String> {
    // `ORDER BY 2`: ClickHouse's positional arguments (on by default).
    if let Some(n) = super::canon::positional(expr) {
        return match items.get(n - 1)? {
            Item::Named(name) => {
                Some(outputs.iter().find(|(s, _)| s == name).map(|(_, n)| n.clone()).unwrap_or_else(|| name.clone()))
            }
            Item::Star => None,
        };
    }
    let text = expr.to_string();
    if let Some(a) = aggs.iter().find(|a| a.sql == text) {
        return Some(a.alias.clone());
    }
    if let Some((_, n)) = plan.computed.iter().find(|(s, _)| *s == text) {
        return Some(n.clone());
    }
    let name = scope.field(expr)?;
    if let Some((_, npl)) = outputs.iter().find(|(sql, _)| *sql == name) {
        return Some(npl.clone());
    }
    // A non-aggregating query may sort by any column.
    (!grouped && NPL_FIELD.is_match(&name)).then_some(name)
}

/// Best-effort: the time bounds of the outer SELECT, whatever else the query
/// does (the AI path keeps this reading of the window).
pub(super) fn window_only(sql: &str, _ctx: &ConvertContext) -> (Option<TimeBound>, Option<TimeBound>) {
    let Ok(pre) = preprocess(sql) else { return (None, None) };
    let Ok(query) = parse_one(&pre) else { return (None, None) };
    let mut window = Window::default();
    window_of(&query, &mut window, 0);
    (window.earliest, window.latest)
}

/// The time bounds of a SELECT and of the subqueries it reads FROM (a bound
/// inside `FROM (SELECT … WHERE {W})` bounds the outer query's rows too).
fn window_of(query: &Query, window: &mut Window, depth: usize) {
    if depth > 16 {
        return;
    }
    let SetExpr::Select(select) = query.body.as_ref() else { return };
    for from in &select.from {
        if let TableFactor::Derived { subquery, .. } = &from.relation {
            window_of(subquery, window, depth + 1);
        }
    }
    let mut qualifiers = Vec::new();
    for from in &select.from {
        if let TableFactor::Table { name, alias, .. } = &from.relation {
            qualifiers.push(table_base(name));
            qualifiers.push(name.to_string());
            if let Some(a) = alias {
                qualifiers.push(a.name.value.clone());
            }
        }
    }
    let scope = Scope::plain(qualifiers);
    for clause in [select.prewhere.as_ref(), select.selection.as_ref()].into_iter().flatten() {
        for c in conjuncts(clause) {
            let _ = window.take(&scope, c);
        }
    }
}
