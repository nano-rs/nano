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
fn parse_instant(s: &str) -> Option<DateTime<Utc>> {
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
            if slot.is_some() {
                return Err(Unsupported::at(format!("more than one {which} bound on `timestamp`"), conjunct.span()));
            }
            *slot = Some(value);
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
        ("uniq" | "uniqexact" | "uniqcombined" | "uniqcombined64" | "uniqhll12", [a]) if !is_distinct_call(f) => {
            let f = field(a)?;
            Ok((format!("dc({f})"), format!("dc_{}", slug(&f))))
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
            let c = eval_condition(scope, cond)?;
            Ok((format!("count(eval({c}))"), "count_if".into()))
        }
        ("sumif", [a, Arg::Expr(cond)]) => {
            let f = field(a)?;
            let c = eval_condition(scope, cond)?;
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
    let mut head: Vec<Filter> = Vec::new();
    let mut wheres: Vec<Filter> = Vec::new();
    for c in rest {
        if let Some(f) = translate_filter(&scope, c)? {
            if f.where_only() {
                wheres.push(f);
            } else {
                head.push(f);
            }
        }
    }

    // Projection.
    let mut star = false;
    let mut columns: Vec<(String, Option<String>)> = Vec::new(); // (field, alias)
    let mut aggs: Vec<Agg> = Vec::new();
    for item in &select.projection {
        let (expr, alias) = match item {
            SelectItem::Wildcard(opts) => {
                if opts.opt_exclude.is_some() || opts.opt_except.is_some() || opts.opt_replace.is_some()
                    || opts.opt_rename.is_some() || opts.opt_ilike.is_some()
                {
                    return Err(Unsupported::new("a `*` with EXCEPT / REPLACE"));
                }
                star = true;
                continue;
            }
            SelectItem::UnnamedExpr(e) => (e, None),
            SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias.value.clone())),
            other => return Err(Unsupported::at("this select item", other.span())),
        };
        if contains_aggregate(expr) {
            let (npl, default_alias) = agg_call(&scope, expr)?;
            let alias = alias.unwrap_or(default_alias);
            if !NPL_ALIAS.is_match(&alias) {
                return Err(Unsupported::at(format!("the output name `{alias}`"), expr.span()));
            }
            aggs.push(Agg { sql: expr.to_string(), npl, alias });
        } else if let Some(f) = scope.field(expr) {
            columns.push((npl_field(&f, expr.span())?, alias));
        } else {
            return Err(Unsupported::at(format!("the computed column `{expr}`"), expr.span()));
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
    let grouped = !aggs.is_empty() || !group_exprs.is_empty();

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
    if grouped {
        let mut keys: Vec<String> = Vec::new();
        for g in &group_exprs {
            let key = match scope.field(g) {
                Some(name) => columns
                    .iter()
                    .find(|(_, alias)| alias.as_deref() == Some(name.as_str()))
                    .map(|(f, _)| f.clone())
                    .unwrap_or(name),
                None => return Err(Unsupported::at(format!("the GROUP BY expression `{g}`"), g.span())),
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
        for k in &keys {
            outputs.push((k.clone(), k.clone()));
        }
        for a in &aggs {
            outputs.push((a.alias.clone(), a.alias.clone()));
        }
        if aggs.is_empty() {
            return Err(Unsupported::new("GROUP BY without an aggregate (a DISTINCT)"));
        }
        npl.push_str(" | stats ");
        npl.push_str(&aggs.iter().map(|a| format!("{} as {}", a.npl, a.alias)).collect::<Vec<_>>().join(", "));
        if !keys.is_empty() {
            npl.push_str(" by ");
            npl.push_str(&keys.join(", "));
        }
        if let Some(having) = &select.having {
            let rewritten = rewrite_outputs(having, &aggs);
            let post_scope = Scope::plain(Vec::new());
            match translate_filter(&post_scope, &rewritten)? {
                Some(f) => {
                    npl.push_str(" | where ");
                    npl.push_str(&f.render());
                }
                None => {}
            }
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
    }

    // ORDER BY → sort.
    if let Some(order) = &query.order_by {
        if order.interpolate.is_some() {
            return Err(Unsupported::new("ORDER BY … INTERPOLATE"));
        }
        let OrderByKind::Expressions(items) = &order.kind else {
            return Err(Unsupported::new("ORDER BY ALL"));
        };
        let mut keys = Vec::new();
        for item in items {
            if item.with_fill.is_some() || item.options.nulls_first.is_some() {
                return Err(Unsupported::at("ORDER BY … WITH FILL / NULLS FIRST|LAST", item.expr.span()));
            }
            let name = order_name(&scope, &item.expr, &aggs, &outputs, grouped)
                .ok_or_else(|| Unsupported::at(format!("the ORDER BY key `{}`: nPL sorts by fields and stats outputs only", item.expr), item.expr.span()))?;
            let desc = matches!(item.options.sort, Some(OrderBySort::Desc));
            keys.push(if desc { format!("-{name}") } else { name });
        }
        npl.push_str(" | sort ");
        npl.push_str(&keys.join(", "));
    }

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

    if !grouped && !star && !columns.is_empty() {
        npl.push_str(" | table ");
        npl.push_str(&columns.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>().join(", "));
    }

    Ok(Converted { npl, dataset, earliest: window.earliest, latest: window.latest })
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
/// swap each projected aggregate for its output name.
fn rewrite_outputs(expr: &Expr, aggs: &[Agg]) -> Expr {
    let text = expr.to_string();
    if let Some(a) = aggs.iter().find(|a| a.sql == text) {
        return Expr::Identifier(sqlparser::ast::Ident::new(a.alias.clone()));
    }
    match expr {
        Expr::BinaryOp { left, op, right } => Expr::BinaryOp {
            left: Box::new(rewrite_outputs(left, aggs)),
            op: op.clone(),
            right: Box::new(rewrite_outputs(right, aggs)),
        },
        Expr::Nested(e) => Expr::Nested(Box::new(rewrite_outputs(e, aggs))),
        Expr::UnaryOp { op, expr: e } => Expr::UnaryOp { op: *op, expr: Box::new(rewrite_outputs(e, aggs)) },
        other => other.clone(),
    }
}

fn order_name(scope: &Scope, expr: &Expr, aggs: &[Agg], outputs: &[(String, String)], grouped: bool) -> Option<String> {
    let text = expr.to_string();
    if let Some(a) = aggs.iter().find(|a| a.sql == text) {
        return Some(a.alias.clone());
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
    let SetExpr::Select(select) = query.body.as_ref() else { return (None, None) };
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
    let mut window = Window::default();
    for clause in [select.prewhere.as_ref(), select.selection.as_ref()].into_iter().flatten() {
        for c in conjuncts(clause) {
            let _ = window.take(&scope, c);
        }
    }
    (window.earliest, window.latest)
}
