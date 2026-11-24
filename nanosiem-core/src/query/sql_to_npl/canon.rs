// SPDX-License-Identifier: AGPL-3.0-or-later

//! The round-trip proof: a normalized signature of a SQL query, read the same
//! way from the original Agent Lane SQL and from the SQL the production nPL
//! compiler emits for the converted query, and a comparison of the two.
//!
//! The generator's SQL is a chain of CTE stages (`stage_0` reads and filters
//! the table, later stages aggregate, filter, sort and limit). The signature
//! flattens either shape into one pipeline: table, pre-aggregation filters,
//! group keys, aggregates, post-aggregation filters, order and limit.
//! Predicates are normalized (`lower(col) = 'x'` and `col ILIKE …` read as
//! case-insensitive; parentheses, operand order, `NOT` over a comparison and
//! conjunct order do not matter) so equivalent SQL compares equal.

use std::collections::{BTreeSet, HashMap};
use std::fmt;

use chrono::TimeZone;
use serde::Serialize;
use sqlparser::ast::{
    BinaryOperator, Expr, GroupByExpr, InTarget, LimitClause, OrderByKind, OrderBySort, Query, Select, SelectItem, SetExpr,
    TableFactor, UnaryOperator, Value,
};

use super::convert::{
    conjuncts, contains_aggregate, function_args, function_name, is_aggregate_name, is_distinct_call, parse_one,
    sentinel_of, table_base, table_kind, Arg, TableKind, TIME_COLUMN,
};
use super::ConvertContext;
use crate::query::{parse_query, ClickHouseSqlGenerator, Dataset, QueryOptions, TimeRange};

/// The row cap the comparator compiles with. Distinctive so the generator's
/// outer result cap is told apart from a `| head` the query asked for.
const PROBE_LIMIT: u64 = 999_983;

/// How the compiled nPL departs from the SQL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[schema(as = SqlToNplDifferenceKind)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceKind {
    /// Search returns a superset: case-insensitive matching, or a hostname
    /// that also matches its FQDN.
    Broader,
    /// The results can differ.
    Different,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[schema(as = SqlToNplDifference)]
pub struct Difference {
    pub kind: DifferenceKind,
    pub detail: String,
}

impl Difference {
    fn different(detail: impl Into<String>) -> Self {
        Self { kind: DifferenceKind::Different, detail: detail.into() }
    }
    fn broader(detail: impl Into<String>) -> Self {
        Self { kind: DifferenceKind::Broader, detail: detail.into() }
    }
}

/// A literal operand.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Lit {
    Str(String),
    Num(String),
    Bool(bool),
    Null,
    /// Anything else, by its SQL text (a window placeholder, a function of
    /// literals, another column).
    Expr(String),
}

impl fmt::Display for Lit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // sql-lint: allow(canonical comparison form for the SQL-to-nPL exactness check; never executed)
            Lit::Str(s) => write!(f, "'{}'", s.replace('\'', "\\'")),
            Lit::Num(n) => write!(f, "{n}"),
            Lit::Bool(b) => write!(f, "{b}"),
            Lit::Null => write!(f, "NULL"),
            Lit::Expr(e) => write!(f, "{e}"),
        }
    }
}

impl Lit {
    fn lowered(self) -> Lit {
        match self {
            Lit::Str(s) => Lit::Str(s.to_lowercase()),
            other => other,
        }
    }
    fn cased(&self) -> bool {
        matches!(self, Lit::Str(s) if s.to_lowercase() != s.to_uppercase())
    }
}

/// A normalized predicate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Canon {
    And(Vec<Canon>),
    Or(Vec<Canon>),
    Not(Box<Canon>),
    Cmp { col: String, ci: bool, op: &'static str, val: Lit },
    In { col: String, ci: bool, neg: bool, vals: Vec<Lit> },
    Like { col: String, ci: bool, neg: bool, pat: String },
    Null { col: String, neg: bool },
    /// `col [NOT] IN (SELECT …)` (NAN-5614).
    InSub { col: String, ci: bool, neg: bool, global: bool, sub: Box<SubCanon> },
    True,
    Other(String),
}

/// A subquery an `IN` filter reads, normalized like a whole query.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SubCanon {
    table: String,
    /// The column it returns; `None` when it does not return one plain column.
    ret: Option<String>,
    /// Its filters, time bounds dropped.
    filters: Vec<Canon>,
    /// Its time bounds on `timestamp`; `None` once they are known to be the
    /// enclosing query's own (what an nPL subsearch always runs over).
    bounds: Option<Vec<(&'static str, Lit)>>,
    limit: Option<u64>,
    /// Anything else it does (aggregation, order, shape), which no nPL
    /// subsearch does.
    extra: Vec<String>,
}

impl fmt::Display for SubCanon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filters = self.filters.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(" AND ");
        write!(f, "SELECT {} FROM {}", self.ret.as_deref().unwrap_or("?"), self.table)?;
        if !filters.is_empty() {
            write!(f, " WHERE {filters}")?;
        }
        if let Some(b) = &self.bounds {
            let b = b.iter().map(|(op, v)| format!("timestamp {op} {v}")).collect::<Vec<_>>().join(" AND ");
            write!(f, " [own window: {}]", if b.is_empty() { "none".to_string() } else { b })?;
        }
        for e in &self.extra {
            write!(f, " {e}")?;
        }
        if let Some(l) = self.limit {
            write!(f, " LIMIT {l}")?;
        }
        Ok(())
    }
}

/// What the dataset a SELECT reads guarantees about its columns.
#[derive(Debug, Clone, Copy, Default)]
struct Facts {
    /// The detections source (NAN-5612), whose column types are fixed by the
    /// shared builder: `severity` / `detection_path` are always lowercase,
    /// `rule_id` / `matched_log_id` are UUIDs, `risk_score` an
    /// integer.
    signals: bool,
}

impl Facts {
    /// `lower(col)` is `col`.
    fn lowered(&self, col: &str) -> bool {
        use crate::schema::SchemaProfile as _;
        self.signals && crate::schema::SignalsProfile.is_lowercased_at_ingest(col)
    }

    /// A never-NULL integer column (Int64 on both legs).
    fn integer(&self, col: &str) -> bool {
        self.signals && col == "risk_score"
    }

    /// `toString(col)` is never `''`, so nPL's dc() (which skips empty
    /// values) counts what `uniqExact(col)` counts. Also never NULL: both
    /// legs of the source write these as non-Nullable UUID (`toUUIDOrZero`
    /// on the findings leg), Int64 and DateTime64.
    fn never_empty(&self, col: &str) -> bool {
        self.signals && matches!(col, "rule_id" | "matched_log_id" | "risk_score" | TIME_COLUMN)
    }
}

fn col_text(col: &str, ci: bool) -> String {
    if ci {
        format!("lower({col})")
    } else {
        col.to_string()
    }
}

impl fmt::Display for Canon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let join = |v: &[Canon], sep: &str| v.iter().map(|c| format!("{c}")).collect::<Vec<_>>().join(sep);
        match self {
            Canon::And(v) => write!(f, "({})", join(v, " AND ")),
            Canon::Or(v) => write!(f, "({})", join(v, " OR ")),
            Canon::Not(c) => write!(f, "NOT {c}"),
            Canon::Cmp { col, ci, op, val } => write!(f, "{} {op} {val}", col_text(col, *ci)),
            Canon::In { col, ci, neg, vals } => write!(
                f,
                "{} {}IN ({})",
                col_text(col, *ci),
                if *neg { "NOT " } else { "" },
                vals.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ")
            ),
            Canon::Like { col, ci, neg, pat } => {
                write!(f, "{} {}LIKE '{pat}'", col_text(col, *ci), if *neg { "NOT " } else { "" })
            }
            Canon::Null { col, neg } => write!(f, "{col} IS {}NULL", if *neg { "NOT " } else { "" }),
            Canon::InSub { col, ci, neg, global, sub } => write!(
                f,
                "{} {}{}IN ({sub})",
                col_text(col, *ci),
                if *global { "GLOBAL " } else { "" },
                if *neg { "NOT " } else { "" }
            ),
            Canon::True => write!(f, "true"),
            Canon::Other(s) => write!(f, "{s}"),
        }
    }
}

const NEGATED: &[(&str, &str)] = &[("=", "!="), ("!=", "="), (">", "<="), ("<=", ">"), ("<", ">="), (">=", "<")];

fn negate_op(op: &'static str) -> &'static str {
    NEGATED.iter().find(|(a, _)| *a == op).map(|(_, b)| *b).unwrap_or(op)
}

fn flip_op(op: &'static str) -> &'static str {
    match op {
        ">" => "<",
        "<" => ">",
        ">=" => "<=",
        "<=" => ">=",
        other => other,
    }
}

fn op_of(op: &BinaryOperator) -> Option<&'static str> {
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

/// Escape a literal for use inside a LIKE pattern.
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

/// Reads expressions within one SELECT.
struct Reader<'a> {
    qualifiers: &'a [String],
    /// Output names an earlier stage (or this SELECT's projection) defined,
    /// mapped to what they stand for (a column or an aggregate's canon).
    outputs: &'a HashMap<String, String>,
    facts: Facts,
    /// For reading `IN (SELECT …)` subqueries.
    ctx: &'a ConvertContext,
}

impl Reader<'_> {
    /// A column reference, through `lower` / `toString` / `assumeNotNull`.
    /// An aggregate reads as its canonical text.
    fn column(&self, expr: &Expr) -> Option<(String, bool)> {
        match expr {
            Expr::Identifier(i) => {
                if sentinel_of(expr).is_some() {
                    return None;
                }
                Some((self.outputs.get(&i.value).cloned().unwrap_or_else(|| i.value.clone()), false))
            }
            Expr::CompoundIdentifier(parts) => {
                let names: Vec<&str> = parts.iter().map(|p| p.value.as_str()).collect();
                let qualified = names.len() > 1 && self.qualifiers.iter().any(|q| q == names[0]);
                let names = if qualified { &names[1..] } else { &names[..] };
                let name = names.join(".");
                // `t.col` over a real table names its column, never a SELECT
                // alias (over a CTE or a subquery it names that one's output).
                if qualified && self.qualifiers.iter().any(|q| q == BASE_TABLE_MARK) {
                    return Some((name, false));
                }
                Some((self.outputs.get(&name).cloned().unwrap_or(name), false))
            }
            Expr::Nested(e) => self.column(e),
            Expr::Function(f) => {
                let name = function_name(f).to_ascii_lowercase();
                if is_aggregate_name(&name) {
                    return Some((self.aggregate(expr), false));
                }
                // nPL's values(), an aggregate under a string join.
                if name == "arraystringconcat" {
                    let a = self.aggregate(expr);
                    if is_single_call(&a, "values") {
                        return Some((a, false));
                    }
                }
                match (name.as_str(), function_args(f).as_slice()) {
                    // A column the source always writes lowercase reads the
                    // same through lower(); so does a value that already is
                    // `lower(…)` (NAN-5630: an eval'd `u = lower(x)` compared
                    // as `lower(toString(u))`).
                    ("lower" | "lowerutf8", [Arg::Expr(e)]) => self.column(e).map(|(c, ci)| {
                        if ci || is_single_call(&c, "lower") {
                            return (c, ci);
                        }
                        let ci = !self.facts.lowered(&c);
                        (c, ci)
                    }),
                    ("tostring" | "assumenotnull", [Arg::Expr(e)]) => self.column(e),
                    // nPL eval reads numbers through a float parse
                    // (`toFloat64OrNull(toString(x))`, and its
                    // `coalesce(…, toFloat64(parseDateTime64BestEffortOrNull(…)))`
                    // form over a computed field): `tofloat(x)`. Where it
                    // changes nothing (a numeric value compared with a number,
                    // or divided) the comparison and the division drop it.
                    _ if float_parse_operand(f).is_some() => {
                        let e = float_parse_operand(f).expect("checked");
                        let (c, ci) = self.column(e)?;
                        Some((format!("tofloat({})", col_text(&c, ci)), false))
                    }
                    // NAN-5630: any other scalar function is a computed
                    // value, read structurally.
                    _ => Some((self.scalar(expr), false)),
                }
            }
            // NAN-5630: arithmetic, CASE and array subscripts are computed
            // values too.
            Expr::BinaryOp {
                op:
                    BinaryOperator::Plus
                    | BinaryOperator::Minus
                    | BinaryOperator::Multiply
                    | BinaryOperator::Divide
                    | BinaryOperator::Modulo,
                ..
            }
            | Expr::Case { .. }
            | Expr::CompoundFieldAccess { .. } => Some((self.scalar(expr), false)),
            _ => None,
        }
    }

    /// Is a canonical value known to be a number? A numeric column, a
    /// number, or a count / distinct count / sum / average / length (the
    /// float parse of a number is the number; of anything else it is not).
    fn numeric(&self, canon: &str) -> bool {
        use crate::schema::SchemaProfile as _;
        if canon.parse::<f64>().is_ok() || self.facts.integer(canon) {
            return true;
        }
        let numeric_column = if self.facts.signals {
            crate::schema::SignalsProfile.is_numeric_field(canon)
        } else {
            self.ctx.profile.is_numeric_field(canon)
        };
        if numeric_column {
            return true;
        }
        const NUMERIC_CALLS: &[&str] =
            &["count", "countIf", "dc", "dc_nonempty", "estdc", "estdc_nonempty", "sum", "sumIf", "avg", "length", "lengthutf8"];
        if NUMERIC_CALLS.iter().any(|n| is_single_call(canon, n)) {
            return true;
        }
        // min / max of a numeric column (never of the timestamp).
        ["min", "max"].iter().any(|n| {
            is_single_call(canon, n)
                && canon[n.len() + 1..canon.len() - 1] != *TIME_COLUMN
                && self.numeric(&canon[n.len() + 1..canon.len() - 1])
        })
    }

    /// NAN-5630: the canonical form of a VALUE (a computed column, a group
    /// key, an aggregate argument, a sort key). Unlike [`Self::column`],
    /// `lowerUTF8` stays distinct from `lower` here: a predicate against a
    /// lowercase literal reads the same through either, a value does not.
    fn value(&self, expr: &Expr) -> String {
        match expr {
            Expr::Nested(e) => self.value(e),
            // As a value, `toString(x)` is a string (it sorts as one) and
            // `assumeNotNull(x)` turns NULL into a default; a predicate reads
            // through both, a value does not.
            Expr::Function(f)
                if ["lowerUTF8", "toString", "assumeNotNull"].iter().any(|n| function_name(f).eq_ignore_ascii_case(n)) =>
            {
                match function_args(f).as_slice() {
                    [Arg::Expr(e)] => format!("{}({})", function_name(f).to_ascii_lowercase(), self.value(e)),
                    _ => expr.to_string(),
                }
            }
            _ => match self.column(expr) {
                Some((c, ci)) => col_text(&c, ci),
                None => self.scalar(expr),
            },
        }
    }

    /// The structural canon of a computed expression. Function names are
    /// lowercased, CH aliases folded (`replace` / `replaceAll`, `trim` /
    /// `trimBoth`, one-character `splitByChar` / `splitByString`), constant
    /// integer arithmetic folded, a `multiIf` / `CASE` cut at its first
    /// constant-true branch, and a time bucket read as its width when the
    /// named function and `toStartOfInterval` are the same bucket. Anything
    /// it does not model reads as its SQL text, which never matches the
    /// other side's unless the two are the same text.
    fn scalar(&self, expr: &Expr) -> String {
        match expr {
            Expr::Nested(e) => self.scalar(e),
            Expr::Value(_) => self.literal(expr).to_string(),
            Expr::UnaryOp { op: UnaryOperator::Minus, expr: inner } => match self.literal(expr) {
                Lit::Num(n) => n,
                _ => format!("(-{})", self.value(inner)),
            },
            Expr::BinaryOp { left, op, right } => {
                let arith = match op {
                    BinaryOperator::Plus => "+",
                    BinaryOperator::Minus => "-",
                    BinaryOperator::Multiply => "*",
                    BinaryOperator::Divide => "/",
                    BinaryOperator::Modulo => "%",
                    // A condition (comparison, AND / OR, …) as a value.
                    _ => return self.predicate(expr).to_string(),
                };
                if let (Lit::Num(a), Lit::Num(b)) = (self.literal(left), self.literal(right)) {
                    if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
                        let folded = match arith {
                            "+" => a.checked_add(b),
                            "-" => a.checked_sub(b),
                            "*" => a.checked_mul(b),
                            _ => None,
                        };
                        if let Some(v) = folded {
                            return v.to_string();
                        }
                    }
                }
                let (l, r) = (self.value(left), self.value(right));
                // ClickHouse divides in Float64 whatever the operand types,
                // so nPL's float parse of a numeric operand changes nothing.
                // (`+ - *` keep integer types in SQL; nPL computes them in
                // Float64, which is a different value type.)
                let (l, r) = if arith == "/" { (self.unfloat(l), self.unfloat(r)) } else { (l, r) };
                format!("({l} {arith} {r})")
            }
            Expr::Case { operand: None, conditions, else_result, .. } => {
                let mut parts = Vec::new();
                for w in conditions {
                    parts.push((self.value(&w.condition), self.value(&w.result)));
                }
                let otherwise = else_result.as_ref().map(|e| self.value(e)).unwrap_or_else(|| "NULL".into());
                multi_if(parts, otherwise)
            }
            Expr::CompoundFieldAccess { root, access_chain } => {
                let mut out = self.value(root);
                for a in access_chain {
                    match a {
                        sqlparser::ast::AccessExpr::Subscript(sqlparser::ast::Subscript::Index { index }) => {
                            out = format!("{out}[{}]", self.value(index));
                        }
                        _ => return expr.to_string(),
                    }
                }
                out
            }
            Expr::Interval(i) => interval_canon(i, self).unwrap_or_else(|| expr.to_string()),
            Expr::Function(f) => self.scalar_function(f).unwrap_or_else(|| expr.to_string()),
            _ => expr.to_string(),
        }
    }

    /// NAN-5630: `position(col, 'needle') > 0` (or `>= 1`, `!= 0`; `= 0`
    /// negated) is the substring match `col LIKE '%needle%'`;
    /// `positionCaseInsensitive` the case-insensitive one. Both fold ASCII
    /// only, as `lower()` does, so only an ASCII needle is read this way.
    fn position_match(&self, left: &Expr, op: &BinaryOperator, right: &Expr) -> Option<Canon> {
        let Expr::Function(f) = left else { return None };
        let name = function_name(f).to_ascii_lowercase();
        let ci = match name.as_str() {
            "position" => false,
            "positioncaseinsensitive" => true,
            _ => return None,
        };
        if f.over.is_some() || !matches!(f.parameters, sqlparser::ast::FunctionArguments::None) {
            return None;
        }
        let args = function_args(f);
        let [Arg::Expr(hay), Arg::Expr(needle)] = args.as_slice() else { return None };
        let Lit::Str(n) = self.literal(needle) else { return None };
        if n.is_empty() || !n.is_ascii() {
            return None;
        }
        let Lit::Num(k) = self.literal(right) else { return None };
        let neg = match (op, k.as_str()) {
            (BinaryOperator::Gt, "0") | (BinaryOperator::GtEq, "1") | (BinaryOperator::NotEq, "0") => false,
            (BinaryOperator::Eq, "0") | (BinaryOperator::LtEq, "0") | (BinaryOperator::Lt, "1") => true,
            _ => return None,
        };
        let (col, col_ci) = self.column(hay)?;
        if col_ci && !ci && n != n.to_lowercase() {
            // `position(lower(x), 'Abc')` never matches.
            return None;
        }
        Some(like(col, ci || col_ci, neg, format!("%{}%", like_escape(&n))))
    }

    /// `tofloat(x)` → `x` when `x` is numeric.
    fn unfloat(&self, v: String) -> String {
        match v.strip_prefix("tofloat(").and_then(|r| r.strip_suffix(')')) {
            Some(inner) if is_single_call(&v, "tofloat") && self.numeric(inner) => inner.to_string(),
            _ => v,
        }
    }

    fn scalar_function(&self, f: &sqlparser::ast::Function) -> Option<String> {
        if f.over.is_some()
            || f.filter.is_some()
            || !f.within_group.is_empty()
            || !matches!(f.parameters, sqlparser::ast::FunctionArguments::None)
            || is_distinct_call(f)
        {
            return None;
        }
        let name = function_name(f).to_ascii_lowercase();
        let raw_args = function_args(f);
        let exprs: Vec<&Expr> = raw_args
            .iter()
            .map(|a| match a {
                Arg::Expr(e) => Some(*e),
                _ => None,
            })
            .collect::<Option<_>>()?;
        let args: Vec<String> = exprs.iter().map(|e| self.value(e)).collect();
        let name = match name.as_str() {
            // ClickHouse aliases of one function.
            "replace" => "replaceall".to_string(),
            "trim" => "trimboth".to_string(),
            "lcase" => "lower".to_string(),
            "ucase" => "upper".to_string(),
            // `splitByChar` takes a one-character separator, on which it
            // splits exactly as `splitByString` does.
            "splitbychar" if matches!(exprs.first().map(|e| self.literal(e)), Some(Lit::Str(s)) if s.chars().count() == 1) => {
                "splitbystring".to_string()
            }
            "multiif" if args.len() >= 3 && args.len() % 2 == 1 => {
                let mut pairs = Vec::new();
                for p in args[..args.len() - 1].chunks(2) {
                    pairs.push((p[0].clone(), p[1].clone()));
                }
                return Some(multi_if(pairs, args[args.len() - 1].clone()));
            }
            "tostartofinterval" if args.len() == 2 => {
                return Some(match bucket_seconds(&args[1]) {
                    Some(s) => format!("bucket({}, {s})", args[0]),
                    None => format!("tostartofinterval({}, {})", args[0], args[1]),
                });
            }
            "tostartofminute" | "tostartoffiveminutes" | "tostartoftenminutes" | "tostartoffifteenminutes"
            | "tostartofhour"
                if args.len() == 1 =>
            {
                let s = match name.as_str() {
                    "tostartofminute" => 60,
                    "tostartoffiveminutes" => 300,
                    "tostartoftenminutes" => 600,
                    "tostartoffifteenminutes" => 900,
                    _ => 3600,
                };
                return Some(format!("bucket({}, {s})", args[0]));
            }
            n if n.starts_with("tointerval") && args.len() == 1 => {
                let unit = n.strip_prefix("tointerval")?;
                return Some(format!("interval({}, {unit})", args[0]));
            }
            _ => name,
        };
        Some(format!("{name}({})", args.join(", ")))
    }

    fn literal(&self, expr: &Expr) -> Lit {
        match expr {
            Expr::Value(v) => match &v.value {
                Value::SingleQuotedString(s) | Value::EscapedStringLiteral(s) => Lit::Str(s.clone()),
                Value::Number(n, _) => Lit::Num(n.parse::<f64>().map(|f| f.to_string()).unwrap_or_else(|_| n.clone())),
                Value::Boolean(b) => Lit::Bool(*b),
                Value::Null => Lit::Null,
                _ => Lit::Expr(expr.to_string()),
            },
            Expr::UnaryOp { op: UnaryOperator::Minus, expr: inner } => match self.literal(inner) {
                Lit::Num(n) => Lit::Num(n.parse::<f64>().map(|f| (-f).to_string()).unwrap_or(format!("-{n}"))),
                _ => Lit::Expr(expr.to_string()),
            },
            Expr::Nested(e) => self.literal(e),
            _ => Lit::Expr(expr.to_string()),
        }
    }

    fn is_literal(&self, expr: &Expr) -> bool {
        sentinel_of(expr).is_some()
            || !matches!(self.literal(expr), Lit::Expr(_))
            || is_constant(expr)
            || self.column(expr).is_none()
    }

    /// The canonical text of an aggregate.
    fn aggregate(&self, expr: &Expr) -> String {
        let Expr::Function(f) = expr else { return expr.to_string() };
        let name = function_name(f).to_ascii_lowercase();
        let args = function_args(f);
        // A window, FILTER, parametric (`uniqUpTo(5)(x)`, `groupUniqArray(10)(x)`)
        // or DISTINCT form means something else than the plain aggregate.
        // NAN-5630: an aggregate's argument is a value (`max(lowerUTF8(x))`
        // is not `max(lower(x))`; `max(toString(port))` compares strings).
        let col = |a: &Arg| match a {
            Arg::Expr(e) => Some(self.value(e)),
            _ => None,
        };
        // `groupUniqArray(N)(x)`: kept structured so the comparison can say
        // how nPL's values() differs.
        if name == "groupuniqarray" && f.over.is_none() && f.filter.is_none() && !is_distinct_call(f) {
            if let (sqlparser::ast::FunctionArguments::List(params), [a]) = (&f.parameters, args.as_slice()) {
                if let ([sqlparser::ast::FunctionArg::Unnamed(sqlparser::ast::FunctionArgExpr::Expr(n))], Some(c)) =
                    (params.args.as_slice(), col(a))
                {
                    if let Lit::Num(n) = self.literal(n) {
                        return format!("groupUniqArray({n})({c})");
                    }
                }
            }
        }
        let plain = f.over.is_none()
            && f.filter.is_none()
            && f.within_group.is_empty()
            && matches!(f.parameters, sqlparser::ast::FunctionArguments::None)
            && (name == "count" || !is_distinct_call(f));
        if !plain {
            return expr.to_string();
        }
        let out = match (name.as_str(), args.as_slice()) {
            ("count", []) | ("count", [Arg::Star]) => Some("count()".to_string()),
            ("count", [a]) if is_distinct_call(f) => col(a).map(|c| format!("dc({c})")),
            ("count", [a]) => col(a).map(|c| format!("count({c})")),
            ("uniqexact", [a]) => col(a).map(|c| format!("dc({c})")),
            // NAN-5657: the approximate distinct counts are nPL's estdc, not
            // its exact dc, so an approximate count is never called exact.
            ("uniq" | "uniqcombined" | "uniqcombined64" | "uniqhll12", [a]) => col(a).map(|c| format!("estdc({c})")),
            (
                func @ ("uniqexactif" | "uniqif" | "uniqcombinedif" | "uniqcombined64if" | "uniqhll12if"),
                [a, Arg::Expr(cond)],
            ) => {
                let c = col(a);
                let base = if func == "uniqexactif" { "dc" } else { "estdc" };
                // `uniqExactIf(x, toString(x) != '')`: nPL's dc, which skips
                // empty values (`uniqCombined64If(…)`: its estdc).
                match (c, self.predicate(cond)) {
                    (Some(c), Canon::Cmp { col, op: "!=", val: Lit::Str(s), .. }) if s.is_empty() && col_text(&col, false) == c => {
                        // NAN-5614: a column that is never empty (a UUID, a
                        // number) loses nothing to the empty-value skip.
                        if self.facts.never_empty(&c) {
                            Some(format!("{base}({c})"))
                        } else {
                            Some(format!("{base}_nonempty({c})"))
                        }
                    }
                    _ => None,
                }
            }
            // NAN-5614: conditional aggregates, read as the condition's canon.
            ("countif", [Arg::Expr(cond)]) => Some(format!("countIf({})", self.predicate(cond))),
            ("sumif", [a, Arg::Expr(cond)]) => col(a).map(|c| format!("sumIf({c}, {})", self.predicate(cond))),
            // `sum(if(c, x, 0))` adds x over the rows where c holds and 0
            // elsewhere (a NULL condition takes the 0 branch, as sumIf skips
            // it): the same total as `sumIf(x, c)` when x is never NULL (over
            // a Nullable x with no matching value sumIf is NULL, the sum 0),
            // which only the detections source guarantees.
            ("sum", [Arg::Expr(Expr::Function(inner))]) if function_name(inner).eq_ignore_ascii_case("if") => {
                match function_args(inner).as_slice() {
                    [Arg::Expr(cond), Arg::Expr(x), Arg::Expr(zero)]
                        if matches!(self.literal(zero), Lit::Num(ref n) if n == "0") =>
                    {
                        self.column(x)
                            .filter(|(c, ci)| !ci && self.facts.never_empty(c))
                            .map(|(c, _)| format!("sumIf({c}, {})", self.predicate(cond)))
                    }
                    _ => None,
                }
            }
            ("argmax" | "argmin", [a, b]) => match (col(a), col(b)) {
                (Some(a), Some(b)) => Some(format!("{name}({a}, {b})")),
                _ => None,
            },
            ("any", [a]) => col(a).map(|c| format!("any({c})")),
            ("sum" | "avg" | "min" | "max", [a]) => col(a).map(|c| format!("{name}({c})")),
            ("groupuniqarray", [a]) => col(a).map(|c| format!("groupUniqArray({c})")),
            // nPL's values(): exactly the generator's shape (NAN-5614: a
            // different separator, cap or filter is a different aggregate).
            ("arraystringconcat", [Arg::Expr(inner), Arg::Expr(sep)])
                if self.literal(sep) == Lit::Str(", ".into()) && is_values_shape(inner) =>
            {
                find_group_uniq_arg(inner).and_then(|e| self.column(e)).map(|(c, _)| format!("values({c})"))
            }
            _ => None,
        };
        out.unwrap_or_else(|| expr.to_string())
    }

    /// Normalize one predicate.
    fn predicate(&self, expr: &Expr) -> Canon {
        match expr {
            Expr::Nested(e) => self.predicate(e),
            Expr::Value(v) if matches!(&v.value, Value::Boolean(true)) => Canon::True,
            Expr::Value(v) if matches!(&v.value, Value::Number(n, _) if n == "1") => Canon::True,
            Expr::BinaryOp { op: BinaryOperator::And, .. } => {
                and(flatten(expr, &BinaryOperator::And).into_iter().map(|e| self.predicate(e)).collect())
            }
            Expr::BinaryOp { op: BinaryOperator::Or, .. } => {
                or(flatten(expr, &BinaryOperator::Or).into_iter().map(|e| self.predicate(e)).collect())
            }
            Expr::UnaryOp { op: UnaryOperator::Not, expr: inner } => not(self.predicate(inner)),
            Expr::BinaryOp { left, op, right } => {
                if let Some(c) = self.position_match(left, op, right) {
                    return c;
                }
                let Some(op) = op_of(op) else { return Canon::Other(expr.to_string()) };
                let (col, lit, op) = match (self.column(left), self.column(right)) {
                    (Some(c), _) if self.is_literal(right) => (c, self.literal(right), op),
                    (_, Some(c)) if self.is_literal(left) => (c, self.literal(left), flip_op(op)),
                    _ => return Canon::Other(expr.to_string()),
                };
                // A float parse of a numeric value, compared with a number,
                // compares the value.
                let col = match (&col, &lit) {
                    ((c, false), Lit::Num(_)) => (self.unfloat(c.clone()), false),
                    _ => col,
                };
                if col.1 && has_upper(&lit) {
                    return unmatchable(expr);
                }
                cmp(col, op, lit)
            }
            Expr::In { expr: inner, target: InTarget::List(list), negated, .. } => match self.column(inner) {
                Some((col, ci)) => {
                    if ci && list.iter().any(|v| has_upper(&self.literal(v))) {
                        return unmatchable(expr);
                    }
                    let mut vals: Vec<Lit> =
                        list.iter().map(|v| if ci { self.literal(v).lowered() } else { self.literal(v) }).collect();
                    vals.sort();
                    vals.dedup();
                    let ci = ci && vals.iter().any(Lit::cased);
                    if vals.len() == 1 {
                        let op = if *negated { "!=" } else { "=" };
                        return Canon::Cmp { col, ci, op, val: vals.remove(0) };
                    }
                    Canon::In { col, ci, neg: *negated, vals }
                }
                None => Canon::Other(expr.to_string()),
            },
            Expr::Like { negated, expr: inner, pattern, escape_char: None, any: false } => {
                match (self.column(inner), self.literal(pattern)) {
                    (Some((_, true)), Lit::Str(p)) if p != p.to_lowercase() => unmatchable(expr),
                    (Some((col, ci)), Lit::Str(p)) => like(col, ci, *negated, p),
                    _ => Canon::Other(expr.to_string()),
                }
            }
            Expr::ILike { negated, expr: inner, pattern, escape_char: None, any: false } => {
                match (self.column(inner), self.literal(pattern)) {
                    (Some((col, _)), Lit::Str(p)) => like(col, true, *negated, p),
                    _ => Canon::Other(expr.to_string()),
                }
            }
            Expr::In { expr: inner, target: InTarget::Subquery(q), negated, global } => {
                match (self.column(inner), sub_canon(q, self.ctx)) {
                    (Some((col, ci)), Ok(sub)) => {
                        Canon::InSub { col, ci, neg: *negated, global: *global, sub: Box::new(sub) }
                    }
                    _ => Canon::Other(expr.to_string()),
                }
            }
            Expr::IsNull(inner) => match self.column(inner) {
                Some((col, _)) => Canon::Null { col, neg: false },
                None => Canon::Other(expr.to_string()),
            },
            Expr::IsNotNull(inner) => match self.column(inner) {
                Some((col, _)) => Canon::Null { col, neg: true },
                None => Canon::Other(expr.to_string()),
            },
            Expr::Between { expr: inner, negated, low, high } => {
                let both = and(vec![
                    self.predicate(&Expr::BinaryOp { left: inner.clone(), op: BinaryOperator::GtEq, right: low.clone() }),
                    self.predicate(&Expr::BinaryOp { left: inner.clone(), op: BinaryOperator::LtEq, right: high.clone() }),
                ]);
                if *negated {
                    not(both)
                } else {
                    both
                }
            }
            Expr::Function(f) => {
                let name = function_name(f).to_ascii_lowercase();
                match (name.as_str(), function_args(f).as_slice()) {
                    ("isnull", [Arg::Expr(e)]) | ("isnotnull", [Arg::Expr(e)]) => match self.column(e) {
                        Some((col, _)) => Canon::Null { col, neg: name == "isnotnull" },
                        None => Canon::Other(expr.to_string()),
                    },
                    ("startswith", [Arg::Expr(e), Arg::Expr(p)]) | ("endswith", [Arg::Expr(e), Arg::Expr(p)]) => {
                        match (self.column(e), self.literal(p)) {
                            (Some((col, ci)), Lit::Str(v)) => {
                                let body = like_escape(&v);
                                let pat = if name == "startswith" { format!("{body}%") } else { format!("%{body}") };
                                like(col, ci, false, pat)
                            }
                            _ => Canon::Other(expr.to_string()),
                        }
                    }
                    ("like" | "ilike" | "notlike" | "notilike", [Arg::Expr(e), Arg::Expr(p)]) => {
                        match (self.column(e), self.literal(p)) {
                            (Some((col, ci)), Lit::Str(v)) => {
                                like(col, ci || name.contains("ilike"), name.starts_with("not"), v)
                            }
                            _ => Canon::Other(expr.to_string()),
                        }
                    }
                    ("match", [Arg::Expr(e), Arg::Expr(p)]) => match (self.column(e), self.literal(p)) {
                        (Some((col, ci)), Lit::Str(v)) => Canon::Other(format!("match({}, '{v}')", col_text(&col, ci))),
                        _ => Canon::Other(expr.to_string()),
                    },
                    _ => Canon::Other(expr.to_string()),
                }
            }
            _ => Canon::Other(expr.to_string()),
        }
    }
}

/// The cap nPL's values() compiles with (the generator's
/// `max_group_array_size` default; pinned by a test).
pub(super) const NPL_VALUES_CAP: u64 = 100;

/// `arrayFilter(x -> x != '', groupUniqArray(<cap>)(toString(col)))`, the
/// generator's values() body.
fn is_values_shape(expr: &Expr) -> bool {
    let Expr::Function(filter) = expr else { return false };
    if !function_name(filter).eq_ignore_ascii_case("arrayFilter") {
        return false;
    }
    let filter_args = function_args(filter);
    let [Arg::Expr(lambda), Arg::Expr(Expr::Function(group))] = filter_args.as_slice() else { return false };
    let body: String = lambda.to_string().chars().filter(|c| !c.is_whitespace()).collect();
    if body != "x->x!=''" && body != "x->x<>''" {
        return false;
    }
    let cap_ok = matches!(&group.parameters, sqlparser::ast::FunctionArguments::List(l)
        if matches!(l.args.as_slice(), [sqlparser::ast::FunctionArg::Unnamed(sqlparser::ast::FunctionArgExpr::Expr(Expr::Value(v)))]
            if matches!(&v.value, Value::Number(n, _) if n.parse::<u64>().ok() == Some(NPL_VALUES_CAP))));
    let to_string = matches!(function_args(group).as_slice(), [Arg::Expr(Expr::Function(t))]
        if function_name(t).eq_ignore_ascii_case("toString"));
    function_name(group).eq_ignore_ascii_case("groupUniqArray") && cap_ok && to_string
}

fn find_group_uniq_arg(expr: &Expr) -> Option<&Expr> {
    match expr {
        Expr::Function(f) => {
            let args = function_args(f);
            if function_name(f).eq_ignore_ascii_case("groupUniqArray") {
                if let [Arg::Expr(e)] = args.as_slice() {
                    return Some(e);
                }
            }
            args.into_iter().find_map(|a| match a {
                Arg::Expr(e) => find_group_uniq_arg(e),
                _ => None,
            })
        }
        Expr::Lambda(l) => find_group_uniq_arg(&l.body),
        Expr::Nested(e) => find_group_uniq_arg(e),
        _ => None,
    }
}

/// In a SELECT's qualifiers: it reads a real table (not a CTE or subquery).
const BASE_TABLE_MARK: &str = "\u{0}table";

/// `GROUP BY 2` / `ORDER BY 2`: the 1-based SELECT item a bare integer
/// names (ClickHouse's `enable_positional_arguments`, on by default).
pub(super) fn positional(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Value(v) => match &v.value {
            Value::Number(n, _) => n.parse::<usize>().ok().filter(|n| *n > 0),
            _ => None,
        },
        _ => None,
    }
}

/// NAN-5608 P2-19: a bound on `timestamp` Search can run over: a window
/// placeholder or a literal instant (bare, or in a one-argument conversion).
fn known_bound(v: &Lit) -> bool {
    static CONVERTED: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
        regex::Regex::new(r"(?i)^(todatetime|todatetime64|parsedatetimebesteffort|parsedatetime64besteffort)\('([^'\\]*)'(, *\d+)?\)$")
            .expect("static regex")
    });
    match v {
        Lit::Str(s) => super::convert::parse_instant(s).is_some(),
        Lit::Expr(e) => {
            [super::convert::EARLIEST_SENTINEL, super::convert::LATEST_SENTINEL]
                .iter()
                .any(|s| e.strip_prefix(s).is_some_and(|pad| pad.chars().all(|c| c == '_')))
                || CONVERTED.captures(e).is_some_and(|c| super::convert::parse_instant(&c[2]).is_some())
        }
        _ => false,
    }
}

/// Is `canon` exactly one call of `name` (`name(…)` with the first `(`
/// closing at the very end)? Quote-aware: a literal may hold parentheses.
pub(super) fn is_single_call(canon: &str, name: &str) -> bool {
    let Some(rest) = canon.strip_prefix(name).and_then(|r| r.strip_prefix('(')) else { return false };
    let mut depth = 1usize;
    let mut in_str = false;
    let mut chars = rest.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' if in_str => {
                chars.next();
            }
            '\'' => in_str = !in_str,
            '(' if !in_str => depth += 1,
            ')' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return i == rest.len() - 1;
                }
            }
            _ => {}
        }
    }
    false
}

/// The operand of nPL's float parse of a value: `toFloat64OrNull(toString(x))`,
/// or its `coalesce(…, toFloat64(parseDateTime64BestEffortOrNull(toString(x), 3, 'UTC')))`
/// form (which only differs from it where `x` is not a number).
fn float_parse_operand(f: &sqlparser::ast::Function) -> Option<&Expr> {
    fn to_float_of(f: &sqlparser::ast::Function) -> Option<&Expr> {
        if !function_name(f).eq_ignore_ascii_case("toFloat64OrNull") {
            return None;
        }
        let [Arg::Expr(Expr::Function(s))] = function_args(f).as_slice() else { return None };
        if !function_name(s).eq_ignore_ascii_case("toString") {
            return None;
        }
        match function_args(s).as_slice() {
            [Arg::Expr(x)] => Some(*x),
            _ => None,
        }
    }
    let name = function_name(f).to_ascii_lowercase();
    if name == "tofloat64ornull" {
        return to_float_of(f);
    }
    if name != "coalesce" {
        return None;
    }
    let [Arg::Expr(Expr::Function(first)), Arg::Expr(Expr::Function(second))] = function_args(f).as_slice() else {
        return None;
    };
    let x = to_float_of(first)?;
    // The fallback leg: toFloat64(parseDateTime64BestEffortOrNull(toString(x), 3, 'UTC')).
    if !function_name(second).eq_ignore_ascii_case("toFloat64") {
        return None;
    }
    let [Arg::Expr(Expr::Function(parse))] = function_args(second).as_slice() else { return None };
    if !function_name(parse).eq_ignore_ascii_case("parseDateTime64BestEffortOrNull") {
        return None;
    }
    match function_args(parse).as_slice() {
        [Arg::Expr(Expr::Function(s)), _, _]
            if function_name(s).eq_ignore_ascii_case("toString")
                && matches!(function_args(s).as_slice(), [Arg::Expr(y)] if y.to_string() == x.to_string()) =>
        {
            Some(x)
        }
        _ => None,
    }
}

/// An expression with no column in it (a literal, a function of literals,
/// a window placeholder).
fn is_constant(expr: &Expr) -> bool {
    match expr {
        Expr::Value(_) => true,
        Expr::Identifier(_) => sentinel_of(expr).is_some(),
        Expr::Nested(e) | Expr::UnaryOp { expr: e, .. } => is_constant(e),
        Expr::BinaryOp { left, right, .. } => is_constant(left) && is_constant(right),
        Expr::Interval(i) => is_constant(&i.value),
        Expr::Function(f) => {
            !is_aggregate_name(&function_name(f))
                && function_args(f).iter().all(|a| matches!(a, Arg::Expr(e) if is_constant(e)))
        }
        _ => false,
    }
}

/// `multiIf(c1, v1, …, else)`, cut at the first constant-true condition
/// (its value is the result from there on, whatever follows).
fn multi_if(pairs: Vec<(String, String)>, otherwise: String) -> String {
    let mut kept = Vec::new();
    let mut otherwise = otherwise;
    for (c, v) in pairs {
        if c == "1" || c == "true" {
            otherwise = v;
            break;
        }
        kept.push(format!("{c}, {v}"));
    }
    if kept.is_empty() {
        return otherwise;
    }
    format!("multiif({}, {otherwise})", kept.join(", "))
}

/// `INTERVAL n unit` as `interval(n, unit)` (unit lowercase, singular).
fn interval_canon(i: &sqlparser::ast::Interval, reader: &Reader) -> Option<String> {
    let units = ["second", "minute", "hour", "day", "week", "month", "year"];
    let norm = |u: &str| {
        let u = u.to_ascii_lowercase();
        let u = u.strip_suffix('s').map(str::to_string).unwrap_or(u);
        units.contains(&u.as_str()).then_some(u)
    };
    if i.last_field.is_some() || i.fractional_seconds_precision.is_some() {
        return None;
    }
    match (&i.leading_field, reader.literal(&i.value)) {
        (Some(field), Lit::Num(n)) => Some(format!("interval({n}, {})", norm(&field.to_string())?)),
        (None, Lit::Str(s)) => {
            let (n, unit) = s.trim().split_once(char::is_whitespace)?;
            let n: u64 = n.parse().ok()?;
            Some(format!("interval({n}, {})", norm(unit.trim())?))
        }
        _ => None,
    }
}

/// The width of a `toStartOfInterval` bucket that the named functions
/// (`toStartOfHour`, …) and every other spelling of it compute alike: a
/// width in seconds, minutes or hours that divides a day evenly (epoch- and
/// day-aligned buckets then coincide on the UTC time column). Day and wider
/// buckets are not folded (`toStartOfInterval(…, INTERVAL 1 DAY)` is a
/// `Date`, `toStartOfDay` a `DateTime`).
fn bucket_seconds(interval: &str) -> Option<u64> {
    let inner = interval.strip_prefix("interval(")?.strip_suffix(')')?;
    let (n, unit) = inner.split_once(", ")?;
    let n: u64 = n.parse().ok()?;
    let secs = n.checked_mul(match unit {
        "second" => 1,
        "minute" => 60,
        "hour" => 3600,
        _ => return None,
    })?;
    (secs > 0 && secs < 86_400 && 86_400 % secs == 0).then_some(secs)
}

fn flatten<'e>(expr: &'e Expr, op: &BinaryOperator) -> Vec<&'e Expr> {
    match expr {
        Expr::BinaryOp { left, op: o, right } if o == op => {
            let mut v = flatten(left, op);
            v.extend(flatten(right, op));
            v
        }
        Expr::Nested(e) if matches!(e.as_ref(), Expr::BinaryOp { op: o, .. } if o == op) => flatten(e, op),
        _ => vec![expr],
    }
}

fn has_upper(lit: &Lit) -> bool {
    matches!(lit, Lit::Str(s) if *s != s.to_lowercase())
}

/// `lower(col)` compared with a value holding uppercase letters: it can never
/// match (`= …`) or always matches (`!= …`), whatever nPL says. Kept as an
/// opaque term so it never compares equal to nPL's case-folded form.
fn unmatchable(expr: &Expr) -> Canon {
    Canon::Other(format!("{expr} [lower() against an uppercase value]"))
}

fn cmp((col, ci): (String, bool), op: &'static str, val: Lit) -> Canon {
    let val = if ci { val.lowered() } else { val };
    let ci = ci && val.cased();
    Canon::Cmp { col, ci, op, val }
}

fn like(col: String, ci: bool, neg: bool, pat: String) -> Canon {
    let pat = if ci { pat.to_lowercase() } else { pat };
    let ci = ci && pat.to_lowercase() != pat.to_uppercase();
    Canon::Like { col, ci, neg, pat }
}

fn and(parts: Vec<Canon>) -> Canon {
    let mut set: BTreeSet<Canon> = BTreeSet::new();
    for p in parts {
        match p {
            Canon::True => {}
            Canon::And(inner) => set.extend(inner),
            other => {
                set.insert(other);
            }
        }
    }
    match set.len() {
        0 => Canon::True,
        1 => set.into_iter().next().expect("one"),
        _ => Canon::And(set.into_iter().collect()),
    }
}

fn or(parts: Vec<Canon>) -> Canon {
    let mut set: BTreeSet<Canon> = BTreeSet::new();
    for p in parts {
        match p {
            Canon::True => return Canon::True,
            Canon::Or(inner) => set.extend(inner),
            other => {
                set.insert(other);
            }
        }
    }
    match set.len() {
        1 => set.into_iter().next().expect("one"),
        _ => Canon::Or(set.into_iter().collect()),
    }
}

fn not(c: Canon) -> Canon {
    match c {
        Canon::Not(inner) => *inner,
        Canon::Cmp { col, ci, op, val } if matches!(op, "=" | "!=") => Canon::Cmp { col, ci, op: negate_op(op), val },
        Canon::In { col, ci, neg, vals } => Canon::In { col, ci, neg: !neg, vals },
        Canon::Like { col, ci, neg, pat } => Canon::Like { col, ci, neg: !neg, pat },
        Canon::Null { col, neg } => Canon::Null { col, neg: !neg },
        Canon::InSub { col, ci, neg, global, sub } => Canon::InSub { col, ci, neg: !neg, global, sub },
        other => Canon::Not(Box::new(other)),
    }
}

/// The pipeline a query reads as.
#[derive(Debug, Default, Clone)]
pub(super) struct Signature {
    table: Option<String>,
    filters: Vec<Canon>,
    grouped: bool,
    keys: Vec<String>,
    /// NAN-5630: the keys the aggregated result still shows.
    visible_keys: BTreeSet<String>,
    aggs: Vec<String>,
    post: Vec<Canon>,
    order: Option<Vec<String>>,
    limit: Option<u64>,
    /// The order in effect when the limit cut the rows.
    limit_order: Option<Vec<String>>,
    project: Option<Vec<String>>,
    /// Pipeline facts the other fields cannot express: a filter or an
    /// aggregation applied after a row limit, a second aggregation, and SQL
    /// clauses the comparison does not model (DISTINCT, OFFSET, LIMIT BY).
    /// Any difference here is a difference in results.
    shape: BTreeSet<String>,
}

/// CTE nesting the walk follows before giving up (and the guard against a
/// CTE that names itself).
const MAX_DEPTH: usize = 64;

#[derive(Default)]
struct Walk {
    sig: Signature,
    outputs: HashMap<String, String>,
    depth: usize,
    visiting: Vec<String>,
    /// NAN-5630: the aggregated result's computed columns, by output name:
    /// the aggregates, then any value a later stage computes from them
    /// (`| eval ratio=f/n`), less any a later stage drops
    /// (`SELECT * EXCEPT (…)`, nPL's `| fields - …`).
    agg_outputs: Vec<(String, String)>,
    /// The last SELECT's items, canonical, for a positional ORDER BY.
    last_projection: Vec<String>,
    /// The group keys the aggregated result shows: (output name, canon).
    key_names: Vec<(String, String)>,
}

/// Read the subquery of an `IN (SELECT …)` filter (NAN-5614). DISTINCT is
/// dropped (IN reads a set); everything an nPL subsearch cannot do is kept
/// in `extra` so it never compares equal to one.
fn sub_canon(q: &Query, ctx: &ConvertContext) -> Result<SubCanon, String> {
    let mut walk = Walk::default();
    walk.query(q, &HashMap::new(), ctx)?;
    let sig = walk.sig;
    let bounds = time_bounds_of(&sig.filters);
    let filters = normalize_conjuncts(sig.filters, true).into_iter().map(|c| resolve_windows(c, &bounds)).collect();
    // DISTINCT changes nothing IN matches, unless a LIMIT then cuts the rows.
    let mut extra: Vec<String> =
        sig.shape.iter().filter(|s| sig.limit.is_some() || s.as_str() != "SELECT DISTINCT").cloned().collect();
    if sig.grouped {
        extra.push(format!("GROUP BY [{}] computing [{}]", sig.keys.join(", "), sig.aggs.join(", ")));
    }
    if !sig.post.is_empty() {
        let post = normalize_conjuncts(sig.post, false);
        extra.push(format!("HAVING {}", post.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(" AND ")));
    }
    if sig.limit.is_some() {
        if let Some(order) = &sig.limit_order {
            extra.push(format!("ORDER BY [{}]", order.join(", ")));
        }
    }
    // IN compares the values, not their spelling: `toString(x)` returns
    // what `x` does (the subsearch returns its values as strings).
    let ret = match &sig.project {
        Some(cols) if !sig.grouped && cols.len() == 1 => {
            let c = &cols[0];
            Some(match c.strip_prefix("tostring(").and_then(|r| r.strip_suffix(')')) {
                Some(inner) if is_single_call(c, "tostring") => inner.to_string(),
                _ => c.clone(),
            })
        }
        _ => None,
    };
    Ok(SubCanon {
        table: sig.table.unwrap_or_else(|| "?".into()),
        ret,
        filters,
        bounds: Some(bounds),
        limit: sig.limit,
        extra,
    })
}

const RANGE_OPS: [&str; 4] = [">", ">=", "<", "<="];

/// The bounds on `timestamp` among a SELECT's (unnormalized) filters.
fn time_bounds_of(filters: &[Canon]) -> Vec<(&'static str, Lit)> {
    fn walk(c: &Canon, out: &mut Vec<(&'static str, Lit)>) {
        match c {
            Canon::And(v) => v.iter().for_each(|c| walk(c, out)),
            Canon::Cmp { col, op, val, .. } if col == TIME_COLUMN && RANGE_OPS.contains(op) => out.push((*op, val.clone())),
            _ => {}
        }
    }
    let mut out = Vec::new();
    filters.iter().for_each(|c| walk(c, &mut out));
    out.sort();
    out.dedup();
    out
}

/// Mark each `IN (SELECT …)` whose own window is `bounds` (the enclosing
/// query's) as running over the enclosing window.
fn resolve_windows(c: Canon, bounds: &[(&'static str, Lit)]) -> Canon {
    match c {
        // Rebuilt through and() / or() / not() so the result stays sorted.
        Canon::And(v) => and(v.into_iter().map(|c| resolve_windows(c, bounds)).collect()),
        Canon::Or(v) => or(v.into_iter().map(|c| resolve_windows(c, bounds)).collect()),
        Canon::Not(inner) => not(resolve_windows(*inner, bounds)),
        Canon::InSub { col, ci, neg, global, mut sub } => {
            if sub.bounds.as_deref() == Some(bounds) {
                sub.bounds = None;
            }
            Canon::InSub { col, ci, neg, global, sub }
        }
        other => other,
    }
}

impl Walk {
    /// What the table this walk reads guarantees.
    fn facts(&self) -> Facts {
        Facts { signals: matches!(self.sig.table.as_deref(), Some(SIGNALS_SOURCE) | Some(SIGNALS_TABLE)) }
    }

    fn query(&mut self, q: &Query, ctes: &HashMap<String, Query>, ctx: &ConvertContext) -> Result<(), String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("the query nests too deeply".into());
        }
        let mut ctes = ctes.clone();
        if let Some(with) = &q.with {
            for cte in &with.cte_tables {
                ctes.insert(cte.alias.name.value.clone(), (*cte.query).clone());
            }
        }
        match q.body.as_ref() {
            SetExpr::Select(s) => self.select(s, &ctes, ctx)?,
            SetExpr::Query(inner) => self.query(inner, &ctes, ctx)?,
            _ => return Err("a set operation".into()),
        }
        let qualifiers: Vec<String> = Vec::new();
        // NAN-5630: clauses that change the rows, or how the query reads
        // (`SETTINGS prefer_column_name_to_alias = 1`), and that no nPL has.
        if q.settings.is_some() {
            self.sig.shape.insert("SETTINGS".into());
        }
        if q.fetch.is_some() || !q.locks.is_empty() || q.format_clause.is_some() || q.for_clause.is_some() {
            self.sig.shape.insert("FETCH / FOR / FORMAT".into());
        }
        if let Some(order) = &q.order_by {
            if order.interpolate.is_some() {
                self.sig.shape.insert("ORDER BY … INTERPOLATE".into());
            }
            match &order.kind {
                OrderByKind::Expressions(items) => {
                    if items.iter().any(|i| i.with_fill.is_some()) {
                        self.sig.shape.insert("ORDER BY … WITH FILL".into());
                    }
                    if items.iter().any(|i| i.options.nulls_first.is_some()) {
                        self.sig.shape.insert("ORDER BY … NULLS FIRST / LAST".into());
                    }
                }
                _ => {
                    self.sig.shape.insert("ORDER BY ALL".into());
                }
            }
            if let OrderByKind::Expressions(items) = &order.kind {
                let reader = Reader { qualifiers: &qualifiers, outputs: &self.outputs, facts: self.facts(), ctx };
                let keys = items
                    .iter()
                    .map(|i| {
                        // `ORDER BY 2`: ClickHouse's positional arguments
                        // (on by default) name the second SELECT item.
                        let name = positional(&i.expr)
                            .and_then(|n| self.last_projection.get(n - 1).cloned())
                            .unwrap_or_else(|| reader.value(&i.expr));
                        let dir = if matches!(i.options.sort, Some(OrderBySort::Desc)) { "desc" } else { "asc" };
                        format!("{name} {dir}")
                    })
                    .collect();
                self.sig.order = Some(keys);
            }
        }
        match &q.limit_clause {
            Some(LimitClause::LimitOffset { offset, limit_by, .. }) => {
                if offset.is_some() {
                    self.sig.shape.insert("OFFSET".into());
                }
                if !limit_by.is_empty() {
                    self.sig.shape.insert("LIMIT … BY".into());
                }
            }
            Some(_) => {
                self.sig.shape.insert("LIMIT offset, count".into());
            }
            None => {}
        }
        if let Some(LimitClause::LimitOffset { limit: Some(Expr::Value(v)), .. }) = &q.limit_clause {
            if let Value::Number(n, _) = &v.value {
                if let Ok(n) = n.parse::<u64>() {
                    if n != PROBE_LIMIT {
                        self.sig.limit = Some(self.sig.limit.map_or(n, |l| l.min(n)));
                        self.sig.limit_order = self.sig.order.clone();
                    }
                }
            }
        }
        Ok(())
    }

    fn select(&mut self, s: &Select, ctes: &HashMap<String, Query>, ctx: &ConvertContext) -> Result<(), String> {
        let [from] = s.from.as_slice() else { return Err("not exactly one FROM table".into()) };
        if !from.joins.is_empty() {
            return Err("a JOIN".into());
        }
        let mut qualifiers = Vec::new();
        match &from.relation {
            TableFactor::Table { name, alias, args, sample, .. } => {
                // NAN-5608 P2-19: what no nPL does is a shape difference.
                if sample.is_some() {
                    self.sig.shape.insert("SAMPLE".into());
                }
                if args.is_some() {
                    self.sig.shape.insert("a table function".into());
                }
                let base = table_base(name);
                let cte_name = name.to_string();
                if let Some(cte) = ctes.get(&cte_name) {
                    if self.visiting.contains(&cte_name) {
                        return Err(format!("the CTE `{cte_name}` refers to itself"));
                    }
                    self.visiting.push(cte_name.clone());
                    self.query(cte, ctes, ctx)?;
                    self.visiting.pop();
                } else {
                    let table = match table_kind(&base, ctx) {
                        TableKind::Events => ctx.events_table().to_string(),
                        TableKind::Signals => SIGNALS_SOURCE.to_string(),
                        TableKind::SignalsTable => SIGNALS_TABLE.to_string(),
                        TableKind::Other(t) => t,
                    };
                    self.sig.table = Some(table.clone());
                    qualifiers.push(BASE_TABLE_MARK.to_string());
                    qualifiers.push(base.clone());
                    qualifiers.push(table);
                    qualifiers.push(name.to_string());
                }
                if let Some(a) = alias {
                    qualifiers.push(a.name.value.clone());
                }
            }
            TableFactor::Derived { subquery, alias, .. } => {
                self.query(subquery, ctes, ctx)?;
                if let Some(a) = alias {
                    qualifiers.push(a.name.value.clone());
                }
            }
            _ => return Err("a table function".into()),
        }

        match &s.distinct {
            Some(sqlparser::ast::Distinct::On(_)) => {
                self.sig.shape.insert("SELECT DISTINCT ON".into());
            }
            Some(_) => {
                self.sig.shape.insert("SELECT DISTINCT".into());
            }
            None => {}
        }
        // NAN-5630: what the converter refuses (check_select_shape) is a
        // shape here, so nPL from elsewhere never matches it.
        if s.top.is_some() {
            self.sig.shape.insert("SELECT TOP".into());
        }
        if s.qualify.is_some() || !s.named_window.is_empty() {
            self.sig.shape.insert("QUALIFY / WINDOW".into());
        }
        if !s.lateral_views.is_empty() || !s.connect_by.is_empty() || s.into.is_some() {
            self.sig.shape.insert("LATERAL VIEW / CONNECT BY / INTO".into());
        }
        if !s.cluster_by.is_empty() || !s.distribute_by.is_empty() || !s.sort_by.is_empty() {
            self.sig.shape.insert("CLUSTER / DISTRIBUTE / SORT BY".into());
        }
        let group_exprs: Vec<&Expr> = match &s.group_by {
            GroupByExpr::Expressions(e, modifiers) => {
                // NAN-5608 P2-19: ROLLUP / CUBE / TOTALS add rows no nPL adds.
                if !modifiers.is_empty() {
                    self.sig.shape.insert("GROUP BY … WITH ROLLUP / CUBE / TOTALS / GROUPING SETS".into());
                }
                e.iter().collect()
            }
            GroupByExpr::All(_) => return Err("GROUP BY ALL".into()),
        };
        let aggregating = !group_exprs.is_empty()
            || s.projection.iter().any(|i| match i {
                SelectItem::UnnamedExpr(e) | SelectItem::ExprWithAlias { expr: e, .. } => contains_aggregate(e),
                _ => false,
            });

        // Projection: aliases this stage defines. NAN-5630: ClickHouse
        // resolves a SELECT alias anywhere in the same SELECT (other items,
        // WHERE, GROUP BY, HAVING), in whatever order the items come, so the
        // computed aliases are resolved first: each sees every OTHER alias
        // (its own name inside its definition is the column), to a fixed
        // point.
        let aliased: Vec<(String, &Expr)> = s
            .projection
            .iter()
            .filter_map(|item| match item {
                SelectItem::ExprWithAlias { expr, alias } if !contains_aggregate(expr) => {
                    Some((alias.value.clone(), expr))
                }
                _ => None,
            })
            .collect();
        let mut resolved: HashMap<String, String> = HashMap::new();
        for _ in 0..=aliased.len().min(MAX_DEPTH) {
            let mut next = HashMap::new();
            for (name, expr) in &aliased {
                let mut outs = self.outputs.clone();
                for (n, c) in &resolved {
                    if n != name {
                        outs.insert(n.clone(), c.clone());
                    }
                }
                let c = Reader { qualifiers: &qualifiers, outputs: &outs, facts: self.facts(), ctx }.value(expr);
                next.insert(name.clone(), c);
            }
            if next == resolved {
                break;
            }
            resolved = next;
        }
        let mut new_outputs = self.outputs.clone();
        for (n, c) in &resolved {
            if n != c {
                new_outputs.insert(n.clone(), c.clone());
            }
        }
        let mut columns: Option<Vec<String>> = Some(Vec::new());
        // (output name, canon) of the aggregates, and of the other items.
        let mut agg_items: Vec<(String, String)> = Vec::new();
        let mut plain_items: Vec<(String, String)> = Vec::new();
        let mut item_canons: Vec<String> = Vec::new();
        // Items that are a wildcard, and the names it leaves out.
        let mut wildcard = false;
        let mut excepted: Vec<String> = Vec::new();
        {
            let reader = Reader { qualifiers: &qualifiers, outputs: &new_outputs, facts: self.facts(), ctx };
            for item in &s.projection {
                let (expr, alias) = match item {
                    SelectItem::UnnamedExpr(e) => (e, None),
                    SelectItem::ExprWithAlias { expr, alias } => (expr, Some(alias.value.clone())),
                    SelectItem::Wildcard(opts) | SelectItem::QualifiedWildcard(_, opts) => {
                        wildcard = true;
                        if let Some(e) = &opts.opt_except {
                            excepted.push(e.first_element.value.clone());
                            excepted.extend(e.additional_elements.iter().map(|i| i.value.clone()));
                        }
                        if let Some(e) = &opts.opt_exclude {
                            match e {
                                sqlparser::ast::ExcludeSelectItem::Single(i) => excepted.push(i.to_string()),
                                sqlparser::ast::ExcludeSelectItem::Multiple(v) => {
                                    excepted.extend(v.iter().map(|i| i.to_string()))
                                }
                            }
                        }
                        if opts.opt_replace.is_some() || opts.opt_rename.is_some() || opts.opt_ilike.is_some() {
                            self.sig.shape.insert("a `*` with REPLACE / RENAME / ILIKE".into());
                        }
                        columns = None;
                        item_canons.push("*".into());
                        continue;
                    }
                    _ => {
                        columns = None;
                        self.sig.shape.insert("a multi-alias SELECT item".into());
                        item_canons.push("?".into());
                        continue;
                    }
                };
                if let Expr::Function(f) = expr {
                    if f.over.is_some() {
                        self.sig.shape.insert("a window function".into());
                    }
                }
                if contains_aggregate(expr) {
                    // NAN-5630: an expression over aggregates
                    // (`countIf(c) / count()`) reads structurally, its
                    // aggregate calls canonical.
                    let canon = match expr {
                        Expr::Function(f) if is_aggregate_name(&function_name(f)) => reader.aggregate(expr),
                        _ => reader.value(expr),
                    };
                    agg_items.push((alias.clone().unwrap_or_else(|| expr.to_string()), canon.clone()));
                    item_canons.push(canon);
                    continue;
                }
                // An aliased item is what the alias resolved to (reading it
                // again through `new_outputs` would apply `f(x) AS x` twice).
                let c = match &alias {
                    Some(a) => resolved.get(a).cloned().unwrap_or_else(|| reader.value(expr)),
                    None => reader.value(expr),
                };
                if let Some(cols) = columns.as_mut() {
                    cols.push(c.clone());
                }
                plain_items.push((alias.clone().unwrap_or_else(|| expr.to_string()), c.clone()));
                item_canons.push(c);
            }
        }
        for item in &s.projection {
            if let SelectItem::ExprWithAlias { expr, alias } = item {
                if contains_aggregate(expr) {
                    if let Some((_, canon)) = agg_items.iter().find(|(n, _)| *n == alias.value) {
                        new_outputs.insert(alias.value.clone(), canon.clone());
                        new_outputs.insert(expr.to_string(), canon.clone());
                    }
                }
            } else if let SelectItem::UnnamedExpr(expr) = item {
                if let Some((_, canon)) = agg_items.iter().find(|(n, _)| *n == expr.to_string()) {
                    new_outputs.insert(expr.to_string(), canon.clone());
                }
            }
        }
        self.last_projection = item_canons.clone();
        // WHERE reads names of the stage below plus this SELECT's own aliases
        // (ClickHouse resolves a SELECT alias inside its WHERE); a
        // post-aggregation stage's names are the aggregate outputs.
        {
            let reader = Reader { qualifiers: &qualifiers, outputs: &new_outputs, facts: self.facts(), ctx };
            let wheres: Vec<Canon> = [s.prewhere.as_ref(), s.selection.as_ref()]
                .into_iter()
                .flatten()
                .flat_map(conjuncts)
                .map(|c| reader.predicate(c))
                .collect();
            if !wheres.is_empty() && self.sig.limit.is_some() {
                self.sig.shape.insert("a filter after the row limit".into());
            }
            if self.sig.grouped {
                self.sig.post.extend(wheres);
            } else {
                self.sig.filters.extend(wheres);
            }
        }
        self.outputs = new_outputs;

        if aggregating {
            if self.sig.limit.is_some() {
                self.sig.shape.insert("an aggregation after the row limit".into());
            }
            if self.sig.grouped {
                self.sig.shape.insert("a second aggregation".into());
            }
            let reader = Reader { qualifiers: &qualifiers, outputs: &self.outputs, facts: self.facts(), ctx };
            let mut keys: Vec<String> = group_exprs
                .iter()
                .map(|g| {
                    positional(g)
                        .and_then(|n| item_canons.get(n - 1).cloned())
                        .unwrap_or_else(|| reader.value(g))
                })
                .collect();
            keys.sort();
            keys.dedup();
            self.sig.grouped = true;
            // NAN-5630: an item computed from the keys (`lower(k)` next to
            // `GROUP BY k`) is an output column too.
            // The keys the result shows, by name: a later stage may drop
            // or overwrite one.
            self.key_names = plain_items.iter().filter(|(_, c)| keys.contains(c)).cloned().collect();
            self.sig.visible_keys = self.key_names.iter().map(|(_, c)| c.clone()).collect();
            let computed = plain_items.into_iter().filter(|(_, c)| !keys.contains(c));
            self.agg_outputs = agg_items.into_iter().chain(computed).collect();
            self.sig.keys = keys;
            let having: Vec<Canon> =
                s.having.iter().flat_map(conjuncts).map(|c| reader.predicate(c)).collect();
            self.sig.post.extend(having);
            self.sync_aggs();
            self.sig.project = None;
        } else if self.sig.grouped {
            // NAN-5630: a stage over the aggregated rows. A computed item
            // adds (or replaces) an output column; `* EXCEPT (…)` drops
            // some; an explicit column list keeps only the ones it names.
            let named: Vec<String> = s
                .projection
                .iter()
                .filter_map(|i| match i {
                    SelectItem::UnnamedExpr(Expr::Identifier(id)) => Some(id.value.clone()),
                    SelectItem::ExprWithAlias { alias, .. } => Some(alias.value.clone()),
                    _ => None,
                })
                .collect();
            if !wildcard {
                self.agg_outputs.retain(|(n, _)| named.contains(n));
            }
            self.agg_outputs.retain(|(n, _)| !excepted.contains(n));
            // A key the stage leaves out, or redefines, is gone from the result.
            let dropped: Vec<(String, String)> = self
                .key_names
                .iter()
                .filter(|(n, c)| {
                    (!wildcard && !named.contains(n))
                        || excepted.contains(n)
                        || plain_items.iter().any(|(pn, pc)| pn == n && pc != c)
                })
                .cloned()
                .collect();
            for (n, c) in &dropped {
                self.key_names.retain(|(kn, _)| kn != n);
                if !self.key_names.iter().any(|(_, kc)| kc == c) {
                    self.sig.visible_keys.remove(c);
                }
            }
            for (name, canon) in plain_items {
                let existing = self.agg_outputs.iter().any(|(n, _)| *n == name);
                if !existing && self.sig.keys.contains(&canon) {
                    // A group key passed through.
                    continue;
                }
                self.agg_outputs.retain(|(n, _)| *n != name);
                self.agg_outputs.push((name, canon));
            }
            self.sync_aggs();
        } else if let Some(cols) = columns {
            self.sig.project = Some(cols);
        }
        Ok(())
    }

    fn sync_aggs(&mut self) {
        let mut aggs: Vec<String> = self.agg_outputs.iter().map(|(_, c)| c.clone()).collect();
        aggs.sort();
        self.sig.aggs = aggs;
    }
}

/// Read a SQL query (the converter's preprocessed original, or the
/// generator's output) into its signature.
pub(super) fn signature_of_sql(sql: &str, ctx: &ConvertContext) -> Result<Signature, String> {
    // `json.^"key"` (a JSON column's sub-object) is ClickHouse-only syntax
    // sqlparser does not read; as a plain subcolumn it canonicalizes the same.
    let sql = sql.replace(".^\"", ".\"");
    let q = parse_one(&sql).map_err(|u| u.reason)?;
    let mut walk = Walk::default();
    walk.query(&q, &HashMap::new(), ctx)?;
    let mut sig = walk.sig;
    // NAN-5614: an `IN (SELECT …)` over the query's own window runs over the
    // window an nPL subsearch runs over.
    let bounds = time_bounds_of(&sig.filters);
    // NAN-5608 P2-19: the bounds are dropped from the comparison (they are
    // the Search time range, not a term), so one Search cannot run over
    // (`now() - INTERVAL 1 DAY`, an epoch number) is a shape of its own.
    for (op, v) in &bounds {
        if !known_bound(v) {
            sig.shape.insert(format!(
                "a time bound `timestamp {op} {v}` that is neither the run window nor a literal instant, so \
                 Search cannot run over it"
            ));
        }
    }
    sig.filters = normalize_conjuncts(sig.filters, true).into_iter().map(|c| resolve_windows(c, &bounds)).collect();
    sig.post = normalize_conjuncts(sig.post, false).into_iter().map(|c| resolve_windows(c, &bounds)).collect();
    Ok(sig)
}

/// Flatten, drop `true` and (pre-aggregation) the time bounds, sort.
fn normalize_conjuncts(parts: Vec<Canon>, drop_time: bool) -> Vec<Canon> {
    let all = and(parts);
    let list = match all {
        Canon::True => Vec::new(),
        Canon::And(v) => v,
        other => vec![other],
    };
    let list: Vec<Canon> = list
        .into_iter()
        .filter(|c| {
            !(drop_time && matches!(c, Canon::Cmp { col, op, .. } if col == TIME_COLUMN && matches!(*op, ">" | ">=" | "<" | "<=")))
        })
        .collect();
    // The generator adds a token prefilter next to a multi-word substring
    // match (`LIKE '%a b%' AND LIKE '%a%'`, for the text index). A substring
    // conjunct another conjunct on the same column already implies changes
    // nothing: drop it on both sides.
    let implied = |c: &Canon| {
        let Canon::Like { col, ci, neg: false, pat } = c else { return false };
        let Some(x) = pat.strip_prefix('%').and_then(|p| p.strip_suffix('%')).filter(|x| !x.contains(['%', '_', '\\'])) else {
            return false;
        };
        list.iter().any(|d| match d {
            Canon::Like { col: c2, ci: ci2, neg: false, pat: p2 } if d != c && c2 == col && ci2 == ci && !p2.contains(['_', '\\']) => {
                p2.split('%').any(|seg| seg.contains(x))
            }
            _ => false,
        })
    };
    list.iter().filter(|c| !implied(c)).cloned().collect()
}

/// How a signature names the detections a query reads (NAN-5612): every
/// detection that fired (the `{signals}` placeholder; what `dataset=signals`
/// reads) versus the physical real-time `signals` table alone.
pub(super) const SIGNALS_SOURCE: &str = "signals";
pub(super) const SIGNALS_TABLE: &str = "signals table (real-time detections only)";

/// Does this signature read the detections (either form)?
pub(super) fn reads_signals(sig: &Signature) -> bool {
    matches!(sig.table.as_deref(), Some(SIGNALS_SOURCE) | Some(SIGNALS_TABLE))
}

/// Compile nPL the way Search does (one WHERE with the bounds, `lower(col)`
/// index forms, no SETTINGS) against the context's events table, or, for
/// `dataset=signals` (NAN-5612), against the detections source, which the
/// comparison names by its placeholder (the source itself is the shared
/// detections builder, identical on both sides by construction).
pub(super) fn compile_npl(npl: &str, ctx: &ConvertContext, dataset: Dataset) -> Result<String, String> {
    let ast = parse_query(npl).map_err(|e| format!("nPL parse error: {e}"))?;
    // The override also names the source of a `[dataset=signals …]`
    // subsearch from a logs query (NAN-5614).
    // Unrestricted: a conversion probe compiled for comparison, never a
    // viewer's read.
    let mut generator = ClickHouseSqlGenerator::scoped_with_table(
        ctx.events_table().to_string(),
        crate::query::GeneratorScope::unrestricted(),
    )
        .with_profile(ctx.profile.clone())
        .with_cluster_routing(false)
        .with_signals_source_override(super::convert::SIGNALS_SENTINEL);
    if dataset == Dataset::Signals {
        generator = generator.with_dataset(Dataset::Signals);
    }
    let options = QueryOptions { limit: Some(PROBE_LIMIT as usize), omit_settings: true, ..QueryOptions::default() };
    let start = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).single().ok_or("bad probe instant")?;
    let range = TimeRange::new(start, start + chrono::Duration::days(1));
    generator
        .generate_with_options(&ast, &range, &options)
        .map_err(|e| format!("nPL could not be compiled: {e}"))
}

/// Strip what Search matches more loosely than SQL: case and the hostname
/// FQDN prefix (`h = 'x' OR startsWith(h, 'x.')`).
fn loosen(c: &Canon) -> Canon {
    match c {
        Canon::Cmp { col, op, val, .. } => Canon::Cmp { col: col.clone(), ci: false, op, val: val.clone().lowered() },
        Canon::In { col, neg, vals, .. } => {
            Canon::In { col: col.clone(), ci: false, neg: *neg, vals: vals.iter().cloned().map(Lit::lowered).collect() }
        }
        Canon::Like { col, neg, pat, .. } => Canon::Like { col: col.clone(), ci: false, neg: *neg, pat: pat.to_lowercase() },
        Canon::And(v) => and(v.iter().map(loosen).collect()),
        Canon::Or(v) => {
            // Search widens `h = 'x'` to `h = 'x' OR startsWith(h, 'x.')`:
            // drop only the prefix disjunct that matches a sibling value.
            let mut values: Vec<(String, String)> = Vec::new();
            for x in v {
                match x {
                    Canon::Cmp { col, op: "=", val: Lit::Str(s), .. } => values.push((col.clone(), s.to_lowercase())),
                    Canon::In { col, neg: false, vals, .. } => values.extend(
                        vals.iter().filter_map(|l| match l {
                            Lit::Str(s) => Some((col.clone(), s.to_lowercase())),
                            _ => None,
                        }),
                    ),
                    _ => {}
                }
            }
            let fqdn = |x: &Canon| match x {
                Canon::Like { col, neg: false, pat, .. } => {
                    values.iter().any(|(c, val)| c == col && *pat == format!("{}.%", like_escape(val)))
                }
                _ => false,
            };
            or(v.iter().filter(|x| !fqdn(x)).map(loosen).collect())
        }
        Canon::Not(inner) => not(loosen(inner)),
        other => other.clone(),
    }
}

/// `generated` is `original` with only a row cap added to its subquery:
/// the cap.
fn capped_subsearch(original: &Canon, generated: &Canon) -> Option<u64> {
    match (original, generated) {
        (
            Canon::InSub { col, ci, neg, global, sub },
            Canon::InSub { col: c2, ci: ci2, neg: n2, global: g2, sub: s2 },
        ) if col == c2 && ci == ci2 && neg == n2 && global == g2 && sub.limit.is_none() => {
            let cap = s2.limit?;
            // The subsearch's DISTINCT matters only under its cap.
            let extra = s2.extra.iter().filter(|e| e.as_str() != "SELECT DISTINCT").cloned().collect();
            let uncapped = SubCanon { limit: None, extra, ..(**s2).clone() };
            (**sub == uncapped).then_some(cap)
        }
        _ => None,
    }
}

fn compare_predicates(what: &str, original: &[Canon], generated: &[Canon], out: &mut Vec<Difference>) {
    let o: BTreeSet<&Canon> = original.iter().collect();
    let g: BTreeSet<&Canon> = generated.iter().collect();
    let mut missing: Vec<&Canon> = o.difference(&g).copied().collect();
    let mut extra: Vec<&Canon> = g.difference(&o).copied().collect();
    // Pair each loosened match: Search matches it more broadly.
    let mut i = 0;
    while i < missing.len() {
        let loose = loosen(missing[i]);
        // Case folding narrows a negated match, so only a positive one can
        // be called broader.
        let negated = matches!(
            missing[i],
            Canon::Not(_) | Canon::Cmp { op: "!=", .. } | Canon::In { neg: true, .. } | Canon::Like { neg: true, .. }
        );
        if let Some(j) = extra.iter().position(|e| !negated && loosen(e) == loose) {
            out.push(Difference::broader(format!(
                "{what}: Search matches `{}` where the SQL matched `{}` (case-insensitive, or a hostname's FQDN too)",
                extra[j], missing[i]
            )));
            extra.remove(j);
            missing.remove(i);
        } else {
            i += 1;
        }
    }
    // NAN-5614: an `IN (SELECT …)` the nPL subsearch reproduces in all but
    // its row cap.
    let mut i = 0;
    while i < missing.len() {
        if let Some(j) = extra.iter().position(|e| capped_subsearch(missing[i], e).is_some()) {
            let cap = capped_subsearch(missing[i], extra[j]).expect("matched");
            out.push(Difference::different(format!(
                "{what}: the nPL subsearch returns at most {cap} distinct values, in no set order, where the SQL \
                 subquery returns all of them (`{}`); once more than {cap} values match, Search can return \
                 different rows",
                missing[i]
            )));
            extra.remove(j);
            missing.remove(i);
        } else {
            i += 1;
        }
    }
    for m in missing {
        out.push(Difference::different(format!("{what}: the nPL does not apply `{m}`")));
    }
    for e in extra {
        out.push(Difference::different(format!("{what}: the nPL also applies `{e}`")));
    }
}

/// `groupUniqArray([N])(c)` in the SQL against nPL's `values(c)`: the
/// generated aggregate it pairs with, and how they differ.
fn values_difference(m: &str, generated: &BTreeSet<&String>) -> Option<(String, String)> {
    let rest = m.strip_prefix("groupUniqArray(")?;
    let (cap, col) = match rest.split_once(")(") {
        Some((n, c)) => (Some(n), c.strip_suffix(')')?),
        None => (None, rest.strip_suffix(')')?),
    };
    let values = format!("values({col})");
    if !generated.contains(&values) {
        return None;
    }
    let sql = match cap {
        Some(n) => format!("keeps at most {n} distinct `{col}` values (an arbitrary {n}) as an array"),
        None => format!("keeps every distinct `{col}` value as an array"),
    };
    let detail = format!(
        "aggregate: `{m}` {sql}; nPL's values({col}) keeps up to {} distinct values, drops empty ones and joins them \
         into one comma-separated string",
        NPL_VALUES_CAP
    );
    Some((values, detail))
}

/// Every way `generated` departs from `original`.
pub(super) fn compare(original: &Signature, generated: &Signature) -> Vec<Difference> {
    let mut out = Vec::new();
    for s in original.shape.difference(&generated.shape) {
        out.push(Difference::different(format!("shape: the SQL has {s}, the nPL does not")));
    }
    for s in generated.shape.difference(&original.shape) {
        out.push(Difference::different(format!("shape: the nPL has {s}, the SQL does not")));
    }
    if original.table.as_deref() == Some(SIGNALS_TABLE) && generated.table.as_deref() == Some(SIGNALS_SOURCE) {
        out.push(Difference::broader(
            "table: the SQL reads the real-time `signals` table only; dataset=signals also reads scheduled \
             detections (findings)",
        ));
    } else if original.table != generated.table {
        out.push(Difference::different(format!(
            "table: the SQL reads `{}`, the nPL reads `{}`",
            original.table.as_deref().unwrap_or("?"),
            generated.table.as_deref().unwrap_or("?")
        )));
    }
    compare_predicates("filter", &original.filters, &generated.filters, &mut out);
    if original.grouped != generated.grouped {
        out.push(Difference::different(if original.grouped {
            "the SQL aggregates, the nPL does not"
        } else {
            "the nPL aggregates, the SQL does not"
        }));
    }
    if original.keys != generated.keys {
        out.push(Difference::different(format!(
            "group by: the SQL groups by [{}], the nPL by [{}]",
            original.keys.join(", "),
            generated.keys.join(", ")
        )));
    }
    if original.grouped && generated.grouped {
        for k in original.visible_keys.difference(&generated.visible_keys) {
            out.push(Difference::different(format!(
                "group by: the SQL returns the key `{k}`, the nPL drops or overwrites it"
            )));
        }
    }
    if original.aggs != generated.aggs {
        let o: BTreeSet<&String> = original.aggs.iter().collect();
        let g: BTreeSet<&String> = generated.aggs.iter().collect();
        let mut explained: BTreeSet<String> = BTreeSet::new();
        for m in o.difference(&g) {
            let nonempty = ["dc", "estdc"].into_iter().find_map(|func| {
                let rest = m.strip_prefix(func)?.strip_prefix('(')?;
                Some((func, format!("{func}_nonempty({rest}")))
            });
            if let Some((func, _)) = nonempty.as_ref().filter(|(_, n)| g.contains(n)) {
                out.push(Difference::different(format!(
                    "aggregate: `{m}` in the SQL counts empty values; nPL's {func}() skips them"
                )));
            } else if let Some((values, detail)) = values_difference(m, &g) {
                out.push(Difference::different(detail));
                explained.insert(values);
            } else if let Some(col) = m.strip_prefix("any(").and_then(|r| r.strip_suffix(')')) {
                let first = format!("argmin({col}, {TIME_COLUMN})");
                if g.contains(&first) {
                    out.push(Difference::different(format!(
                        "aggregate: `{m}` returns an arbitrary row's `{col}`; nPL's first({col}) returns the earliest \
                         row's, one of the values the SQL could return"
                    )));
                    explained.insert(first);
                } else {
                    out.push(Difference::different(format!("aggregate: the nPL does not compute `{m}`")));
                }
            } else {
                out.push(Difference::different(format!("aggregate: the nPL does not compute `{m}`")));
            }
        }
        for e in g.difference(&o) {
            if !e.starts_with("dc_nonempty(") && !e.starts_with("estdc_nonempty(") && !explained.contains(*e) {
                out.push(Difference::different(format!("aggregate: the nPL computes `{e}`, which the SQL does not")));
            }
        }
    }
    compare_predicates("having", &original.post, &generated.post, &mut out);
    let (o_order, g_order) = if original.limit.is_some() {
        (&original.limit_order, &generated.limit_order)
    } else {
        (&original.order, &generated.order)
    };
    // The dc() empty-value difference is reported once, above.
    let g_order = g_order.as_ref().map(|g| g.iter().map(|k| k.replace("dc_nonempty(", "dc(")).collect::<Vec<_>>());
    if let Some(o) = o_order {
        if Some(o) != g_order.as_ref() {
            out.push(Difference::different(format!(
                "order: the SQL sorts by [{}], the nPL by [{}]",
                o.join(", "),
                g_order.as_ref().map(|g| g.join(", ")).unwrap_or_default()
            )));
        }
    }
    if original.limit != generated.limit {
        out.push(Difference::different(format!(
            "limit: the SQL keeps {}, the nPL keeps {}",
            original.limit.map_or("all rows".to_string(), |l| format!("{l} rows")),
            generated.limit.map_or("all rows".to_string(), |l| format!("{l} rows"))
        )));
    }
    if let Some(cols) = &original.project {
        if !original.grouped && Some(cols) != generated.project.as_ref() {
            out.push(Difference::different(format!(
                "columns: the SQL returns [{}], the nPL returns {}",
                cols.join(", "),
                generated.project.as_ref().map(|g| format!("[{}]", g.join(", "))).unwrap_or("every column".into())
            )));
        }
    }
    out
}
