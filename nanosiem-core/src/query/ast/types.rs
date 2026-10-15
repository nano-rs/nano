// SPDX-License-Identifier: AGPL-3.0-or-later

//! Core AST types for piped query language
//!
//! This module defines the fundamental AST node types: Query, SearchExpr,
//! Comparator, Value, and time/binning-related types.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

use super::commands::Command;
use super::eval::EvalExpression;

/// Span specification for bin command - supports both time and numeric binning
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BinSpan {
    /// Time-based binning (e.g., 10m, 1h, 1d)
    Time(Duration),
    /// Numeric binning (e.g., 5000 for bytes, 100 for counts)
    Numeric(f64),
    /// `bins=N` (NAN-3312): at most N buckets. Only defined for the time
    /// column, where the SQL generator derives a round span from the query
    /// time range; a non-time field is rejected rather than guessed.
    Bins(u32),
}

/// Window type for time-based binning
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum WindowType {
    /// Tumbling window: fixed-size, non-overlapping windows (default)
    /// Each event belongs to exactly one window
    #[default]
    Tumbling,
    /// Hop window: fixed-size windows that advance by a specified interval
    /// Events may belong to multiple windows (overlapping)
    /// Example: 1-hour window advancing every 5 minutes
    Hop {
        /// How much the window advances each step
        advance: Duration,
    },
    /// Sliding window: window slides with each event
    /// Every event starts a new window of the specified span
    Sliding,
}

/// Time interval units for INTERVAL syntax
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntervalUnit {
    /// Microseconds
    Microsecond,
    /// Milliseconds
    Millisecond,
    /// Seconds
    Second,
    /// Minutes
    Minute,
    /// Hours
    Hour,
    /// Days
    Day,
    /// Weeks
    Week,
    /// Months (approximated as 30 days)
    Month,
    /// Years (approximated as 365 days)
    Year,
}

impl IntervalUnit {
    /// Returns the string representation of the interval unit
    pub fn as_str(&self) -> &'static str {
        match self {
            IntervalUnit::Microsecond => "microsecond",
            IntervalUnit::Millisecond => "millisecond",
            IntervalUnit::Second => "second",
            IntervalUnit::Minute => "minute",
            IntervalUnit::Hour => "hour",
            IntervalUnit::Day => "day",
            IntervalUnit::Week => "week",
            IntervalUnit::Month => "month",
            IntervalUnit::Year => "year",
        }
    }

    /// Returns the plural form of the interval unit
    pub fn as_plural_str(&self) -> &'static str {
        match self {
            IntervalUnit::Microsecond => "microseconds",
            IntervalUnit::Millisecond => "milliseconds",
            IntervalUnit::Second => "seconds",
            IntervalUnit::Minute => "minutes",
            IntervalUnit::Hour => "hours",
            IntervalUnit::Day => "days",
            IntervalUnit::Week => "weeks",
            IntervalUnit::Month => "months",
            IntervalUnit::Year => "years",
        }
    }

    /// Convert to seconds (approximation for months/years)
    pub fn to_seconds(&self, value: u64) -> u64 {
        match self {
            IntervalUnit::Microsecond => value / 1_000_000,
            IntervalUnit::Millisecond => value / 1_000,
            IntervalUnit::Second => value,
            IntervalUnit::Minute => value.saturating_mul(60),
            IntervalUnit::Hour => value.saturating_mul(3600),
            IntervalUnit::Day => value.saturating_mul(86400),
            IntervalUnit::Week => value.saturating_mul(604800),
            IntervalUnit::Month => value.saturating_mul(2592000), // 30 days
            IntervalUnit::Year => value.saturating_mul(31536000), // 365 days
        }
    }
}

/// Root query type - either a search expression or a piped query
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Query {
    /// Simple search expression without pipes
    Search(SearchExpr),
    /// Piped query: source | command
    Piped {
        source: Box<Query>,
        command: Command,
    },
}

/// Search expression types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SearchExpr {
    /// Keyword search (uses BM25)
    Keyword(String),
    /// Field filter: field op value
    FieldFilter {
        field: String,
        op: Comparator,
        value: Value,
        /// How the right-hand side was WRITTEN in the source text (NAN-2380).
        /// Defaults to [`RhsSyntax::Literal`], so nodes built in code — and
        /// ASTs deserialized from before this field existed — keep the
        /// literal-value semantics they have always had.
        #[serde(default)]
        rhs: RhsSyntax,
    },
    /// Function filter: function(args) op value
    FunctionFilter {
        function: EvalExpression,
        op: Comparator,
        value: Value,
    },
    /// Field function filter: field op function(args)
    FieldFunctionFilter {
        field: String,
        op: Comparator,
        function: EvalExpression,
    },
    /// Field IN list: field IN (val1, val2, ...)
    InList {
        field: String,
        values: Vec<Value>,
        negated: bool,
    },
    /// Logical AND of two expressions
    And(Box<SearchExpr>, Box<SearchExpr>),
    /// Logical OR of two expressions
    Or(Box<SearchExpr>, Box<SearchExpr>),
    /// Logical NOT of an expression
    Not(Box<SearchExpr>),
    /// Grouped expression (parentheses)
    Group(Box<SearchExpr>),
    /// Standalone boolean function predicate: isnull(field), like(field, pattern), cidrmatch(cidr, ip), etc.
    /// Used in `| where` for functions that return a boolean without needing op + value
    BooleanFunction(EvalExpression),
    /// Arithmetic/computed predicate used by piped `where` clauses, for example
    /// `(last_seen - first_seen) >= 300`. Ordinary field filters deliberately
    /// stay in the variants above so their index-aware SQL generation is
    /// unchanged.
    EvalPredicate(EvalExpression),
    /// Literal string comparison: "value" = "value"
    /// Used for parameter expansion checks like "$user"="*"
    LiteralComparison {
        left: String,
        op: Comparator,
        right: Value,
    },
    /// IOC observable match (NAN-1580): match a value (or list of values, or
    /// values sourced from an enrichment feed) across ALL observable columns
    /// (src_ip, dest_ip, file_hash, url, query, user_id, sender, cve, …).
    /// Parsed from the `ioc=<v>` / `ioc in [v1, v2]` / `ioc in feed("arg")`
    /// surface forms. Usable on its own as a normal observable term; when paired
    /// with `| retro` it drives the retro-hunt display.
    IocMatch {
        /// Literal indicator values. Empty when sourced from a feed or lookup.
        values: Vec<Value>,
        /// Enrichment-feed source (`ioc in threatfox("apt29")`). `None` for
        /// literal value / list / lookup forms.
        feed: Option<IocFeed>,
        /// Internal lookup-table source (`ioc in lookup("threat_iocs")`).
        /// `None` for literal value / list / feed forms (NAN-1581 Phase 6).
        /// Mutually exclusive with `feed`. The service layer PRE-RESOLVES this to
        /// concrete `values` (via `LookupService`) before SQL generation, so the
        /// sql-gen never sees an unresolved lookup source.
        lookup: Option<IocLookup>,
    },
    /// Field IN [search ...] subsearch filter
    InSubsearch {
        field: String,
        subsearch: Box<Query>,
        negated: bool,
        /// Cross-dataset correlation (NAN-1562): the dataset the subsearch runs
        /// against, parsed from a leading `dataset=<logs|spans|metrics>` token
        /// inside the `[ ]` brackets. `None` means the subsearch inherits the
        /// outer query's dataset (the pre-existing, byte-identical behavior).
        subsearch_dataset: Option<crate::query::clickhouse_sql_gen::otel::Dataset>,
    },
}

/// Enrichment-feed source for an IOC observable match (NAN-1580).
///
/// Built from the `ioc in <feed>("<arg>")` surface form. Named providers
/// (threatfox, misp, otx, feodo, abuse) interpret `arg` as a provider-specific
/// selector such as an actor/campaign. The generic `feed("source")` form
/// addresses a tenant-defined enrichment source by exact ID or display name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocFeed {
    /// Feed selector (feed | threatfox | misp | otx | feodo | abuse).
    pub name: String,
    /// Feed-specific query argument (e.g. "apt29").
    pub arg: String,
}

/// Internal lookup-table source for an IOC observable match (NAN-1581 Phase 6).
///
/// Built from the `ioc in lookup("<table>")` / `ioc in lookup("<table>",
/// "<column>")` surface forms (and the `ioc in [inputlookup <table>]` alias). The
/// indicator values are read from the named lookup table's `column` (defaulting
/// to the table's registry primary-key column when omitted) and pre-resolved to
/// concrete `IocMatch::values` by the service layer before SQL generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocLookup {
    /// Logical lookup-table name (as registered in the lookup registry).
    pub table: String,
    /// Optional column to read indicator values from. `None` ⇒ the table's
    /// registry primary-key column.
    pub column: Option<String>,
}

/// How the right-hand side of a [`SearchExpr::FieldFilter`] was WRITTEN (NAN-2380).
///
/// `nano` has always parsed `a = b` and `a = "b"` into the identical AST, so a
/// field REFERENCE and a string LITERAL were indistinguishable downstream. That
/// is why `| where src_ip != dest_ip` compiled to `src_ip != 'dest_ip'` — true
/// for every row — instead of a column-to-column comparison: the exact inverse
/// of the intended predicate, returned with a plausible row count and no error.
///
/// Carrying the surface form on the node lets the SQL generator — the one place
/// that also knows the active schema profile — tell the two readings apart. The
/// marker is inert everywhere else: consumers that ignore it behave exactly as
/// they did before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum RhsSyntax {
    /// The RHS is unambiguously a VALUE: it was quoted in the source text
    /// (`user="dest_ip"`), it is a typed literal (number / bool / IP / regex /
    /// interval), or the node was constructed in code. Default, so nothing that
    /// does not opt in changes meaning.
    #[default]
    Literal,
    /// The RHS was an unquoted, identifier-shaped bare token in the source text
    /// (`| where src_ip != dest_ip`). Ambiguous by construction: it may be a
    /// value that happens to spell a column name (`target_type=user`) or a
    /// reference to that column.
    Bareword,
}

/// True when `s` is an unquoted, identifier-shaped token — the only RHS text
/// that is AMBIGUOUS between a value and a column reference (NAN-2380).
///
/// Single source of truth for three places that must agree exactly:
///   * the parser, which stamps [`RhsSyntax::Bareword`] on such an RHS,
///   * the pretty-printer, which must re-emit those values BARE so the marker
///     survives the AST -> text -> AST round-trip the source-scope gate does,
///   * the SQL generator, which decides what the token means.
///
/// Deliberately narrow: dotted identifier segments only. Wildcards, IPs, paths,
/// emails, hyphens, digits-first tokens and the reserved words are excluded, so
/// anything that could not re-tokenize verbatim as a bare value is never marked.
pub fn is_bareword_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if matches!(
        s.to_ascii_uppercase().as_str(),
        "AND" | "OR" | "NOT" | "TRUE" | "FALSE"
    ) {
        return false;
    }
    s.split('.').all(|segment| {
        let mut chars = segment.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Comparison operators for field filters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Comparator {
    /// Equal (=)
    Eq,
    /// Not equal (!=)
    Ne,
    /// Greater than (>)
    Gt,
    /// Less than (<)
    Lt,
    /// Greater than or equal (>=)
    Gte,
    /// Less than or equal (<=)
    Lte,
    /// Regex match (=/pattern/)
    Regex,
    /// Negated regex match (!=/pattern/)
    NotRegex,
    /// LIKE pattern match (field LIKE "pattern")
    Like,
    /// NOT LIKE pattern match
    NotLike,
    /// Contains substring (field CONTAINS "value")
    Contains,
    /// Does not contain substring (field NOT CONTAINS "value")
    NotContains,
    /// Starts with (field STARTSWITH "value")
    StartsWith,
    /// Does not start with (field NOT STARTSWITH "value")
    NotStartsWith,
    /// Ends with (field ENDSWITH "value")
    EndsWith,
    /// Does not end with (field NOT ENDSWITH "value")
    NotEndsWith,
}

impl Comparator {
    /// Returns the string representation of the comparator
    pub fn as_str(&self) -> &'static str {
        match self {
            Comparator::Eq => "=",
            Comparator::Ne => "!=",
            Comparator::Gt => ">",
            Comparator::Lt => "<",
            Comparator::Gte => ">=",
            Comparator::Lte => "<=",
            Comparator::Regex => "=",
            Comparator::NotRegex => "!=",
            Comparator::Like => "LIKE",
            Comparator::NotLike => "NOT LIKE",
            Comparator::Contains => "CONTAINS",
            Comparator::NotContains => "NOT CONTAINS",
            Comparator::StartsWith => "STARTSWITH",
            Comparator::NotStartsWith => "NOT STARTSWITH",
            Comparator::EndsWith => "ENDSWITH",
            Comparator::NotEndsWith => "NOT ENDSWITH",
        }
    }
}

/// Value types for field filters
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// String value (quoted or unquoted)
    String(String),
    /// Numeric value (integer or float)
    Number(f64),
    /// Boolean value
    Bool(bool),
    /// IP address value
    Ip(IpAddr),
    /// Regex pattern (from /pattern/ syntax)
    Regex(String),
    /// Time interval (INTERVAL 1 DAY, INTERVAL 2 HOUR, etc.)
    Interval(Duration, IntervalUnit),
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::String(s) => {
                // Quote strings that are empty, contain spaces, or special characters
                if s.is_empty() || s.contains(' ') || s.contains('|') || s.contains('"') {
                    write!(f, "\"{}\"", s.replace('"', "\\\""))
                } else {
                    write!(f, "{}", s)
                }
            }
            Value::Number(n) => {
                if n.fract() == 0.0 {
                    write!(f, "{}", *n as i64)
                } else {
                    write!(f, "{}", n)
                }
            }
            Value::Bool(b) => write!(f, "{}", b),
            Value::Ip(ip) => write!(f, "{}", ip),
            Value::Regex(pattern) => {
                // Escape only delimiters that are not already escaped. The parser
                // preserves regex escapes, so blindly replacing `/` breaks `/\\/`.
                write!(f, "/")?;
                let mut escaped = false;
                for ch in pattern.chars() {
                    if ch == '/' && !escaped {
                        write!(f, "\\")?;
                    }
                    write!(f, "{ch}")?;
                    escaped = ch == '\\' && !escaped;
                }
                write!(f, "/")
            }
            Value::Interval(duration, unit) => {
                // NAN-3080: print the value IN ITS UNIT. Printing the seconds
                // count with the unit multiplied the interval on every
                // pretty-print/re-parse round trip (every lean detection is
                // re-serialized by source pinning): `INTERVAL 24 HOUR` ran as
                // `INTERVAL 86400 HOURS`, almost ten years.
                let secs = duration.as_secs();
                let per_unit = unit.to_seconds(1);
                if per_unit > 0 && secs % per_unit == 0 {
                    write!(f, "INTERVAL {} {}", secs / per_unit, unit.as_plural_str().to_uppercase())
                } else {
                    write!(f, "INTERVAL {secs} SECONDS")
                }
            }
        }
    }
}
