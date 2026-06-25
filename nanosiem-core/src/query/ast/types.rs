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
            IntervalUnit::Minute => value * 60,
            IntervalUnit::Hour => value * 3600,
            IntervalUnit::Day => value * 86400,
            IntervalUnit::Week => value * 604800,
            IntervalUnit::Month => value * 2592000, // 30 days
            IntervalUnit::Year => value * 31536000, // 365 days
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
    /// Literal string comparison: "value" = "value"
    /// Used for parameter expansion checks like "$user"="*"
    LiteralComparison {
        left: String,
        op: Comparator,
        right: Value,
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
            Value::Regex(pattern) => write!(f, "/{}/", pattern.replace('/', "\\/")),
            Value::Interval(duration, unit) => {
                let value = duration.as_secs();
                write!(
                    f,
                    "INTERVAL {} {}",
                    value,
                    unit.as_plural_str().to_uppercase()
                )
            }
        }
    }
}
