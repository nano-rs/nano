// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregation types for the query AST
//!
//! This module defines aggregation functions and specifications used by
//! stats, timechart, eventstats, and streamstats commands.

use serde::{Deserialize, Serialize};

use super::eval::EvalExpression;

/// Aggregation specification for stats/timechart commands
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Aggregation {
    /// Aggregation function
    pub func: AggFunc,
    /// Field to aggregate (None for count())
    pub field: Option<String>,
    /// Optional alias for the result
    pub alias: Option<String>,
    /// Optional condition for conditional aggregation (e.g., count(eval(status_code=200)))
    pub condition: Option<EvalExpression>,
    /// Optional expression argument (e.g., sum(bytes_in + bytes_out))
    /// When present, takes precedence over `field` for SQL generation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_expr: Option<EvalExpression>,
}

impl Aggregation {
    /// Create a new aggregation
    pub fn new(func: AggFunc, field: Option<String>) -> Self {
        Self {
            func,
            field,
            alias: None,
            condition: None,
            field_expr: None,
        }
    }

    /// Create a new aggregation with an alias
    pub fn with_alias(func: AggFunc, field: Option<String>, alias: String) -> Self {
        Self {
            func,
            field,
            alias: Some(alias),
            condition: None,
            field_expr: None,
        }
    }

    /// Create a new conditional aggregation (e.g., count(eval(condition)))
    pub fn with_condition(func: AggFunc, field: Option<String>, condition: EvalExpression) -> Self {
        Self {
            func,
            field,
            alias: None,
            condition: Some(condition),
            field_expr: None,
        }
    }
}

/// Aggregation functions
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AggFunc {
    /// Count of records
    Count,
    /// Distinct count of field values
    Dc,
    /// Sum of field values
    Sum,
    /// Average of field values
    Avg,
    /// Minimum field value
    Min,
    /// Maximum field value
    Max,
    /// Collect all unique values into an array
    Values,
    /// Collect all values into an array (including duplicates)
    List,
    /// First value in the group (by timestamp)
    First,
    /// Last value in the group (by timestamp)
    Last,
    /// Range (max - min)
    Range,
    /// Earliest (minimum) timestamp value
    Earliest,
    /// Latest (maximum) timestamp value
    Latest,
    /// Standard deviation
    Stdev,
    /// Variance
    Var,
    /// Median (50th percentile)
    Median,
    /// 95th percentile
    Perc95,
    /// Percentile (requires parameter 0-100)
    Percentile(u8),
    /// Mode (most common value)
    Mode,
    /// Sparkline (mini time-series chart, collects values into array)
    Sparkline,
}

impl AggFunc {
    /// Returns the string representation of the function
    pub fn as_str(&self) -> &'static str {
        match self {
            AggFunc::Count => "count",
            AggFunc::Dc => "dc",
            AggFunc::Sum => "sum",
            AggFunc::Avg => "avg",
            AggFunc::Min => "min",
            AggFunc::Max => "max",
            AggFunc::Values => "values",
            AggFunc::List => "list",
            AggFunc::First => "first",
            AggFunc::Last => "last",
            AggFunc::Range => "range",
            AggFunc::Earliest => "earliest",
            AggFunc::Latest => "latest",
            AggFunc::Stdev => "stdev",
            AggFunc::Var => "var",
            AggFunc::Median => "median",
            AggFunc::Perc95 => "perc95",
            AggFunc::Percentile(_) => "percentile",
            AggFunc::Mode => "mode",
            AggFunc::Sparkline => "sparkline",
        }
    }
}

impl Eq for AggFunc {}
