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

    /// The output column name this aggregation will emit in the SELECT clause.
    ///
    /// Must stay in sync with the alias scheme in
    /// `clickhouse_sql_gen/aggregation.rs`. Downstream commands (e.g. the
    /// auto-sort rewrite in `search/query_processing/auto_sort.rs`) reference
    /// this name when building `SortField`s.
    pub fn output_alias(&self) -> String {
        if let Some(a) = &self.alias {
            return a.clone();
        }
        if self.field.is_none() && self.func == AggFunc::Count {
            return "count".to_string();
        }
        if matches!(self.func, AggFunc::Values | AggFunc::List) {
            if let Some(field) = &self.field {
                return format!("{}_{}", self.func.as_str(), field);
            }
        }
        self.func.as_str().to_string()
    }

    /// SPL-style display name, `func(arg)` (`dc(device.hostname)`,
    /// `perc99(bytes)`, `count(eval(...))`).
    fn display_name(&self) -> String {
        use crate::query::PrettyPrint;
        if let (AggFunc::Percentile(pct), Some(field), None) =
            (self.func, &self.field, &self.field_expr)
        {
            return format!("perc{pct}({field})");
        }
        Aggregation { alias: None, ..self.clone() }.pretty_print()
    }

    /// NAN-4279 (F10): give un-aliased aggregations that would share an output
    /// column a unique, SPL-style name.
    ///
    /// The default output name is the bare function (`dc`), so
    /// `stats dc(a), dc(b)` emitted two `AS dc` columns and chDB refused the
    /// query (MULTIPLE_EXPRESSIONS_FOR_ALIAS). Only colliding aggregations are
    /// renamed, to `dc(a)` / `dc(b)`, so every query that worked before keeps
    /// its column names (`stats dc(src_ip) by x | where dc > 5`). A field-less
    /// `count` keeps `count`. An exact repeat gets a numeric suffix.
    pub fn disambiguate_default_aliases(aggregations: &mut [Aggregation]) {
        use std::collections::{HashMap, HashSet};
        let mut uses: HashMap<String, usize> = HashMap::new();
        for agg in aggregations.iter() {
            *uses.entry(agg.output_alias()).or_default() += 1;
        }
        if uses.values().all(|&n| n == 1) {
            return;
        }
        let mut taken: HashSet<String> = aggregations
            .iter()
            .filter(|agg| agg.alias.is_some())
            .map(Aggregation::output_alias)
            .collect();
        let renamed: Vec<bool> = aggregations
            .iter()
            .map(|agg| {
                agg.alias.is_none()
                    && uses[&agg.output_alias()] > 1
                    && (agg.field.is_some() || agg.field_expr.is_some() || agg.condition.is_some())
            })
            .collect();
        // Names that stay as they are are reserved first, so a rename can
        // never take a column another aggregation keeps.
        for (agg, renamed) in aggregations.iter().zip(&renamed) {
            if !renamed {
                taken.insert(agg.output_alias());
            }
        }
        for (agg, renamed) in aggregations.iter_mut().zip(renamed) {
            if !renamed {
                continue;
            }
            let base = agg.display_name();
            let mut name = base.clone();
            let mut n = 2;
            while !taken.insert(name.clone()) {
                name = format!("{base}_{n}");
                n += 1;
            }
            agg.alias = Some(name);
        }
    }
}

/// Aggregation functions
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AggFunc {
    /// Count of records
    Count,
    /// Distinct count of field values (exact — uniqExact; memory grows
    /// linearly with cardinality, ~190 B per distinct string state)
    Dc,
    /// Approximate distinct count (uniqCombined64 — ~0.9% measured error,
    /// fixed small memory footprint; use on high-cardinality fields)
    EstDc,
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
    /// Per-second rate of a (cumulative) counter over the group's time window
    /// (NAN-1528, OTLP metrics). `rate(value)`.
    Rate,
    /// Histogram quantile (NAN-1528, OTLP metrics). The `u8` is the percentile
    /// (0-100), mirroring [`AggFunc::Percentile`]. `histogram_quantile(value, N)`.
    HistogramQuantile(u8),
}

impl AggFunc {
    /// Returns the string representation of the function
    pub fn as_str(&self) -> &'static str {
        match self {
            AggFunc::Count => "count",
            AggFunc::Dc => "dc",
            AggFunc::EstDc => "estdc",
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
            AggFunc::Rate => "rate",
            AggFunc::HistogramQuantile(_) => "histogram_quantile",
        }
    }

    /// Whether descending sort on this aggregation's output gives an analyst
    /// a useful "biggest first" view — i.e. whether it's a reasonable default
    /// for implicit top-N ordering.
    ///
    /// Note: this is about *meaning*, not type. `min(string_field)` is
    /// technically lexically sortable but a desc sort on it surfaces "the
    /// alphabetically highest single value per group", which is rarely what
    /// the analyst wants. The exclusions below capture aggregations where
    /// descending order is either type-ambiguous (`mode`, `first`, `last`)
    /// or structurally non-comparable (`values`, `list`, `sparkline` — these
    /// produce arrays/concatenated strings).
    pub fn is_meaningful_for_top_n(&self) -> bool {
        !matches!(
            self,
            AggFunc::Values
                | AggFunc::List
                | AggFunc::Sparkline
                | AggFunc::Mode
                | AggFunc::First
                | AggFunc::Last
        )
    }
}

impl Eq for AggFunc {}
