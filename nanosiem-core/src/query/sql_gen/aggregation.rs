// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregation SQL generation (stats and timechart commands)
//!
//! Generates PostgreSQL SQL for stats and timechart aggregation commands,
//! supporting all aggregation functions (count, sum, avg, dc, percentile, etc.).

use super::field_utils::*;
use super::SqlGenError;
use crate::query::ast::*;
use std::fmt::Write;

impl super::SqlGenerator {
    /// Generate SQL for stats command
    pub(super) fn generate_stats_sql(
        &self,
        source: &str,
        aggregations: &[Aggregation],
        group_by: Option<&[String]>,
    ) -> Result<String, SqlGenError> {
        let agg_exprs: Vec<String> = aggregations
            .iter()
            .map(|agg| {
                let (field_expr, _) = agg
                    .field
                    .as_ref()
                    .map(|f| field_to_sql_expr(f))
                    .unwrap_or_else(|| ("*".to_string(), false));

                // Build the aggregation expression based on function type
                let agg_expr = match agg.func {
                    AggFunc::Count => format!("COUNT({})", field_expr),
                    AggFunc::Dc => format!("COUNT(DISTINCT {})", field_expr),
                    AggFunc::Sum => format!("SUM({})", field_expr),
                    AggFunc::Avg => format!("AVG({})", field_expr),
                    AggFunc::Min => format!("MIN({})", field_expr),
                    AggFunc::Max => format!("MAX({})", field_expr),
                    AggFunc::Values => format!("ARRAY_AGG(DISTINCT {})", field_expr),
                    AggFunc::List => format!("ARRAY_AGG({})", field_expr),
                    AggFunc::First => {
                        format!("(ARRAY_AGG({} ORDER BY timestamp ASC))[1]", field_expr)
                    }
                    AggFunc::Last => {
                        format!("(ARRAY_AGG({} ORDER BY timestamp DESC))[1]", field_expr)
                    }
                    AggFunc::Range => format!("(MAX({}) - MIN({}))", field_expr, field_expr),
                    AggFunc::Earliest => format!("MIN({})", field_expr), // For timestamps
                    AggFunc::Latest => format!("MAX({})", field_expr),   // For timestamps
                    AggFunc::Stdev => format!("STDDEV({})", field_expr),
                    AggFunc::Var => format!("VARIANCE({})", field_expr),
                    AggFunc::Median => format!(
                        "PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY {})",
                        field_expr
                    ),
                    AggFunc::Perc95 => format!(
                        "PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY {})",
                        field_expr
                    ),
                    AggFunc::Percentile(pct) => format!(
                        "PERCENTILE_CONT({}) WITHIN GROUP (ORDER BY {})",
                        pct as f64 / 100.0,
                        field_expr
                    ),
                    AggFunc::Mode => format!("MODE() WITHIN GROUP (ORDER BY {})", field_expr),
                    AggFunc::Sparkline => {
                        // PostgreSQL sparkline: bucket events by time and count per bucket.
                        // Uses ARRAY_AGG on a time-bucketed count subquery pattern.
                        // Simplified: just count 1 per event for now (PG is fallback).
                        "ARRAY_AGG(1 ORDER BY timestamp)".to_string()
                    }
                };

                // Determine the alias:
                // 1. Use explicit alias if provided
                // 2. For count(*), default to "count"
                // 3. For other aggregations, use the function name (e.g., "dc", "sum", "avg")
                let alias = if let Some(a) = agg.alias.as_ref() {
                    format!(" AS {}", escape_identifier(a))
                } else if agg.field.is_none() && agg.func == AggFunc::Count {
                    " AS count".to_string()
                } else {
                    // Use function name as default alias for aggregations
                    format!(" AS {}", agg.func.as_str())
                };
                format!("{}{}", agg_expr, alias)
            })
            .collect();

        let select_clause = match group_by {
            Some(fields) => {
                let group_fields: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let (expr, needs_alias) = field_to_sql_expr(f);
                        if needs_alias {
                            format!("{} AS {}", expr, escape_identifier(f))
                        } else {
                            expr
                        }
                    })
                    .collect();
                format!("{}, {}", group_fields.join(", "), agg_exprs.join(", "))
            }
            None => agg_exprs.join(", "),
        };

        let mut sql = format!("  SELECT {}\n  FROM {}", select_clause, source);

        if let Some(fields) = group_by {
            let group_fields: Vec<String> = fields
                .iter()
                .map(|f| {
                    let (expr, _) = field_to_sql_expr(f);
                    expr
                })
                .collect();
            write!(sql, "\n  GROUP BY {}", group_fields.join(", ")).unwrap();
        }

        Ok(sql)
    }

    /// Generate SQL for timechart command
    pub(super) fn generate_timechart_sql(
        &self,
        source: &str,
        span: &std::time::Duration,
        aggregations: &[Aggregation],
        split_by: &[String],
    ) -> Result<String, SqlGenError> {
        // Determine the date_trunc interval
        let interval = duration_to_interval(span);

        let agg_exprs: Vec<String> = aggregations
            .iter()
            .map(|agg| {
                let (field_expr, _) = agg
                    .field
                    .as_ref()
                    .map(|f| field_to_sql_expr(f))
                    .unwrap_or_else(|| ("*".to_string(), false));

                // For dc() (distinct count), wrap with DISTINCT
                let field_expr = if agg.func == AggFunc::Dc {
                    format!("DISTINCT {}", field_expr)
                } else {
                    field_expr
                };

                // Build the full aggregation expression
                let agg_expr = match agg.func {
                    AggFunc::Count => format!("COUNT({})", field_expr),
                    AggFunc::Dc => format!("COUNT({})", field_expr),
                    AggFunc::Sum => format!("SUM({})", field_expr),
                    AggFunc::Avg => format!("AVG({})", field_expr),
                    AggFunc::Min => format!("MIN({})", field_expr),
                    AggFunc::Max => format!("MAX({})", field_expr),
                    AggFunc::Values => format!("ARRAY_AGG(DISTINCT {})", field_expr),
                    AggFunc::List => format!("ARRAY_AGG({})", field_expr),
                    AggFunc::First => {
                        format!("(ARRAY_AGG({} ORDER BY timestamp ASC))[1]", field_expr)
                    }
                    AggFunc::Last => {
                        format!("(ARRAY_AGG({} ORDER BY timestamp DESC))[1]", field_expr)
                    }
                    AggFunc::Range => format!("(MAX({}) - MIN({}))", field_expr, field_expr),
                    AggFunc::Earliest => format!("MIN({})", field_expr),
                    AggFunc::Latest => format!("MAX({})", field_expr),
                    AggFunc::Stdev => format!("STDDEV({})", field_expr),
                    AggFunc::Var => format!("VARIANCE({})", field_expr),
                    AggFunc::Median => format!(
                        "PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY {})",
                        field_expr
                    ),
                    AggFunc::Perc95 => format!(
                        "PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY {})",
                        field_expr
                    ),
                    AggFunc::Percentile(pct) => format!(
                        "PERCENTILE_CONT({}) WITHIN GROUP (ORDER BY {})",
                        pct as f64 / 100.0,
                        field_expr
                    ),
                    AggFunc::Mode => format!("MODE() WITHIN GROUP (ORDER BY {})", field_expr),
                    AggFunc::Sparkline => {
                        // PostgreSQL sparkline: bucket events by time and count per bucket.
                        // Uses ARRAY_AGG on a time-bucketed count subquery pattern.
                        // Simplified: just count 1 per event for now (PG is fallback).
                        "ARRAY_AGG(1 ORDER BY timestamp)".to_string()
                    }
                };
                let alias = agg
                    .alias
                    .as_ref()
                    .or(agg.field.as_ref())
                    .map(|a| format!(" AS {}", escape_identifier(a)))
                    .unwrap_or_else(|| {
                        if agg.field.is_none() && agg.func == AggFunc::Count {
                            " AS count".to_string()
                        } else {
                            String::new()
                        }
                    });
                format!("{}{}", agg_expr, alias)
            })
            .collect();

        let time_bucket = format!("date_trunc('{}', timestamp) AS time_bucket", interval);

        let select_clause = if split_by.is_empty() {
            format!("{}, {}", time_bucket, agg_exprs.join(", "))
        } else {
            let split_selects: Vec<String> = split_by
                .iter()
                .map(|field| {
                    let (field_expr, needs_alias) = field_to_sql_expr(field);
                    if needs_alias {
                        format!("{} AS {}", field_expr, escape_identifier(field))
                    } else {
                        field_expr.clone()
                    }
                })
                .collect();
            format!(
                "{}, {}, {}",
                time_bucket,
                split_selects.join(", "),
                agg_exprs.join(", ")
            )
        };

        let mut sql = format!("  SELECT {}\n  FROM {}", select_clause, source);

        let group_clause = if split_by.is_empty() {
            "time_bucket".to_string()
        } else {
            let split_group_bys: Vec<String> = split_by
                .iter()
                .map(|field| {
                    let (field_expr, _) = field_to_sql_expr(field);
                    field_expr
                })
                .collect();
            format!("time_bucket, {}", split_group_bys.join(", "))
        };
        write!(sql, "\n  GROUP BY {}\n  ORDER BY time_bucket", group_clause).unwrap();

        Ok(sql)
    }
}
