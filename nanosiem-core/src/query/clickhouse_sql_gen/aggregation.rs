// SPDX-License-Identifier: AGPL-3.0-or-later

//! Aggregation SQL generation (stats and timechart commands)
//!
//! Generates ClickHouse SQL for GROUP BY aggregations and time-bucketed charts.

use super::eval_functions::eval_expression_to_sql;
use super::helpers::*;
use super::ClickHouseSqlGenerator;
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;
use std::fmt::Write;

impl ClickHouseSqlGenerator {
    /// Generate SQL for stats command
    pub(super) fn generate_stats_sql(
        &self,
        source: &str,
        aggregations: &[Aggregation],
        group_by: Option<&[String]>,
        sparkline_span_secs: Option<u64>,
    ) -> Result<String, SqlGenError> {
        // Pre-compute which aggregation aliases shadow their input field
        // e.g. `min(timestamp) AS timestamp` — ClickHouse inlines CTEs and expands
        // aliases, so downstream stages would see `min(timestamp)` instead of a plain
        // column, causing ILLEGAL_AGGREGATION errors.
        let shadowed_aliases: Vec<String> = aggregations
            .iter()
            .filter_map(|agg| {
                let alias_name = agg.alias.as_ref().cloned().unwrap_or_default();
                if !alias_name.is_empty() {
                    if let Some(field) = &agg.field {
                        if normalize_field_name(field) == alias_name {
                            return Some(alias_name);
                        }
                    }
                }
                None
            })
            .collect();

        let agg_exprs: Vec<String> = aggregations.iter()
            .map(|agg| {
                // Check if this is a conditional aggregation
                if let Some(condition) = &agg.condition {
                    // Conditional aggregation: func(eval(condition))
                    let cond_sql = eval_expression_to_sql(self, condition)?;

                    let agg_expr = match agg.func {
                        AggFunc::Count => format!("countIf({})", cond_sql),
                        AggFunc::Sum => {
                            // For sum(eval(if(cond, field, 0))), extract field and condition
                            // For now, just use sumIf with the condition
                            if let Some(field) = &agg.field {
                                let (field_expr, _) = field_to_sql_expr(field, self);
                                format!("sumIf({}, {})", field_expr, cond_sql)
                            } else {
                                format!("sumIf(1, {})", cond_sql)
                            }
                        }
                        AggFunc::Avg => {
                            if let Some(field) = &agg.field {
                                let (field_expr, _) = field_to_sql_expr(field, self);
                                format!("avgIf({}, {})", field_expr, cond_sql)
                            } else {
                                format!("avgIf(1, {})", cond_sql)
                            }
                        }
                        _ => {
                            // For other functions, fall back to regular aggregation
                            return Err(SqlGenError::UnsupportedOperation(
                                format!("Conditional aggregation not supported for {:?}", agg.func)
                            ));
                        }
                    };

                    let alias = agg.alias.as_ref()
                        .map(|a| format!(" AS {}", escape_identifier(a)))
                        .unwrap_or_else(|| format!(" AS {}", agg.func.as_str()));

                    Ok(format!("{}{}", agg_expr, alias))
                } else {
                    // Regular aggregation
                    // Check for expression argument first (e.g., sum(bytes_in + bytes_out))
                    let (field_expr, _) = if let Some(expr) = &agg.field_expr {
                        (eval_expression_to_sql(self, expr)?, false)
                    } else {
                        agg.field.as_ref()
                            .map(|f| field_to_sql_expr(f, self))
                            .unwrap_or_else(|| ("*".to_string(), false))
                    };

                    // Use count() without args when counting all rows - it's 20-30% faster
                    // as it skips memory allocation (ClickHouse 2025+ optimization)
                    let agg_expr = match agg.func {
                        AggFunc::Count => {
                            if field_expr == "*" {
                                "count()".to_string()
                            } else {
                                format!("count({})", field_expr)
                            }
                        }
                    AggFunc::Dc => format!("uniqExact({})", field_expr),
                    AggFunc::Sum => format!("sum({})", field_expr),
                    AggFunc::Avg => format!("avg({})", field_expr),
                    AggFunc::Min => format!("min({})", field_expr),
                    AggFunc::Max => format!("max({})", field_expr),
                    AggFunc::Values => format!("arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::List => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::First => format!("argMin({}, timestamp)", field_expr),
                    AggFunc::Last => format!("argMax({}, timestamp)", field_expr),
                    AggFunc::Range => format!("(max({}) - min({}))", field_expr, field_expr),
                    AggFunc::Earliest => format!("min({})", field_expr),
                    AggFunc::Latest => format!("max({})", field_expr),
                    AggFunc::Stdev => format!("stddevPop({})", field_expr),
                    AggFunc::Var => format!("varPop({})", field_expr),
                    AggFunc::Median => format!("median({})", field_expr),
                    AggFunc::Perc95 => format!("quantile(0.95)({})", field_expr),
                    AggFunc::Percentile(pct) => format!("quantile({})({})", pct as f64 / 100.0, field_expr),
                    AggFunc::Mode => format!("topK(1)({})[1]", field_expr),
                    AggFunc::Sparkline => {
                        // Sparkline creates a mini timechart per group: bucket events
                        // into time intervals and count per bucket.
                        // Uses sumMap to aggregate counts by time bucket in a single pass.
                        let span = sparkline_span_secs.unwrap_or(1800); // default 30min
                        format!(
                            "sumMap([toUInt32(toStartOfInterval(timestamp, toIntervalSecond({})))], [toUInt64(1)]).2",
                            span
                        )
                    }
                };

                // Determine the alias:
                // 1. Use explicit alias if provided
                // 2. For count(*), default to "count"
                // 3. For values/list with a field, use "values_field" or "list_field" to avoid conflicts
                // 4. For other aggregations, use the function name (e.g., "dc", "sum", "avg")
                let alias_name = if let Some(a) = agg.alias.as_ref() {
                    a.clone()
                } else if agg.field.is_none() && agg.func == AggFunc::Count {
                    "count".to_string()
                } else if matches!(agg.func, AggFunc::Values | AggFunc::List) {
                    // For values() and list(), include field name in alias to avoid conflicts
                    // when multiple values() calls are used
                    if let Some(field) = agg.field.as_ref() {
                        format!("{}_{}", agg.func.as_str(), field)
                    } else {
                        agg.func.as_str().to_string()
                    }
                } else {
                    // Use function name as default alias for aggregations
                    agg.func.as_str().to_string()
                };

                // Detect alias-shadows-field conflicts: e.g. `min(timestamp) AS timestamp`
                // ClickHouse inlines CTEs and expands aliases, so a downstream CTE
                // referencing `timestamp` would expand to `min(timestamp)`, causing
                // ILLEGAL_AGGREGATION in GROUP BY/WHERE contexts.
                // Use a temp `_agg_` prefix; the outer subquery renames it back.
                let shadows_field = agg.field.as_ref()
                    .map(|f| normalize_field_name(f) == alias_name)
                    .unwrap_or(false);
                let sql_alias = if shadows_field {
                    format!("_agg_{}", alias_name)
                } else {
                    alias_name
                };

                Ok(format!("{} AS {}", agg_expr, escape_identifier(&sql_alias)))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let select_clause = match group_by {
            Some(fields) => {
                let group_fields: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let (expr, needs_cast) = field_to_sql_expr(f, self);
                        // Use the normalized field name as alias so subsequent commands
                        // can reference it consistently (e.g., _time -> timestamp)
                        let normalized = normalize_field_name(f);
                        // Wrap dynamic/JSON fields with toString() to match GROUP BY clause
                        // Always add explicit alias to ensure column name appears in output
                        if needs_cast {
                            format!("toString({}) AS {}", expr, escape_identifier(normalized))
                        } else {
                            format!("{} AS {}", expr, escape_identifier(normalized))
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
                    let (expr, needs_cast) = field_to_sql_expr(f, self);
                    // Wrap dynamic/JSON fields with toString() to avoid ClickHouse GROUP BY type errors
                    if needs_cast {
                        format!("toString({})", expr)
                    } else {
                        expr
                    }
                })
                .collect();
            write!(sql, "\n  GROUP BY {}", group_fields.join(", ")).unwrap();
        }

        // If any aggregation alias shadows its input field, wrap in a subquery
        // that renames `_agg_X` back to `X` so downstream CTEs see a plain column.
        if !shadowed_aliases.is_empty() {
            let temp_cols: Vec<String> = shadowed_aliases
                .iter()
                .map(|name| escape_identifier(&format!("_agg_{}", name)))
                .collect();
            let renames: Vec<String> = shadowed_aliases
                .iter()
                .map(|name| {
                    format!(
                        "{} AS {}",
                        escape_identifier(&format!("_agg_{}", name)),
                        escape_identifier(name)
                    )
                })
                .collect();
            sql = format!(
                "  SELECT * EXCEPT({}), {}\n  FROM (\n  {}\n  )",
                temp_cols.join(", "),
                renames.join(", "),
                sql
            );
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
        limit: Option<usize>,
        cont: bool,
    ) -> Result<String, SqlGenError> {
        let time_bucket_expr = self.generate_time_bucket(span);

        let agg_exprs: Vec<String> = aggregations.iter()
            .map(|agg| {
                let field_expr = agg.field.as_ref()
                    .map(|f| {
                        let (expr, _) = field_to_sql_expr(f, self);
                        if agg.func == AggFunc::Dc {
                            expr // uniq() handles distinct internally
                        } else {
                            expr
                        }
                    })
                    .unwrap_or_else(|| "*".to_string());

                // Use count() without args when counting all rows for better performance
                let agg_expr = match agg.func {
                    AggFunc::Count => {
                        if field_expr == "*" {
                            "count()".to_string()
                        } else {
                            format!("count({})", field_expr)
                        }
                    }
                    AggFunc::Dc => format!("uniqExact({})", field_expr),
                    AggFunc::Sum => format!("sum({})", field_expr),
                    AggFunc::Avg => format!("avg({})", field_expr),
                    AggFunc::Min => format!("min({})", field_expr),
                    AggFunc::Max => format!("max({})", field_expr),
                    AggFunc::Values => format!("arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::List => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::First => format!("argMin({}, timestamp)", field_expr),
                    AggFunc::Last => format!("argMax({}, timestamp)", field_expr),
                    AggFunc::Range => format!("(max({}) - min({}))", field_expr, field_expr),
                    AggFunc::Earliest => format!("min({})", field_expr),
                    AggFunc::Latest => format!("max({})", field_expr),
                    AggFunc::Stdev => format!("stddevPop({})", field_expr),
                    AggFunc::Var => format!("varPop({})", field_expr),
                    AggFunc::Median => format!("median({})", field_expr),
                    AggFunc::Perc95 => format!("quantile(0.95)({})", field_expr),
                    AggFunc::Percentile(pct) => format!("quantile({})({})", pct as f64 / 100.0, field_expr),
                    AggFunc::Mode => format!("topK(1)({})[1]", field_expr),
                    AggFunc::Sparkline => {
                        // Sparkline in timechart: use a fraction of the timechart span
                        let sub_span = (span.as_secs() / 10).max(60);
                        format!(
                            "sumMap([toUInt32(toStartOfInterval(timestamp, toIntervalSecond({})))], [toUInt64(1)]).2",
                            sub_span
                        )
                    }
                };

                let alias = agg.alias.as_ref()
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

        let time_bucket = format!("{} AS time_bucket", time_bucket_expr);

        let select_clause = if split_by.is_empty() {
            format!("{}, {}", time_bucket, agg_exprs.join(", "))
        } else {
            let split_selects: Vec<String> = split_by
                .iter()
                .map(|field| {
                    let (field_expr, needs_cast) = field_to_sql_expr(field, self);
                    if needs_cast {
                        format!("toString({}) AS {}", field_expr, escape_identifier(field))
                    } else {
                        format!("{} AS {}", field_expr, escape_identifier(field))
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

        // Apply limit filter: only include top N split-by values by first aggregation
        if let (Some(field), Some(n)) = (split_by.first(), limit) {
            let (field_expr, needs_cast) = field_to_sql_expr(field, self);
            let field_in_subq = if needs_cast {
                format!("toString({})", field_expr)
            } else {
                field_expr.clone()
            };
            // Determine aggregate for ranking (use first aggregation)
            let rank_agg = if let Some(first_agg) = aggregations.first() {
                let agg_field = first_agg
                    .field
                    .as_ref()
                    .map(|f| {
                        let (e, _) = field_to_sql_expr(f, self);
                        e
                    })
                    .unwrap_or_else(|| "*".to_string());
                match first_agg.func {
                    AggFunc::Count => {
                        if agg_field == "*" {
                            "count()".to_string()
                        } else {
                            format!("count({})", agg_field)
                        }
                    }
                    AggFunc::Sum => format!("sum({})", agg_field),
                    AggFunc::Avg => format!("avg({})", agg_field),
                    AggFunc::Dc => format!("uniqExact({})", agg_field),
                    _ => "count()".to_string(),
                }
            } else {
                "count()".to_string()
            };
            write!(
                sql,
                "\n  WHERE {} IN (SELECT {} FROM {} GROUP BY {} ORDER BY {} DESC LIMIT {})",
                escape_identifier(field),
                field_in_subq,
                source,
                field_in_subq,
                rank_agg,
                n
            )
            .unwrap();
        }

        let group_clause = if split_by.is_empty() {
            "time_bucket".to_string()
        } else {
            let split_group_bys: Vec<String> = split_by
                .iter()
                .map(|field| {
                    let (field_expr, needs_cast) = field_to_sql_expr(field, self);
                    if needs_cast {
                        format!("toString({})", field_expr)
                    } else {
                        field_expr
                    }
                })
                .collect();
            format!("time_bucket, {}", split_group_bys.join(", "))
        };
        write!(sql, "\n  GROUP BY {}\n  ORDER BY time_bucket", group_clause).unwrap();

        // cont=true: fill gaps in time axis with zeros using WITH FILL STEP
        if cont {
            let span_secs = span.as_secs();
            write!(sql, " ASC WITH FILL STEP toIntervalSecond({})", span_secs).unwrap();
        }

        Ok(sql)
    }
}
