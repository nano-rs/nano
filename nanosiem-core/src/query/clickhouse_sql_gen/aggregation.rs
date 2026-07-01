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
        //
        // NAN-1160: this MUST use the same key as the inline `shadows_field` predicate
        // below — `agg.output_alias()` (which has func-name and values_/list_ fallbacks),
        // NOT the raw `agg.alias`. Keying off the explicit alias alone missed the
        // un-aliased func-named-field case (`stats count(count) by x`): output_alias()
        // falls back to `count`, the inline guard renamed the column to `_agg_count`, but
        // no outer rename-back was emitted — so a downstream `count` reference (including
        // the NAN-806 auto-injected `ORDER BY count`) hit UNKNOWN_IDENTIFIER.
        let shadowed_aliases: Vec<String> = aggregations
            .iter()
            .filter_map(|agg| {
                let alias_name = agg.output_alias();
                if let Some(field) = &agg.field {
                    // by_field_output_name: an upstream-computed input keeps its
                    // raw name (`max(method) AS method` after a rex capture is a
                    // shadow too), everything else compares the normalized name
                    // exactly as before (NAN-1341).
                    if by_field_output_name(field, self) == alias_name {
                        return Some(alias_name);
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
                    // dc() is intentionally exact (uniqExact): detection thresholds
                    // (`where dc > N`) and Splunk parity depend on exact counts.
                    // Memory grows linearly with cardinality (~190 B/distinct string);
                    // estdc() is the bounded-memory alternative (~0.9% error).
                    AggFunc::Dc => format!("uniqExact({})", field_expr),
                    AggFunc::EstDc => format!("uniqCombined64({})", field_expr),
                    AggFunc::Sum => format!("sum({})", field_expr),
                    AggFunc::Avg => format!("avg({})", field_expr),
                    AggFunc::Min => format!("min({})", field_expr),
                    AggFunc::Max => format!("max({})", field_expr),
                    AggFunc::Values => format!("arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::List => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::First => format!("argMin({}, {})", field_expr, self.time_column()),
                    AggFunc::Last => format!("argMax({}, {})", field_expr, self.time_column()),
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
                            "sumMap([toUInt32(toStartOfInterval({}, toIntervalSecond({})))], [toUInt64(1)]).2",
                            self.time_column(),
                            span
                        )
                    }
                    // NAN-1528 (OTLP metrics): per-second rate of a cumulative
                    // counter over the group's window = (last - first value) /
                    // window-seconds. greatest(...,1) guards a zero-width window
                    // (single point / same-second bucket) against div-by-zero.
                    AggFunc::Rate if self.is_metrics_dataset() => {
                        self.metric_rate_expr(&field_expr)
                    }
                    AggFunc::Rate => format!(
                        "(max({0}) - min({0})) / greatest(dateDiff('second', min({1}), max({1})), 1)",
                        field_expr,
                        self.time_column(),
                    ),
                    // NAN-1528 (OTLP metrics): histogram quantile. Pragmatic form
                    // — quantileTDigest over the per-data-point values (works for
                    // gauge/summary points). True OTLP-bucket interpolation over
                    // bucket_counts/explicit_bounds is a later refinement.
                    AggFunc::HistogramQuantile(pct) => {
                        // Clamp to <=100 so the quantile level stays in [0,1]
                        // (the parser admits a u8 up to 255).
                        format!("quantileTDigest({})({})", pct.min(100) as f64 / 100.0, field_expr)
                    }
                };
                // NAN-1555: on a metrics rollup table, rewrite a value-aggregation
                // onto the pre-aggregated state columns. No-op off the rollup
                // (returns the per-row expr above) → byte-identical for logs/spans/
                // raw metrics.
                let agg_expr = self
                    .rollup_value_agg(&agg.func, &field_expr, agg.field.as_deref())
                    .unwrap_or(agg_expr);

                // Output column name. The scheme lives on `Aggregation::output_alias`
                // so downstream rewrites (auto-sort) can reference the same name.
                let alias_name = agg.output_alias();

                // Detect alias-shadows-field conflicts: e.g. `min(timestamp) AS timestamp`
                // ClickHouse inlines CTEs and expands aliases, so a downstream CTE
                // referencing `timestamp` would expand to `min(timestamp)`, causing
                // ILLEGAL_AGGREGATION in GROUP BY/WHERE contexts.
                // Use a temp `_agg_` prefix; the outer subquery renames it back.
                let shadows_field = agg.field.as_ref()
                    .map(|f| by_field_output_name(f, self) == alias_name)
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
                        // Output alias: the normalized field name so subsequent
                        // commands can reference it consistently (e.g., _time ->
                        // timestamp) — except an upstream value-computed by-field,
                        // which keeps its raw name to match the shadowed expr
                        // `field_to_sql_expr` just emitted (NAN-1341).
                        let normalized = by_field_output_name(f, self);
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
    /// NAN-1555: counter-reset-aware per-second `rate()` for a cumulative metric
    /// over a group's window. Sums the POSITIVE consecutive deltas of the
    /// time-ordered values — a counter reset (process restart) produces a negative
    /// delta which is dropped rather than counted as a huge spike, matching
    /// Prometheus `rate()` reset semantics — and divides by the observed window
    /// seconds. For a monotonic counter with no reset this equals
    /// `(last - first) / secs`. Used only on the metrics dataset; the logs path
    /// keeps the prior `(max - min) / secs` form (byte-identical).
    pub(crate) fn metric_rate_expr(&self, field_expr: &str) -> String {
        let ts = self.time_column();
        format!(
            "arraySum(arrayMap(d -> if(d > 0, d, 0), \
             arrayDifference(arrayMap(p -> p.2, arraySort(p -> p.1, groupArray(({ts}, {field_expr})))))))\
             / greatest(dateDiff('second', min({ts}), max({ts})), 1)"
        )
    }

    fn is_metrics_dataset(&self) -> bool {
        self.profile.id() == crate::schema::SchemaId::Metrics
    }

    /// NAN-1555 resolution routing: rewrite a `value` aggregation onto the
    /// `otel_metrics_1m/_1h` rollup's pre-aggregated state columns
    /// (`value_sum`/`value_count`/`value_min`/`value_max`/`value_state`).
    ///
    /// Returns `Some(expr)` only when the generator is pointed at a rollup table
    /// (`is_metrics_rollup`) AND the aggregated field is `value` AND the function
    /// has a rollup form. `None` otherwise — but `core_search` only routes a query
    /// to the rollup when EVERY one of its aggregations is covered here (and its
    /// filters/group-bys touch only the rollup's `metric_name`/`service_name`
    /// keys), so the `None` fallback to per-row aggregation is never reached on a
    /// rollup table in practice. The rollup avg/min/max/sum/quantiles were
    /// validated equal to the raw aggregation within 0.0002% (migration 144).
    fn rollup_value_agg(
        &self,
        func: &AggFunc,
        field_expr: &str,
        field: Option<&str>,
    ) -> Option<String> {
        if !self.is_metrics_rollup() {
            return None;
        }
        let is_value = field == Some("value") || field_expr == "value";
        // `count` has a rollup form regardless of field (it counts rows ≡ data
        // points → sum(value_count)); every other rollup form is value-specific.
        if !is_value && !matches!(func, AggFunc::Count) {
            return None;
        }
        let q = "quantilesTDigestMerge(0.5, 0.95, 0.99)(value_state)";
        let ts = self.time_column();
        Some(match func {
            AggFunc::Avg => "sum(value_sum) / greatest(sum(value_count), 1)".to_string(),
            AggFunc::Sum => "sum(value_sum)".to_string(),
            AggFunc::Min | AggFunc::Earliest => "min(value_min)".to_string(),
            AggFunc::Max | AggFunc::Latest => "max(value_max)".to_string(),
            AggFunc::Count => "sum(value_count)".to_string(),
            AggFunc::Median => format!("{q}[1]"),
            AggFunc::Perc95 => format!("{q}[2]"),
            // The rollup t-digest stores p50/p95/p99 only; other percentiles are
            // not rollup-eligible (core_search keeps them on raw).
            AggFunc::Percentile(50) => format!("{q}[1]"),
            AggFunc::Percentile(95) => format!("{q}[2]"),
            AggFunc::Percentile(99) => format!("{q}[3]"),
            // `sum`/`count`/`rate` are intentionally NOT rollup-routed (see
            // `metrics_routing::agg_is_rollup_value`): sum/count are additive and
            // would over-count the window-edge bucket, and rate must stay
            // reset-aware on raw points. They never reach here; return None so a
            // stray rollup-mode call can't silently emit a wrong aggregate. `ts`
            // (the rollup time column) is retained for the (unused) signature.
            _ => {
                let _ = ts;
                return None;
            }
        })
    }

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

        // (aggregate expression, output column name) per aggregation. The name is
        // None only for field-less non-count aggregations (no alias to derive) —
        // those columns keep ClickHouse's expression-derived name.
        let agg_cols: Vec<(String, Option<String>)> = aggregations.iter()
            .map(|agg| {
                let field_expr = agg.field.as_ref()
                    .map(|f| {
                        let (expr, _) = field_to_sql_expr(f, self);
                        expr
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
                    AggFunc::EstDc => format!("uniqCombined64({})", field_expr),
                    AggFunc::Sum => format!("sum({})", field_expr),
                    AggFunc::Avg => format!("avg({})", field_expr),
                    AggFunc::Min => format!("min({})", field_expr),
                    AggFunc::Max => format!("max({})", field_expr),
                    AggFunc::Values => format!("arrayStringConcat(arrayFilter(x -> x != '', groupUniqArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::List => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArray({})(toString({}))), ', ')", self.max_group_array_size, field_expr),
                    AggFunc::First => format!("argMin({}, {})", field_expr, self.time_column()),
                    AggFunc::Last => format!("argMax({}, {})", field_expr, self.time_column()),
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
                            "sumMap([toUInt32(toStartOfInterval({}, toIntervalSecond({})))], [toUInt64(1)]).2",
                            self.time_column(),
                            sub_span
                        )
                    }
                    // NAN-1528 (OTLP metrics): per-second counter rate over the
                    // timechart bucket. See the stats-path arm for rationale.
                    AggFunc::Rate if self.is_metrics_dataset() => {
                        self.metric_rate_expr(&field_expr)
                    }
                    AggFunc::Rate => format!(
                        "(max({0}) - min({0})) / greatest(dateDiff('second', min({1}), max({1})), 1)",
                        field_expr,
                        self.time_column(),
                    ),
                    // NAN-1528 (OTLP metrics): histogram quantile (pragmatic
                    // quantileTDigest form — see the stats-path arm).
                    AggFunc::HistogramQuantile(pct) => {
                        // Clamp to <=100 so the quantile level stays in [0,1]
                        // (the parser admits a u8 up to 255).
                        format!("quantileTDigest({})({})", pct.min(100) as f64 / 100.0, field_expr)
                    }
                };
                // NAN-1555: metrics-rollup value-aggregation rewrite (no-op off the
                // rollup; see the stats-path arm).
                let agg_expr = self
                    .rollup_value_agg(&agg.func, &field_expr, agg.field.as_deref())
                    .unwrap_or(agg_expr);

                let name = agg
                    .alias
                    .clone()
                    .or_else(|| agg.field.clone())
                    .or_else(|| {
                        (agg.field.is_none() && agg.func == AggFunc::Count)
                            .then(|| "count".to_string())
                    });
                (agg_expr, name)
            })
            .collect();

        let agg_exprs: Vec<String> = agg_cols
            .iter()
            .map(|(expr, name)| match name {
                Some(n) => format!("{} AS {}", expr, escape_identifier(n)),
                None => expr.clone(),
            })
            .collect();

        let time_bucket = format!("{} AS time_bucket", time_bucket_expr);

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

        let select_clause = if split_by.is_empty() {
            format!("{}, {}", time_bucket, agg_exprs.join(", "))
        } else {
            format!(
                "{}, {}, {}",
                time_bucket,
                split_selects.join(", "),
                agg_exprs.join(", ")
            )
        };

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

        let mut sql = format!("  SELECT {}\n  FROM {}", select_clause, source);

        // Apply limit filter: only include top N split-by values by first aggregation
        match (split_by.first(), limit) {
            (Some(field), Some(n)) => {
                let first_func = aggregations.first().map(|a| a.func);
                let rank_field = aggregations.first().and_then(|a| a.field.as_ref());
                let rank_field_expr = rank_field.map(|f| {
                    let (e, _) = field_to_sql_expr(f, self);
                    e
                });
                // Two-pass form is kept when:
                //  - the rank aggregation is dc()/estdc(): distinct counts are NOT
                //    per-bucket decomposable (the union of per-bucket distinct sets
                //    isn't the sum of their sizes), or
                //  - any aggregation column has no derivable output name (field-less
                //    non-count aggregations keep ClickHouse's expression-derived
                //    name, which the single-scan outer projection can't reference).
                // Everything else uses the single-scan windowed form (NAN-1430 / D1).
                let any_unnamed = agg_cols.iter().any(|(_, name)| name.is_none());
                if matches!(first_func, Some(AggFunc::Dc) | Some(AggFunc::EstDc)) || any_unnamed
                {
                    let (field_expr, needs_cast) = field_to_sql_expr(field, self);
                    let field_in_subq = if needs_cast {
                        format!("toString({})", field_expr)
                    } else {
                        field_expr.clone()
                    };
                    let agg_field = rank_field_expr.unwrap_or_else(|| "*".to_string());
                    let rank_agg = match first_func {
                        Some(AggFunc::Count) => {
                            if agg_field == "*" {
                                "count()".to_string()
                            } else {
                                format!("count({})", agg_field)
                            }
                        }
                        Some(AggFunc::Sum) => format!("sum({})", agg_field),
                        Some(AggFunc::Avg) => format!("avg({})", agg_field),
                        Some(AggFunc::Dc) => format!("uniqExact({})", agg_field),
                        Some(AggFunc::EstDc) => format!("uniqCombined64({})", agg_field),
                        _ => "count()".to_string(),
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
                    write!(sql, "\n  GROUP BY {}\n  ORDER BY time_bucket", group_clause)
                        .unwrap();
                } else {
                    // Single-scan top-N (NAN-1430 / audit D1): the old form's rank
                    // subquery (`WHERE x IN (SELECT … FROM stage_0 … LIMIT n)`)
                    // re-read the raw-scan CTE — physical read_rows was exactly 2x.
                    // Instead: aggregate ONCE per (bucket, split), then rank split
                    // values with window functions over the (small) aggregated
                    // stage and keep the top N. Chained derived tables, not nested
                    // windows in one SELECT — the latter fails on CH 26.4 with
                    // NOT_FOUND_COLUMN_IN_BLOCK.
                    //
                    // Rank value decomposition (helper columns carried through the
                    // aggregated stage; exact for count/sum, avg carries sum+count
                    // and divides at the end):
                    //   count → sum(per-bucket count)  sum → sum(per-bucket sum)
                    //   avg   → sum(per-bucket sum) / sum(per-bucket count)
                    //   other → row count (matches the old form's count() fallback)
                    let (helper_cols, total_expr) = match (first_func, &rank_field_expr) {
                        (Some(AggFunc::Count), Some(f)) => (
                            format!("count({}) AS __rank_val", f),
                            "sum(__rank_val) OVER (PARTITION BY __rank_key)".to_string(),
                        ),
                        (Some(AggFunc::Sum), Some(f)) => (
                            format!("sum({}) AS __rank_val", f),
                            "sum(__rank_val) OVER (PARTITION BY __rank_key)".to_string(),
                        ),
                        (Some(AggFunc::Avg), Some(f)) => (
                            format!("sum({0}) AS __rank_sum, count({0}) AS __rank_cnt", f),
                            "(sum(__rank_sum) OVER (PARTITION BY __rank_key) / sum(__rank_cnt) OVER (PARTITION BY __rank_key))".to_string(),
                        ),
                        // count() without a field, and every other rank function
                        // (the old form also fell back to count() for those).
                        _ => (
                            "count() AS __rank_val".to_string(),
                            "sum(__rank_val) OVER (PARTITION BY __rank_key)".to_string(),
                        ),
                    };
                    // The split column is re-selected under a reserved alias
                    // (__rank_key) so the window stages reference a name no user
                    // alias can collide with.
                    let (split_expr, needs_cast) = field_to_sql_expr(field, self);
                    let split_key = if needs_cast {
                        format!("toString({})", split_expr)
                    } else {
                        split_expr
                    };
                    // ClickHouse substitutes a SELECT-level alias into sibling
                    // expressions: `sum(bytes_in) AS bytes_in` makes the helper's
                    // `bytes_in` expand to the aggregate (ILLEGAL_AGGREGATION) —
                    // and timechart's DEFAULT alias is the input field name, so
                    // this is the common case, not the edge. Emit any aggregation
                    // whose output name collides with an identifier the helpers /
                    // rank key reference under a positional temp name and rename
                    // it back in the outer projection (same scheme stats uses for
                    // its `_agg_` shadow guard).
                    // The trailing reserved names guard against a user alias
                    // colliding with the rank machinery's own columns
                    // (MULTIPLE_EXPRESSIONS_FOR_ALIAS otherwise).
                    let shadow_sources: Vec<&str> = [
                        rank_field.map(|f| f.as_str()),
                        rank_field_expr.as_deref(),
                        Some(field.as_str()),
                        Some(split_key.as_str()),
                        Some("__rank_key"),
                        Some("__rank_val"),
                        Some("__rank_sum"),
                        Some("__rank_cnt"),
                        Some("__rank_total"),
                        Some("__rank"),
                    ]
                    .into_iter()
                    .flatten()
                    .collect();
                    let mut inner_aggs = Vec::with_capacity(agg_cols.len());
                    let mut outer_aggs = Vec::with_capacity(agg_cols.len());
                    for (i, (expr, name)) in agg_cols.iter().enumerate() {
                        // any_unnamed was handled by the two-pass branch above
                        let name = name.as_deref().unwrap_or_default();
                        if shadow_sources.contains(&name) {
                            inner_aggs.push(format!("{} AS _agg_topn_{}", expr, i));
                            outer_aggs.push(format!(
                                "_agg_topn_{} AS {}",
                                i,
                                escape_identifier(name)
                            ));
                        } else {
                            inner_aggs.push(format!("{} AS {}", expr, escape_identifier(name)));
                            outer_aggs.push(escape_identifier(name));
                        }
                    }
                    let inner_select = if split_selects.is_empty() {
                        format!("{}, {}", time_bucket, inner_aggs.join(", "))
                    } else {
                        format!(
                            "{}, {}, {}",
                            time_bucket,
                            split_selects.join(", "),
                            inner_aggs.join(", ")
                        )
                    };
                    let outer_select = {
                        let split_names: Vec<String> =
                            split_by.iter().map(|f| escape_identifier(f)).collect();
                        format!(
                            "time_bucket, {}, {}",
                            split_names.join(", "),
                            outer_aggs.join(", ")
                        )
                    };
                    sql = format!(
                        "  SELECT {outer_select}\n  \
                         FROM (\n    \
                         SELECT *, dense_rank() OVER (ORDER BY __rank_total DESC, __rank_key ASC) AS __rank\n    \
                         FROM (\n      \
                         SELECT *, {total_expr} AS __rank_total\n      \
                         FROM (\n  \
                         SELECT {inner_select}, {split_key} AS __rank_key, {helper_cols}\n  \
                         FROM {source}\n  \
                         GROUP BY {group_clause}\n      \
                         )\n    \
                         )\n  \
                         )\n  \
                         WHERE __rank <= {n}\n  ORDER BY time_bucket"
                    );
                }
            }
            _ => {
                write!(sql, "\n  GROUP BY {}\n  ORDER BY time_bucket", group_clause).unwrap();
            }
        }

        // cont=true: fill gaps in time axis with zeros using WITH FILL STEP.
        // NAN-1555: metrics ALWAYS gap-fill (a metric time series with holes reads
        // as missing data, not "no value"), and over the FULL window — `FROM` the
        // span-aligned window start `TO` the end — so leading/trailing empty
        // buckets render too, not just gaps between the first and last datapoint.
        // NAN-1555: force full-window gap-fill for SINGLE-series metric charts only.
        // With a split-by, ClickHouse `WITH FILL` cannot partition per series — it
        // fills the GLOBAL time axis once, emitting synthetic rows with an EMPTY
        // split column (`service_name=''`) and one row per gap instead of one per
        // series (NAN-1555 adversarial review). So a multi-series metric chart keeps
        // the normal `cont` behavior (no forced full-window fill); the per-series
        // grid is the FE/glue's job, as it is for logs.
        let metrics = self.profile.id() == crate::schema::SchemaId::Metrics && split_by.is_empty();
        if cont || metrics {
            let span_secs = span.as_secs().max(1);
            let window = self
                .generation_time_range
                .read()
                .ok()
                .and_then(|g| g.clone());
            match (metrics, window) {
                (true, Some(tr)) => {
                    // Align FROM to the span grid so the fill grid coincides with
                    // the `toStartOf*` buckets; TO is the window end (exclusive upper
                    // buckets are simply absent). Bound literals are second-precision
                    // (the bucket is, too).
                    write!(
                        sql,
                        " ASC WITH FILL FROM toStartOfInterval(toDateTime('{start}', 'UTC'), \
                         toIntervalSecond({span_secs})) TO toDateTime('{end}', 'UTC') \
                         STEP toIntervalSecond({span_secs})",
                        start = crate::sql_hygiene::format_ch_bound(&tr.start),
                        end = crate::sql_hygiene::format_ch_bound(&tr.end),
                    )
                    .unwrap();
                }
                _ => {
                    write!(sql, " ASC WITH FILL STEP toIntervalSecond({})", span_secs).unwrap();
                }
            }
        }

        Ok(sql)
    }
}
