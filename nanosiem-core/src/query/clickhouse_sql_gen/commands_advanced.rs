// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complex command SQL generation
//!
//! Helper methods for complex command match arms: StreamStats, EventStats,
//! Sequence, Funnel, Anomaly, Tree, Asset, Cloud.

use super::helpers::*;
use super::{extract_fields_from_search_expr, ClickHouseSqlGenerator};
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;

/// Sentinel substituted for NULL group keys in the map-scalar attach shape used
/// by eventstats / anomaly (NAN-1642). Rows whose BY-key is NULL (reachable via
/// `by ext.*` and any Nullable column) must land in the same group on BOTH the
/// map-build side and the per-row lookup side, so they receive their group's
/// aggregate instead of the Map default value (0 / ''). The leading NUL byte
/// makes collision with a real key value practically impossible: no toString()
/// rendering of a column value starts with '\0' unless the raw data itself
/// contains NUL-prefixed binary, and `PARTITION BY` grouped NULLs together the
/// same way before this rewrite.
const NULL_KEY_SENTINEL: &str = "'\\0__null__'";

/// Null-canonicalized group-key expression, used verbatim on both the
/// map-build side (`GROUP BY __nano_k`) and the per-row lookup side
/// (`__nano_map[<key>]`) so the two sides can never disagree on group
/// membership.
///
/// Multi-key `by a, b` renders `toString(tuple(a, b))`: the tuple rendering
/// quote-delimits and escapes each string component, so component boundaries
/// are unambiguous for ANY content (including embedded NUL bytes), and NULL
/// elements render as an unquoted `NULL` token — distinct from every quoted
/// string — grouping exactly like `PARTITION BY a, b` did. Single-key uses
/// the sentinel form; its only residual collision is a raw value literally
/// equal to `\0__null__` (see [`NULL_KEY_SENTINEL`]).
fn null_canonical_key_sql(key_exprs: &[String]) -> String {
    if key_exprs.len() == 1 {
        format!(
            "coalesce(toString({}), {})",
            key_exprs[0], NULL_KEY_SENTINEL
        )
    } else {
        format!("toString(tuple({}))", key_exprs.join(", "))
    }
}

/// Scalar subquery producing a per-group aggregate Map: canonicalized key →
/// aggregate value(s). Attached per row via `map[<key>]`, this replaces the
/// whole-partition window shape (`agg(x) OVER (PARTITION BY k)`), which
/// buffers the entire partition and OOMs (Code 241) at production scale
/// (NAN-1642: 24h/21.4M rows in 1.9s/155MiB where both the window and a LEFT
/// JOIN join-back OOM — the JOIN defeats ClickHouse lazy materialization).
/// The scalar is evaluated once per query (ClickHouse scalar-subquery cache).
fn group_agg_map_sql(build_key_sql: &str, value_sql: &str, stats_source: &str) -> String {
    format!(
        "(SELECT mapFromArrays(groupArray(__nano_k), groupArray(__nano_v)) FROM \
         (SELECT {} AS __nano_k, {} AS __nano_v FROM {} GROUP BY __nano_k))",
        build_key_sql, value_sql, stats_source
    )
}

/// Per-group (or global) z-score constants attach layer: annotates every row
/// of `attach_source` with `avg_val` / `stddev_val` computed over
/// `stats_source`. `keys` is `(build_key, lookup_key)` — the map-build side
/// groups `stats_source` by `build_key`, each row of `attach_source` looks its
/// group up via `lookup_key`; `None` means a single global group (plain scalar
/// tuple, no map needed).
fn zscore_attach_sql(
    attach_source: &str,
    stats_source: &str,
    value_expr: &str,
    keys: Option<(&str, &str)>,
) -> String {
    match keys {
        None => format!(
            "WITH (SELECT tuple(toFloat64(avg({v})), toFloat64(stddevPop({v}))) FROM {ss}) AS __nano_stats\n    \
             SELECT *, __nano_stats.1 as avg_val, __nano_stats.2 as stddev_val\n    \
             FROM {atk}",
            v = value_expr,
            ss = stats_source,
            atk = attach_source
        ),
        Some((build_key, lookup_key)) => {
            let map = group_agg_map_sql(
                build_key,
                &format!(
                    "tuple(toFloat64(avg({v})), toFloat64(stddevPop({v})))",
                    v = value_expr
                ),
                stats_source,
            );
            format!(
                "WITH {map} AS __nano_stats\n    \
                 SELECT *, __nano_stats[{lk}].1 as avg_val, __nano_stats[{lk}].2 as stddev_val\n    \
                 FROM {atk}",
                map = map,
                lk = lookup_key,
                atk = attach_source
            )
        }
    }
}

/// Per-group (or global) MAD constants attach layer: annotates every row of
/// `attach_source` with `median_val` / `mad_val` computed over `stats_source`.
/// Two bounded GROUP BY passes replace the two stacked whole-partition
/// quantile windows: the second map's build references the first
/// (`__nano_med[__nano_k]`) to compute the median absolute deviation — the
/// identical scalar text is computed once (scalar-subquery cache).
fn mad_attach_sql(
    attach_source: &str,
    stats_source: &str,
    value_expr: &str,
    keys: Option<(&str, &str)>,
) -> String {
    match keys {
        None => format!(
            "WITH (SELECT toFloat64(quantile(0.5)({v})) FROM {ss}) AS __nano_med,\n      \
             (SELECT toFloat64(quantile(0.5)(abs({v} - __nano_med))) FROM {ss}) AS __nano_mad\n    \
             SELECT *, __nano_med as median_val, __nano_mad as mad_val\n    \
             FROM {atk}",
            v = value_expr,
            ss = stats_source,
            atk = attach_source
        ),
        Some((build_key, lookup_key)) => {
            let med_map = group_agg_map_sql(
                build_key,
                &format!("toFloat64(quantile(0.5)({}))", value_expr),
                stats_source,
            );
            let mad_map = group_agg_map_sql(
                build_key,
                &format!(
                    "toFloat64(quantile(0.5)(abs({} - __nano_med[__nano_k])))",
                    value_expr
                ),
                stats_source,
            );
            format!(
                "WITH {med} AS __nano_med,\n      \
                 {mad} AS __nano_mad\n    \
                 SELECT *, __nano_med[{lk}] as median_val, __nano_mad[{lk}] as mad_val\n    \
                 FROM {atk}",
                med = med_map,
                mad = mad_map,
                lk = lookup_key,
                atk = attach_source
            )
        }
    }
}

impl ClickHouseSqlGenerator {
    /// Shared z-score scoring wrapper: score/flag every row of the attach
    /// layer against its group's avg/stddev. The math is unchanged from the
    /// window-function era — only where the per-group constants come from
    /// changed (NAN-1642).
    fn zscore_outer_sql(
        value_col: &str,
        threshold: f64,
        attach: &str,
        filter_anomalies: bool,
    ) -> String {
        let filter = if filter_anomalies {
            "\n  WHERE is_anomaly = 1"
        } else {
            ""
        };
        format!(
            "  SELECT *, avg_val, stddev_val,\n    \
             abs({v} - avg_val) / nullIf(stddev_val, 0) as anomaly_score,\n    \
             if(abs({v} - avg_val) > {t} * stddev_val, 1, 0) as is_anomaly\n  \
             FROM (\n    {attach}\n  ){filter}\n  \
             ORDER BY anomaly_score DESC",
            v = value_col,
            t = threshold,
            attach = attach,
            filter = filter
        )
    }

    /// Shared MAD scoring wrapper (see [`Self::zscore_outer_sql`]).
    fn mad_outer_sql(
        value_col: &str,
        threshold: f64,
        attach: &str,
        filter_anomalies: bool,
    ) -> String {
        let filter = if filter_anomalies {
            "\n  WHERE is_anomaly = 1"
        } else {
            ""
        };
        format!(
            "  SELECT *, median_val, mad_val,\n    \
             abs({v} - median_val) / nullIf(mad_val * 1.4826, 0) as anomaly_score,\n    \
             if(abs({v} - median_val) > {t} * mad_val * 1.4826, 1, 0) as is_anomaly\n  \
             FROM (\n    {attach}\n  ){filter}\n  \
             ORDER BY anomaly_score DESC",
            v = value_col,
            t = threshold,
            attach = attach,
            filter = filter
        )
    }

    /// Generate SQL for streamstats command using window functions
    pub(super) fn generate_streamstats_sql(
        &self,
        source: &str,
        aggregations: &[Aggregation],
        group_by: &Option<Vec<String>>,
        current: bool,
        window: &Option<usize>,
    ) -> Result<String, SqlGenError> {
        // Build the frame specification based on current and window options
        let frame_end = if current {
            "CURRENT ROW"
        } else {
            "1 PRECEDING"
        };
        let frame_start = match window {
            Some(n) => format!("{} PRECEDING", n),
            None => "UNBOUNDED PRECEDING".to_string(),
        };
        let frame_spec = format!("ROWS BETWEEN {} AND {}", frame_start, frame_end);

        // Build PARTITION BY clause
        let partition_clause = match group_by {
            Some(fields) => {
                let partition_fields: Vec<String> = fields
                    .iter()
                    .map(|f| {
                        let (expr, _) = field_to_sql_expr(f, self);
                        expr
                    })
                    .collect();
                format!("PARTITION BY {} ", partition_fields.join(", "))
            }
            None => String::new(),
        };

        // O27 (NAN-1721): order the streamstats windows on the active dataset's
        // time column (`start_time` for spans) — a bare `dataset=spans …
        // | streamstats …` otherwise references a nonexistent `timestamp`
        // column. Logs keep `timestamp` byte-identical.
        let tc = self.time_column();

        // Build window function expressions for each aggregation
        let window_exprs: Vec<String> = aggregations.iter()
            .map(|agg| {
                let (field_expr, _) = agg.field.as_ref()
                    .map(|f| field_to_sql_expr(f, self))
                    .unwrap_or_else(|| ("*".to_string(), false));

                // Map aggregation functions to window functions
                // For last() with current=false, use lagInFrame for "previous value"
                let window_func = match agg.func {
                    AggFunc::Count => format!("count({}) OVER ({}ORDER BY {tc} {})",
                        if field_expr == "*" { "" } else { &field_expr }, partition_clause, frame_spec),
                    AggFunc::Sum => format!("sum({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Avg => format!("avg({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Min => format!("min({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Max => format!("max({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::First => {
                        // first() in streamstats context means first value in the window
                        format!("first_value({}) OVER ({}ORDER BY {tc} {})",
                            field_expr, partition_clause, frame_spec)
                    }
                    AggFunc::Last => {
                        // For current=false, last() means "previous value" - use lagInFrame
                        if !current {
                            format!("lagInFrame({}, 1) OVER ({}ORDER BY {tc})",
                                field_expr, partition_clause)
                        } else {
                            format!("last_value({}) OVER ({}ORDER BY {tc} {})",
                                field_expr, partition_clause, frame_spec)
                        }
                    }
                    AggFunc::Dc => format!("uniqExact({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::EstDc => format!("uniqCombined64({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Values => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArrayDistinct({})(toString({})) OVER ({}ORDER BY {tc} {})), ', ')",
                        self.max_group_array_size, field_expr, partition_clause, frame_spec),
                    AggFunc::List => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArray({})(toString({})) OVER ({}ORDER BY {tc} {})), ', ')",
                        self.max_group_array_size, field_expr, partition_clause, frame_spec),
                    AggFunc::Stdev => format!("stddevPop({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Var => format!("varPop({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Range => format!("(max({}) OVER ({}ORDER BY {tc} {}) - min({}) OVER ({}ORDER BY {tc} {}))",
                        field_expr, partition_clause, frame_spec, field_expr, partition_clause, frame_spec),
                    AggFunc::Earliest => format!("min({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Latest => format!("max({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                    _ => format!("count({}) OVER ({}ORDER BY {tc} {})",
                        field_expr, partition_clause, frame_spec),
                };

                // Apply alias
                let alias = agg.alias.as_ref()
                    .map(|a| a.clone())
                    .unwrap_or_else(|| {
                        // Generate default alias based on function and field
                        let func_name = match agg.func {
                            AggFunc::Count => "count",
                            AggFunc::Sum => "sum",
                            AggFunc::Avg => "avg",
                            AggFunc::Min => "min",
                            AggFunc::Max => "max",
                            AggFunc::First => "first",
                            AggFunc::Last => "last",
                            AggFunc::Dc => "dc",
                            AggFunc::EstDc => "estdc",
                            AggFunc::Values => "values",
                            AggFunc::List => "list",
                            AggFunc::Stdev => "stdev",
                            AggFunc::Var => "var",
                            AggFunc::Range => "range",
                            AggFunc::Earliest => "earliest",
                            AggFunc::Latest => "latest",
                            _ => "agg",
                        };
                        match &agg.field {
                            Some(f) => format!("{}_{}", func_name, f),
                            None => func_name.to_string(),
                        }
                    });

                format!("{} AS {}", window_func, escape_identifier(&alias))
            })
            .collect();

        Ok(format!(
            "  SELECT *, {} FROM {}",
            window_exprs.join(", "),
            source
        ))
    }

    /// Generate SQL for eventstats command using the map-scalar attach shape.
    ///
    /// NAN-1642: the previous whole-partition window emission
    /// (`agg(x) OVER (PARTITION BY k)` / `OVER ()`) buffered the entire
    /// partition in memory and OOM'd (Code 241) at ≥15min windows at
    /// production scale. Per-group aggregates are now computed once into a
    /// scalar Map (bounded GROUP BY memory) and attached per row via a map
    /// lookup on the null-canonicalized key; with no `by` clause the whole
    /// set is a single global group and a plain scalar subquery suffices.
    pub(super) fn generate_eventstats_sql(
        &self,
        source: &str,
        aggregations: &[Aggregation],
        group_by: &Option<Vec<String>>,
    ) -> Result<String, SqlGenError> {
        let key_exprs: Vec<String> = group_by
            .as_ref()
            .map(|fields| fields.iter().map(|f| by_field_sql(f, self)).collect())
            .unwrap_or_default();
        let grouped = !key_exprs.is_empty();

        // O27 (NAN-1721): earliest()/latest() argMin/argMax on the active dataset's
        // time column (`start_time` for spans), not the logs-only `timestamp`.
        // Logs keep `timestamp` byte-identical.
        let tc = self.time_column();

        let mut value_exprs: Vec<String> = Vec::with_capacity(aggregations.len());
        let mut aliases: Vec<String> = Vec::with_capacity(aggregations.len());
        for agg in aggregations {
            let field_expr = agg
                .field
                .as_ref()
                .map(|f| by_field_sql(f, self))
                .unwrap_or_else(|| "*".to_string());

            // Exhaustive on purpose. Previously the `_` arm silently emitted `count() OVER`
            // for stdev/var/values/list/range/median/perc/mode/first/last/earliest/latest,
            // returning a row count under the user's alias (NAN-1145). Every variant now maps
            // to its real plain aggregate (mirroring streamstats/stats) or is rejected —
            // never silently count(). A new AggFunc variant forces a decision here.
            //
            // Numeric-returning aggregates are toFloat64-normalized so map
            // values have a uniform, non-surprising type; value-typed
            // aggregates (min/max/first/last/earliest/latest/mode) keep the
            // field's own type, and values()/list() stay String — matching
            // the window emission's output types.
            let value_expr = match agg.func {
                AggFunc::Count => "toFloat64(count())".to_string(),
                AggFunc::Dc => {
                    // Same aggregates the window emission used: exact
                    // count(DISTINCT) over the whole set, uniqExact per group.
                    if grouped {
                        format!("toFloat64(uniqExact({}))", field_expr)
                    } else {
                        format!("toFloat64(count(DISTINCT {}))", field_expr)
                    }
                }
                AggFunc::EstDc => {
                    // Approximate distinct count: bounded memory via
                    // uniqCombined64 (~0.9% measured error).
                    format!("toFloat64(uniqCombined64({}))", field_expr)
                }
                AggFunc::Sum => format!("toFloat64(sum({}))", field_expr),
                AggFunc::Avg => format!("toFloat64(avg({}))", field_expr),
                AggFunc::Min => format!("min({})", field_expr),
                AggFunc::Max => format!("max({})", field_expr),
                AggFunc::Stdev => format!("toFloat64(stddevPop({}))", field_expr),
                AggFunc::Var => format!("toFloat64(varPop({}))", field_expr),
                AggFunc::Range => format!("toFloat64(max({0}) - min({0}))", field_expr),
                AggFunc::Median => format!("toFloat64(median({}))", field_expr),
                AggFunc::Perc95 => format!("toFloat64(quantile(0.95)({}))", field_expr),
                AggFunc::Percentile(p) => {
                    format!(
                        "toFloat64(quantile({})({}))",
                        f64::from(p) / 100.0,
                        field_expr
                    )
                }
                AggFunc::Values => format!(
                    "arrayStringConcat(arrayFilter(x -> x != '', \
                     groupUniqArray({})(toString({}))), ', ')",
                    self.max_group_array_size, field_expr
                ),
                AggFunc::List => format!(
                    "arrayStringConcat(arrayFilter(x -> x != '', \
                     groupArray({})(toString({}))), ', ')",
                    self.max_group_array_size, field_expr
                ),
                AggFunc::First => format!("any({})", field_expr),
                AggFunc::Last => format!("anyLast({})", field_expr),
                AggFunc::Earliest => format!("argMin({}, {tc})", field_expr),
                AggFunc::Latest => format!("argMax({}, {tc})", field_expr),
                AggFunc::Mode => format!("(topK(1)({}))[1]", field_expr),
                AggFunc::Sparkline => {
                    return Err(SqlGenError::InvalidQuery(
                        "eventstats does not support sparkline() — there is no whole-partition \
                         window form; use timechart or stats sparkline() instead"
                            .into(),
                    ))
                }
                // NAN-1528: rate()/histogram_quantile() are OTLP-metric stats
                // (need a min/max-over-window or quantileTDigest reduction);
                // they have no whole-partition window form. Use stats/timechart
                // on the `metrics` dataset instead.
                AggFunc::Rate | AggFunc::HistogramQuantile(_) => {
                    return Err(SqlGenError::InvalidQuery(
                        "eventstats does not support rate()/histogram_quantile() — use \
                         stats or timechart on the metrics dataset instead"
                            .into(),
                    ))
                }
            };

            let alias = agg.alias.as_ref().cloned().unwrap_or_else(|| {
                let func_name = match agg.func {
                    AggFunc::Count => "count",
                    AggFunc::Dc => "dc",
                    AggFunc::EstDc => "estdc",
                    AggFunc::Sum => "sum",
                    AggFunc::Avg => "avg",
                    AggFunc::Min => "min",
                    AggFunc::Max => "max",
                    AggFunc::Stdev => "stdev",
                    AggFunc::Var => "var",
                    AggFunc::Range => "range",
                    AggFunc::Median => "median",
                    AggFunc::Perc95 => "perc95",
                    AggFunc::Percentile(_) => "percentile",
                    AggFunc::Values => "values",
                    AggFunc::List => "list",
                    AggFunc::First => "first",
                    AggFunc::Last => "last",
                    AggFunc::Earliest => "earliest",
                    AggFunc::Latest => "latest",
                    AggFunc::Mode => "mode",
                    AggFunc::Sparkline => "sparkline",
                    AggFunc::Rate => "rate",
                    AggFunc::HistogramQuantile(_) => "histogram_quantile",
                };
                match &agg.field {
                    Some(f) => format!("{}_{}", func_name, normalize_field_name(f)),
                    None => func_name.to_string(),
                }
            });

            value_exprs.push(value_expr);
            aliases.push(alias);
        }

        // One scalar per eventstats stage: multiple aggregations share a
        // single tuple-valued map / scalar so the stage source is scanned
        // once for the constants regardless of aggregation count.
        let value_pack = if value_exprs.len() == 1 {
            value_exprs[0].clone()
        } else {
            format!("tuple({})", value_exprs.join(", "))
        };
        let element = |i: usize, base: &str| -> String {
            if value_exprs.len() == 1 {
                base.to_string()
            } else {
                format!("{}.{}", base, i + 1)
            }
        };

        let (with_scalar, attach_exprs) = if grouped {
            let key_sql = null_canonical_key_sql(&key_exprs);
            let map = group_agg_map_sql(&key_sql, &value_pack, source);
            let attaches: Vec<String> = aliases
                .iter()
                .enumerate()
                .map(|(i, alias)| {
                    format!(
                        "{} AS {}",
                        element(i, &format!("__nano_es[{}]", key_sql)),
                        escape_identifier(alias)
                    )
                })
                .collect();
            (map, attaches)
        } else {
            let scalar = format!("(SELECT {} FROM {})", value_pack, source);
            let attaches: Vec<String> = aliases
                .iter()
                .enumerate()
                .map(|(i, alias)| {
                    format!("{} AS {}", element(i, "__nano_es"), escape_identifier(alias))
                })
                .collect();
            (scalar, attaches)
        };

        Ok(format!(
            "  WITH {} AS __nano_es\n  SELECT *, {} FROM {}",
            with_scalar,
            attach_exprs.join(", "),
            source
        ))
    }

    /// Generate SQL for sequence detection command
    pub(super) fn generate_sequence_sql(
        &self,
        source: &str,
        group_by: &[String],
        maxspan: &Option<std::time::Duration>,
        conditions: &[SearchExpr],
        capture_fields: &[String],
    ) -> Result<String, SqlGenError> {
        if conditions.is_empty() {
            return Err(SqlGenError::InvalidQuery(
                "Sequence requires at least one condition".into(),
            ));
        }

        // Convert each condition to SQL
        let condition_sqls: Result<Vec<String>, SqlGenError> = conditions
            .iter()
            .map(|cond| self.generate_search_expr(cond))
            .collect();
        let condition_sqls = condition_sqls?;
        let n_conds = condition_sqls.len();

        // Extract field names from each condition for auto-capture
        let condition_fields: Vec<Vec<String>> = conditions
            .iter()
            .map(|cond| extract_fields_from_search_expr(cond))
            .collect();

        // Group by fields
        let group_fields: Vec<String> = group_by
            .iter()
            .map(|f| by_field_sql(f, self))
            .collect();

        // Build the sequence function for HAVING clause. HAVING filters *groups*
        // that contain a valid chronological match; it's already correct. The
        // chronology fix is below, in how we *report* each step's event.
        let (sequence_func, maxspan_seconds) = if let Some(span) = maxspan {
            let seconds = span.as_secs();
            (
                format!(
                    "windowFunnel({})(toUInt32(timestamp), {}) = {}",
                    seconds,
                    condition_sqls.join(", "),
                    n_conds
                ),
                Some(seconds),
            )
        } else {
            let pattern = (1..=n_conds)
                .map(|i| format!("(?{})", i))
                .collect::<Vec<_>>()
                .join("");
            (
                format!(
                    "sequenceMatch('{}')(toUInt32(timestamp), {})",
                    pattern,
                    condition_sqls.join(", ")
                ),
                None,
            )
        };

        // Per-step captured fields: union of (condition_fields[i] + user capture_fields),
        // preserving each step's own list for the final column naming. We also build a
        // deduped ordered list of *all* captured fields so we know where each lives in
        // the _evts tuple.
        let mut all_fields_ordered: Vec<String> = Vec::new();
        let mut per_step_captures: Vec<Vec<String>> = Vec::with_capacity(n_conds);
        for i in 0..n_conds {
            let mut step_list: Vec<String> = Vec::new();
            let push_unique = |list: &mut Vec<String>, name: &str| {
                let norm = normalize_field_name(name).to_string();
                if !list.iter().any(|x| x.eq_ignore_ascii_case(&norm)) {
                    list.push(norm);
                }
            };
            for f in &condition_fields[i] {
                push_unique(&mut step_list, f);
            }
            for f in capture_fields {
                push_unique(&mut step_list, f);
            }
            for f in &step_list {
                if !all_fields_ordered
                    .iter()
                    .any(|x| x.eq_ignore_ascii_case(f))
                {
                    all_fields_ordered.push(f.clone());
                }
            }
            per_step_captures.push(step_list);
        }

        // Tuple layout for _evts (1-indexed, matching ClickHouse tuple access):
        //   1: ts (UInt32)
        //   2: id
        //   3..2+K: captured field values (K = all_fields_ordered.len())
        //   3+K..2+K+N: cond flags (N = n_conds)
        let k = all_fields_ordered.len();
        let field_pos = |name: &str| -> usize {
            // position of `name` in all_fields_ordered, plus tuple offset (2 for ts, id)
            3 + all_fields_ordered
                .iter()
                .position(|f| f.eq_ignore_ascii_case(name))
                .expect("field must be in all_fields_ordered")
        };
        let flag_pos = |i: usize| -> usize { 3 + k + i };

        // Build the tuple construction for groupArrayIf
        let mut tuple_parts: Vec<String> = Vec::with_capacity(2 + k + n_conds);
        tuple_parts.push("toUInt32(timestamp)".to_string());
        tuple_parts.push("id".to_string());
        for f in &all_fields_ordered {
            // Resolve the capture value through the active profile (NAN-1346): a step
            // condition field like `action` is a UDM name with no OCSF column, so the
            // raw `escape_identifier(f)` emits `action` → Code 47. `by_field_sql`
            // routes it to the OCSF equivalent (and the class-split unified column for
            // host/process/url). UDM explicit columns resolve byte-identically.
            tuple_parts.push(by_field_sql(f, self));
        }
        for c in &condition_sqls {
            tuple_parts.push(format!("if({}, 1, 0)", c));
        }
        // Only events matching at least one step-condition need to be in _evts
        let any_cond = condition_sqls
            .iter()
            .map(|c| format!("({})", c))
            .collect::<Vec<_>>()
            .join(" OR ");

        // -------- Layer 0 (innermost): per-group aggregation --------
        // Step 1 still uses argMinIf/minIf directly: step 1 has no prior step to
        // anchor to, and its "earliest matching event" is the correct semantics.
        let mut layer0_cols: Vec<String> = Vec::new();
        for f in &group_fields {
            layer0_cols.push(f.clone());
        }
        let cond1 = &condition_sqls[0];
        layer0_cols.push(format!("minIf(timestamp, {}) AS step1_time", cond1));
        layer0_cols.push(format!(
            "argMinIf(id, timestamp, {}) AS step1_event_id",
            cond1
        ));
        for f in &per_step_captures[0] {
            // Alias suffix must be a bare identifier — OCSF dotted fields
            // (`process.name`) would produce an invalid `step1_process.name`
            // alias, so sanitize dots to underscores (NAN-1294). The value
            // expression resolves through the active profile (NAN-1346) so a UDM
            // condition field (`action`) maps to its OCSF column instead of a raw
            // reference that 500s.
            layer0_cols.push(format!(
                "argMinIf({}, timestamp, {}) AS step1_{}",
                by_field_sql(f, self),
                cond1,
                f.replace('.', "_")
            ));
        }
        // Sorted event tuple array — only if there's at least one step beyond 1.
        let needs_evts = n_conds > 1;
        if needs_evts {
            layer0_cols.push(format!(
                "arraySort(e -> e.1, groupArrayIf(tuple({}), {})) AS _evts",
                tuple_parts.join(", "),
                any_cond
            ));
        }
        layer0_cols.push("count() AS sequence_count".to_string());

        let maxspan_column = if let Some(secs) = maxspan_seconds {
            format!(", {} AS maxspan_seconds", secs)
        } else {
            String::new()
        };

        let inner = format!(
            "SELECT {}{}\n    FROM {}\n    GROUP BY {}\n    HAVING {}",
            layer0_cols.join(", "),
            maxspan_column,
            source,
            group_fields.join(", "),
            sequence_func
        );

        // -------- Layers 1..N-1: compute _step_{k+1} = first cond_{k+1} event
        //          in _evts with timestamp strictly after the previous step. --------
        // After layer `k` runs, `_step_{k+1}` is in scope as a tuple. For step 2
        // the anchor is `step1_time`; for step 3+ it's `_step_k.1`.
        let mut current_query = inner;
        for k_idx in 1..n_conds {
            let prev_ts_expr = if k_idx == 1 {
                "step1_time".to_string()
            } else {
                format!("_step_{}.1", k_idx)
            };
            let wrapper = format!(
                "SELECT *, arrayFirst(e -> e.{flag} = 1 AND e.1 > toUInt32({prev}), _evts) AS _step_{next}\n    FROM (\n    {inner}\n    )",
                flag = flag_pos(k_idx),
                prev = prev_ts_expr,
                next = k_idx + 1,
                inner = current_query
            );
            current_query = wrapper;
        }

        // -------- Outermost layer: project step columns + duration + timestamp. --------
        let mut outer_cols: Vec<String> = Vec::new();
        for f in &group_fields {
            outer_cols.push(f.clone());
        }
        outer_cols.push("step1_time".to_string());
        outer_cols.push("step1_event_id".to_string());
        for f in &per_step_captures[0] {
            outer_cols.push(format!("step1_{}", f.replace('.', "_")));
        }
        for k_idx in 1..n_conds {
            let step_num = k_idx + 1;
            let tup = format!("_step_{}", step_num);
            outer_cols.push(format!(
                "toDateTime({tup}.1) AS step{n}_time",
                tup = tup,
                n = step_num
            ));
            outer_cols.push(format!("{tup}.2 AS step{n}_event_id", tup = tup, n = step_num));
            for f in &per_step_captures[k_idx] {
                outer_cols.push(format!(
                    "{tup}.{pos} AS step{n}_{f}",
                    tup = tup,
                    pos = field_pos(f),
                    n = step_num,
                    f = f.replace('.', "_")
                ));
            }
        }
        outer_cols.push("sequence_count".to_string());
        if let Some(secs) = maxspan_seconds {
            outer_cols.push(format!("{} AS maxspan_seconds", secs));
        }
        // Duration: step1_time → last step's time. Always ≥ 0 because steps are
        // chronologically walked; can be 0 only when events share the same second.
        let last_step_ts = if n_conds == 1 {
            "step1_time".to_string()
        } else {
            format!("toDateTime(_step_{}.1)", n_conds)
        };
        outer_cols.push(format!(
            "dateDiff('second', step1_time, {}) AS sequence_duration_seconds",
            last_step_ts
        ));
        outer_cols.push("step1_time AS _seq_timestamp".to_string());

        // Wrap again to rename _seq_timestamp → timestamp for downstream CTEs
        // (| table, | where, | risk). Same pattern as before — keeping `timestamp`
        // visible to downstream commands without shadowing the inner aggregation.
        Ok(format!(
            "  SELECT *, _seq_timestamp AS timestamp FROM (\n    SELECT {}\n    FROM (\n    {}\n    )\n    ORDER BY step1_time DESC\n  )",
            outer_cols.join(", "),
            current_query
        ))
    }

    /// Generate SQL for funnel analysis command
    pub(super) fn generate_funnel_sql(
        &self,
        source: &str,
        group_by: &[String],
        window: &std::time::Duration,
        steps: &[(String, SearchExpr)],
    ) -> Result<String, SqlGenError> {
        if steps.is_empty() {
            return Err(SqlGenError::InvalidQuery(
                "Funnel requires at least one step".into(),
            ));
        }

        // Convert each step condition to SQL
        let condition_sqls: Result<Vec<String>, SqlGenError> = steps
            .iter()
            .map(|(_, cond)| self.generate_search_expr(cond))
            .collect();
        let condition_sqls = condition_sqls?;

        // Group by fields
        let group_fields: Vec<String> = group_by
            .iter()
            .map(|f| by_field_sql(f, self))
            .collect();

        let seconds = window.as_secs();

        // Build CASE that maps funnel_level → declared step name. Only stages
        // 1..N are emitted; level 0 (matched no stage) is deliberately excluded.
        let step_name_cases: Vec<String> = steps
            .iter()
            .enumerate()
            .map(|(i, (name, _))| format!("WHEN {} THEN '{}'", i + 1, escape_string(name)))
            .collect();
        let step_name_expr = format!(
            "CASE funnel_level {} ELSE 'none' END AS step_name",
            step_name_cases.join(" ")
        );

        // Literal array [1, 2, ..., N] — cross-joined with the per-entity
        // windowFunnel result so the output shape is always exactly N rows,
        // one per declared stage, regardless of which levels were reached.
        let stage_array = (1..=steps.len())
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Per-field argMax expressions. The name list lives in
        // `crate::search::query_processing::FUNNEL_DROPPER_FIELDS` so the
        // post-processor reads the exact same set.
        //
        // We use argMaxIf (not argMax) for fields where the "zero/empty" value
        // is meaningful noise we want to skip:
        //   - dest_port == 0 is the column default for events without a port;
        //     leaving it in would surface "dest_port 0 · 78%" as a top dropper
        //     attribute, which is misleading.
        //
        // For string fields, argMax returns '' for sources that don't populate
        // the column, and the post-processor filters '' before top-K.
        // Resolve each dropper field through the active profile so OCSF reads its
        // promoted column instead of a literal UDM name; the `_last_<name>` /
        // `_droppers_<name>` aliases stay keyed by the canonical UDM name so the
        // post-processor reads the same set. Fields the active schema has no
        // column for are SKIPPED (None) rather than emitting an unknown-column
        // reference. For UDM `udm_column_sql` returns the escaped column itself,
        // so this is byte-identical (`dest_port` keeps its zero-filtered argMaxIf).
        let argmax_expr = |name: &str| -> Option<String> {
            let col = self.profile.udm_column_sql(name)?;
            // Port fields default to 0 for portless events; argMaxIf skips that
            // noise so it never surfaces as a top dropper attribute.
            let is_port = name.ends_with("_port") || name == "port";
            if is_port {
                Some(format!(
                    "argMaxIf(toString({col}), timestamp, {col} != 0) AS _last_{name}"
                ))
            } else {
                Some(format!("argMax({col}, timestamp) AS _last_{name}"))
            }
        };

        let entity_argmax: Vec<String> = crate::search::query_processing::FUNNEL_DROPPER_FIELDS
            .iter()
            .filter_map(|name| argmax_expr(name))
            .collect();

        // Outer aggregation: one groupArraySampleIf per curated field, capped
        // at 1000 per stage to bound memory. Use the -If combinator (matches
        // the rest of this generator's style) rather than the SQL-standard
        // FILTER clause for older ClickHouse compatibility.
        let dropper_samples: Vec<String> = crate::search::query_processing::FUNNEL_DROPPER_FIELDS
            .iter()
            // Mirror `entity_argmax`: only emit a sampler for fields the active
            // schema actually produced a `_last_<name>` column for.
            .filter(|name| self.profile.udm_column_sql(name).is_some())
            .map(|name| {
                format!(
                    "groupArraySampleIf(1000)(_last_{name}, _fl == funnel_level) AS _droppers_{name}"
                )
            })
            .collect();

        // Idle span: seconds between the first and last timestamp per entity.
        // Median across the set of droppers at this stage.
        //
        // `_span_s` is captured in the entity CTE; `medianIf` in the outer
        // aggregation restricts to droppers (entities whose max level equals
        // this stage — i.e., they reached stage N but not N+1).
        let span_expr = "toUnixTimestamp(max(timestamp)) - toUnixTimestamp(min(timestamp)) AS _span_s";
        let dropper_median_idle = "medianIf(_span_s, _fl == funnel_level) AS dropper_median_idle_s";

        // Dropper count: entities where _fl == this stage (reached this stage
        // but not the next). The final stage's dropper_count is always 0 by
        // construction since there's no "next" stage to drop to.
        let dropper_count_expr = "countIf(_fl == funnel_level) AS dropper_count";

        // 1) Inner: per `by`-group max level reached via windowFunnel (0..N).
        // 2) ARRAY JOIN [1..N] explodes each entity row into N rows, one per
        //    declared stage. GROUP BY lvl with countIf(_fl >= lvl) yields
        //    *cumulative* per-stage counts — entities reaching at least that
        //    stage. By construction monotonically non-increasing, since
        //    {fl >= k+1} ⊆ {fl >= k}.
        // (NAN-392 cumulative-counts fix from main is already incorporated
        //  in the main format string below; the redesign branch added the
        //  dropper-attribution columns on top.)
        Ok(format!(
            "  SELECT funnel_level, {step_name}, countIf(_fl >= funnel_level) AS count, {drop_count}, {drop_idle}, {drop_samples}\n  FROM (\n    SELECT {group}, windowFunnel({seconds})(toUInt32(timestamp), {conds}) AS _fl, {argmax}, {span}\n    FROM {source}\n    GROUP BY {group}\n  )\n  ARRAY JOIN [{stages}] AS funnel_level\n  GROUP BY funnel_level\n  ORDER BY funnel_level ASC",
            step_name = step_name_expr,
            drop_count = dropper_count_expr,
            drop_idle = dropper_median_idle,
            drop_samples = dropper_samples.join(", "),
            group = group_fields.join(", "),
            seconds = seconds,
            conds = condition_sqls.join(", "),
            argmax = entity_argmax.join(", "),
            span = span_expr,
            source = source,
            stages = stage_array,
        ))
    }

    /// Generate SQL for anomaly detection command
    pub(super) fn generate_anomaly_sql(
        &self,
        source: &str,
        field: &str,
        by_fields: &[String],
        threshold: f64,
        method: &AnomalyMethod,
    ) -> Result<String, SqlGenError> {
        let by_exprs: Vec<String> = by_fields
            .iter()
            .map(|b| by_field_sql(b, self))
            .collect();

        // Aggregation-first syntax: field contains "(" like "count()" or "sum(bytes_out)"
        // → compute the aggregation per by_fields group, then detect anomalies on the result
        let is_aggregation = field.contains('(');
        if is_aggregation {
            return self
                .generate_anomaly_aggregation_sql(source, field, &by_exprs, threshold, method);
        }

        let field_expr = by_field_sql(field, self);
        // NAN-1642: per-group z-score/MAD constants come from a map-scalar
        // attach (or a plain scalar with no `by`) instead of whole-partition
        // windows, which buffered every wide row of the partition and OOM'd
        // (Code 241) at production scale. The scoring math is unchanged.
        let lookup_key = (!by_exprs.is_empty()).then(|| null_canonical_key_sql(&by_exprs));
        let keys = lookup_key
            .as_deref()
            .map(|k| (k, k));

        // Non-column numeric fields: aggregation/alias names that are not part of
        // any schema's column universe but are still numeric when statistical
        // anomaly runs on a computed result (stats aliases) or on common
        // non-canonical aliases. The schema columns themselves are classified via
        // the active profile below, so OCSF promoted numeric columns
        // (`dst_endpoint.port`, byte counts, …) also get direct statistical
        // anomaly instead of count-based. For UDM the union reproduces the prior
        // hardcoded list exactly (every real UDM numeric column already resolves
        // through `profile.is_numeric_field`).
        const NUMERIC_COMPUTED_FIELDS: &[&str] = &[
            // Non-canonical numeric aliases not carried in the profile field set
            "dst_port",
            "http_status",
            "severity_level",
            // Common computed fields from stats commands
            "count",
            "sum",
            "avg",
            "min",
            "max",
            "dc",
            "distinct_count",
            "percent",
            "stdev",
            "var",
            "range",
            "median",
            "anomaly_score",
            "host_count",
            "total_occurrences",
            "_anomaly_count",
        ];

        let normalized = normalize_field_name(field);
        let is_numeric = self.profile.is_numeric_field(normalized.as_ref())
            || NUMERIC_COMPUTED_FIELDS.contains(&normalized.as_ref());

        if is_numeric {
            // Direct anomaly on numeric values
            match method {
                AnomalyMethod::ZScore => {
                    let attach = zscore_attach_sql(source, source, &field_expr, keys);
                    Ok(Self::zscore_outer_sql(&field_expr, threshold, &attach, true))
                }
                AnomalyMethod::Mad => {
                    let attach = mad_attach_sql(source, source, &field_expr, keys);
                    Ok(Self::mad_outer_sql(&field_expr, threshold, &attach, true))
                }
            }
        } else {
            // Categorical/string field: count occurrences per group, then detect
            // anomalously rare values. e.g. "anomaly field=process_name by user"
            // → count each (user, process_name) pair, find unusually low counts.
            //
            // The window count + row_number dedup preserves all original columns
            // (timestamp, etc.) for downstream commands like `| table timestamp`
            // and is partitioned by (by-fields, field) — fine-grained partitions,
            // not the OOM-class whole-set buffering. The per-BY-group stats over
            // those pair counts, previously coarse whole-partition windows, come
            // from a bounded pair-count GROUP BY instead (NAN-1642): one row per
            // (by, field) pair carrying the same count `_anomaly_count` holds.
            let partition_cols = if !by_exprs.is_empty() {
                format!("{}, {}", by_exprs.join(", "), field_expr)
            } else {
                field_expr.clone()
            };
            let count_source = format!(
                "(SELECT * FROM (\
                SELECT *, \
                count() OVER (PARTITION BY {pcols}) as _anomaly_count, \
                row_number() OVER (PARTITION BY {pcols} ORDER BY timestamp DESC) as _rn \
                FROM {source}\
                ) WHERE _rn = 1)",
                pcols = partition_cols,
                source = source
            );
            let count_field = "_anomaly_count";

            // One row per (by, field) pair with its occurrence count — the same
            // value distribution the stats windows previously aggregated over
            // `count_source`, but built with plain GROUP BY memory bounds and
            // without re-executing the windowed dedup.
            let (pair_source, pair_keys): (String, Option<(&str, &str)>) = match &lookup_key {
                Some(key) => (
                    format!(
                        "(SELECT {key} AS __nano_k, count() AS __nano_cnt FROM {source} \
                         GROUP BY __nano_k, {field})",
                        key = key,
                        source = source,
                        field = field_expr
                    ),
                    Some(("__nano_k", key.as_str())),
                ),
                None => (
                    format!(
                        "(SELECT count() AS __nano_cnt FROM {source} GROUP BY {field})",
                        source = source,
                        field = field_expr
                    ),
                    None,
                ),
            };

            match method {
                AnomalyMethod::ZScore => {
                    let attach =
                        zscore_attach_sql(&count_source, &pair_source, "__nano_cnt", pair_keys);
                    Ok(Self::zscore_outer_sql(count_field, threshold, &attach, true))
                }
                AnomalyMethod::Mad => {
                    let attach =
                        mad_attach_sql(&count_source, &pair_source, "__nano_cnt", pair_keys);
                    Ok(Self::mad_outer_sql(count_field, threshold, &attach, true))
                }
            }
        }
    }

    /// Generate SQL for aggregation-first anomaly syntax: `anomaly count() by user, url_domain`
    /// First computes the aggregation per group, then detects anomalies on the aggregated values.
    fn generate_anomaly_aggregation_sql(
        &self,
        source: &str,
        agg_expr: &str,
        by_exprs: &[String],
        threshold: f64,
        method: &AnomalyMethod,
    ) -> Result<String, SqlGenError> {
        // Build the GROUP BY and aggregation source
        // e.g., SELECT user, url_domain, count() as _agg_value FROM source GROUP BY user, url_domain
        let group_cols = if by_exprs.is_empty() {
            // No group-by: aggregate over the entire dataset (single row result)
            return Err(SqlGenError::InvalidQuery(
                "anomaly with aggregation requires at least one 'by' field".into(),
            ));
        } else {
            by_exprs.join(", ")
        };

        // Normalize the agg expression into valid ClickHouse: map dc→uniq and
        // resolve the inner field through the active profile (NAN-1345). Without the
        // resolution, `sum(bytes_in)` emits the raw `bytes_in`, which under OCSF is
        // `traffic.bytes_in` → `Code 47 Unknown identifier 'bytes_in'`. `stats` /
        // `streamstats` already resolve agg fields; anomaly's aggregation-first path
        // did not. `count()` (empty inner) and computed aliases pass through unchanged.
        let func_mapped = agg_expr
            .replace("dc(", "uniq(")
            .replace("distinct_count(", "uniq(");
        let ch_agg = match (func_mapped.find('('), func_mapped.rfind(')')) {
            (Some(lp), Some(rp)) if rp > lp => {
                let func = &func_mapped[..lp];
                let inner = func_mapped[lp + 1..rp].trim();
                if inner.is_empty() {
                    func_mapped.clone()
                } else {
                    format!("{}({})", func, by_field_sql(inner, self))
                }
            }
            _ => func_mapped.clone(),
        };

        let agg_source = format!(
            "(SELECT {group_cols}, {agg} as _agg_value, \
            max(timestamp) as timestamp \
            FROM {source} \
            GROUP BY {group_cols})",
            group_cols = group_cols,
            agg = ch_agg,
            source = source
        );

        // NAN-1642: the global stats over the per-group aggregates were
        // whole-set windows (`… OVER ()`) buffering every group row; the same
        // constants now come from a scalar tuple over `agg_source` (a single
        // global group — every group's value is scored against the whole
        // distribution, unchanged). No is_anomaly filter on this path: all
        // groups are returned, scored.
        let val = "_agg_value";
        match method {
            AnomalyMethod::ZScore => {
                let attach = zscore_attach_sql(&agg_source, &agg_source, val, None);
                Ok(Self::zscore_outer_sql(val, threshold, &attach, false))
            }
            AnomalyMethod::Mad => {
                let attach = mad_attach_sql(&agg_source, &agg_source, val, None);
                Ok(Self::mad_outer_sql(val, threshold, &attach, false))
            }
        }
    }
}
