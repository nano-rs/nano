// SPDX-License-Identifier: AGPL-3.0-or-later

//! Complex command SQL generation
//!
//! Helper methods for complex command match arms: StreamStats, EventStats,
//! Sequence, Funnel, Anomaly, Tree, Asset, Cloud.

use super::helpers::*;
use super::{extract_fields_from_search_expr, ClickHouseSqlGenerator};
use crate::query::ast::*;
use crate::query::sql_gen::SqlGenError;

impl ClickHouseSqlGenerator {
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

        // Build window function expressions for each aggregation
        let window_exprs: Vec<String> = aggregations.iter()
            .map(|agg| {
                let (field_expr, _) = agg.field.as_ref()
                    .map(|f| field_to_sql_expr(f, self))
                    .unwrap_or_else(|| ("*".to_string(), false));

                // Map aggregation functions to window functions
                // For last() with current=false, use lagInFrame for "previous value"
                let window_func = match agg.func {
                    AggFunc::Count => format!("count({}) OVER ({}ORDER BY timestamp {})",
                        if field_expr == "*" { "" } else { &field_expr }, partition_clause, frame_spec),
                    AggFunc::Sum => format!("sum({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Avg => format!("avg({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Min => format!("min({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Max => format!("max({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::First => {
                        // first() in streamstats context means first value in the window
                        format!("first_value({}) OVER ({}ORDER BY timestamp {})",
                            field_expr, partition_clause, frame_spec)
                    }
                    AggFunc::Last => {
                        // For current=false, last() means "previous value" - use lagInFrame
                        if !current {
                            format!("lagInFrame({}, 1) OVER ({}ORDER BY timestamp)",
                                field_expr, partition_clause)
                        } else {
                            format!("last_value({}) OVER ({}ORDER BY timestamp {})",
                                field_expr, partition_clause, frame_spec)
                        }
                    }
                    AggFunc::Dc => format!("uniqExact({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::EstDc => format!("uniqCombined64({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Values => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArrayDistinct({})(toString({})) OVER ({}ORDER BY timestamp {})), ', ')",
                        self.max_group_array_size, field_expr, partition_clause, frame_spec),
                    AggFunc::List => format!("arrayStringConcat(arrayFilter(x -> x != '', groupArray({})(toString({})) OVER ({}ORDER BY timestamp {})), ', ')",
                        self.max_group_array_size, field_expr, partition_clause, frame_spec),
                    AggFunc::Stdev => format!("stddevPop({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Var => format!("varPop({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Range => format!("(max({}) OVER ({}ORDER BY timestamp {}) - min({}) OVER ({}ORDER BY timestamp {}))",
                        field_expr, partition_clause, frame_spec, field_expr, partition_clause, frame_spec),
                    AggFunc::Earliest => format!("min({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    AggFunc::Latest => format!("max({}) OVER ({}ORDER BY timestamp {})",
                        field_expr, partition_clause, frame_spec),
                    _ => format!("count({}) OVER ({}ORDER BY timestamp {})",
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

    /// Generate SQL for eventstats command using window functions
    pub(super) fn generate_eventstats_sql(
        &self,
        source: &str,
        aggregations: &[Aggregation],
        group_by: &Option<Vec<String>>,
    ) -> Result<String, SqlGenError> {
        let partition_clause = match group_by {
            Some(fields) => {
                let partition_fields: Vec<String> = fields
                    .iter()
                    .map(|f| by_field_sql(f, self))
                    .collect();
                partition_fields.join(", ")
            }
            None => String::new(),
        };

        let window_exprs: Vec<String> = aggregations
            .iter()
            .map(|agg| -> Result<String, SqlGenError> {
                let field_expr = agg
                    .field
                    .as_ref()
                    .map(|f| by_field_sql(f, self))
                    .unwrap_or_else(|| "*".to_string());

                // Whole-partition window (no ORDER BY): eventstats annotates every row with the
                // group aggregate. Computed once and reused by every arm below.
                let over = if partition_clause.is_empty() {
                    "OVER ()".to_string()
                } else {
                    format!("OVER (PARTITION BY {})", partition_clause)
                };

                // Exhaustive on purpose. Previously the `_` arm silently emitted `count() OVER`
                // for stdev/var/values/list/range/median/perc/mode/first/last/earliest/latest,
                // returning a row count under the user's alias (NAN-1145). Every variant now maps
                // to its real window aggregate (mirroring streamstats/stats) or is rejected —
                // never silently count(). A new AggFunc variant forces a decision here.
                let window_func = match agg.func {
                    AggFunc::Count => format!("count() {}", over),
                    AggFunc::Dc => {
                        // ClickHouse has no distinct window function; over the whole set use a
                        // scalar subquery, otherwise approximate with uniqExact over the partition.
                        if partition_clause.is_empty() {
                            format!("(SELECT count(DISTINCT {}) FROM {})", field_expr, source)
                        } else {
                            format!("uniqExact({}) {}", field_expr, over)
                        }
                    }
                    AggFunc::EstDc => {
                        // Approximate distinct count: same shape as dc() but bounded
                        // memory via uniqCombined64 (~0.9% measured error).
                        if partition_clause.is_empty() {
                            format!("(SELECT uniqCombined64({}) FROM {})", field_expr, source)
                        } else {
                            format!("uniqCombined64({}) {}", field_expr, over)
                        }
                    }
                    AggFunc::Sum => format!("sum({}) {}", field_expr, over),
                    AggFunc::Avg => format!("avg({}) {}", field_expr, over),
                    AggFunc::Min => format!("min({}) {}", field_expr, over),
                    AggFunc::Max => format!("max({}) {}", field_expr, over),
                    AggFunc::Stdev => format!("stddevPop({}) {}", field_expr, over),
                    AggFunc::Var => format!("varPop({}) {}", field_expr, over),
                    AggFunc::Range => format!("(max({0}) {1} - min({0}) {1})", field_expr, over),
                    AggFunc::Median => format!("median({}) {}", field_expr, over),
                    AggFunc::Perc95 => format!("quantile(0.95)({}) {}", field_expr, over),
                    AggFunc::Percentile(p) => {
                        format!("quantile({})({}) {}", f64::from(p) / 100.0, field_expr, over)
                    }
                    AggFunc::Values => format!(
                        "arrayStringConcat(arrayFilter(x -> x != '', \
                         groupUniqArray({})(toString({})) {}), ', ')",
                        self.max_group_array_size, field_expr, over
                    ),
                    AggFunc::List => format!(
                        "arrayStringConcat(arrayFilter(x -> x != '', \
                         groupArray({})(toString({})) {}), ', ')",
                        self.max_group_array_size, field_expr, over
                    ),
                    AggFunc::First => format!("any({}) {}", field_expr, over),
                    AggFunc::Last => format!("anyLast({}) {}", field_expr, over),
                    AggFunc::Earliest => format!("argMin({}, timestamp) {}", field_expr, over),
                    AggFunc::Latest => format!("argMax({}, timestamp) {}", field_expr, over),
                    AggFunc::Mode => format!("(topK(1)({}) {})[1]", field_expr, over),
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

                Ok(format!("{} AS {}", window_func, escape_identifier(&alias)))
            })
            .collect::<Result<Vec<String>, SqlGenError>>()?;

        Ok(format!(
            "  SELECT *, {} FROM {}",
            window_exprs.join(", "),
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
        let partition_clause = if !by_exprs.is_empty() {
            format!("PARTITION BY {}", by_exprs.join(", "))
        } else {
            String::new()
        };

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
                    Ok(format!(
                        "  SELECT *, avg_val, stddev_val,\n    \
                        abs({field} - avg_val) / nullIf(stddev_val, 0) as anomaly_score,\n    \
                        if(abs({field} - avg_val) > {threshold} * stddev_val, 1, 0) as is_anomaly\n  \
                        FROM (\n    \
                        SELECT *, avg({field}) OVER ({partition}) as avg_val,\n      \
                        stddevPop({field}) OVER ({partition}) as stddev_val\n    \
                        FROM {source}\n  )\n  \
                        WHERE is_anomaly = 1\n  \
                        ORDER BY anomaly_score DESC",
                        field = field_expr,
                        threshold = threshold,
                        partition = partition_clause,
                        source = source
                    ))
                }
                AnomalyMethod::Mad => {
                    Ok(format!(
                        "  SELECT *, median_val, mad_val,\n    \
                        abs({field} - median_val) / nullIf(mad_val * 1.4826, 0) as anomaly_score,\n    \
                        if(abs({field} - median_val) > {threshold} * mad_val * 1.4826, 1, 0) as is_anomaly\n  \
                        FROM (\n    \
                        SELECT *, median_val,\n      \
                        quantile(0.5)(abs({field} - median_val)) OVER ({partition}) as mad_val\n    \
                        FROM (\n      \
                        SELECT *, quantile(0.5)({field}) OVER ({partition}) as median_val\n      \
                        FROM {source}\n    )\n  )\n  \
                        WHERE is_anomaly = 1\n  \
                        ORDER BY anomaly_score DESC",
                        field = field_expr,
                        threshold = threshold,
                        partition = partition_clause,
                        source = source
                    ))
                }
            }
        } else {
            // Categorical/string field: count occurrences per group, then detect
            // anomalously rare values. e.g. "anomaly field=process_name by user"
            // → count each (user, process_name) pair, find unusually low counts.
            //
            // Uses window functions (not GROUP BY) to preserve all original columns
            // (timestamp, etc.) for downstream commands like `| table timestamp`.
            // Steps: window count per group → dedup to 1 row per group → anomaly stats.
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

            match method {
                AnomalyMethod::ZScore => {
                    Ok(format!(
                        "  SELECT *, avg_val, stddev_val,\n    \
                        abs({cf} - avg_val) / nullIf(stddev_val, 0) as anomaly_score,\n    \
                        if(abs({cf} - avg_val) > {threshold} * stddev_val, 1, 0) as is_anomaly\n  \
                        FROM (\n    \
                        SELECT *, avg({cf}) OVER ({partition}) as avg_val,\n      \
                        stddevPop({cf}) OVER ({partition}) as stddev_val\n    \
                        FROM {count_source}\n  )\n  \
                        WHERE is_anomaly = 1\n  \
                        ORDER BY anomaly_score DESC",
                        cf = count_field,
                        threshold = threshold,
                        partition = partition_clause,
                        count_source = count_source
                    ))
                }
                AnomalyMethod::Mad => {
                    Ok(format!(
                        "  SELECT *, median_val, mad_val,\n    \
                        abs({cf} - median_val) / nullIf(mad_val * 1.4826, 0) as anomaly_score,\n    \
                        if(abs({cf} - median_val) > {threshold} * mad_val * 1.4826, 1, 0) as is_anomaly\n  \
                        FROM (\n    \
                        SELECT *, median_val,\n      \
                        quantile(0.5)(abs({cf} - median_val)) OVER ({partition}) as mad_val\n    \
                        FROM (\n      \
                        SELECT *, quantile(0.5)({cf}) OVER ({partition}) as median_val\n      \
                        FROM {count_source}\n    )\n  )\n  \
                        WHERE is_anomaly = 1\n  \
                        ORDER BY anomaly_score DESC",
                        cf = count_field,
                        threshold = threshold,
                        partition = partition_clause,
                        count_source = count_source
                    ))
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

        let val = "_agg_value";
        match method {
            AnomalyMethod::ZScore => {
                Ok(format!(
                    "  SELECT *, avg_val, stddev_val,\n    \
                    abs({val} - avg_val) / nullIf(stddev_val, 0) as anomaly_score,\n    \
                    if(abs({val} - avg_val) > {threshold} * stddev_val, 1, 0) as is_anomaly\n  \
                    FROM (\n    \
                    SELECT *, avg({val}) OVER () as avg_val,\n      \
                    stddevPop({val}) OVER () as stddev_val\n    \
                    FROM {agg_source}\n  )\n  \
                    ORDER BY anomaly_score DESC",
                    val = val,
                    threshold = threshold,
                    agg_source = agg_source,
                ))
            }
            AnomalyMethod::Mad => {
                Ok(format!(
                    "  SELECT *, median_val, mad_val,\n    \
                    abs({val} - median_val) / nullIf(mad_val * 1.4826, 0) as anomaly_score,\n    \
                    if(abs({val} - median_val) > {threshold} * mad_val * 1.4826, 1, 0) as is_anomaly\n  \
                    FROM (\n    \
                    SELECT *, median_val,\n      \
                    quantile(0.5)(abs({val} - median_val)) OVER () as mad_val\n    \
                    FROM (\n      \
                    SELECT *, quantile(0.5)({val}) OVER () as median_val\n      \
                    FROM {agg_source}\n    )\n  )\n  \
                    ORDER BY anomaly_score DESC",
                    val = val,
                    threshold = threshold,
                    agg_source = agg_source,
                ))
            }
        }
    }
}
