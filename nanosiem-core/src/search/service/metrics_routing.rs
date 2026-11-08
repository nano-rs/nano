// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1555 resolution routing — decide whether a metrics nPL query can be served
//! from the pre-aggregated `otel_metrics_1m`/`_1h` rollup (migration 144) instead
//! of scanning raw `otel_metrics`.
//!
//! DELIBERATELY CONSERVATIVE: [`metrics_rollup_grain`] returns `None` (→ read raw,
//! which is always correct) for anything it does not fully recognize as
//! rollup-equivalent. A query is eligible ONLY when it is a single aggregating
//! command (`stats`/`chart`/`timechart`) whose:
//! - source filter is a conjunction of `metric_name`/`service_name` equalities (or
//!   bare `*`) — the rollup is keyed by those and carries no tag maps, so a tag
//!   filter or any free-text/keyword/IN/OR/NOT/value predicate disqualifies it;
//! - aggregations are all over `value` (or `count`) with a rollup-backed function
//!   (avg/sum/min/max/count/median/p95/p50|95|99/rate) and no conditional/expr arg;
//! - group-by is a subset of `{service_name, metric_name}` (the rollup's keys);
//! - window is WIDE enough that the rollup's coarser resolution is a win (and, for
//!   `timechart`, the rollup grain is no finer than the chart span).
//!
//! The rollup's avg/sum/min/max/quantiles were validated equal to the raw
//! aggregation within 0.0002% (migration 144); the generator's `rollup_value_agg`
//! emits the merged-state forms when pointed at a rollup table.

use crate::query::{
    AggFunc, Aggregation, Command, Comparator, MetricRollup, Query, SearchExpr, TimeRange,
};
use crate::schema::canonicalize_metric_field;

/// Below this window the raw scan (pruned by the `idx_metric_name` set index + the
/// `(metric_name, service_name, timestamp)` sort key + time partition) is fast
/// enough that the rollup's resolution loss isn't worth it.
const MIN_WINDOW_FOR_MINUTE_ROLLUP: i64 = 6 * 3600; // 6 hours
/// Above this window the coarse hourly rollup is preferred (1m rollup would still
/// scan thousands of minute rows per series).
const MIN_WINDOW_FOR_HOUR_ROLLUP: i64 = 7 * 86400; // 7 days

/// Pick a rollup grain for an eligible metrics aggregate query over a wide window,
/// or `None` to read raw `otel_metrics`.
pub(super) fn metrics_rollup_grain(
    query: &Query,
    time_range: &TimeRange,
) -> Option<MetricRollup> {
    // Exactly one bare-search source + one aggregating command (no multi-stage
    // pipes — a `where`/`eval`/`rex` stage could reference per-point columns the
    // rollup lacks).
    let Query::Piped { source, command } = query else {
        return None;
    };
    let Query::Search(filter) = source.as_ref() else {
        return None;
    };
    if !filter_is_rollup_safe(filter) {
        return None;
    }

    let (aggs, group_by, span_secs): (&[Aggregation], &[String], Option<u64>) = match command {
        Command::Stats { aggregations, group_by } | Command::Chart { aggregations, group_by } => {
            (aggregations, group_by.as_deref().unwrap_or(&[]), None)
        }
        Command::Timechart { aggregations, split_by, span, .. } => {
            (aggregations, split_by.as_slice(), Some(span.as_secs()))
        }
        _ => return None,
    };

    if aggs.is_empty() || !aggs.iter().all(agg_is_rollup_value) {
        return None;
    }
    if !group_by.iter().all(|g| {
        let c = canonicalize_metric_field(g);
        c == "service_name" || c == "metric_name"
    }) {
        return None;
    }

    let window_secs = (time_range.end - time_range.start).num_seconds();
    select_grain(window_secs, span_secs)
}

/// Whether a single aggregation is a rollup-backed `value` (or `count`) aggregation.
fn agg_is_rollup_value(a: &Aggregation) -> bool {
    // Conditional aggregation (`count(eval(...))`) and expression args
    // (`sum(a+b)`) have no rollup form.
    if a.condition.is_some() || a.field_expr.is_some() {
        return false;
    }
    let is_value = a
        .field
        .as_deref()
        .map(|f| canonicalize_metric_field(f) == "value")
        .unwrap_or(false);
    match a.func {
        AggFunc::Avg
        | AggFunc::Min
        | AggFunc::Max
        | AggFunc::Earliest
        | AggFunc::Latest
        | AggFunc::Median
        | AggFunc::Perc95 => is_value,
        // The rollup t-digest stores p50/p95/p99 only.
        AggFunc::Percentile(p) => is_value && matches!(p, 50 | 95 | 99),
        // `rate()` is DELIBERATELY excluded from the rollup: the raw rate is
        // counter-reset-aware (sum of positive consecutive deltas of the
        // time-ordered points), which the rollup cannot reconstruct — it keeps
        // only per-bucket min/max/sum/count/tdigest, no per-point order. The
        // `max(value_max) - min(value_min)` rollup form diverges from the raw rate
        // by 5-6 orders of magnitude (NAN-1555 adversarial review). `sum`/`count`
        // are excluded too: they are ADDITIVE, so the half-open window bound still
        // can't make a coarse-grain rollup's edge bucket match raw to the
        // data-point — these stay on raw (always exact). avg/min/max/quantiles ARE
        // rollup-equivalent (validated within 0.0002%) and keep routing.
        _ => false,
    }
}

/// Whether the source filter touches ONLY the rollup's key columns by equality.
fn filter_is_rollup_safe(expr: &SearchExpr) -> bool {
    match expr {
        SearchExpr::FieldFilter { field, op, .. } => {
            matches!(op, Comparator::Eq) && {
                let c = canonicalize_metric_field(field);
                c == "metric_name" || c == "service_name"
            }
        }
        SearchExpr::And(l, r) => filter_is_rollup_safe(l) && filter_is_rollup_safe(r),
        SearchExpr::Group(inner) => filter_is_rollup_safe(inner),
        // Bare `*` match-all carries no predicate.
        SearchExpr::Keyword(k) => k == "*",
        _ => false,
    }
}

fn select_grain(window_secs: i64, span_secs: Option<u64>) -> Option<MetricRollup> {
    match span_secs {
        // Timechart: the rollup grain must be no FINER than the chart span (reading
        // an hourly rollup for a sub-hour chart would lose the buckets).
        Some(s) => {
            if s >= 3600 && window_secs > MIN_WINDOW_FOR_HOUR_ROLLUP {
                Some(MetricRollup::Hour)
            } else if s >= 60 && window_secs > MIN_WINDOW_FOR_MINUTE_ROLLUP {
                Some(MetricRollup::Minute)
            } else {
                None
            }
        }
        // Stats: a single scalar over the whole window.
        None => {
            if window_secs > MIN_WINDOW_FOR_HOUR_ROLLUP {
                Some(MetricRollup::Hour)
            } else if window_secs > MIN_WINDOW_FOR_MINUTE_ROLLUP {
                Some(MetricRollup::Minute)
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;

    fn win(days: i64) -> TimeRange {
        TimeRange {
            start: "2026-06-01T00:00:00Z".parse().unwrap(),
            end: ("2026-06-01T00:00:00Z".parse::<chrono::DateTime<chrono::Utc>>().unwrap()
                + chrono::Duration::days(days)),
        }
    }

    fn grain(q: &str, days: i64) -> Option<MetricRollup> {
        metrics_rollup_grain(&parse_query(q).unwrap(), &win(days))
    }

    #[test]
    fn eligible_aggregate_over_wide_window_routes_to_rollup() {
        // Stats avg(value) by service over a 30-day window → hourly rollup.
        assert_eq!(
            grain(r#"metric_name="cpu" | stats avg(value) by service_name"#, 30),
            Some(MetricRollup::Hour)
        );
        // 1-day window → minute rollup.
        assert_eq!(
            grain(r#"metric_name="cpu" | stats avg(value) by service_name"#, 1),
            Some(MetricRollup::Minute)
        );
        // timechart hourly over 30 days → hourly rollup.
        assert_eq!(
            grain(r#"metric_name="cpu" | timechart span=1h avg(value)"#, 30),
            Some(MetricRollup::Hour)
        );
        // Rollup-equivalent funcs: avg/min/max/median/p95.
        for f in ["min(value)", "max(value)", "median(value)", "p95(value)"] {
            assert!(
                grain(&format!(r#"metric_name="cpu" | stats {f} by service_name"#), 30).is_some(),
                "{f} should be rollup-eligible"
            );
        }
    }

    #[test]
    fn additive_and_rate_aggs_stay_on_raw() {
        // NAN-1555 adversarial review: sum/count are additive (would over-count the
        // window-edge bucket) and rate must stay reset-aware on raw points — none
        // of these are rollup-equivalent, so they are NOT routed (→ raw, exact).
        assert_eq!(grain(r#"metric_name="cpu" | stats sum(value) by service_name"#, 30), None);
        assert_eq!(grain(r#"metric_name="cpu" | stats count by service_name"#, 30), None);
        assert_eq!(grain(r#"metric_name="cpu" | stats rate(value) by service_name"#, 30), None);
        assert_eq!(
            grain(r#"metric_name="cpu" | timechart span=1h rate(value)"#, 30),
            None
        );
        // A mixed agg list with any non-rollup func disqualifies the whole query.
        assert_eq!(
            grain(r#"metric_name="cpu" | stats avg(value), sum(value) by service_name"#, 30),
            None
        );
    }

    #[test]
    fn narrow_window_stays_on_raw() {
        // 1-hour window is below the minute-rollup threshold → raw.
        assert_eq!(
            metrics_rollup_grain(
                &parse_query(r#"metric_name="cpu" | stats avg(value) by service_name"#).unwrap(),
                &TimeRange {
                    start: "2026-06-01T00:00:00Z".parse().unwrap(),
                    end: "2026-06-01T01:00:00Z".parse().unwrap(),
                },
            ),
            None
        );
        // Sub-minute timechart span can't use the minute rollup.
        assert_eq!(
            grain(r#"metric_name="cpu" | timechart span=10s avg(value)"#, 30),
            None
        );
    }

    #[test]
    fn ineligible_shapes_stay_on_raw() {
        // Tag filter (rollup carries no tag maps).
        assert_eq!(grain(r#"metric_name="cpu" http.route="/api" | stats avg(value)"#, 30), None);
        // Tag group-by.
        assert_eq!(grain(r#"metric_name="cpu" | stats avg(value) by http.route"#, 30), None);
        // Aggregation over a non-value field.
        assert_eq!(grain(r#"metric_name="cpu" | stats avg(count) by service_name"#, 30), None);
        // Unsupported function (stdev has no rollup state).
        assert_eq!(grain(r#"metric_name="cpu" | stats stdev(value) by service_name"#, 30), None);
        // Distinct-count has no rollup state.
        assert_eq!(grain(r#"metric_name="cpu" | stats dc(value) by service_name"#, 30), None);
        // Multi-stage pipe (a where stage references per-point value).
        assert_eq!(
            grain(r#"metric_name="cpu" | where value > 0.5 | stats avg(value) by service_name"#, 30),
            None
        );
        // Free-text keyword predicate.
        assert_eq!(grain(r#"cpu | stats avg(value) by service_name"#, 30), None);
        // Raw event search (no aggregating command).
        assert_eq!(grain(r#"metric_name="cpu""#, 30), None);
    }

    #[test]
    fn match_all_aggregate_is_eligible() {
        // `*` carries no predicate; aggregate across metrics grouped by metric_name.
        assert!(grain(r#"* | stats avg(value) by metric_name"#, 30).is_some());
    }
}
