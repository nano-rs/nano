// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1555 Phase 2 — nPL → ClickHouse SQL generation over the OTLP metrics
//! dataset. Pins the generated SQL shape for `dataset=metrics`. Each statement was
//! also executed against a live `otel_metrics` (55M rows) during development.

use nanosiem_core::query::{
    parse_query, ClickHouseSqlGenerator, Dataset, MetricRollup, TimeRange,
};

fn tr() -> TimeRange {
    TimeRange {
        start: "2026-06-20T00:00:00Z".parse().unwrap(),
        end: "2026-06-25T00:00:00Z".parse().unwrap(),
    }
}

fn m(q: &str) -> String {
    ClickHouseSqlGenerator::new()
        .with_dataset(Dataset::Metrics)
        .generate(&parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}")), &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

fn roll(q: &str) -> String {
    ClickHouseSqlGenerator::new()
        .with_dataset(Dataset::Metrics)
        .with_metrics_rollup(MetricRollup::Minute)
        .generate(&parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}")), &tr())
        .unwrap_or_else(|e| panic!("gen {q}: {e}"))
}

#[test]
fn metrics_where_on_tag_uses_map_subscript_not_bare_column() {
    // NAN-1555 review fix: `| where <tag>=…` re-derives the Map subscript (the
    // maps pass through the SELECT * a where-stage forces), not a bare column ref
    // that 500s (CH Code 47).
    let sql = m(r#"metric_name="x" | where http.route="/api""#);
    assert!(sql.contains("attributes['http.route']"), "{sql}");
    assert!(sql.contains("resource_attributes['http.route']"), "{sql}");
}

#[test]
fn metrics_timechart_split_by_does_not_force_global_gap_fill() {
    // NAN-1555 review fix: a multi-series metric chart must NOT force WITH FILL
    // (CH can't partition the fill per series → blank-series synthetic rows).
    let split = m(r#"metric_name="x" | timechart span=1h avg(value) by service_name"#);
    assert!(!split.contains("WITH FILL"), "multi-series must not force fill: {split}");
    // Single-series still gap-fills.
    let single = m(r#"metric_name="x" | timechart span=1h avg(value)"#);
    assert!(single.contains("WITH FILL FROM"), "single-series should fill: {single}");
}

// --- Resolution routing: rollup-mode codegen (validated equal to raw on CH) ----

#[test]
fn rollup_reads_rollup_table_and_passes_state_columns() {
    let sql = roll(r#"metric_name="x" | stats avg(value) by service_name"#);
    assert!(sql.contains("FROM otel_metrics_1m"), "{sql}");
    assert!(sql.contains("minute BETWEEN"), "{sql}");
    // SELECT * so the pre-aggregated state columns flow to the aggregation stage.
    assert!(sql.contains("SELECT * FROM otel_metrics_1m"), "{sql}");
}

#[test]
fn rollup_rewrites_value_aggregations_onto_state_columns() {
    // Only avg/min/max/median/p95 are rollup-routed (sum/count/rate stay on raw —
    // they are additive / reset-aware and not rollup-equivalent).
    assert!(roll(r#"metric_name="x" | stats avg(value) by service_name"#)
        .contains("sum(value_sum) / greatest(sum(value_count), 1)"));
    assert!(roll(r#"metric_name="x" | stats min(value) by service_name"#).contains("min(value_min)"));
    assert!(roll(r#"metric_name="x" | stats max(value) by service_name"#).contains("max(value_max)"));
    assert!(roll(r#"metric_name="x" | timechart span=1h p95(value)"#)
        .contains("quantilesTDigestMerge(0.5, 0.95, 0.99)(value_state)[2]"));
}

#[test]
fn raw_path_unaffected_by_rollup_helpers() {
    // Without with_metrics_rollup, the raw per-row aggregation is emitted.
    let sql = m(r#"metric_name="x" | stats avg(value) by service_name"#);
    assert!(sql.contains("avg(value)"), "{sql}");
    assert!(!sql.contains("value_sum"), "{sql}");
    assert!(sql.contains("FROM otel_metrics"), "{sql}");
}

#[test]
fn metrics_target_table_and_time_column() {
    let sql = m(r#"metric_name="x""#);
    assert!(sql.contains("FROM otel_metrics"), "{sql}");
    assert!(sql.contains("timestamp BETWEEN"), "{sql}");
}

#[test]
fn metric_name_filter_uses_raw_set_index_form() {
    // metric_name is lowercased-at-ingest → raw equality so the idx_metric_name
    // set index + sort-key prefix prune (NOT lower()-wrapped, which would defeat them).
    let sql = m(r#"metric_name="system.cpu.utilization""#);
    assert!(sql.contains("metric_name = 'system.cpu.utilization'"), "{sql}");
    assert!(!sql.contains("lower(metric_name)"), "{sql}");
}

#[test]
fn metrics_value_is_numeric() {
    let sql = m(r#"metric_name="x" | where value > 0.9"#);
    assert!(sql.contains("value > 0.9"), "{sql}");
    assert!(!sql.contains("toString(value)"), "{sql}");
}

#[test]
fn metrics_stats_avg_by_service() {
    let sql = m(r#"metric_name="x" | stats avg(value) by service_name"#);
    assert!(sql.contains("avg(value) AS avg"), "{sql}");
    assert!(sql.contains("GROUP BY service_name"), "{sql}");
}

#[test]
fn metrics_timechart_buckets_on_timestamp() {
    let sql = m(r#"metric_name="x" | timechart span=1h avg(value)"#);
    assert!(sql.contains("toStartOfHour(timestamp)"), "{sql}");
    assert!(sql.contains("avg(value)"), "{sql}");
}

#[test]
fn metrics_quantile_aggregation() {
    let sql = m(r#"metric_name="x" | timechart span=1h p95(value)"#);
    assert!(sql.contains("quantile(0.95)(value)"), "{sql}");
}

#[test]
fn metrics_tag_filter_uses_map_subscript() {
    let sql = m(r#"metric_name="x" http.route="/api""#);
    assert!(sql.contains("attributes['http.route']"), "{sql}");
    assert!(sql.contains("resource_attributes['http.route']"), "{sql}");
    assert!(!sql.contains("JSONExtractString(metadata"), "{sql}");
}

#[test]
fn metrics_timechart_gap_fills_full_window() {
    // Metrics timeseries always gap-fill (holes read as missing data), over the
    // FULL window via WITH FILL FROM..TO so leading/trailing empty buckets render.
    let sql = m(r#"metric_name="x" | timechart span=1h avg(value)"#);
    assert!(sql.contains("WITH FILL FROM toStartOfInterval(toDateTime("), "{sql}");
    assert!(sql.contains("STEP toIntervalSecond(3600)"), "{sql}");
}

#[test]
fn metrics_rate_is_counter_reset_aware() {
    // rate() on metrics sums positive deltas of the time-ordered values (drops
    // reset spikes), NOT the naive (max-min).
    let sql = m(r#"metric_name="x" | timechart span=1h rate(value)"#);
    assert!(sql.contains("arrayDifference(arrayMap(p -> p.2, arraySort(p -> p.1, groupArray((timestamp, value"), "{sql}");
    assert!(sql.contains("if(d > 0, d, 0)"), "{sql}");
    assert!(!sql.contains("(max(value) - min(value))"), "metrics rate must be reset-aware: {sql}");
}

#[test]
fn metrics_service_alias_canonicalizes() {
    // `service` -> `service_name`; no UDM cloud_service aliasing.
    let sql = m(r#"metric_name="x" | stats avg(value) by service"#);
    assert!(sql.contains("GROUP BY service_name"), "{sql}");
    assert!(!sql.contains("cloud_service"), "{sql}");
}

// --- O45 (NAN-1733): the audit-view gate is a logs-only concern -------------

#[test]
fn metrics_drop_the_logs_audit_exclusion() {
    // `enforce_non_audit_query` appends `… AND source_type != "audit"` for users
    // without `audit:view`. On metrics there is no `source_type` column — it would
    // resolve to a per-row attributes-Map lookup that hides any data point a tenant
    // tagged `source_type=audit`. It must be dropped for `Dataset::Metrics`.
    for q in [r#"metric_name="x""#, r#"metric_name="x" | stats avg(value) by service"#] {
        let enforced = nanosiem_core::search::query_processing::enforce_non_audit_query(q)
            .unwrap_or_else(|e| panic!("enforce {q}: {e}"));
        let sql = ClickHouseSqlGenerator::new()
            .with_dataset(Dataset::Metrics)
            .generate(
                &parse_query(&enforced).unwrap_or_else(|e| panic!("parse {enforced}: {e}")),
                &tr(),
            )
            .unwrap_or_else(|e| panic!("generate {enforced}: {e}"));
        assert!(
            !sql.contains("!= 'audit'") && !sql.contains("'audit'"),
            "metrics must not carry the audit gate for `{q}`: {sql}"
        );
    }
}
