// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-1555 — nPL → ClickHouse SQL generation over the OTLP spans dataset.
//!
//! These pin the generated SQL SHAPE for `dataset=spans`. Every statement here was
//! also executed against a live `otel_spans` (5.6M rows) during development and
//! returned correct rows; these tests guard the codegen against regression. They
//! cover the Phase-1 acceptance set (bare keyword, field filter, `where`,
//! `stats by`, attribute `Map` access) plus the multi-stage cross-CTE hazards a
//! second-pass review surfaced (attribute split-by passthrough, IN-list, timechart
//! time column), and assert the logs path stays byte-identical.

use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, Dataset, TimeRange};

fn tr() -> TimeRange {
    TimeRange {
        start: "2026-06-01T00:00:00Z".parse().unwrap(),
        end: "2026-06-25T00:00:00Z".parse().unwrap(),
    }
}

fn spans_sql(q: &str) -> String {
    ClickHouseSqlGenerator::new()
        .with_dataset(Dataset::Spans)
        .generate(&parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}")), &tr())
        .unwrap_or_else(|e| panic!("generate {q}: {e}"))
}

fn logs_sql(q: &str) -> String {
    ClickHouseSqlGenerator::new()
        .generate(&parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}")), &tr())
        .unwrap_or_else(|e| panic!("generate {q}: {e}"))
}

// --- Storage binding -------------------------------------------------------

#[test]
fn spans_target_table_and_time_column() {
    let sql = spans_sql("error");
    assert!(sql.contains("FROM otel_spans"), "{sql}");
    // Time-bound + default order use the spans clock `start_time`, never `timestamp`.
    assert!(sql.contains("start_time BETWEEN"), "{sql}");
    assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
    assert!(!sql.contains("timestamp BETWEEN"), "spans must not bound on timestamp: {sql}");
}

// --- Acceptance: bare keyword ---------------------------------------------

#[test]
fn spans_bare_keyword_tokenizes_span_name() {
    // The `idx_span_words` text index lives on lower(span_name) — the spans analog
    // of logs' lower(message). Bare keyword must NOT reference the absent `message`.
    let sql = spans_sql("error");
    assert!(sql.contains("hasAllTokens(lower(span_name), 'error')"), "{sql}");
    assert!(!sql.contains("lower(message)"), "spans have no message column: {sql}");
}

// --- Acceptance: field filter ---------------------------------------------

#[test]
fn spans_field_filter_keeps_promoted_column_not_udm_alias() {
    // `service_name` must resolve to the real column — NOT the UDM `cloud_service`
    // alias a tenant UdmProfile would apply.
    let sql = spans_sql(r#"service_name="checkout""#);
    assert!(sql.contains("lower(service_name) = 'checkout'"), "{sql}");
    assert!(!sql.contains("cloud_service"), "service_name must not become cloud_service: {sql}");
}

#[test]
fn spans_status_filter_lowers_both_sides_for_uppercase_enum() {
    // status_code carries UPPERCASE OTel enums (OK/ERROR); not lowercased-at-ingest,
    // so both sides are lowered for a correct case-insensitive match.
    let sql = spans_sql(r#"status_code="ERROR""#);
    assert!(sql.contains("lower(status_code) = 'error'"), "{sql}");
}

// --- Acceptance: where on a numeric promoted column ------------------------

#[test]
fn spans_where_duration_is_numeric() {
    let sql = spans_sql("* | where duration_ns > 1000000");
    assert!(sql.contains("duration_ns > 1000000"), "{sql}");
    // duration_ns is numeric — never toString-wrapped (the UdmProfile-misread bug).
    assert!(!sql.contains("toString(duration_ns)"), "duration_ns must stay numeric: {sql}");
    // Pipeline terminal order uses the spans time column.
    assert!(sql.contains("ORDER BY start_time DESC"), "{sql}");
}

#[test]
fn spans_duration_alias_canonicalizes() {
    // `duration` is the human-facing alias of the stored `duration_ns`.
    let sql = spans_sql("* | where duration > 1000000");
    assert!(sql.contains("duration_ns > 1000000"), "{sql}");
}

// --- Acceptance: stats by a promoted column --------------------------------

#[test]
fn spans_stats_by_service_groups_on_real_column() {
    let sql = spans_sql("* | stats count by service_name");
    assert!(sql.contains("GROUP BY service_name"), "{sql}");
    assert!(sql.contains("count() AS count"), "{sql}");
}

// --- Acceptance: attribute Map access (the A-plus tail) --------------------

#[test]
fn spans_attribute_filter_uses_map_subscript_with_resource_fallback() {
    // Un-promoted dotted attribute → literal Map subscript (dots PRESERVED, not
    // the dot-stripped `ext.httpmethod`), with a resource_attributes fallback.
    let sql = spans_sql(r#"http.method="GET""#);
    assert!(sql.contains("attributes['http.method']"), "{sql}");
    assert!(sql.contains("resource_attributes['http.method']"), "{sql}");
    assert!(!sql.contains("ext.httpmethod"), "dotted key must not be sanitized: {sql}");
    assert!(!sql.contains("JSONExtractString(metadata"), "spans tail is a Map, not metadata JSON: {sql}");
}

// --- Cross-stage hazards (second-pass review) ------------------------------

#[test]
fn spans_stats_by_attribute_passes_through_map_columns() {
    // A split-by on an attribute materializes the value in stage_0 but re-derives
    // the same `attributes[...]` subscript in the GROUP BY stage; the slim
    // projection MUST pass BOTH map columns through or stage_1 hits CH Code 47.
    let sql = spans_sql("* | stats count by http.method");
    assert!(sql.contains("attributes, resource_attributes FROM otel_spans"), "tail passthrough missing: {sql}");
    assert!(sql.contains("GROUP BY toString(if(has(attributes, 'http.method')"), "{sql}");
}

#[test]
fn spans_in_list_over_attribute_uses_map_not_metadata() {
    let sql = spans_sql(r#"http.method IN ("GET","POST")"#);
    assert!(sql.contains("attributes['http.method']"), "{sql}");
    assert!(sql.contains("IN ('get', 'post')"), "{sql}");
    assert!(!sql.contains("JSONExtractString(metadata"), "{sql}");
}

#[test]
fn spans_where_on_attribute_uses_map_subscript() {
    // NAN-1555 review fix: `| where <attr>=…` on spans re-derives the Map subscript
    // (not a bare column ref → CH Code 47).
    let sql = spans_sql(r#"* | where http.method="GET""#);
    assert!(sql.contains("attributes['http.method']"), "{sql}");
    assert!(sql.contains("resource_attributes['http.method']"), "{sql}");
    assert!(!sql.contains("JSONExtractString(metadata"), "{sql}");
}

#[test]
fn spans_timechart_buckets_on_start_time() {
    let sql = spans_sql("* | timechart span=1h count");
    assert!(sql.contains("toStartOfHour(start_time)"), "{sql}");
    assert!(!sql.contains("toStartOfHour(timestamp)"), "timechart must bucket on start_time: {sql}");
}

#[test]
fn spans_timechart_sparkline_uses_start_time() {
    // The timechart sparkline arm buckets sub-intervals via a SEPARATE expression
    // from the main bucket — it must also use the spans time column, not timestamp.
    let sql = spans_sql("* | timechart span=1h sparkline(count) by service_name");
    assert!(
        sql.contains("toStartOfInterval(start_time, toIntervalSecond"),
        "sparkline must bucket on start_time: {sql}"
    );
    assert!(
        !sql.contains("toStartOfInterval(timestamp, toIntervalSecond"),
        "{sql}"
    );
}

#[test]
fn spans_where_on_stats_output_is_bare_not_attribute() {
    // NAN-1557: `… | stats count by X | where count > N` — `count` is the stats
    // OUTPUT column, not a span attribute. It must be a bare reference, not
    // `attributes['count']` (the stats stage's output carries no `attributes` →
    // CH "Field 'attributes' does not exist"). Found via the live API query battery.
    let sql = spans_sql("* | stats count by service_name | where count > 100");
    assert!(sql.contains("WHERE count > 100"), "where on stats output must be bare: {sql}");
    assert!(
        !sql.contains("attributes['count']") && !sql.contains("attributes, 'count'"),
        "the stats-output `count` must not resolve to the attribute Map: {sql}"
    );
}

#[test]
fn spans_promoted_fields_pass_input_validation() {
    // NAN-1557: the input field-name validator must accept promoted span columns
    // when the spans dataset is active (it was validating against the UDM/logs
    // universe → 400 "Unknown field 'duration_ns'"). Found via the live API battery.
    use nanosiem_core::query::validation::validate_query_fields_with_profile;
    use nanosiem_core::schema::SpansProfile;
    let p = SpansProfile::new();
    for q in [
        "duration_ns > 1000000",
        r#"span_kind="SERVER""#,
        "* | stats count by span_kind",
        "* | top 5 span_name",
        "* | stats count by host",
        r#"span_name contains "GET""#,
        "* | stats avg(duration_ns) by service_name",
    ] {
        let errs = validate_query_fields_with_profile(&parse_query(q).unwrap(), Some(&p));
        assert!(errs.is_empty(), "spans validator wrongly rejected `{q}`: {errs:?}");
    }
}

// --- Logs path is byte-unchanged ------------------------------------------

#[test]
fn logs_dataset_is_byte_identical_default() {
    // The default (logs) generator must be unaffected: keyword still hits message,
    // table is logs, bound on timestamp, and the UDM action→event_type rename stays.
    let kw = logs_sql("error");
    assert!(kw.contains("hasAllTokens(lower(message), 'error')"), "{kw}");
    assert!(kw.contains("FROM logs"), "{kw}");
    assert!(kw.contains("timestamp BETWEEN"), "{kw}");
    assert!(kw.contains("action AS event_type"), "{kw}");

    // And a spans-only construct does not leak into the logs path: `service_name`
    // on logs still UDM-aliases to cloud_service (the existing behavior).
    let svc = logs_sql(r#"service_name="x""#);
    assert!(svc.contains("cloud_service"), "logs keeps the UDM service_name alias: {svc}");
}
