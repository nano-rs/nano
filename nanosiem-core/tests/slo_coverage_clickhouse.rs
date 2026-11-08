// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3894: execute the generated per-service SLO coverage probe (and the
//! availability compute it accompanies) against a real ClickHouse, on the
//! production `otel_service_red_1m` / `otel_metrics_1h` DDL (migrations 143,
//! 144). Every scenario uses its own service names, so the suite only reads
//! rows it wrote (no truncation).
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test slo_coverage_clickhouse -- --ignored
//! ```
mod common_ch;

use chrono::{DateTime, Duration, DurationRound, Utc};
use common_ch::{statement, Ch};
use nanosiem_core::query::{
    slo_compute_sql, slo_coverage_complete, slo_coverage_sql, SliKind, TimeRange,
    OTEL_SPAN_TTL_SECS, SLO_COVERAGE_MAX_GAP_SECS,
};

const RED_DDL: &str = include_str!("../../clickhouse/143_otel_service_red_rollup.sql");
const ROLLUP_DDL: &str = include_str!("../../clickhouse/144_otel_metrics_rollup.sql");

fn num(v: &serde_json::Value) -> f64 {
    v.as_str()
        .map_or_else(|| v.as_f64().unwrap(), |s| s.parse().unwrap())
}

async fn schema(ch: &Ch) {
    ch.run("CREATE DATABASE IF NOT EXISTS nanosiem").await;
    ch.run(&statement(RED_DDL, "CREATE TABLE IF NOT EXISTS nanosiem.otel_service_red_1m\n"))
        .await;
    ch.run(&statement(ROLLUP_DDL, "CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics_1h\n"))
        .await;
}

fn unique(name: &str) -> String {
    format!("{name}-{}", &uuid::Uuid::new_v4().simple().to_string()[..10])
}

/// The verdict exactly as `observability_slo_compute_with_coverage` forms it.
async fn covered(ch: &Ch, service: &str, range: &TimeRange) -> bool {
    let rows = ch.rows(&slo_coverage_sql(service, range, false)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let reaches_ttl =
        (range.end - range.start).num_seconds() + SLO_COVERAGE_MAX_GAP_SECS >= OTEL_SPAN_TTL_SECS;
    slo_coverage_complete(
        num(&rows[0]["samples"]) as u64,
        num(&rows[0]["first_seen"]) as i64,
        num(&rows[0]["max_gap_secs"]) as i64,
        range.start,
        reaches_ttl,
    )
}

/// One request minute for `service` (RED rollup row).
async fn span_minute(ch: &Ch, service: &str, at: DateTime<Utc>, requests: u64, errors: u64) {
    let minute = at.duration_trunc(Duration::minutes(1)).unwrap();
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_service_red_1m \
           (service_name, minute, request_count, error_count, duration_state) \
         SELECT '{service}', toDateTime('{}', 'UTC'), {requests}, {errors}, \
                quantilesTDigestState(0.5, 0.95, 0.99)(toFloat64(10))",
        minute.format("%Y-%m-%d %H:%M:%S")
    ))
    .await;
}

/// Request minutes every `step` from `from` to `to` in one insert.
async fn span_series(ch: &Ch, service: &str, from: DateTime<Utc>, to: DateTime<Utc>, step: Duration) {
    let from = from.duration_trunc(Duration::minutes(1)).unwrap();
    let n = ((to - from).num_seconds() / step.num_seconds()).max(0) + 1;
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_service_red_1m \
           (service_name, minute, request_count, error_count, duration_state) \
         SELECT '{service}', toDateTime('{}', 'UTC') + number * {}, 10, 0, \
                quantilesTDigestState(0.5, 0.95, 0.99)(toFloat64(10)) \
         FROM numbers({n}) GROUP BY number",
        from.format("%Y-%m-%d %H:%M:%S"),
        step.num_seconds()
    ))
    .await;
}

/// Hourly metric exports for `service` (SDK runtime metrics with no traffic).
async fn metric_hours(ch: &Ch, service: &str, from: DateTime<Utc>, to: DateTime<Utc>) {
    let from = from.duration_trunc(Duration::hours(1)).unwrap();
    let n = (to - from).num_hours().max(0) + 1;
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_metrics_1h \
           (metric_name, service_name, hour, value_sum, value_count, value_min, value_max, value_state) \
         SELECT 'process.runtime.memory', '{service}', \
                toDateTime64('{}', 3, 'UTC') + toIntervalHour(number), 1, 1, 1, 1, \
                quantilesTDigestState(0.5, 0.95, 0.99)(toFloat64(1)) \
         FROM numbers({n}) GROUP BY number",
        from.format("%Y-%m-%d %H:%M:%S")
    ))
    .await;
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn broken_target_service_is_partial_even_when_another_service_is_healthy() {
    let ch = Ch::from_env();
    schema(&ch).await;
    let now = Utc::now();
    let week = TimeRange::new(now - Duration::days(7), now);
    let checkout = unique("checkout");
    let payments = unique("payments");
    // payments: continuous telemetry across and before the window.
    span_series(&ch, &payments, week.start - Duration::hours(2), now, Duration::minutes(30)).await;
    // checkout: one request just before the window start, then nothing for
    // six days (broken exporter), then its final day.
    span_minute(&ch, &checkout, week.start - Duration::minutes(5), 10, 0).await;
    span_series(&ch, &checkout, now - Duration::days(1), now, Duration::minutes(30)).await;

    assert!(covered(&ch, &payments, &week).await);
    assert!(!covered(&ch, &checkout, &week).await, "a six-day gap is not full coverage");
    // A service that only exists inside the window is not covered either.
    let fresh = unique("fresh");
    span_series(&ch, &fresh, now - Duration::days(2), now, Duration::minutes(30)).await;
    assert!(!covered(&ch, &fresh, &week).await, "first seen inside the window");
    // A service with no telemetry at all.
    assert!(!covered(&ch, &unique("absent"), &week).await);
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn low_volume_service_fully_retained_is_covered() {
    let ch = Ch::from_env();
    schema(&ch).await;
    let now = Utc::now();
    let week = TimeRange::new(now - Duration::days(7), now);

    // One request every 3 hours, no other service anywhere near the window
    // start: covered (gaps stay under the 6 h tolerance).
    let sparse = unique("sparse");
    span_series(&ch, &sparse, week.start - Duration::hours(3), now, Duration::hours(3)).await;
    assert!(covered(&ch, &sparse, &week).await);

    // Requests only twice a day, but the SDK exports metrics hourly: the
    // metric exports prove delivery, so the window is covered.
    let quiet = unique("quiet");
    span_series(&ch, &quiet, week.start - Duration::hours(1), now, Duration::hours(12)).await;
    assert!(!covered(&ch, &quiet, &week).await, "12 h request gaps alone are not coverage");
    metric_hours(&ch, &quiet, week.start - Duration::hours(2), now).await;
    assert!(covered(&ch, &quiet, &week).await);
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn thirty_day_window_on_thirty_day_ttl_is_covered_by_rows_at_its_start() {
    let ch = Ch::from_env();
    schema(&ch).await;
    // Rows before a 30-day window's start are being TTL-reaped, so activity
    // within one tolerance after the start stands in for "at or before".
    let now = Utc::now();
    let month = TimeRange::new(now - Duration::days(30), now);
    let svc = unique("monthly");
    span_series(&ch, &svc, month.start + Duration::minutes(10), now, Duration::hours(4)).await;
    span_minute(&ch, &svc, month.start + Duration::minutes(10), 1000, 20).await;
    assert!(covered(&ch, &svc, &month).await);

    // The compute reads the same rollup.
    let rows = ch
        .rows(&slo_compute_sql(&svc, SliKind::Availability, None, &month, false))
        .await;
    assert!(num(&rows[0]["total"]) >= 1000.0);
    assert!(num(&rows[0]["total"]) - num(&rows[0]["good"]) >= 20.0);
}
