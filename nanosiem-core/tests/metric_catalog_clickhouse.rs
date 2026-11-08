// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4098: execute the bounded metric-catalog SQL against a real ClickHouse
//! on the production `otel_metrics_1h` DDL (migration 144). Each run uses a
//! unique service name, so it only reads rows it wrote.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test metric_catalog_clickhouse -- --ignored
//! ```
mod common_ch;

use chrono::{DateTime, Duration, Utc};
use common_ch::{statement, Ch};
use nanosiem_core::query::{metric_names_sql, METRIC_NAMES_CAP};

const ROLLUP_DDL: &str = include_str!("../../clickhouse/144_otel_metrics_rollup.sql");

async fn ensure_schema(ch: &Ch) {
    ch.run("CREATE DATABASE IF NOT EXISTS nanosiem").await;
    ch.run(&statement(ROLLUP_DDL, "CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics_1h\n"))
        .await;
}

async fn insert(ch: &Ch, service: &str, names_sql: &str, hour: DateTime<Utc>) {
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_metrics_1h \
           (metric_name, service_name, hour, value_sum, value_count, value_min, value_max, value_state) \
         SELECT name, '{service}', toStartOfHour(toDateTime64('{}', 3, 'UTC')), 1, 1, 1, 1, \
                quantilesTDigestState(0.5, 0.95, 0.99)(toFloat64(1)) \
         FROM ({names_sql}) GROUP BY name",
        common_ch::ts(hour)
    ))
    .await;
}

fn names(rows: &[serde_json::Value]) -> Vec<String> {
    rows.iter()
        .map(|r| r["metric_name"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn catalog_lists_only_names_inside_the_window() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let service = format!("nan4098-{}", uuid::Uuid::new_v4().simple());
    let now = Utc::now();
    insert(&ch, &service, "SELECT 'cpu.recent' AS name", now - Duration::minutes(5)).await;
    insert(&ch, &service, "SELECT 'disk.daily' AS name", now - Duration::hours(20)).await;
    insert(&ch, &service, "SELECT 'batch.weekly' AS name", now - Duration::days(5)).await;
    insert(&ch, &service, "SELECT 'gone.last_month' AS name", now - Duration::days(20)).await;

    let day = ch.rows(&metric_names_sql(Some(&service), now, 24, false)).await;
    assert_eq!(names(&day), vec!["cpu.recent", "disk.daily"]);
    let hour = ch.rows(&metric_names_sql(Some(&service), now, 1, false)).await;
    assert_eq!(names(&hour), vec!["cpu.recent"]);
    let week = ch.rows(&metric_names_sql(Some(&service), now, 168, false)).await;
    assert_eq!(names(&week), vec!["batch.weekly", "cpu.recent", "disk.daily"]);
    // A request past 7 days is clamped: last month's name never appears.
    let clamped = ch.rows(&metric_names_sql(Some(&service), now, 10_000, false)).await;
    assert_eq!(names(&clamped), names(&week));
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn catalog_returns_one_more_than_the_cap_so_callers_can_flag_partial() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let service = format!("nan4098-cap-{}", uuid::Uuid::new_v4().simple());
    let now = Utc::now();
    insert(
        &ch,
        &service,
        &format!("SELECT concat('m.', toString(number)) AS name FROM numbers({})", METRIC_NAMES_CAP + 50),
        now - Duration::minutes(10),
    )
    .await;
    let rows = ch.rows(&metric_names_sql(Some(&service), now, 24, false)).await;
    assert_eq!(rows.len(), METRIC_NAMES_CAP + 1);
}
