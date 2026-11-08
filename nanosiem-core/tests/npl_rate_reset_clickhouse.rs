// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4902 lane I: nPL `| stats rate(value)` on the metrics dataset applies
//! the Prometheus reset rule — a decrease means the counter restarted from
//! zero, so the post-reset value is the increment (`100 -> 150 -> 5 -> 20` is
//! `50 + 5 + 15 = 70`, not the old `50 + 0 + 15 = 65`). Executes the generated
//! SQL on a real ClickHouse against the production `otel_metrics` DDL, with a
//! unique metric name per run.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test npl_rate_reset_clickhouse -- --ignored
//! ```

use chrono::{Duration, Utc};
use nanosiem_core::query::{parse_query, ClickHouseSqlGenerator, Dataset, TimeRange};

const OTEL_METRICS_DDL: &str = include_str!("../../clickhouse/140_otel_metrics.sql");

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    // Shared transport: pins LZ4 (raw clients fail against CH 26.9+).
    let mut client = nanosiem_core::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

/// The DDL statement starting at `head`, comment lines stripped.
fn statement(head: &str) -> String {
    let start = OTEL_METRICS_DDL.find(head).unwrap_or_else(|| panic!("{head} not in DDL"));
    OTEL_METRICS_DDL[start..]
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// The single `rate(...) as r` column; Nullable since NAN-4291 (#8595).
#[derive(clickhouse::Row, serde::Deserialize)]
struct RateRow {
    r: Option<f64>,
}

async fn rate(ch: &clickhouse::Client, npl: &str, range: &TimeRange) -> f64 {
    let sql = ClickHouseSqlGenerator::new()
        .with_dataset(Dataset::Metrics)
        .generate(&parse_query(npl).unwrap(), range)
        .unwrap();
    assert!(!sql.contains("if(d > 0, d, 0)"), "pre-fix reset rule still emitted:\n{sql}");
    // The metrics generator targets the unqualified `otel_metrics`; production
    // clients run with database `nanosiem`.
    ch.clone()
        .with_database("nanosiem")
        .query(&sql)
        // NAN-4291 (#8595): an ungrouped aggregate is NULL over an empty
        // window, so the column is Nullable(Float64). This window is never
        // empty, so the rate must be present.
        .fetch_one::<RateRow>()
        .await
        .unwrap_or_else(|e| panic!("{e}\n--- SQL ---\n{sql}"))
        .r
        .unwrap_or_else(|| panic!("rate over a non-empty window must not be NULL\n--- SQL ---\n{sql}"))
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn npl_rate_adds_the_post_reset_value() {
    let ch = ch();
    ch.query("CREATE DATABASE IF NOT EXISTS nanosiem").execute().await.unwrap();
    ch.query(&statement("CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics\n"))
        .execute()
        .await
        .unwrap();
    ch.query(
        "ALTER TABLE nanosiem.otel_metrics \
         ADD COLUMN IF NOT EXISTS aggregation_temporality Int8 DEFAULT 0",
    )
    .execute()
    .await
    .unwrap();

    let metric = format!("nan4902_rate_reset_{}", uuid::Uuid::new_v4().simple());
    let start = Utc::now() - Duration::minutes(10);
    // 100 -> 150 -> 5 (restart) -> 20, 10 s apart: increase 70 over 30 s.
    let rows: Vec<String> = [100.0, 150.0, 5.0, 20.0]
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let at = start + Duration::seconds(10 * i as i64);
            format!(
                "('{metric}','sum','api',toDateTime64('{}',9,'UTC'),{v},2)",
                at.format("%Y-%m-%d %H:%M:%S%.6f")
            )
        })
        .collect();
    ch.query(&format!(
        "INSERT INTO nanosiem.otel_metrics \
         (metric_name, metric_type, service_name, timestamp, value, aggregation_temporality) \
         VALUES {}",
        rows.join(",")
    ))
    .execute()
    .await
    .unwrap();

    let range = TimeRange::new(start - Duration::minutes(1), Utc::now());
    let got = rate(&ch, &format!(r#"metric_name="{metric}" | stats rate(value) as r"#), &range).await;
    assert!((got - 70.0 / 30.0).abs() < 1e-9, "rate = 70 / 30 s, got {got}");

    // A monotonic counter is unchanged: (last - first) / secs.
    let mono = format!("{metric}_mono");
    let rows: Vec<String> = [10.0, 40.0, 40.0, 70.0]
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let at = start + Duration::seconds(10 * i as i64);
            format!(
                "('{mono}','sum','api',toDateTime64('{}',9,'UTC'),{v},2)",
                at.format("%Y-%m-%d %H:%M:%S%.6f")
            )
        })
        .collect();
    ch.query(&format!(
        "INSERT INTO nanosiem.otel_metrics \
         (metric_name, metric_type, service_name, timestamp, value, aggregation_temporality) \
         VALUES {}",
        rows.join(",")
    ))
    .execute()
    .await
    .unwrap();
    let got = rate(&ch, &format!(r#"metric_name="{mono}" | stats rate(value) as r"#), &range).await;
    assert!((got - 2.0).abs() < 1e-9, "monotonic rate = 60 / 30 s, got {got}");
}
