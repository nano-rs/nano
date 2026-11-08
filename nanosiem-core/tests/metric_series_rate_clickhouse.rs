// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4031: execute the generated metrics-v2 `rate` SQL against a real
//! ClickHouse and check per-series correctness. Uses the production
//! `otel_metrics` DDL (migrations 140 + 158) and a unique metric name per run,
//! so it only appends rows that no other query reads.
//!
//! ```text
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test metric_series_rate_clickhouse -- --ignored
//! ```

use chrono::{DateTime, Duration, Utc};
use nanosiem_core::query::{
    metric_scalar_sql, metric_timeseries_v2_sql, MetricAgg, MetricQuery, MetricTagFilter,
    TimeRange,
};

const OTEL_METRICS_DDL: &str = include_str!("../../clickhouse/140_otel_metrics.sql");

struct Ch {
    http: reqwest::Client,
    url: String,
    user: Option<String>,
    password: Option<String>,
}

impl Ch {
    fn from_env() -> Self {
        Self {
            http: reqwest::Client::new(),
            url: std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
                .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse"),
            user: std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER").ok(),
            password: std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD").ok(),
        }
    }

    async fn run(&self, sql: &str) -> String {
        let mut req = self.http.post(&self.url).body(sql.to_owned());
        if let Some(user) = &self.user {
            req = req.header("X-ClickHouse-User", user);
        }
        if let Some(password) = &self.password {
            req = req.header("X-ClickHouse-Key", password);
        }
        let resp = req.send().await.expect("ClickHouse reachable");
        let status = resp.status();
        let body = resp.text().await.unwrap();
        assert!(status.is_success(), "{status}: {body}\n--- SQL ---\n{sql}");
        body
    }

    async fn rows(&self, sql: &str) -> Vec<serde_json::Value> {
        self.run(&format!("{sql}\nFORMAT JSONEachRow"))
            .await
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

/// The statement starting at `head`, comment lines stripped (comments may
/// themselves contain `;`, so drop them before looking for the terminator).
fn statement(sql: &str, head: &str) -> String {
    let start = sql.find(head).unwrap_or_else(|| panic!("{head} not in DDL"));
    sql[start..]
        .lines()
        .filter(|l| !l.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .next()
        .unwrap()
        .lines()
        .collect::<Vec<_>>()
        .join("\n")
}

async fn ensure_schema(ch: &Ch) {
    ch.run("CREATE DATABASE IF NOT EXISTS nanosiem").await;
    ch.run(&statement(
        OTEL_METRICS_DDL,
        "CREATE TABLE IF NOT EXISTS nanosiem.otel_metrics\n",
    ))
    .await;
    ch.run(
        "ALTER TABLE nanosiem.otel_metrics \
         ADD COLUMN IF NOT EXISTS aggregation_temporality Int8 DEFAULT 0",
    )
    .await;
}

fn ts(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
}

/// One cumulative counter point.
fn point(
    metric: &str,
    at: DateTime<Utc>,
    value: f64,
    env: &str,
    replica: &str,
    status: &str,
    reorder: bool,
) -> String {
    let attrs = if reorder {
        format!("map('status','{status}','device','0')")
    } else {
        format!("map('device','0','status','{status}')")
    };
    format!(
        "('{metric}','sum','api',toDateTime64('{}',9,'UTC'),{value},2,{attrs},\
         map('deployment.environment','{env}','service.instance.id','{replica}'))",
        ts(at)
    )
}

fn scalar(rows: &[serde_json::Value]) -> Vec<(String, Option<f64>)> {
    rows.iter()
        .map(|r| {
            (
                r["series_key"].as_str().unwrap().to_owned(),
                r["v"].as_f64(),
            )
        })
        .collect()
}

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn counter_rates_are_partitioned_per_series() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let metric = format!("nan4031_requests_total_{}", uuid::Uuid::new_v4().simple());
    let start = Utc::now() - Duration::minutes(30);
    let mut values = Vec::new();
    for tick in 0..=10i64 {
        let at = start + Duration::seconds(60 * tick);
        let t = tick as f64;
        // prod: two IDLE replicas at very different absolute totals — each
        // series alone is flat, so the true rate is 0. Interleaving them in one
        // group (the pre-fix SQL) reads every replica switch as a positive delta.
        values.push(point(&metric, at, 100.0, "prod", "r1", "200", false));
        values.push(point(&metric, at, 5000.0, "prod", "r2", "200", false));
        // stage: two ACTIVE replicas at 1/s and 2/s → 3/s total; replica r4
        // re-orders its attribute map every other tick (same canonical series).
        values.push(point(&metric, at, 1000.0 + 60.0 * t, "stage", "r3", "200", false));
        values.push(point(&metric, at, 60.0 * 2.0 * t, "stage", "r4", "200", tick % 2 == 1));
    }
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_metrics \
         (metric_name, metric_type, service_name, timestamp, value, aggregation_temporality, \
          attributes, resource_attributes) VALUES {}",
        values.join(",")
    ))
    .await;

    let range = TimeRange::new(start - Duration::minutes(1), Utc::now());
    let grouped = MetricQuery {
        metric_name: &metric,
        service_name: Some("api"),
        agg: MetricAgg::Rate,
        group_by: Some("deployment.environment"),
        filters: &[],
        step_secs: 3600,
    };
    let got = scalar(&ch.rows(&metric_scalar_sql(&grouped, &range, false)).await);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0].0, "prod");
    assert!(got[0].1.unwrap().abs() < 1e-9, "idle replicas must rate 0: {got:?}");
    assert_eq!(got[1].0, "stage");
    assert!((got[1].1.unwrap() - 3.0).abs() < 1e-9, "1/s + 2/s: {got:?}");

    // Ungrouped: still one scalar row, the sum of the per-series rates.
    let fleet = MetricQuery {
        group_by: None,
        ..grouped.clone()
    };
    let got = ch.rows(&metric_scalar_sql(&fleet, &range, false)).await;
    assert_eq!(got.len(), 1, "{got:?}");
    assert!((got[0]["v"].as_f64().unwrap() - 3.0).abs() < 1e-9, "{got:?}");
    assert_eq!(got[0]["row_count"].as_f64().unwrap() as i64, 44);

    // Timeseries panel, one sample per series per 60 s bucket (f9398dd36 on
    // ClickHouse): each bucket used to hold a single point per series and read
    // 0. The increment now lands in the later point's bucket (rate =
    // increase / step); the first bucket has no previous sample → NULL.
    let per_minute = MetricQuery {
        step_secs: 60,
        ..grouped.clone()
    };
    let got = ch
        .rows(&metric_timeseries_v2_sql(&per_minute, &range, false))
        .await;
    for (env, rate) in [("stage", 3.0), ("prod", 0.0)] {
        let buckets: Vec<Option<f64>> = got
            .iter()
            .filter(|r| r["series_key"] == env)
            .map(|r| r["v"].as_f64())
            .collect();
        assert_eq!(buckets.len(), 11, "{env}: {got:?}");
        assert_eq!(buckets[0], None, "{env}: first bucket has no previous sample");
        for v in &buckets[1..] {
            assert!((v.unwrap() - rate).abs() < 1e-9, "{env}: {buckets:?}");
        }
    }

    // Filtered on a label no series carries → no rows (the evaluator's
    // NAN-4031 fill turns that into 0.0 using the base count query).
    let filters = [MetricTagFilter {
        key: "status".into(),
        value: "500".into(),
    }];
    let errors = MetricQuery {
        filters: &filters,
        ..grouped.clone()
    };
    assert!(ch
        .rows(&metric_scalar_sql(&errors, &range, false))
        .await
        .is_empty());
    let base = MetricQuery {
        agg: MetricAgg::Count,
        filters: &[],
        ..grouped
    };
    let counts = scalar(&ch.rows(&metric_scalar_sql(&base, &range, false)).await);
    let filled = nanosiem_core::observability::eval::fill_missing_counter_rates(
        vec![],
        vec![],
        counts,
    );
    assert_eq!(
        filled,
        vec![("prod".into(), Some(0.0)), ("stage".into(), Some(0.0))]
    );
}

/// Insert rows and return the metric name (unique per call).
async fn seed(ch: &Ch, name: &str, points: &[(i64, f64, &str)], start: DateTime<Utc>) -> String {
    let metric = format!("{name}_{}", uuid::Uuid::new_v4().simple());
    let values: Vec<String> = points
        .iter()
        .map(|(secs, value, replica)| {
            point(&metric, start + Duration::seconds(*secs), *value, "prod", replica, "200", false)
        })
        .collect();
    ch.run(&format!(
        "INSERT INTO nanosiem.otel_metrics \
         (metric_name, metric_type, service_name, timestamp, value, aggregation_temporality, \
          attributes, resource_attributes) VALUES {}",
        values.join(",")
    ))
    .await;
    metric
}

fn rate_query(metric: &str, step_secs: u64) -> MetricQuery<'_> {
    MetricQuery {
        metric_name: metric,
        service_name: Some("api"),
        agg: MetricAgg::Rate,
        group_by: Some("deployment.environment"),
        filters: &[],
        step_secs,
    }
}

/// Codex P1: a series with one sample has no rate. It must read as no-data
/// (NULL), never a healthy 0 that would close an open incident — on the
/// scalar (monitor) path and in every timeseries bucket.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn single_sample_series_rate_is_null_not_zero() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let start = Utc::now() - Duration::minutes(10);
    let range = TimeRange::new(start - Duration::minutes(1), Utc::now());
    // Two replicas, one sample each: the whole group is undersampled.
    let metric = seed(&ch, "nan4031_single", &[(0, 500.0, "r1"), (30, 900.0, "r2")], start).await;
    let rows = ch.rows(&metric_scalar_sql(&rate_query(&metric, 60), &range, false)).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0]["v"].is_null(), "undersampled group must be NULL: {rows:?}");
    assert_eq!(rows[0]["row_count"].as_f64().unwrap() as i64, 2);
    let buckets = ch
        .rows(&metric_timeseries_v2_sql(&rate_query(&metric, 60), &range, false))
        .await;
    assert!(!buckets.is_empty());
    assert!(buckets.iter().all(|r| r["v"].is_null()), "{buckets:?}");

    // One sampled replica plus one single-sample replica: the rate is the
    // sampled replica's own (the undersampled one contributes nothing).
    let metric = seed(
        &ch,
        "nan4031_mixed",
        &[(0, 0.0, "r1"), (60, 120.0, "r1"), (30, 7.0, "r2")],
        start,
    )
    .await;
    let rows = ch.rows(&metric_scalar_sql(&rate_query(&metric, 60), &range, false)).await;
    assert!((rows[0]["v"].as_f64().unwrap() - 2.0).abs() < 1e-9, "{rows:?}");
}

/// Codex P1: a decrease is a counter reset; the post-reset value is the
/// increment. 100 -> 150 -> 5 -> 20 increased by 50 + 5 + 15 = 70.
#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn counter_reset_adds_the_post_reset_value() {
    let ch = Ch::from_env();
    ensure_schema(&ch).await;
    let start = Utc::now() - Duration::minutes(10);
    let range = TimeRange::new(start - Duration::minutes(1), Utc::now());
    let metric = seed(
        &ch,
        "nan4031_reset",
        &[(0, 100.0, "r1"), (10, 150.0, "r1"), (20, 5.0, "r1"), (30, 20.0, "r1"), (40, 20.0, "r1")],
        start,
    )
    .await;
    // Rate: 70 over 40 observed seconds (the trailing unchanged sample adds 0).
    let rows = ch.rows(&metric_scalar_sql(&rate_query(&metric, 60), &range, false)).await;
    assert!((rows[0]["v"].as_f64().unwrap() - 70.0 / 40.0).abs() < 1e-9, "{rows:?}");
    // Sum (window increase) uses the same reset rule.
    let sum = MetricQuery {
        agg: MetricAgg::Sum,
        ..rate_query(&metric, 60)
    };
    let rows = ch.rows(&metric_scalar_sql(&sum, &range, false)).await;
    assert!((rows[0]["v"].as_f64().unwrap() - 70.0).abs() < 1e-9, "{rows:?}");
    // Timeseries: one bucket covering everything carries the same increase.
    let buckets = ch
        .rows(&metric_timeseries_v2_sql(&rate_query(&metric, 3600), &range, false))
        .await;
    let total: f64 = buckets.iter().filter_map(|r| r["v"].as_f64()).sum::<f64>() * 3600.0;
    assert!((total - 70.0).abs() < 1e-6, "{buckets:?}");
}
