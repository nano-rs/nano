// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! NAN-4944: the analyst-facing timechart completion path must choose its
//! bounded rank/select/OTHER plan before materializing a large bucket×series
//! probe. This live-ClickHouse test creates 20k series across 40 buckets
//! (800k bucket-series groups) under a 64 MiB query cap. It then proves the
//! response succeeds, the unsafe probe never appears in `system.query_log`,
//! and prints each bounded plan's `read_bytes` for review evidence. It also
//! covers a two-field split whose leading field has only two values while the
//! full `(user, src_ip)` tuple has 20k values.
//!
//! Run:
//! `cargo test -p nanosiem-core --test timechart_high_cardinality_integration -- --ignored --nocapture`

use chrono::{Duration, Utc};
use nanosiem_core::search::{AdmissionConfig, AdmissionController, QueryPriority};
use nanosiem_core::{DualPool, DualPoolConfig, SearchRequest, SearchService, TimeRangeInput};
use serde::Deserialize;
use std::sync::Arc;

const SERIES: u64 = 20_000;
const BUCKETS: u64 = 40;
const MEMORY_LIMIT: &str = "67108864";

#[derive(Debug, Deserialize, clickhouse::Row)]
struct QueryStat {
    query: String,
    read_rows: u64,
    read_bytes: u64,
    result_rows: u64,
    memory_usage: u64,
}

struct EnvRestore(Option<std::ffi::OsString>);

impl Drop for EnvRestore {
    fn drop(&mut self) {
        if let Some(value) = self.0.take() {
            std::env::set_var("CLICKHOUSE_QUERY_MAX_MEMORY_BYTES", value);
        } else {
            std::env::remove_var("CLICKHOUSE_QUERY_MAX_MEMORY_BYTES");
        }
    }
}

#[tokio::test]
#[ignore = "needs live PostgreSQL + ClickHouse"]
async fn high_cardinality_timechart_returns_via_preselected_bounded_plans() {
    if std::env::var("SKIP_DB_TESTS").is_ok() {
        eprintln!("Skipping (SKIP_DB_TESTS set)");
        return;
    }

    let restore = EnvRestore(std::env::var_os("CLICKHOUSE_QUERY_MAX_MEMORY_BYTES"));
    std::env::set_var("CLICKHOUSE_QUERY_MAX_MEMORY_BYTES", MEMORY_LIMIT);
    let config = match DualPoolConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Skipping: database test environment is incomplete ({error})");
            return;
        }
    };
    let pool = match DualPool::new(&config).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("Skipping: databases not reachable ({error})");
            return;
        }
    };
    drop(restore);
    assert_eq!(
        pool.query_memory_ceiling_bytes(),
        Some(MEMORY_LIMIT.parse().unwrap())
    );

    let run_tag = format!("nan4944hc{:x}", Utc::now().timestamp_micros());
    let request_id = format!("{run_tag}-query");
    let anchor_seconds = (Utc::now() - Duration::hours(6))
        .timestamp()
        .div_euclid(300)
        * 300;
    let start = chrono::DateTime::<Utc>::from_timestamp(anchor_seconds, 0).unwrap();
    let end = start + Duration::seconds((BUCKETS * 300) as i64);
    let insert = format!(
        "INSERT INTO nanosiem.logs (timestamp, message, source_type, user, src_ip) \
         SELECT toDateTime64({anchor_seconds}, 6) + toIntervalSecond(intDiv(number, {SERIES}) * 300 + number % 240), \
                'nan4944 high-cardinality probe', '{run_tag}', concat('low-', toString(number % 2)), \
                concat('series-', toString(number % {SERIES})) \
         FROM numbers({})",
        SERIES * BUCKETS
    );
    pool.clickhouse_admin()
        .query(&insert)
        .execute()
        .await
        .expect("insert high-cardinality fixture");

    let mut service = SearchService::with_dual_pool(&pool);
    service.set_admission_controller(Arc::new(AdmissionController::new(AdmissionConfig {
        global_adhoc_limit: 4,
        per_user_limit: 4,
        max_queue_depth: 8,
        queue_timeout_ms: 30_000,
    })));
    let request: SearchRequest = serde_json::from_value(serde_json::json!({
        "query": format!("source_type={run_tag} | timechart span=5m limit=10 count by src_ip"),
        "time_range": TimeRangeInput::new(start, end),
        "limit": 1000,
        "skip_histogram": true,
        "skip_field_stats": true,
        "request_id": request_id,
    }))
    .unwrap();
    let response = service
        .search_with_admission(
            request,
            uuid::Uuid::now_v7(),
            QueryPriority::Interactive,
            &nanosiem_core::auth::ScopeSet::unrestricted(),
        )
        .await
        .expect("bounded timechart must fit the low memory limit");

    assert_eq!(response.results.len(), BUCKETS as usize);
    for row in &response.results {
        let total = row
            .as_object()
            .unwrap()
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "time_bucket" | "_timechart"))
            .map(|(_, value)| value.as_u64().expect("count series are numeric"))
            .sum::<u64>();
        assert_eq!(
            total, SERIES,
            "selected series + OTHER preserve each bucket total"
        );
    }

    pool.clickhouse_admin()
        .query("SYSTEM FLUSH LOGS")
        .execute()
        .await
        .expect("flush query log");
    let stats = pool
        .clickhouse_admin()
        .query(
            "SELECT query, read_rows, read_bytes, result_rows, memory_usage \
             FROM system.query_log \
             WHERE type = 'QueryFinish' AND query_id = ? \
             ORDER BY event_time_microseconds",
        )
        .bind(&request_id)
        .fetch_all::<QueryStat>()
        .await
        .expect("query-log plan evidence");

    assert_eq!(
        stats.len(),
        4,
        "estimate + rank + selected + OTHER, no bucket×series probe: {stats:#?}"
    );
    assert!(
        stats[0].query.contains("uniqCombined64"),
        "first plan is the cheap cardinality estimate"
    );
    assert!(
        stats[1].query.contains("__nano_timechart_rank"),
        "ranking precedes bucket scans"
    );
    assert!(
        stats.iter().all(|stat| stat.result_rows <= SERIES),
        "every plan has bounded output: {stats:#?}"
    );
    for (plan, stat) in ["estimate", "rank", "selected", "OTHER"]
        .into_iter()
        .zip(&stats)
    {
        eprintln!(
            "timechart plan={plan} read_rows={} read_bytes={} result_rows={} memory_usage={}",
            stat.read_rows, stat.read_bytes, stat.result_rows, stat.memory_usage
        );
    }

    let tuple_request_id = format!("{run_tag}-tuple-query");
    let tuple_request: SearchRequest = serde_json::from_value(serde_json::json!({
        "query": format!(
            "source_type={run_tag} | timechart span=5m limit=10 count by user, src_ip"
        ),
        "time_range": TimeRangeInput::new(start, end),
        "limit": 1000,
        "skip_histogram": true,
        "skip_field_stats": true,
        "request_id": tuple_request_id,
    }))
    .unwrap();
    let tuple_response = service
        .search_with_admission(
            tuple_request,
            uuid::Uuid::now_v7(),
            QueryPriority::Interactive,
            &nanosiem_core::auth::ScopeSet::unrestricted(),
        )
        .await
        .expect("multi-field timechart must start with the bounded plan");

    assert_eq!(tuple_response.results.len(), BUCKETS as usize);
    for row in &tuple_response.results {
        let total = row
            .as_object()
            .unwrap()
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), "time_bucket" | "_timechart"))
            .map(|(_, value)| value.as_u64().expect("count series are numeric"))
            .sum::<u64>();
        assert_eq!(
            total, SERIES,
            "selected tuple series + OTHER preserve each bucket total"
        );
    }

    pool.clickhouse_admin()
        .query("SYSTEM FLUSH LOGS")
        .execute()
        .await
        .expect("flush tuple query log");
    let tuple_stats = pool
        .clickhouse_admin()
        .query(
            "SELECT query, read_rows, read_bytes, result_rows, memory_usage \
             FROM system.query_log \
             WHERE type = 'QueryFinish' AND query_id = ? \
             ORDER BY event_time_microseconds",
        )
        .bind(&tuple_request_id)
        .fetch_all::<QueryStat>()
        .await
        .expect("tuple query-log plan evidence");

    assert_eq!(
        tuple_stats.len(),
        3,
        "rank + selected + OTHER, with no estimator or bucket×tuple probe: {tuple_stats:#?}"
    );
    assert!(
        tuple_stats[0].query.contains("__nano_timechart_rank"),
        "multi-field plan ranks before bucket scans"
    );
    assert!(
        tuple_stats
            .iter()
            .all(|stat| !stat.query.contains("uniqCombined64")),
        "multi-field splits conservatively bypass the scalar estimator"
    );
    for (plan, stat) in ["tuple-rank", "tuple-selected", "tuple-OTHER"]
        .into_iter()
        .zip(&tuple_stats)
    {
        eprintln!(
            "timechart plan={plan} read_rows={} read_bytes={} result_rows={} memory_usage={}",
            stat.read_rows, stat.read_bytes, stat.result_rows, stat.memory_usage
        );
    }

    pool.clickhouse_admin()
        .query(&format!(
            "DELETE FROM nanosiem.logs WHERE source_type = '{run_tag}'"
        ))
        .execute()
        .await
        .expect("remove high-cardinality fixture");
    pool.close().await;
}
