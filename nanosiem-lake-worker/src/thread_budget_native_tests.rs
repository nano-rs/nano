// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4174, native: the thread budget as chDB sees it. Each statement
//! reports the `max_threads` / `max_parsing_threads` chDB actually ran it
//! with, through the real executor (and the real lane router), while other
//! statements hold their grants.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=...
//! cargo test -p nanosiem-lake-worker --lib thread_budget::native -- --ignored --nocapture --test-threads=1
//! ```

use super::{Priority, ThreadBudget};
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::planner::NativeQueryPlan;
use std::sync::Arc;
use std::time::Duration;

const POOL: u64 = 6;

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    runtime
}

fn pool(runtime: &NativeChdb, lanes: usize, name: &str, budget: &Arc<ThreadBudget>) -> NativeExecutor {
    NativeExecutor::start_with_server_memory_limit(runtime.clone(), lanes, name, ExecutorMode::ReadOnly, Some(3 << 30))
        .unwrap()
        .with_thread_budget(budget.clone())
}

/// A statement that reports its effective thread settings after `sleep_s`,
/// planned at 8 threads (more than the pool).
fn probe(sleep_s: f64) -> NativeQueryPlan {
    NativeQueryPlan {
        query_sha256: String::new(),
        sql: format!(
            "SELECT toUInt64(getSetting('max_threads')) AS threads, toUInt64(getSetting('max_parsing_threads')) AS parsing, \
             sleep({sleep_s}) AS slept SETTINGS max_threads=8, max_execution_time=30"
        ),
        params: vec![],
        budget: crate::planner::QueryBudget { candidate_objects: 1, estimated_scan_bytes: 0, max_query_bytes: u64::MAX },
        native_event_rows: false,
        temporary_aliases: Default::default(),
        schema_defaults: vec![],
        reader: Default::default(),
    }
}

/// `(threads, parsing threads)` chDB ran `plan` with.
async fn threads_of(executor: &NativeExecutor, plan: NativeQueryPlan) -> (u64, u64) {
    let output = executor.execute(plan).await.unwrap();
    parse(&output.data)
}

fn parse(data: &[u8]) -> (u64, u64) {
    let row: serde_json::Value = serde_json::from_slice(data.split(|b| *b == b'\n').next().unwrap()).unwrap();
    let number = |name: &str| row[name].as_u64().or_else(|| row[name].as_str().and_then(|v| v.parse().ok())).unwrap();
    (number("threads"), number("parsing"))
}

async fn as_request<T>(request_id: &str, work: impl std::future::Future<Output = T>) -> T {
    crate::query_timing::measure(request_id, async { Ok::<_, ()>(work.await) }).await.unwrap()
}

/// Wait until `budget` holds `(interactive, companion, background)` grants.
async fn until_running(budget: &ThreadBudget, expected: (u64, u64, u64)) {
    for _ in 0..500 {
        if budget.running() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("budget never reached {expected:?}: {:?}", budget.running());
}

/// Fair sharing: a lone interactive statement runs on the whole pool (not
/// the old fixed 4); one started beside it gets half, a third a third; and
/// once they end the next lone statement has the whole pool again. Every
/// grant also bounds chDB's Parquet parsing pool.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn interactive_statements_share_the_pool_fairly() {
    let budget = ThreadBudget::new(POOL);
    let executor = pool(&runtime(), 4, "parts", &budget);
    assert_eq!(as_request("user-a", threads_of(&executor, probe(0.0))).await, (POOL, POOL));

    let (first_executor, second_executor) = (executor.clone(), executor.clone());
    let first = tokio::spawn(async move { as_request("user-a", threads_of(&first_executor, probe(2.0))).await });
    until_running(&budget, (1, 0, 0)).await;
    let second = tokio::spawn(async move { as_request("user-b", threads_of(&second_executor, probe(1.5))).await });
    until_running(&budget, (2, 0, 0)).await;
    let third = as_request("user-c", threads_of(&executor, probe(0.0))).await;
    assert_eq!(third, (POOL / 3, POOL / 3), "three running: a third each");
    assert_eq!(second.await.unwrap(), (POOL / 2, POOL / 2), "beside one other: half");
    assert_eq!(first.await.unwrap(), (POOL, POOL), "alone when it started");
    until_running(&budget, (0, 0, 0)).await;
    assert_eq!(as_request("user-a", threads_of(&executor, probe(0.0))).await, (POOL, POOL));
    // A histogram companion takes at most two, beside its own primary too.
    assert_eq!(as_request("user-a-hist", threads_of(&executor, probe(0.0))).await, (2, 2));
}

/// Priority: background work (outside any request: a durable bare-* or
/// retro job, a partial build; or a `detect-` request) takes half the pool
/// on an idle process, never shrinks an interactive statement, and gets a
/// single thread while anything interactive runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn background_work_yields_to_interactive_statements() {
    let budget = ThreadBudget::new(POOL);
    let runtime = runtime();
    let lanes = pool(&runtime, 4, "parts", &budget);
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 30))
        .unwrap()
        .with_thread_budget(budget.clone());
    assert_eq!(Priority::current(), Priority::Background);

    // A job alone on an idle process: half the pool.
    let job_writer = writer.clone();
    let job = tokio::spawn(async move { threads_of(&job_writer, probe(2.0)).await });
    until_running(&budget, (0, 0, 1)).await;
    // An interactive statement beside the job still gets the whole pool.
    let user_lanes = lanes.clone();
    let user = tokio::spawn(async move { as_request("user-a", threads_of(&user_lanes, probe(1.5))).await });
    until_running(&budget, (1, 0, 1)).await;
    // A job (or a scheduled detection request) starting now gets one thread.
    let late_job = threads_of(&lanes, probe(0.0)).await;
    let detection = as_request("detect-0192", threads_of(&lanes, probe(0.0))).await;
    assert_eq!((late_job, detection), ((1, 1), (1, 1)));
    assert_eq!(user.await.unwrap(), (POOL, POOL), "a running job never shrinks interactive work");
    assert_eq!(job.await.unwrap(), (POOL / 2, POOL / 2), "an idle-process job leaves half the pool free");
    until_running(&budget, (0, 0, 0)).await;
    assert_eq!(threads_of(&lanes, probe(0.0)).await, (POOL / 2, POOL / 2));
}

/// Through the lane router: with a budget the fixed 4-thread interactive
/// cap gives way to the pool, and a predictable 7 d string aggregate starts
/// on the large lane without a small-lane attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn router_takes_threads_from_the_budget_and_routes_large_aggregates_large() {
    use crate::part_query::lanes::{run_sized, LaneMemo, LargeLane};
    let budget = ThreadBudget::new(POOL);
    let runtime = runtime();
    let small = pool(&runtime, 2, "parts", &budget);
    let large = LargeLane::new(pool(&runtime, 2, "parts-large", &budget), 3 << 29);
    let memo = LaneMemo::default();
    let output = as_request("user-a", run_sized(&small, Some(&large), &memo, probe(0.0))).await.unwrap();
    assert_eq!(parse(&output.data), (POOL, POOL), "a lone statement is no longer capped at 4");
    assert_eq!((small.status().completed, large.executor().status().completed), (1, 0));

    let mut aggregate = probe(0.0);
    aggregate.query_sha256 = "b".repeat(64);
    aggregate.reader = crate::planner::ReaderShape { string_group_by: true, window_class: 8, ..Default::default() };
    let output = as_request("user-a", run_sized(&small, Some(&large), &memo, aggregate)).await.unwrap();
    assert_eq!(parse(&output.data), (POOL, POOL));
    assert_eq!((small.status().completed, small.status().failed, large.executor().status().completed), (1, 0, 1),
        "the predicted aggregate ran once, on the large lane");
    assert_eq!(memo.len(), 0, "a prediction is not an escalation");
}
