// Native-lane only, like free_feed_native / synthient_native: needs a
// digest-verified chDB (NANO_CHDB_LIBRARY_PATH / _SHA256) and runs with
// `--features enterprise,enrichment-read-audit`. Without the gate the default
// workspace run fails on the missing library instead of testing anything.
#![cfg(all(
    feature = "enterprise",
    feature = "enrichment-read-audit",
    target_os = "linux"
))]
//! Real chDB head-of-line regression; requires the verified native fixture.
use nanosiem_lake_worker::{
    executor::{ExecutorError, NativeExecutor},
    native::NativeChdb,
    query_timing,
};
use std::time::{Duration, Instant};

async fn wait_until_running(executor: &NativeExecutor) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while executor.status().in_flight == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_lane_wait_times_out_without_executing_abandoned_sql() {
    assert_eq!(
        std::env::var("EXECUTOR_LANE_WAIT_TIMEOUT").as_deref(),
        Ok("1")
    );
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("real native library required"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("verified digest required"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    let first_executor = executor.clone();
    let first = tokio::spawn(async move {
        first_executor
            .execute_sql("SELECT sleep(2.5)".into(), vec![])
            .await
            .unwrap()
    });
    wait_until_running(&executor).await;
    query_timing::measure("native-hol", async {
        let start = Instant::now();
        let result = executor.execute_sql("SELECT 42".into(), vec![]).await;
        assert!(matches!(result, Err(ExecutorError::LaneWaitTimeout)));
        assert!(start.elapsed() < Duration::from_secs(2));
        let phases = query_timing::current().unwrap();
        let phases = phases.lock().unwrap();
        assert!(phases.lane_wait_ms >= 900.0);
        assert_eq!(phases.chdb_ms, 0.0);
        Ok::<_, ()>(())
    })
    .await
    .unwrap();
    first.await.unwrap();
    assert_eq!(
        executor.status().completed,
        1,
        "timed-out query must not execute"
    );
    assert_eq!(executor.status().lane_wait_timeouts, 1);
    assert!(executor.status().lane_wait_ms >= 900);

    let first_executor = executor.clone();
    let first = tokio::spawn(async move {
        first_executor
            .execute_sql("SELECT sleep(0.15)".into(), vec![])
            .await
            .unwrap()
    });
    wait_until_running(&executor).await;
    query_timing::measure("native-wait-success", async {
        executor
            .execute_sql("SELECT 43".into(), vec![])
            .await
            .unwrap();
        let phases = query_timing::current().unwrap();
        let phases = phases.lock().unwrap();
        assert!(phases.lane_wait_ms > 0.0);
        assert!(phases.chdb_ms > 0.0);
        Ok::<_, ()>(())
    })
    .await
    .unwrap();
    first.await.unwrap();
    assert_eq!(executor.status().completed, 3);
}
