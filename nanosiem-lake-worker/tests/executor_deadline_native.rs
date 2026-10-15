//! NAN-2511 runtime capability probes. Run individually under a process timeout
//! with NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256. Source inspection is
//! not a substitute for running these against the deployment's pinned artifact.
use nanosiem_lake_worker::{executor::NativeExecutor, native::NativeChdb, query_timing};
use std::time::{Duration, Instant};

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    // chDB owns process-global state beyond the last connection's lifetime.
    std::mem::forget(runtime.clone());
    runtime
}

#[tokio::test]
#[ignore = "requires a digest-verified native chDB library"]
async fn executor_interactive_parquet_deadline_throws_and_lane_is_reusable() {
    let runtime = runtime();
    let dir = tempfile::tempdir().unwrap();
    let parquet = dir.path().join("slow.parquet");
    let connection = runtime.connect(&[]).unwrap();
    connection.query_with_params(
        // Keep each sleepEachRow block below chDB's three-second sleep ceiling;
        // max_block_size alone does not split native Parquet row groups.
        "INSERT INTO FUNCTION file({path:String}, Parquet) SELECT number FROM numbers(10000) SETTINGS output_format_parquet_row_group_size=128",
        "JSONEachRow", &[("path", parquet.to_str().unwrap())],
    ).unwrap();
    drop(connection);
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    query_timing::measure("native-interactive-deadline", async {
        // A short interactive tier for the regression; production defaults to 55s.
        query_timing::current().unwrap().lock().unwrap().execution_seconds = 1;
        let started = Instant::now();
        let error = executor.execute_sql(
            "SELECT sum(sleepEachRow(0.001) + number) FROM file({path:String}, Parquet) SETTINGS max_execution_time=300, timeout_overflow_mode='throw', timeout_before_checking_execution_speed=0, max_threads=1, max_block_size=128".into(),
            vec![("path".into(), parquet.to_str().unwrap().into())],
        ).await.unwrap_err();
        let message = error.to_string();
        assert!(message.contains("TIMEOUT_EXCEEDED") || message.contains("Timeout exceeded"), "{message}");
        assert!(started.elapsed() < Duration::from_secs(5), "cooperative timeout overshot by more than the test allowance");
        executor.execute_sql("SELECT 42".into(), vec![]).await.unwrap();
        assert_eq!(executor.status().in_flight, 0);
        assert_eq!(executor.status().failed, 1);
        assert_eq!(executor.status().completed, 1);
        Ok::<_, ()>(())
    }).await.unwrap();
}

#[test]
#[ignore = "capability probe: requires pinned chDB; run under timeout 30s with --nocapture"]
fn executor_native_query_id_and_control_connection_kill_probe() {
    let runtime = runtime();
    let control = runtime.connect(&[]).unwrap();
    // Explicitly test the proposed SETTINGS primitive before claiming KILL can
    // address a running execution. query_id is not a normal upstream setting.
    let id = format!("nan2511-{}", uuid::Uuid::new_v4());
    let check = control.query_with_params(
        &format!("SELECT currentQueryID() AS id SETTINGS query_id='{id}'"), "JSONEachRow", &[],
    );
    let output = check.expect("this artifact does not support query_id as a SQL setting; cancellation cannot use this primitive");
    assert!(String::from_utf8_lossy(&output.data).contains(&id), "query_id setting did not bind the execution identity");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let query_id = id.clone();
    let worker = std::thread::spawn(move || {
        let connection = runtime.connect(&[]).unwrap();
        started_tx.send(()).unwrap();
        let started = Instant::now();
        let result = connection.query_with_params(
            &format!("SELECT sum(sleepEachRow(0.001)) FROM numbers(10000) SETTINGS query_id='{query_id}', max_block_size=128, max_threads=1, max_execution_time=15"),
            "JSONEachRow", &[],
        );
        (started.elapsed(), result)
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let active = control.query_with_params(
            "SELECT count() AS n FROM system.processes WHERE query_id={id:String}", "JSONEachRow", &[("id", &id)],
        ).unwrap();
        let row: serde_json::Value = serde_json::from_slice(&active.data).unwrap();
        if row["n"].as_u64() == Some(1) || row["n"].as_str() == Some("1") { break; }
        assert!(Instant::now() < deadline, "second connection cannot observe the target query");
        std::thread::sleep(Duration::from_millis(10));
    }
    control.query_with_params("KILL QUERY WHERE query_id={id:String} ASYNC", "JSONEachRow", &[("id", &id)]).unwrap();
    let (elapsed, result) = worker.join().unwrap();
    let error = result.unwrap_err().to_string();
    assert!(error.contains("QUERY_WAS_CANCELLED") || error.contains("cancelled"), "{error}");
    assert!(elapsed < Duration::from_secs(5));
    control.query_with_params("SELECT 42", "JSONEachRow", &[]).unwrap();
}
