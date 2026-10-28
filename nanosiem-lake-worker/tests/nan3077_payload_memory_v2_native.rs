// SPDX-License-Identifier: AGPL-3.0-or-later
//! Saved local full-event parity and memory gate. No service or event-content output.
use nanosiem_lake_worker::{
    executor::{ExecutorMode, NativeExecutor},
    native::NativeChdb,
};
use parquet::file::reader::{FileReader, SerializedFileReader};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

fn files(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "parquet") {
            out.push(path);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires pinned native runtime and NAN3077_REAL_PARTS saved local fixture"]
async fn widest_real_payload_matches_reference_under_statement_cap() {
    const CHILD: &str = "NAN3077_PAYLOAD_CHILD";
    const TEST: &str = "widest_real_payload_matches_reference_under_statement_cap";
    if let Ok(mode) = std::env::var(CHILD) {
        let mut paths = Vec::new();
        files(
            Path::new(&std::env::var("NAN3077_REAL_PARTS").unwrap()),
            &mut paths,
        );
        paths.sort();
        let mut schemas = paths
            .iter()
            .map(|path| {
                let reader = SerializedFileReader::new(File::open(path).unwrap()).unwrap();
                let metadata = reader.metadata().file_metadata();
                (
                    metadata.schema_descr().num_columns(),
                    metadata.schema().clone(),
                    path.clone(),
                )
            })
            .collect::<Vec<_>>();
        schemas.sort_by_key(|(width, _, _)| *width);
        let (width, schema, _) = schemas.last().unwrap();
        assert!(
            *width >= 379,
            "fixture must include the widest captured schema"
        );
        let mut selected = schemas
            .iter()
            .filter(|(_, candidate, _)| candidate == schema)
            .map(|(_, _, path)| path.display().to_string())
            .collect::<Vec<_>>();
        // Use the eight largest files of the widest captured schema. This is
        // a bounded payload window, not a claim about a full-day 124-file scan.
        let captured_files = selected.len();
        selected.sort_by_key(|path| std::cmp::Reverse(std::fs::metadata(path).unwrap().len()));
        let file_limit = std::env::var("NAN3077_PAYLOAD_FILES")
            .ok()
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(8);
        if file_limit != 0 {
            selected.truncate(file_limit);
        }
        let spec = nanosiem_lake_worker::planner::local_path_spec(&mut selected).unwrap();
        let runtime = NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        )
        .unwrap();
        std::mem::forget(runtime.clone());
        let connection = NativeExecutor::start_with_server_memory_limit(
            runtime.clone(),
            1,
            "payload-v2",
            ExecutorMode::ReadOnly,
            Some(12 << 30),
        )
        .unwrap();
        let base = "SELECT * FROM file({paths:String}, Parquet) ORDER BY time DESC, metadata.uid DESC LIMIT 201 SETTINGS max_threads=8, max_memory_usage=10737418240, max_execution_time=600, max_bytes_before_external_sort=805306368, max_temporary_data_on_disk_size_for_query=6442450944, use_query_cache=0";
        let budget_threads = if mode == "one-budget" { 1 } else { 8 };
        // NAN-4694: "role-small-lane" is an 8-core query role's role-derived
        // payload reader (4 threads x 512 rows) at the small-lane statement
        // cap it actually runs under.
        let small_lane_bytes = nanosiem_lake_worker::part_query::memory_budget::SMALL_QUERY_BYTES;
        let statement_cap = if mode == "role-small-lane" {
            small_lane_bytes
        } else {
            nanosiem_lake_worker::planner::PAYLOAD_READER_MEMORY_BYTES
        };
        let reader_threads = match mode.as_str() {
            "reference" => 8,
            _ => nanosiem_lake_worker::planner::payload_role_defaults(budget_threads, statement_cap).0,
        };
        // The whole day (`NAN3077_PAYLOAD_FILES=0`) outgrows a small lane at
        // any reader setting (~0.9 GiB of sort state at 1 x 128), so the role
        // mode is held to the large-lane cap there like the others.
        let memory_cap = if mode == "role-small-lane" && file_limit != 0 {
            small_lane_bytes
        } else if file_limit == 0 {
            1_503_238_553_u64
        } else {
            1_288_490_188_u64
        };
        let sql = if mode == "reference" {
            base.into()
        } else {
            // NAN-3077's statement (one reader thread, 128-row blocks) is the
            // role defaults at a one-reader statement cap; "role-small-lane"
            // is the 8-core role's (NAN-4694).
            let bounded = nanosiem_lake_worker::planner::bounded_payload_settings(
                base.into(),
                budget_threads,
                statement_cap,
            )
            .replace(
                "max_memory_usage=10737418240",
                &format!("max_memory_usage={memory_cap}"),
            );
            bounded
        };
        let monitor = NativeExecutor::start_with_server_memory_limit(
            runtime,
            1,
            "payload-monitor",
            ExecutorMode::ReadOnly,
            Some(12 << 30),
        )
        .unwrap();
        let task = tokio::spawn(async move {
            connection
                .execute_sql(sql, vec![("paths".into(), spec)])
                .await
                .expect("payload must succeed on its first attempt")
        });
        let mut peak_memory_bytes = 0_u64;
        while !task.is_finished() {
            let sample = monitor.execute_sql(
                "SELECT max(peak_memory_usage) AS peak FROM system.processes WHERE startsWith(query, 'SELECT * FROM file(')".into(),
                vec![],
            ).await.unwrap();
            let value: serde_json::Value = serde_json::from_slice(&sample.data).unwrap();
            let peak = value["peak"]
                .as_u64()
                .or_else(|| value["peak"].as_str().and_then(|value| value.parse().ok()))
                .expect("native peak memory is an unsigned integer");
            peak_memory_bytes = peak_memory_bytes.max(peak);
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let output = task.await.unwrap();
        assert!(
            peak_memory_bytes > 0,
            "must observe the running payload query"
        );
        if mode != "reference" {
            assert!(
                peak_memory_bytes < memory_cap,
                "query peak exceeds statement cap"
            );
        }
        let rows = output
            .data
            .split(|byte| *byte == b'\n')
            .filter(|row| !row.is_empty())
            .count();
        assert_eq!(rows, 201);
        let digest = hex::encode(Sha256::digest(&output.data));
        let hwm = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap()
            .to_string();
        println!("PAYLOAD_RESULT {digest}");
        println!("PAYLOAD_METRICS mode={mode} budget_threads={budget_threads} reader_threads={reader_threads} columns={width} captured_files={captured_files} files={} rows={rows} bytes={} query_peak_bytes={peak_memory_bytes} wall_ms={} {hwm}",
            selected.len(), output.data.len(), output.elapsed.as_millis());
        return;
    }
    // Fresh processes keep the unbounded reference's allocations out of the
    // bounded memory measurement and avoid a failure/retry on any executor.
    let mut reference = None;
    for mode in ["reference", "eight-budget", "one-budget", "role-small-lane"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(CHILD, mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode} child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        let digest = stdout
            .lines()
            .find_map(|line| line.strip_prefix("PAYLOAD_RESULT "))
            .unwrap();
        if let Some(expected) = &reference {
            assert_eq!(digest, expected, "{mode} row parity");
        } else {
            reference = Some(digest.to_string());
        }
        for line in stdout
            .lines()
            .filter(|line| line.starts_with("PAYLOAD_METRICS "))
        {
            println!("{line}");
        }
    }
}
