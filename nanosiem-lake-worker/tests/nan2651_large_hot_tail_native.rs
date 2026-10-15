//! NAN-2651: a schema-v4 hot tail larger than 2^31 bytes and 3 GiB, read
//! through the planner's single local `file()` leaf by the read-only executor
//! under the production 512 MiB chDB process cap.
//!
//! Run (tmpfs, like the reader's cache):
//!   NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... \
//!   NAN2651_DIR=/dev/shm/nan2651 cargo test -p nanosiem-lake-worker \
//!     --test nan2651_large_hot_tail_native -- --ignored --nocapture
use nanosiem_lake_worker::{
    executor::{ExecutorMode, NativeExecutor},
    generation::HotTailManifest,
    native::NativeChdb,
    planner::{
        plan_broad_log_query_with_candidates_and_tail, CompiledQuery, ObjectStoreCredentials,
        SnapshotCache, SnapshotCacheObject, SourceManifest, TenantQueryConfig,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

const SCHEMA: &str = "time DateTime64(6, 'UTC'), message Nullable(String), src_endpoint Tuple(ip Nullable(String))";

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::test]
#[ignore = "multi-GiB tmpfs fixture; requires a digest-verified native chDB library"]
async fn hot_tail_above_2_pow_31_and_3_gib_is_queryable_under_the_512_mib_cap() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let root = PathBuf::from(std::env::var("NAN2651_DIR").unwrap_or_else(|_| "/dev/shm/nan2651".into()));
    let objects_dir = root.join("objects");
    std::fs::create_dir_all(&objects_dir).unwrap();
    let objects = env_or("NAN2651_OBJECTS", 1_257);
    let rows = env_or("NAN2651_ROWS_PER_OBJECT", 3_000);
    let row_chars = env_or("NAN2651_ROW_CHARS", 1_000);
    let cap = env_or("NAN2651_SERVER_MEMORY_BYTES", 512 << 20);
    let lanes = env_or("NAN2651_LANES", 4) as usize;

    // Build the fixture once (a separate, uncapped process-first connection
    // would fix server settings, so generation uses the capped args too).
    let args = nanosiem_lake_worker::executor::executor_connection_args(Some(cap));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let generator = runtime.connect(&arg_refs).unwrap();
    let mut paths = Vec::new();
    let mut total = 0_u64;
    let base_ms = 1_790_103_900_000_i64;
    for index in 0..objects {
        let path = objects_dir.join(format!("{index:064x}.parquet"));
        if !path.exists() {
            let staged = objects_dir.join(format!(".{index}.tmp.parquet"));
            let _ = std::fs::remove_file(&staged);
            generator
                .query_with_params(
                    &format!(
                        "INSERT INTO FUNCTION file({{output:String}}, Parquet, {{schema:String}}) \
                         SELECT fromUnixTimestamp64Milli(toInt64({start}) + number * 10, 'UTC') AS time, \
                         randomPrintableASCII({row_chars}) AS message, \
                         tuple(IPv4NumToString(toUInt32(rand()))) AS src_endpoint \
                         FROM numbers({rows})",
                        start = base_ms + index as i64 * 60_000,
                    ),
                    "JSONEachRow",
                    &[("output", staged.to_str().unwrap()), ("schema", SCHEMA)],
                )
                .unwrap();
            std::fs::rename(&staged, &path).unwrap();
        }
        total += std::fs::metadata(&path).unwrap().len();
        paths.push(path);
    }
    drop(generator);
    eprintln!("fixture: {objects} objects, {total} bytes (2^31 = {}, 3 GiB = {})", 1_u64 << 31, 3_u64 << 30);

    let base = root.join("base.parquet");
    let base_bytes = std::fs::metadata(&paths[0]).unwrap().len();
    if !base.exists() {
        std::fs::copy(&paths[0], &base).unwrap();
    }
    let base_key = "s3://bucket/table/data/base.parquet";
    let manifest: SourceManifest = serde_json::from_value(json!({
        "tenant_id":"tenant-a", "objects":[{
            "event_object_key":base_key, "event_object_version":"v1",
            "event_object_bytes":base_bytes, "rows":rows, "available_paths":["time","message","src_endpoint.ip"],
            "field_types":{"time":"timestamp","message":"string","src_endpoint.ip":"string"}
        }]
    }))
    .unwrap();
    let tenant = TenantQueryConfig {
        tenant_id: "tenant-a".into(),
        source: "https://object.test/bucket/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: u64::MAX / 4,
        max_memory_bytes: 400 << 20,
        max_execution_seconds: 300,
        threads: 4,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: base.to_str().unwrap().into(),
            objects: BTreeMap::from([(
                base_key.into(),
                SnapshotCacheObject { version_id: "v1".into(), bytes: base_bytes, path: base.clone() },
            )]),
            bytes: base_bytes,
            read_schema: Some(SCHEMA.into()),
            bootstrap: false,
        }),
    };
    let tail_objects: Vec<Value> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| {
            json!({
                "source_uri": format!("s3://bucket/table/data/committed/{index:05}.parquet"),
                "version_id": "v1",
                "size_bytes": std::fs::metadata(path).unwrap().len(),
                "rows": rows,
                "sha256": format!("{index:064x}"),
                "min_time_ms": base_ms + index as i64 * 60_000,
                "max_time_ms": base_ms + index as i64 * 60_000 + rows as i64 * 10,
                "committed": true,
            })
        })
        .collect();
    let mut tail: HotTailManifest = serde_json::from_value(json!({
        "schema_version":4,"tenant_id":"tenant-a","table":"logs",
        "base_snapshot_id":1,"head_snapshot_id":1,"tail_id":"a".repeat(64),
        "head_metadata_location":"s3://bucket/table/metadata/00001.metadata.json",
        "iceberg_metadata_file_path":"metadata/00001.metadata.json",
        "read_schema":SCHEMA,
        "available_paths":["time","message","src_endpoint.ip"],
        "objects":tail_objects,
    }))
    .unwrap();
    tail.local_paths = paths.clone();

    let executor = NativeExecutor::start_with_server_memory_limit(
        runtime,
        lanes,
        "query",
        ExecutorMode::ReadOnly,
        Some(cap),
    )
    .unwrap();
    let mut plans = Vec::new();
    for (label, sql) in [
        ("count", "WITH stage_0 AS (SELECT * FROM __nano_lake_source__ WHERE 1) SELECT count() AS total FROM stage_0"),
        ("newest", "SELECT * FROM __nano_lake_source__ WHERE 1"),
        ("keyword", "SELECT * FROM __nano_lake_source__ WHERE positionCaseInsensitive(\"message\", 'zzz') > 0"),
        ("stats", "WITH stage_0 AS (SELECT * FROM __nano_lake_source__ WHERE 1) SELECT \"src_endpoint.ip\" AS ip, count() AS c FROM stage_0 GROUP BY ip ORDER BY c DESC LIMIT 10"),
    ] {
        let query: CompiledQuery = serde_json::from_value(json!({
            "schema_version":1,"profile":"ocsf","dataset":"logs",
            "source_placeholder":"__nano_lake_source__","query_sha256":"a".repeat(64),
            "start":"2026-09-22T00:00:00Z","end":"2026-09-25T00:00:00Z",
            "limit":50,"table_view":true,"newest_first_event_rows":true,
            "required_columns":[{"name":"time","field_type":"timestamp"},
                {"name":"message","field_type":"string"},{"name":"src_endpoint.ip","field_type":"string"}],
            "sql":sql
        }))
        .unwrap();
        let plan = plan_broad_log_query_with_candidates_and_tail(&tenant, &manifest, &query, None, Some(&tail))
            .unwrap_or_else(|error| panic!("{label}: plan: {error}"));
        plans.push((label, plan.sql.clone(), plan.params.clone()));
        let started = std::time::Instant::now();
        let result = executor.execute_sql(plan.sql, plan.params).await;
        match result {
            Ok(output) => eprintln!(
                "{label}: ok in {:?}, {} bytes: {}",
                started.elapsed(),
                output.data.len(),
                String::from_utf8_lossy(&output.data[..output.data.len().min(200)])
            ),
            Err(error) => eprintln!("{label}: error in {:?}: {error}", started.elapsed()),
        }
    }
    // Concurrent pressure: every plan on every lane, repeatedly, so memory
    // limit exceptions interleave inside the Parquet reader.
    let rounds = env_or("NAN2651_STRESS_ROUNDS", 0);
    for round in 0..rounds {
        let results = futures::future::join_all(
            plans
                .iter()
                .cycle()
                .take(plans.len() * lanes)
                .map(|(_, sql, params)| executor.execute_sql(sql.clone(), params.clone())),
        )
        .await;
        let failures = results.iter().filter(|result| result.is_err()).count();
        eprintln!("stress round {round}: {} queries, {failures} failed", results.len());
    }
}
