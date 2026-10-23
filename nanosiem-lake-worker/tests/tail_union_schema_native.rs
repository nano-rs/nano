//! NAN-2505: heterogeneous Parquet through the planner and read-only executor.
//! Run with NANO_CHDB_LIBRARY_PATH and NANO_CHDB_LIBRARY_SHA256.
use nanosiem_lake_worker::{
    executor::NativeExecutor,
    generation::HotTailManifest,
    native::NativeChdb,
    planner::{
        plan_broad_log_query_with_candidates_and_tail, CompiledQuery, ObjectStoreCredentials,
        SnapshotCache, SnapshotCacheObject, SourceManifest, TenantQueryConfig,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[tokio::test]
#[ignore = "requires a digest-verified native chDB library"]
async fn heterogeneous_tail_preserves_nested_columns_and_missing_defaults() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let cloud_schema = "time DateTime64(6, 'UTC'), api Tuple(name Nullable(String))";
    let network_schema = "time DateTime64(6, 'UTC'), src_endpoint Tuple(location Tuple(country Nullable(String))), enrichments Array(Tuple(provider Nullable(String)))";
    let full_schema = format!("{cloud_schema}, src_endpoint Tuple(location Tuple(country Nullable(String))), enrichments Array(Tuple(provider Nullable(String)))");
    let cloud = dir.path().join("cloud.parquet");
    let network = dir.path().join("network.parquet");
    let connection = runtime.connect(&[]).unwrap();
    for (name, parquet, schema, row) in [
        ("cloud", &cloud, cloud_schema, json!({"time":"2026-08-10 12:00:00", "api":{"name":"ListBuckets"}})),
        ("network", &network, network_schema, json!({"time":"2026-08-10 12:00:01", "src_endpoint":{"location":{"country":"US"}}, "enrichments":[{"provider":"producer"}]})),
    ] {
        let input = dir.path().join(format!("{name}.jsonl"));
        std::fs::write(&input, row.to_string()).unwrap();
        connection.query_with_params(
            "INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow",
            &[("output", parquet.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", schema)],
        ).unwrap();
    }
    drop(connection);
    let bytes = std::fs::metadata(&cloud).unwrap().len();
    let base_key = "s3://bucket/table/data/base.parquet";
    let manifest: SourceManifest = serde_json::from_value(json!({
        "tenant_id":"tenant-a", "objects":[{
            "event_object_key":base_key, "event_object_version":"v1",
            "event_object_bytes":bytes, "rows":1, "available_paths":["time","api.name"],
            "field_types":{"time":"timestamp","api.name":"string"}
        }]
    })).unwrap();
    let tenant = TenantQueryConfig {
        tenant_id: "tenant-a".into(),
        source: "https://object.test/bucket/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: 10_000_000, max_memory_bytes: 1_000_000_000,
        max_execution_seconds: 30, threads: 1,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: cloud.to_str().unwrap().into(),
            objects: BTreeMap::from([(base_key.into(), SnapshotCacheObject {
                version_id: "v1".into(), bytes, path: cloud.clone(),
            })]),
            bytes, read_schema: Some(cloud_schema.into()), bootstrap: false,
        }),
    };
    let mut tail: HotTailManifest = serde_json::from_value(json!({
        "schema_version":4,"tenant_id":"tenant-a","table":"logs",
        "base_snapshot_id":1,"head_snapshot_id":2,"tail_id":"a".repeat(64),
        "head_metadata_location":"s3://bucket/table/metadata/00002.metadata.json",
        "iceberg_metadata_file_path":"metadata/00002.metadata.json",
        "read_schema":full_schema,
        "available_paths":["time","api.name","src_endpoint.location.country","enrichments.provider"],
        "objects":[
            {"source_uri":"s3://bucket/table/data/tail-cloud.parquet","version_id":"v1","size_bytes":bytes,"rows":1},
            {"source_uri":"s3://bucket/table/data/tail-network.parquet","version_id":"v2","size_bytes":std::fs::metadata(&network).unwrap().len(),"rows":1}
        ]
    })).unwrap();
    tail.local_paths = vec![cloud, network];
    let executor = NativeExecutor::start(runtime, 1).unwrap();
    for candidates in [None, Some([].as_slice())] {
        for (path, kind, predicate, expected) in [
            ("time", "timestamp", "1".to_string(), if candidates.is_some() { 2 } else { 3 }),
            ("enrichments.provider", "array", "has(\"enrichments.provider\", 'producer')".into(), 1),
            ("src_endpoint.location.country", "string", "isNotNull(\"src_endpoint.location.country\")".into(), 1),
        ] {
            let query: CompiledQuery = serde_json::from_value(json!({
                "schema_version":1,"profile":"ocsf","dataset":"logs",
                "source_placeholder":"__nano_lake_source__","query_sha256":"a".repeat(64),
                "start":"2026-08-10T00:00:00Z","end":"2026-08-11T00:00:00Z",
                "limit":100,"table_view":true,"newest_first_event_rows":true,
                "required_columns":if path == "time" {
                    vec![json!({"name":"time","field_type":"timestamp"}),
                        json!({"name":"api.name","field_type":"string"}),
                        json!({"name":"src_endpoint.location.country","field_type":"string"}),
                        json!({"name":"enrichments.provider","field_type":"array"})]
                } else { vec![json!({"name":path,"field_type":kind}), json!({"name":"time","field_type":"timestamp"})] },
                "sql":format!("SELECT * FROM __nano_lake_source__ WHERE {predicate}")
            })).unwrap();
            let plan = plan_broad_log_query_with_candidates_and_tail(
                &tenant, &manifest, &query, candidates, Some(&tail),
            ).unwrap();
            let mut stats_query = query;
            stats_query.sql = format!("WITH stage_0 AS (SELECT * FROM __nano_lake_source__ WHERE {predicate}) SELECT count() AS total FROM stage_0");
            let stats = plan_broad_log_query_with_candidates_and_tail(
                &tenant, &manifest, &stats_query, candidates, Some(&tail),
            ).unwrap();
            let result = executor.execute_sql(stats.sql, stats.params).await.unwrap();
            let count: Value = serde_json::from_slice(&result.data).unwrap();
            assert_eq!(count["total"], expected, "{path}");
            let result = executor.execute_sql(plan.sql, plan.params).await.unwrap();
            let rows: Vec<Value> = String::from_utf8(result.data).unwrap().lines()
                .map(|line| serde_json::from_str(line).unwrap()).collect();
            assert_eq!(rows.len(), expected, "{path}: {rows:?}");
            if path == "time" {
                let missing = rows.iter().find(|row| row["api"]["name"] == "ListBuckets").unwrap();
                assert!(missing["src_endpoint"]["location"]["country"].is_null());
                assert_eq!(missing["enrichments"], json!([]));
            }
        }
    }
}

#[test]
#[ignore = "1M-row micro-benchmark; requires a digest-verified native chDB library"]
fn table_view_user_hunt_reads_minimal_uniform_roots() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let c = runtime.connect(&[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    // NAN-2510 geometry: 1M rows in fifty 20k-row Parquet objects. Add the
    // user hunt's roots and unrelated wide catalog roots to expose over-read.
    let schema = "time DateTime64(6, 'UTC'), actor Tuple(user Tuple(name Nullable(String))), user Tuple(name Nullable(String)), src_endpoint Tuple(ip Nullable(String), location Tuple(country Nullable(String))), enrichments Array(Tuple(provider Nullable(String))), http_request Tuple(body Nullable(String)), file Tuple(name Nullable(String)), process Tuple(command_line Nullable(String))";
    let mut paths = Vec::new();
    for part in 0..50 {
        let output = dir.path().join(format!("part-{part}.parquet"));
        c.query_with_params(&format!(
            "INSERT INTO FUNCTION file({{output:String}}, Parquet, {{schema:String}}) SELECT fromUnixTimestamp64Micro(1786363200000000 + toInt64(number)), tuple(tuple(if(number % 101 = 0, 'jsmith', 'other'))), tuple(if(number % 103 = 0, 'jsmith', 'other')), tuple('8.8.8.8', tuple(if(number % 2 = 0, 'US', 'CA'))), [], tuple(repeat(hex(cityHash64(number)), 32)), tuple(repeat(hex(cityHash64(number + 1)), 16)), tuple(repeat(hex(cityHash64(number + 2)), 32)) FROM numbers({}, 20000)", part * 20000),
            "JSONEachRow", &[("output", output.to_str().unwrap()), ("schema", schema)],
        ).unwrap();
        paths.push(output);
    }
    let base_key = "s3://bucket/table/data/base.parquet";
    let bytes = std::fs::metadata(&paths[0]).unwrap().len();
    let available = ["time", "actor.user.name", "user.name", "src_endpoint.ip", "src_endpoint.location.country", "enrichments.provider", "http_request.body", "file.name", "process.command_line"];
    let manifest: SourceManifest = serde_json::from_value(json!({
        "tenant_id":"tenant-a", "objects":[{
            "event_object_key":base_key, "event_object_version":"v1", "event_object_bytes":bytes,
            "rows":20000, "available_paths":available,
            "field_types":{"time":"timestamp", "actor.user.name":"string", "user.name":"string"}
        }]
    })).unwrap();
    let tenant = TenantQueryConfig {
        tenant_id: "tenant-a".into(), source: "https://object.test/bucket/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: 10_000_000_000, max_memory_bytes: 1_000_000_000,
        max_execution_seconds: 60, threads: 1, credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: paths[0].to_str().unwrap().into(),
            objects: BTreeMap::from([(base_key.into(), SnapshotCacheObject {
                version_id: "v1".into(), bytes, path: paths[0].clone(),
            })]), bytes, read_schema: Some(schema.into()), bootstrap: false,
        }),
    };
    let mut tail: HotTailManifest = serde_json::from_value(json!({
        "schema_version":4, "tenant_id":"tenant-a", "table":"logs",
        "base_snapshot_id":1, "head_snapshot_id":2, "tail_id":"a".repeat(64),
        "head_metadata_location":"s3://bucket/table/metadata/00002.metadata.json",
        "iceberg_metadata_file_path":"metadata/00002.metadata.json",
        "read_schema":schema, "available_paths":available,
        "objects":paths.iter().enumerate().map(|(i, path)| json!({
            "source_uri":format!("s3://bucket/table/data/tail-{i}.parquet"),
            "version_id":"v1", "size_bytes":std::fs::metadata(path).unwrap().len(), "rows":20000
        })).collect::<Vec<_>>()
    })).unwrap();
    tail.local_paths = paths;
    let query: CompiledQuery = serde_json::from_value(json!({
        "schema_version":1, "profile":"ocsf", "dataset":"logs",
        "source_placeholder":"__nano_lake_source__", "query_sha256":"a".repeat(64),
        "start":"2026-08-10T00:00:00Z", "end":"2026-08-11T00:00:00Z",
        "limit":50, "table_view":true, "newest_first_event_rows":true,
        "required_columns":[{"name":"actor.user.name","field_type":"string"},
            {"name":"user.name","field_type":"string"},{"name":"time","field_type":"timestamp"}],
        "sql":"SELECT * FROM __nano_lake_source__ WHERE (\"actor.user.name\" = 'jsmith' OR \"user.name\" = 'jsmith') ORDER BY \"time\" DESC LIMIT 50"
    })).unwrap();
    let plan = plan_broad_log_query_with_candidates_and_tail(
        &tenant, &manifest, &query, Some(&[]), Some(&tail),
    ).unwrap();
    let minimal = format!("SELECT actor, user, time FROM file('{}/*.parquet', Parquet, {{schema:String}}) WHERE (actor.user.name = 'jsmith' OR user.name = 'jsmith') ORDER BY time DESC LIMIT 50 SETTINGS max_threads=1, input_format_parquet_allow_missing_columns=1", dir.path().display());
    let mut before_query = query;
    // Full-event requests retain the old all-root output, giving an exact
    // executable baseline for the pre-NAN-2518 table-view scan shape.
    before_query.table_view = false;
    let before = plan_broad_log_query_with_candidates_and_tail(
        &tenant, &manifest, &before_query, Some(&[]), Some(&tail),
    ).unwrap();
    let params = plan.params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>();
    let before_params = before.params.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect::<Vec<_>>();
    let queries = [(&minimal, vec![("schema", schema)]), (&plan.sql, params), (&before.sql, before_params)];
    let mut measurements = [Vec::new(), Vec::new(), Vec::new()];
    let mut bytes_read = [0; 3];
    let values = |data: &[u8]| String::from_utf8_lossy(data).lines().map(|line| {
        let row: Value = serde_json::from_str(line).unwrap();
        json!({"actor":row["actor"], "user":row["user"], "time":row["time"]})
    }).collect::<Vec<_>>();
    let expected = values(&c.query_with_params(&minimal, "JSONEachRow", &[("schema", schema)]).unwrap().data);
    assert_eq!(expected.len(), 50);
    // Interleave runs to avoid a systematic cache/warmup advantage.
    for round in 0..12 {
        for offset in 0..3 {
            let i = (round + offset) % 3;
            let (sql, params) = &queries[i];
            let start = std::time::Instant::now();
            let result = c.query_with_params(sql, "JSONEachRow", params).unwrap();
            let wall = start.elapsed().as_secs_f64();
            assert_eq!(values(&result.data), expected);
            if round > 0 { measurements[i].push(wall); }
            bytes_read[i] = result.storage_bytes_read;
        }
    }
    let medians = measurements.map(|mut samples| { samples.sort_by(f64::total_cmp); samples[5] });
    eprintln!("NAN-2518 1M rows / 50 Parquet objects, median of 11: minimal={} bytes/{:.6}s planned={} bytes/{:.6}s before={} bytes/{:.6}s; ratios bytes={:.3} wall={:.3}", bytes_read[0], medians[0], bytes_read[1], medians[1], bytes_read[2], medians[2], bytes_read[1] as f64 / bytes_read[0] as f64, medians[1] / medians[0]);
    eprintln!("NAN-2518 before SQL: {}", before.sql);
    eprintln!("NAN-2518 after SQL: {}", plan.sql);
    assert!(bytes_read[1] as f64 <= bytes_read[0] as f64 * 1.2);
    assert!(medians[1] <= medians[0] * 1.2);
}

// Frozen compiler output, including the 25 display fields that the earlier
// three-field SELECT-* benchmark omitted. Compare all returned values, not
// merely IDs. NAN-4168: stamped values read as stored, expired or not.
#[tokio::test]
#[ignore = "requires a digest-verified native chDB library"]
async fn nan2523_compiler_leaf_page_preserves_rows_and_stamped_values() {
    use sha2::Digest;
    async move {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let c = runtime.connect(&[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let artifact_dir = std::env::var("NAN2523_ARTIFACT_DIR").ok().map(std::path::PathBuf::from);
    if let Some(path) = &artifact_dir {
        std::fs::create_dir_all(path).unwrap();
    }
    let fixture: Value = serde_json::from_str(include_str!("fixtures/nan2469-live-tail-read-schema.json")).unwrap();
    let schema = fixture["read_schema"].as_str().unwrap();
    let available = fixture["available_paths"].clone();
    let mut paths = Vec::new();
    let rows_per_object = std::env::var("NAN2523_ROWS_PER_OBJECT").ok()
        .map(|value| value.parse::<usize>().unwrap()).unwrap_or(20_000);
    let object_count = std::env::var("NAN2523_OBJECT_COUNT").ok()
        .map(|value| value.parse::<usize>().unwrap()).unwrap_or(3);
    let sparse = std::env::var_os("NAN2523_SPARSE").is_some();
    assert!((3..=21).contains(&object_count));
    assert!(rows_per_object > 0 && rows_per_object * object_count <= 900_000);
    for part in 0..object_count {
        let input = dir.path().join(format!("part-{part}.jsonl"));
        let parquet = dir.path().join(format!("part-{part}.parquet"));
        let rows = (0..rows_per_object).map(|i| {
            let id = i * object_count + part;
            // Interleave the top rows across the snapshot and tail files.
            let user = if (!sparse || part == 0 || part == object_count - 1) && (if sparse { i } else { id }) % 3 == 0 { "JSmith" } else { "other" };
            let actor = if (!sparse || part == 0 || part == object_count - 1) && (if sparse { i } else { id }) % 7 == 0 { "jsmith" } else { "other" };
            let endpoint = json!({"ip":"8.8.8.8", "port":443, "hostname":"producer",
                "location":{"country":"US", "continent":"NA", "provider":"geo"},
                "autonomous_system":{"number":64512,"name":"producer ASN"}});
            json!({"time":format!("2026-09-21 14:00:00.{id:06}"),
                "metadata":{"uid":format!("event-{id}"),"log_source":"fixture"},
                "actor":{"user":{"name":actor},"process":{"name":"actor-process"}},
                "user":{"name":user},"message":format!("event {id}"),
                "activity_name":"login", "class_uid":3002, "severity":"Informational",
                "src_endpoint":endpoint,"dst_endpoint":endpoint,
                "raw_data":"unused wide payload".repeat(128),
                "enrichments":if id % 2 == 0 { json!([{"provider":"platform/ipinfo_lite", "name":"src_endpoint.ip", "data":{
                    "contract_version":1,"feed_class":"baseline","feed_id":"ipinfo_lite","feed_revision_id":1,
                    "valid_until":if id % 4 == 0 { "2020-01-01T00:00:00Z" } else { "2026-09-22T00:00:00Z" },"status":"match",
                    "owned_fields":["src_endpoint.location.country", "dst_endpoint.location.country"]}}]) } else { json!([]) }
            }).to_string()
        }).collect::<Vec<_>>().join("\n");
        std::fs::write(&input, rows).unwrap();
        c.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow", &[("output",parquet.to_str().unwrap()),("input",input.to_str().unwrap()),("schema",schema)]).unwrap();
        paths.push(parquet);
    }
    let bytes = std::fs::metadata(&paths[0]).unwrap().len();
    let base_key = "s3://bucket/table/data/base.parquet";
    let manifest: SourceManifest = serde_json::from_value(json!({"tenant_id":"tenant-a", "objects":[{
        "event_object_key":base_key,"event_object_version":"v1","event_object_bytes":bytes,
        "rows":rows_per_object,"available_paths":available,
        "field_types":{"time":"timestamp","actor.user.name":"string","user.name":"string"}
    }]})).unwrap();
    let mut tenant = TenantQueryConfig {
        tenant_id:"tenant-a".into(),source:"https://object.test/bucket/table".into(),
        iceberg_metadata_file_path:"metadata/00001.metadata.json".into(),
        max_query_bytes:1_000_000_000,max_memory_bytes:1_000_000_000,
        max_execution_seconds:60,threads:1,credentials:ObjectStoreCredentials::DefaultChain,
        snapshot_cache:Some(SnapshotCache {source_spec:paths[0].to_str().unwrap().into(),
            objects:BTreeMap::from([(base_key.into(), SnapshotCacheObject {
                version_id:"v1".into(),bytes,path:paths[0].clone(),
            })]),bytes,read_schema:Some(schema.into()),bootstrap:false}),
    };
    let mut tail: HotTailManifest = serde_json::from_value(json!({
        "schema_version":4,"tenant_id":"tenant-a","table":"logs",
        "base_snapshot_id":1,"head_snapshot_id":2,"tail_id":"a".repeat(64),
        "head_metadata_location":"s3://bucket/table/metadata/00002.metadata.json",
        "iceberg_metadata_file_path":"metadata/00002.metadata.json",
        "read_schema":schema,"available_paths":available,
        "objects":paths[1..].iter().enumerate().map(|(i,path)| json!({
            "source_uri":format!("s3://bucket/table/data/tail-{i}.parquet"),"version_id":"v1",
            "size_bytes":std::fs::metadata(path).unwrap().len(),"rows":rows_per_object,
            "sha256":hex::encode(sha2::Sha256::digest(std::fs::read(path).unwrap()))
        })).collect::<Vec<_>>()
    })).unwrap();
    tail.local_paths = paths[1..].to_vec();
    let mut query: CompiledQuery = serde_json::from_str(include_str!("fixtures/nan2523-leaf-compiled.json")).unwrap();
    let aggregate: CompiledQuery = serde_json::from_str(include_str!("fixtures/nan2523-aggregate-compiled.json")).unwrap();
    let mut before: CompiledQuery = serde_json::from_str(include_str!("fixtures/nan2523-leaf-compiled.json")).unwrap();
    before.newest_first_event_rows = sparse; // sparse baseline is pass 2
    if sparse {
        tenant.threads = 8;
        query.candidate_hints = vec![nanosiem_lake_worker::planner::CandidateHint::Any { alternatives:
            ["actor.user.name", "user.name"].into_iter().map(|path| nanosiem_lake_worker::planner::CandidateHint::Entity {
                source_path:path.into(), value:"jsmith".into(),
            }).collect() }];
    }
    let decode = |data: &[u8]| String::from_utf8_lossy(data).lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
    for (scope, candidates, selected_tail) in [
        ("combined", None, Some(&tail)),
        ("generation", None, None),
        ("tail", Some([].as_slice()), Some(&tail)),
        ("chunk", None, Some(&tail)),
        ("cursor", None, Some(&tail)),
    ] {
        if sparse && matches!(scope, "chunk" | "cursor") { continue; }
        let mut expected = None;
        for (name, compiled) in [("before", &before), ("after", &query), ("aggregate", &aggregate)] {
            use nanosiem_lake_worker::planner::{
                plan_broad_log_query_with_candidates_tail_and_time,
                plan_broad_log_query_with_candidates_tail_time_and_cursor,
                SourceTimeFence, SourceCursorFence,
            };
            let plan_started = std::time::Instant::now();
            let plan = if scope == "chunk" {
                plan_broad_log_query_with_candidates_tail_and_time(
                    &tenant, &manifest, compiled, candidates, selected_tail,
                    Some(SourceTimeFence { start:"2026-09-21T14:00:00.010000Z",
                        end:"2026-09-21T14:00:00.040000Z", end_inclusive:false,
                        exact_times: None }),
                )
            } else if scope == "cursor" {
                plan_broad_log_query_with_candidates_tail_time_and_cursor(
                    &tenant, &manifest, compiled, candidates, selected_tail, None,
                    SourceCursorFence { time:"2026-09-21T14:00:00.030000Z", event_uid:"event-30000" },
                )
            } else {
                plan_broad_log_query_with_candidates_and_tail(
                    &tenant, &manifest, compiled, candidates, selected_tail,
                )
            }.unwrap();
            if sparse { eprintln!("NAN-2523 {scope} {name} plan_ms={:.3}", plan_started.elapsed().as_secs_f64()*1000.0); }
            if sparse && name == "after" && matches!(scope, "tail" | "combined") {
                assert_eq!(plan.params.iter().find(|(key,_)| key == "hot_tail_source").unwrap().1, tail.local_paths.last().unwrap().display().to_string(), "only the matching tail object should survive");
            }
            if scope == "combined" {
                std::fs::write(format!("/tmp/nan2523-{name}.sql"), &plan.sql).unwrap();
                eprintln!("NAN-2523 {name} columns: {:?}", compiled.required_columns);
            }
            let params = plan.params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
            if let Some(path) = &artifact_dir {
                std::fs::write(path.join(format!("{scope}-{name}.sql")), &plan.sql).unwrap();
                std::fs::write(path.join(format!("{scope}-{name}-params.json")), serde_json::to_vec_pretty(&plan.params).unwrap()).unwrap();
                let explain = c.query_with_params(&format!("EXPLAIN actions=1 {}", plan.sql), "TSVRaw", &params).unwrap();
                std::fs::write(path.join(format!("{scope}-{name}-explain.txt")), &explain.data).unwrap();
            }
            let mut samples = Vec::new();
            let mut read = (0, 0);
            for _ in 0..4 {
                let start = std::time::Instant::now();
                let result = c.query_with_params(&plan.sql, "JSONEachRow", &params).unwrap();
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
                read = (result.storage_rows_read, result.storage_bytes_read);
                let rows = decode(&result.data);
                if name == "before" { expected = Some(rows); }
                else if name == "after" {
                    assert_eq!(rows.len(), 101); // executor keeps one lookahead row
                    assert_eq!(&rows, expected.as_ref().unwrap(), "{scope}");
                    if scope == "combined" {
                        for row in &rows {
                            assert_eq!(row["src_endpoint.location.country"], "US");
                            assert_eq!(row["dst_endpoint.location.country"], "US");
                            assert!(!row["src_endpoint.autonomous_system.number"].is_null());
                        }
                    }
                }
            }
            samples.remove(0); // warmup
            samples.sort_by(f64::total_cmp);
            eprintln!("NAN-2523 {scope} {name} chdb_ms={:.3} read_rows={} read_bytes={}", samples[1], read.0, read.1);
        }
    }
    if sparse {
        let mut serial_ms = 0.0;
        let mut expected = Vec::new();
        for (i, path) in tail.local_paths.iter().enumerate() {
            let mut one = tail.clone();
            one.objects = vec![tail.objects[i].clone()]; one.local_paths = vec![path.clone()];
            let plan = plan_broad_log_query_with_candidates_and_tail(&tenant, &manifest, &before, Some(&[]), Some(&one)).unwrap();
            let params = plan.params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
            let start = std::time::Instant::now();
            let result = c.query_with_params(&plan.sql, "JSONEachRow", &params).unwrap();
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            serial_ms += ms; expected.extend(decode(&result.data));
            eprintln!("NAN-2523 sparse per-object {i} chdb_ms={ms:.3}");
        }
        expected.sort_by(|a,b| b["time"].as_str().cmp(&a["time"].as_str())); expected.truncate(101);
        let locator = nanosiem_lake_worker::planner::table_view_locator(&query).unwrap();
        let mut after_ms = 0.0;
        for (label, compiled) in [("locator", &locator), ("page", &query)] {
            let plan = plan_broad_log_query_with_candidates_and_tail(&tenant, &manifest, compiled, Some(&[]), Some(&tail)).unwrap();
            let params = plan.params.iter().map(|(k,v)| (k.as_str(),v.as_str())).collect::<Vec<_>>();
            let start = std::time::Instant::now();
            let result = c.query_with_params(&plan.sql, "JSONEachRow", &params).unwrap();
            let ms = start.elapsed().as_secs_f64() * 1000.0; after_ms += ms;
            if label == "page" { assert_eq!(decode(&result.data), expected); }
            eprintln!("NAN-2523 sparse {label} chdb_ms={ms:.3} candidate_objects={}", plan.budget.candidate_objects);
        }
        eprintln!("NAN-2523 sparse {} objects serial_ms={serial_ms:.3} locator_plus_page_ms={after_ms:.3}", tail.objects.len());
        if tail.objects.len() >= 20 { assert!(after_ms < serial_ms * 0.65, "sparse scan must be sub-linear versus serial statement opens"); }
    }
    if artifact_dir.is_some() { eprintln!("NAN-2523 retained fixtures: {}", dir.keep().display()); }
    }.await;
}
