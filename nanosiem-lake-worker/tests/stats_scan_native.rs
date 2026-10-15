// Native-lane only, like free_feed_native / synthient_native: needs a
// digest-verified chDB (NANO_CHDB_LIBRARY_PATH / _SHA256) and runs with
// `--features enterprise,enrichment-read-audit`. Without the gate the default
// workspace run fails on the missing library instead of testing anything.
#![cfg(all(
    feature = "enterprise",
    feature = "enrichment-read-audit",
    target_os = "linux"
))]
//! NAN-2499: actual compiler/planner, a 24h generation and forty hydrated tail objects.
//! Requires the same verified chDB/compiler environment as stored_enrichment_native.
use nanosiem_lake_worker::{
    enrichment_read,
    generation::HotTailManifest,
    native::{NativeChdb, NativeConnection, NativeQueryOutput},
    planner::{
        plan_broad_log_query_with_candidates_and_tail, CompiledQuery, ObjectStoreCredentials,
        SnapshotCache, SnapshotCacheObject, SourceManifest, TenantQueryConfig,
    },
};
use serde_json::json;
use std::{collections::BTreeMap, io::Write, path::Path};

const QUERY: &str = "metadata.log_source=conduit_proxy action_id=1 | stats sum(traffic.bytes_out) as bytes_out_total by src_endpoint.ip | eventstats avg(bytes_out_total) as fleet_avg | where bytes_out_total > fleet_avg | sort -bytes_out_total | head 20";
const SCHEMA: &str = "time DateTime64(6,'UTC'), action_id Int64, metadata Tuple(uid String,log_source String), traffic Tuple(bytes_out UInt64,bytes_in UInt64), src_endpoint Tuple(ip String,port UInt16,location Tuple(country Nullable(String),continent Nullable(String),provider Nullable(String)),autonomous_system Tuple(number Nullable(UInt32),name Nullable(String))), process Tuple(name String,cmd_line String), enrichments Array(Tuple(name String,value String,type String,provider String,data Tuple(contract_version UInt16,feed_id String,feed_class String,feed_revision_id Int64,valid_until String,status String,owned_fields Array(String))))";
fn compile(hours: u32, fields: &BTreeMap<String, String>) -> CompiledQuery {
    let mut child = std::process::Command::new(std::env::var("NANO_LAKE_COMPILER").unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(json!({"query":QUERY,"dataset":"logs","start":format!("2026-08-07T{:02}:00:00Z",24-hours),"end":"2026-08-08T00:00:00Z","limit":100,"table_view":false,"event_contract":"ocsf-1.9","snapshot_field_types":fields}).to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    serde_json::from_slice(&out.stdout).unwrap()
}
fn run(c: &NativeConnection, sql: &str, params: &[(String, String)]) -> NativeQueryOutput {
    c.query_with_params(
        sql,
        "JSONEachRow",
        &params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}
fn generate(c: &NativeConnection, path: &Path, rows: u64, offset: u64) {
    if path.exists() {
        return;
    }
    // Two base objects each span 24h; forty tail objects span successive windows.
    // Ordered timestamps, 3:1 proxy/sysmon mix. Varied endpoints,
    // nested structs and stamps force the production mask, unlike flat microbenchmarks.
    let sql = format!(
        r#"INSERT INTO FUNCTION file({{path:String}}, Parquet)
    SELECT event.time AS time, event.action_id AS action_id, event.metadata AS metadata, event.traffic AS traffic, event.src_endpoint AS src_endpoint, event.process AS process, event.enrichments AS enrichments FROM (SELECT CAST(tuple(fromUnixTimestamp64Micro(1786060800000000 + toInt64(if({offset} < 2*{rows}, number*86400000000/{rows}, (number+{offset})*86400000000/{total}))),
       toInt64(if(number%4=0,2,1)), tuple(toString(number+{offset}),if(number%4=0,'sysmon','conduit_proxy')),
       tuple(toUInt64(cityHash64(number)%1000000),toUInt64(number%5000)),
       tuple(concat('10.',toString(intDiv(number%8192,256)),'.0.',toString(number%256)),toUInt16(443),tuple('US','NA','producer'),tuple(toUInt32(64512),'producer ASN')),
       tuple(if(number%4=0,'powershell.exe','conduit'),hex(cityHash64(number))),
       [tuple('src_endpoint.ip','8.8.8.8','geoip','platform/ipinfo_lite',tuple(toUInt16(1),'ipinfo_lite','baseline',toInt64(1),'2026-08-08T00:00:00Z','match',['src_endpoint.location.country']))]),
       {{schema:String}}) AS event FROM numbers({rows}))
       SETTINGS max_threads=12, output_format_parquet_row_group_size=65536"#,
        total = rows * 42
    );
    c.query_with_params(
        &sql,
        "JSONEachRow",
        &[
            ("path", path.to_str().unwrap()),
            ("schema", &format!("Tuple({SCHEMA})")),
        ],
    )
    .unwrap();
}
#[test]
fn stats_scan_scales_with_bytes_and_preserves_rows() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let c = runtime.connect(&[]).unwrap();
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/nan2499");
    std::fs::create_dir_all(&dir).unwrap();
    let dir = dir.canonicalize().unwrap();
    let rows: u64 = std::env::var("NAN2499_ROWS_PER_OBJECT")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(180224);
    let data = dir.join(format!("typed-rows-{rows}"));
    std::fs::create_dir_all(&data).unwrap();
    let fields: BTreeMap<String, String> = [
        ("time", "timestamp"),
        ("action_id", "integer"),
        ("metadata.uid", "string"),
        ("metadata.log_source", "string"),
        ("traffic.bytes_out", "integer"),
        ("src_endpoint.ip", "ip_address"),
        ("src_endpoint.location.country", "string"),
        ("enrichments.provider", "array"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let mut base_objects = BTreeMap::new();
    let mut objects = vec![];
    let mut tail_objects = vec![];
    let mut local_paths = vec![];
    let mut base_bytes = 0;
    for i in 0..42 {
        let path = data.join(format!("object-{i:02}.parquet"));
        generate(&c, &path, rows, i * rows);
        let bytes = std::fs::metadata(&path).unwrap().len();
        let key = format!("s3://fixture/table/data/object-{i:02}.parquet");
        if i < 2 {
            base_bytes += bytes;
            base_objects.insert(
                key.clone(),
                SnapshotCacheObject {
                    version_id: "v1".into(),
                    bytes,
                    path,
                },
            );
            objects.push(json!({"event_object_key":key,"event_object_version":"v1","event_object_bytes":bytes,"rows":rows,"available_paths":fields.keys().collect::<Vec<_>>(),"field_types":fields}));
        } else {
            tail_objects.push(json!({"source_uri":key,"version_id":"v1","size_bytes":bytes,"rows":rows,"committed":true,"min_time_ms":1786060800000_i64+(i*86400000/42) as i64,"max_time_ms":1786060800000_i64+((i+1)*86400000/42) as i64}));
            local_paths.push(path);
        }
    }
    let tenant_id = uuid::Uuid::from_u128(1).to_string();
    let tenant = TenantQueryConfig {
        tenant_id: tenant_id.clone(),
        source: "https://object.test/fixture/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: 20_000_000_000,
        max_memory_bytes: 4_000_000_000,
        max_execution_seconds: 120,
        threads: 12,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: format!("{}/object-{{00,01}}.parquet", data.display()),
            objects: base_objects,
            bytes: base_bytes,
            read_schema: Some(SCHEMA.into()),
            bootstrap: false,
        }),
    };
    let manifest: SourceManifest =
        serde_json::from_value(json!({"tenant_id":tenant_id,"objects":objects})).unwrap();
    let mut tail: HotTailManifest = serde_json::from_value(json!({"schema_version":4,"tenant_id":tenant_id,"table":"logs","base_snapshot_id":1,"head_snapshot_id":2,"head_metadata_location":"s3://fixture/table/metadata/00002.metadata.json","iceberg_metadata_file_path":"metadata/00002.metadata.json","read_schema":SCHEMA,"available_paths":fields.keys().collect::<Vec<_>>(),"objects":tail_objects})).unwrap();
    tail.local_paths = local_paths;
    let authority = enrichment_read::current();
    let old_ip = enrichment_read::root_expression("src_endpoint", &authority);
    let mut results = vec![];
    for hours in [1, 6, 24] {
        let compiled = compile(hours, &fields);
        let plan = plan_broad_log_query_with_candidates_and_tail(
            &tenant,
            &manifest,
            &compiled,
            None,
            Some(&tail),
        )
        .unwrap();
        std::fs::write(
            dir.join(format!("{hours}h-params.json")),
            serde_json::to_vec(&plan.params).unwrap(),
        )
        .unwrap();
        // Frozen pre-fix projection, preserving the identical compiler and scan settings.
        let old_leaf = format!("tupleElement({old_ip}, 'ip') AS `src_endpoint.ip`");
        let new_leaf = "`src_endpoint`.`ip` AS `src_endpoint.ip`";
        assert!(
            plan.sql.contains(new_leaf),
            "producer IP must use the native leaf"
        );
        let before = plan.sql.replace(new_leaf, &old_leaf);
        let after = plan.sql.clone();
        std::fs::write(dir.join(format!("{hours}h-before.sql")), &before).unwrap();
        std::fs::write(dir.join(format!("{hours}h-after.sql")), &after).unwrap();
        // The old expression is deliberately expensive. Execute it once for
        // the correctness oracle; sample the production path after a warmup.
        let baseline = run(&c, &before, &plan.params);
        assert!(!baseline.data.is_empty());
        let mut times_after = vec![];
        let mut bytes = 0;
        let mut read_rows = 0;
        for repetition in 0..4 {
            let b = run(&c, &after, &plan.params);
            assert_eq!(baseline.data, b.data, "byte-equivalent rows at {hours}h");
            if repetition > 0 {
                times_after.push(b.elapsed.as_secs_f64());
            }
            bytes = b.storage_bytes_read;
            read_rows = b.storage_rows_read;
        }
        times_after.sort_by(f64::total_cmp);
        let before_bytes = baseline.storage_bytes_read;
        println!(
            "NAN2499 {hours}h before={:.6} after={:.6} read_bytes={bytes} before_read_bytes={before_bytes} read_rows={read_rows} estimated_bytes={}",
            baseline.elapsed.as_secs_f64(), times_after[1], plan.budget.estimated_scan_bytes
        );
        results.push((times_after[1], bytes));
        for (label, sql) in [("before", &before), ("after", &after)] {
            for explain in ["PIPELINE", "indexes=1"] {
                let out = c
                    .query_with_params(
                        &format!("EXPLAIN {explain} {sql}"),
                        "TSVRaw",
                        &plan
                            .params
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                std::fs::write(
                    dir.join(format!("{hours}h-{label}-{explain}.txt")),
                    out.data,
                )
                .unwrap();
            }
        }
    }
    assert!(
        results[2].0 / results[1].0 <= 2.0 * results[2].1 as f64 / results[1].1 as f64,
        "24h/6h exceeds twice the actual scan byte ratio: {results:?}"
    );
}
