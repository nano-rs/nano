//! Rule-library query shapes through the real planner and native chDB.
//! Run with NANO_CHDB_LIBRARY_PATH and NANO_CHDB_LIBRARY_SHA256.
//!
//! dns_over_https (OCSF): the rule's full-row pipeline filters on two
//! grandchildren of `http_request` in separate stages
//! (`where url.url_string … OR … | where … | where url.path …`). It failed in
//! the lake with `Not found column tupleElement(http_request, 'url') in block`.
//! The SQL below is `lake_query_compile`'s output for the rule text.
use nanosiem_lake_worker::{
    executor::NativeExecutor,
    native::NativeChdb,
    planner::{
        local_path_spec, plan_broad_log_query_with_candidates_and_tail, CompiledQuery,
        ObjectStoreCredentials, SnapshotCache, SnapshotCacheObject, SourceManifest,
        TenantQueryConfig,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The part-log read schema (the union of every part's shape).
const READ_SCHEMA: &str = "time DateTime64(6, 'UTC'), class_uid Nullable(Int32), \
    metadata Tuple(uid Nullable(String), log_source Nullable(String)), \
    src_endpoint Tuple(hostname Nullable(String), ip Nullable(String)), \
    dst_endpoint Tuple(hostname Nullable(String), ip Nullable(String), port Nullable(Int32)), \
    http_request Tuple(url Tuple(hostname Nullable(String), path Nullable(String), url_string Nullable(String)), user_agent Nullable(String))";

/// A part whose events carry no URL: its `http_request` Tuple has no `url`.
const NO_URL_PART_SCHEMA: &str = "time DateTime64(6, 'UTC'), class_uid Nullable(Int32), \
    metadata Tuple(uid Nullable(String), log_source Nullable(String)), \
    src_endpoint Tuple(hostname Nullable(String), ip Nullable(String)), \
    dst_endpoint Tuple(hostname Nullable(String), ip Nullable(String), port Nullable(Int32)), \
    http_request Tuple(user_agent Nullable(String))";

const PATHS: &[(&str, &str)] = &[
    ("time", "timestamp"),
    ("class_uid", "integer"),
    ("metadata.uid", "string"),
    ("metadata.log_source", "string"),
    ("src_endpoint.hostname", "string"),
    ("src_endpoint.ip", "string"),
    ("dst_endpoint.hostname", "string"),
    ("dst_endpoint.ip", "string"),
    ("dst_endpoint.port", "integer"),
    ("http_request.url.hostname", "string"),
    ("http_request.url.path", "string"),
    ("http_request.url.url_string", "string"),
    ("http_request.user_agent", "string"),
];

const DNS_OVER_HTTPS_WHERES: &str = r#"WITH stage_0 AS (
  SELECT * FROM __nano_lake_source__
  WHERE time BETWEEN '2026-09-28 00:00:00.000000' AND '2026-09-29 00:00:00.000000'
  AND (class_uid = 4002)
),
stage_1 AS (
  SELECT * FROM stage_0
  WHERE ((toString("http_request.url.url_string") iLike '%dns-query%' OR toString("http_request.url.url_string") iLike '%resolve?%') OR "dst_endpoint.ip" IN ('1.1.1.1', '8.8.8.8'))
),
stage_2 AS (
  SELECT * FROM stage_1
  WHERE "dst_endpoint.port" = 443
),
stage_3 AS (
  SELECT * FROM stage_2
  WHERE toString("http_request.url.path") iLike '%dns-query%'
)
SELECT * FROM stage_3 ORDER BY time DESC, "metadata.uid" DESC LIMIT 10000 SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order=0, optimize_aggregation_in_order=1"#;

fn compiled(sql: &str, required: &[&str]) -> CompiledQuery {
    let types: BTreeMap<&str, &str> = PATHS.iter().copied().collect();
    serde_json::from_value(json!({
        "schema_version":1,"profile":"ocsf","dataset":"logs",
        "source_placeholder":"__nano_lake_source__","query_sha256":"a".repeat(64),
        "start":"2026-09-28T00:00:00Z","end":"2026-09-29T00:00:00Z",
        "limit":10000,"table_view":false,"newest_first_event_rows":false,
        "required_columns": required.iter().map(|name| json!({"name":name,"field_type":types[name]})).collect::<Vec<_>>(),
        "sql": sql,
    }))
    .unwrap()
}

struct Fixture {
    _dir: tempfile::TempDir,
    runtime: NativeChdb,
    manifest: SourceManifest,
    tenant: TenantQueryConfig,
}

fn fixture() -> Fixture {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let write = |name: &str, schema: &str, rows: &[Value]| -> PathBuf {
        let input = dir.path().join(format!("{name}.jsonl"));
        let output = dir.path().join(format!("{name}.parquet"));
        std::fs::write(
            &input,
            rows.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        connection
            .query_with_params(
                "INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
                "JSONEachRow",
                &[("output", output.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", schema)],
            )
            .unwrap();
        output
    };
    let with_url = write(
        "part-1",
        READ_SCHEMA,
        &[
            json!({"time":"2026-09-28 12:00:00","class_uid":4002,"metadata":{"uid":"a","log_source":"proxy"},
            "src_endpoint":{"hostname":"ws-1","ip":"10.0.0.5"},"dst_endpoint":{"hostname":"cloudflare-dns.com","ip":"1.1.1.1","port":443},
            "http_request":{"url":{"hostname":"cloudflare-dns.com","path":"/dns-query","url_string":"https://cloudflare-dns.com/dns-query?dns=AAAB"},"user_agent":"curl"}}),
            json!({"time":"2026-09-28 12:00:01","class_uid":4002,"metadata":{"uid":"b","log_source":"proxy"},
            "src_endpoint":{"hostname":"ws-2","ip":"10.0.0.6"},"dst_endpoint":{"hostname":"example.com","ip":"93.184.216.34","port":443},
            "http_request":{"url":{"hostname":"example.com","path":"/index.html","url_string":"https://example.com/index.html"},"user_agent":"curl"}}),
        ],
    );
    let without_url = write(
        "part-2",
        NO_URL_PART_SCHEMA,
        &[
            json!({"time":"2026-09-28 12:00:02","class_uid":4002,"metadata":{"uid":"c","log_source":"proxy"},
            "src_endpoint":{"hostname":"ws-3","ip":"10.0.0.7"},"dst_endpoint":{"hostname":"h","ip":"1.1.1.1","port":443},
            "http_request":{"user_agent":"curl"}}),
        ],
    );
    drop(connection);
    let files = [
        (with_url, "s3://bucket/table/data/part-1.parquet"),
        (without_url, "s3://bucket/table/data/part-2.parquet"),
    ];
    let size = |path: &Path| std::fs::metadata(path).unwrap().len();
    let manifest: SourceManifest = serde_json::from_value(json!({
        "tenant_id":"tenant-a",
        "objects": files.iter().map(|(path, key)| json!({
            "event_object_key":key,"event_object_version":"v1","event_object_bytes":size(path),"rows":1,
            "available_paths": PATHS.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            "field_types": PATHS.iter().map(|(p, t)| (p.to_string(), json!(t))).collect::<serde_json::Map<_, _>>(),
        })).collect::<Vec<_>>(),
    }))
    .unwrap();
    let mut paths = files
        .iter()
        .map(|(p, _)| p.to_str().unwrap().to_string())
        .collect::<Vec<_>>();
    let tenant = TenantQueryConfig {
        tenant_id: "tenant-a".into(),
        source: "https://object.test/bucket/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: 10_000_000,
        max_memory_bytes: 1_000_000_000,
        max_execution_seconds: 30,
        threads: 1,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: local_path_spec(&mut paths).unwrap(),
            objects: files
                .iter()
                .map(|(path, key)| {
                    (
                        key.to_string(),
                        SnapshotCacheObject {
                            version_id: "v1".into(),
                            bytes: size(path),
                            path: path.clone(),
                        },
                    )
                })
                .collect(),
            bytes: files.iter().map(|(p, _)| size(p)).sum(),
            read_schema: Some(READ_SCHEMA.into()),
            bootstrap: false,
        }),
    };
    Fixture {
        _dir: dir,
        runtime,
        manifest,
        tenant,
    }
}

async fn run(fixture: &Fixture, query: &CompiledQuery) -> Vec<Value> {
    let plan = plan_broad_log_query_with_candidates_and_tail(
        &fixture.tenant,
        &fixture.manifest,
        query,
        None,
        None,
    )
    .unwrap();
    let executor = NativeExecutor::start(fixture.runtime.clone(), 1).unwrap();
    let result = executor
        .execute_sql(plan.sql.clone(), plan.params.clone())
        .await
        .unwrap_or_else(|error| panic!("{error}\n--- plan ---\n{}", plan.sql));
    String::from_utf8(result.data)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
#[ignore = "requires a digest-verified native chDB library"]
async fn dns_over_https_full_row_pipeline_runs_on_native_ocsf_parts() {
    let fixture = fixture();
    let query = compiled(
        DNS_OVER_HTTPS_WHERES,
        &[
            "class_uid",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "http_request.url.path",
            "http_request.url.url_string",
            "metadata.uid",
            "time",
        ],
    );
    let rows = run(&fixture, &query).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["http_request"]["url"]["path"], "/dns-query");
    assert_eq!(rows[0]["src_endpoint"]["hostname"], "ws-1");
}

#[tokio::test]
#[ignore = "requires a digest-verified native chDB library"]
async fn dns_over_https_base_risk_runs_on_native_ocsf_parts() {
    let fixture = fixture();
    let sql = DNS_OVER_HTTPS_WHERES.replace(
        "\nSELECT * FROM stage_3 ORDER BY",
        ",\nstage_4 AS (\n  SELECT *,\n    45 AS raw_risk_score,\n    45 AS risk_score,\n    coalesce(toString(\"src_endpoint.hostname\"), 'unknown') AS risk_entity,\n    ['DNS-over-HTTPS detected'] AS risk_factors\n  FROM stage_3\n)\nSELECT * FROM stage_4 ORDER BY",
    );
    let query = compiled(
        &sql,
        &[
            "class_uid",
            "dst_endpoint.ip",
            "dst_endpoint.port",
            "http_request.url.path",
            "http_request.url.url_string",
            "metadata.uid",
            "src_endpoint.hostname",
            "time",
        ],
    );
    let rows = run(&fixture, &query).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["risk_entity"], "ws-1");
}

/// Endpoint roots next to a prevalence-stamped `enrichments` column, exactly
/// as ingest[T] writes an OCSF network part.
const ENRICHED_SCHEMA: &str = "time DateTime64(6, 'UTC'), class_uid Nullable(Int64), \
    metadata Tuple(uid Nullable(String), log_source Nullable(String)), \
    src_endpoint Tuple(ip Nullable(String), hostname Nullable(String)), \
    dst_endpoint Tuple(hostname Nullable(String), ip Nullable(String), port Nullable(Int64)), \
    enrichments Array(Tuple(data Tuple(as_of Nullable(String), host_count Nullable(Int64), host_count_saturated Nullable(Bool), \
        is_new Nullable(Bool), is_rare Nullable(Bool), artifact_type Nullable(String), first_seen Nullable(String), \
        last_seen Nullable(String), prevalence_score Nullable(Int64), total_occurrences Nullable(Int64)), \
        name Nullable(String), provider Nullable(String), short_desc Nullable(String), type Nullable(String), value Nullable(String)))";

const ENRICHED_PATHS: &[(&str, &str)] = &[
    ("time", "timestamp"),
    ("class_uid", "long"),
    ("metadata.uid", "string"),
    ("metadata.log_source", "string"),
    ("src_endpoint.ip", "string"),
    ("src_endpoint.hostname", "string"),
    ("dst_endpoint.hostname", "string"),
    ("dst_endpoint.ip", "string"),
    ("dst_endpoint.port", "long"),
    ("enrichments.data.host_count", "array"),
    ("enrichments.name", "array"),
    ("enrichments.provider", "array"),
    ("enrichments.type", "array"),
    ("enrichments.value", "array"),
];

/// `lateral_movement-ocsf/rdp_lateral_movement`'s SQL prefix (before its
/// `| prevalence` stage), as `lake_query_compile` emits it for
/// `class_uid=4001 dst_endpoint.port=3389
///  | where is_private_ip(src_endpoint.ip) AND is_private_ip(dst_endpoint.ip)`.
const RDP_LATERAL_MOVEMENT: &str = r#"WITH stage_0 AS (
  SELECT * FROM __nano_lake_source__
  WHERE time BETWEEN '2026-09-28 00:00:00.000000' AND '2026-09-29 00:00:00.000000'
  AND ((class_uid = 4001 AND "dst_endpoint.port" = 3389))
),
stage_1 AS (
  SELECT * FROM stage_0
  WHERE (ifNull((isIPv4String(toString("src_endpoint.ip")) OR isIPv6String(toString("src_endpoint.ip"))) AND (isIPAddressInRange(toString("src_endpoint.ip"), '10.0.0.0/8') OR isIPAddressInRange(toString("src_endpoint.ip"), '172.16.0.0/12') OR isIPAddressInRange(toString("src_endpoint.ip"), '192.168.0.0/16')), 0) AND ifNull((isIPv4String(toString("dst_endpoint.ip")) OR isIPv6String(toString("dst_endpoint.ip"))) AND (isIPAddressInRange(toString("dst_endpoint.ip"), '10.0.0.0/8') OR isIPAddressInRange(toString("dst_endpoint.ip"), '172.16.0.0/12') OR isIPAddressInRange(toString("dst_endpoint.ip"), '192.168.0.0/16')), 0))
)
SELECT * FROM stage_1 ORDER BY time DESC, "metadata.uid" DESC LIMIT 10001 SETTINGS max_threads=16, max_execution_time=300, optimize_read_in_order=0, optimize_aggregation_in_order=1"#;

fn enriched_compiled(sql: &str, required: &[&str]) -> CompiledQuery {
    let types: BTreeMap<&str, &str> = ENRICHED_PATHS.iter().copied().collect();
    serde_json::from_value(json!({
        "schema_version":1,"profile":"ocsf","dataset":"logs",
        "source_placeholder":"__nano_lake_source__","query_sha256":"a".repeat(64),
        "start":"2026-09-28T00:00:00Z","end":"2026-09-29T00:00:00Z",
        "limit":10001,"table_view":false,"newest_first_event_rows":false,
        "required_columns": required.iter().map(|name| json!({"name":name,"field_type":types[name]})).collect::<Vec<_>>(),
        "sql": sql,
    }))
    .unwrap()
}

fn enriched_fixture() -> Fixture {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let dir = tempfile::tempdir().unwrap();
    let connection = runtime.connect(&[]).unwrap();
    let stamp = |value: &str, hosts: i64| json!({"data":{"as_of":"2026-09-28T00:00:00Z","host_count":hosts,"host_count_saturated":false,
        "is_new":false,"is_rare":hosts < 5,"artifact_type":"ip","first_seen":"2026-09-01T00:00:00Z","last_seen":"2026-09-28T00:00:00Z",
        "prevalence_score":hosts,"total_occurrences":hosts * 3},
        "name":"prevalence","provider":"nano/prevalence","short_desc":null,"type":"prevalence","value":value});
    let rows = [
        // Internal RDP: the rule's match.
        json!({"time":"2026-09-28 12:00:00","class_uid":4001,"metadata":{"uid":"rdp-1","log_source":"windows_sysmon"},
            "src_endpoint":{"ip":"10.0.0.5","hostname":"ws-1"},"dst_endpoint":{"hostname":"srv-1","ip":"10.0.0.9","port":3389},
            "enrichments":[stamp("10.0.0.5", 2), stamp("10.0.0.9", 1)]}),
        // RDP to a public address: not lateral.
        json!({"time":"2026-09-28 12:00:01","class_uid":4001,"metadata":{"uid":"rdp-2","log_source":"windows_sysmon"},
            "src_endpoint":{"ip":"10.0.0.6","hostname":"ws-2"},"dst_endpoint":{"hostname":"ext","ip":"93.184.216.34","port":3389},
            "enrichments":[stamp("93.184.216.34", 40)]}),
        // Internal, another port.
        json!({"time":"2026-09-28 12:00:02","class_uid":4001,"metadata":{"uid":"ssh-1","log_source":"windows_sysmon"},
            "src_endpoint":{"ip":"10.0.0.7","hostname":"ws-3"},"dst_endpoint":{"hostname":"srv-2","ip":"10.0.0.10","port":22},
            "enrichments":[]}),
        // Internal RDP with no stamp at all.
        json!({"time":"2026-09-28 12:00:03","class_uid":4001,"metadata":{"uid":"rdp-3","log_source":"windows_sysmon"},
            "src_endpoint":{"ip":"192.168.1.4","hostname":"ws-4"},"dst_endpoint":{"hostname":"srv-3","ip":"172.16.0.3","port":3389},
            "enrichments":[]}),
    ];
    let input = dir.path().join("part-1.jsonl");
    let output = dir.path().join("part-1.parquet");
    std::fs::write(&input, rows.iter().map(Value::to_string).collect::<Vec<_>>().join("\n")).unwrap();
    connection
        .query_with_params(
            "INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow",
            &[("output", output.to_str().unwrap()), ("input", input.to_str().unwrap()), ("schema", ENRICHED_SCHEMA)],
        )
        .unwrap();
    drop(connection);
    let key = "s3://bucket/table/data/part-1.parquet";
    let size = std::fs::metadata(&output).unwrap().len();
    let manifest: SourceManifest = serde_json::from_value(json!({
        "tenant_id":"tenant-a",
        "objects": [{
            "event_object_key":key,"event_object_version":"v1","event_object_bytes":size,"rows":rows.len(),
            "available_paths": ENRICHED_PATHS.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            "field_types": ENRICHED_PATHS.iter().map(|(p, t)| (p.to_string(), json!(t))).collect::<serde_json::Map<_, _>>(),
        }],
    }))
    .unwrap();
    let mut paths = vec![output.to_str().unwrap().to_string()];
    let tenant = TenantQueryConfig {
        tenant_id: "tenant-a".into(),
        source: "https://object.test/bucket/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: 10_000_000,
        max_memory_bytes: 1_000_000_000,
        max_execution_seconds: 30,
        threads: 1,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: local_path_spec(&mut paths).unwrap(),
            objects: [(key.to_string(), SnapshotCacheObject { version_id: "v1".into(), bytes: size, path: output.clone() })]
                .into_iter()
                .collect(),
            bytes: size,
            read_schema: Some(ENRICHED_SCHEMA.into()),
            bootstrap: false,
        }),
    };
    Fixture { _dir: dir, runtime, manifest, tenant }
}

/// NAN-3052: rdp_lateral_movement on lean. The rule filters on `dst_endpoint`
/// in stage 0 and on both endpoints' `ip` in stage 1, over parts whose
/// `enrichments` carry prevalence stamps; it died on every run with
/// `Code: 10. Not found column arrayExists(__nano_e …)`.
#[tokio::test]
#[ignore = "requires a digest-verified native chDB library"]
async fn rdp_lateral_movement_runs_on_native_enriched_ocsf_parts() {
    let fixture = enriched_fixture();
    let query = enriched_compiled(
        RDP_LATERAL_MOVEMENT,
        &["class_uid", "dst_endpoint.ip", "dst_endpoint.port", "metadata.uid", "src_endpoint.ip", "time"],
    );
    let rows = run(&fixture, &query).await;
    let uids = rows.iter().map(|row| row["metadata"]["uid"].as_str().unwrap()).collect::<Vec<_>>();
    assert_eq!(uids, ["rdp-3", "rdp-1"], "{rows:?}");
    // Full rows: the endpoints come back whole, with their stamps.
    assert_eq!(rows[1]["src_endpoint"]["hostname"], "ws-1");
    assert_eq!(rows[1]["dst_endpoint"]["port"], 3389);
    assert_eq!(rows[1]["enrichments"].as_array().map(Vec::len), Some(2));
}
