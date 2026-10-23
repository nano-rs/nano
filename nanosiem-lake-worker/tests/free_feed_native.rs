#![cfg(all(
    feature = "enterprise",
    feature = "enrichment-read-audit",
    target_os = "linux"
))]
// SPDX-License-Identifier: AGPL-3.0-or-later
use chrono::{Duration, Utc};
use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};

use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::planner::{
    plan_broad_log_query, CompiledQuery, ObjectStoreCredentials, SnapshotCache,
    SnapshotCacheObject, SourceManifest, TenantQueryConfig,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use uuid::Uuid;

fn compile(query: &str, fields: &BTreeMap<String, String>) -> Result<CompiledQuery, String> {
    let mut child = std::process::Command::new(
        std::env::var("NANO_LAKE_COMPILER").expect("real compiler required"),
    )
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped())
    .spawn()
    .unwrap();
    child.stdin.take().unwrap().write_all(json!({"query":query,"dataset":"logs","start":"2026-08-07T00:00:00Z","end":"2026-08-08T00:00:00Z","limit":100,"table_view":false,"event_contract":"ocsf-1.9","snapshot_field_types":fields}).to_string().as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

#[path = "support/free_feeds.rs"]
mod fixture;
use fixture::*;
use nanosiem_core::platform_enrichment::adapters::tor;
#[test]
fn free_adapters_native_stored_selectors_refresh_and_correlation() {
    let now = Utc::now();
    let mut f = Fixture::new();
    f.install(
        "tor_exit_nodes",
        1,
        tor(b"192.0.2.1\n2001:db8::1\n").unwrap(),
        Duration::zero(),
    );
    f.install(
        "threatfox",
        1,
        export(
            &[
                (10, "192.0.2.1:443", "ip:port", "alpha", 40),
                (20, "192.0.2.1:443", "ip:port", "beta", 90),
                (30, "[2001:db8::1]:8443", "ip:port", "v6", 70),
                (40, "example.com", "domain", "domain", 80),
                (
                    50,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "md5_hash",
                    "hash",
                    60,
                ),
                (60, "https://example.com/Case?A=1", "url", "url", 50),
            ],
            now + Duration::hours(2),
        ),
        Duration::zero(),
    );
    let old = f.stamp("old", event());
    let stamp = |e: &Value, feed: &str, subject: &str| {
        e["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["provider"] == format!("platform/{feed}") && r["name"] == subject)
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(stamp(&old, "threatfox", "src_endpoint.ip").len(), 2);
    assert_eq!(
        stamp(&old, "threatfox", "dst_endpoint.ip")[0]["data"]["malware"],
        "v6"
    );
    assert_eq!(
        stamp(&old, "threatfox", "query.hostname")[0]["data"]["malware"],
        "domain"
    );
    assert_eq!(
        stamp(&f.stamp("file", file_event()), "threatfox", "file.hashes")[0]["data"]["malware"],
        "hash"
    );
    assert_eq!(
        stamp(
            &f.stamp("http", http_event()),
            "threatfox",
            "http_request.url.url_string"
        )[0]["data"]["malware"],
        "url"
    );
    let mut mismatch = event();
    mismatch["src_endpoint"]["port"] = json!(8443);
    mismatch["dst_endpoint"]["port"] = json!(443);
    let mismatch = f.stamp("ports", mismatch);
    assert_eq!(
        stamp(&mismatch, "threatfox", "src_endpoint.ip")[0]["data"]["status"],
        "no_match"
    );
    assert_eq!(
        stamp(&mismatch, "threatfox", "dst_endpoint.ip")[0]["data"]["status"],
        "no_match"
    );
    let mut collision = event();
    collision["query"]["hostname"] = json!("a".repeat(32));
    assert_eq!(
        stamp(
            &f.stamp("type-collision", collision),
            "threatfox",
            "query.hostname"
        )[0]["data"]["status"],
        "no_match"
    );
    let mut case = http_event();
    case["http_request"]["url"]["url_string"] = json!("https://example.com/case?A=1");
    assert_eq!(
        stamp(
            &f.stamp("url-case", case),
            "threatfox",
            "http_request.url.url_string"
        )[0]["data"]["status"],
        "no_match"
    );
    let mut exhausted = file_event();
    exhausted["file"]["hashes"] = json!(vec![json!({"algorithm_id":1,"value":"a".repeat(32)}); 17]);
    assert_eq!(
        stamp(&f.stamp("resource", exhausted), "threatfox", "file.hashes")[0]["data"]["reason"],
        "resource_limit"
    );
    f.install(
        "tor_exit_nodes",
        2,
        tor(b"192.0.2.99\n").unwrap(),
        Duration::zero(),
    );
    f.install(
        "threatfox",
        2,
        export(&[], now + Duration::hours(2)),
        Duration::zero(),
    );
    let new = f.stamp("new", event());
    assert_eq!(
        stamp(&new, "tor_exit_nodes", "src_endpoint.ip")[0]["data"]["is_tor"],
        false
    );
    assert_eq!(
        stamp(&new, "threatfox", "src_endpoint.ip")[0]["data"]["status"],
        "no_match"
    );
    assert_eq!(f.stamp("old", event()), old, "replay restamped history");
    // Search starts only after all conversions, matching, normalization and signing.
    let before = nanosiem_core::platform_enrichment::read::audit::counts();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let parquet = dir.path().join("events.parquet");
    let rows=[old,new].into_iter().map(|e|json!({"time":"2026-08-07 12:00:00","metadata":{"uid":e["metadata"]["uid"],"log_source":"fixture"},"src_endpoint":{"ip":"192.0.2.1","location":{"country":null},"autonomous_system":{"number":null}},"enrichments":e["enrichments"]}).to_string()).collect::<Vec<_>>();
    std::fs::write(&path, rows.join("\n")).unwrap();
    let schema = "time DateTime64(6,'UTC'), metadata Tuple(uid String,log_source String), src_endpoint Tuple(ip String,location Tuple(country Nullable(String)),autonomous_system Tuple(number Nullable(UInt32))), enrichments Array(Tuple(name String,value String,type String,provider String,data Tuple(contract_version UInt16,feed_id String,feed_class String,feed_revision_id Int64,valid_until String,status String,owned_fields Array(String),country_name Nullable(String),threat_type Nullable(String),malware Nullable(String),confidence_level Nullable(Int64),is_tor Nullable(Bool),vpn Nullable(Bool),premium Tuple(tier Nullable(String),grant_revision Nullable(Int64),entitlement_revision Nullable(Int64)))))";
    connection.query_with_params("INSERT INTO FUNCTION file({parquet:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})", "JSONEachRow", &[("parquet",parquet.to_str().unwrap()),("input",path.to_str().unwrap()),("schema",schema)]).unwrap();
    let fields: BTreeMap<String, String> = [
        ("time", "timestamp"),
        ("metadata.uid", "string"),
        ("metadata.log_source", "string"),
        ("src_endpoint.ip", "ip_address"),
        ("src_endpoint.location.country", "string"),
        ("src_endpoint.autonomous_system.number", "integer"),
        ("enrichments.name", "array"),
        ("enrichments.value", "array"),
        ("enrichments.provider", "array"),
        ("enrichments.type", "array"),
        ("enrichments.data.contract_version", "array"),
        ("enrichments.data.feed_id", "array"),
        ("enrichments.data.feed_class", "array"),
        ("enrichments.data.feed_revision_id", "array"),
        ("enrichments.data.valid_until", "array"),
        ("enrichments.data.status", "array"),
        ("enrichments.data.owned_fields", "array"),
        ("enrichments.data.country_name", "array"),
        ("enrichments.data.threat_type", "array"),
        ("enrichments.data.malware", "array"),
        ("enrichments.data.confidence_level", "array"),
        ("enrichments.data.is_tor", "array"),
        ("enrichments.data.vpn", "array"),
        ("enrichments.data.premium.tier", "array"),
        ("enrichments.data.premium.grant_revision", "array"),
        ("enrichments.data.premium.entitlement_revision", "array"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    let key = "s3://fixture/table/data/events.parquet";
    let tenant_id = Uuid::from_u128(1).to_string();
    let bytes = std::fs::metadata(&parquet).unwrap().len();
    let tenant = TenantQueryConfig {
        tenant_id: tenant_id.clone(),
        source: "https://object.test/fixture/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(),
        max_query_bytes: 100_000_000,
        max_memory_bytes: 1_000_000_000,
        max_execution_seconds: 30,
        threads: 2,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache {
            source_spec: parquet.to_str().unwrap().into(),
            objects: BTreeMap::from([(
                key.into(),
                SnapshotCacheObject {
                    version_id: "v1".into(),
                    bytes,
                    path: parquet.clone(),
                },
            )]),
            bytes,
            read_schema: Some(schema.into()),
            bootstrap: false,
        }),
    };
    let manifest: SourceManifest = serde_json::from_value(json!({"tenant_id":tenant_id,"objects":[{"event_object_key":key,"event_object_version":"v1","event_object_bytes":bytes,"rows":2,"available_paths":fields.keys().collect::<Vec<_>>(),"field_types":fields}]})).unwrap();

    eprintln!("NAN2469_NATIVE_SEARCH_BEGIN");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (query, expected) in [
        ("* | stats count", 2),
        ("src_is_tor=true | stats count", 1),
        ("metadata.uid=old src_is_tor=true | stats count", 1),
        ("metadata.uid=old ioc_src_ip_malware=alpha | stats count", 1),
        ("src_is_tor=false | stats count", 1),
        (
            "ioc_src_ip_malware=alpha ioc_src_ip_confidence=40 | stats count",
            1,
        ),
        (
            "ioc_src_ip_malware=alpha ioc_src_ip_confidence=90 | stats count",
            0,
        ),
        ("ioc_src_ip_malware=beta | stats count", 0),
        ("ioc_domain_malware=domain | stats count", 1),
        ("* | eval tor=src_is_tor | where tor=true | stats count", 1),
    ] {
        let compiled = compile(query, &fields).unwrap();
        assert!(!compiled.sql.contains("JOIN"));
        let plan = rt.block_on(async { plan_broad_log_query(&tenant, &manifest, &compiled).unwrap() });
        let params = plan
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>();
        let output = connection
            .query_with_params(&plan.sql, "JSONEachRow", &params)
            .unwrap();
        let row: Value = serde_json::from_slice(&output.data).unwrap();
        assert_eq!(row["count"], expected, "{query}: {row}");
    }
    let compiled = compile("* | stats count by src_is_tor", &fields).unwrap();
    let plan = rt.block_on(async { plan_broad_log_query(&tenant, &manifest, &compiled).unwrap() });
    let params = plan
        .params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect::<Vec<_>>();
    let output = connection
        .query_with_params(&plan.sql, "JSONEachRow", &params)
        .unwrap();
    let groups = String::from_utf8(output.data.to_vec())
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(groups.len(), 2);
    assert_eq!(
        groups
            .iter()
            .map(|g| g["count"].as_u64().unwrap())
            .sum::<u64>(),
        2
    );
    eprintln!("NAN2469_NATIVE_SEARCH_END");
    assert_eq!(
        before,
        nanosiem_core::platform_enrichment::read::audit::counts(),
        "search called feed reader/matcher"
    );
}

#[test]
fn free_verdict_freshness_expiry_and_missing_are_ocsf_valid() {
    let mut f = Fixture::new();
    f.install(
        "tor_exit_nodes",
        1,
        tor(b"192.0.2.1\n").unwrap(),
        Duration::hours(7),
    );
    f.install(
        "threatfox",
        1,
        export(
            &[(1, "192.0.2.1:443", "ip:port", "short", 80)],
            Utc::now() + Duration::hours(1),
        ),
        Duration::hours(7),
    );
    let old = f.stamp("stale", event());
    let data = |e: &Value, feed: &str, subject: &str| {
        e["enrichments"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["provider"] == format!("platform/{feed}") && r["name"] == subject)
            .unwrap()["data"]
            .clone()
    };
    assert_eq!(
        data(&old, "tor_exit_nodes", "src_endpoint.ip")["is_tor"],
        true
    );
    assert_eq!(
        data(&old, "tor_exit_nodes", "src_endpoint.ip")["freshness_at_ingest"],
        "stale"
    );
    // NAN-2554: a stale-but-unexpired snapshot still proves absence. The
    // decision is served as `no_match` and the staleness travels with the
    // stamp in `freshness_at_ingest`, rather than being erased as `unknown`.
    assert_eq!(
        data(&old, "tor_exit_nodes", "dst_endpoint.ip")["status"],
        "no_match"
    );
    assert_eq!(
        data(&old, "tor_exit_nodes", "dst_endpoint.ip")["freshness_at_ingest"],
        "stale"
    );
    assert_eq!(
        data(&old, "tor_exit_nodes", "dst_endpoint.ip")["is_tor"],
        false
    );
    assert_eq!(
        data(&old, "threatfox", "src_endpoint.ip")["status"],
        "match"
    );
    f.claim.vector.admitted_at += Duration::hours(2);
    *f.journal.1.lock().unwrap() = f.claim.clone();
    let expired = f.stamp("individual-expiry", event());
    // NAN-2554: the individual IOC expired, so the indicator genuinely does not
    // match. The snapshot is stale but well inside `hard_expiry_seconds`, so
    // that absence is recorded rather than erased.
    assert_eq!(
        data(&expired, "threatfox", "src_endpoint.ip")["status"],
        "no_match"
    );
    assert_eq!(
        data(&expired, "threatfox", "src_endpoint.ip")["freshness_at_ingest"],
        "stale"
    );
    f.claim.vector.admitted_at += Duration::hours(24);
    *f.journal.1.lock().unwrap() = f.claim.clone();
    let hard = f.stamp("hard-expiry", event());
    assert_eq!(
        data(&hard, "tor_exit_nodes", "src_endpoint.ip")["reason"],
        "expired"
    );
    f.claim.vector.admitted_at -= Duration::hours(26);
    *f.journal.1.lock().unwrap() = f.claim.clone();
    f.ready.clear();
    let missing = f.stamp("missing", event());
    assert_eq!(
        data(&missing, "tor_exit_nodes", "src_endpoint.ip")["reason"],
        "missing"
    );
    assert_eq!(f.stamp("stale", event()), old);
    let mut fresh = Fixture::new();
    fresh.install(
        "threatfox",
        1,
        export(
            &[(1, "192.0.2.1:443", "ip:port", "short", 80)],
            Utc::now() + Duration::seconds(30),
        ),
        Duration::zero(),
    );
    fresh.claim.vector.admitted_at += Duration::minutes(1);
    *fresh.journal.1.lock().unwrap() = fresh.claim.clone();
    let expired_fresh = fresh.stamp("fresh-individual-expiry", event());
    assert_eq!(
        data(&expired_fresh, "threatfox", "src_endpoint.ip")["status"],
        "no_match"
    );
    let mut corrupt = Fixture::new();
    let mut artifact = export(
        &[(1, "192.0.2.1:443", "ip:port", "invalid-expiry", 80)],
        Utc::now() + Duration::hours(1),
    );
    let value_offset = u64::from_le_bytes(artifact.bytes[56..64].try_into().unwrap()) as usize;
    artifact.bytes[value_offset + 12..value_offset + 20].copy_from_slice(&i64::MAX.to_le_bytes());
    corrupt.install("threatfox", 1, artifact, Duration::zero());
    let refused = corrupt.stamp("unrepresentable-expiry", event());
    assert_eq!(
        data(&refused, "threatfox", "src_endpoint.ip")["reason"],
        "unavailable"
    );
}
