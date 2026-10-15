#![cfg(all(
    feature = "enterprise",
    feature = "enrichment-read-audit",
    target_os = "linux"
))]
// SPDX-License-Identifier: AGPL-3.0-or-later
use chrono::{Duration, Utc};
use nanosiem_core::platform_enrichment::read::ReadAuthorization;
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
use nanosiem_core::platform_enrichment::{
    adapters::{synthient, Artifact},
    AdmissionDecision, StampReason,
};
fn artifact() -> Artifact {
    let a = synthient::convert(
        include_bytes!("../../nanosiem-core/tests/fixtures/synthient/sanitized.jsonl").as_slice(),
    )
    .unwrap();
    Artifact {
        bytes: std::fs::read(a.file.path()).unwrap(),
        rows: a.rows,
        adapter: "packed-prefix/1",
    }
}
fn data(event: &Value, subject: &str) -> Value {
    event["enrichments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["provider"] == "platform/synthient" && r["name"] == subject)
        .unwrap()["data"]
        .clone()
}
#[test]
fn synthient_native_two_tenants_shared_bytes_rotation_and_masked_export() {
    let now = Utc::now();
    let mut f = Fixture::new();
    f.install("synthient", 1, artifact(), Duration::zero());
    let old = f.stamp("old", event());
    assert_eq!(data(&old, "src_endpoint.ip")["vpn"], false);
    assert_eq!(data(&old, "src_endpoint.ip")["proxy"], true);
    assert_eq!(data(&old, "src_endpoint.ip")["residential_proxy"], true);
    assert!(data(&old, "src_endpoint.ip")["bot"].is_null());
    assert_eq!(data(&old, "src_endpoint.ip")["scope"], "exact");
    assert_eq!(data(&old, "src_endpoint.ip")["confidence_level"], 95);
    assert_eq!(data(&old, "dst_endpoint.ip")["bot"], true);
    assert_eq!(data(&old, "dst_endpoint.ip")["scope"], "prefix");
    assert_eq!(
        data(&old, "src_endpoint.ip")["premium"]["grant_revision"],
        1
    );
    let mut next = artifact();
    // Deterministic full replacement removes every old network.
    let empty = synthient::convert(
        b"{\"schema\":\"nano-synthient-fixture/1\",\"rows\":0,\"complete\":true}\n".as_slice(),
    )
    .unwrap();
    next.bytes = std::fs::read(empty.file.path()).unwrap();
    next.rows = 0;
    f.install("synthient", 2, next, Duration::zero());
    let new = f.stamp("new", event());
    assert_eq!(data(&new, "src_endpoint.ip")["status"], "unknown");
    f.ready.retain(|(v, _)| v.name().starts_with("synthient-2-"));
    let replay_counts = nanosiem_core::platform_enrichment::read::audit::counts();
    assert_eq!(f.stamp("old", event()), old, "old admission was restamped");
    assert_eq!(replay_counts, nanosiem_core::platform_enrichment::read::audit::counts());
    let before = nanosiem_core::platform_enrichment::read::audit::counts();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[]).unwrap();
    let mut revisions = Vec::new();
    for feed in ["synthient"] {
        for rev in [1, 2] {
            revisions.push(AuthorizedRevision {
                tenant_id: Uuid::from_u128(1),
                reference: RevisionReference {
                    feed_id: feed.into(),
                    feed_revision: rev,
                    tier: "sandbox".into(),
                    grant_revision: 1,
                    entitlement_revision: 1,
                },
                class: FeedClass::Premium,
                digest: "ab".repeat(32),
                mapping_revision: 1,
                deny_epoch: 0,
                valid_until: now + Duration::hours(1),
                evaluated_at: now,
            });
        }
    }
    let authority = ReadAuthorization::from_resolved(Uuid::from_u128(1), now, &revisions);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let parquet = dir.path().join("events.parquet");
    let rows=[old,new].into_iter().map(|e|json!({"time":"2026-08-07 12:00:00","metadata":{"uid":e["metadata"]["uid"],"log_source":"fixture"},"src_endpoint":{"ip":"192.0.2.1","location":{"country":null},"autonomous_system":{"number":null}},"enrichments":e["enrichments"]}).to_string()).collect::<Vec<_>>();
    std::fs::write(&path, rows.join("\n")).unwrap();
    let schema = "time DateTime64(6,'UTC'), metadata Tuple(uid String,log_source String), src_endpoint Tuple(ip String,location Tuple(country Nullable(String)),autonomous_system Tuple(number Nullable(UInt32))), enrichments Array(Tuple(name String,value String,type String,provider String,data Tuple(contract_version UInt16,feed_id String,feed_class String,feed_revision_id Int64,valid_until String,status String,owned_fields Array(String),country_name Nullable(String),threat_type Nullable(String),malware Nullable(String),confidence_level Nullable(Int64),is_tor Nullable(Bool),vpn Nullable(Bool),proxy Nullable(Bool),residential_proxy Nullable(Bool),bot Nullable(Bool),premium Tuple(tier Nullable(String),grant_revision Nullable(Int64),entitlement_revision Nullable(Int64)))))";
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
        ("enrichments.data.proxy", "array"),
        ("enrichments.data.residential_proxy", "array"),
        ("enrichments.data.bot", "array"),
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
    let mut manifest: SourceManifest = serde_json::from_value(json!({"tenant_id":tenant_id,"objects":[{"event_object_key":key,"event_object_version":"v1","event_object_bytes":bytes,"rows":2,"available_paths":fields.keys().collect::<Vec<_>>(),"field_types":fields}]})).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Identical local artifact handles remain loaded for both tenants. Rights
    // come from each tenant's read context, not those handles or stored stamps.
    for (auth, expected) in [
        (authority.clone(), 1),
        (ReadAuthorization::unknown(Uuid::from_u128(2), now), 0),
    ] {
        let mut config = tenant.clone();
        config.tenant_id = serde_json::to_value(&auth).unwrap()["tenant_id"]
            .as_str()
            .unwrap()
            .to_owned();
        manifest.tenant_id = config.tenant_id.clone();
        let scoped = &manifest;
        for query in [
            "synthient_src_proxy=true | stats count",
            "synthient_src_vpn=false | stats count",
            "synthient_dest_bot=true | stats count",
        ] {
            let compiled = compile(query, &fields).unwrap();
            let plan = rt.block_on(nanosiem_lake_worker::enrichment_read::scope(
                auth.clone(),
                async { plan_broad_log_query(&config, &scoped, &compiled).unwrap() },
            ));
            let params = plan
                .params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>();
            let result = connection
                .query_with_params(&plan.sql, "JSONEachRow", &params)
                .unwrap();
            let row: Value = serde_json::from_slice(&result.data).unwrap();
            assert_eq!(row["count"], expected, "{query}: {row}");
        }
        let compiled = compile("* | table synthient_src_proxy, enrichments.provider, enrichments.data.proxy", &fields).unwrap();
        let mut plan = rt.block_on(nanosiem_lake_worker::enrichment_read::scope(
            auth.clone(),
            async { plan_broad_log_query(&config, &scoped, &compiled).unwrap() },
        ));
        let export = dir.path().join(format!("export-{expected}.parquet"));
        plan.params
            .push(("export".into(), export.to_str().unwrap().into()));
        plan.sql = format!(
            "INSERT INTO FUNCTION file({{export:String}}, Parquet) {}",
            plan.sql
        );
        let params = plan
            .params
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect::<Vec<_>>();
        connection
            .query_with_params(&plan.sql, "JSONEachRow", &params)
            .unwrap();
        let result = connection
            .query_with_params(
                "SELECT * FROM file({export:String}, Parquet)",
                "JSONEachRow",
                &[("export", export.to_str().unwrap())],
            )
            .unwrap();
        let text = String::from_utf8(result.data.to_vec()).unwrap();
        let exported = text.lines().map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
        assert_eq!(exported.len(), 2);
        let providers = |row: &Value| row.get("enrichments.provider").unwrap().as_array().unwrap().clone();
        if expected == 0 {
            for row in &exported {
                assert!(providers(row).is_empty(), "generic export leaked denied tags: {row}");
                assert!(row.get("synthient_src_proxy").unwrap().is_null());
                assert_eq!(row.get("enrichments.data.proxy").unwrap(), &json!([]));
            }
        } else {
            assert!(exported.iter().any(|row| providers(row).contains(&json!("platform/synthient"))), "authorized export lost tags: {text}");
        }
    }
    assert_eq!(
        before,
        nanosiem_core::platform_enrichment::read::audit::counts()
    );
}
#[test]
fn synthient_missing_expired_disabled_unknown_and_prefix_verdicts() {
    let mut f = Fixture::new();
    f.install("synthient", 1, artifact(), Duration::zero());
    for (ip, status, vpn) in [
        ("192.0.2.55", "match", json!(true)),
        ("198.51.100.1", "no_match", json!(false)),
        ("203.0.113.1", "unknown", Value::Null),
        ("198.51.100.2", "unknown", Value::Null),
    ] {
        let mut e = event();
        e["src_endpoint"]["ip"] = json!(ip);
        let d = data(&f.stamp(ip, e), "src_endpoint.ip");
        assert_eq!(d["status"], status);
        assert_eq!(d["vpn"], vpn);
    }
    // NAN-2554: keep serving the last good snapshot. A stale-but-unexpired
    // observation retains both its positive and its negative verdicts; the
    // staleness travels with the stamp in `freshness_at_ingest` so a consumer
    // that needs a freshness guarantee can filter on it.
    f.claim.feed_times.get_mut("synthient").unwrap().upstream_at =
        Some(f.claim.vector.admitted_at - Duration::hours(7));
    *f.journal.1.lock().unwrap() = f.claim.clone();
    let stale = data(&f.stamp("stale", event()), "src_endpoint.ip");
    assert_eq!(stale["proxy"], true);
    assert_eq!(stale["vpn"], false);
    assert_eq!(stale["freshness_at_ingest"], "stale");
    f.claim.feed_times.get_mut("synthient").unwrap().valid_until =
        Some(f.claim.vector.admitted_at - Duration::seconds(1));
    *f.journal.1.lock().unwrap() = f.claim.clone();
    assert_eq!(
        data(&f.stamp("expired-license", event()), "src_endpoint.ip")["reason"],
        "expired"
    );
    f.claim.feed_times.get_mut("synthient").unwrap().valid_until =
        Some(f.claim.vector.admitted_at + Duration::hours(1));
    let feed = f
        .claim
        .vector
        .feeds
        .iter_mut()
        .find(|f| f.feed_id == "synthient")
        .unwrap();
    let selected = feed.decision.clone();
    feed.decision = AdmissionDecision::Unknown {
        reason: StampReason::Disabled,
        artifact: None,
        right: None,
    };
    *f.journal.1.lock().unwrap() = f.claim.clone();
    let before = nanosiem_core::platform_enrichment::read::audit::counts();
    assert_eq!(
        data(&f.stamp("disabled-tenant", event()), "src_endpoint.ip")["reason"],
        "disabled"
    );
    assert_eq!(
        before,
        nanosiem_core::platform_enrichment::read::audit::counts()
    );
    f.claim
        .vector
        .feeds
        .iter_mut()
        .find(|f| f.feed_id == "synthient")
        .unwrap()
        .decision = selected;
    *f.journal.1.lock().unwrap() = f.claim.clone();
    f.ready.clear();
    assert_eq!(
        data(&f.stamp("missing-artifact", event()), "src_endpoint.ip")["reason"],
        "missing"
    );
}
