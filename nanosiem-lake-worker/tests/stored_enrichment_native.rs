// SPDX-License-Identifier: AGPL-3.0-or-later
// Native-lane only, like free_feed_native / synthient_native: needs a
// digest-verified chDB (NANO_CHDB_LIBRARY_PATH / _SHA256) and runs with
// `--features enterprise,enrichment-read-audit`. Without the gate the default
// workspace run fails on the missing library instead of testing anything.
#![cfg(all(
    feature = "enterprise",
    feature = "enrichment-read-audit",
    target_os = "linux"
))]
use chrono::{Duration, Utc};
use nanosiem_core::platform_enrichment::read::ReadAuthorization;
use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};
use nanosiem_lake_worker::enrichment_read::root_expression;
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

fn planner_walk(
    connection: &nanosiem_lake_worker::native::NativeConnection,
    executor: &nanosiem_lake_worker::executor::NativeExecutor,
    authority: &ReadAuthorization,
    revisions: &[AuthorizedRevision],
    dir: &std::path::Path,
) {
    let path = dir.join("planner-events.jsonl");
    let parquet = dir.join("planner-events.parquet");
    let now = Utc::now();
    let record = |revision: i64, until: chrono::DateTime<Utc>| json!({"name":"src_endpoint.ip","value":"8.8.8.8","type":"geoip","provider":"platform/ipinfo_lite","data":{"contract_version":1,"feed_id":"ipinfo_lite","feed_class":"baseline","feed_revision_id":revision,"valid_until":until.to_rfc3339(),"status":"match","owned_fields":["src_endpoint.location.country"],"country_name":"United States"}});
    let mut rows = Vec::new();
    // Known revision, ungranted revision, expired ownership, then old data.
    for (i, mut records) in [
        vec![record(1, now + Duration::minutes(5))],
        vec![record(2, now + Duration::minutes(1))],
        vec![record(1, now - Duration::seconds(1))],
        vec![],
    ]
    .into_iter()
    .enumerate()
    {
        if i == 0 {
            for (provider, subject, payload, status, premium) in [
                (
                    "threatfox",
                    "dst_endpoint.ip",
                    json!({"threat_type":"benign","malware":"other","confidence_level":90}),
                    "match",
                    false,
                ),
                (
                    "threatfox",
                    "src_endpoint.ip",
                    json!({"threat_type":"malware","malware":"sample","confidence_level":40}),
                    "match",
                    false,
                ),
                (
                    "tor_exit_nodes",
                    "src_endpoint.ip",
                    json!({"is_tor":false}),
                    "no_match",
                    false,
                ),
                (
                    "synthient",
                    "src_endpoint.ip",
                    json!({"vpn":true}),
                    "match",
                    true,
                ),
            ] {
                let mut item = record(1, now + Duration::minutes(5));
                item["name"] = json!(subject);
                item["provider"] = json!(format!("platform/{provider}"));
                item["data"]["feed_id"] = json!(provider);
                item["data"]["status"] = json!(status);
                item["data"]["owned_fields"] = json!([]);
                item["data"]
                    .as_object_mut()
                    .unwrap()
                    .extend(payload.as_object().unwrap().clone());
                if premium {
                    item["data"]["feed_class"] = json!("premium");
                    item["data"]["premium"] =
                        json!({"tier":"premium","grant_revision":1,"entitlement_revision":1});
                }
                records.push(item);
            }
        }
        rows.push(json!({"time":"2026-08-07 12:00:00","metadata":{"uid":format!("event-{i}"),"log_source":"fixture"},"src_endpoint":{"ip":"8.8.8.8","location":{"country":"US"},"autonomous_system":{"number":64512}},"enrichments":records}).to_string());
    }
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
    let manifest: SourceManifest = serde_json::from_value(json!({"tenant_id":tenant_id,"objects":[{"event_object_key":key,"event_object_version":"v1","event_object_bytes":bytes,"rows":4,"available_paths":fields.keys().collect::<Vec<_>>(),"field_types":fields}]})).unwrap();
    assert!(compile("synthient_src_vpp=true | stats count", &fields).is_err());
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for (context, expected) in [
        (authority.clone(), 2),
        (ReadAuthorization::unknown(Uuid::from_u128(1), now), 1),
    ] {
        for query in [
            "enriched_src_country_code=US | stats count",
            "* | eval country=enriched_src_country_code | where country=US | stats count",
            // NAN-2499: native producer IP and masked country share a physical
            // root. Predicate pushdown must preserve the mask and read header.
            "src_endpoint.ip=8.8.8.8 enriched_src_country_code=US | stats count by src_endpoint.ip",
        ] {
            let compiled = compile(query, &fields).unwrap();
            assert!(!compiled.sql.contains("JOIN"));
            let plan = rt.block_on(nanosiem_lake_worker::enrichment_read::scope(
                context.clone(),
                async { plan_broad_log_query(&tenant, &manifest, &compiled).unwrap() },
            ));
            let params = plan
                .params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>();
            let output = connection
                .query_with_params(&plan.sql, "JSONEachRow", &params)
                .unwrap();
            let row: Value = serde_json::from_slice(&output.data).unwrap();
            assert_eq!(row["count"], expected, "{query}: {}", plan.sql);
        }
        for (query, matches) in [
            ("ioc_src_ip_threat_type=malware | stats count", 1),
            (
                "ioc_src_ip_malware=sample ioc_src_ip_confidence=40 | stats count",
                1,
            ),
            ("ioc_src_ip_malware=other | stats count", 0),
            ("ioc_src_ip_threat_type=benign | stats count", 0),
            ("ioc_dest_ip_threat_type=benign | stats count", 1),
            ("synthient_src_vpn=true | stats count", 1),
            ("src_is_tor=false | stats count", 1),
        ] {
            let compiled = compile(query, &fields).unwrap();
            let plan = rt.block_on(nanosiem_lake_worker::enrichment_read::scope(
                context.clone(),
                async { plan_broad_log_query(&tenant, &manifest, &compiled).unwrap() },
            ));
            let params = plan
                .params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>();
            let output = connection
                .query_with_params(&plan.sql, "JSONEachRow", &params)
                .unwrap();
            let row: Value = serde_json::from_slice(&output.data).unwrap();
            assert_eq!(
                row["count"],
                if expected == 2 { matches } else { 0 },
                "{query}: {}",
                plan.sql
            );
        }
        for query in [
            "* | sort -time | head 10",
            "* | table enriched_src_country, enriched_src_country_code, enriched_src_asn",
            "* | stats count by enriched_src_country_code",
            "* | table synthient_src_vpn, ioc_src_ip_threat_type, src_is_tor",
            "* | table enrichments.data.country_name",
        ] {
            let compiled = compile(query, &fields).unwrap();
            let plan = rt.block_on(nanosiem_lake_worker::enrichment_read::scope(
                context.clone(),
                async { plan_broad_log_query(&tenant, &manifest, &compiled).unwrap() },
            ));
            let params = plan
                .params
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>();
            let output = connection
                .query_with_params(&plan.sql, "JSONEachRow", &params)
                .unwrap();
            assert!(!output.data.is_empty(), "{query}");
        }
    }
    // One real native query over all four rows proves masking before return:
    // valid stamp visible, denied revision and expired stamp masked, producer intact.
    rt.block_on(nanosiem_lake_worker::enrichment_read::scope(authority.clone(), async {
        let compiled = compile("* | sort -time | head 10", &fields).unwrap();
        let plan = plan_broad_log_query(&tenant, &manifest, &compiled).unwrap();
        let completed = executor.status().completed;
        let output = executor.execute(plan).await.unwrap();
        assert_eq!(executor.status().completed - completed, 1, "exactly one chDB query");
        let rows = String::from_utf8(output.data).unwrap().lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
        assert_eq!(rows.len(), 4);
        for row in rows {
            let id = row["metadata"]["uid"].as_str().unwrap();
            let country = &row["src_endpoint"]["location"]["country"];
            match id {
                "event-0" => { assert_eq!(country, "US"); assert!(!row["enrichments"].as_array().unwrap().is_empty()); }
                "event-1" | "event-2" => { assert!(country.is_null(), "{row}"); assert_eq!(row["enrichments"], json!([])); }
                "event-3" => assert_eq!(country, "US"),
                _ => panic!("unexpected row {row}"),
            }
        }
    }));
    // Exercise the dedicated event-detail and field-stat planners, plus the
    // durable export INSERT shape, through the actual native executor.
    for (context, visible) in [
        (authority.clone(), true),
        (ReadAuthorization::unknown(Uuid::from_u128(1), now), false),
    ] {
        rt.block_on(nanosiem_lake_worker::enrichment_read::scope(context,async {
            use nanosiem_lake_worker::planner::*;
            let deny = Default::default();
            let plan = plan_fetch_log(&tenant,&manifest,&FetchLogPlanRequest{
                event_id:"event-0",start:None,end:None,log_source:None,deny_source_types:&deny,
            }).unwrap();
            let result=executor.execute(plan).await.unwrap();
            let row:Value=serde_json::from_slice(&result.data).unwrap();
            assert_eq!(row["src_endpoint"]["location"]["country"],if visible { json!("US") } else { Value::Null });
            assert_eq!(row["src_endpoint"]["autonomous_system"]["number"],64512);
            let start=chrono::DateTime::parse_from_rfc3339("2026-08-07T00:00:00Z").unwrap().timestamp_micros();
            let plan=plan_count_aggregate_query(&tenant,&manifest,&CountAggregatePlanRequest{
                group_field:"src_endpoint.location.country",group_results:true,multi_value:false,predicate:None,
                bucket_span_us:None,start_us:start,end_exclusive_us:start+86_400_000_000,
                source_filter:None,deny_source_types:&deny,source:CountAggregateSource::Base,group_by_source:false,
            }).unwrap().unwrap();
            let result=executor.execute(plan).await.unwrap();
            let text=String::from_utf8(result.data).unwrap();
            assert!(text.contains("US"),"producer country must remain in field stats: {text}");
            let compiled=compile("* | sort -time | head 10",&fields).unwrap();
            let mut plan=plan_broad_log_query(&tenant,&manifest,&compiled).unwrap();
            let export=dir.join(format!("export-{visible}.parquet"));
            plan.params.push(("fixture_export".into(),export.to_str().unwrap().into()));
            plan.sql=format!("INSERT INTO FUNCTION file({{fixture_export:String}}, Parquet) {}",plan.sql);
            executor.execute(plan).await.unwrap();
            let result=connection.query_with_params("SELECT count() AS n FROM file({path:String},Parquet) WHERE src_endpoint.location.country='US'","JSONEachRow",&[("path",export.to_str().unwrap())]).unwrap();
            let row:Value=serde_json::from_slice(&result.data).unwrap();
            assert_eq!(row["n"],if visible {2} else {1});
        }));
    }
    let compiled = compile("enriched_src_country_code=US | stats count", &fields).unwrap();
    let tenant_uuid = Uuid::from_u128(1);
    let key = format!("{}:count", authority.cache_identity());
    let resolver =
        || async { ReadAuthorization::from_resolved(tenant_uuid, Utc::now(), revisions) };
    let fresh: Value = rt
        .block_on(nanosiem_lake_worker::enrichment_read::execute(
            resolver,
            async {
                let plan = plan_broad_log_query(&tenant, &manifest, &compiled).unwrap();
                let output = executor.execute(plan).await.unwrap();
                let row: Value = serde_json::from_slice(&output.data).unwrap();
                row
            },
        ))
        .unwrap();
    assert_eq!(fresh["count"], 2);
    let (_, report_fence) = rt.block_on(
        nanosiem_core::platform_enrichment::read::capture_result_fence(async {
            let fence = authority.fence(None);
            tokio::spawn(
                nanosiem_core::platform_enrichment::read::inherit_result_fence(async move {
                    nanosiem_core::platform_enrichment::read::record_result_fence(Some(fence));
                }),
            )
            .await
            .unwrap();
            let (csv, truncated) = nanosiem_core::reports::render::render_csv(
                &[fresh.clone()],
                &["count".into()],
                1024,
            );
            assert!(!truncated);
            assert!(String::from_utf8(csv).unwrap().contains('2'));
        }),
    );
    assert_eq!(
        report_fence.unwrap().authority_sha256,
        authority.cache_identity()
    );

    // A deny at dispatch selects a different cache identity.
    rt.block_on(nanosiem_lake_worker::enrichment_read::execute(
        || async { ReadAuthorization::unknown(tenant_uuid, Utc::now()) },
        async {
            let denied_key = format!(
                "{}:count",
                nanosiem_lake_worker::enrichment_read::current().cache_identity()
            );
            assert_ne!(denied_key, key);
        },
    ))
    .unwrap();
    // Dispatch resolves once; nested reads/commit checks inherit that snapshot.
    // Metadata changes are observed on the next request, not a second resolve
    // that can turn a transient PG failure into an in-flight identity mismatch.
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let result = rt.block_on(nanosiem_lake_worker::enrichment_read::execute(
        || async {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            ReadAuthorization::from_resolved(tenant_uuid, Utc::now(), revisions)
        },
        async {
            nanosiem_lake_worker::enrichment_read::execute(
                || async { panic!("nested read must inherit dispatch authority") },
                async {
                    nanosiem_lake_worker::enrichment_read::validate_return(&tenant_id).await.unwrap();
                },
            ).await.unwrap()
        },
    ));
    result.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    // A window containing ONLY aged platform stamps succeeds. Exercise both
    // native event roots and flat leaf projections through the real executor.
    std::fs::write(&path, &rows[2]).unwrap();
    std::fs::remove_file(&parquet).unwrap();
    connection.query_with_params("INSERT INTO FUNCTION file({parquet:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})", "JSONEachRow", &[("parquet",parquet.to_str().unwrap()),("input",path.to_str().unwrap()),("schema",schema)]).unwrap();
    for query in ["* | sort -time | head 10", "* | table enriched_src_country, enriched_src_country_code"] {
        let aged = compile(query, &fields).unwrap();
        rt.block_on(nanosiem_lake_worker::enrichment_read::execute(resolver, async {
            let plan = plan_broad_log_query(&tenant, &manifest, &aged).unwrap();
            let output = executor.execute(plan).await.unwrap();
            let row: Value = serde_json::from_slice(&output.data).unwrap();
            if query.contains("table") {
                assert_eq!(row.get("enriched_src_country"), Some(&Value::Null), "{row}");
                assert_eq!(row.get("src_endpoint.location.country"), Some(&Value::Null), "{row}");
            } else {
                assert!(row["src_endpoint"]["location"]["country"].is_null(), "{row}");
                assert_eq!(row["enrichments"], json!([]));
            }
        })).unwrap();
    }

    // Actual stored-stamp expiry while the native engine is executing. Only
    // fixture setup replaces this local object, before creating the plan.
    let deadline = Utc::now() + Duration::seconds(1);
    let mut expiring: Value = serde_json::from_str(&rows[0]).unwrap();
    expiring["enrichments"][0]["data"]["valid_until"] = json!(deadline.to_rfc3339());
    std::fs::write(&path, expiring.to_string()).unwrap();
    std::fs::remove_file(&parquet).unwrap();
    connection.query_with_params("INSERT INTO FUNCTION file({parquet:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})", "JSONEachRow", &[("parquet",parquet.to_str().unwrap()),("input",path.to_str().unwrap()),("schema",schema)]).unwrap();
    let result = rt.block_on(nanosiem_lake_worker::enrichment_read::execute(
        resolver,
        async {
            let mut plan = plan_broad_log_query(&tenant, &manifest, &compiled).unwrap();
            plan.sql = plan
                .sql
                .replace("count() AS count", "(count()+sleep(1.5)) AS count");
            assert!(plan.sql.contains("sleep(1.5)"));
            executor.execute(plan).await
        },
    ));
    let output = result.unwrap().unwrap();
    let row: Value = serde_json::from_slice(&output.data).unwrap();
    assert_eq!(row["count"], 1, "validity is frozen at dispatch, not execution wall time");
}

#[test]
fn stored_enrichment_native_scan_masks_before_operations() {
    assert!(
        cfg!(feature = "enrichment-read-audit"),
        "artifact/lookup instrumentation is required"
    );
    #[cfg(feature = "enrichment-read-audit")]
    let before = nanosiem_core::platform_enrichment::read::audit::counts();
    #[cfg(feature = "enrichment-read-audit")]
    assert_eq!(before, (0, 0));
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("real native library required"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("verified digest required"),
    )
    .unwrap();
    // chDB has process-lifetime background threads. Keep its code mapped even
    // when an assertion unwinds, as the production worker does until exit.
    std::mem::forget(runtime.clone());
    let connection = runtime.connect(&[]).unwrap();
    let executor =
        nanosiem_lake_worker::executor::NativeExecutor::start(runtime.clone(), 1).unwrap();
    let tenant = Uuid::from_u128(1);
    let now = Utc::now();
    let revision = AuthorizedRevision {
        tenant_id: tenant,
        reference: RevisionReference {
            feed_id: "ipinfo_lite".into(),
            feed_revision: 1,
            tier: "included".into(),
            grant_revision: 1,
            entitlement_revision: 1,
        },
        class: FeedClass::Baseline,
        digest: "ab".repeat(32),
        mapping_revision: 1,
        deny_epoch: 1,
        valid_until: now + Duration::hours(1),
        evaluated_at: now,
    };
    let mut revisions = vec![revision.clone()];
    for feed in ["threatfox", "tor_exit_nodes", "synthient"] {
        let mut extra = revision.clone();
        extra.reference.feed_id = feed.into();
        if feed == "synthient" {
            extra.class = FeedClass::Premium;
            extra.reference.tier = "premium".into();
        }
        revisions.push(extra);
    }
    let allowed = ReadAuthorization::from_resolved(tenant, now, &revisions);
    let overflow = ReadAuthorization::from_resolved(tenant, now, &vec![revision.clone(); 65]);
    assert!(serde_json::to_value(overflow).unwrap()["rights"]
        .as_array()
        .unwrap()
        .is_empty());
    let historical_time = now - Duration::minutes(2);
    let mut expired_right = revision.clone();
    expired_right.evaluated_at = historical_time;
    expired_right.valid_until = now - Duration::minutes(1);
    let historical = ReadAuthorization::from_resolved(tenant, historical_time, &[expired_right.clone()]);
    let expired_grant = ReadAuthorization::from_resolved(tenant, now, &[expired_right]);
    assert!(
        !historical.may_return(&historical, None),
        "metadata evaluation time cannot extend an expired right at return"
    );

    let denied = ReadAuthorization::unknown(tenant, now);
    let foreign = ReadAuthorization::from_resolved(Uuid::from_u128(2), now, &[revision.clone()]);
    let stamp = json!({"name":"src_endpoint.ip","value":"8.8.8.8","type":"geoip","provider":"platform/ipinfo_lite",
        "data":{"contract_version":1,"feed_id":"ipinfo_lite","feed_class":"baseline","feed_revision_id":1,
        "valid_until":(now+Duration::minutes(5)).to_rfc3339(),"status":"match",
        "owned_fields":["src_endpoint.location.country"]}});
    let data = json!({"src_endpoint":{"location":{"country":"US"},"autonomous_system":{"number":64512}},"enrichments":[stamp]}).to_string();
    let schema = "src_endpoint Tuple(location Tuple(country Nullable(String)), autonomous_system Tuple(number Nullable(UInt32))), enrichments Array(Tuple(name String,value String,type String,provider String,data Tuple(contract_version UInt16,feed_id String,feed_class String,feed_revision_id Int64,valid_until String,status String,owned_fields Array(String))))";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, data).unwrap();
    eprintln!("NAN2469_NATIVE_SEARCH_BEGIN");
    for (authority, visible) in [(&allowed, true), (&denied, false), (&foreign, false), (&expired_grant, false)] {
        let scan = format!("(SELECT {} AS src_endpoint, {} AS enrichments FROM file({{event_path:String}}, JSONEachRow, {{event_schema:String}}))", root_expression("src_endpoint", authority), root_expression("enrichments", authority));
        for (query, expected) in [
            (format!("SELECT count() AS n FROM {scan} WHERE src_endpoint.location.country='US'"), if visible { 1 } else { 0 }),
            (format!("SELECT count() AS n FROM {scan} WHERE src_endpoint.autonomous_system.number=64512"), 1),
            (format!("SELECT length(enrichments) AS n FROM {scan} ORDER BY src_endpoint.location.country LIMIT 1"), if visible { 1 } else { 0 }),
        ] {
            let query = format!("{query} SETTINGS prefer_column_name_to_alias=1");
            let output = connection.query_with_params(&query, "JSONEachRow", &[("event_path", path.to_str().unwrap()), ("event_schema", schema), ("nano_enrichment_authority", &authority.sql_control_metadata())]).unwrap();
            let row: Value = serde_json::from_slice(&output.data).unwrap();
            assert_eq!(row["n"], expected, "{query}");
        }
    }
    assert!(!allowed.may_return(&denied, None));
    assert!(!allowed.may_return(&allowed, Some(now)));
    let mut revoked = revision.clone();
    revoked.deny_epoch += 1;
    let revoked = ReadAuthorization::from_resolved(tenant, now, &[revoked]);
    assert_ne!(allowed.cache_identity(), revoked.cache_identity());
    assert!(!allowed.may_return(&revoked, None));
    planner_walk(&connection, &executor, &allowed, &revisions, dir.path());
    eprintln!("NAN2469_NATIVE_SEARCH_END");
    #[cfg(feature = "enrichment-read-audit")]
    assert_eq!(
        before,
        nanosiem_core::platform_enrichment::read::audit::counts(),
        "search touched an enrichment artifact or feed matcher"
    );
}
