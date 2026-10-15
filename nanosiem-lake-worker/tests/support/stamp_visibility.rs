//! Live schema captured 2026-09-21; no network or live credentials required.
use super::*;
use nanosiem_core::platform_enrichment::*;
use nanosiem_lake_worker::{platform_stamping::*, enrichment_read, generation::HotTailManifest,
    planner::{plan_broad_log_query_with_candidates_and_tail, CompiledQuery,
        ObjectStoreCredentials, SnapshotCache, SnapshotCacheObject, SourceManifest, TenantQueryConfig}};
use std::{collections::BTreeMap, sync::{Arc, Mutex}, io::Write};
#[path = "free_feeds.rs"]
#[allow(dead_code)]
mod fixture;

fn date(s: &str) -> chrono::DateTime<Utc> { s.parse().unwrap() }
fn now() -> chrono::DateTime<Utc> { date("2026-09-21T12:10:00.123456Z") }
fn rights() -> ReadAuthorization {
    let revisions = [
        ("ipinfo_lite", 1, "2026-10-04T08:03:19Z"),
        ("threatfox", 1, "2026-09-22T01:48:41Z"),
        ("threatfox", 2, "2026-09-22T05:48:41Z"),
        ("tor_exit_nodes", 1, "2026-09-21T23:55:24Z"),
        ("tor_exit_nodes", 2, "2026-09-22T05:57:52Z"),
    ].map(|(feed, revision, expiry)| AuthorizedRevision {
        tenant_id: uuid::Uuid::from_u128(1), evaluated_at: now(), valid_until: date(expiry),
        reference: RevisionReference { feed_id: feed.into(), feed_revision: revision,
            tier: "included".into(), grant_revision: 1, entitlement_revision: 1 },
        class: FeedClass::Baseline, digest: "a".repeat(64), mapping_revision: 1, deny_epoch: 0,
    });
    ReadAuthorization::from_resolved(uuid::Uuid::from_u128(1), now(), &revisions)
}
struct Geo;
impl ExactLookup for Geo {
    fn lookup(&self, revision: &SelectedFeedRevision, _: &str) -> Result<Option<GeoRecord>, StampReason> {
        assert_eq!(revision.revision, 1);
        Ok(Some(GeoRecord { country_code: Some("US".into()), country_name: Some("United States".into()),
            continent: Some("NA".into()), asn: Some(15169), as_name: Some("Google".into()), ..Default::default() }))
    }
}
fn stamper(mode: runtime::Mode) -> ShadowStamper {
    let mut claim = fixture::Fixture::new().claim;
    claim.mode = mode;
    claim.vector.admitted_at = now();
    claim.vector.feeds = [("ipinfo_lite", 1), ("threatfox", 2), ("tor_exit_nodes", 2)].map(|(feed, revision)| AdmissionFeed {
        feed_id: feed.into(), deny_epoch: 0,
        decision: AdmissionDecision::Selected { artifact: SelectedFeedRevision {
            revision, digest: "a".repeat(64), mapping_revision: 1 },
            right: AdmissionRight { tier: "included".into(), grant_revision: 1, entitlement_revision: 1 } },
    }).to_vec();
    for (feed, upstream, expiry, hard, fresh) in [
        ("ipinfo_lite", "2026-09-20T08:03:19Z", "2026-10-04T08:03:19Z", 1209600, 604800),
        ("threatfox", "2026-09-21T05:48:41Z", "2026-09-22T05:48:41Z", 86400, 21600),
        ("tor_exit_nodes", "2026-09-21T05:57:52Z", "2026-09-22T05:57:52Z", 86400, 21600),
    ] {
        claim.feed_times.insert(feed.into(), FeedTime { upstream_at: Some(date(upstream)),
            valid_until: Some(date(expiry)), freshness: FreshnessAtIngest::Fresh,
            hard_expiry_seconds: Some(hard), freshness_seconds: Some(fresh) });
    }
    let journal = Arc::new(fixture::Journal(Mutex::new(BTreeMap::new()), Mutex::new(claim)));
    ShadowStamper::new(journal, Arc::new(Geo), ed25519_dalek::SigningKey::from_bytes(&[9;32]), "fixture".into()).unwrap()
}
fn stamped() -> Value {
    let stamper = stamper(runtime::Mode::Live);
    let mut event = fixture::event();
    event["time"] = json!("2026-09-21T12:00:00Z");
    event["src_endpoint"]["ip"] = json!("8.8.8.8");
    event["dst_endpoint"]["ip"] = json!("1.1.1.1");
    use sha2::Digest;
    let source: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&event).unwrap()).into();
    let mut session = stamper.begin(fixture::TENANT, "fixture", source, &mut event, [None,None,None], &"a".repeat(64)).unwrap();
    assert!(session.is_live());
    session.decorate(&mut event).unwrap();
    let (_, event) = nanosiem_lake_worker::iceberg::normalize_event(&nanosiem_lake_worker::iceberg::EventRow {
        event_uid: "fixture".into(), event_kind: nanosiem_lake_worker::iceberg::EventKind::Source, ocsf_event: event,
    }, fixture::TENANT).unwrap();
    session.finalize(&event).unwrap();
    assert_eq!(event["dst_endpoint"]["location"]["country"], "US");
    event
}

#[test]
fn enrichment_read_bronze_stamp_wire_contract() {
    let event = stamped();
    let stamp = event["enrichments"].as_array().unwrap().iter().find(|s| s["provider"] == "platform/ipinfo_lite").unwrap();
    assert_eq!(stamp["data"]["contract_version"], 1);
    assert_eq!(stamp["data"]["feed_revision_id"], 1);
    assert_eq!(stamp["data"]["status"], "match");
    assert_eq!(stamp["data"]["feed_class"], "baseline");
    assert_eq!(stamp["data"]["valid_until"], "2026-10-04T08:03:19Z");
    assert_eq!(stamp["data"]["admitted_at"], "2026-09-21T12:10:00.123456Z");
    assert!(stamp["data"].get("premium").is_none());
    let control: Value = serde_json::from_str(&rights().sql_control_metadata()).unwrap();
    assert_eq!(control[0]["feed_revision"], 1);
    assert_eq!(control[0]["valid_until"], stamp["data"]["valid_until"]);
}

fn compile(query: &str) -> CompiledQuery {
    let mut child = std::process::Command::new(std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER"))
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(json!({"query":query,"dataset":"logs","start":"2026-09-21T00:00:00Z","end":"2026-09-22T00:00:00Z","limit":100,"table_view":false,"event_contract":"ocsf-1.9","snapshot_field_types":{"enrichments.provider":"array","dst_endpoint.location.country":"string","time":"timestamp"}}).to_string().as_bytes()).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    serde_json::from_slice(&result.stdout).unwrap()
}

#[tokio::test]
#[ignore = "requires digest-verified native chDB and NANO_LAKE_COMPILER"]
async fn enrichment_read_live_stamp_visibility() {
    let runtime = super::runtime();
    let c = runtime.connect(&[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let event = stamped();
    eprintln!("bronze stamps: {}", event["enrichments"]);
    let live: Value = serde_json::from_str(include_str!("../fixtures/nan2469-live-tail-read-schema.json")).unwrap();
    let input = dir.path().join("event.jsonl");
    let parquet = dir.path().join("event.parquet");
    std::fs::write(&input, event.to_string()).unwrap();
    c.query_with_params("INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String}) SETTINGS input_format_skip_unknown_fields=1, date_time_input_format='best_effort'", "JSONEachRow",
        &[("output",parquet.to_str().unwrap()),("input",input.to_str().unwrap()),("schema",live["read_schema"].as_str().unwrap())]).unwrap();
    let auth = rights();
    let source = format!("file('{}', Parquet)", parquet.display());
    // Evaluate every old conjunct independently, including revision even when contract_version fails.
    let record = "toJSONString(e)";
    let data = format!("JSONExtractRaw({record}, 'data')");
    let right = "arrayElement(JSONExtractArrayRaw({nano_enrichment_authority:String}), 1)";
    let now_sql = format!("fromUnixTimestamp64Micro({})", now().timestamp_micros());
    let terms = [
        ("contract_version", format!("JSONExtractInt({data}, 'contract_version') = 1")),
        ("status", format!("JSONExtractString({data}, 'status') IN ('match','no_match')")),
        ("valid_until_parse", format!("parseDateTime64BestEffortOrNull(JSONExtractString({data}, 'valid_until'), 6, 'UTC') > {now_sql}")),
        ("provider_match", format!("JSONExtractString({record}, 'provider') = concat('platform/', JSONExtractString({right}, 'feed_id'))")),
        ("feed_id", format!("JSONExtractString({data}, 'feed_id') = JSONExtractString({right}, 'feed_id')")),
        ("feed_revision_id", format!("JSONExtractInt({data}, 'feed_revision_id') = JSONExtractInt({right}, 'feed_revision')")),
        ("rights_valid_until", format!("parseDateTime64BestEffortOrNull(JSONExtractString({right}, 'valid_until'), 6, 'UTC') > {now_sql}")),
        ("premium_baseline", format!("JSONExtractString({right}, 'tier') = 'included' AND JSONExtractString({data}, 'feed_class') = 'baseline' AND JSONExtractString({data}, 'premium','tier') = '' AND JSONExtractInt({data}, 'premium','grant_revision') = 0 AND JSONExtractInt({data}, 'premium','entitlement_revision') = 0")),
    ];
    let columns = terms.iter().map(|(name, expr)| format!("({expr}) AS {name}")).collect::<Vec<_>>().join(", ");
    let probe = format!("SELECT {record} AS stamp_json, {columns}, {} AS old_allowed, {} AS tuple_allowed, has(e.data.owned_fields, 'dst_endpoint.location.country') AS owns_country, toTypeName(e.data.owned_fields) AS owned_type, toTypeName(e.data.contract_version) AS contract_type, parseDateTime64BestEffortOrNull(e.data.admitted_at,6,'UTC') IS NOT NULL AS admitted_parse, parseDateTime64BestEffortOrNull(e.data.upstream_at,6,'UTC') IS NOT NULL AS upstream_parse FROM {source} ARRAY JOIN enrichments AS e WHERE e.provider='platform/ipinfo_lite' AND e.name='dst_endpoint.ip'", auth.permission_sql(record), auth.tuple_permission_sql("e"));
    let result = run(&c, &probe, &auth);
    eprintln!("mask terms: {}", String::from_utf8_lossy(&result.data));
    let row: Value = serde_json::from_slice(&result.data).unwrap();
    assert_eq!(row["tuple_allowed"], 1);
    let tuple_terms = [
        ("contract_version", "ifNull(e.data.contract_version, 0) = 1".to_string()),
        ("status", "ifNull(e.data.status, '') IN ('match','no_match')".into()),
        ("valid_until_parse", format!("parseDateTime64BestEffortOrNull(ifNull(e.data.valid_until, ''),6,'UTC') > {now_sql}")),
        ("provider_match", "e.provider = concat('platform/', ifNull(e.data.feed_id, ''))".into()),
        ("feed_id", "e.data.feed_id = 'ipinfo_lite'".into()),
        ("feed_revision_id", "toInt64(ifNull(e.data.feed_revision_id, 0)) = toInt64(1)".into()),
        ("rights_valid_until", format!("parseDateTime64BestEffortOrNull(JSONExtractString({right}, 'valid_until'),6,'UTC') > {now_sql}")),
        ("premium_baseline", "e.data.feed_class = 'baseline' AND ifNull(tupleElement(tupleElement(e.data,'premium',tuple()),'tier',''),'') = '' AND ifNull(tupleElement(tupleElement(e.data,'premium',tuple()),'grant_revision',0),0) = 0 AND ifNull(tupleElement(tupleElement(e.data,'premium',tuple()),'entitlement_revision',0),0) = 0".into()),
    ];
    let columns = tuple_terms.iter().map(|(name, expr)| format!("({expr}) AS {name}")).collect::<Vec<_>>().join(", ");
    let tuple_result = run(&c, &format!("SELECT {columns} FROM {source} ARRAY JOIN enrichments AS e WHERE e.provider='platform/ipinfo_lite' AND e.name='dst_endpoint.ip'"), &auth);
    eprintln!("tuple terms: {}", String::from_utf8_lossy(&tuple_result.data));
    let tuple_row: Value = serde_json::from_slice(&tuple_result.data).unwrap();
    for (term, _) in &terms {
        assert_eq!(row[*term], 1, "old {term}");
        assert_eq!(tuple_row[*term], 1, "tuple {term}");
    }
    for term in ["old_allowed", "tuple_allowed", "owns_country", "admitted_parse", "upstream_parse"] {
        assert_eq!(row[term], 1, "{term}");
    }
    assert_eq!(row["owned_type"], "Array(Nullable(String))");
    assert_eq!(row["contract_type"], "Nullable(Int64)");
    drop(c);
    let executor = nanosiem_lake_worker::executor::NativeExecutor::start(runtime, 1).unwrap();
    let bytes = std::fs::metadata(&parquet).unwrap().len();
    let base_key = "s3://bucket/table/data/base.parquet";
    let config = TenantQueryConfig { tenant_id: fixture::TENANT.into(), source: "https://object.test/bucket/table".into(),
        iceberg_metadata_file_path: "metadata/00001.metadata.json".into(), max_query_bytes: 10000000,
        max_memory_bytes: 1000000000, max_execution_seconds: 30, threads: 1,
        credentials: ObjectStoreCredentials::DefaultChain,
        snapshot_cache: Some(SnapshotCache { source_spec: parquet.to_str().unwrap().into(), objects: BTreeMap::from([(base_key.into(), SnapshotCacheObject { version_id: "v1".into(), bytes, path: parquet.clone() })]),
            bytes, read_schema: Some(live["read_schema"].as_str().unwrap().into()), bootstrap: false }) };
    let manifest: SourceManifest = serde_json::from_value(json!({"tenant_id":fixture::TENANT,"objects":[{"event_object_key":base_key,"event_object_version":"v1","event_object_bytes":bytes,"rows":1,"available_paths":live["available_paths"],"field_types":{"time":"timestamp","enrichments.provider":"array","dst_endpoint.location.country":"string"}}]})).unwrap();
    let mut tail: HotTailManifest = serde_json::from_value(json!({"schema_version":4,"tenant_id":fixture::TENANT,"table":"logs",
        "base_snapshot_id":1,"head_snapshot_id":2,"tail_id":"a".repeat(64),"head_metadata_location":"s3://bucket/table/metadata/00002.metadata.json",
        "iceberg_metadata_file_path":"metadata/00002.metadata.json","read_schema":live["read_schema"],"available_paths":live["available_paths"],
        "objects":[{"source_uri":"s3://bucket/table/data/tail.parquet","version_id":"v1","size_bytes":std::fs::metadata(&parquet).unwrap().len(),"rows":1}]})).unwrap();
    tail.local_paths = vec![parquet];
    for (resolved, auth) in [(true, auth), (false, ReadAuthorization::unknown(uuid::Uuid::from_u128(1), now()))] {
    for query in ["enrichments.provider=\"platform/ipinfo_lite\" | stats count()", "* | where isnotnull(dst_endpoint.location.country)"] {
        let compiled = compile(query);
        let plan = enrichment_read::scope(auth.clone(), async {
            plan_broad_log_query_with_candidates_and_tail(&config, &manifest, &compiled, Some(&[]), Some(&tail)).unwrap()
        }).await;
        for old in [true, false] {
            let mut sql = plan.sql.clone();
            if old {
                // Restore the pre-NAN-2510 mask at the exact planner projection sites.
                for root in ["enrichments", "src_endpoint", "dst_endpoint"] {
                    sql = sql.replace(&root_expression(root, &auth), &old_root(root, &auth));
                }
                sql = sql.replace(&leaf_expression("dst_endpoint.location.country", &auth),
                    &format!("tupleElement(tupleElement({}, 'location'), 'country')", old_root("dst_endpoint", &auth)));
            }
            if old { assert_ne!(sql, plan.sql, "old mask must replace the production projection"); }
            let mut params = plan.params.clone();
            params.push(("nano_enrichment_authority".into(), auth.sql_control_metadata()));
            let result = executor.execute_sql(sql, params).await.unwrap();
            eprintln!("query={query} resolved={resolved} old={old} result={}", String::from_utf8_lossy(&result.data));
            if query.contains("stats") {
                let count: Value = serde_json::from_slice(&result.data).unwrap();
                assert_eq!(count.as_object().unwrap().values().next().unwrap(), &json!(u64::from(resolved)));
            } else {
                let rows: Vec<Value> = String::from_utf8_lossy(&result.data).lines().map(|line| serde_json::from_str(line).unwrap()).collect();
                assert_eq!(rows.len(), usize::from(resolved));
                if resolved { assert_eq!(rows[0]["dst_endpoint"]["location"]["country"], "US"); }
            }
        }
    }
}
}

#[path = "tail_stamp_roundtrip.rs"]
mod tail_stamp_roundtrip;
