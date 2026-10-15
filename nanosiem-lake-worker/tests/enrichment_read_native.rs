//! NAN-2510. Run ignored tests with NANO_CHDB_LIBRARY_PATH and
//! NANO_CHDB_LIBRARY_SHA256 pointing to a digest-verified chDB C ABI library.
use chrono::{Duration, Utc};
use nanosiem_core::platform_enrichment::{
    read::ReadAuthorization, AuthorizedRevision, FeedClass, RevisionReference,
};
use nanosiem_lake_worker::{
    enrichment_read::{leaf_expression, owner_denial_probe_sql, root_expression},
    native::{NativeChdb, NativeConnection, NativeQueryOutput},
};
use serde_json::{json, Value};

const ENDPOINT: &str = "Tuple(ip Nullable(String), port Nullable(UInt16), location Tuple(country Nullable(String), continent Nullable(String), provider Nullable(String), city Nullable(String)), autonomous_system Tuple(number Nullable(UInt32), name Nullable(String)))";
const STAMPS: &str = "Array(Tuple(provider Nullable(String), name Nullable(String), data Tuple(contract_version Nullable(Int64), feed_id Nullable(String), feed_class Nullable(String), feed_revision_id Nullable(Int64), valid_until Nullable(String), status Nullable(String), owned_fields Array(Nullable(String)), premium Tuple(tier Nullable(String), grant_revision Nullable(Int64), entitlement_revision Nullable(Int64)))))";

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    ).unwrap();
    std::mem::forget(runtime.clone());
    runtime
}

fn authority() -> ReadAuthorization {
    let now = Utc::now();
    let tenant = uuid::Uuid::nil();
    ReadAuthorization::from_resolved(tenant, now, &[AuthorizedRevision {
        tenant_id: tenant,
        reference: RevisionReference { feed_id: "geo".into(), feed_revision: 1,
            tier: "included".into(), grant_revision: 1, entitlement_revision: 1 },
        class: FeedClass::Baseline, digest: "a".repeat(64), mapping_revision: 1,
        deny_epoch: 0, valid_until: now + Duration::hours(1), evaluated_at: now,
    }, AuthorizedRevision {
        tenant_id: tenant,
        reference: RevisionReference { feed_id: "paid_geo".into(), feed_revision: 2,
            tier: "paid".into(), grant_revision: 3, entitlement_revision: 4 },
        class: FeedClass::Premium, digest: "b".repeat(64), mapping_revision: 1,
        deny_epoch: 0, valid_until: now + Duration::hours(1), evaluated_at: now,
    }])
}

fn run(c: &NativeConnection, sql: &str, authority: &ReadAuthorization) -> NativeQueryOutput {
    c.query_with_params(sql, "JSONEachRow",
        &[("nano_enrichment_authority", &authority.sql_control_metadata())]).unwrap()
}

// Frozen pre-NAN-2510 expression: compare full endpoints and stamps, not just
// country, so producer siblings and all five owned leaves are regression tested.
fn old_root(root: &str, authority: &ReadAuthorization) -> String {
    let allowed = authority.permission_sql("toJSONString(__nano_e)");
    let denied = format!("startsWith(JSONExtractString(toJSONString(__nano_e), 'provider'), 'platform/') AND NOT ifNull({allowed}, 0)");
    if root == "enrichments" {
        return format!("arrayFilter(__nano_e -> NOT ({denied}), enrichments)");
    }
    let mut args = vec![format!("toJSONString({root})")];
    for (parent, leaf) in [("location","country"), ("location","continent"), ("location","provider"), ("autonomous_system","number"), ("autonomous_system","name")] {
        let owns = format!("arrayExists(__nano_e -> ({denied}) AND has(JSONExtract(toJSONString(__nano_e), 'data', 'owned_fields', 'Array(String)'), '{root}.{parent}.{leaf}'), enrichments)");
        args.push(format!("if({owns}, '{{\"{parent}\":{{\"{leaf}\":null}}}}', '{{}}')"));
    }
    format!("JSONExtract(JSONMergePatch({}), toTypeName({root}))", args.join(", "))
}

#[test]
fn enrichment_read_nonempty_rights_sql_shape() {
    let sql = leaf_expression("src_endpoint.location.country", &authority());
    assert_eq!(sql.matches("arrayFilter(").count(), 0);
    assert_eq!(sql.matches("'owned_fields'").count(), 1);
    assert_eq!(sql.matches("parseDateTime64BestEffortOrNull").count(), 1);
    assert!(!sql.contains("JSON"));
    assert!(!sql.contains("nano_enrichment_authority"));
    assert!(sql.contains("has([tuple('baseline'"));
}

#[test]
#[ignore = "requires a digest-verified native chDB library"]
fn enrichment_read_parquet_matches_old_mask() {
    let runtime = runtime();
    let c = runtime.connect(&[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let auth = authority();
    let now = auth.evaluated_at();
    let stamp = |revision, expiry: chrono::DateTime<Utc>| json!({
        "provider":"platform/geo", "name":"src_endpoint.ip",
        "data":{"contract_version":1,"feed_id":"geo","feed_class":"baseline",
        "feed_revision_id":revision,"valid_until":expiry.to_rfc3339(),"status":"match",
        "owned_fields":["src_endpoint.location.country","dst_endpoint.location.country",
        "src_endpoint.location.continent","src_endpoint.location.provider",
        "src_endpoint.autonomous_system.number","src_endpoint.autonomous_system.name"]}
    });
    let producer = json!({"provider":"producer/custom","name":"tag","data":{}});
    let permitted = stamp(1, now + Duration::minutes(30));
    let mut invalid = permitted.clone();
    invalid["data"]["status"] = json!("error");
    let mut no_match = permitted.clone();
    no_match["data"]["status"] = json!("no_match");
    let mut wrong_provider = permitted.clone();
    wrong_provider["provider"] = json!("platform/other");
    let mut wrong_contract = permitted.clone();
    wrong_contract["data"]["contract_version"] = json!(2);
    let mut premium = permitted.clone();
    premium["provider"] = json!("platform/paid_geo");
    premium["data"]["feed_id"] = json!("paid_geo");
    premium["data"]["feed_class"] = json!("premium");
    premium["data"]["feed_revision_id"] = json!(2);
    premium["data"]["premium"] = json!({"tier":"paid","grant_revision":3,"entitlement_revision":4});
    let mut wrong_grant = premium.clone();
    wrong_grant["data"]["premium"]["grant_revision"] = json!(2);
    let mut wrong_entitlement = premium.clone();
    wrong_entitlement["data"]["premium"]["entitlement_revision"] = json!(3);
    let mut wrong_tier = premium.clone();
    wrong_tier["data"]["premium"]["tier"] = json!("other");
    let rows = [
        json!([]), json!([producer.clone()]), json!([permitted.clone()]),
        json!([stamp(1, now - Duration::seconds(1))]),
        json!([stamp(2, now + Duration::minutes(30))]),
        json!([producer, permitted.clone(), stamp(2, now + Duration::minutes(30))]),
        json!([invalid]), json!([no_match]), json!([wrong_provider]), json!([wrong_contract]),
        json!([{"provider":"platform/unknown","data":{}}]),
        json!([{"provider":null,"data":{}}]),
        json!([premium]), json!([wrong_grant]), json!([wrong_entitlement]), json!([wrong_tier]),
        json!([stamp(1, now)]),
    ];
    let endpoint = json!({"ip":"8.8.8.8","port":443,"location":{"country":"US","continent":"NA","provider":"geo","city":"producer city"},"autonomous_system":{"number":64512,"name":"producer ASN"}});
    let input = dir.path().join("events.jsonl");
    let parquet = dir.path().join("events.parquet");
    std::fs::write(&input, rows.iter().enumerate().map(|(id, enrichments)| {
        json!({"id":id,"src_endpoint":endpoint,"dst_endpoint":endpoint,"enrichments":enrichments}).to_string()
    }).collect::<Vec<_>>().join("\n")).unwrap();
    let schema = format!("id UInt64, src_endpoint {ENDPOINT}, dst_endpoint {ENDPOINT}, enrichments {STAMPS}");
    c.query_with_params(
        "INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
        "JSONEachRow", &[("output",parquet.to_str().unwrap()),("input",input.to_str().unwrap()),("schema",&schema)],
    ).unwrap();
    for auth in [auth, ReadAuthorization::unknown(uuid::Uuid::nil(), now)] {
        let projection = |old: bool| {
            ["src_endpoint","dst_endpoint","enrichments"].iter().map(|root| {
                let expr = if old { old_root(root, &auth) } else { root_expression(root, &auth) };
                format!("{expr} AS masked_{root}")
            }).collect::<Vec<_>>().join(", ")
        };
        let source = format!("file('{}', Parquet)", parquet.display());
        let old = run(&c, &format!("SELECT id, {} FROM {source} ORDER BY id", projection(true)), &auth);
        let new = run(&c, &format!("SELECT id, {} FROM {source} ORDER BY id", projection(false)), &auth);
        let values = |bytes: &[u8]| String::from_utf8_lossy(bytes).lines().map(|line| serde_json::from_str::<Value>(line).unwrap()).collect::<Vec<_>>();
        assert_eq!(values(&new.data), values(&old.data));
        let leaf = leaf_expression("src_endpoint.location.country", &auth);
        let result = run(&c, &format!("SELECT id, {leaf} AS country, toTypeName({}) = toTypeName(src_endpoint) AS same_type FROM {source} ORDER BY id", root_expression("src_endpoint", &auth)), &auth);
        for (row, root) in values(&result.data).iter().zip(values(&new.data)) {
            assert_eq!(row["same_type"], 1);
            assert_eq!(row["country"], root["masked_src_endpoint"]["location"]["country"]);
        }
        assert_eq!(values(&new.data)[0]["masked_src_endpoint"], endpoint);
        assert!(values(&new.data)[3]["masked_src_endpoint"]["location"]["country"].is_null());
    }
    // Older physical schemas may omit siblings, subtrees, or all stamp data.
    for schema in [
        "src_endpoint Tuple(location Tuple(country Nullable(String))), enrichments Array(Tuple(provider Nullable(String)))",
        "src_endpoint Tuple(ip Nullable(String)), enrichments Array(Tuple(provider Nullable(String)))",
    ] {
        let sql = format!("SELECT toTypeName({}) = toTypeName(src_endpoint) AS same_type FROM null('{}')", root_expression("src_endpoint", &authority()), schema);
        // null() has no rows, but still resolves every tuple/matcher and type.
        run(&c, &sql, &authority());
    }
}

/// NAN-2869 mask elision guard (zero cross-tenant sharing): query[T] drops the
/// location/ASN masks for a file only when the owner-denial probe proves that
/// no row carries a platform stamp the authority denies. A tenant WITHOUT the
/// feed right must see the probe fail (masks stay on, the leaf reads NULL);
/// a tenant WITH it, or a file whose leaves no platform stamp owns, is clean.
#[test]
#[ignore = "requires a digest-verified native chDB library"]
fn owner_denial_probe_elides_masks_only_for_rights_the_tenant_holds() {
    let runtime = runtime();
    let c = runtime.connect(&[]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let granted = authority();
    let now = granted.evaluated_at();
    let no_rights = ReadAuthorization::unknown(uuid::Uuid::nil(), now);
    let geo = json!({
        "provider":"platform/geo", "name":"src_endpoint.ip",
        "data":{"contract_version":1,"feed_id":"geo","feed_class":"baseline",
        "feed_revision_id":1,"valid_until":(now + Duration::minutes(30)).to_rfc3339(),"status":"match",
        "owned_fields":["src_endpoint.location.country","src_endpoint.autonomous_system.number"]}
    });
    let producer = json!({"provider":"producer/custom","name":"tag","data":{}});
    let endpoint = json!({"ip":"8.8.8.8","port":443,"location":{"country":"US","continent":"NA","provider":"geo","city":"c"},"autonomous_system":{"number":64512,"name":"asn"}});
    let schema = format!("id UInt64, src_endpoint {ENDPOINT}, dst_endpoint {ENDPOINT}, enrichments {STAMPS}");
    let write = |name: &str, rows: &[Value]| {
        let input = dir.path().join(format!("{name}.jsonl"));
        let parquet = dir.path().join(format!("{name}.parquet"));
        std::fs::write(&input, rows.iter().enumerate().map(|(id, enrichments)| {
            json!({"id":id,"src_endpoint":endpoint,"dst_endpoint":endpoint,"enrichments":enrichments}).to_string()
        }).collect::<Vec<_>>().join("\n")).unwrap();
        c.query_with_params(
            "INSERT INTO FUNCTION file({output:String}, Parquet) SELECT * FROM file({input:String}, JSONEachRow, {schema:String})",
            "JSONEachRow", &[("output",parquet.to_str().unwrap()),("input",input.to_str().unwrap()),("schema",&schema)],
        ).unwrap();
        parquet
    };
    let stamped = write("stamped", &[json!([]), json!([geo.clone()]), json!([producer.clone(), geo])]);
    let producer_only = write("producer_only", &[json!([producer]), json!([])]);
    let probe = |path: &std::path::Path, auth: &ReadAuthorization| -> (u64, i64) {
        let output = c.query_with_params(&owner_denial_probe_sql(auth), "JSONEachRow",
            &[("probe_source", path.to_str().unwrap()), ("probe_schema", &schema)]).unwrap();
        let row: Value = serde_json::from_str(String::from_utf8_lossy(&output.data).lines().next().unwrap()).unwrap();
        let number = |value: &Value| value.as_i64().or_else(|| value.as_str().and_then(|v| v.parse().ok())).unwrap();
        (number(&row["denied"]) as u64, number(&row["expires_us"]))
    };
    // Granted: clean, and the proof expires with the owning stamp.
    let (denied, expires) = probe(&stamped, &granted);
    assert_eq!(denied, 0);
    assert!(expires <= (now + Duration::minutes(30)).timestamp_micros() && expires > now.timestamp_micros());
    // No rights: two rows carry a denied owning stamp, so masks must stay on.
    assert_eq!(probe(&stamped, &no_rights).0, 2);
    let country = run(&c, &format!("SELECT id, {} AS country FROM file('{}', Parquet) ORDER BY id",
        leaf_expression("src_endpoint.location.country", &no_rights), stamped.display()), &no_rights);
    let countries = String::from_utf8_lossy(&country.data).lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["country"].clone()).collect::<Vec<_>>();
    assert_eq!(countries, vec![json!("US"), Value::Null, Value::Null]);
    // Leaves no platform stamp owns are producer values: clean for anyone.
    assert_eq!(probe(&producer_only, &no_rights).0, 0);
}

#[test]
#[ignore = "1M-row micro-benchmark; requires a digest-verified native chDB library"]
fn enrichment_read_bench_mask() {
    let runtime = runtime();
    let c = runtime.connect(&[]).unwrap();
    let auth = authority();
    // Stage a synthetic million-row table, then persist fifty Parquet objects
    // to match the reported tail scan. Fixture generation is outside timing.
    // Also report Memory timings separately: they expose fixed planning cost.
    // Vary country so the aggregate cannot be constant-folded.
    c.query_with_params(&format!("CREATE TABLE mask_bench (src_endpoint {ENDPOINT}, enrichments {STAMPS}) ENGINE=Memory"), "JSONEachRow", &[]).unwrap();
    c.query_with_params(
        "INSERT INTO mask_bench SELECT tuple('8.8.8.8', 443, tuple(if(number % 2 = 0, 'US', 'CA'), 'NA', 'producer', 'city'), tuple(64512, 'ASN')), [] FROM numbers(1000000)",
        "JSONEachRow", &[],
    ).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for part in 0..50 {
        let output = dir.path().join(format!("part-{part}.parquet"));
        c.query_with_params(
            &format!("INSERT INTO FUNCTION file({{output:String}}, Parquet) SELECT * FROM mask_bench LIMIT 20000 OFFSET {}", part * 20000),
            "JSONEachRow", &[("output", output.to_str().unwrap())],
        ).unwrap();
    }
    let source = format!("file('{}/*.parquet', Parquet)", dir.path().display());
    let native = "tupleElement(tupleElement(src_endpoint, 'location'), 'country')".to_string();
    let masked = leaf_expression("src_endpoint.location.country", &auth);
    let old = format!("tupleElement(tupleElement({}, 'location'), 'country')", old_root("src_endpoint", &auth));
    let measure = |label: &str, expr: &str, source: &str| {
        let sql = format!("SELECT sum(length({expr})) AS total FROM {source} SETTINGS max_threads=1");
        let warmup = run(&c, &sql, &auth);
        let mut samples = (0..7).map(|_| {
            let result = run(&c, &sql, &auth);
            assert_eq!(serde_json::from_slice::<Value>(&result.data).unwrap()["total"], 2000000);
            result.elapsed.as_secs_f64()
        }).collect::<Vec<_>>();
        samples.sort_by(f64::total_cmp);
        eprintln!("bench_mask {label}: bytes={} median={:.6}s", warmup.storage_bytes_read, samples[3]);
        samples[3]
    };
    let baseline = measure("Parquet native", &native, &source);
    let optimized = measure("Parquet masked", &masked, &source);
    let previous = measure("Parquet old mask", &old, &source);
    let roundtrip = measure("Parquet JSON roundtrip", "tupleElement(tupleElement(JSONExtract(toJSONString(src_endpoint), toTypeName(src_endpoint)), 'location'), 'country')", &source);
    let memory_baseline = measure("Memory native", &native, "mask_bench");
    let memory_masked = measure("Memory masked", &masked, "mask_bench");
    eprintln!("bench_mask Memory: unmasked={memory_baseline:.6}s masked={memory_masked:.6}s ratio={:.3}", memory_masked / memory_baseline);
    eprintln!("bench_mask root JSON roundtrip alone={roundtrip:.6}s");
    eprintln!("bench_mask SQL: {masked}");
    eprintln!("bench_mask 1000000 rows / 50 Parquet objects, median of 7: unmasked={baseline:.6}s masked={optimized:.6}s old={previous:.6}s ratio={:.3}", optimized / baseline);
    assert!(optimized <= baseline * 2.0, "masked / unmasked = {}", optimized / baseline);
}

#[cfg(all(feature = "enterprise", target_os = "linux"))]
#[path = "support/stamp_visibility.rs"]
mod stamp_visibility;
