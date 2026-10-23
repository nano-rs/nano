// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3032: v2 token block indexes change cost, never results.
//!
//! The same sysmon-shaped rows are ingested twice through `ingest[T]` into
//! signed parts: once writing v1 `tokens.nti` and once writing v2. Every
//! query then runs through the native part query engine over both, and
//! must return the same rows. Rare-token counts are also checked against
//! the generator. Queries cover tokens, AND, OR, NOT, wildcards, contains
//! and hash pivots.
//!
//! Run: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER,
//! `cargo test -p nanosiem-lake-worker --test nan3032_keyword_index_native -- --ignored --nocapture`

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use ed25519_dalek::SigningKey;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::parts::part_log::{load_log, LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::{LocalPartSigner, TenantKeySet};
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const TENANT: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
const ROWS: usize = 6_000;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-test-0001", SigningKey::from_bytes(&[11; 32])).unwrap()
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).with_batch_size(1_024).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// Row `i`: every row says `powershell` (common); row i carries rare id
/// `rid{i % 997}` only for i < 997 * 2 (so each rare id is in ≤ 2 rows),
/// a unique hash (also in `process.file.hashes`), and a few spread markers.
fn raw(i: usize) -> String {
    let mut text = format!("EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe pid={i} Hashes=SHA256={}", hash(i));
    if i < 997 * 2 {
        text.push_str(&format!(" corr=rid{} ", i % 997));
    }
    if i % 1_500 == 7 {
        text.push_str(" mimikatz sekurlsa::logonpasswords");
    }
    if i % 3 == 0 {
        text.push_str(" svchost.exe -k netsvcs");
    }
    text
}

fn hash(i: usize) -> String {
    format!("{:064x}", (i as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835))
}

fn row(i: usize, time: &str) -> Value {
    json!({
        "activity_id": 1, "activity_name": "Launch", "category_uid": 1, "category_name": "System Activity",
        "class_uid": 1007, "class_name": "Process Activity", "type_uid": 100701,
        "severity": "Informational", "severity_id": 1, "status": "Success", "status_id": 1,
        "time": time,
        "raw_data": raw(i),
        "raw_data_size": raw(i).len(),
        "metadata": {"uid": format!("uid-{i:06}"), "version": "1.9.0", "log_source": "windows_sysmon", "tenant_uid": TENANT,
                     "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "actor": {"process": {"name": "explorer.exe", "pid": 4}},
        "process": {"name": "powershell.exe", "pid": i, "file": {"name": "powershell.exe", "type_id": 1,
                    "hashes": [{"algorithm_id": 3, "value": hash(i)}]}},
        "device": {"hostname": format!("ws-{:03}.corp.local", i % 50), "type_id": 2},
    })
}

fn notice(key: &str, at_ms: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0,
        sha256: None, edge_sha256: None, notified_at_ms: at_ms,
    }
}

async fn engine_over(root: &Path, rows: &[Value], v2: bool, now: chrono::DateTime<chrono::Utc>) -> PartQueryEngine {
    engine_over_with_budget(root, rows, v2, now, false, false).await
}

async fn engine_over_with_budget(root: &Path, rows: &[Value], v2: bool, now: chrono::DateTime<chrono::Utc>, bounded: bool, split: bool) -> PartQueryEngine {
    nanosiem_lake_worker::parts::block_index::set_enabled(v2);
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    write_bronze(&sources_dir.join("bronze/0001.parquet"), rows);
    if let Err(error) = nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join("bronze/0001.parquet")], TENANT) {
        panic!("bronze admission refused the fixture: {error:#}");
    }
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
    for (index, chunk) in rows.chunks(if split { rows.len() / 2 } else { rows.len() }).enumerate() {
        let key = format!("bronze/{index:04}.parquet");
        write_bronze(&sources_dir.join(&key), chunk);
        nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).unwrap();
        let at = now_ms + index as i64 * 11_000;
        spool.deliver(&notice(&key, at)).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    assert!(load_log(&parts, TENANT).await.unwrap().parts().next().is_some(), "a signed part was published");
    drop(ingestor);
    nanosiem_lake_worker::parts::block_index::set_enabled(false);

    // Every token index is the version this run asked for.
    let mut magics = BTreeSet::new();
    for entry in walk(&root.join("parts")) {
        if entry.extension().is_some_and(|e| e == "nti") {
            magics.insert(std::fs::read(&entry).unwrap()[..8].to_vec());
        }
    }
    assert_eq!(magics, BTreeSet::from([if v2 { b"NANOTKI2".to_vec() } else { b"NANOTKI1".to_vec() }]));

    let trusted: TenantKeySet = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3032-local";
    let query_budget = if bounded {
        let live = load_log(&parts, TENANT).await.unwrap();
        let mut largest = 0;
        let mut sidecar_bytes = 0;
        for part in live.parts() {
            let keys = nanosiem_lake_worker::parts::format::PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
            let signed = nanosiem_lake_worker::parts::provenance::SignedProvenance::verify_bytes(
                &parts.get(&keys.provenance()).await.unwrap().unwrap(), TENANT, &trusted).unwrap();
            for (_, _, bytes) in signed.record.files.all() { largest = largest.max(bytes); }
            sidecar_bytes += signed.record.files.data.iter().map(|data| data.tokens.bytes).sum::<u64>()
                + signed.record.files.partials.iter().map(|partial| partial.bytes).sum::<u64>();
        }
        assert!(sidecar_bytes > largest, "old sidecar batch would exceed the cold budget");
        largest
    } else { 256 << 20 };
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: root.join("query-cache"), max_bytes: query_budget * 8, query_max_bytes: query_budget,
        fetch_concurrency: 2, fetch_deadline: Duration::from_secs(30),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, if v2 { "nan3032-v2" } else { "nan3032-v1" }, ExecutorMode::ReadOnly).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 256 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 60, threads: 1,
    }, store, view, fetcher, executor).unwrap()
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() { out.extend(walk(&path)); } else { out.push(path); }
    }
    out
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn v2_block_index_returns_what_v1_returns() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let now = chrono::Utc::now();
    let base = now - chrono::Duration::seconds(120);
    let rows = (0..ROWS)
        .map(|i| row(i, &(base + chrono::Duration::milliseconds(i as i64 * 10)).to_rfc3339()))
        .collect::<Vec<_>>();
    let (start, end) = ((now - chrono::Duration::minutes(10)).to_rfc3339(), (now + chrono::Duration::minutes(10)).to_rfc3339());
    let v1_dir = tempfile::tempdir().unwrap();
    let v2_dir = tempfile::tempdir().unwrap();
    let v1 = engine_over(v1_dir.path(), &rows, false, now).await;
    let v2 = engine_over(v2_dir.path(), &rows, true, now).await;
    let request = |query: &str, limit: usize| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(), start: start.clone(), end: end.clone(),
        limit, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    let expected = |pred: &dyn Fn(usize) -> bool| (0..ROWS).filter(|i| pred(*i)).count() as u64;
    let rare = |k: usize| move |i: usize| i < 997 * 2 && i % 997 == k;
    let mut cases: Vec<(String, Option<u64>)> = vec![
        ("rid17 | stats count".into(), Some(expected(&rare(17)))),
        ("rid996 | stats count".into(), Some(expected(&rare(996)))),
        ("rid5000 | stats count".into(), Some(0)),
        ("mimikatz | stats count".into(), Some(expected(&|i| i % 1_500 == 7))),
        ("mimikatz sekurlsa | stats count".into(), Some(expected(&|i| i % 1_500 == 7))),
        ("rid17 OR rid400 | stats count".into(), Some(expected(&|i| rare(17)(i) || rare(400)(i)))),
        ("rid17 powershell | stats count".into(), Some(expected(&rare(17)))),
        // NAN-3037: these rows have NO `message` (NULL in the part). Keyword
        // NOT must treat the NULL column as "does not contain", not drop the row.
        ("powershell NOT rid17 | stats count".into(), Some(ROWS as u64 - 2)),
        ("svchost NOT rid17 | stats count".into(), Some(expected(&|i| i % 3 == 0 && !rare(17)(i)))),
        ("powershell NOT (rid17 OR rid400) | stats count".into(), Some(ROWS as u64 - 4)),
        ("powershell NOT (mimikatz OR (rid17 rid400)) | stats count".into(), Some(expected(&|i| i % 1_500 != 7))),
        ("powershell NOT rid17 NOT rid400 | stats count".into(), Some(ROWS as u64 - 4)),
        ("NOT (NOT rid17) | stats count".into(), Some(expected(&rare(17)))),
        ("powershell | search NOT rid17 | stats count".into(), Some(ROWS as u64 - 2)),
        // Splunk field semantics on an absent field (`user.name` is NULL on
        // every row): `NOT f=v` includes it, `f!=v` excludes it.
        ("NOT user.name=bob | stats count".into(), Some(ROWS as u64)),
        ("user.name!=bob | stats count".into(), Some(0)),
        ("NOT process.name=powershell.exe | stats count".into(), Some(0)),
        ("powershell | stats count".into(), Some(ROWS as u64)),
        ("svchost | stats count".into(), Some(expected(&|i| i % 3 == 0))),
        ("svch* | stats count".into(), None),
        // NAN-3034: `*kw*` searches raw_data too (it used to search only the
        // NULL `message` and return 0); `vchos` is a partial token and must
        // never prune.
        ("*vchos* | stats count".into(), Some(expected(&|i| i % 3 == 0))),
        ("*vchos* NOT rid17 | stats count".into(), Some(expected(&|i| i % 3 == 0 && !rare(17)(i)))),
        ("*svchost.exe* | stats count".into(), Some(expected(&|i| i % 3 == 0))),
        ("\"corr=rid17 \" | stats count".into(), None),
        (format!("{} | stats count", hash(4_242)), Some(1)),
        (format!("process.file.hashes.value=\"{}\" | stats count", hash(4_243)), None),
        ("process.cmd_line=*powershell* | stats count".into(), None),
        ("rid17 | head 5".into(), None),
        ("rid17 OR metadata.log_source=windows_sysmon | stats count".into(), Some(ROWS as u64)),
    ];
    cases.push(("device.hostname=\"ws-007.corp.local\" rid57 | stats count".into(), Some(expected(&|i| rare(57)(i) && i % 50 == 7))));
    let mut fine_used = 0;
    for (query, want) in &cases {
        let a = v1.broad_npl(&request(query, 100)).await.unwrap_or_else(|e| panic!("v1 {query}: {e:#}"));
        let b = v2.broad_npl(&request(query, 100)).await.unwrap_or_else(|e| panic!("v2 {query}: {e:#}"));
        let (ra, rb) = (&a["result"]["rows"], &b["result"]["rows"]);
        eprintln!("{query}\n  v1 {} | v2 {} | v2 planner {}", ra.to_string().chars().take(120).collect::<String>(),
            rb.to_string().chars().take(120).collect::<String>(), b["planner"]);
        assert_eq!(ra, rb, "{query}: v2 returned different rows");
        if let Some(want) = want {
            assert_eq!(rb[0]["count"], json!(want), "{query}: wrong count");
        }
        if b["planner"]["fine_runs"].as_u64().unwrap_or(0) > 0 {
            fine_used += 1;
        }
    }
    assert!(fine_used >= 5, "the v2 block index fenced only {fine_used} queries");
}


#[tokio::test(flavor = "current_thread")]
#[ignore = "requires pinned native chDB and lake compiler"]
async fn over_budget_signed_prewarm_finishes_and_remains_queryable() {
    let now = chrono::Utc::now();
    let base = now - chrono::Duration::minutes(5);
    let rows = (0..32_000).map(|i| row(i, &(base - chrono::Duration::hours(i as i64 / 1000)
        + chrono::Duration::milliseconds((i as i64 % 1000) * 10)).to_rfc3339())).collect::<Vec<_>>();
    let root = tempfile::tempdir().unwrap();
    let engine = engine_over_with_budget(root.path(), &rows, true, now, true, false).await;
    tokio::time::timeout(Duration::from_secs(10), engine.prewarm_parts(24)).await.unwrap().unwrap();
    let request = BroadNplRequest {
        request_id: "bounded-prewarm".into(), tenant_id: TENANT.into(), dataset: "logs".into(),
        query: "powershell | stats count".into(), start: (now - chrono::Duration::minutes(10)).to_rfc3339(),
        end: (now + chrono::Duration::minutes(10)).to_rfc3339(), limit: 1000, offset: 0,
        table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    let answer = engine.broad_npl(&request).await.unwrap();
    assert_eq!(answer["result"]["rows"][0]["count"], json!(1000), "bounded readiness leaves verified query execution usable");
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires pinned native chDB and lake compiler"]
async fn part_result_cache_v1_v2_cold_warm_disabled_parity() {
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-01T16:15:00Z").unwrap().with_timezone(&chrono::Utc);
    let base = now - chrono::Duration::minutes(10);
    // Tie timestamps deliberately; payload still sorts by UID.
    let rows = (0..6_000).map(|i| row(i, &(base + chrono::Duration::milliseconds((i / 3) as i64 * 10)).to_rfc3339())).collect::<Vec<_>>();
    let mut all = Vec::new();
    for v2 in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        eprintln!("CACHE_PARITY opening v{}", if v2 {2} else {1});
        let engine = engine_over_with_budget(dir.path(), &rows, v2, now, false, true).await;
        eprintln!("CACHE_PARITY opened");
        let mut answers = Vec::new();
        for query in ["*", "device.hostname=ws-007.corp.local", "raw_data=\"*vchos*\"", "process.pid=-987654", "process.pid=1 | stats count", "powershell | timechart span=1m count() as count"] {
            let mut r: BroadNplRequest = serde_json::from_value(json!({
                "request_id":"cache-parity", "tenant_id":TENANT, "dataset":"logs", "query":query,
                "start":base.to_rfc3339(), "end":now.to_rfc3339(), "limit":20,
                "table_view":true, "use_cache":true,
            })).unwrap();
            r.use_cache = false;
            let reference = engine.broad_npl(&r).await.unwrap();
            eprintln!("CACHE_PARITY reference complete: {query}");
            r.use_cache = true;
            let cold = engine.broad_npl(&r).await.unwrap();
            assert_eq!(reference["result"]["rows"], cold["result"]["rows"], "{query}");
            let warm = engine.broad_npl(&r).await.unwrap();
            r.use_cache = false;
            let disabled = engine.broad_npl(&r).await.unwrap();
            for other in [&warm, &disabled] {
                assert_eq!(cold["result"]["rows"], other["result"]["rows"], "{query}");
                assert_eq!(cold["result"]["page_has_more"], other["result"]["page_has_more"], "{query}");
                assert_eq!(cold["schema_defaults"], other["schema_defaults"], "{query}");
            }
            if query == "*" { assert!(warm["planner"]["result_cache"]["hits"].as_u64().unwrap() > 0); }
            if query == "process.pid=-987654" { assert!(warm["planner"]["result_cache"]["negative_hits"].as_u64().unwrap() > 0); }
            if query == "*" {
                r.use_cache = true;
                let row = cold["result"]["rows"][19].clone();
                r.cursor_time = row["time"].as_str().map(|text| {
                    chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f").unwrap().and_utc().to_rfc3339()
                });
                r.cursor_event_uid = row["metadata.uid"].as_str().map(str::to_owned);
                assert!(r.cursor_time.is_some() && r.cursor_event_uid.is_some());
                let page = engine.broad_npl(&r).await.unwrap();
                let repeated = engine.broad_npl(&r).await.unwrap();
                assert_eq!(page["result"]["rows"], repeated["result"]["rows"]);
                // Different clipped window must not reuse the full-part negative.
                r.cursor_time = None; r.cursor_event_uid = None;
                r.start = (base + chrono::Duration::seconds(10)).to_rfc3339();
                let clipped = engine.broad_npl(&r).await.unwrap();
                r.use_cache = false;
                assert_eq!(clipped["result"]["rows"], engine.broad_npl(&r).await.unwrap()["result"]["rows"]);
            }
            eprintln!("CACHE_PARITY v{} {} cold_ms={:.3} warm_ms={:.3}", if v2 {2} else {1}, query,
                cold["wall_seconds"].as_f64().unwrap()*1000.0, warm["wall_seconds"].as_f64().unwrap()*1000.0);
            answers.push(cold["result"]["rows"].clone());
        }
        let mut empty: BroadNplRequest = serde_json::from_value(json!({
            "request_id":"empty-cache-parity", "tenant_id":TENANT, "dataset":"logs", "query":"* | stats count",
            "start":now.to_rfc3339(), "end":(now + chrono::Duration::minutes(30)).to_rfc3339(),
            "limit":20, "table_view":true, "use_cache":true,
        })).unwrap();
        let cached = engine.broad_npl(&empty).await.unwrap();
        empty.use_cache = false;
        let reference = engine.broad_npl(&empty).await.unwrap();
        assert_eq!(cached["result"]["rows"], reference["result"]["rows"]);
        assert_eq!(cached["schema_defaults"], reference["schema_defaults"]);
        assert_eq!(cached["budget"], reference["budget"]);
        all.push(answers);
    }
    assert_eq!(all[0], all[1]);
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
}

/// NAN-4285: a CIDR inside `IN (...)` / `NOT IN (...)` is network
/// membership -- the same answer as the equivalent `ip=cidr OR …` chain --
/// for search terms and `| where`, IPv4 and IPv6, mixed address+CIDR lists
/// and negation. The lists used to compile to a string IN-list, so
/// `IN (10.0.0.0/8)` matched nothing and `NOT IN (10.0.0.0/8)` everything.
/// Runs the real compiler (NANO_LAKE_COMPILER) and native chDB over parts.
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires pinned native chDB and lake compiler"]
async fn cidr_in_lists_are_network_membership_on_native_parts() {
    const IPS: &[Option<&str>] = &[
        Some("10.1.2.3"), Some("172.16.5.5"), Some("192.168.1.1"), Some("8.8.8.8"),
        Some("93.184.216.34"), Some("fe80::1"), Some("2001:db8::5"), Some("2001:4860::8888"), None,
    ];
    let now = chrono::DateTime::parse_from_rfc3339("2026-10-01T16:15:00Z").unwrap().with_timezone(&chrono::Utc);
    let base = now - chrono::Duration::minutes(10);
    let rows = (0..900).map(|i| {
        let time = (base + chrono::Duration::milliseconds(i as i64 * 100)).to_rfc3339();
        let mut event = json!({
            "activity_id": 6, "activity_name": "Traffic", "category_uid": 4, "category_name": "Network Activity",
            "class_uid": 4001, "class_name": "Network Activity", "type_uid": 400106,
            "severity": "Informational", "severity_id": 1, "time": time,
            "raw_data": format!("conn {i}"), "raw_data_size": format!("conn {i}").len(),
            "metadata": {"uid": format!("uid-{i:06}"), "version": "1.9.0", "log_source": "zeek_conn", "tenant_uid": TENANT,
                         "product": {"name": "Zeek", "vendor_name": "Zeek"}},
            "src_endpoint": {"ip": "10.9.9.9", "port": 50000},
        });
        if let Some(ip) = IPS[i % IPS.len()] {
            event["dst_endpoint"] = json!({"ip": ip, "port": 443});
        }
        event
    }).collect::<Vec<_>>();
    let in_net = |ip: &str, cidr: &str| -> bool {
        let ip: std::net::IpAddr = ip.parse().unwrap();
        let (net, bits) = cidr.split_once('/').unwrap();
        let (net, bits): (std::net::IpAddr, u32) = (net.parse().unwrap(), bits.parse().unwrap());
        match (ip, net) {
            (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
                let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                u32::from(a) & mask == u32::from(n) & mask
            }
            (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
                let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
                u128::from(a) & mask == u128::from(n) & mask
            }
            _ => false,
        }
    };
    let expect = |entries: &[&str], negated: bool| -> u64 {
        let member = |ip: &str| entries.iter().any(|entry| if entry.contains('/') { in_net(ip, entry) } else { ip == *entry });
        (0..rows.len()).filter(|i| match IPS[i % IPS.len()] {
            Some(ip) => member(ip) != negated,
            None => false,
        }).count() as u64
    };
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_over(dir.path(), &rows, true, now).await;
    let count = |query: String| {
        let engine = &engine;
        async move {
            let request: BroadNplRequest = serde_json::from_value(json!({
                "request_id":"nan4285", "tenant_id":TENANT, "dataset":"logs", "query":query,
                "start":base.to_rfc3339(), "end":now.to_rfc3339(), "limit":20, "table_view":true,
            })).unwrap();
            let answer = engine.broad_npl(&request).await.unwrap_or_else(|e| panic!("{query}: {e}"));
            answer["result"]["rows"][0]["count"].as_u64().unwrap_or_else(|| panic!("{query}: {answer}"))
        }
    };
    let private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"];
    let cases: &[(&[&str], &str)] = &[
        (&private, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"),
        (&["10.0.0.0/8"], "10.0.0.0/8"),
        (&["10.0.0.0/8", "8.8.8.8"], "10.0.0.0/8, 8.8.8.8"),
        (&["fe80::/10", "2001:db8::/32"], "\"fe80::/10\", \"2001:db8::/32\""),
        (&["2001:4860::8888", "fe80::/10", "192.168.0.0/16", "8.8.8.8"], "\"2001:4860::8888\", \"fe80::/10\", 192.168.0.0/16, 8.8.8.8"),
    ];
    for (entries, list) in cases {
        let (hit, miss) = (expect(entries, false), expect(entries, true));
        assert!(hit > 0 && miss > 0, "{list}: fixture must split the rows");
        for (query, expected) in [
            (format!("dst_endpoint.ip IN ({list}) | stats count"), hit),
            (format!("dst_endpoint.ip NOT IN ({list}) | stats count"), miss),
            (format!("* | where dst_endpoint.ip IN ({list}) | stats count"), hit),
            (format!("* | where dst_endpoint.ip NOT IN ({list}) | stats count"), miss),
        ] {
            assert_eq!(count(query.clone()).await, expected, "{query}");
        }
    }
    // The control the finding used: the OR chain, `=` and `!=`, here and in `| where`.
    let chain = private.iter().map(|c| format!("dst_endpoint.ip={c}")).collect::<Vec<_>>().join(" OR ");
    assert_eq!(count(format!("({chain}) | stats count")).await, expect(&private, false));
    assert_eq!(count("* | where dst_endpoint.ip=\"10.0.0.0/8\" | stats count".into()).await, expect(&["10.0.0.0/8"], false));
    assert_eq!(count("* | where dst_endpoint.ip!=\"10.0.0.0/8\" | stats count".into()).await, expect(&["10.0.0.0/8"], true));
    assert_eq!(count("* | where dst_endpoint.ip=\"fe80::/10\" | stats count".into()).await, expect(&["fe80::/10"], false));
    // After an aggregation the by-field is still an IP field.
    let request: BroadNplRequest = serde_json::from_value(json!({
        "request_id":"nan4285-by", "tenant_id":TENANT, "dataset":"logs",
        "query":"* | stats count by dst_endpoint.ip | where dst_endpoint.ip IN (10.0.0.0/8, 8.8.8.8)",
        "start":base.to_rfc3339(), "end":now.to_rfc3339(), "limit":20, "table_view":true,
    })).unwrap();
    let answer = engine.broad_npl(&request).await.unwrap();
    let mut seen = answer["result"]["rows"].as_array().unwrap().iter()
        .map(|row| row["dst_endpoint.ip"].as_str().map(str::to_owned).unwrap_or_else(|| row["dst_endpoint"]["ip"].to_string()))
        .collect::<Vec<_>>();
    seen.sort();
    assert_eq!(seen, vec!["10.1.2.3".to_string(), "8.8.8.8".to_string()], "{answer}");
}
