// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2998: dotted keys under `unmapped` on the lean path.
//!
//! The ocsf-1.9 catalog parsers' NAN-2421 residual spill writes flat dotted
//! keys inside `unmapped` (`unmapped["event_data.destination_hostname"]`).
//! This drives such rows through bronze admission, `ingest[T]` (signed L0
//! parts) and the native part query engine.
//!
//! Bronze comes from `NAN2998_BRONZE_DIR` when set (real Container Vector
//! 0.57 parquet from the catalog parsers), else it is written here.
//!
//! Run: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER,
//! `cargo test -p nanosiem-lake-worker --test nan2998_dotted_unmapped_native -- --ignored --nocapture`

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
const SIGNER_KEY_ID: &str = "lab-signer-test-0001";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new(SIGNER_KEY_ID, SigningKey::from_bytes(&[11; 32])).unwrap()
}

fn trusted() -> TenantKeySet {
    signer().trusted()
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// A windows_sysmon EID 3 row shaped like the ocsf-1.9 catalog parser output.
fn sysmon_row(uid: &str, time: &str) -> Value {
    json!({
        "activity_id": 1, "activity_name": "Open", "category_uid": 4, "category_name": "Network Activity",
        "class_uid": 4001, "class_name": "Network Activity", "type_uid": 400101,
        "severity": "Informational", "severity_id": 1, "status": "Success", "status_id": 1,
        "time": time,
        "raw_data": format!("sysmon NetworkConnect {uid:>8}"),
        "raw_data_size": 30,
        "metadata": {"uid": uid, "version": "1.9.0", "log_source": "windows_sysmon", "tenant_uid": TENANT,
                     "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "src_endpoint": {"ip": "10.1.1.152", "port": 57028},
        "dst_endpoint": {"ip": "105.240.28.169", "port": 53},
        "unmapped": {
            "event_data.destination_hostname": "-",
            "event_data.rule_name": "NetworkConnect",
            "keywords": "0x8000000000000000",
            "level_value": 4
        }
    })
}

fn notice(key: &str, at_ms: i64) -> SourceNotice {
    SourceNotice {
        tenant_id: TENANT.into(), key: key.into(), version: "1".into(), bytes: 0,
        sha256: None, edge_sha256: None, notified_at_ms: at_ms,
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256 and NANO_LAKE_COMPILER"]
async fn dotted_unmapped_keys_ingest_and_query_natively() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let now = chrono::Utc::now();
    let mut keys = Vec::new();
    let (start, end, expected_dash) = if let Ok(src) = std::env::var("NAN2998_BRONZE_DIR") {
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            std::fs::copy(&path, sources_dir.join("bronze").join(&name)).unwrap();
            keys.push(format!("bronze/{name}"));
        }
        let expected: Option<u64> = std::env::var("NAN2998_EXPECT_DASH").ok().map(|v| v.parse().unwrap());
        (std::env::var("NAN2998_START").unwrap(), std::env::var("NAN2998_END").unwrap(), expected)
    } else {
        let time = (now - chrono::Duration::seconds(30)).to_rfc3339();
        let mut rows = (0..5).map(|i| sysmon_row(&format!("uid-{i}"), &time)).collect::<Vec<_>>();
        match std::env::var("NAN2998_COLLIDE").as_deref() {
            // A nested object and a flat dotted sibling under the same prefix.
            Ok("sibling") => rows[0]["unmapped"] = json!({"moat": {"chain": "c"}, "moat.acked": true}),
            // The same flattened name twice: nested moat.acked and flat "moat.acked".
            Ok("duplicate") => rows[0]["unmapped"] = json!({"moat": {"acked": false}, "moat.acked": true}),
            _ => {}
        }
        write_bronze(&sources_dir.join("bronze/0001.parquet"), &rows);
        keys.push("bronze/0001.parquet".into());
        ((now - chrono::Duration::minutes(10)).to_rfc3339(), (now + chrono::Duration::minutes(10)).to_rfc3339(),
         Some(if std::env::var("NAN2998_COLLIDE").is_ok() { 4 } else { 5 }))
    };
    keys.sort();
    for key in &keys {
        match nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join(key)], TENANT) {
            Ok(a) => eprintln!("admission {key}: {} rows", a.batch.into_rows().len()),
            Err(e) => eprintln!("admission {key} FAILED: {e:#}"),
        }
    }

    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
    for key in &keys {
        spool.deliver(&notice(key, now_ms)).unwrap();
    }
    let report = ingestor.tick(now_ms + 1_000).await.expect("ingest admits dotted unmapped keys");
    eprintln!("tick: admitted={} dups={} flushed={}", report.admitted_rows, report.duplicates, report.flushed_parts);
    ingestor.flush_now(now_ms + 5_000).await.expect("ingest flushes dotted unmapped keys into signed parts");
    assert!(spool.pending(1).await.unwrap().is_empty(), "every notice acked (none refused)");
    let live = load_log(&parts, TENANT).await.unwrap();
    assert!(live.parts().next().is_some(), "a signed part was published");
    drop(ingestor);

    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted()).await.unwrap();
    let bucket = "nan2998-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: root.join("query-cache"), max_bytes: 256 << 20, query_max_bytes: 256 << 20,
        fetch_concurrency: 2, fetch_deadline: Duration::from_secs(30),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted(), cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime, 1, "nan2998-native", ExecutorMode::ReadOnly).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 256 << 20, max_memory_bytes: 1 << 30, max_execution_seconds: 60, threads: 1,
    }, store, view, fetcher, executor).unwrap();
    let request = |query: &str| BroadNplRequest {
        request_id: uuid::Uuid::new_v4().to_string(), tenant_id: TENANT.into(),
        dataset: "logs".into(), query: query.into(), start: start.clone(), end: end.clone(),
        limit: 10, offset: 0, table_view: false, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: BTreeMap::new(), watch_weights: Default::default(), minimum_clear_revision: None, deny_source_types: BTreeSet::new(),
    };
    let mut failures = Vec::new();
    for q in [
        "* | stats count",
        "*",
        "NetworkConnect | stats count",
        "class_uid=4001 | stats count",
        "unmapped.keywords=\"0x8000000000000000\" | stats count",
        "unmapped.event_data.destination_hostname=\"-\" | stats count",
        "* | table unmapped.event_data.rule_name, unmapped.event_data.destination_hostname",
        "* | stats count by unmapped.event_data.rule_name",
        "unmapped.moat.acked=true | stats count",
        "* | table unmapped.moat.chain",
    ] {
        match engine.broad_npl(&request(q)).await {
            Ok(value) => eprintln!("OK   {q}\n     {}", value["result"]["rows"].to_string().chars().take(300).collect::<String>()),
            Err(error) => { eprintln!("FAIL {q}\n     {error:#}"); failures.push(format!("{q}: {error:#}")); }
        }
    }
    if let Some(expected) = expected_dash {
        let v = engine.broad_npl(&request("unmapped.event_data.destination_hostname=\"-\" | stats count")).await.unwrap();
        assert_eq!(v["result"]["rows"][0]["count"], expected, "{v}");
    }
    // A collision (a nested object AND a flat dotted sibling under one prefix)
    // only breaks queries that name the ambiguous path itself; every other
    // query over the same signed part keeps working, and ingest never refuses.
    let collide = std::env::var("NAN2998_COLLIDE").is_ok();
    let unexpected = failures.iter()
        .filter(|f| !(collide && f.starts_with("unmapped.moat.acked=true")))
        .collect::<Vec<_>>();
    assert!(unexpected.is_empty(), "native queries failed: {unexpected:#?}");
    if collide { assert_eq!(failures.len(), 1, "the ambiguous path is the only failure: {failures:#?}"); }
}
