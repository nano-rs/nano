// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3081: a raw-row query over a source with no parts.
//!
//! On the pooled host (2026-09-30) `metadata.log_source="linux_audit" | where
//! class_uid=1001` answered HTTP 400 `Code: 352. Block structure mismatch
//! ... different types` from chDB: the tenant has windows_sysmon parts but no
//! linux_audit ones, so source-family pruning leaves no part and the engine
//! plans the typed empty relation of the read schema. The same query with a
//! `| table` projection answered 200 / 0 rows. A source that has no data
//! must answer 0 rows, not an engine error.
//!
//! Real ingest (seed schema), real part engine, the production chDB library:
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --test nan3081_empty_source_native -- --ignored --nocapture
//! ```
use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::part_query::detections::DetectionGate;
use nanosiem_lake_worker::part_query::engine::{EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::part_query::memory_budget::QueryMemoryBudget;
use nanosiem_lake_worker::part_query::server::QueryService;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::io::Cursor;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const TENANT: &str = "7a1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f42";
const GIB: u64 = 1024 * 1024 * 1024;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3081-01", SigningKey::from_bytes(&[31; 32])).unwrap()
}

/// A Sysmon process launch (class 1007) or file create (class 1001), all
/// from windows_sysmon; nothing from linux_audit / endpoint_edr.
fn row(i: usize, time: &str) -> Value {
    let host = format!("ws-{:03}.corp.local", i % 50);
    let raw = format!("event {i}");
    let common = json!({"severity_id": 1, "time": time, "raw_data_size": raw.len(), "raw_data": raw,
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "windows_sysmon", "tenant_uid": TENANT,
                     "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "device": {"hostname": host, "type_id": 2},
        "actor": {"process": {"name": "explorer.exe", "pid": 4, "cmd_line": "explorer.exe"}, "user": {"name": format!("user{}", i % 20)}}});
    let mut event = common;
    let obj = event.as_object_mut().unwrap();
    if i % 2 == 0 {
        obj.insert("class_uid".into(), json!(1007));
        obj.insert("class_name".into(), json!("Process Activity"));
        obj.insert("category_uid".into(), json!(1));
        obj.insert("type_uid".into(), json!(100701));
        obj.insert("activity_id".into(), json!(1));
        obj.insert("process".into(), json!({"name": "svchost.exe", "pid": i, "cmd_line": "svchost.exe -k netsvcs",
            "file": {"name": "svchost.exe", "type_id": 1, "hashes": [{"algorithm_id": 3, "value": format!("{i:064x}")}]}}));
    } else {
        obj.insert("class_uid".into(), json!(1001));
        obj.insert("class_name".into(), json!("File System Activity"));
        obj.insert("category_uid".into(), json!(1));
        obj.insert("type_uid".into(), json!(100101));
        obj.insert("activity_id".into(), json!(1));
        obj.insert("file".into(), json!({"name": format!("f{i}.txt"), "path": format!("C:\\Temp\\f{i}.txt"), "type_id": 1}));
    }
    event
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).with_batch_size(4_096).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

async fn open_service(root: &Path) -> (Arc<QueryService>, tempfile::TempDir) {
    let state = tempfile::tempdir_in(root).unwrap();
    let trusted = signer().trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let head = view.head().map_or(0, |(seq, _)| seq);
    let bucket = "nan3081-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.path().join("cache"), max_bytes: GIB, query_max_bytes: GIB / 2,
        fetch_concurrency: 4, fetch_deadline: Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let budget = QueryMemoryBudget::derive(3 * GIB, None);
    let executor = NativeExecutor::start_with_server_memory_limit(runtime.clone(), budget.concurrency, "parts", ExecutorMode::ReadOnly, Some(budget.server_bytes))
        .unwrap()
        .with_result_limit(budget.result_bytes);
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(budget.server_bytes)).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 64 * GIB, max_memory_bytes: budget.per_query_bytes, max_execution_seconds: 120, threads: 2,
    }, store, view, fetcher, executor).unwrap().with_writer(writer).with_state_dir(state.path());
    let gate = DetectionGate::new(Some(state.path().to_path_buf()), head).unwrap();
    let service = QueryService::new(engine, gate, state.path().to_path_buf(), "compiler".into(), "chdb".into(), None, 24, None);
    service.clone().start_ready_with_background_prewarm();
    (service, state)
}

async fn post(service: &Arc<QueryService>, body: &Value) -> (u16, Value) {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(service.clone().serve_stream(server));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
    tokio::spawn(connection);
    let request = Request::builder().method("POST").uri("/v1/query").header("host", "cell").header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn raw_rows_over_a_source_with_no_parts_answer_zero_rows() {
    let root = tempfile::tempdir().unwrap();
    let span_ms = 20 * 60_000_i64;
    let rows = 2_000;
    let now = chrono::Utc::now();
    {
        let parts = LocalObjectStore::new(root.path().join("parts")).unwrap();
        let sources_dir = root.path().join("sources");
        std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
        let sources = LocalObjectStore::new(&sources_dir).unwrap();
        let spool = SpoolQueue::new(root.path().join("spool"), TENANT).unwrap();
        let signer = signer();
        let mut cfg = IngestConfig::new(TENANT, root.path().join("work"));
        cfg.flush_interval_override_ms = Some(1_000);
        let now_ms = now.timestamp_millis();
        let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
        let batch = (0..rows)
            .map(|i| row(i, &(now - chrono::Duration::milliseconds(span_ms - span_ms * i as i64 / rows as i64)).to_rfc3339()))
            .collect::<Vec<_>>();
        write_bronze(&sources_dir.join("bronze/0000.parquet"), &batch);
        nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join("bronze/0000.parquet")], TENANT).expect("bronze admitted");
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/0000.parquet".into(), version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: now_ms }).unwrap();
        ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
        ingestor.flush_now(now_ms + 5_000).await.expect("ingest flushes");
    }
    let (service, _state) = open_service(root.path()).await;
    let start = (now - chrono::Duration::hours(1)).to_rfc3339();
    let end = (now + chrono::Duration::minutes(1)).to_rfc3339();
    let query = |q: &str| json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
        "dataset": "logs", "query": q, "start": start, "end": end, "limit": 1_001, "offset": 0, "table_view": false, "use_cache": false});

    // Controls: the populated source answers; the projected form of the
    // empty source already answered.
    let (status, body) = post(&service, &query("metadata.log_source=\"windows_sysmon\" | where class_uid=1001")).await;
    assert_eq!(status, 200, "{body}");
    assert!(!body["result"]["rows"].as_array().unwrap().is_empty());
    let (status, body) = post(&service, &query("metadata.log_source=\"linux_audit\" | where class_uid=1001 | table time, device.hostname, file.path")).await;
    assert_eq!(status, 200, "{body}");

    for q in [
        "metadata.log_source=\"linux_audit\" | where class_uid=1001",
        "metadata.log_source=\"linux_audit\" OR metadata.log_source=\"endpoint_edr\" | where class_uid=1001 AND activity_id=1",
        "metadata.log_source=\"linux_audit\" OR metadata.log_source=\"endpoint_edr\"\n| where class_uid=1001 AND activity_id=1\n| where file.path CONTAINS \"/etc/systemd/\" OR file.path CONTAINS \"/lib/systemd/\"\n| where file.path CONTAINS \".service\"",
        "metadata.log_source=\"linux_audit\"",
    ] {
        let (status, body) = post(&service, &query(q)).await;
        assert_eq!(status, 200, "{q}: {body}");
        assert_eq!(body["result"]["rows"].as_array().map(Vec::len), Some(0), "{q}");
    }
}
