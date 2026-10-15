// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3715: query[T]'s operator routes over HTTP, as the cell router
//! forwards them: `POST /v1/debug/sql-probe` and `GET /v1/debug/slow-queries`
//! answer only a router-stamped request; the probe answers counts and cost,
//! never rows; the slow-query ring serves what real searches left in it.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --test nan3715_probe_routes_native -- --ignored --nocapture
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
use nanosiem_lake_worker::part_ingest::{
    IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue,
};
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
    LocalPartSigner::new("lab-signer-nan3715-01", SigningKey::from_bytes(&[37; 32])).unwrap()
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
    let (schema, _) =
        infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema))
        .with_batch_size(4_096)
        .build(Cursor::new(json))
        .unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| {
            ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None)
                .unwrap()
        });
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

async fn open_service(root: &Path) -> (Arc<QueryService>, tempfile::TempDir) {
    let state = tempfile::tempdir_in(root).unwrap();
    let trusted = signer().trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone())
        .await
        .unwrap();
    let head = view.head().map_or(0, |(seq, _)| seq);
    let bucket = "nan3715-local";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: state.path().join("cache"),
            max_bytes: GIB,
            query_max_bytes: GIB / 2,
            fetch_concurrency: 4,
            fetch_deadline: Duration::from_secs(60),
        },
        TENANT,
        bucket,
        &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local(
            bucket,
            store.clone(),
            root.join("parts"),
        )),
    )
    .unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let budget = QueryMemoryBudget::derive(3 * GIB, None);
    let executor = NativeExecutor::start_with_server_memory_limit(
        runtime.clone(),
        budget.concurrency,
        "parts",
        ExecutorMode::ReadOnly,
        Some(budget.server_bytes),
    )
    .unwrap()
    .with_result_limit(budget.result_bytes);
    let writer = NativeExecutor::start_with_server_memory_limit(
        runtime,
        1,
        "parts-rw",
        ExecutorMode::ReadWrite,
        Some(budget.server_bytes),
    )
    .unwrap();
    let engine = PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
            max_query_bytes: 64 * GIB,
            max_memory_bytes: budget.per_query_bytes,
            max_execution_seconds: 120,
            threads: 2,
        },
        store,
        view,
        fetcher,
        executor,
    )
    .unwrap()
    .with_writer(writer)
    .with_state_dir(state.path());
    let gate = DetectionGate::new(Some(state.path().to_path_buf()), head).unwrap();
    let service = QueryService::new(
        engine,
        gate,
        state.path().to_path_buf(),
        "compiler".into(),
        "chdb".into(),
        None,
        24,
        None,
    );
    service.clone().start_ready_with_background_prewarm();
    (service, state)
}

const STAMP: (&str, &str) = ("x-nano-cell-operator-debug", "admitted");

async fn call(
    service: &Arc<QueryService>,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
) -> (u16, Value) {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(service.clone().serve_stream(server));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client))
        .await
        .unwrap();
    tokio::spawn(connection);
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "cell")
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(Bytes::from(
            body.map_or_else(String::new, Value::to_string),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn operator_routes_answer_only_router_stamped_requests() {
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
        let mut ingestor = Ingestor::open(
            cfg,
            &parts,
            &sources,
            &spool as &dyn NoticeQueue,
            &signer,
            signer.trusted(),
            BronzeIngestEnricher::disabled(),
            &seed_schema(),
            now_ms,
        )
        .await
        .expect("ingest opens");
        let batch = (0..rows)
            .map(|i| {
                row(
                    i,
                    &(now
                        - chrono::Duration::milliseconds(
                            span_ms - span_ms * i as i64 / rows as i64,
                        ))
                    .to_rfc3339(),
                )
            })
            .collect::<Vec<_>>();
        write_bronze(&sources_dir.join("bronze/0000.parquet"), &batch);
        nanosiem_lake_worker::bronze::admit_bronze_files(
            &[sources_dir.join("bronze/0000.parquet")],
            TENANT,
        )
        .expect("bronze admitted");
        spool
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(),
                key: "bronze/0000.parquet".into(),
                version: "1".into(),
                bytes: 0,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: now_ms,
            })
            .unwrap();
        ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
        ingestor
            .flush_now(now_ms + 5_000)
            .await
            .expect("ingest flushes");
    }
    let (service, _state) = open_service(root.path()).await;
    let probe = json!({"tenant_id": TENANT, "start": (now - chrono::Duration::hours(1)).to_rfc3339(),
        "end": (now + chrono::Duration::minutes(1)).to_rfc3339(), "npl": "metadata.log_source=windows_sysmon | stats count() as n",
        "knobs": {"prune_blooms": false}});

    // Unstamped (what any non-operator caller looks like past the router).
    let (status, body) = call(&service, "POST", "/v1/debug/sql-probe", &[], Some(&probe)).await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = call(
        &service,
        "GET",
        "/v1/debug/slow-queries",
        &[("x-nano-cell-operator-debug", "yes")],
        None,
    )
    .await;
    assert_eq!(status, 403, "only the router's exact stamp admits: {body}");

    // Stamped: the probe answers cost and a row count, never rows.
    let (status, body) = call(
        &service,
        "POST",
        "/v1/debug/sql-probe",
        &[STAMP],
        Some(&probe),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["mode"], "engine");
    assert_eq!(body["rows"], 1);
    assert!(body["read"]["bytes"].as_u64().unwrap() > 0, "{body}");
    assert!(
        body.get("result").is_none() && !body.to_string().contains("uid-0000"),
        "no row data: {body}"
    );
    let mut other = probe.clone();
    other["tenant_id"] = json!("00000000-0000-4000-8000-000000000000");
    let (status, _) = call(
        &service,
        "POST",
        "/v1/debug/sql-probe",
        &[STAMP],
        Some(&other),
    )
    .await;
    assert_eq!(status, 400, "another tenant's id is refused");

    // The slow-query ring: what a slow real search left, replayable.
    let request: nanosiem_lake_worker::part_query::engine::BroadNplRequest = serde_json::from_value(json!({
        "request_id": "slow-1", "tenant_id": TENANT, "dataset": "logs", "query": "device.hostname=ws-001.corp.local",
        "start": "2026-10-12T00:00:00Z", "end": "2026-10-12T06:00:00Z", "limit": 100, "table_view": true,
        "deny_source_types": ["linux_audit"]})).unwrap();
    let answer = json!({"query_sha256": "ab", "result": {"result_rows": 2, "rows": [{"secret": 1}], "storage_bytes": 9}});
    assert!(service.slow_queries().observe(
        nanosiem_lake_worker::part_query::slow_queries::Observed::broad(
            "query",
            &request,
            2_500.0,
            None,
            Some(&answer),
            json!({"chdb_ms": 2_000.0})
        )
    ));
    let (status, body) = call(
        &service,
        "GET",
        "/v1/debug/slow-queries?min_ms=1000&limit=10",
        &[STAMP],
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let entry = &body["entries"][0];
    assert_eq!(entry["npl"], "device.hostname=ws-001.corp.local");
    assert_eq!(entry["window_seconds"], 6 * 3600);
    assert_eq!(entry["deny_source_types"], json!(["linux_audit"]));
    assert_eq!(entry["storage_bytes"], 9);
    assert!(
        !body.to_string().contains("secret"),
        "never row data: {body}"
    );
    let (_, body) = call(
        &service,
        "GET",
        "/v1/debug/slow-queries?min_ms=5000",
        &[STAMP],
        None,
    )
    .await;
    assert_eq!(body["entries"].as_array().map(Vec::len), Some(0));
}
