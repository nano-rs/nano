// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3644, native: a read over the cold ceiling runs in batches and
//! answers exactly what an engine with room for the whole window answers,
//! for aggregations of every kind, an empty match, a newest-first row page
//! and a durable job's spooled result.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::cold_batches_native -- --ignored --nocapture --test-threads=1
//! ```

use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use crate::part_query::log_view::PartLogView;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const TENANT: &str = "5b1d2c3e-4f5a-4b6c-8d7e-9f0a1b2c3d4e";
const FILES: usize = 4;
const ROWS_PER_FILE: usize = 300;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3644", ed25519_dalek::SigningKey::from_bytes(&[44; 32])).unwrap()
}

fn source(i: usize) -> &'static str {
    ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3]
}

fn event(i: usize, time: &str) -> Value {
    let raw = format!("raw {i} {}", "y".repeat(400));
    let mut row = json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": format!("event {i} {}", "x".repeat(200)), "raw_data_size": raw.len(), "raw_data": raw,
        "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source(i), "tenant_uid": TENANT,
                     "product": {"name": source(i), "vendor_name": "fixture"}},
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 5, i % 17), "hostname": format!("host{}", i % 13)},
        // Skewed so `rare`/`top` have no ties: dst0..dst5 hold 20, 40, 76,
        // 152, 304 and 608 of the 1,200 rows.
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443, "hostname": format!("dst{}", ((i % 63) + 1).ilog2())},
    });
    if source(i) == "conduit_proxy" {
        row["traffic"] = json!({"bytes_out": (i as i64 * 37) % 5_000 + 1, "bytes_in": 10});
    }
    row
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut lines, event).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema)).build(std::io::Cursor::new(lines)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap())
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// `FILES` bronze files (a part per file and event hour), newest first, rows 10 s apart.
async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
    for n in 0..FILES {
        let range = n * ROWS_PER_FILE..(n + 1) * ROWS_PER_FILE;
        let batch = range.map(|i| event(i, &(now - Duration::seconds(i as i64 * 10 + 30)).to_rfc3339())).collect::<Vec<_>>();
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        let at = now_ms + n as i64 * 10_000;
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: at }).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
}

fn runtime() -> NativeChdb {
    static RUNTIME: std::sync::OnceLock<NativeChdb> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    ).unwrap()).clone()
}

/// An engine over the fixture whose reader cache holds `cache_bytes`, with
/// `query_bytes` as its heavy threshold (one heavy slot).
async fn engine(root: &std::path::Path, name: &str, cache_bytes: u64, query_bytes: u64) -> PartQueryEngine {
    let signer = signer();
    let state = root.join(name);
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3644-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.join("cache"), max_bytes: cache_bytes, query_max_bytes: query_bytes,
        fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = runtime();
    let small = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(256 << 20))
        .unwrap().with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
        max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20, max_execution_seconds: 120, threads: 2,
    }, store, view, fetcher, small).unwrap().with_writer(writer).with_large(large, 3 << 29).with_state_dir(&state)
}

fn request(query: &str, now: DateTime<Utc>, id: &str) -> BroadNplRequest {
    BroadNplRequest {
        request_id: id.into(), tenant_id: TENANT.into(), dataset: "logs".into(), query: query.into(),
        start: (now - Duration::hours(24)).to_rfc3339(), end: (now + Duration::minutes(1)).to_rfc3339(),
        limit: 500, offset: 0, table_view: false, use_cache: false, cursor_time: None, cursor_event_uid: None,
        anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

fn granted() -> nanosiem_core::platform_enrichment::read::ReadAuthorization {
    nanosiem_core::platform_enrichment::read::ReadAuthorization::from_resolved(TENANT.parse().unwrap(), Utc::now(), &[])
}

async fn answer(engine: &PartQueryEngine, query: &str, now: DateTime<Utc>, id: &str) -> Value {
    let request = request(query, now, id);
    crate::query_timing::measure(id, Box::pin(crate::enrichment_read::scope(granted(), engine.broad_npl(&request)))).await
        .unwrap_or_else(|error| panic!("{query}: {error}"))
}

/// Rows in a canonical order (unordered aggregates may come back in any).
fn canonical(answer: &Value, ordered: bool) -> Vec<String> {
    let mut rows = answer["result"]["rows"].as_array().unwrap_or_else(|| panic!("no rows in {answer}"))
        .iter().map(Value::to_string).collect::<Vec<_>>();
    if !ordered {
        rows.sort();
    }
    rows
}

/// Total data bytes of every part, and the largest part's.
async fn part_bytes(engine: &PartQueryEngine, now: DateTime<Utc>) -> (u64, u64) {
    let (parts, _, _, _) = engine.snapshot((now - Duration::hours(24)).timestamp_micros(), now.timestamp_micros()).await.unwrap();
    // Parts are per event hour, so a file spanning an hour boundary is two.
    assert!(parts.len() >= FILES, "at least one part per bronze file");
    let records = engine.fetcher().records(&parts).await.unwrap();
    let sizes = records.iter().map(|record| record.files.data.iter().map(|data| data.bytes).sum::<u64>()).collect::<Vec<_>>();
    (sizes.iter().sum(), *sizes.iter().max().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn reads_over_the_cold_ceiling_run_in_batches_and_match_the_whole_window() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    std::env::remove_var(crate::part_query::range_fetch::FLAG);
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let truth = engine(root.path(), "truth", 1 << 30, 1 << 29).await;
    let (total, largest) = part_bytes(&truth, now).await;
    // One heavy slot and a threshold of half the largest part: the ceiling
    // is cache - threshold = 2.5x the largest, leaving the threshold free
    // for sidecars as on a cell. It admits any one part but not the whole
    // window, and a batch (half the ceiling) holds a part or two.
    let (cache_bytes, query_bytes) = (largest * 3, largest / 2);
    assert!(total > cache_bytes, "the whole window must be over the ceiling ({total} vs {cache_bytes})");
    let small = engine(root.path(), "small", cache_bytes, query_bytes).await;
    let cases: &[(&str, bool)] = &[
        ("* | stats count by metadata.log_source", false),
        ("* | stats dc(src_endpoint.hostname) as hosts, count by metadata.log_source", false),
        ("metadata.log_source=conduit_proxy | stats avg(traffic.bytes_out) as avg_out, sum(traffic.bytes_out) as total by src_endpoint.ip | sort -total | head 5", true),
        ("* | rare limit=3 dst_endpoint.hostname", true),
        ("* | top limit=2 dst_endpoint.hostname", true),
        ("* | timechart span=1h count", true),
        ("* | eval h=upper(src_endpoint.hostname) | stats count by h | sort -count, h | head 3", true),
        ("* | stats earliest(time) as first, latest(time) as last, count by metadata.log_source", false),
    ];
    for (index, (query, ordered)) in cases.iter().enumerate() {
        let expected = answer(&truth, query, now, &format!("truth-{index}")).await;
        small.fetcher().cache().evict_unreferenced(Default::default()).await.unwrap();
        let got = answer(&small, query, now, &format!("small-{index}")).await;
        let batches = got["planner"]["cold_batches"]["batches"].as_u64()
            .unwrap_or_else(|| panic!("{query}: the small cache did not batch: {}", got["planner"]));
        assert!(batches >= 2, "{query}: {batches} batch(es)");
        assert_eq!(canonical(&got, *ordered), canonical(&expected, *ordered), "{query}");
        assert!(!canonical(&got, *ordered).is_empty(), "{query}: no rows");
    }

    // No batch matches a row: the answer over an empty input.
    // A regex is not pruned by any index, so every file is leased and
    // every batch's first stage comes back empty.
    let query = "message=/zz-no-such-text-zz/ | stats count";
    let expected = answer(&truth, query, now, "truth-empty").await;
    small.fetcher().cache().evict_unreferenced(Default::default()).await.unwrap();
    let got = answer(&small, query, now, "small-empty").await;
    // Each batch spools an empty Native frame (a few bytes, no rows); the
    // final read takes its structure from the first stage, not the file.
    assert!(got["planner"]["cold_batches"]["spill_bytes"].as_u64().unwrap() < 1024, "{}", got["planner"]);
    assert_eq!(canonical(&got, false), canonical(&expected, false));

    // A newest-first row page walks its chunks, splitting any chunk over
    // the ceiling, and returns the same newest rows.
    let query = "metadata.log_source=windows_sysmon | head 250";
    let expected = answer(&truth, query, now, "truth-page").await;
    small.fetcher().cache().evict_unreferenced(Default::default()).await.unwrap();
    let got = answer(&small, query, now, "small-page").await;
    let uids = |answer: &Value| answer["result"]["rows"].as_array().unwrap().iter()
        .map(|row| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid")).and_then(Value::as_str).unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(uids(&got).len(), 250);
    assert_eq!(uids(&got), uids(&expected));

    // A durable job's batched read: the final statement spooled to Parquet
    // (as `jobs::run_search_job` runs it) holds the whole window's answer.
    small.fetcher().cache().evict_unreferenced(Default::default()).await.unwrap();
    let query = "* | stats count by metadata.log_source";
    let request = request(query, now, "job");
    let compiled = small.compile(&request, small.field_types().await.unwrap()).await.unwrap();
    let window = crate::part_query::engine::compiled_window_us(&compiled).unwrap();
    let refused = small.select_with(window.0, window.1, &compiled.candidate_hints, None).await.err();
    let Some(crate::part_query::engine::PartQueryError::ColdScanTooLarge { needed_bytes, .. }) = refused else {
        panic!("the whole window must be refused by the small cache: {refused:?}");
    };
    let batched = crate::enrichment_read::scope(granted(), small.cold_batches(&compiled, window, None, needed_bytes, Default::default())).await.unwrap();
    let out = tempfile::tempdir().unwrap();
    let path = out.path().join("result.parquet");
    let mut plan = batched.plan.clone();
    plan.params.push(("job_result_output".into(), path.to_str().unwrap().into()));
    plan.sql = format!("INSERT INTO FUNCTION file({{job_result_output:String}}, Parquet) {}", plan.sql);
    small.writer().unwrap().execute(plan).await.unwrap();
    let rows = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&path).unwrap())
        .unwrap().build().unwrap().map(|batch| batch.unwrap().num_rows()).sum::<usize>();
    assert_eq!(rows, 3, "one group per log source");
}
