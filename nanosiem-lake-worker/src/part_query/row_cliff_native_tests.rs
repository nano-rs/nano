// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3265, native: full-row newest-first pages of one source at and past
//! the old 1,000-row progressive line (limit x offset), with every whole
//! second a 20-way time tie, run end-to-end (real compiler, planner, parts,
//! chDB under a 256 MiB statement budget) and compared row-for-row, in
//! order, with the materialized page (the fixture sorted by `time DESC,
//! metadata.uid DESC`, then offset/limit).
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::engine::row_cliff_native -- --ignored --nocapture --test-threads=1
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
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const TENANT: &str = "3e1f6a2b-9c4d-4e5f-8a7b-6c5d4e3f2a1b";
/// Events per whole second (each second is a PER_SECOND-way tie).
const PER_SECOND: usize = 20;
const SECONDS: usize = 600;

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3265", ed25519_dalek::SigningKey::from_bytes(&[65; 32])).unwrap()
}

/// Every fifth event is another source the page must skip.
fn apache(i: usize) -> bool {
    i % 5 != 0
}

/// A scrambled uid, so uid order is not arrival order.
fn uid(i: usize) -> String {
    format!("uid-{:08x}", (i as u64).wrapping_mul(2_654_435_761) % 4_294_967_291)
}

fn event_time(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    let base = now.with_timezone(&Utc) - Duration::seconds(60);
    let base = DateTime::<Utc>::from_timestamp(base.timestamp(), 0).unwrap();
    base - Duration::seconds((i / PER_SECOND) as i64)
}

fn event(i: usize, now: DateTime<Utc>) -> Value {
    let source = if apache(i) { "apache_access" } else { "nginx_access" };
    let text = format!("GET /index.html?seq={i} HTTP/1.1 200");
    let raw = format!("10.0.0.{} - - {text} {}", i % 250, "x".repeat(200));
    json!({
        "class_uid": 4002, "category_uid": 4, "activity_id": 1, "type_uid": 400201, "severity_id": 1,
        "time": event_time(now, i).to_rfc3339_opts(SecondsFormat::Millis, true), "message": text,
        "raw_data_size": raw.len(), "raw_data": raw, "status": "Success",
        "metadata": {"uid": uid(i), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": source, "vendor_name": "fixture"}},
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": format!("web{}", i % 5)},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
        "http_request": {"http_method": "GET", "url": {"path": "/index.html"}},
    })
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

/// The events as four bronze files (four parts), oldest first.
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
    let rows = PER_SECOND * SECONDS;
    let quarter = rows / 4;
    for n in 0..4 {
        let range = (rows - (n + 1) * quarter)..(rows - n * quarter);
        let batch = range.map(|i| event(i, now)).collect::<Vec<_>>();
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

async fn engine(root: &std::path::Path) -> PartQueryEngine {
    engine_with_result_limit(root, 64 << 20).await
}

async fn engine_with_result_limit(root: &std::path::Path, result_limit: u64) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3265-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.join("cache"), max_bytes: 1 << 30, query_max_bytes: 1 << 29,
        fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let small = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(256 << 20))
        .unwrap().with_result_limit(result_limit);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
        max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20, max_execution_seconds: 120, threads: 2,
    }, store, view, fetcher, small).unwrap().with_writer(writer).with_large(large, 3 << 29).with_state_dir(&state)
}

fn granted() -> nanosiem_core::platform_enrichment::read::ReadAuthorization {
    use nanosiem_core::platform_enrichment::{AuthorizedRevision, FeedClass, RevisionReference};
    let tenant: uuid::Uuid = TENANT.parse().unwrap();
    let now = Utc::now();
    nanosiem_core::platform_enrichment::read::ReadAuthorization::from_resolved(tenant, now, &[AuthorizedRevision {
        tenant_id: tenant,
        reference: RevisionReference { feed_id: "ipinfo_lite".into(), feed_revision: 2, tier: "included".into(), grant_revision: 1, entitlement_revision: 1 },
        class: FeedClass::Baseline, digest: "0".repeat(64), mapping_revision: 1, deny_epoch: 0,
        valid_until: now + Duration::days(30), evaluated_at: now,
    }])
}

fn request(now: DateTime<Utc>, limit: usize, offset: usize, table_view: bool) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan3265".into(), tenant_id: TENANT.into(), dataset: "logs".into(),
        query: "metadata.log_source=\"apache_access\"".into(),
        start: (now - Duration::hours(1)).to_rfc3339(), end: (now + Duration::minutes(1)).to_rfc3339(),
        limit, offset, table_view, use_cache: false, cursor_time: None, cursor_event_uid: None,
        anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

fn row_uid(row: &Value) -> String {
    row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid")).and_then(Value::as_str)
        .unwrap_or_else(|| panic!("row without metadata.uid: {row}")).to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn deep_full_row_pages_walk_and_equal_the_materialized_page() {
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    // The materialized page: every apache event in event order.
    let mut truth = (0..PER_SECOND * SECONDS).filter(|i| apache(*i)).map(|i| (event_time(now, i), uid(i))).collect::<Vec<_>>();
    truth.sort_unstable_by(|a, b| b.cmp(a));
    let truth = truth.into_iter().map(|(_, uid)| uid).collect::<Vec<_>>();
    let mut matrix = Vec::new();
    for table_view in [false, true] {
        for (limit, offset) in [(200, 0), (750, 0), (999, 0), (1_000, 0), (200, 800), (2_000, 0), (5_000, 0), (200, 4_500), (8_000, 1_000)] {
            let started = std::time::Instant::now();
            let answer = crate::query_timing::measure("nan3265", Box::pin(crate::enrichment_read::scope(granted(),
                engine.broad_npl(&request(now, limit, offset, table_view))))).await
                .unwrap_or_else(|error| panic!("limit {limit} offset {offset} (table_view={table_view}): {error}"));
            let wall = started.elapsed().as_secs_f64();
            let rows = answer["result"]["rows"].as_array().unwrap_or_else(|| panic!("no rows in {answer}"));
            let got = rows.iter().map(row_uid).collect::<Vec<_>>();
            let expected = truth.iter().skip(offset).take(limit).cloned().collect::<Vec<_>>();
            assert_eq!(got.len(), expected.len(), "limit {limit} offset {offset} (table_view={table_view})");
            assert!(got == expected, "limit {limit} offset {offset} (table_view={table_view}): first mismatch at {:?}",
                got.iter().zip(&expected).position(|(a, b)| a != b));
            assert_eq!(answer["result"]["page_has_more"].as_bool(), Some(truth.len() > offset + limit));
            let planner = &answer["planner"];
            assert_eq!(planner["kind"], "progressive_newest_first", "limit {limit} offset {offset}: every newest-first page walks");
            matrix.push(format!("table_view={table_view:<5} limit {limit:>5} offset {offset:>5}: {wall:>6.3}s chunks {:>3} continuations {:>3} statements {:>3} capped {}",
                planner["chunks_executed"], planner["chunk_continuations"], planner["successful_native_statements"], planner["row_capped"]));
        }
    }
    eprintln!("NAN-3265 native page matrix ({} apache rows, {PER_SECOND}-way ties):\n{}", truth.len(), matrix.join("\n"));
}

/// NAN-3270, native: under a 1 MiB result budget (~1 KB decoded rows) a
/// 2,000-row page comes back cut by bytes with the `(time, uid)` cursor of
/// its last row, never refused; continuing from the cursor (as the search
/// service does) fills exactly the materialized page; a deep offset is
/// walked as stubs and served whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn byte_cut_pages_continue_to_the_materialized_page() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine_with_result_limit(root.path(), 1 << 20).await;
    let mut truth = (0..PER_SECOND * SECONDS).filter(|i| apache(*i)).map(|i| (event_time(now, i), uid(i))).collect::<Vec<_>>();
    truth.sort_unstable_by(|a, b| b.cmp(a));
    let truth = truth.into_iter().map(|(_, uid)| uid).collect::<Vec<_>>();
    let run = |request: BroadNplRequest| {
        let engine = &engine;
        async move {
            crate::query_timing::measure("nan3270", Box::pin(crate::enrichment_read::scope(granted(), engine.broad_npl(&request)))).await
                .unwrap_or_else(|error| panic!("limit {} offset {}: {error}", request.limit, request.offset))
        }
    };
    for table_view in [false, true] {
        let (limit, offset) = (2_000_usize, 0_usize);
        let mut got = Vec::new();
        let mut request = request(now, limit, offset, table_view);
        let mut answers = 0;
        let mut cut = false;
        loop {
            let answer = run(request.clone()).await;
            answers += 1;
            assert!(answers <= 16, "fill made no progress");
            let rows = answer["result"]["rows"].as_array().unwrap();
            assert!(!rows.is_empty() || answer["result"]["continuation"].is_null());
            got.extend(rows.iter().map(row_uid));
            let Some(next) = answer["result"]["continuation"].as_object() else {
                assert_eq!(answer["result"]["page_has_more"].as_bool(), Some(truth.len() > offset + limit));
                break;
            };
            cut = true;
            assert_eq!(answer["result"]["page_byte_cut"], true);
            assert_eq!(answer["result"]["page_has_more"], true);
            assert_eq!(answer["planner"]["byte_cut"], true);
            assert!(answer["planner"]["held_bytes"].as_u64().unwrap() <= (1 << 20) / 100 * 75 + 4_096);
            assert_eq!(next["cursor_event_uid"].as_str(), got.last().map(String::as_str), "the cursor is the last row returned");
            if got.len() >= limit {
                break;
            }
            request.offset = 0;
            request.limit = limit - got.len();
            request.cursor_time = Some(next["cursor_time"].as_str().unwrap().to_string());
            request.cursor_event_uid = Some(next["cursor_event_uid"].as_str().unwrap().to_string());
        }
        assert!(cut || table_view, "2,000 full rows exceed a 1 MiB result budget");
        let expected = truth.iter().skip(offset).take(limit).cloned().collect::<Vec<_>>();
        assert!(got == expected, "table_view={table_view}: {} rows, first mismatch at {:?}", got.len(),
            got.iter().zip(&expected).position(|(a, b)| a != b));
        eprintln!("NAN-3270 native: table_view={table_view} limit {limit}: {answers} answers");
        // A deep offset: its rows are stubs, the page itself fits.
        let answer = run(self::request(now, 300, 1_500, table_view)).await;
        let rows = answer["result"]["rows"].as_array().unwrap().iter().map(row_uid).collect::<Vec<_>>();
        assert_eq!(rows, truth[1_500..1_800].to_vec(), "table_view={table_view} offset 1500");
        assert!(answer["result"]["continuation"].is_null());
    }
}
