// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3150, native: lean-gate k6 query shapes that failed in chDB on a lake
//! cell, run end-to-end (real compiler, planner, parts, chDB) and checked
//! against fixture-derived truth and their `| where` equivalents.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::engine::lean_query_native -- --ignored --nocapture --test-threads=1
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

#[path = "native_scan_native_tests.rs"]
mod native_scan;

#[path = "two_pass_ocsf_native_tests.rs"]
mod two_pass_ocsf;

// Historical hosted parser outputs and their fixture stay in the private edition.
#[cfg(feature = "enterprise")]
#[path = "landing_receipts_hosted_tests.rs"]
mod landing_receipts_hosted;

pub(crate) const TENANT: &str = "7a3c1e5b-2d4f-4b6a-8c9e-0f1a2b3c4d5e";
pub(crate) const ROWS: usize = 900;
const HASH: &str = "14e0857b37f6c5e5e90bab786a4db8fceb4166afe75e617519d942656976481e";
const PROXY_IP: &str = "10.1.5.242";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3150", ed25519_dalek::SigningKey::from_bytes(&[50; 32])).unwrap()
}

pub(crate) fn source(i: usize) -> &'static str {
    ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3]
}

/// The hash appears only in sysmon events (never in CloudTrail), so the OR
/// shape's two arms select disjoint rows.
fn has_hash(i: usize) -> bool {
    source(i) == "windows_sysmon" && i % 7 == 1
}

fn bytes_out(i: usize) -> i64 {
    (i as i64 * 37) % 5_000 + 1
}

fn proxy_hit(i: usize) -> bool {
    source(i) == "conduit_proxy" && i % 4 != 0
}

fn event(i: usize, time: &str, with_traffic: bool) -> Value {
    let text = match source(i) {
        "windows_sysmon" if has_hash(i) => format!("Process Create rundll32.exe Hashes: SHA256={HASH} seq {i}"),
        "windows_sysmon" => format!("Process Create svchost.exe seq {i}"),
        "conduit_proxy" => format!("CONNECT proxy flow seq {i}"),
        _ => format!("AssumeRole call seq {i}"),
    };
    let mut row = json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": text, "raw_data": format!("raw {text}"), "raw_data_size": text.len() + 4, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source(i), "tenant_uid": TENANT,
                     "product": {"name": source(i), "vendor_name": "fixture"}},
        // NAN-3154: every other source hostname is a mixed-case FQDN
        // (admission lowercases it), so a dotless `hostN` literal must match
        // both spellings.
        "src_endpoint": {"ip": if proxy_hit(i) { PROXY_IP.to_string() } else { format!("10.0.{}.{}", i % 7, i % 200) },
                         "hostname": if i % 2 == 0 { format!("HOST{}.Corp.Local", i % 11) } else { format!("host{}", i % 11) }},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443, "hostname": format!("host{}", i % 11)},
    });
    if with_traffic && source(i) == "conduit_proxy" {
        row["traffic"] = json!({"bytes_out": bytes_out(i), "bytes_in": 10});
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

/// Two bronze files, two parts: the older one predates `traffic` entirely
/// (a typed column the newer part carries and the older one lacks).
pub(crate) async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    ingest_rows(root, now, ROWS, 7_000).await
}

/// `rows` events `spacing_ms` apart, newest first, as two bronze files.
async fn ingest_rows(root: &std::path::Path, now: DateTime<Utc>, rows: usize, spacing_ms: i64) {
    let half = rows / 2;
    let batches = [(half..rows, false), (0..half, true)].into_iter().map(|(range, traffic)| {
        range.map(|i| event(i, &(now - Duration::milliseconds(i as i64 * spacing_ms + 30_000)).to_rfc3339(), traffic)).collect::<Vec<_>>()
    }).collect::<Vec<_>>();
    ingest_batches(root, now, batches).await
}

/// Each batch is one bronze file and one part.
async fn ingest_batches(root: &std::path::Path, now: DateTime<Utc>, batches: Vec<Vec<Value>>) {
    ingest_batches_with_merges(root, now, batches, true).await
}

async fn ingest_batches_with_merges(root: &std::path::Path, now: DateTime<Utc>, batches: Vec<Vec<Value>>, merge: bool) {
    ingest_batches_with_probe_key(root, now, batches, merge, None).await;
}
async fn ingest_batches_with_probe_key(root: &std::path::Path, now: DateTime<Utc>, batches: Vec<Vec<Value>>, merge: bool,
    key: Option<nanosiem_core::platform_probe::PlatformProbeKey>) -> crate::part_ingest::landing_receipts::Receipts {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    *config.platform_probe_key.write().unwrap() = key;
    if !merge { config.max_merges_per_tick = 0; }
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
    for (n, batch) in batches.into_iter().enumerate() {
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        let at = now_ms + n as i64 * 10_000;
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: at }).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    ingestor.landing_receipts.clone()
}

pub(crate) async fn engine(root: &std::path::Path) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3150-local";
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
        .unwrap().with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
        max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20, max_execution_seconds: 120, threads: 2,
    }, store, view, fetcher, small).unwrap().with_writer(writer).with_large(large, 3 << 29).with_state_dir(&state)
}

fn request(query: &str, now: DateTime<Utc>, table_view: bool) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan3150".into(), tenant_id: TENANT.into(), dataset: "logs".into(), query: query.into(),
        start: (now - Duration::hours(24)).to_rfc3339(), end: (now + Duration::minutes(1)).to_rfc3339(),
        limit: 200, offset: 0, table_view, use_cache: true, cursor_time: None, cursor_event_uid: None,
        anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
        // The live search key's lake scope hides `audit` (the k6 failure's
        // statement carried `notEquals(lower(__nano_path_0), 'audit')`).
        deny_source_types: ["audit".to_string()].into_iter().collect(),
    }
}

async fn rows(engine: &PartQueryEngine, query: &str, now: DateTime<Utc>, table_view: bool) -> Vec<Value> {
    // Production runs every statement under `query_timing::measure`
    // (the interactive deadline and streamed native execution).
    let request = request(query, now, table_view);
    let answer = crate::query_timing::measure("nan3150", Box::pin(engine.broad_npl(&request))).await
        .unwrap_or_else(|error| panic!("{query} (table_view={table_view}): {error}"));
    answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows array in {answer}"))
}

fn uids(rows: &[Value]) -> Vec<String> {
    let mut uids = rows.iter().map(|row| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid"))
        .and_then(Value::as_str).unwrap_or_else(|| panic!("row without metadata.uid: {row}")).to_string()).collect::<Vec<_>>();
    uids.sort();
    uids
}

fn count(rows: &[Value]) -> u64 {
    assert_eq!(rows.len(), 1, "{rows:?}");
    let value = &rows[0]["count"];
    value.as_u64().or_else(|| value.as_str().and_then(|s| s.parse().ok())).unwrap_or_else(|| panic!("count in {rows:?}"))
}

/// k6 `structured:source_or_unique_hash`: an OR of a field equality and a
/// bare keyword died natively with `Not found column
/// lower(__table5.__nano_path_0) in block`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn field_equality_or_bare_keyword_executes_and_matches_truth() {
    // Production cells run with the part result cache (locators) on.
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    // Rows are newest first: a smaller index is a newer event.
    let truth = |keep: &dyn Fn(usize) -> bool, page: usize| -> Vec<String> {
        let mut uids = (0..ROWS).filter(|i| keep(*i)).take(page).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();
        uids.sort();
        uids
    };
    let either = |i: usize| source(i) == "aws_cloudtrail" || has_hash(i);
    let expected = truth(&either, usize::MAX);
    let hash_only = (0..ROWS).filter(|i| has_hash(*i)).count() as u64;
    assert!(hash_only > 0 && expected.len() > 200);
    // The k6 shape (request limit 200, `| head 100`) and its variants.
    for (query, page) in [
        (format!("metadata.log_source=aws_cloudtrail OR {HASH} | head 100"), 100),
        (format!("metadata.log_source=aws_cloudtrail OR {HASH}"), 200),
        (format!("{HASH} OR metadata.log_source=aws_cloudtrail | head 50"), 50),
    ] {
        for table_view in [true, false] {
            let got = rows(&engine, &query, now, table_view).await;
            assert_eq!(uids(&got), truth(&either, page), "{query} (table_view={table_view})");
        }
    }
    // The streamed raw-event read (`/v1/query/pages`) of the same shape.
    for page_rows in [50, 500] {
        // A 24 h window is not announced newest-first for streaming (the
        // envelope says so and the caller falls back to `broad_npl`); the
        // streamed path is exercised over the fixture's own 3 h.
        let mut request = request(&format!("metadata.log_source=aws_cloudtrail OR {HASH}"), now, false);
        request.start = (now - Duration::hours(3)).to_rfc3339();
        let streamed = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
        let sink = streamed.clone();
        crate::query_timing::measure("nan3150-pages", Box::pin(engine.broad_npl_pages(&request, page_rows, move |line| {
            let rows = match line {
                crate::part_query::engine::PagedLine::Envelope(envelope) => envelope["result"]["rows"].as_array().cloned().unwrap_or_default(),
                crate::part_query::engine::PagedLine::Page(rows) => rows,
            };
            sink.lock().unwrap().extend(rows);
            async { true }
        }))).await.unwrap_or_else(|error| panic!("streamed pages ({page_rows}): {error}"));
        let streamed = streamed.lock().unwrap().clone();
        assert_eq!(uids(&streamed), truth(&either, 200), "streamed pages ({page_rows})");
    }
    let got = count(&rows(&engine, &format!("metadata.log_source=aws_cloudtrail OR {HASH} | stats count"), now, false).await);
    assert_eq!(got, expected.len() as u64);
    // The `| where` equivalent of the field arm, and each arm alone.
    let field_arm = count(&rows(&engine, "* | where metadata.log_source=\"aws_cloudtrail\" | stats count", now, false).await);
    let keyword_arm = count(&rows(&engine, &format!("{HASH} | stats count"), now, false).await);
    assert_eq!(keyword_arm, hash_only);
    assert_eq!(field_arm + keyword_arm, got, "the arms are disjoint");
    // Same shape on other paths: a nested leaf and a top-level column.
    for (query, truth) in [
        (format!("dst_endpoint.hostname=host3 OR {HASH}"), (0..ROWS).filter(|i| i % 11 == 3 || has_hash(*i)).count()),
        (format!("status=Failure OR {HASH}"), hash_only as usize),
        (format!("metadata.log_source=aws_cloudtrail OR rundll32"), (0..ROWS).filter(|i| source(*i) == "aws_cloudtrail" || has_hash(*i)).count()),
    ] {
        let got = count(&rows(&engine, &format!("{query} | stats count"), now, false).await);
        assert_eq!(got, truth as u64, "{query}");
        let events = rows(&engine, &format!("{query} | head 100"), now, true).await;
        assert_eq!(events.len(), truth.min(100), "{query} (events)");
    }
}

/// k6 `conduit_proxy bytes_out` timechart: HTTP 400 on the lake cell.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn source_and_entity_timechart_sum_matches_where_equivalent() {
    // Production cells run with the part result cache (locators) on.
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let truth: i64 = (0..ROWS / 2).filter(|i| proxy_hit(*i)).map(bytes_out).sum();
    let total = |rows: &[Value]| -> i64 {
        rows.iter().map(|row| {
            let value = &row["bytes_out_total"];
            value.as_i64().or_else(|| value.as_f64().map(|v| v as i64))
                .or_else(|| value.as_str().and_then(|s| s.parse::<f64>().ok()).map(|v| v as i64))
                .unwrap_or(0)
        }).sum()
    };
    // The search service sends a lake timechart as `… | timechart … | sort
    // time_bucket` (nanosiem-core search/service/timechart.rs bucket_query);
    // that wrapper died with `Unknown identifier ext.time_bucket`.
    let shape = format!("metadata.log_source=conduit_proxy src_endpoint.ip={PROXY_IP} | timechart span=1h sum(traffic.bytes_out) as bytes_out_total | sort time_bucket");
    let equivalent = format!("* | where metadata.log_source=\"conduit_proxy\" AND src_endpoint.ip=\"{PROXY_IP}\" | timechart span=1h sum(traffic.bytes_out) as bytes_out_total | sort time_bucket");
    let bare = format!("metadata.log_source=conduit_proxy src_endpoint.ip={PROXY_IP} | timechart span=1h sum(traffic.bytes_out) as bytes_out_total");
    for table_view in [true, false] {
        let got = rows(&engine, &shape, now, table_view).await;
        let reference = rows(&engine, &equivalent, now, table_view).await;
        assert_eq!(total(&got), truth, "{shape} (table_view={table_view}): {got:?}");
        assert_eq!(got, reference, "{shape} vs | where (table_view={table_view})");
        assert_eq!(got, rows(&engine, &bare, now, table_view).await, "{shape} vs the unwrapped timechart");
    }
}

async fn envelope(engine: &PartQueryEngine, request: &BroadNplRequest) -> Value {
    crate::query_timing::measure("nan3155", Box::pin(engine.broad_npl(request))).await
        .unwrap_or_else(|error| panic!("{}: {error}", request.query))
}

fn ordered_uids(rows: &[Value]) -> Vec<String> {
    rows.iter().map(|row| row["metadata.uid"].as_str().unwrap_or_else(|| panic!("{row}")).to_string()).collect()
}

/// NAN-3159: the scan estimate comes from the footer's column chunks (the
/// leaves read, in the row groups kept), within 2x of the bytes chDB reports
/// reading, and never above the whole-file charge it replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn scan_estimate_tracks_bytes_read_within_2x() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // Realistic part sizes (the fixed per-file footer allowance is noise
    // next to MB-scale column chunks, as on a live cell).
    ingest_rows(root.path(), now, 60_000, 50).await;
    let engine = engine(root.path()).await;
    let (mut files, mut data_files) = (0_u64, 0);
    let mut stack = vec![root.path().join("parts")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                stack.push(entry.path());
            } else if entry.file_name().to_str().is_some_and(|name| name.starts_with("data-") && name.ends_with(".parquet")) {
                files += entry.metadata().unwrap().len();
                data_files += 1;
            }
        }
    }
    eprintln!("whole data files: {data_files} files, {files} bytes");
    // `within`: the estimate must land within 2x of the bytes read. A bare
    // `* | stats count by F` stays an upper bound only: the compiler lists
    // `message`/`raw_data` among its scan columns there (chDB prunes them),
    // and those shapes are served from rollups (lean plan Phase 0 item 1).
    //
    // A bare `… | head 100` is an upper bound only too. Since NAN-3162
    // (dbcfb91c9) the request's 24 h + 1 min window keeps the uid tie-break,
    // so the page walks progressively newest first and stops in its first
    // 1-minute chunk (before, a > 24 h window ran one whole-window statement
    // that read ~every leaf). The planner charges the chunk's kept row groups
    // (the footer's finest unit); chDB pushes the chunk's time fence down to
    // page statistics and reads only the pages of that minute (~1,200 of
    // 30,000 rows of a one-group file): estimate 400–520 KB, read 46–170 KB
    // (3–11x). Over-charging a page is the safe side for admission. A
    // full-width non-progressive read (`sort <field> | head`) keeps the
    // full-event 2x check.
    for (query, table_view, within) in [
        ("* | head 100", false, false),
        ("* | head 100", true, false),
        ("* | sort metadata.log_source | head 100", false, true),
        ("rundll32 | stats count", false, true),
        ("metadata.log_source=windows_sysmon | head 100", false, false),
        ("metadata.log_source=windows_sysmon | head 100", true, false),
        ("dst_endpoint.hostname=host3 | sort -time | head 50", true, true),
        ("metadata.log_source=conduit_proxy | timechart span=1h count", false, true),
        ("* | stats count by metadata.log_source", false, false),
        ("* | stats count by src_endpoint.ip", false, false),
    ] {
        let mut request = request(query, now, table_view);
        request.use_cache = false;
        let answer = envelope(&engine, &request).await;
        let estimate = answer["budget"]["estimated_scan_bytes"].as_u64().unwrap_or_else(|| panic!("{query}: {answer}"));
        let read = answer["result"]["storage_bytes"].as_u64().unwrap();
        let ratio = estimate as f64 / read.max(1) as f64;
        eprintln!("{query} (table_view={table_view}): estimate {estimate} read {read} whole files {files} ratio {ratio:.2}");
        assert!(estimate <= files, "{query}: never above the whole-file charge");
        assert!(estimate >= read / 2, "{query} (table_view={table_view}): estimate {estimate} under half of read {read}");
        if within {
            assert!(ratio <= 2.0, "{query} (table_view={table_view}): estimate {estimate} vs read {read}");
        }
    }
}

/// NAN-3155: staged row shapes (`| sort … | head N`, `| where` pages) run as
/// a narrow identity pass plus a payload fetch. Rows, their order and
/// cursor paging are identical to the one-pass statement and to truth.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn two_pass_row_shapes_match_one_pass_order_and_cursor_pages() {
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    // A smaller index is a newer event. NAN-4278: rows come back in the
    // query's own order (before, an explicit sort's head was re-sorted
    // newest first, and these truths encoded that).
    let host3 = (0..ROWS).filter(|i| i % 11 == 3).collect::<Vec<_>>();
    let uid = |i: &usize| format!("uid-{i:08}");
    let newest = |n: usize| host3.iter().take(n).map(uid).collect::<Vec<_>>();
    let oldest = |n: usize| host3.iter().rev().take(n).map(uid).collect::<Vec<_>>();
    let by_source = {
        let mut v = host3.clone();
        v.sort_by_key(|i| (source(*i), *i));
        v.iter().take(10).map(uid).collect::<Vec<_>>()
    };
    let cases: Vec<(&str, usize, Vec<String>)> = vec![
        ("dst_endpoint.hostname=host3 | sort -time | head 20", 200, newest(20)),
        ("* | where dst_endpoint.hostname=\"host3\" | sort -time | head 20", 200, newest(20)),
        ("dst_endpoint.hostname=host3 | sort time | head 20", 200, oldest(20)),
        ("* | where dst_endpoint.hostname=\"host3\" | sort time | head 20", 200, oldest(20)),
        ("* | where dst_endpoint.hostname=\"host3\"", 200, newest(usize::MAX)),
        ("* | where dst_endpoint.hostname=\"host3\"", 30, newest(30)),
        ("dst_endpoint.hostname=host3 | sort metadata.log_source, -time | head 10", 200, by_source),
    ];
    for (query, limit, truth) in cases {
        let mut request = request(query, now, true);
        request.limit = limit;
        std::env::set_var("NANO_LAKE_TWO_PASS", "0");
        let one = envelope(&engine, &request).await;
        std::env::remove_var("NANO_LAKE_TWO_PASS");
        let two = envelope(&engine, &request).await;
        let planner = &two["planner"];
        // NAN-4263: `sort -time` restates the implicit newest-first order
        // and compiles to the plain head (no sort statement to two-pass).
        assert!(query.contains("sort -time")
            || planner["two_pass"]["statements"].as_u64().unwrap_or(0) >= 2
            || planner["two_pass_chunks"].as_u64().unwrap_or(0) >= 1, "{query}: two-pass did not engage: {planner}");
        assert_eq!(two["result"]["rows"], one["result"]["rows"], "{query}: rows, values and order equal the one-pass statement");
        assert_eq!(two["result"]["page_has_more"], one["result"]["page_has_more"], "{query}");
        assert_eq!(ordered_uids(two["result"]["rows"].as_array().unwrap()), truth, "{query}");
    }
    // Cursor paging (the UI's infinite scroll) over a two-pass shape.
    let query = "dst_endpoint.hostname=host3 | sort -time | head 50";
    let mut pages = Vec::new();
    let mut request = request(query, now, true);
    request.limit = 10;
    for _ in 0..3 {
        let page = envelope(&engine, &request).await;
        let rows = page["result"]["rows"].as_array().unwrap().clone();
        assert_eq!(rows.len(), 10, "{page}");
        let last = rows.last().unwrap();
        let time = last["time"].as_str().unwrap().replace(' ', "T");
        request.cursor_time = Some(if time.ends_with('Z') { time } else { format!("{time}Z") });
        request.cursor_event_uid = Some(last["metadata.uid"].as_str().unwrap().to_string());
        pages.extend(ordered_uids(&rows));
    }
    assert_eq!(pages, newest(30), "cursor pages continue the result exactly");
}

/// NAN-4214: a `| head N` with no explicit sort returns the NEWEST N events
/// whatever per-row filters, enrichers or projections sit around it. Before
/// the fix every shape below compiled to an unordered `SELECT * … LIMIT N`
/// and returned whichever rows the reader produced first (the oldest here).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn head_without_sort_returns_the_newest_events_around_any_row_command() {
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    // A smaller index is a newer event.
    let sysmon = (0..ROWS).filter(|i| source(*i) == "windows_sysmon").collect::<Vec<_>>();
    let newest = |n: usize| sysmon.iter().take(n).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();
    let oldest = |n: usize| sysmon.iter().rev().take(n).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();
    for query in [
        "metadata.log_source=windows_sysmon | head 20",
        "metadata.log_source=windows_sysmon | table metadata.uid, time | head 20",
        "metadata.log_source=windows_sysmon | table metadata.uid | head 20",
        "metadata.log_source=windows_sysmon | fields metadata.uid | head 20",
        "metadata.log_source=windows_sysmon | head 20 | table metadata.uid",
        "metadata.log_source=windows_sysmon | eval marker=1 | head 20",
        "metadata.log_source=windows_sysmon | where severity_id=1 | head 20",
        "* | where metadata.log_source=\"windows_sysmon\" | table metadata.uid | head 20",
        "metadata.log_source=windows_sysmon | eval marker=1 | table metadata.uid, marker | head 20",
    ] {
        for table_view in [true, false] {
            let got = rows(&engine, query, now, table_view).await;
            let got = got.iter().map(|row| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid"))
                .and_then(Value::as_str).unwrap_or_else(|| panic!("{query}: {row}")).to_string()).collect::<Vec<_>>();
            assert_eq!(got, newest(20), "{query} (table_view={table_view})");
        }
    }
    // An explicit sort still owns the order.
    let got = rows(&engine, "metadata.log_source=windows_sysmon | sort time | table metadata.uid | head 20", now, true).await;
    assert_eq!(ordered_uids(&got), oldest(20));
}

/// NAN-4222: chDB keys its Parquet metadata (footer) cache by file path.
/// Every statement used to read through a fresh per-lease hard link, so the
/// cache never hit and every footer was re-parsed per statement; leased reads
/// now go through one stable path per object, and a repeat statement over the
/// same files hits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn repeat_statements_reuse_the_native_parquet_footer_cache() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let probe = runtime.connect(&["--memory_worker_use_cgroup=0", "--memory_worker_dynamic_hard_limit=0"]).unwrap();
    let hits = || -> u64 {
        let output = probe.query_with_params("SELECT sum(value) AS hits FROM system.events WHERE event = 'ParquetMetadataCacheHits'", "JSONEachRow", &[]).unwrap();
        let row: Value = serde_json::from_slice(&output.data).unwrap_or(json!({"hits": 0}));
        row["hits"].as_u64().or_else(|| row["hits"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0)
    };
    // Distinct statements (no result reuse) over the same parts.
    let first = rows(&engine, "metadata.log_source=windows_sysmon | stats count by dst_endpoint.hostname", now, false).await;
    assert!(!first.is_empty());
    let before = hits();
    let second = rows(&engine, "metadata.log_source=windows_sysmon | stats count by src_endpoint.ip", now, false).await;
    assert!(!second.is_empty());
    let after = hits();
    assert!(after > before, "the repeat statement must hit chDB's footer cache (hits {before} -> {after})");
}

/// NAN-4236: a tied sort is cut by a total order, so a 7 d top-N returns
/// the same rows in the same order on every run, across both parts. The
/// fixture's per-host counts tie (900 events over 11 hosts), every event
/// shares one severity, and timechart series share each bucket. Before the
/// fix windows over 24 h kept whichever tied rows chDB produced first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn tied_sorts_return_identical_rows_on_every_run() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let run = |query: &'static str| {
        let engine = &engine;
        async move {
            let mut request = request(query, now, false);
            request.start = (now - Duration::days(7)).to_rfc3339();
            request.use_cache = false;
            let answer = crate::query_timing::measure("nan4236", Box::pin(engine.broad_npl(&request))).await
                .unwrap_or_else(|error| panic!("{query}: {error}"));
            answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows in {answer}"))
        }
    };
    let text = |row: &Value, key: &str| row.get(key).or_else(|| row.pointer(&format!("/{}", key.replace('.', "/"))))
        .map(|value| value.as_str().map(str::to_string).unwrap_or_else(|| value.to_string()))
        .unwrap_or_else(|| panic!("{key} missing in {row}"));
    // Truth: count desc, then the group key ascending.
    let ranked = |events: Vec<usize>, n: usize| {
        let mut counts = std::collections::BTreeMap::<String, u64>::new();
        for i in events { *counts.entry(format!("host{}", i % 11)).or_default() += 1; }
        let mut counts = counts.into_iter().collect::<Vec<_>>();
        counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        counts.into_iter().take(n).map(|(host, _)| host).collect::<Vec<_>>()
    };
    let sysmon = (0..ROWS).filter(|i| source(*i) == "windows_sysmon").collect::<Vec<_>>();
    let cases: Vec<(&'static str, Option<Vec<String>>, &'static str)> = vec![
        ("metadata.log_source=windows_sysmon | stats count by dst_endpoint.hostname | sort -count | head 3",
         Some(ranked(sysmon, 3)), "dst_endpoint.hostname"),
        ("* | top 3 dst_endpoint.hostname", Some(ranked((0..ROWS).collect(), 3)), "dst_endpoint.hostname"),
        ("* | sort -severity_id | head 20", Some((0..20).map(|i| format!("uid-{i:08}")).collect()), "metadata.uid"),
        ("* | stats count by dst_endpoint.hostname, src_endpoint.ip | sort -count | head 5", None, "dst_endpoint.hostname"),
        ("* | timechart span=1h count by dst_endpoint.hostname", None, "dst_endpoint.hostname"),
    ];
    for (query, truth, key) in cases {
        let first = run(query).await;
        assert!(!first.is_empty(), "{query}");
        if let Some(truth) = truth {
            assert_eq!(first.iter().map(|row| text(row, key)).collect::<Vec<_>>(), truth, "{query}");
        }
        for attempt in 1..5 {
            assert_eq!(run(query).await, first, "{query}: run {attempt} differs from run 0");
        }
    }
    // Series inside one timechart bucket come back in key order.
    let chart = run("* | timechart span=1h count by dst_endpoint.hostname").await;
    let bucket = |row: &Value| row.as_object().unwrap().iter()
        .find(|(name, _)| name.contains("time")).map(|(_, value)| value.to_string()).unwrap_or_default();
    for pair in chart.windows(2) {
        if bucket(&pair[0]) == bucket(&pair[1]) {
            assert!(text(&pair[0], "dst_endpoint.hostname") < text(&pair[1], "dst_endpoint.hostname"), "{chart:?}");
        }
    }
}

/// NAN-4263 (FP T67): a bare `*` with `head N` and a projection is the N
/// newest events, newest first, read by the newest-first chunk walk -- in
/// either command order, and in the form the lake search service sends
/// (`lake_head_page_plan` pulls the head out: `* | table …` with limit N).
/// Before, that form compiled to an unordered `SELECT … LIMIT n` over the
/// whole window: 7 d on FP read 2291 files and returned rows from hours and
/// days back, not time-ordered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn bare_star_projection_heads_return_the_newest_rows_newest_first() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    // Rows are newest first: a smaller index is a newer event.
    let newest = |n: usize| (0..n).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();
    let in_order = |rows: &[Value]| rows.iter().map(|row| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid"))
        .and_then(Value::as_str).unwrap_or_else(|| panic!("row without metadata.uid: {row}")).to_string()).collect::<Vec<_>>();
    for (query, limit, page) in [
        // As the search service sends them (head pulled out, limit = N).
        ("* | table time, metadata.uid", 120, 120),
        ("* | fields time, metadata.uid, dst_endpoint.hostname", 120, 120),
        ("* | rename dst_endpoint.hostname AS host", 120, 120),
        ("* | sort -_time | table time, metadata.uid", 120, 120),
        // As typed, both orders.
        ("* | head 120 | table time, metadata.uid", 200, 120),
        ("* | table time, metadata.uid | head 120", 200, 120),
        ("* | fields time, metadata.uid | head 120", 200, 120),
        ("* | eval x=1 | head 120", 200, 120),
        ("* | sort -_time | table time, metadata.uid | head 120", 200, 120),
    ] {
        for table_view in [true, false] {
            let mut request = request(query, now, table_view);
            request.limit = limit;
            request.use_cache = false;
            let answer = crate::query_timing::measure("nan4263", Box::pin(engine.broad_npl(&request))).await
                .unwrap_or_else(|error| panic!("{query}: {error}"));
            let rows = answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows in {answer}"));
            assert_eq!(in_order(&rows), newest(page), "{query} (table_view={table_view}): the newest {page}, newest first");
            assert_eq!(answer["result"]["newest_first_event_rows"], json!(true), "{query}: {}", answer["result"]);
            assert_eq!(answer["planner"]["kind"], json!("progressive_newest_first"), "{query}: {}", answer["planner"]);
        }
    }
    // A projection without the cursor fields still returns the newest rows
    // in order (the walk rereads a full chunk instead of continuing it).
    let mut request = request("* | table dst_endpoint.hostname, severity_id", now, true);
    request.limit = 120;
    let answer = crate::query_timing::measure("nan4263", Box::pin(engine.broad_npl(&request))).await.unwrap();
    let rows = answer["result"]["rows"].as_array().cloned().unwrap();
    let hosts = rows.iter().map(|row| row["dst_endpoint.hostname"].as_str().map(str::to_string)
        .or_else(|| row.pointer("/dst_endpoint/hostname").and_then(Value::as_str).map(str::to_string)).unwrap()).collect::<Vec<_>>();
    assert_eq!(hosts, (0..120).map(|i| format!("host{}", i % 11)).collect::<Vec<_>>());
    assert_eq!(answer["planner"]["kind"], json!("progressive_newest_first"), "{}", answer["planner"]);
}

/// NAN-4278 (searchfuzz F4/F8, FP T70): an explicit `sort` keeps its order to
/// the end of the result, and `tail N` / `reverse` take the rows from the END
/// of the current order, last first. Before, `sort -x | head N` came back
/// re-sorted newest-first, and `tail N` returned the newest N rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn explicit_sorts_keep_their_order_and_tail_takes_the_end() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let uid = |i: &usize| format!("uid-{i:08}");
    let in_order = |rows: &[Value]| rows.iter().map(|row| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid"))
        .and_then(Value::as_str).unwrap_or_else(|| panic!("row without metadata.uid: {row}")).to_string()).collect::<Vec<_>>();
    // Rows are newest first (a smaller index is newer); only the newer half
    // carries `traffic.bytes_out`, so the older proxy rows sort as NULL.
    let proxy = (0..ROWS).filter(|i| source(*i) == "conduit_proxy").collect::<Vec<_>>();
    let mut by_bytes_desc = proxy.iter().copied().filter(|i| *i < ROWS / 2).collect::<Vec<_>>();
    by_bytes_desc.sort_by(|a, b| bytes_out(*b).cmp(&bytes_out(*a)).then(a.cmp(b)));
    let oldest_proxy_first = proxy.iter().rev().take(3).map(uid).collect::<Vec<_>>();
    let mut newest_100_ascending = proxy[..100].to_vec();
    newest_100_ascending.sort_by_key(|i| bytes_out(*i));
    let cases: Vec<(&str, Vec<String>)> = vec![
        // The default newest-first listing: its end is the oldest rows.
        ("* | tail 5", (ROWS - 5..ROWS).rev().map(|i| uid(&i)).collect()),
        ("* | tail 5 | table time, metadata.uid", (ROWS - 5..ROWS).rev().map(|i| uid(&i)).collect()),
        ("* | tail 5 | fields time, metadata.uid", (ROWS - 5..ROWS).rev().map(|i| uid(&i)).collect()),
        ("* | reverse | head 4", (ROWS - 4..ROWS).rev().map(|i| uid(&i)).collect()),
        // `sort ±x` followed by head / table / fields: the user's order.
        ("metadata.log_source=conduit_proxy | sort -traffic.bytes_out | head 20", by_bytes_desc[..20].iter().map(uid).collect()),
        ("metadata.log_source=conduit_proxy | sort -traffic.bytes_out | head 20 | table traffic.bytes_out, metadata.uid",
         by_bytes_desc[..20].iter().map(uid).collect()),
        ("metadata.log_source=conduit_proxy | sort -traffic.bytes_out | head 20 | fields traffic.bytes_out, metadata.uid",
         by_bytes_desc[..20].iter().map(uid).collect()),
        ("metadata.log_source=conduit_proxy | sort +traffic.bytes_out | head 5",
         by_bytes_desc.iter().rev().take(5).map(uid).collect()),
        // `sort x | tail N`: the end of the sort, NULLs included where the
        // sort puts them (last, in both directions), last row first.
        ("metadata.log_source=conduit_proxy | sort -traffic.bytes_out | tail 3", oldest_proxy_first.clone()),
        ("metadata.log_source=conduit_proxy | sort +traffic.bytes_out | tail 3", oldest_proxy_first),
        ("metadata.log_source=conduit_proxy | head 100 | sort -traffic.bytes_out | tail 3",
         newest_100_ascending[..3].iter().map(uid).collect()),
        // Unchanged: the default listing is the newest rows, newest first.
        ("* | head 5", (0..5).map(|i| uid(&i)).collect()),
        ("* | table time, metadata.uid | head 5", (0..5).map(|i| uid(&i)).collect()),
    ];
    for (query, truth) in cases {
        for table_view in [true, false] {
            let mut request = request(query, now, table_view);
            request.use_cache = false;
            let answer = crate::query_timing::measure("nan4278", Box::pin(engine.broad_npl(&request))).await
                .unwrap_or_else(|error| panic!("{query}: {error}"));
            let rows = answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows in {answer}"));
            assert_eq!(in_order(&rows), truth, "{query} (table_view={table_view})");
        }
    }
}

/// NAN-4284 (searchfuzz F19, FP T70): a join whose subsearch has more rows
/// than its cap still matches every main-side key. The subsearch is narrowed
/// to those keys before the cap. Before, the cap kept an arbitrary subset:
/// left-join fields read `0` and an inner join returned no rows. Unmatched
/// left-join fields are NULL, not the type default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn capped_join_subsearch_matches_every_main_key_and_misses_are_null() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let ip = |i: usize| if proxy_hit(i) { PROXY_IP.to_string() } else { format!("10.0.{}.{}", i % 7, i % 200) };
    let total = |key: &str| (0..ROWS).filter(|i| ip(*i) == key).count() as u64;
    let run = |query: String| {
        let engine = &engine;
        async move {
            let mut request = request(&query, now, false);
            request.use_cache = false;
            let answer = crate::query_timing::measure("nan4284", Box::pin(engine.broad_npl(&request))).await
                .unwrap_or_else(|error| panic!("{query}: {error}"));
            answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows in {answer}"))
        }
    };
    let field = |row: &Value, key: &str| row.get(key).cloned().or_else(|| row.pointer(&format!("/{}", key.replace('.', "/"))).cloned())
        .unwrap_or(Value::Null);
    let as_u64 = |value: &Value| value.as_u64().or_else(|| value.as_str().and_then(|s| s.parse().ok()));
    // The subsearch has one row per source IP (several hundred), far past
    // maxout=3. The five newest CloudTrail rows have five distinct IPs.
    let sub = "[search * | stats count as total by src_endpoint.ip]";
    for join in ["type=left", "type=inner"] {
        let rows = run(format!("metadata.log_source=aws_cloudtrail | head 5 | join {join} maxout=5 src_endpoint.ip {sub}")).await;
        assert_eq!(rows.len(), 5, "{join}: {rows:?}");
        for row in &rows {
            let key = field(row, "src_endpoint.ip");
            let key = key.as_str().unwrap_or_else(|| panic!("{row}"));
            assert_eq!(as_u64(&field(row, "total")), Some(total(key)), "{join}: {row}");
        }
    }
    // No CloudTrail IP occurs in sysmon: every left-join row is unmatched.
    let rows = run(format!(
        "metadata.log_source=aws_cloudtrail | head 5 | join type=left src_endpoint.ip \
         [search metadata.log_source=windows_sysmon | stats count as total by src_endpoint.ip]"
    )).await;
    assert_eq!(rows.len(), 5, "{rows:?}");
    for row in &rows {
        assert!(field(row, "total").is_null(), "an unmatched left join reads NULL, not 0: {row}");
    }
}

/// NAN-4291 (F6): an ungrouped `stats` over no rows is one row, count 0 and
/// every other aggregate null, whether the window holds parts that match
/// nothing (the search the API sends for an expired window, `… NOT *`) or
/// holds no parts at all (a future window). Grouped stats have no rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn ungrouped_stats_over_no_rows_is_count_zero_and_null_aggregates() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let aggregates = "stats count, dc(actor.user.name) as users, max(time) as mt, min(dst_endpoint.port) as lo, \
                      avg(dst_endpoint.port) as a, sum(dst_endpoint.port) as s, values(actor.user.name) as v";
    let future = |query: &str| {
        let mut request = request(query, now, false);
        request.start = (now + Duration::days(400)).to_rfc3339();
        request.end = (now + Duration::days(401)).to_rfc3339();
        request.use_cache = false;
        request
    };
    let in_window = |query: &str| {
        let mut request = request(query, now, false);
        request.use_cache = false;
        request
    };
    for request in [
        in_window(&format!("(metadata.log_source=aws_cloudtrail) NOT * | {aggregates}")),
        future(&format!("metadata.log_source=aws_cloudtrail | {aggregates}")),
    ] {
        let answer = crate::query_timing::measure("nan4291", Box::pin(engine.broad_npl(&request))).await
            .unwrap_or_else(|error| panic!("{}: {error}", request.query));
        let rows = answer["result"]["rows"].as_array().cloned().unwrap_or_default();
        assert_eq!(rows.len(), 1, "{}: {answer}", request.query);
        let row = &rows[0];
        for zero in ["count", "users"] {
            let value = &row[zero];
            assert!(value.as_u64() == Some(0) || value.as_str() == Some("0"), "{}: {zero} in {row}", request.query);
        }
        for null in ["mt", "lo", "a", "s", "v"] {
            assert!(row.get(null).is_some_and(Value::is_null), "{}: {null} is null over no rows: {row}", request.query);
        }
    }
    // The two per-slice merge plans' statements (core `lake_stats_merge` and
    // the distinct-state plan): an empty slice is count 0 and null states,
    // which their merges read as "no rows"; a non-empty slice has values.
    let sliced = "stats count, earliest(time) as first_seen, latest(time) as last_seen, \
                  first(src_endpoint.ip) as first_user, last(src_endpoint.ip) as last_user";
    let distinct = "eval __nano_distinct_token = base64_encode(tostring(src_endpoint.ip)) \
                    | stats values(__nano_distinct_token) as __nano_distinct_values, count";
    for (tail, states) in [
        (sliced, &["first_seen", "last_seen", "first_user", "last_user"][..]),
        (distinct, &["__nano_distinct_values"][..]),
    ] {
        for (request, empty) in [
            (future(&format!("metadata.log_source=aws_cloudtrail | {tail}")), true),
            (in_window(&format!("metadata.log_source=aws_cloudtrail | {tail}")), false),
        ] {
            let answer = crate::query_timing::measure("nan4291", Box::pin(engine.broad_npl(&request))).await
                .unwrap_or_else(|error| panic!("{}: {error}", request.query));
            let rows = answer["result"]["rows"].as_array().cloned().unwrap_or_default();
            assert_eq!(rows.len(), 1, "{}: {answer}", request.query);
            let row = &rows[0];
            let count = row["count"].as_u64().or_else(|| row["count"].as_str().and_then(|s| s.parse().ok()));
            assert_eq!(count == Some(0), empty, "{}: {row}", request.query);
            for state in states {
                assert_eq!(row.get(*state).is_some_and(Value::is_null), empty, "{}: {state} in {row}", request.query);
            }
        }
    }
    for request in [
        in_window("(metadata.log_source=aws_cloudtrail) NOT * | stats count, max(time) as mt by actor.user.name"),
        future("metadata.log_source=aws_cloudtrail | stats count, max(time) as mt by actor.user.name"),
    ] {
        let answer = crate::query_timing::measure("nan4291", Box::pin(engine.broad_npl(&request))).await
            .unwrap_or_else(|error| panic!("{}: {error}", request.query));
        let rows = answer["result"]["rows"].as_array().cloned().unwrap_or_default();
        assert!(rows.is_empty(), "{}: {answer}", request.query);
    }
}

/// NAN-4313: a scan-budget-sliced `stats sum / avg / min / max` is exact.
/// The statement the search service sends each slice (avg as its sum and
/// count partials) runs through the real compiler and engine over four
/// half-open slices of a window, two of them empty, and the service's own
/// merge of those rows equals the unsliced statement, ungrouped and grouped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn budget_sliced_numeric_stats_merge_to_the_unsliced_answer() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let profile = nanosiem_core::schema::OcsfProfile::lake_1_9();
    let numeric = |field: &str| nanosiem_core::schema::SchemaProfile::is_numeric_field(&profile, field);
    let run = |query: String, start: DateTime<Utc>, end: DateTime<Utc>| {
        let engine = &engine;
        async move {
            let mut request = request(&query, now, false);
            request.start = start.to_rfc3339();
            request.end = end.to_rfc3339();
            request.use_cache = false;
            let answer = crate::query_timing::measure("nan4313", Box::pin(engine.broad_npl(&request))).await
                .unwrap_or_else(|error| panic!("{query}: {error}"));
            answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: {answer}"))
        }
    };
    // Rows span the last ~1 h 46 min: the oldest and newest slices are empty.
    let cuts = [now - Duration::hours(24), now - Duration::hours(2), now - Duration::hours(1), now + Duration::minutes(1),
                now + Duration::days(1)];
    let number = |value: &Value| value.as_f64().or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| panic!("{value}"));
    for tail in ["", " by src_endpoint.hostname"] {
        let query = format!(
            "metadata.log_source=conduit_proxy | stats count, sum(traffic.bytes_out) as s, avg(traffic.bytes_out) as a, \
             min(traffic.bytes_out) as lo, max(traffic.bytes_out) as hi{tail}"
        );
        let statement = nanosiem_core::search::service::sliced_stats_statement(&query, &numeric)
            .unwrap_or_else(|| panic!("{query} must be slice-mergeable"));
        assert!(statement.contains("__nano_avg_sum_") && statement.contains("__nano_avg_count_"), "{statement}");
        let mut slices = Vec::new();
        let mut empty = 0;
        for window in cuts.windows(2) {
            let rows = run(statement.clone(), window[0], window[1]).await;
            empty += usize::from(rows.iter().all(|row| number(&row["count"]) == 0.0));
            slices.push((nanosiem_core::search::TimeRangeInput::new(window[0], window[1]), rows));
        }
        assert_eq!(empty, 2, "{query}: two slices hold no rows");
        let mut merged = nanosiem_core::search::service::merge_sliced_stats(&query, &numeric, slices).unwrap().unwrap();
        let mut whole = run(query.clone(), cuts[0], cuts[4]).await;
        let key = |row: &Value| row.get("src_endpoint.hostname").or_else(|| row.pointer("/src_endpoint/hostname"))
            .map(Value::to_string).unwrap_or_default();
        merged.sort_by_key(key);
        whole.sort_by_key(key);
        assert_eq!(merged.len(), whole.len(), "{query}: {merged:?} vs {whole:?}");
        assert!(!whole.is_empty() && number(&whole[0]["count"]) > 0.0, "{query}: {whole:?}");
        for (merged, whole) in merged.iter().zip(&whole) {
            assert_eq!(key(merged), key(whole));
            for state in ["count", "s", "lo", "hi"] {
                assert_eq!(number(&merged[state]), number(&whole[state]), "{query}: {state} merged {merged} vs unsliced {whole}");
            }
            // The merged avg is the exact Float64 Σsum/Σcount; the worker's
            // JSON prints a Float64 to 16 significant digits (9138/14 reads
            // 1305.428571428571, the f64 is 1305.4285714285713).
            let (merged_avg, whole_avg) = (number(&merged["a"]), number(&whole["a"]));
            assert!((merged_avg - whole_avg).abs() <= whole_avg.abs() * 1e-12,
                "{query}: a merged {merged} vs unsliced {whole}");
        }
    }
}

/// NAN-3154: ingest-lowercased paths compare RAW (the dotless hostname
/// expansion included), the attested `metadata.log_source` compares raw, a
/// dotless hostname gets an entity-ranges-resolved candidate hint, and every
/// answer equals the `| where` form and the fixture truth. (`| where` does
/// not FQDN-expand a dotless literal, so its form spells the FQDN out.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn raw_identity_equality_and_dotless_host_hint_match_where_and_truth() {
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let field_types = engine.field_types().await.unwrap();
    // The hint is off by default: no hint even when the gate would allow it.
    crate::part_query::host_hint::TEST_DENSITY_DIVISOR.store(0, std::sync::atomic::Ordering::Relaxed);
    std::env::remove_var(crate::part_query::host_hint::FLAG);
    let off = engine.compile(&request(r#"src_endpoint.hostname="Host3" | stats count"#, now, false), field_types.clone()).await.unwrap();
    // (The compiler's own keyword-sidecar hint stays; no entity-ranges `Any`.)
    assert!(!off.candidate_hints.iter().any(|hint| matches!(hint, crate::planner::CandidateHint::Any { .. })), "flag off: {:?}", off.candidate_hints);
    crate::part_query::host_hint::TEST_DENSITY_DIVISOR.store(u64::MAX, std::sync::atomic::Ordering::Relaxed);
    std::env::set_var(crate::part_query::host_hint::FLAG, "1");
    let host_hinted = |compiled: &crate::planner::CompiledQuery| compiled.candidate_hints.iter().any(|hint| matches!(hint,
        crate::planner::CandidateHint::Any { alternatives }
            if alternatives.iter().any(|alt| matches!(alt, crate::planner::CandidateHint::Entity { value, .. } if value == "host3.corp.local"))));
    let aggregate = request(r#"src_endpoint.hostname="Host3" metadata.log_source="AWS_CloudTrail" | stats count"#, now, false);
    let compiled = engine.compile(&aggregate, field_types.clone()).await.unwrap();
    assert!(compiled.sql.contains(r#"("src_endpoint.hostname" = 'host3' OR startsWith("src_endpoint.hostname", 'host3.'))"#), "{}", compiled.sql);
    assert!(compiled.sql.contains(r#""metadata.log_source" = 'aws_cloudtrail'"#), "attested raw: {}", compiled.sql);
    // host3 is in every row group of this tiny fixture: too dense to hint.
    assert!(!host_hinted(&compiled), "dense: {:?}", compiled.candidate_hints);
    let mut answers = Vec::new();
    for divisor in [u64::MAX, 0] {
        // 0 turns the density gate off: the entity-ranges hint must resolve
        // the FQDN spelling and leave every answer unchanged.
        crate::part_query::host_hint::TEST_DENSITY_DIVISOR.store(divisor, std::sync::atomic::Ordering::Relaxed);
        let compiled = engine.compile(&aggregate, field_types.clone()).await.unwrap();
        assert_eq!(host_hinted(&compiled), divisor == 0, "{:?}", compiled.candidate_hints);
        answers.push(rows(&engine, r#"src_endpoint.hostname="Host3" | stats count by metadata.log_source"#, now, false).await);
    }
    assert_eq!(answers[0], answers[1], "the hint never changes an answer");
    let truth = |keep: &dyn Fn(usize) -> bool| (0..ROWS).filter(|i| keep(*i)).count() as u64;
    // Rows are newest first: the 100 smallest matching indexes.
    let newest = |keep: &dyn Fn(usize) -> bool| -> Vec<String> {
        let mut uids = (0..ROWS).filter(|i| keep(*i)).take(100).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();
        uids.sort();
        uids
    };
    let keep_of = |n: usize| -> Box<dyn Fn(usize) -> bool> {
        match n {
            0 => Box::new(|i| i % 11 == 3),
            1 => Box::new(|i| i % 11 == 3 && i % 2 == 0),
            2 => Box::new(|i| i % 11 == 3 || (i % 11 == 4 && i % 2 == 0)),
            3 => Box::new(|i| source(i) == "aws_cloudtrail" && i % 11 == 5),
            _ => Box::new(proxy_hit),
        }
    };
    for (n, (query, where_form, expected)) in [
        (r#"src_endpoint.hostname="Host3""#, r#"src_endpoint.hostname="host3" OR src_endpoint.hostname="host3.corp.local""#, truth(&|i| i % 11 == 3)),
        (r#"src_endpoint.hostname="host3.corp.local""#, r#"src_endpoint.hostname="HOST3.corp.local""#, truth(&|i| i % 11 == 3 && i % 2 == 0)),
        (r#"src_endpoint.hostname IN ("host3", "host4.corp.local")"#,
            r#"src_endpoint.hostname="host3" OR src_endpoint.hostname="host3.corp.local" OR src_endpoint.hostname="host4.corp.local""#,
            truth(&|i| i % 11 == 3 || (i % 11 == 4 && i % 2 == 0))),
        (r#"metadata.log_source="AWS_CloudTrail" src_endpoint.hostname="host5""#, r#"metadata.log_source="aws_cloudtrail" AND (src_endpoint.hostname="host5" OR src_endpoint.hostname="host5.corp.local")"#,
            truth(&|i| source(i) == "aws_cloudtrail" && i % 11 == 5)),
        (format!("src_endpoint.ip={PROXY_IP}").as_str(), format!("src_endpoint.ip=\"{PROXY_IP}\"").as_str(), truth(&proxy_hit)),
    ].into_iter().enumerate() {
        assert!(expected > 0, "{query}");
        let got = count(&rows(&engine, &format!("{query} | stats count"), now, false).await);
        let reference = count(&rows(&engine, &format!("* | where {where_form} | stats count"), now, false).await);
        assert_eq!(got, expected, "{query}");
        assert_eq!(reference, expected, "| where {where_form}");
        let events = rows(&engine, &format!("{query} | head 100"), now, true).await;
        let reference = rows(&engine, &format!("* | where {where_form} | sort -time | head 100"), now, true).await;
        assert_eq!(uids(&events), newest(&*keep_of(n)), "{query} (events)");
        assert_eq!(uids(&events), uids(&reference), "{query} vs | where (events)");
    }
}

/// NAN-3221: a full-event needle page (`table_view` off: an entity and a
/// keyword, each in every row group, together in few rows) is located by a
/// narrow statement and read full-width only at the located instants. Rows,
/// their values, their order, `page_has_more` and cursor pages are identical
/// to the one-pass full-width read; a mask-dependent predicate keeps the
/// one-pass read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn full_event_needle_locator_matches_one_pass_rows_order_and_cursor_pages() {
    // Exercise the locator fallback explicitly; eligible full-event pages
    // otherwise prefer authenticated two-pass materialization.
    std::env::set_var("NANO_LAKE_TWO_PASS", "0");
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now).await;
    let engine = engine(root.path()).await;
    let uid = |i: usize| format!("uid-{i:08}");
    // A smaller index is a newer event; output order is newest first.
    let newest = |keep: &dyn Fn(usize) -> bool, n: usize| (0..ROWS).filter(|i| keep(*i)).take(n).map(uid).collect::<Vec<_>>();
    // Full-event rows nest the uid; table rows flatten it.
    let event_uid = |row: &Value| row.get("metadata.uid").or_else(|| row.pointer("/metadata/uid"))
        .and_then(Value::as_str).unwrap_or_else(|| panic!("row without metadata.uid: {row}")).to_string();
    let ordered = |rows: &[Value]| rows.iter().map(event_uid).collect::<Vec<_>>();
    let cases: Vec<(String, usize, Vec<String>)> = vec![
        // log source + entity + keyword (the live needle shape).
        (format!("metadata.log_source=conduit_proxy src_endpoint.ip=\"{PROXY_IP}\" proxy"), 200, newest(&proxy_hit, 200)),
        (format!("metadata.log_source=conduit_proxy src_endpoint.ip=\"{PROXY_IP}\" flow"), 25, newest(&proxy_hit, 25)),
        // A rare conjunction (a sequence number), and one with no match.
        (format!("src_endpoint.ip=\"{PROXY_IP}\" \"seq 110\""), 200, newest(&|i| proxy_hit(i) && i == 110, 200)),
        (format!("src_endpoint.ip=\"{PROXY_IP}\" svchost"), 200, Vec::new()),
        (format!("src_endpoint.ip=\"{PROXY_IP}\" (message=\"*seq 2\" OR message=\"*seq 11\")"), 200,
            newest(&|i| proxy_hit(i) && (i == 2 || i == 11), 200)),
        ("metadata.log_source=conduit_proxy proxy".to_string(), 7, newest(&|i| source(i) == "conduit_proxy", 7)),
    ];
    for (query, limit, truth) in cases {
        let mut request = request(&query, now, false);
        request.limit = limit;
        request.use_cache = false;
        std::env::set_var("NANO_LAKE_FULL_EVENT_LOCATOR", "0");
        let one = envelope(&engine, &request).await;
        std::env::remove_var("NANO_LAKE_FULL_EVENT_LOCATOR");
        engine.clear_locator_cache();
        let located = envelope(&engine, &request).await;
        let planner = &located["planner"];
        assert_eq!(one["planner"]["located_chunks"].as_u64(), Some(0), "{query}: the kill switch keeps one pass: {}", one["planner"]);
        // (A page every index proves empty never reaches a statement.)
        assert!(truth.is_empty() || planner["located_chunks"].as_u64().unwrap_or(0) >= 1, "{query}: locator did not engage: {planner}");
        assert_eq!(located["result"]["rows"], one["result"]["rows"], "{query}: rows, values and order equal the one-pass read");
        assert_eq!(located["result"]["page_has_more"], one["result"]["page_has_more"], "{query}");
        assert_eq!(ordered(located["result"]["rows"].as_array().unwrap()), truth, "{query}");
    }
    // Cursor paging (infinite scroll) over the needle page.
    let query = format!("metadata.log_source=conduit_proxy src_endpoint.ip=\"{PROXY_IP}\" proxy");
    let mut request = request(&query, now, false);
    request.limit = 10;
    request.use_cache = false;
    let mut pages = Vec::new();
    for _ in 0..3 {
        let page = envelope(&engine, &request).await;
        assert!(page["planner"]["located_chunks"].as_u64().unwrap_or(0) >= 1, "{}", page["planner"]);
        let rows = page["result"]["rows"].as_array().unwrap().clone();
        assert_eq!(rows.len(), 10, "{page}");
        let last = rows.last().unwrap();
        let time = last["time"].as_str().unwrap().replace(' ', "T");
        request.cursor_time = Some(if time.ends_with('Z') { time } else { format!("{time}Z") });
        request.cursor_event_uid = Some(event_uid(last));
        pages.extend(ordered(&rows));
    }
    assert_eq!(pages, newest(&proxy_hit, 30), "cursor pages continue the result exactly");
    // NAN-4307: an enrichment leaf is a plain stored column since NAN-4168
    // (#7257, ingest-only enrichment, no read-time masks), so it is located
    // like any other leaf, and the located page must equal the one-pass read
    // (the fixture stores no location, so both are empty).
    let mut enriched_request = self::request("src_endpoint.location.country=US proxy", now, false);
    enriched_request.use_cache = false;
    std::env::set_var("NANO_LAKE_FULL_EVENT_LOCATOR", "0");
    let one = envelope(&engine, &enriched_request).await;
    std::env::remove_var("NANO_LAKE_FULL_EVENT_LOCATOR");
    engine.clear_locator_cache();
    let located = envelope(&engine, &enriched_request).await;
    assert!(located["planner"]["located_chunks"].as_u64().unwrap_or(0) >= 1, "{}", located["planner"]);
    assert_eq!(located["result"]["rows"], one["result"]["rows"], "rows equal the one-pass read");
    assert_eq!(located["result"]["page_has_more"], one["result"]["page_has_more"]);
    assert!(ordered(located["result"]["rows"].as_array().unwrap()).is_empty(), "{located}");
    std::env::remove_var("NANO_LAKE_TWO_PASS");
}

/// NAN-4295 (F22, second half): `stats count by <array leaf>` groups by
/// each element (SPL multivalue `by`), not by the whole array, and a
/// repeated object's missing leaf is no `[null]` group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn stats_by_array_field_counts_each_element() {
    const N: usize = 60;
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // Even rows: Authorize Session (`privileges[]`); odd rows: Detection
    // Finding (`evidences[]`, a repeated object).
    let privileged = |i: usize| i % 2 == 0;
    let events = (0..N).map(|i| {
        let time = (now - Duration::seconds(i as i64 * 10 + 30)).to_rfc3339();
        let metadata = json!({"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "fixture_arrays",
            "tenant_uid": TENANT, "product": {"name": "fixture_arrays", "vendor_name": "fixture"}});
        if privileged(i) {
            let privileges = match (i / 2) % 3 {
                0 => json!(["SeDebugPrivilege", "SeBackupPrivilege"]),
                1 => json!(["SeDebugPrivilege"]),
                _ => json!([]),
            };
            json!({"class_uid": 3003, "category_uid": 3, "activity_id": 1, "type_uid": 300301, "severity_id": 1,
                "time": time, "message": format!("session seq {i}"), "raw_data": format!("raw seq {i}"), "raw_data_size": format!("raw seq {i}").len(), "status": "Success", "metadata": metadata,
                "user": {"name": format!("user{}", i % 5)}, "privileges": privileges})
        } else {
            // The second evidence has no `src_endpoint`: a NULL leaf element.
            let evidences = if (i / 2) % 2 == 0 {
                json!([{"src_endpoint": {"hostname": "ev-a"}}, {"process": {"name": "no-endpoint.exe", "pid": 4242}}])
            } else {
                json!([{"src_endpoint": {"hostname": "ev-b"}}])
            };
            json!({"class_uid": 2004, "category_uid": 2, "activity_id": 1, "type_uid": 200401, "severity_id": 1,
                "time": time, "message": format!("finding seq {i}"), "raw_data": format!("raw seq {i}"), "raw_data_size": format!("raw seq {i}").len(), "status": "Success", "metadata": metadata,
                "finding_info": {"uid": format!("f-{i}"), "title": "fixture finding"}, "evidences": evidences})
        }
    }).collect::<Vec<_>>();
    ingest_batches(root.path(), now, vec![events]).await;
    let engine = engine(root.path()).await;
    let groups = |rows: Vec<Value>, field: &str| -> std::collections::BTreeMap<String, u64> {
        rows.iter().map(|row| {
            let key = match row.get(field).unwrap_or_else(|| panic!("no {field} in {row}")) {
                Value::String(value) => value.clone(),
                Value::Number(value) => value.to_string(),
                other => panic!("{field} group is not one element: {other} in {rows:?}"),
            };
            let count = &row["count"];
            (key, count.as_u64().or_else(|| count.as_str().and_then(|s| s.parse().ok())).unwrap())
        }).collect()
    };
    let by = |keep: &dyn Fn(usize) -> bool| (0..N).filter(|i| keep(*i)).count() as u64;
    let privileges = std::collections::BTreeMap::from([
        ("SeBackupPrivilege".to_string(), by(&|i| privileged(i) && (i / 2) % 3 == 0)),
        ("SeDebugPrivilege".to_string(), by(&|i| privileged(i) && (i / 2) % 3 != 2)),
    ]);
    let hostnames = std::collections::BTreeMap::from([
        ("ev-a".to_string(), by(&|i| !privileged(i) && (i / 2) % 2 == 0)),
        ("ev-b".to_string(), by(&|i| !privileged(i) && (i / 2) % 2 == 1)),
    ]);
    for table_view in [false, true] {
        let got = rows(&engine, "* | stats count by privileges", now, table_view).await;
        assert_eq!(groups(got, "privileges"), privileges, "table_view={table_view}");
        let got = rows(&engine, "* | stats count by evidences.src_endpoint.hostname", now, table_view).await;
        assert_eq!(groups(got, "evidences.src_endpoint.hostname"), hostnames, "table_view={table_view}");
    }
    // A non-string repeated leaf (`evidences[].process.pid`, integer) splits
    // the same way; the evidence without a process is no group.
    let got = rows(&engine, "* | stats count by evidences.process.pid", now, false).await;
    assert_eq!(groups(got, "evidences.process.pid"),
        std::collections::BTreeMap::from([("4242".to_string(), by(&|i| !privileged(i) && (i / 2) % 2 == 0))]));
    // A search filter on the same array keeps whole events: every element of
    // a matching event is counted (SPL multivalue `by`).
    let got = rows(&engine, "privileges=SeBackupPrivilege | stats count by privileges", now, false).await;
    assert_eq!(groups(got, "privileges"), std::collections::BTreeMap::from([
        ("SeBackupPrivilege".to_string(), by(&|i| privileged(i) && (i / 2) % 3 == 0)),
        ("SeDebugPrivilege".to_string(), by(&|i| privileged(i) && (i / 2) % 3 == 0)),
    ]));
    // `mvexpand` first: the same per-element counts.
    let got = rows(&engine, "* | mvexpand privileges | stats count by privileges", now, false).await;
    assert_eq!(groups(got, "privileges"), privileges);
    // Downstream the group key is one element: `where` compares it as such.
    let got = rows(&engine, r#"* | stats count by privileges | where privileges="SeDebugPrivilege""#, now, false).await;
    assert_eq!(groups(got, "privileges"), std::collections::BTreeMap::from([("SeDebugPrivilege".to_string(), by(&|i| privileged(i) && (i / 2) % 3 != 2))]));
    // A scalar by-field next to the array one: one row per (scalar, element).
    let got = rows(&engine, "* | stats count by metadata.log_source, privileges", now, false).await;
    let total: u64 = got.iter().map(|row| row["count"].as_u64().or_else(|| row["count"].as_str().and_then(|s| s.parse().ok())).unwrap()).sum();
    assert_eq!(total, privileges.values().sum::<u64>(), "{got:?}");
}

/// Real admission, signed parts, compiler and query engine: a sealed probe is
/// searchable, while the production detection predicate excludes it before stats.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires native chDB and the nPL compiler artifacts"]
async fn platform_probe_lands_but_cannot_contribute_to_detection_or_risk() {
    use nanosiem_core::platform_probe::{PlatformProbe, PlatformProbeKey};
    use nanosiem_core::query::{parse_query, PrettyPrint};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let signing = ed25519_dalek::SigningKey::from_bytes(&[86;32]);
    let mut probe = PlatformProbe { tenant_id: TENANT.parse().unwrap(), roll_id: uuid::Uuid::from_u128(20),
        probe_id: uuid::Uuid::from_u128(21), source_slug:"audit".into(), parser_bundle_sha256:"a".repeat(64),
        issued_at_ms:now.timestamp_millis(), expires_at_ms:now.timestamp_millis()+900_000, signature_hex:String::new() };
    probe.sign(&signing);
    let signed = probe.event();
    let mut forged = signed.clone();
    let mut unsigned = probe.clone(); unsigned.probe_id=uuid::Uuid::from_u128(22); unsigned.signature_hex.clear();
    forged["metadata"]["uid"]=json!(unsigned.probe_id);
    forged["unmapped"]["nano_platform_probe"]=json!(serde_json::to_string(&unsigned).unwrap());
    forged["unmapped"]["nano_platform_probe_trusted"]=json!("v1");
    let mut normal=event(42,&now.to_rfc3339(),false);
    normal["metadata"]["log_source"]=json!("audit");
    normal["time"]=json!(now.timestamp_millis());
    let key=PlatformProbeKey {tenant_id:probe.tenant_id,public_key_hex:hex::encode(signing.verifying_key().to_bytes())};
    ingest_batches_with_probe_key(root.path(),now,vec![vec![signed,forged,normal]],false,Some(key)).await;
    let engine=engine(root.path()).await;
    let mut raw=request("* | stats count() as n",now,false); raw.deny_source_types.clear();
    let result=engine.broad_npl(&raw).await.unwrap();
    assert_eq!(result["result"]["rows"][0]["n"].as_u64().or_else(||result["result"]["rows"][0]["n"].as_str().and_then(|s|s.parse().ok())),Some(2));
    let rule=parse_query("* | stats count() as n").unwrap();
    raw.query=nanosiem_core::detection::query_enrichment::exclude_platform_probes(&rule).pretty_print();
    let result=engine.broad_npl(&raw).await.unwrap();
    assert_eq!(result["result"]["rows"][0]["n"].as_u64().or_else(||result["result"]["rows"][0]["n"].as_str().and_then(|s|s.parse().ok())),Some(1));
    let rule=parse_query(&format!("metadata.uid=\"{}\" | stats count() as n | where n>0",probe.probe_id)).unwrap();
    raw.query=nanosiem_core::detection::query_enrichment::exclude_platform_probes(&rule).pretty_print();
    let result=engine.broad_npl(&raw).await.unwrap();
    assert!(result["result"]["rows"].as_array().unwrap().is_empty(),"no match can reach alert or risk finding creation");
    raw.query=format!("metadata.uid=\"{}\"",probe.probe_id);
    let result=engine.broad_npl(&raw).await.unwrap();
    assert_eq!(result["result"]["rows"].as_array().unwrap().len(),1,"ordinary search retains the probe");
}
