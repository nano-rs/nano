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
use std::collections::BTreeMap;
use std::sync::Arc;

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
    let half = rows / 2;
    for (n, (range, traffic)) in [(half..rows, false), (0..half, true)].into_iter().enumerate() {
        let batch = range.map(|i| event(i, &(now - Duration::milliseconds(i as i64 * spacing_ms + 30_000)).to_rfc3339(), traffic)).collect::<Vec<_>>();
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
    let answer = crate::query_timing::measure("nan3150", Box::pin(crate::enrichment_read::scope(granted(),
        engine.broad_npl(&request)))).await
        .unwrap_or_else(|error| panic!("{query} (table_view={table_view}): {error}"));
    answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{query}: no rows array in {answer}"))
}

/// The k6 grant cell's authority: the tenant holds the platform ipinfo read
/// grant, so endpoint masks carry a real permission predicate.
pub(crate) fn granted() -> nanosiem_core::platform_enrichment::read::ReadAuthorization {
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
    crate::query_timing::measure("nan3155", Box::pin(crate::enrichment_read::scope(granted(),
        engine.broad_npl(request)))).await
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
    // A smaller index is a newer event; output order is newest first.
    let host3 = (0..ROWS).filter(|i| i % 11 == 3).collect::<Vec<_>>();
    let uid = |i: &usize| format!("uid-{i:08}");
    let newest = |n: usize| host3.iter().take(n).map(uid).collect::<Vec<_>>();
    let oldest = |n: usize| { let mut v = host3.iter().rev().take(n).copied().collect::<Vec<_>>(); v.sort(); v.iter().map(uid).collect::<Vec<_>>() };
    let by_source = {
        let mut v = host3.clone();
        v.sort_by_key(|i| (source(*i), *i));
        let mut top = v.into_iter().take(10).collect::<Vec<_>>();
        top.sort();
        top.iter().map(uid).collect::<Vec<_>>()
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
        assert!(planner["two_pass"]["statements"].as_u64().unwrap_or(0) >= 2
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
    // A predicate on a masked leaf is never located (it reads the masked value).
    let mut masked_request = self::request("src_endpoint.location.country=US proxy", now, false);
    masked_request.use_cache = false;
    let masked = envelope(&engine, &masked_request).await;
    assert_eq!(masked["planner"]["located_chunks"].as_u64().unwrap_or(0), 0, "{}", masked["planner"]);
}
