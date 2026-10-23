// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3133, native: signed column-range cold fetch against the real chDB
//! library and the real nPL compiler.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::range_fetch::native -- --ignored --nocapture --test-threads=1
//! ```

use super::*;
use crate::part_query::prune;
use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use crate::part_query::log_view::PartLogView;
use crate::parts::format::{ParquetSettings, PartId};
use crate::parts::levels::Level;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const TENANT: &str = "5d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const ROWS: usize = 6_000;

fn runtime() -> NativeChdb {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    ).unwrap();
    // chDB keeps process-global hooks: keep the library loaded until exit.
    std::mem::forget(runtime.clone());
    runtime
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3133", ed25519_dalek::SigningKey::from_bytes(&[33; 32])).unwrap()
}

/// Incompressible filler: a narrow search must not read it.
fn filler(i: usize, bytes: usize) -> String {
    let mut out = String::with_capacity(bytes);
    let mut seed = i as u64;
    while out.len() < bytes {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        out.push_str(&format!("{seed:016x}"));
    }
    out.truncate(bytes);
    out
}

fn event(i: usize, time: &str) -> Value {
    let raw = format!("cloud {i} {}", filler(i, 1_024));
    json!({
        "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "activity_id": 1, "type_uid": 600301,
        "severity_id": (i % 5) as i64, "time": time, "raw_data": raw, "raw_data_size": raw.len(),
        "status": if i % 9 == 0 { "Failure" } else { "Success" },
        "message": format!("call {} {}", i % 41, filler(i + 7, 256)),
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "profiles": ["cloud"],
                     "log_source": if i % 3 == 0 { "azure_audit" } else { "aws_cloudtrail" }, "tenant_uid": TENANT,
                     "product": {"name": "CloudTrail", "vendor_name": "AWS"}},
        "actor": {"user": {"name": format!("user{}", i % 23), "uid": format!("arn:aws:iam::100:user/{}", i % 23)}},
        "api": {"operation": if i % 2 == 0 { "ListRoles" } else { "GetObject" },
                "service": {"name": if i % 2 == 0 { "iam" } else { "s3" }},
                "request": {"uid": format!("req-{i}"), "data": filler(i + 3, 384)}},
        "cloud": {"provider": "AWS", "region": if i % 4 == 0 { "eu-west-1" } else { "us-east-1" }, "account": {"uid": "100"}},
        "src_endpoint": {"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": format!("host{}", i % 13),
                         "location": {"country": (["US", "DE", "JP"])[i % 3], "continent": "X"},
                         "autonomous_system": {"number": 64_500 + (i % 4) as i64, "name": format!("AS-{}", i % 4)}},
        "dst_endpoint": {"ip": format!("203.0.113.{}", i % 9),
                         "location": {"country": (["FR", "BR"])[i % 2]},
                         "autonomous_system": {"number": 65_000 + (i % 3) as i64, "name": format!("DST-{}", i % 3)}},
        "resources": [{"uid": format!("r{}", i % 50), "type": if i % 2 == 0 { "Role" } else { "Bucket" }}],
        "unmapped": {"blob": filler(i + 11, 512)},
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

/// Ingest the fixture (range manifests on) into `root/parts`.
async fn ingest(root: &std::path::Path, now: DateTime<Utc>, ranges: bool) {
    if ranges {
        std::env::set_var("NANO_LAKE_PARQUET_RANGE_WRITE", "1");
    } else {
        std::env::remove_var("NANO_LAKE_PARQUET_RANGE_WRITE");
    }
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
    // Fifty minutes: one or two L0 parts of thousands of rows (several row
    // groups each), like a production data file in miniature.
    let batch = (0..ROWS)
        .map(|i| event(i, &(now - Duration::milliseconds(i as i64 * 500 + 30_000)).to_rfc3339()))
        .collect::<Vec<_>>();
    write_bronze(&sources_dir.join("bronze/0000.parquet"), &batch);
    crate::bronze::admit_bronze_files(&[sources_dir.join("bronze/0000.parquet")], TENANT).expect("bronze admitted");
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/0000.parquet".into(), version: "1".into(), bytes: 0,
        sha256: None, edge_sha256: None, notified_at_ms: now_ms }).unwrap();
    ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
    ingestor.flush_now(now_ms + 5_000).await.expect("ingest flushes");
    std::env::remove_var("NANO_LAKE_PARQUET_RANGE_WRITE");
}

async fn engine(root: &std::path::Path, cache: &str, lanes: &(NativeExecutor, NativeExecutor, NativeExecutor)) -> PartQueryEngine {
    let signer = signer();
    let state = root.join(cache);
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3133-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.join("cache"), max_bytes: 1 << 30, query_max_bytes: 1 << 29,
        fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
        max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20, max_execution_seconds: 120, threads: 2,
    }, store, view, fetcher, lanes.0.clone()).unwrap().with_writer(lanes.2.clone()).with_large(lanes.1.clone(), 3 << 29).with_state_dir(&state)
}

fn lanes() -> (NativeExecutor, NativeExecutor, NativeExecutor) {
    let runtime = runtime();
    let small = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(256 << 20))
        .unwrap().with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    (small, large, writer)
}

/// Drop every unleased reader-cache object (and reusable sparse file) so
/// the next query starts cold.
async fn evict_all(engine: &PartQueryEngine) {
    engine.fetcher().reset_sparse_memo().await;
    let objects = engine.fetcher().cache().scratch_dir("objects");
    let digests = std::fs::read_dir(&objects).unwrap().flatten()
        .filter_map(|entry| entry.file_name().to_str()?.strip_suffix(".bin").map(str::to_owned))
        .collect::<Vec<_>>();
    let deferred = engine.fetcher().cache().evict_unleased(digests).await.unwrap();
    assert!(deferred.is_empty(), "no lease outlives a query");
}

fn request(query: &str, now: DateTime<Utc>, table_view: bool) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan3133".into(), tenant_id: TENANT.into(), dataset: "logs".into(), query: query.into(),
        start: (now - Duration::hours(2)).to_rfc3339(), end: (now + Duration::minutes(1)).to_rfc3339(),
        limit: 2_000, offset: 0, table_view, use_cache: false, cursor_time: None, cursor_event_uid: None,
        anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

/// One cold run: rows, the reader-cache bytes it fetched, its planner evidence.
async fn cold(engine: &PartQueryEngine, request: &BroadNplRequest, ranged: bool) -> (Value, u64, Value) {
    if ranged { std::env::set_var(FLAG, "1") } else { std::env::remove_var(FLAG) }
    evict_all(engine).await;
    let before = engine.fetcher().cache().stats().fetched_bytes;
    let answer = engine.broad_npl(request).await.unwrap_or_else(|error| panic!("{} ({ranged}): {error}", request.query));
    let fetched = engine.fetcher().cache().stats().fetched_bytes - before;
    std::env::remove_var(FLAG);
    let result = &answer["result"];
    (json!({"rows": result["rows"], "has_more": result["page_has_more"], "group_total": result["group_total"]}),
        fetched, { let mut planner = answer["planner"].clone(); planner["storage_bytes"] = result["storage_bytes"].clone(); planner })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn ranged_search_matches_whole_files_and_fetches_a_fraction() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now, true).await;
    for entry in walkdir(&root.path().join("parts")) {
        if entry.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("ranges-")) {
            let ranges: Vec<ParquetRangeDigest> = serde_json::from_slice(&std::fs::read(&entry).unwrap()).unwrap();
            let mut by_column = BTreeMap::<String, u64>::new();
            for range in &ranges { *by_column.entry(range.column.clone().unwrap_or_else(|| "<footer>".into())).or_default() += range.bytes; }
            let mut sizes = by_column.into_iter().collect::<Vec<_>>();
            sizes.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
            println!("NAN3133 manifest {} ranges={} top={:?}", entry.display(), ranges.len(), &sizes[..sizes.len().min(12)]);
        }
    }
    let lanes = lanes();
    let whole = engine(root.path(), "whole", &lanes).await;
    let ranged = engine(root.path(), "ranged", &lanes).await;

    // (query, table_view, narrow: must be ranged and >= 10x cheaper)
    let shapes: &[(&str, bool, bool)] = &[
        ("api.operation=ListRoles | stats count by actor.user.name", false, true),
        ("* | stats count", false, false),
        ("* | timechart span=5m count", false, false),
        ("api.operation=ListRoles | timechart span=5m count", false, true),
        ("cloud.region=eu-west-1 | timechart span=10m count by api.operation", false, true),
        ("* | timechart span=10m count by api.operation", false, false),
        ("metadata.log_source=azure_audit | stats count by cloud.region, api.service.name", false, true),
        ("actor.user.name=/user1.*/ | stats count by actor.user.name", false, true),
        ("status=Failure | stats dc(actor.user.uid) as users, count by cloud.region | sort -count", false, true),
        ("api.operation=GetObject | table time, actor.user.name, api.operation, src_endpoint.ip", false, true),
        ("severity_id>=3 | stats max(time) as last, min(severity_id) as low by severity_id", false, true),
        // Entity pivots keep whole files (and their in-file bloom pruning).
        ("src_endpoint.ip=\"10.0.3.17\" | stats count by src_endpoint.hostname", false, false),
        ("actor.user.name=user7 | stats count by api.operation", false, false),
        // Geo/ASN: plain endpoint leaves (NAN-4168: no read-time masks).
        ("* | stats count by src_endpoint.location.country", false, false),
        ("api.operation=ListRoles | stats count by src_endpoint.location.country, dst_endpoint.autonomous_system.number", false, true),
        ("* | stats count by src_endpoint.ip | sort -count | head 5", false, false),
        // `*` pipelines: the compiler projects the event text bodies
        // (message, raw_data), so they are not narrow (whole files).
        // Raw event rows: every root (whole files).
        ("api.operation=GetObject", false, false),
        ("actor.user.name=user7", false, false),
        // The compiler's table view: a flat projection, not SELECT *.
        ("api.operation=GetObject", true, false),
        // Free text reads the event text columns.
        ("cloud", false, false),
    ];
    let mut report = Vec::new();
    for (query, table_view, narrow) in shapes {
        let request = request(query, now, *table_view);
        let field_types = ranged.field_types().await.unwrap();
        let compiled = ranged.compile(&request, field_types.clone()).await.unwrap();
        let roots = field_types.keys().filter_map(|p| p.split('.').next()).map(str::to_owned).collect();
        let scoped = derive_scope(&compiled, &roots).is_ok();
        match derive_scope(&compiled, &roots) {
            Ok(scope) => println!("NAN3133 scope {query:?}: roots={:?} leaves={:?}\nNAN3133 contract required={:?} projected={:?}", scope.roots, scope.leaves,
                compiled.required_columns.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), compiled.projected_scan_columns),
            Err(reason) => println!("NAN3133 scope {query:?}: {}", reason.as_str()),
        }
        let (expected, whole_total, whole_planner) = cold(&whole, &request, false).await;
        let (actual, range_total, planner) = cold(&ranged, &request, true).await;
        assert_eq!(actual, expected, "{query} (table_view={table_view}): ranged rows differ from whole-file rows");
        assert!(expected["rows"].as_array().is_some_and(|rows| !rows.is_empty()), "{query}: the shape must return rows");
        // Data-stage bytes: whole data files (off) vs signed ranges plus any
        // whole fallbacks (on). Sidecars (tokens, uids) cost the same in both.
        let whole_bytes = whole_planner["whole_fetched_bytes"].as_u64().unwrap_or(0);
        let range_bytes = planner["range_fetched_bytes"].as_u64().unwrap_or(0) + planner["whole_fetched_bytes"].as_u64().unwrap_or(0);
        let range_files = planner["range_files"].as_u64().unwrap_or(0);
        println!("NAN3133 shape={query:?} table_view={table_view} data_whole={whole_bytes} data_ranged={range_bytes} ratio={:.1} total_whole={whole_total} total_ranged={range_total} range_files={range_files} chdb_read_whole={} fallbacks={} rerun={}",
            whole_bytes as f64 / range_bytes.max(1) as f64, whole_planner["storage_bytes"], planner["range_fallbacks"], planner["range_fetch_rerun"]);
        assert!(planner["range_fetch_rerun"].is_null(), "{query}: a ranged read failed natively and was rerun");
        // At worst (a fallback) the signed manifests are the only extra bytes.
        assert!(range_total <= whole_total + whole_total / 50 + 65_536, "{query}: ranged total {range_total} > whole total {whole_total}");
        if prune::uses_entities(&compiled.candidate_hints) {
            // A wide shape (raw rows) never ranges, so only a scoped pivot
            // records the fallback; bareword pivots are hinted too (NAN-3162).
            if scoped {
                assert!(planner["range_fallbacks"]["entity_pivot"].as_u64().unwrap_or(0) > 0, "{query}: pivots keep whole files ({planner})");
            }
            assert_eq!(planner["kept_row_groups"], whole_planner["kept_row_groups"], "{query}: bloom row-group pruning is preserved");
            assert_eq!(planner["row_groups"], whole_planner["row_groups"], "{query}");
            println!("NAN3133 pivot {query:?} kept_row_groups={} of {}", planner["kept_row_groups"], planner["row_groups"]);
        }
        if *narrow {
            assert!(range_files > 0, "{query}: a narrow shape must read ranged files ({planner})");
            assert!(range_bytes * 10 <= whole_bytes, "{query}: ranged {range_bytes} bytes vs whole {whole_bytes}");
        }
        report.push((query.to_string(), *table_view, whole_bytes, range_bytes, range_files));
    }
    let status = stats_json();
    println!("NAN3133 status {status}");
    assert!(status["range_fetched_bytes"].as_u64().unwrap() > 0);
    let sparse_dir = ranged.fetcher().cache().scratch_dir("ranged");
    let files = walkdir(&sparse_dir).into_iter().filter(|path| path.extension().is_some_and(|ext| ext == "parquet")).count();
    assert!(files <= SPARSE_MEMO_ENTRIES, "sparse files are bounded by the reuse memo: {files}");
}

/// Legacy parts (no range manifest) always take the whole-file path, and a
/// sparse file whose scope misses a column the query reads fails natively,
/// then reruns on whole files with identical rows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn legacy_parts_and_missed_columns_fall_back_to_whole_files() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now, false).await;
    let lanes = lanes();
    let whole = engine(root.path(), "whole", &lanes).await;
    let ranged = engine(root.path(), "ranged", &lanes).await;
    let request = request("api.operation=ListRoles | stats count by actor.user.name", now, false);
    let (expected, whole_bytes, _) = cold(&whole, &request, false).await;
    let (actual, range_bytes, planner) = cold(&ranged, &request, true).await;
    assert_eq!(actual, expected);
    assert_eq!(planner["range_files"], json!(0));
    assert!(planner["range_fallbacks"]["no_sidecar"].as_u64().unwrap() > 0, "{planner}");
    assert_eq!(range_bytes, whole_bytes, "legacy parts fetch exactly the whole files");
}

/// The rerun guard: a scope that misses a read root fails in chDB (a hole is
/// never read as data) and the request reruns once on whole files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_scope_that_misses_a_column_reruns_on_whole_files() {
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    ingest(root.path(), now, true).await;
    let lanes = lanes();
    let whole = engine(root.path(), "whole", &lanes).await;
    let ranged = engine(root.path(), "ranged", &lanes).await;
    let request = request("api.operation=ListRoles | stats count by actor.user.name", now, false);
    let (expected, _, _) = cold(&whole, &request, false).await;
    // Force a scope without `actor` for this request only.
    set_test_root_exclusion(Some("actor"));
    let (actual, _, planner) = cold(&ranged, &request, true).await;
    set_test_root_exclusion(None);
    assert_eq!(actual, expected);
    assert_eq!(planner["range_fetch_rerun"], json!("native_error"), "{planner}");
}

/// chDB reads only the projected chunks of a sparse file (the rest are
/// holes), with the real writer properties (page index, bloom filters).
#[tokio::test]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn chdb_reads_sparse_files_with_a_sanitized_footer() {
    let dir = tempfile::tempdir().unwrap();
    let whole = dir.path().join("whole.parquet");
    write_fixture(&whole, 5_000);
    let ranges = crate::parts::parquet_ranges::build(&whole).unwrap();
    let bytes = std::fs::metadata(&whole).unwrap().len();
    let body = std::fs::read(&whole).unwrap();
    let roots = ["time", "metadata", "api", "severity_id", "actor"].iter().map(|r| r.to_string()).collect();
    let selected = select_ranges(&ranges, &ColumnScope::new(roots, Default::default()));
    let footer = ranges.iter().find(|r| r.column.is_none()).unwrap();
    let mut chunks = Vec::new();
    for index in &selected {
        let range = &ranges[*index];
        if range.column.is_none() { continue }
        let path = dir.path().join(format!("chunk{index}"));
        std::fs::write(&path, &body[range.offset as usize..(range.offset + range.bytes) as usize]).unwrap();
        chunks.push((range.offset, path));
    }
    let footer_path = dir.path().join("footer");
    std::fs::write(&footer_path, &body[footer.offset as usize..]).unwrap();
    let sparse_dir = dir.path().join("ranged");
    let store = SparseStore::open(&sparse_dir, 64 << 20).unwrap();
    let source = dir.path().join("empty-source");
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: dir.path().join("cache"), max_bytes: 64 << 20, query_max_bytes: 64 << 20,
        fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
    }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local("bucket", Arc::new(LocalObjectStore::new(&source).unwrap()), source.clone()))).unwrap();
    let chunks = chunks.into_iter().map(|(offset, path)| (offset, std::fs::metadata(&path).unwrap().len(), path)).collect::<Vec<_>>();
    let (sparse, _reservation) = store.build(&cache, "key", bytes, footer.offset, footer.bytes, &footer.sha256, &footer_path, &chunks).unwrap();
    let allocated = { use std::os::unix::fs::MetadataExt; std::fs::metadata(sparse.path()).unwrap().blocks() * 512 };
    println!("whole {bytes} bytes; sparse allocates {allocated} bytes");
    let executor = NativeExecutor::start_named_with_mode(runtime(), 1, "nan3133", ExecutorMode::ReadOnly).unwrap();
    let run = |sql: &str, path: &std::path::Path| {
        let (executor, sql, path) = (executor.clone(), sql.to_string(), path.display().to_string());
        async move { executor.execute_sql(sql, vec![("p".into(), path)]).await.map(|out| String::from_utf8_lossy(&out.data).to_string()) }
    };
    for sql in [
        "SELECT count() AS c FROM file({p:String}, Parquet)",
        "SELECT metadata.log_source AS s, count() AS c FROM file({p:String}, Parquet) GROUP BY s ORDER BY s",
        "SELECT api.operation AS o, count() AS c FROM file({p:String}, Parquet) WHERE time > 1790000100000000 GROUP BY o ORDER BY o",
        "SELECT time, metadata.uid, actor.user.name FROM file({p:String}, Parquet) WHERE actor.user.name = 'user3' ORDER BY time DESC LIMIT 5",
        "SELECT metadata.uid FROM file({p:String}, Parquet) WHERE metadata.uid = 'uid-00004242'",
        "SELECT count() FROM file({p:String}, Parquet) WHERE match(metadata.uid, 'uid-0000(1|2)')",
        "SELECT severity_id, max(time) FROM file({p:String}, Parquet) WHERE severity_id IN (1,3) GROUP BY severity_id ORDER BY severity_id SETTINGS input_format_parquet_bloom_filter_push_down=1, input_format_parquet_page_filter_push_down=1",
        "SELECT _row_number, metadata.uid FROM file({p:String}, Parquet) WHERE _row_number >= 1500 AND _row_number < 1503 ORDER BY _row_number",
        "SELECT count() FROM file({p:String}, Parquet) WHERE time BETWEEN 1790000100000000 AND 1790000200000000 SETTINGS optimize_move_to_prewhere=1",
    ] {
        let expected = run(sql, &whole).await.unwrap();
        let actual = run(sql, sparse.path()).await.unwrap_or_else(|error| panic!("{sql}: {error}"));
        assert_eq!(actual, expected, "{sql}");
    }
    for sql in [
        "SELECT count() FROM file({p:String}, Parquet) WHERE raw_data LIKE '%event 7%'",
        "SELECT max(length(unmapped.blob)) FROM file({p:String}, Parquet)",
        "SELECT src_endpoint.ip FROM file({p:String}, Parquet) LIMIT 3",
        "SELECT * FROM file({p:String}, Parquet) LIMIT 3",
    ] {
        let error = run(sql, sparse.path()).await.expect_err(sql).to_string();
        assert!(error.contains("TProtocolException") || error.contains("Parquet"), "{sql}: {error}");
    }
    let kept = sparse.path().to_path_buf();
    drop(sparse);
    drop(store);
    assert!(!kept.exists(), "the last holder removes a sparse file");
}

fn write_fixture(path: &std::path::Path, rows: usize) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for i in 0..rows {
        let row = json!({
            "time": 1_790_000_000_000_000_i64 + i as i64 * 1_000_000,
            "severity_id": (i % 5) as i64,
            "raw_data": format!("event {i} {}", filler(i, 200)),
            "metadata": {"uid": format!("uid-{i:08}"), "log_source": if i % 3 == 0 { "aws_cloudtrail" } else { "okta" }},
            "actor": {"user": {"name": format!("user{}", i % 17), "uid": format!("arn:{i}")}},
            "api": {"operation": if i % 2 == 0 { "ListRoles" } else { "GetObject" }},
            "src_endpoint": {"ip": format!("10.0.{}.{}", i % 7, i % 251)},
            "unmapped": {"blob": filler(i + 1, 400)},
        });
        serde_json::to_writer(&mut lines, &row).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let schema = Arc::new(schema);
    let mut settings = ParquetSettings::for_level(Level::L0);
    settings.row_group_rows = 1_000;
    let id = PartId::parse("1790330400123-9f86d081884c7d65").unwrap();
    let props = settings.writer_properties(rows as u64, &id, Level::L0, TENANT, "f").unwrap();
    let reader = arrow_json::ReaderBuilder::new(schema.clone()).with_batch_size(1_000).build(std::io::Cursor::new(lines)).unwrap();
    let mut writer = parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), schema, Some(props)).unwrap();
    for batch in reader { writer.write(&batch.unwrap()).unwrap(); }
    writer.close().unwrap();
}

fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() { out.extend(walkdir(&path)) } else { out.push(path) }
    }
    out
}

/// NAN-3141: a read of an unfetched region of a sparse file must stay an
/// ordinary query error. It must never put the embedded engine into its
/// process-wide crashed state (Code 236 "The server is shutting down due to
/// a fatal error" for every later query): after every probe, `SELECT 1`
/// must still answer. Probes cover every column outside the scope, in the
/// projection, in WHERE/PREWHERE, under the planner's Parquet settings, with
/// an explicit narrow schema, multi-file globs and concurrent lanes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn nan3141_hole_reads_never_crash_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let whole = dir.path().join("whole.parquet");
    write_fixture(&whole, 5_000);
    let ranges = crate::parts::parquet_ranges::build(&whole).unwrap();
    let bytes = std::fs::metadata(&whole).unwrap().len();
    let body = std::fs::read(&whole).unwrap();
    let footer = ranges.iter().find(|r| r.column.is_none()).unwrap().clone();
    let footer_path = dir.path().join("footer");
    std::fs::write(&footer_path, &body[footer.offset as usize..]).unwrap();
    let source = dir.path().join("empty-source");
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: dir.path().join("cache"), max_bytes: 256 << 20, query_max_bytes: 256 << 20,
        fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(5),
    }, TENANT, "bucket", &parts_key_prefix(TENANT).unwrap(),
        Arc::new(StoreObjectSource::local("bucket", Arc::new(LocalObjectStore::new(&source).unwrap()), source.clone()))).unwrap();
    let store = SparseStore::open(&dir.path().join("ranged"), 256 << 20).unwrap();
    // Several scopes: each leaves different columns as holes.
    let scopes: &[&[&str]] = &[&["time"], &["time", "metadata"], &["time", "api", "severity_id"], &["time", "actor", "src_endpoint"]];
    let mut sparse_files = Vec::new();
    for (n, roots) in scopes.iter().enumerate() {
        let roots = roots.iter().map(|r| r.to_string()).collect();
        let selected = select_ranges(&ranges, &ColumnScope::new(roots, Default::default()));
        let mut chunks = Vec::new();
        for index in &selected {
            let range = &ranges[*index];
            if range.column.is_none() { continue }
            let path = dir.path().join(format!("s{n}-chunk{index}"));
            std::fs::write(&path, &body[range.offset as usize..(range.offset + range.bytes) as usize]).unwrap();
            chunks.push((range.offset, range.bytes, path));
        }
        let (sparse, reservation) = store.build(&cache, &format!("k{n}"), bytes, footer.offset, footer.bytes, &footer.sha256, &footer_path, &chunks).unwrap();
        sparse_files.push((sparse, reservation));
    }
    let executor = NativeExecutor::start_named_with_mode(runtime(), 4, "nan3141", ExecutorMode::ReadOnly).unwrap();
    let alive = |executor: NativeExecutor| async move {
        match executor.execute_sql("SELECT 1 AS one".into(), vec![]).await {
            Ok(_) => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    };
    let columns = ["time", "severity_id", "raw_data", "metadata.uid", "metadata.log_source", "actor.user.name", "actor.user.uid",
        "api.operation", "src_endpoint.ip", "unmapped.blob"];
    let settings = [
        "",
        " SETTINGS optimize_move_to_prewhere=1, input_format_parquet_filter_push_down=1, input_format_parquet_page_filter_push_down=1, input_format_parquet_bloom_filter_push_down=1",
        " SETTINGS optimize_move_to_prewhere=0, input_format_parquet_filter_push_down=0, input_format_parquet_use_offset_index=0, max_threads=16",
        " SETTINGS input_format_parquet_allow_missing_columns=1, input_format_parquet_memory_high_watermark=33554432, input_format_parquet_prefer_block_bytes=1048576, input_format_parquet_max_block_size=128, max_threads=8",
    ];
    let mut sql = Vec::new();
    for column in columns {
        for setting in settings {
            sql.push(format!("SELECT count() FROM file({{p:String}}, Parquet) WHERE toString({column}) LIKE '%7%'{setting}"));
            sql.push(format!("SELECT {column} FROM file({{p:String}}, Parquet) ORDER BY time DESC LIMIT 5{setting}"));
            sql.push(format!("SELECT _row_number, {column} FROM file({{p:String}}, Parquet) WHERE _row_number >= 1500 AND _row_number < 1503 AND time > 0{setting}"));
            sql.push(format!("SELECT count() FROM file({{p:String}}, Parquet) PREWHERE toString({column}) != '' WHERE severity_id >= 0{setting}"));
        }
    }
    sql.push("SELECT * FROM file({p:String}, Parquet) LIMIT 3".into());
    sql.push("SELECT count() FROM file({p:String}, Parquet, 'time Int64, severity_id Int64, `metadata.uid` String') WHERE severity_id = 3 SETTINGS input_format_parquet_allow_missing_columns=1".into());
    let mut failures = 0usize;
    let mut answered = 0usize;
    for (n, (sparse, _)) in sparse_files.iter().enumerate() {
        let path = sparse.path().display().to_string();
        // Run four probes at a time (one per lane), then prove the engine is alive.
        for batch in sql.chunks(4) {
            let runs = batch.iter().map(|statement| {
                let (executor, statement, path) = (executor.clone(), statement.clone(), path.clone());
                async move {
                    let outcome = tokio::time::timeout(std::time::Duration::from_secs(60),
                        executor.execute_sql(statement.clone(), vec![("p".into(), path)])).await;
                    (statement, outcome)
                }
            });
            for (statement, outcome) in futures::future::join_all(runs).await {
                match outcome {
                    Err(_) => panic!("scope {n}: probe hung (a faulting native thread parks in chDB's handler): {statement}"),
                    Ok(Ok(_)) => answered += 1,
                    Ok(Err(error)) => {
                        failures += 1;
                        let text = error.to_string();
                        assert!(!text.contains("fatal error"), "scope {n}: {statement}: {text}");
                    }
                }
            }
            if let Err(error) = alive(executor.clone()).await {
                panic!("scope {n}: engine crashed after {batch:?}: {error}");
            }
        }
    }
    // The same probes on a file deleted under a live query (mmap keeps it).
    let (sparse, _) = sparse_files.pop().unwrap();
    let path = sparse.path().display().to_string();
    let run = executor.execute_sql("SELECT count() FROM file({p:String}, Parquet) WHERE toString(api.operation) LIKE '%o%' SETTINGS max_threads=4".into(),
        vec![("p".into(), path)]);
    drop(sparse);
    let _ = run.await;
    alive(executor.clone()).await.expect("engine alive after a sparse file vanished");
    println!("NAN3141 probes answered={answered} failed_cleanly={failures}; engine alive");
}

