// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4311, native: `<kw> | stats count by metadata.log_source` from the v3
//! token counts of an hour part's source-family files, end-to-end (real
//! ingestor and hour merge, compiler, planner, chDB, the production
//! `broad_npl` path). Every answer with the counts on must equal the answer
//! with them off (probe knob `keyword_counts=0`, the plain scan), row for row
//! and in page order: whole and cut windows, common, partial, rare and absent
//! tokens, an alias, a page smaller than the group count (the rescan) and a
//! later page. The scalar count and histogram keep their parity too.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::keyword_count::native_tests -- --ignored --nocapture --test-threads=1
//! ```

use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, EngineSettings, PartQueryEngine};
use crate::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use crate::part_query::log_view::PartLogView;
use crate::parts::levels::Level;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::perf_overrides::{Parsed, Probe};
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, DurationRound, Utc};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

const TENANT: &str = "7c2e4a1b-3d5f-4e6a-8b9c-0d1e2f3a4b5c";
const ROWS: usize = 60_000;
const BRONZE_FILES: usize = 4;
/// Nine sources: the hour merge gives the seven largest their own family
/// files and writes the two smallest to the overflow file (scanned).
const SOURCES: [(&str, usize); 9] = [
    ("windows_sysmon", 30), ("windows_event", 20), ("apache_access", 12), ("zeek_conn", 10), ("aws_cloudtrail", 9),
    ("okta_system", 7), ("linux_auditd", 6), ("tiny_a", 4), ("tiny_b", 2),
];

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan4311", ed25519_dalek::SigningKey::from_bytes(&[43; 32])).unwrap()
}

fn source(i: usize) -> &'static str {
    let total = SOURCES.iter().map(|(_, weight)| weight).sum::<usize>();
    let mut slot = i % total;
    for (source, weight) in SOURCES {
        if slot < weight {
            return source;
        }
        slot -= weight;
    }
    unreachable!()
}

fn event(i: usize, time: &str) -> Value {
    let source = source(i);
    let mut text = format!("Process create seq {i} on host{}", i % 13);
    if i % 3 == 0 { text.push_str(" svchost.exe -k netsvcs"); }
    // `powershell` only on some sources.
    if source.starts_with("windows") && i % 2 == 0 { text.push_str(" PowerShell.EXE -nop"); }
    if i % 997 == 0 { text.push_str(" mimikatz"); }
    let raw = format!("raw {source} {text}");
    json!({
        "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701,
        "severity_id": 1, "time": time, "message": text, "raw_data_size": raw.len(), "raw_data": raw,
        "process": {"pid": 4000 + i % 97, "name": format!("proc{}", i % 97), "file": {"name": format!("proc{}.exe", i % 97), "type_id": 1}},
        "actor": {"process": {"pid": 600, "name": "services.exe"}},
        "device": {"hostname": format!("ws-{}.corp.local", i % 13), "type_id": 2},
        "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
            "product": {"name": source, "vendor_name": "fixture"}},
    })
}

fn write_bronze(path: &std::path::Path, events: &[Value]) {
    use arrow_json::reader::infer_json_schema_from_seekable;
    let mut lines = Vec::new();
    for event in events {
        serde_json::to_writer(&mut lines, event).unwrap();
        lines.push(b'\n');
    }
    let (schema, _) =
        infer_json_schema_from_seekable(&mut std::io::Cursor::new(lines.clone()), None).unwrap();
    let reader = arrow_json::ReaderBuilder::new(Arc::new(schema))
        .build(std::io::Cursor::new(lines))
        .unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        writer
            .get_or_insert_with(|| {
                parquet::arrow::ArrowWriter::try_new(
                    std::fs::File::create(path).unwrap(),
                    batch.schema(),
                    None,
                )
                .unwrap()
            })
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

fn event_time(hour: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    hour + Duration::milliseconds(i as i64 * 59)
}

/// Ingest one hour (v3 token indexes) and advance the clock until it is a
/// single hour part.
async fn ingest_and_seal(root: &std::path::Path, hour: DateTime<Utc>) {
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    let hour_ms = hour.timestamp_millis();
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), hour_ms).await.expect("ingest opens");
    let per = ROWS / BRONZE_FILES;
    for n in 0..BRONZE_FILES {
        let batch = (n * per..(n + 1) * per).map(|i| event(i, &event_time(hour, i).to_rfc3339())).collect::<Vec<_>>();
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        let at = event_time(hour, (n + 1) * per).timestamp_millis();
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: at }).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    let mut clock = hour_ms + 4 * 3_600_000;
    for _ in 0..600 {
        ingestor.tick(clock).await.expect("tick");
        clock += 1_000;
        let live = crate::parts::part_log::load_log(&parts, TENANT).await.unwrap();
        if live.parts().count() == 1 && live.parts().all(|part| part.level == Level::Hour) {
            crate::parts::block_index::set_enabled(false);
            crate::parts::token_counts::set_enabled(false);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the hour never sealed into one hour part");
}

async fn engine(root: &std::path::Path) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone())
        .await
        .unwrap();
    let bucket = "nan4311-local";
    let cache = ReaderObjectCache::open(
        ReaderObjectCacheSettings {
            root: state.join("cache"),
            max_bytes: 1 << 30,
            query_max_bytes: 1 << 29,
            fetch_concurrency: 4,
            fetch_deadline: std::time::Duration::from_secs(60),
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
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let small = NativeExecutor::start_with_server_memory_limit(
        runtime.clone(),
        1,
        "parts",
        ExecutorMode::ReadOnly,
        Some(256 << 20),
    )
    .unwrap()
    .with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(
        runtime.clone(),
        1,
        "parts-large",
        ExecutorMode::ReadOnly,
        Some(3 << 29),
    )
    .unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(
        runtime,
        1,
        "parts-rw",
        ExecutorMode::ReadWrite,
        Some(3 << 29),
    )
    .unwrap();
    PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER")
                .expect("NANO_LAKE_COMPILER")
                .into(),
            max_query_bytes: 64 << 30,
            max_memory_bytes: 256 << 20,
            max_execution_seconds: 120,
            threads: 2,
        },
        store,
        view,
        fetcher,
        small,
    )
    .unwrap()
    .with_writer(writer)
    .with_large(large, 3 << 29)
    .with_state_dir(&state)
}

fn request(query: &str, start: DateTime<Utc>, end: DateTime<Utc>, limit: usize, offset: usize) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan4311".into(), tenant_id: TENANT.into(), dataset: "logs".into(), query: query.into(),
        start: start.to_rfc3339(), end: end.to_rfc3339(), limit, offset, table_view: true, use_cache: false,
        cursor_time: None, cursor_event_uid: None, anchor_us: None, decay: None,
        clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

/// The answer's rows, page flag and total, and the count evidence, with
/// the counts on or off.
async fn run(engine: &PartQueryEngine, request: &BroadNplRequest, counts: bool) -> (Value, u64) {
    let scope = Arc::new(Parsed {
        probe: Some(Probe { knobs: BTreeMap::from([("keyword_counts", u64::from(counts))]), settings: Vec::new() }),
        ..Parsed::default()
    });
    let answer = crate::perf_overrides::scoped(Some(scope), crate::query_timing::measure("nan4311", engine.broad_npl(request)))
        .await
        .unwrap_or_else(|error| panic!("{} (counts {counts}): {error}", request.query));
    let groups = answer["planner"]["count_groups"].as_u64().unwrap_or(0);
    (json!({"rows": answer["result"]["rows"], "more": answer["result"]["page_has_more"], "total": answer["result"]["total_count"]}), groups)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn source_counts_from_family_files_match_the_scan() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let dir = tempfile::tempdir().unwrap();
    let hour = (Utc::now() - Duration::hours(30)).duration_trunc(Duration::hours(1)).unwrap();
    ingest_and_seal(dir.path(), hour).await;
    let engine = engine(dir.path()).await;
    let end = event_time(hour, ROWS);
    let windows = [
        (hour - Duration::hours(1), hour + Duration::hours(2)),
        (hour, hour + Duration::hours(1)),
        // Cuts through every family file's (only) row group: all scanned.
        (hour + Duration::minutes(10), end - Duration::minutes(5)),
    ];
    let (mut served, mut compared) = (0, 0);
    for (start, end) in windows {
        for token in ["svchost", "powershell", "process", "mimikatz", "absent"] {
            let mut queries = vec![
                (format!("{token} | stats count by metadata.log_source"), 100, 0),
                (format!("{token} | stats count as n by metadata.log_source"), 100, 0),
                // Fewer groups than the sources: the merge must rescan.
                (format!("{token} | stats count by metadata.log_source"), 2, 0),
                (format!("{token} | stats count by metadata.log_source"), 3, 4),
                (format!("{token} | stats count"), 100, 0),
                (format!("{token} | timechart span=5m count() as count"), 1_000, 0),
            ];
            queries.push((format!("{token} | stats count by metadata.log_source | head 3"), 100, 0));
            for (query, limit, offset) in queries {
                let request = request(&query, start, end, limit, offset);
                let (scan, scan_groups) = run(&engine, &request, false).await;
                assert_eq!(scan_groups, 0, "{query}: counts off must scan");
                let (counted, groups) = run(&engine, &request, true).await;
                assert_eq!(counted, scan, "{query} limit {limit} offset {offset} over [{start}, {end}]: counts differ from the scan");
                compared += 1;
                if groups > 0 {
                    served += 1;
                }
                if query.ends_with("by metadata.log_source") && limit == 100 && token == "svchost" && start <= hour && end > event_time(hour, ROWS) {
                    // Seven source families counted; the two overflow
                    // sources scanned (they are in the answer).
                    assert!(groups >= 7, "{query}: the family files must be counted ({groups} groups)");
                    let rows = counted["rows"].as_array().unwrap();
                    assert_eq!(rows.len(), SOURCES.len(), "{query}: {rows:?}");
                }
                if query.contains("head 3") {
                    assert_eq!(groups, 0, "{query}: another shape never counts");
                }
            }
        }
    }
    eprintln!("{served} of {compared} answers used the counts");
    assert!(served >= 2 * 3 * 4, "counts served only {served} answers");
}
