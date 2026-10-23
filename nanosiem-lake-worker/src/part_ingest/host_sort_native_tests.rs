// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3412, native: host-sorted endpoint hours end to end (real ingestor
//! and hour merges under `NANO_LAKE_ENDPOINT_HOST_SORT`, real compiler,
//! planner, chDB). Two tenants hold the same events in two hours: one
//! written entirely time-sorted, one mixed (hour A time-sorted, hour B
//! host-sorted, then rewritten with late rows, which restores time order for
//! the merge and host-sorts again). Every host, time-range, `head`,
//! newest-first and count answer must be identical between them and equal
//! to the fixture truth, and the host-sorted hour must keep fewer row groups
//! for a single host.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_ingest::host_sort::native -- --ignored --nocapture --test-threads=1
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
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, DurationRound, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const TENANT: &str = "7a2e4c1d-3b5f-4e6a-8c9d-0f1e2d3c4b5a";
/// Rows per hour, two thirds sysmon.
const ROWS: usize = 36_000;
/// Late rows later written into hour B.
const LATE: usize = 60;
const BRONZE_FILES: usize = 3;
const HEAVY: &str = "ws-heavy.corp.local";
const RARE: &str = "ws-rare.corp.local";

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3412", ed25519_dalek::SigningKey::from_bytes(&[34; 32])).unwrap()
}

/// Event `i` of hour `h` (0 = A, 1 = B); `i >= ROWS` are late rows.
fn sysmon(i: usize) -> bool {
    i % 3 != 2
}

fn host(i: usize) -> String {
    match i {
        _ if i.is_multiple_of(5) => HEAVY.into(),
        1_003 | 20_002 | 35_998 | 36_004 => RARE.into(),
        _ => format!("ws-{:03}.corp.local", (i * 7) % 300),
    }
}

fn uid(h: usize, i: usize) -> String {
    format!("uid-{h}-{i:06}")
}

fn event_time(hour: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    if i < ROWS {
        // Pairs share a timestamp: ties break on uid.
        hour + Duration::milliseconds((i / 2) as i64 * 199)
    } else {
        hour + Duration::seconds((i - ROWS) as i64 * 59) + Duration::milliseconds(7)
    }
}

fn event(h: usize, i: usize, time: &str) -> Value {
    let text = format!("seq {h} {i}");
    let digest = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(i.to_le_bytes()));
    let raw = format!("raw {text} {digest}{digest}");
    let source = if sysmon(i) { "windows_sysmon" } else { "conduit_proxy" };
    let mut row = if sysmon(i) {
        json!({
            "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701, "severity_id": 1,
            "process": {"pid": 4000 + i % 97, "name": format!("proc{}", i % 23), "file": {"name": format!("proc{}.exe", i % 23), "type_id": 1}},
            "actor": {"process": {"pid": 600, "name": "services.exe"}},
            "device": {"hostname": host(i), "type_id": 2},
            "status": "Success",
        })
    } else {
        json!({
            "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
            "src_endpoint": {"ip": format!("10.0.{}.{}", i % 7, i % 200), "hostname": host(i)},
            "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
            "status": "Success",
        })
    };
    row["time"] = json!(time);
    row["message"] = json!(text);
    row["raw_data_size"] = json!(raw.len());
    row["raw_data"] = json!(raw);
    row["metadata"] = json!({"uid": uid(h, i), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
        "product": {"name": source, "vendor_name": "fixture"}});
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

/// Ingest rows `range` of hour `h` under the host-sort switch `host_sort`,
/// then advance the clock until every live part is an hour part, one per
/// hour ingested so far, holding every row. `clock` (ms) only moves forward
/// across calls on one tenant.
async fn ingest_and_seal(root: &std::path::Path, hours: &[DateTime<Utc>], h: usize, range: std::ops::Range<usize>, host_sort: bool, clock: &mut i64) {
    if host_sort {
        std::env::set_var(super::ENABLE_ENV, "1");
    } else {
        std::env::remove_var(super::ENABLE_ENV);
    }
    let hour = hours[h];
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    *clock = (*clock).max(hour.timestamp_millis());
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), *clock).await.expect("ingest opens");
    let files = if range.len() < BRONZE_FILES { 1 } else { BRONZE_FILES };
    let per = range.len().div_ceil(files);
    for n in 0..files {
        let rows = (range.start + n * per)..(range.start + (n + 1) * per).min(range.end);
        let batch = rows.clone().map(|i| event(h, i, &event_time(hour, i).to_rfc3339())).collect::<Vec<_>>();
        let key = format!("bronze/{h}-{}-{n:04}.parquet", range.start);
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        let at = (*clock + 1_000).max(event_time(hour, rows.end.min(ROWS)).timestamp_millis());
        *clock = at + 5_000;
        spool.deliver(&SourceNotice {
            tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None, notified_at_ms: at,
        }).unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
    *clock = (*clock).max(hour.timestamp_millis() + 4 * 3_600_000);
    let want_parts = h + 1;
    let want_rows = (h * ROWS + range.end) as u64;
    for _ in 0..1_200 {
        ingestor.tick(*clock).await.expect("tick");
        *clock += 1_000;
        let live = crate::parts::part_log::load_log(&parts, TENANT).await.unwrap();
        if live.parts().count() == want_parts
            && live.parts().all(|part| part.level == Level::Hour)
            && live.parts().map(|part| part.rows).sum::<u64>() == want_rows
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("hour {h} rows {range:?} never sealed into hour parts");
}

/// Whether hour `hour`'s live part has a host-sorted data file.
async fn hour_is_host_sorted(root: &std::path::Path, hour: DateTime<Utc>) -> bool {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let live = crate::parts::part_log::load_log(&parts, TENANT).await.unwrap();
    let event_hour = (hour.timestamp() / 3_600) as i32;
    let part = live.parts().find(|part| part.event_hour == event_hour).expect("hour part").clone();
    let keys = crate::parts::format::PartKeys::new(TENANT, part.level, part.event_hour, &part.part_id).unwrap();
    (0..part.data_files as usize).any(|index| {
        let path = root.join("parts").join(keys.data(index));
        super::is_host_sorted(&path).unwrap()
    })
}

async fn engine(root: &std::path::Path) -> PartQueryEngine {
    let signer = signer();
    let state = root.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3412-local";
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
        Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts"))),
    )
    .unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").expect("NANO_CHDB_LIBRARY_PATH"),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").expect("NANO_CHDB_LIBRARY_SHA256"),
    )
    .unwrap();
    std::mem::forget(runtime.clone());
    let small = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(256 << 20))
        .unwrap()
        .with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    PartQueryEngine::new(
        EngineSettings {
            tenant_id: TENANT.into(),
            bucket: bucket.into(),
            compiler: std::env::var("NANO_LAKE_COMPILER").expect("NANO_LAKE_COMPILER").into(),
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

fn request(query: &str, start: DateTime<Utc>, end: DateTime<Utc>, limit: usize, table_view: bool) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan3412".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start: start.to_rfc3339(),
        end: end.to_rfc3339(),
        limit,
        offset: 0,
        table_view,
        use_cache: false,
        cursor_time: None,
        cursor_event_uid: None,
        anchor_us: None,
        decay: None,
        clear_boundaries: Default::default(),
        watch_weights: Default::default(),
        minimum_clear_revision: None,
        deny_source_types: Default::default(),
    }
}

async fn run(engine: &PartQueryEngine, request: &BroadNplRequest) -> (Vec<Value>, crate::query_timing::Funnel) {
    engine.clear_locator_cache();
    crate::query_timing::measure("nan3412", async {
        let answer = engine.broad_npl(request)
            .await
            .unwrap_or_else(|error| panic!("{}: {error}", request.query));
        let funnel = crate::query_timing::current().expect("request scope").lock().unwrap().funnel.clone();
        let rows = answer["result"]["rows"].as_array().cloned().unwrap_or_else(|| panic!("{}: no rows in {answer}", request.query));
        Ok::<_, ()>((rows, funnel))
    })
    .await
    .unwrap()
}

fn uids(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            row.get("metadata.uid")
                .or_else(|| row.pointer("/metadata/uid"))
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("row without metadata.uid: {row}"))
                .to_string()
        })
        .collect()
}

fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}

/// Fixture rows `(time, uid)` of both hours (with the late rows) matching
/// `keep`, newest first.
fn truth(hours: &[DateTime<Utc>], keep: impl Fn(usize) -> bool, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<String> {
    let mut rows = Vec::new();
    for (h, hour) in hours.iter().enumerate() {
        let count = if h == 1 { ROWS + LATE } else { ROWS };
        for i in (0..count).filter(|i| keep(*i)) {
            let time = event_time(*hour, i);
            if time >= start && time <= end {
                rows.push((time, uid(h, i)));
            }
        }
    }
    rows.sort_by(|a, b| b.cmp(a));
    rows.into_iter().map(|(_, uid)| uid).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn host_sorted_hours_answer_exactly_like_time_sorted_hours() {
    let a = (Utc::now() - Duration::hours(10)).duration_trunc(Duration::hours(1)).unwrap();
    let hours = [a, a + Duration::hours(1)];
    let off = tempfile::tempdir().unwrap();
    let mixed = tempfile::tempdir().unwrap();
    let (mut off_clock, mut mixed_clock) = (0, 0);
    ingest_and_seal(off.path(), &hours, 0, 0..ROWS, false, &mut off_clock).await;
    ingest_and_seal(off.path(), &hours, 1, 0..ROWS, false, &mut off_clock).await;
    ingest_and_seal(off.path(), &hours, 1, ROWS..ROWS + LATE, false, &mut off_clock).await;
    ingest_and_seal(mixed.path(), &hours, 0, 0..ROWS, false, &mut mixed_clock).await;
    ingest_and_seal(mixed.path(), &hours, 1, 0..ROWS, true, &mut mixed_clock).await;
    assert!(hour_is_host_sorted(mixed.path(), hours[1]).await, "hour B is host-sorted");
    // A late-data rewrite of the host-sorted hour (restored to time order
    // for the merge) writes it host-sorted again.
    ingest_and_seal(mixed.path(), &hours, 1, ROWS..ROWS + LATE, true, &mut mixed_clock).await;
    std::env::remove_var(super::ENABLE_ENV);
    assert!(!hour_is_host_sorted(mixed.path(), hours[0]).await, "hour A stays time-sorted");
    assert!(hour_is_host_sorted(mixed.path(), hours[1]).await, "rewritten hour B is host-sorted");
    assert!(!hour_is_host_sorted(off.path(), hours[1]).await);

    let off = engine(off.path()).await;
    let mixed = engine(mixed.path()).await;
    let (start, end) = (hours[0] - Duration::minutes(5), hours[1] + Duration::hours(2));
    let narrow = (hours[1] + Duration::minutes(10), hours[1] + Duration::minutes(25));
    let host_is = |name: &'static str| move |i: usize| sysmon(i) && host(i) == name;
    // (query, window, limit, newest-first truth if exact, ordered page)
    type Case<'a> = (&'a str, (DateTime<Utc>, DateTime<Utc>), usize, Option<Vec<String>>, bool);
    let cases: Vec<Case> = vec![
        ("device.hostname=\"ws-rare.corp.local\"", (start, end), 100_000, Some(truth(&hours, host_is(RARE), start, end)), false),
        ("device.hostname=\"ws-heavy.corp.local\"", (start, end), 100_000, Some(truth(&hours, host_is(HEAVY), start, end)), false),
        ("device.hostname=\"ws-heavy.corp.local\"", narrow, 100_000, Some(truth(&hours, host_is(HEAVY), narrow.0, narrow.1)), false),
        ("device.hostname=\"ws-017.corp.local\"", narrow, 100_000, Some(truth(&hours, host_is("ws-017.corp.local"), narrow.0, narrow.1)), false),
        ("device.hostname=\"ws-heavy.corp.local\" | head 20", (start, end), 20, Some(truth(&hours, host_is(HEAVY), start, end)[..20].to_vec()), true),
        ("device.hostname=\"ws-rare.corp.local\" | head 2", (start, end), 2, Some(truth(&hours, host_is(RARE), start, end)[..2].to_vec()), true),
        ("metadata.log_source=\"windows_sysmon\"", (start, end), 50, Some(truth(&hours, sysmon, start, end)[..50].to_vec()), true),
        ("metadata.log_source=\"windows_sysmon\"", narrow, 50, Some(truth(&hours, sysmon, narrow.0, narrow.1)[..50].to_vec()), true),
        ("*", narrow, 75, None, true),
    ];
    for (query, (from, to), limit, expected, ordered) in cases {
        let request = request(query, from, to, limit, true);
        let (want, _) = run(&off, &request).await;
        let (got, _) = run(&mixed, &request).await;
        let (want, got) = (uids(&want), uids(&got));
        if ordered {
            assert_eq!(got, want, "{query} [{from}, {to}] newest-first page");
        } else {
            assert_eq!(sorted(got.clone()), sorted(want.clone()), "{query} [{from}, {to}] rows");
        }
        if let Some(expected) = expected {
            if ordered {
                assert_eq!(got, expected, "{query} [{from}, {to}] truth");
            } else {
                assert_eq!(sorted(got), sorted(expected), "{query} [{from}, {to}] truth");
            }
        }
    }
    // Counts and the host-stats shape (the 7 d host stats in production).
    for (query, window, expected) in [
        ("device.hostname=\"ws-heavy.corp.local\" | stats count() as n", (start, end), truth(&hours, host_is(HEAVY), start, end).len()),
        ("device.hostname=\"ws-rare.corp.local\" | stats count() as n", (start, end), truth(&hours, host_is(RARE), start, end).len()),
        ("device.hostname=\"ws-heavy.corp.local\" | stats count() as n", narrow, truth(&hours, host_is(HEAVY), narrow.0, narrow.1).len()),
    ] {
        let request = request(query, window.0, window.1, 1_000, false);
        let (want, _) = run(&off, &request).await;
        let (got, _) = run(&mixed, &request).await;
        assert_eq!(got, want, "{query}");
        let n = got[0]["n"].as_u64().or_else(|| got[0]["n"].as_str().and_then(|n| n.parse().ok())).unwrap();
        assert_eq!(n as usize, expected, "{query} truth");
    }
    let stats = request("device.hostname=\"ws-heavy.corp.local\" | stats count() as n by process.name", start, end, 1_000, false);
    let (want, _) = run(&off, &stats).await;
    let (got, _) = run(&mixed, &stats).await;
    let rows = |rows: &[Value]| sorted(rows.iter().map(Value::to_string).collect());
    assert!(!want.is_empty());
    assert_eq!(rows(&got), rows(&want), "host stats by process");

    // Pruning: over hour B alone a rare-host search keeps fewer row groups
    // of the host-sorted hour (smaller groups, and only the host's).
    let hour_b = request("device.hostname=\"ws-rare.corp.local\"", hours[1], hours[1] + Duration::minutes(59), 100_000, true);
    let (_, off_funnel) = run(&off, &hour_b).await;
    let (_, mixed_funnel) = run(&mixed, &hour_b).await;
    eprintln!("nan3412 rare host hour B: time-sorted {}/{} row groups, host-sorted {}/{}",
        off_funnel.kept_row_groups, off_funnel.row_groups, mixed_funnel.kept_row_groups, mixed_funnel.row_groups);
    assert!(mixed_funnel.kept_row_groups <= 3, "{mixed_funnel:?}");
}
