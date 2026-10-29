// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4190, native: single-host hunts over a multi-day window of resident
//! files, with the window entity index off and on (real ingest, compiler,
//! planner, chDB). The hunted host is "dense" as on the live cell: a burst
//! of three events every three minutes, so it is in every row group, while
//! its rows are under 1% of the window. With the index, its rows are read
//! run by run: results are identical (and equal fixture truth), fewer rows
//! are decoded, and the selection reads no in-file bloom for it. Prints the
//! PR's before/after numbers (`NAN4190 ...`).
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::entity_index_native -- --ignored --nocapture --test-threads=1
//! ```

use super::native::{digest, engine, rows_of, TENANT};
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, PartQueryEngine};
use crate::part_query::entity_index;
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

/// 16 parts of 40,000 events, one every 10 ms (~1.8 h): hour files of
/// ~65,536-row groups, as on the live cell (~450 events/s there).
const PARTS: usize = 16;
const PER_PART: usize = 40_000;
const ROWS: usize = PARTS * PER_PART;
/// A burst of four events every 45,000 rows: in most row groups (as a
/// host seen every few minutes is on the live cell), ~0.01% of the rows.
const HOST: &str = "ws-exec-087.corp.local";
/// Every 8th row: dense (recorded as whole groups).
const BUSY: &str = "ws-busy.corp.local";
/// Never present.
const ABSENT: &str = "ws-nowhere.corp.local";
const CODES: [&str; 5] = ["4624", "4625", "4688", "4672", "5156"];

fn host(i: usize) -> String {
    if i % 45_000 < 4 {
        HOST.into()
    } else if i % 8 == 5 {
        BUSY.into()
    } else {
        format!("ws-{}.corp.local", i % 997)
    }
}

fn user(i: usize) -> String {
    if i % 720 == 1 { "admin".into() } else { format!("u{}", i % 50) }
}

fn code(i: usize) -> &'static str {
    CODES[(i / 7) % CODES.len()]
}

fn event(i: usize, time: &str) -> Value {
    let text = format!("event {} seq {i} {}", code(i), "x".repeat(i % 120));
    json!({
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1, "status_id": 1,
        "service": {"name": "windows logon"},
        "time": time, "message": text, "raw_data": format!("raw {text}"), "raw_data_size": text.len() + 4, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "profiles": ["host"], "log_source": "windows_security", "tenant_uid": TENANT,
                     "event_code": code(i), "product": {"name": "windows_security", "vendor_name": "fixture"}},
        "device": {"hostname": host(i), "type_id": 1, "ip": format!("10.2.{}.{}", (i / 250) % 250, i % 250)},
        "user": {"name": user(i)},
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

/// A smaller index is a newer event.
fn event_time(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    now - Duration::milliseconds(i as i64 * 10 + 30_000)
}

async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    // The density fixture's signer: `engine` trusts exactly this key.
    let signer = LocalPartSigner::new("lab-signer-nan3158", ed25519_dalek::SigningKey::from_bytes(&[58; 32])).unwrap();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(
        config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms,
    )
    .await
    .expect("ingest opens");
    for n in 0..PARTS {
        let range = (PARTS - 1 - n) * PER_PART..(PARTS - n) * PER_PART;
        let batch = range.map(|i| event(i, &event_time(now, i).to_rfc3339())).collect::<Vec<_>>();
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        let at = now_ms + n as i64 * 10_000;
        spool
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None,
                notified_at_ms: at,
            })
            .unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
}

fn request(query: &str, now: DateTime<Utc>) -> BroadNplRequest {
    request_over(query, now, 3)
}

fn request_over(query: &str, now: DateTime<Utc>, days: i64) -> BroadNplRequest {
    BroadNplRequest {
        request_id: "nan4190".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start: (now - Duration::days(days)).to_rfc3339(),
        end: (now + Duration::minutes(1)).to_rfc3339(),
        limit: 10_000,
        offset: 0,
        table_view: true,
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

#[derive(Default, Clone)]
struct Measured {
    wall_ms: f64,
    select_ms: f64,
    select_cpu_ms: f64,
    footer_read_ms: f64,
    chdb_ms: f64,
    storage_rows: u64,
    storage_bytes: u64,
    funnel: crate::query_timing::Funnel,
}

/// One query with native diagnostics, its phases and funnel.
async fn traced(engine: &PartQueryEngine, step: &BroadNplRequest) -> (Value, Measured) {
    engine.clear_locator_cache();
    let started = std::time::Instant::now();
    let (answer, mut measured) = crate::query_timing::measure("nan4190", async {
        let answer = super::super::debug::collect(engine.broad_npl(step)).await?;
        let phases = crate::query_timing::current().expect("request scope");
        let phases = phases.lock().unwrap();
        let measured = Measured {
            select_ms: phases.select_sidecar_ms + phases.select_token_ms + phases.select_bloom_ms,
            select_cpu_ms: phases.select_cpu_ms,
            footer_read_ms: phases.footer_read_ms,
            chdb_ms: phases.chdb_ms,
            funnel: phases.funnel.clone(),
            ..Measured::default()
        };
        Ok::<_, crate::part_query::engine::PartQueryError>((answer, measured))
    })
    .await
    .unwrap_or_else(|error| panic!("{}: {error}", step.query));
    measured.wall_ms = started.elapsed().as_secs_f64() * 1e3;
    for statement in answer["planner"]["native_debug"]["statements"].as_array().cloned().unwrap_or_default() {
        measured.storage_rows += statement["storage_rows"].as_u64().unwrap_or(0);
        measured.storage_bytes += statement["storage_bytes"].as_u64().unwrap_or(0);
    }
    (answer, measured)
}

/// The second of two runs (caches warm, as on a live cell).
async fn warm(engine: &PartQueryEngine, step: &BroadNplRequest) -> (Value, Measured) {
    let _ = traced(engine, step).await;
    traced(engine, step).await
}

fn sorted_digest(rows: &[Value]) -> String {
    let mut rows = rows.iter().map(|row| serde_json::to_string(row).unwrap()).collect::<Vec<_>>();
    rows.sort();
    digest(&rows.into_iter().map(Value::String).collect::<Vec<_>>())
}

fn report(label: &str, query: &str, m: &Measured) {
    let f = &m.funnel;
    println!(
        "NAN4190 {label} {query:?}: wall_ms={:.0} select_ms={:.1} select_cpu_ms={:.1} footer_read_ms={:.1} chdb_ms={:.1} \
         storage_rows={} storage_bytes={} time_files={} index_files={} index_pruned={} infile_pruned={} row_groups={} kept_groups={} \
         candidate_blocks={} fine_runs={} fine_declined={}",
        m.wall_ms, m.select_ms, m.select_cpu_ms, m.footer_read_ms, m.chdb_ms, m.storage_rows, m.storage_bytes, f.time_files,
        f.entity_index_files, f.entity_index_pruned_files, f.infile_pruned_files, f.row_groups, f.kept_row_groups,
        f.candidate_blocks, f.fine_runs, f.fine_declined_runs,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn dense_host_hunts_read_only_matching_runs_with_identical_results() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // Entity bloom sidecars on every file (as on the live cell's parts).
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    ingest(root.path(), now).await;
    std::env::remove_var("NANO_LAKE_UID_SIDECAR_WRITE");
    let engine = engine(root.path()).await;
    // Warm: every data file local (the resident hot window).
    let _ = traced(&engine, &request("* | stats count", now)).await;

    let queries = [
        format!("device.hostname=\"{HOST}\" | timechart span=1h count by metadata.event_code"),
        format!("device.hostname=\"{HOST}\" | stats count by metadata.event_code"),
        format!("device.hostname=\"{HOST}\" | sort -time | head 50"),
        format!("device.hostname=\"{HOST}\" user.name=\"admin\" | stats count"),
        format!("device.hostname=\"{BUSY}\" | stats count by metadata.event_code"),
        format!("device.hostname=\"{ABSENT}\" | stats count"),
    ];
    let mut off = Vec::new();
    for query in &queries {
        off.push(warm(&engine, &request(query, now)).await);
    }

    // Build the index over the resident window (before it: no index, the
    // per-file path, as on a process that has not built one yet).
    let started = std::time::Instant::now();
    let mut built = entity_index::MergeReport::default();
    for _ in 0..8 {
        let report = entity_index::merge_once(&engine, &root.path().join("state"), Utc::now().timestamp_micros()).await.unwrap();
        if !report.built {
            break;
        }
        built = report;
    }
    println!("NAN4190 build: sources={} bytes={} wall_ms={:.0}", built.sources, built.bytes, started.elapsed().as_secs_f64() * 1e3);
    assert!(built.sources > 0, "{built:?}");

    let truth_host = (0..ROWS).filter(|i| host(*i) == HOST).count() as u64;
    for (query, (off_answer, off_m)) in queries.iter().zip(&off) {
        let (on_answer, on_m) = warm(&engine, &request(query, now)).await;
        report("off", query, off_m);
        report("on ", query, &on_m);
        let (rows_off, rows_on) = (rows_of(off_answer), rows_of(&on_answer));
        assert_eq!(sorted_digest(&rows_on), sorted_digest(&rows_off), "{query}: rows identical with the index off\n{rows_on:?}\n{rows_off:?}");
        // Every resident file of the window is indexed: the index answers all.
        assert_eq!(on_m.funnel.entity_index_files, on_m.funnel.time_files, "{query}: answered by the index");
        assert!(on_m.storage_rows <= off_m.storage_rows, "{query}: the index never reads more rows ({} > {})", on_m.storage_rows, off_m.storage_rows);
        if query.contains("stats count by metadata.event_code") && query.contains(HOST) {
            let total = rows_on.iter().map(|row| row["count"].as_u64().or_else(|| row["count"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0)).sum::<u64>();
            assert_eq!(total, truth_host, "{query}: truth");
        }
        if query.contains(ABSENT) {
            assert_eq!(on_m.funnel.entity_index_pruned_files, on_m.funnel.entity_index_files, "absent host: every file pruned by the index");
        }
    }
    // Per-request override off on an index-on process: per-file path.
    let query = &queries[0];
    let overrides = crate::perf_overrides::Overrides { entity_index: Some(false), ..Default::default() };
    let scope = Arc::new(crate::perf_overrides::Parsed { overrides, ..Default::default() });
    let (answer, m) = crate::perf_overrides::scoped(Some(scope), traced(&engine, &request(query, now))).await;
    assert_eq!(m.funnel.entity_index_files, 0, "override off reads no index");
    assert_eq!(sorted_digest(&rows_of(&answer)), sorted_digest(&rows_of(&off[0].0)));
}

// NAN-4772: the index on by default. A 7-day window shaped like the reference
// cell that NAN-4211 broke: ~2,000 one-row-group hour files (12 flushes per
// event hour, 167 hours), the hunted host in every file as one sparse block
// run. The index's exact runs over 7 days fence every file, past chDB's
// statement size: the engine declines them for the coarse selection (same
// rows) where the statement used to fail; over 1 day they fit and are used.

/// Event hours (all inside a 7-day window ending now).
const WEEK_HOURS: usize = 167;
/// Rows per hour file: four 1,024-row blocks, so one block of the host is
/// a run (not "whole group").
const FILE_ROWS: usize = 3_100;
/// Event hours per flush (one file each).
const HOURS_PER_FLUSH: usize = 12;
/// ~12 files per event hour: 2,016 files.
const WEEK_FLUSHES: usize = 168;
/// Flushes ingested after the index is built (its stale tail).
const LATE_FLUSHES: usize = 2;
/// An indicator (`device.ip` is not an indexed path: the control).
const WEEK_IP: &str = "10.9.9.9";

/// `(event hour, round)` of slot `s` (one file).
fn slot_of(s: usize) -> (usize, usize) {
    (s % WEEK_HOURS, s / WEEK_HOURS)
}

fn week_host(s: usize, o: usize) -> String {
    let (h, r) = slot_of(s);
    let at = 1_100 + (h * 7 + r * 13) % 800;
    if (at..at + 3).contains(&o) {
        HOST.into()
    } else if o % 8 == 5 {
        BUSY.into()
    } else {
        format!("ws-{}.corp.local", (o + h) % 997)
    }
}

fn week_user(s: usize, o: usize) -> String {
    let (h, r) = slot_of(s);
    if o == 60 && (h + r) % 9 == 0 { "admin".into() } else { format!("u{}", o % 50) }
}

fn week_ip(s: usize, o: usize) -> String {
    let (h, r) = slot_of(s);
    if o == 2_500 && r % 4 == 0 { WEEK_IP.into() } else { format!("10.2.{}.{}", o % 250, h % 250) }
}

/// `base` is the hour `now` falls in; hour `h` is `h + 1` hours before it.
fn week_time(base: DateTime<Utc>, s: usize, o: usize) -> DateTime<Utc> {
    let (h, r) = slot_of(s);
    base - Duration::hours(h as i64 + 1) + Duration::milliseconds(o as i64 * 1_100 + r as i64 * 50)
}

fn hour_of(now: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(now.timestamp() - now.timestamp().rem_euclid(3_600), 0).unwrap()
}

fn week_event(s: usize, o: usize, time: &str) -> Value {
    let code = CODES[(o / 7 + s) % CODES.len()];
    let text = format!("event {code} slot {s} row {o}");
    json!({
        "class_uid": 3002, "category_uid": 3, "activity_id": 1, "type_uid": 300201, "severity_id": 1, "status_id": 1,
        "service": {"name": "windows logon"},
        "time": time, "message": text, "raw_data": format!("raw {text}"), "raw_data_size": text.len() + 4, "status": "Success",
        "metadata": {"uid": format!("wk-{s:05}-{o:04}"), "version": "1.9.0", "profiles": ["host"], "log_source": "windows_security", "tenant_uid": TENANT,
                     "event_code": code, "product": {"name": "windows_security", "vendor_name": "fixture"}},
        "device": {"hostname": week_host(s, o), "type_id": 1, "ip": week_ip(s, o)},
        "user": {"name": week_user(s, o)},
    })
}

/// Ingest `flushes` (one bronze object and one flush each, `HOURS_PER_FLUSH`
/// one-row-group hour files; no merges, as the L0 window NAN-4211 hit).
async fn ingest_week(root: &std::path::Path, now: DateTime<Utc>, flushes: std::ops::Range<usize>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = LocalPartSigner::new("lab-signer-nan3158", ed25519_dalek::SigningKey::from_bytes(&[58; 32])).unwrap();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    config.max_merges_per_tick = 0;
    let now_ms = now.timestamp_millis();
    let base = hour_of(now);
    let first = now_ms + flushes.start as i64 * 10_000;
    let mut ingestor = Ingestor::open(
        config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), first,
    )
    .await
    .expect("ingest opens");
    for n in flushes {
        let batch = (n * HOURS_PER_FLUSH..(n + 1) * HOURS_PER_FLUSH)
            .flat_map(|s| (0..FILE_ROWS).map(move |o| (s, o)))
            .map(|(s, o)| week_event(s, o, &week_time(base, s, o).to_rfc3339()))
            .collect::<Vec<_>>();
        let key = format!("bronze/week-{n:05}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        let at = now_ms + n as i64 * 10_000;
        spool
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None, edge_sha256: None,
                notified_at_ms: at,
            })
            .unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor.flush_now(at + 5_000).await.expect("ingest flushes");
    }
}

/// Replace indexed L0 inputs through the real compactor and signed log.
async fn merge_week(root: &std::path::Path, now: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = LocalPartSigner::new("lab-signer-nan3158", ed25519_dalek::SigningKey::from_bytes(&[58; 32])).unwrap();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.max_merges_per_tick = 1;
    config.merge_policy.sealed_remerge_debounce_ms = 0;
    let at = now.timestamp_millis() + (WEEK_FLUSHES + LATE_FLUSHES + 1) as i64 * 10_000;
    let mut ingestor = Ingestor::open(
        config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), at,
    ).await.unwrap();
    let report = ingestor.tick(at).await.unwrap();
    assert!(report.merges > 0, "real superseding merge must run: {report:?}");
}

/// Rows of `slots` inside `[start, end]` matching `keep`.
fn week_truth(now: DateTime<Utc>, slots: usize, days: i64, keep: &dyn Fn(usize, usize) -> bool) -> u64 {
    let (base, start, end) = (hour_of(now), now - Duration::days(days), now + Duration::minutes(1));
    (0..slots)
        .flat_map(|s| (0..FILE_ROWS).map(move |o| (s, o)))
        .filter(|(s, o)| keep(*s, *o) && (start..=end).contains(&week_time(base, *s, *o)))
        .count() as u64
}

fn count_sum(rows: &[Value]) -> u64 {
    rows.iter().map(|row| row["count"].as_u64().or_else(|| row["count"].as_str().and_then(|v| v.parse().ok())).unwrap_or(0)).sum()
}

type Keep = Box<dyn Fn(usize, usize) -> bool>;

/// `(query, rows matching it)`: host, user and IP hunts, a dense host, an
/// absent host. `head 50` checks its row count, the rest their summed counts.
fn week_queries() -> Vec<(String, Keep)> {
    let host: fn() -> Keep = || Box::new(|s, o| week_host(s, o) == HOST);
    vec![
        (format!("device.hostname=\"{HOST}\" | timechart span=1h count"), host()),
        (format!("device.hostname=\"{HOST}\" | stats count by metadata.event_code"), host()),
        (format!("device.hostname=\"{HOST}\" | sort -time | head 50"), host()),
        ("user.name=\"admin\" | stats count".to_string(), Box::new(|s, o| week_user(s, o) == "admin")),
        (format!("device.ip=\"{WEEK_IP}\" | stats count"), Box::new(|s, o| week_ip(s, o) == WEEK_IP)),
        (format!("device.hostname=\"{BUSY}\" | stats count"), Box::new(|s, o| week_host(s, o) == BUSY)),
        (format!("device.hostname=\"{ABSENT}\" | stats count"), Box::new(|_, _| false)),
    ]
}

const WINDOWS: [i64; 2] = [1, 7];

/// Every week query over each window: `(days, query index, digest, measured)`.
/// Each answer equals the fixture truth over `slots`.
async fn week_arm(engine: &PartQueryEngine, label: &str, now: DateTime<Utc>, slots: usize, off: bool) -> Vec<(i64, usize, String, Measured)> {
    let mut out = Vec::new();
    for days in WINDOWS {
        for (n, (query, keep)) in week_queries().iter().enumerate() {
            let step = request_over(query, now, days);
            let (answer, m) = if off {
                let overrides = crate::perf_overrides::Overrides { entity_index: Some(false), ..Default::default() };
                let scope = Arc::new(crate::perf_overrides::Parsed { overrides, ..Default::default() });
                crate::perf_overrides::scoped(Some(scope), traced(engine, &step)).await
            } else {
                traced(engine, &step).await
            };
            report(&format!("{label} {days}d"), query, &m);
            let rows = rows_of(&answer);
            let truth = week_truth(now, slots, days, keep.as_ref());
            if query.contains("head 50") {
                assert_eq!(rows.len() as u64, truth.min(50), "{label} {days}d {query}: truth");
            } else {
                assert_eq!(count_sum(&rows), truth, "{label} {days}d {query}: truth");
            }
            out.push((days, n, sorted_digest(&rows), m));
        }
    }
    out
}

fn assert_identical(label: &str, left: &[(i64, usize, String, Measured)], right: &[(i64, usize, String, Measured)]) {
    let queries = week_queries();
    assert_eq!(left.len(), right.len());
    for (l, r) in left.iter().zip(right) {
        assert_eq!((l.0, l.1, &l.2), (r.0, r.1, &r.2), "{label} {}d {}: rows identical", l.0, queries[l.1].0);
    }
}

fn arm_at(arm: &[(i64, usize, String, Measured)], days: i64, query: usize) -> &Measured {
    &arm.iter().find(|(d, n, _, _)| *d == days && *n == query).expect("measured").3
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn week_hunts_identical_with_index_missing_partial_full_stale_and_off() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let started = std::time::Instant::now();
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    ingest_week(root.path(), now, 0..WEEK_FLUSHES).await;
    println!("NAN4772 ingest: flushes={WEEK_FLUSHES} wall_s={:.1}", started.elapsed().as_secs_f64());
    let engine = super::native::engine_with_limits(root.path(), 3 << 29, 2, 1 << 30).await;
    let _ = traced(&engine, &request_over("* | stats count", now, 7)).await;
    let slots = WEEK_FLUSHES * HOURS_PER_FLUSH;
    const HOST_STATS: usize = 1;
    const ABSENT_Q: usize = 6;

    // Missing: no index yet (a process before its first build).
    let missing = week_arm(&engine, "missing", now, slots, false).await;
    for (days, n, _, m) in &missing {
        assert_eq!(m.funnel.entity_index_files, 0, "{days}d {n}: no index");
    }
    let week_files = arm_at(&missing, 7, HOST_STATS).funnel.time_files;
    assert!(week_files >= 2_000, "the fixture is the NAN-4211 shape: {week_files} files over 7d");

    // Partial: one build pass (MAX_TAIL_FILES files indexed, the rest per file).
    let first = entity_index::merge_once(&engine, &root.path().join("state"), Utc::now().timestamp_micros()).await.unwrap();
    assert!(first.built && first.sources > 0 && first.sources < week_files, "{first:?}");
    let partial = week_arm(&engine, "partial", now, slots, false).await;
    assert_identical("partial vs missing", &partial, &missing);
    let m = arm_at(&partial, 7, HOST_STATS);
    assert!(m.funnel.entity_index_files > 0 && m.funnel.entity_index_files < m.funnel.time_files, "partial: {:?}", m.funnel);

    // Full: build passes until nothing is due.
    let mut built = first;
    for _ in 0..128 {
        let report = entity_index::merge_once(&engine, &root.path().join("state"), Utc::now().timestamp_micros()).await.unwrap();
        if !report.built {
            break;
        }
        built = report;
    }
    println!("NAN4772 build: sources={} bytes={}", built.sources, built.bytes);
    let full = week_arm(&engine, "full", now, slots, false).await;
    assert_identical("full vs missing", &full, &missing);
    for days in WINDOWS {
        let m = arm_at(&full, days, HOST_STATS);
        assert_eq!(m.funnel.entity_index_files, m.funnel.time_files, "{days}d: every file answered by the index");
        let absent = arm_at(&full, days, ABSENT_Q);
        assert_eq!(absent.funnel.entity_index_pruned_files, absent.funnel.time_files, "{days}d absent host: every file pruned");
    }
    // NAN-4211: over 7 days the exact runs fence every file, past the
    // statement budget: declined (the coarse selection, same rows) where
    // the statement used to fail. Over 1 day they fit and are used.
    let week = arm_at(&full, 7, HOST_STATS);
    assert!(week.funnel.fine_declined_runs > 0 && week.funnel.fine_runs == 0, "7d: {:?}", week.funnel);
    let day = arm_at(&full, 1, HOST_STATS);
    assert!(day.funnel.fine_runs > 0 && day.funnel.fine_declined_runs == 0, "1d: {:?}", day.funnel);
    assert!(day.storage_rows < arm_at(&missing, 1, HOST_STATS).storage_rows, "1d: the runs read fewer rows");

    // Per-request override off on a built index: the per-file path.
    let off = week_arm(&engine, "off", now, slots, true).await;
    assert_identical("off vs missing", &off, &missing);
    for (days, n, _, m) in &off {
        assert_eq!(m.funnel.entity_index_files, 0, "{days}d {n}: override off reads no index");
    }

    // Stale: new flushes after the build. The index serves only the live
    // files it covers (a source key is `(part, file, sha256)`, so a merged
    // or superseded file is uncovered the same way); the rest take the
    // per-file path.
    ingest_week(root.path(), now, WEEK_FLUSHES..WEEK_FLUSHES + LATE_FLUSHES).await;
    std::env::remove_var("NANO_LAKE_UID_SIDECAR_WRITE");
    let slots = (WEEK_FLUSHES + LATE_FLUSHES) * HOURS_PER_FLUSH;
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let stale = week_arm(&engine, "stale", now, slots, false).await;
    let stale_off = week_arm(&engine, "stale-off", now, slots, true).await;
    assert_identical("stale vs off", &stale, &stale_off);
    let m = arm_at(&stale, 7, HOST_STATS);
    assert!(m.funnel.entity_index_files < m.funnel.time_files, "stale: a tail outside the index {:?}", m.funnel);

    merge_week(root.path(), now).await;
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    let merged = week_arm(&engine, "superseded", now, slots, false).await;
    let merged_off = week_arm(&engine, "superseded-off", now, slots, true).await;
    assert_identical("superseded vs off", &merged, &merged_off);
    assert_identical("compaction preserves rows", &merged, &stale_off);
    let m = arm_at(&merged, 7, HOST_STATS);
    assert!(m.funnel.entity_index_files > 0 && m.funnel.entity_index_files < arm_at(&stale, 7, HOST_STATS).funnel.entity_index_files,
        "superseded sources leave index coverage: {:?}", m.funnel);

    // An incomplete backing file cannot prove absence: every file scans.
    let index = engine.entity_index().current().unwrap();
    std::fs::OpenOptions::new().write(true).open(index.path()).unwrap().set_len(0).unwrap();
    let truncated = week_arm(&engine, "truncated", now, slots, false).await;
    assert_identical("truncated vs scan", &truncated, &merged_off);
    assert!(truncated.iter().all(|(_, _, _, m)| m.funnel.entity_index_files == 0));
}
