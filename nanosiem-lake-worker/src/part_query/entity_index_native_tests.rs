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
    BroadNplRequest {
        request_id: "nan4190".into(),
        tenant_id: TENANT.into(),
        dataset: "logs".into(),
        query: query.into(),
        start: (now - Duration::days(3)).to_rfc3339(),
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
    std::env::remove_var(entity_index::FLAG);
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

    // Build the index over the resident window.
    std::env::set_var(entity_index::FLAG, "1");
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
    std::env::remove_var(entity_index::FLAG);
}
