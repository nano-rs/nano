// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3165, native: an entity `head N` over many resident hot files (real
//! compiler, planner, parts with locator/bloom sidecars, chDB). With the
//! NAN-3165 paths off (sidecar pruning for resident files, payload over every
//! chunk candidate) and on (in-file Parquet blooms for resident files,
//! payload over only the files holding a located instant), rows are
//! hash-identical, equal the `* | where` form and fixture truth, cursor pages
//! continue exactly, and the payload opens fewer files. Prints the per-shape
//! select CPU, statements and files for the PR's before/after numbers.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::sidecar_native -- --ignored --nocapture --test-threads=1
//! ```

use super::native::{digest, engine, envelope, ordered_uids, request, rows_of, statements, TENANT};
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

/// 48 parts (one data file each) of 400 events, one every 4 s (~21 h).
const PARTS: usize = 48;
const PER_PART: usize = 400;
const ROWS: usize = PARTS * PER_PART;
/// In 3 rows of every part (144 rows): present in every file, but a
/// `head 100` page lives in the newest ~third of them.
const SPREAD_IP: &str = "10.6.6.6";
/// In 4 rows of the whole window.
const SPARSE_IP: &str = "10.7.7.7";
const SPARSE_ROWS: [usize; 4] = [11, 7_000, 13_000, 19_000];

fn src_ip(i: usize) -> String {
    if SPARSE_ROWS.contains(&i) {
        SPARSE_IP.to_string()
    } else if i % PER_PART == 17 || i % PER_PART == 211 || i % PER_PART == 389 {
        SPREAD_IP.to_string()
    } else {
        format!("10.1.{}.{}", (i / 250) % 250, i % 250)
    }
}

fn event(i: usize, time: &str) -> Value {
    let source = ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3];
    let text = format!("event {source} seq {i}");
    json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": text, "raw_data": format!("raw {text}"), "raw_data_size": text.len() + 4, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": source, "vendor_name": "fixture"}},
        "src_endpoint": {"ip": src_ip(i), "hostname": format!("web{}.corp.local", i % 40)},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
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
            .get_or_insert_with(|| {
                parquet::arrow::ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap()
            })
            .write(&batch)
            .unwrap();
    }
    writer.unwrap().close().unwrap();
}

/// A smaller index is a newer event.
fn event_time(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    now - Duration::seconds(i as i64 * 4 + 30)
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

const FLAGS: [&str; 2] = ["NANO_LAKE_RESIDENT_INFILE_BLOOMS", "NANO_LAKE_PAYLOAD_AT_INSTANTS"];

/// One run with the NAN-3165 paths on or off, and its process CPU (ms).
async fn run(engine: &super::super::engine::PartQueryEngine, step: &super::super::engine::BroadNplRequest, on: bool) -> (Value, f64) {
    for flag in FLAGS {
        if on { std::env::remove_var(flag) } else { std::env::set_var(flag, "0") }
    }
    // Unattributed process CPU, but this test is the only work in the process.
    let cpu = crate::query_timing::process_cpu_ms().unwrap();
    let answer = envelope(engine, step).await;
    let cpu = crate::query_timing::process_cpu_ms().unwrap() - cpu;
    for flag in FLAGS {
        std::env::remove_var(flag);
    }
    (answer, cpu)
}

fn sum_preselect(planner: &Value, field: &str) -> u64 {
    planner["preselect"]["evidence"][field].as_u64().unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn resident_entity_head_reads_fewer_files_with_identical_rows() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // Entity bloom sidecars on every file (as on the live cell's parts).
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    ingest(root.path(), now).await;
    std::env::remove_var("NANO_LAKE_UID_SIDECAR_WRITE");
    let engine = engine(root.path()).await;
    let uid = |i: usize| format!("uid-{i:08}");
    let truth = |ip: &str, n: usize| (0..ROWS).filter(|i| src_ip(*i) == ip).take(n).map(uid).collect::<Vec<_>>();
    // Warm: every data file local (the resident hot window).
    let _ = envelope(&engine, &request("* | stats count", now, 10)).await;
    let _ = envelope(&engine, &request(&format!("src_endpoint.ip=\"{SPREAD_IP}\" | head 100"), now, 200)).await;
    for ip in [SPREAD_IP, SPARSE_IP] {
        for (shape, head) in [("| head 100", 100_usize), ("| head 20", 20), ("| sort -time | head 50", 50)] {
            let query = format!("src_endpoint.ip=\"{ip}\" {shape}");
            let step = request(&query, now, 200);
            // Off, on, then each again: the second of each pair is reported
            // (sidecar/summary caches warm, as on a live cell).
            let _ = run(&engine, &step, false).await;
            let (off, off_cpu) = run(&engine, &step, false).await;
            let _ = run(&engine, &step, true).await;
            let (on, on_cpu) = run(&engine, &step, true).await;
            let (rows_off, rows_on) = (rows_of(&off), rows_of(&on));
            let expected = truth(ip, head);
            assert_eq!(ordered_uids(&rows_on), expected, "{query}: truth");
            assert_eq!(digest(&rows_on), digest(&rows_off), "{query}: rows hash-identical with NAN-3165 off");
            assert_eq!(on["result"]["page_has_more"], off["result"]["page_has_more"], "{query}");
            let reference = rows_of(&envelope(&engine, &request(&format!("* | where src_endpoint.ip=\"{ip}\" | sort -time | head {head}"), now, 200)).await);
            assert_eq!(ordered_uids(&rows_on), ordered_uids(&reference), "{query} vs | where");
            let (p_off, p_on) = (&off["planner"], &on["planner"]);
            println!(
                "NAN3165 {query:?}: process_cpu_ms off={off_cpu:.1} on={on_cpu:.1} | select_cpu_s off={} on={} | statements off={} on={} \
                 | payload_files off={} on={} (narrowed {}) | payload_source_files off={} on={} | sidecar_pruned off={} on={} | resident_infile off={} on={} | kept_row_groups off={} on={}",
                p_off["select_cpu_s"], p_on["select_cpu_s"], statements(&off), statements(&on),
                p_off["payload_files"], p_on["payload_files"], p_on["payload_narrowed_files"],
                p_off["payload_source_files"], p_on["payload_source_files"],
                sum_preselect(p_off, "entity_sidecar_pruned_files"), sum_preselect(p_on, "entity_sidecar_pruned_files"),
                sum_preselect(p_off, "resident_infile_files"), sum_preselect(p_on, "resident_infile_files"),
                sum_preselect(p_off, "kept_row_groups"), sum_preselect(p_on, "kept_row_groups"),
            );
            assert!(statements(&on) <= statements(&off), "{query}: {p_on}");
            assert!(
                p_on["payload_source_files"].as_u64().unwrap() <= p_off["payload_source_files"].as_u64().unwrap(),
                "{query}: payload never opens more files"
            );
        }
    }
    // Cursor paging (infinite scroll): identical pages on and off,
    // continuing the result exactly.
    for query in [format!("src_endpoint.ip=\"{SPREAD_IP}\""), format!("src_endpoint.ip=\"{SPREAD_IP}\" | sort -time | head 100")] {
        let mut pages = [Vec::new(), Vec::new()];
        for (slot, on) in [(0, false), (1, true)] {
            let mut step = request(&query, now, 25);
            for _ in 0..3 {
                let (page, _) = run(&engine, &step, on).await;
                let rows = rows_of(&page);
                assert_eq!(rows.len(), 25, "{query}: {page}");
                let last = rows.last().unwrap();
                let time = last["time"].as_str().unwrap().replace(' ', "T");
                step.cursor_time = Some(if time.ends_with('Z') { time } else { format!("{time}Z") });
                step.cursor_event_uid = Some(last["metadata.uid"].as_str().unwrap().to_string());
                pages[slot].extend(rows);
            }
        }
        assert_eq!(digest(&pages[1]), digest(&pages[0]), "{query}: cursor pages identical with NAN-3165 off");
        assert_eq!(ordered_uids(&pages[1]), truth(SPREAD_IP, 75), "{query}: cursor pages continue the result exactly");
    }
}
