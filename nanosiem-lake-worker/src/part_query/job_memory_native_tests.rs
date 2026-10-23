// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4164, native: an escalated bare-keyword search job whose statement
//! chDB refuses for memory in the read stage (wide `raw_data`, the job's
//! threads, the default Parquet prefetch) reruns on a bounded reader and
//! commits the exact page instead of failing. This is the 2026-10-20 large-tenant 7 d
//! `48.170.34.111` failure (3.55 of 3.54 GiB at 16 threads, `ColumnData:
//! column: raw_data`), reproduced at a small job-lane cap through the
//! production path: real ingest, the cell's engine wiring and `run_job`.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::jobs::memory_native -- --ignored --nocapture --test-threads=1
//! ```

use super::super::density::native::{engine_with_job_cap, ingest_parts, TENANT};
use crate::job::{LakeQueryJobRequest, LakeQueryJobSpec, ResourceClass, JOB_SCHEMA_VERSION};
use crate::part_query::job_results::JobResultStore;
use crate::part_query::jobs::{result_page, run_job, PartJobPin};
use chrono::{Duration, Utc};
use nanosiem_core::search::DurableLakeTask;
use serde_json::{json, Value};
use std::sync::atomic::AtomicBool;

const NEEDLE: &str = "48.170.34.111";
const PARTS: usize = 8;
const PER_PART: usize = 2_500;
/// The job lane's cap: the unbounded statement at [`THREADS`] outgrows it
/// in the read stage (12+ MiB) while the bounded rungs fit. Calibrated on
/// the pinned libchdb: at 14 MiB 7 statements were refused and every walk
/// window still completed; at 8 MiB even one ~7 MiB raw_data column chunk
/// is refused. `NAN4164_JOB_CAP_MIB` overrides it to recalibrate.
const JOB_CAP_MIB: u64 = 14;
const THREADS: u64 = 8;

fn is_needle(i: usize) -> bool {
    i % 3_331 == 17
}

fn is_near_miss(i: usize) -> bool {
    i % 3_331 == 1_000
}

/// ~3 KiB of log-like text with per-row hex, like live raw_data.
fn raw_text(i: usize) -> String {
    const VOCAB: [&str; 12] = [
        "EventID=4625", "LogonType=3", "Status=0xc000006d", "Workstation=WS-FIN-095", "Process=lsass.exe",
        "TargetUserName=dthomas", "IpPort=49832", "AuthenticationPackage=NTLM", "Keywords=0x8010000000000000",
        "Channel=Security", "Computer=dc01.corp.local", "Task=12544",
    ];
    let mut state = (i as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    let mut out = String::with_capacity(3_200);
    if is_needle(i) {
        out.push_str(&format!("IpAddress={NEEDLE} "));
    } else if is_near_miss(i) {
        out.push_str(&format!("IpAddress=1{NEEDLE}9 "));
    } else {
        out.push_str(&format!("IpAddress=10.1.{}.{} ", i / 250 % 250, i % 250));
    }
    while out.len() < 3_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push_str(VOCAB[(state % VOCAB.len() as u64) as usize]);
        out.push_str(&format!(" {state:016x} "));
    }
    out
}

fn event(i: usize, time: &str) -> Value {
    let raw = raw_text(i);
    json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": format!("connection seq {i}"), "raw_data_size": raw.len(), "raw_data": raw, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "windows_security", "tenant_uid": TENANT,
                     "product": {"name": "windows_security", "vendor_name": "fixture"}},
        "src_endpoint": {"ip": "10.2.2.2", "hostname": "ws-fin-095.corp.local"},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
    })
}

fn spec(pin: &PartJobPin, query: &str, start: &str, end: &str, limit: usize) -> LakeQueryJobSpec {
    LakeQueryJobSpec {
        schema_version: JOB_SCHEMA_VERSION,
        job_id: "01a15737-4894-7203-95b2-7d4c9b4e1bec".into(),
        attempt_id: "attempt-1".into(),
        fence_token: format!("01a15737-4894-7203-95b2-7d4c9b4e1bec:1:1:{}", "f".repeat(36)),
        tenant_id: TENANT.into(),
        generation_id: pin.generation_id.clone(),
        event_config_sha256: pin.event_config_sha256.clone(),
        snapshot_id: pin.snapshot_id,
        compiler_sha256: pin.compiler_sha256.clone(),
        native_artifact_sha256: pin.native_artifact_sha256.clone(),
        hot_tail_manifest_sha256: None,
        hot_tail_snapshot_id: None,
        hot_tail_id: None,
        resource_class: ResourceClass::Medium,
        scan_budget_bytes: 1 << 34,
        submitted_at: Utc::now(),
        scope_deny: Default::default(),
        task: DurableLakeTask::SearchNplV1,
        request: LakeQueryJobRequest {
            dataset: "logs".into(),
            query: query.into(),
            start: start.into(),
            end: end.into(),
            limit,
            offset: 0,
            table_view: true,
            anchor_us: None,
            decay: None,
            clear_boundaries: Default::default(),
            minimum_clear_revision: None,
        },
        result_page_rows: 10_000,
        retention_proof: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_memory_refused_keyword_job_reruns_bounded_and_commits_the_page() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let cap = std::env::var("NAN4164_JOB_CAP_MIB").ok().and_then(|v| v.parse().ok()).unwrap_or(JOB_CAP_MIB) << 20;
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let rows = PARTS * PER_PART;
    let time = |i: usize| now - Duration::seconds(i as i64 * 2 + 30);
    // Oldest part first; a smaller index is a newer event.
    let batches = (0..PARTS)
        .map(|n| ((PARTS - 1 - n) * PER_PART..(PARTS - n) * PER_PART).map(|i| event(i, &time(i).to_rfc3339())).collect())
        .collect();
    ingest_parts(root.path(), now, batches).await;
    let engine = engine_with_job_cap(root.path(), cap, THREADS).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = JobResultStore::new(TENANT, None);
    results.install(Some(opendal::Operator::new(opendal::services::Memory::default()).unwrap().finish()));

    // Fewer needle rows than the page: the newest-first walk widens to the
    // whole window, which reads every part's raw_data (the live shape).
    let expected = (0..rows).filter(|i| is_needle(*i)).map(|i| format!("uid-{i:08}")).collect::<Vec<_>>();
    assert!(!expected.is_empty() && expected.len() < 10, "{expected:?}");
    let start = (now - Duration::hours(23)).to_rfc3339();
    let end = (now + Duration::minutes(1)).to_rfc3339();
    let spec = spec(&pin, NEEDLE, &start, &end, 10);
    let writer = engine.writer().expect("job lane");
    let before = writer.status();
    let reference = run_job(&engine, &spec, &results, &pin, &AtomicBool::new(false))
        .await
        .expect("a memory refusal reruns bounded instead of failing the job");
    let after = writer.status();
    let page = result_page(&results, &reference, &spec.job_id, TENANT, 0).await.unwrap();
    let uids = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["metadata.uid"].as_str().map(str::to_string).unwrap_or_else(|| row["metadata"]["uid"].as_str().unwrap().to_string()))
        .collect::<Vec<_>>();
    println!(
        "NAN4164 job cap={} MiB threads={THREADS}: refused={} completed={} rows={}",
        cap >> 20,
        after.failed - before.failed,
        after.completed - before.completed,
        uids.len()
    );
    assert_eq!(uids, expected, "the committed page is exactly the needle rows, newest first (no near misses)");
    assert!(after.failed > before.failed, "the cap must refuse the unbounded statement (the live failure); recalibrate JOB_CAP_MIB");
}

/// NAN-4164: a newest-first page that spans several disjoint walk chunks
/// (15 m, 1 h, 4 h, the rest) commits exactly the top rows, newest first:
/// needle rows on either side of the newest chunk's lower bound (1 ms
/// apart: ingest keeps event time at millisecond grain, so 1 µs apart they
/// tie) each appear once, since the chunk bounds are inclusive and disjoint,
/// and nothing older than the page leaks in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_page_spanning_walk_chunks_commits_the_exact_top_rows() {
    use chrono::Timelike;
    let _ = tracing_subscriber::fmt().with_env_filter("nanosiem_lake_worker::part_query::jobs=info").with_test_writer().try_init();
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    // Whole seconds, so the newest event (and so the walk anchor) is exact.
    let now = Utc::now().with_nanosecond(0).unwrap();
    let time = |i: usize| now - Duration::seconds(i as i64 * 2 + 30);
    let newest = time(0);
    let first_chunk_start = newest + Duration::microseconds(1) - Duration::minutes(15);
    let edge = |uid: &str, at: chrono::DateTime<Utc>| {
        let mut row = event(17, &at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true));
        row["metadata"]["uid"] = json!(uid);
        row
    };
    let batches = (0..PARTS)
        .map(|n| {
            let mut batch: Vec<Value> = ((PARTS - 1 - n) * PER_PART..(PARTS - n) * PER_PART).map(|i| event(i, &time(i).to_rfc3339())).collect();
            if n == PARTS - 1 {
                // The newest chunk starts 1 µs past `newest - 15 m`: the first
                // row is its oldest millisecond, the second (exactly
                // `newest - 15 m`, the chunk's start - 1 µs) the next chunk's newest.
                batch.push(edge("edge-newer", first_chunk_start + Duration::microseconds(999)));
                batch.push(edge("edge-older", first_chunk_start - Duration::microseconds(1)));
            }
            batch
        })
        .collect();
    ingest_parts(root.path(), now, batches).await;
    let engine = engine_with_job_cap(root.path(), 3 << 29, THREADS).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = JobResultStore::new(TENANT, None);
    results.install(Some(opendal::Operator::new(opendal::services::Memory::default()).unwrap().finish()));

    // Newest first: uid 17 (64 s old), the two edge rows (~15 m), then the
    // index needles at ~1.9 h and ~3.7 h (the 1 h–4 h chunk) and ~5.6 h (the
    // oldest chunk, which holds two more that the page leaves out).
    let mut all = vec!["uid-00000017".to_string(), "edge-newer".into(), "edge-older".into()];
    all.extend((18..PARTS * PER_PART).filter(|i| is_needle(*i)).map(|i| format!("uid-{i:08}")));
    let start = (now - Duration::hours(23)).to_rfc3339();
    let end = (now + Duration::minutes(1)).to_rfc3339();
    for limit in [1, 2, 3, 6, all.len() + 4] {
        let mut spec = spec(&pin, NEEDLE, &start, &end, limit);
        spec.job_id = format!("01a15737-4894-7203-95b2-7d4c9b4e1b{limit:02}");
        spec.fence_token = format!("{}:1:1:{}", spec.job_id, "f".repeat(36));
        let writer = engine.writer().expect("job lane");
        let before = writer.status().completed;
        let reference = run_job(&engine, &spec, &results, &pin, &AtomicBool::new(false)).await.expect("the page commits");
        let statements = writer.status().completed - before;
        let page = result_page(&results, &reference, &spec.job_id, TENANT, 0).await.unwrap();
        let uids = page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["metadata.uid"].as_str().map(str::to_string).unwrap_or_else(|| row["metadata"]["uid"].as_str().unwrap().to_string()))
            .collect::<Vec<_>>();
        println!("NAN4164 chunked page limit={limit}: statements={statements} {uids:?}");
        assert_eq!(uids, all[..limit.min(all.len())], "limit {limit}: exactly the newest needle rows, each once");
        // The statement asks for `limit + 1` rows (the has-more probe). The
        // newest 15 m chunk holds uid 17 and edge-newer, so limit 1 ends the
        // walk there; limit 2 needs edge-older from the next chunk. A page
        // larger than the matches reads every chunk once.
        match limit {
            1 => assert_eq!(statements, 1, "edge-newer is in the newest chunk, which ends the walk"),
            2 => assert_eq!(statements, 2, "edge-older is the next chunk's newest row"),
            _ if limit > all.len() => assert!(statements >= 4, "every chunk is read: {statements}"),
            _ => {}
        }
    }
}
