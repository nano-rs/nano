// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3171, native: a rare hash searched as a bareword when it is present
//! in EVERY file of the window, a few times each (the live blaster: each of
//! 500 hashes every hour, ~164 events a day). Token indexes then prune no
//! file and only some row groups; the v2 block runs can narrow the scan to
//! ~one raw_data page per event, but a whole-window selection offers more
//! of them than NAN-3032's per-selection `FINE_RUN_BUDGET`, so it fenced the
//! kept row groups whole (and a page then walked narrower chunks: the live
//! funnel's extra statements). With the cost rule it fences the runs. Rows
//! and counts are identical either way (`NANO_LAKE_FINE_RUN_COST=0` is the
//! before), for `head`, `stats count by` and an OR of two barewords, and
//! equal the fixture truth and the unpruned `| where like(...)` scan.
//!
//! Rows carry a ~1 KB `raw_data` (the live sysmon JSON body), so one block
//! is about one data page, the granularity a block fence can skip.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::bareword_spread_native -- --ignored --nocapture --test-threads=1
//! ```

use super::native::{digest, engine, envelope, ordered_uids, request, rows_of, TENANT};
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, PartQueryEngine};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

const HASH: &str = "0faafb1b35275f3912da163319c87e224985b26b36e662f813897f22445e187e";
const HASH2: &str = "7d0c4f2a9be31c55e8a6d1907f3b2c4e6a8d0f1e2b3c4d5e6f708192a3b4c5d6";

fn knob(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Files (one bronze batch, one L0 part each) and rows per file: two
/// 65,536-row groups per batch, one UTC event hour per batch (the newest
/// `parts()` whole hours before the fixture clock). Every hit is in the first
/// group, so row-group pruning keeps half of each file under a fence (the
/// live funnel's shape: about half the groups kept).
fn parts() -> usize {
    knob("NAN3171_PARTS", 12)
}

fn per_part() -> usize {
    knob("NAN3171_PER_PART", 131_072)
}

/// `HASH` per file, in distinct blocks of the first group.
const HITS: usize = 12;

/// `HASH` twelve times per file, every ~5th block of its first group;
/// `HASH2` once, in block 2. Thirteen of 64 blocks: never past the "common"
/// quarter, so each file offers its runs: 144 (`HASH`) and 156 (the OR)
/// over the window, past `FINE_RUN_BUDGET`.
fn hit(i: usize) -> Option<&'static str> {
    let offset = i % per_part();
    if (0..HITS).any(|k| offset == 65_536 * k / HITS + 300) {
        Some(HASH)
    } else if offset == 2_548 {
        Some(HASH2)
    } else {
        None
    }
}

fn source(i: usize) -> &'static str {
    if hit(i).is_some() {
        "windows_sysmon"
    } else {
        ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3]
    }
}

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn event(i: usize, time: &str) -> Value {
    let source = source(i);
    let hash = match hit(i) {
        Some(hash) => hash.to_string(),
        None => format!(
            "{:016x}{:016x}{:016x}{:016x}",
            mix(i as u64),
            mix(i as u64 ^ 1),
            mix(i as u64 ^ 2),
            mix(i as u64 ^ 3)
        ),
    };
    let text = format!(
        "Process Create: Image=C:\\Windows\\proc{} Hashes=SHA256={hash} seq {i} source {source}",
        i % 97
    );
    // ~1 KB of per-row-distinct body, as a raw sysmon event (the hash in
    // the message only, so every surface holding it is the same rows).
    let body = (0..14)
        .map(|k| format!("{:016x}", mix(i as u64 * 31 + k)))
        .collect::<Vec<_>>()
        .join(" ");
    let raw = format!(
        "{{\"EventID\":1,\"Computer\":\"ws{}.corp.local\",\"RecordNumber\":{i},\"CommandLine\":\"C:\\\\Windows\\\\proc{}.exe -k {body}\",\
         \"ParentImage\":\"C:\\\\Windows\\\\System32\\\\services.exe\",\"User\":\"CORP\\\\user{}\",\"LogonGuid\":\"{body}\"}}",
        i % 40,
        i % 97,
        i % 600
    );
    json!({
        "class_uid": 1007, "category_uid": 1, "activity_id": 1, "type_uid": 100701, "severity_id": 1,
        "time": time, "message": text, "raw_data": raw, "raw_data_size": raw.len(), "status": "Success",
        "metadata": {"uid": uid(i), "version": "1.9.0", "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": source, "vendor_name": "fixture"}},
        "process": {"pid": 4000 + i % 97, "name": format!("proc{}", i % 97), "file": {"name": format!("proc{}.exe", i % 97), "type_id": 1,
                    "hashes": [{"algorithm_id": 3, "value": hash}]}},
        "actor": {"process": {"pid": 600, "name": "services.exe"}},
        "device": {"hostname": format!("ws{}.corp.local", i % 40), "type_id": 2},
    })
}

fn uid(i: usize) -> String {
    format!("uid-{i:08}")
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

/// NAN-3805: the fixture clock, `wall` floored to its UTC hour. Ingest
/// writes one part per UTC event hour, so a batch that straddles an hour
/// boundary is cut into two parts with smaller row groups, where the hits
/// can crowd past the "common" quarter and offer no block runs. With
/// `Utc::now()` and ~1.75 h batches the cut points moved with the time of
/// day: the OR query saw 105-127 runs at some hours, under the 128-run
/// `FINE_RUN_BUDGET` the test must exceed, and passed at others. On an hour
/// boundary every batch is exactly one event hour ([`event_time`]), so no
/// batch is cut and the layout is the same at every hour of the day
/// (measured: 149 `HASH` runs and 161 for the OR).
fn fixture_now(wall: DateTime<Utc>) -> DateTime<Utc> {
    wall - Duration::microseconds(wall.timestamp_micros().rem_euclid(HOUR_US))
}

const HOUR_US: i64 = 3_600_000_000;

/// A smaller index is a newer event. Batch `b` (indexes `b * per_part()..`)
/// fills the UTC hour `[now - (b + 1) h, now - b h)` evenly, half a step off
/// both edges, so on an hour-aligned `now` ([`fixture_now`]) it never
/// straddles an event-hour boundary.
fn event_time(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    let (batch, offset) = ((i / per_part()) as i64, (i % per_part()) as i64);
    let step_us = HOUR_US / per_part() as i64;
    now - Duration::microseconds(batch * HOUR_US + offset * step_us + step_us / 2)
}

async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    let (parts_n, per) = (parts(), per_part());
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = LocalPartSigner::new(
        "lab-signer-nan3158",
        ed25519_dalek::SigningKey::from_bytes(&[58; 32]),
    )
    .unwrap();
    let mut config = IngestConfig::new(TENANT, root.join("work"));
    config.flush_interval_override_ms = Some(1_000);
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(
        config,
        &parts,
        &sources,
        &spool as &dyn NoticeQueue,
        &signer,
        signer.trusted(),
        BronzeIngestEnricher::disabled(),
        &seed_schema(),
        now_ms,
    )
    .await
    .expect("ingest opens");
    for n in 0..parts_n {
        let range = (parts_n - 1 - n) * per..(parts_n - n) * per;
        let batch = range
            .map(|i| event(i, &event_time(now, i).to_rfc3339()))
            .collect::<Vec<_>>();
        let key = format!("bronze/{n:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT)
            .expect("bronze admitted");
        let at = now_ms + n as i64 * 10_000;
        spool
            .deliver(&SourceNotice {
                tenant_id: TENANT.into(),
                key,
                version: "1".into(),
                bytes: 0,
                sha256: None,
                edge_sha256: None,
                notified_at_ms: at,
            })
            .unwrap();
        ingestor.tick(at + 1_000).await.expect("ingest admits");
        ingestor
            .flush_now(at + 5_000)
            .await
            .expect("ingest flushes");
    }
}

struct Run {
    /// The answer, or the engine's error (the before may exceed the test
    /// engine's 256 MiB budget decoding whole row groups).
    answer: Result<Value, String>,
    funnel: crate::query_timing::Funnel,
    wall: f64,
}

impl Run {
    fn rows(&self) -> Vec<Value> {
        rows_of(self.answer.as_ref().expect("answer"))
    }
}

async fn attempt(
    engine: &PartQueryEngine,
    request: &BroadNplRequest,
) -> (Result<Value, String>, crate::query_timing::Funnel) {
    crate::query_timing::measure("nan3171", async {
        engine.clear_locator_cache();
        let answer = engine.broad_npl(request)
            .await
            .map_err(|error| error.to_string());
        let funnel = crate::query_timing::current()
            .expect("request scope")
            .lock()
            .unwrap()
            .funnel
            .clone();
        Ok::<_, ()>((answer, funnel))
    })
    .await
    .unwrap()
}

/// The query warm (second run), with the cost rule on or off.
async fn run(engine: &PartQueryEngine, query: &str, now: DateTime<Utc>, cost_rule: bool) -> Run {
    if cost_rule {
        std::env::remove_var("NANO_LAKE_FINE_RUN_COST");
    } else {
        std::env::set_var("NANO_LAKE_FINE_RUN_COST", "0");
    }
    let step = request(query, now, 200);
    let _ = attempt(engine, &step).await;
    let started = std::time::Instant::now();
    let (answer, funnel) = attempt(engine, &step).await;
    let wall = started.elapsed().as_secs_f64();
    std::env::remove_var("NANO_LAKE_FINE_RUN_COST");
    let label = if cost_rule { "after" } else { "before" };
    let (statements, storage_rows, storage_bytes) = match &answer {
        Ok(answer) => (
            answer["planner"]["successful_native_statements"].clone(),
            answer["result"]["storage_rows"].clone(),
            answer["result"]["storage_bytes"].clone(),
        ),
        Err(error) => (
            json!(null),
            json!(null),
            json!(format!(
                "ERROR {}",
                error.chars().take(160).collect::<String>()
            )),
        ),
    };
    println!(
        "NAN3171 {label} {query}: wall_s={wall:.3} statements={statements} selections={} fetched_files={} row_groups={} kept_row_groups={} \
         candidate_blocks={} fine_runs={} fine_declined_runs={} storage_rows={storage_rows} storage_bytes={storage_bytes}",
        funnel.selections,
        funnel.fetched_files,
        funnel.row_groups,
        funnel.kept_row_groups,
        funnel.candidate_blocks,
        funnel.fine_runs,
        funnel.fine_declined_runs,
    );
    Run {
        answer,
        funnel,
        wall,
    }
}

fn count_of(row: &Value) -> Option<u64> {
    row["count"]
        .as_u64()
        .or_else(|| row["count"].as_str().and_then(|s| s.parse().ok()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn spread_hash_bareword_fences_block_runs_past_the_run_budget() {
    // The live cell's writer flags: v4 keyword index (blocks, counts,
    // trigrams) and the part result cache.
    crate::parts::block_index::set_enabled(true);
    crate::parts::token_counts::set_enabled(true);
    std::env::set_var(crate::parts::sidecar::TRIGRAM_ENABLE_ENV, "1");
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    // NAN3171_FIXTURE=<dir> keeps (and reuses) the built parts between runs.
    let kept = std::env::var_os("NAN3171_FIXTURE").map(std::path::PathBuf::from);
    let temp = tempfile::tempdir().unwrap();
    let root = kept.unwrap_or_else(|| temp.path().to_path_buf());
    let clock = root.join("now.txt");
    let now = match std::fs::read_to_string(&clock)
        .ok()
        .and_then(|text| text.trim().parse::<DateTime<Utc>>().ok())
    {
        Some(now) => now,
        None => {
            let now = fixture_now(Utc::now());
            std::fs::create_dir_all(&root).unwrap();
            ingest(&root, now).await;
            std::fs::write(&clock, now.to_rfc3339()).unwrap();
            now
        }
    };
    let _ = std::fs::remove_dir_all(root.join("state"));
    std::env::set_var("NANO_LAKE_PART_RESULT_CACHE", "1");
    let engine = engine(&root).await;
    let _ = envelope(&engine, &request("* | stats count", now, 10)).await;

    // NAN3179_FORM=or|set|where: one fence form only, in a fresh process
    // (the test engine's 256 MiB process budget and caches make in-process
    // A/B order-dependent); best of three warm runs per query.
    if let Ok(form) = std::env::var("NAN3179_FORM") {
        for (query, reference) in fence_queries() {
            let (query, set) = match form.as_str() {
                "or" => (query, Some(false)),
                "set" => (query, Some(true)),
                _ => (reference, None),
            };
            let mut best: Option<(f64, f64)> = None;
            for _ in 0..3 {
                let (run, cpu) = fence_form(&engine, &query, now, set).await;
                if let Err(error) = &run.answer {
                    println!("NAN3179-FORM {form} {query}: ERROR {}", error.chars().take(200).collect::<String>());
                    break;
                }
                best = Some(best.map_or((run.wall, cpu), |(w, c)| (w.min(run.wall), c.min(cpu))));
            }
            if let Some((wall, cpu)) = best {
                println!("NAN3179-FORM {form} {query}: wall_s={wall:.3} cpu_ms={cpu:.0}");
            }
        }
        return;
    }
    let rows = parts() * per_part();
    // Newest first, as a page returns them.
    let truth = |hashes: &[&str]| {
        (0..rows)
            .filter(|i| hit(*i).is_some_and(|h| hashes.contains(&h)))
            .map(uid)
            .collect::<Vec<_>>()
    };
    assert_eq!(truth(&[HASH]).len(), parts() * HITS);
    assert!(
        truth(&[HASH]).len() > 128,
        "the fixture must exceed FINE_RUN_BUDGET"
    );

    // Rows: `head 100` of one hash and of an OR of two. Each first selects
    // the whole window, over the run budget.
    let mut walls = Vec::new();
    for (query, hashes) in [
        (format!("{HASH} | head 100"), vec![HASH]),
        (format!("{HASH} OR {HASH2} | head 100"), vec![HASH, HASH2]),
    ] {
        let before = run(&engine, &query, now, false).await;
        let after = run(&engine, &query, now, true).await;
        let expected = truth(&hashes).into_iter().take(100).collect::<Vec<_>>();
        assert_eq!(
            ordered_uids(&before.rows()),
            expected,
            "{query}: before, truth"
        );
        assert_eq!(
            ordered_uids(&after.rows()),
            expected,
            "{query}: after, truth"
        );
        assert_eq!(
            digest(&before.rows()),
            digest(&after.rows()),
            "{query}: rows identical"
        );
        assert_eq!(
            before.answer.as_ref().unwrap()["result"]["page_has_more"],
            after.answer.as_ref().unwrap()["result"]["page_has_more"],
            "{query}"
        );
        // The before declines the whole-window runs; the after fences them.
        assert!(
            before.funnel.fine_declined_runs > 128,
            "{query}: before {:?}",
            before.funnel
        );
        assert!(
            after.funnel.fine_runs > 128 && after.funnel.fine_declined_runs == 0,
            "{query}: after {:?}",
            after.funnel
        );
        walls.push((query.clone(), before.wall, after.wall));
    }

    // Counts: `stats count by` of one hash and of the OR, against the
    // unpruned `| where like(...)` scan (message only: within budget).
    for (query, reference, hashes) in [
        (
            format!("{HASH} | stats count by metadata.log_source"),
            format!("* | where like(message, \"%{HASH}%\") | stats count by metadata.log_source"),
            vec![HASH],
        ),
        (
            format!("{HASH} OR {HASH2} | stats count by metadata.log_source"),
            format!("* | where like(message, \"%{HASH}%\") OR like(message, \"%{HASH2}%\") | stats count by metadata.log_source"),
            vec![HASH, HASH2],
        ),
    ] {
        let before = run(&engine, &query, now, false).await;
        let after = run(&engine, &query, now, true).await;
        let unpruned = run(&engine, &reference, now, true).await;
        let expected = truth(&hashes).len() as u64;
        for (label, outcome) in [("after", &after), ("unpruned", &unpruned)] {
            let rows = outcome.rows();
            assert_eq!(rows.len(), 1, "{query}: {label} {rows:?}");
            assert_eq!(rows[0]["metadata.log_source"], json!("windows_sysmon"), "{query}: {label}");
            assert_eq!(count_of(&rows[0]), Some(expected), "{query}: {label}");
        }
        assert_eq!(digest(&after.rows()), digest(&unpruned.rows()), "{query} vs | where");
        // The before reads whole kept groups: identical when it fits the
        // test engine's 256 MiB budget, a budget refusal otherwise.
        match &before.answer {
            Ok(_) => assert_eq!(digest(&before.rows()), digest(&after.rows()), "{query}: before vs after"),
            Err(error) => assert!(error.contains("memory"), "{query}: before failed: {error}"),
        }
        assert!(before.funnel.fine_declined_runs > 128 && before.funnel.fine_runs == 0, "{query}: before {:?}", before.funnel);
        assert!(after.funnel.fine_runs > 128 && after.funnel.fine_declined_runs == 0, "{query}: after {:?}", after.funnel);
        walls.push((query.clone(), before.wall, after.wall));
    }
    for (query, before, after) in &walls {
        println!("NAN3171-RATIO {query}: before {before:.3}s after {after:.3}s");
    }

    // NAN-3179: the fine runs under the set fence and under the OR fence
    // (`NANO_LAKE_FENCE_SET=0`): identical rows and counts, equal to the
    // unpruned `| where` scan; CPU and wall printed per form.
    for (query, reference) in fence_queries() {
        let or = fence_form(&engine, &query, now, Some(false)).await;
        let set = fence_form(&engine, &query, now, Some(true)).await;
        let unfenced = fence_form(&engine, &reference, now, None).await;
        // The process-wide 256 MiB test budget may refuse a run late in
        // this long test (the same as the before above): compare the rest.
        let rows = |form: &str, run: &Run| match &run.answer {
            Ok(answer) => Some(rows_of(answer)),
            Err(error) if error.contains("memory") => {
                println!("NAN3179 {query}: {form} refused by the test memory budget");
                None
            }
            Err(error) => panic!("{query}: {form} failed: {error}"),
        };
        let (set_rows, or_rows, where_rows) = (rows("set", &set.0), rows("OR", &or.0), rows("| where", &unfenced.0));
        if let (Some(set_rows), Some(or_rows)) = (&set_rows, &or_rows) {
            assert_eq!(digest(set_rows), digest(or_rows), "{query}: set vs OR fence");
        }
        if let Some(set_rows) = &set_rows {
            assert!(set.0.funnel.fine_runs > 128, "{query}: {:?}", set.0.funnel);
            if query.contains("stats") {
                if let Some(where_rows) = &where_rows {
                    assert_eq!(digest(set_rows), digest(where_rows), "{query} vs | where");
                }
            } else {
                let hashes: &[&str] = if query.contains(HASH2) { &[HASH, HASH2] } else { &[HASH] };
                let expected = truth(hashes).into_iter().take(100).collect::<Vec<_>>();
                assert_eq!(ordered_uids(set_rows), expected, "{query}: truth");
            }
        }
        println!(
            "NAN3179 {query}: or wall_s={:.3} cpu_ms={:.0} | set wall_s={:.3} cpu_ms={:.0} | unfenced(| where) wall_s={:.3} cpu_ms={:.0}",
            or.0.wall, or.1, set.0.wall, set.1, unfenced.0.wall, unfenced.1
        );
    }
}

/// The NAN-3179 A/B queries and their unfenced `| where` references.
fn fence_queries() -> Vec<(String, String)> {
    vec![
        (format!("{HASH} | head 100"), format!("* | where like(message, \"%{HASH}%\") | head 100")),
        (
            format!("{HASH} OR {HASH2} | head 100"),
            format!("* | where like(message, \"%{HASH}%\") OR like(message, \"%{HASH2}%\") | head 100"),
        ),
        (
            format!("{HASH} | stats count by metadata.log_source"),
            format!("* | where like(message, \"%{HASH}%\") | stats count by metadata.log_source"),
        ),
        (
            format!("{HASH} OR {HASH2} | stats count by metadata.log_source"),
            format!("* | where like(message, \"%{HASH}%\") OR like(message, \"%{HASH2}%\") | stats count by metadata.log_source"),
        ),
    ]
}

/// The query warm (second run) under one fence form (`None`: the default),
/// with the process CPU (ms) of the timed run.
async fn fence_form(engine: &PartQueryEngine, query: &str, now: DateTime<Utc>, set: Option<bool>) -> (Run, f64) {
    match set {
        Some(false) => std::env::set_var("NANO_LAKE_FENCE_SET", "0"),
        _ => std::env::remove_var("NANO_LAKE_FENCE_SET"),
    }
    let step = request(query, now, 200);
    let _ = attempt(engine, &step).await;
    let cpu = crate::query_timing::process_cpu_ms().unwrap();
    let started = std::time::Instant::now();
    let (answer, funnel) = attempt(engine, &step).await;
    let wall = started.elapsed().as_secs_f64();
    let cpu = crate::query_timing::process_cpu_ms().unwrap() - cpu;
    std::env::remove_var("NANO_LAKE_FENCE_SET");
    (Run { answer, funnel, wall }, cpu)
}
