// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3169, native: a dense-entity host timeline (`device.hostname=X |
//! sort -time | head 50`) over a day of parts where the host is in every
//! file. Real compiler, planner, parts with entity-ranges partials, chDB.
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=...
//! cargo test -p nanosiem-lake-worker --lib part_query::density::host_timeline_native -- --ignored --nocapture --test-threads=1
//! ```

use super::native::{digest, engine, ordered_uids, request, rows_of, statements, TENANT};
use crate::enrichment::BronzeIngestEnricher;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::part_query::engine::{BroadNplRequest, PartQueryEngine};
use crate::parts::part_log::LocalObjectStore;
use crate::parts::provenance::LocalPartSigner;
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::sync::Arc;

/// 24 parts of 10,000 events, one every 330 ms (~22 h).
const PARTS: usize = 24;
const PER_PART: usize = 10_000;
const ROWS: usize = PARTS * PER_PART;
/// In every 8th row (12.5%): dense, in every file and row group.
const DENSE_HOST: &str = "ws-hr-132.corp.local";
/// In every 64th row (1.6%): below the dense cut, still in every file.
const BUSY_HOST: &str = "ws-fin-7.corp.local";
/// In every 40th row (2.5%, below the dense cut) of every eighth part only:
/// the preselect keeps a few row groups (one source family's on a live
/// cell), which used to read the whole window as one chunk.
const CLUSTER_HOST: &str = "ws-ops-3.corp.local";
/// In 3 rows of the window.
const SPARSE_HOST: &str = "ws-lab-9.corp.local";
const SPARSE_ROWS: [usize; 3] = [1_001, 90_017, 200_003];

fn host(i: usize) -> String {
    if SPARSE_ROWS.contains(&i) {
        SPARSE_HOST.to_string()
    } else if i % 8 == 3 {
        DENSE_HOST.to_string()
    } else if i % 64 == 5 {
        BUSY_HOST.to_string()
    } else if i % 40 == 7 && (i / PER_PART).is_multiple_of(8) {
        CLUSTER_HOST.to_string()
    } else {
        format!("ws-{}.corp.local", i % 997)
    }
}

fn event(i: usize, time: &str) -> Value {
    let source = ["aws_cloudtrail", "windows_sysmon", "conduit_proxy"][i % 3];
    let text = format!("event {source} seq {i} {}", "x".repeat(i % 200));
    json!({
        "class_uid": 4001, "category_uid": 4, "activity_id": 6, "type_uid": 400106, "severity_id": 1,
        "time": time, "message": text, "raw_data": format!("raw {text}"), "raw_data_size": text.len() + 4, "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "profiles": ["host"], "log_source": source, "tenant_uid": TENANT,
                     "product": {"name": source, "vendor_name": "fixture"}},
        "device": {"hostname": host(i), "type_id": 1, "ip": format!("10.2.{}.{}", (i / 250) % 250, i % 250)},
        "src_endpoint": {"ip": format!("10.1.{}.{}", (i / 250) % 250, i % 250)},
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

/// A smaller index is a newer event.
fn event_time(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    now - Duration::milliseconds(i as i64 * 330 + 30_000)
}

async fn ingest(root: &std::path::Path, now: DateTime<Utc>) {
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    // The density fixture's signer: `engine` trusts exactly this key.
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
    for n in 0..PARTS {
        let range = (PARTS - 1 - n) * PER_PART..(PARTS - n) * PER_PART;
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

/// One cold step with native diagnostics (statement SQL and rows/bytes
/// read) and its process CPU (ms; this test is the only work in the process).
async fn traced(engine: &PartQueryEngine, step: &BroadNplRequest) -> (Value, f64) {
    engine.clear_locator_cache();
    let cpu = crate::query_timing::process_cpu_ms().unwrap();
    let answer = crate::query_timing::measure(
        "nan3169",
        Box::pin(super::super::debug::collect(engine.broad_npl(step))),
    )
    .await
    .unwrap_or_else(|error| panic!("{}: {error}", step.query));
    (answer, crate::query_timing::process_cpu_ms().unwrap() - cpu)
}

fn native_statements(answer: &Value) -> Vec<Value> {
    answer["planner"]["native_debug"]["statements"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn rows_read(answer: &Value) -> u64 {
    native_statements(answer)
        .iter()
        .map(|s| s["storage_rows"].as_u64().unwrap_or(0))
        .sum()
}

fn bytes_read(answer: &Value) -> u64 {
    native_statements(answer)
        .iter()
        .map(|s| s["storage_bytes"].as_u64().unwrap_or(0))
        .sum()
}

fn report(label: &str, answer: &Value, cpu: f64, dump_sql: bool) {
    let planner = &answer["planner"];
    println!(
        "NAN3169 {label}: cpu_ms={cpu:.0} statements={} rows_read={} bytes_read={} chunks={} two_pass_chunks={} density={} preselect={} kept_groups={}/{} whole={} payload_files={}",
        planner["successful_native_statements"], rows_read(answer), bytes_read(answer), planner["chunks_executed"],
        planner["two_pass_chunks"], planner["density"]["dense"], !planner["preselect"].is_null(),
        planner["preselect"]["evidence"]["kept_row_groups"], planner["preselect"]["evidence"]["row_groups"],
        planner["whole_window_preselected"], planner["payload_files"],
    );
    for (n, statement) in native_statements(answer).iter().enumerate() {
        println!(
            "  #{n} rows={} bytes={} lane={}",
            statement["storage_rows"], statement["storage_bytes"], statement["lane"]
        );
        if dump_sql {
            println!("{}\n", statement["sql"].as_str().unwrap_or_default());
        }
    }
}

const FLAGS: [&str; 2] = [
    "NANO_LAKE_DENSITY_OVER_SELECTIVE",
    "NANO_LAKE_BOUND_PARSING_THREADS",
];

/// One traced step with the NAN-3169 paths on or off.
async fn switched(engine: &PartQueryEngine, step: &BroadNplRequest, on: bool) -> (Value, f64) {
    for flag in FLAGS {
        if on {
            std::env::remove_var(flag)
        } else {
            std::env::set_var(flag, "0")
        }
    }
    let answer = traced(engine, step).await;
    for flag in FLAGS {
        std::env::remove_var(flag);
    }
    answer
}

/// NAN-3169: host timelines read only the newest rows that fill the page.
/// With the fix off and on, rows are hash-identical, equal fixture truth
/// and the `* | where` form, and cursor pages continue exactly. A dense host
/// fills its page in one density-sized chunk (two statements); a host kept
/// in a few row groups no longer reads every kept group of the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn dense_host_timeline_reads_only_the_newest_rows() {
    std::env::remove_var("NANO_LAKE_PART_RESULT_CACHE");
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    std::env::set_var("NANO_LAKE_UID_SIDECAR_WRITE", "1");
    ingest(root.path(), now).await;
    std::env::remove_var("NANO_LAKE_UID_SIDECAR_WRITE");
    let engine = engine(root.path()).await;
    let uid = |i: usize| format!("uid-{i:08}");
    let truth = |name: &str, n: usize| {
        (0..ROWS)
            .filter(|i| host(*i) == name)
            .take(n)
            .map(uid)
            .collect::<Vec<_>>()
    };
    // Warm: every data file local (the resident hot window).
    let _ = traced(&engine, &request("* | stats count", now, 10)).await;
    let dump = std::env::var("NAN3169_DUMP_SQL").is_ok();
    for name in [DENSE_HOST, CLUSTER_HOST, BUSY_HOST, SPARSE_HOST] {
        for (form, shape, head) in [
            ("quoted", "| sort -time | head 50", 50_usize),
            ("bare", "| sort -time | head 50", 50),
            ("quoted", "| head 100", 100),
        ] {
            let pivot = if form == "bare" {
                format!("device.hostname={name}")
            } else {
                format!("device.hostname=\"{name}\"")
            };
            let query = format!("{pivot} {shape}");
            let step = request(&query, now, 200);
            let _ = switched(&engine, &step, false).await;
            let (off, off_cpu) = switched(&engine, &step, false).await;
            let _ = switched(&engine, &step, true).await;
            let (on, on_cpu) = switched(&engine, &step, true).await;
            report(&format!("{query} [off]"), &off, off_cpu, false);
            report(&format!("{query} [on]"), &on, on_cpu, dump);
            let rows = rows_of(&on);
            assert_eq!(ordered_uids(&rows), truth(name, head), "{query}: truth");
            assert_eq!(
                digest(&rows),
                digest(&rows_of(&off)),
                "{query}: rows hash-identical with the fix off"
            );
            assert_eq!(
                on["result"]["page_has_more"], off["result"]["page_has_more"],
                "{query}"
            );
            let (reference, _) = traced(
                &engine,
                &request(
                    &format!("* | where device.hostname=\"{name}\" | sort -time | head {head}"),
                    now,
                    200,
                ),
            )
            .await;
            assert_eq!(
                ordered_uids(&rows),
                ordered_uids(&rows_of(&reference)),
                "{query} vs | where"
            );
            assert!(
                statements(&on) <= statements(&off),
                "{query}: the fix never adds statements"
            );
            assert!(
                rows_read(&on) <= rows_read(&off),
                "{query}: the fix never reads more rows"
            );
            match name {
                DENSE_HOST => {
                    assert!(statements(&on) <= 2, "{query}: {}", on["planner"]);
                    // The newest ~2x page of rows at 1 in 8, the page, and
                    // the payload file's owner probe: never the window.
                    assert!(
                        rows_read(&on) <= (ROWS / 16) as u64,
                        "{query}: {} rows read",
                        rows_read(&on)
                    );
                }
                CLUSTER_HOST => {
                    assert!(statements(&on) <= 2, "{query}: {}", on["planner"]);
                    assert!(
                        rows_read(&on) * 4 <= rows_read(&off),
                        "{query}: {} rows read, {} before",
                        rows_read(&on),
                        rows_read(&off)
                    );
                }
                SPARSE_HOST => assert!(statements(&on) <= 2, "{query}: {}", on["planner"]),
                _ => {}
            }
        }
    }
    // NAN-3179: every timeline under the set fence and the OR fence
    // (`NANO_LAKE_FENCE_SET=0`): rows hash-identical; CPU per form.
    for name in [DENSE_HOST, CLUSTER_HOST, BUSY_HOST, SPARSE_HOST] {
        for query in [
            format!("device.hostname=\"{name}\" | sort -time | head 50"),
            format!("device.hostname=\"{name}\" | head 100"),
            format!("device.hostname=\"{name}\" | stats count by metadata.log_source"),
        ] {
            let step = request(&query, now, 200);
            let mut forms = Vec::new();
            for set in [false, true] {
                if set {
                    std::env::remove_var("NANO_LAKE_FENCE_SET");
                } else {
                    std::env::set_var("NANO_LAKE_FENCE_SET", "0");
                }
                let _ = traced(&engine, &step).await;
                forms.push(traced(&engine, &step).await);
                std::env::remove_var("NANO_LAKE_FENCE_SET");
            }
            let (or, or_cpu) = &forms[0];
            let (set, set_cpu) = &forms[1];
            println!("NAN3179 {query}: or cpu_ms={or_cpu:.0} rows_read={} | set cpu_ms={set_cpu:.0} rows_read={}", rows_read(or), rows_read(set));
            assert_eq!(digest(&rows_of(set)), digest(&rows_of(or)), "{query}: set vs OR fence");
            if dump {
                for statement in native_statements(set) {
                    println!("{}\n", statement["sql"].as_str().unwrap_or_default());
                }
            }
        }
    }
    // Parquet decode pool: chDB decodes row groups on its parsing pool
    // (`max_parsing_threads`, every host core by default) whatever
    // `max_threads` says. Interactive statements now carry the budget.
    let (on, _) = switched(
        &engine,
        &request(
            &format!("device.hostname=\"{BUSY_HOST}\" | sort -time | head 50"),
            now,
            200,
        ),
        true,
    )
    .await;
    for s in native_statements(&on) {
        let sql = s["sql"].as_str().unwrap();
        assert!(
            sql.contains("max_parsing_threads=2"),
            "every statement bounds its parsing pool: {sql}"
        );
    }
    // Cursor paging (infinite scroll): identical pages on and off,
    // continuing the result exactly, across chunk boundaries.
    for name in [DENSE_HOST, CLUSTER_HOST] {
        for query in [
            format!("device.hostname=\"{name}\" | sort -time | head 200"),
            format!("device.hostname=\"{name}\""),
        ] {
            let mut pages = [Vec::new(), Vec::new()];
            for (slot, on) in [(0, false), (1, true)] {
                let mut step = request(&query, now, 40);
                for _ in 0..4 {
                    let (page, _) = switched(&engine, &step, on).await;
                    let rows = rows_of(&page);
                    assert_eq!(rows.len(), 40, "{query}: {page}");
                    let last = rows.last().unwrap();
                    let time = last["time"].as_str().unwrap().replace(' ', "T");
                    step.cursor_time = Some(if time.ends_with('Z') {
                        time
                    } else {
                        format!("{time}Z")
                    });
                    step.cursor_event_uid =
                        Some(last["metadata.uid"].as_str().unwrap().to_string());
                    pages[slot].extend(rows);
                }
            }
            assert_eq!(
                digest(&pages[1]),
                digest(&pages[0]),
                "{query}: cursor pages identical with the fix off"
            );
            assert_eq!(
                ordered_uids(&pages[1]),
                truth(name, 160),
                "{query}: cursor pages continue the result exactly"
            );
        }
    }
    // Last, evidence only (printed, never asserted): chDB's Parquet parsing
    // pool with and without the statement's thread budget. The process-wide
    // chDB memory fence is the fixture's, so the bench may be refused.
    let input = root.path().join("nan3169-wide.parquet");
    let params = vec![(
        "wide_input".to_string(),
        input.to_string_lossy().into_owned(),
    )];
    let written = engine.with_job_statements(engine.run_sql(
        "INSERT INTO FUNCTION file({wide_input:String}, Parquet) SELECT toDateTime64(number, 6) AS time, \
                concat('ws-', toString(number % 997), '.corp.local') AS host, concat(toString(cityHash64(number)), '-', hex(MD5(toString(number)))) AS v \
         FROM numbers(2000000) SETTINGS max_threads=1, output_format_parquet_row_group_size=65536".into(),
        params.clone())).await.is_ok();
    for bounded in [false, true, false, true].into_iter().filter(|_| written) {
        let settings = if bounded {
            "max_threads=2, max_parsing_threads=2"
        } else {
            "max_threads=2"
        };
        let sql = format!("SELECT time FROM file({{wide_input:String}}, Parquet) WHERE host = 'ws-7.corp.local' ORDER BY time DESC LIMIT 50 SETTINGS max_block_size=8192, {settings}");
        let (wall, cpu) = (
            std::time::Instant::now(),
            crate::query_timing::process_cpu_ms().unwrap(),
        );
        if let Err(error) = engine
            .with_job_statements(engine.run_sql(sql, params.clone()))
            .await
        {
            println!("NAN3169 parsing pool bench skipped: {error}");
            break;
        }
        let (wall, cpu) = (
            wall.elapsed().as_secs_f64() * 1e3,
            crate::query_timing::process_cpu_ms().unwrap() - cpu,
        );
        println!("NAN3169 parsing pool bounded={bounded}: wall_ms={wall:.0} cpu_ms={cpu:.0} ({:.1} cores)", cpu / wall);
    }
}
