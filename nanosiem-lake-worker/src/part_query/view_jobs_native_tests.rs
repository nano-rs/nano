// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3078, native: a durable job whose admitted range crosses the tenant's
//! retention cutoff never returns an event older than the cutoff, for a plain
//! search and for a product view, through query[T]'s real job path (parts,
//! chDB, the compiler, R2 result commit).
//!
//! Run the whole module (all 29 tests) with one command:
//!
//! ```sh
//! cargo build -p nanosiem-core --bin lake_query_compile
//! export NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=...
//! cargo test -p nanosiem-lake-worker --lib part_query::view_jobs::native:: -- --ignored --test-threads=1
//! ```
//!
//! The module is self-contained beyond those two variables (NAN-3805):
//! - the compiler is `NANO_LAKE_COMPILER` when set, else the
//!   `lake_query_compile` built into this test binary's own target dir
//!   ([`fixture_compiler`]); a missing binary fails before any job runs,
//!   not as a `compiler start failed` deep inside one;
//! - every test takes [`serial`], so they never overlap even without
//!   `--test-threads=1`: they share one in-process chDB server and flip
//!   process-global state (`force_step_bytes`, fold/merge counters, the
//!   facet fixture env flags, product-state build queues);
//! - the fixture sizes the read lane itself ([`fixture_executor_mb`],
//!   [`FIXTURE_EXECUTOR_MB`]); `NAN3161_EXECUTOR_MB` only overrides it.
//!   That lane's limit becomes chDB's process-wide `max_server_memory_usage`,
//!   which counts the process RSS every earlier test left behind: at 2 GiB
//!   the last tests of a full run hit `MEMORY_LIMIT_EXCEEDED` although each
//!   passes alone;
//! - the facet tests set their own writer/read flags ([`EnvFlags`]).

use super::super::engine::{EngineSettings, PartQueryEngine};
use super::super::fetch::{parts_key_prefix, PartFetcher, StoreObjectSource};
use super::super::job_results::JobResultStore;
use super::super::jobs::{result_page, run_job, PartJobPin};
use super::super::log_view::PartLogView;
use super::super::server::R2Credentials;
use crate::enrichment::BronzeIngestEnricher;
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::job::{LakeQueryJobRequest, LakeQueryJobSpec, ResourceClass, JOB_SCHEMA_VERSION};
use crate::native::NativeChdb;
use crate::part_ingest::ingest::seed_schema;
use crate::part_ingest::{IngestConfig, Ingestor, NoticeQueue, SourceNotice, SpoolQueue};
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::LocalPartSigner;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings};
use chrono::{DateTime, Duration, Utc};
use nanosiem_core::search::{DurableLakeTask, DurableResultRetentionProof, SearchTenantScope, TimeRangeInput};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

const TENANT: &str = "3b8e9d2a-6c1f-4e0a-9b7d-2f5c8a1e4d60";
const ROWS: usize = 600;

/// Serializes this module's tests (see the module docs). A test that
/// panicked poisons nothing: the next one still runs.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The fixture's read-lane memory, in MiB: chDB's process-wide cap for the
/// whole run (see the module docs). 4 GiB leaves room for the RSS a full
/// run accumulates; the month fixtures need more than 256 MiB on their own.
const FIXTURE_EXECUTOR_MB: u64 = 4_096;

/// [`FIXTURE_EXECUTOR_MB`], or `NAN3161_EXECUTOR_MB` when set (a bench
/// knob); an unparsable value fails loudly rather than silently shrinking
/// the cap.
fn fixture_executor_mb() -> u64 {
    match std::env::var("NAN3161_EXECUTOR_MB") {
        Ok(value) => value.trim().parse().ok().filter(|mb| *mb > 0)
            .unwrap_or_else(|| panic!("NAN3161_EXECUTOR_MB={value:?} is not a positive number of MiB")),
        Err(_) => FIXTURE_EXECUTOR_MB,
    }
}

/// The lake compiler: `NANO_LAKE_COMPILER`, or `lake_query_compile` next
/// to this test binary (`target/<profile>/deps/..` → `target/<profile>/`),
/// so a plain `cargo test` in the same target dir finds it. A path with no
/// binary (never built, or a target dir the harness did not build into)
/// fails loudly here.
fn fixture_compiler() -> std::path::PathBuf {
    let path = match std::env::var_os("NANO_LAKE_COMPILER") {
        Some(path) => std::path::PathBuf::from(path),
        None => std::env::current_exe().ok()
            .and_then(|exe| exe.parent()?.parent().map(|profile| profile.join("lake_query_compile")))
            .expect("test binary path has a target profile dir"),
    };
    assert!(path.is_file(), "lake compiler {} does not exist: run `cargo build -p nanosiem-core --bin lake_query_compile` \
        in this target dir, or point NANO_LAKE_COMPILER at a built one", path.display());
    path
}

/// Process env flags set for one test and restored (even on panic) when
/// dropped. Only taken under [`serial`].
struct EnvFlags(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl EnvFlags {
    fn set(flags: &[(&'static str, &str)]) -> Self {
        let previous = flags.iter().map(|(name, value)| {
            let old = std::env::var_os(name);
            std::env::set_var(name, value);
            (*name, old)
        }).collect();
        Self(previous)
    }
}

impl Drop for EnvFlags {
    fn drop(&mut self) {
        for (name, old) in self.0.drain(..).rev() {
            match old {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

fn signer() -> LocalPartSigner {
    LocalPartSigner::new("lab-signer-nan3078", ed25519_dalek::SigningKey::from_bytes(&[31; 32])).unwrap()
}

/// Half a minute off the minute grid, so no event sits on the cutoff.
fn event_at(now: DateTime<Utc>, i: usize) -> DateTime<Utc> {
    now - Duration::minutes(i as i64 + 1) - Duration::seconds(30)
}

fn event(i: usize, time: &str) -> Value {
    let raw = format!("cloud {i}");
    json!({
        "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "activity_id": 1, "type_uid": 600301,
        "severity_id": 1, "time": time, "raw_data": raw, "raw_data_size": raw.len(), "status": "Success",
        "metadata": {"uid": format!("uid-{i:08}"), "version": "1.9.0", "profiles": ["cloud"], "log_source": "aws_cloudtrail", "tenant_uid": TENANT,
                     "product": {"name": "CloudTrail", "vendor_name": "AWS"}},
        "actor": {"user": {"name": "alice", "uid": "arn:aws:iam::100:user/alice"}},
        "api": {"operation": if i % 2 == 0 { "ListRoles" } else { "GetObject" }, "service": {"name": if i % 2 == 0 { "iam" } else { "s3" }}},
        "cloud": {"provider": "AWS", "region": "us-east-1", "account": {"uid": "100"}},
        "src_endpoint": {"ip": format!("10.0.0.{}", i % 5)},
        "resources": if i % 3 == 0 { json!([]) } else {
            json!([{"uid": "one", "type": "Role"}, {"uid": "two", "type": if i % 2 == 0 { "Role" } else { "Bucket" }}])
        },
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

/// An in-process S3 stand-in (any key) for the `job_results` grant.
async fn fake_r2() -> String {
    use axum::{body::Bytes, http::{Method, StatusCode, Uri}, response::IntoResponse, Router};
    let objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::default();
    let app = Router::new().fallback(move |method: Method, uri: Uri, body: Bytes| {
        let objects = objects.clone();
        async move {
            let path = uri.path().trim_start_matches('/').to_string();
            match method {
                Method::PUT => {
                    objects.lock().unwrap().insert(path, body.to_vec());
                    (StatusCode::OK, [("etag", "\"e\"")]).into_response()
                }
                Method::GET => match objects.lock().unwrap().get(&path) {
                    Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
                    None => (StatusCode::NOT_FOUND, [("content-type", "application/xml")],
                        b"<?xml version=\"1.0\"?><Error><Code>NoSuchKey</Code></Error>".to_vec()).into_response(),
                },
                _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    endpoint
}

async fn engine(root: &std::path::Path, now: DateTime<Utc>) -> PartQueryEngine {
    engine_with_spacing(root, now, 1).await
}

async fn engine_with_spacing(root: &std::path::Path, now: DateTime<Utc>, minutes: i64) -> PartQueryEngine {
    engine_with_facet_variants(root, now, minutes, false).await
}

async fn engine_with_facet_variants(root: &std::path::Path, now: DateTime<Utc>, minutes: i64, variants: bool) -> PartQueryEngine {
    engine_with_variants(root, now, minutes, variants, false).await
}

async fn engine_with_variants(root: &std::path::Path, now: DateTime<Utc>, minutes: i64, variants: bool, asset: bool) -> PartQueryEngine {
    engine_with_locator_ties(root, now, minutes, variants, asset, false).await
}

async fn engine_with_locator_ties(root: &std::path::Path, now: DateTime<Utc>, minutes: i64, variants: bool, asset: bool, ties: bool) -> PartQueryEngine {
    engine_with_detail_fixture(root, now, minutes, variants, asset, ties, false).await
}

async fn engine_with_detail_fixture(root: &std::path::Path, now: DateTime<Utc>, minutes: i64, variants: bool, asset: bool, ties: bool, details: bool) -> PartQueryEngine {
    engine_with_detail_pattern(root, now, minutes, variants, asset, ties, details, false).await
}

async fn engine_with_detail_pattern(root: &std::path::Path, now: DateTime<Utc>, minutes: i64, variants: bool, asset: bool, ties: bool, details: bool, sparse: bool) -> PartQueryEngine {
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
    // The default fixture spans ten hours; wide-view fixtures span several days.
    let batch = (0..ROWS)
        .map(|i| {
            let mut row = event(i, &(now - Duration::minutes((i as i64 + 1) * minutes) - Duration::seconds(30)).to_rfc3339());
            if ties {
                // 300 matching rows at one instant, larger than a page. UID
                // descending order must survive the time-only locator cutoff.
                row["time"] = json!((now - Duration::minutes(30)).to_rfc3339());
            }
            if variants {
                if i % 11 == 0 {
                    row["class_uid"] = json!(1001);
                    row["class_name"] = json!("File Activity");
                    row["category_uid"] = json!(1);
                    row["type_uid"] = json!(100101);
                    row["device"] = json!({"hostname":"fixture-host", "type_id":1});
                    row["file"] = json!({"name":"fixture.log", "path":"/fixture.log", "type_id":1,
                        "hashes":[{"algorithm_id":3,"value":"a".repeat(64)}]});
                }
                if i % 3 == 0 { row["metadata"]["log_source"] = json!("azure_audit"); }
                if i % 5 == 0 { row["cloud"]["region"] = Value::Null; }
                if i % 7 == 0 { row["resources"] = json!([{"uid":"null-type", "type": null}, {"uid":"role-one", "type": "Role"}, {"uid":"role-two", "type": "Role"}]); }
                if i % 13 == 0 { row["activity_name"] = json!("Update"); }
                if i % 11 == 0 {
                    row.as_object_mut().unwrap().remove("resources");
                    row.as_object_mut().unwrap().remove("src_endpoint");
                }
            }
            if asset {
                if i % 4 == 0 { row["actor"]["user"]["name"] = Value::Null; }
                if i % 9 == 0 { row["actor"]["user"]["name"] = json!(""); }
                if i % 6 == 0 && i % 11 != 0 {
                    row["user"] = json!({"name":"fallback"});
                    row["dst_endpoint"] = json!({"hostname":"fixture-host", "ip":"10.0.0.1"});
                    row["class_uid"] = json!(3002);
                    row["class_name"] = json!("Authentication");
                    row["category_uid"] = json!(3);
                    row["type_uid"] = json!(300201);
                    row.as_object_mut().unwrap().remove("api");
                    row.as_object_mut().unwrap().remove("resources");
                    row["status"] = json!(if i % 12 == 0 { "FaIlUrE" } else { "Success" });
                }
            }
            if details {
                row["class_uid"] = json!(4001);
                row["class_name"] = json!("Network Activity");
                row["category_uid"] = json!(4);
                row["type_uid"] = json!(400101);
                for name in ["api", "resources", "cloud", "file", "process", "device", "activity_name"] {
                    row.as_object_mut().unwrap().remove(name);
                }
                row["metadata"]["profiles"] = json!(["host"]);
                row["device"] = json!({"hostname": "host.fixture.test", "type_id": 2});
                row["src_endpoint"] = json!({"hostname": "host.fixture.test", "ip": "10.0.0.1"});
                row["dst_endpoint"] = json!({"hostname": "example.test", "ip": "203.0.113.7", "port": 443});
                row["connection_info"] = json!({"protocol_num": 6, "direction_id": 2});
                row["actor"]["process"] = json!({"pid": 42, "name": "fixture.exe", "cmd_line": "fixture.exe --test",
                    "file": {"name": "fixture.exe", "path": "/fixture.exe", "type_id": 1,
                        "hashes": [{"algorithm_id": 3, "value": "a".repeat(64)}, {"algorithm_id": 1, "value": "b".repeat(32)}]}});
            }
            if sparse && i % 137 != 0 {
                row["actor"]["process"]["file"]["hashes"][0]["value"] = json!("c".repeat(64));
                row["dst_endpoint"]["hostname"] = json!("other.test");
            }
            row
        })
        .collect::<Vec<_>>();
    write_bronze(&sources_dir.join("bronze/0000.parquet"), &batch);
    crate::bronze::admit_bronze_files(&[sources_dir.join("bronze/0000.parquet")], TENANT).expect("bronze admitted");
    spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key: "bronze/0000.parquet".into(), version: "1".into(), bytes: 0,
        sha256: None, edge_sha256: None, notified_at_ms: now_ms }).unwrap();
    ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
    ingestor.flush_now(now_ms + 5_000).await.expect("ingest flushes");

    reopen_engine(root).await
}

async fn reopen_engine(root: &std::path::Path) -> PartQueryEngine {
    reopen_engine_at(root, "state").await
}

/// Another process's engine over the same signed parts, with its own state
/// dir and cache (NAN-3148: query[T] and product[T] side by side).
async fn reopen_engine_at(root: &std::path::Path, state_name: &str) -> PartQueryEngine {
    // NAN3168_ENGINE_THREADS: the interactive thread budget (bench: a wide
    // budget shows the product budget, not the engine's, bounds a build).
    let threads = std::env::var("NAN3168_ENGINE_THREADS").ok().and_then(|value| value.parse().ok()).unwrap_or(2_u64);
    reopen_engine_with_threads(root, state_name, threads).await
}

async fn reopen_engine_with_threads(root: &std::path::Path, state_name: &str, threads: u64) -> PartQueryEngine {
    let signer = signer();
    let state = root.join(state_name);
    std::fs::create_dir_all(&state).unwrap();
    let trusted = signer.trusted();
    let store: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(root.join("parts")).unwrap());
    let view = PartLogView::open(store.as_ref(), TENANT, trusted.clone()).await.unwrap();
    let bucket = "nan3078-local";
    let cache = ReaderObjectCache::open(ReaderObjectCacheSettings {
        root: state.join("cache"), max_bytes: 1 << 30, query_max_bytes: 1 << 29,
        fetch_concurrency: 4, fetch_deadline: std::time::Duration::from_secs(60),
    }, TENANT, bucket, &parts_key_prefix(TENANT).unwrap(),
    Arc::new(StoreObjectSource::local(bucket, store.clone(), root.join("parts")))).unwrap();
    let fetcher = PartFetcher::new(TENANT, bucket, store.clone(), trusted, cache).unwrap();
    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    ).unwrap();
    std::mem::forget(runtime.clone());
    let read_lane_mb = fixture_executor_mb();
    let executor = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts", ExecutorMode::ReadOnly, Some(read_lane_mb << 20))
        .unwrap()
        .with_result_limit(64 << 20);
    let large = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-large", ExecutorMode::ReadOnly, Some(3 << 29)).unwrap();
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(3 << 29)).unwrap();
    PartQueryEngine::new(EngineSettings {
        tenant_id: TENANT.into(), bucket: bucket.into(),
        compiler: fixture_compiler(),
        max_query_bytes: 64 << 30, max_memory_bytes: 256 << 20, max_execution_seconds: 120, threads,
    }, store, view, fetcher, executor).unwrap().with_writer(writer).with_large(large, 3 << 29).with_state_dir(&state)
}

fn spec(pin: &PartJobPin, attempt: &str, task: DurableLakeTask, query: &str, start: DateTime<Utc>, end: DateTime<Utc>,
    proof: Option<DurableResultRetentionProof>) -> LakeQueryJobSpec {
    LakeQueryJobSpec {
        schema_version: JOB_SCHEMA_VERSION,
        job_id: "nan3078-job".into(),
        attempt_id: attempt.into(),
        fence_token: format!("nan3078-job:1:1:{}", "f".repeat(36)),
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
        task,
        request: LakeQueryJobRequest {
            dataset: "logs".into(),
            query: query.into(),
            start: start.to_rfc3339(),
            end: end.to_rfc3339(),
            limit: 10_000,
            offset: 0,
            table_view: false,
            anchor_us: None,
            decay: None,
            clear_boundaries: Default::default(),
            minimum_clear_revision: None,
        },
        result_page_rows: 10_000,
        retention_proof: proof,
    }
}

fn event_time(row: &Value) -> DateTime<Utc> {
    let text = row.get("time").and_then(Value::as_str).expect("row time");
    DateTime::parse_from_rfc3339(text).map(|time| time.with_timezone(&Utc))
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%S%.f").map(|time| time.and_utc()))
        .expect("parse row time")
}

#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_job_whose_range_crosses_the_cutoff_never_returns_expired_rows() {
    let _serial = serial();
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine(root.path(), now).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = JobResultStore::new(TENANT, None);
    let endpoint = fake_r2().await;
    results.install(Some(results.operator_for(&serde_json::from_value::<R2Credentials>(json!({
        "endpoint": endpoint, "region": "auto", "access_key_id": "k", "secret_access_key": "s",
    })).unwrap()).unwrap()));

    // An erasure made the last four hours the only retained events: the
    // tenant's cutoff sits in the middle of the fixture.
    let cutoff = now - Duration::hours(4);
    let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, cutoff.timestamp_micros()).unwrap();
    let end = now + Duration::minutes(1);
    // The caller asked for the whole ten hours; admission binds it to the cutoff.
    let asked = now - Duration::hours(10);
    assert!(DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(asked, end)).is_err());
    let proof = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(cutoff, end)).unwrap();
    let cancelled = AtomicBool::new(false);
    let expected = (0..ROWS).filter(|i| event_at(now, *i) >= cutoff).count() as u64;
    assert!(expected > 0 && (expected as usize) < ROWS, "the cutoff splits the fixture");

    // A plain search.
    let search = spec(&pin, "attempt-search", DurableLakeTask::SearchNplV1, "*", cutoff, end, Some(proof.clone()));
    let reference = run_job(&engine, &search, &results, &pin, &cancelled).await.expect("search job runs");
    let page = result_page(&results, &reference, "nan3078-job", TENANT, 0).await.unwrap();
    let rows = page["rows"].as_array().unwrap();
    assert_eq!(rows.len() as u64, expected);
    assert!(rows.iter().all(|row| event_time(row) >= cutoff), "a search row predates the cutoff");

    // A product view (the Cloud dossier fold) counts only retained events.
    let dossier = DurableLakeTask::CloudDossierV1 {
        principal: "alice".into(),
        account: None,
        provider: None,
        filters: Default::default(),
        event_query: "class_uid=6003 | sort -time".into(),
        risk: None,
    };
    let view = spec(&pin, "attempt-dossier", dossier.clone(), "| cloud principal=alice", cutoff, end, Some(proof.clone()));
    let reference = run_job(&engine, &view, &results, &pin, &cancelled).await.expect("dossier job runs");
    let page = result_page(&results, &reference, "nan3078-job", TENANT, 0).await.unwrap();
    let artifact = &page["rows"][0];
    assert_eq!(artifact["operation"], "cloud_dossier");
    assert_eq!(artifact["response"]["error_rate"]["events_total"], json!(expected));
    let first_seen = artifact["response"]["identity"]["first_seen"].as_str().unwrap();
    assert!(event_time(&json!({"time": first_seen})) >= cutoff);

    // A durable baseline admitted over its lookback: the lookback reads are
    // clamped to the cutoff too, and every dimension is evaluated.
    let baseline = DurableLakeTask::BaselineV1 {
        entity_type: "ip".into(),
        entity_value: "10.0.0.1".into(),
        window_days: 7,
        activity_days: 30,
        dims: None,
        incident_start_micros: (now - Duration::hours(1)).timestamp_micros(),
        incident_end_micros: end.timestamp_micros(),
    };
    let view = spec(&pin, "attempt-baseline", baseline, "ip=\"10.0.0.1\" | baseline", cutoff, end, Some(proof.clone()));
    let reference = run_job(&engine, &view, &results, &pin, &cancelled).await.expect("baseline job runs");
    let page = result_page(&results, &reference, "nan3078-job", TENANT, 0).await.unwrap();
    let rows = page["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| row["entity_type"] == "ip" && row.get("partial").is_none_or(Value::is_null)), "{rows:?}");

    // A spec whose window is wider than its proof is refused, not clamped.
    let wide = spec(&pin, "attempt-wide", DurableLakeTask::SearchNplV1, "*", asked, end, Some(proof.clone()));
    assert!(run_job(&engine, &wide, &results, &pin, &cancelled).await.is_err());
    // A view without the runner's proof is refused.
    let bare = spec(&pin, "attempt-bare", dossier, "| cloud principal=alice", cutoff, end, None);
    assert!(run_job(&engine, &bare, &results, &pin, &cancelled).await.is_err());
    // A job for another tenant is refused before it reads.
    let mut foreign = spec(&pin, "attempt-foreign", DurableLakeTask::SearchNplV1, "*", cutoff, end, Some(proof));
    foreign.tenant_id = "9d0c7b1e-2f3a-4b5c-8d6e-7f8091a2b3c4".into();
    assert!(run_job(&engine, &foreign, &results, &pin, &cancelled).await.is_err());
}

// ---------------------------------------------------------------------------
// NAN-3086: `| retro` as a durable cell job.
// ---------------------------------------------------------------------------

fn retro_task(indicators: &[&str], axis: &str, submode: &str) -> DurableLakeTask {
    DurableLakeTask::RetroV1 {
        indicators: indicators.iter().map(|value| value.to_string()).collect(),
        axis: axis.into(),
        submode: submode.into(),
        offset: 0,
        limit: 50,
    }
}

fn seen(value: &Value) -> DateTime<Utc> {
    event_time(&json!({"time": value.as_str().expect("a seen timestamp")}))
}

/// Retained fixture events carrying `ip` as their source endpoint.
fn retained_hits(now: DateTime<Utc>, floor: DateTime<Utc>, ip: usize) -> u64 {
    (0..ROWS).filter(|i| i % 5 == ip && event_at(now, *i) >= floor).count() as u64
}

#[allow(clippy::too_many_arguments)]
async fn run_retro_job(
    engine: &PartQueryEngine,
    results: &JobResultStore,
    pin: &PartJobPin,
    attempt: &str,
    task: DurableLakeTask,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    proof: Option<DurableResultRetentionProof>,
) -> anyhow::Result<Value> {
    let spec = spec(pin, attempt, task, "ioc=\"10.0.0.1\" | retro", start, end, proof);
    let reference = run_job(engine, &spec, results, pin, &AtomicBool::new(false)).await?;
    let page = result_page(results, &reference, "nan3078-job", TENANT, 0).await?;
    Ok(page["rows"][0].clone())
}

async fn job_results() -> Arc<JobResultStore> {
    let results = JobResultStore::new(TENANT, None);
    let endpoint = fake_r2().await;
    results.install(Some(results.operator_for(&serde_json::from_value::<R2Credentials>(json!({
        "endpoint": endpoint, "region": "auto", "access_key_id": "k", "secret_access_key": "s",
    })).unwrap()).unwrap()));
    results
}

#[cfg(feature = "enterprise")]
/// A seven-day exact companion counts older days, respects the admitted
/// retention cutoff and applies source authorization to every aggregate read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn seven_day_asset_summary_counts_retained_rows_and_scoped_facets() {
    let _serial = serial();
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine_with_spacing(root.path(), now, 16).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = job_results().await;
    let end = now + Duration::minutes(1);
    let cancelled = AtomicBool::new(false);
    for days in [7, 3] {
        let start = now - Duration::days(days);
        let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, start.timestamp_micros()).unwrap();
        let proof = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(start, end)).unwrap();
        let expected = (0..ROWS).filter(|i| {
            i % 5 == 1 && now - Duration::minutes((*i as i64 + 1) * 16) - Duration::seconds(30) >= start
        }).count() as u64;
        let recent = (0..ROWS).filter(|i| i % 5 == 1 && (*i + 1) * 16 < 24 * 60).count() as u64;
        assert!(expected > recent, "older days must contribute");
        let base = "src_endpoint.ip=\"10.0.0.1\"";
        for deny in ["hidden-source", "aws_cloudtrail"] {
            let task = DurableLakeTask::AssetV1 {
                identifier_field: "src_endpoint.ip".into(), identifier_value: "10.0.0.1".into(),
                identities: vec![], filters: None,
                summary_query: format!("{base} | stats count() as event_count, count(eval(class_uid=6003)) as cloud_api_count"),
                source_query: format!("{base} | stats count() as event_count by metadata.log_source | sort -event_count | head 50"),
                user_query: format!("{base} | eval asset_user=coalesce(actor.user.name,user.name) | stats count() as event_count by asset_user | sort -event_count | head 50"),
            };
            let mut view = spec(&pin, &format!("asset-{days}-{deny}"), task, "| asset", start, end, Some(proof.clone()));
            view.scope_deny.insert(deny.to_string());
            let reference = run_job(&engine, &view, &results, &pin, &cancelled).await.expect("Asset summary job runs");
            let page = result_page(&results, &reference, "nan3078-job", TENANT, 0).await.unwrap();
            let response = &page["rows"][0]["response"];
            let count = if deny == "aws_cloudtrail" { 0 } else { expected };
            assert_eq!(response["total_count"], json!(count));
            assert_eq!(response["total_count_exact"], json!(true));
            let expected_facets = if count == 0 { json!({"event_kind": [], "source_type": [], "user": []}) }
                else { json!({"event_kind": [["CLOUD_API", count]], "source_type": [["aws_cloudtrail", count]], "user": [["alice", count]]}) };
            assert_eq!(response["facets"], expected_facets);
        }
    }
}

#[cfg(feature = "enterprise")]
/// A retro whose admitted range crosses the tenant's retention cutoff counts
/// only retained events in every submode: the rollup, the per-field
/// attribution, the pivot slices and the first/last seen bounds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_retro_whose_range_crosses_the_cutoff_never_counts_expired_rows() {
    let _serial = serial();
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine(root.path(), now).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = job_results().await;

    // An erasure left the last four hours as the only retained events.
    let cutoff = now - Duration::hours(4);
    let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, cutoff.timestamp_micros()).unwrap();
    let end = now + Duration::minutes(1);
    // The analyst asked for the whole ten hours (retro asks for all
    // retention); a proof over it cannot be minted, admission binds it.
    assert!(DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(now - Duration::hours(10), end)).is_err());
    let proof = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(cutoff, end)).unwrap();
    let expected = retained_hits(now, cutoff, 1);
    assert!(expected > 0 && expected < retained_hits(now, now - Duration::hours(11), 1), "the cutoff splits the fixture");

    // Summary: hits, attribution and bounds are retained-only.
    let row = run_retro_job(&engine, &results, &pin, "attempt-retro-summary", retro_task(&["10.0.0.1"], "indicator", "summary"), cutoff, end, Some(proof.clone()))
        .await
        .expect("retro summary job runs");
    assert_eq!(row["submode"], "summary", "{row}");
    let indicator = &row["indicator"];
    assert_eq!(indicator["hits"], json!(expected), "{row}");
    assert!(seen(&indicator["first_seen"]) >= cutoff, "{row}");
    assert!(seen(&indicator["last_seen"]) <= end, "{row}");
    assert_eq!(indicator["distinct_hosts"], json!(1), "{row}");
    let matched = indicator["matched_fields"].as_array().unwrap();
    assert!(matched.iter().any(|field| field[0] == "src_endpoint.ip" && field[1] == json!(expected)), "{row}");
    assert!(
        matched.iter().all(|field| field[0] != "dst_endpoint.ip"),
        "a field that never carries the indicator is not attributed: {row}"
    );
    assert_eq!(indicator["top_entities"][0]["id"], "10.0.0.1", "{row}");
    assert_eq!(indicator["top_entities"][0]["hits"], json!(expected), "{row}");

    // Campaign list: an indicator seen only before the cutoff reads as no-hit.
    let row = run_retro_job(&engine, &results, &pin, "attempt-retro-list",
        retro_task(&["10.0.0.1", "10.0.0.2", "203.0.113.9"], "indicator", "list"), cutoff, end, Some(proof.clone()))
        .await
        .expect("retro list job runs");
    assert_eq!(row["submode"], "list", "{row}");
    let rows = row["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{row}");
    for listed in rows {
        let ip: usize = listed["value"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap();
        assert_eq!(listed["hits"], json!(retained_hits(now, cutoff, ip)), "{row}");
        assert!(seen(&listed["first_seen"]) >= cutoff, "{row}");
    }
    assert_eq!(row["no_hits"], json!(["203.0.113.9"]), "{row}");

    // Pivot by asset: the sliced grouped reads are clamped too.
    let row = run_retro_job(&engine, &results, &pin, "attempt-retro-pivot",
        retro_task(&["10.0.0.1", "10.0.0.3"], "asset", "pivot"), cutoff, end, Some(proof.clone()))
        .await
        .expect("retro pivot job runs");
    assert_eq!(row["submode"], "pivot", "{row}");
    let pivots = row["pivot_rows"].as_array().unwrap();
    assert_eq!(pivots.len(), 2, "{row}");
    assert!(pivots.iter().all(|pivot| seen(&pivot["first_seen"]) >= cutoff), "{row}");

    // A retro spec wider than its proof is refused, not clamped.
    assert!(run_retro_job(&engine, &results, &pin, "attempt-retro-wide", retro_task(&["10.0.0.1"], "indicator", "summary"),
        now - Duration::hours(10), end, Some(proof.clone())).await.is_err());
    // A retro without the runner's proof is refused.
    assert!(run_retro_job(&engine, &results, &pin, "attempt-retro-bare", retro_task(&["10.0.0.1"], "indicator", "summary"),
        cutoff, end, None).await.is_err());
    // A forged proof (cutoff moved back so it would admit expired events)
    // is refused.
    let mut forged = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(cutoff, end)).unwrap();
    forged.cutoff_micros = (cutoff - Duration::hours(6)).timestamp_micros();
    forged.min_event_time_micros = forged.cutoff_micros;
    assert!(run_retro_job(&engine, &results, &pin, "attempt-retro-forged", retro_task(&["10.0.0.1"], "indicator", "summary"),
        cutoff - Duration::hours(6), end, Some(forged)).await.is_err());
    // Tenant isolation: another tenant's retro is refused before it reads.
    let mut foreign = spec(&pin, "attempt-retro-foreign", retro_task(&["10.0.0.1"], "indicator", "summary"),
        "ioc=\"10.0.0.1\" | retro", cutoff, end, Some(proof));
    foreign.tenant_id = "9d0c7b1e-2f3a-4b5c-8d6e-7f8091a2b3c4".into();
    assert!(run_job(&engine, &foreign, &results, &pin, &AtomicBool::new(false)).await.is_err());
}

#[cfg(feature = "enterprise")]
/// The rolling cutoff moves while a retro waits in the queue: the attempt
/// derives the CURRENT cutoff from the proof and reads less, never older.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_queued_retro_reads_less_as_the_cutoff_moves() {
    let _serial = serial();
    let root = tempfile::tempdir().unwrap();
    let real_now = Utc::now();
    // The fixture's ten hours straddle the 30-day rolling cutoff.
    let anchor = real_now - Duration::days(30) + Duration::hours(5);
    let engine = engine(root.path(), anchor).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = job_results().await;

    let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, 0).unwrap();
    // Admitted three hours ago: the proof's cutoff is three hours older than
    // the cutoff the attempt runs under.
    let queued_at = real_now - Duration::hours(3);
    let admitted_cutoff = tenant.event_time_cutoff(queued_at).unwrap();
    let end = anchor + Duration::minutes(1);
    let proof = DurableResultRetentionProof::from_shared_job(tenant, queued_at, &TimeRangeInput::new(admitted_cutoff, end)).unwrap();
    let current_cutoff = real_now - Duration::days(30);
    let at_admission = retained_hits(anchor, admitted_cutoff, 1);
    let now_retained = retained_hits(anchor, current_cutoff + Duration::minutes(1), 1);
    assert!(now_retained > 0 && now_retained < at_admission, "the cutoff moved across fixture events");

    let row = run_retro_job(&engine, &results, &pin, "attempt-retro-moving", retro_task(&["10.0.0.1"], "indicator", "summary"),
        admitted_cutoff, end, Some(proof))
        .await
        .expect("queued retro runs");
    let indicator = &row["indicator"];
    let hits = indicator["hits"].as_u64().unwrap();
    // The attempt's own clock sits a little after `current_cutoff`, so allow
    // the events that expired between that instant and the assertion.
    assert!(hits <= retained_hits(anchor, current_cutoff, 1) && hits >= now_retained, "{row}");
    assert!(hits < at_admission, "a queued retro read expired events: {row}");
    assert!(seen(&indicator["first_seen"]) >= current_cutoff, "{row}");
}

// ---------------------------------------------------------------------------
// NAN-3088: Prevalence export (and the rare list read from it) as a durable
// cell job.
// ---------------------------------------------------------------------------

fn prevalence_task(window: &str, artifact_type: Option<&str>, max_prevalence: u64) -> DurableLakeTask {
    DurableLakeTask::PrevalenceExportV1 {
        window: window.into(),
        artifact_type: artifact_type.map(str::to_string),
        max_prevalence,
        format: "json".into(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_prevalence_job(
    engine: &PartQueryEngine,
    results: &JobResultStore,
    pin: &PartJobPin,
    attempt: &str,
    task: DurableLakeTask,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    proof: Option<DurableResultRetentionProof>,
    deny: &[&str],
) -> anyhow::Result<(Vec<Value>, bool)> {
    let mut spec = spec(pin, attempt, task, "prevalence rare window=24h type=all max_prevalence=3 format=json", start, end, proof);
    spec.scope_deny = deny.iter().map(|source| source.to_string()).collect();
    let reference = run_job(engine, &spec, results, pin, &AtomicBool::new(false)).await?;
    if reference.parts == 0 {
        return Ok((Vec::new(), reference.has_more));
    }
    let page = result_page(results, &reference, "nan3078-job", TENANT, 0).await?;
    Ok((page["rows"].as_array().cloned().unwrap_or_default(), reference.has_more))
}

#[cfg(feature = "enterprise")]
/// An export whose admitted range crosses the tenant's retention cutoff is
/// exact at the cutoff: every artifact's occurrences and first sighting count
/// only retained events, through the same partials + edge rows `| prevalence`
/// reads. Filters, the source deny set and the row cap hold; a wider, bare,
/// forged or foreign job is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn a_prevalence_export_whose_range_crosses_the_cutoff_is_exact_at_the_cutoff() {
    let _serial = serial();
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine(root.path(), now).await;
    // query[T] always runs with product state attached (NAN-3148: in-process
    // publisher by default, a consumer beside product[T]). Its request path
    // never builds product state, so a durable export must read the committed
    // partials directly instead of answering `product_state_warming` before
    // the first publish cycle. A bare engine (no product state) models the
    // pre-NAN-3148 in-process build queue that no worker drains here.
    engine.set_product_state(super::super::product_publish::Published::in_process(engine.identity_state_dir().to_path_buf())).unwrap();
    assert!(!engine.identity_state_dir().join(super::super::product_publish::MANIFEST).exists(), "no cycle has published yet");
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = job_results().await;

    // An erasure left the last four hours as the only retained events.
    let cutoff = now - Duration::hours(4);
    let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, cutoff.timestamp_micros()).unwrap();
    let end = now + Duration::minutes(1);
    let proof = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(cutoff, end)).unwrap();
    assert!(retained_hits(now, cutoff, 1) < retained_hits(now, now - Duration::hours(11), 1), "the cutoff splits the fixture");

    // Each of the five source IPs is seen from one (unknown) host: all rare.
    let (rows, truncated) = run_prevalence_job(&engine, &results, &pin, "attempt-prev", prevalence_task("24h", None, 3),
        cutoff, end, Some(proof.clone()), &[])
        .await
        .expect("prevalence export job runs");
    assert!(!truncated);
    assert_eq!(rows.len(), 5, "{rows:?}");
    for row in &rows {
        let ip: usize = row["artifact"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap();
        assert_eq!(row["artifact_type"], "ip_address_private", "{row}");
        assert_eq!(row["host_count"], json!(1), "{row}");
        assert_eq!(row["is_rare"], json!(true), "{row}");
        // NAN-3161: whole parts answer the export with the cutoff as a hard
        // floor, so the part straddling it is left out: exactly the events
        // from the next event hour on count, never one before the cutoff.
        let floor_hour = DateTime::from_timestamp_micros(cutoff.timestamp_micros().div_euclid(3_600_000_000) * 3_600_000_000 + 3_600_000_000).unwrap();
        assert_eq!(row["total_occurrences"], json!(retained_hits(now, floor_hour, ip)), "only retained events count: {row}");
        assert!(seen(&row["first_seen"]) >= cutoff, "{row}");
        assert!(seen(&row["last_seen"]) <= end, "{row}");
        // RFC3339, one spelling for every reader.
        assert!(chrono::DateTime::parse_from_rfc3339(row["first_seen"].as_str().unwrap()).is_ok(), "{row}");
    }

    // The row cap flags truncation instead of dropping silently.
    let mut capped = spec(&pin, "attempt-prev-cap", prevalence_task("24h", None, 3), "prevalence export", cutoff, end, Some(proof.clone()));
    capped.request.limit = 2;
    let reference = run_job(&engine, &capped, &results, &pin, &AtomicBool::new(false)).await.expect("capped export runs");
    assert_eq!((reference.rows, reference.has_more), (2, true));

    // max_prevalence, the artifact type and the caller's source deny set all
    // filter inside the cell.
    for (attempt, task, deny) in [
        ("attempt-prev-max", prevalence_task("24h", None, 0), &[][..]),
        ("attempt-prev-type", prevalence_task("24h", Some("hash"), 3), &[][..]),
        ("attempt-prev-deny", prevalence_task("24h", None, 3), &["aws_cloudtrail"][..]),
    ] {
        let (rows, _) = run_prevalence_job(&engine, &results, &pin, attempt, task, cutoff, end, Some(proof.clone()), deny)
            .await
            .expect("filtered export runs");
        assert!(rows.is_empty(), "{attempt}: {rows:?}");
    }

    // An admitted range wider than the task's declared window is refused.
    assert!(run_prevalence_job(&engine, &results, &pin, "attempt-prev-window", prevalence_task("1h", None, 3),
        cutoff, end, Some(proof.clone()), &[]).await.is_err());
    // A spec wider than its proof is refused, not clamped.
    assert!(run_prevalence_job(&engine, &results, &pin, "attempt-prev-wide", prevalence_task("24h", None, 3),
        now - Duration::hours(10), end, Some(proof.clone()), &[]).await.is_err());
    // Without the runner's proof nothing bounds the read: refused.
    assert!(run_prevalence_job(&engine, &results, &pin, "attempt-prev-bare", prevalence_task("24h", None, 3),
        cutoff, end, None, &[]).await.is_err());
    // A forged proof (cutoff moved back to admit expired events) is refused.
    let mut forged = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(cutoff, end)).unwrap();
    forged.cutoff_micros = (cutoff - Duration::hours(6)).timestamp_micros();
    forged.min_event_time_micros = forged.cutoff_micros;
    assert!(run_prevalence_job(&engine, &results, &pin, "attempt-prev-forged", prevalence_task("24h", None, 3),
        cutoff - Duration::hours(6), end, Some(forged), &[]).await.is_err());
    // Tenant isolation: another tenant's export is refused before it reads.
    let mut foreign = spec(&pin, "attempt-prev-foreign", prevalence_task("24h", None, 3), "prevalence export", cutoff, end, Some(proof));
    foreign.tenant_id = "9d0c7b1e-2f3a-4b5c-8d6e-7f8091a2b3c4".into();
    assert!(run_job(&engine, &foreign, &results, &pin, &AtomicBool::new(false)).await.is_err());
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn prevalence_signed_summary_reuse_matches_raw_rows_and_uncached_edges() {
    let _serial = serial();
    use super::super::partials::{prevalence_lookup_bounds, prevalence_lookup_uncached};
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let engine = engine(root.path(), now).await;
    let artifacts = (0..5)
        .map(|i| format!("10.0.0.{i}"))
        .chain(["10.99.99.99".into(), "10.0.0.0".into()])
        .collect::<Vec<_>>();
    let mut before = std::time::Duration::ZERO;
    let mut after = [std::time::Duration::ZERO; 2];
    for seed in 0..120_u64 {
        let from = now - Duration::minutes(60 + (seed * 43 % 540) as i64);
        let to = now - Duration::minutes((seed * 17 % 50) as i64);
        let deny = if seed % 3 == 0 {
            vec!["aws_cloudtrail".into()]
        } else {
            vec!["hidden".into()]
        };
        let threshold = 1 + seed % 7;
        let started = std::time::Instant::now();
        let expected = prevalence_lookup_uncached(
            &engine,
            &artifacts,
            from.timestamp_micros(),
            to.timestamp_micros(),
            &deny,
            threshold,
        )
        .await
        .unwrap();
        before += started.elapsed();
        let expected = serde_json::to_value(expected).unwrap();
        // Cold and warm results must equal the independent exact path.
        for pass in 0..2 {
            let started = std::time::Instant::now();
            let (actual, hits, misses) =
                crate::query_timing::measure("prevalence-reuse-fixture", async {
                    let actual = prevalence_lookup_bounds(
                        &engine,
                        &artifacts,
                        from.timestamp_micros(),
                        to.timestamp_micros(),
                        &deny,
                        threshold,
                    )
                    .await?;
                    let phases = crate::query_timing::current().unwrap();
                    let phases = phases.lock().unwrap();
                    Ok::<_, super::super::engine::PartQueryError>((
                        actual,
                        phases.prevalence_memo_hits,
                        phases.prevalence_memo_misses,
                    ))
                })
                .await
                .unwrap();
            after[pass] += started.elapsed();
            if pass == 1 {
                let inside = engine
                    .snapshot(from.timestamp_micros(), to.timestamp_micros())
                    .await
                    .unwrap()
                    .0
                    .len();
                // NAN-3161: every overlapping part, edges included, is a
                // whole-part summary; nothing is re-scanned from rows.
                assert_eq!(
                    hits, inside,
                    "every selected whole part reuses its verified summary"
                );
                assert_eq!(engine.fetcher().prevalence_raw_scans(), 0);
                assert_eq!(misses, 0, "a repeat must not rerun whole-part SQL");
            }
            assert_eq!(
                serde_json::to_value(&actual).unwrap(),
                expected,
                "seed={seed}"
            );
            let overlapping = engine.snapshot(from.timestamp_micros(), to.timestamp_micros()).await.unwrap().0;
            for artifact in &actual {
                let address = artifact
                    .artifact
                    .rsplit('.')
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                let times = (0..ROWS)
                    .filter(|i| i % 5 == address)
                    .map(|i| event_at(now, i))
                    // NAN-3161: every overlapping part counts whole.
                    .filter(|at| overlapping.iter().any(|part| (part.min_time_us..=part.max_time_us).contains(&at.timestamp_micros())))
                    .collect::<Vec<_>>();
                assert_ne!(seed % 3, 0, "a denied source must not contribute");
                assert_eq!(artifact.total_occurrences as usize, times.len());
                assert_eq!(
                    artifact.first_seen,
                    crate::prevalence::format_micros(
                        times.iter().min().unwrap().timestamp_micros()
                    )
                );
                assert_eq!(
                    artifact.last_seen,
                    crate::prevalence::format_micros(
                        times.iter().max().unwrap().timestamp_micros()
                    )
                );
            }
            if seed % 3 == 0 {
                assert!(actual.is_empty());
            }
        }
    }
    eprintln!(
        "signed prevalence 120 scoped ragged windows: uncached={before:?}; first={:?}; repeated={:?}",
        after[0], after[1]
    );
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn correlated_cloud_facets_match_seven_scans_and_independent_rows() {
    let _serial = serial();
    use super::super::engine::BroadNplRequest;
    use nanosiem_core::search::SearchService;
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let engine = engine_with_spacing(root.path(), now, 17).await;
    let mut before = std::time::Duration::ZERO;
    let mut after = std::time::Duration::ZERO;
    let mut compared_after = std::time::Duration::ZERO;
    for seed in 0..120_u64 {
        let from = now - Duration::minutes(60 + (seed * 43 % 10_000) as i64);
        let to = now - Duration::minutes((seed * 17 % 50) as i64);
        let deny = seed % 7 == 0;
        let address = seed % 5;
        let base = format!("class_uid=6003 AND src_endpoint.ip=\"10.0.0.{address}\"");
        let request = |query: String| BroadNplRequest {
            request_id: format!("cloud-correlated-{seed}"),
            tenant_id: TENANT.into(),
            dataset: "logs".into(),
            query,
            start: from.to_rfc3339(),
            end: to.to_rfc3339(),
            limit: 50_000,
            offset: 0,
            table_view: false,
            use_cache: false,
            cursor_time: None,
            cursor_event_uid: None,
            anchor_us: None,
            decay: None,
            clear_boundaries: Default::default(),
            watch_weights: Default::default(),
            minimum_clear_revision: None,
            deny_source_types: if deny {
                ["aws_cloudtrail".into()].into()
            } else {
                Default::default()
            },
        };
        let expected: Vec<_> = (0..ROWS)
            .filter(|i| {
                let at = now - Duration::minutes((*i as i64 + 1) * 17) - Duration::seconds(30);
                !deny && *i % 5 == address as usize && at >= from && at <= to
            })
            .map(|i| {
                let mut row = event(i, &now.to_rfc3339());
                row["event_count"] = json!(1);
                row["resources.type"] = json!(
                    row["resources"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| r["type"].clone())
                        .collect::<Vec<_>>()
                );
                row
            })
            .collect();
        let expected = SearchService::assemble_lake_cloud_correlated_summary(&expected);
        let started = std::time::Instant::now();
        let actual = engine
            .broad_npl(&request(
                SearchService::lake_cloud_correlated_summary_query(&base),
            ))
            .await
            .unwrap();
        let elapsed = started.elapsed();
        after += elapsed;
        if seed < 12 {
            compared_after += elapsed;
        }
        let actual = SearchService::assemble_lake_cloud_correlated_summary(
            actual["result"]["rows"].as_array().unwrap(),
        );
        assert_eq!(actual.0, expected.0, "seed={seed}");
        assert_eq!(
            serde_json::to_value(&actual.1).unwrap(),
            serde_json::to_value(&expected.1).unwrap(),
            "seed={seed}"
        );
        if seed < 12 {
            let started = std::time::Instant::now();
            let queries = SearchService::lake_cloud_events_summary_queries(&base);
            let total = engine.broad_npl(&request(queries.total)).await.unwrap();
            let mut legs = Vec::new();
            for query in [
                queries.providers,
                queries.services,
                queries.regions,
                queries.accounts,
                queries.resource_types,
                queries.change_types,
            ] {
                let output = engine.broad_npl(&request(query)).await.unwrap();
                legs.push(output["result"]["rows"].as_array().unwrap().clone());
            }
            before += started.elapsed();
            let old = SearchService::assemble_lake_cloud_events_summary(
                total["result"]["rows"].as_array().unwrap(),
                &legs[0],
                &legs[1],
                &legs[2],
                &legs[3],
                &legs[4],
                &legs[5],
                &[],
                &[],
                false,
            );
            assert_eq!(old.0, actual.0);
            // The old SQL leaves ties unspecified; compare each facet as a map.
            let normalize = |facets| {
                let mut value = serde_json::to_value(facets).unwrap();
                for values in value.as_object_mut().unwrap().values_mut() {
                    values
                        .as_array_mut()
                        .unwrap()
                        .sort_by_key(|v| v[0].as_str().unwrap().to_owned());
                }
                value
            };
            assert_eq!(normalize(old.1), normalize(actual.1));
        }
    }
    eprintln!(
        "cloud correlated facets: seven scans (12 windows)={before:?}; one scan (same 12)={compared_after:?}; one scan (120 windows)={after:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn persisted_cloud_facets_match_raw_groups_over_ragged_scoped_windows() {
    let _serial = serial();
    use super::super::engine::BroadNplRequest;
    use nanosiem_core::search::SearchService;
    // The fixture writes Cloud facet summaries and reads them (both default off).
    let _flags = EnvFlags::set(&[("NANO_LAKE_CLOUD_FACET_SUMMARIES", "1"), ("NANO_LAKE_CLOUD_FACET_READS", "1")]);
    assert!(crate::cloud_facet_summaries::enabled() && crate::cloud_facet_summaries::reads_enabled(), "enable both Cloud facet fixture flags");
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let engine = engine_with_facet_variants(root.path(), now, 17, true).await;
    let mut before = std::time::Duration::ZERO;
    let mut after = std::time::Duration::ZERO;
    let mut hits = 0;
    for seed in 0..120_u64 {
        let from = now - Duration::minutes(60 + (seed * 43 % 10_000) as i64);
        let to = now - Duration::minutes((seed * 17 % 50) as i64);
        let request = |base: &str| BroadNplRequest {
            request_id: format!("persisted-cloud-{seed}"), tenant_id: TENANT.into(), dataset: "logs".into(),
            query: SearchService::lake_cloud_correlated_summary_query(base),
            start: from.to_rfc3339(), end: to.to_rfc3339(), limit: 50_000,
            offset: 0, table_view: false, use_cache: false, cursor_time: None, cursor_event_uid: None,
            anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
            deny_source_types: if seed % 7 == 0 { ["aws_cloudtrail".into()].into() } else { Default::default() },
        };
        // An equivalent extra predicate intentionally forces the ordinary,
        // compiled raw scan. Compare complete correlated groups, not just totals.
        let started = std::time::Instant::now();
        let raw = engine.broad_npl(&request("class_uid=6003 AND class_uid=6003")).await.unwrap();
        before += started.elapsed();
        let started = std::time::Instant::now();
        let summary = engine.broad_npl(&request("class_uid=6003")).await.unwrap();
        after += started.elapsed();
        if summary["planner"]["cloud_facet_summary_parts"].as_u64().unwrap_or(0) > 0 { hits += 1; }
        let normalize = |response: &Value| {
            let mut rows = response["result"]["rows"].as_array().unwrap().clone();
            for row in &mut rows {
                let count = row["event_count"].as_u64().or_else(|| row["event_count"].as_str()?.parse().ok()).unwrap();
                row["event_count"] = json!(count);
            }
            rows.sort_by_key(Value::to_string);
            rows
        };
        assert_eq!(normalize(&summary), normalize(&raw), "seed={seed}, planner={}", summary["planner"]);
        assert!(!summary["result"]["page_has_more"].as_bool().unwrap());
    }
    assert!(hits > 0, "fixture must exercise persisted summaries");
    eprintln!("persisted Cloud 120 windows: raw={before:?}, persisted/hybrid={after:?}, hits={hits}");
}

#[cfg(feature = "enterprise")]
/// Wide dossiers use the same scoped rows and assembler as an independent raw
/// read; the moving receipt excludes expired rows and never keeps only 24h.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn seven_day_asset_dossier_matches_raw_rows_and_retention_scope() {
    let _serial = serial();
    use super::super::engine::BroadNplRequest;
    use nanosiem_core::search::SearchService;
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine_with_facet_variants(root.path(), now, 16, true).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = job_results().await;
    // Check lane selection directly: readonly=2 allows temporary tables, so
    // DDL success cannot distinguish an interactive lane from the job lane.
    let statement = "SELECT toUInt8(getSetting('readonly')) AS mode";
    let mode = |output: crate::native::NativeQueryOutput| {
        super::super::engine::decode_rows(&output.data).unwrap()[0]["mode"].as_u64().unwrap()
    };
    assert_eq!(mode(engine.run_sql(statement.into(), vec![]).await.unwrap()), 2);
    assert_eq!(mode(engine.with_job_statements(engine.run_sql(statement.into(), vec![])).await.unwrap()), 0);
    assert_eq!(mode(engine.run_sql(statement.into(), vec![]).await.unwrap()), 2);
    let query = "(device.hostname=\"fixture-host\" OR src_endpoint.ip=\"10.0.0.1\") | table time,class_uid,status,metadata.log_source,device.hostname,src_endpoint.ip,src_endpoint.hostname,actor.user.name,file.hashes.value | sort -time";
    let task = || DurableLakeTask::AssetDossierV1 {
        identifier_field: "device.hostname".into(), identifier_value: "fixture-host".into(),
        identities: vec![json!({"hostname":"fixture-host","ip":"10.0.0.1"})], event_query: query.into(),
    };
    for seed in 0..120_u64 {
        let start = now - Duration::days(7);
        let cutoff = now - Duration::minutes(60 + (seed * 83 % 10_000) as i64);
        let end = now - Duration::minutes((seed * 17 % 50) as i64);
        let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, cutoff.timestamp_micros()).unwrap();
        assert!(DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(start, end)).is_err());
        let proof = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(cutoff, end)).unwrap();
        let deny = if seed % 7 == 0 { "aws_cloudtrail" } else { "hidden-source" };
        let mut job = spec(&pin, &format!("dossier-{seed}"), task(), "| asset", cutoff, end, Some(proof));
        job.scope_deny.insert(deny.into());
        let read = |request_id: String, query: String, limit: usize| {
            let engine = &engine;
            async move {
                engine.broad_npl(&BroadNplRequest {
                    request_id, tenant_id: TENANT.into(), dataset: "logs".into(),
                    query, start: cutoff.to_rfc3339(), end: end.to_rfc3339(), limit,
                    offset: 0, table_view: false, use_cache: false, cursor_time: None, cursor_event_uid: None,
                    anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
                    deny_source_types: [deny.into()].into(),
                }).await.unwrap()
            }
        };
        let raw = read(format!("raw-dossier-{seed}"), query.into(), 10_000).await;
        let rows = raw["result"]["rows"].as_array().unwrap().clone();
        if seed == 119 {
            assert!(rows.iter().any(|row| event_time(row) < now - Duration::days(1)), "older days must contribute");
        }
        // NAN-3276: the durable dossier folds the bounded card aggregates
        // (the interactive dossier's reads), never the event rows.
        let window = nanosiem_core::query::TimeRange::new(cutoff, end);
        let identities = [json!({"hostname":"fixture-host","ip":"10.0.0.1"})];
        let mut cards = nanosiem_core::search::LakeAssetCards::new();
        for card in SearchService::lake_asset_dossier_card_reads("device.hostname", "fixture-host", &identities, &window).unwrap() {
            let (mut card_rows, mut exact) = (Vec::new(), true);
            for (index, card_query) in card.queries.iter().enumerate() {
                let answer = read(format!("card-{seed}-{}-{index}", card.view), card_query.clone(), card.limit).await;
                let slice = answer["result"]["rows"].as_array().unwrap().clone();
                exact &= !answer["result"]["page_has_more"].as_bool().unwrap_or(false) && slice.len() < card.limit;
                card_rows.extend(slice);
            }
            cards.insert(&card, card_rows, exact);
        }
        let artifacts = cards.artifacts();
        let baseline_start = (end - Duration::hours(24)).max(cutoff);
        let mut prevalence = BTreeMap::new();
        if !artifacts.is_empty() {
            for row in super::super::partials::prevalence_lookup_floored(
                &engine, &artifacts, baseline_start.timestamp_micros(), end.timestamp_micros(),
                Some(cutoff.timestamp_micros()), &[deny.into()], super::super::partials::DEFAULT_RARITY_THRESHOLD,
            ).await.unwrap() {
                prevalence.insert(row.artifact, (row.host_count, row.is_rare, row.prevalence_score));
            }
        }
        let expected = cards.dossier(&window, &prevalence);
        let reference = run_job(&engine, &job, &results, &pin, &AtomicBool::new(false)).await.unwrap();
        let page = result_page(&results, &reference, "nan3078-job", TENANT, 0).await.unwrap();
        assert_eq!(page["rows"][0]["response"], serde_json::to_value(expected).unwrap(), "seed={seed}");
    }
    // The same valid task must fail under a tiny collection budget, rather
    // than returning an apparently complete slice of its event set.
    let bounded = spec(&pin, "dossier-byte-budget", task(), "| asset", now - Duration::days(7), now, None);
    let cancelled = AtomicBool::new(false);
    let reader = super::ViewReader {
        engine: &engine, writer: engine.writer().unwrap(), spec: &bounded, pin: &pin,
        window: (now - Duration::days(7), now), cancelled: &cancelled,
        collect_bytes: 1, lane: tokio::sync::Mutex::new(Default::default()),
    };
    let error = super::execute_view(&reader, &bounded).await.unwrap_err();
    assert!(error.to_string().contains("durable view envelope"), "{error:#}");
    let mut missing_proof = spec(&pin, "dossier-no-proof", task(), "| asset", now - Duration::days(7), now, None);
    assert!(run_job(&engine, &missing_proof, &results, &pin, &AtomicBool::new(false)).await.is_err());
    missing_proof.tenant_id = "9d0c7b1e-2f3a-4b5c-8d6e-7f8091a2b3c4".into();
    assert!(run_job(&engine, &missing_proof, &results, &pin, &AtomicBool::new(false)).await.is_err());
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn persisted_asset_facets_match_raw_groups_over_ragged_scoped_windows() {
    let _serial = serial();
    use super::super::engine::BroadNplRequest;
    // The fixture writes Asset facet summaries and reads them (both default off).
    let _flags = EnvFlags::set(&[("NANO_LAKE_ASSET_FACET_SUMMARIES", "1"), ("NANO_LAKE_ASSET_FACET_READS", "1")]);
    assert!(crate::asset_facet_summaries::enabled() && crate::asset_facet_summaries::reads_enabled());
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    let engine = engine_with_variants(root.path(), now, 17, true, true).await;
    let mut before = std::time::Duration::ZERO;
    let mut after = std::time::Duration::ZERO;
    let mut hits = 0;
    for seed in 0..120_u64 {
        let from = now - Duration::minutes(60 + (seed * 43 % 10_000) as i64);
        let to = now - Duration::minutes((seed * 17 % 50) as i64);
        // Overlapping legs must count each event only once. Uppercase user
        // literals exercise case-insensitive membership; absent hosts/IPs and
        // mixed source denials exercise empty and scoped groups.
        let predicate = format!("(device.hostname IN (\"fixture-host\") OR src_endpoint.ip IN (\"10.0.0.{}\") OR actor.user.name IN (\"{}\"))", seed % 7, if seed % 17 == 0 { "" } else if seed % 5 == 0 { "ALICE" } else { "absent" });
        let request = |base: &str| BroadNplRequest {
            request_id: format!("persisted-asset-{seed}"), tenant_id: TENANT.into(), dataset: "logs".into(),
            query: format!("{base}{}", crate::asset_facet_summaries::SUFFIX),
            start: from.to_rfc3339(), end: to.to_rfc3339(), limit: 10_000,
            offset: 0, table_view: false, use_cache: false, cursor_time: None, cursor_event_uid: None,
            anchor_us: None, decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(), minimum_clear_revision: None,
            deny_source_types: if seed % 7 == 0 { ["aws_cloudtrail".into()].into() } else { Default::default() },
        };
        let started = std::time::Instant::now();
        let raw = engine.broad_npl(&request(&format!("{predicate} AND class_uid>=0"))).await.unwrap();
        before += started.elapsed();
        let started = std::time::Instant::now();
        let summary = engine.broad_npl(&request(&predicate)).await.unwrap();
        after += started.elapsed();
        if summary["planner"]["facet_summary_path"] == crate::asset_facet_summaries::PATH { hits += 1; }
        if seed % 17 == 0 { assert!(summary["planner"].get("facet_summary_path").is_none(), "empty literals must retain the compiler's NULL/default semantics"); }
        let normalize = |response: &Value| {
            let mut rows = response["result"]["rows"].as_array().unwrap().clone();
            for row in &mut rows {
                for field in ["event_count", "class_uid", "asset_auth_failure"] {
                    let count = row[field].as_u64().or_else(|| row[field].as_str()?.parse().ok()).unwrap();
                    row[field] = json!(count);
                }
            }
            rows.sort_by_key(Value::to_string); rows
        };
        assert_eq!(normalize(&summary), normalize(&raw), "seed={seed}, planner={}", summary["planner"]);
        assert!(!summary["result"]["page_has_more"].as_bool().unwrap());
    }
    assert!(hits > 0, "fixture must exercise persisted summaries");
    eprintln!("persisted Asset 120 windows: raw={before:?}, persisted/hybrid={after:?}, hits={hits}");
}

#[cfg(feature = "enterprise")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: chDB artifact and lake compiler"]
async fn durable_lateral_matches_scoped_retained_auth_events() {
    let _serial = serial();
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    let engine = engine_with_variants(root.path(), now, 16, true, true).await;
    let (head, schema) = engine.head_and_schema_fingerprint().await;
    let pin = PartJobPin::at_head(head, schema.as_deref(), &"b".repeat(64), &"c".repeat(64)).unwrap();
    let results = job_results().await;
    let query = "dst_endpoint.hostname=\"fixture-host\" | lateral methods=auth maxhops=2";
    let contribution = now - Duration::days(7);
    let tenant = SearchTenantScope::enterprise_shared_retained(TENANT.parse().unwrap(), 1, 30, contribution.timestamp_micros()).unwrap();
    let proof = DurableResultRetentionProof::from_shared_job(tenant, now, &TimeRangeInput::new(contribution, now)).unwrap();
    let before_backfill = spec(&pin, "lateral-incomplete-identity", DurableLakeTask::LateralV1 {
        query: query.into(), start_micros: contribution.timestamp_micros(), end_micros: now.timestamp_micros(),
    }, query, contribution, now, Some(proof.clone()));
    let error = run_job(&engine, &before_backfill, &results, &pin, &AtomicBool::new(false)).await.unwrap_err();
    assert!(error.to_string().contains("identity coverage is incomplete"), "{error:#}");
    let backfill = super::super::identity::backfill_once(&engine, &root.path().join("state"), now.timestamp_micros(), 512, None).await.unwrap();
    assert_eq!(backfill.remaining, 0);
    for seed in 0..120_u64 {
        let start = now - Duration::minutes(60 + (seed * 83 % 9_900) as i64);
        let end = now - Duration::minutes((seed * 13 % 50) as i64);
        let task = DurableLakeTask::LateralV1 { query: query.into(), start_micros: start.timestamp_micros(), end_micros: end.timestamp_micros() };
        let mut job = spec(&pin, &format!("lateral-{seed}"), task, query, contribution, now, Some(proof.clone()));
        let denied = if seed % 7 == 0 { "azure_audit" } else { "aws_cloudtrail" };
        job.scope_deny = [denied.into()].into();
        let expected = (0..ROWS).filter(|i| {
            let at = now - Duration::minutes((*i as i64 + 1) * 16) - Duration::seconds(30);
            i % 6 == 0 && i % 11 != 0 && at >= start && at <= end && denied != "azure_audit"
        }).count();
        let reference = run_job(&engine, &job, &results, &pin, &AtomicBool::new(false)).await.unwrap();
        let page = result_page(&results, &reference, "nan3078-job", TENANT, 0).await.unwrap();
        let response = &page["rows"][0]["response"];
        assert_eq!(response["total_count"], expected, "seed={seed}");
        assert_eq!(response["total_count_exact"], true);
        let rows = response["results"].as_array().unwrap();
        assert_eq!(rows.len(), expected + 1);
        for row in &rows[1..] {
            let value = row["timestamp"].as_str().unwrap();
            let at = DateTime::parse_from_rfc3339(value).map(|time| time.with_timezone(&Utc)).unwrap_or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f").unwrap().and_utc()
            });
            assert!(at >= start && at <= end, "expired or future edge: {row}");
            assert_eq!(row["log_source"], "azure_audit");
        }
        assert_eq!(DateTime::parse_from_rfc3339(rows[0]["_lateral_time_range"]["start"].as_str().unwrap()).unwrap().timestamp_micros(), start.timestamp_micros());
    }
    let task = || DurableLakeTask::LateralV1 { query: query.into(), start_micros: contribution.timestamp_micros(), end_micros: now.timestamp_micros() };
    let missing = spec(&pin, "lateral-missing-proof", task(), query, contribution, now, None);
    assert!(run_job(&engine, &missing, &results, &pin, &AtomicBool::new(false)).await.is_err());
    let mut foreign = spec(&pin, "lateral-foreign", task(), query, contribution, now, Some(proof.clone()));
    foreign.tenant_id = "9d0c7b1e-2f3a-4b5c-8d6e-7f8091a2b3c4".into();
    assert!(run_job(&engine, &foreign, &results, &pin, &AtomicBool::new(false)).await.is_err());
    let bounded = spec(&pin, "lateral-bounded", task(), query, contribution, now, Some(proof));
    assert!(run_job(&engine, &bounded, &results, &pin, &AtomicBool::new(true)).await.is_err());
    let cancelled = AtomicBool::new(false);
    let reader = super::ViewReader { engine: &engine, writer: engine.writer().unwrap(), spec: &bounded, pin: &pin,
        window: (contribution, now), cancelled: &cancelled, collect_bytes: 1, lane: tokio::sync::Mutex::new(Default::default()) };
    assert!(super::execute_view(&reader, &bounded).await.is_err());
}

/// NAN-3399: after a merge pass, a lookup reads one merged file instead of
/// every part's identity source and answers exactly as before (the signed
/// parts' real cache layout: content-addressed objects and backfill files).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: chDB artifact"]
async fn merged_identity_index_answers_lookups_exactly_as_the_sources() {
    let _serial = serial();
    use super::super::identity::{lookup, normalize_items, LookupKind};
    use super::super::identity_merged::{merge_once, REBUILD_FILES};
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp_micros(Utc::now().timestamp_micros()).unwrap();
    // Host-bearing events (10.0.0.1 = host.fixture.test) over ~160 hours.
    let engine = engine_with_detail_fixture(root.path(), now, 16, false, false, false, true).await;
    let state = root.path().join("state");
    let backfill = super::super::identity::backfill_once(&engine, &state, now.timestamp_micros(), 512, None).await.unwrap();
    assert_eq!(backfill.remaining, 0);
    let raw = (0..6).flat_map(|i| [(format!("10.0.0.{}", i % 3), (now - Duration::hours(i * 20)).to_rfc3339())])
        .collect::<Vec<_>>();
    let items = normalize_items(LookupKind::Ip, &raw).unwrap();
    let (before, index) = lookup(&engine, &state, LookupKind::Ip, &items, &["azure_audit".into()]).await.unwrap();
    let files = index["timing"]["identity_files"].as_u64().unwrap();
    assert!(files as usize >= REBUILD_FILES, "the fixture must have enough sources to merge ({files})");
    assert_eq!(index["timing"]["identity_tail_files"], files, "no merged index yet: every source is read");
    assert!(before.len() >= 2, "the fixture must exercise hits: {before:?}");
    // A running durable job owns the read-write lane: no build starts.
    let job = engine.admit_job(std::time::Duration::from_secs(1)).await.unwrap();
    let held = merge_once(&engine, &state, now.timestamp_micros()).await.unwrap();
    assert!(!held.built, "never builds beside a durable job: {held:?}");
    drop(job);
    let report = merge_once(&engine, &state, now.timestamp_micros()).await.unwrap();
    assert!(report.built, "{report:?}");
    assert_eq!(report.sources as u64, files);
    let (after, index) = lookup(&engine, &state, LookupKind::Ip, &items, &["azure_audit".into()]).await.unwrap();
    assert_eq!(after, before);
    assert_eq!(index["timing"]["identity_tail_files"], 0, "{index}");
    assert_eq!(index["timing"]["identity_merged_sources"], files, "{index}");
    let unchanged = merge_once(&engine, &state, now.timestamp_micros()).await.unwrap();
    assert!(!unchanged.built, "nothing new: no rebuild");
    let merged_files = std::fs::read_dir(state.join(super::super::identity_merged::DIR)).unwrap().flatten().count();
    assert_eq!(merged_files, 1, "one merged file on disk");
}

/// Exercise the default progressive locator through signed parts,
/// including a cursor page; compare against one unpruned native statement.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: chDB artifact, lake compiler"]
async fn progressive_locator_pages_equal_unpruned_native_statement() {
    let _serial = serial();
    use super::super::engine::BroadNplRequest;
    use crate::planner;
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::parse_from_rfc3339("2026-09-29T12:00:00Z").unwrap().with_timezone(&Utc);
    let engine = engine_with_locator_ties(root.path(), now, 1, false, false, std::env::var("NANO_LAB_LOCATOR_TIES").as_deref() == Ok("1")).await;
    let mut request: BroadNplRequest = serde_json::from_value(json!({
        "request_id": "progressive-native", "tenant_id": TENANT, "dataset": "logs",
        "query": "actor.user.name=\"alice\" api.operation=\"ListRoles\"",
        "start": (now - Duration::hours(12)).to_rfc3339(), "end": now.to_rfc3339(),
        "limit": 100, "offset": 0, "table_view": true,
    })).unwrap();
    for cursor_page in [false, true] {
        let selection = engine.select((now - Duration::hours(12)).timestamp_micros(), now.timestamp_micros(), &[]).await.unwrap();
        let compiled = engine.compile(&request, selection.field_types.clone()).await.unwrap();
        let cursor = request.cursor_time.as_deref().zip(request.cursor_event_uid.as_deref());
        let plan = match cursor {
            Some((time, event_uid)) => planner::plan_broad_log_query_with_candidates_tail_time_and_cursor(
                &selection.tenant, &selection.manifest, &compiled, None, None, None,
                planner::SourceCursorFence { time, event_uid }),
            None => planner::plan_broad_log_query(&selection.tenant, &selection.manifest, &compiled),
        }.unwrap();
        let output = engine.run(plan).await.unwrap();
        let reference: Vec<Value> = output.data.split(|b| *b == b'\n').filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap()).collect();
        let actual = engine.progressive(&compiled, cursor, None, 0).await.unwrap();
        assert_eq!(actual.rows, reference, "cursor={cursor_page}");
        assert_eq!(actual.planner["locator_fallbacks"], 0);
        let last = &actual.rows[99];
        request.cursor_time = Some(event_time(last).to_rfc3339());
        request.cursor_event_uid = Some(last["metadata.uid"].as_str().expect("uid").to_string());
    }
}

#[tokio::test]
#[ignore = "requires verified chDB and local compiler"]
async fn lean_prevalence_explorer_and_detail_return_real_scoped_context() {
    let _serial = serial();
    use super::super::partials::{prevalence_detail, prevalence_explorer, PrevalenceDetailRequest, PrevalenceExplorerRequest};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine_with_detail_fixture(root.path(), now, 1, true, false, false, true).await;
    for artifact in ["a".repeat(64), "b".repeat(32), "example.test".into(), "203.0.113.7".into(), "alice".into(), "host.fixture.test".into()] {
        let request = PrevalenceDetailRequest {request_id: "fixture-detail".into(), tenant_id: TENANT.into(), window: "24h".into(), artifact, deny_source_types: vec![]};
        let start = std::time::Instant::now();
        assert!(prevalence_detail(&engine, &request).await.unwrap_err().to_string().contains(super::super::product_state::WARMING));
        assert!(start.elapsed() < std::time::Duration::from_millis(300));
        let work = super::super::product_state::take(engine.identity_state_dir()).unwrap();
        super::super::product_state::prepare(&engine, engine.identity_state_dir(), work).await.unwrap();
        let response = prevalence_detail(&engine, &request).await.unwrap();
        assert_eq!(response["tenant_id"], TENANT);
        let detail = &response["result"];
        if request.artifact == "host.fixture.test" {
            assert_eq!(detail["top_hosts"], json!([]), "observer-only domain is not an artifact match");
            continue;
        }
        assert_eq!(detail["top_hosts"][0]["host"], "host.fixture.test");
        assert_eq!(detail["top_users"][0]["user"], "alice");
        assert_eq!(detail["top_hosts"][0]["count"].as_u64().unwrap(), ROWS as u64);
        if request.artifact.len() == 32 || request.artifact.len() == 64 {
            assert_eq!(detail["processes"][0]["process_name"], "fixture.exe");
            assert_eq!(detail["processes"][0]["command_line"], "fixture.exe --test");
            assert_eq!(detail["top_file_names"][0]["file_name"], "fixture.exe");
        }
        let denied = PrevalenceDetailRequest {deny_source_types: vec!["aws_cloudtrail".into(), "azure_audit".into()], ..request};
        assert!(prevalence_detail(&engine, &denied).await.unwrap_err().to_string().contains(super::super::product_state::WARMING));
        let work = super::super::product_state::take(engine.identity_state_dir()).unwrap();
        super::super::product_state::prepare(&engine, engine.identity_state_dir(), work).await.unwrap();
        let response = prevalence_detail(&engine, &denied).await.unwrap();
        assert_eq!(response["result"]["top_hosts"], json!([]));
        let other = PrevalenceDetailRequest {tenant_id: "00000000-0000-4000-8000-000000000002".into(), ..denied};
        assert!(prevalence_detail(&engine, &other).await.is_err());
    }
    let request = PrevalenceExplorerRequest {request_id: "fixture-explorer".into(), tenant_id: TENANT.into(), window: "24h".into(), end: Some(now.to_rfc3339()), artifact_type: None, risk_level: None, first_seen_since: None, search: None, limit: 2, offset: 0, cursor: None, rarity_threshold: Some(3), deny_source_types: vec![]};
    let error = prevalence_explorer(&engine, &request).await.unwrap_err();
    assert!(error.to_string().contains(super::super::product_state::WARMING));
    let work = super::super::product_state::take(engine.identity_state_dir()).unwrap();
    super::super::product_state::prepare(&engine, engine.identity_state_dir(), work).await.unwrap();
    let mut timings = Vec::new();
    for _ in 0..5 {
        let start = std::time::Instant::now();
        prevalence_explorer(&engine, &request).await.unwrap();
        timings.push(start.elapsed());
    }
    timings.sort();
    println!("lean signed-parts explorer fixture p50={:.3}s", timings[2].as_secs_f64());
    assert!(timings[2] < std::time::Duration::from_secs(2));
    let first = prevalence_explorer(&engine, &request).await.unwrap();
    assert_eq!(first["result"]["artifacts"].as_array().unwrap().len(), 2);
    assert_eq!(first["result"]["has_more"], true);
    let cursor = serde_json::from_value(first["result"]["next_cursor"].clone()).unwrap();
    // NAN-3802: page 1's cursor must pass the API's validation unchanged.
    assert_eq!(nanosiem_core::prevalence::lookup::validated_explorer_cursor(&cursor).unwrap(), cursor);
    let next = prevalence_explorer(&engine, &PrevalenceExplorerRequest {cursor: Some(cursor), ..request.clone()}).await.unwrap();
    assert_eq!(first["result"]["total"], next["result"]["total"]);
    for item in next["result"]["artifacts"].as_array().unwrap() {
        assert!(!first["result"]["artifacts"].as_array().unwrap().iter().any(|old| old["artifact"] == item["artifact"]), "first={first} next={next}");
    }
    let empty = prevalence_explorer(&engine, &PrevalenceExplorerRequest {search: Some("absent.fixture".into()), ..request}).await.unwrap();
    assert_eq!(empty["result"]["total"], 0);
    assert_eq!(empty["result"]["artifacts"], json!([]));
}

#[tokio::test]
#[ignore = "native: verified chDB artifact and lake compiler"]
async fn maintained_explorer_week_matches_uncached_signed_partials_at_hour_edges() {
    let _serial = serial();
    use super::super::partials::{prevalence_explorer, prevalence_lookup_uncached, PrevalenceExplorerRequest};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // Hundreds of live parts across multiple days, with one ragged edge.
    let engine = engine_with_detail_fixture(root.path(), now, 71, true, false, false, true).await;
    let request = PrevalenceExplorerRequest {request_id:"week-explorer".into(),tenant_id:TENANT.into(),window:"7d".into(),end:Some(now.to_rfc3339()),
        artifact_type:None,risk_level:None,first_seen_since:None,search:None,limit:200,offset:0,cursor:None,rarity_threshold:Some(3),deny_source_types:vec![]};
    let cold = std::time::Instant::now();
    let error = prevalence_explorer(&engine, &request).await.unwrap_err();
    assert!(error.to_string().contains(super::super::product_state::WARMING));
    assert!(cold.elapsed() < std::time::Duration::from_millis(200));
    let work = super::super::product_state::take(engine.identity_state_dir()).unwrap();
    let first_build = std::time::Instant::now();
    super::super::product_state::prepare(&engine, engine.identity_state_dir(), work.clone()).await.unwrap();
    println!("multi-day prevalence first background build: {:?}", first_build.elapsed());
    // Model a late signed arrival: maintain the inventory without one
    // immutable part (mid-window, so it lands in a cached day block), then
    // add it back. Unchanged day blocks are reused (NAN-3161: the arrival
    // rebuilds its day, the blocks above it, the stable prefix and the fold).
    let from = now.timestamp_micros() - 7 * 86_400_000_000;
    let (parts, _, _, _) = engine.snapshot(from, now.timestamp_micros()).await.unwrap();
    let work = super::super::product_state::Work::Prevalence(parts.clone());
    {
        let full = super::super::partials::maintained_prevalence(&engine, &parts).await.unwrap();
        assert!(full.is_file(), "the explorer's warm build maintained the whole-part window state");
        let mut prior = parts.clone();
        prior.sort_by_key(|part| part.event_hour);
        prior.remove(prior.len() / 2);
        for entry in std::fs::read_dir(engine.identity_state_dir()).unwrap().flatten() {
            if entry.file_name().to_string_lossy().starts_with("prevalence-") { std::fs::remove_file(entry.path()).unwrap(); }
        }
        super::super::product_state::BUILD.scope((), super::super::partials::maintained_prevalence(&engine, &prior)).await.unwrap();
        let merges = super::super::partials::prevalence_state_merges();
        let refresh = std::time::Instant::now();
        super::super::product_state::prepare(&engine, engine.identity_state_dir(), work.clone()).await.unwrap();
        println!("multi-day prevalence one-part refresh: {:?} ({} merges)", refresh.elapsed(),
            super::super::partials::prevalence_state_merges() - merges);
        assert!(refresh.elapsed() < std::time::Duration::from_secs(2));
        assert!(super::super::partials::prevalence_state_merges() - merges <= 8, "a late part rebuilds O(log days) states");
        assert_eq!(engine.fetcher().prevalence_raw_scans(), 0);
    }
    let before = std::fs::read_dir(engine.identity_state_dir()).unwrap().flatten()
        .filter(|entry|entry.file_name().to_string_lossy().starts_with("prevalence-state-v2-"))
        .map(|entry|(entry.path(),std::fs::read(entry.path()).unwrap())).collect::<Vec<_>>();
    drop(engine);
    let engine = reopen_engine(root.path()).await;
    let reuse = std::time::Instant::now();
    super::super::product_state::prepare(&engine, engine.identity_state_dir(), work).await.unwrap();
    println!("multi-day prevalence restart reuse: {:?}", reuse.elapsed());
    for (path, bytes) in before { assert_eq!(std::fs::read(path).unwrap(), bytes); }
    for deny in [vec![],vec!["azure_audit".into()],vec!["azure_audit".into(),"aws_cloudtrail".into()]] {
        let request = PrevalenceExplorerRequest {deny_source_types:deny.clone(),..request.clone()};
        let actual = prevalence_explorer(&engine,&request).await.unwrap();
        let items = actual["result"]["artifacts"].as_array().unwrap();
        let artifacts = items.iter().map(|row|row["artifact"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        let oracle = prevalence_lookup_uncached(&engine,&artifacts,now.timestamp_micros()-7*86_400_000_000,now.timestamp_micros(),&deny,3).await.unwrap();
        for item in items {
            let expected = oracle.iter().find(|row|row.artifact==item["artifact"]).unwrap();
            let expected = serde_json::to_value(expected).unwrap();
            for field in ["host_count","total_occurrences","first_seen","last_seen","is_rare","prevalence_score"] {
                assert_eq!(item[field],expected[field],"field={field} artifact={}",item["artifact"]);
            }
        }
        let start = std::time::Instant::now();
        let warm = prevalence_explorer(&engine,&request).await.unwrap();
        assert_eq!(actual["result"],warm["result"]);
        assert!(start.elapsed()<std::time::Duration::from_secs(2),"warm explorer took {:?}",start.elapsed());
    }
    let states = std::fs::read_dir(root.path().join("state")).unwrap().flatten()
        .filter(|entry|entry.file_name().to_string_lossy().starts_with("prevalence-state-v2-")).count();
    assert!(states > 1,"daily aggregates and window state are persisted and reused across viewer scopes");
}

/// NAN-3805: a typed artifact whose columns no object in range carries (a
/// domain or hash on a Cloud-only tenant, or in a detail slice holding only
/// other sources) answers an empty, complete detail. It used to fail the
/// build ("artifact type is not present in the immutable event schema"), so
/// the demand was re-filed and the detail stayed warming forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn detail_of_an_artifact_kind_absent_from_the_schema_is_empty() {
    let _serial = serial();
    use super::super::detail_scan::scan;
    use super::super::partials::PrevalenceDetailRequest;
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // CloudTrail rows only: no dst_endpoint/query/url hostname, no hashes.
    let engine = engine(root.path(), now).await;
    let (from, to) = ((now - Duration::days(1)).timestamp_micros(), now.timestamp_micros());
    for artifact in ["example.test".to_string(), "a".repeat(64)] {
        let selection = engine.select(from, to, &[]).await.unwrap();
        assert!(!selection.manifest.objects.is_empty(), "the fixture has rows in range");
        let (source, params) = crate::planner::trusted_iceberg_source(&selection.tenant).unwrap();
        let reference = crate::prevalence::read_part_detail(engine.executor(), &selection.tenant, &selection.manifest,
            source, params, "1".into(), &artifact, from, to).await.unwrap();
        assert!(reference.top_hosts.is_empty(), "{artifact}: {reference:?}");
        let request = PrevalenceDetailRequest { request_id: String::new(), tenant_id: TENANT.into(), window: "24h".into(),
            artifact: artifact.clone(), deny_source_types: vec![] };
        let answer = super::super::product_state::BUILD
            .scope((), scan(&engine, &request, from, to, std::time::Instant::now(), |_| Ok(())))
            .await.unwrap();
        assert_eq!(answer["top_hosts"], json!([]), "{artifact}: {answer}");
        assert_eq!(answer["coverage"]["complete"], true, "{artifact}: {answer}");
    }
}

#[tokio::test]
#[ignore = "native: verified chDB artifact and lake compiler"]
async fn product_state_failure_retries_without_gating_http_readiness() {
    let _serial = serial();
    let log_dir = tempfile::tempdir().unwrap();
    let log_path = log_dir.path().join("product-state.log");
    let log_writer = std::fs::File::create(&log_path).unwrap();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).without_time()
        .with_writer(move || log_writer.try_clone().unwrap()).finish();
    use super::super::{detections::DetectionGate, server::QueryService};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn call(service: &Arc<QueryService>, path: &str, body: Option<Value>) -> (u16, Value) {
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(service.clone().serve_stream(server));
        let data = body.as_ref().map(Value::to_string).unwrap_or_default();
        let method = if body.is_some() { "POST" } else { "GET" };
        client.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{data}", data.len()).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut response)).await.unwrap().unwrap();
        task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        let (header, body) = response.split_once("\r\n\r\n").unwrap();
        (header.split_whitespace().nth(1).unwrap().parse().unwrap(), serde_json::from_str(body).unwrap())
    }
    let root = tempfile::tempdir().unwrap();
    let engine = engine(root.path(), Utc::now()).await;
    let _logging = tracing::subscriber::set_default(subscriber);
    // A non-directory output path deliberately fails the first build. The
    // engine's authenticated inventory/cache remains intact.
    let product_dir = root.path().join("product-state");
    std::fs::write(&product_dir, b"fault injection").unwrap();
    let gate = DetectionGate::new(None, 0).unwrap();
    let service = QueryService::new(engine, gate, product_dir.clone(), "a".repeat(64), "b".repeat(64), None, 24, None);
    service.enable_product_state_maintenance();
    service.clone().spawn_prewarm();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if call(&service, "/v1/status", None).await.0 == 200 { break; }
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let request = json!({"request_id":"warming-test", "tenant_id":TENANT,
        "risk_operation":"overview", "anchor_us":Utc::now().timestamp_micros(),
        "decay":{"decay_0_24h":1.0,"decay_1_3d":1.0,"decay_3_5d":1.0,"decay_5_7d":1.0}});
    // More than the first retry interval: repeated failures leave Ready.
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let start = std::time::Instant::now();
    let (status, body) = call(&service, "/v1/risk", Some(request.clone())).await;
    assert!(start.elapsed() < std::time::Duration::from_millis(200));
    assert_eq!(status, 409);
    assert_eq!(body["availability"]["reason"], "warming");
    assert_eq!(body["ready"], true);
    assert_eq!(call(&service, "/v1/status", None).await.0, 200);
    for (path, body) in [
        ("/v1/prevalence/explorer", json!({"request_id":"warming-explorer", "tenant_id":TENANT, "window":"24h", "limit":10})),
        ("/v1/risk", { let mut entities = request.clone(); entities["risk_operation"] = json!("entities"); entities }),
    ] {
        let started = std::time::Instant::now();
        let (status, body) = call(&service, path, Some(body)).await;
        assert_eq!(status, 409, "{path}: {body}");
        assert_eq!(body["availability"]["reason"], "warming");
        assert!(started.elapsed() < std::time::Duration::from_millis(300));
    }
    // NAN-3791: a detail miss does not wait for product state. It answers
    // from the process's own first-answer-budget scan (1.5 s), and answers
    // 409 warming only while that scan's single slot or its admission is
    // busy (a build retry can hold admission for a moment).
    let detail = json!({"request_id":"warming-detail", "tenant_id":TENANT, "window":"24h", "artifact":"example.test"});
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let started = std::time::Instant::now();
        let (status, body) = call(&service, "/v1/prevalence/detail", Some(detail.clone())).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "detail took {:?}", started.elapsed());
        if status == 200 {
            assert_eq!(body["ok"], true, "{body}");
            assert_eq!(body["result"]["artifact"], "example.test", "{body}");
            assert_eq!(body["result"]["coverage"]["refining"], false, "{body}");
            break;
        }
        assert_eq!(status, 409, "/v1/prevalence/detail: {body}");
        assert_eq!(body["availability"]["reason"], "warming", "{body}");
        assert!(std::time::Instant::now() < deadline, "detail never answered from its quick scan: {body}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    std::fs::remove_file(&product_dir).unwrap();
    std::fs::create_dir(&product_dir).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let (status, body) = call(&service, "/v1/risk", Some(request.clone())).await;
        if status == 200 { assert_eq!(body["ok"], true); break; }
        assert_eq!(body["reason"], "warming");
        assert!(std::time::Instant::now() < deadline, "background retry did not recover: {body}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    // NAN-3271: routes gate per window (risk on its own ledger), so wait for
    // every window route before reading the build logs.
    for window in ["1h", "24h", "7d", "30d"] {
        let request = json!({"request_id":"recovered-explorer", "tenant_id":TENANT, "window":window, "limit":10});
        loop {
            let (status, body) = call(&service, "/v1/prevalence/explorer", Some(request.clone())).await;
            if status == 200 { break; }
            assert_eq!(body["reason"], "warming", "{window}: {body}");
            assert!(std::time::Instant::now() < deadline, "{window} never published: {body}");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    assert_eq!(call(&service, "/v1/status", None).await.0, 200);
    let logs = std::fs::read_to_string(&log_path).unwrap();
    assert!(logs.contains("product state build failed"));
    assert!(logs.contains("next_retry_ms="));
    assert!(logs.contains("product state ready"));
    assert!(logs.contains("rows="));
    // NAN-3168 evidence on every build.
    assert!(logs.contains("cpu_ms=") && logs.contains("cpu_scope=\"process\"") && logs.contains("threads=1"), "{logs}");
    for hours in [1, 24, 168, 720] {
        assert!(logs.contains(&format!("window_hours={hours}")), "missing window {hours}: {logs}");
    }
}


/// NAN-3148: product[T] builds and publishes; query[T] (a consumer) serves
/// the published snapshots, which equal the legacy in-process build at the
/// same anchor, and never builds or queues product work itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn published_product_state_equals_the_in_process_build_and_query_never_builds() {
    let _serial = serial();
    use super::super::partials::{maintained_detail_bounds, prevalence_detail, prevalence_explorer, PrevalenceDetailRequest, PrevalenceExplorerRequest};
    use super::super::product_publish::{pending_demands, read_manifest, write_manifest, Cycle, Published, Publisher, PublisherStatus, WINDOWS};
    use super::super::product_state::{self, WARMING};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // ~30 days of events (one every 71 min) so every window has content.
    let legacy = engine_with_detail_fixture(root.path(), now, 71, true, false, false, true).await;
    let product_dir = root.path().join("product");
    std::fs::create_dir_all(product_dir.join("demand")).unwrap();

    // product[T]: build, publish; a second cycle without new parts is skipped.
    let built_engine = Arc::new(reopen_engine_at(root.path(), "product").await);
    built_engine.set_product_state(Published::publisher(product_dir.clone())).unwrap();
    let status = Arc::new(PublisherStatus::default());
    let mut publisher = Publisher::new(built_engine.clone(), status.clone()).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(publisher.cycle().await, Cycle::Built);
    println!("product cycle (risk + 4 windows): {:?}", started.elapsed());
    let manifest = publisher.manifest().clone();
    assert!(manifest.complete());
    assert!(manifest.log_head.is_some());
    let files_before = std::fs::read_dir(&product_dir).unwrap().count();
    assert_eq!(publisher.cycle().await, Cycle::Skipped, "no new parts: no rebuild");
    assert_eq!(publisher.manifest().version, manifest.version, "a skipped cycle publishes nothing");
    assert_eq!(std::fs::read_dir(&product_dir).unwrap().count(), files_before);

    // Flag off: query[T] alone, its in-process publisher building into its
    // own state dir; its request path reads exactly like a consumer.
    let inproc_dir = root.path().join("inproc");
    let inproc = Arc::new(reopen_engine_at(root.path(), "inproc").await);
    inproc.set_product_state(Published::in_process(inproc_dir.clone())).unwrap();
    let mut local_publisher = Publisher::new(inproc.clone(), Arc::new(PublisherStatus::default())).unwrap();
    assert!(prevalence_explorer(&inproc, &PrevalenceExplorerRequest { request_id: "cold".into(), tenant_id: TENANT.into(),
        window: "24h".into(), end: None, artifact_type: None, risk_level: None, first_seen_since: None, search: None, limit: 5,
        offset: 0, cursor: None, rarity_threshold: Some(3), deny_source_types: vec![] }).await.unwrap_err().to_string().contains(WARMING),
        "nothing published yet: warming, never an in-request build");
    assert_eq!(local_publisher.cycle().await, Cycle::Built);
    assert_eq!(local_publisher.cycle().await, Cycle::Skipped, "flag off: no rebuild without new parts either");
    let local_manifest = local_publisher.manifest().clone();

    // query[T] as a consumer of the published dir.
    let consumer = reopen_engine_at(root.path(), "query").await;
    consumer.set_product_state(Published::consumer(product_dir.clone())).unwrap();
    for window in WINDOWS {
        let entry = &manifest.windows[window];
        for deny in [vec![], vec!["azure_audit".to_string()]] {
            let moving = PrevalenceExplorerRequest { request_id: "nan3148".into(), tenant_id: TENANT.into(), window: window.into(), end: None,
                artifact_type: None, risk_level: None, first_seen_since: None, search: None, limit: 200, offset: 0, cursor: None,
                rarity_threshold: Some(3), deny_source_types: deny.clone() };
            let published = prevalence_explorer(&consumer, &moving).await.unwrap();
            assert_eq!(published["product_state"]["version"], json!(manifest.version));
            assert_eq!(published["product_state"]["stale"], json!(false));
            // The legacy in-process build at exactly the published anchor.
            let exact = PrevalenceExplorerRequest { end: Some(DateTime::<Utc>::from_timestamp_micros(entry.to_us).unwrap().to_rfc3339()), ..moving };
            let local = loop {
                match prevalence_explorer(&legacy, &exact).await {
                    Ok(answer) => break answer,
                    Err(error) => {
                        assert!(error.to_string().contains(WARMING), "{error}");
                        while let Some(work) = product_state::take(legacy.identity_state_dir()) {
                            product_state::prepare(&legacy, legacy.identity_state_dir(), work).await.unwrap();
                        }
                    }
                }
            };
            assert!(local["result"]["total"].as_u64().unwrap() > 0 || window == "1h", "window={window} has content");
            assert_eq!(published["result"], local["result"], "window={window} deny={deny:?}");
            // In-process (flag off), compared at its own published anchor.
            let inproc_entry = &local_manifest.windows[window];
            let served = prevalence_explorer(&inproc, &PrevalenceExplorerRequest { end: None, ..exact.clone() }).await.unwrap();
            let at_anchor = PrevalenceExplorerRequest { end: Some(DateTime::<Utc>::from_timestamp_micros(inproc_entry.to_us).unwrap().to_rfc3339()), ..exact.clone() };
            let reference = loop {
                match prevalence_explorer(&legacy, &at_anchor).await {
                    Ok(answer) => break answer,
                    Err(_) => while let Some(work) = product_state::take(legacy.identity_state_dir()) {
                        product_state::prepare(&legacy, legacy.identity_state_dir(), work).await.unwrap();
                    },
                }
            };
            assert_eq!(served["result"], reference["result"], "in-process window={window} deny={deny:?}");
        }
    }
    assert!(product_state::take(consumer.identity_state_dir()).is_none(), "the consumer queued no in-process work");

    // NAN-3791: the maintained explorer state answers exactly what the
    // per-request window aggregate answers, for every filter, page and
    // deny shape (a deny set naming a scope in the window falls back).
    for window in WINDOWS {
        // The fixture's newest event is 71.5 min old: the 1h window holds no
        // parts, so it publishes no window file (nor explorer state).
        let Some(name) = manifest.windows[window].window.as_ref() else {
            assert_eq!(window, "1h", "only the 1h window of this fixture is empty");
            continue;
        };
        let window_file = product_dir.join(name);
        let explorer = super::super::partials::explorer_path(&window_file);
        assert!(explorer.is_file(), "window={window}: product[T] built its explorer state with the window");
        let base = PrevalenceExplorerRequest { request_id: "nan3791".into(), tenant_id: TENANT.into(), window: window.into(), end: None,
            artifact_type: None, risk_level: None, first_seen_since: None, search: None, limit: 3, offset: 0, cursor: None,
            rarity_threshold: Some(3), deny_source_types: vec![] };
        let mut variants = vec![
            base.clone(),
            PrevalenceExplorerRequest { offset: 2, ..base.clone() },
            PrevalenceExplorerRequest { artifact_type: Some("domain".into()), ..base.clone() },
            PrevalenceExplorerRequest { risk_level: Some("rare".into()), ..base.clone() },
            PrevalenceExplorerRequest { risk_level: Some("new".into()), ..base.clone() },
            PrevalenceExplorerRequest { search: Some("EXAMPLE".into()), ..base.clone() },
            PrevalenceExplorerRequest { deny_source_types: vec!["no_such_source".into()], ..base.clone() },
            PrevalenceExplorerRequest { deny_source_types: vec!["azure_audit".into()], ..base.clone() },
        ];
        let first = prevalence_explorer(&consumer, &base).await.unwrap();
        if let Some(cursor) = first["result"]["next_cursor"].as_object() {
            variants.push(PrevalenceExplorerRequest { cursor: Some(serde_json::from_value(json!({
                "last_seen": cursor["last_seen"], "kind": cursor["kind"], "artifact": cursor["artifact"]})).unwrap()), ..base.clone() });
        }
        for request in &variants {
            let from_state = prevalence_explorer(&consumer, request).await.unwrap();
            let hidden = explorer.with_extension("hidden");
            std::fs::rename(&explorer, &hidden).unwrap();
            let from_window = prevalence_explorer(&consumer, request).await;
            std::fs::rename(&hidden, &explorer).unwrap();
            assert_eq!(from_state["result"], from_window.unwrap()["result"], "window={window} request={request:?}");
        }
    }
    // Flag off, a detail miss: a demand for the local publisher and (NAN-3791:
    // in-process query[T] reads like a consumer outside its build authority)
    // an answer at once from its own first-answer-budget scan.
    let miss = PrevalenceDetailRequest { request_id: "inproc-detail".into(), tenant_id: TENANT.into(), window: "24h".into(),
        artifact: "example.test".into(), deny_source_types: vec![] };
    let start = std::time::Instant::now();
    let quick = prevalence_detail(&inproc, &miss).await.unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(2), "first answer under two seconds: {:?}", start.elapsed());
    assert_eq!(quick["result"]["coverage"]["refining"], json!(false));
    assert!(product_state::take(inproc.identity_state_dir()).is_none());
    assert_eq!(pending_demands(&inproc_dir).len(), 1);
    assert_eq!(local_publisher.serve_demands().await, 1);
    assert_eq!(prevalence_detail(&inproc, &miss).await.unwrap()["result"]["artifact"], json!("example.test"));

    // A miss the consumer cannot serve files a demand and (NAN-3791) answers
    // at once from its own first-answer-budget scan, never a state build.
    let detail = PrevalenceDetailRequest { request_id: "nan3148-detail".into(), tenant_id: TENANT.into(), window: "24h".into(),
        artifact: "example.test".into(), deny_source_types: vec![] };
    let start = std::time::Instant::now();
    let quick = prevalence_detail(&consumer, &detail).await.unwrap();
    assert!(start.elapsed() < std::time::Duration::from_secs(2), "first answer under two seconds: {:?}", start.elapsed());
    assert_eq!(quick["result"]["artifact"], json!("example.test"));
    assert_eq!(quick["result"]["coverage"]["refining"], json!(false), "nothing replaces a quick answer in place");
    assert!(product_state::take(consumer.identity_state_dir()).is_none());
    assert!(product_state::take(&root.path().join("query")).is_none());
    assert_eq!(pending_demands(&product_dir).len(), 1);
    assert_eq!(publisher.serve_demands().await, 1);
    assert!(pending_demands(&product_dir).is_empty());
    let served = prevalence_detail(&consumer, &detail).await.unwrap();
    let latest = publisher.manifest().latest.values().find(|entry| entry.file.starts_with("product-detail-")).unwrap().clone();
    let reference = loop {
        match maintained_detail_bounds(&legacy, &detail, latest.from_us, latest.to_us).await {
            Ok(answer) => break answer,
            Err(_) => {
                let work = product_state::take(legacy.identity_state_dir()).unwrap();
                product_state::prepare(&legacy, legacy.identity_state_dir(), work).await.unwrap();
            }
        }
    };
    assert_eq!(served["result"], reference, "published detail equals the in-process build");

    // Risk: the seven-day ledger is served from product[T]'s dir.
    let anchor = manifest.latest.values().find(|entry| entry.file.starts_with("risk-ledger-")).unwrap();
    let (ledger, _) = super::super::risk::ledger(&consumer, &root.path().join("query"), anchor.from_us, anchor.to_us).await.unwrap();
    assert_eq!(ledger.parent(), Some(product_dir.as_path()));

    // A restarted query[T] serves the last snapshot at once, marked stale
    // when old; a new version swaps in without a restart.
    let mut old = read_manifest(&product_dir).unwrap();
    for entry in old.windows.values_mut() { entry.built_at_us -= 3 * 3_600_000_000; }
    old.version += 1;
    write_manifest(&product_dir, &old).unwrap();
    drop(consumer);
    let restarted = reopen_engine_at(root.path(), "query").await;
    restarted.set_product_state(Published::consumer(product_dir.clone())).unwrap();
    let request = PrevalenceExplorerRequest { request_id: "nan3148-restart".into(), tenant_id: TENANT.into(), window: "7d".into(), end: None,
        artifact_type: None, risk_level: None, first_seen_since: None, search: None, limit: 5, offset: 0, cursor: None,
        rarity_threshold: Some(3), deny_source_types: vec![] };
    let stale = prevalence_explorer(&restarted, &request).await.unwrap();
    assert_eq!(stale["product_state"]["stale"], json!(true));
    assert_eq!(stale["product_state"]["version"], json!(old.version));

    // A restarted product[T] resumes the manifest. NAN-3799: the 1h
    // snapshot (3 h old) no longer covers its span and is withdrawn (the
    // consumer warms on it), the 7d one keeps serving; only 1h rebuilds.
    drop(publisher);
    let resumed_engine = Arc::new(reopen_engine_at(root.path(), "product").await);
    resumed_engine.set_product_state(Published::publisher(product_dir.clone())).unwrap();
    let mut resumed = Publisher::new(resumed_engine, Arc::new(PublisherStatus::default())).unwrap();
    assert_eq!(resumed.manifest().version, old.version + 1);
    assert!(!resumed.manifest().windows.contains_key("1h") && resumed.manifest().windows.contains_key("7d"));
    assert_eq!(read_manifest(&product_dir).unwrap().version, old.version + 1, "the withdrawal is published");
    assert_eq!(resumed.cycle().await, Cycle::Built);
    assert!(resumed.manifest().windows.contains_key("1h"));
    let rebuilt = resumed.manifest().windows["7d"].built_at_us;
    assert_eq!(rebuilt, old.windows["7d"].built_at_us, "a window still inside its span is not rebuilt on resume");
}

/// NAN-3168: a product-state statement is bounded to the product thread
/// budget (one core by default) even when the interactive budget is wide:
/// a CPU-bound statement under build authority burns ~1 core of process
/// CPU per wall second, the same statement outside it several. Also shows
/// `max_threads=1` alone does not bound a Parquet read (the parsing pool).
/// Needs a process-wide chDB memory cap of at least 2 GiB (the fixture's
/// [`FIXTURE_EXECUTOR_MB`]).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn nan3168_build_statements_stay_on_the_product_thread_budget() {
    let _serial = serial();
    use super::super::product_state::{build_threads, BUILD};
    let root = tempfile::tempdir().unwrap();
    let _fixture = engine(root.path(), Utc::now()).await;
    let engine = reopen_engine_with_threads(root.path(), "cpu", 8).await;
    // A wide Parquet input with many row groups: product statements are
    // Parquet reads, and chDB decodes row groups on its format-parsing pool
    // (`max_parsing_threads`, every core by default) whatever `max_threads`
    // says. Written once, outside the measurement.
    let input = root.path().join("nan3168-burn.parquet");
    let input_param = vec![("burn_input".to_string(), input.to_string_lossy().into_owned())];
    engine.with_job_statements(engine.run_sql(
        "INSERT INTO FUNCTION file({burn_input:String}, Parquet) SELECT number % 100000 AS k, \
                concat(toString(cityHash64(number)), '-', hex(MD5(toString(number)))) AS v \
         FROM numbers(30000000) SETTINGS max_threads=1, output_format_parquet_row_group_size=100000".into(),
        input_param.clone())).await.unwrap();
    async fn burn(engine: &PartQueryEngine, params: Vec<(String, String)>) -> (f64, f64) {
        burn_with(engine, params, super::super::partials::statement_settings(engine)).await
    }
    async fn burn_with(engine: &PartQueryEngine, params: Vec<(String, String)>, settings: String) -> (f64, f64) {
        let sql = format!("SELECT count() AS rows, sum(length(v)) AS bytes, uniqCombined(k) AS keys FROM file({{burn_input:String}}, Parquet){settings}");
        let (wall, cpu) = (std::time::Instant::now(), nan3161_cpu_seconds());
        engine.with_job_statements(engine.run_sql(sql, params)).await.unwrap();
        (wall.elapsed().as_secs_f64(), nan3161_cpu_seconds() - cpu)
    }
    let (build_wall, build_cpu) = BUILD.scope((), burn(&engine, input_param.clone())).await;
    let (query_wall, query_cpu) = burn(&engine, input_param.clone()).await;
    // `max_threads=1` alone does not bound it: the parsing pool goes wide.
    let threads_only = BUILD.scope((), async {
        super::super::partials::statement_settings(&engine).replace(", max_parsing_threads=1", "")
    }).await;
    assert!(threads_only.contains("max_threads=1") && !threads_only.contains("max_parsing_threads"));
    let (only_wall, only_cpu) = burn_with(&engine, input_param, threads_only).await;
    println!("nan3168 max_threads=1 without max_parsing_threads: wall {only_wall:.2}s cpu {only_cpu:.2}s ({:.2} cores)", only_cpu / only_wall);
    let (build_cores, query_cores) = (build_cpu / build_wall, query_cpu / query_wall);
    println!("nan3168 build: wall {build_wall:.2}s cpu {build_cpu:.2}s ({build_cores:.2} cores, budget {}); \
              interactive: wall {query_wall:.2}s cpu {query_cpu:.2}s ({query_cores:.2} cores, budget 8)", build_threads());
    assert!(build_cores <= build_threads() as f64 + 0.35, "a build used {build_cores:.2} cores");
    assert!(query_cores > build_cores + 0.5, "the interactive budget is wider ({query_cores:.2} vs {build_cores:.2})");
}

async fn nan3168_publisher(root: &std::path::Path, product_dir: &std::path::Path) -> super::super::product_publish::Publisher {
    use super::super::product_publish::{Published, Publisher, PublisherStatus};
    let engine = Arc::new(reopen_engine_at(root, "product").await);
    engine.set_product_state(Published::publisher(product_dir.to_path_buf())).unwrap();
    Publisher::new(engine, Arc::new(PublisherStatus::default())).unwrap()
}

/// NAN-3168: after new parts a cycle rebuilds the 1h window and defers the
/// long ones (their exact snapshot stays published and fresh) until their
/// interval elapses; the cycle log names both sets and carries CPU evidence;
/// every statement runs on the one-thread product budget (chDB accepts it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn nan3168_long_windows_are_deferred_between_their_rebuilds() {
    let _serial = serial();
    use super::super::product_publish::{read_manifest, write_manifest, Cadence, Cycle, WINDOWS};
    let log_dir = tempfile::tempdir().unwrap();
    let log_path = log_dir.path().join("nan3168.log");
    let log_writer = std::fs::File::create(&log_path).unwrap();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).without_time()
        .with_writer(move || log_writer.try_clone().unwrap()).finish();
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let _fixture = engine_with_detail_fixture(root.path(), now, 71, true, false, false, true).await;
    let product_dir = root.path().join("product");
    std::fs::create_dir_all(product_dir.join("demand")).unwrap();
    // Pretend the part log moved past every published snapshot (a new part).
    let behind = |product_dir: &std::path::Path| {
        let mut manifest = read_manifest(product_dir).unwrap();
        let older = manifest.log_head.map(|head| head.saturating_sub(1));
        manifest.log_head = older;
        for entry in manifest.windows.values_mut() { entry.log_head = older; }
        write_manifest(product_dir, &manifest).unwrap();
        manifest
    };
    let _logging = tracing::subscriber::set_default(subscriber);

    let mut publisher = nan3168_publisher(root.path(), &product_dir).await;
    assert_eq!(publisher.cycle().await, Cycle::Built, "first cycle: every window");
    let first = publisher.manifest().clone();
    assert!(first.complete());

    drop(publisher);
    let stale = behind(&product_dir);
    let mut publisher = nan3168_publisher(root.path(), &product_dir).await;
    assert_eq!(publisher.cycle().await, Cycle::Built);
    let second = publisher.manifest().clone();
    assert_eq!(second.log_head, first.log_head);
    assert_ne!(second.windows["1h"].built_at_us, stale.windows["1h"].built_at_us, "1h follows every moved head");
    assert_eq!(second.windows["1h"].log_head, first.log_head);
    for window in ["24h", "7d", "30d"] {
        assert_eq!(second.windows[window], stale.windows[window], "{window} is deferred, its snapshot kept");
    }
    // Head unmoved, long windows behind but inside their interval: skipped.
    assert_eq!(publisher.cycle().await, Cycle::Skipped);

    // The pre-NAN-3168 rule (every window on every moved head) still holds
    // under a zero cadence.
    drop(publisher);
    let stale = behind(&product_dir);
    let mut publisher = nan3168_publisher(root.path(), &product_dir).await;
    publisher.set_cadence(Cadence::every_cycle());
    assert_eq!(publisher.cycle().await, Cycle::Built);
    for window in WINDOWS {
        assert_ne!(publisher.manifest().windows[window].built_at_us, stale.windows[window].built_at_us, "{window} rebuilt");
    }

    let logs = std::fs::read_to_string(&log_path).unwrap();
    assert!(logs.contains("windows_rebuilt=1h,24h,7d,30d windows_skipped= "), "{logs}");
    assert!(logs.contains("windows_rebuilt=1h windows_skipped=24h,7d,30d"), "{logs}");
    assert!(logs.contains("product state window rebuilt"));
    assert!(logs.contains("cpu_scope=\"process\" threads=1"), "{logs}");
}

/// NAN-3926: a real publication after an empty startup bypasses the long-window
/// cadence once; the consumer immediately sees the first artifacts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn nan3926_empty_startup_publishes_first_artifacts_on_next_tick() {
    let _serial = serial();
    use super::super::product_publish::{write_manifest, Cycle, Manifest, Published, WindowEntry, WINDOWS};
    use super::super::partials::{prevalence_explorer, PrevalenceExplorerRequest};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let _fixture = engine_with_detail_fixture(root.path(), now, 1, true, false, false, true).await;
    let product_dir = root.path().join("product");
    std::fs::create_dir_all(product_dir.join("demand")).unwrap();
    // The previous publication predates the fixture's artifact-bearing parts.
    let mut startup = Manifest::new(TENANT);
    for window in WINDOWS {
        let (from_us, to_us) = super::super::partials::moving_bounds(window).unwrap();
        startup.windows.insert(window.into(), WindowEntry { from_us, to_us,
            window: None, history: None, log_head: None, built_at_us: now.timestamp_micros(),
            artifact_rows: Some(0), warmup_complete: false });
    }
    write_manifest(&product_dir, &startup).unwrap();
    let mut publisher = nan3168_publisher(root.path(), &product_dir).await;
    assert_eq!(publisher.cycle().await, Cycle::Built);
    let consumer = reopen_engine_at(root.path(), "query").await;
    consumer.set_product_state(Published::consumer(product_dir)).unwrap();
    for window in WINDOWS {
        let entry = &publisher.manifest().windows[window];
        assert!(entry.artifact_rows.unwrap() > 0, "{window} has first artifacts");
        assert!(entry.warmup_complete, "{window} cannot bypass cadence again");
        let request = PrevalenceExplorerRequest { request_id: "nan3926".into(), tenant_id: TENANT.into(),
            window: window.into(), end: None, artifact_type: None, risk_level: None, first_seen_since: None,
            search: None, limit: 50, offset: 0, cursor: None, rarity_threshold: Some(3), deny_source_types: vec![] };
        let response = prevalence_explorer(&consumer, &request).await.unwrap();
        assert!(response["result"]["total"].as_u64().unwrap() > 0);
        assert_eq!(response["product_state"]["warming"], false);
        let foreign = PrevalenceExplorerRequest { tenant_id: "00000000-0000-4000-8000-000000000002".into(), ..request };
        assert!(prevalence_explorer(&consumer, &foreign).await.is_err());
    }
    assert_eq!(publisher.cycle().await, Cycle::Skipped);
}

// ---------------------------------------------------------------- NAN-3279

/// A one-shot fold of `parts`' prevalence partials (the oracle every
/// maintained state must equal), as a [`nan3161_digest`].
async fn nan3279_one_shot(engine: &PartQueryEngine, parts: &[crate::parts::part_log::PartRef]) -> (u64, u64) {
    use super::super::fetch::FileSet;
    use super::super::partials::path_set;
    use crate::parts::provenance::PartialKind;
    let local = engine.fetcher().ensure(parts, &[FileSet::Partial(PartialKind::Prevalence)]).await.unwrap();
    let paths = local.of(FileSet::Partial(PartialKind::Prevalence)).map(|file| file.path.clone()).collect::<Vec<_>>();
    nan3161_digest(engine,
        "SELECT kind, scope, entity, arraySort(groupUniqArrayArray(1000)(host_fingerprints)) AS host_fingerprints, \
                toUInt8(length(host_fingerprints) = 1000) AS host_count_saturated, max(is_private) AS is_private, \
                min(first_seen) AS first_seen, max(last_seen) AS last_seen, sum(daily_count) AS total_occurrences \
         FROM file({p:String}, Parquet) WHERE host_cap = 1000 GROUP BY kind, scope, entity",
        vec![("p".into(), path_set(&paths).unwrap())]).await
}

async fn nan3279_state_digest(engine: &PartQueryEngine, path: &std::path::Path) -> (u64, u64) {
    nan3161_digest(engine, "SELECT * FROM file({p:String}, Parquet)", vec![("p".into(), path.to_string_lossy().into_owned())]).await
}

/// Remove every maintained prevalence state (and persisted fold step) in
/// `dir`: a cold product dir, as after a restart that lost or invalidated
/// the stable state and its day blocks.
fn nan3279_clear_states(dir: &std::path::Path) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with("prevalence-") || name.starts_with(".prevalence-") {
            std::fs::remove_file(entry.path()).unwrap();
        }
    }
}

/// NAN-3279: a stepwise (hash-range) fold yields exactly the rows of the
/// one-statement fold and of a one-shot fold of the partials, for a week and
/// a month built cold; each step takes its own idle admission slot and
/// releases it, so other work is admitted between steps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn nan3279_stepwise_fold_equals_one_statement_and_frees_the_slot_between_steps() {
    let _serial = serial();
    use super::super::partials::{maintained_prevalence, prevalence_fold_steps, prevalence_state_statements};
    use super::super::product_state::{force_step_bytes, BUILD};
    use std::sync::atomic::Ordering;
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    // ~30 days of events, one every 71 minutes: hundreds of hourly parts.
    let engine = Arc::new(engine_with_detail_fixture(root.path(), now, 71, true, false, false, true).await);
    let state = engine.identity_state_dir().to_path_buf();
    let to = now.timestamp_micros();
    for days in [7_i64, 30] {
        let (parts, _, _, _) = engine.snapshot(to - days * NAN3161_DAY_US, to).await.unwrap();
        let oracle = nan3279_one_shot(&engine, &parts).await;
        assert!(oracle.0 > 0);

        nan3279_clear_states(&state);
        force_step_bytes(u64::MAX);
        let steps = prevalence_fold_steps();
        let single = BUILD.scope((), maintained_prevalence(&engine, &parts)).await.unwrap();
        assert_eq!(prevalence_fold_steps(), steps, "{days}d: one statement per fold");
        let single = nan3279_state_digest(&engine, &single).await;

        nan3279_clear_states(&state);
        force_step_bytes(4_096);
        let (steps, statements) = (prevalence_fold_steps(), prevalence_state_statements());
        let done = Arc::new(AtomicBool::new(false));
        let probe = tokio::spawn({
            let (engine, done) = (engine.clone(), done.clone());
            async move {
                // Interactive-side view: whenever every slot is free, take
                // one and give it back. Record which fold step had run.
                let mut seen = Vec::new();
                while !done.load(Ordering::Relaxed) {
                    if let Some(slot) = engine.try_admit_idle() {
                        seen.push(prevalence_fold_steps());
                        drop(slot);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                }
                seen
            }
        });
        let started = std::time::Instant::now();
        let stepped = BUILD.scope((), maintained_prevalence(&engine, &parts)).await.unwrap();
        done.store(true, Ordering::Relaxed);
        let seen = probe.await.unwrap();
        let (fold_steps, statements) = (prevalence_fold_steps() - steps, prevalence_state_statements() - statements);
        println!("nan3279 {days}d cold stepwise build: {:?}, {fold_steps} fold steps, {statements} statements", started.elapsed());
        assert!(fold_steps > 2, "{days}d: folds ran in steps ({fold_steps})");
        assert!(statements >= fold_steps, "every step took its own idle slot");
        let between = seen.iter().filter(|count| **count > steps && **count < steps + fold_steps).count();
        assert!(between > 0, "{days}d: the idle slot was free between steps (probe saw {seen:?})");
        let stepped = nan3279_state_digest(&engine, &stepped).await;
        assert_eq!(stepped, single, "{days}d: stepwise fold == one-statement fold");
        assert_eq!(stepped, oracle, "{days}d: == one-shot fold of the partials");
        let leftovers = std::fs::read_dir(&state).unwrap().flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".prevalence-step-")).count();
        assert_eq!(leftovers, 0, "assembled steps are removed");
    }
    force_step_bytes(0);
}

/// NAN-3279: after a restart with no stable state (nor day blocks) for the
/// current inventory, one publisher cycle publishes 7d and 30d through many
/// bounded fold steps, and each published window equals a one-shot fold of
/// its parts' partials.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn nan3279_restart_publishes_long_windows_in_bounded_steps() {
    let _serial = serial();
    use super::super::partials::prevalence_fold_steps;
    use super::super::product_publish::{Cadence, Cycle, MANIFEST};
    use super::super::product_state::force_step_bytes;
    let log_dir = tempfile::tempdir().unwrap();
    let log_path = log_dir.path().join("nan3279.log");
    let log_writer = std::fs::File::create(&log_path).unwrap();
    let subscriber = tracing_subscriber::fmt().with_ansi(false).without_time()
        .with_writer(move || log_writer.try_clone().unwrap()).finish();
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let _fixture = engine_with_detail_fixture(root.path(), now, 71, true, false, false, true).await;
    let product_dir = root.path().join("product");
    std::fs::create_dir_all(product_dir.join("demand")).unwrap();
    let _logging = tracing::subscriber::set_default(subscriber);
    force_step_bytes(8_192);

    let mut publisher = nan3168_publisher(root.path(), &product_dir).await;
    publisher.set_cadence(Cadence::every_cycle());
    assert_eq!(publisher.cycle().await, Cycle::Built);
    assert!(publisher.manifest().complete());
    drop(publisher);

    // Restart: nothing published, no stable state, no day blocks.
    nan3279_clear_states(&product_dir);
    // Every published file, the manifest (`product-manifest.json`) included.
    for entry in std::fs::read_dir(&product_dir).unwrap().flatten() {
        if entry.file_name().to_string_lossy().starts_with("product-") { std::fs::remove_file(entry.path()).unwrap(); }
    }
    assert!(!product_dir.join(MANIFEST).exists());
    let steps = prevalence_fold_steps();
    let started = std::time::Instant::now();
    let mut publisher = nan3168_publisher(root.path(), &product_dir).await;
    assert_eq!(publisher.cycle().await, Cycle::Built, "the restarted publisher converges in one cycle");
    let manifest = publisher.manifest().clone();
    let fold_steps = prevalence_fold_steps() - steps;
    println!("nan3279 restart cycle: {:?}, {fold_steps} fold steps", started.elapsed());
    assert!(manifest.complete());
    assert!(fold_steps > 8, "long windows folded in many steps ({fold_steps})");
    drop(publisher);
    force_step_bytes(0);

    let oracle = reopen_engine_at(root.path(), "oracle").await;
    for window in ["7d", "30d"] {
        let entry = &manifest.windows[window];
        let file = product_dir.join(entry.window.as_ref().expect("the window holds parts"));
        let (parts, _, _, _) = oracle.snapshot(entry.from_us, entry.to_us).await.unwrap();
        assert_eq!(nan3279_state_digest(&oracle, &file).await, nan3279_one_shot(&oracle, &parts).await, "{window}");
    }
    let logs = std::fs::read_to_string(&log_path).unwrap();
    assert!(logs.contains("prevalence state folded in steps"), "{logs}");
    assert!(!logs.contains("product state build failed"), "{logs}");
}

// ---------------------------------------------------------------- NAN-3161

const NAN3161_HOUR_US: i64 = 3_600_000_000;
const NAN3161_DAY_US: i64 = 24 * NAN3161_HOUR_US;

/// A month of hourly traffic: 60% of destinations recur from a fixed pool,
/// 40% are new every hour; 40 reporting hosts.
fn nan3161_event(uid: usize, time: DateTime<Utc>) -> Value {
    let mut row = event(uid, &time.to_rfc3339());
    let hour = time.timestamp().div_euclid(3_600) as usize;
    let destination = if uid % 5 < 3 {
        let n = (uid * 7_919) % 2_000;
        format!("198.51.{}.{}", n / 250, n % 250)
    } else {
        format!("203.{}.{}.{}", (hour / 250) % 250, hour % 250, uid % 250)
    };
    // Network Activity under the host profile (as the detail fixture).
    row["class_uid"] = json!(4001);
    row["class_name"] = json!("Network Activity");
    row["category_uid"] = json!(4);
    row["type_uid"] = json!(400101);
    for name in ["api", "resources", "cloud", "actor"] {
        row.as_object_mut().unwrap().remove(name);
    }
    row["metadata"]["profiles"] = json!(["host"]);
    row["src_endpoint"] = json!({"hostname": format!("host-{}", uid % 40), "ip": format!("10.0.0.{}", uid % 5)});
    row["dst_endpoint"] = json!({"hostname": "example.test", "ip": destination, "port": 443});
    row["connection_info"] = json!({"protocol_num": 6, "direction_id": 2});
    row["device"] = json!({"hostname": format!("host-{}", uid % 40), "type_id": 2});
    row
}

fn nan3161_cpu_seconds() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: plain syscall writing into the provided struct.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    let usage = unsafe { usage.assume_init() };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// NAN-3161 bench: eight 10-minute product cycles (crossing an hour and a
/// day boundary) over a month of hourly parts, with a new arrival before
/// every cycle. Prints wall and process CPU per cycle. On the new code it
/// also asserts zero raw scans and that every incrementally maintained
/// window state equals a one-shot aggregation of its parts' partials.
///
/// ```sh
/// NAN3161_EVENTS_PER_HOUR=120 cargo test -p nanosiem-lake-worker --lib \
///   part_query::view_jobs::native::nan3161 -- --ignored --nocapture --test-threads=1
/// ```
#[tokio::test]
#[ignore = "native: verified chDB artifact and lake compiler"]
async fn nan3161_product_cycles_fold_hourly_partials_without_raw_scans() {
    let _serial = serial();
    use super::super::partials::{window_state, window_us};
    use super::super::product_state::BUILD;
    let per_hour = std::env::var("NAN3161_EVENTS_PER_HOUR").ok().and_then(|value| value.parse().ok()).unwrap_or(120_usize);
    let root = tempfile::tempdir().unwrap();
    let parts = LocalObjectStore::new(root.path().join("parts")).unwrap();
    let sources_dir = root.path().join("sources");
    std::fs::create_dir_all(sources_dir.join("bronze")).unwrap();
    let sources = LocalObjectStore::new(&sources_dir).unwrap();
    let spool = SpoolQueue::new(root.path().join("spool"), TENANT).unwrap();
    let signer = signer();
    let mut config = IngestConfig::new(TENANT, root.path().join("work"));
    config.flush_interval_override_ms = Some(1_000);
    // Hourly L0 parts only: no merge reshuffles the inventory mid-bench.
    config.merge_policy.minute_min_l0_parts = usize::MAX;
    config.merge_policy.minute_max_l0_age_ms = i64::MAX / 4;
    config.merge_policy.hour_seal_ms = i64::MAX / 4;
    let wall_now_ms = Utc::now().timestamp_millis();
    let mut ingestor = Ingestor::open(config, &parts, &sources, &spool as &dyn NoticeQueue, &signer, signer.trusted(),
        BronzeIngestEnricher::disabled(), &seed_schema(), wall_now_ms).await.expect("ingest opens");
    // Anchor 23:20 two days ago: cycles 4.. cross midnight.
    let today = Utc::now().timestamp_micros().div_euclid(NAN3161_DAY_US) * NAN3161_DAY_US;
    let anchor0 = today - 2 * NAN3161_DAY_US + 23 * NAN3161_HOUR_US + 20 * 60_000_000;
    let at = |us: i64| DateTime::<Utc>::from_timestamp_micros(us).unwrap();
    let mut uid = 0_usize;
    let mut batch = 0_usize;
    let mut ingest = |events: Vec<Value>, ingestor_now_ms: i64| {
        let key = format!("bronze/{batch:04}.parquet");
        batch += 1;
        write_bronze(&sources_dir.join(&key), &events);
        crate::bronze::admit_bronze_files(&[sources_dir.join(&key)], TENANT).expect("bronze admitted");
        spool.deliver(&SourceNotice { tenant_id: TENANT.into(), key, version: "1".into(), bytes: 0,
            sha256: None, edge_sha256: None, notified_at_ms: ingestor_now_ms }).unwrap();
    };
    let first_hour = anchor0.div_euclid(NAN3161_HOUR_US) - 31 * 24;
    let mut history = Vec::new();
    for hour in first_hour..=anchor0.div_euclid(NAN3161_HOUR_US) {
        for k in 0..per_hour {
            let time = hour * NAN3161_HOUR_US + (k as i64 * NAN3161_HOUR_US) / per_hour as i64 + 7_000_000;
            if time < anchor0 {
                history.push(nan3161_event(uid, at(time)));
                uid += 1;
            }
        }
    }
    let rows = history.len();
    // Bronze admission bounds rows per object: one object per 40k events.
    for chunk in history.chunks(40_000) {
        ingest(chunk.to_vec(), wall_now_ms);
        ingestor.tick(wall_now_ms + 1_000).await.expect("ingest admits");
        ingestor.flush_now(wall_now_ms + 5_000).await.expect("ingest flushes");
    }
    let engine = reopen_engine(root.path()).await;
    let (live, _, _, _) = engine.snapshot(i64::MIN / 2, i64::MAX / 2).await.unwrap();
    println!("nan3161 fixture: {rows} events, {} parts, {per_hour}/hour", live.len());
    let windows = ["1h", "24h", "7d", "30d"];
    let mut cycles = Vec::new();
    for cycle in 0..8_i64 {
        let anchor = anchor0 + cycle * 600_000_000;
        if cycle > 0 {
            // A new arrival: the last ten minutes' events, as one L0.
            let events = (0..per_hour / 6)
                .map(|k| { uid += 1; nan3161_event(uid, at(anchor - 600_000_000 + 1 + (k as i64 * 600_000_000) / (per_hour / 6).max(1) as i64)) })
                .collect::<Vec<_>>();
            let now_ms = Utc::now().timestamp_millis();
            ingest(events, now_ms);
            ingestor.tick(now_ms + 1_000).await.expect("ingest admits");
            ingestor.flush_now(now_ms + 5_000).await.expect("ingest flushes");
            engine.refresh().await.unwrap();
        }
        let (cpu, wall) = (nan3161_cpu_seconds(), std::time::Instant::now());
        let mut states = Vec::new();
        for window in windows {
            let from = anchor - window_us(window).unwrap();
            let (state, history) = BUILD.scope((), window_state(&engine, from, anchor)).await.unwrap();
            states.push((window, from, state.unwrap(), history.unwrap()));
        }
        let (wall, cpu) = (wall.elapsed().as_secs_f64(), nan3161_cpu_seconds() - cpu);
        println!("nan3161 cycle {cycle}: wall {wall:.3}s cpu {cpu:.3}s");
        cycles.push((wall, cpu));
        nan3161_after_checks(&engine, &states, anchor).await;
    }
    let steady = &cycles[1..];
    let mean = |values: Vec<f64>| values.iter().sum::<f64>() / values.len() as f64;
    println!(
        "nan3161 summary: cold wall {:.3}s cpu {:.3}s; steady mean wall {:.3}s cpu {:.3}s (max wall {:.3}s)",
        cycles[0].0, cycles[0].1,
        mean(steady.iter().map(|c| c.0).collect()), mean(steady.iter().map(|c| c.1).collect()),
        steady.iter().map(|c| c.0).fold(0.0, f64::max),
    );
}

/// One digest over a window-file row shape: `(rows, sum of row hashes)`.
/// Saturated host sets compare by size (their 1,000 kept members are an
/// arbitrary subset in either build).
async fn nan3161_digest(engine: &PartQueryEngine, relation: &str, params: Vec<(String, String)>) -> (u64, u64) {
    let sql = format!(
        "SELECT count() AS rows, sum(cityHash64(kind, scope, entity, length(host_fingerprints), host_count_saturated, is_private, \
                toUnixTimestamp64Micro(toDateTime64(first_seen, 6, 'UTC')), toUnixTimestamp64Micro(toDateTime64(last_seen, 6, 'UTC')), \
                total_occurrences, if(host_count_saturated = 1, [], arraySort(host_fingerprints)))) AS digest FROM ({relation})"
    );
    let rows = engine.execute_sql(sql, params).await.unwrap();
    let number = |value: &Value| value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok())).unwrap();
    (number(&rows[0]["rows"]), number(&rows[0]["digest"]))
}

/// NAN-3161 acceptance per cycle: no raw scan; every maintained window
/// equals a one-shot fold of its parts' partials; lookups equal an exact
/// raw scan on hour-aligned bounds, and on moving bounds equal the raw scan
/// of the overlapped whole hours (the documented edge semantics).
async fn nan3161_after_checks(engine: &PartQueryEngine, states: &[(&str, i64, std::path::PathBuf, std::path::PathBuf)], anchor: i64) {
    use super::super::fetch::FileSet;
    use super::super::partials::{path_set, prevalence_lookup_floored, DEFAULT_RARITY_THRESHOLD};
    use crate::parts::provenance::PartialKind;
    assert_eq!(engine.fetcher().prevalence_raw_scans(), 0, "a prevalence path leased raw data files");
    for (window, from, state, _) in states {
        let (parts, _, _, _) = engine.snapshot(*from, anchor).await.unwrap();
        let local = engine.fetcher().ensure(&parts, &[FileSet::Partial(PartialKind::Prevalence)]).await.unwrap();
        let paths = local.of(FileSet::Partial(PartialKind::Prevalence)).map(|file| file.path.clone()).collect::<Vec<_>>();
        let one_shot = nan3161_digest(engine,
            "SELECT kind, scope, entity, arraySort(groupUniqArrayArray(1000)(host_fingerprints)) AS host_fingerprints, \
                    toUInt8(length(host_fingerprints) = 1000) AS host_count_saturated, max(is_private) AS is_private, \
                    min(first_seen) AS first_seen, max(last_seen) AS last_seen, sum(daily_count) AS total_occurrences \
             FROM file({p:String}, Parquet) WHERE host_cap = 1000 GROUP BY kind, scope, entity",
            vec![("p".into(), path_set(&paths).unwrap())]).await;
        let maintained = nan3161_digest(engine, "SELECT * FROM file({p:String}, Parquet)",
            vec![("p".into(), state.to_string_lossy().into_owned())]).await;
        assert_eq!(maintained, one_shot, "{window} window state differs from a one-shot fold");
        assert!(maintained.0 > 0);
    }
    // Lookups against an exact raw reference (taken outside any prevalence
    // path, so it is not counted as one).
    let open_hour = anchor.div_euclid(NAN3161_HOUR_US) * NAN3161_HOUR_US;
    let moving_from = anchor - NAN3161_HOUR_US;
    for (from, to, floor, reference_from, reference_to) in [
        // Hour-aligned: identical to an exact scan of the bounds.
        (open_hour - 24 * NAN3161_HOUR_US, open_hour - 1, None, open_hour - 24 * NAN3161_HOUR_US, open_hour - 1),
        // Moving: every overlapping (event-hour bound) part, whole.
        (moving_from, anchor, None, i64::MIN / 4, i64::MAX / 4),
        // A retention floor mid-hour: a part straddling it is left out, a
        // later part of the same hour still counts; nothing before it does.
        (moving_from, anchor, Some(moving_from), i64::MIN / 4, i64::MAX / 4),
    ] {
        let (mut parts, _, _, _) = engine.snapshot(from, to).await.unwrap();
        if let Some(floor) = floor {
            parts.retain(|part| part.min_time_us >= floor);
        }
        let local = engine.fetcher().ensure(&parts, &[FileSet::AllData]).await.unwrap();
        let mut arms = Vec::new();
        let mut params = vec![("from_us".to_string(), reference_from.to_string()), ("to_us".to_string(), reference_to.to_string())];
        for (index, file) in local.of(FileSet::AllData).enumerate() {
            let name = format!("ref_{index}");
            arms.push(format!("SELECT kind, scope, entity, host, is_private, time FROM ({})",
                crate::prevalence_build::observation_select_sql(&file.path, &name).unwrap()));
            params.push((name, file.path.to_string_lossy().into_owned()));
        }
        let reference = engine.execute_sql(format!(
            "SELECT kind, entity, uniqExact(host) AS hosts, count() AS total, toUnixTimestamp64Micro(min(time)) AS first_us, \
                    toUnixTimestamp64Micro(max(time)) AS last_us \
             FROM ({}) WHERE toUnixTimestamp64Micro(time) >= {{from_us:Int64}} AND toUnixTimestamp64Micro(time) <= {{to_us:Int64}} \
             GROUP BY kind, entity ORDER BY kind, entity", arms.join(" UNION ALL ")), params).await.unwrap();
        assert!(!reference.is_empty());
        // Host counts: the partials attribute an IP to the host on the far
        // side of a network row (sidedness); the raw observation SQL uses
        // one host for every IP leg. That definition gap predates NAN-3161
        // (the old edge arm mixed both), so hosts are checked against the
        // partials' own fold over exactly these parts.
        let partials_local = engine.fetcher().ensure(&parts, &[FileSet::Partial(PartialKind::Prevalence)]).await.unwrap();
        let partial_paths = partials_local.of(FileSet::Partial(PartialKind::Prevalence)).map(|file| file.path.clone()).collect::<Vec<_>>();
        let hosts = engine.execute_sql(
            "SELECT kind, entity, length(arrayDistinct(arrayFlatten(groupArray(host_fingerprints)))) AS hosts \
             FROM file({p:String}, Parquet) GROUP BY kind, entity".into(),
            vec![("p".into(), path_set(&partial_paths).unwrap())]).await.unwrap();
        let artifacts = reference.iter().map(|row| row["entity"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        let results = prevalence_lookup_floored(engine, &artifacts, from, to, floor, &[], DEFAULT_RARITY_THRESHOLD).await.unwrap();
        let number = |value: &Value| value.as_i64().or_else(|| value.as_str().and_then(|text| text.parse().ok())).unwrap();
        for row in &reference {
            let entity = row["entity"].as_str().unwrap();
            let found = results.iter().find(|result| result.artifact == entity).unwrap_or_else(|| panic!("{entity} missing"));
            let partial_hosts = hosts.iter().find(|host| host["kind"] == row["kind"] && host["entity"] == row["entity"]).unwrap();
            assert_eq!(found.host_count, number(&partial_hosts["hosts"]) as u64, "{entity} hosts");
            assert_eq!(found.total_occurrences, number(&row["total"]) as u64, "{entity} total");
            assert_eq!(found.first_seen, crate::prevalence::format_micros(number(&row["first_us"])), "{entity} first");
            assert_eq!(found.last_seen, crate::prevalence::format_micros(number(&row["last_us"])), "{entity} last");
        }
        assert_eq!(engine.fetcher().prevalence_raw_scans(), 0, "a lookup leased raw data files");
    }
}

/// NAN-3277: the lean baseline's activity read
/// (`device.hostname="<dotless>" | timechart span=1h count`) answers every
/// event of the entity over a 7-day lookback exactly as over one day, and
/// returns `count` in a shape the baseline parses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256, NANO_LAKE_COMPILER"]
async fn baseline_activity_timechart_answers_a_7d_lookback_like_a_1d_one() {
    let _serial = serial();
    use super::super::engine::BroadNplRequest;
    let root = tempfile::tempdir().unwrap();
    let now = DateTime::from_timestamp(1_790_000_000, 0).unwrap();
    // 600 events 20 minutes apart: ~8.3 days; every 11th on fixture-host.
    let engine = engine_with_variants(root.path(), now, 20, true, false).await;
    let host_times = (0..ROWS)
        .filter(|i| i % 11 == 0)
        .map(|i| now - Duration::minutes((i as i64 + 1) * 20) - Duration::seconds(30))
        .collect::<Vec<_>>();
    let incident_start = now - Duration::hours(1);
    let coverage_end = incident_start - Duration::minutes(i64::from(chrono::Timelike::minute(&incident_start)))
        - Duration::seconds(i64::from(chrono::Timelike::second(&incident_start)));
    for days in [1_i64, 7] {
        let start = incident_start - Duration::days(days);
        let expected = host_times.iter().filter(|time| **time >= start && **time < coverage_end).count() as u64;
        assert!(expected > 0);
        for field in ["device.hostname", "src_endpoint.hostname"] {
            let response = engine.broad_npl(&BroadNplRequest {
                request_id: format!("baseline-activity-{days}-{field}"), tenant_id: TENANT.into(), dataset: "logs".into(),
                query: format!("{field}=\"fixture-host\" | timechart span=1h count"),
                start: start.to_rfc3339(), end: coverage_end.to_rfc3339(), limit: 5_000, offset: 0,
                table_view: false, use_cache: true, cursor_time: None, cursor_event_uid: None, anchor_us: None,
                decay: None, clear_boundaries: Default::default(), watch_weights: Default::default(),
                minimum_clear_revision: None, deny_source_types: Default::default(),
            }).await.unwrap();
            let rows = response["result"]["rows"].as_array().unwrap();
            let total = rows.iter().map(|row| row["count"].as_u64()
                .or_else(|| row["count"].as_str().and_then(|count| count.parse().ok()))
                .unwrap_or_else(|| panic!("count {row}"))).sum::<u64>();
            eprintln!("NAN-3277 {days}d {field}: rows={} total={total} expected={} sample={:?} planner={}",
                rows.len(), if field == "device.hostname" { expected } else { 0 }, rows.first(), response["planner"]);
            if field == "device.hostname" {
                assert_eq!(total, expected, "{days}d planner={}", response["planner"]);
            }
        }
    }
}


/// NAN-3760: the raw scan reference, measured at increasing part counts.
#[tokio::test]
#[ignore = "native scale fixture: requires verified chDB and compiler"]
async fn nan3760_detail_scale_and_parity() {
    let _serial = serial();
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    for spacing in [1, 71] {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let engine = engine_with_detail_pattern(root.path(), now, spacing, true, false, false, true, true).await;
        let from = (now - Duration::days(30)).timestamp_micros();
        let to = now.timestamp_micros();
        for artifact in ["10.0.0.1".to_string(), "a".repeat(64), "example.test".to_string()] {
            for deny in [vec![], vec!["azure_audit".to_string()]] {
                let started = std::time::Instant::now();
                let selection = engine.select(from, to, &[]).await.unwrap();
                let (source, params) = crate::planner::trusted_iceberg_source(&selection.tenant).unwrap();
                let scope = if deny.is_empty() { "1" } else { "lower(tupleElement(metadata, 'log_source')) != 'azure_audit'" }.to_string();
                let reference = crate::prevalence::read_part_detail(engine.executor(), &selection.tenant, &selection.manifest,
                    source, params, scope, &artifact, from, to).await.unwrap();
                println!("NAN3760 before spacing={spacing} artifact={} denied={} objects={} wall_ms={} hosts={}",
                    if artifact.len() == 64 { "rare-hash" } else { &artifact }, deny.len(), selection.manifest.objects.len(), started.elapsed().as_millis(), reference.top_hosts.len());
                let started = std::time::Instant::now();
                let narrowed = engine.select(from, to, &crate::prevalence::detail_candidate_hints(&artifact, &engine.field_types().await.unwrap())).await.unwrap();
                let (source, params) = crate::planner::trusted_iceberg_source(&narrowed.tenant).unwrap();
                let scope = if deny.is_empty() { "1" } else { "lower(tupleElement(metadata, 'log_source')) != 'azure_audit'" }.to_string();
                let result = crate::prevalence::read_part_detail(engine.executor(), &narrowed.tenant, &narrowed.manifest,
                    source, params, scope, &artifact, from, to).await.unwrap();
                assert_eq!(serde_json::to_value(&result).unwrap(), serde_json::to_value(&reference).unwrap(), "artifact={artifact} deny={deny:?}");
                println!("NAN3760 after spacing={spacing} artifact={} denied={} objects={} wall_ms={}",
                    if artifact.len() == 64 { "rare-hash" } else { &artifact }, deny.len(), narrowed.manifest.objects.len(), started.elapsed().as_millis());
                if artifact.len() == 64 && spacing == 71 {
                    assert!(narrowed.manifest.objects.len() < selection.manifest.objects.len() / 10);
                }

            }
        }
    }
}


/// NAN-3858: a detail demand filed while a window build's statement holds
/// the product process's idle slot for longer than the old 10-second wall
/// budget (tenant-a: a 1h window statement held it 29 s, and the demand failed
/// at 10.0 s without scanning) waits it out uncharged and publishes the
/// complete answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: requires verified chDB and compiler"]
async fn nan3858_detail_demand_completes_behind_a_long_window_statement() {
    let _serial = serial();
    use super::super::partials::{prevalence_detail, PrevalenceDetailRequest};
    use super::super::product_publish::{pending_demands, Published, Publisher, PublisherStatus};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let _fixture = engine_with_detail_fixture(root.path(), now, 1, true, false, false, true).await;
    let dir = root.path().join("product");
    let builder = Arc::new(reopen_engine_at(root.path(), "builder").await);
    builder.set_product_state(Published::publisher(dir.clone())).unwrap();
    let mut publisher = Publisher::new(builder.clone(), Arc::new(PublisherStatus::default())).unwrap();
    let consumer = reopen_engine_at(root.path(), "consumer").await;
    consumer.set_product_state(Published::consumer(dir.clone())).unwrap();
    let request = PrevalenceDetailRequest { request_id: "poll-1".into(), tenant_id: TENANT.into(), window: "24h".into(),
        artifact: "10.0.0.1".into(), deny_source_types: vec![] };
    prevalence_detail(&consumer, &request).await.unwrap();
    assert_eq!(pending_demands(&dir).len(), 1);
    // A window statement takes the idle slot first and holds it 15 s.
    let hold = std::time::Duration::from_secs(15);
    let (taken_tx, taken_rx) = tokio::sync::oneshot::channel();
    let statement = {
        let builder = builder.clone();
        tokio::spawn(async move {
            let _slot = super::super::product_state::idle(&builder).await;
            let _ = taken_tx.send(());
            tokio::time::sleep(hold).await;
        })
    };
    taken_rx.await.unwrap();
    let started = std::time::Instant::now();
    assert_eq!(publisher.serve_demands().await, 1, "the demand outlives a statement longer than the old 10 s budget");
    let waited = started.elapsed();
    statement.await.unwrap();
    assert!(waited >= hold - std::time::Duration::from_secs(1), "it really waited for the slot: {waited:?}");
    let mut request = request;
    request.request_id = "poll-2".into();
    let answer = prevalence_detail(&consumer, &request).await.unwrap();
    let coverage = &answer["result"]["coverage"];
    assert_eq!(coverage["complete"], true, "{coverage}");
    assert_eq!(coverage["refining"], false, "{coverage}");
    assert!(!answer["result"]["top_hosts"].as_array().unwrap().is_empty());
    println!("NAN3858 native demand behind a {}s statement: served after {} ms, complete={}", hold.as_secs(), waited.as_millis(), coverage["complete"]);
}

/// NAN-3760: changing HTTP request IDs and minute anchors must converge on
/// the logical published identity, including the source visibility fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: requires verified chDB and compiler"]
async fn nan3760_detail_demand_converges_across_poll_ids() {
    let _serial = serial();
    use super::super::partials::{prevalence_detail, PrevalenceDetailRequest};
    use super::super::product_publish::{pending_demands, Published, Publisher, PublisherStatus};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let _fixture = engine_with_detail_fixture(root.path(), now, 1, true, false, false, true).await;
    let dir = root.path().join("product");
    let builder = Arc::new(reopen_engine_at(root.path(), "builder").await);
    builder.set_product_state(Published::publisher(dir.clone())).unwrap();
    let mut publisher = Publisher::new(builder, Arc::new(PublisherStatus::default())).unwrap();
    let consumer = reopen_engine_at(root.path(), "consumer").await;
    consumer.set_product_state(Published::consumer(dir.clone())).unwrap();
    let mut request = PrevalenceDetailRequest { request_id: "poll-1".into(), tenant_id: TENANT.into(), window: "1h".into(),
        artifact: "10.0.0.1".into(), deny_source_types: vec!["azure_audit".into()] };
    // NAN-3791: a consumer with no published detail answers from its own
    // bounded quick scan (never refining) and still files the demand once.
    let quick = prevalence_detail(&consumer, &request).await.unwrap();
    assert_eq!(quick["result"]["coverage"]["refining"], false, "{quick}");
    request.request_id = "poll-2".into();
    assert!(prevalence_detail(&consumer, &request).await.is_ok());
    assert_eq!(pending_demands(&dir).len(), 1, "poll IDs do not multiply work");
    tokio::time::timeout(std::time::Duration::from_secs(10), publisher.serve_demands()).await.expect("detail build converges");
    request.request_id = "poll-3".into();
    let answer = prevalence_detail(&consumer, &request).await.unwrap();
    assert_eq!(answer["request_id"], "poll-3");
    assert!(!answer["result"]["top_hosts"].as_array().unwrap().is_empty());
    assert!(answer["result"]["source_types"].as_array().unwrap().iter().all(|row| row["source_type"] != "azure_audit"));
    request.tenant_id = "another-tenant".into();
    assert!(prevalence_detail(&consumer, &request).await.is_err());
    assert!(pending_demands(&dir).is_empty(), "another tenant cannot enqueue into this publisher");
    let mut wrong_manifest = publisher.manifest().clone();
    wrong_manifest.tenant_id = "another-tenant".into();
    super::super::product_publish::write_manifest(&dir, &wrong_manifest).unwrap();
    request.tenant_id = TENANT.into();
    // NAN-3791: a foreign-tenant manifest is never read; the consumer falls
    // back to its own quick scan of this tenant's rows (the cached quick
    // answer above), never the published detail.
    match prevalence_detail(&consumer, &request).await {
        Err(_) => {}
        Ok(answer) => assert_eq!(answer["result"], quick["result"], "foreign tenant manifests cannot serve a cached detail"),
    }

}


#[tokio::test]
#[ignore = "native explorer scale profile"]
async fn nan3760_explorer_scale() {
    let _serial = serial();
    use super::super::partials::{prevalence_explorer, PrevalenceExplorerRequest};
    use super::super::product_state;
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let engine = engine_with_detail_pattern(root.path(), now, 71, true, false, false, true, true).await;
    for window in ["7d", "30d"] {
        let mut request = PrevalenceExplorerRequest { request_id: "profile".into(), tenant_id: TENANT.into(), window: window.into(), end: Some(now.to_rfc3339()),
            artifact_type: None, risk_level: None, first_seen_since: None, search: None, limit: 50, offset: 0, cursor: None,
            rarity_threshold: None, deny_source_types: vec![] };
        let start = std::time::Instant::now();
        loop {
            match prevalence_explorer(&engine, &request).await {
                Ok(answer) => { println!("NAN3760 explorer window={window} cold_ms={} total={}", start.elapsed().as_millis(), answer["result"]["total"]); break; }
                Err(error) => {
                    assert!(error.to_string().contains(product_state::WARMING), "{error}");
                    let work = product_state::take(engine.identity_state_dir()).unwrap();
                    product_state::prepare(&engine, engine.identity_state_dir(), work).await.unwrap();
                }
            }
        }
        let start = std::time::Instant::now();
        let answer = prevalence_explorer(&engine, &request).await.unwrap();
        println!("NAN3760 explorer window={window} warm_ms={} total={}", start.elapsed().as_millis(), answer["result"]["total"]);
        let total = answer["result"]["total"].clone();
        request.limit = 2;
        let first = prevalence_explorer(&engine, &request).await.unwrap();
        assert_eq!(first["result"]["total"], total);
        request.cursor = Some(serde_json::from_value(first["result"]["next_cursor"].clone()).unwrap());
        let second = prevalence_explorer(&engine, &request).await.unwrap();
        for counter in ["total", "rare_count", "new_count", "high_risk_asset_count"] {
            assert_eq!(first["result"][counter], second["result"][counter], "counter before cursor: {counter}");
        }
        request.cursor = None;
        request.offset = 100;
        let past_end = prevalence_explorer(&engine, &request).await.unwrap();
        assert_eq!(past_end["result"]["total"], total);
        assert_eq!(past_end["result"]["artifacts"], json!([]));
        request.offset = 0;
        request.search = Some("no-such-artifact".into());
        let empty = prevalence_explorer(&engine, &request).await.unwrap();
        assert_eq!(empty["result"]["total"], 0);
        request.search = None;
        request.artifact_type = Some("hash".into());
        request.deny_source_types = vec!["azure_audit".into()];
        let hashes = prevalence_explorer(&engine, &request).await.unwrap();
        assert_eq!(hashes["result"]["total"], 3);

    }
}


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native HTTP detail demand regression"]
async fn nan3760_http_detail_enqueues_without_explorer_or_native_slot() {
    let _serial = serial();
    use super::super::{detections::DetectionGate, server::QueryService, product_publish::{Published, pending_demands, Publisher, PublisherStatus}};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let root = tempfile::tempdir().unwrap();
    let _fixture = engine_with_detail_fixture(root.path(), Utc::now(), 1, true, false, false, true).await;
    let product = root.path().join("product");
    let builder = Arc::new(reopen_engine_at(root.path(), "builder").await);
    builder.set_product_state(Published::publisher(product.clone())).unwrap();
    let mut publisher = Publisher::new(builder, Arc::new(PublisherStatus::default())).unwrap();
    let engine = reopen_engine_at(root.path(), "http-query").await;
    let service = QueryService::new(engine, DetectionGate::new(None, 0).unwrap(), root.path().join("http-query"), "a".repeat(64), "b".repeat(64), None, 24, None);
    service.enable_product_state_consumer(product.clone()).unwrap();
    // Hold every native permit. A warming JSON read must still file demand;
    // NAN-3791: it answers 200 from a quick scan on the companion slot.
    let slot = service.engine().try_admit_idle().unwrap();
    for (expected, warming) in [(200, true), (200, false)] {
        let body = json!({"request_id":"http-detail", "tenant_id":TENANT, "window":"1h", "artifact":"10.0.0.1"}).to_string();
        let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
        let task = tokio::spawn(service.clone().serve_stream(server));
        client.write_all(format!("POST /v1/prevalence/detail HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(2), client.read_to_end(&mut response)).await.unwrap().unwrap();
        task.await.unwrap();
        let response = String::from_utf8(response).unwrap();
        let (header, body) = response.split_once("\r\n\r\n").unwrap();
        assert_eq!(header.split_whitespace().nth(1).unwrap().parse::<u16>().unwrap(), expected, "{body}");
        if warming {
            assert_eq!(pending_demands(&product).len(), 1);
            assert_eq!(publisher.serve_demands().await, 1);
        }
    }
    drop(slot);
}


/// NAN-3766: the budgeted newest-first walk. With its full budget it equals
/// the single whole-window statement (the NAN-3760 reference) for common,
/// sparse and rare artifacts under every deny scope. With an artificially
/// small budget a common artifact over many parts still answers, flags
/// coverage < 100%, and its counts are exactly those of the covered range.
#[tokio::test]
#[ignore = "native scale fixture: requires verified chDB and compiler"]
async fn nan3766_detail_budget_partial_and_full_parity() {
    let _serial = serial();
    use super::super::detail_scan::{scan, DetailBudget, BUDGET};
    use super::super::partials::PrevalenceDetailRequest;
    let _ = tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init();
    let without_coverage = |mut value: Value| { value.as_object_mut().unwrap().remove("coverage"); value };
    let scope = |deny: &[String]| if deny.is_empty() { "1".to_string() } else { "lower(tupleElement(metadata, 'log_source')) != 'azure_audit'".to_string() };
    for spacing in [1, 71] {
        let root = tempfile::tempdir().unwrap();
        let now = Utc::now();
        let engine = engine_with_detail_pattern(root.path(), now, spacing, true, false, false, true, true).await;
        let from = (now - Duration::days(30)).timestamp_micros();
        let to = now.timestamp_micros();
        for artifact in ["10.0.0.1".to_string(), "a".repeat(64), "example.test".to_string()] {
            for deny in [vec![], vec!["azure_audit".to_string()]] {
                let label = if artifact.len() == 64 { "rare-hash" } else { artifact.as_str() };
                let request = PrevalenceDetailRequest { request_id: String::new(), tenant_id: TENANT.into(), window: "30d".into(),
                    artifact: artifact.clone(), deny_source_types: deny.clone() };
                let started = std::time::Instant::now();
                let selection = engine.select(from, to, &[]).await.unwrap();
                let (source, params) = crate::planner::trusted_iceberg_source(&selection.tenant).unwrap();
                let reference = crate::prevalence::read_part_detail(engine.executor(), &selection.tenant, &selection.manifest,
                    source, params, scope(&deny), &artifact, from, to).await.unwrap();
                let reference_ms = started.elapsed().as_millis();
                let started = std::time::Instant::now();
                let mut firsts = 0;
                let full = scan(&engine, &request, from, to, started, |_| { firsts += 1; Ok(()) }).await.unwrap();
                println!("NAN3766 full spacing={spacing} artifact={label} denied={} objects={} single_ms={reference_ms} walk_ms={} firsts={firsts}",
                    deny.len(), selection.manifest.objects.len(), started.elapsed().as_millis());
                assert_eq!(full["coverage"]["complete"], true, "{artifact} {deny:?}: {}", full["coverage"]);
                assert_eq!(full["coverage"]["refining"], false);
                assert_eq!(full["coverage"]["approximate"], false);
                assert_eq!(without_coverage(full.clone()), serde_json::to_value(&reference).unwrap(), "parity artifact={artifact} deny={deny:?}");
            }
        }
        // A tiny budget: only the newest slice runs, and it still answers.
        let request = PrevalenceDetailRequest { request_id: String::new(), tenant_id: TENANT.into(), window: "30d".into(),
            artifact: "10.0.0.1".into(), deny_source_types: vec![] };
        let tiny = DetailBudget { total: std::time::Duration::ZERO, first: std::time::Duration::from_secs(5), slice: std::time::Duration::from_secs(5) };
        let started = std::time::Instant::now();
        let partial = BUDGET.scope(tiny, scan(&engine, &request, from, to, started, |_| Ok(()))).await.unwrap();
        let coverage = &partial["coverage"];
        assert_eq!(coverage["complete"], false, "{coverage}");
        let scanned_from = chrono::DateTime::parse_from_rfc3339(coverage["scanned_start"].as_str().unwrap()).unwrap().timestamp_micros();
        assert!(scanned_from > from && scanned_from < to);
        let covered = (to - scanned_from) as f64 / (to - from) as f64;
        // The partial counts are exactly the covered range's counts.
        let selection = engine.select(scanned_from, to, &[]).await.unwrap();
        if selection.manifest.objects.is_empty() {
            // No part in the newest slice: an empty, flagged answer.
            assert_eq!(partial["top_hosts"], json!([]));
        } else {
            let (source, params) = crate::planner::trusted_iceberg_source(&selection.tenant).unwrap();
            let expected = crate::prevalence::read_part_detail(engine.executor(), &selection.tenant, &selection.manifest,
                source, params, "1".into(), "10.0.0.1", scanned_from, to).await.unwrap();
            assert_eq!(without_coverage(partial.clone()), serde_json::to_value(&expected).unwrap());
        }
        println!("NAN3766 tiny-budget spacing={spacing} covered_pct={:.3} wall_ms={} hosts={}",
            covered * 100.0, started.elapsed().as_millis(), partial["top_hosts"]);
        // A budget shorter than the whole walk: whatever it covers is
        // flagged and exact for its range.
        let short = DetailBudget { total: std::time::Duration::from_millis(250), first: std::time::Duration::from_millis(100), slice: std::time::Duration::from_millis(250) };
        let started = std::time::Instant::now();
        let mut firsts = Vec::new();
        let answer = BUDGET.scope(short, scan(&engine, &request, from, to, started, |first| { firsts.push(first.clone()); Ok(()) })).await.unwrap();
        let answer_from = chrono::DateTime::parse_from_rfc3339(answer["coverage"]["scanned_start"].as_str().unwrap()).unwrap().timestamp_micros();
        println!("NAN3766 short-budget spacing={spacing} complete={} covered_pct={:.1} firsts={} wall_ms={} host_count={}",
            answer["coverage"]["complete"], (to - answer_from) as f64 * 100.0 / (to - from) as f64, firsts.len(),
            started.elapsed().as_millis(), answer["top_hosts"][0]["count"]);
        for first in &firsts {
            assert_eq!(first["coverage"]["refining"], true);
            assert_eq!(first["coverage"]["complete"], false);
        }
        if answer["coverage"]["complete"] == false && answer_from < to - 3_600_000_000 {
            let selection = engine.select(answer_from, to, &[]).await.unwrap();
            let (source, params) = crate::planner::trusted_iceberg_source(&selection.tenant).unwrap();
            let expected = crate::prevalence::read_part_detail(engine.executor(), &selection.tenant, &selection.manifest,
                source, params, "1".into(), "10.0.0.1", answer_from, to).await.unwrap();
            assert_eq!(without_coverage(answer.clone()), serde_json::to_value(&expected).unwrap());
        }
        if spacing == 1 {
            assert!(partial["top_hosts"][0]["count"].as_u64().unwrap() > 0, "the newest slice holds rows");
            assert!(partial["top_hosts"][0]["count"].as_u64().unwrap() < ROWS as u64, "never the whole window's count");
        }
    }
}


/// NAN-3766: through the real publisher: a build that will run past its
/// first-answer budget publishes the newest slice (`refining`) and then the
/// final answer; a build out of budget still publishes a flagged partial.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "native: requires verified chDB and compiler"]
async fn nan3766_publisher_publishes_first_and_partial_details() {
    let _serial = serial();
    use super::super::detail_scan::{DetailBudget, BUDGET};
    use super::super::partials::{prevalence_detail, PrevalenceDetailRequest};
    use super::super::product_publish::{pending_demands, Published, Publisher, PublisherStatus};
    let root = tempfile::tempdir().unwrap();
    let now = Utc::now();
    let _fixture = engine_with_detail_fixture(root.path(), now, 1, true, false, false, true).await;
    let dir = root.path().join("product");
    let builder = Arc::new(reopen_engine_at(root.path(), "builder").await);
    builder.set_product_state(Published::publisher(dir.clone())).unwrap();
    let mut publisher = Publisher::new(builder, Arc::new(PublisherStatus::default())).unwrap();
    let consumer = reopen_engine_at(root.path(), "consumer").await;
    consumer.set_product_state(Published::consumer(dir.clone())).unwrap();

    // First answer at once (first = 0), then the walk completes: two publishes.
    let mut request = PrevalenceDetailRequest { request_id: "poll-1".into(), tenant_id: TENANT.into(), window: "24h".into(),
        artifact: "10.0.0.1".into(), deny_source_types: vec!["azure_audit".into()] };
    // NAN-3791: a consumer miss files a demand and answers at once from its
    // own first-answer-budget scan, never refining (nothing replaces it).
    let quick = prevalence_detail(&consumer, &request).await.unwrap();
    assert_eq!(quick["result"]["coverage"]["refining"], false, "{}", quick["result"]["coverage"]);
    assert_eq!(pending_demands(&dir).len(), 1, "the miss filed a demand");
    let version = publisher.manifest().version;
    let eager = DetailBudget { total: std::time::Duration::from_secs(8), first: std::time::Duration::ZERO, slice: std::time::Duration::from_secs(8) };
    assert_eq!(BUDGET.scope(eager, publisher.serve_demands()).await, 1);
    assert_eq!(publisher.manifest().version, version + 2, "a first, partial publish, then the final one");
    let answer = prevalence_detail(&consumer, &request).await.unwrap();
    assert_eq!(answer["result"]["coverage"]["complete"], true, "{}", answer["result"]["coverage"]);
    assert_eq!(answer["result"]["coverage"]["refining"], false);
    assert!(answer["result"]["source_types"].as_array().unwrap().iter().all(|row| row["source_type"] != "azure_audit"));
    let first = std::fs::read_dir(&dir).unwrap().flatten()
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".partial.state")).expect("first answer state");
    let first_path = first.path();
    let first: Value = serde_json::from_slice(&std::fs::read(&first_path).unwrap()).unwrap();
    assert_eq!(first["coverage"]["complete"], false);
    assert_eq!(first["coverage"]["refining"], true);

    // The final build failed or timed out after the first answer was
    // published: the manifest still names the first answer. Within the
    // build deadline it is served as refining; past it, as a final partial
    // answer with its exact range, so the explorer stops polling.
    let first_name = first_path.file_name().unwrap().to_string_lossy().into_owned();
    for (until, refining) in [(Utc::now().timestamp_micros() + 60_000_000, true), (Utc::now().timestamp_micros() - 1, false)] {
        let mut stored = first.clone();
        stored["coverage"]["refining_until_us"] = json!(until);
        std::fs::write(&first_path, serde_json::to_vec(&stored).unwrap()).unwrap();
        let mut manifest = publisher.manifest().clone();
        let mut pointed = 0;
        for entry in manifest.latest.values_mut().filter(|entry| entry.file.contains("product-detail-")) {
            entry.file = first_name.clone();
            entry.built_at_us = Utc::now().timestamp_micros();
            pointed += 1;
        }
        assert_eq!(pointed, 1);
        manifest.version += 1;
        super::super::product_publish::write_manifest(&dir, &manifest).unwrap();
        request.request_id = format!("poll-first-{refining}");
        let served = prevalence_detail(&consumer, &request).await.unwrap();
        let coverage = &served["result"]["coverage"];
        assert_eq!(coverage["refining"], refining, "{coverage}");
        assert_eq!(coverage["complete"], false);
        assert_eq!(coverage["scanned_start"], first["coverage"]["scanned_start"]);
        assert!(coverage.get("refining_until_us").is_none(), "the internal deadline never reaches the API");
    }

    // Out of budget: still published, flagged partial, never refining.
    request.window = "7d".into();
    request.request_id = "poll-2".into();
    let quick = prevalence_detail(&consumer, &request).await.unwrap();
    assert_eq!(quick["result"]["coverage"]["refining"], false, "{}", quick["result"]["coverage"]);
    assert_eq!(pending_demands(&dir).len(), 1, "the miss filed a demand");
    let tiny = DetailBudget { total: std::time::Duration::ZERO, first: std::time::Duration::from_secs(5), slice: std::time::Duration::from_secs(5) };
    assert_eq!(BUDGET.scope(tiny, publisher.serve_demands()).await, 1);
    assert!(pending_demands(&dir).is_empty());
    let answer = prevalence_detail(&consumer, &request).await.unwrap();
    let coverage = &answer["result"]["coverage"];
    assert_eq!(coverage["complete"], false, "{coverage}");
    assert_eq!(coverage["refining"], false);
    assert!(coverage["scanned_start"].as_str().unwrap() > coverage["window_start"].as_str().unwrap());
    let hosts = answer["result"]["top_hosts"].as_array().unwrap();
    assert!(!hosts.is_empty() && hosts[0]["count"].as_u64().unwrap() < ROWS as u64, "{hosts:?}");
}
