// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4592 tests: write-behind part completions, coalesced owner calls, and
//! the large-tenant-sized throughput and backlog-convergence checks. Every test drives
//! the production write path: `NativePartWriter::new` +
//! `R2PartStore::new_split(..).with_native_writer(..)` (as `cell.rs` builds
//! them) against a loopback owner and a loopback R2.
use super::*;
use crate::part_ingest::r2_put::R2PartStore;
use crate::part_ingest::s3_store::S3Location;
use crate::parts::part_log::{ObjectStore, WriterClass};
use axum::{extract::State, routing::{post, put}, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const T: &str = "00000000-0000-4000-8000-000000000001";
const BUCKET: &str = "nano-shared-r2-t";

/// A loopback writer owner: single and (optionally) batch routes, with the
/// latencies of a real one.
#[derive(Default)]
struct Owner {
    serve_batch: bool,
    authorize_latency: Duration,
    complete_latency: Duration,
    /// Refuse the next N completions (single or per batch item) with 409.
    refuse_completes: Mutex<usize>,
    /// Answer every batch call with this status instead.
    batch_status: Option<u16>,
    /// Refuse single authorizations of keys containing this with 409.
    refuse_authorize_of: Option<&'static str>,
    single_authorize: AtomicUsize,
    single_complete: AtomicUsize,
    batch_authorize: AtomicUsize,
    batch_complete: AtomicUsize,
    batch_objects: AtomicUsize,
    /// Shared with the loopback R2: the order owner completions and
    /// provider PUTs happened in.
    events: Arc<Mutex<Vec<String>>>,
}

fn identity_for(request: &Value) -> Value {
    let mut identity = request.clone();
    identity["schema_version"] = json!(3);
    identity["tenant_uuid"] = json!(T);
    identity["bucket"] = request["object_bucket"].clone();
    identity["key"] = request["object_key"].clone();
    identity["sha256"] = request["content_sha256"].clone();
    identity["authorization_expires_at"] = json!((Utc::now() + chrono::Duration::minutes(4)).to_rfc3339());
    identity["owner_reservation_sha256"] = json!("a".repeat(64));
    identity["deletion_unit_id"] = json!("00000000-0000-4000-8000-000000000001");
    identity
}

fn receipt_for(body: &Value) -> Value {
    json!({"schema_version":1,"status":"registered","request_id":body["request"]["request_id"],
        "deletion_unit_id":body["identity"]["deletion_unit_id"],
        "completion_receipt_id":"00000000-0000-4000-8000-000000000002",
        "artifact_id":"00000000-0000-4000-8000-000000000003","completion_receipt_sha256":"b".repeat(64)})
}

type Reply = (axum::http::StatusCode, Json<Value>);
fn status(code: u16, body: Value) -> Reply { (axum::http::StatusCode::from_u16(code).unwrap(), Json(body)) }

impl Owner {
    fn complete_one(&self, body: &Value) -> Result<Value, Reply> {
        assert_eq!(body["object"]["writer_authority_sha256"], body["identity"]["owner_reservation_sha256"]);
        let refused = { let mut left = self.refuse_completes.lock().unwrap(); let refused = *left > 0; *left = left.saturating_sub(1); refused };
        if refused {
            return Err(status(409, json!({"error":"writer_request_conflict"})));
        }
        self.events.lock().unwrap().push(format!("complete {}", body["request"]["object_key"].as_str().unwrap()));
        Ok(receipt_for(body))
    }
}

async fn authorize(State(owner): State<Arc<Owner>>, Json(request): Json<Value>) -> Reply {
    owner.single_authorize.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(owner.authorize_latency).await;
    if owner.refuse_authorize_of.is_some_and(|needle| request["object_key"].as_str().unwrap().contains(needle)) {
        return status(409, json!({"error":"writer_request_conflict"}));
    }
    status(200, identity_for(&request))
}

async fn complete(State(owner): State<Arc<Owner>>, Json(body): Json<Value>) -> Reply {
    owner.single_complete.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(owner.complete_latency).await;
    match owner.complete_one(&body) { Ok(receipt) => status(200, receipt), Err(reply) => reply }
}

async fn authorize_batch(State(owner): State<Arc<Owner>>, Json(body): Json<Value>) -> Reply {
    if !owner.serve_batch { return status(404, json!({})); }
    if let Some(code) = owner.batch_status { return status(code, json!({"error":"refused","failed_index":0})); }
    let requests = body["requests"].as_array().unwrap();
    assert!(!requests.is_empty() && requests.len() <= NATIVE_BATCH_MAX_ITEMS);
    assert_eq!(body["schema_version"], 1);
    owner.batch_authorize.fetch_add(1, Ordering::SeqCst);
    owner.batch_objects.fetch_add(requests.len(), Ordering::SeqCst);
    // The owner runs four items at a time: one wave for <= 4 objects.
    tokio::time::sleep(owner.authorize_latency).await;
    status(200, json!({"schema_version":1,"identities":requests.iter().map(identity_for).collect::<Vec<_>>()}))
}

async fn complete_batch(State(owner): State<Arc<Owner>>, Json(body): Json<Value>) -> Reply {
    if !owner.serve_batch { return status(404, json!({})); }
    if let Some(code) = owner.batch_status { return status(code, json!({"error":"refused","failed_index":0})); }
    let completions = body["completions"].as_array().unwrap();
    assert!(!completions.is_empty() && completions.len() <= NATIVE_BATCH_MAX_ITEMS);
    owner.batch_complete.fetch_add(1, Ordering::SeqCst);
    owner.batch_objects.fetch_add(completions.len(), Ordering::SeqCst);
    tokio::time::sleep(owner.complete_latency).await;
    let mut receipts = Vec::new();
    for (index, completion) in completions.iter().enumerate() {
        match owner.complete_one(completion) {
            Ok(receipt) => receipts.push(receipt),
            Err((code, Json(mut error))) => { error["failed_index"] = json!(index); return (code, Json(error)); }
        }
    }
    status(200, json!({"schema_version":1,"receipts":receipts}))
}

struct Harness {
    store: R2PartStore,
    owner: Arc<Owner>,
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Harness {
    fn drop(&mut self) { for task in &self.tasks { task.abort(); } }
}
impl Harness {
    fn writer(&self) -> &NativePartWriter { self.store.native_writer_for_tests() }
    fn events(&self) -> Vec<String> { self.owner.events.lock().unwrap().clone() }
}

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    (origin, tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); }))
}

/// How a test's writer is set up (production defaults otherwise).
#[derive(Clone, Copy)]
struct Setup {
    /// The pre-NAN-4592 write path (the throughput baseline).
    legacy: bool,
    /// Tenant EPS for the owner pacer (`with_ingest_eps`, as `cell.rs`).
    eps: f64,
    /// Gathering window; wider than production where a test needs its
    /// concurrent writes to be exactly one batch.
    window: Duration,
    put_latency: Duration,
    /// NAN-4713: extra PUT latency in [0, put_jitter), fixed per key (objects of
    /// different sizes land at different times, as on R2).
    put_jitter: Duration,
    /// NAN-4713: the completion hold cap (production unless a test needs it
    /// out of reach).
    hold: Duration,
}
const CORRECTNESS: Setup = Setup { legacy: false, eps: 500.0, window: Duration::from_millis(50), put_latency: Duration::ZERO, put_jitter: Duration::ZERO, hold: COMPLETION_HOLD_MAX };

/// The production write path: `NativePartWriter::new` (paced from the
/// tenant's EPS) bound into `R2PartStore::new_split`, exactly as `cell.rs`.
async fn harness(owner: Owner, setup: Setup) -> Harness {
    let Setup { legacy, eps, window, put_latency, put_jitter, hold } = setup;
    let owner = Arc::new(owner);
    let routes = Router::new()
        .route("/internal/v1/enterprise-shared/lake-writers:authorize", post(authorize))
        .route("/internal/v1/enterprise-shared/lake-writers:complete", post(complete))
        .route(NATIVE_AUTHORIZE_BATCH_PATH, post(authorize_batch))
        .route(NATIVE_COMPLETE_BATCH_PATH, post(complete_batch))
        .with_state(owner.clone());
    let (origin, owner_task) = serve(routes).await;
    let events = owner.events.clone();
    let r2 = Router::new().route("/{*path}", put(move |axum::extract::Path(path): axum::extract::Path<String>| {
        let events = events.clone();
        async move {
            let spread = u32::from(Sha256::digest(path.as_bytes())[0]) * 100 / 256;
            tokio::time::sleep(put_latency + put_jitter * spread / 100).await;
            events.lock().unwrap().push(format!("put {}", path.trim_start_matches(&format!("{BUCKET}/"))));
            (axum::http::StatusCode::OK, [("etag", format!("\"{}\"", hex::encode(&Sha256::digest(path.as_bytes())[..16])))], "")
        }
    }));
    let (r2_origin, r2_task) = serve(r2).await;
    let dir = tempfile::tempdir().unwrap();
    let permission: WritePermission = serde_json::from_value(json!({"token":"test-only-token",
        "audience":"owner","scope":"lake-parts:write","tenantId":T,"tenantKey":"logical-tenant",
        "cellId":"cell","principalId":"principal","role":"ingest",
        "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()})).unwrap();
    let mut writer = NativePartWriter::new(&origin, None, T, "cell", BUCKET, permission, dir.path()).unwrap()
        .with_ingest_eps(eps).unwrap()
        .with_unavailable_retry_window(Duration::ZERO)
        .with_coalesce_window(window)
        .with_completion_hold(hold);
    if legacy {
        writer = writer.with_synchronous_completion();
    }
    let location = |key: &str| S3Location { endpoint: r2_origin.clone(), region: "auto".into(), bucket: BUCKET.into(),
        prefix: String::new(), access_key_id: key.into(), secret_access_key: "s".into(), session_token: Some("t".into()) };
    let store = R2PartStore::new_split(&location("part"), &location("log"), T, &dir.path().join("spill")).unwrap()
        .with_native_writer(Arc::new(writer)).unwrap();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    Harness { store, owner, _dir: dir, tasks: vec![owner_task, r2_task] }
}

fn root() -> String { format!("lake/parts/v1/tenant={T}/") }
fn part_hints() -> WriteHints { WriteHints { class: WriterClass::LakePart, event_hour: 1, min_time_ms: 3_600_000, max_time_ms: 3_600_001 } }
fn log_hints() -> WriteHints { WriteHints { class: WriterClass::LakePartLog, ..part_hints() } }
fn data_key(flush: usize, file: usize) -> String { format!("{}parts/l0/1970/01/01/01/p{flush}/data-{file:05}.parquet", root()) }
fn provenance_key(flush: usize) -> String { format!("{}parts/l0/1970/01/01/01/p{flush}/provenance.json", root()) }
fn entry_key(seq: usize) -> String { format!("{}log/entries/{seq:020}.json", root()) }

/// One large-tenant ingest flush on the native write path, stage by stage as
/// `publish_parts` + the part-log append run it: the part's data files
/// together, then its signed provenance, then the log entry naming them.
async fn flush(store: &R2PartStore, n: usize, files: usize) {
    let writes = (0..files).map(|file| async move {
        store.put_if_absent_with(&data_key(n, file), format!("data {n} {file}").as_bytes(), &part_hints()).await
    });
    for written in futures::future::join_all(writes).await { assert!(written.unwrap()); }
    assert!(store.put_if_absent_with(&provenance_key(n), format!("provenance {n}").as_bytes(), &part_hints()).await.unwrap());
    assert!(store.put_if_absent_with(&entry_key(n + 1), format!("entry {n}").as_bytes(), &log_hints()).await.unwrap());
}

/// `files` data files of flush `n`, written together (as one publication).
async fn write_parts(store: &R2PartStore, n: usize, files: usize) -> Vec<Result<bool>> {
    futures::future::join_all((0..files).map(|file| async move {
        store.put_if_absent_with(&data_key(n, file), b"data", &part_hints()).await
    })).await
}

fn index_of(events: &[String], event: &str) -> usize {
    events.iter().position(|seen| seen == event).unwrap_or_else(|| panic!("{event} never happened: {events:#?}"))
}

/// A part object's write returns once its PUT evidence is journaled; its
/// owner completion is write-behind. The log entry that names it is never
/// PUT before every one of those completions registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn part_completions_are_write_behind_and_the_log_entry_waits_for_them() {
    let h = harness(Owner { complete_latency: Duration::from_millis(1_500), ..Default::default() }, CORRECTNESS).await;
    let started = std::time::Instant::now();
    let results = write_parts(&h.store, 0, 3).await;
    for written in results { assert!(written.unwrap()); }
    assert!(started.elapsed() < Duration::from_millis(1_000), "part writes do not wait for owner completion");
    assert_eq!(h.writer().diagnostics()["completion_deferred_total"], 3);
    assert!(h.writer().diagnostics()["completion_outstanding"].as_u64().unwrap() > 0);
    assert!(h.store.put_if_absent_with(&entry_key(1), b"entry", &log_hints()).await.unwrap());
    let events = h.events();
    let entry_put = index_of(&events, &format!("put {}", entry_key(1)));
    for file in 0..3 {
        assert!(index_of(&events, &format!("complete {}", data_key(0, file))) < entry_put,
            "the log entry landed before part {file} was registered: {events:#?}");
    }
    assert!(index_of(&events, &format!("complete {}", entry_key(1))) > entry_put, "the entry itself completes on its write");
    assert_eq!(h.writer().diagnostics()["completion_outstanding"], 0);
    // Every completion is archived: nothing is left for a replay.
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/registered")).unwrap().count(), 4);
    assert_eq!(h.writer().diagnostics()["timings"]["completion_barrier_wait"]["finished_total"], 1);
}

/// A write-behind completion the owner refuses fails the next part-log
/// write closed (nothing is PUT), and the journal's replay registers it
/// before the retried write lands: the same outcome a failed synchronous
/// completion had, one flush retry later.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_write_behind_completion_fails_the_log_write_closed_and_replays() {
    let h = harness(Owner { complete_latency: Duration::from_millis(200), refuse_completes: Mutex::new(1),
        ..Default::default() }, CORRECTNESS).await;
    assert!(h.store.put_if_absent_with(&data_key(0, 0), b"data", &part_hints()).await.unwrap());
    // The entry's write passes its replay check before the completion is
    // refused, so its barrier reports the refusal.
    let error = h.store.put_if_absent_with(&entry_key(1), b"entry", &log_hints()).await.unwrap_err();
    assert_eq!(error.downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(409), "{error:#}");
    assert!(format!("{error:#}").contains("write-behind part completion failed"));
    assert!(!h.events().iter().any(|event| event == &format!("put {}", entry_key(1))), "nothing named the part");
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 1,
        "the part's PUT evidence stays journaled; the refused entry journaled nothing");
    // The retry replays the part's completion first, then the entry lands.
    assert!(h.store.put_if_absent_with(&entry_key(1), b"entry", &log_hints()).await.unwrap());
    let events = h.events();
    assert!(index_of(&events, &format!("complete {}", data_key(0, 0))) < index_of(&events, &format!("put {}", entry_key(1))));
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
    assert_eq!(h.owner.single_authorize.load(Ordering::SeqCst), 3,
        "the entry re-asks its (idempotent) authorization; the stored part is never re-authorized");
    assert_eq!(h.events().iter().filter(|event| event.starts_with("put ")).count(), 2, "one PUT each");
}

/// A refusal that lands before the next log write starts is replayed by
/// that write's own journal check: the write simply succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_completion_refused_before_the_log_write_is_replayed_by_it() {
    let h = harness(Owner { refuse_completes: Mutex::new(1), ..Default::default() }, CORRECTNESS).await;
    assert!(h.store.put_if_absent_with(&data_key(0, 0), b"data", &part_hints()).await.unwrap());
    tokio::time::timeout(Duration::from_secs(5), h.writer().lane.idle()).await.unwrap();
    assert!(h.writer().needs_replay.load(Ordering::SeqCst));
    assert!(h.store.put_if_absent_with(&entry_key(1), b"entry", &log_hints()).await.unwrap());
    assert_eq!(h.owner.single_complete.load(Ordering::SeqCst), 3, "refused, replayed, entry");
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
}

/// A retried write of a part whose write-behind completion is still in
/// flight waits for it, then finds it registered: one completion, no PUT.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retried_part_write_waits_for_its_own_write_behind_completion() {
    let h = harness(Owner { complete_latency: Duration::from_millis(200), ..Default::default() }, CORRECTNESS).await;
    assert!(h.store.put_if_absent_with(&data_key(0, 0), b"data", &part_hints()).await.unwrap());
    assert!(h.store.put_if_absent_with(&data_key(0, 0), b"data", &part_hints()).await.unwrap());
    assert_eq!(h.owner.single_complete.load(Ordering::SeqCst), 1);
    assert_eq!(h.events().iter().filter(|event| event.starts_with("put ")).count(), 1);
}

/// Part objects written together reach the owner as one batch each way
/// (at most NATIVE_BATCH_MAX_ITEMS objects per call, several calls at once).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn part_objects_written_together_share_batch_calls() {
    let h = harness(Owner { serve_batch: true, ..Default::default() }, CORRECTNESS).await;
    flush(&h.store, 0, 3).await;
    assert_eq!(h.owner.batch_authorize.load(Ordering::SeqCst), 1, "three data files: one authorize call");
    assert_eq!(h.owner.batch_complete.load(Ordering::SeqCst), 1, "and one completion call");
    // The provenance and the log entry authorize alone (each is written after
    // the one before it). The provenance's completion is held until the
    // entry's barrier and rides the data files' batch; only the entry, which
    // the log waits on, completes alone.
    assert_eq!(h.owner.single_authorize.load(Ordering::SeqCst), 2);
    assert_eq!(h.owner.single_complete.load(Ordering::SeqCst), 1);
    // A wide catch-up flush: 10 files go out as 4 + 4 + 2.
    let results = write_parts(&h.store, 1, 10).await;
    for written in results { assert!(written.unwrap()); }
    tokio::time::timeout(Duration::from_secs(5), h.writer().lane.idle()).await.unwrap();
    assert_eq!(h.owner.batch_authorize.load(Ordering::SeqCst), 4);
    assert_eq!(h.owner.batch_complete.load(Ordering::SeqCst), 4);
    // The first flush's completion batch carried the provenance too (3 + 1).
    assert_eq!(h.owner.batch_objects.load(Ordering::SeqCst), 3 + 4 + 10 + 10);
    let diagnostics = h.writer().diagnostics();
    assert_eq!(diagnostics["authorize_batch_objects_total"], 13);
    assert_eq!(diagnostics["complete_batch_objects_total"], 14);
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/registered")).unwrap().count(), 15);
}

/// The deployed owner (no batch routes yet): the first batch 404s, the
/// objects use the single routes, and the writer stops asking for a while.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_without_batch_routes_gets_single_calls_and_is_not_reasked() {
    for unserved in [404, 401] {
        // A 5 ms pacer: the singles' PUTs land inside one completion window.
        let h = harness(Owner { serve_batch: true, batch_status: Some(unserved), ..Default::default() },
            Setup { eps: 32_000.0, ..CORRECTNESS }).await;
        flush(&h.store, 0, 3).await;
        flush(&h.store, 1, 3).await;
        tokio::time::timeout(Duration::from_secs(5), h.writer().lane.idle()).await.unwrap();
        let diagnostics = h.writer().diagnostics();
        assert_eq!(diagnostics["authorize_batch_started_total"], 1, "{unserved}: asked once");
        assert_eq!(diagnostics["complete_batch_started_total"], 1, "{unserved}: asked once");
        assert_eq!(diagnostics["batch_routes"], json!({"authorize_batch_usable": false, "complete_batch_usable": false}));
        assert_eq!(h.owner.single_authorize.load(Ordering::SeqCst), 10);
        assert_eq!(h.owner.single_complete.load(Ordering::SeqCst), 10);
        assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/registered")).unwrap().count(), 10);
    }
}

/// Any other batch refusal is re-asked object by object, so each key gets
/// its exact outcome: the refused key fails, its neighbours are written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_batch_is_reasked_per_object_for_exact_outcomes() {
    let h = harness(Owner { serve_batch: true, batch_status: Some(409), refuse_authorize_of: Some("data-00001"),
        ..Default::default() }, CORRECTNESS).await;
    let results = write_parts(&h.store, 0, 3).await;
    assert!(results[0].as_ref().unwrap() & results[2].as_ref().unwrap());
    let refused = results[1].as_ref().unwrap_err();
    assert_eq!(refused.downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(409));
    assert!(refused.downcast_ref::<crate::parts::part_log::LogKeyHeld>().is_none(), "a part key is never a held log key");
    tokio::time::timeout(Duration::from_secs(5), h.writer().lane.idle()).await.unwrap();
    // The authorize batch fell back; the two written parts' completions
    // also fall back (one batch, or two lone completions when the pacer
    // spaced their PUTs apart). Either way each completes exactly once.
    assert!(h.writer().diagnostics()["batch_fallbacks_total"].as_u64().unwrap() >= 1);
    assert_eq!(h.owner.single_complete.load(Ordering::SeqCst), 2);
    assert_eq!(h.writer().diagnostics()["batch_routes"]["authorize_batch_usable"], true, "a refusal is not an unserved route");
}

/// An owner unavailable through the whole retry window fails every object
/// of the batch with its status (never multiplied into single calls).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unavailable_owner_fails_the_batch_without_fanning_out() {
    let h = harness(Owner { serve_batch: true, batch_status: Some(503), ..Default::default() }, CORRECTNESS).await;
    let results = write_parts(&h.store, 0, 3).await;
    for result in results {
        assert_eq!(result.unwrap_err().downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(503));
    }
    assert_eq!(h.owner.single_authorize.load(Ordering::SeqCst), 0);
    assert_eq!(h.events().len(), 0, "nothing was PUT");
}

// ------------------------------------------------- throughput / convergence

/// The large tenant on FP (10-26): owner authorize p90 2.5 s, complete p90 4.1 s, ~7k
/// rows and 4-5 objects per flush (3 data files, provenance, log entry).
/// Time runs 1/4 of real here (slow enough that scheduler jitter on a busy
/// test host stays small beside the owner latencies); PUT is 0.3 s real.
const SCALE: u32 = 4;
fn large_tenant_p90_owner(serve_batch: bool) -> Owner {
    Owner { serve_batch, authorize_latency: Duration::from_millis(2_500) / SCALE,
        complete_latency: Duration::from_millis(4_100) / SCALE, ..Default::default() }
}
/// The owner pacer scaled with time: `with_ingest_eps` of 12800 is the
/// 12.5 ms interval that is the large tenant's 50 ms at 1/4.
const LARGE: Setup = Setup { legacy: false, eps: 12_800.0, window: lanes_window(), put_latency: Duration::from_millis(300 / SCALE as u64), put_jitter: Duration::ZERO, hold: COMPLETION_HOLD_MAX };
const LEGACY_LARGE: Setup = Setup { legacy: true, ..LARGE };
/// The production gathering window (unscaled: it costs the scaled flush
/// 4x what it costs a real one, so the comparison is conservative).
const fn lanes_window() -> Duration { super::COALESCE_WINDOW }
const LARGE_ROWS_PER_FLUSH: f64 = 7_000.0;
/// The large tenant's arrival rate: the commit rate it could not exceed (rows/s, real).
const LARGE_ARRIVAL_ROWS_PER_S: f64 = 480.0;

/// Mean real-time seconds per flush over `flushes` back-to-back flushes.
async fn seconds_per_flush(h: &Harness, flushes: usize, offset: usize) -> f64 {
    let started = std::time::Instant::now();
    for n in offset..offset + flushes { flush(&h.store, n, 3).await; }
    started.elapsed().as_secs_f64() * f64::from(SCALE) / flushes as f64
}

/// Commits/s headroom at the large tenant's size: at the large tenant's measured owner p90 the
/// pre-NAN-4592 native path (every completion on its write, one owner call
/// per object) alone commits below the large tenant's arrival rate (the growing
/// backlog); the current path takes at least a fifth off every flush and
/// lifts the commit rate by at least a quarter. (The native path is ~60%
/// of the large tenant's 19.8 s median seal-to-commit; prevalence and the shared
/// reservation lock, NAN-4583, are the rest: see the PR for the budget.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_tenant_sized_flushes_commit_with_headroom_over_arrival() {
    let legacy = harness(large_tenant_p90_owner(false), LEGACY_LARGE).await;
    let before = seconds_per_flush(&legacy, 3, 0).await;
    let current = harness(large_tenant_p90_owner(true), LARGE).await;
    let after = seconds_per_flush(&current, 3, 0).await;
    let (rows_before, rows_after) = (LARGE_ROWS_PER_FLUSH / before, LARGE_ROWS_PER_FLUSH / after);
    eprintln!("large-tenant p90 native path: {before:.1} s/flush ({rows_before:.0} rows/s) -> {after:.1} s/flush ({rows_after:.0} rows/s)");
    // Legacy: 3 x (2.5 + 0.3 + 4.1) = 20.7 s per flush, 338 rows/s: below
    // the large tenant's arrival, i.e. its growing backlog. Now: data files 2.8 s, then
    // provenance 2.8 s, then the entry's authorization overlapping the
    // provenance's completion (4.1 s), its PUT and its completion: ~14.1 s.
    assert!(rows_before < LARGE_ARRIVAL_ROWS_PER_S, "the legacy path is the observed bottleneck ({rows_before:.0} rows/s)");
    assert!(after < before * 0.8, "at least a fifth off every flush ({before:.1} -> {after:.1} s)");
    assert!(rows_after > rows_before * 1.25, "commit rate up at least a quarter ({rows_before:.0} -> {rows_after:.0} rows/s)");
    // Five owner calls instead of ten per flush: 3 data files authorize in one
    // batch, provenance and entry authorize alone; the data files' and the
    // provenance's completions drain as one batch at the entry's barrier, and
    // the entry completes alone.
    let calls = |h: &Harness| ["authorize_started_total", "complete_started_total", "authorize_batch_started_total",
        "complete_batch_started_total"].iter().map(|k| h.writer().diagnostics()[*k].as_u64().unwrap()).sum::<u64>();
    assert_eq!(calls(&legacy), 3 * 10);
    assert_eq!(calls(&current), 3 * 5);
}

/// Backlog convergence: the large tenant's backlog (sealed flushes waiting to commit)
/// arrives at the rate the legacy path commits, on top of a standing
/// backlog. The current path drains it to zero within its bound; the
/// legacy path never shrinks it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_tenant_backlog_drains_to_zero_on_the_current_path() {
    // Scaled seconds per flush, measured on each path.
    let legacy = harness(large_tenant_p90_owner(false), LEGACY_LARGE).await;
    let legacy_service = seconds_per_flush(&legacy, 2, 0).await / f64::from(SCALE);
    let current = harness(large_tenant_p90_owner(true), LARGE).await;
    let service = seconds_per_flush(&current, 2, 0).await / f64::from(SCALE);
    // Flushes arrive exactly as fast as the legacy path commits them.
    let arrival = Duration::from_secs_f64(legacy_service);
    let standing = 3_usize;
    let drained = async {
        let (mut backlog, mut committed, mut next_arrival) = (standing, 2_usize, tokio::time::Instant::now() + arrival);
        let started = tokio::time::Instant::now();
        let mut peak = backlog;
        while backlog > 0 {
            flush(&current.store, committed, 3).await;
            committed += 1;
            backlog -= 1;
            while tokio::time::Instant::now() >= next_arrival {
                backlog += 1;
                next_arrival += arrival;
            }
            peak = peak.max(backlog);
            assert!(started.elapsed() < Duration::from_secs(180), "backlog {backlog} never drained");
        }
        (started.elapsed(), peak)
    };
    let (elapsed, peak) = drained.await;
    // Drain rate 1/service - 1/arrival: the standing backlog clears within
    // standing / (1 - service/arrival) service times, plus slack for jitter.
    let bound = standing as f64 * service / (1.0 - service / legacy_service);
    eprintln!("the large-tenant backlog of {standing}: drained in {:.1} s scaled (bound {bound:.1} s), peak {peak}; service {service:.3} s vs arrival {legacy_service:.3} s",
        elapsed.as_secs_f64());
    assert!(service < legacy_service * 0.75, "service {service:.3} s vs arrival {legacy_service:.3} s");
    assert!(elapsed.as_secs_f64() <= bound * 1.5, "drained in {:.1} s, bound {bound:.1} s", elapsed.as_secs_f64());
    assert!(peak <= standing, "the backlog never grew while draining");
    // Every committed flush's objects are registered; none left to replay.
    tokio::time::timeout(Duration::from_secs(5), current.writer().lane.idle()).await.unwrap();
    assert_eq!(std::fs::read_dir(current._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
}

/// NAN-4713: owner calls per object at FP's measured shape. Each flush is 3
/// data files whose PUTs land at different times (size spread), then the
/// signed provenance, then the log entry. Owner latencies are FP's p50
/// (authorize 1.0 s, complete 1.4 s) and PUT 300 ms +0..400 ms, all at 1/SCALE.
/// Prints the call counts so a before/after run can be compared; asserts the
/// floor the tick-drained completion lane guarantees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_calls_per_object_at_fp_shape() {
    let owner = Owner { serve_batch: true, authorize_latency: Duration::from_millis(1_000) / SCALE,
        complete_latency: Duration::from_millis(1_400) / SCALE, ..Default::default() };
    let setup = Setup { legacy: false, eps: 12_800.0, window: lanes_window(),
        put_latency: Duration::from_millis(300) / SCALE, put_jitter: Duration::from_millis(400) / SCALE, hold: COMPLETION_HOLD_MAX };
    let h = harness(owner, setup).await;
    const FLUSHES: usize = 12;
    let started = std::time::Instant::now();
    for n in 0..FLUSHES { flush(&h.store, n, 3).await; }
    let per_flush = started.elapsed().as_secs_f64() * f64::from(SCALE) / FLUSHES as f64;
    let o = &h.owner;
    let (sa, sc, ba, bc, bo) = (o.single_authorize.load(Ordering::SeqCst), o.single_complete.load(Ordering::SeqCst),
        o.batch_authorize.load(Ordering::SeqCst), o.batch_complete.load(Ordering::SeqCst), o.batch_objects.load(Ordering::SeqCst));
    let objects = FLUSHES * 5;
    let calls = sa + sc + ba + bc;
    eprintln!("NAN-4713 fp-shape {FLUSHES} flushes ({objects} objects, {} owner object-ops): authorize single={sa} batch={ba}; \
complete single={sc} batch={bc}; batched objects={bo}; owner calls={calls} ({:.2} per object); {per_flush:.2} s/flush real",
        objects * 2, calls as f64 / objects as f64);
    assert_eq!(sa + sc + bo, objects * 2, "every object authorized and completed exactly once");
    // Per flush: one authorize batch (data files), provenance + entry
    // authorize singly (sequential by construction); the part completions of
    // the flush register in one batch at the entry's barrier, the entry
    // completes singly. 5 calls for 5 objects' 10 owner operations.
    assert!(calls <= FLUSHES * 5 + 2, "owner calls {calls} > {} (tick-drained completions)", FLUSHES * 5 + 2);
    assert!(bc >= FLUSHES - 1, "part completions batch per flush ({bc} batches)");
}

// ------------------------------------------------- NAN-4713 tick-drained lane

fn completed(h: &Harness, key: &str) -> usize {
    h.events().iter().filter(|event| *event == &format!("complete {key}")).count()
}

/// NAN-4713 (mutation guard): part completions held for their tick are
/// drained by the next part-log entry's barrier. The entry is PUT only after
/// the owner acked every one of them, each exactly once, and the barrier never
/// waits out the hold cap. Batch routes served or not (the per-object
/// fallback of an owner without them).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_completions_are_acked_before_the_entry_lands_without_waiting_out_the_hold() {
    // A hold far out of the test's reach: a barrier that did not drain the
    // lane would wait it out.
    const HOLD: Duration = Duration::from_secs(60);
    for serve_batch in [true, false] {
        let h = harness(Owner { serve_batch, complete_latency: Duration::from_millis(300), ..Default::default() },
            Setup { hold: HOLD, ..CORRECTNESS }).await;
        // Two data files and the provenance: below a full batch, so held.
        let results = write_parts(&h.store, 0, 2).await;
        for written in results { assert!(written.unwrap()); }
        assert!(h.store.put_if_absent_with(&provenance_key(0), b"provenance", &part_hints()).await.unwrap());
        assert_eq!(h.writer().lane.outstanding(), 3, "{serve_batch}: held for the tick");
        assert!(!h.events().iter().any(|event| event.starts_with("complete ")), "{serve_batch}: nothing completed yet");
        let started = std::time::Instant::now();
        assert!(h.store.put_if_absent_with(&entry_key(1), b"entry", &log_hints()).await.unwrap());
        assert!(started.elapsed() < Duration::from_secs(15),
            "{serve_batch}: the barrier drains the held completions, never waits out the cap ({:?})", started.elapsed());
        let events = h.events();
        let entry_put = index_of(&events, &format!("put {}", entry_key(1)));
        for key in [data_key(0, 0), data_key(0, 1), provenance_key(0)] {
            assert!(index_of(&events, &format!("complete {key}")) < entry_put,
                "{serve_batch}: the entry landed before {key} was acked: {events:#?}");
            assert_eq!(completed(&h, &key), 1, "{serve_batch}: {key} registered exactly once");
        }
        assert_eq!(h.writer().lane.outstanding(), 0);
        assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/registered")).unwrap().count(), 4);
    }
}

/// NAN-4713: a batch the owner refuses partway (item 0 of 3) is re-asked per
/// object; the entry still lands only after all three are acked, each once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partially_refused_held_batch_falls_back_before_the_entry_lands() {
    let h = harness(Owner { serve_batch: true, refuse_completes: Mutex::new(1), ..Default::default() }, CORRECTNESS).await;
    let results = write_parts(&h.store, 0, 3).await;
    for written in results { assert!(written.unwrap()); }
    assert!(h.store.put_if_absent_with(&entry_key(1), b"entry", &log_hints()).await.unwrap());
    let events = h.events();
    let entry_put = index_of(&events, &format!("put {}", entry_key(1)));
    for file in 0..3 {
        assert!(index_of(&events, &format!("complete {}", data_key(0, file))) < entry_put, "{events:#?}");
        assert_eq!(completed(&h, &data_key(0, file)), 1);
    }
    assert!(h.writer().diagnostics()["batch_fallbacks_total"].as_u64().unwrap() >= 1);
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
}

/// NAN-4713: a held completion that no tick follows is still sent by the
/// hold cap alone (no waiter drives it), and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_completion_no_tick_follows_completes_at_the_hold_cap() {
    let h = harness(Owner::default(), CORRECTNESS).await;
    let started = std::time::Instant::now();
    assert!(h.store.put_if_absent_with(&data_key(0, 0), b"data", &part_hints()).await.unwrap());
    while h.writer().lane.outstanding() > 0 {
        assert!(started.elapsed() < COMPLETION_HOLD_MAX + Duration::from_secs(3), "the hold cap never fired");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(started.elapsed() >= COMPLETION_HOLD_MAX - Duration::from_millis(100), "held until the cap ({:?})", started.elapsed());
    assert_eq!(completed(&h, &data_key(0, 0)), 1);
    assert_eq!(std::fs::read_dir(h._dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
}
