// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4676 (FP-INC-1027): a journaled native intent whose owner completion
//! window closed while the owner could not register it (control DB read-only
//! for 5 h). Every test drives the production write path, as `cell.rs` builds
//! it: `NativePartWriter::new` + `R2PartStore::new_split(..).with_native_writer(..)`
//! + `replay_pending`, against a stateful loopback owner that enforces the
//! real owner's completion rules (`writer-owner-service.ts`
//! `completeNativeCell` / `#complete` / `authorize`) and a loopback R2 that
//! stores objects (PUT if-none-match, GET, HEAD).
use super::*;
use crate::part_ingest::r2_put::R2PartStore;
use crate::part_ingest::s3_store::S3Location;
use crate::parts::part_log::{ObjectStore, WriterClass};
use axum::{extract::State, http::{HeaderMap, StatusCode}, response::IntoResponse, routing::{get, post}, Json, Router};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

const T: &str = "00000000-0000-4000-8000-000000000001";
const BUCKET: &str = "nano-shared-r2-t";

type Objects = Arc<Mutex<BTreeMap<String, (Vec<u8>, String)>>>;

struct Claim {
    identity: Value,
    revision: u64,
    receipt: Option<Value>,
}

/// The owner's native-cell contract, as far as this incident needs it.
struct Owner {
    /// The control DB is read-only: every owner route answers 503.
    authorize_unavailable: AtomicBool,
    complete_unavailable: AtomicBool,
    /// Completion window of a fresh reservation (70 min in production).
    window: chrono::Duration,
    /// The renewal is refused (e.g. 9000123's renewal limit).
    refuse_renewal: bool,
    /// Refuse every completion with 409 although its window is open.
    conflict_completes: bool,
    /// An owner that predates stale-attempt renewal: `stale_recovery` is
    /// ignored and the closed window's historical identity comes back.
    ignore_renewal: bool,
    claims: Mutex<HashMap<String, Claim>>,
    /// Registered copy-registry rows, one per completed object.
    registered: Mutex<Vec<String>>,
    authorize_calls: AtomicUsize,
    renewal_calls: AtomicUsize,
    complete_calls: AtomicUsize,
    objects: Objects,
}

fn hex64(seed: &str) -> String { hex::encode(Sha256::digest(seed.as_bytes())) }
type Reply = (StatusCode, Json<Value>);
fn reply(code: u16, body: Value) -> Reply { (StatusCode::from_u16(code).unwrap(), Json(body)) }
fn deadline(identity: &Value) -> chrono::DateTime<Utc> {
    chrono::DateTime::parse_from_rfc3339(identity["completion_deadline_at"].as_str().unwrap()).unwrap().with_timezone(&Utc)
}

impl Owner {
    fn new(window: chrono::Duration) -> Self {
        Self { authorize_unavailable: AtomicBool::new(false), complete_unavailable: AtomicBool::new(false), window,
            refuse_renewal: false, conflict_completes: false, ignore_renewal: false, claims: Mutex::default(), registered: Mutex::default(),
            authorize_calls: AtomicUsize::new(0), renewal_calls: AtomicUsize::new(0), complete_calls: AtomicUsize::new(0),
            objects: Objects::default() }
    }
    fn identity(request: &Value, revision: u64, completion_deadline: chrono::DateTime<Utc>) -> Value {
        let mut identity = request.clone();
        let rid = request["request_id"].as_str().unwrap();
        identity["schema_version"] = json!(3);
        identity["tenant_uuid"] = json!(T);
        identity["bucket"] = request["object_bucket"].clone();
        identity["key"] = request["object_key"].clone();
        identity["sha256"] = request["content_sha256"].clone();
        identity["authorization_attempt_revision"] = json!(revision);
        identity["authorization_expires_at"] = json!((Utc::now() + chrono::Duration::minutes(4)).to_rfc3339());
        identity["completion_deadline_at"] = json!(completion_deadline.to_rfc3339_opts(SecondsFormat::Millis, true));
        // The stable writer identity binds the effective deadline (9000123).
        identity["writer_identity_sha256"] = json!(hex64(&format!("identity {rid} {}", identity["completion_deadline_at"])));
        identity["owner_reservation_sha256"] = json!(hex64(&format!("reservation {rid} {revision}")));
        identity["deletion_unit_id"] = json!("00000000-0000-4000-8000-000000000001");
        identity
    }
}

async fn authorize(State(owner): State<Arc<Owner>>, Json(mut request): Json<Value>) -> Reply {
    owner.authorize_calls.fetch_add(1, Ordering::SeqCst);
    if owner.authorize_unavailable.load(Ordering::SeqCst) { return reply(503, json!({"error":"writer_owner_unavailable"})); }
    // The owner strips the instruction before digesting the request.
    let renew = request.as_object_mut().unwrap().remove("stale_recovery") == Some(json!("renew"));
    if renew { owner.renewal_calls.fetch_add(1, Ordering::SeqCst); }
    let rid = request["request_id"].as_str().unwrap().to_string();
    let mut claims = owner.claims.lock().unwrap();
    let Some(claim) = claims.get_mut(&rid) else {
        let identity = Owner::identity(&request, 1, Utc::now() + owner.window);
        claims.insert(rid, Claim { identity: identity.clone(), revision: 1, receipt: None });
        return reply(200, identity);
    };
    if claim.receipt.is_some() || deadline(&claim.identity) > Utc::now() {
        return reply(200, claim.identity.clone());
    }
    if !renew || owner.ignore_renewal {
        // A closed window without renewal: the exact historical identity.
        return reply(200, claim.identity.clone());
    }
    if owner.refuse_renewal {
        return reply(409, json!({"error":"writer_request_conflict"}));
    }
    claim.revision += 1;
    claim.identity = Owner::identity(&request, claim.revision, Utc::now() + owner.window);
    reply(200, claim.identity.clone())
}

async fn complete(State(owner): State<Arc<Owner>>, Json(body): Json<Value>) -> Reply {
    owner.complete_calls.fetch_add(1, Ordering::SeqCst);
    if owner.complete_unavailable.load(Ordering::SeqCst) { return reply(503, json!({"error":"writer_owner_unavailable"})); }
    let conflict = || reply(409, json!({"error":"writer_request_conflict"}));
    let rid = body["request"]["request_id"].as_str().unwrap().to_string();
    let mut claims = owner.claims.lock().unwrap();
    let Some(claim) = claims.get_mut(&rid) else { return conflict() };
    // completeNativeCell: the signed pre-PUT authority is the current one.
    if body["identity"]["writer_identity_sha256"] != claim.identity["writer_identity_sha256"]
        || body["identity"]["owner_reservation_sha256"] != body["object"]["writer_authority_sha256"] {
        return conflict();
    }
    if let Some(receipt) = &claim.receipt { return reply(200, receipt.clone()); }
    // #complete: "completion differs from the stable owner-authorized writer".
    if owner.conflict_completes || deadline(&body["identity"]) <= Utc::now() { return conflict(); }
    // Provider HEAD: the stored object is exactly the journaled evidence.
    let path = format!("{BUCKET}/{}", body["request"]["object_key"].as_str().unwrap());
    match owner.objects.lock().unwrap().get(&path) {
        Some((bytes, etag)) if json!(etag) == body["object"]["etag"]
            && json!(hex::encode(Sha256::digest(bytes))) == body["request"]["content_sha256"] => {}
        _ => return conflict(),
    }
    let receipt = json!({"schema_version":1,"status":"registered","request_id":rid,
        "deletion_unit_id":body["identity"]["deletion_unit_id"],
        "completion_receipt_id":"00000000-0000-4000-8000-000000000002",
        "artifact_id":"00000000-0000-4000-8000-000000000003","completion_receipt_sha256":"b".repeat(64)});
    claim.receipt = Some(receipt.clone());
    owner.registered.lock().unwrap().push(body["request"]["object_key"].as_str().unwrap().to_string());
    reply(200, receipt)
}

async fn serve(router: Router) -> (String, std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    (format!("http://{addr}"), addr, tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); }))
}

struct Harness {
    owner: Arc<Owner>,
    owner_origin: String,
    r2_origin: String,
    puts: Arc<AtomicUsize>,
    dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Harness {
    fn drop(&mut self) { for task in &self.tasks { task.abort(); } }
}

async fn harness(owner: Owner) -> Harness {
    let owner = Arc::new(owner);
    let routes = Router::new()
        .route("/internal/v1/enterprise-shared/lake-writers:authorize", post(authorize))
        .route("/internal/v1/enterprise-shared/lake-writers:complete", post(complete))
        .with_state(owner.clone());
    let (owner_origin, _, owner_task) = serve(routes).await;
    let puts = Arc::new(AtomicUsize::new(0));
    let state = (owner.objects.clone(), puts.clone());
    let r2 = Router::new().route("/{bucket}/{*key}", get(|State((objects, _)): State<(Objects, Arc<AtomicUsize>)>,
        axum::extract::Path((bucket, key)): axum::extract::Path<(String, String)>| async move {
        match objects.lock().unwrap().get(&format!("{bucket}/{key}")) {
            Some((bytes, etag)) => ([("etag", etag.clone())], bytes.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, "<Error><Code>NoSuchKey</Code></Error>").into_response(),
        }
    }).put(|State((objects, puts)): State<(Objects, Arc<AtomicUsize>)>,
        axum::extract::Path((bucket, key)): axum::extract::Path<(String, String)>, headers: HeaderMap, body: axum::body::Bytes| async move {
        assert_eq!(headers["if-none-match"], "*");
        puts.fetch_add(1, Ordering::SeqCst);
        let mut objects = objects.lock().unwrap();
        let path = format!("{bucket}/{key}");
        if objects.contains_key(&path) {
            return (StatusCode::PRECONDITION_FAILED, "<Error><Code>PreconditionFailed</Code></Error>").into_response();
        }
        let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
        objects.insert(path, (body.to_vec(), etag.clone()));
        (StatusCode::OK, [("etag", etag)]).into_response()
    })).with_state(state);
    let (r2_origin, _, r2_task) = serve(r2).await;
    Harness { owner, owner_origin, r2_origin, puts, dir: tempfile::tempdir().unwrap(), tasks: vec![owner_task, r2_task] }
}

impl Harness {
    /// One cell process: the production writer and store over the same
    /// state directory (a restart is simply a second call).
    fn process(&self) -> R2PartStore {
        let permission: WritePermission = serde_json::from_value(json!({"token":"test-only-token",
            "audience":"owner","scope":"lake-parts:write","tenantId":T,"tenantKey":"logical-tenant",
            "cellId":"cell","principalId":"principal","role":"ingest",
            "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()})).unwrap();
        let writer = NativePartWriter::new(&self.owner_origin, None, T, "cell", BUCKET, permission, self.dir.path()).unwrap()
            .with_ingest_eps(500.0).unwrap()
            .with_unavailable_retry_window(Duration::ZERO);
        let location = |key: &str| S3Location { endpoint: self.r2_origin.clone(), region: "auto".into(), bucket: BUCKET.into(),
            prefix: String::new(), access_key_id: key.into(), secret_access_key: "s".into(), session_token: Some("t".into()) };
        R2PartStore::new_split(&location("part"), &location("log"), T, &self.dir.path().join("spill")).unwrap()
            .with_native_writer(Arc::new(writer)).unwrap()
    }
    fn journal(&self, sub: &str) -> Vec<PathBuf> {
        let mut paths = std::fs::read_dir(self.dir.path().join("native-writer-receipts").join(sub)).unwrap()
            .map(|entry| entry.unwrap().path()).collect::<Vec<_>>();
        paths.sort();
        paths
    }
    fn registered(&self, key: &str) -> usize {
        self.owner.registered.lock().unwrap().iter().filter(|registered| *registered == key).count()
    }
    /// FP-INC-1027: the control DB goes read-only (both owner routes 503).
    fn outage(&self, read_only: bool) {
        self.owner.authorize_unavailable.store(read_only, Ordering::SeqCst);
        self.owner.complete_unavailable.store(read_only, Ordering::SeqCst);
    }
}

fn root() -> String { format!("lake/parts/v1/tenant={T}/") }
fn part_key(part: &str) -> String { format!("{}parts/l0/1970/01/01/01/{part}/data-00000.parquet", root()) }
fn entry_key(seq: usize) -> String { format!("{}log/entries/{seq:020}.json", root()) }
fn hints(class: WriterClass) -> WriteHints { WriteHints { class, event_hour: 1, min_time_ms: 3_600_000, max_time_ms: 3_600_001 } }
fn read_json(path: &Path) -> Value { serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap() }

/// Write `key` while the owner's completion is unavailable: the PUT lands
/// and its evidence is journaled, the completion is not registered.
async fn write_through_completion_outage(h: &Harness, store: &R2PartStore, key: &str, class: WriterClass) {
    h.owner.complete_unavailable.store(true, Ordering::SeqCst);
    let written = store.put_if_absent_with(key, b"payload", &hints(class)).await;
    match class {
        // Write-behind (NAN-4592): the write returns, its completion fails.
        WriterClass::LakePart => {
            assert!(written.unwrap());
            let writer = store.native_writer_for_tests();
            tokio::time::timeout(Duration::from_secs(5), writer.write_behind_idle_for_tests()).await.unwrap();
            assert!(writer.needs_replay.load(Ordering::SeqCst));
        }
        WriterClass::LakePartLog => {
            assert_eq!(written.unwrap_err().downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(503));
        }
    }
    assert_eq!(h.journal("pending").len(), 1, "the PUT evidence is journaled");
    assert_eq!(h.registered(key), 0);
}

/// The incident end to end, for a part object and for a part-log entry:
/// owner outage → completion deadline expires → owner back → the restarted
/// cell's replay (the call that crash-looped tzd every ~65 s) renews the
/// exact request and registers the already-landed object once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_intent_after_owner_outage_is_renewed_and_registered_once() {
    for (key, class) in [(part_key("p0"), WriterClass::LakePart), (entry_key(1), WriterClass::LakePartLog)] {
        let h = harness(Owner::new(chrono::Duration::milliseconds(1_500))).await;
        let store = h.process();
        store.native_writer_for_tests().replay_pending().await.unwrap();
        write_through_completion_outage(&h, &store, &key, class).await;
        // The whole control DB is read-only: replays fail and retry.
        h.outage(true);
        assert!(store.native_writer_for_tests().replay_pending().await.is_err());
        tokio::time::sleep(Duration::from_millis(1_700)).await;
        let pending = h.journal("pending");
        assert!(completion_window_closed(&read_json(&pending[0])["identity"]), "the window closed during the outage");
        // Owner recovers. Cell restart (crash loop shape): open + replay.
        h.outage(false);
        drop(store);
        let store = h.process();
        store.native_writer_for_tests().replay_pending().await.expect("replay recovers instead of crash-looping");

        assert_eq!(h.registered(&key), 1, "{key}: registered exactly once");
        assert_eq!(h.owner.renewal_calls.load(Ordering::SeqCst), 1);
        assert_eq!(h.puts.load(Ordering::SeqCst), 1, "never re-PUT");
        assert!(h.journal("pending").is_empty());
        let registered = h.journal("registered");
        assert_eq!(registered.len(), 1);
        let archived = read_json(&registered[0]);
        assert_eq!(archived["identity"]["authorization_attempt_revision"], 2, "a fresh owner-authorized identity");
        assert_eq!(archived["object"]["writer_authority_sha256"], archived["identity"]["owner_reservation_sha256"]);
        // The refused intent is quarantined with its evidence and the refusal.
        let quarantined = h.journal("quarantined");
        assert_eq!(quarantined.len(), 1);
        let evidence = read_json(&quarantined[0]);
        assert!(quarantined[0].file_name().unwrap().to_str().unwrap().contains(".superseded."));
        assert_eq!(evidence["owner_status"], 409);
        assert_eq!(evidence["intent"]["identity"]["authorization_attempt_revision"], 1);
        assert_eq!(evidence["intent"]["object"]["etag"], archived["object"]["etag"], "the same landed object");
        assert!(evidence["intent"]["registered"].is_null());
        assert!(!std::fs::read_to_string(&quarantined[0]).unwrap().contains("test-only-token"));
        assert_eq!(store.native_writer_for_tests().diagnostics()["expired_intent_renewed_total"], 1);

        // Replay again, and retry the original write: idempotent, no new rows.
        let completes = h.owner.complete_calls.load(Ordering::SeqCst);
        store.native_writer_for_tests().replay_pending().await.unwrap();
        assert!(store.put_if_absent_with(&key, b"payload", &hints(class)).await.unwrap());
        assert_eq!(h.owner.complete_calls.load(Ordering::SeqCst), completes, "archived: no owner call");
        assert_eq!(h.registered(&key), 1);
        assert_eq!(h.puts.load(Ordering::SeqCst), 1);
    }
}

/// The same expiry reached on the live write path (no restart): the next
/// write's replay renews it, and the write proceeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_next_write_replays_and_renews_an_expired_part_completion() {
    let h = harness(Owner::new(chrono::Duration::milliseconds(800))).await;
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    write_through_completion_outage(&h, &store, &part_key("p0"), WriterClass::LakePart).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    h.owner.complete_unavailable.store(false, Ordering::SeqCst);
    assert!(store.put_if_absent_with(&entry_key(1), b"entry", &hints(WriterClass::LakePartLog)).await.unwrap());
    assert_eq!(h.registered(&part_key("p0")), 1);
    assert_eq!(h.registered(&entry_key(1)), 1);
    assert!(h.journal("pending").is_empty());
}

/// When the owner will not renew (its renewal limit), a part object is
/// quarantined instead of holding every later write (and every cell start)
/// hostage; the same key reports its outcome unresolved, so ingest rebuilds
/// the unpublished part under a new part ID — registered once, never twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unrenewable_expired_part_is_quarantined_and_rebuilt_under_a_new_part() {
    let h = harness(Owner { refuse_renewal: true, ..Owner::new(chrono::Duration::milliseconds(800)) }).await;
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    let old = part_key("p-old");
    write_through_completion_outage(&h, &store, &old, WriterClass::LakePart).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    h.owner.complete_unavailable.store(false, Ordering::SeqCst);
    drop(store);
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.expect("an unrenewable part never blocks the cell");
    assert!(h.journal("pending").is_empty());
    let quarantined = h.journal("quarantined");
    let abandoned = quarantined.iter().find(|path| path.to_str().unwrap().ends_with(".abandoned.json")).expect("abandoned evidence");
    assert_eq!(read_json(abandoned)["owner_status"], 409);
    assert_eq!(read_json(abandoned)["intent"]["object"]["etag"].as_str().map(|etag| etag.len()), Some(34));
    assert_eq!(store.native_writer_for_tests().diagnostics()["expired_intent_abandoned_total"], 1);
    // A retried publication of that part: unresolved, never re-authorized
    // or re-PUT, so `rebuild_unresolved_publication` rebuilds the hour.
    let authorizations = h.owner.authorize_calls.load(Ordering::SeqCst);
    let error = store.put_if_absent_with(&old, b"payload", &hints(WriterClass::LakePart)).await.unwrap_err();
    assert_eq!(error.downcast_ref::<NativePutUnresolved>().map(|unresolved| unresolved.key.as_str()), Some(old.as_str()));
    assert_eq!(h.owner.authorize_calls.load(Ordering::SeqCst), authorizations);
    assert_eq!(h.puts.load(Ordering::SeqCst), 1);
    // The rebuilt part (new part ID) and the entry naming it land normally.
    let rebuilt = part_key("p-rebuilt");
    assert!(store.put_if_absent_with(&rebuilt, b"payload", &hints(WriterClass::LakePart)).await.unwrap());
    assert!(store.put_if_absent_with(&entry_key(1), b"entry", &hints(WriterClass::LakePartLog)).await.unwrap());
    assert_eq!(h.registered(&old), 0, "the abandoned object is never registered");
    assert_eq!(h.registered(&rebuilt), 1, "the rows are registered exactly once");
    assert_eq!(h.registered(&entry_key(1)), 1);
}

/// A part-log entry is never abandoned (its deterministic key may already be
/// named by the log): an unrenewable one stays pending and fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unrenewable_expired_log_entry_stays_pending_and_fails_closed() {
    let h = harness(Owner { refuse_renewal: true, ..Owner::new(chrono::Duration::milliseconds(800)) }).await;
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    write_through_completion_outage(&h, &store, &entry_key(1), WriterClass::LakePartLog).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    h.owner.complete_unavailable.store(false, Ordering::SeqCst);
    let error = h.process().native_writer_for_tests().replay_pending().await.unwrap_err();
    assert_eq!(error.chain().find_map(|cause| cause.downcast_ref::<OwnerRefused>()).map(|refused| refused.status), Some(409));
    assert_eq!(h.journal("pending").len(), 1, "the entry's evidence stays pending");
    assert!(h.journal("quarantined").iter().all(|path| !path.to_str().unwrap().ends_with(".abandoned.json")));
    assert_eq!(h.registered(&entry_key(1)), 0);
}

/// A renewal that does not open a fresh window (an owner that ignores
/// `stale_recovery`) is refused locally: the original intent and its PUT
/// evidence stay pending untouched, and the expired identity is never
/// presented for completion again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_without_a_fresh_window_keeps_the_original_intent_pending() {
    let h = harness(Owner { ignore_renewal: true, ..Owner::new(chrono::Duration::milliseconds(800)) }).await;
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    write_through_completion_outage(&h, &store, &part_key("p0"), WriterClass::LakePart).await;
    let before = std::fs::read(&h.journal("pending")[0]).unwrap();
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    h.owner.complete_unavailable.store(false, Ordering::SeqCst);
    let completes = h.owner.complete_calls.load(Ordering::SeqCst);
    let error = h.process().native_writer_for_tests().replay_pending().await.unwrap_err();
    assert!(format!("{error:#}").contains("did not open a fresh window"), "{error:#}");
    assert_eq!(h.owner.renewal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(h.owner.complete_calls.load(Ordering::SeqCst), completes + 1, "only the refused replay; no completion under the stale identity");
    assert_eq!(std::fs::read(&h.journal("pending")[0]).unwrap(), before, "the original intent is untouched");
    assert_eq!(h.registered(&part_key("p0")), 0);
}

/// The completion answers the expired 409 but the renewal itself is
/// unavailable (503, e.g. the control DB still read-only): every replay
/// fails and retries, the intent stays pending and is never abandoned, and
/// the quarantine holds one record for the refused attempt, not one per
/// retry. Once the owner can renew, the same replay recovers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unavailable_renewal_retries_without_growing_the_quarantine() {
    let h = harness(Owner::new(chrono::Duration::milliseconds(800))).await;
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    write_through_completion_outage(&h, &store, &part_key("p0"), WriterClass::LakePart).await;
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    h.owner.complete_unavailable.store(false, Ordering::SeqCst);
    h.owner.authorize_unavailable.store(true, Ordering::SeqCst);
    for _ in 0..3 {
        let error = h.process().native_writer_for_tests().replay_pending().await.unwrap_err();
        assert!(error.chain().any(|cause| cause.downcast_ref::<OwnerRefused>().is_some_and(|refused| refused.status == 503)), "{error:#}");
    }
    assert_eq!(h.journal("pending").len(), 1, "never abandoned on a transient renewal failure");
    let quarantined = h.journal("quarantined");
    assert_eq!(quarantined.len(), 1, "one record per refused attempt: {quarantined:?}");
    assert!(quarantined[0].file_name().unwrap().to_str().unwrap().contains(".superseded."));
    assert_eq!(h.registered(&part_key("p0")), 0);
    h.owner.authorize_unavailable.store(false, Ordering::SeqCst);
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.expect("recovers once the owner can renew");
    assert_eq!(h.registered(&part_key("p0")), 1);
    assert_eq!(h.puts.load(Ordering::SeqCst), 1, "never re-PUT");
    assert_eq!(h.journal("quarantined").len(), 1);
    assert!(h.journal("pending").is_empty());
}

/// A 409 while the window is still open is a real conflict: never renewed,
/// nothing quarantined.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conflict_inside_the_window_is_not_renewed() {
    let h = harness(Owner { conflict_completes: true, ..Owner::new(chrono::Duration::minutes(70)) }).await;
    let store = h.process();
    store.native_writer_for_tests().replay_pending().await.unwrap();
    assert!(store.put_if_absent_with(&part_key("p0"), b"payload", &hints(WriterClass::LakePart)).await.unwrap());
    tokio::time::timeout(Duration::from_secs(5), store.native_writer_for_tests().write_behind_idle_for_tests()).await.unwrap();
    let error = store.native_writer_for_tests().replay_pending().await.unwrap_err();
    assert_eq!(error.downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(409));
    assert_eq!(h.owner.renewal_calls.load(Ordering::SeqCst), 0);
    assert!(h.journal("quarantined").is_empty());
    assert_eq!(h.journal("pending").len(), 1);
}

#[test]
fn expiry_and_permanent_refusal_classification() {
    assert!(completion_window_closed(&json!({"completion_deadline_at":(Utc::now()-chrono::Duration::seconds(1)).to_rfc3339()})));
    assert!(!completion_window_closed(&json!({"completion_deadline_at":(Utc::now()+chrono::Duration::seconds(60)).to_rfc3339()})));
    assert!(!completion_window_closed(&json!({})), "no deadline is never expired");
    assert!(!completion_window_closed(&json!({"completion_deadline_at":"not a time"})));
    for status in [409, 410, 422] {
        assert!(owner_refused_permanently(&OwnerRefused { status }.into()), "{status}");
    }
    for status in [400, 401, 403, 404, 408, 429, 500, 502, 503, 504] {
        assert!(!owner_refused_permanently(&OwnerRefused { status }.into()), "{status}");
    }
    assert!(!owner_refused_permanently(&anyhow::anyhow!("connection reset")));
    assert!(owner_refused_permanently(&anyhow::Error::from(OwnerRefused { status: 409 }).context("renew")));
}
