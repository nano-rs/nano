// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner/Worker/R2 I/O doubles; the cell's guarded constructor, bounded fold,
//! index publication, catch-up runner and delete executor are production code.
use super::*;
use crate::lake_part_gc::{delete_control::*, LakePartDeleteRequest};
use crate::part_ingest::iceberg_export::lifecycle::TenantCatalog;
use crate::parts::levels::Level;

const ORPHAN: u64 = 1_000_000;

struct Owner {
    tenant: String,
    bucket: Arc<Bucket>,
    shas: std::sync::Mutex<Vec<String>>,
    pending: u64,
    refusals_left: AtomicUsize,
    authorizations: AtomicUsize,
    retired: AtomicUsize,
}

async fn index(State(owner): State<Arc<Owner>>, body: axum::body::Bytes) -> Response {
    use base64::Engine as _;
    let request: crate::lake_part_gc::index::IndexRequest = serde_json::from_slice(&body).unwrap();
    assert_eq!(request.tenant_uuid, owner.tenant);
    let mut shas = owner.shas.lock().unwrap();
    if request.entries.iter().any(|entry| entry.seq == owner.pending)
        && owner.refusals_left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok()
    {
        // Control's refusal is atomic: none of this batch was indexed.
        return (StatusCode::CONFLICT, axum::Json(serde_json::json!({
            "error": "lake_part_index_receipt_missing"
        }))).into_response();
    }
    for entry in &request.entries {
        assert_eq!(entry.seq, shas.len() as u64);
        let raw = base64::engine::general_purpose::STANDARD.decode(&entry.entry_base64).unwrap();
        assert_eq!(owner.bucket.entries.read().unwrap().get(&entry.seq), Some(&raw));
        let parsed = crate::parts::part_log::LogEntry::parse_bytes(&raw, &owner.tenant).unwrap();
        assert_eq!(parsed.prev_sha256, shas.last().cloned().unwrap_or_else(|| crate::parts::part_log::GENESIS_PREV.into()));
        shas.push(crate::parts::sha256_hex(&raw));
    }
    axum::Json(serde_json::json!({
        "tenant_uuid": owner.tenant, "indexed_through_seq": shas.len().checked_sub(1),
        "head_entry_sha256": shas.last(), "checkpoint_seq": null, "folded_through_seq": null,
    })).into_response()
}

async fn authorize(State(owner): State<Arc<Owner>>, axum::Json(request): axum::Json<LakePartDeleteRequest>) -> Response {
    request.validate().unwrap();
    assert_eq!(request.tenant_uuid, owner.tenant);
    assert_eq!(owner.shas.lock().unwrap().len(), owner.bucket.entries.read().unwrap().len(), "no permit on an incomplete index");
    assert!(request.key.contains(&format!("/{}/", crate::lake_part_gc::planner::tests::id(ORPHAN))), "only the old orphan may be authorized");
    owner.authorizations.fetch_add(1, Ordering::SeqCst);
    let now = chrono::Utc::now();
    axum::Json(LakePartDeletePermit {
        permit_id: request.permit_id().unwrap(),
        owner_authorization: DeleteOwnerAuthorization {
            schema_version: 1, signer_key_id: "receipt-fixture".into(),
            issued_at: now.to_rfc3339(), expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
            identity_sha256: request.digest().unwrap(), signature_base64: "fixture-signature".into(),
        },
        request,
    }).into_response()
}

async fn capability() -> Response {
    axum::Json(serde_json::json!({
        "schema_version": DELETE_CONTROL_SCHEMA_VERSION, "contract": DELETE_CONTROL_CONTRACT,
        "operations": [crate::lake_part_gc::OPERATION],
    })).into_response()
}

async fn prepare(axum::Json(permit): axum::Json<LakePartDeletePermit>) -> Response {
    permit.verify(&permit.request, chrono::Utc::now()).unwrap();
    axum::Json(permit).into_response()
}

async fn retire(State(owner): State<Arc<Owner>>, axum::Json(permit): axum::Json<LakePartDeletePermit>) -> Response {
    permit.verify(&permit.request, chrono::Utc::now()).unwrap();
    assert!(owner.bucket.objects.write().unwrap().remove(&permit.request.key).is_some());
    owner.retired.fetch_add(1, Ordering::SeqCst);
    axum::Json(LakePartDeleteReceipt {
        schema_version: DELETE_CONTROL_SCHEMA_VERSION, permit_id: permit.permit_id,
        identity_sha256: permit.owner_authorization.identity_sha256,
        receipt_sha256: "a".repeat(64), state: "receipt_appended".into(), final_head_absent: true,
    }).into_response()
}

struct Worker {
    url: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) { self.task.abort(); }
}

fn worker_tls() -> (reqwest::Client, rustls::ServerConfig) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(cert.cert.der()).unwrap()).build().unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions().unwrap().with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
    (client, tls)
}

async fn worker(owner: Arc<Owner>, tls: rustls::ServerConfig) -> Worker {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://localhost:{}/", listener.local_addr().unwrap().port());
    let app = Router::new()
        .route(WORKER_CAPABILITIES_PATH, axum::routing::post(capability))
        .route(WORKER_PREPARE_PATH, axum::routing::post(prepare))
        .route(WORKER_RETIRE_PATH, axum::routing::post(retire))
        .with_state(owner);
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), hyper_util::service::TowerToHyperService::new(app))
                    .await.unwrap();
            });
        }
    });
    Worker { url, task }
}

/// Called after both real catalog startup paths by the activation tests.
pub(crate) async fn assert_catalog_gc_settles(tenant: &str, catalog: Arc<TenantCatalog>) {
    exercise(tenant, Some(catalog), 9, 2, true).await;
}

async fn exercise(tenant: &str, catalog: Option<Arc<TenantCatalog>>, entries: u64, refusals: usize, completes: bool) {
    // The guarded constructor uses this exact owner origin. The I/O double
    // is wired after R2 exists, before a pass can start.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let owner_url = format!("http://{}/", listener.local_addr().unwrap());
    let (client, tls) = worker_tls();
    let f = fixture_for_tenant(entries, Duration::ZERO, 200, &owner_url, tenant, Some(client)).await;
    let now = chrono::Utc::now().timestamp_millis();
    // A settled prefix and a young (but past the 60 s age gate) entry whose
    // writer completion is still reaching control, as immediately after roll.
    {
        use crate::parts::part_log::{LogEntry, LogOp};
        let mut history = f.bucket.entries.write().unwrap();
        let LogOp::Genesis { schema } = LogEntry::parse_bytes(&history[&0], tenant).unwrap().op else { unreachable!() };
        let raw = history.get_mut(&(entries - 1)).unwrap();
        let mut tail = LogEntry::parse_bytes(raw, tenant).unwrap();
        tail.appended_at_ms = now - 90_000;
        // Keep historical adds at their real part-ID times (the fold enforces
        // the 48 h ID window); only this current schema append is pending.
        tail.op = LogOp::Schema { schema };
        *raw = tail.to_bytes().unwrap();
    }
    let orphan = crate::lake_part_gc::planner::tests::key(ORPHAN, Level::L0, "data-00000.parquet").replace(TENANT_UUID, tenant);
    let live = crate::lake_part_gc::planner::tests::key(1, Level::L0, "data-00000.parquet").replace(TENANT_UUID, tenant);
    f.bucket.objects.write().unwrap().extend([(orphan.clone(), b"orphan".to_vec()), (live.clone(), b"live".to_vec())]);
    let owner = Arc::new(Owner {
        tenant: tenant.into(), bucket: f.bucket.clone(), shas: Default::default(), pending: entries - 1,
        refusals_left: AtomicUsize::new(refusals), authorizations: AtomicUsize::new(0), retired: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route(crate::lake_part_gc::INDEX_PATH, axum::routing::post(index))
        .route(crate::lake_part_gc::AUTHORIZE_PATH, axum::routing::post(authorize))
        .with_state(owner.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let worker = worker(owner.clone(), tls).await;
    let access = LakePartGcAccess::parse(&serde_json::json!({
        "schema_version":1,
        "owner_delete":{"token":"fixture","audience":"owner","scope":OWNER_DELETE_SCOPE,
            "expires_at":(chrono::Utc::now()+chrono::Duration::minutes(10)).to_rfc3339()},
        "retention_authority":{"url":worker.url,"token":"fixture"},
    })).unwrap();
    f.gc.update(Some(&access), Some(&serde_json::json!({
        "schema_version":1,"tenant_id":tenant,"tenant_slug":"fixture","enabled":true,"expires_at":"2099-01-01T00:00:00Z",
    })));
    f.gc.shared.pacer.set_rate(0);
    if let Some(catalog) = catalog { f.gc.attach_catalog(catalog).unwrap(); }
    if entries > VIEW_PERSIST_EVERY {
        let first = f.gc.run_pass_now(now).await.unwrap();
        assert_eq!(first.paused_reason.as_deref(), Some("log_catching_up"));
        assert_eq!(owner.authorizations.load(Ordering::SeqCst), 0);
    }
    if completes {
        let report = tokio::time::timeout(Duration::from_secs(30), run_catch_up(f.gc.shared.clone(), f.gc.state.clone(), now))
            .await.expect("receipt settlement and bounded catch-up converge").unwrap();
        assert!(report.paused_reason.is_none(), "{report:?}");
        assert_eq!(report.deleted, 1, "the same task deletes after the completion arrives");
        assert_eq!(report.indexed, entries, "accepted prefixes remain in the progress count");
        assert_eq!(owner.shas.lock().unwrap().len(), entries as usize);
        assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(entries - 1));
        assert!(!f.bucket.objects.read().unwrap().contains_key(&orphan));
    } else {
        let report = f.gc.run_pass_now(now).await.unwrap();
        assert_eq!(report.paused_reason.as_deref(), Some(crate::lake_part_gc::executor::INDEX_SETTLING));
        assert_eq!(report.indexed, entries - 1);
        let report = f.gc.run_pass_now(now + 1).await.unwrap();
        assert_eq!(report.paused_reason.as_deref(), Some(crate::lake_part_gc::executor::INDEX_SETTLING));
        assert_eq!(report.index_head_seq, Some(entries - 2), "pending completion preserves the actual indexed head");
        assert_eq!(report.deleted, 0);
        let publication = run_index_only(f.gc.shared.clone()).await.unwrap();
        assert_eq!(publication.paused_reason.as_deref(), Some(crate::lake_part_gc::executor::INDEX_SETTLING));
        assert_eq!(publication.index_head_seq, Some(entries - 2));
        assert!(!publication.backoff);
        let expired = f.gc.run_pass_now(now + crate::lake_part_gc::index::RECEIPT_WINDOW_MS + 1).await.unwrap();
        assert_eq!(expired.paused_reason.as_deref(), Some("lake_part_index_receipt_missing"));
        assert_eq!(expired.deleted, 0);
        assert_eq!(owner.authorizations.load(Ordering::SeqCst), 0);
        assert_eq!(owner.retired.load(Ordering::SeqCst), 0);
        assert!(f.bucket.objects.read().unwrap().contains_key(&orphan));
    }
    assert!(f.bucket.objects.read().unwrap().contains_key(&live), "live part remains protected");
    assert!(!f.bucket.requests.lock().unwrap().iter().any(|(key, _)| key.ends_with(".parquet")), "no part files read for receipt settlement");
    server.abort();
}

#[tokio::test]
async fn guarded_receipt_completion_retries_in_the_same_gc_task() {
    exercise(TENANT_UUID, None, 9, 2, true).await;
}

#[tokio::test]
async fn guarded_incomplete_receipt_never_authorizes_or_deletes() {
    exercise(TENANT_UUID, None, 9, usize::MAX, false).await;
}

#[tokio::test]
async fn guarded_catching_up_log_converges_and_then_settles_its_receipt() {
    exercise(TENANT_UUID, None, VIEW_PERSIST_EVERY + 9, 2, true).await;
}
