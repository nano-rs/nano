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
    historical: bool,
    race: Option<LiveRace>,
}

struct LiveRace {
    ledger: Arc<crate::lake_part_gc::index::ReceiptedAppends>,
    publish_watermark: bool,
    arrivals_left: AtomicUsize,
    incomplete: AtomicUsize,
    refusal: std::sync::Mutex<Option<&'static str>>,
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
    owner.authorizations.fetch_add(1, Ordering::SeqCst);
    if let Some(race) = &owner.race {
        if let Some(code) = *race.refusal.lock().unwrap() {
            return (StatusCode::CONFLICT, axum::Json(serde_json::json!({"error": code}))).into_response();
        }
        if owner.shas.lock().unwrap().len() != owner.bucket.entries.read().unwrap().len() {
            race.incomplete.fetch_add(1, Ordering::SeqCst);
            return (StatusCode::CONFLICT, axum::Json(serde_json::json!({
                "error": "lake_part_index_incomplete"
            }))).into_response();
        }
    }
    assert_eq!(owner.shas.lock().unwrap().len(), owner.bucket.entries.read().unwrap().len(), "no permit on an incomplete index");
    let orphan = request.key.contains(&format!("/{}/", crate::lake_part_gc::planner::tests::id(ORPHAN)));
    let superseded = owner.historical && request.key.contains(&format!("/{}/", crate::lake_part_gc::planner::tests::id(2)));
    assert!(orphan || superseded, "only the orphan and verified superseded data may be authorized");
    if superseded {
        assert_eq!(request.reason, if request.key.ends_with("provenance.json") {
            crate::lake_part_gc::LakePartDeleteReason::Retention
        } else { crate::lake_part_gc::LakePartDeleteReason::Superseded });
        assert!(request.removal_seq.is_some() && request.removal_entry_sha256.is_some());
    }
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
    if let Some(race) = &owner.race {
        if race.arrivals_left.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
            // Deterministic live-ingest commit between two deletes. The next
            // candidate must survive the fold, never be permanently skipped.
            use crate::parts::part_log::{LogEntry, LogOp};
            let mut history = owner.bucket.entries.write().unwrap();
            let LogOp::Genesis { schema } = LogEntry::parse_bytes(&history[&0], &owner.tenant).unwrap().op else { unreachable!() };
            let (&seq, raw) = history.last_key_value().unwrap();
            let mut entry = LogEntry::parse_bytes(raw, &owner.tenant).unwrap();
            entry.seq = seq + 1;
            entry.prev_sha256 = crate::parts::sha256_hex(raw);
            entry.appended_at_ms = chrono::Utc::now().timestamp_millis() - 120_000;
            entry.op = LogOp::Schema { schema };
            history.insert(entry.seq, entry.to_bytes().unwrap());
            if race.publish_watermark { race.ledger.record(entry.seq, entry.appended_at_ms); }
        }
    }
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
    exercise_history(tenant, catalog, entries, refusals, completes, false).await;
}

async fn exercise_history(tenant: &str, catalog: Option<Arc<TenantCatalog>>, entries: u64, refusals: usize, completes: bool, historical: bool) {
    // The guarded constructor uses this exact owner origin. The I/O double
    // is wired after R2 exists, before a pass can start.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let owner_url = format!("http://{}/", listener.local_addr().unwrap());
    let (client, tls) = worker_tls();
    let mut f = fixture_for_tenant(entries, Duration::ZERO, 200, &owner_url, tenant, Some(client.clone())).await;
    let entries = if historical {
        use crate::lake_part_gc::planner::tests::part_ref;
        use crate::parts::part_log::{LogOp, SourceRef};
        let mut chain = Chain::new();
        chain.add(1, T0 + 1);
        // All 300k adds precede their merges, within ONE ID-memory window.
        // The transient live prefix exceeds the resident limit; total exact
        // history exceeds 3x the limit of a 1 GiB role. Aging metadata or
        // merely compacting removed IDs cannot pass this.
        let make_part = |n, level| part_ref(n, level);
        for batch in 0..300_u64 {
            let first = 2 + batch * 1000;
            let parts = (first..first + 1000).map(|n| make_part(n, Level::L0)).collect();
            chain.push(LogOp::Add { parts, consumed: vec![SourceRef {
                key: format!("bronze/batch-{batch}"), version: "1".into(), sha256: "d".repeat(64),
            }], edge_log: None }, T0 + 1_000_000);
        }
        for batch in 0..300_u64 {
            let first = 2 + batch * 1000;
            let supersedes = (first..first + 1000).map(|n| make_part(n, Level::L0).part_id).collect();
            chain.push(LogOp::Merge { output: make_part(800_000 + batch, Level::Minute), supersedes }, T0 + 1_100_000);
        }
        let LogOp::Genesis { schema } = chain.entries[0].0.op.clone() else { unreachable!() };
        chain.push(LogOp::Schema { schema }, T0 + 30 * 86_400_000);
        let count = chain.entries.len() as u64;
        *f.bucket.entries.write().unwrap() = chain.entries.into_iter()
            .map(|(entry, _)| (entry.seq, entry.to_bytes().unwrap())).collect();
        let views = f.gc.shared.views.as_ref().unwrap();
        // Same budget function as production, with a 1 GiB role boundary.
        views.test_memory_limit.store(1024 * 1024 * 1024, Ordering::Relaxed);
        views.save_every_ms.store(VIEW_SAVE_EVERY.as_millis() as u64, Ordering::Relaxed);
        count
    } else { entries };
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
    let superseded = crate::lake_part_gc::planner::tests::key(2, Level::L0, "data-00000.parquet");
    let provenance = crate::lake_part_gc::planner::tests::key(2, Level::L0, "provenance.json");
    if historical {
        f.bucket.objects.write().unwrap().extend([(superseded.clone(), b"superseded".to_vec()),
            (provenance.clone(), b"provenance".to_vec())]);
    }
    let owner = Arc::new(Owner {
        tenant: tenant.into(), bucket: f.bucket.clone(), shas: Default::default(), pending: entries - 1,
        refusals_left: AtomicUsize::new(refusals), authorizations: AtomicUsize::new(0), retired: AtomicUsize::new(0), historical,
        race: None,
    });
    let app = Router::new()
        .route(crate::lake_part_gc::INDEX_PATH, axum::routing::post(index))
        .route(crate::lake_part_gc::AUTHORIZE_PATH, axum::routing::post(authorize))
        .layer(axum::extract::DefaultBodyLimit::max(INDEX_REQUEST_LIMIT))
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
        let report = tokio::time::timeout(Duration::from_secs(if historical { 300 } else { 30 }), run_catch_up(f.gc.shared.clone(), f.gc.state.clone(), now))
            .await.expect("receipt settlement and bounded catch-up converge").unwrap();
        assert!(report.paused_reason.is_none(), "{report:?}");
        assert_eq!(report.deleted, if historical { 2 } else { 1 }, "the same task deletes after verification");
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
    if historical {
        assert!(!f.bucket.objects.read().unwrap().contains_key(&superseded));
        assert!(f.bucket.objects.read().unwrap().contains_key(&provenance), "supersession keeps provenance");
        let views = f.gc.shared.views.as_ref().unwrap();
        let state = f.gc.state.lock().await;
        assert!(state.view.part_count() > 589_824);
        assert!(state.view.resident_refs() < 2_000, "resident state excludes lifetime history");
        let cache_bytes = state.view.history().unwrap().cache_bytes().unwrap();
        let cache_reservation = views.budget().sqlite_cache_bytes.saturating_mul(8);
        assert!(cache_bytes as u64 <= cache_reservation, "role-bounded SQLite resident cache: {cache_bytes}");
        let peak_cache = f.gc.shared.max_history_cache_bytes.load(Ordering::SeqCst);
        let peak_refs = f.gc.shared.max_resident_refs.load(Ordering::SeqCst);
        assert!(peak_cache <= cache_reservation, "paged cache stays within the role reservation during folding: {peak_cache}");
        assert!(state.view.part_count() >= 3 * views.budget().parts);
        assert!(peak_refs < views.budget().parts as u64, "replay stays within the resident limit: {peak_refs}");
        assert!(peak_refs < 10_000, "entry-sized working set independent of the transient 300k live prefix: {peak_refs}");
        assert!(state.view.is_live(&crate::lake_part_gc::planner::tests::id(1)));
        eprintln!("GC_HISTORY_PEAK resident_refs={peak_refs} sqlite_cache_bytes={peak_cache} sqlite_reservation_bytes={cache_reservation}");
        eprintln!("GC_HISTORY refs={} resident_refs={} sqlite_cache_bytes={cache_bytes} disk_bytes={}",
            state.view.part_count(), state.view.resident_refs(), state.view.history().unwrap().disk_bytes().unwrap());
        for output in 800_000..800_300 {
            assert!(state.view.is_live(&crate::lake_part_gc::planner::tests::id(output)));
        }
        views.save(tenant, &state.view).unwrap();
        let status = f.gc.capacity_status().unwrap();
        assert!(status.complete);
        assert_eq!(status.history_refs as usize, state.view.part_count());
        assert_eq!(status.legacy_remaining_refs, 0);
        assert_eq!(status.legacy_runway_seconds, Some(0), "#8384 would already be exhausted");
        let loaded = views.load(tenant).unwrap().unwrap();
        assert_eq!(loaded.part_count(), state.view.part_count());
        assert_eq!(loaded.head_seq(), state.view.head_seq());
        drop(loaded);
        drop(state);
        // A real guarded restart uses a fresh ephemeral state dir and the
        // persistent view dir, under a downsized 1 GiB role boundary.
        let restart_state = tempfile::tempdir().unwrap();
        let restarted_store = Arc::new(R2PartStore::new_split(&f.location, &f.location,
            tenant, &restart_state.path().join("spill")).unwrap());
        let restarted = CellSanctionedPartGc::new_guarded(tenant, &owner_url, None,
            restarted_store, fixture_keys(), restart_state.path(), Some(f.dir.path()), Some(client.clone())).unwrap();
        restarted.shared.views.as_ref().unwrap().test_memory_limit.store(1024 * 1024 * 1024, Ordering::Relaxed);
        restarted.update(Some(&access), Some(&serde_json::json!({
            "schema_version":1,"tenant_id":tenant,"tenant_slug":"fixture","enabled":true,"expires_at":"2099-01-01T00:00:00Z",
        })));
        restarted.shared.pacer.set_rate(0);
        let previous = std::mem::replace(&mut f.gc, restarted);
        drop(previous);
        let views = f.gc.shared.views.as_ref().unwrap();
        let before_reads = f.bucket.requests.lock().unwrap().len();
        f.bucket.objects.write().unwrap().insert(superseded.clone(), b"late-superseded".to_vec());
        let late = f.gc.run_pass_now(now + 1).await.unwrap();
        assert!(late.paused_reason.is_none(), "{late:?}");
        assert_eq!(late.deleted, 1, "late old object retains its exact removal proof");
        assert_eq!(f.gc.state.lock().await.view.part_count(), 600_301);
        assert!(f.bucket.requests.lock().unwrap().len() - before_reads < 100,
            "guarded restart resumes the saved cursor rather than replaying genesis");
        // The same exact old proof also supports retention of provenance,
        // never a reclassification as a never-added orphan.
        let mut retention_access = access.clone();
        retention_access.policy = Some(GcPolicyOverrides { retention_days: Some(30), ..GcPolicyOverrides::default() });
        f.gc.update(Some(&retention_access), Some(&serde_json::json!({
            "schema_version":1,"tenant_id":tenant,"tenant_slug":"fixture","enabled":true,"expires_at":"2099-01-01T00:00:00Z",
        })));
        f.gc.shared.pacer.set_rate(0);
        let retention = f.gc.run_pass_now(now + 2).await.unwrap();
        assert!(retention.paused_reason.is_none(), "{retention:?}");
        assert_eq!(retention.deleted, 1);
        assert!(!f.bucket.objects.read().unwrap().contains_key(&provenance));
        let saved_path = views.path.with_extension("unavailable");
        std::fs::rename(&views.path, &saved_path).unwrap();
        let before = owner.authorizations.load(Ordering::SeqCst);
        let unavailable = f.gc.run_pass_now(now + 3).await.unwrap();
        assert_eq!(unavailable.paused_reason.as_deref(), Some("log_unverifiable"));
        assert_eq!(owner.authorizations.load(Ordering::SeqCst), before);
        std::fs::rename(&saved_path, &views.path).unwrap();
        // A larger role budget changes no verification rule. A broken next
        // hash link must still refuse the pass before another authorization.
        let mut broken = crate::parts::part_log::LogEntry::parse_bytes(
            &f.bucket.entries.read().unwrap()[&(entries - 1)], tenant).unwrap();
        broken.seq = entries;
        broken.prev_sha256 = "0".repeat(64);
        f.bucket.entries.write().unwrap().insert(entries, broken.to_bytes().unwrap());
        f.bucket.objects.write().unwrap().insert(superseded.clone(), b"superseded".to_vec());
        let before = owner.authorizations.load(Ordering::SeqCst);
        let report = f.gc.run_pass_now(now + 1).await.unwrap();
        assert_eq!(report.paused_reason.as_deref(), Some("log_unverifiable"));
        assert_eq!(report.deleted, 0);
        assert_eq!(owner.authorizations.load(Ordering::SeqCst), before);
        assert!(f.bucket.objects.read().unwrap().contains_key(&superseded));
        // A fresh guarded process presented with corrupt persistent storage
        // refuses before owner/Worker I/O; no checkpoint/absence shortcut.
        let valid_path = views.path.with_extension("valid");
        std::fs::rename(&views.path, &valid_path).unwrap();
        std::fs::write(&views.path, b"not a SQLite database").unwrap();
        let corrupt_state = tempfile::tempdir().unwrap();
        let corrupt_store = Arc::new(R2PartStore::new_split(&f.location, &f.location,
            tenant, &corrupt_state.path().join("spill")).unwrap());
        let corrupt = CellSanctionedPartGc::new_guarded(tenant, &owner_url, None,
            corrupt_store, fixture_keys(), corrupt_state.path(), Some(f.dir.path()), Some(client.clone())).unwrap();
        corrupt.update(Some(&retention_access), Some(&serde_json::json!({
            "schema_version":1,"tenant_id":tenant,"tenant_slug":"fixture","enabled":true,"expires_at":"2099-01-01T00:00:00Z",
        })));
        corrupt.shared.pacer.set_rate(0);
        let before = owner.authorizations.load(Ordering::SeqCst);
        let refused = corrupt.run_pass_now(now + 4).await.unwrap();
        assert_eq!(refused.paused_reason.as_deref(), Some("log_unverifiable"));
        assert_eq!(refused.deleted, 0);
        assert_eq!(owner.authorizations.load(Ordering::SeqCst), before);
        std::fs::remove_file(&views.path).unwrap();
        std::fs::rename(valid_path, &views.path).unwrap();
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

#[tokio::test]
async fn guarded_gc_view_budget_verifies_large_history_deletes_and_still_fails_closed() {
    exercise_history(TENANT_UUID, None, 1, 0, true, true).await;
}

/// Production guarded constructor -> run_catch_up -> bounded passes -> HTTP
/// owner/Worker, with real S3 transport counters. Compare identical arrivals
/// with/without the local writer feed; neither path may bypass an NL009.
#[tokio::test]
async fn guarded_live_commits_collect_old_keys_without_stale_authorizations_or_extra_r2() {
    let baseline = live_commit_fixture(false, None, false).await;
    let guarded = live_commit_fixture(true, None, false).await;
    assert_eq!(guarded.0, 0, "known local commits never reach control as stale authorizations");
    assert!(baseline.0 > 0, "the same arrivals reproduce the old NL009 retry path");
    assert!(guarded.1 <= baseline.1, "R2 requests cannot increase: guarded={guarded:?}, baseline={baseline:?}");
    assert_eq!(guarded.2, 4, "one exact owner authorization per collected key");
    assert!(guarded.2 < baseline.2);
}

#[tokio::test]
async fn guarded_unknown_index_gap_is_never_cached_as_a_permanent_key_refusal() {
    live_commit_fixture(true, Some("lake_part_index_incomplete"), false).await;
}

#[tokio::test]
async fn guarded_missing_writer_receipt_stays_skipped_without_worker_deletion() {
    live_commit_fixture(true, Some(crate::lake_part_gc::executor::OBJECT_NOT_FOUND), false).await;
}

#[tokio::test]
async fn guarded_completed_head_beyond_missing_entry_stops_after_bounded_reads() {
    live_commit_fixture(true, None, true).await;
}

async fn live_commit_fixture(publish_watermark: bool, refusal: Option<&'static str>, missing_log_entry: bool) -> (usize, usize, usize) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let owner_url = format!("http://{}/", listener.local_addr().unwrap());
    let (client, tls) = worker_tls();
    let f = fixture_for_tenant(3, Duration::ZERO, 200, &owner_url, TENANT_UUID, Some(client)).await;
    let keys: Vec<_> = ["data-00000.parquet", "tokens-00000.nti", "entities-00000.json", "provenance.json"]
        .into_iter().map(|file| crate::lake_part_gc::planner::tests::key(ORPHAN, Level::L0, file)).collect();
    for key in &keys { f.bucket.objects.write().unwrap().insert(key.clone(), b"orphan".to_vec()); }
    let owner = Arc::new(Owner {
        tenant: TENANT_UUID.into(), bucket: f.bucket.clone(), shas: Default::default(), pending: u64::MAX,
        refusals_left: AtomicUsize::new(0), authorizations: AtomicUsize::new(0), retired: AtomicUsize::new(0), historical: false,
        race: Some(LiveRace {
            ledger: f.gc.receipted_appends(), publish_watermark, arrivals_left: AtomicUsize::new(3),
            incomplete: AtomicUsize::new(0), refusal: std::sync::Mutex::new(refusal),
        }),
    });
    let app = Router::new()
        .route(crate::lake_part_gc::INDEX_PATH, axum::routing::post(index))
        .route(crate::lake_part_gc::AUTHORIZE_PATH, axum::routing::post(authorize))
        .with_state(owner.clone());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let worker = worker(owner.clone(), tls).await;
    let access = LakePartGcAccess::parse(&serde_json::json!({
        "schema_version": 1,
        "owner_delete": {"token":"fixture", "audience":"owner", "scope":OWNER_DELETE_SCOPE,
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339()},
        "retention_authority": {"url":worker.url, "token":"fixture"},
    })).unwrap();
    f.gc.update(Some(&access), Some(&serde_json::json!({
        "schema_version":1, "tenant_id":TENANT_UUID, "tenant_slug":"fixture", "enabled":true,
        "expires_at":"2099-01-01T00:00:00Z",
    })));
    f.gc.shared.pacer.set_rate(0);
    let now = chrono::Utc::now().timestamp_millis();
    if missing_log_entry {
        // A completed local append contradicts an absent sequence in the
        // store. It must not turn the writer-ahead yield into an hour of
        // no-progress tail reads. Both the inventory and deletes stay closed.
        let missing = f.bucket.entries.write().unwrap().remove(&2).unwrap();
        f.gc.receipted_appends().record(2, now - 120_000);
        let report = tokio::time::timeout(Duration::from_secs(15), run_catch_up(f.gc.shared.clone(), f.gc.state.clone(), now))
            .await.expect("a known local log gap exhausts only the bounded integrity retries").unwrap();
        assert_eq!(report.paused_reason.as_deref(), Some(LOG_UNVERIFIABLE));
        assert!(report.backoff);
        assert_eq!(report.deleted, 0);
        assert_eq!(owner.authorizations.load(Ordering::SeqCst), 0);
        assert_eq!(owner.retired.load(Ordering::SeqCst), 0);
        assert_eq!(f.bucket.objects.read().unwrap().len(), keys.len());
        assert!(f.gc.state.lock().await.refused_keys.is_empty());
        let reads = f.bucket.requests.lock().unwrap().len();
        assert!(reads <= READ_AHEAD_WINDOW * (MAX_CATCH_UP_RETRIES as usize + 1), "unbounded gap reads: {reads}");
        // The refusal is not permanent key state: restoring the exact entry
        // permits the next task to verify it and collect the same inventory.
        f.bucket.entries.write().unwrap().insert(2, missing);
    }
    if let Some(code) = refusal {
        let report = f.gc.run_pass_now(now).await.unwrap();
        assert_eq!(report.deleted, 0);
        assert_eq!(owner.retired.load(Ordering::SeqCst), 0);
        assert_eq!(f.bucket.objects.read().unwrap().len(), keys.len());
        if code == "lake_part_index_incomplete" {
            assert_eq!(report.paused_reason.as_deref(), Some(code));
            assert!(f.gc.state.lock().await.refused_keys.is_empty(), "tenant-wide NL009 never poisons a key");
            *owner.race.as_ref().unwrap().refusal.lock().unwrap() = None;
        } else {
            assert!(report.paused_reason.is_none(), "missing receipt is a per-key refusal");
            assert_eq!(report.skipped.get(code), Some(&4));
            assert_eq!(f.gc.state.lock().await.refused_keys.count(code, now), 4);
            let before = owner.authorizations.load(Ordering::SeqCst);
            let next = f.gc.run_pass_now(now + 1).await.unwrap();
            assert_eq!(next.deleted, 0);
            assert_eq!(owner.authorizations.load(Ordering::SeqCst), before, "no repeated receipt-gap churn");
            server.abort();
            return (0, f.bucket.requests.lock().unwrap().len(), before);
        }
    }
    let report = tokio::time::timeout(Duration::from_secs(30), run_catch_up(f.gc.shared.clone(), f.gc.state.clone(), now))
        .await.expect("live-ingest candidates drain in the same task").unwrap();
    assert!(report.paused_reason.is_none(), "{report:?}");
    assert_eq!(report.deleted, 4);
    assert_eq!(report.deleted_reported, 4);
    assert_eq!(owner.retired.load(Ordering::SeqCst), 4);
    assert!(keys.iter().all(|key| !f.bucket.objects.read().unwrap().contains_key(key)));
    assert!(f.gc.state.lock().await.refused_keys.is_empty());
    let race = owner.race.as_ref().unwrap();
    let result = (race.incomplete.load(Ordering::SeqCst), f.bucket.requests.lock().unwrap().len(), owner.authorizations.load(Ordering::SeqCst));
    let next = f.gc.run_pass_now(now + 1).await.unwrap();
    assert!(next.paused_reason.is_none());
    assert_eq!(next.deleted, 0);
    assert_eq!(owner.authorizations.load(Ordering::SeqCst), result.2, "collected keys never re-stop a later pass");
    eprintln!("GC_LIVE_COMMITS watermark={publish_watermark} incomplete={} r2={} authorizes={}", result.0, result.1, result.2);
    server.abort();
    result
}
