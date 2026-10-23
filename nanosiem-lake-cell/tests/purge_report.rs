//! NAN-3000: drain → purge → verify → report against a fake platform that
//! enforces the platform's contract (`apps/api/src/routes/lake-cell-reports.ts`
//! + `services/shared-infrastructure/lake-cell-reports.ts`):
//!
//! - `POST /api/v1/lake/cells/{cell_id}/status`, 404 while the flag is off;
//! - bearer = the cell's projected SA token (the fake plays TokenReview:
//!   it accepts only the token currently issued to this cell), 401 else;
//! - strict body (unknown fields → 400), ≤64 tenants / purges;
//! - a push naming a tenant that is neither placed nor draining here, or a
//!   purge with no open drain here, is refused WHOLE (403), nothing stored;
//! - a verified purge for a tenant not also listed, `at` ≥ `removed_at`,
//!   closes the drain.
//!
//! Runs unprivileged: the tenant trees are owned by the test user. The same
//! purge under the cell's exact 5A capabilities (tenant-uid-owned trees) is
//! `tenant_dirs::tests::cell_5a_capabilities`; with real jailed processes,
//! the `purge` phase of the isolation suite.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use nanosiem_lake_cell::contract::TenantId;
use nanosiem_lake_cell::report::{
    LedgerSource, LedgerStore, PushOutcome, Reporter, StatusSource, TenantState,
};
use nanosiem_lake_cell::tenant_dirs;
use nanosiem_lake_cell::uidmap::TenantIds;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CELL: &str = "cell-us-p-7a1b";
const A: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
const B: &str = "7a2d2f3b-6c9f-4e5d-8b4f-1f3c8d0e2a11";
const C: &str = "8b3e3a4c-7d0a-4f6e-9c5a-2a4d9e1f3b22";

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

// ------------------------------------------------------------------ fake platform

#[derive(Default)]
struct Platform {
    enabled: bool,
    /// The token TokenReview accepts right now for `system:serviceaccount:
    /// nano-lake-cells:nano-cell-<CELL>`.
    valid_token: String,
    placed: BTreeSet<String>,
    /// Open drains of this cell: tenant → removed_at.
    drains: BTreeMap<String, chrono::DateTime<chrono::Utc>>,
    closed: BTreeMap<String, Value>,
    /// Respond 503 to the next N requests.
    fail_next: u32,
    requests: Vec<(u16, Option<Value>)>,
    stored: Option<Value>,
}

fn check_body(p: &Platform, raw: &[u8]) -> Result<Value, u16> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| 400u16)?;
    let obj = v.as_object().ok_or(400u16)?;
    let allowed = ["cell_id", "placement_revision", "tenants", "purged"];
    if obj.keys().any(|k| !allowed.contains(&k.as_str())) {
        return Err(400);
    }
    if v["cell_id"] != CELL {
        return Err(403);
    }
    let rev = v["placement_revision"].as_u64().ok_or(400u16)?;
    if rev > 2_147_483_647 {
        return Err(400);
    }
    let tenants = v["tenants"].as_array().ok_or(400u16)?;
    let purged = v.get("purged").and_then(Value::as_array).cloned().unwrap_or_default();
    if tenants.len() > 64 || purged.len() > 64 {
        return Err(400);
    }
    for t in tenants {
        let o = t.as_object().ok_or(400u16)?;
        if o.len() != 2 || !["running", "idle", "draining"].contains(&t["state"].as_str().unwrap_or("")) {
            return Err(400);
        }
        let id = t["tenant_id"].as_str().ok_or(400u16)?;
        if !p.placed.contains(id) && !p.drains.contains_key(id) {
            return Err(403);
        }
    }
    for x in &purged {
        let o = x.as_object().ok_or(400u16)?;
        let keys = ["tenant_id", "reason", "verified", "at", "cache_bytes_removed", "tmp_bytes_removed"];
        if o.keys().any(|k| !keys.contains(&k.as_str())) || !x["verified"].is_boolean() {
            return Err(400);
        }
        if !["drain", "move", "deprovision"].contains(&x["reason"].as_str().unwrap_or("")) {
            return Err(400);
        }
        chrono::DateTime::parse_from_rfc3339(x["at"].as_str().ok_or(400u16)?).map_err(|_| 400u16)?;
        if !p.drains.contains_key(x["tenant_id"].as_str().ok_or(400u16)?) {
            return Err(403);
        }
    }
    Ok(v)
}

async fn handle(p: Arc<Mutex<Platform>>, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    let auth = req.headers().get("authorization").and_then(|h| h.to_str().ok()).map(str::to_owned);
    let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
    let mut p = p.lock().unwrap();
    let code = (|| {
        if path != format!("/api/v1/lake/cells/{CELL}/status") || !p.enabled {
            return 404;
        }
        if auth.as_deref() != Some(&format!("Bearer {}", p.valid_token)) {
            return 401;
        }
        if p.fail_next > 0 {
            p.fail_next -= 1;
            return 503;
        }
        match check_body(&p, &body) {
            Err(code) => code,
            Ok(v) => {
                // verifiedPurges + saveStatus: close the matching open drains.
                let listed: BTreeSet<&str> = v["tenants"].as_array().unwrap().iter().filter_map(|t| t["tenant_id"].as_str()).collect();
                for x in v["purged"].as_array().cloned().unwrap_or_default() {
                    let t = x["tenant_id"].as_str().unwrap().to_owned();
                    let at = chrono::DateTime::parse_from_rfc3339(x["at"].as_str().unwrap()).unwrap();
                    if x["verified"] == true && !listed.contains(t.as_str()) && p.drains.get(&t).is_some_and(|r| at >= *r) {
                        p.drains.remove(&t);
                        p.closed.insert(t, x.clone());
                    }
                }
                p.stored = Some(v);
                204
            }
        }
    })();
    let parsed = serde_json::from_slice(&body).ok();
    p.requests.push((code, parsed));
    Response::builder().status(code).body(Full::new(Bytes::new())).unwrap()
}

async fn serve(p: Arc<Mutex<Platform>>) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let p = p.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req| {
                    let p = p.clone();
                    async move { Ok::<_, std::convert::Infallible>(handle(p, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
            });
        }
    });
    // The cell's `control_url` is the platform API base, `/api` included.
    format!("http://{addr}/api/")
}

// ------------------------------------------------------------------ cell side

fn own_ids() -> TenantIds {
    // SAFETY: geteuid/getegid never fail.
    let (u, g) = unsafe { (libc::geteuid(), libc::getegid()) };
    TenantIds { slot: 0, ingest_uid: u, query_uid: u, detect_uid: u, landing_uid: Some(u), gid: g }
}

/// A tree with cache, spill and tmp content, plus links into `sibling`.
fn populate(tenants: &Path, t: &str, sibling: &str) {
    tenant_dirs::ensure_tenant_tree(tenants, t, &own_ids()).unwrap();
    let root = tenants.join(t);
    std::fs::write(root.join("parts/p-0001.parquet"), vec![1u8; 4096]).unwrap();
    std::fs::create_dir_all(root.join("ingest/spill")).unwrap();
    std::fs::write(root.join("ingest/spill/s-1"), vec![2u8; 100]).unwrap();
    std::fs::create_dir_all(root.join("query/cache/reader")).unwrap();
    std::fs::write(root.join("query/cache/reader/blk"), vec![3u8; 900]).unwrap();
    std::fs::write(root.join("detect/prevalence.snapshot"), vec![4u8; 50]).unwrap();
    std::fs::write(root.join("query/tmp/sort-1"), vec![5u8; 300]).unwrap();
    std::fs::write(root.join("ingest/tmp/stage"), vec![6u8; 7]).unwrap();
    std::os::unix::fs::symlink(tenants.join(sibling), root.join("query/to-sibling")).unwrap();
}

/// What the supervisor's purge does for one drained tenant (the supervisor
/// additionally proves no process / cgroup / fd of the tenant is left).
fn purge_and_record(tenants: &Path, ledger: &LedgerStore, t: &str) -> tenant_dirs::PurgeBytes {
    let bytes = tenant_dirs::purge_tenant_tree(tenants, t).unwrap();
    assert!(!tenant_dirs::tenant_tree_present(tenants, t).unwrap(), "{t} not verified gone");
    let at = chrono::Utc::now();
    assert!(ledger.update(|l| {
        let r = l.record(&tid(t), bytes, at, now_ms());
        (r, r)
    }));
    bytes
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn digest(tenants: &Path, t: &str) -> Vec<(String, Vec<u8>)> {
    fn walk(p: &Path, base: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(p).unwrap().flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let path = e.path();
            let rel = path.strip_prefix(base).unwrap().display().to_string();
            let ft = std::fs::symlink_metadata(&path).unwrap().file_type();
            if ft.is_dir() {
                out.push((rel, vec![]));
                walk(&path, base, out);
            } else {
                out.push((rel, if ft.is_file() { std::fs::read(&path).unwrap() } else { b"link".to_vec() }));
            }
        }
    }
    let mut out = vec![];
    walk(&tenants.join(t), &tenants.join(t), &mut out);
    out
}

#[tokio::test]
async fn drain_purge_verify_report() {
    let d = tempfile::tempdir().unwrap();
    let tenants = d.path().join("tenants");
    std::fs::create_dir(&tenants).unwrap();
    let identity = d.path().join("identity.token");
    std::fs::write(&identity, "sa-token-1\n").unwrap();

    let platform = Arc::new(Mutex::new(Platform {
        valid_token: "sa-token-1".into(),
        placed: [A, B].iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }));
    let url = serve(platform.clone()).await;
    let reporter = Reporter::new(&url, CELL, identity.clone()).unwrap().with_retry(3, Duration::from_millis(20));
    assert_eq!(reporter.url(), format!("{}v1/lake/cells/{CELL}/status", url));

    // Cell: A and B placed and populated; B's tree links into A's.
    populate(&tenants, A, B);
    populate(&tenants, B, A);
    let ledger = Arc::new(LedgerStore::open(&d.path().join("purge-ledger.json")).unwrap());
    ledger.update(|l| (l.on_placement(&[tid(A), tid(B)].into_iter().collect(), now_ms()), true));
    let src = LedgerSource {
        cell_id: CELL.into(),
        revision: Mutex::new(41),
        placed: Mutex::new(vec![(tid(A), TenantState::Running), (tid(B), TenantState::Idle)]),
        ledger: ledger.clone(),
    };
    let a_before = digest(&tenants, A);

    // Platform flag off: 404, nothing lost, INFO only.
    let s = reporter.push_once(&src).await;
    assert_eq!(s.outcome, PushOutcome::Disabled);
    platform.lock().unwrap().enabled = true;
    let s = reporter.push_once(&src).await;
    assert_eq!(s.outcome, PushOutcome::Accepted);
    assert_eq!(platform.lock().unwrap().stored.as_ref().unwrap()["tenants"].as_array().unwrap().len(), 2);

    // Placement change: the platform opens B's drain and places only A.
    {
        let mut p = platform.lock().unwrap();
        p.placed.remove(B);
        p.drains.insert(B.into(), chrono::Utc::now() - chrono::Duration::seconds(1));
    }
    *src.revision.lock().unwrap() = 42;
    *src.placed.lock().unwrap() = vec![(tid(A), TenantState::Running)];
    let removed = ledger.update(|l| (l.on_placement(&[tid(A)].into_iter().collect(), now_ms()), true));
    assert_eq!(removed, vec![tid(B)]);

    // Before the purge B is reported draining (allowed: its drain is open).
    let s = reporter.push_once(&src).await;
    assert_eq!(s.outcome, PushOutcome::Accepted);
    let stored = platform.lock().unwrap().stored.clone().unwrap();
    assert_eq!(stored["tenants"], serde_json::json!([{"tenant_id": A, "state": "running"}, {"tenant_id": B, "state": "draining"}]));
    assert_eq!(stored["purged"], serde_json::json!([]));
    assert!(platform.lock().unwrap().drains.contains_key(B), "no purge yet: drain stays open");

    // Drained (the supervisor's reaper has forgotten B) → purge → verify.
    let bytes = purge_and_record(&tenants, &ledger, B);
    assert_eq!(bytes.tmp_bytes, 300 + 7);
    assert_eq!(bytes.cache_bytes, 4096 + 100 + 900 + 50);
    // Zero cross-tenant: A's tree is byte-for-byte unchanged.
    assert_eq!(digest(&tenants, A), a_before, "purging B changed A's tree");

    // Token rotation: the kubelet rewrote the projected token; the platform
    // only accepts the new one. A stale token is a 401 and nothing is lost.
    platform.lock().unwrap().valid_token = "sa-token-2".into();
    let s = reporter.push_once(&src).await;
    assert_eq!(s.outcome, PushOutcome::Unauthenticated);
    assert!(ledger.snapshot().purged.contains_key(&tid(B)));
    std::fs::write(&identity, "sa-token-2").unwrap();

    // A transient 503 is retried within the push.
    platform.lock().unwrap().fail_next = 1;
    let s = reporter.push_once(&src).await;
    assert_eq!(s.outcome, PushOutcome::Accepted);
    assert_eq!(s.acknowledged, vec![tid(B)]);
    {
        let p = platform.lock().unwrap();
        assert!(!p.drains.contains_key(B), "the verified purge closed B's drain");
        let closed = &p.closed[B];
        assert_eq!((closed["verified"].as_bool(), closed["reason"].as_str()), (Some(true), Some("drain")));
        assert_eq!(closed["tmp_bytes_removed"], 307);
        assert_eq!(p.stored.as_ref().unwrap()["tenants"], serde_json::json!([{"tenant_id": A, "state": "running"}]));
        assert_eq!(p.stored.as_ref().unwrap()["placement_revision"], 42);
    }
    // Acknowledged: not sent again (the platform would refuse the whole
    // push, the drain being closed).
    assert!(ledger.snapshot().purged.is_empty());
    let s = reporter.push_once(&src).await;
    assert_eq!(s.outcome, PushOutcome::Accepted);
    assert_eq!(platform.lock().unwrap().stored.as_ref().unwrap()["purged"], serde_json::json!([]));

    // Every request carried the rotated-in token only after rotation, and a
    // well-formed body (no 400s).
    assert!(platform.lock().unwrap().requests.iter().all(|(c, _)| *c != 400));

    // The ledger survives a restart of the supervisor.
    let reopened = LedgerStore::open(&d.path().join("purge-ledger.json")).unwrap().snapshot();
    assert_eq!(reopened, ledger.snapshot());
}

#[tokio::test]
async fn forbidden_push_falls_back_and_settles_each_purge() {
    let d = tempfile::tempdir().unwrap();
    let tenants = d.path().join("tenants");
    std::fs::create_dir(&tenants).unwrap();
    let identity = d.path().join("identity.token");
    std::fs::write(&identity, "tok").unwrap();
    // B has an open drain here; C does not (a dedicated cell, or a drain
    // already closed by an earlier push whose response was lost).
    let platform = Arc::new(Mutex::new(Platform {
        enabled: true,
        valid_token: "tok".into(),
        placed: [A.to_string()].into_iter().collect(),
        drains: [(B.to_string(), chrono::Utc::now() - chrono::Duration::seconds(5))].into_iter().collect(),
        ..Default::default()
    }));
    let url = serve(platform.clone()).await;
    let reporter = Reporter::new(&url, CELL, identity).unwrap().with_retry(1, Duration::from_millis(1));
    let ledger = Arc::new(LedgerStore::memory());
    ledger.update(|l| (l.on_placement(&[tid(A), tid(B), tid(C)].into_iter().collect(), 1), true));
    ledger.update(|l| (l.on_placement(&[tid(A)].into_iter().collect(), 2), true));
    for t in [A, B, C] {
        populate(&tenants, t, A);
    }
    let a_before = digest(&tenants, A);
    purge_and_record(&tenants, &ledger, C);
    purge_and_record(&tenants, &ledger, B);
    assert_eq!(digest(&tenants, A), a_before);
    let src = LedgerSource {
        cell_id: CELL.into(),
        revision: Mutex::new(7),
        placed: Mutex::new(vec![(tid(A), TenantState::Idle)]),
        ledger: ledger.clone(),
    };
    let s = reporter.push_once(&src).await;
    // Whole push 403 (C) → placed-only accepted → B alone accepted, C alone
    // 403 and dropped.
    assert_eq!(s.outcome, PushOutcome::Accepted);
    assert_eq!(s.acknowledged, vec![tid(B)]);
    assert_eq!(s.dropped, vec![tid(C)]);
    assert!(ledger.snapshot().purged.is_empty());
    let p = platform.lock().unwrap();
    assert!(p.closed.contains_key(B) && !p.closed.contains_key(C));
    let codes: Vec<u16> = p.requests.iter().map(|(c, _)| *c).collect();
    assert_eq!(codes[0], 403, "{codes:?}");
    assert_eq!(codes.iter().filter(|c| **c == 204).count(), 2, "{codes:?}");
}

#[tokio::test]
async fn failures_keep_everything_for_the_next_push() {
    let d = tempfile::tempdir().unwrap();
    let identity = d.path().join("missing.token");
    let platform = Arc::new(Mutex::new(Platform { enabled: true, valid_token: "tok".into(), ..Default::default() }));
    let url = serve(platform.clone()).await;
    let ledger = Arc::new(LedgerStore::memory());
    ledger.update(|l| (l.on_placement(&[tid(B)].into_iter().collect(), 1), true));
    ledger.update(|l| (l.on_placement(&BTreeSet::new(), 2), true));
    ledger.update(|l| (l.record(&tid(B), Default::default(), chrono::Utc::now(), 3), true));
    let src = LedgerSource { cell_id: CELL.into(), revision: Mutex::new(1), placed: Mutex::new(vec![]), ledger: ledger.clone() };
    // No identity token: nothing sent.
    let r = Reporter::new(&url, CELL, identity.clone()).unwrap().with_retry(2, Duration::from_millis(1));
    assert_eq!(r.push_once(&src).await.outcome, PushOutcome::NoIdentity);
    assert!(platform.lock().unwrap().requests.is_empty());
    // Platform down (5xx on every attempt): bounded retries, kept.
    std::fs::write(&identity, "tok").unwrap();
    platform.lock().unwrap().fail_next = 10;
    assert_eq!(r.push_once(&src).await.outcome, PushOutcome::Failed);
    assert_eq!(platform.lock().unwrap().requests.len(), 2, "exactly the configured attempts");
    // Nobody listening: transport error, kept.
    let dead = Reporter::new("http://127.0.0.1:9", CELL, identity).unwrap().with_retry(1, Duration::from_millis(1));
    assert_eq!(dead.push_once(&src).await.outcome, PushOutcome::Failed);
    assert!(ledger.snapshot().purged.contains_key(&tid(B)));
    // A malformed cell id never reaches the wire.
    assert!(Reporter::new(&url, "../x", d.path().join("t")).is_err());
    let _ = src.snapshot();
}
