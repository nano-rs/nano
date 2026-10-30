// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local HTTP fixtures use R2PartStore -> S3 -> GcHttp -> CountingHttp.
use super::*;
use crate::lake_part_gc::planner::tests::{Chain, T0};
pub(crate) use crate::lake_part_gc::request::tests::TENANT_UUID;
use crate::part_ingest::s3_store::S3Location;
use crate::parts::format::LogKeys;
use crate::parts::part_log::ObjectStore;
use crate::parts::provenance::TenantKeySet;
use axum::{
    body::Body,
    extract::{Path as HttpPath, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::AtomicUsize;

#[path = "part_gc_catalog_wipe_tests.rs"]
mod catalog_wipe_tests;

#[path = "part_gc_receipt_tests.rs"]
pub(crate) mod receipt_tests;

struct Bucket {
    entries: RwLock<BTreeMap<u64, Vec<u8>>>,
    objects: RwLock<BTreeMap<String, Vec<u8>>>,
    delay: Duration,
    requests: std::sync::Mutex<Vec<(String, std::time::Instant)>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
    sent: AtomicU64,
    retry: AtomicBool,
    checkpoints: AtomicUsize,
    endless_pages: AtomicBool,
    body_mode: AtomicUsize,
    page_objects: AtomicUsize,
    /// NAN-4567: per-key LastModified for `objects` listings (default
    /// 2026-09-28T00:00:00Z), and a listing that leaks another tenant's key.
    modified: RwLock<BTreeMap<String, String>>,
    leak_foreign: AtomicBool,
}
struct Active(Arc<Bucket>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn object(
    State(bucket): State<Arc<Bucket>>,
    HttpPath((_name, key)): HttpPath<(String, String)>,
) -> Response {
    bucket
        .requests
        .lock()
        .unwrap()
        .push((key.clone(), std::time::Instant::now()));
    if bucket.retry.swap(false, Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "<Error><Code>SlowDown</Code></Error>",
        )
            .into_response();
    }
    let active = bucket.active.fetch_add(1, Ordering::SeqCst) + 1;
    bucket.max_active.fetch_max(active, Ordering::SeqCst);
    let held = Active(bucket.clone());
    let seq = key
        .rsplit('/')
        .next()
        .unwrap()
        .trim_end_matches(".json")
        .parse::<u64>()
        .ok();
    let bytes = if let Some(bytes) = bucket.objects.read().unwrap().get(&key).cloned() {
        Some(bytes)
    } else if key.contains("/entries/") {
        seq.and_then(|seq| bucket.entries.read().unwrap().get(&seq).cloned())
    } else {
        Some(b"invalid checkpoint".to_vec())
    };
    let status = if bytes.is_some() {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    };
    let bytes = bytes.unwrap_or_else(|| b"<Error><Code>NoSuchKey</Code></Error>".to_vec());
    let mode = bucket.body_mode.load(Ordering::SeqCst);
    if mode == 1 {
        drop(held);
        return Response::builder()
            .status(status)
            .header("content-length", 4 * 1024 * 1024 + 1)
            .body(Body::from_stream(futures::stream::pending::<
                Result<bytes::Bytes, std::io::Error>,
            >()))
            .unwrap();
    }
    let truncated_length = bytes.len();
    let count = if mode == 2 { 65 } else { 1 };
    let chunk = if mode == 2 { vec![b'x'; 65536] } else { bytes };
    let delay = if mode == 3 {
        Duration::from_secs(60)
    } else {
        bucket.delay
    };
    let stream = futures::stream::unfold((held, chunk, 0), move |(held, chunk, n)| async move {
        if n == count {
            return None;
        }
        tokio::time::sleep(delay).await;
        held.0.sent.fetch_add(chunk.len() as u64, Ordering::SeqCst);
        Some((
            Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(&chunk)),
            (held, chunk, n + 1),
        ))
    });
    let mut response = Response::builder().status(status);
    if mode == 4 {
        response = response.status(StatusCode::PARTIAL_CONTENT).header(
            "content-range",
            format!("bytes 0-{}/{}", truncated_length - 1, truncated_length + 1),
        );
    }
    response.body(Body::from_stream(stream)).unwrap()
}

async fn listing(
    State(bucket): State<Arc<Bucket>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    bucket
        .requests
        .lock()
        .unwrap()
        .push(("LIST".into(), std::time::Instant::now()));
    let prefix = query.get("prefix").cloned().unwrap_or_default();
    if prefix.contains("/bronze-quarantine-v1/")
        || (prefix.ends_with("/parts/") && bucket.page_objects.load(Ordering::SeqCst) == 0)
    {
        // NAN-4567: the stored objects under the prefix, one page.
        let modified = bucket.modified.read().unwrap();
        let mut keys: Vec<(String, usize)> = bucket.objects.read().unwrap().iter()
            .filter(|(key, _)| key.starts_with(&prefix)).map(|(key, bytes)| (key.clone(), bytes.len())).collect();
        if bucket.leak_foreign.load(Ordering::SeqCst) {
            keys.push((format!("{prefix}objects/{}.parquet", "f".repeat(64))
                .replace(TENANT_UUID, "7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00"), 10));
        }
        let objects = keys.iter().map(|(key, size)| format!(
            "<Contents><Key>{key}</Key><Size>{size}</Size><LastModified>{}</LastModified><ETag>e-{size}</ETag></Contents>",
            modified.get(key).map_or("2026-09-28T00:00:00.000Z", String::as_str))).collect::<String>();
        return (StatusCode::OK, [("content-type", "application/xml")],
            format!("<ListBucketResult><IsTruncated>false</IsTruncated>{objects}</ListBucketResult>")).into_response();
    }
    let total = bucket.page_objects.load(Ordering::SeqCst);
    if total > 0 {
        let start = query.get("continuation-token").and_then(|n| n.parse::<usize>().ok())
            .unwrap_or_else(|| query.get("start-after").and_then(|key| key.rsplit('/').next()?.trim_end_matches(".json").parse::<usize>().ok()).map_or(0, |n| n + 1));
        let end = (start + 64).min(total);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let objects = (start..end).map(|n| format!("<Contents><Key>{prefix}{n:020}.json</Key><Size>10</Size><LastModified>2026-09-28T00:00:00.000Z</LastModified><ETag>e</ETag></Contents>")).collect::<String>();
        let next = if end < total { format!("<NextContinuationToken>{end}</NextContinuationToken>") } else { String::new() };
        return (StatusCode::OK, [("content-type", "application/xml")], format!("<ListBucketResult><IsTruncated>{}</IsTruncated>{next}{objects}</ListBucketResult>", end < total)).into_response();
    }
    let count = bucket.checkpoints.load(Ordering::SeqCst);
    // Pages like S3: max-keys, start-after and continuation tokens (NAN-4160).
    let start = query.get("continuation-token").and_then(|n| n.parse::<usize>().ok())
        .or_else(|| query.get("start-after").and_then(|key| key.rsplit('/').next()?.trim_end_matches(".json").parse::<usize>().ok()).map(|n| n + 1))
        .unwrap_or(0).min(count);
    let end = query.get("max-keys").and_then(|n| n.parse::<usize>().ok()).map_or(count, |max| (start + max).min(count));
    let entries = (start..end)
        .map(|n| format!("<Contents><Key>{prefix}{n:020}.json</Key><Size>10</Size><LastModified>2026-09-28T00:00:00.000Z</LastModified><ETag>e</ETag></Contents>"))
        .collect::<String>();
    let paging = if bucket.endless_pages.load(Ordering::SeqCst) {
        "<IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken>".to_string()
    } else if end < count {
        format!("<IsTruncated>true</IsTruncated><NextContinuationToken>{end}</NextContinuationToken>")
    } else {
        "<IsTruncated>false</IsTruncated>".to_string()
    };
    (
        StatusCode::OK,
        [("content-type", "application/xml")],
        format!("<ListBucketResult>{paging}{entries}</ListBucketResult>"),
    )
        .into_response()
}

pub(crate) struct Fixture {
    bucket: Arc<Bucket>,
    pub(crate) store: Arc<R2PartStore>,
    gc: CellSanctionedPartGc,
    server: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
    location: S3Location,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn history(entries: u64) -> BTreeMap<u64, Vec<u8>> {
    let mut chain = Chain::new();
    for n in 1..entries {
        chain.add(n, T0 + n as i64);
    }
    chain
        .entries
        .into_iter()
        .map(|(entry, _)| (entry.seq, entry.to_bytes().unwrap()))
        .collect()
}

pub(crate) fn permission(gc: &CellSanctionedPartGc, rate: u32, ttl: chrono::Duration) {
    permission_with_owner_ttl(gc, rate, ttl, chrono::Duration::minutes(10));
}

fn permission_with_owner_ttl(
    gc: &CellSanctionedPartGc,
    rate: u32,
    ttl: chrono::Duration,
    owner_ttl: chrono::Duration,
) {
    let access = LakePartGcAccess::parse(&serde_json::json!({
        "schema_version": 1,
        "owner_delete": {"token":"fixture", "audience":"owner", "scope":OWNER_DELETE_SCOPE,
            "expires_at": (chrono::Utc::now() + owner_ttl).to_rfc3339()},
        "retention_authority":{"url":"https://127.0.0.1:1/", "token":"fixture"},
        "policy":{"log_reads_per_second":rate}
    }))
    .unwrap();
    gc.update(
        Some(&access),
        Some(&serde_json::json!({
            "schema_version":1, "tenant_id":gc.shared.tenant_uuid, "tenant_slug":"fixture", "enabled":true,
            "expires_at":(chrono::Utc::now() + ttl).to_rfc3339()
        })),
    );
}

pub(crate) fn fixture_keys() -> TenantKeySet {
    TenantKeySet::new([(
        crate::parts::provenance::tests::SIGNER.into(),
        crate::parts::provenance::tests::test_key(7).verifying_key(),
    )])
}

pub(crate) async fn fixture(entries: u64, delay: Duration, rate: u32) -> Fixture {
    fixture_with_owner(entries, delay, rate, "http://127.0.0.1:1/").await
}

async fn fixture_with_owner(entries: u64, delay: Duration, rate: u32, owner_url: &str) -> Fixture {
    fixture_for_tenant(entries, delay, rate, owner_url, TENANT_UUID, None).await
}

async fn fixture_for_tenant(
    entries: u64, delay: Duration, rate: u32, owner_url: &str, tenant: &str, worker_http: Option<reqwest::Client>,
) -> Fixture {
    let mut log = history(entries);
    if tenant != TENANT_UUID {
        let mut prev = crate::parts::part_log::GENESIS_PREV.to_string();
        for raw in log.values_mut() {
            let mut entry = crate::parts::part_log::LogEntry::parse_bytes(raw, TENANT_UUID).unwrap();
            entry.tenant_id = tenant.into();
            entry.prev_sha256 = prev;
            *raw = entry.to_bytes().unwrap();
            prev = crate::parts::sha256_hex(raw);
        }
    }
    let bucket = Arc::new(Bucket {
        entries: RwLock::new(log),
        objects: RwLock::new(BTreeMap::new()),
        delay,
        requests: Default::default(),
        active: AtomicUsize::new(0),
        max_active: AtomicUsize::new(0),
        sent: AtomicU64::new(0),
        retry: AtomicBool::new(false),
        checkpoints: AtomicUsize::new(0),
        endless_pages: AtomicBool::new(false),
        body_mode: AtomicUsize::new(0),
        page_objects: AtomicUsize::new(0),
        modified: RwLock::new(BTreeMap::new()),
        leak_foreign: AtomicBool::new(false),
    });
    let app = Router::new()
        .route("/{bucket}", get(listing))
        .route("/{bucket}/", get(listing))
        .route("/{bucket}/{*key}", get(object))
        .with_state(bucket.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let location = S3Location {
        endpoint: format!("http://{}", listener.local_addr().unwrap()),
        region: "auto".into(),
        bucket: "fixture".into(),
        prefix: String::new(),
        access_key_id: "fixture".into(),
        secret_access_key: "fixture".into(),
        session_token: None,
    };
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        R2PartStore::new_split(&location, &location, tenant, &dir.path().join("spill"))
            .unwrap(),
    );
    let gc = CellSanctionedPartGc::new_guarded(
        tenant,
        owner_url,
        None,
        store.clone(),
        fixture_keys(),
        dir.path(),
        None,
        worker_http,
    )
    .unwrap()
    // Every slice persists: these tests read the view back after folds.
    .with_view_save_interval(Duration::ZERO);
    permission(&gc, rate, chrono::Duration::minutes(10));
    Fixture {
        bucket,
        store,
        gc,
        server,
        dir,
        location,
    }
}

async fn fold(f: &Fixture) {
    loop {
        let mut state = f.gc.state.lock().await;
        if advance_view(f.gc.shared.views.as_ref(), &f.gc.shared, &mut state)
            .await
            .unwrap()
        {
            break;
        }
    }
}

/// NAN-4380: the fixture builds `new_guarded`, the same constructor the cell
/// uses. Exercise its actual prepare/retire seams; no permissive `new()` path.
#[tokio::test]
async fn guarded_gc_never_planned_parts_get_local_receipts_before_worker_delete() {
    guarded_gc_catalog_case(false).await;
}

#[tokio::test]
async fn guarded_gc_historical_parts_reach_the_worker_with_the_agent_lane_degraded_when_the_cache_fails() {
    guarded_gc_catalog_case(true).await;
}

async fn guarded_gc_catalog_case(ever_planned: bool) {
    use crate::part_ingest::iceberg_export::lifecycle::{test_support::Basin, TenantCatalog};
    use crate::parts::part_log::{LocalObjectStore, PartLogWriter};
    let f = fixture(1, Duration::ZERO, 200).await;
    let local = tempfile::tempdir().unwrap();
    let source = Arc::new(LocalObjectStore::new(local.path().join("parts")).unwrap());
    let writer = PartLogWriter::open(source.as_ref(), TENANT_UUID, 1,
        &crate::part_ingest::ingest::seed_schema(), chrono::Utc::now().timestamp_millis()).await.unwrap();
    drop(writer);
    let backend = Basin::new(TENANT_UUID, local.path().into(), source, fixture_keys()).await;
    if ever_planned {
        let history = local.path().join("catalog/export/committed");
        std::fs::create_dir_all(&history).unwrap();
        let manifest = crate::part_ingest::export::ExportManifest {
            tenant_id: TENANT_UUID.into(), planned_at_ms: 1, previous_plan_ms: None,
            add: vec![], remove_parts: vec![crate::lake_part_gc::request::tests::PART.into()], hours: vec![],
        };
        std::fs::write(history.join("0000000000001.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
    }
    let catalog = Arc::new(TenantCatalog::new(TENANT_UUID, local.path().join("catalog"), backend.clone()).unwrap());
    f.gc.attach_catalog(catalog.clone()).unwrap();
    let seams = Seams { shared: f.gc.shared.clone(), fence: InventoryFence::capture(&f.gc.shared).unwrap(),
        receipted: std::sync::Mutex::new(vec![]), catalog_pass: Default::default() };
    let request = crate::lake_part_gc::request::tests::superseded();
    let now = chrono::Utc::now();
    let permit = LakePartDeletePermit { permit_id: request.permit_id().unwrap(),
        owner_authorization: crate::lake_part_gc::delete_control::DeleteOwnerAuthorization {
            schema_version: 1, signer_key_id: "fixture-owner".into(), issued_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
            identity_sha256: request.digest().unwrap(), signature_base64: "fixture-signature".into(),
        }, request };
    catalog.sync_parts(TENANT_UUID, vec![], now.timestamp_millis(), &crate::parts::levels::MergePolicy::default()).await.unwrap();
    let checks = backend.checks.load(Ordering::SeqCst);
    backend.fail_cache.store(true, Ordering::SeqCst);
    let part = crate::lake_part_gc::request::tests::PART;
    if ever_planned {
        // Part GC is never gated on the agent catalog: an unacknowledged
        // result cache degrades the lane (reads closed) and the Worker is
        // reached on both seams.
        for retired in [false, true] {
            let error = if retired { seams.retire(&permit).await.unwrap_err() } else { seams.prepare(&permit).await.unwrap_err() };
            assert!(error.to_string().contains("retention authority"), "the Worker is reached: {error:#}");
        }
        assert_eq!(catalog.require_removed(TENANT_UUID, part).unwrap().manifest_sha256,
            crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(TENANT_UUID, part));
        assert!(backend.blocked.load(Ordering::SeqCst), "agent reads closed");
        backend.fail_cache.store(false, Ordering::SeqCst);
    }
    // A failed inspection stays cached for that pass. Recovery gets a new pass.
    let seams = Seams { shared: f.gc.shared.clone(), fence: InventoryFence::capture(&f.gc.shared).unwrap(),
        receipted: std::sync::Mutex::new(vec![]), catalog_pass: Default::default() };
    // The fake Worker is deliberately unavailable: once custody is receipted,
    // the operation reaches that exact production transport and fails there.
    let error = seams.prepare(&permit).await.unwrap_err();
    assert!(error.to_string().contains("retention authority"), "{error:#}");
    catalog.require_removed(TENANT_UUID, part).unwrap();
    let error = seams.retire(&permit).await.unwrap_err();
    assert!(error.to_string().contains("retention authority"), "{error:#}");
    if !ever_planned { assert_eq!(backend.checks.load(Ordering::SeqCst), checks, "never-planned parts use no catalog calls"); }
    let mut foreign = permit.clone();
    foreign.request.tenant_uuid = "3867bbbb-0000-4000-8000-000000000002".into();
    assert!(seams.retire(&foreign).await.unwrap_err().to_string().contains("cross-tenant"));
}

#[tokio::test]
async fn production_http_ordered_window_throughput_and_bounds() {
    const N: u64 = 96;
    let serial = fixture(N, Duration::from_millis(60), 100).await;
    let started = std::time::Instant::now();
    let mut view = LakePartLogView::genesis();
    for seq in 0..=N {
        let Some(entry) = serial.gc.shared.reader.verified_entry(seq).await.unwrap() else {
            break;
        };
        view.apply(&entry.entry, &entry.sha256).unwrap();
    }
    let serial_time = started.elapsed();
    let parallel = fixture(N, Duration::from_millis(60), 100).await;
    let started = std::time::Instant::now();
    fold(&parallel).await;
    let parallel_time = started.elapsed();
    assert_eq!(
        parallel.gc.state.lock().await.view.head_seq(),
        view.head_seq()
    );
    assert!(
        parallel_time < serial_time / 2,
        "serial={serial_time:?} parallel={parallel_time:?}"
    );
    assert!(parallel.bucket.max_active.load(Ordering::SeqCst) <= READ_AHEAD_WINDOW);
    let requests = parallel.bucket.requests.lock().unwrap();
    assert!(requests.len() <= N as usize + READ_AHEAD_WINDOW);
    // Attempt starts are observed immediately before CountingHttp; provider
    // dispatch can bunch together and is not the client pacing boundary.
    let starts = parallel.gc.shared.transport_observation.attempt_times.lock().unwrap();
    assert_eq!(starts.len(), requests.len());
    for pair in starts.windows(2) {
        assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(8));
    }
    println!(
        "NAN3116 identical100RPS serial_ms={} ordered8_ms={} speedup={:.2} serial_requests={} ordered_requests={} max_http={} reserved_raw={} parsed_allowance={} actual_body_bytes={} peak_body={} peak_chunk={}",
        serial_time.as_millis(),
        parallel_time.as_millis(),
        serial_time.as_secs_f64() / parallel_time.as_secs_f64(),
        serial.bucket.requests.lock().unwrap().len(),
        requests.len(),
        parallel.bucket.max_active.load(Ordering::SeqCst),
        RAW_READ_AHEAD_BUDGET,
        PARSED_ENTRY_BUDGET,
        parallel
            .gc
            .shared
            .transport_observation
            .body_bytes
            .load(Ordering::Relaxed),
        parallel
            .gc
            .shared
            .transport_observation
            .peak_body
            .load(Ordering::Relaxed),
        parallel
            .gc
            .shared
            .transport_observation
            .peak_chunk
            .load(Ordering::Relaxed)
    );
}

#[tokio::test]
async fn production_http_retries_caps_and_checkpoint_limits() {
    let f = fixture(2, Duration::ZERO, 100).await;
    let key = LogKeys::new(TENANT_UUID).unwrap().entry(0);
    f.bucket.retry.store(true, Ordering::SeqCst);
    assert!(f.store.get(&key).await.unwrap().is_some());
    assert_eq!(f.bucket.requests.lock().unwrap().len(), 2);
    assert_eq!(f.gc.reads(), 2, "logical get must not double-charge");
    let timestamps = f.gc.shared.transport_observation.attempt_times.lock().unwrap();
    assert!(timestamps[1].duration_since(timestamps[0]) >= Duration::from_millis(10));
    drop(timestamps);
    for mode in [1, 2, 4] {
        f.bucket.body_mode.store(mode, Ordering::SeqCst);
        let before = f.bucket.requests.lock().unwrap().len();
        assert!(f.store.get(&key).await.is_err(), "body mode {mode}");
        assert_eq!(
            f.bucket.requests.lock().unwrap().len(),
            before + 1,
            "cap refusal must not retry"
        );
    }
    f.bucket.body_mode.store(0, Ordering::SeqCst);
    // NAN-4160: a prefix past one guarded page is paged, not refused; these
    // fixture checkpoints have no bodies, so the candidate cap still holds.
    f.bucket.checkpoints.store(257, Ordering::SeqCst);
    let lists = f.bucket.requests.lock().unwrap().iter().filter(|(op, _)| op == "LIST").count();
    assert!(f
        .gc
        .shared
        .reader
        .newest_checkpoint()
        .await
        .unwrap_err()
        .to_string()
        .contains("candidate limit"));
    assert_eq!(f.bucket.requests.lock().unwrap().iter().filter(|(op, _)| op == "LIST").count() - lists, 2,
        "257 numbered keys are two bounded pages");
    f.bucket.checkpoints.store(17, Ordering::SeqCst);
    assert!(f
        .gc
        .shared
        .reader
        .newest_checkpoint()
        .await
        .unwrap_err()
        .to_string()
        .contains("candidate limit"));
    f.bucket.checkpoints.store(0, Ordering::SeqCst);
    f.bucket.endless_pages.store(true, Ordering::SeqCst);
    let before = f.bucket.requests.lock().unwrap().len();
    assert!(f.gc.shared.reader.newest_checkpoint().await.is_err());
    assert_eq!(f.bucket.requests.lock().unwrap().len() - before, 16);
}

#[tokio::test]
async fn production_http_withdraw_expire_cancel_and_refresh() {
    for expiry in [0, 1, 2] {
        let f = fixture(32, Duration::ZERO, 1).await;
        f.bucket.body_mode.store(3, Ordering::SeqCst);
        if expiry == 1 {
            permission(&f.gc, 1, chrono::Duration::milliseconds(120));
        } else if expiry == 2 {
            permission_with_owner_ttl(
                &f.gc,
                1,
                chrono::Duration::minutes(10),
                BEARER_SKEW + chrono::Duration::milliseconds(120),
            );
        }
        let work = async {
            let mut state = f.gc.state.lock().await;
            advance_view(f.gc.shared.views.as_ref(), &f.gc.shared, &mut state).await
        };
        let stop = async {
            while f.bucket.active.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if expiry == 0 {
                f.gc.update(None, None);
            }
        };
        let (result, ()) = tokio::join!(work, stop);
        assert!(result.is_err());
        assert!(f.gc.state.lock().await.view.head_seq().is_none());
        let requests = f.bucket.requests.lock().unwrap().len();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            f.bucket.active.load(Ordering::SeqCst),
            0,
            "cancelled body must close"
        );
        assert_eq!(
            f.bucket.requests.lock().unwrap().len(),
            requests,
            "no residual queued attempts"
        );
        assert_eq!(requests, 1);
        permission(&f.gc, 100, chrono::Duration::minutes(10));
        f.bucket.body_mode.store(0, Ordering::SeqCst);
        fold(&f).await;
        assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(31));
    }
    let f = fixture(10, Duration::ZERO, 100).await;
    f.bucket.body_mode.store(3, Ordering::SeqCst);
    let mut state = f.gc.state.lock().await;
    assert!(tokio::time::timeout(
        Duration::from_millis(100),
        advance_view(None, &f.gc.shared, &mut state)
    )
    .await
    .is_err());
    drop(state);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.bucket.active.load(Ordering::SeqCst), 0);
    let count = f.bucket.requests.lock().unwrap().len();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.bucket.requests.lock().unwrap().len(), count);
}

#[tokio::test]
async fn production_http_large_history_arrivals_gap_chain_persistence() {
    let f = fixture(4200, Duration::ZERO, 200).await;
    let partial = f.gc.run_pass_now(T0).await.unwrap();
    assert_eq!(partial.paused_reason.as_deref(), Some("log_catching_up"));
    assert_eq!(partial.deleted, 0);
    assert!(f.gc.state.lock().await.view.head_seq().unwrap() < VIEW_PERSIST_EVERY);
    assert!(
        f.bucket
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|(key, _)| key != "LIST"),
        "partial view cannot enter listing/deletion"
    );
    // Append during catch-up, before the terminal head is captured.
    *f.bucket.entries.write().unwrap() = history(4213);
    fold(&f).await;
    assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(4212));
    assert_eq!(
        f.gc.shared
            .views
            .as_ref()
            .unwrap()
            .load(TENANT_UUID)
            .unwrap()
            .unwrap()
            .head_seq(),
        Some(4212)
    );
    assert!(f.bucket.max_active.load(Ordering::SeqCst) <= READ_AHEAD_WINDOW);
    let g = fixture(32, Duration::from_millis(10), 200).await;
    g.bucket.entries.write().unwrap().remove(&3);
    fold(&g).await;
    assert_eq!(g.gc.state.lock().await.view.head_seq(), Some(2));
    assert!(g
        .bucket
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|(key, _)| key.ends_with("00000000000000000004.json")));
    // A gap is terminal for this captured prefix, and a later executor fold
    // cannot bridge it. No provider mutation ever exists in this fixture.
    assert!(g
        .bucket
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|(key, _)| key != "DELETE"));
    for defect in [0, 1, 2] {
        let bad = fixture(20, Duration::ZERO, 200).await;
        let raw = bad.bucket.entries.read().unwrap()[&5].clone();
        let mut entry = crate::parts::part_log::LogEntry::parse_bytes(&raw, TENANT_UUID).unwrap();
        match defect {
            0 => entry.prev_sha256 = "f".repeat(64),
            1 => entry.seq = 6,
            _ => entry.writer_epoch = 0,
        }
        bad.bucket
            .entries
            .write()
            .unwrap()
            .insert(5, entry.to_bytes().unwrap());
        let mut state = bad.gc.state.lock().await;
        assert!(advance_view(None, &bad.gc.shared, &mut state)
            .await
            .is_err());
        assert_eq!(state.view.head_seq(), Some(4));
    }
    let save = fixture(40, Duration::ZERO, 200).await;
    let path = save.dir.path().join("lake-part-gc/view.sqlite");
    std::fs::create_dir_all(&path).unwrap();
    let mut state = save.gc.state.lock().await;
    assert!(
        advance_view(save.gc.shared.views.as_ref(), &save.gc.shared, &mut state)
            .await
            .is_err()
    );
    let count = save.gc.reads();
    let head = state.view.head_seq();
    assert!(
        advance_view(save.gc.shared.views.as_ref(), &save.gc.shared, &mut state)
            .await
            .is_err()
    );
    assert_eq!(save.gc.reads(), count);
    assert_eq!(state.view.head_seq(), head);
    std::fs::remove_dir(&path).unwrap();
    assert!(
        advance_view(save.gc.shared.views.as_ref(), &save.gc.shared, &mut state)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn production_http_complete_view_publication_keeps_fresh_arrival_fence() {
    let f = fixture(32, Duration::ZERO, 200).await;
    fold(&f).await;
    let index = crate::lake_part_gc::index::tests::FakeIndex::new(Vec::new());
    let reader = CompleteViewReader {
        shared: f.gc.shared.clone(), head: Some(31),
        fence: InventoryFence::capture(&f.gc.shared).unwrap(),
        checkpoint: Arc::new(tokio::sync::Mutex::new(None)),
        advanced: AtomicBool::new(false),
    };
    let outcome = crate::lake_part_gc::index::sync_index_through_view(
        &index, &reader, TENANT_UUID, Some(31), T0 + 86_400_000, None,
    ).await.unwrap();
    assert!(matches!(outcome, crate::lake_part_gc::index::IndexSyncOutcome::Synced {
        caught_up: true, pushed: 32, ..
    }));
    assert_eq!(index.shas.lock().unwrap().len(), 32);
    // Publishing a captured prefix is not an absence assertion. Actual guarded
    // HTTP must still observe a new tail, and only bounded fold may apply it.
    *f.bucket.entries.write().unwrap() = history(33);
    let before = f.bucket.requests.lock().unwrap().len();
    assert!(reader.verified_entry(32).await.is_err());
    assert!(reader.advanced.load(Ordering::SeqCst));
    assert!(f.bucket.requests.lock().unwrap()[before..].iter()
        .any(|(key, _)| key.ends_with("00000000000000000032.json")));
    assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(31));
    fold(&f).await;
    assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(32));
    let current = CompleteViewReader { head: Some(32), advanced: AtomicBool::new(false), ..reader };
    let outcome = crate::lake_part_gc::index::sync_index_through_view(
        &index, &current, TENANT_UUID, Some(32), T0 + 86_400_000, None,
    ).await.unwrap();
    let view = f.gc.state.lock().await;
    let (head, sha, _) = view.view.live().head().unwrap();
    assert!(matches!(outcome, crate::lake_part_gc::index::IndexSyncOutcome::Synced { status, caught_up: true, pushed: 1, .. }
        if status.indexed_through_seq == Some(head) && status.head_entry_sha256.as_deref() == Some(sha)));
    assert!(f.bucket.requests.lock().unwrap().iter().all(|(key, _)| key != "DELETE"));
    // No mock permit/receipt is fabricated here; positive owner/Worker
    // retirement remains the separate sanctioned-route TLS coverage domain.
}

#[tokio::test]
async fn production_http_owner_index_and_retry_generation() {
    let f = fixture(32, Duration::ZERO, 100).await;
    fold(&f).await;
    let index = crate::lake_part_gc::index::tests::FakeIndex::new(Vec::new());
    let reader = CompleteViewReader {
        shared: f.gc.shared.clone(),
        head: Some(31),
        fence: InventoryFence {
            route: f.gc.shared.current().unwrap(),
            epoch: f.gc.shared.route_epoch.load(Ordering::SeqCst),
            scope: f.gc.shared.lister.inventory_scope(),
            deadline: tokio::time::Instant::now() + INVENTORY_LIFETIME,
        },
        checkpoint: Arc::new(tokio::sync::Mutex::new(None)),
        advanced: AtomicBool::new(false),
    };
    let before = f.gc.reads();
    let requests = f.bucket.requests.lock().unwrap().len();
    let outcome = crate::lake_part_gc::index::sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None)
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        crate::lake_part_gc::index::IndexSyncOutcome::Synced {
            caught_up: true,
            ..
        }
    ));
    assert_eq!(index.shas.lock().unwrap().len(), 32);
    assert_eq!(
        f.gc.reads() - before,
        (f.bucket.requests.lock().unwrap().len() - requests) as u64
    );
    f.bucket.checkpoints.store(257, Ordering::SeqCst);
    // Start a fresh discovery lifetime: immutable inventories cache an admitted
    // checkpoint, so changing this provider fixture must not reuse that cache.
    *reader.checkpoint.lock().await = None;
    assert!(
        crate::lake_part_gc::index::sync_index(&index, &reader, TENANT_UUID, T0 + 86_400_000, None)
            .await
            .is_err(),
        "owner indexing must use bounded discovery"
    );
    f.bucket.checkpoints.store(0, Ordering::SeqCst);
    let key = LogKeys::new(TENANT_UUID).unwrap().entry(0);
    let requests = f.bucket.requests.lock().unwrap().len();
    let stale = f.store.gc_operator_snapshot(&key);
    f.bucket.retry.store(true, Ordering::SeqCst);
    let work = f.store.get(&key);
    let refresh = async {
        while f.bucket.requests.lock().unwrap().len() == requests {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
        f.gc.update(None, None);
        f.store.replace_split(&f.location, &f.location).unwrap();
        permission(&f.gc, 200, chrono::Duration::minutes(10));
    };
    let (old, ()) = tokio::join!(work, refresh);
    assert!(
        old.is_err(),
        "old RetryLayer operation must be cancelled during its delay"
    );
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        f.bucket.requests.lock().unwrap().len(),
        requests + 1,
        "no old generation retry after refresh"
    );
    assert!(
        stale.read(&key).await.is_err(),
        "old operator snapshot must refuse after refresh"
    );
    assert_eq!(f.bucket.requests.lock().unwrap().len(), requests + 1);
    let before = f.gc.reads();
    assert!(f.store.get(&key).await.unwrap().is_some());
    assert_eq!(f.gc.reads(), before + 1);
    assert_eq!(f.gc.shared.pacer.per_second.load(Ordering::Relaxed), 200);
    assert!(f
        .store
        .delete(&format!("lake/parts/v1/tenant={TENANT_UUID}/parts/l0/x"))
        .await
        .is_err());
}

#[test]
fn dense_parse_is_refused_before_deserialization() {
    let mut raw = b"[".to_vec();
    raw.extend_from_slice(&b"0,".repeat(100_000));
    raw.extend_from_slice(b"0]");
    assert!(raw.len() < crate::parts::format::MAX_LOG_OBJECT_BYTES);
    assert!(gc_parsed_preflight(&raw).is_err());
    assert!(gc_parsed_preflight(br#"{"field":"\\\"{[,:"}"#).is_ok());
}

#[tokio::test]
async fn production_http_valid_checkpoint_and_signed_provenance() {
    use crate::parts::format::PartKeys;
    use crate::parts::part_log::PartRef;
    use crate::parts::provenance::{Ed25519Signature, SignedProvenance};
    use base64::Engine;
    use ed25519_dalek::Signer;
    let f = fixture(2, Duration::ZERO, 100).await;
    let mut chain = Chain::new();
    chain.add(1, T0 + 1);
    let checkpoint = chain.view().live().checkpoint(TENANT_UUID).unwrap();
    let keys = LogKeys::new(TENANT_UUID).unwrap();
    f.bucket.objects.write().unwrap().insert(
        keys.checkpoint(checkpoint.seq),
        checkpoint.to_bytes().unwrap().unwrap(),
    );
    f.bucket.checkpoints.store(2, Ordering::SeqCst);
    let before = f.gc.reads();
    let claim =
        f.gc.shared
            .reader
            .newest_checkpoint()
            .await
            .unwrap()
            .unwrap();
    assert_eq!(claim.seq, 1);
    assert_eq!(
        f.gc.reads() - before,
        3,
        "list + checkpoint + corresponding entry each reacquire pacer"
    );
    let mut record = crate::parts::provenance::tests::sample_record();
    record.tenant_id = TENANT_UUID.into();
    record.signer_key_id = crate::parts::provenance::tests::SIGNER.into();
    let key = crate::parts::provenance::tests::test_key(7);
    let signature = Ed25519Signature {
        alg: "ed25519".into(),
        key_id: crate::parts::provenance::tests::SIGNER.into(),
        sig: base64::engine::general_purpose::STANDARD
            .encode(key.sign(&record.signing_message().unwrap()).to_bytes()),
    };
    let signed = SignedProvenance::assemble(record, signature, &fixture_keys()).unwrap();
    let bytes = signed.to_bytes().unwrap();
    let part = PartRef::from_record(&signed.record, &crate::parts::sha256_hex(&bytes), true);
    let path = PartKeys::new(TENANT_UUID, part.level, part.event_hour, &part.part_id)
        .unwrap()
        .provenance();
    f.bucket
        .objects
        .write()
        .unwrap()
        .insert(path.clone(), bytes);
    let before = f.gc.reads();
    assert_eq!(
        f.gc.shared.reader.verified_provenance(&part).await.unwrap(),
        signed.record
    );
    assert_eq!(f.gc.reads() - before, 1);
    // The provenance cap is 1 MiB, stricter than the log cap: both advertised
    // and chunked actual bodies are refused in the actual GC HTTP hook.
    f.bucket.body_mode.store(1, Ordering::SeqCst);
    assert!(f.store.get(&path).await.is_err());
    f.bucket.body_mode.store(0, Ordering::SeqCst);
    f.bucket
        .objects
        .write()
        .unwrap()
        .insert(path.clone(), vec![b'x'; 1024 * 1024 + 1]);
    assert!(f.gc.shared.reader.verified_provenance(&part).await.is_err());
    f.bucket.body_mode.store(2, Ordering::SeqCst);
    assert!(f.store.get(&path).await.is_err());
    for pair in f.gc.shared.transport_observation.attempt_times.lock().unwrap().windows(2) {
        assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(8));
    }
}

/// A real guarded R2 reader, fresh pod/store/GC runtime per roll, the same
/// persistent A/B volume. Cover both a mid-rebuild roll and a completed tail
/// reached inside the normal 60-second checkpoint throttle.
#[tokio::test]
async fn production_gc_roll_resumes_partial_and_commits_completed_history_on_hot_volume() {
    fn boot(f: &Fixture, pod: &std::path::Path, hot: &std::path::Path) -> CellSanctionedPartGc {
        let store = Arc::new(R2PartStore::new_split(&f.location, &f.location, TENANT_UUID,
            &pod.join("spill")).unwrap());
        let gc = CellSanctionedPartGc::new_guarded(TENANT_UUID, "http://127.0.0.1:1/", None,
            store, fixture_keys(), pod, Some(hot), None).unwrap();
        permission(&gc, 200, chrono::Duration::minutes(10));
        gc.shared.pacer.set_rate(0);
        gc
    }
    let entries = VIEW_PERSIST_EVERY * 2 + 10;
    let f = fixture(entries, Duration::ZERO, 200).await;
    let hot = tempfile::tempdir().unwrap();
    let pod = tempfile::tempdir().unwrap();
    let first = boot(&f, pod.path(), hot.path());
    let saved_head = {
        let mut state = first.state.lock().await;
        assert!(!advance_view(first.shared.views.as_ref(), &first.shared, &mut state).await.unwrap());
        let head = state.view.head_seq().unwrap();
        assert!(head > 0 && head < entries - 1, "a bounded slice stops inside the rebuild");
        head
    };
    assert!(hot.path().join("lake-part-gc/view.sqlite").is_file());
    assert!(!pod.path().join("lake-part-gc").exists());
    drop(first);
    drop(pod);

    let pod = tempfile::tempdir().unwrap();
    let second = boot(&f, pod.path(), hot.path());
    {
        let mut state = second.state.lock().await;
        assert!(!advance_view(second.shared.views.as_ref(), &second.shared, &mut state).await.unwrap());
        let head = state.view.head_seq().unwrap();
        assert!(head > saved_head);
        assert!(second.reads() <= head - saved_head + 1 + READ_AHEAD_WINDOW as u64,
            "verify saved head, new entries and bounded speculation, never genesis");
        let checkpoint_at = tokio::time::Instant::now();
        let mut complete = false;
        for _ in 0..20 {
            complete = advance_view(second.shared.views.as_ref(), &second.shared, &mut state).await.unwrap();
            if complete { break; }
        }
        assert!(complete, "the resumed rebuild reaches its tail");
        assert!(checkpoint_at.elapsed() < VIEW_SAVE_EVERY, "completion is inside the checkpoint throttle");
        let views = second.shared.views.as_ref().unwrap();
        assert!(!views.save_due());
        assert_eq!(views.load(TENANT_UUID).unwrap().unwrap().head_seq(), Some(entries - 1),
            "completed history must already be durable before a roll");
        assert!(views.load("7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00").is_err(),
            "a persisted volume never authorizes another tenant's history");
    }
    drop(second);
    drop(pod);

    *f.bucket.entries.write().unwrap() = history(entries + 5);
    let pod = tempfile::tempdir().unwrap();
    let third = boot(&f, pod.path(), hot.path());
    let mut state = third.state.lock().await;
    assert!(advance_view(third.shared.views.as_ref(), &third.shared, &mut state).await.unwrap());
    assert_eq!(state.view.head_seq(), Some(entries + 4));
    assert!(third.reads() <= 8, "roll verifies head + five new entries + tail, never genesis");
    assert!(!pod.path().join("lake-part-gc").exists());
}

#[tokio::test]
async fn production_http_resume_and_background_backoff() {
    let f = fixture(64, Duration::ZERO, 200).await;
    fold(&f).await;
    let resumed = CellSanctionedPartGc::new_guarded(
        TENANT_UUID,
        "http://127.0.0.1:1/",
        None,
        f.store.clone(),
        fixture_keys(),
        f.dir.path(),
        None,
        None,
    )
    .unwrap();
    permission(&resumed, 200, chrono::Duration::minutes(10));
    let mut state = resumed.state.lock().await;
    assert!(
        advance_view(resumed.shared.views.as_ref(), &resumed.shared, &mut state)
            .await
            .unwrap()
    );
    assert_eq!(state.view.head_seq(), Some(63));
    assert!(
        resumed.reads() <= 9,
        "one saved-head verification and at most eight terminal probes"
    );
    drop(state);
    let bad = fixture(20, Duration::ZERO, 200).await;
    let raw = bad.bucket.entries.read().unwrap()[&5].clone();
    let mut entry = crate::parts::part_log::LogEntry::parse_bytes(&raw, TENANT_UUID).unwrap();
    entry.prev_sha256 = "f".repeat(64);
    bad.bucket
        .entries
        .write()
        .unwrap()
        .insert(5, entry.to_bytes().unwrap());
    let started = std::time::Instant::now();
    bad.gc.schedule_pass(T0).await;
    tokio::time::timeout(Duration::from_secs(20), bad.gc.wait_idle())
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(7));
    let report = bad.gc.poll_report(T0 + 1).await.unwrap().unwrap();
    assert_eq!(report.paused_reason.as_deref(), Some("log_unverifiable"));
    assert!(report.backoff);
    assert_eq!(report.deleted, 0);
    assert_eq!(bad.gc.state.lock().await.view.head_seq(), Some(4));
    assert!(bad
        .bucket
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|(key, _)| key != "LIST"));
    let before = bad.gc.reads();
    bad.gc.schedule_pass(T0 + 2).await;
    assert_eq!(bad.gc.reads(), before);
}

#[tokio::test]
async fn production_http_guarded_inventory_survives_repeated_same_scope_refresh() {
    let f = fixture(1, Duration::ZERO, 200).await;
    f.bucket.page_objects.store(640, Ordering::SeqCst);
    let prefix = format!("{}/tenant={TENANT_UUID}/parts/", crate::parts::format::PARTS_ROOT);
    let scope = f.store.part_inventory_scope();
    let listing = f.store.list_part_objects(&prefix);
    let refresh = async {
        for rotation in 0..3 {
            tokio::time::sleep(Duration::from_millis(250)).await;
            // Production successful exchange cancels before operator replacement.
            f.gc.suspend_requests();
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut location = f.location.clone();
            location.access_key_id = format!("rotation-{rotation}");
            f.store.replace_split(&location, &location).unwrap();
            permission(&f.gc, 200, chrono::Duration::minutes(10));
        }
    };
    let (objects, ()) = tokio::join!(listing, refresh);
    let objects = objects.unwrap();
    assert_eq!(objects.len(), 640);
    assert_eq!(f.store.part_inventory_scope(), scope);
    for (n, object) in objects.iter().enumerate() {
        assert_eq!(object.key, format!("{prefix}{n:020}.json"));
        assert_eq!(object.strong_etag, "\"e\"");
    }
    let attempts = f.gc.shared.transport_observation.attempt_times.lock().unwrap();
    assert!(attempts.len() >= 10 && attempts.len() <= 16, "bounded retries: {}", attempts.len());
    for pair in attempts.windows(2) {
        assert!(pair[1].duration_since(pair[0]) >= Duration::from_millis(4));
    }
}

/// NAN-3444: a successful exchange fences the fold read in flight. That is
/// the designed refresh window, not an unverifiable log: the pass pauses as
/// `credential_refresh` (same retry/back-off) and the next pass resumes.
#[tokio::test]
async fn production_http_refresh_fence_mid_fold_is_a_credential_refresh_pause() {
    let f = fixture(32, Duration::ZERO, 100).await;
    f.bucket.body_mode.store(3, Ordering::SeqCst);
    let work = async {
        let mut inventory = None;
        run_one(f.gc.shared.clone(), f.gc.state.clone(), T0, &mut inventory).await
    };
    let refresh = async {
        while f.bucket.active.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // Production order (cell.rs `secrets`): suspend, swap, then update.
        f.gc.suspend_requests();
        tokio::time::sleep(Duration::from_millis(20)).await;
        permission(&f.gc, 100, chrono::Duration::minutes(10));
    };
    let (report, ()) = tokio::join!(work, refresh);
    let report = report.unwrap();
    assert_eq!(report.paused_reason.as_deref(), Some(CREDENTIAL_REFRESH));
    assert!(report.backoff, "retry semantics are unchanged");
    f.bucket.body_mode.store(0, Ordering::SeqCst);
    fold(&f).await;
    assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(31));
}

/// Both notifications can be coalesced before the pending R2 operation
/// observes either. The new route is usable, but the old read must still be
/// cancelled as a routine refresh and its verified prefix must survive.
#[tokio::test]
async fn production_http_completed_refresh_mid_fold_retries_without_integrity_warning() {
    let f = fixture(32, Duration::ZERO, 100).await;
    f.bucket.body_mode.store(3, Ordering::SeqCst);
    let work = async {
        let mut inventory = None;
        run_one(f.gc.shared.clone(), f.gc.state.clone(), T0, &mut inventory).await
    };
    let refresh = async {
        while f.bucket.active.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        f.gc.suspend_requests();
        permission(&f.gc, 100, chrono::Duration::minutes(10));
    };
    let (report, ()) = tokio::join!(work, refresh);
    assert_eq!(report.unwrap().paused_reason.as_deref(), Some(CREDENTIAL_REFRESH));
    f.bucket.body_mode.store(0, Ordering::SeqCst);
    fold(&f).await;
    assert_eq!(f.gc.state.lock().await.view.head_seq(), Some(31));
}

#[test]
fn only_the_refresh_fence_is_a_credential_refresh_pause() {
    let fenced = anyhow::Error::from(
        opendal::Error::new(opendal::ErrorKind::PermissionDenied, "GC route unavailable")
            .set_source(anyhow::Error::from(RefreshSuspended)),
    )
    .context("GC log read");
    assert_eq!(fold_refused(&fenced, "t").paused_reason.as_deref(), Some(CREDENTIAL_REFRESH));
    let withdrawn = anyhow::Error::from(
        opendal::Error::new(opendal::ErrorKind::PermissionDenied, "GC route unavailable")
            .set_source(anyhow::anyhow!("lake_part_gc route was withdrawn")),
    );
    assert_eq!(fold_refused(&withdrawn, "t").paused_reason.as_deref(), Some(LOG_UNVERIFIABLE));
    assert_eq!(
        fold_refused(&anyhow::anyhow!("GC log reader returned wrong sequence"), "t")
            .paused_reason
            .as_deref(),
        Some(LOG_UNVERIFIABLE)
    );
}

/// NAN-3852 (the load-test tenant, 10-14): the cell logged `deleted_total 26` while the
/// heartbeat metric stayed 0 until the task ended. The route exposes the
/// per-cycle count while a task is still in flight.
#[tokio::test]
async fn live_deleted_total_follows_each_bounded_cycle() {
    use crate::part_ingest::part_gc_gate::SanctionedPartGc;
    let f = fixture(4, Duration::ZERO, 100).await;
    assert_eq!(SanctionedPartGc::deleted_total(&f.gc), Some(0));
    for deleted in [26, 0, 384] {
        report_progress(&f.gc.shared, Some(3), &PassReport { deleted, index_head_seq: Some(3), ..PassReport::default() });
    }
    assert_eq!(SanctionedPartGc::deleted_total(&f.gc), Some(410));
}

/// NAN-4194: the cell wires the persistent view dir through the production
/// (guarded) constructor. T57 panicked every ingest role here because the
/// builder called `Arc::get_mut` after the R2 guard took its weak reference.
/// A rolled pod (fresh ephemeral state dir) resumes from the hot dir within a
/// page or two of reads instead of refolding from seq 0.
#[tokio::test]
async fn guarded_constructor_resumes_the_view_from_the_hot_dir_on_a_fresh_pod() {
    let f = fixture(64, Duration::ZERO, 200).await;
    fold(&f).await;
    let fresh_pod = tempfile::tempdir().unwrap();
    let resumed = CellSanctionedPartGc::new_guarded(
        TENANT_UUID,
        "http://127.0.0.1:1/",
        None,
        f.store.clone(),
        fixture_keys(),
        fresh_pod.path(),
        Some(f.dir.path()),
        None,
    )
    .unwrap()
    .with_view_save_interval(Duration::ZERO);
    permission(&resumed, 200, chrono::Duration::minutes(10));
    let mut state = resumed.state.lock().await;
    assert!(
        advance_view(resumed.shared.views.as_ref(), &resumed.shared, &mut state)
            .await
            .unwrap()
    );
    assert_eq!(state.view.head_seq(), Some(63));
    assert!(resumed.reads() <= 9, "resumed from the hot dir, not refolded from seq 0");
    assert!(!fresh_pod.path().join("lake-part-gc").exists(), "the view lives on the hot dir only");
}

/// NAN-4188: through the production (guarded) constructor, a receipted append
/// from this process's writer starts an index publication at the next ingest
/// tick, beside a pass, once per new append and at most once per gap.
#[tokio::test]
async fn guarded_follower_starts_a_publication_per_receipted_append() {
    let f = fixture(8, Duration::ZERO, 200).await;
    assert_follower_publishes_per_receipted_append(&f.gc, 7).await;
}

/// NAN-4188: shared with the cell's production-wiring boot test. `gc` must
/// have an unreachable owner (the publication fails and backs off) and a
/// delete route (see [`permission`]); `last_seq` is the log's newest seq.
pub(crate) async fn assert_follower_publishes_per_receipted_append(gc: &CellSanctionedPartGc, last_seq: u64) {
    let now = chrono::Utc::now().timestamp_millis();
    {
        let mut runner = gc.runner.lock().await;
        runner.armed = true;
        // The scheduled index-only cadence is not due: only the follower is.
        runner.next_index_ms = now + 3_600_000;
    }
    let before = gc.shared.follower_publications.load(Ordering::Relaxed);
    let publications = || gc.shared.follower_publications.load(Ordering::Relaxed) - before;
    let receipted = gc.receipted_appends();
    receipted.record(last_seq + 1, now - INDEX_SETTLE_FOR_TESTS);
    let _ = gc.poll_report(now).await;
    assert_eq!(publications(), 1, "a receipted append starts a publication at the next tick");
    loop {
        let finished = gc.runner.lock().await.index_task.as_ref().is_none_or(|task| task.is_finished());
        if finished {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let _ = gc.poll_report(now + 1).await;
    assert_eq!(publications(), 1, "never twice for the same receipted append");
    receipted.record(last_seq + 2, now);
    let _ = gc.poll_report(now + FOLLOW_MIN_GAP_MS + 1).await;
    assert_eq!(publications(), 1, "a failed publication backs the follower off");
    gc.runner.lock().await.next_follow_ms = 0;
    let _ = gc.poll_report(now + FOLLOW_MIN_GAP_MS + 2).await;
    assert_eq!(publications(), 2, "a new receipted append once the back-off ends");
}

const INDEX_SETTLE_FOR_TESTS: i64 = crate::lake_part_gc::index::INDEX_SETTLE_MS;

/// NAN-4567: the owner + Worker stand-in for the bronze quarantine expiry
/// tests. It answers like the real route and, like the Worker, deletes the
/// permitted key from the fixture bucket.
struct QuarantineAuthority {
    bucket: Arc<Bucket>,
    quarantine: bool,
    authorized: std::sync::Mutex<Vec<LakePartDeleteRequest>>,
}

#[async_trait]
impl LakePartDeleteAuthority for QuarantineAuthority {
    async fn worker_supports_lake_part_delete(&self) -> Result<bool> { Ok(true) }
    async fn worker_supports_quarantine_expiry(&self) -> Result<bool> { Ok(self.quarantine) }
    async fn authorize(&self, request: &LakePartDeleteRequest) -> Result<LakePartDeletePermit> {
        request.validate()?;
        self.authorized.lock().unwrap().push(request.clone());
        let now = chrono::Utc::now();
        Ok(LakePartDeletePermit {
            request: request.clone(),
            permit_id: request.permit_id()?,
            owner_authorization: crate::lake_part_gc::delete_control::DeleteOwnerAuthorization {
                schema_version: 1, signer_key_id: "fixture-owner".into(), issued_at: now.to_rfc3339(),
                expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
                identity_sha256: request.digest()?, signature_base64: "fixture-signature".into(),
            },
        })
    }
    async fn prepare(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeletePermit> { Ok(permit.clone()) }
    async fn retire(&self, permit: &LakePartDeletePermit) -> Result<LakePartDeleteReceipt> {
        self.bucket.objects.write().unwrap().remove(&permit.request.key);
        Ok(LakePartDeleteReceipt {
            schema_version: crate::lake_part_gc::delete_control::DELETE_CONTROL_SCHEMA_VERSION,
            permit_id: permit.permit_id.clone(),
            identity_sha256: permit.owner_authorization.identity_sha256.clone(),
            receipt_sha256: "a".repeat(64), state: "receipt_appended".into(), final_head_absent: true,
        })
    }
}

/// A restore-readable record of `id` at `written_ms`: its key and bytes.
fn quarantine_record(tenant: &str, id: &str, written_ms: i64) -> (String, Vec<u8>) {
    let body = serde_json::to_vec(&serde_json::json!({
        "kind": "nano.lake.bronze-quarantine-record.v1", "tenant_id": tenant, "id": id, "entry": null,
    })).unwrap();
    let key = format!("{}records/{written_ms:013}-{}.json",
        crate::lake_part_gc::quarantine_expiry::quarantine_prefix(tenant), &crate::parts::sha256_hex(&body)[..16]);
    assert_eq!(crate::part_ingest::quarantine_store::record_id(tenant, &key, &body).as_deref(), Some(id));
    (key, body)
}

fn rfc3339_ms(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// NAN-4567: through `new_guarded` (the cell's constructor) and its guarded
/// R2 lister, the GC deletes exactly the expired quarantine keys, objects
/// before records; young entries, and another tenant's keys, survive.
#[tokio::test]
async fn guarded_gc_expires_only_the_tenants_expired_bronze_quarantine() {
    use crate::lake_part_gc::quarantine_expiry::{quarantine_prefix, QuarantineExpiryReport};
    let f = fixture(1, Duration::ZERO, 200).await;
    let listed_at = chrono::DateTime::parse_from_rfc3339("2026-09-28T00:00:00Z").unwrap().timestamp_millis();
    let now = listed_at + 27 * 86_400_000;
    let day = 86_400_000;
    let prefix = quarantine_prefix(TENANT_UUID);
    let other = "7f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    let (expired, reused, young) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
    let expired_object = format!("{prefix}objects/{expired}.parquet");
    let reused_object = format!("{prefix}objects/{reused}.parquet");
    let young_object = format!("{prefix}objects/{young}.parquet");
    let (old_record, old_body) = quarantine_record(TENANT_UUID, &expired, listed_at);
    // A later keep of the same bytes as an old object: its young record keeps it.
    let (young_record, young_body) = quarantine_record(TENANT_UUID, &reused, now - day);
    let foreign_object = format!("{}objects/{expired}.parquet", quarantine_prefix(other));
    let (foreign_record, foreign_body) = quarantine_record(other, &expired, listed_at);
    {
        let mut objects = f.bucket.objects.write().unwrap();
        for key in [&expired_object, &reused_object, &young_object, &foreign_object] {
            objects.insert(key.clone(), b"parquet".to_vec());
        }
        objects.insert(old_record.clone(), old_body);
        objects.insert(young_record.clone(), young_body);
        objects.insert(foreign_record.clone(), foreign_body);
        let mut modified = f.bucket.modified.write().unwrap();
        modified.insert(young_object.clone(), rfc3339_ms(now - day));
        modified.insert(young_record.clone(), rfc3339_ms(now - day));
    }
    let surviving = |f: &Fixture| f.bucket.objects.read().unwrap().keys().cloned().collect::<Vec<_>>();

    // An older Worker (no quarantine capability): nothing is asked.
    let old_worker = QuarantineAuthority { bucket: f.bucket.clone(), quarantine: false, authorized: Default::default() };
    let mut state = f.gc.state.lock().await;
    let report = quarantine_expiry_if_due(&f.gc.shared, &old_worker, &mut state, "fixture", now).await.unwrap();
    assert_eq!(report.skipped, Some("worker_capability_missing"));
    assert!(old_worker.authorized.lock().unwrap().is_empty());
    // Not due again inside the interval.
    let authority = QuarantineAuthority { bucket: f.bucket.clone(), quarantine: true, authorized: Default::default() };
    assert!(quarantine_expiry_if_due(&f.gc.shared, &authority, &mut state, "fixture", now + 1).await.is_none());

    let next = now + crate::lake_part_gc::quarantine_expiry::QUARANTINE_EXPIRY_INTERVAL_MS;
    let report: QuarantineExpiryReport =
        quarantine_expiry_if_due(&f.gc.shared, &authority, &mut state, "fixture", next).await.unwrap();
    let asked: Vec<_> = authority.authorized.lock().unwrap().iter().map(|r| r.key.clone()).collect();
    assert_eq!(asked, vec![expired_object.clone(), old_record.clone()], "objects before records; nothing young");
    assert_eq!((report.plan.objects, report.plan.records, report.plan.kept_by_young_record), (1, 1, 1));
    assert_eq!(report.young_records, 1);
    assert_eq!(report.executed.deleted, 2);
    for request in authority.authorized.lock().unwrap().iter() {
        assert_eq!(request.reason, crate::lake_part_gc::LakePartDeleteReason::QuarantineExpired);
        assert_eq!(request.tenant_uuid, TENANT_UUID);
        assert_eq!(request.bucket, crate::lake_part_gc::request::tenant_bucket(TENANT_UUID));
    }
    let mut left = surviving(&f);
    left.sort();
    let mut expected = vec![reused_object.clone(), young_object.clone(), young_record.clone(),
        foreign_object.clone(), foreign_record.clone()];
    expected.sort();
    assert_eq!(left, expected, "young entries and the other tenant's keys survive");

    // A listing that names another tenant's key fails the pass: nothing asked.
    f.bucket.leak_foreign.store(true, Ordering::SeqCst);
    let leaky = QuarantineAuthority { bucket: f.bucket.clone(), quarantine: true, authorized: Default::default() };
    assert!(quarantine_expiry_if_due(&f.gc.shared, &leaky, &mut state, "fixture",
        next + crate::lake_part_gc::quarantine_expiry::QUARANTINE_EXPIRY_INTERVAL_MS).await.is_none(), "an escaped listing fails the pass");
    assert!(leaky.authorized.lock().unwrap().is_empty());
    assert_eq!(surviving(&f).len(), 5);
}

/// NAN-4601: the owner's index route as control answers it (exact chain,
/// no gaps); every other owner route (authorize) is only counted.
#[derive(Default)]
struct OwnerIndex {
    shas: std::sync::Mutex<Vec<String>>,
    other_calls: AtomicUsize,
}

async fn owner_index_stub(State(owner): State<Arc<OwnerIndex>>, body: axum::body::Bytes) -> Response {
    use base64::Engine as _;
    use sha2::Digest as _;
    let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let mut shas = owner.shas.lock().unwrap();
    for entry in request["entries"].as_array().unwrap() {
        assert_eq!(entry["seq"].as_u64().unwrap(), shas.len() as u64, "index pushed out of order");
        let bytes = base64::engine::general_purpose::STANDARD.decode(entry["entry_base64"].as_str().unwrap()).unwrap();
        shas.push(hex::encode(sha2::Sha256::digest(&bytes)));
    }
    assert!(request["deleted"].as_array().unwrap().is_empty(), "a held feed reports no deletes");
    axum::Json(serde_json::json!({
        "tenant_uuid": TENANT_UUID,
        "indexed_through_seq": shas.len().checked_sub(1),
        "head_entry_sha256": shas.last(),
        "checkpoint_seq": null,
        "folded_through_seq": null,
    }))
    .into_response()
}

async fn owner_other(State(owner): State<Arc<OwnerIndex>>) -> Response {
    owner.other_calls.fetch_add(1, Ordering::SeqCst);
    (StatusCode::FORBIDDEN, "not expected while held").into_response()
}

/// NAN-4601 on the cell's guarded constructor (`new_guarded`, the R2 part
/// store the cell wires): while ingest holds a recorded catalog the gate only
/// drives `feed_index_only`. The part log reaches control's index through the
/// owner, and no delete pass is ever started: no authorize, no Worker call,
/// no pass task, no view fold.
#[tokio::test]
async fn guarded_held_feed_publishes_the_index_and_never_starts_a_pass() {
    let owner = Arc::new(OwnerIndex::default());
    let app = Router::new()
        .route(crate::lake_part_gc::INDEX_PATH, axum::routing::post(owner_index_stub))
        .fallback(owner_other)
        .with_state(owner.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let owner_url = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // `fixture` delivers an enabled grant and the route (`permission`).
    let f = fixture_with_owner(8, Duration::ZERO, 200, &owner_url).await;
    let start = chrono::Utc::now().timestamp_millis();
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut tick = 0;
        while owner.shas.lock().unwrap().len() < 8 {
            // What the ingest gate forwards while held (part_gc_gate tests
            // pin the forwarding); never a pass report here.
            assert!(SanctionedPartGc::feed_index_only(&f.gc, start + tick).await.is_none(), "no pass ever reports");
            tick += 1;
            f.gc.wait_index_idle().await;
            // The scheduled cadence after a publication is a minute.
            f.gc.runner.lock().await.next_index_ms = 0;
        }
    })
    .await
    .expect("the held feed published the whole log to control's index");
    let runner = f.gc.runner.lock().await;
    assert!(runner.task.is_none(), "the held feed never starts a delete pass");
    assert!(runner.armed, "an open grant arms the index feed");
    drop(runner);
    assert_eq!(owner.other_calls.load(Ordering::SeqCst), 0, "no authorize or other owner call");
    assert!(f.gc.index_only_indexed() >= 8);
    assert!(!f.gc.shared.view_complete.load(Ordering::SeqCst), "no view was folded: nothing to plan from");
    // Withdrawing the grant closes the feed too (it needs the open route).
    f.gc.update(None, None);
    f.gc.runner.lock().await.next_index_ms = 0;
    let calls = owner.shas.lock().unwrap().len();
    assert!(SanctionedPartGc::feed_index_only(&f.gc, start + 1_000_000).await.is_none());
    f.gc.wait_index_idle().await;
    assert!(f.gc.runner.lock().await.index_task.is_none(), "no publication without the route");
    assert_eq!(owner.shas.lock().unwrap().len(), calls);
    server.abort();
}

#[tokio::test]
async fn production_gc_capacity_warning_survives_index_only_and_no_pending_backlog() {
    let f = fixture(3, Duration::ZERO, 200).await;
    let views = f.gc.shared.views.as_ref().unwrap();
    views.test_memory_limit.store(10 * 2048 * 4, Ordering::Relaxed);
    let mut state = f.gc.state.lock().await;
    advance_view(Some(views), &f.gc.shared, &mut state).await.unwrap();
    // A pressured partial observation stays latched through index-only work.
    observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), false, 8).unwrap();
    drop(state);
    let warning = f.gc.capacity_pressure().expect("early capacity warning");
    assert_eq!(warning.reason, "history_capacity");
    assert_eq!(warning.blocked_seconds, 0, "no dependency on pending-part age");
    assert!(f.gc.capacity_status().unwrap().metric_lines("fixture", TENANT_UUID).contains("lake_part_gc_capacity_pressure"));
    let _ = run_index_only(f.gc.shared.clone()).await;
    assert!(f.gc.capacity_pressure().is_some(), "index-only progress cannot clear the latch");
    views.test_memory_limit.store(1024 * 1024 * 1024, Ordering::Relaxed);
    let mut state = f.gc.state.lock().await;
    assert!(advance_view(Some(views), &f.gc.shared, &mut state).await.unwrap());
    assert!(f.gc.capacity_pressure().is_none(), "only verified healthy capacity clears it");
}

#[tokio::test]
async fn production_gc_capacity_warns_on_transitions_and_one_periodic_summary() {
    // tracing's process-wide callsite interest cache races parallel tests
    // with no subscriber. Isolate actual event counting in this exact test.
    const NAME: &str = "part_ingest::part_gc_cell::transport_tests::production_gc_capacity_warns_on_transitions_and_one_periodic_summary";
    if !std::env::args().any(|arg| arg == NAME) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--nocapture"]).output().unwrap();
        assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        return;
    }
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    let captured = Capture(Arc::default());
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt().without_time().with_ansi(false)
        .with_max_level(tracing::Level::WARN).with_writer(move || writer.clone()).finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let f = fixture(3, Duration::ZERO, 200).await;
    let views = f.gc.shared.views.as_ref().unwrap();
    // Real bounded fold: both Add entries reach the incoming reservation
    // warning threshold; complete healthy evidence clears it only once.
    views.test_memory_limit.store(8 * 2048 * 4, Ordering::Relaxed);
    let mut state = f.gc.state.lock().await;
    assert!(advance_view(Some(views), &f.gc.shared, &mut state).await.unwrap());
    for _ in 0..1000 {
        observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), false, 6).unwrap();
    }
    assert!(f.gc.capacity_pressure().is_some());
    // Changing the pressure detail updates telemetry, without a new entry
    // transition or an extra log before the periodic deadline.
    f.gc.shared.capacity_pressure.lock().unwrap().as_mut().unwrap().detail = "history_disk".into();
    observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), false, 6).unwrap();
    assert_eq!(f.gc.capacity_pressure().unwrap().detail, "resident_memory");
    *f.gc.shared.capacity_log.lock().unwrap() = Some(tokio::time::Instant::now() - PROGRESS_LOG_EVERY);
    for _ in 0..1000 {
        observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), false, 6).unwrap();
    }
    observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), false, 0).unwrap();
    assert!(f.gc.capacity_pressure().is_some(), "partial healthy evidence cannot clear pressure");
    observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), true, 0).unwrap();
    observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), true, 0).unwrap();
    observe_capacity(Some(views), &f.gc.shared, &state.view, views.budget(), false, 6).unwrap();
    let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert_eq!(logs.matches("capacity pressure; action required").count(), 4, "{logs}");
    assert_eq!(logs.matches("capacity pressure cleared").count(), 2, "{logs}");
}

#[tokio::test]
async fn production_gc_history_total_and_runway_use_complete_measured_samples() {
    let f = fixture(3, Duration::ZERO, 200).await;
    let views = f.gc.shared.views.as_ref().unwrap();
    let mut state = f.gc.state.lock().await;
    assert!(advance_view(Some(views), &f.gc.shared, &mut state).await.unwrap());
    let first = f.gc.capacity_status().unwrap();
    assert_eq!(first.history_refs, 2);
    assert!(first.complete);
    assert_eq!(first.legacy_runway_seconds, None, "unknown growth must stay unknown");
    f.gc.shared.capacity_baseline.lock().unwrap().as_mut().unwrap().0 -= Duration::from_secs(120);
    *f.bucket.entries.write().unwrap() = history(5);
    assert!(advance_view(Some(views), &f.gc.shared, &mut state).await.unwrap());
    let second = f.gc.capacity_status().unwrap();
    assert_eq!(second.history_refs, 4);
    assert_eq!(second.head_seq, Some(4));
    assert!(second.observed_at_ms > 0);
    assert_eq!(second.growth_refs_per_day, Some(1440));
    assert_eq!(second.legacy_remaining_refs, second.legacy_limit_refs - 4);
    assert_eq!(second.legacy_runway_seconds, Some(second.legacy_remaining_refs * 60));
    let lines = second.metric_lines("fixture", TENANT_UUID);
    assert!(lines.contains("lake_part_gc_history_refs"));
    assert!(lines.contains("lake_part_gc_history_legacy_runway_seconds"));
}

#[tokio::test]
async fn production_gc_previous_snapshot_schema_rebuilds_live_membership() {
    let f = fixture(5, Duration::ZERO, 200).await;
    fold(&f).await;
    let views = f.gc.shared.views.as_ref().unwrap();
    // v2 has exact known/removal history but no disk-backed live table.
    rusqlite::Connection::open(&views.path).unwrap().execute_batch("DROP TABLE live").unwrap();
    let restart_state = tempfile::tempdir().unwrap();
    let restarted = CellSanctionedPartGc::new_guarded(
        TENANT_UUID, "http://127.0.0.1:1/", None, f.store.clone(), fixture_keys(),
        restart_state.path(), Some(f.dir.path()), None).unwrap();
    permission(&restarted, 200, chrono::Duration::minutes(10));
    restarted.shared.pacer.set_rate(0);
    let mut state = restarted.state.lock().await;
    assert!(advance_view(restarted.shared.views.as_ref(), &restarted.shared, &mut state).await.unwrap());
    assert_eq!(state.view.head_seq(), Some(4));
    assert!(state.view.is_live(&crate::lake_part_gc::planner::tests::id(1)));
    assert!(restarted.reads() >= 5, "old snapshots must replay the verified prefix");
    let saved = restarted.shared.views.as_ref().unwrap().load(TENANT_UUID).unwrap().unwrap();
    assert_eq!(saved.head_seq(), state.view.head_seq());
    assert!(saved.is_live(&crate::lake_part_gc::planner::tests::id(1)));
}

#[tokio::test]
async fn production_gc_corrupt_cache_cannot_resume_a_valid_head_over_a_broken_prefix() {
    for mutation in [
        "UPDATE snapshot SET body=CAST(' ' || CAST(body AS TEXT) AS BLOB)",
        "UPDATE known SET id='1790330400099-0000000000000099' WHERE id=(SELECT min(id) FROM known)",
        "DELETE FROM live",
        "DROP TABLE live", // Previous snapshot schema must rebuild from genesis.
        "UPDATE live SET adopted=1",
        "UPDATE live SET original_key='wrong/key'",
    ] {
        let f = fixture(5, Duration::ZERO, 200).await;
        f.gc.shared.pacer.set_rate(0);
        let views = f.gc.shared.views.as_ref().unwrap();
        let mut state = f.gc.state.lock().await;
        assert!(advance_view(Some(views), &f.gc.shared, &mut state).await.unwrap());
        assert_eq!(state.view.head_seq(), Some(4));
        drop(state);
        rusqlite::Connection::open(&views.path).unwrap().execute_batch(mutation).unwrap();
        assert!(views.load(TENANT_UUID).is_err(), "valid SQLite is insufficient: {mutation}");
        // The saved head is still byte-identical, but replay must detect this
        // earlier broken link rather than trust the corrupt local state.
        let mut entry = crate::parts::part_log::LogEntry::parse_bytes(
            &f.bucket.entries.read().unwrap()[&1], TENANT_UUID).unwrap();
        entry.prev_sha256 = "f".repeat(64);
        f.bucket.entries.write().unwrap().insert(1, entry.to_bytes().unwrap());
        let restart_state = tempfile::tempdir().unwrap();
        let restarted = CellSanctionedPartGc::new_guarded(
            TENANT_UUID, "http://127.0.0.1:1/", None, f.store.clone(), fixture_keys(),
            restart_state.path(), Some(f.dir.path()), None).unwrap();
        permission(&restarted, 200, chrono::Duration::minutes(10));
        restarted.shared.pacer.set_rate(0);
        let report = restarted.run_pass_now(T0).await.unwrap();
        assert_eq!(report.paused_reason.as_deref(), Some("log_unverifiable"), "{report:?}");
        assert_eq!(report.deleted, 0);
        assert_eq!(report.planned, 0);
        assert_eq!(restarted.state.lock().await.view.head_seq(), Some(0), "replayed genesis");
    }
}
