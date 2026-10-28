// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4726: the hosted cell's retention retire step, on the production
//! wiring: the guarded `CellSanctionedPartGc` (the constructor the cell uses)
//! fed a `lake_part_gc` route through `update`, behind the
//! `ExchangedGrantAuthority` delete gate installed with
//! `set_part_gc_authority`, driven by the ingest tick.
use super::*;
use crate::lake_part_gc::request::tests::TENANT_UUID;
use crate::part_ingest::part_gc_cell::transport_tests::fixture_keys;
use crate::part_ingest::part_gc_cell::{CellSanctionedPartGc, LakePartGcAccess, OWNER_DELETE_SCOPE};
use crate::part_ingest::part_gc_gate::{ExchangedGrantAuthority, SanctionedPartGc};
use crate::part_ingest::s3_store::S3Location;
use crate::parts::part_log::{LocalObjectStore, RetireReason};
use crate::parts::provenance::LocalPartSigner;

const NOW: i64 = 1_800_000_000_000;
const DAY: i64 = 86_400_000;
const OTHER: &str = "00000000-0000-4000-8000-000000004726";

fn route_value(policy: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "owner_delete": {"token": "fixture", "audience": "owner",
            "scope": OWNER_DELETE_SCOPE,
            "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()},
        "retention_authority": {"url": "https://127.0.0.1:1/", "token": "fixture"},
        "policy": policy,
    })
}

/// The gate checks the grant at the tick's `now_ms` (the fixed [`NOW`]) and
/// the pass's route at the wall clock: valid at both.
fn grant(tenant: &str, enabled: bool) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1, "tenant_id": tenant, "tenant_slug": "fixture", "enabled": enabled,
        "expires_at": (chrono::Utc::now() + chrono::Duration::days(3650)).to_rfc3339()
    })
}

/// The cell's guarded pass (`new_guarded`, as `cell.rs` wires it). Its store
/// is never contacted: the retention read only consults the route.
fn guarded_pass(dir: &Path) -> Arc<CellSanctionedPartGc> {
    let location = S3Location {
        endpoint: "http://127.0.0.1:1".into(), region: "auto".into(), bucket: "fixture".into(),
        prefix: String::new(), access_key_id: "fixture".into(), secret_access_key: "fixture".into(),
        session_token: None,
    };
    let store = Arc::new(super::super::r2_put::R2PartStore::new_split(&location, &location, TENANT_UUID,
        &dir.join("spill")).unwrap());
    Arc::new(CellSanctionedPartGc::new_guarded(TENANT_UUID, "http://127.0.0.1:1/", None, store, fixture_keys(),
        dir, None).unwrap())
}

/// Feed one exchange to the pass and the gate, as `cell.rs` does on start
/// and on every refresh. An unreadable route reaches `update` as `None`.
fn exchange(pass: &CellSanctionedPartGc, gate: &ExchangedGrantAuthority, route: Option<serde_json::Value>,
    grant: Option<serde_json::Value>) {
    let access = route.and_then(|value| LakePartGcAccess::parse(&value).ok());
    pass.update(access.as_ref(), grant.as_ref());
    gate.update(grant.as_ref());
}

/// `created_ms` is the part id's time (inside the log's id memory); the
/// rows span `min_ms..=max_ms`.
fn part(fingerprint: &str, created_ms: i64, min_ms: i64, max_ms: i64) -> PartRef {
    PartRef {
        part_id: PartId::new(created_ms).unwrap(), level: Level::L0,
        event_hour: (min_ms / 3_600_000) as i32, event_day: None, rows: 1,
        min_time_us: min_ms * 1000, max_time_us: max_ms * 1000,
        schema_fingerprint: fingerprint.into(), provenance_sha256: "0".repeat(64),
        merkle_root: "0".repeat(64), sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
    }
}

fn source(tenant: &str, name: &str) -> SourceRef {
    SourceRef { key: format!("tenant_id={tenant}/logs/{name}.parquet"), version: "v1".into(), sha256: "0".repeat(64) }
}

fn live(ingestor: &Ingestor<'_>) -> BTreeSet<String> {
    ingestor.log.live().parts().map(|p| p.part_id.as_str().to_string()).collect()
}

struct Parts {
    expired: PartRef,
    straddling: PartRef,
    recent: PartRef,
}

/// Three parts for a 30-day retention at `NOW`: wholly past it, straddling
/// the cutoff (oldest row past, newest row 1 h inside), and recent.
async fn seed(ingestor: &mut Ingestor<'_>, tenant: &str) -> Parts {
    let fingerprint = ingestor.log.live().schema().unwrap().fingerprint.clone();
    let cutoff = NOW - 30 * DAY;
    let parts = Parts {
        expired: part(&fingerprint, NOW - 3_000, cutoff - 2 * DAY, cutoff - DAY),
        straddling: part(&fingerprint, NOW - 2_000, cutoff - DAY / 2, cutoff + 3_600_000),
        recent: part(&fingerprint, NOW - 1_000, NOW - 60_000, NOW - 1_000),
    };
    ingestor.log.append(LogOp::Add {
        parts: vec![parts.expired.clone(), parts.straddling.clone(), parts.recent.clone()],
        consumed: vec![source(tenant, "seed")], edge_log: None,
    }, NOW).await.unwrap();
    parts
}

async fn open<'a>(dir: &Path, tenant: &str, store: &'a LocalObjectStore, signer: &'a LocalPartSigner,
    queue: &'a super::super::discovery::SpoolQueue) -> Ingestor<'a> {
    let mut cfg = IngestConfig::new(tenant, dir.join(format!("ingest-{tenant}")));
    cfg.prevalence_enabled = false;
    Ingestor::open(cfg, store, store, queue, signer, signer.trusted(), BronzeIngestEnricher::disabled(),
        &seed_schema(), NOW).await.unwrap()
}

/// Parts retired for retention in the tenant's committed log (read back
/// from the store, not from memory).
async fn retention_retires(store: &LocalObjectStore, tenant: &str, head: u64) -> usize {
    let keys = LogKeys::new(tenant).unwrap();
    let mut retired = 0;
    for seq in 0..=head {
        let Some(bytes) = store.get(&keys.entry(seq)).await.unwrap() else { continue };
        let entry: LogEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(entry.tenant_id, tenant);
        if let LogOp::Retire { parts, reason: RetireReason::Retention, .. } = &entry.op {
            retired += parts.len();
        }
    }
    retired
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_retention_retires_only_wholly_expired_parts_of_this_tenant() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
    let signer = LocalPartSigner::new("nan4726-retention", ed25519_dalek::SigningKey::from_bytes(&[47; 32])).unwrap();
    let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT_UUID).unwrap();
    let other_queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool-b"), OTHER).unwrap();
    let mut ingestor = open(dir.path(), TENANT_UUID, &store, &signer, &queue).await;
    let mut other = open(dir.path(), OTHER, &store, &signer, &other_queue).await;
    let parts = seed(&mut ingestor, TENANT_UUID).await;
    let other_parts = seed(&mut other, OTHER).await;
    let all = live(&ingestor);
    let other_all = live(&other);

    let pass = guarded_pass(&dir.path().join("gc"));
    let gate = Arc::new(ExchangedGrantAuthority::new(TENANT_UUID, Some(pass.clone() as Arc<dyn SanctionedPartGc>)));
    ingestor.set_part_gc_authority(gate.clone());
    // One scan per interval; every scan here is due.
    async fn tick(ingestor: &mut Ingestor<'_>) -> usize {
        let at = ingestor.last_retention_scan_ms.unwrap_or(NOW) + HOSTED_RETENTION_SCAN_INTERVAL_MS;
        ingestor.retire_hosted_expired(at).await.unwrap()
    }

    // Fail closed: no route, a route without a policy, an unreadable route
    // (a retention outside 30/90/180/365), a disabled grant, a grant naming
    // another tenant: nothing is retired.
    exchange(&pass, &gate, None, Some(grant(TENANT_UUID, true)));
    assert_eq!(tick(&mut ingestor).await, 0);
    exchange(&pass, &gate, Some(route_value(serde_json::json!({}))), Some(grant(TENANT_UUID, true)));
    assert_eq!(tick(&mut ingestor).await, 0, "no policy, no retention retires");
    exchange(&pass, &gate, Some(route_value(serde_json::json!({"retention_days": 7}))), Some(grant(TENANT_UUID, true)));
    assert_eq!(tick(&mut ingestor).await, 0, "an unreadable policy retires nothing");
    exchange(&pass, &gate, Some(route_value(serde_json::json!({"retention_days": 30}))), Some(grant(TENANT_UUID, false)));
    assert_eq!(tick(&mut ingestor).await, 0, "a disabled grant retires nothing");
    exchange(&pass, &gate, Some(route_value(serde_json::json!({"retention_days": 30}))), Some(grant(OTHER, true)));
    assert_eq!(tick(&mut ingestor).await, 0, "a grant for another tenant retires nothing");
    assert_eq!(live(&ingestor), all);

    // A catalog hold keeps every part (no gate while held).
    exchange(&pass, &gate, Some(route_value(serde_json::json!({"retention_days": 30}))), Some(grant(TENANT_UUID, true)));
    ingestor.cfg.catalog_attachment_failure = Some("fixture_hold");
    assert_eq!(tick(&mut ingestor).await, 0, "a catalog hold retires nothing");
    ingestor.cfg.catalog_attachment_failure = None;

    // The open gate with a 30-day policy: only the wholly expired part.
    assert_eq!(tick(&mut ingestor).await, 1);
    let mut kept = all.clone();
    kept.remove(parts.expired.part_id.as_str());
    assert_eq!(live(&ingestor), kept, "parts inside retention and the straddling part are kept");
    let head = ingestor.log.live().head().unwrap().0;
    assert_eq!(retention_retires(&store, TENANT_UUID, head).await, 1);
    // Idempotent: the next scan appends nothing.
    let head = ingestor.log.live().head().unwrap().0;
    assert_eq!(tick(&mut ingestor).await, 0);
    assert_eq!(ingestor.log.live().head().unwrap().0, head);

    // Throttled: a scan within the interval of the last one does nothing,
    // even when a part is due.
    let straddle_gone = parts.straddling.max_time_us / 1000 + 30 * DAY + 1;
    ingestor.last_retention_scan_ms = Some(straddle_gone - HOSTED_RETENTION_SCAN_INTERVAL_MS + 1);
    assert_eq!(ingestor.retire_hosted_expired(straddle_gone).await.unwrap(), 0, "throttled");
    assert!(live(&ingestor).contains(parts.straddling.part_id.as_str()));
    // The straddling part goes once its newest row is past retention.
    ingestor.last_retention_scan_ms = None;
    assert_eq!(ingestor.retire_hosted_expired(straddle_gone - 2).await.unwrap(), 0, "one ms early: kept");
    ingestor.last_retention_scan_ms = None;
    assert_eq!(ingestor.retire_hosted_expired(straddle_gone).await.unwrap(), 1);
    assert!(live(&ingestor).contains(parts.recent.part_id.as_str()));
    assert!(!live(&ingestor).contains(parts.straddling.part_id.as_str()));

    // Another tenant (no gate of its own, same store) is untouched: its
    // committed log, reread from the store, still holds all of its parts.
    assert_eq!(other.retire_hosted_expired(straddle_gone).await.unwrap(), 0);
    let other_head = other.log.live().head().unwrap().0;
    drop(other);
    assert_eq!(retention_retires(&store, OTHER, other_head).await, 0);
    let reread = crate::parts::part_log::load_log(&store, OTHER).await.unwrap();
    let reread: BTreeSet<String> = reread.parts().map(|p| p.part_id.as_str().to_string()).collect();
    assert_eq!(reread, other_all);
    assert!(reread.contains(other_parts.expired.part_id.as_str()));
}

/// The step is wired into the ingest tick's maintenance (not only callable).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_ingest_tick_runs_the_hosted_retention_step() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalObjectStore::new(dir.path().join("store")).unwrap();
    let signer = LocalPartSigner::new("nan4726-retention-tick", ed25519_dalek::SigningKey::from_bytes(&[48; 32])).unwrap();
    let queue = super::super::discovery::SpoolQueue::new(dir.path().join("spool"), TENANT_UUID).unwrap();
    let mut ingestor = open(dir.path(), TENANT_UUID, &store, &signer, &queue).await;
    let parts = seed(&mut ingestor, TENANT_UUID).await;
    let pass = guarded_pass(&dir.path().join("gc"));
    let gate = Arc::new(ExchangedGrantAuthority::new(TENANT_UUID, Some(pass.clone() as Arc<dyn SanctionedPartGc>)));
    ingestor.set_part_gc_authority(gate.clone());
    exchange(&pass, &gate, Some(route_value(serde_json::json!({"retention_days": 30}))), Some(grant(TENANT_UUID, true)));
    ingestor.tick(NOW + 1_000).await.unwrap();
    assert!(!live(&ingestor).contains(parts.expired.part_id.as_str()), "the tick retired the expired part");
    assert!(live(&ingestor).contains(parts.straddling.part_id.as_str()));
    assert!(live(&ingestor).contains(parts.recent.part_id.as_str()));
}

/// Each layer of the gate holds on its own (the ingest tests above pass
/// through both): the pass reads the policy only from a route that may
/// delete, and the authority asks the pass only while its grant is open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_gate_layer_alone_withholds_the_retention() {
    let dir = tempfile::tempdir().unwrap();
    // The pass: a delivered route with a policy but a disabled grant.
    let pass = guarded_pass(&dir.path().join("gc"));
    let route = LakePartGcAccess::parse(&route_value(serde_json::json!({"retention_days": 90}))).unwrap();
    pass.update(Some(&route), Some(&grant(TENANT_UUID, false)));
    assert_eq!(pass.retention_days(), None, "a disabled grant's route carries no retention");
    pass.update(Some(&route), Some(&grant(TENANT_UUID, true)));
    assert_eq!(pass.retention_days(), Some(90));
    pass.suspend_requests();
    assert_eq!(pass.retention_days(), None, "a refreshing route carries no retention");

    // The authority: a pass that would always answer, behind a closed grant.
    struct Always;
    #[async_trait::async_trait]
    impl SanctionedPartGc for Always {
        async fn run_pass(&self, _now_ms: i64) -> Result<crate::lake_part_gc::PassReport> { anyhow::bail!("unused") }
        fn retention_days(&self) -> Option<u64> { Some(30) }
    }
    let gate = ExchangedGrantAuthority::new(TENANT_UUID, Some(Arc::new(Always)));
    assert_eq!(gate.retention_days(NOW).await.unwrap(), None, "no grant delivered");
    gate.update(Some(&grant(TENANT_UUID, false)));
    assert_eq!(gate.retention_days(NOW).await.unwrap(), None, "grant disabled");
    gate.update(Some(&grant(OTHER, true)));
    assert_eq!(gate.retention_days(NOW).await.unwrap(), None, "grant names another tenant");
    let expired = serde_json::json!({"schema_version": 1, "tenant_id": TENANT_UUID, "tenant_slug": "fixture",
        "enabled": true, "expires_at": "2026-01-01T00:00:00Z"});
    gate.update(Some(&expired));
    assert_eq!(gate.retention_days(NOW).await.unwrap(), None, "grant expired");
    gate.update(Some(&grant(TENANT_UUID, true)));
    assert_eq!(gate.retention_days(NOW).await.unwrap(), Some(30));
}
