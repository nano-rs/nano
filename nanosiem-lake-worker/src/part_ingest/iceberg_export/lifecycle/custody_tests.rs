// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
const TENANT: &str = "3867aaaa-0000-4000-8000-000000000001";
const A: &str = "0000000000001-aaaaaaaaaaaaaaaa";
const B: &str = "0000000000002-bbbbbbbbbbbbbbbb";
#[derive(Default)]
struct Backend {
    trace: Mutex<Vec<&'static str>>,
    blocked: AtomicBool,
    fail_cache: AtomicBool,
    stall_inspection: AtomicBool,
    /// Parts the catalog still references (NAN-4612).
    pinned: Mutex<BTreeSet<String>>,
    /// NAN-4662: the remote table has no snapshot (cleared by any commit).
    never_committed: AtomicBool,
    fail_commit: AtomicBool,
    fail_commit_state: AtomicBool,
    fail_inspection: AtomicBool,
    commit_state_reads: std::sync::atomic::AtomicUsize,
}
#[async_trait::async_trait]
impl IcebergCommitter for Backend {
    async fn commit(&self, _: &ExportManifest) -> Result<()> {
        ensure!(!self.fail_commit.load(Ordering::SeqCst), "create table refused: InvalidLocation");
        self.never_committed.store(false, Ordering::SeqCst);
        self.trace.lock().unwrap().push("commit");
        Ok(())
    }
}
#[async_trait::async_trait]
impl CatalogLifecycleBackend for Backend {
    fn tenant_id(&self) -> &str {
        TENANT
    }
    fn bucket(&self) -> &str {
        "nano-shared-r2-3867aaaa-0000-4000-8000-000000000001"
    }
    async fn verify_maintenance(&self) -> Result<()> {
        self.trace.lock().unwrap().push("policy");
        Ok(())
    }
    async fn export_head(&self, _: bool) -> Result<crate::part_ingest::iceberg_export::ExportHead> {
        // This fixture's commits are not a chain: it never holds a checkpoint.
        Ok(Default::default())
    }
    async fn no_committed_snapshot(&self) -> Result<bool> {
        self.commit_state_reads.fetch_add(1, Ordering::SeqCst);
        ensure!(!self.fail_commit_state.load(Ordering::SeqCst), "catalog commit-state lookup unavailable");
        Ok(self.never_committed.load(Ordering::SeqCst))
    }
    async fn close_and_drain(&self) -> Result<()> {
        self.blocked.store(true, Ordering::SeqCst);
        self.trace.lock().unwrap().push("close");
        Ok(())
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        self.trace.lock().unwrap().push("inspect");
        ensure!(!self.fail_inspection.load(Ordering::SeqCst), "catalog inspection unavailable");
        if self.stall_inspection.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(self.pinned.lock().unwrap().clone())
    }
    async fn invalidate_results(&self) -> Result<()> {
        ensure!(!self.fail_cache.load(Ordering::SeqCst), "cache unavailable");
        self.trace.lock().unwrap().push("cache");
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        self.blocked.store(false, Ordering::SeqCst);
        self.trace.lock().unwrap().push("open");
        Ok(())
    }
}
fn history(dir: &std::path::Path) {
    // Acknowledged historical plans are input evidence, not a permissive test
    // constructor. Reopening production custody must recover BOTH IDs.
    let manifest = ExportManifest {
        tenant_id: TENANT.into(),
        planned_at_ms: 1,
        previous_plan_ms: None,
        add: vec![],
        remove_parts: vec![A.into(), B.into()],
        hours: vec![],
    };
    std::fs::create_dir_all(dir.join("export/committed")).unwrap();
    std::fs::write(
        dir.join("export/committed/0000000000001.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}
async fn sync(catalog: &TenantCatalog, now: i64) {
    catalog
        .sync_parts(TENANT, vec![], now, &MergePolicy::default())
        .await
        .unwrap();
}
#[tokio::test]
async fn never_planned_receipts_are_local_durable_and_tenant_bound() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    assert!(
        catalog.fence_retirement(TENANT, A).await.is_err(),
        "missing custody must fail closed"
    );
    backend.fail_cache.store(true, Ordering::SeqCst);
    assert!(catalog
        .sync_parts(TENANT, vec![], 9, &MergePolicy::default())
        .await
        .is_err());
    assert!(
        catalog.fence_retirement(TENANT, A).await.is_err(),
        "failed initialization cannot mint local receipts"
    );
    backend.fail_cache.store(false, Ordering::SeqCst);
    sync(&catalog, 10).await;
    backend.trace.lock().unwrap().clear();
    backend.fail_cache.store(true, Ordering::SeqCst);
    for i in 1..=128 {
        catalog
            .fence_retirement(TENANT, &format!("{i:013}-aaaaaaaaaaaaaaaa"))
            .await
            .unwrap();
    }
    assert!(
        backend.trace.lock().unwrap().is_empty(),
        "no provider calls for never-planned parts"
    );
    drop(catalog);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    catalog.require_removed(TENANT, A).unwrap();
    assert!(catalog
        .fence_retirement("3867bbbb-0000-4000-8000-000000000002", B)
        .await
        .is_err());
    assert!(backend.trace.lock().unwrap().is_empty());
}
#[tokio::test]
async fn historical_parts_share_one_inspection_per_gc_pass_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 10).await;
    drop(catalog);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    backend.trace.lock().unwrap().clear();
    let pass = CatalogGcPass::default();
    for part in [A, A, B, B] {
        catalog.fence_in_pass(TENANT, part, &pass).await.unwrap();
    }
    assert_eq!(
        *backend.trace.lock().unwrap(),
        ["close", "policy", "inspect", "cache", "open"]
    );
}
/// NAN-4612: a pinned part is refused per part (typed, no receipt); it
/// does not poison the pass's proof for the next historical part.
#[tokio::test]
async fn one_pinned_part_does_not_poison_the_pass() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 10).await;
    backend.pinned.lock().unwrap().insert(A.into());
    let pass = CatalogGcPass::default();
    for _ in 0..2 {
        let error = catalog.fence_in_pass(TENANT, A, &pass).await.unwrap_err();
        assert!(
            error.downcast_ref::<CatalogPinsPart>().is_some(),
            "{error:#}"
        );
    }
    assert!(catalog.require_removed(TENANT, A).is_err());
    catalog.fence_in_pass(TENANT, B, &pass).await.unwrap();
    catalog.require_removed(TENANT, B).unwrap();
}
/// NAN-4636: a refused, pinned fence never drops the reader result cache;
/// the first part that can actually be retired invalidates it, once per pass.
#[tokio::test]
async fn pinned_refusals_keep_the_result_cache_until_a_part_retires() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 10).await;
    backend.pinned.lock().unwrap().insert(A.into());
    backend.trace.lock().unwrap().clear();
    let pass = CatalogGcPass::default();
    for _ in 0..2 {
        let error = catalog.fence_in_pass(TENANT, A, &pass).await.unwrap_err();
        assert!(
            error.downcast_ref::<CatalogPinsPart>().is_some(),
            "{error:#}"
        );
    }
    assert!(
        !backend.trace.lock().unwrap().contains(&"cache"),
        "a pinned refusal must not invalidate: {:?}",
        backend.trace.lock().unwrap()
    );
    catalog.fence_in_pass(TENANT, B, &pass).await.unwrap();
    catalog.fence_in_pass(TENANT, B, &pass).await.unwrap();
    // Bind the trace first: a guard alive inside assert_eq! would deadlock
    // the failure message's second lock (a hang instead of a failure).
    let trace = backend.trace.lock().unwrap().clone();
    assert_eq!(
        trace.iter().filter(|s| **s == "cache").count(),
        1,
        "{trace:?}"
    );
    let error = catalog.fence_in_pass(TENANT, A, &pass).await.unwrap_err();
    assert!(
        error.downcast_ref::<CatalogPinsPart>().is_some(),
        "{error:#}"
    );
}
#[tokio::test]
async fn batch_evidence_is_rejected_after_a_writer_sync() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend).unwrap();
    sync(&catalog, 10).await;
    let pass = CatalogGcPass::default();
    catalog.fence_in_pass(TENANT, A, &pass).await.unwrap();
    sync(&catalog, 3_600_010).await;
    assert!(catalog
        .fence_in_pass(TENANT, B, &pass)
        .await
        .unwrap_err()
        .to_string()
        .contains("changed during GC pass"));
    assert!(catalog.require_removed(TENANT, B).is_err());
    catalog
        .fence_in_pass(TENANT, B, &CatalogGcPass::default())
        .await
        .unwrap();
}
#[tokio::test]
async fn closed_barrier_retries_immediately_and_hourly_sync_never_drains_readers() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 10).await;
    backend.fail_cache.store(true, Ordering::SeqCst);
    let pass = CatalogGcPass::default();
    assert!(catalog.fence_in_pass(TENANT, A, &pass).await.is_err());
    let calls = backend.trace.lock().unwrap().len();
    assert!(catalog.fence_in_pass(TENANT, B, &pass).await.is_err());
    assert_eq!(
        backend.trace.lock().unwrap().len(),
        calls,
        "failed inspection is also once per pass"
    );
    assert!(backend.blocked.load(Ordering::SeqCst));
    backend.fail_cache.store(false, Ordering::SeqCst);
    backend.trace.lock().unwrap().clear();
    sync(&catalog, 11).await;
    assert_eq!(
        *backend.trace.lock().unwrap(),
        ["close", "policy", "inspect", "cache", "open"]
    );
    assert!(!backend.blocked.load(Ordering::SeqCst));
    backend.fail_cache.store(true, Ordering::SeqCst);
    assert!(catalog.fence_retirement(TENANT, A).await.is_err());
    drop(catalog);
    backend.fail_cache.store(false, Ordering::SeqCst);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 12).await;
    assert!(!backend.blocked.load(Ordering::SeqCst));
    backend.trace.lock().unwrap().clear();
    sync(&catalog, 3_600_012).await;
    assert_eq!(*backend.trace.lock().unwrap(), ["policy", "inspect"]);
}

#[tokio::test(start_paused = true)]
async fn timed_out_inspection_is_not_restarted_for_each_part_in_a_pass() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 10).await;
    backend.stall_inspection.store(true, Ordering::SeqCst);
    let pass = CatalogGcPass::default();
    assert!(catalog
        .fence_in_pass(TENANT, A, &pass)
        .await
        .unwrap_err()
        .to_string()
        .contains("timed out"));
    let count = backend.trace.lock().unwrap().len();
    assert!(catalog
        .fence_in_pass(TENANT, B, &pass)
        .await
        .unwrap_err()
        .to_string()
        .contains("canceled"));
    assert_eq!(backend.trace.lock().unwrap().len(), count);
    assert!(backend.blocked.load(Ordering::SeqCst));
    backend.stall_inspection.store(false, Ordering::SeqCst);
    sync(&catalog, 11).await;
    assert!(!backend.blocked.load(Ordering::SeqCst));
    catalog
        .fence_in_pass(TENANT, B, &CatalogGcPass::default())
        .await
        .unwrap();
}

/// NAN-4662 fixtures: an hour part the writer plans (sealed long ago).
fn hour_part(id: &str) -> PartRef {
    PartRef {
        part_id: PartId::parse(id).unwrap(),
        level: crate::parts::levels::Level::Hour,
        event_hour: 0,
        event_day: None,
        rows: 1,
        min_time_us: 1,
        max_time_us: 1,
        schema_fingerprint: "0".repeat(64),
        provenance_sha256: "0".repeat(64),
        merkle_root: "0".repeat(64),
        sorted: true,
        data_bytes: 1,
        row_groups: 1,
        data_files: 1,
    }
}
fn reads(backend: &Backend) -> usize {
    backend.commit_state_reads.load(Ordering::SeqCst)
}

/// NAN-4662 (the large tenant): the agent catalog never committed (create table refused),
/// the planned-index marker never appeared and the first plan stays pending.
/// A part that plan names stays held per key (its ambiguous commit could
/// still land); every other part is receipted without draining readers.
#[tokio::test]
async fn uncommitted_catalog_plan_holds_only_the_parts_it_names() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Backend::default());
    backend.never_committed.store(true, Ordering::SeqCst);
    backend.fail_commit.store(true, Ordering::SeqCst);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    let error = catalog
        .sync_parts(TENANT, vec![hour_part(A)], 48 * 3_600_000, &MergePolicy::default())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("InvalidLocation"), "{error:#}");
    assert!(!dir.path().join(PLANNED_INDEX_READY).exists());
    assert_eq!(catalog.pending().unwrap().len(), 1, "the plan stays pending");
    backend.trace.lock().unwrap().clear();
    let pass = CatalogGcPass::default();
    for _ in 0..2 {
        let error = catalog.fence_in_pass(TENANT, A, &pass).await.unwrap_err();
        assert!(error.downcast_ref::<CatalogPartUnproven>().is_some(), "{error:#}");
    }
    assert!(catalog.require_removed(TENANT, A).is_err(), "a pending-plan part is never receipted");
    catalog.fence_in_pass(TENANT, B, &pass).await.unwrap();
    catalog.require_removed(TENANT, B).unwrap();
    assert_eq!(reads(&backend), 1, "one commit-state read per generation");
    assert!(
        backend.trace.lock().unwrap().is_empty(),
        "no reader drain, inspection or commit: {:?}",
        backend.trace.lock().unwrap()
    );
    // the large tenant retries its failing sync every ~90 s: each attempt moves the custody
    // generation, which re-reads the commit state instead of stopping GC.
    let c = "0000000000003-cccccccccccccccc";
    assert!(catalog
        .sync_parts(TENANT, vec![hour_part(A)], 48 * 3_600_000 + 90_000, &MergePolicy::default())
        .await
        .is_err());
    catalog.fence_in_pass(TENANT, c, &pass).await.unwrap();
    catalog.require_removed(TENANT, c).unwrap();
    assert_eq!(reads(&backend), 2);
    assert!(catalog.fence_in_pass(TENANT, A, &pass).await.unwrap_err().downcast_ref::<CatalogPartUnproven>().is_some());
}

/// NAN-4662: an unreadable catalog proves nothing; a committed table keeps
/// the full NAN-4612 fence (no marker: held, pass-wide).
#[tokio::test]
async fn committed_or_unreadable_catalog_keeps_the_fence() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Backend::default());
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    for (never_committed, unreadable) in [(false, false), (true, true)] {
        backend.never_committed.store(never_committed, Ordering::SeqCst);
        backend.fail_commit_state.store(unreadable, Ordering::SeqCst);
        let error = catalog
            .fence_in_pass(TENANT, B, &CatalogGcPass::default())
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<CatalogPartUnproven>().is_none(), "{error:#}");
        assert!(format!("{error:#}").contains("planned index not initialized"), "{error:#}");
        assert!(catalog.require_removed(TENANT, B).is_err());
    }
    assert_eq!(reads(&backend), 2);
    backend.fail_commit_state.store(false, Ordering::SeqCst);
    catalog.fence_in_pass(TENANT, B, &CatalogGcPass::default()).await.unwrap();
    // An acknowledged plan on this volume: the catalog is not even asked.
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    backend.never_committed.store(true, Ordering::SeqCst);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    let error = catalog.fence_in_pass(TENANT, "0000000000003-cccccccccccccccc", &CatalogGcPass::default()).await.unwrap_err();
    assert!(format!("{error:#}").contains("planned index not initialized"), "{error:#}");
    assert_eq!(reads(&backend), 0);
}

/// NAN-4662: a plan recorded AFTER the pass read the commit state (the
/// writer's first plan; its create/commit failed, so it may still land) is
/// respected: the sync moved the generation, the re-read names the part, and
/// it is held per key while an unrelated part still proceeds.
#[tokio::test]
async fn a_plan_recorded_after_the_commit_state_read_holds_its_parts() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(Backend::default());
    backend.never_committed.store(true, Ordering::SeqCst);
    backend.fail_commit.store(true, Ordering::SeqCst);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    let pass = CatalogGcPass::default();
    catalog.fence_in_pass(TENANT, B, &pass).await.unwrap();
    assert_eq!(reads(&backend), 1);
    assert!(catalog
        .sync_parts(TENANT, vec![hour_part(A)], 48 * 3_600_000, &MergePolicy::default())
        .await
        .is_err());
    assert_eq!(catalog.pending().unwrap().len(), 1, "the plan naming A is on disk");
    let error = catalog.fence_in_pass(TENANT, A, &pass).await.unwrap_err();
    assert!(error.downcast_ref::<CatalogPartUnproven>().is_some(), "{error:#}");
    assert!(catalog.require_removed(TENANT, A).is_err(), "a part a later plan names is never receipted");
    assert_eq!(reads(&backend), 2, "the sync forced a fresh read");
    catalog.fence_in_pass(TENANT, "0000000000003-cccccccccccccccc", &pass).await.unwrap();
}

/// NAN-4662: on a committed table a failed inspection holds every planned
/// part (per key, never receipted) and asks no commit-state question; only
/// never-planned parts, cleared by the reconciled planned index, proceed.
#[tokio::test]
async fn a_failed_inspection_on_a_committed_table_holds_every_planned_part() {
    let dir = tempfile::tempdir().unwrap();
    history(dir.path());
    let backend = Arc::new(Backend::default());
    backend.never_committed.store(true, Ordering::SeqCst);
    let catalog = TenantCatalog::new(TENANT, dir.path().into(), backend.clone()).unwrap();
    sync(&catalog, 10).await;
    backend.fail_inspection.store(true, Ordering::SeqCst);
    let pass = CatalogGcPass::default();
    for part in [A, B] {
        let error = catalog.fence_in_pass(TENANT, part, &pass).await.unwrap_err();
        assert!(error.downcast_ref::<CatalogPartUnproven>().is_some(), "{error:#}");
        assert!(catalog.require_removed(TENANT, part).is_err(), "a planned part is never receipted");
    }
    catalog.fence_in_pass(TENANT, "0000000000003-cccccccccccccccc", &pass).await.unwrap();
    assert_eq!(reads(&backend), 0, "an acknowledged plan vetoes the commit-state read");
}
