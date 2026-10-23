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
}
#[async_trait::async_trait]
impl IcebergCommitter for Backend {
    async fn commit(&self, _: &ExportManifest) -> Result<()> {
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
    async fn close_and_drain(&self) -> Result<()> {
        self.blocked.store(true, Ordering::SeqCst);
        self.trace.lock().unwrap().push("close");
        Ok(())
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        self.trace.lock().unwrap().push("inspect");
        if self.stall_inspection.load(Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        Ok(BTreeSet::new())
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
