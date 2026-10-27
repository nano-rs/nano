//! Mock only provider/control I/O. TenantCatalog's production constructor,
//! durable planner, fresh serving backend, retry fences and GC receipts run.
use super::*;
use crate::parts::{format::PartId, levels::Level};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, Ordering},
};
const T: &str = "3867aaaa-0000-4000-8000-000000000001";
const BUCKET: &str = "nano-shared-r2-3867aaaa-0000-4000-8000-000000000001";
#[derive(Default)]
struct Provider {
    tables: Mutex<HashMap<String, Arc<Table>>>,
    registry: Mutex<Option<String>>,
    trace: Arc<Mutex<Vec<String>>>,
    fail_publish: AtomicBool,
    fail_retire: Arc<AtomicBool>,
    probes: Mutex<Vec<String>>,
    /// NAN-4662: the remote epoch listing is unavailable.
    fail_list: AtomicBool,
    /// NAN-4614: the next commit hangs before it lands (a cut-off attempt).
    stall: Arc<AtomicBool>,
    /// NAN-4614: the next commit lands but its response is lost.
    lose_response: Arc<AtomicBool>,
    /// NAN-4614: the next commit to a serving epoch (not the master) hangs.
    stall_epoch: Arc<AtomicBool>,
}
struct Table {
    name: String,
    parts: Mutex<BTreeSet<String>>,
    /// NAN-4627: the export chain head, enforced with the REST committer's
    /// own ordering rule, and each part's key hour.
    head: Mutex<Option<(i64, String)>>,
    hours: Mutex<std::collections::BTreeMap<String, i32>>,
    dropped: AtomicBool,
    trace: Arc<Mutex<Vec<String>>>,
    fail_retire: Arc<AtomicBool>,
    /// NAN-4614: how often each part was registered (added) in this table.
    adds: Mutex<HashMap<String, usize>>,
    commits: std::sync::atomic::AtomicUsize,
    stall: Arc<AtomicBool>,
    lose_response: Arc<AtomicBool>,
    stall_epoch: Arc<AtomicBool>,
}
#[async_trait::async_trait]
impl IcebergCommitter for Table {
    async fn commit(&self, m: &ExportManifest) -> Result<()> {
        ensure!(m.tenant_id == T, "foreign tenant");
        if self.stall.swap(false, Ordering::SeqCst)
            || self.name != "events" && self.stall_epoch.swap(false, Ordering::SeqCst)
        {
            std::future::pending::<()>().await;
        }
        let landed = self.apply(m)?;
        ensure!(!(landed && self.lose_response.swap(false, Ordering::SeqCst)), "commit response lost");
        Ok(())
    }
}
impl Table {
    /// `Ok(true)`: a new snapshot landed; `Ok(false)`: checkpoint skip.
    fn apply(&self, m: &ExportManifest) -> Result<bool> {
        let mut head = self.head.lock().unwrap();
        let (at, digest) = head.clone().unzip();
        if crate::part_ingest::iceberg_export::checkpoint_decision(at, digest.as_deref(), m)? {
            return Ok(false);
        }
        let mut parts = self.parts.lock().unwrap();
        for p in &m.remove_parts {
            parts.remove(p);
        }
        for p in &m.add {
            let key = crate::lake_part_gc::parse_part_file_key(&p.keys[0]).unwrap();
            self.hours.lock().unwrap().insert(p.part_id.clone(), (key.path_hour.timestamp() / 3600) as i32);
            parts.insert(p.part_id.clone());
            *self.adds.lock().unwrap().entry(p.part_id.clone()).or_default() += 1;
        }
        *head = Some((m.planned_at_ms, crate::part_ingest::iceberg_export::manifest_digest(m)?));
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}
#[async_trait::async_trait]
impl CatalogLifecycleBackend for Table {
    fn tenant_id(&self) -> &str {
        T
    }
    fn bucket(&self) -> &str {
        BUCKET
    }
    async fn verify_maintenance(&self) -> Result<()> {
        Ok(())
    }
    async fn export_head(&self, with_parts: bool) -> Result<crate::part_ingest::iceberg_export::ExportHead> {
        let hours = self.hours.lock().unwrap();
        Ok(crate::part_ingest::iceberg_export::ExportHead {
            checkpoint: self.head.lock().unwrap().as_ref().map(|h| h.0),
            parts: if with_parts {
                self.parts.lock().unwrap().iter().map(|p| (p.clone(), hours[p])).collect()
            } else {
                Default::default()
            },
        })
    }
    /// NAN-4662: like the REST backend, an absent (dropped) or never
    /// committed table has no snapshot.
    async fn no_committed_snapshot(&self) -> Result<bool> {
        Ok(self.head.lock().unwrap().is_none())
    }
    async fn close_and_drain(&self) -> Result<()> {
        Ok(())
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        Ok(self.parts.lock().unwrap().clone())
    }
    async fn invalidate_results(&self) -> Result<()> {
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        Ok(())
    }
}
#[async_trait::async_trait]
impl ServingTable for Table {
    async fn retire(&self) -> Result<()> {
        ensure!(
            !self.fail_retire.load(Ordering::SeqCst),
            "provider delete unavailable"
        );
        self.trace
            .lock()
            .unwrap()
            .push(format!("retire:{}", self.name));
        self.parts.lock().unwrap().clear();
        *self.head.lock().unwrap() = None;
        self.dropped.store(true, Ordering::SeqCst);
        Ok(())
    }
}
#[async_trait::async_trait]
impl ServingFactory for Provider {
    fn tenant_id(&self) -> &str {
        T
    }
    fn bucket(&self) -> &str {
        BUCKET
    }
    fn build(&self, name: &str) -> Result<Arc<dyn ServingTable>> {
        let mut tables = self.tables.lock().unwrap();
        Ok(tables
            .entry(name.into())
            .or_insert_with(|| {
                Arc::new(Table {
                    name: name.into(),
                    parts: Mutex::new(BTreeSet::new()),
                    head: Mutex::new(None),
                    hours: Mutex::new(Default::default()),
                    dropped: AtomicBool::new(false),
                    trace: self.trace.clone(),
                    fail_retire: self.fail_retire.clone(),
                    adds: Mutex::new(HashMap::new()),
                    commits: Default::default(),
                    stall: self.stall.clone(),
                    lose_response: self.lose_response.clone(),
                    stall_epoch: self.stall_epoch.clone(),
                })
            })
            .clone())
    }
    async fn close(&self) -> Result<()> {
        self.trace.lock().unwrap().push("closed".into());
        Ok(())
    }
    async fn retire_registry(&self) -> Result<()> {
        ensure!(
            !self.fail_publish.load(Ordering::SeqCst),
            "registry unavailable"
        );
        self.trace.lock().unwrap().push("registry-retired".into());
        *self.registry.lock().unwrap() = None;
        Ok(())
    }
    async fn publish(&self, proof: Value) -> Result<()> {
        ensure!(
            !self.fail_publish.load(Ordering::SeqCst),
            "registry unavailable"
        );
        let name = proof["table"].as_str().unwrap().to_string();
        // Like platform publish_serving: exactly one sealed (past) hour.
        let start = chrono::DateTime::parse_from_rfc3339(proof["probe_window"]["start"].as_str().unwrap()).unwrap();
        let end = chrono::DateTime::parse_from_rfc3339(proof["probe_window"]["end"].as_str().unwrap()).unwrap();
        ensure!(end - start == chrono::Duration::hours(1) && end <= chrono::Utc::now() && start.timestamp() % 3600 == 0,
            "catalog_probe_window_invalid");
        self.probes.lock().unwrap().push(start.to_rfc3339());
        // Like platform publish_serving: every serving name must be retired.
        if let Some(old) = self.registry.lock().unwrap().clone() {
            ensure!(
                old != name && proof["retired"].as_array().unwrap().iter().any(|n| n == &old),
                "catalog_serving_epoch_not_fresh"
            );
        }
        self.registry.lock().unwrap().replace(name.clone());
        self.trace.lock().unwrap().push(format!("publish:{name}"));
        Ok(())
    }
    async fn invalidate(&self) -> Result<()> {
        self.trace.lock().unwrap().push("fresh-cache-fence".into());
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        self.trace.lock().unwrap().push("open".into());
        Ok(())
    }
    async fn list_epochs(&self) -> Result<BTreeSet<String>> {
        ensure!(!self.fail_list.load(Ordering::SeqCst), "epoch listing unavailable");
        Ok(self
            .tables
            .lock()
            .unwrap()
            .values()
            .filter(|t| t.name != "events" && !t.dropped.load(Ordering::SeqCst))
            .map(|t| t.name.clone())
            .collect())
    }
}
fn part() -> PartRef {
    PartRef {
        part_id: PartId::parse("0000000000001-aaaaaaaaaaaaaaaa").unwrap(),
        level: Level::Hour,
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
async fn setup() -> (tempfile::TempDir, Arc<Provider>, Arc<TenantCatalog>) {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let backend =
        Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = Arc::new(TenantCatalog::new(T, dir.path().join("custody"), backend).unwrap());
    catalog
        .sync_parts(T, vec![part()], 48 * 3600000, &MergePolicy::default())
        .await
        .unwrap();
    assert_eq!(provider.probes.lock().unwrap().last().unwrap(), "1970-01-01T00:00:00+00:00");
    (dir, provider, catalog)
}
#[tokio::test]
async fn full_erasure_switches_names_before_drop_and_gc_receipt_including_empty_lake() {
    let (_dir, provider, catalog) = setup().await;
    let old = provider.registry.lock().unwrap().clone().unwrap();
    catalog
        .sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default())
        .await
        .unwrap();
    let new = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(old, new);
    let receipt = catalog
        .fence_retirement(T, part().part_id.as_str())
        .await
        .unwrap();
    assert_eq!(receipt.part_id, part().part_id.to_string());
    let trace = provider.trace.lock().unwrap();
    let publish = trace
        .iter()
        .position(|s| s == &format!("publish:{new}"))
        .unwrap();
    let retire = trace
        .iter()
        .position(|s| {
            s == &format!(
                "retire:{}",
                old.strip_prefix("agent.")
                    .unwrap()
                    .strip_suffix("_v1")
                    .unwrap()
            )
        })
        .unwrap();
    assert!(publish < retire);
    assert!(provider
        .build(
            new.strip_prefix("agent.")
                .unwrap()
                .strip_suffix("_v1")
                .unwrap()
        )
        .unwrap()
        .expire_and_inspect()
        .await
        .unwrap()
        .is_empty());
}
#[tokio::test]
async fn registry_failure_blocks_gc_and_retries_the_durable_fresh_epoch() {
    let (_dir, provider, catalog) = setup().await;
    provider.fail_publish.store(true, Ordering::SeqCst);
    assert!(catalog
        .sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default())
        .await
        .is_err());
    assert!(catalog.require_removed(T, part().part_id.as_str()).is_err());
    provider.fail_publish.store(false, Ordering::SeqCst);
    catalog
        .sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default())
        .await
        .unwrap();
    catalog
        .fence_retirement(T, part().part_id.as_str())
        .await
        .unwrap();
}
#[tokio::test]
async fn serving_metadata_delete_failure_keeps_gc_blocked_until_retirement_completes() {
    let (_dir, provider, catalog) = setup().await;
    provider.fail_retire.store(true, Ordering::SeqCst);
    assert!(catalog
        .sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default())
        .await
        .is_err());
    assert!(catalog.require_removed(T, part().part_id.as_str()).is_err());
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog
        .sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default())
        .await
        .unwrap();
    catalog
        .fence_retirement(T, part().part_id.as_str())
        .await
        .unwrap();
}
#[tokio::test]
async fn installation_rotation_publishes_a_fresh_name_even_with_unchanged_parts_after_restart() {
    let (dir, provider, catalog) = setup().await;
    let old = provider.registry.lock().unwrap().clone().unwrap();
    drop(catalog);
    let backend =
        Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend).unwrap();
    catalog.fence_installation().await.unwrap();
    catalog
        .sync_parts(T, vec![part()], 48 * 3600000 + 1, &MergePolicy::default())
        .await
        .unwrap();
    assert_ne!(provider.registry.lock().unwrap().as_ref().unwrap(), &old);
}

#[tokio::test]
async fn uninstall_retires_registry_before_every_serving_table_and_private_master() {
    let (dir, provider, catalog) = setup().await;
    drop(catalog);
    let backend = FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap();
    provider.trace.lock().unwrap().clear();
    backend.uninstall().await.unwrap();
    assert!(provider.registry.lock().unwrap().is_none());
    let trace = provider.trace.lock().unwrap().clone();
    assert_eq!(&trace[..2], &["closed", "registry-retired"]);
    assert_eq!(trace.last().unwrap(), "retire:events");
    for table in provider.tables.lock().unwrap().values() {
        assert!(table.parts.lock().unwrap().is_empty());
    }
    assert!(backend.state().active.is_none());
    backend.uninstall().await.unwrap(); // dropped-table retries remain idempotent
}
#[tokio::test]
async fn uninstall_registry_or_metadata_failure_keeps_custody_recoverable() {
    let (dir, provider, catalog) = setup().await;
    drop(catalog);
    let backend = FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap();
    provider.fail_publish.store(true, Ordering::SeqCst);
    assert!(backend.uninstall().await.is_err());
    assert!(provider.registry.lock().unwrap().is_some());
    provider.fail_publish.store(false, Ordering::SeqCst);
    provider.fail_retire.store(true, Ordering::SeqCst);
    assert!(backend.uninstall().await.is_err());
    assert!(backend.state().active.is_some());
    provider.fail_retire.store(false, Ordering::SeqCst);
    backend.uninstall().await.unwrap();
    assert!(backend.state().active.is_none());
}

fn epoch(registered: &str) -> String {
    registered.strip_prefix("agent.").unwrap().strip_suffix("_v1").unwrap().into()
}
/// NAN-4615: a cell roll wipes `agent-catalog/` (serving state and custody)
/// after a crash left epoch E1 still holding part P while master dropped it
/// (and a pending E2 never published). The rebuilt writer must find both
/// epochs in the remote catalog, name them retired in the next publish and
/// drop them before any proof; P gets no receipt until then.
#[tokio::test]
async fn wiped_writer_retires_epochs_it_forgot_before_any_gc_receipt() {
    let (dir, provider, catalog) = setup().await;
    let e1 = epoch(&provider.registry.lock().unwrap().clone().unwrap());
    let p = part().part_id.to_string();
    // Master commits P's removal, then publish of the fresh epoch fails.
    provider.fail_publish.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.is_err());
    provider.fail_publish.store(false, Ordering::SeqCst);
    assert!(!provider.build("events").unwrap().expire_and_inspect().await.unwrap().contains(&p));
    assert!(provider.build(&e1).unwrap().expire_and_inspect().await.unwrap().contains(&p));
    let e2 = provider.list_epochs().await.unwrap().into_iter().find(|n| n != &e1).unwrap();
    drop(catalog);
    // The roll: the data-wipe init container empties the volume.
    std::fs::remove_dir_all(dir.path().join("serving")).unwrap();
    std::fs::remove_dir_all(dir.path().join("custody")).unwrap();
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend.clone()).unwrap();
    assert!(backend.state().active.is_none() && backend.state().retired.is_empty());
    // No read barrier, unknown epochs: the proof itself fails closed.
    let error = backend.expire_and_inspect().await.unwrap_err();
    assert!(error.to_string().contains("unknown to this writer"), "{error:#}");
    assert!(catalog.fence_retirement(T, &p).await.is_err());
    assert!(catalog.require_removed(T, &p).is_err());
    provider.trace.lock().unwrap().clear();
    // The lake kept ingesting: Q is live (a wiped writer also lost its probe
    // hour, so it needs a sealed live part to publish).
    let q = PartRef { part_id: PartId::parse("0000000000002-bbbbbbbbbbbbbbbb").unwrap(), min_time_us: 2, max_time_us: 2, ..part() };
    // A retire failure keeps it blocked: E1 still references P.
    provider.fail_retire.store(true, Ordering::SeqCst);
    let error = catalog.sync_parts(T, vec![q.clone()], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap_err();
    assert!(format!("{error:#}").contains("provider delete unavailable"), "{error:#}");
    assert!(catalog.fence_retirement(T, &p).await.is_err());
    assert!(catalog.require_removed(T, &p).is_err());
    assert!(provider.build(&e1).unwrap().expire_and_inspect().await.unwrap().contains(&p));
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog.sync_parts(T, vec![q], 49 * 3600000 + 2, &MergePolicy::default()).await.unwrap();
    let live = epoch(&provider.registry.lock().unwrap().clone().unwrap());
    assert!(live != e1 && live != e2);
    let trace = provider.trace.lock().unwrap().clone();
    let publish = trace.iter().position(|s| s == &format!("publish:agent.{live}_v1")).unwrap();
    for old in [&e1, &e2] {
        let retired = trace.iter().position(|s| s == &format!("retire:{old}")).unwrap();
        assert!(publish < retired, "{trace:?}");
    }
    assert_eq!(provider.list_epochs().await.unwrap(), BTreeSet::from([live]));
    assert!(backend.state().retired.is_empty());
    catalog.fence_retirement(T, &p).await.unwrap();
}

/// The newest acknowledged manifest in the writer's custody.
fn last_committed(dir: &std::path::Path) -> ExportManifest {
    let mut paths = std::fs::read_dir(dir.join("custody/export/committed"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    serde_json::from_slice(&std::fs::read(paths.last().unwrap()).unwrap()).unwrap()
}
/// NAN-4627: the roll's data-wipe empties `export/state.json` and
/// `serving/state.json` after the master holds a checkpoint. The rebuilt
/// writer must continue the master's chain (never plan with no predecessor)
/// and plan its fresh epoch at the master checkpoint, so the next delta
/// commits to BOTH the master and the active epoch, with GC unblocked only
/// once that reconciled sync completes.
#[tokio::test]
async fn wiped_writer_rebuilds_the_export_chain_and_the_next_delta_commits() {
    let (dir, provider, catalog) = setup().await;
    let master = provider.build("events").unwrap();
    let c1 = master.export_head(false).await.unwrap().checkpoint.unwrap();
    drop(catalog);
    std::fs::remove_dir_all(dir.path().join("serving")).unwrap();
    std::fs::remove_dir_all(dir.path().join("custody")).unwrap();
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend.clone()).unwrap();
    // GC cannot act on the wiped volume before the rebuild.
    assert!(catalog.fence_retirement(T, part().part_id.as_str()).await.is_err());
    // Same live set: the rebuilt state needs no new plan; a fresh epoch is
    // published at the master checkpoint and the forgotten one retired.
    catalog.sync_parts(T, vec![part()], 49 * 3600000, &MergePolicy::default()).await.unwrap();
    assert_eq!(master.export_head(false).await.unwrap().checkpoint, Some(c1), "no commit was needed");
    let state: ExportState = serde_json::from_slice(&std::fs::read(dir.path().join("custody/export/state.json")).unwrap()).unwrap();
    assert_eq!(state.last_plan_ms, c1);
    assert_eq!(state.exported[&0], vec![part().part_id.to_string()]);
    let active = epoch(&provider.registry.lock().unwrap().clone().unwrap());
    assert_eq!(provider.build(&active).unwrap().export_head(false).await.unwrap().checkpoint, Some(c1));
    // The next delta continues the chain on the master AND the active epoch.
    let q = PartRef { part_id: PartId::parse("0000000000002-bbbbbbbbbbbbbbbb").unwrap(), min_time_us: 2, max_time_us: 2, ..part() };
    catalog.sync_parts(T, vec![part(), q.clone()], 50 * 3600000, &MergePolicy::default()).await.unwrap();
    let delta = last_committed(dir.path());
    assert_eq!(delta.previous_plan_ms, Some(c1));
    assert!(delta.add.iter().any(|f| f.part_id == q.part_id.as_str()));
    for table in [master.clone(), provider.build(&active).unwrap()] {
        assert_eq!(table.export_head(false).await.unwrap().checkpoint, Some(delta.planned_at_ms));
        assert!(table.expire_and_inspect().await.unwrap().contains(q.part_id.as_str()));
    }
    assert!(std::fs::read_dir(dir.path().join("custody/export/pending")).unwrap().next().is_none());
}

/// NAN-4627 (P2): the roll also wipes `probe_hour`. A fully erased lake has
/// no sealed live part, so the rebuilt writer derives the probe from the
/// master checkpoint (a sealed, past hour) instead of failing activation
/// with "no sealed hour" until new data seals.
#[tokio::test]
async fn wiped_writer_with_no_sealed_part_probes_the_hour_before_the_master_checkpoint() {
    let (dir, provider, catalog) = setup().await;
    // Full erasure: the master is empty, its checkpoint is 49h.
    catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.unwrap();
    let master = provider.build("events").unwrap();
    assert!(master.expire_and_inspect().await.unwrap().is_empty());
    assert_eq!(master.export_head(false).await.unwrap().checkpoint, Some(49 * 3600000));
    let before = provider.registry.lock().unwrap().clone().unwrap();
    drop(catalog);
    std::fs::remove_dir_all(dir.path().join("serving")).unwrap();
    std::fs::remove_dir_all(dir.path().join("custody")).unwrap();
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend.clone()).unwrap();
    catalog.sync_parts(T, vec![], 50 * 3600000, &MergePolicy::default()).await.unwrap();
    let after = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(after, before, "a fresh epoch was published");
    assert_eq!(provider.probes.lock().unwrap().last().unwrap(), "1970-01-03T00:00:00+00:00");
    assert_eq!(backend.state().probe_hour, Some(48 * 3600000));
    assert_eq!(provider.list_epochs().await.unwrap(), BTreeSet::from([epoch(&after)]));
}

/// NAN-4662: the fresh serving backend proves "never committed" only when
/// no serving epoch exists (each one references the master's parts) and the
/// private master has no snapshot.
#[tokio::test]
async fn no_committed_snapshot_needs_no_epoch_and_an_uncommitted_master() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let backend = FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap();
    assert!(backend.no_committed_snapshot().await.unwrap());
    provider.fail_list.store(true, Ordering::SeqCst);
    assert!(backend.no_committed_snapshot().await.is_err(), "an unlisted epoch set proves nothing");
    provider.fail_list.store(false, Ordering::SeqCst);
    let manifest = |planned_at_ms| ExportManifest {
        tenant_id: T.into(),
        planned_at_ms,
        previous_plan_ms: None,
        add: vec![],
        remove_parts: vec![],
        hours: vec![],
    };
    let epoch = provider.build("events_0123456789abcdef0123456789abcdef").unwrap();
    epoch.commit(&manifest(1)).await.unwrap();
    assert!(!backend.no_committed_snapshot().await.unwrap(), "a serving epoch exists");
    epoch.retire().await.unwrap();
    assert!(backend.no_committed_snapshot().await.unwrap());
    provider.build("events").unwrap().commit(&manifest(2)).await.unwrap();
    assert!(!backend.no_committed_snapshot().await.unwrap(), "the master committed");
}

/// NAN-4662: a writer sync is the only path that commits. One that lands
/// mid-pass voids the pass's no-commit proof: the catalog is read again, the
/// part it just exported meets the full catalog fence and is never receipted.
#[tokio::test]
async fn a_commit_mid_pass_voids_the_no_commit_proof() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let backend =
        Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend).unwrap();
    let other = "0000000000002-bbbbbbbbbbbbbbbb";
    let pass = crate::part_ingest::iceberg_export::lifecycle::CatalogGcPass::default();
    catalog.fence_in_pass(T, other, &pass).await.unwrap();
    catalog.require_removed(T, other).unwrap();
    catalog
        .sync_parts(T, vec![part()], 48 * 3600000, &MergePolicy::default())
        .await
        .unwrap();
    let exported = part().part_id.to_string();
    for pass in [pass, crate::part_ingest::iceberg_export::lifecycle::CatalogGcPass::default()] {
        let error = catalog.fence_in_pass(T, &exported, &pass).await.unwrap_err();
        assert_eq!(error.to_string(), "catalog metadata still pins part", "{error:#}");
        assert!(catalog.require_removed(T, &exported).is_err(), "a committed part is never receipted");
    }
}

/// NAN-4614: `n` sealed hour parts, one per hour from hour 0.
fn live_set(n: usize) -> Vec<PartRef> {
    (0..n)
        .map(|i| PartRef {
            part_id: PartId::parse(&format!("{:013}-aaaaaaaaaaaaaaaa", i + 1)).unwrap(),
            event_hour: i as i32,
            min_time_us: i as i64 * 3_600_000_000 + 1,
            max_time_us: i as i64 * 3_600_000_000 + 1,
            data_bytes: 1 << 30,
            ..part()
        })
        .collect()
}
const LIVE_NOW: i64 = 96 * 3_600_000;
const BATCH: crate::part_ingest::export::ExportBatchBounds =
    crate::part_ingest::export::ExportBatchBounds { max_files: 4, max_bytes: u64::MAX };
/// One batch per sync (the budget is spent once one batch ran).
const ONE_BATCH_PER_SYNC: super::super::super::lifecycle::SyncLimits = super::super::super::lifecycle::SyncLimits {
    batch_budget: std::time::Duration::ZERO,
    hard_bound: std::time::Duration::from_secs(30),
    batch: BATCH,
};
/// The large-tenant shape: a fresh install (new activation) whose first sync must
/// register the whole live set in the private master AND a fresh serving
/// epoch, through the production TenantCatalog and FreshServingBackend.
fn fresh_install(dir: &std::path::Path, provider: &Arc<Provider>) -> Arc<TenantCatalog> {
    let backend = Arc::new(
        FreshServingBackend::new(provider.clone(), dir.join("serving"))
            .unwrap()
            .with_batch(BATCH),
    );
    Arc::new(
        TenantCatalog::new(T, dir.join("custody"), backend)
            .unwrap()
            .with_limits(ONE_BATCH_PER_SYNC),
    )
}
fn table(provider: &Provider, name: &str) -> Arc<Table> {
    provider.tables.lock().unwrap()[name].clone()
}
/// Sync until converged; returns how many syncs stopped at their budget.
async fn converge(catalog: &TenantCatalog, parts: &[PartRef], max: usize) -> usize {
    let mut incomplete = 0;
    for pass in 0..max {
        match catalog.sync_parts(T, parts.to_vec(), LIVE_NOW + pass as i64, &MergePolicy::default()).await {
            Ok(()) => return incomplete,
            Err(error) => {
                let progress = error
                    .downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>()
                    .unwrap_or_else(|| panic!("only budget stops: {error:#}"));
                assert!(progress.committed >= 1 && progress.remaining >= 1, "{error:#}");
                incomplete += 1;
            }
        }
    }
    panic!("catalog sync did not converge in {max} syncs");
}
fn assert_registered_once(table: &Table, parts: &[PartRef]) {
    let adds = table.adds.lock().unwrap();
    assert_eq!(adds.len(), parts.len(), "{}: every live part registered", table.name);
    assert!(adds.values().all(|n| *n == 1), "{}: no part registered twice: {adds:?}", table.name);
}

/// NAN-4614: a live set larger than one sync budget converges over several
/// syncs, each committing durable batches the next one resumes after; the
/// master and the published epoch hold every part exactly once.
#[tokio::test]
async fn first_export_larger_than_one_budget_converges_over_several_syncs() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(22);
    let incomplete = converge(&catalog, &parts, 64).await;
    // 22 parts / 4 per batch = 6 master batches, one per sync; the last
    // settles and builds the epoch (6 batches of its own) in that sync.
    assert_eq!(incomplete, 5, "one master batch per sync until the last");
    let master = table(&provider, "events");
    assert_eq!(master.commits.load(Ordering::SeqCst), 6);
    assert_registered_once(&master, &parts);
    let name = provider.registry.lock().unwrap().clone().expect("epoch published");
    let epoch = table(&provider, name.strip_prefix("agent.").unwrap().strip_suffix("_v1").unwrap());
    assert_eq!(epoch.commits.load(Ordering::SeqCst), 6);
    assert_registered_once(&epoch, &parts);
    // The epoch chain ends at the master checkpoint, so the next delta
    // continues both.
    assert_eq!(epoch.head.lock().unwrap().as_ref().unwrap().0, master.head.lock().unwrap().as_ref().unwrap().0);
    let mut more = parts.clone();
    more.extend(live_set(23).into_iter().skip(22));
    catalog.sync_parts(T, more.clone(), LIVE_NOW + 3_600_000, &MergePolicy::default()).await.unwrap();
    assert_registered_once(&master, &more);
    assert_registered_once(&epoch, &more);
    // Converged custody: a never-planned part's GC receipt needs no catalog.
    catalog.fence_retirement(T, "0000000000999-aaaaaaaaaaaaaaaa").await.unwrap();
}

/// NAN-4614: a sync cut off inside a batch (the attempt never landed), a
/// commit whose response was lost (it landed), a restart from durable state
/// only, and a sync cut off inside the fresh epoch build all resume without
/// registering any part twice, in the master or the published epoch.
#[tokio::test]
async fn cut_off_or_ambiguous_batches_resume_without_duplicate_registrations() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(14); // 4 master batches: 4, 4, 4, 2
    let incomplete = |result: Result<()>| {
        let error = result.unwrap_err();
        assert!(error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some(), "{error:#}");
    };
    let sync = |catalog: Arc<TenantCatalog>, at: i64| {
        let parts = parts.clone();
        async move { catalog.sync_parts(T, parts, at, &MergePolicy::default()).await }
    };
    incomplete(sync(catalog.clone(), LIVE_NOW).await);
    let master = table(&provider, "events");
    assert_eq!(master.commits.load(Ordering::SeqCst), 1);
    // Batch 2 lands; its response is lost.
    provider.lose_response.store(true, Ordering::SeqCst);
    let error = sync(catalog.clone(), LIVE_NOW + 1).await.unwrap_err();
    assert!(format!("{error:#}").contains("commit response lost"), "{error:#}");
    assert_eq!(master.commits.load(Ordering::SeqCst), 2);
    // Its replay is a checkpoint skip, never a second registration.
    incomplete(sync(catalog.clone(), LIVE_NOW + 2).await);
    assert_eq!(master.commits.load(Ordering::SeqCst), 2);
    // Batch 3 hangs before it lands: the sync is cut off.
    provider.stall.store(true, Ordering::SeqCst);
    let cut = tokio::time::timeout(std::time::Duration::from_millis(200), sync(catalog.clone(), LIVE_NOW + 3)).await;
    assert!(cut.is_err(), "the stalled batch cut the sync off");
    assert_eq!(master.commits.load(Ordering::SeqCst), 2);
    // Restart from durable state only; the fresh epoch's first batch hangs.
    drop(catalog);
    let catalog = fresh_install(dir.path(), &provider);
    provider.stall_epoch.store(true, Ordering::SeqCst);
    let mut epoch_cut = false;
    for pass in 0..8 {
        match tokio::time::timeout(std::time::Duration::from_millis(500), sync(catalog.clone(), LIVE_NOW + 10 + pass)).await {
            Err(_) => {
                epoch_cut = true;
                break;
            }
            Ok(result) => incomplete(result),
        }
    }
    assert!(epoch_cut, "the epoch build was cut off");
    assert_eq!(master.commits.load(Ordering::SeqCst), 4, "the master chain completed first");
    assert!(provider.registry.lock().unwrap().is_none(), "a cut-off epoch is never published");
    converge(&catalog, &parts, 8).await;
    assert_registered_once(&master, &parts);
    let name = provider.registry.lock().unwrap().clone().expect("epoch published");
    let epoch = table(&provider, name.strip_prefix("agent.").unwrap().strip_suffix("_v1").unwrap());
    assert_registered_once(&epoch, &parts);
    assert_eq!(epoch.commits.load(Ordering::SeqCst), 4);
}

/// NAN-4614 review: a removal batch that is not the sync's last (a backlog
/// plan replayed while the live set already moved on) must not settle on
/// its own. Settling builds the pending serving epoch from the CURRENT live
/// set while the master still holds that batch's state, so the epoch is
/// retired as "live set changed" on every sync and the chain (and with it
/// every planned part's GC) never converges.
#[tokio::test]
async fn a_replayed_removal_plan_behind_a_newer_delta_still_converges() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(4);
    converge(&catalog, &parts, 8).await;
    // Hour 0's part is replaced (a removal); that plan lands but the
    // response is lost, so it stays durably pending.
    let mut replaced = parts.clone();
    replaced[0].part_id = PartId::parse("0000000000100-aaaaaaaaaaaaaaaa").unwrap();
    provider.lose_response.store(true, Ordering::SeqCst);
    let error = catalog
        .sync_parts(T, replaced.clone(), LIVE_NOW + 100, &MergePolicy::default())
        .await
        .unwrap_err();
    assert!(format!("{error:#}").contains("commit response lost"), "{error:#}");
    // Before the replay, a new hour seals: the replayed removal plan is no
    // longer the last batch of the next sync.
    let mut moved = replaced.clone();
    moved.push(live_set(5).pop().unwrap());
    let mut converged = false;
    for pass in 0..6 {
        match catalog.sync_parts(T, moved.clone(), LIVE_NOW + 200 + pass, &MergePolicy::default()).await {
            Ok(()) => {
                converged = true;
                break;
            }
            Err(error) => assert!(
                error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some(),
                "only budget stops: {error:#}"
            ),
        }
    }
    assert!(converged, "the chain converges");
    let master = table(&provider, "events");
    let expected = moved.iter().map(|p| p.part_id.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(*master.parts.lock().unwrap(), expected);
    let name = provider.registry.lock().unwrap().clone().expect("epoch published");
    let epoch = table(&provider, name.strip_prefix("agent.").unwrap().strip_suffix("_v1").unwrap());
    assert_eq!(*epoch.parts.lock().unwrap(), expected, "the published epoch is the converged live set");
    // The removal acknowledged by a sync that stopped at its budget is
    // still settled (receipted) by the sync that converged.
    catalog.require_removed(T, parts[0].part_id.as_str()).unwrap();
    assert!(!dir.path().join("custody/export/unsettled").read_dir().unwrap().any(|_| true));
    catalog.fence_retirement(T, parts[0].part_id.as_str()).await.unwrap();
}
