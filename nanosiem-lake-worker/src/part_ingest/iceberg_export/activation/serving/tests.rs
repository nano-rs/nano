//! Mock only provider/control I/O. TenantCatalog's production constructor,
//! durable planner, fresh serving backend, retry fences and GC receipts run.
use super::*;
use crate::parts::{format::PartId, levels::Level};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
const T: &str = "3867aaaa-0000-4000-8000-000000000001";
const BUCKET: &str = "nano-shared-r2-3867aaaa-0000-4000-8000-000000000001";
#[derive(Default)]
struct Provider {
    tables: Mutex<HashMap<String, Arc<Table>>>,
    registry: Arc<Mutex<Option<String>>>,
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
    /// FP-T101: ...once that epoch already landed this many commits.
    stall_epoch_after: Arc<AtomicUsize>,
    /// FP-T101: each published epoch and the parts it held when published.
    published: Mutex<Vec<(String, BTreeSet<String>)>>,
    /// NAN-4734: platform control's privacy fence (`state.privacy`): the
    /// serving names closed by `close_and_drain`, and whether
    /// `publish_serving` has since recorded a fresh serving proof.
    /// `writer_reopen` deletes it; `invalidate_results` and `writer_reopen`
    /// are refused without the fresh proof, exactly like the platform.
    fence: Arc<Mutex<Option<(BTreeSet<String>, bool)>>>,
    /// Every control call the platform model refused.
    refused: Mutex<Vec<String>>,
    /// NAN-4774: the activation is not `active`/`deactivated` (a rotation
    /// onto the wiped volume, or still converging): `writer_adopt` refuses.
    not_active: AtomicBool,
    /// NAN-4774: platform `custody.converged`, reset by `writer_attached`.
    converged: AtomicBool,
    /// NAN-4798: every control call (and epoch retirement) fails with a
    /// connection reset until this tokio instant (a network outage).
    reset_until: Arc<Mutex<Option<tokio::time::Instant>>>,
    /// NAN-4798: the next successful publish starts an outage this long.
    reset_after_publish: Mutex<Option<std::time::Duration>>,
    /// NAN-4798: the next `writer_reopen` lands but its response is lost.
    lose_reopen_response: AtomicBool,
}
fn link(reset_until: &Mutex<Option<tokio::time::Instant>>) -> Result<()> {
    if reset_until.lock().unwrap().is_some_and(|until| tokio::time::Instant::now() < until) {
        return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset by peer").into());
    }
    Ok(())
}
impl Provider {
    fn refuse(&self, op: &str, code: &str) -> Result<()> {
        self.refused.lock().unwrap().push(format!("{op}:{code}"));
        anyhow::bail!("catalog control refused: HTTP 403 ({code})")
    }
}
struct Table {
    name: String,
    registry: Arc<Mutex<Option<String>>>,
    fence: Arc<Mutex<Option<(BTreeSet<String>, bool)>>>,
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
    /// FP-T101: every commit request, including checkpoint skips.
    calls: AtomicUsize,
    stall: Arc<AtomicBool>,
    lose_response: Arc<AtomicBool>,
    stall_epoch: Arc<AtomicBool>,
    stall_epoch_after: Arc<AtomicUsize>,
    /// NAN-4782: metadata-only seeds that landed (a copy of the master's
    /// live entries; no part is prepared or read).
    seeds: AtomicUsize,
    reset_until: Arc<Mutex<Option<tokio::time::Instant>>>,
    fail_seed_schema: AtomicBool,
}
#[async_trait::async_trait]
impl IcebergCommitter for Table {
    async fn commit(&self, m: &ExportManifest) -> Result<()> {
        ensure!(m.tenant_id == T, "foreign tenant");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.stall.swap(false, Ordering::SeqCst)
            || self.name != "events"
                && self.commits.load(Ordering::SeqCst) >= self.stall_epoch_after.load(Ordering::SeqCst)
                && self.stall_epoch.swap(false, Ordering::SeqCst)
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
    async fn live_entries(&self) -> Result<crate::part_ingest::iceberg_export::LiveEntries> {
        let head = self.head.lock().unwrap().clone();
        let parts = self.parts.lock().unwrap().clone();
        Ok(crate::part_ingest::iceberg_export::LiveEntries {
            checkpoint: head.as_ref().map(|h| h.0),
            digest: head.map(|h| h.1),
            schema: None,
            files: vec![],
            all_parts: parts.clone(),
            parts,
        })
    }
    /// Like the REST seed: one commit replacing the current snapshot with
    /// exactly the master's entries, at the master's checkpoint and digest;
    /// a no-op when already equal. Counts as one registration per part.
    async fn seed(&self, entries: &crate::part_ingest::iceberg_export::LiveEntries) -> Result<()> {
        ensure!(self.name != "events", "the master is never seeded");
        if self.fail_seed_schema.swap(false, Ordering::SeqCst) {
            anyhow::bail!(super::super::super::SeedSchemaMismatch);
        }
        if self.stall_epoch.swap(false, Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        let wanted = entries.checkpoint.zip(entries.digest.clone());
        let mut head = self.head.lock().unwrap();
        ensure!(head.as_ref().map(|h| h.0) <= entries.checkpoint, "serving epoch is ahead of the master");
        let mut parts = self.parts.lock().unwrap();
        if *head == wanted && *parts == entries.parts {
            return Ok(());
        }
        let mut hours = self.hours.lock().unwrap();
        hours.clear();
        let mut adds = self.adds.lock().unwrap();
        for part in &entries.parts {
            hours.insert(part.clone(), 0);
            if !parts.contains(part) {
                *adds.entry(part.clone()).or_default() += 1;
            }
        }
        *parts = entries.parts.clone();
        *head = wanted;
        self.seeds.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn retire(&self) -> Result<()> {
        // The production broker requires an open privacy fence even for an
        // unpublished leftover, and refuses any still-registered serving name.
        link(&self.reset_until)?;
        ensure!(self.fence.lock().unwrap().is_some(), "agent_catalog_table_still_serving");
        ensure!(self.registry.lock().unwrap().as_deref() != Some(&format!("agent.{}_v1", self.name)),
            "agent_catalog_table_still_serving");
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
                    registry: self.registry.clone(),
                    fence: self.fence.clone(),
                    parts: Mutex::new(BTreeSet::new()),
                    head: Mutex::new(None),
                    hours: Mutex::new(Default::default()),
                    dropped: AtomicBool::new(false),
                    trace: self.trace.clone(),
                    fail_retire: self.fail_retire.clone(),
                    adds: Mutex::new(HashMap::new()),
                    commits: Default::default(),
                    calls: Default::default(),
                    stall: self.stall.clone(),
                    lose_response: self.lose_response.clone(),
                    stall_epoch: self.stall_epoch.clone(),
                    stall_epoch_after: self.stall_epoch_after.clone(),
                    seeds: Default::default(),
                    reset_until: self.reset_until.clone(),
                    fail_seed_schema: Default::default(),
                })
            })
            .clone())
    }
    async fn close(&self) -> Result<()> {
        link(&self.reset_until)?;
        let names = self.registry.lock().unwrap().iter().cloned().collect();
        self.fence.lock().unwrap().get_or_insert((names, false));
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
        link(&self.reset_until)?;
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
        // Like platform publish_serving: only inside a closed privacy window,
        // and never under a name that window closed.
        if self.fence.lock().unwrap().as_ref().is_none_or(|(closed, _)| closed.contains(&name)) {
            return self.refuse("publish_serving", "catalog_serving_epoch_not_fresh");
        }
        let held = self.tables.lock().unwrap()[epoch(&name).as_str()].parts.lock().unwrap().clone();
        self.published.lock().unwrap().push((name.clone(), held));
        self.registry.lock().unwrap().replace(name.clone());
        self.fence.lock().unwrap().as_mut().expect("privacy fence").1 = true;
        self.trace.lock().unwrap().push(format!("publish:{name}"));
        if let Some(outage) = self.reset_after_publish.lock().unwrap().take() {
            *self.reset_until.lock().unwrap() = Some(tokio::time::Instant::now() + outage);
        }
        Ok(())
    }
    async fn invalidate(&self) -> Result<()> {
        link(&self.reset_until)?;
        let registered = self.registry.lock().unwrap().clone();
        let fresh = self.fence.lock().unwrap().as_ref().is_some_and(|(closed, fresh)| {
            *fresh && registered.as_ref().is_none_or(|name| !closed.contains(name))
        });
        if !fresh {
            return self.refuse("invalidate_results", "catalog_fresh_serving_proof_missing");
        }
        self.trace.lock().unwrap().push("fresh-cache-fence".into());
        Ok(())
    }
    async fn reopen(&self) -> Result<()> {
        link(&self.reset_until)?;
        if !self.fence.lock().unwrap().as_ref().is_some_and(|(_, fresh)| *fresh) {
            return self.refuse("writer_reopen", "catalog_fresh_serving_proof_missing");
        }
        *self.fence.lock().unwrap() = None;
        self.converged.store(true, Ordering::SeqCst);
        self.trace.lock().unwrap().push("open".into());
        if self.lose_reopen_response.swap(false, Ordering::SeqCst) {
            return Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset by peer").into());
        }
        Ok(())
    }
    /// Like platform `writer_adopt`: only this activation's sole registered
    /// serving name, with no open privacy fence and an active activation.
    async fn adopt(&self, table: &str) -> Result<()> {
        if self.not_active.load(Ordering::SeqCst) {
            return self.refuse("writer_adopt", "catalog_adopt_activation_not_active");
        }
        if self.fence.lock().unwrap().is_some() {
            return self.refuse("writer_adopt", "catalog_adopt_privacy_open");
        }
        if self.registry.lock().unwrap().as_deref() != Some(table) {
            return self.refuse("writer_adopt", "catalog_adopt_not_registered");
        }
        self.converged.store(true, Ordering::SeqCst);
        self.trace.lock().unwrap().push(format!("adopt:{table}"));
        Ok(())
    }
    async fn list_epochs(&self) -> Result<BTreeSet<String>> {
        link(&self.reset_until)?;
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
        request_hours: None,
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
    // NAN-4798: the fresh epoch was published before the retirement failed.
    let published = provider.published.lock().unwrap().len();
    let registered = provider.registry.lock().unwrap().clone();
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog
        .sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default())
        .await
        .unwrap();
    // ...and the retry finished THAT epoch: no new mint, no seed, no rebuild.
    assert_eq!(provider.published.lock().unwrap().len(), published);
    assert_eq!(*provider.registry.lock().unwrap(), registered);
    assert!(provider.fence.lock().unwrap().is_none());
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
    // Part GC never waits on the catalog: P is receipted with the agent
    // lane degraded. The gateway is closed (E1 can no longer be read) and a
    // fresh pending epoch exists BEFORE the receipt.
    provider.trace.lock().unwrap().clear();
    let receipt = catalog.fence_retirement(T, &p).await.unwrap();
    assert_eq!(receipt.manifest_sha256, crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(T, &p));
    assert_eq!(provider.trace.lock().unwrap().first().map(String::as_str), Some("closed"));
    assert!(backend.state().pending.is_some(), "a fresh epoch replaces every forgotten one");
    provider.trace.lock().unwrap().clear();
    // The lake kept ingesting: Q is live (a wiped writer also lost its probe
    // hour, so it needs a sealed live part to publish).
    let q = PartRef { part_id: PartId::parse("0000000000002-bbbbbbbbbbbbbbbb").unwrap(), min_time_us: 2, max_time_us: 2, ..part() };
    // A retire failure keeps it blocked: E1 still references P.
    provider.fail_retire.store(true, Ordering::SeqCst);
    let error = catalog.sync_parts(T, vec![q.clone()], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap_err();
    assert!(format!("{error:#}").contains("provider delete unavailable"), "{error:#}");
    // E1 still names P, but the lane stays closed: nothing reopens it.
    assert!(provider.build(&e1).unwrap().expire_and_inspect().await.unwrap().contains(&p));
    let trace = provider.trace.lock().unwrap().clone();
    assert!(!trace.iter().any(|s| s == "open"), "{trace:?}");
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
    // GC acts on the wiped volume before the rebuild: a part the writer no
    // longer holds is receipted with the lane degraded (closed) instead.
    let gone = "0000000000009-aaaaaaaaaaaaaaaa";
    let receipt = catalog.fence_retirement(T, gone).await.unwrap();
    assert_eq!(receipt.manifest_sha256, crate::part_ingest::iceberg_export::lifecycle::degraded_receipt_sha256(T, gone));
    assert!(provider.trace.lock().unwrap().iter().any(|s| s == "closed"));
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
    // NAN-4774: a rotation onto the wiped volume: the platform refuses to
    // adopt the old activation's epoch, so a fresh one is published.
    provider.not_active.store(true, Ordering::SeqCst);
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
    provider.close().await.unwrap();
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
            .unwrap(),
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
    // settles and seeds the epoch from the master (NAN-4782: one metadata
    // commit, no batch replay, nothing prepared) in that sync.
    assert_eq!(incomplete, 5, "one master batch per sync until the last");
    let master = table(&provider, "events");
    assert_eq!(master.commits.load(Ordering::SeqCst), 6);
    assert_registered_once(&master, &parts);
    let name = provider.registry.lock().unwrap().clone().expect("epoch published");
    let epoch = table(&provider, name.strip_prefix("agent.").unwrap().strip_suffix("_v1").unwrap());
    assert_eq!(epoch.seeds.load(Ordering::SeqCst), 1, "one metadata-only seed");
    assert_eq!(epoch.calls.load(Ordering::SeqCst), 0, "no batch was replayed into the epoch");
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
    // Restart from durable state only; the fresh epoch's seed hangs.
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
    assert_eq!(epoch.seeds.load(Ordering::SeqCst), 1, "the cut seed never landed; one did");
    assert_eq!(epoch.calls.load(Ordering::SeqCst), 0, "no batch was replayed into the epoch");
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

/// NAN-4782: master batches done, then the fresh epoch is seeded (from the
/// master's catalog entries) but its publish fails: an interrupted fresh
/// epoch that already holds the live set and was never exposed. Returns it.
async fn cut_epoch_build(provider: &Arc<Provider>, catalog: &Arc<TenantCatalog>, parts: &[PartRef]) -> String {
    let error = catalog.sync_parts(T, parts.to_vec(), LIVE_NOW, &MergePolicy::default()).await.unwrap_err();
    assert!(error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some(), "{error:#}");
    provider.fail_publish.store(true, Ordering::SeqCst);
    let error = catalog.sync_parts(T, parts.to_vec(), LIVE_NOW + 1, &MergePolicy::default()).await.unwrap_err();
    assert!(format!("{error:#}").contains("registry unavailable"), "{error:#}");
    provider.fail_publish.store(false, Ordering::SeqCst);
    assert!(provider.registry.lock().unwrap().is_none(), "an interrupted epoch is never published");
    let pending = provider.list_epochs().await.unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let pending = pending.into_iter().next().unwrap();
    assert_eq!(*table(provider, &pending).parts.lock().unwrap(), ids(parts), "the epoch was seeded");
    assert_eq!(table(provider, &pending).seeds.load(Ordering::SeqCst), 1);
    pending
}
fn retired(provider: &Provider) -> Vec<String> {
    provider.trace.lock().unwrap().iter().filter(|s| s.starts_with("retire:")).cloned().collect()
}
fn ids(parts: &[PartRef]) -> BTreeSet<String> {
    parts.iter().map(|p| p.part_id.to_string()).collect()
}

/// FP-T101 / NAN-4782: an interrupted fresh epoch resumes after the master
/// committed a newly sealed hour. It is re-seeded from the moved master in
/// one metadata commit and the SAME epoch is published; it is never retired
/// and rebuilt, and no batch is ever replayed into it.
#[tokio::test]
async fn an_interrupted_epoch_is_reseeded_from_the_moved_master_not_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(8);
    let pending = cut_epoch_build(&provider, &catalog, &parts).await;
    let moved = live_set(9);
    converge(&catalog, &moved, 8).await;
    let (master, epoch) = (table(&provider, "events"), table(&provider, &pending));
    assert!(retired(&provider).is_empty(), "{:?}", provider.trace.lock().unwrap());
    assert_eq!(*provider.published.lock().unwrap(), vec![(format!("agent.{pending}_v1"), ids(&moved))]);
    assert_eq!(epoch.seeds.load(Ordering::SeqCst), 2, "seeded again from the moved master");
    assert_eq!(epoch.calls.load(Ordering::SeqCst), 0, "no batch replayed");
    assert_registered_once(&epoch, &moved);
    // The epoch carries the master checkpoint: the next delta continues both.
    assert_eq!(epoch.head.lock().unwrap().as_ref().unwrap().0, master.head.lock().unwrap().as_ref().unwrap().0);
    let more = live_set(10);
    catalog.sync_parts(T, more.clone(), LIVE_NOW + 3_600_000, &MergePolicy::default()).await.unwrap();
    assert_registered_once(&master, &more);
    assert_registered_once(&epoch, &more);
    assert_eq!(epoch.calls.load(Ordering::SeqCst), 1, "the add-only delta commits to the active epoch");
}

/// NAN-4782: removals and erasures are already reflected in the master's
/// live set. The interrupted (unpublished) epoch held part P; P is replaced
/// (a merge; an erasure is the same shape) before the epoch resumes. The
/// re-seed copies the master's entries, so the published epoch never holds
/// P, and P's GC receipt follows once the converged sync settles it.
#[tokio::test]
async fn a_reseeded_epoch_never_exposes_a_part_the_master_removed() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(8);
    let pending = cut_epoch_build(&provider, &catalog, &parts).await;
    let removed = parts[0].part_id.to_string();
    assert!(table(&provider, &pending).parts.lock().unwrap().contains(&removed), "the interrupted epoch held it");
    let mut replaced = parts.clone();
    replaced[0].part_id = PartId::parse("0000000000100-aaaaaaaaaaaaaaaa").unwrap();
    converge(&catalog, &replaced, 8).await;
    assert!(retired(&provider).is_empty(), "{:?}", provider.trace.lock().unwrap());
    let published = provider.published.lock().unwrap().clone();
    assert_eq!(published, vec![(format!("agent.{pending}_v1"), ids(&replaced))]);
    assert!(!published[0].1.contains(&removed), "the removed part is never published");
    assert!(!table(&provider, &pending).parts.lock().unwrap().contains(&removed));
    assert_eq!(*table(&provider, "events").parts.lock().unwrap(), ids(&replaced));
    assert_eq!(table(&provider, &pending).calls.load(Ordering::SeqCst), 0, "no batch replayed");
    catalog.require_removed(T, &removed).unwrap();
    catalog.fence_retirement(T, &removed).await.unwrap();
}

/// The fallback stays fail-closed: a master that holds a part the live set
/// cannot reproduce is never copied into a fresh name. Nothing is seeded or
/// published until the master and the live set agree again.
#[tokio::test]
async fn an_epoch_whose_master_differs_from_the_live_set_is_never_seeded_or_published() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(8);
    let pending = cut_epoch_build(&provider, &catalog, &parts).await;
    let stray = "0000000000777-aaaaaaaaaaaaaaaa".to_string();
    table(&provider, "events").parts.lock().unwrap().insert(stray.clone());
    let error = catalog.sync_parts(T, parts.clone(), LIVE_NOW + 2, &MergePolicy::default()).await.unwrap_err();
    assert!(format!("{error:#}").contains("serving epoch live set changed; replay required"), "{error:#}");
    assert!(provider.registry.lock().unwrap().is_none(), "never exposed");
    assert!(!table(&provider, &pending).parts.lock().unwrap().contains(&stray), "never copied");
    assert_eq!(table(&provider, &pending).seeds.load(Ordering::SeqCst), 1, "not re-seeded");
    table(&provider, "events").parts.lock().unwrap().remove(&stray);
    converge(&catalog, &parts, 8).await;
    let name = provider.registry.lock().unwrap().clone().unwrap();
    assert_eq!(provider.published.lock().unwrap().clone(), vec![(name.clone(), ids(&parts))]);
    assert_registered_once(&table(&provider, &epoch(&name)), &parts);
}

fn degraded(part: &str) -> String {
    super::super::super::lifecycle::degraded_receipt_sha256(T, part)
}
fn trace(provider: &Provider) -> Vec<String> {
    provider.trace.lock().unwrap().clone()
}

/// Decision 10-26: part GC is NEVER gated on agent catalog custody.
/// A cell roll lands mid epoch build (custody unconverged, no planned
/// index) and the part log erases a part that the master's unacknowledged
/// backlog batch AND the pending epoch's uncommitted batch both add. GC
/// receipts it at once (agent lane degraded, reads closed); the next syncs
/// tolerate the vanished part: the backlog is set aside and rebuilt from
/// the catalog, the epoch naming it is retired unexposed, and the lane
/// reopens only on a fresh epoch that does not hold it.
#[tokio::test]
async fn gc_proceeds_with_custody_unconverged_and_the_next_sync_tolerates_the_vanished_part() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(8); // master batches 0-3, 4-7; then the epoch seed
    let pending = cut_epoch_build(&provider, &catalog, &parts).await;
    assert!(!dir.path().join("custody/planned-index-ready").exists(), "custody never converged");
    drop(catalog);
    // The roll: a new writer process (no live set in memory).
    let catalog = fresh_install(dir.path(), &provider);
    let erased = parts[5].part_id.to_string();
    provider.trace.lock().unwrap().clear();
    let receipt = catalog.fence_retirement(T, &erased).await.unwrap();
    assert_eq!(receipt.manifest_sha256, degraded(&erased), "never held on the catalog");
    assert!(trace(&provider).contains(&"closed".to_string()), "reads closed before the receipt");
    assert!(dir.path().join("custody/gc-degraded").exists());
    // The writer's next syncs, with the part gone from the live set.
    let live = parts.iter().filter(|p| p.part_id.to_string() != erased).cloned().collect::<Vec<_>>();
    let mut converged = false;
    for pass in 0..8 {
        match catalog.sync_parts(T, live.clone(), LIVE_NOW + 10 + pass, &MergePolicy::default()).await {
            Ok(()) => {
                converged = true;
                break;
            }
            Err(error) => {
                let text = format!("{error:#}");
                assert!(
                    error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some()
                        || text.contains("names a part removed by part GC"),
                    "the vanished part never wedges the sync: {text}"
                );
            }
        }
    }
    assert!(converged, "{:?}", trace(&provider));
    let master = table(&provider, "events");
    assert_eq!(*master.parts.lock().unwrap(), ids(&live));
    // NAN-4782: the interrupted epoch that named it is re-seeded from the
    // master (which no longer holds it) before it is ever published.
    let published = provider.published.lock().unwrap().clone();
    assert_eq!(published.len(), 1, "{published:?}");
    assert_eq!(published[0].0, format!("agent.{pending}_v1"));
    assert_eq!(published[0].1, ids(&live), "the published epoch never holds the vanished part");
    assert!(!table(&provider, &pending).parts.lock().unwrap().contains(&erased));
    let trace = trace(&provider);
    let publish = trace.iter().position(|s| s.starts_with("publish:")).unwrap();
    let open = trace.iter().position(|s| s == "open").unwrap();
    assert!(publish < open, "reads reopen only on the fresh epoch: {trace:?}");
    assert!(!dir.path().join("custody/gc-degraded").exists());
    catalog.require_removed(T, &erased).unwrap();
}

/// Decoupled GC, erasure safety: the ACTIVE (exposed) epoch references a
/// part the writer no longer holds and the catalog cannot clear it. GC is
/// not held; the gateway is closed before the receipt, nothing reopens it
/// while that epoch is current, and reads come back only on a fresh epoch
/// name without the part (the old one retired after the publish names it).
#[tokio::test]
async fn an_exposed_epoch_referencing_a_gc_deleted_part_is_never_served() {
    let (dir, provider, catalog) = setup().await;
    let e1 = epoch(&provider.registry.lock().unwrap().clone().unwrap());
    let p = part().part_id.to_string();
    assert!(table(&provider, &e1).parts.lock().unwrap().contains(&p));
    drop(catalog);
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend).unwrap();
    provider.trace.lock().unwrap().clear();
    let receipt = catalog.fence_retirement(T, &p).await.unwrap();
    assert_eq!(receipt.manifest_sha256, degraded(&p));
    let closed = trace(&provider);
    assert_eq!(closed.first().map(String::as_str), Some("closed"), "{closed:?}");
    assert!(!closed.iter().any(|s| s == "open" || s.starts_with("publish:")), "{closed:?}");
    // Another GC part in the same state never reopens the degraded lane.
    let other = "0000000000005-aaaaaaaaaaaaaaaa";
    catalog.fence_retirement(T, other).await.unwrap();
    assert!(!trace(&provider).iter().any(|s| s == "open"));
    // The writer's next sync (P is gone from the part log).
    catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.unwrap();
    let trace = trace(&provider);
    let e2 = epoch(&provider.registry.lock().unwrap().clone().unwrap());
    assert_ne!(e2, e1);
    assert!(!table(&provider, &e2).parts.lock().unwrap().contains(&p));
    let publish = trace.iter().position(|s| s == &format!("publish:agent.{e2}_v1")).unwrap();
    let retire = trace.iter().position(|s| s == &format!("retire:{e1}")).unwrap();
    let open = trace.iter().position(|s| s == "open").unwrap();
    assert!(publish < retire && publish < open, "{trace:?}");
    assert!(!table(&provider, "events").parts.lock().unwrap().contains(&p));
}

/// NAN-4721 + NAN-4782: the fresh epoch reads no part file (it is a
/// metadata copy of the master), so it has nothing to yield to ingest:
/// with the ingest lag alert holding, the converging sync seeds and
/// publishes at once, without spending any of the yield budget. (The
/// master's own cold reads still yield inside the export target.)
#[tokio::test(start_paused = true)]
async fn a_serving_epoch_seed_reads_no_part_and_never_waits_on_ingest_lag() {
    use crate::part_ingest::agent_lane::PRESSURE_POLL;
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(8); // 2 master batches, then the seed
    let error = catalog.sync_parts(T, parts.clone(), LIVE_NOW, &MergePolicy::default()).await.unwrap_err();
    assert!(error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some(), "{error:#}");
    catalog.ingest_pressure().set(true);
    tokio::time::timeout(PRESSURE_POLL, catalog.sync_parts(T, parts.clone(), LIVE_NOW + 1, &MergePolicy::default()))
        .await
        .expect("the seed never waits on ingest")
        .unwrap();
    assert_eq!(catalog.ingest_pressure().yielded_ms(), 0);
    let name = provider.registry.lock().unwrap().clone().expect("epoch published");
    let epoch = table(&provider, &epoch(&name));
    assert_eq!((epoch.seeds.load(Ordering::SeqCst), epoch.calls.load(Ordering::SeqCst)), (1, 0));
    assert_registered_once(&epoch, &parts);
}

/// NAN-4734: after a converged privacy pass, `writer_reopen` deletes the
/// platform's privacy fence. A later add-only sync (a new sealed hour, no
/// removal) must converge without asking the platform to invalidate (the
/// platform refuses it with `catalog_fresh_serving_proof_missing`, which
/// wedged a tenant's agent lane), and a later removal must still take the full
/// fence: close, fresh name, invalidate, receipt, reopen.
#[tokio::test]
async fn add_only_sync_after_converged_reopen_needs_no_fence_and_removals_still_take_it() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(2);
    converge(&catalog, &parts, 8).await;
    assert!(provider.fence.lock().unwrap().is_none(), "converged pass reopened and ended the fence");
    let published = provider.registry.lock().unwrap().clone().unwrap();
    // Add-only: a new sealed hour, an hour later (past the debounce).
    let more = live_set(3);
    let at = LIVE_NOW + 3_600_000;
    provider.trace.lock().unwrap().clear();
    catalog.sync_parts(T, more.clone(), at, &MergePolicy::default()).await.unwrap();
    assert!(provider.refused.lock().unwrap().is_empty(), "{:?}", provider.refused.lock().unwrap());
    assert!(provider.trace.lock().unwrap().is_empty(), "add-only: no close, publish, invalidate or reopen");
    assert_eq!(provider.registry.lock().unwrap().as_ref(), Some(&published), "same serving name");
    assert_registered_once(&table(&provider, "events"), &more);
    assert_registered_once(&table(&provider, &epoch(&published)), &more);
    // Removal: the first part leaves the live set. Privacy takes the fence.
    let removed = more[0].part_id.to_string();
    catalog.sync_parts(T, more[1..].to_vec(), at + 3_600_000, &MergePolicy::default()).await.unwrap();
    assert!(provider.refused.lock().unwrap().is_empty(), "{:?}", provider.refused.lock().unwrap());
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(fresh, published, "a removal publishes a fresh serving name");
    let trace = provider.trace.lock().unwrap().clone();
    let at_ = |s: &str| trace.iter().position(|t| t == s).unwrap_or_else(|| panic!("{s} missing: {trace:?}"));
    assert!(at_("closed") < at_(&format!("publish:{fresh}")));
    assert!(at_(&format!("publish:{fresh}")) < at_("fresh-cache-fence"));
    assert!(at_("fresh-cache-fence") < at_("open"));
    assert!(provider.fence.lock().unwrap().is_none());
    catalog.require_removed(T, &removed).unwrap();
    assert!(!table(&provider, &epoch(&fresh)).parts.lock().unwrap().contains(&removed));
}

/// NAN-4734: the fence still binds a removal. If the fresh serving name
/// cannot be published, the platform never proves the cache fence and the
/// removed part gets no GC receipt; the next sync completes the fence.
#[tokio::test]
async fn a_removal_without_a_fresh_serving_name_is_never_receipted() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(2);
    converge(&catalog, &parts, 8).await;
    let removed = parts[0].part_id.to_string();
    provider.trace.lock().unwrap().clear();
    provider.fail_publish.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, parts[1..].to_vec(), LIVE_NOW + 3_600_000, &MergePolicy::default()).await.is_err());
    assert!(catalog.require_removed(T, &removed).is_err(), "no receipt before a fresh name is published");
    assert!(!provider.trace.lock().unwrap().iter().any(|t| t == "open"), "reads stay closed");
    provider.fail_publish.store(false, Ordering::SeqCst);
    catalog.sync_parts(T, parts[1..].to_vec(), LIVE_NOW + 3_600_001, &MergePolicy::default()).await.unwrap();
    assert!(provider.refused.lock().unwrap().is_empty(), "{:?}", provider.refused.lock().unwrap());
    catalog.require_removed(T, &removed).unwrap();
}

/// NAN-4734: a merge is a removal. One sync that both adds (a new sealed
/// hour) and replaces hour parts with the day part merged from them must
/// take the full privacy fence against the platform's rules: close, fresh
/// name, invalidate, receipts for every replaced part, reopen. It is never
/// classified as add-only.
#[tokio::test]
async fn a_merge_with_new_data_in_the_same_sync_takes_the_privacy_fence() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(4);
    converge(&catalog, &parts, 8).await;
    let published = provider.registry.lock().unwrap().clone().unwrap();
    // Hours 0..=2 merge into one day part; hour 3 stays; hour 4 is new.
    let day = PartRef {
        part_id: PartId::parse("0000000000200-aaaaaaaaaaaaaaaa").unwrap(),
        level: Level::Day,
        event_hour: 0,
        event_day: Some(0),
        min_time_us: 1,
        max_time_us: 2 * 3_600_000_000 + 1,
        ..parts[0].clone()
    };
    let mut merged = vec![day, parts[3].clone()];
    merged.push(live_set(5).pop().unwrap());
    provider.trace.lock().unwrap().clear();
    let mut done = false;
    for pass in 0..8 {
        match catalog.sync_parts(T, merged.clone(), LIVE_NOW + 3_600_000 + pass, &MergePolicy::default()).await {
            Ok(()) => {
                done = true;
                break;
            }
            Err(error) => assert!(
                error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some(),
                "only budget stops: {error:#}"
            ),
        }
    }
    assert!(done, "the merge converges");
    assert!(provider.refused.lock().unwrap().is_empty(), "{:?}", provider.refused.lock().unwrap());
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(fresh, published, "a merge publishes a fresh serving name");
    let trace = provider.trace.lock().unwrap().clone();
    let at_ = |s: &str| trace.iter().position(|t| t == s).unwrap_or_else(|| panic!("{s} missing: {trace:?}"));
    assert!(at_("closed") < at_(&format!("publish:{fresh}")));
    assert!(at_(&format!("publish:{fresh}")) < at_("fresh-cache-fence"));
    assert!(at_("fresh-cache-fence") < at_("open"));
    let expected = merged.iter().map(|p| p.part_id.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(*table(&provider, &epoch(&fresh)).parts.lock().unwrap(), expected);
    for replaced in &parts[..3] {
        catalog.require_removed(T, replaced.part_id.as_str()).unwrap();
    }
    assert!(catalog.require_removed(T, parts[3].part_id.as_str()).is_err(), "a kept part is never receipted");
}

/// NAN-4774: one activation's writer volume, through the production attach
/// installation step (`install_or_fence`), TenantCatalog and FreshServingBackend.
struct Writer {
    backend: Arc<FreshServingBackend>,
    catalog: Arc<TenantCatalog>,
}
async fn attach_writer(dir: &std::path::Path, provider: &Arc<Provider>, activation: uuid::Uuid) -> Writer {
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.join("serving")).unwrap());
    let catalog = Arc::new(TenantCatalog::new(T, dir.join("custody"), backend.clone()).unwrap().with_limits(ONE_BATCH_PER_SYNC));
    super::super::install_or_fence(&catalog, dir, activation, &super::super::AttachProgress::default()).await.unwrap();
    // `writer_attached` resets the platform's convergence on every attach.
    provider.converged.store(false, Ordering::SeqCst);
    Writer { backend, catalog }
}
/// The roll: the successor pod mounts the other A/B claim (an empty volume)
/// with the same activation; the platform rows and the R2 catalog persist.
async fn roll(dir: &std::path::Path, provider: &Arc<Provider>, old: Writer, activation: uuid::Uuid) -> Writer {
    drop(old);
    std::fs::remove_dir_all(dir).unwrap();
    std::fs::create_dir_all(dir).unwrap();
    provider.trace.lock().unwrap().clear();
    let writer = attach_writer(dir, provider, activation).await;
    assert!(provider.trace.lock().unwrap().is_empty(), "a wiped volume defers the fence to the first sync");
    writer
}
async fn converge_at(catalog: &TenantCatalog, parts: &[PartRef], at: i64) {
    for pass in 0..32 {
        match catalog.sync_parts(T, parts.to_vec(), at + pass, &MergePolicy::default()).await {
            Ok(()) => return,
            Err(error) => assert!(
                error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some(),
                "only budget stops: {error:#}"
            ),
        }
    }
    panic!("sync did not converge");
}
/// A validated activation: the first install publishes epoch E holding `parts`.
async fn validated(dir: &std::path::Path, provider: &Arc<Provider>, parts: &[PartRef]) -> (Writer, uuid::Uuid, String) {
    let activation = uuid::Uuid::new_v4();
    let writer = attach_writer(dir, provider, activation).await;
    converge_at(&writer.catalog, parts, LIVE_NOW).await;
    assert!(provider.converged.load(Ordering::SeqCst) && provider.fence.lock().unwrap().is_none());
    let published = provider.registry.lock().unwrap().clone().unwrap();
    assert_registered_once(&table(provider, &epoch(&published)), parts);
    (writer, activation, published)
}

/// NAN-4774 full sequence: validated epoch -> roll (A/B claim swap wipes the
/// volume) -> restart -> the successor ADOPTS the published epoch: no close,
/// no new pending epoch, no publish, no part registered twice (no rebuild
/// read), platform custody converged again, the next delta lands on the
/// master AND the adopted epoch, and GC proofs work again (planned index rebuilt).
#[tokio::test]
async fn a_rolled_writer_adopts_its_published_epoch_without_a_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(6);
    let (writer, activation, published) = validated(&work, &provider, &parts).await;
    let e = epoch(&published);
    let writer = roll(&work, &provider, writer, activation).await;
    assert!(!writer.catalog.recovery_required(), "reads stay open across the roll");
    // The lake kept ingesting during the roll: one new sealed hour.
    let more = live_set(7);
    converge_at(&writer.catalog, &more, LIVE_NOW + 3_600_000).await;
    assert!(provider.refused.lock().unwrap().is_empty(), "{:?}", provider.refused.lock().unwrap());
    let trace = provider.trace.lock().unwrap().clone();
    assert_eq!(trace.first(), Some(&format!("adopt:{published}")), "{trace:?}");
    assert!(!trace.iter().any(|t| t == "closed" || t.starts_with("publish:") || t == "open"), "no fence, no fresh epoch: {trace:?}");
    assert_eq!(provider.registry.lock().unwrap().as_ref(), Some(&published), "same serving name");
    assert_eq!(provider.list_epochs().await.unwrap(), BTreeSet::from([e.clone()]), "no new pending epoch");
    assert!(provider.converged.load(Ordering::SeqCst), "platform custody converged on the adopted epoch");
    let state = writer.backend.state();
    assert_eq!((state.active.as_deref(), state.pending.as_deref()), (Some(e.as_str()), None));
    assert!(state.retired.is_empty());
    // Every part registered exactly once in the epoch: nothing was rebuilt.
    assert_registered_once(&table(&provider, &e), &more);
    assert_registered_once(&table(&provider, "events"), &more);
    let master = table(&provider, "events");
    assert_eq!(table(&provider, &e).export_head(false).await.unwrap().checkpoint, master.export_head(false).await.unwrap().checkpoint);
    // GC custody is whole again: a live part is pinned, never receipted.
    assert!(writer.catalog.fence_retirement(T, more[0].part_id.as_str()).await.is_err());
    // A later erasure still takes the full fence and a fresh name.
    converge_at(&writer.catalog, &more[1..], LIVE_NOW + 2 * 3_600_000).await;
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(fresh, published);
    assert!(!table(&provider, &epoch(&fresh)).parts.lock().unwrap().contains(more[0].part_id.as_str()));
    writer.catalog.require_removed(T, more[0].part_id.as_str()).unwrap();
}

/// NAN-4774 negative: the epoch's watermark differs from the master's (the
/// roll landed between the master commit and the epoch commit). Not proven:
/// today's privacy pass and fresh build, the old epoch retired after publish.
/// Same for an epoch at the master's watermark whose referenced parts differ
/// (it still names a part the master no longer holds): the parts proof alone
/// refuses it, before the platform is asked.
#[tokio::test]
async fn a_rolled_writer_rebuilds_when_the_epoch_watermark_or_parts_differ() {
    for case in ["watermark", "parts"] {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("catalog");
        let provider = Arc::new(Provider::default());
        let parts = live_set(3);
        let (writer, activation, published) = validated(&work, &provider, &parts).await;
        let e = table(&provider, &epoch(&published));
        if case == "watermark" {
            let mut head = e.head.lock().unwrap();
            let (at, digest) = head.clone().unwrap();
            *head = Some((at - 1, digest));
        } else {
            e.parts.lock().unwrap().insert("0000000000099-aaaaaaaaaaaaaaaa".into());
        }
        let writer = roll(&work, &provider, writer, activation).await;
        converge_at(&writer.catalog, &parts, LIVE_NOW + 3_600_000).await;
        assert_rebuilt(&provider, &published, false);
        assert_eq!(writer.backend.state().active.as_deref(), Some(epoch(provider.registry.lock().unwrap().as_ref().unwrap()).as_str()), "{case}");
    }
}

/// NAN-4774 negative: an erasure committed to the master after the epoch
/// was published (the old writer's privacy pass was cut off by the roll
/// before its fresh epoch published). The epoch still holds the erased part:
/// never adopted, never served again; the part is receipted only after the
/// fresh name is published.
#[tokio::test]
async fn a_rolled_writer_never_adopts_an_epoch_holding_an_erased_part() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(3);
    let (writer, activation, published) = validated(&work, &provider, &parts).await;
    let erased = parts[0].part_id.to_string();
    provider.fail_publish.store(true, Ordering::SeqCst);
    for pass in 0..32 {
        let _ = writer.catalog.sync_parts(T, parts[1..].to_vec(), LIVE_NOW + 3_600_000 + pass, &MergePolicy::default()).await;
        if !table(&provider, "events").parts.lock().unwrap().contains(&erased) { break; }
    }
    assert!(!table(&provider, "events").parts.lock().unwrap().contains(&erased), "the master committed the erasure");
    assert!(table(&provider, &epoch(&published)).parts.lock().unwrap().contains(&erased));
    provider.fail_publish.store(false, Ordering::SeqCst);
    // The platform fence the cut-off pass opened ends with that pod's life
    // only through a fresh publish; model the worst case (fence gone) so the
    // writer's own proof is what refuses the adoption.
    *provider.fence.lock().unwrap() = None;
    let writer = roll(&work, &provider, writer, activation).await;
    converge_at(&writer.catalog, &parts[1..], LIVE_NOW + 2 * 3_600_000).await;
    // Multiple epochs require fenced retirement; neither is adopted.
    assert_rebuilt(&provider, &published, false);
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert!(!table(&provider, &epoch(&fresh)).parts.lock().unwrap().contains(&erased));
    assert!(table(&provider, &epoch(&published)).dropped.load(Ordering::SeqCst), "the epoch holding it is gone");
    // The wiped volume lost the old receipt; part GC proves it again now
    // that no retained metadata references the part.
    writer.catalog.fence_retirement(T, &erased).await.unwrap();
}

/// NAN-4774 negative: an erasure in the part log that the master has not
/// seen yet (it ran during the roll). Equality with the master is insufficient:
/// the pending removal must refuse adoption before custody can converge.
#[tokio::test]
async fn an_erasure_during_the_roll_refuses_adoption_and_takes_the_fence() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(3);
    let (writer, activation, published) = validated(&work, &provider, &parts).await;
    let erased = parts[0].part_id.to_string();
    let writer = roll(&work, &provider, writer, activation).await;
    converge_at(&writer.catalog, &parts[1..], LIVE_NOW + 3_600_000).await;
    assert_rebuilt(&provider, &published, false);
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(fresh, published, "the erasure publishes a fresh name");
    let trace = provider.trace.lock().unwrap().clone();
    let at = |s: &str| trace.iter().position(|t| t == s).unwrap_or_else(|| panic!("{s} missing: {trace:?}"));
    assert!(at("closed") < at(&format!("publish:{fresh}")));
    assert!(at(&format!("publish:{fresh}")) < at(&format!("retire:{}", epoch(&published))));
    assert!(at(&format!("publish:{fresh}")) < at("fresh-cache-fence"));
    assert!(!table(&provider, &epoch(&fresh)).parts.lock().unwrap().contains(&erased));
    writer.catalog.require_removed(T, &erased).unwrap();
}

#[tokio::test]
async fn a_rolled_writer_with_a_leftover_epoch_rebuilds_under_the_broker_retirement_fence() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(3);
    let (writer, activation, published) = validated(&work, &provider, &parts).await;
    let leftover = format!("events_{}", uuid::Uuid::new_v4().simple());
    let extra = provider.build(&leftover).unwrap();
    assert!(extra.retire().await.is_err(), "the production broker requires privacy even for a leftover");
    let writer = roll(&work, &provider, writer, activation).await;
    converge_at(&writer.catalog, &parts, LIVE_NOW + 3_600_000).await;
    assert_rebuilt(&provider, &published, false);
    assert!(table(&provider, &leftover).dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn local_closed_reads_or_unsettled_removals_refuse_adoption_before_platform_io() {
    for closed in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("catalog");
        let provider = Arc::new(Provider::default());
        let parts = live_set(3);
        let (writer, activation, published) = validated(&work, &provider, &parts).await;
        let writer = roll(&work, &provider, writer, activation).await;
        if closed {
            std::fs::write(work.join("custody/reads-closed"), T).unwrap();
        } else {
            let unsettled = work.join("custody/export/unsettled");
            std::fs::create_dir_all(&unsettled).unwrap();
            std::fs::write(unsettled.join("0000000000001.json"),
                serde_json::to_vec(&vec![("0000000000099-aaaaaaaaaaaaaaaa", "a".repeat(64))]).unwrap()).unwrap();
        }
        converge_at(&writer.catalog, &parts, LIVE_NOW + 3_600_000).await;
        assert_rebuilt(&provider, &published, false);
    }
}

#[tokio::test]
async fn an_add_only_backlog_on_the_wiped_writer_refuses_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(3);
    let (writer, activation, published) = validated(&work, &provider, &parts).await;
    let mut state = ExportState::load_durable(&work.join("custody")).unwrap();
    let writer = roll(&work, &provider, writer, activation).await;
    let more = live_set(4);
    let at = LIVE_NOW + 3_600_000;
    let pending = plan_export_reconciled(&more, &state, at, &MergePolicy::default());
    let batches = state.split_plan(T, &pending, BATCH).unwrap();
    assert!(batches.iter().all(|m| m.remove_parts.is_empty()));
    state.record_durable_batches(&work.join("custody"), batches, at).unwrap();
    converge_at(&writer.catalog, &more, at).await;
    assert_rebuilt(&provider, &published, false);
}

/// NAN-4774 negative: custody not held for this epoch. A rotation onto the
/// wiped volume (another activation, not active) or an open privacy fence:
/// the platform refuses `writer_adopt` and the writer rebuilds.
#[tokio::test]
async fn a_rolled_writer_rebuilds_when_the_platform_refuses_custody() {
    for case in ["not_active", "fence_open"] {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("catalog");
        let provider = Arc::new(Provider::default());
        let parts = live_set(3);
        let (writer, activation, published) = validated(&work, &provider, &parts).await;
        match case {
            "not_active" => provider.not_active.store(true, Ordering::SeqCst),
            _ => *provider.fence.lock().unwrap() = Some((BTreeSet::from([published.clone()]), false)),
        }
        let writer = roll(&work, &provider, writer, activation).await;
        converge_at(&writer.catalog, &parts, LIVE_NOW + 3_600_000).await;
        assert_rebuilt(&provider, &published, true);
        assert!(provider.converged.load(Ordering::SeqCst), "{case}: converged through the fresh publish");
    }
}

/// The fallback: closed reads, a fresh epoch published, the old one retired
/// after that publish, and nothing adopted.
fn assert_rebuilt(provider: &Provider, published: &str, refused: bool) {
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(fresh, published, "a fresh epoch replaces the unproven one");
    let trace = provider.trace.lock().unwrap().clone();
    assert!(!trace.iter().any(|t| t.starts_with("adopt:")), "{trace:?}");
    let at = |s: &str| trace.iter().position(|t| t == s).unwrap_or_else(|| panic!("{s} missing: {trace:?}"));
    assert!(at("closed") < at(&format!("publish:{fresh}")));
    assert!(at(&format!("publish:{fresh}")) < at(&format!("retire:{}", epoch(published))));
    assert_eq!(
        provider.refused.lock().unwrap().iter().any(|r| r.starts_with("writer_adopt:")),
        refused,
        "{:?}",
        provider.refused.lock().unwrap()
    );
}

/// NAN-4782 goal 2: a roll lands MID-EPOCH. An erasure closed reads (the
/// platform privacy fence is open on E1), the master committed the removal
/// and a fresh epoch E2 was seeded, then publish failed and the A/B claim
/// swap wiped `serving/state.json` and all custody. Everything the successor
/// needs comes from the catalog and the platform: the master checkpoint
/// (export head), every epoch it forgot (the catalog listing, retired through
/// the verified path), the open fence (the platform refuses adoption). It
/// re-exports nothing (no master commit), replays no batch into any epoch
/// (a fresh name is one metadata-only seed), never exposes the erased part,
/// and GC receipts it only after the forgotten epochs are retired.
#[tokio::test]
async fn a_roll_mid_epoch_recovers_from_catalog_and_platform_without_a_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(6);
    let (writer, activation, published) = validated(&work, &provider, &parts).await;
    let e1 = epoch(&published);
    let erased = parts[0].part_id.to_string();
    let live = parts[1..].to_vec();
    provider.fail_publish.store(true, Ordering::SeqCst);
    let error = loop {
        match writer.catalog.sync_parts(T, live.clone(), LIVE_NOW + 3_600_000, &MergePolicy::default()).await {
            Err(error) if error.downcast_ref::<super::super::super::lifecycle::CatalogSyncIncomplete>().is_some() => {}
            other => break other.unwrap_err(),
        }
    };
    assert!(format!("{error:#}").contains("registry unavailable"), "{error:#}");
    provider.fail_publish.store(false, Ordering::SeqCst);
    let master = table(&provider, "events");
    assert_eq!(*master.parts.lock().unwrap(), ids(&live), "the master committed the erasure");
    assert!(provider.fence.lock().unwrap().is_some(), "the platform privacy fence is open");
    let e2 = provider.list_epochs().await.unwrap().into_iter().find(|n| n != &e1).unwrap();
    let master_commits = master.commits.load(Ordering::SeqCst);
    // The roll.
    let writer = roll(&work, &provider, writer, activation).await;
    assert!(writer.backend.state().active.is_none() && writer.backend.state().pending.is_none());
    converge_at(&writer.catalog, &live, LIVE_NOW + 2 * 3_600_000).await;
    assert_eq!(master.commits.load(Ordering::SeqCst), master_commits, "the master was not re-exported");
    let fresh = epoch(&provider.registry.lock().unwrap().clone().unwrap());
    assert!(fresh != e1 && fresh != e2, "a fresh name is the fence");
    let state = writer.backend.state();
    assert_eq!((state.active.as_deref(), state.pending.as_deref()), (Some(fresh.as_str()), None));
    assert!(state.retired.is_empty());
    assert_eq!(state.last_plan_ms, master.head.lock().unwrap().as_ref().unwrap().0, "checkpoint learned from the catalog");
    for name in [&e1, &e2, &fresh] {
        assert_eq!(table(&provider, name).calls.load(Ordering::SeqCst), 0, "{name}: no batch replayed into an epoch");
    }
    assert_eq!(table(&provider, &fresh).seeds.load(Ordering::SeqCst), 1);
    assert_eq!(*table(&provider, &fresh).parts.lock().unwrap(), ids(&live));
    // No privacy regression: publish before any old name is dropped, nothing
    // published after the erasure holds the erased part, reads reopen last.
    let trace = provider.trace.lock().unwrap().clone();
    let publish = trace.iter().position(|s| s == &format!("publish:agent.{fresh}_v1")).unwrap();
    for old in [&e1, &e2] {
        let retired = trace.iter().position(|s| s == &format!("retire:{old}")).unwrap_or_else(|| panic!("{old} retired: {trace:?}"));
        assert!(publish < retired, "{trace:?}");
    }
    let open = trace.iter().rposition(|s| s == "open").unwrap();
    assert!(publish < open, "{trace:?}");
    let published = provider.published.lock().unwrap().clone();
    assert!(published[1..].iter().all(|(_, held)| !held.contains(&erased)), "{published:?}");
    assert_eq!(provider.list_epochs().await.unwrap(), BTreeSet::from([fresh]));
    assert!(provider.fence.lock().unwrap().is_none());
    writer.catalog.fence_retirement(T, &erased).await.unwrap();
}

/// NAN-4782 goal 2, steady state: a roll after a converged epoch rebuilds
/// nothing. The platform confirms the published epoch (`writer_adopt`), the
/// catalog proves it equals the master, and the successor seeds nothing,
/// commits nothing to the master and opens no fence. When the platform
/// refuses instead (here: the activation is not active), the fallback is a
/// fresh NAME seeded from the master: still no batch replay, no master
/// re-export, and no part file read.
#[tokio::test]
async fn a_steady_state_roll_adopts_or_reseeds_but_never_replays() {
    for refuse in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let work = dir.path().join("catalog");
        let provider = Arc::new(Provider::default());
        let parts = live_set(6);
        let (writer, activation, published) = validated(&work, &provider, &parts).await;
        let e1 = epoch(&published);
        let master = table(&provider, "events");
        let master_commits = master.commits.load(Ordering::SeqCst);
        let e1_seeds = table(&provider, &e1).seeds.load(Ordering::SeqCst);
        provider.not_active.store(refuse, Ordering::SeqCst);
        let writer = roll(&work, &provider, writer, activation).await;
        converge_at(&writer.catalog, &parts, LIVE_NOW + 1_000).await;
        assert_eq!(master.commits.load(Ordering::SeqCst), master_commits, "refuse={refuse}: no master re-export");
        let active = writer.backend.state().active.unwrap();
        if refuse {
            assert_ne!(active, e1);
            assert_eq!(table(&provider, &active).seeds.load(Ordering::SeqCst), 1);
            assert!(provider.trace.lock().unwrap().iter().any(|s| s == &format!("retire:{e1}")));
        } else {
            assert_eq!(active, e1, "adopted");
            assert_eq!(table(&provider, &e1).seeds.load(Ordering::SeqCst), e1_seeds, "nothing seeded");
            assert!(!provider.trace.lock().unwrap().iter().any(|s| s == "closed"));
        }
        assert_eq!(table(&provider, &active).calls.load(Ordering::SeqCst), 0, "no batch replayed");
        assert_eq!(*table(&provider, &active).parts.lock().unwrap(), ids(&parts));
    }
}

/// NAN-4798 helpers: the published epochs and the serving tables seeded.
fn published(provider: &Provider) -> Vec<String> {
    provider.published.lock().unwrap().iter().map(|(name, _)| name.clone()).collect()
}
fn seeds(provider: &Provider) -> usize {
    provider.tables.lock().unwrap().values().map(|t| t.seeds.load(Ordering::SeqCst)).sum()
}

#[tokio::test]
async fn metadata_only_epoch_seed_preserves_gc_writer_receipt_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("catalog");
    let provider = Arc::new(Provider::default());
    let parts = live_set(3);
    let (writer, activation, _) = validated(&work, &provider, &parts).await;
    let before = seeds(&provider);
    let master_calls = table(&provider, "events").calls.load(Ordering::SeqCst);
    provider.not_active.store(true, Ordering::SeqCst); // gateway refuses adoption
    let writer = roll(&work, &provider, writer, activation).await;
    converge_at(&writer.catalog, &parts, LIVE_NOW + 3_600_000).await;
    assert_eq!(seeds(&provider), before + 1);
    assert_eq!(table(&provider, "events").calls.load(Ordering::SeqCst), master_calls, "no master rebuild");
    let name = provider.registry.lock().unwrap().clone().unwrap();
    assert_eq!(table(&provider, &epoch(&name)).calls.load(Ordering::SeqCst), 0, "metadata seed reads no part files");
    crate::part_ingest::part_gc_cell::transport_tests::receipt_tests::assert_catalog_gc_settles(T, writer.catalog).await;
}

#[tokio::test]
async fn full_catalog_rebuild_preserves_gc_writer_receipt_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let (writer, _, _) = validated(dir.path(), &provider, &live_set(3)).await;
    assert!(table(&provider, "events").calls.load(Ordering::SeqCst) > 0, "empty master rebuilt through export");
    crate::part_ingest::part_gc_cell::transport_tests::receipt_tests::assert_catalog_gc_settles(T, writer.catalog).await;
}
fn q() -> PartRef {
    PartRef { part_id: PartId::parse("0000000000002-bbbbbbbbbbbbbbbb").unwrap(), min_time_us: 2, max_time_us: 2, ..part() }
}

/// NAN-4798: a 5-minute run of connection resets right after
/// `publish_serving` (retire, purge, invalidate and reopen all fail) is
/// ridden out inside the sync: the SAME epoch reopens, with no new mint.
#[tokio::test(start_paused = true)]
async fn a_five_minute_reset_window_after_publish_reopens_the_same_epoch_without_a_new_mint() {
    let (_dir, provider, catalog) = setup().await;
    let before = published(&provider);
    let seeded = seeds(&provider);
    let tables = provider.tables.lock().unwrap().len();
    *provider.reset_after_publish.lock().unwrap() = Some(std::time::Duration::from_secs(5 * 60));
    let started = tokio::time::Instant::now();
    catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(5 * 60));
    let after = published(&provider);
    assert_eq!(after.len(), before.len() + 1, "exactly one fresh epoch for the erasure");
    assert_eq!(seeds(&provider), seeded + 1, "the outage never rebuilds the epoch");
    assert_eq!(provider.tables.lock().unwrap().len(), tables + 1, "no extra epoch minted");
    assert_eq!(provider.registry.lock().unwrap().as_ref(), after.last());
    assert!(provider.fence.lock().unwrap().is_none(), "reads reopened");
    assert!(!catalog.recovery_required());
    assert!(provider.refused.lock().unwrap().is_empty());
    catalog.fence_retirement(T, part().part_id.as_str()).await.unwrap();
}

/// NAN-4798: an outage longer than the retry budget fails the sync CLOSED
/// (reads closed, no receipt, the gateway never reopened); the next sync
/// finishes the already-published epoch instead of minting a new one.
#[tokio::test(start_paused = true)]
async fn an_outage_past_the_retry_budget_stays_closed_and_the_next_sync_finishes_the_same_epoch() {
    let (_dir, provider, catalog) = setup().await;
    *provider.reset_after_publish.lock().unwrap() = Some(std::time::Duration::from_secs(25 * 60));
    let error = catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.unwrap_err();
    assert!(format!("{error:#}").contains("connection reset"), "{error:#}");
    // Fail closed: nothing leaks while the platform is unreachable.
    assert!(catalog.recovery_required(), "reads-closed marker kept");
    assert!(provider.fence.lock().unwrap().is_some(), "gateway fence still closed");
    let trace = provider.trace.lock().unwrap().clone();
    let publish = trace.iter().rposition(|s| s.starts_with("publish:")).unwrap();
    assert!(!trace[publish..].iter().any(|s| s == "open"), "reads never reopened");
    assert!(catalog.require_removed(T, part().part_id.as_str()).is_err(), "no GC receipt");
    let epochs = published(&provider);
    let seeded = seeds(&provider);
    tokio::time::advance(std::time::Duration::from_secs(25 * 60)).await;
    catalog.sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap();
    assert_eq!(published(&provider), epochs, "no new epoch minted or published");
    assert_eq!(seeds(&provider), seeded, "no epoch seeded");
    assert_eq!(provider.registry.lock().unwrap().as_ref(), epochs.last());
    assert!(provider.fence.lock().unwrap().is_none());
    assert!(!catalog.recovery_required());
    catalog.fence_retirement(T, part().part_id.as_str()).await.unwrap();
}

/// The finishing checkpoint is durable across a process restart, including
/// repeated retirement failures. No retry may seed or publish a new epoch.
#[tokio::test]
async fn a_restarted_writer_finishes_the_same_epoch_after_repeated_retirement_failures() {
    let (dir, provider, catalog) = setup().await;
    provider.fail_retire.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.is_err());
    let epochs = published(&provider);
    let seeded = seeds(&provider);
    drop(catalog);
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    assert!(backend.published_under_fence().is_some());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend.clone()).unwrap();
    for pass in 1..=3 {
        assert!(catalog.sync_parts(T, vec![], 49 * 3600000 + pass, &MergePolicy::default()).await.is_err());
        assert!(catalog.recovery_required());
        assert!(provider.fence.lock().unwrap().is_some());
        assert_eq!(published(&provider), epochs);
        assert_eq!(seeds(&provider), seeded);
        assert!(backend.state().pending.is_none());
    }
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog.sync_parts(T, vec![], 49 * 3600000 + 4, &MergePolicy::default()).await.unwrap();
    assert_eq!(published(&provider), epochs);
    assert_eq!(seeds(&provider), seeded);
    assert!(backend.published_under_fence().is_none());
    assert!(!catalog.recovery_required());
    assert!(provider.fence.lock().unwrap().is_none());
}

/// Both markers independently invalidate a finishing proof. This also
/// checks the conservative path after restart, when only disk state exists.
#[tokio::test]
async fn gc_degraded_or_a_wiped_index_while_finishing_still_mints() {
    for degraded in [false, true] {
        let (dir, provider, catalog) = setup().await;
        provider.fail_retire.store(true, Ordering::SeqCst);
        assert!(catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.is_err());
        let epochs = published(&provider);
        let seeded = seeds(&provider);
        drop(catalog);
        let custody = dir.path().join("custody");
        if degraded {
            std::fs::write(custody.join("gc-degraded"), T).unwrap();
        } else {
            std::fs::remove_file(custody.join("planned-index-ready")).unwrap();
        }
        let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
        let catalog = TenantCatalog::new(T, custody, backend).unwrap();
        provider.fail_retire.store(false, Ordering::SeqCst);
        catalog.sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap();
        let after = published(&provider);
        assert_eq!(after.len(), epochs.len() + 1, "degraded={degraded}");
        assert_ne!(after.last(), epochs.last());
        assert_eq!(seeds(&provider), seeded + 1);
        assert!(provider.fence.lock().unwrap().is_none());
        assert!(!catalog.recovery_required());
    }
}

/// Persist the new pending epoch even when an explicit installation close
/// fails to reach the gateway. A later sync must not resume the old proof.
#[tokio::test(start_paused = true)]
async fn a_failed_explicit_close_durably_discards_finishing_before_gateway_io() {
    let (dir, provider, catalog) = setup().await;
    provider.fail_retire.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.is_err());
    let epochs = published(&provider);
    *provider.reset_until.lock().unwrap() = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(25 * 60));
    assert!(catalog.fence_installation().await.is_err());
    drop(catalog);
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let state = backend.state();
    assert!(state.finishing.is_none());
    assert!(state.pending.is_some());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend).unwrap();
    *provider.reset_until.lock().unwrap() = None;
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog.sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap();
    assert_eq!(published(&provider).len(), epochs.len() + 1);
    assert_ne!(published(&provider).last(), epochs.last());
    assert!(provider.fence.lock().unwrap().is_none());
    assert!(!catalog.recovery_required());
}

/// NAN-4798: the fence is load-bearing. A removal planned AFTER the epoch
/// was published (here a second erasure while its retirement still fails)
/// is a real privacy event: the next sync mints a fresh epoch.
#[tokio::test]
async fn an_erasure_after_the_publish_still_mints_a_fresh_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let backend = Arc::new(FreshServingBackend::new(provider.clone(), dir.path().join("serving")).unwrap());
    let catalog = TenantCatalog::new(T, dir.path().join("custody"), backend).unwrap();
    catalog.sync_parts(T, vec![part(), q()], 48 * 3600000, &MergePolicy::default()).await.unwrap();
    provider.fail_retire.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, vec![q()], 49 * 3600000, &MergePolicy::default()).await.is_err());
    let finishing = published(&provider);
    assert_eq!(provider.registry.lock().unwrap().as_ref(), finishing.last());
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog.sync_parts(T, vec![], 50 * 3600000, &MergePolicy::default()).await.unwrap();
    let after = published(&provider);
    assert_eq!(after.len(), finishing.len() + 1, "a fresh epoch for the new erasure");
    assert_ne!(after.last(), finishing.last());
    assert_eq!(provider.registry.lock().unwrap().as_ref(), after.last());
    assert!(provider.published.lock().unwrap().last().unwrap().1.is_empty());
    assert!(provider.fence.lock().unwrap().is_none());
    catalog.fence_retirement(T, q().part_id.as_str()).await.unwrap();
}

/// NAN-4798: a GC degrade or an installation fence while an epoch is still
/// finishing closes for a reason the sync cannot re-derive: it mints.
#[tokio::test]
async fn an_installation_fence_while_finishing_still_mints() {
    let (_dir, provider, catalog) = setup().await;
    provider.fail_retire.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.is_err());
    let finishing = published(&provider);
    provider.fail_retire.store(false, Ordering::SeqCst);
    catalog.fence_installation().await.unwrap();
    catalog.sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap();
    let after = published(&provider);
    assert_eq!(after.len(), finishing.len() + 1);
    assert_ne!(after.last(), finishing.last());
}

/// NAN-4798: `writer_reopen` landed but its response was lost, so its retry
/// is refused (the platform ended the fence). The epoch can never finish:
/// the next sync mints instead of wedging on a missing fresh proof.
#[tokio::test]
async fn a_lost_reopen_response_mints_on_the_next_sync_and_never_wedges() {
    let (_dir, provider, catalog) = setup().await;
    provider.lose_reopen_response.store(true, Ordering::SeqCst);
    assert!(catalog.sync_parts(T, vec![], 49 * 3600000, &MergePolicy::default()).await.is_err());
    assert!(catalog.recovery_required());
    let before = published(&provider);
    catalog.sync_parts(T, vec![], 49 * 3600000 + 1, &MergePolicy::default()).await.unwrap();
    assert_eq!(published(&provider).len(), before.len() + 1);
    assert!(provider.fence.lock().unwrap().is_none());
    assert!(!catalog.recovery_required());
}

#[tokio::test]
async fn an_epoch_with_incompatible_field_ids_is_replaced_before_retirement() {
    let dir = tempfile::tempdir().unwrap();
    let provider = Arc::new(Provider::default());
    let catalog = fresh_install(dir.path(), &provider);
    catalog.fence_installation().await.unwrap();
    let parts = live_set(8);
    let pending = cut_epoch_build(&provider, &catalog, &parts).await;
    table(&provider, &pending).fail_seed_schema.store(true, Ordering::SeqCst);
    let error = catalog.sync_parts(T, parts.clone(), LIVE_NOW + 2, &MergePolicy::default()).await.unwrap_err();
    assert!(error.downcast_ref::<super::super::super::SeedSchemaMismatch>().is_some(), "{error:#}");
    assert!(provider.registry.lock().unwrap().is_none());
    assert!(retired(&provider).is_empty(), "old metadata stays fenced until a replacement is published");
    converge(&catalog, &parts, 8).await;
    let fresh = provider.registry.lock().unwrap().clone().unwrap();
    assert_ne!(fresh, format!("agent.{pending}_v1"));
    let trace = trace(&provider);
    let publish = trace.iter().position(|event| event == &format!("publish:{fresh}")).unwrap();
    let retire = trace.iter().position(|event| event == &format!("retire:{pending}")).unwrap();
    assert!(publish < retire, "{trace:?}");
    assert_eq!(table(&provider, &epoch(&fresh)).calls.load(Ordering::SeqCst), 0, "no part replay");
    assert_eq!(table(&provider, &epoch(&fresh)).seeds.load(Ordering::SeqCst), 1);
}
