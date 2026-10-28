// SPDX-License-Identifier: AGPL-3.0-or-later

//! Catalog custody shared by the lean writer, erasure and part GC. See
//! docs/architecture/agent-lane-catalog-lifecycle.md for the provider contract.
//! No provider endpoint, credential, TTL or maintenance attestation is guessed.

use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

use anyhow::{ensure, Context, Result};
use iceberg::Catalog;
use serde::{Deserialize, Serialize};

pub mod metadata;

use super::{
    hosted::{privacy_expiry_updates, HostedCatalogPolicy},
    manifest_digest, ExportTable, RestIcebergCommitter,
};
use crate::{
    iceberg::CatalogConfig,
    part_ingest::export::{plan_export_reconciled, ExportManifest, ExportState, IcebergCommitter},
    parts::{
        format::PartId,
        levels::MergePolicy,
        part_log::{LiveSet, PartRef},
    },
    rest_commit::CommitOutcome,
};

/// The gateway must durably close admission, drain reads and fence cached
/// results before acknowledging privacy. A successful catalog overwrite alone
/// says nothing about Basin's result cache. Implementations are tenant-bound.
/// No live Basin implementation is supplied until its cache behavior is proven.
#[async_trait::async_trait]
pub trait CatalogReadFence: Send + Sync {
    fn tenant_id(&self) -> &str;
    fn bucket(&self) -> &str;
    async fn close_and_drain(&self) -> Result<()>;
    async fn invalidate_results(&self) -> Result<()>;
    async fn reopen(&self) -> Result<()>;
}

/// Narrow catalog API seam. Tests replace network IO, not lifecycle ordering,
/// the durable planner, the erasure executor or the GC receipt check.
#[async_trait::async_trait]
pub trait CatalogLifecycleBackend: IcebergCommitter {
    /// Activation's fresh serving-table adapter snapshots the committed live
    /// set before a privacy fence. Existing backends perform no additional work.
    async fn prepare_sync(&self, _parts: &[PartRef], _now_ms: i64, _policy: &MergePolicy) -> Result<()> { Ok(()) }
    fn tenant_id(&self) -> &str;
    fn bucket(&self) -> &str;
    async fn verify_maintenance(&self) -> Result<()>;
    /// NAN-4627: the master table's export chain head, read from the remote
    /// catalog. `with_parts` also lists the current snapshot's parts. Never
    /// mutates the catalog.
    async fn export_head(&self, with_parts: bool) -> Result<super::ExportHead>;
    /// NAN-4662: `Ok(true)` only when the remote catalog itself shows that no
    /// table this backend owns has ever committed a snapshot, so no catalog
    /// metadata can reference any part. Never mutates the catalog. The
    /// default never proves it: GC then keeps the full catalog fence.
    async fn no_committed_snapshot(&self) -> Result<bool> {
        Ok(false)
    }
    async fn close_and_drain(&self) -> Result<()>;
    /// Rewrite manifests and expire historical snapshots. Return ALL part IDs
    /// still present in retained metadata, including deleted entries/bounds.
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>>;
    async fn invalidate_results(&self) -> Result<()>;
    async fn reopen(&self) -> Result<()>;
    /// Part GC never waits on this catalog: `vanished(part)` is true once a
    /// part holds a GC receipt (its files may be deleted). A backend with
    /// its own durable pending work must never commit such a part.
    fn set_vanished(&self, _vanished: Vanished) {}
    /// NAN-4721: the tenant's ingest-lag signal. Agent-catalog work yields
    /// to ingest while it is set (see [`crate::part_ingest::agent_lane`]).
    fn set_ingest_pressure(&self, _pressure: Arc<crate::part_ingest::agent_lane::IngestPressure>) {}
}

/// See [`CatalogLifecycleBackend::set_vanished`].
pub(crate) type Vanished = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Existing REST committer plus the provider's maintenance and reader controls.
/// Construct one per tenant contract. A caller cannot substitute a foreign
/// bucket, ambient credentials or a gateway fence belonging to another tenant.
pub struct RestLifecycleBackend {
    committer: RestIcebergCommitter,
    policy: Arc<dyn HostedCatalogPolicy>,
    readers: Arc<dyn CatalogReadFence>,
    bucket: String,
    metadata: Arc<metadata::MetadataGc>,
}

impl RestLifecycleBackend {
    pub(crate) fn with_platform_auth(
        mut self,
        client: Arc<crate::part_ingest::platform_tls::PlatformCatalogClient>,
        token: String,
        storage: Arc<dyn iceberg::io::StorageFactory>,
    ) -> Self {
        self.committer = self.committer.with_platform_auth(client, token, storage);
        self
    }
    pub fn new(
        config: CatalogConfig,
        table: ExportTable,
        target: Arc<super::hosted::HostedExportTarget>,
        policy: Arc<dyn HostedCatalogPolicy>,
        readers: Arc<dyn CatalogReadFence>,
        metadata: Arc<metadata::MetadataGc>,
    ) -> Result<Self> {
        let bucket = crate::lake_part_gc::request::tenant_bucket(&table.tenant_id);
        ensure!(
            readers.tenant_id() == table.tenant_id && readers.bucket() == bucket,
            "catalog reader fence belongs to another tenant"
        );
        ensure!(
            !config.vended_credentials && !config.s3_default_credentials,
            "catalog lifecycle refuses ambient credentials"
        );
        ensure!(
            table.data_prefix
                == format!(
                    "s3://{bucket}/{}/tenant={}/parts/",
                    crate::parts::format::PARTS_ROOT,
                    table.tenant_id
                ),
            "catalog lifecycle source belongs to another tenant"
        );
        ensure!(
            target.data_prefix() == table.data_prefix,
            "catalog lifecycle target differs"
        );
        let id = table
            .contract
            .table_ident(&table.namespace, &table.dataset)?;
        let traditional = format!(
            "s3://{bucket}/{}/{}/{}",
            crate::parts::format::iceberg_export_prefix(&table.tenant_id)?,
            table.namespace,
            id.name
        );
        // NAN-4614: this tenant's R2-managed platform prefix, or its legacy one
        // until the installation's writer rotation.
        let platform = |prefix: String| format!("s3://{bucket}/{prefix}{}", id.name);
        let current = platform(super::activation::platform_metadata_prefix(&table.tenant_id));
        let legacy = platform(super::activation::legacy_platform_metadata_prefix(&table.tenant_id));
        ensure!(
            table.location == traditional
                || table.namespace == "agent"
                    && (table.location == current || table.location == legacy),
            "catalog lifecycle metadata belongs to another bucket"
        );
        metadata.validate_binding(&table.tenant_id, &table.location)?;
        Ok(Self {
            committer: RestIcebergCommitter::new(config, table, target)?.for_lifecycle(),
            policy,
            readers,
            bucket,
            metadata,
        })
    }

    /// NAN-4615: every serving epoch (`events_<32 hex>`) the remote catalog
    /// still holds in this namespace, as dataset names. The catalog survives
    /// a cell roll that wipes the writer's local serving state, so this is
    /// how a wiped writer learns of epochs it must retire before any GC proof.
    /// Any unexpected table name fails closed.
    pub(crate) async fn list_serving_epochs(&self) -> Result<BTreeSet<String>> {
        let catalog = self
            .committer
            .load_catalog()
            .await
            .map_err(|_| anyhow::anyhow!("catalog epoch listing session unavailable"))?;
        let namespace = self.committer.table_id().namespace.clone();
        let tables = catalog
            .list_tables(&namespace)
            .await
            .map_err(|_| anyhow::anyhow!("catalog epoch listing unavailable"))?;
        ensure!(tables.len() <= 4096, "catalog epoch listing exceeds bound");
        let mut epochs = BTreeSet::new();
        for table in tables {
            ensure!(table.namespace == namespace, "catalog epoch listing crossed namespaces");
            if let Some(dataset) = serving_epoch_dataset(&table.name)? {
                epochs.insert(dataset);
            }
        }
        Ok(epochs)
    }

    /// Only the activation writer calls this, AFTER the coordinator has
    /// removed this serving name from its registry under a drained epoch.
    pub(crate) async fn retire_serving_table(&self) -> Result<()> {
        let catalog = self.committer.load_catalog().await?;
        let id = self.committer.table_id();
        if catalog.table_exists(id).await? {
            let table=catalog.load_table(id).await?;
            self.committer.table.contract.validate_identity(&table,&self.committer.table.tenant_id,&self.committer.table.location)?;
            catalog.drop_table(id).await?;
        }
        ensure!(!catalog.table_exists(id).await?,"retired serving table is still reachable");
        self.metadata.purge_dropped().await
    }
}

#[async_trait::async_trait]
impl IcebergCommitter for RestLifecycleBackend {
    async fn commit(&self, manifest: &ExportManifest) -> Result<()> {
        self.verify_maintenance().await?;
        self.committer.commit(manifest).await
    }
}

#[async_trait::async_trait]
impl CatalogLifecycleBackend for RestLifecycleBackend {
    fn tenant_id(&self) -> &str {
        &self.committer.table.tenant_id
    }
    fn bucket(&self) -> &str {
        &self.bucket
    }
    async fn verify_maintenance(&self) -> Result<()> {
        self.policy
            .verify_manual_maintenance(self.committer.table_id())
            .await
            .map_err(|_| anyhow::anyhow!("catalog automatic maintenance controls unavailable"))
    }
    async fn export_head(&self, with_parts: bool) -> Result<super::ExportHead> {
        let catalog = self
            .committer
            .load_catalog()
            .await
            .map_err(|_| anyhow::anyhow!("catalog export head session unavailable"))?;
        let id = self.committer.table_id();
        if !catalog
            .table_exists(id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog export head lookup unavailable"))?
        {
            return Ok(super::ExportHead::default());
        }
        let table = catalog
            .load_table(id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog export head table unavailable"))?;
        self.committer.table.contract.validate_table(
            &table,
            self.tenant_id(),
            &self.committer.table.location,
        )?;
        super::export_head_of(
            &table,
            &self.committer.table.data_prefix,
            self.committer.table.max_files,
            with_parts,
        )
        .await
    }
    /// NAN-4662: absent, or present (the broker creates it) with no snapshot.
    async fn no_committed_snapshot(&self) -> Result<bool> {
        let catalog = self
            .committer
            .load_catalog()
            .await
            .map_err(|_| anyhow::anyhow!("catalog commit-state session unavailable"))?;
        let id = self.committer.table_id();
        if !catalog
            .table_exists(id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog commit-state lookup unavailable"))?
        {
            return Ok(true);
        }
        let table = catalog
            .load_table(id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog commit-state table unavailable"))?;
        self.committer.table.contract.validate_table(
            &table,
            self.tenant_id(),
            &self.committer.table.location,
        )?;
        Ok(never_committed(&table))
    }
    async fn close_and_drain(&self) -> Result<()> {
        self.readers.close_and_drain().await
    }
    async fn invalidate_results(&self) -> Result<()> {
        self.readers.invalidate_results().await
    }
    async fn reopen(&self) -> Result<()> {
        self.readers.reopen().await
    }
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>> {
        self.verify_maintenance().await?;
        let catalog = self
            .committer
            .load_catalog()
            .await
            .map_err(|_| anyhow::anyhow!("catalog lifecycle session unavailable"))?;
        let id = self.committer.table_id();
        let table = catalog
            .load_table(id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog lifecycle table unavailable"))?;
        self.committer.table.contract.validate_table(
            &table,
            self.tenant_id(),
            &self.committer.table.location,
        )?;
        let (requirements, updates) = privacy_expiry_updates(&table)?;
        if !updates.is_empty() {
            let client = self
                .committer
                .commit_client()
                .await
                .map_err(|_| anyhow::anyhow!("catalog expiry session unavailable"))?;
            ensure!(
                matches!(
                    client.commit(requirements, updates).await,
                    Ok(CommitOutcome::Committed(_))
                ),
                "catalog expiry unacknowledged"
            );
        }
        let reloaded = catalog
            .load_table(id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog expiry reload unavailable"))?;
        ensure!(
            reloaded.metadata().uuid() == table.metadata().uuid()
                && reloaded.metadata().current_snapshot_id()
                    == table.metadata().current_snapshot_id()
                && reloaded
                    .metadata()
                    .snapshots()
                    .all(|s| Some(s.snapshot_id()) == reloaded.metadata().current_snapshot_id()),
            "catalog expiry not observed"
        );
        let retained =
            metadata::retained_metadata(&reloaded, self.committer.table.max_files).await?;
        self.metadata
            .purge(
                reloaded.metadata().uuid(),
                reloaded
                    .metadata_location()
                    .context("catalog metadata location missing")?,
                &retained,
            )
            .await?;
        metadata_parts(
            &reloaded,
            &self.committer.table.data_prefix,
            self.committer.table.max_files,
        )
        .await
    }
}

/// NAN-4662: a table no export ever committed to: no current snapshot and no
/// snapshot in its metadata, so no manifest (live or deleted entry) exists.
pub(crate) fn never_committed(table: &iceberg::table::Table) -> bool {
    table.metadata().current_snapshot_id().is_none() && table.metadata().snapshots().len() == 0
}

/// `events_v1` (the private master) is not an epoch; `events_<32 hex>_v1` is.
/// Anything else in the serving namespace is refused (NAN-4615).
pub(crate) fn serving_epoch_dataset(table: &str) -> Result<Option<String>> {
    if table == "events_v1" {
        return Ok(None);
    }
    let hex = table
        .strip_prefix("events_")
        .and_then(|rest| rest.strip_suffix("_v1"))
        .filter(|hex| hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    match hex {
        Some(hex) => Ok(Some(format!("events_{hex}"))),
        None => anyhow::bail!("unexpected table in the serving catalog namespace"),
    }
}

/// Inspect tombstones too: their min/max bounds may contain erased values even
/// though no query considers the entry live. Never use a current-files-only
/// reachability check as privacy evidence.
pub(super) async fn metadata_parts(
    table: &iceberg::table::Table,
    prefix: &str,
    bound: usize,
) -> Result<BTreeSet<String>> {
    ensure!(
        bound > 0 && bound <= 1_000_000,
        "invalid catalog inspection bound"
    );
    let mut parts = BTreeSet::new();
    let mut inspected = 0usize;
    ensure!(
        table.metadata().snapshots().len() <= 1024,
        "catalog snapshot bound exceeded"
    );
    for snapshot in table.metadata().snapshots() {
        super::hosted::check_metadata_path(table, snapshot.manifest_list())?;
        let list = table.manifest_list_reader(snapshot).load().await?;
        ensure!(
            list.entries().len() <= bound,
            "catalog manifest bound exceeded"
        );
        for descriptor in list.entries() {
            super::hosted::check_metadata_path(table, &descriptor.manifest_path)?;
            ensure!(
                descriptor.content == iceberg::spec::ManifestContentType::Data
                    && descriptor.partition_spec_id == 0,
                "unsupported catalog manifest"
            );
            let manifest = descriptor.load_manifest(table.file_io()).await?;
            inspected = inspected
                .checked_add(manifest.entries().len())
                .context("catalog entry overflow")?;
            ensure!(inspected <= bound, "catalog entry bound exceeded");
            for entry in manifest.entries() {
                parts.insert(super::part_id_from_path(entry.file_path(), prefix)?.to_string());
            }
        }
    }
    Ok(parts)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogRemovedReceipt {
    pub tenant_id: String,
    pub bucket: String,
    pub part_id: String,
    pub manifest_sha256: String,
}

/// The catalog still references this one part; other parts of the pass may
/// proceed. Refused per key, never a pass-wide stop (NAN-4612).
#[derive(Debug, thiserror::Error)]
#[error("catalog metadata still pins part")]
struct CatalogPinsPart;

/// NAN-4662: this one part cannot be proven unreferenced this pass (its
/// catalog inspection failed, or an uncommitted plan names it). Like
/// [`CatalogPinsPart`] it holds only this key: parts the existing proofs
/// clear (never planned, or no committed snapshot) still proceed.
#[derive(Debug, thiserror::Error)]
#[error("catalog cannot prove part unreferenced: {0}")]
struct CatalogPartUnproven(String);

/// Written by a reconciled sync once the planned index covers every part the
/// remote catalog references.
const PLANNED_INDEX_READY: &str = "planned-index-ready";

/// NAN-4715: how long `TenantCatalog::new` waits for a contended writer lease.
const WRITER_LEASE_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The writer lease is an `flock` on `writer.lock`, which belongs to the open
/// file description. The fd is O_CLOEXEC, but a child forked by any other
/// thread (a subprocess spawn) shares that description until its exec, so a
/// lease dropped and re-taken inside that window still reads as held. Every
/// production restart can race a dying writer the same way. A contended lease
/// is retried within `wait`; a second live writer is still refused.
fn acquire_writer_lease(lease: &std::fs::File, wait: std::time::Duration) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        match fs2::FileExt::try_lock_exclusive(lease) {
            Ok(()) => return Ok(()),
            Err(error)
                if error.kind() == fs2::lock_contended_error().kind()
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
#[test]
fn a_writer_lease_released_within_the_wait_is_acquired_and_a_live_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let open = || std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true)
        .open(dir.path().join("writer.lock")).unwrap();
    // A shared open file description (what a forked, not yet exec'd child
    // holds) that goes away shortly.
    let holder = open();
    fs2::FileExt::try_lock_exclusive(&holder).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(holder);
    });
    acquire_writer_lease(&open(), std::time::Duration::from_secs(5)).unwrap();
    release.join().unwrap();
    // A live second writer: refused once the wait is spent.
    // Taken through the lease wait too: the lease just dropped above can be
    // shared for a moment by another test's forked child (the NAN-4715 window).
    let held = open();
    acquire_writer_lease(&held, std::time::Duration::from_secs(5)).unwrap();
    let started = std::time::Instant::now();
    assert!(acquire_writer_lease(&open(), std::time::Duration::from_millis(100)).is_err());
    assert!(started.elapsed() >= std::time::Duration::from_millis(100));
}

/// The strict catalog inspection a GC fence may run, inside its 120 s bound.
const INSPECTION_BOUND: std::time::Duration = std::time::Duration::from_secs(60);

fn degraded_evidence(tenant: &str, bucket: &str, part: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&(tenant, bucket, part, "agent-lane-degraded"))?)
}

/// The receipt digest of a part GC receipted with the agent lane degraded.
#[cfg(test)]
pub(crate) fn degraded_receipt_sha256(tenant: &str, part: &str) -> String {
    let bucket = crate::lake_part_gc::request::tenant_bucket(tenant);
    crate::parts::sha256_hex(&degraded_evidence(tenant, &bucket, part).expect("evidence"))
}

/// Written when part GC receipted a part the strict proofs could not clear
/// (the agent lane degraded). Reads stay closed until a converged sync.
const GC_DEGRADED: &str = "gc-degraded";

/// Owned by the single tenant writer; keep this directory with the existing
/// durable export state. Pending manifests survive every failed provider step.
/// The provider barrier survives loss of the writer's local state as well.
pub struct TenantCatalog {
    tenant: String,
    bucket: String,
    work_dir: PathBuf,
    backend: Arc<dyn CatalogLifecycleBackend>,
    lock: tokio::sync::Mutex<CustodyState>,
    limits: SyncLimits,
    /// The live set of the writer's latest sync (in memory). A degraded
    /// receipt is never minted for a live part: that is a liveness check
    /// (GC asking for live data is a bug elsewhere), not a catalog gate.
    live: std::sync::Mutex<Option<BTreeSet<String>>>,
    /// NAN-4721: set by the ingest loop from its lag alert; the backend's
    /// agent-catalog work yields while it is set.
    pressure: Arc<crate::part_ingest::agent_lane::IngestPressure>,
    _lease: std::fs::File,
}

/// NAN-4614: how much one catalog sync does. The sync budget and the
/// per-commit attempt bound are separate: a sync starts no new batch once
/// `batch_budget` is spent (one batch always runs), and every commit keeps
/// its own bounded attempts (`super::attempt_timeout`). `hard_bound` is only
/// the hang net around the whole sync, above one budget plus one commit.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SyncLimits {
    pub batch_budget: std::time::Duration,
    pub hard_bound: std::time::Duration,
    pub batch: crate::part_ingest::export::ExportBatchBounds,
}

impl SyncLimits {
    pub(crate) const DEFAULT: Self = Self {
        // The lock-hold profile of the old whole-sync bound: a GC pass that
        // waits on custody (120 s) sees the same contention as before.
        batch_budget: std::time::Duration::from_secs(120),
        hard_bound: std::time::Duration::from_secs(30 * 60),
        batch: crate::part_ingest::export::ExportBatchBounds::DEFAULT,
    };
}

/// NAN-4614: the sync committed `committed` batches and stopped at its
/// budget with `remaining` durable batches still to publish. Not a failure:
/// the next sync resumes at the first uncommitted batch. Custody (read
/// barrier, GC fence) stays exactly as for any unconverged sync.
#[derive(Debug, thiserror::Error)]
#[error("catalog sync budget spent after {committed} batches; {remaining} durable batches resume next sync")]
pub struct CatalogSyncIncomplete {
    pub committed: usize,
    pub remaining: usize,
}

#[derive(Default)]
struct CustodyState {
    last_success: Option<i64>,
    generation: u64,
}

/// One instance per sanctioned GC pass. A failed inspection is cached too;
/// retry belongs to the next pass, never to each physical file.
#[derive(Default)]
pub(crate) struct CatalogGcPass {
    proof: std::sync::OnceLock<std::result::Result<RetirementProof, String>>,
    attempted: std::sync::atomic::AtomicBool,
    /// Result-cache invalidation runs once per pass, and only once a part is
    /// actually about to be retired: a pass whose parts are all pinned leaves
    /// the reader cache intact (NAN-4636). Cached like the proof, failure too.
    invalidated: std::sync::OnceLock<std::result::Result<(), String>>,
    invalidate_attempted: std::sync::atomic::AtomicBool,
    /// NAN-4662: the last commit-state read of this pass, taken only when
    /// the existing proofs cannot clear a part, and re-read when a writer
    /// sync moved the custody generation (the large tenant retries its failing sync every
    /// ~90 s, so voiding the pass instead would starve GC).
    uncommitted: std::sync::Mutex<Option<UncommittedRead>>,
    uncommitted_reads: std::sync::atomic::AtomicU32,
    uncommitted_inflight: std::sync::atomic::AtomicBool,
    /// The degraded-lane read fence runs once per pass.
    degraded_close: std::sync::atomic::AtomicBool,
}
/// Bound on commit-state reads per GC pass; past it the fence holds.
const UNCOMMITTED_READS_PER_PASS: u32 = 64;
/// One commit-state read at one custody generation. `named: None` = not
/// proven (committed, unreadable). `Some`: the remote catalog holds no
/// committed snapshot, and these are the parts an uncommitted local plan
/// (pending or superseded) mentions: an ambiguous commit of one of those may
/// still land, so they stay held.
struct UncommittedRead {
    generation: u64,
    named: Option<BTreeSet<String>>,
}
struct RetirementProof {
    tenant: String,
    generation: u64,
    referenced: BTreeSet<String>,
}

/// Aborting a writer also cancels its catalog flight. Provider barriers and
/// pending manifests deliberately survive cancellation.
pub(crate) struct CatalogFlight {
    pub head: u64,
    pub handle: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for CatalogFlight {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl std::fmt::Debug for TenantCatalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantCatalog")
            .field("tenant", &self.tenant)
            .finish_non_exhaustive()
    }
}

impl TenantCatalog {
    pub fn new(
        tenant: &str,
        work_dir: PathBuf,
        backend: Arc<dyn CatalogLifecycleBackend>,
    ) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(tenant)?;
        let bucket = crate::lake_part_gc::request::tenant_bucket(tenant);
        ensure!(
            backend.tenant_id() == tenant && backend.bucket() == bucket,
            "catalog backend belongs to another tenant"
        );
        std::fs::create_dir_all(&work_dir)?;
        let lease = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(work_dir.join("writer.lock"))?;
        acquire_writer_lease(&lease, WRITER_LEASE_WAIT).context("catalog writer already held")?;
        let service = Self {
            tenant: tenant.into(),
            bucket,
            work_dir,
            backend,
            lock: tokio::sync::Mutex::new(CustodyState::default()),
            limits: SyncLimits::DEFAULT,
            live: std::sync::Mutex::new(None),
            pressure: Arc::default(),
            _lease: lease,
        };
        service.backend.set_ingest_pressure(service.pressure.clone());
        service.recover_planned_index()?;
        let receipts = service.work_dir.join("catalog-removed");
        service.backend.set_vanished(Arc::new(move |part: &str| {
            PartId::parse(part).is_err() || receipts.join(format!("{part}.json")).try_exists().unwrap_or(true)
        }));
        Ok(service)
    }

    /// NAN-4721: the ingest loop reports its lag alert here every health
    /// update; agent-catalog work yields while it is set.
    pub fn ingest_pressure(&self) -> &crate::part_ingest::agent_lane::IngestPressure {
        &self.pressure
    }

    /// Tests shrink the batch and budget to drive multi-pass convergence
    /// through this production service.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: SyncLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The writer scheduler must bypass its own hourly debounce too. An IO
    /// error is conservatively recovery-required; sync reports the actual error.
    pub(crate) fn recovery_required(&self) -> bool {
        self.work_dir
            .join("reads-closed")
            .try_exists()
            .unwrap_or(true)
    }

    pub fn validate_tenant(&self, tenant: &str) -> Result<()> {
        ensure!(tenant == self.tenant, "cross-tenant catalog access refused");
        Ok(())
    }

    /// Called with the writer's committed part-log view. There is no object
    /// listing and no caller-supplied source coordinates. Empty erased hours
    /// reconcile through the same durable planner as ordinary seals.
    pub async fn sync(
        &self,
        tenant: &str,
        live: &LiveSet,
        now_ms: i64,
        policy: &MergePolicy,
    ) -> Result<()> {
        self.sync_parts(tenant, live.parts().cloned().collect(), now_ms, policy)
            .await
    }

    pub(crate) async fn sync_parts(
        &self,
        tenant: &str,
        mut refs: Vec<PartRef>,
        now_ms: i64,
        policy: &MergePolicy,
    ) -> Result<()> {
        self.validate_tenant(tenant)?;
        refs.retain(|p| {
            matches!(
                p.level,
                crate::parts::levels::Level::Hour | crate::parts::levels::Level::Day
            )
        });
        // A receipted part may already be deleted by part GC (which never
        // waits on this catalog): it must never (re)enter the catalog, and
        // the plan below removes it wherever the catalog still holds it.
        // Fail closed by error, never by dropping: an unreadable receipt
        // store must not silently empty the agent catalog of live parts.
        let mut kept = Vec::with_capacity(refs.len());
        for part in refs {
            if !self.receipt_path(part.part_id.as_str())?.try_exists()? {
                kept.push(part);
            }
        }
        let refs = kept;
        *self.live.lock().map_err(|_| anyhow::anyhow!("catalog live set poisoned"))? =
            Some(refs.iter().map(|p| p.part_id.to_string()).collect());
        let started = std::time::Instant::now();
        tokio::time::timeout(self.limits.hard_bound, async {
            let mut custody = self.lock.lock().await;
            let mut state = ExportState::load_durable(&self.work_dir)?;
            let mut plans = self.pending()?;
            let mut pending = plan_export_reconciled(&refs, &state, now_ms, policy);
            let desired = refs.iter().map(|p| p.part_id.as_str()).collect::<BTreeSet<_>>();
            self.backend.prepare_sync(&refs, now_ms, policy).await?;
            let closed = self.work_dir.join("reads-closed").try_exists()?;
            if !closed && plans.is_empty() && pending.is_empty()
                && custody.last_success.is_some_and(|at| now_ms >= at && now_ms - at < 3_600_000) {
                return Ok(());
            }
            // NAN-4627: before any plan, publish or GC proof, the local chain
            // must continue the remote checkpoint. A cell roll wipes
            // export/state.json; a restore can leave it behind the catalog.
            if let Some(rebuilt) = self.reconcile_export_state(&state, &plans, &refs, now_ms, policy).await? {
                state = rebuilt;
                plans = self.pending()?;
                pending = plan_export_reconciled(&refs, &state, now_ms, policy);
            }
            custody.generation = custody.generation.checked_add(1).context("catalog generation overflow")?;
            let mut privacy = closed || !self.work_dir.join(PLANNED_INDEX_READY).try_exists()? || pending.iter().any(|(hour, _)| {
                state.exported.get(&hour.event_hour).is_some_and(|old| old.iter().any(|p| !hour.parts.contains(p)))
            });
            for path in &plans {
                let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                privacy |= !manifest.remove_parts.is_empty() || manifest.add.iter().any(|p| !desired.contains(p.part_id.as_str()));
            }
            // NAN-4614: removals committed by an earlier sync's non-final
            // batch and not yet settled; this sync's last batch settles them.
            let mut removed = self.unsettled()?;
            privacy |= !removed.is_empty();
            if privacy { self.close().await?; }
            self.backend.verify_maintenance().await?;
            let plans = self.rebatch_backlog_head(plans).await?;
            tracing::info!(stage = "reconciled", backlog = plans.len(), hours = pending.len(), privacy,
                elapsed_ms = started.elapsed().as_millis() as u64, "catalog sync stage");
            // NAN-4614: the backlog of durable batches first, oldest first.
            // Every batch commits (and checkpoints) on its own; once the
            // budget is spent no further batch starts, and the next sync
            // resumes at the first uncommitted one. Only the sync's last
            // batch settles (expire, inspect, invalidate, removal receipts),
            // for every removal committed before it in this sync: a serving
            // epoch is built from the live set, which only the whole chain
            // reaches.
            let mut published = 0usize;
            let backlog = plans.len();
            for (index, path) in plans.iter().enumerate() {
                if published > 0 && started.elapsed() >= self.limits.batch_budget {
                    return Err(CatalogSyncIncomplete { committed: published, remaining: backlog - index }.into());
                }
                self.publish(path, privacy, index + 1 == backlog && pending.is_empty(), &mut removed).await?;
                published += 1;
            }
            if !pending.is_empty() {
                let at = now_ms.max(state.last_plan_ms.checked_add(1).context("catalog clock overflow")?);
                // Membership must reach disk BEFORE a plan can reach disk or
                // the provider (including an ambiguous commit response).
                for (_, parts) in &pending { for part in parts { self.remember(part.part_id.as_str())?; } }
                let batches = state.split_plan(tenant, &pending, self.limits.batch)?;
                let paths = state.record_durable_batches(&self.work_dir, batches, at)?;
                tracing::info!(stage = "planned", batches = paths.len(), hours = pending.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64, "catalog sync stage");
                for (index, path) in paths.iter().enumerate() {
                    if published > 0 && started.elapsed() >= self.limits.batch_budget {
                        return Err(CatalogSyncIncomplete { committed: published, remaining: paths.len() - index }.into());
                    }
                    self.publish(path, privacy, index + 1 == paths.len(), &mut removed).await?;
                    published += 1;
                }
            }
            tracing::info!(stage = "published", batches = published,
                elapsed_ms = started.elapsed().as_millis() as u64, "catalog sync stage");
            let remaining = self.backend.expire_and_inspect().await?;
            if !remaining.iter().all(|p| desired.contains(p.as_str())) {
                self.close().await?;
                anyhow::bail!("catalog contains parts outside the committed live set; recover durable custody");
            }
            if !removed.is_empty() {
                // Unsettled removals with no batch left to settle them (the
                // chain was rebuilt from the catalog): settle here.
                ensure!(removed.iter().all(|(part, _)| !remaining.contains(part)), "catalog still exposes removed part metadata");
                // Unsettled removals force privacy above; never receipt one
                // without the closed read fence and fresh serving name.
                ensure!(privacy, "catalog removal requires read barrier");
                self.backend.invalidate_results().await?;
                self.settle_removed(&mut removed)?;
            }
            for part in remaining { self.remember(&part)?; }
            if privacy {
                // Also repairs a previous retirement/cache failure with no
                // outstanding manifest, even inside the hourly debounce.
                self.backend.invalidate_results().await?;
                self.reopen().await?;
            }
            self.write_marker(PLANNED_INDEX_READY, self.tenant.as_bytes())?;
            if self.work_dir.join(GC_DEGRADED).try_exists()? {
                // The lane degraded by part GC is whole again: this sync
                // removed every receipted part and (privacy) published a
                // fresh epoch before reopening reads.
                std::fs::remove_file(self.work_dir.join(GC_DEGRADED))?;
                tracing::info!("agent catalog converged after part GC degraded the lane");
            }
            custody.last_success = Some(now_ms);
            tracing::info!(stage = "converged", elapsed_ms = started.elapsed().as_millis() as u64, "catalog sync stage");
            Ok(())
        })
        .await
        .context("catalog sync timed out; read barrier and pending plans retained")?
    }

    /// NAN-4627: compare the local export chain with the remote checkpoint.
    /// Consistent (the checkpoint is the chain's base or one of its pending
    /// plans): nothing to do. Remote ahead (a wiped or restored volume):
    /// rebuild `ExportState` from the catalog's current snapshot, with the
    /// remote checkpoint as the only predecessor, and set aside pending plans
    /// that can never commit on top of it. Remote behind: fail closed.
    /// Every step is idempotent, so a restart mid-rebuild simply repeats it.
    async fn reconcile_export_state(
        &self,
        state: &ExportState,
        plans: &[PathBuf],
        refs: &[PartRef],
        now_ms: i64,
        policy: &MergePolicy,
    ) -> Result<Option<ExportState>> {
        let mut base = state.last_plan_ms;
        let mut chain = Vec::with_capacity(plans.len());
        for (index, path) in plans.iter().enumerate() {
            let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
            if index == 0 {
                base = manifest.previous_plan_ms.unwrap_or(0);
            }
            chain.push(manifest.planned_at_ms);
        }
        let remote = self.backend.export_head(false).await?.checkpoint.unwrap_or(0);
        // A pending plan that adds a part part GC may already have deleted
        // can never commit (its data is gone): set the plans aside and
        // rebuild from the catalog like a wiped volume.
        let mut vanished = false;
        for path in plans {
            let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
            vanished |= manifest.add.iter().any(|p| self.receipted(&p.part_id));
        }
        if (remote == base || chain.contains(&remote)) && !vanished {
            return Ok(None);
        }
        // A restart after the supersede step but before the rebuilt state
        // landed leaves state.json (or the first remaining plan) chained on a
        // plan that was set aside and never committed. Walk back through
        // superseded plans to the last base this writer really built on.
        let base = self.unsuperseded_base(base)?;
        if remote < base {
            return Err(super::ExportStateUnrecoverable {
                reason: "remote export checkpoint is behind the local export chain",
            }
            .into());
        }
        tracing::warn!(
            remote,
            local = base,
            superseded = plans.len(),
            "catalog export state is behind the remote checkpoint; rebuilding it from the catalog"
        );
        let head = self.backend.export_head(true).await?;
        ensure!(
            head.checkpoint == Some(remote),
            "catalog export checkpoint moved during rebuild; retry"
        );
        // Live parts the catalog already holds map to exactly the hours the
        // planner would give them; anything else the catalog holds (erased or
        // merged away while the state was lost) stays under its key hour so
        // the next plan removes it.
        let present = refs
            .iter()
            .filter(|p| head.parts.contains_key(p.part_id.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let mut exported = std::collections::BTreeMap::new();
        for (hour, _) in plan_export_reconciled(&present, &ExportState::default(), now_ms, policy) {
            exported.insert(hour.event_hour, hour.parts);
        }
        let mapped = exported.values().flatten().cloned().collect::<BTreeSet<_>>();
        for (part, hour) in &head.parts {
            if !mapped.contains(part) {
                let parts: &mut Vec<String> = exported.entry(*hour).or_default();
                parts.push(part.clone());
                parts.sort();
            }
        }
        // Membership reaches disk before the rebuilt state can.
        for part in head.parts.keys() {
            self.remember(part)?;
        }
        // Set stale plans aside BEFORE the new state lands: a pending plan
        // newer than the rebuilt head would otherwise fail load_durable.
        if !plans.is_empty() {
            let superseded = self.work_dir.join("export/superseded");
            std::fs::create_dir_all(&superseded)?;
            for path in plans {
                std::fs::rename(
                    path,
                    superseded.join(path.file_name().context("catalog manifest name missing")?),
                )?;
            }
            std::fs::File::open(&superseded)?.sync_all()?;
            std::fs::File::open(self.work_dir.join("export/pending"))?.sync_all()?;
        }
        let rebuilt = ExportState { exported, last_plan_ms: remote };
        rebuilt.persist_durable(&self.work_dir)?;
        Ok(Some(rebuilt))
    }

    /// The predecessor a superseded (never committed) plan chained on, walked
    /// back until `base` is not a superseded plan. Superseded plans only ever
    /// leave `export/pending` together with the rebuild that replaces them,
    /// so this can lower the local base but never invent a newer one.
    fn unsuperseded_base(&self, mut base: i64) -> Result<i64> {
        let directory = self.work_dir.join("export/superseded");
        for _ in 0..=1024 {
            let path = directory.join(format!("{base:013}.json"));
            if base <= 0 || !path.try_exists()? {
                return Ok(base);
            }
            let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(&path)?)?;
            ensure!(
                manifest.tenant_id == self.tenant && manifest.planned_at_ms == base,
                "superseded export manifest mismatch"
            );
            let previous = manifest.previous_plan_ms.unwrap_or(0);
            ensure!(previous < base, "superseded export chain does not descend");
            base = previous;
        }
        anyhow::bail!("superseded export chain bound exceeded")
    }

    /// NAN-4614: a pending manifest too large for one bounded commit (one a
    /// pre-batching writer recorded: the large tenant's whole live set) would never land.
    /// While it is the uncommitted head of the chain (the remote checkpoint
    /// is still its predecessor, read under the custody lock that every
    /// commit of this tenant holds), it is replaced by its batches, chained
    /// to END at its own time: the durable state and every later plan keep
    /// their predecessor. The earlier batches are written first and the head
    /// is replaced last. A crash in between leaves stray batches that claim
    /// the head's predecessor next to the original head; they are removed
    /// (never published: this runs before any publish) and written again.
    async fn rebatch_backlog_head(&self, mut plans: Vec<PathBuf>) -> Result<Vec<PathBuf>> {
        if plans.is_empty() {
            return Ok(plans);
        }
        let read = |path: &PathBuf| -> Result<ExportManifest> { Ok(serde_json::from_slice(&std::fs::read(path)?)?) };
        let first = read(&plans[0])?;
        let mut head_index = 0;
        for (index, path) in plans.iter().enumerate().skip(1) {
            if read(path)?.previous_plan_ms == first.previous_plan_ms {
                head_index = index;
            }
        }
        let head = read(&plans[head_index])?;
        let batches = crate::part_ingest::export::split_manifest(head.clone(), self.limits.batch)?;
        let count = i64::try_from(batches.len()).context("catalog batch count overflow")?;
        let floor = head.previous_plan_ms.unwrap_or(0);
        if (count <= 1 && head_index == 0) || head.planned_at_ms - (count - 1) <= floor
            // The durable state must already name the head: then a crash here
            // can never leave `load_durable` a chain it cannot recover.
            || ExportState::load(&self.work_dir)?.last_plan_ms < head.planned_at_ms
        {
            return Ok(plans);
        }
        if self.backend.export_head(false).await?.checkpoint != head.previous_plan_ms {
            // Possibly committed already (an ambiguous response): replay as is.
            return Ok(plans);
        }
        for stray in plans.drain(..head_index) {
            ensure!(
                read(&stray)?.planned_at_ms > floor,
                "catalog stray batch outside its head's range"
            );
            std::fs::remove_file(&stray)?;
        }
        let head_path = plans.remove(0);
        let directory = head_path.parent().context("catalog manifest parent missing")?.to_path_buf();
        std::fs::File::open(&directory)?.sync_all()?;
        let start = head.planned_at_ms - (count - 1);
        let mut paths = Vec::with_capacity(plans.len() + batches.len());
        let mut previous = head.previous_plan_ms;
        for (index, mut batch) in batches.into_iter().enumerate() {
            let at = start + index as i64;
            batch.planned_at_ms = at;
            batch.previous_plan_ms = previous;
            previous = Some(at);
            super::validate_manifest(&batch, &self.tenant, 100_000)?;
            let path = directory.join(format!("{at:013}.json"));
            // Immutable for a new batch; the head is replaced in place.
            super::super::export::atomic_write(&path, &serde_json::to_vec_pretty(&batch)?, at < head.planned_at_ms)?;
            paths.push(path);
        }
        tracing::warn!(batches = paths.len(), parts = head.add.len(),
            "catalog backlog head exceeds one bounded commit; replaced by its batches");
        paths.extend(plans);
        Ok(paths)
    }

    fn pending(&self) -> Result<Vec<PathBuf>> {
        let dir = self.work_dir.join("export/pending");
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut paths = std::fs::read_dir(dir)?
            .map(|e| e.map(|e| e.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.retain(|p| p.extension().is_some_and(|e| e == "json"));
        paths.sort();
        ensure!(paths.len() <= 1024, "catalog pending bound exceeded");
        Ok(paths)
    }

    /// `last`: no further batch of this sync follows. Any other batch only
    /// commits and is acknowledged; its removals are first recorded durably
    /// in `export/unsettled` (and join `removed`), and are settled (proved
    /// unreferenced, results invalidated, receipted) by the last batch of
    /// this or a later sync (NAN-4614). Settling part way would build a
    /// pending serving epoch from a live set the master has not reached,
    /// which is refused on every replay.
    async fn publish(
        &self,
        path: &std::path::Path,
        privacy: bool,
        last: bool,
        removed: &mut Vec<(String, String)>,
    ) -> Result<()> {
        let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
        super::validate_manifest(&manifest, &self.tenant, 100_000)?;
        ensure!(
            manifest.add.iter().all(|p| !self
                .receipt_path(&p.part_id)
                .is_ok_and(|path| path.exists())),
            "catalog publication would resurrect a retired part"
        );
        ensure!(
            privacy || manifest.remove_parts.is_empty(),
            "catalog removal requires read barrier"
        );
        self.backend.verify_maintenance().await?;
        self.backend.commit(&manifest).await?;
        let digest = manifest_digest(&manifest)?;
        let batch = manifest.remove_parts.iter().map(|part| (part.clone(), digest.clone())).collect::<Vec<_>>();
        if !last {
            if !batch.is_empty() {
                // Durable BEFORE the acknowledgment drops the manifest.
                let directory = self.work_dir.join("export/unsettled");
                std::fs::create_dir_all(&directory)?;
                super::super::export::atomic_write(
                    &directory.join(format!("{:013}.json", manifest.planned_at_ms)),
                    &serde_json::to_vec(&batch)?,
                    false,
                )?;
            }
            removed.extend(batch);
            return self.acknowledge(path);
        }
        removed.extend(batch);
        let referenced = self.backend.expire_and_inspect().await?;
        ensure!(
            removed.iter().all(|(part, _)| !referenced.contains(part)),
            "catalog still exposes removed part metadata"
        );
        // NAN-4734: the result-cache fence belongs to the privacy path only.
        // Under privacy the reads are closed and `expire_and_inspect` has
        // just published a fresh serving name, so invalidation proves no old
        // name can answer again. An add-only pass removes nothing: there is
        // no removed row a cache could leak, and the platform refuses
        // `invalidate_results` outside a closed privacy window (no fresh
        // serving proof once `writer_reopen` ended it), which wedged every
        // later sync. Removals always force privacy (see `sync_parts`), so
        // no receipt can be issued here without the fence.
        if privacy {
            self.backend.invalidate_results().await?;
        } else {
            ensure!(removed.is_empty(), "catalog removal requires read barrier");
        }
        self.settle_removed(removed)?;
        self.acknowledge(path)
    }

    /// Removals committed by acknowledged non-final batches, not yet settled.
    fn unsettled(&self) -> Result<Vec<(String, String)>> {
        let mut removed = Vec::new();
        let mut paths = self.manifests("unsettled")?;
        paths.sort();
        ensure!(paths.len() <= 1024, "catalog unsettled bound exceeded");
        for path in paths {
            let batch: Vec<(String, String)> = serde_json::from_slice(&std::fs::read(path)?)?;
            for (part, _) in &batch {
                self.receipt_path(part)?;
            }
            removed.extend(batch);
        }
        Ok(removed)
    }

    /// Receipt every settled removal (proved unreferenced, results
    /// invalidated), then forget the durable unsettled records.
    fn settle_removed(&self, removed: &mut Vec<(String, String)>) -> Result<()> {
        for (part, manifest_sha256) in removed.drain(..) {
            if self.receipt_path(&part)?.exists() {
                continue; // Settled by an earlier attempt.
            }
            let receipt = CatalogRemovedReceipt {
                tenant_id: self.tenant.clone(),
                bucket: self.bucket.clone(),
                part_id: part,
                manifest_sha256,
            };
            self.record_receipt(&receipt)?;
        }
        let directory = self.work_dir.join("export/unsettled");
        let paths = self.manifests("unsettled")?;
        for path in &paths {
            std::fs::remove_file(path)?;
        }
        if !paths.is_empty() {
            std::fs::File::open(&directory)?.sync_all()?;
        }
        Ok(())
    }

    /// Move a committed manifest out of `export/pending`, durably.
    fn acknowledge(&self, path: &std::path::Path) -> Result<()> {
        let committed = self.work_dir.join("export/committed");
        std::fs::create_dir_all(&committed)?;
        std::fs::rename(
            path,
            committed.join(path.file_name().context("catalog manifest name missing")?),
        )?;
        std::fs::File::open(committed)?.sync_all()?;
        std::fs::File::open(path.parent().context("catalog manifest parent missing")?)?
            .sync_all()?;
        Ok(())
    }

    /// Receipted for part GC: its files may be gone. Unreadable means yes.
    fn receipted(&self, part: &str) -> bool {
        self.receipt_path(part).map_or(true, |path| path.try_exists().unwrap_or(true))
    }

    fn receipt_path(&self, part: &str) -> Result<PathBuf> {
        ensure!(part.is_ascii(), "invalid catalog part ID");
        PartId::parse(part)?;
        Ok(self
            .work_dir
            .join("catalog-removed")
            .join(format!("{part}.json")))
    }

    fn record_receipt(&self, receipt: &CatalogRemovedReceipt) -> Result<()> {
        let path = self.receipt_path(&receipt.part_id)?;
        std::fs::create_dir_all(path.parent().context("catalog receipt directory missing")?)?;
        if path.exists() {
            ensure!(
                self.require_removed(&self.tenant, &receipt.part_id)? == *receipt,
                "catalog removal receipt collision"
            );
        } else {
            super::super::export::atomic_write(&path, &serde_json::to_vec(receipt)?, true)?;
        }
        Ok(())
    }

    fn write_marker(&self, name: &str, bytes: &[u8]) -> Result<()> {
        super::super::export::atomic_write(&self.work_dir.join(name), bytes, false)
    }

    pub(crate) async fn fence_installation(&self) -> Result<()> {
        let _guard=self.lock.lock().await;self.close().await
    }

    async fn close(&self) -> Result<()> {
        // Persist first: cancellation, failed provider calls and restart all
        // force recovery instead of taking the recent-success fast path.
        self.write_marker("reads-closed", self.tenant.as_bytes())?;
        self.backend.close_and_drain().await
    }
    async fn reopen(&self) -> Result<()> {
        self.backend.reopen().await?;
        std::fs::remove_file(self.work_dir.join("reads-closed"))?;
        std::fs::File::open(&self.work_dir)?.sync_all()?;
        Ok(())
    }
    fn planned_path(&self, part: &str) -> Result<PathBuf> {
        self.receipt_path(part)?;
        Ok(self
            .work_dir
            .join("ever-planned")
            .join(format!("{part}.json")))
    }
    fn remember(&self, part: &str) -> Result<()> {
        let path = self.planned_path(part)?;
        std::fs::create_dir_all(path.parent().context("planned index directory missing")?)?;
        let bytes = serde_json::to_vec(&(&self.tenant, &self.bucket, part))?;
        if path.exists() {
            ensure!(
                std::fs::read(path)? == bytes,
                "planned index identity differs"
            );
        } else {
            super::super::export::atomic_write(&path, &bytes, true)?;
        }
        Ok(())
    }
    fn recover_planned_index(&self) -> Result<()> {
        // Upgrade existing custody without forgetting historical removals.
        // These files and the index must never be pruned by the legacy pruner.
        for name in ["pending", "committed", "superseded"] {
            let directory = self.work_dir.join("export").join(name);
            if !directory.exists() {
                continue;
            }
            for entry in std::fs::read_dir(directory)? {
                let path = entry?.path();
                if path.extension().is_none_or(|s| s != "json") {
                    continue;
                }
                let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                super::validate_manifest(&manifest, &self.tenant, 100_000)?;
                for part in manifest
                    .add
                    .iter()
                    .map(|p| &p.part_id)
                    .chain(manifest.remove_parts.iter())
                    .chain(manifest.hours.iter().flat_map(|hour| &hour.parts))
                {
                    self.remember(part)?;
                }
            }
        }
        for part in ExportState::load_durable(&self.work_dir)?
            .exported
            .values()
            .flatten()
        {
            self.remember(part)?;
        }
        Ok(())
    }

    pub async fn fence_retirement(
        &self,
        tenant: &str,
        part: &str,
    ) -> Result<CatalogRemovedReceipt> {
        self.fence_in_pass(tenant, part, &CatalogGcPass::default())
            .await
    }
    /// Part GC is NEVER gated on the agent catalog (decision 10-26). The
    /// strict proofs below (never planned, no committed snapshot, a full
    /// inspection that no longer references the part) receipt a part with
    /// the lane intact. Whenever they cannot clear it (planned index absent,
    /// still referenced, inspection failed, an uncommitted plan names it,
    /// custody moved mid-pass), the agent lane degrades instead: reads close
    /// through the privacy path (durable marker first), the part is
    /// receipted, and the writer's next sync drops it from the catalog and
    /// publishes a fresh epoch before reads reopen. See [`Self::degrade`].
    pub(crate) async fn fence_in_pass(
        &self,
        tenant: &str,
        part: &str,
        pass: &CatalogGcPass,
    ) -> Result<CatalogRemovedReceipt> {
        self.validate_tenant(tenant)?;
        self.receipt_path(part)?;
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let custody = self.lock.lock().await;
            if self.receipt_path(part)?.exists() {
                return self.require_removed(tenant, part);
            }
            let planned = self.planned_path(part)?.try_exists()?;
            // A foreign or unreadable marker is custody corruption, never
            // "unconverged": it stays a refusal.
            let indexed = self.planned_index_ready()?;
            let strict = self.strict_evidence(tenant, part, pass, planned, indexed, custody.generation).await;
            let (evidence, reopen) = match strict {
                Ok(proved) => proved,
                Err(error) => {
                    let live = self.live.lock().map_err(|_| anyhow::anyhow!("catalog live set poisoned"))?
                        .as_ref().is_some_and(|live| live.contains(part));
                    if live {
                        // Per key, like any pinned part: the pass goes on.
                        return Err(anyhow::Error::new(CatalogPinsPart));
                    }
                    (self.degrade(tenant, part, pass, &error).await?, false)
                }
            };
            let receipt = CatalogRemovedReceipt {
                tenant_id: self.tenant.clone(),
                bucket: self.bucket.clone(),
                part_id: part.into(),
                manifest_sha256: crate::parts::sha256_hex(&evidence),
            };
            self.record_receipt(&receipt)?;
            // A degraded lane stays closed until a converged sync reopens it.
            if reopen && self.work_dir.join("reads-closed").try_exists()?
                && !self.work_dir.join(GC_DEGRADED).try_exists()?
            {
                self.reopen().await?;
            }
            Ok(receipt)
        })
        .await
        .context("catalog retirement timed out; part retained")?
    }

    /// The pre-decoupling proofs that `part` is unreferenced. `Ok((evidence,
    /// reopen))`; any error means "not proven", never "do not delete".
    async fn strict_evidence(
        &self,
        tenant: &str,
        part: &str,
        pass: &CatalogGcPass,
        planned: bool,
        indexed: bool,
        generation: u64,
    ) -> Result<(Vec<u8>, bool)> {
        // NAN-4662: a catalog that never committed a snapshot references
        // nothing.
        if planned || !indexed {
            if let Some(evidence) = self.uncommitted_evidence(tenant, part, pass, generation).await? {
                return Ok((evidence, false));
            }
        }
        if !planned {
            ensure!(
                indexed,
                "catalog planned index not initialized: waiting for the writer's first reconciled catalog sync"
            );
            return Ok((serde_json::to_vec(&(tenant, &self.bucket, part, "never-planned"))?, false));
        }
        if pass.proof.get().is_none() {
            // A canceled/timed-out attempt must not start again for
            // the next physical file in this same GC pass.
            ensure!(
                !pass.attempted.swap(true, std::sync::atomic::Ordering::SeqCst),
                "catalog inspection canceled; retry next GC pass"
            );
            // Bounded inside the fence's own bound: a hung catalog degrades
            // the lane instead of timing the whole fence out (GC never waits).
            let inspected: Result<RetirementProof> = tokio::time::timeout(INSPECTION_BOUND, async {
                ensure!(self.pending()?.is_empty(), "catalog plan still pending");
                self.close().await?;
                self.backend.verify_maintenance().await?;
                // The pinned check for this part (and every later
                // one) runs below against the cached proof (NAN-4612).
                let referenced = self.backend.expire_and_inspect().await?;
                Ok(RetirementProof { tenant: self.tenant.clone(), generation, referenced })
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("catalog inspection timed out")));
            pass.proof
                .set(inspected.map_err(|e| format!("{e:#}")))
                .map_err(|_| anyhow::anyhow!("catalog GC proof already set"))?;
        }
        let proof = pass
            .proof
            .get()
            .context("catalog GC proof missing")?
            .as_ref()
            .map_err(|e| anyhow::Error::new(CatalogPartUnproven(e.clone())))?;
        ensure!(
            proof.tenant == tenant && proof.generation == generation,
            "catalog changed during GC pass; retry next pass"
        );
        if proof.referenced.contains(part) {
            return Err(anyhow::Error::new(CatalogPinsPart));
        }
        // NAN-4636: invalidate only once a retirement can proceed,
        // before its receipt; a pinned refusal keeps the cache.
        if pass.invalidated.get().is_none() {
            ensure!(
                !pass.invalidate_attempted.swap(true, std::sync::atomic::Ordering::SeqCst),
                "catalog result invalidation canceled; retry next GC pass"
            );
            let outcome = self.backend.invalidate_results().await;
            pass.invalidated
                .set(outcome.map_err(|e| format!("{e:#}")))
                .map_err(|_| anyhow::anyhow!("catalog GC invalidation already set"))?;
        }
        pass.invalidated
            .get()
            .context("catalog GC invalidation missing")?
            .as_ref()
            .map_err(|e| anyhow::anyhow!(e.clone()))?;
        Ok((serde_json::to_vec(&(tenant, &self.bucket, part, &proof.referenced))?, true))
    }

    /// Part GC proceeds; the agent lane pays. Erasure safety for exposed
    /// serving epochs, in order:
    /// 1. `gc-degraded` and `reads-closed` reach disk BEFORE the receipt, so
    ///    every later sync takes the privacy path and no GC pass or sync
    ///    reopens reads until a sync converges without the part (that sync
    ///    drops receipted parts from its live set, removes them from the
    ///    master, and publishes a FRESH epoch name; the old one is retired).
    /// 2. The gateway is closed and drained (the existing privacy fence,
    ///    which also starts a fresh pending epoch) once per pass. A provider
    ///    failure there is logged and does NOT hold the delete: the durable
    ///    marker retries the close on every sync, and a deleted file can no
    ///    longer serve rows through any epoch.
    async fn degrade(&self, tenant: &str, part: &str, pass: &CatalogGcPass, why: &anyhow::Error) -> Result<Vec<u8>> {
        self.write_marker(GC_DEGRADED, self.tenant.as_bytes())?;
        self.write_marker("reads-closed", self.tenant.as_bytes())?;
        if !pass.degraded_close.swap(true, std::sync::atomic::Ordering::SeqCst) {
            if let Err(error) = self.backend.close_and_drain().await {
                tracing::error!(error = %format!("{error:#}"),
                    "agent catalog read fence unavailable; part GC proceeds, reads stay closed by marker");
            }
            tracing::warn!(reason = %format!("{why:#}"),
                "part GC proceeds without agent catalog custody; agent lane degraded until the next converged catalog sync");
        }
        degraded_evidence(tenant, &self.bucket, part)
    }

    pub(crate) async fn guard_delete_in_pass(
        &self,
        permit: &crate::lake_part_gc::LakePartDeletePermit,
        pass: &CatalogGcPass,
    ) -> Result<()> {
        self.validate_tenant(&permit.request.tenant_uuid)?;
        permit.verify(&permit.request, chrono::Utc::now())?;
        ensure!(
            permit.request.bucket == self.bucket,
            "catalog delete bucket differs"
        );
        let parsed = crate::lake_part_gc::parse_part_file_key(&permit.request.key)
            .context("invalid catalog delete key")?;
        ensure!(
            parsed.tenant_uuid == self.tenant,
            "catalog delete key belongs to another tenant"
        );
        // NAN-4612: every custody refusal below is a pass pause the executor
        // reports as such, never a Worker failure. Nothing reaches the Worker.
        let held = |error: anyhow::Error| {
            anyhow::Error::new(crate::lake_part_gc::CatalogCustodyHeld {
                part_pinned: error.downcast_ref::<CatalogPinsPart>().is_some()
                    || error.downcast_ref::<CatalogPartUnproven>().is_some(),
                reason: format!("{error:#}"),
            })
        };
        self.fence_in_pass(&self.tenant, parsed.part_id.as_str(), pass)
            .await
            .map_err(held)?;
        self.require_removed(&self.tenant, parsed.part_id.as_str())
            .map_err(held)?;
        Ok(())
    }

    /// The planned index is complete only after a reconciled sync recorded
    /// every part the remote catalog references. A fresh or wiped custody
    /// volume (the A/B data-volume roll wipes it, NAN-4612) has no index: an
    /// absent part there proves nothing, so it fails closed with a named
    /// reason (not a bare `os error 2`) until the writer's next successful
    /// sync rebuilds the index from the catalog itself. `Ok(false)`: absent.
    /// A foreign or unreadable marker is an error for every part.
    fn planned_index_ready(&self) -> Result<bool> {
        match std::fs::read(self.work_dir.join(PLANNED_INDEX_READY)) {
            Ok(bytes) => {
                ensure!(
                    bytes == self.tenant.as_bytes(),
                    "catalog planned index belongs to another tenant"
                );
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(anyhow::Error::new(error).context("catalog planned index unreadable")),
        }
    }

    /// NAN-4662: evidence that `part` is unreferenced because the catalog has
    /// never committed a snapshot; `None` when that is not proven (GC then
    /// keeps the existing fence). Read under the custody lock and bound to
    /// the custody generation: a writer sync (the only path that commits)
    /// in between forces a fresh read, so a proof never outlives a commit.
    async fn uncommitted_evidence(
        &self,
        tenant: &str,
        part: &str,
        pass: &CatalogGcPass,
        generation: u64,
    ) -> Result<Option<Vec<u8>>> {
        use std::sync::atomic::Ordering::SeqCst;
        self.validate_tenant(tenant)?;
        let current = pass
            .uncommitted
            .lock()
            .map_err(|_| anyhow::anyhow!("catalog GC commit-state proof poisoned"))?
            .as_ref()
            .is_some_and(|read| read.generation == generation);
        if !current {
            // A canceled/timed-out read is not retried within this pass.
            if pass.uncommitted_inflight.load(SeqCst)
                || pass.uncommitted_reads.fetch_add(1, SeqCst) >= UNCOMMITTED_READS_PER_PASS
            {
                return Ok(None);
            }
            pass.uncommitted_inflight.store(true, SeqCst);
            let named = match self.prove_uncommitted().await {
                Ok(named) => named,
                Err(error) => {
                    tracing::warn!(error = %format!("{error:#}"),
                        "agent catalog commit state unreadable; GC keeps the catalog fence");
                    None
                }
            };
            pass.uncommitted_inflight.store(false, SeqCst);
            *pass
                .uncommitted
                .lock()
                .map_err(|_| anyhow::anyhow!("catalog GC commit-state proof poisoned"))? =
                Some(UncommittedRead { generation, named });
        }
        let guard = pass
            .uncommitted
            .lock()
            .map_err(|_| anyhow::anyhow!("catalog GC commit-state proof poisoned"))?;
        let read = guard.as_ref().context("catalog GC commit-state proof missing")?;
        ensure!(read.generation == generation, "catalog changed during GC pass; retry next pass");
        let Some(named) = &read.named else {
            return Ok(None);
        };
        if named.contains(part) {
            return Err(anyhow::Error::new(CatalogPartUnproven(
                "an uncommitted catalog plan names the part".into(),
            )));
        }
        Ok(Some(serde_json::to_vec(&(
            tenant,
            &self.bucket,
            part,
            "no-committed-snapshot",
        ))?))
    }

    async fn prove_uncommitted(&self) -> Result<Option<BTreeSet<String>>> {
        // A plan this volume saw acknowledged: a table was committed, so the
        // full fence applies without asking the catalog.
        if !self.manifests("committed")?.is_empty() {
            return Ok(None);
        }
        if !self.backend.no_committed_snapshot().await? {
            return Ok(None);
        }
        let mut named = BTreeSet::new();
        for name in ["pending", "superseded"] {
            for path in self.manifests(name)? {
                let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                super::validate_manifest(&manifest, &self.tenant, 100_000)?;
                named.extend(
                    manifest
                        .add
                        .iter()
                        .map(|p| p.part_id.clone())
                        .chain(manifest.remove_parts.iter().cloned())
                        .chain(manifest.hours.iter().flat_map(|hour| hour.parts.iter().cloned())),
                );
            }
        }
        Ok(Some(named))
    }

    fn manifests(&self, name: &str) -> Result<Vec<PathBuf>> {
        let directory = self.work_dir.join("export").join(name);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error.into()),
        };
        let mut paths = entries
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.retain(|path| path.extension().is_some_and(|e| e == "json"));
        Ok(paths)
    }

    /// A receipt is a prerequisite, never permission to bypass the existing
    /// owner/control/Worker delete permit. Every physical file in a part uses
    /// this same per-part receipt. Missing/corrupt/foreign evidence fails closed.
    pub fn require_removed(&self, tenant: &str, part: &str) -> Result<CatalogRemovedReceipt> {
        self.validate_tenant(tenant)?;
        let receipt: CatalogRemovedReceipt =
            serde_json::from_slice(&std::fs::read(self.receipt_path(part)?)?)?;
        ensure!(
            receipt.tenant_id == self.tenant
                && receipt.bucket == self.bucket
                && receipt.part_id == part
                && receipt.manifest_sha256.len() == 64
                && receipt
                    .manifest_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
            "catalog removal receipt differs"
        );
        Ok(receipt)
    }
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod custody_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::{part_log::LocalObjectStore, provenance::LocalPartSigner};
    use iceberg::spec::{NestedField, PrimitiveType, Schema, Type};

    struct Fence {
        tenant: String,
        bucket: String,
    }
    #[async_trait::async_trait]
    impl CatalogReadFence for Fence {
        fn tenant_id(&self) -> &str {
            &self.tenant
        }
        fn bucket(&self) -> &str {
            &self.bucket
        }
        async fn close_and_drain(&self) -> Result<()> {
            anyhow::bail!("fixture has no live reader control")
        }
        async fn invalidate_results(&self) -> Result<()> {
            anyhow::bail!("fixture has no live cache control")
        }
        async fn reopen(&self) -> Result<()> {
            anyhow::bail!("fixture has no live reader control")
        }
    }
    struct Policy;
    #[async_trait::async_trait]
    impl HostedCatalogPolicy for Policy {
        async fn verify_manual_maintenance(&self, _: &iceberg::TableIdent) -> Result<()> {
            anyhow::bail!("fixture has no provider maintenance attestation")
        }
    }

    /// NAN-4615: only fresh-epoch names count; the master is skipped and any
    /// other table in the serving namespace fails the listing closed.
    #[test]
    fn serving_epoch_listing_accepts_only_fresh_epoch_names() {
        let hex = "0123456789abcdef0123456789abcdef";
        assert_eq!(serving_epoch_dataset(&format!("events_{hex}_v1")).unwrap(), Some(format!("events_{hex}")));
        assert_eq!(serving_epoch_dataset("events_v1").unwrap(), None);
        for name in [
            format!("events_{}_v1", hex.to_uppercase()),
            format!("events_{}_v1", &hex[1..]),
            format!("events_{hex}_v2"),
            format!("writer_{hex}_v1"),
            "events".into(),
        ] {
            assert!(serving_epoch_dataset(&name).is_err(), "{name}");
        }
    }

    #[test]
    fn rest_catalog_constructor_binds_target_metadata_and_reader_credentials_to_one_tenant() {
        let tenant = "3867aaaa-0000-4000-8000-000000000001";
        let other = "3867bbbb-0000-4000-8000-000000000002";
        let bucket = crate::lake_part_gc::request::tenant_bucket(tenant);
        let dir = tempfile::tempdir().unwrap();
        let signer = LocalPartSigner::new(
            "lab-signer-nan4380",
            ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
        )
        .unwrap();
        let target = Arc::new(
            super::super::hosted::HostedExportTarget::new(
                tenant.into(),
                Arc::new(LocalObjectStore::new(dir.path()).unwrap()),
                signer.trusted(),
                bucket.clone(),
            )
            .unwrap(),
        );
        let table = || ExportTable {
            tenant_id: tenant.into(),
            namespace: "nano".into(),
            dataset: "events".into(),
            location: format!(
                "s3://{bucket}/{}/nano/events_v1",
                crate::parts::format::iceberg_export_prefix(tenant).unwrap()
            ),
            data_prefix: target.data_prefix(),
            max_files: 100,
            contract: super::super::schema::SchemaContract {
                version: 1,
                ocsf_version: "1.9.0".into(),
                schema: Schema::builder()
                    .with_fields([Arc::new(NestedField::optional(
                        1,
                        "time",
                        Type::Primitive(PrimitiveType::Timestamp),
                    ))])
                    .build()
                    .unwrap(),
            },
        };
        let config = CatalogConfig {
            uri: "https://catalog.invalid".into(),
            warehouse: "tenant-catalog".into(),
            credential: None,
            token_file: None,
            oauth_scope: None,
            oauth_audience: None,
            oauth_server_uri: None,
            realm: None,
            allow_anonymous: false,
            s3_endpoint: "https://storage.invalid".into(),
            s3_region: "auto".into(),
            s3_access_key: "fixture".into(),
            s3_secret_key: "fixture".into(),
            s3_session_token: None,
            s3_path_style_access: true,
            s3_default_credentials: false,
            vended_credentials: false,
        };
        let fence = || {
            Arc::new(Fence {
                tenant: tenant.into(),
                bucket: bucket.clone(),
            })
        };
        let metadata = || {
            Arc::new(
                metadata::MetadataGc::new(
                    tenant,
                    &table().location,
                    Arc::new(test_support::LocalMetadataAuthority {
                        tenant: tenant.into(),
                        prefix: format!("{}/metadata/", table().location),
                        directory: dir.path().into(),
                        fail_delete: std::sync::atomic::AtomicBool::new(false),
                    }),
                )
                .unwrap(),
            )
        };
        assert!(RestLifecycleBackend::new(
            config.clone(),
            table(),
            target.clone(),
            Arc::new(Policy),
            fence(),
            metadata()
        )
        .is_ok());
        assert!(RestLifecycleBackend::new(
            config.clone(),
            table(),
            target.clone(),
            Arc::new(Policy),
            Arc::new(Fence {
                tenant: other.into(),
                bucket: crate::lake_part_gc::request::tenant_bucket(other)
            }),
            metadata()
        )
        .is_err());
        let mut foreign = table();
        foreign.location = foreign
            .location
            .replace(&bucket, &crate::lake_part_gc::request::tenant_bucket(other));
        assert!(RestLifecycleBackend::new(
            config.clone(),
            foreign,
            target.clone(),
            Arc::new(Policy),
            fence(),
            metadata()
        )
        .is_err());
        let mut ambient = config.clone();
        ambient.s3_default_credentials = true;
        assert!(RestLifecycleBackend::new(
            ambient,
            table(),
            target.clone(),
            Arc::new(Policy),
            fence(),
            metadata()
        )
        .is_err());
        let mut vended = config;
        vended.vended_credentials = true;
        assert!(RestLifecycleBackend::new(
            vended,
            table(),
            target.clone(),
            Arc::new(Policy),
            fence(),
            metadata()
        )
        .is_err());
    }
}
