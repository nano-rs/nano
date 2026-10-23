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
    rest_commit::{CommitOutcome, RestTableCommitClient},
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
    fn tenant_id(&self) -> &str;
    fn bucket(&self) -> &str;
    async fn verify_maintenance(&self) -> Result<()>;
    async fn close_and_drain(&self) -> Result<()>;
    /// Rewrite manifests and expire historical snapshots. Return ALL part IDs
    /// still present in retained metadata, including deleted entries/bounds.
    async fn expire_and_inspect(&self) -> Result<BTreeSet<String>>;
    async fn invalidate_results(&self) -> Result<()>;
    async fn reopen(&self) -> Result<()>;
}

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
        ensure!(
            table.location
                == format!(
                    "s3://{bucket}/{}/{}/{}",
                    crate::parts::format::iceberg_export_prefix(&table.tenant_id)?,
                    table.namespace,
                    id.name
                ),
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
            .config
            .load()
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
            let client = RestTableCommitClient::new(&self.committer.config, id)
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

/// Owned by the single tenant writer; keep this directory with the existing
/// durable export state. Pending manifests survive every failed provider step.
/// The provider barrier survives loss of the writer's local state as well.
pub struct TenantCatalog {
    tenant: String,
    bucket: String,
    work_dir: PathBuf,
    backend: Arc<dyn CatalogLifecycleBackend>,
    lock: tokio::sync::Mutex<CustodyState>,
    _lease: std::fs::File,
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
        fs2::FileExt::try_lock_exclusive(&lease).context("catalog writer already held")?;
        let service = Self {
            tenant: tenant.into(),
            bucket,
            work_dir,
            backend,
            lock: tokio::sync::Mutex::new(CustodyState::default()),
            _lease: lease,
        };
        service.recover_planned_index()?;
        Ok(service)
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
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut custody = self.lock.lock().await;
            let mut state = ExportState::load_durable(&self.work_dir)?;
            let plans = self.pending()?;
            let pending = plan_export_reconciled(&refs, &state, now_ms, policy);
            let desired = refs.iter().map(|p| p.part_id.as_str()).collect::<BTreeSet<_>>();
            let closed = self.work_dir.join("reads-closed").try_exists()?;
            if !closed && plans.is_empty() && pending.is_empty()
                && custody.last_success.is_some_and(|at| now_ms >= at && now_ms - at < 3_600_000) {
                return Ok(());
            }
            custody.generation = custody.generation.checked_add(1).context("catalog generation overflow")?;
            let mut privacy = closed || !self.work_dir.join("planned-index-ready").try_exists()? || pending.iter().any(|(hour, _)| {
                state.exported.get(&hour.event_hour).is_some_and(|old| old.iter().any(|p| !hour.parts.contains(p)))
            });
            for path in &plans {
                let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
                privacy |= !manifest.remove_parts.is_empty() || manifest.add.iter().any(|p| !desired.contains(p.part_id.as_str()));
            }
            if privacy { self.close().await?; }
            self.backend.verify_maintenance().await?;
            for path in plans { self.publish(&path, privacy).await?; }
            if !pending.is_empty() {
                let at = now_ms.max(state.last_plan_ms.checked_add(1).context("catalog clock overflow")?);
                // Membership must reach disk BEFORE a plan can reach disk or
                // the provider (including an ambiguous commit response).
                for (_, parts) in &pending { for part in parts { self.remember(part.part_id.as_str())?; } }
                let path = state.record_durable_plan(&self.work_dir, tenant, &pending, at)?;
                self.publish(&path, privacy).await?;
            }
            let remaining = self.backend.expire_and_inspect().await?;
            if !remaining.iter().all(|p| desired.contains(p.as_str())) {
                self.close().await?;
                anyhow::bail!("catalog contains parts outside the committed live set; recover durable custody");
            }
            for part in remaining { self.remember(&part)?; }
            if privacy {
                // Also repairs a previous retirement/cache failure with no
                // outstanding manifest, even inside the hourly debounce.
                self.backend.invalidate_results().await?;
                self.reopen().await?;
            }
            self.write_marker("planned-index-ready", self.tenant.as_bytes())?;
            custody.last_success = Some(now_ms);
            Ok(())
        })
        .await
        .context("catalog sync timed out; read barrier and pending plans retained")?
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

    async fn publish(&self, path: &std::path::Path, privacy: bool) -> Result<()> {
        let manifest: ExportManifest = serde_json::from_slice(&std::fs::read(path)?)?;
        super::validate_manifest(&manifest, &self.tenant, 100_000)?;
        ensure!(
            manifest.add.iter().all(|p| !self
                .receipt_path(&p.part_id)
                .is_ok_and(|path| path.exists())),
            "catalog publication would resurrect a retired part"
        );
        self.backend.verify_maintenance().await?;
        self.backend.commit(&manifest).await?;
        let referenced = self.backend.expire_and_inspect().await?;
        ensure!(
            manifest
                .remove_parts
                .iter()
                .all(|p| !referenced.contains(p)),
            "catalog still exposes removed part metadata"
        );
        self.backend.invalidate_results().await?;
        ensure!(
            privacy || manifest.remove_parts.is_empty(),
            "catalog removal requires read barrier"
        );
        for part in &manifest.remove_parts {
            let receipt = CatalogRemovedReceipt {
                tenant_id: self.tenant.clone(),
                bucket: self.bucket.clone(),
                part_id: part.clone(),
                manifest_sha256: manifest_digest(&manifest)?,
            };
            self.record_receipt(&receipt)?;
        }
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
        for name in ["pending", "committed"] {
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
    async fn fence_in_pass(
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
            let evidence = if planned {
                if pass.proof.get().is_none() {
                    // A canceled/timed-out attempt must not start again for
                    // the next physical file in this same GC pass.
                    ensure!(
                        !pass
                            .attempted
                            .swap(true, std::sync::atomic::Ordering::SeqCst),
                        "catalog inspection canceled; retry next GC pass"
                    );
                    let inspected: Result<RetirementProof> = async {
                        ensure!(self.pending()?.is_empty(), "catalog plan still pending");
                        self.close().await?;
                        self.backend.verify_maintenance().await?;
                        let referenced = self.backend.expire_and_inspect().await?;
                        ensure!(
                            !referenced.contains(part),
                            "catalog metadata still pins part"
                        );
                        self.backend.invalidate_results().await?;
                        Ok(RetirementProof {
                            tenant: self.tenant.clone(),
                            generation: custody.generation,
                            referenced,
                        })
                    }
                    .await;
                    pass.proof
                        .set(inspected.map_err(|e| format!("{e:#}")))
                        .map_err(|_| anyhow::anyhow!("catalog GC proof already set"))?;
                }
                let proof = pass
                    .proof
                    .get()
                    .context("catalog GC proof missing")?
                    .as_ref()
                    .map_err(|e| anyhow::anyhow!(e.clone()))?;
                ensure!(
                    proof.tenant == tenant && proof.generation == custody.generation,
                    "catalog changed during GC pass; retry next pass"
                );
                ensure!(
                    !proof.referenced.contains(part),
                    "catalog metadata still pins part"
                );
                serde_json::to_vec(&(tenant, &self.bucket, part, &proof.referenced))?
            } else {
                ensure!(
                    std::fs::read(self.work_dir.join("planned-index-ready"))? == tenant.as_bytes(),
                    "catalog planned index not initialized"
                );
                serde_json::to_vec(&(tenant, &self.bucket, part, "never-planned"))?
            };
            let receipt = CatalogRemovedReceipt {
                tenant_id: self.tenant.clone(),
                bucket: self.bucket.clone(),
                part_id: part.into(),
                manifest_sha256: crate::parts::sha256_hex(&evidence),
            };
            self.record_receipt(&receipt)?;
            if planned && self.work_dir.join("reads-closed").try_exists()? {
                self.reopen().await?;
            }
            Ok(receipt)
        })
        .await
        .context("catalog retirement timed out; part retained")?
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
        self.fence_in_pass(&self.tenant, parsed.part_id.as_str(), pass)
            .await?;
        self.require_removed(&self.tenant, parsed.part_id.as_str())?;
        Ok(())
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
