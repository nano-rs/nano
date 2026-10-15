// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-owned custom IP context for lean cells (NAN-2918 follow-up).
//!
//! Same storage contract as the lean IOC snapshot: the object store passed in
//! is rooted at one tenant's R2 enrichment prefix
//! (`lake/enrichment/v1/tenant_id=<T>/`), snapshots are content-addressed
//! Parquet under `ip_context/snapshots/`, every publication writes an
//! immutable `ip_context/revisions/<rev>.json`, and `ip_context/current.json`
//! is the one mutable pointer. Ingest pins a revision and picks up the next
//! one on its refresh loop.
//!
//! The publisher keeps a lean `IpContextStore` working copy in scratch so the
//! upsert/tombstone/source-delete semantics (and the lean caps enforced before
//! publication) are exactly the gen1 coordinator's; R2 stays authoritative and
//! the working copy is re-seeded whenever it differs from the R2 pointer.

use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

use crate::ip_context::{
    IpContextCounts, IpContextInput, IpContextPublicationResult, IpContextSnapshot, IpContextStore,
    PreparedIpContextPublication,
};
use crate::lean_enrichment_snapshot::{
    fetch_pinned, publish_file, read_pointer, SnapshotKind, SnapshotPointer,
};
use crate::parts::part_log::ObjectStore;

const KIND: SnapshotKind = SnapshotKind::IpContext;

/// The mutation itself was refused (bad row, bad source identity); nothing
/// was published. Distinct from a lean cap refusal
/// (`ip_context::LeanSnapshotCapExceeded`) and from store failures.
#[derive(Debug, thiserror::Error)]
#[error("IP context mutation refused")]
pub struct InvalidIpContextMutation;

/// The tenant pointer moved under this writer; retry against the new revision.
#[derive(Debug, thiserror::Error)]
#[error("tenant IP context snapshot revision changed")]
pub struct IpContextRevisionConflict;

fn refused(error: anyhow::Error) -> anyhow::Error {
    if error
        .downcast_ref::<crate::ip_context::LeanSnapshotCapExceeded>()
        .is_some()
    {
        error
    } else {
        error.context(InvalidIpContextMutation)
    }
}

/// Read side: one tenant's custom IP-context revisions.
pub struct LeanIpContextSnapshots<'a> {
    tenant_id: Uuid,
    objects: &'a dyn ObjectStore,
    scratch: PathBuf,
}

impl<'a> LeanIpContextSnapshots<'a> {
    pub fn new(tenant_id: Uuid, objects: &'a dyn ObjectStore, scratch: &Path) -> Result<Self> {
        ensure!(
            scratch.is_absolute(),
            "IP context scratch directory must be absolute"
        );
        Ok(Self {
            tenant_id,
            objects,
            scratch: scratch.to_path_buf(),
        })
    }

    pub async fn current(&self) -> Result<Option<SnapshotPointer>> {
        read_pointer(self.objects, KIND, self.tenant_id).await
    }

    /// Download (once) and verify a pinned revision; the returned file has
    /// passed the lean reader checks (bytes, rows, decoded size, digest).
    pub async fn fetch(&self, expected: &SnapshotPointer) -> Result<PathBuf> {
        fetch_pinned(
            self.objects,
            KIND,
            self.tenant_id,
            expected,
            &self.scratch,
            |candidate| IpContextSnapshot::open_lean(candidate, &expected.sha256).map(drop),
        )
        .await
    }

    /// Open a pinned revision for ingest stamping.
    pub async fn load(&self, expected: &SnapshotPointer) -> Result<IpContextSnapshot> {
        let path = self.fetch(expected).await?;
        IpContextSnapshot::open_lean(&path, &expected.sha256)
    }
}

/// Write side: the lean coordinator's sole publisher for one tenant. Callers
/// serialize mutations (the coordinator's writer lock).
pub struct LeanIpContextPublisher {
    tenant_id: Uuid,
    /// Shared with blocking tasks: Parquet encode/decode and file I/O run on
    /// the blocking pool, never on the async runtime thread.
    working: Arc<IpContextStore>,
    cache: PathBuf,
}

/// Run a working-copy operation on the blocking pool.
async fn blocking<T: Send + 'static>(
    store: &Arc<IpContextStore>,
    operation: impl FnOnce(&IpContextStore) -> Result<T> + Send + 'static,
) -> Result<T> {
    let store = store.clone();
    tokio::task::spawn_blocking(move || operation(&store))
        .await
        .context("IP context working-copy task failed")?
}

#[derive(Debug, serde::Serialize)]
pub struct LeanIpContextPublication {
    #[serde(flatten)]
    pub result: IpContextPublicationResult,
    /// The R2 revision now current; `None` when the mutation changed nothing.
    pub snapshot_id: Option<String>,
}

impl LeanIpContextPublisher {
    pub fn new(tenant_id: Uuid, scratch: &Path) -> Result<Self> {
        ensure!(
            scratch.is_absolute(),
            "IP context scratch directory must be absolute"
        );
        Ok(Self {
            tenant_id,
            working: Arc::new(IpContextStore::new_lean(scratch.join("ip-context-work"), tenant_id.to_string())?),
            cache: scratch.join("ip-context-cache"),
        })
    }

    pub async fn upsert(
        &self,
        objects: &dyn ObjectStore,
        rows: Vec<IpContextInput>,
    ) -> Result<LeanIpContextPublication> {
        let expected = self.sync(objects).await?;
        let prepared = blocking(&self.working, move |store| store.prepare_upsert(rows).map_err(refused)).await?;
        self.publish(objects, expected, prepared).await
    }

    pub async fn delete_source(
        &self,
        objects: &dyn ObjectStore,
        source_id: &str,
    ) -> Result<LeanIpContextPublication> {
        let expected = self.sync(objects).await?;
        let source_id = source_id.to_string();
        let prepared = blocking(&self.working, move |store| {
            store.prepare_delete_source(&source_id).map_err(refused)
        })
        .await?;
        self.publish(objects, expected, prepared).await
    }

    pub async fn counts(&self, objects: &dyn ObjectStore) -> Result<IpContextCounts> {
        self.sync(objects).await?;
        blocking(&self.working, |store| store.counts()).await
    }

    /// Re-seed the working copy from the R2 pointer when they differ.
    async fn sync(&self, objects: &dyn ObjectStore) -> Result<Option<SnapshotPointer>> {
        let reader = LeanIpContextSnapshots::new(self.tenant_id, objects, &self.cache)?;
        let current = reader.current().await?;
        let local = blocking(&self.working, |store| Ok(store.counts()?.snapshot_sha256)).await?;
        match &current {
            Some(pointer) if local.as_deref() != Some(pointer.sha256.as_str()) => {
                let path = reader.fetch(pointer).await?;
                let sha256 = pointer.sha256.clone();
                blocking(&self.working, move |store| {
                    store.adopt_lean_snapshot(Some((&path, &sha256)))
                })
                .await?;
            }
            None if local.is_some() => {
                blocking(&self.working, |store| store.adopt_lean_snapshot(None)).await?
            }
            _ => {}
        }
        Ok(current)
    }

    async fn publish(
        &self,
        objects: &dyn ObjectStore,
        expected: Option<SnapshotPointer>,
        prepared: PreparedIpContextPublication,
    ) -> Result<LeanIpContextPublication> {
        if prepared.result().status != "published" {
            return Ok(LeanIpContextPublication {
                result: blocking(&self.working, move |store| store.activate(prepared)).await?,
                snapshot_id: expected.map(|pointer| pointer.revision.to_string()),
            });
        }
        let durable = prepared
            .durable_snapshot()
            .cloned()
            .context("prepared IP context publication has no snapshot")?;
        // Single writer per tenant: the pointer must not have moved since sync.
        if read_pointer(objects, KIND, self.tenant_id).await? != expected {
            return Err(IpContextRevisionConflict.into());
        }
        let pointer = publish_file(objects, KIND, self.tenant_id, &durable.path, durable.sha256)
            .await
            .context("publish tenant IP context snapshot")?;
        // The local working copy follows R2 only after the pointer advanced.
        let result = blocking(&self.working, move |store| store.activate(prepared)).await?;
        Ok(LeanIpContextPublication {
            result,
            snapshot_id: Some(pointer.revision.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;

    pub(crate) fn row(network: &str, country: &str) -> IpContextInput {
        IpContextInput {
            network: network.into(),
            source_id: "tenant-cmdb".into(),
            country_code: country.into(),
            updated_at: chrono::Utc::now(),
            deleted: false,
            country: String::new(),
            continent: String::new(),
            continent_code: String::new(),
            asn: "AS64512".into(),
            as_name: "Corp".into(),
            as_domain: String::new(),
        }
    }

    #[tokio::test]
    async fn publishes_revisions_and_reseeds_from_r2_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let objects = LocalObjectStore::new(dir.path().join("r2")).unwrap();
        let publisher = LeanIpContextPublisher::new(tenant, &dir.path().join("a")).unwrap();
        let first = publisher
            .upsert(&objects, vec![row("10.20.0.0/16", "CA")])
            .await
            .unwrap();
        assert_eq!(first.result.status, "published");
        // A fresh process (empty scratch) merges onto the R2 revision.
        let restarted = LeanIpContextPublisher::new(tenant, &dir.path().join("b")).unwrap();
        let second = restarted
            .upsert(&objects, vec![row("192.0.2.0/24", "FR")])
            .await
            .unwrap();
        assert_eq!(second.result.rows, 2);
        assert_ne!(first.snapshot_id, second.snapshot_id);
        let reader = LeanIpContextSnapshots::new(tenant, &objects, &dir.path().join("r")).unwrap();
        let pointer = reader.current().await.unwrap().unwrap();
        assert_eq!(Some(pointer.revision.to_string()), second.snapshot_id);
        let snapshot = reader.load(&pointer).await.unwrap();
        assert_eq!(snapshot.row_count(), 2);
        assert_eq!(
            snapshot.lookup("10.20.1.1").unwrap().unwrap().country_code.as_deref(),
            Some("CA")
        );
        // The original process is stale; it re-seeds rather than losing rows.
        let third = publisher.delete_source(&objects, "tenant-cmdb").await.unwrap();
        assert_eq!(third.result.rows, 0);
        let pointer = reader.current().await.unwrap().unwrap();
        assert_eq!(reader.load(&pointer).await.unwrap().row_count(), 0);
        // An unchanged mutation does not mint a revision.
        let same = publisher.delete_source(&objects, "tenant-cmdb").await.unwrap();
        assert_eq!(same.result.status, "unchanged");
        assert_eq!(same.snapshot_id, Some(pointer.revision.to_string()));
    }
}
