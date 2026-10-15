// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-bound, versioned IOC snapshots for lean cells. The store passed to
//! this module must itself be rooted at one tenant's R2 enrichment prefix.
//! Publication has one writer per tenant; a replacement writes immutable
//! bytes before advancing the durable pointer. Readers always pin a revision.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::enrichment::{write_ioc_snapshot_owned, IocSnapshot, IocSnapshotInput};
use crate::parts::part_log::ObjectStore;

/// Per-tenant ceiling on one lean snapshot object (IOC and custom IP context).
pub const TENANT_SNAPSHOT_LIMIT_BYTES: usize = 64 * 1024 * 1024;
/// The single per-tenant row ceiling for every lean enrichment snapshot: the
/// IOC publisher here and the custom IP-context publisher/reader in
/// `ip_context`. It matches the bound the ClickHouse product enforces on
/// lookup- and feed-backed IOC expansion (`LOOKUP_IOC_MAX` = `FEED_IOC_MAX`
/// = 50,000 in `nanosiem-core/src/search/service/ioc_lookup_resolve.rs`), so a
/// published lean snapshot can always be expanded by search.
pub const TENANT_SNAPSHOT_LIMIT_ROWS: usize = 50_000;
pub enum SourceUpdate {
    Replace {
        source_id: String,
        rows: Vec<IocSnapshotInput>,
    },
    Delete {
        source_id: String,
    },
}

/// One tenant-owned lean snapshot family. Every family lives under the same
/// tenant R2 prefix (`lake/enrichment/v1/tenant_id=<T>/`, the credential
/// scope) with the same layout: content-addressed Parquet, an immutable
/// revision record, and one mutable current pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    Ioc,
    IpContext,
}

impl SnapshotKind {
    fn namespace(self) -> &'static str {
        match self {
            Self::Ioc => "ioc",
            Self::IpContext => "ip_context",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ioc => "IOC",
            Self::IpContext => "IP context",
        }
    }

    fn pointer_key(self) -> String {
        format!("{}/current.json", self.namespace())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotPointer {
    pub tenant_id: Uuid,
    pub revision: Uuid,
    pub sha256: String,
    pub bytes: usize,
}

impl SnapshotPointer {
    fn key(&self, kind: SnapshotKind) -> String {
        format!("{}/snapshots/{}.parquet", kind.namespace(), self.sha256)
    }

    fn revision_key(&self, kind: SnapshotKind) -> String {
        format!("{}/revisions/{}.json", kind.namespace(), self.revision)
    }

    fn check(&self, kind: SnapshotKind, tenant_id: Uuid) -> Result<()> {
        let label = kind.label();
        ensure!(
            self.tenant_id == tenant_id,
            "{label} pointer tenant differs from process tenant"
        );
        ensure!(
            self.bytes > 0 && self.bytes <= TENANT_SNAPSHOT_LIMIT_BYTES,
            "{label} pointer size is invalid"
        );
        ensure!(
            self.sha256.len() == 64 && self.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "{label} pointer digest is invalid"
        );
        Ok(())
    }
}

/// Read one family's current pointer from a tenant-rooted store.
pub(crate) async fn read_pointer(
    objects: &dyn ObjectStore,
    kind: SnapshotKind,
    tenant_id: Uuid,
) -> Result<Option<SnapshotPointer>> {
    let Some(bytes) = objects.get(&kind.pointer_key()).await? else {
        return Ok(None);
    };
    ensure!(bytes.len() <= 4096, "{} pointer is oversized", kind.label());
    let pointer: SnapshotPointer = serde_json::from_slice(&bytes)?;
    pointer.check(kind, tenant_id)?;
    Ok(Some(pointer))
}

/// Download a pinned revision into `scratch` once, bound to its durable
/// revision record and size. `validate` runs on the downloaded bytes before
/// they enter the cache; a refused candidate never becomes a cache hit.
pub(crate) async fn fetch_pinned(
    objects: &dyn ObjectStore,
    kind: SnapshotKind,
    tenant_id: Uuid,
    expected: &SnapshotPointer,
    scratch: &Path,
    validate: impl Fn(&Path) -> Result<()>,
) -> Result<PathBuf> {
    let label = kind.label();
    expected.check(kind, tenant_id)?;
    let revision = objects
        .get(&expected.revision_key(kind))
        .await?
        .with_context(|| format!("pinned {label} revision is missing"))?;
    let recorded: SnapshotPointer = serde_json::from_slice(&revision)?;
    ensure!(
        &recorded == expected,
        "pinned {label} revision differs from the durable record"
    );
    std::fs::create_dir_all(scratch)?;
    let path = scratch.join(format!("{}.parquet", expected.sha256));
    if !path.exists() {
        let temporary = scratch.join(format!(".{}-{}", expected.sha256, Uuid::new_v4()));
        let downloaded = objects.get_to_file(&expected.key(kind), &temporary).await?;
        if !downloaded {
            bail!("pinned tenant {label} snapshot is missing");
        }
        let size = std::fs::metadata(&temporary)?.len() as usize;
        if size != expected.bytes || size > TENANT_SNAPSHOT_LIMIT_BYTES {
            let _ = std::fs::remove_file(&temporary);
            bail!("pinned tenant {label} snapshot exceeds its size cap or differs from pointer");
        }
        if let Err(error) = validate(&temporary) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        std::fs::rename(&temporary, &path)?;
    }
    ensure!(
        std::fs::metadata(&path)?.len() as usize == expected.bytes,
        "cached {label} size differs"
    );
    Ok(path)
}

/// Publish one already-validated snapshot file: immutable content address,
/// then the revision record, then the pointer. The caller is the sole writer
/// for this tenant and family.
pub(crate) async fn publish_file(
    objects: &dyn ObjectStore,
    kind: SnapshotKind,
    tenant_id: Uuid,
    path: &Path,
    digest: String,
) -> Result<SnapshotPointer> {
    let label = kind.label();
    let body = std::fs::read(path)?;
    ensure!(
        body.len() <= TENANT_SNAPSHOT_LIMIT_BYTES,
        "tenant {label} upload exceeds the 64 MiB snapshot cap"
    );
    let pointer = SnapshotPointer {
        tenant_id,
        revision: Uuid::now_v7(),
        sha256: digest,
        bytes: body.len(),
    };
    pointer.check(kind, tenant_id)?;
    if !objects.put_if_absent(&pointer.key(kind), &body).await? {
        // An existing content address must contain the same bytes.
        let existing = objects
            .get(&pointer.key(kind))
            .await?
            .context("existing snapshot disappeared")?;
        ensure!(
            existing == body,
            "content-addressed {label} snapshot has conflicting bytes"
        );
    }
    ensure!(
        objects
            .put_if_absent(&pointer.revision_key(kind), &serde_json::to_vec(&pointer)?)
            .await?,
        "{label} revision collision"
    );
    objects
        .put(&kind.pointer_key(), &serde_json::to_vec(&pointer)?)
        .await?;
    Ok(pointer)
}

pub struct LeanEnrichmentSnapshots<'a> {
    tenant_id: Uuid,
    objects: &'a dyn ObjectStore,
    scratch: PathBuf,
    publication_lock: tokio::sync::Mutex<()>,
}

impl<'a> LeanEnrichmentSnapshots<'a> {
    pub fn new(tenant_id: Uuid, objects: &'a dyn ObjectStore, scratch: &Path) -> Result<Self> {
        ensure!(
            scratch.is_absolute(),
            "snapshot scratch directory must be absolute"
        );
        Ok(Self {
            tenant_id,
            objects,
            scratch: scratch.to_path_buf(),
            publication_lock: tokio::sync::Mutex::new(()),
        })
    }

    pub async fn current(&self) -> Result<Option<SnapshotPointer>> {
        read_pointer(self.objects, SnapshotKind::Ioc, self.tenant_id).await
    }

    /// Fetch a pinned revision. A newer current pointer cannot silently
    /// substitute another snapshot; callers must explicitly restart a scan.
    pub async fn load(&self, expected: &SnapshotPointer) -> Result<IocSnapshot> {
        let path = fetch_pinned(
            self.objects,
            SnapshotKind::Ioc,
            self.tenant_id,
            expected,
            &self.scratch,
            |candidate| {
                check_row_count(candidate)?;
                IocSnapshot::open(candidate, &expected.sha256).map(drop)
            },
        )
        .await?;
        check_row_count(&path)?;
        IocSnapshot::open(&path, &expected.sha256)
    }

    /// The coordinator is the sole writer for this tenant. The caller must
    /// authenticate its tenant assignment before constructing this store.
    pub async fn publish(&self, rows: &[IocSnapshotInput]) -> Result<SnapshotPointer> {
        let _guard = self.publication_lock.lock().await;
        self.publish_locked(rows.to_vec()).await.map(|(pointer, _)| pointer)
    }

    /// Write and publish `rows` (owned: no second copy is held while the
    /// Parquet is encoded). Returns the pointer and the rows written.
    async fn publish_locked(&self, rows: Vec<IocSnapshotInput>) -> Result<(SnapshotPointer, usize)> {
        ensure!(
            rows.len() <= TENANT_SNAPSHOT_LIMIT_ROWS,
            "tenant IOC upload exceeds the {TENANT_SNAPSHOT_LIMIT_ROWS} row snapshot cap"
        );
        std::fs::create_dir_all(&self.scratch)?;
        let temporary = self
            .scratch
            .join(format!(".publish-{}.parquet", Uuid::new_v4()));
        let (digest, written) = match write_ioc_snapshot_owned(&temporary, rows) {
            Ok(written) => written,
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error);
            }
        };
        let bytes = std::fs::metadata(&temporary)?.len() as usize;
        if bytes > TENANT_SNAPSHOT_LIMIT_BYTES {
            let _ = std::fs::remove_file(&temporary);
            bail!("tenant IOC upload exceeds the 64 MiB snapshot cap");
        }
        let published =
            publish_file(self.objects, SnapshotKind::Ioc, self.tenant_id, &temporary, digest).await;
        let _ = std::fs::remove_file(&temporary);
        published.map(|pointer| (pointer, written))
    }

    /// Replace or delete only the selected tenant-owned source. The caller
    /// serializes updates for this tenant; a revision mismatch is a conflict
    /// instead of a lost update.
    pub async fn update_source(
        &self,
        expected: Option<&SnapshotPointer>,
        update: SourceUpdate,
    ) -> Result<SnapshotPointer> {
        self.update_source_counted(expected, update).await.map(|(pointer, _)| pointer)
    }

    /// [`Self::update_source`] also returning the rows of the published
    /// tenant snapshot (every source), without re-loading it (NAN-3882).
    ///
    /// Memory: the current snapshot is materialized once, without the
    /// selected source's old rows, and moved (not cloned) into the writer.
    pub async fn update_source_counted(
        &self,
        expected: Option<&SnapshotPointer>,
        update: SourceUpdate,
    ) -> Result<(SnapshotPointer, usize)> {
        let _guard = self.publication_lock.lock().await;
        let current = self.current().await?;
        ensure!(
            current.as_ref() == expected,
            "tenant IOC snapshot revision changed"
        );
        let (source_id, replacement) = match update {
            SourceUpdate::Replace { source_id, rows } => (source_id, Some(rows)),
            SourceUpdate::Delete { source_id } => (source_id, None),
        };
        ensure!(
            !source_id.is_empty()
                && source_id.len() <= 256
                && source_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
            "tenant IOC source identity is invalid"
        );
        if let Some(ref replacement) = replacement {
            ensure!(
                replacement.iter().all(|row| row.source_id == source_id),
                "IOC rows differ from selected source"
            );
        }
        let mut rows = match &current {
            Some(pointer) => self.load(pointer).await?.into_publication_rows_except(&source_id),
            None => Vec::new(),
        };
        if let Some(mut replacement) = replacement {
            rows.append(&mut replacement);
        }
        self.publish_locked(rows).await
    }
}

fn check_row_count(path: &Path) -> Result<()> {
    let builder = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
        std::fs::File::open(path)?,
    )?;
    ensure!(
        builder.metadata().file_metadata().num_rows() <= TENANT_SNAPSHOT_LIMIT_ROWS as i64,
        "tenant IOC snapshot exceeds its row cap"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;

    #[tokio::test]
    async fn tenant_revision_survives_restart_and_refuses_cross_tenant_read() {
        let dir = tempfile::tempdir().unwrap();
        let objects = LocalObjectStore::new(dir.path().join("r2")).unwrap();
        let tenant = Uuid::new_v4();
        let store =
            LeanEnrichmentSnapshots::new(tenant, &objects, &dir.path().join("scratch")).unwrap();
        let row = IocSnapshotInput {
            ioc_value: "8.8.8.8".into(),
            ioc_type: "ip".into(),
            source_id: "tenant-feed".into(),
            ..Default::default()
        };
        let first = store.publish(&[row]).await.unwrap();
        assert_eq!(
            store.load(&first).await.unwrap().publication_rows().len(),
            1
        );
        let second = store.publish(&[]).await.unwrap();
        assert_ne!(first.revision, second.revision);
        assert_eq!(
            store.load(&first).await.unwrap().publication_rows().len(),
            1
        );
        let restarted =
            LeanEnrichmentSnapshots::new(tenant, &objects, &dir.path().join("restart")).unwrap();
        assert_eq!(restarted.current().await.unwrap(), Some(second));
        let other =
            LeanEnrichmentSnapshots::new(Uuid::new_v4(), &objects, &dir.path().join("other"))
                .unwrap();
        assert!(other.current().await.is_err());
        assert!(other.load(&first).await.is_err());
    }

    #[tokio::test]
    async fn source_update_preserves_other_source_and_refuses_stale_revision() {
        let dir = tempfile::tempdir().unwrap();
        let objects = LocalObjectStore::new(dir.path().join("r2")).unwrap();
        let store =
            LeanEnrichmentSnapshots::new(Uuid::new_v4(), &objects, &dir.path().join("scratch"))
                .unwrap();
        let row = |source: &str| IocSnapshotInput {
            ioc_value: "8.8.8.8".into(),
            ioc_type: "ip".into(),
            source_id: source.into(),
            ..Default::default()
        };
        let first = store.publish(&[row("a"), row("b")]).await.unwrap();
        let second = store
            .update_source(
                Some(&first),
                SourceUpdate::Delete {
                    source_id: "a".into(),
                },
            )
            .await
            .unwrap();
        let rows = store.load(&second).await.unwrap().publication_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source_id, "b");
        assert!(store
            .update_source(
                Some(&first),
                SourceUpdate::Delete {
                    source_id: "b".into()
                }
            )
            .await
            .is_err());
    }
}
