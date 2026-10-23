// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed parts registered in place. Only the fenced hosted coordinator may
//! publish these references; constructing a target does not enable exports.
use super::super::export::ExportManifest;
use super::{
    customer::{footer, stage_bounded},
    validate_manifest, ExportTarget,
};
use crate::parts::{
    format::{PartId, PartKeys, MAX_OBJECT_BYTES, PARTS_ROOT},
    part_log::ObjectStore,
    provenance::{SignedProvenance, TenantKeySet, MAX_PROVENANCE_BYTES},
};
use anyhow::{ensure, Result};
use iceberg::{
    spec::{DataContentType, DataFile, DataFileBuilder, DataFileFormat, Schema, Struct},
    table::Table,
    TableRequirement, TableUpdate,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub struct HostedExportTarget {
    tenant: String,
    source: Arc<dyn ObjectStore>,
    keys: TenantKeySet,
    bucket: String,
}
impl HostedExportTarget {
    pub(crate) fn new(
        tenant: String,
        source: Arc<dyn ObjectStore>,
        keys: TenantKeySet,
        bucket: String,
    ) -> Result<Self> {
        crate::parts::format::validate_tenant_uuid(&tenant)?;
        ensure!(
            bucket == crate::lake_part_gc::request::tenant_bucket(&tenant),
            "hosted bucket belongs to another tenant"
        );
        Ok(Self {
            tenant,
            source,
            keys,
            bucket,
        })
    }
    pub fn from_s3(
        tenant: String,
        location: &crate::part_ingest::s3_store::S3Location,
        keys: TenantKeySet,
    ) -> Result<Self> {
        ensure!(
            location.prefix.is_empty()
                && location.bucket == crate::lake_part_gc::request::tenant_bucket(&tenant),
            "hosted source topology differs"
        );
        let source = Arc::new(crate::part_ingest::s3_store::S3ObjectStore::new(location)?);
        Self::new(tenant, source, keys, location.bucket.clone())
    }
    pub fn data_prefix(&self) -> String {
        format!(
            "s3://{}/{PARTS_ROOT}/tenant={}/parts/",
            self.bucket, self.tenant
        )
    }

    /// Frozen maintenance may rewrite erased parts, but cannot introduce a new
    /// source stream or increase its signed input row count. The authorized
    /// erasure writer owns the row filtering; prepare separately verifies all
    /// replacement bytes/footers against the existing frozen schema.
    pub(super) async fn verify_erasure(&self, manifest: &ExportManifest) -> Result<()> {
        validate_manifest(manifest, &self.tenant, 100_000)?;
        let removed = manifest
            .remove_parts
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut inputs = BTreeMap::new();
        let mut output_rows = 0u64;
        for part in &manifest.add {
            let directory = part.keys[0]
                .rsplit_once('/')
                .ok_or_else(|| anyhow::anyhow!("invalid hosted erasure path"))?
                .0;
            let key = format!("{directory}/provenance.json");
            let size = self
                .source
                .object_size(&key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("hosted erasure proof missing"))?;
            ensure!(
                size > 0 && size <= MAX_PROVENANCE_BYTES as u64,
                "hosted erasure proof exceeds bound"
            );
            let bytes = self
                .source
                .get_range(&key, 0..size)
                .await?
                .ok_or_else(|| anyhow::anyhow!("hosted erasure proof missing"))?;
            ensure!(
                bytes.len() as u64 == size,
                "hosted erasure proof length differs"
            );
            let signed = SignedProvenance::verify_bytes(&bytes, &self.tenant, &self.keys)?;
            ensure!(
                signed.record.part_id.to_string() == part.part_id,
                "hosted erasure part identity differs"
            );
            let crate::parts::provenance::PartInputs::Parts { parts } = &signed.record.inputs
            else {
                anyhow::bail!("frozen erasure cannot ingest new source rows")
            };
            ensure!(!parts.is_empty(), "hosted erasure input set empty");
            for input in parts {
                let id = input.part_id.to_string();
                ensure!(
                    removed.contains(id.as_str()),
                    "frozen rewrite does not replace its signed parents"
                );
                ensure!(
                    inputs.len() < 100_000 || inputs.contains_key(&id),
                    "hosted erasure input bound exceeded"
                );
                if let Some(previous) = inputs.insert(id, input.clone()) {
                    ensure!(previous == *input, "hosted erasure input evidence differs");
                }
            }
            output_rows = output_rows
                .checked_add(signed.record.rows)
                .ok_or_else(|| anyhow::anyhow!("hosted erasure row overflow"))?;
        }
        let input_rows = inputs.values().try_fold(0u64, |sum, input| {
            sum.checked_add(input.rows)
                .ok_or_else(|| anyhow::anyhow!("hosted erasure input overflow"))
        })?;
        ensure!(
            output_rows <= input_rows,
            "frozen erasure increased signed row count"
        );
        Ok(())
    }
}
#[async_trait::async_trait]
impl ExportTarget for HostedExportTarget {
    async fn prepare(
        &self,
        manifest: &ExportManifest,
        schema: &Schema,
    ) -> Result<BTreeMap<String, Vec<DataFile>>> {
        validate_manifest(manifest, &self.tenant, 100_000)?;
        let spool = tempfile::tempdir()?;
        let mut prepared = BTreeMap::new();
        for part in &manifest.add {
            let directory = part.keys[0]
                .rsplit_once('/')
                .ok_or_else(|| anyhow::anyhow!("invalid hosted part"))?
                .0;
            let proof_key = format!("{directory}/provenance.json");
            let size = self
                .source
                .object_size(&proof_key)
                .await?
                .ok_or_else(|| anyhow::anyhow!("hosted proof missing"))?;
            ensure!(
                size > 0 && size <= MAX_PROVENANCE_BYTES as u64,
                "hosted proof exceeds bound"
            );
            let bytes = self
                .source
                .get_range(&proof_key, 0..size)
                .await?
                .ok_or_else(|| anyhow::anyhow!("hosted proof missing"))?;
            ensure!(bytes.len() as u64 == size, "hosted proof length differs");
            let signed = SignedProvenance::verify_bytes(&bytes, &self.tenant, &self.keys)?;
            let record = &signed.record;
            let keys = PartKeys::new(
                &self.tenant,
                record.level,
                record.event_hour,
                &PartId::parse(&part.part_id)?,
            )?;
            ensure!(
                keys.provenance() == proof_key
                    && record.part_id.to_string() == part.part_id
                    && record.rows == part.rows
                    && record.files.data_bytes() == part.bytes
                    && record.min_time_us == part.min_time_us
                    && record.max_time_us == part.max_time_us
                    && record.files.data.len() == part.keys.len(),
                "hosted plan differs from signed record"
            );
            let mut files = Vec::new();
            for (index, digest) in record.files.data.iter().enumerate() {
                ensure!(
                    part.keys[index] == keys.data(index),
                    "hosted source path differs"
                );
                let path = spool.path().join("data.parquet");
                stage_bounded(
                    self.source.as_ref(),
                    &part.keys[index],
                    &path,
                    digest.bytes,
                    &digest.sha256,
                    MAX_OBJECT_BYTES,
                )
                .await?;
                footer(&path, schema, digest.rows)?;
                files.push(
                    DataFileBuilder::default()
                        .content(DataContentType::Data)
                        .file_format(DataFileFormat::Parquet)
                        .file_path(format!("s3://{}/{}", self.bucket, part.keys[index]))
                        .partition(Struct::empty())
                        .partition_spec_id(0)
                        .record_count(digest.rows)
                        .file_size_in_bytes(digest.bytes)
                        .build()?,
                );
            }
            prepared.insert(part.part_id.clone(), files);
        }
        Ok(prepared)
    }
}

/// Count all retained snapshots, including those of frozen contract tables.
/// An unreadable list/manifest or foreign path fails closed. No orphan listing
/// or current-snapshot-only shortcut is valid for GC.
pub async fn reachable_files(
    table: &Table,
    prefix: &str,
    max_entries: usize,
) -> Result<BTreeSet<String>> {
    Ok(inspect_references(table, prefix, max_entries).await?.0)
}

pub async fn reachable_objects(
    table: &Table,
    prefix: &str,
    max_entries: usize,
) -> Result<BTreeSet<String>> {
    let (mut files, metadata) = inspect_references(table, prefix, max_entries).await?;
    files.extend(metadata);
    Ok(files)
}

pub(super) fn check_metadata_path(table: &Table, path: &str) -> Result<()> {
    if table.metadata().location().starts_with("s3://") {
        super::validate_object_uri(path)?;
    }
    let prefix = format!(
        "{}/metadata/",
        table.metadata().location().trim_end_matches('/')
    );
    ensure!(
        path.starts_with(&prefix)
            && path.len() <= 4096
            && !path.contains('%')
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path.split('/').all(|s| !matches!(s, "." | "..")),
        "hosted metadata path escaped table"
    );
    Ok(())
}

async fn inspect_references(
    table: &Table,
    prefix: &str,
    max_entries: usize,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    ensure!(
        max_entries > 0 && max_entries <= 1_000_000,
        "invalid hosted reachability bound"
    );
    ensure!(
        table.metadata().snapshots().len() <= 1024,
        "hosted snapshot bound exceeded"
    );
    let mut inspected = 0usize;
    let mut paths = BTreeSet::new();
    let mut metadata = BTreeSet::new();
    if let Some(path) = table.metadata_location() {
        check_metadata_path(table, path)?;
        metadata.insert(path.to_string());
    }
    for snapshot in table.metadata().snapshots() {
        check_metadata_path(table, snapshot.manifest_list())?;
        metadata.insert(snapshot.manifest_list().to_string());
        let list = table.manifest_list_reader(snapshot).load().await?;
        ensure!(
            list.entries().len() <= max_entries,
            "hosted manifest bound exceeded"
        );
        for descriptor in list.entries() {
            ensure!(
                descriptor.content == iceberg::spec::ManifestContentType::Data
                    && descriptor.partition_spec_id == 0,
                "unsupported hosted manifest"
            );
            check_metadata_path(table, &descriptor.manifest_path)?;
            metadata.insert(descriptor.manifest_path.clone());
            let manifest = descriptor.load_manifest(table.file_io()).await?;
            inspected = inspected
                .checked_add(manifest.entries().len())
                .ok_or_else(|| anyhow::anyhow!("hosted entry overflow"))?;
            ensure!(inspected <= max_entries, "hosted entry bound exceeded");
            for entry in manifest.entries().iter().filter(|e| e.is_alive()) {
                super::part_id_from_path(entry.file_path(), prefix)?;
                paths.insert(entry.file_path().to_string());
            }
        }
    }
    Ok((paths, metadata))
}

/// Expire superseded snapshots only once the REPLACING snapshot has aged past
/// reader grace. A very old snapshot superseded seconds ago must still survive.
/// Provider refs other than main are rejected; external access cannot create them.
pub fn expiry_updates(
    table: &Table,
    now_ms: i64,
    grace_ms: i64,
) -> Result<(Vec<TableRequirement>, Vec<TableUpdate>)> {
    expiry_updates_inner(table, now_ms, grace_ms, false)
}

/// Erasure/retention revoke old readers and expire superseded snapshots
/// immediately. Ordinary compaction continues to honor its reader grace.
pub(super) fn privacy_expiry_updates(
    table: &Table,
) -> Result<(Vec<TableRequirement>, Vec<TableUpdate>)> {
    expiry_updates_inner(
        table,
        chrono::Utc::now().timestamp_millis(),
        3_600_000,
        true,
    )
}
fn expiry_updates_inner(
    table: &Table,
    now_ms: i64,
    grace_ms: i64,
    privacy: bool,
) -> Result<(Vec<TableRequirement>, Vec<TableUpdate>)> {
    ensure!(
        (3_600_000..=7 * 86_400_000).contains(&grace_ms),
        "hosted reader grace outside bounds"
    );
    let value = serde_json::to_value(table.metadata())?;
    let refs = value.get("refs").and_then(|v| v.as_object());
    ensure!(
        privacy || refs.is_none_or(|r| r.keys().all(|k| k == "main")),
        "hosted external refs refused"
    );
    let mut chain = BTreeMap::new();
    for snapshot in table.metadata().snapshots() {
        if let Some(parent) = snapshot.parent_snapshot_id() {
            let previous = chain.insert(parent, snapshot.timestamp_ms());
            ensure!(
                privacy || previous.is_none(),
                "hosted branching snapshot history refused"
            );
        }
    }
    let current = table.metadata().current_snapshot_id();
    let cutoff = now_ms
        .checked_sub(grace_ms)
        .ok_or_else(|| anyhow::anyhow!("hosted expiry clock overflow"))?;
    let expired = table
        .metadata()
        .snapshots()
        .filter(|s| {
            Some(s.snapshot_id()) != current
                && (privacy
                    || chain
                        .get(&s.snapshot_id())
                        .is_some_and(|superseded| *superseded <= cutoff))
        })
        .map(|s| s.snapshot_id())
        .collect::<Vec<_>>();
    let requirements = vec![
        TableRequirement::UuidMatch {
            uuid: table.metadata().uuid(),
        },
        TableRequirement::RefSnapshotIdMatch {
            r#ref: "main".into(),
            snapshot_id: current,
        },
    ];
    let mut requirements = requirements;
    let mut updates = Vec::new();
    if privacy {
        if let Some(refs) = refs {
            for name in refs.keys().filter(|name| name.as_str() != "main") {
                let id = refs[name]
                    .get("snapshot-id")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| anyhow::anyhow!("invalid hosted privacy ref"))?;
                requirements.push(TableRequirement::RefSnapshotIdMatch {
                    r#ref: name.clone(),
                    snapshot_id: Some(id),
                });
                updates.push(TableUpdate::RemoveSnapshotRef {
                    ref_name: name.clone(),
                });
            }
        }
    }
    if !expired.is_empty() {
        updates.push(TableUpdate::RemoveSnapshots {
            snapshot_ids: expired,
        });
    }
    Ok((requirements, updates))
}

/// Provider adapter must verify automatic compaction, snapshot maintenance and
/// orphan/data deletion are OFF. A self-written table property is not evidence.
/// No production provider adapter is shipped until its controls are verified.
#[async_trait::async_trait]
pub trait HostedCatalogPolicy: Send + Sync {
    async fn verify_manual_maintenance(&self, table: &iceberg::TableIdent) -> Result<()>;
}
