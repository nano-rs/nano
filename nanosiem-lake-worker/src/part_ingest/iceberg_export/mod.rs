// SPDX-License-Identifier: AGPL-3.0-or-later

//! Optional export foundation. No serving/ingest caller enables this module.
//! Targets authenticate signed parts and either copy them or resolve their URIs.
//! Only this committer mutates the public contract table.

pub mod schema;
pub mod customer;
pub mod egress;
pub mod runner;
#[cfg(feature = "enterprise")]
pub mod hosted;
#[cfg(feature = "enterprise")]
pub mod hosted_state;
#[cfg(feature = "enterprise")]
pub mod hosted_access;
#[cfg(feature = "enterprise")]
pub mod hosted_budget;
#[cfg(feature = "enterprise")]
pub mod hosted_gateway;
#[cfg(feature = "enterprise")]
pub mod hosted_gateway_s3;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Result};
use iceberg::spec::{
    DataContentType, DataFile, DataFileFormat, ManifestContentType, ManifestListWriter,
    ManifestWriterBuilder, Operation, Snapshot, SnapshotReference, SnapshotRetention, Summary,
    MAIN_BRANCH,
};
use iceberg::table::Table;
use iceberg::{Catalog, TableCreation, TableIdent, TableRequirement, TableUpdate};
use sha2::{Digest, Sha256};

use super::export::{ExportManifest, IcebergCommitter};
use crate::iceberg::CatalogConfig;
use crate::parts::format::{validate_tenant_uuid, PartId, PARTS_ROOT};
use crate::rest_commit::{CommitOutcome, RestTableCommitClient};
use schema::SchemaContract;

const CHECKPOINT: &str = "nano.export.planned_at_ms";
const DIGEST: &str = "nano.export.manifest_sha256";
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);
const ATTEMPTS: usize = 3;

/// The boundary shared by customer-copy and hosted-reference implementations.
/// Implementations must verify signed provenance/checksums, inspect each Parquet
/// footer, and preserve `{part_id}/data-NNNNN.parquet` in immutable destination
/// paths. Destination writes must be conditional/idempotent, never mutate a
/// live immutable object. Counts are per file, not the manifest's aggregate per-part count.
/// Files with embedded IDs must match the resolved contract schema; files without
/// IDs use the published name mapping. Never rewrite or delete source data here.
#[async_trait::async_trait]
pub trait ExportTarget: Send + Sync {
    async fn prepare(
        &self,
        manifest: &ExportManifest,
        schema: &iceberg::spec::Schema,
    ) -> Result<BTreeMap<String, Vec<DataFile>>>;
}

/// Immutable configuration for one tenant/target revision. Construction performs
/// no network IO. The API layer must validate SSRF-safe endpoints before use.
pub struct ExportTable {
    pub tenant_id: String,
    pub namespace: String,
    pub dataset: String,
    pub location: String,
    /// Exact tenant-scoped S3 URI prefix containing the target's data files.
    pub data_prefix: String,
    pub contract: SchemaContract,
    /// Bound on all live + deleted manifest entries inspected per attempt.
    pub max_files: usize,
}

pub struct RestIcebergCommitter {
    config: CatalogConfig,
    table: ExportTable,
    table_id: TableIdent,
    target: Arc<dyn ExportTarget>,
    frozen_erasure: bool,
}

impl RestIcebergCommitter {
    pub fn new(
        config: CatalogConfig,
        table: ExportTable,
        target: Arc<dyn ExportTarget>,
    ) -> Result<Self> {
        validate_tenant_uuid(&table.tenant_id)?;
        ensure!(
            table.max_files > 0 && table.max_files <= 1_000_000,
            "invalid export file bound"
        );
        for uri in [&table.location, &table.data_prefix] {
            validate_object_uri(uri)?;
        }
        let tenant_segment = format!("/tenant={}/", table.tenant_id);
        ensure!(
            format!("{}/", table.location.trim_end_matches('/')).contains(&tenant_segment)
                && table.data_prefix.contains(&tenant_segment),
            "export paths must be tenant-scoped"
        );
        ensure!(
            table.data_prefix.ends_with('/'),
            "export data prefix must end with a slash"
        );
        let table_id = table
            .contract
            .table_ident(&table.namespace, &table.dataset)?;
        Ok(Self {
            config,
            table,
            table_id,
            target,
            frozen_erasure: false,
        })
    }

    #[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
    pub(super) fn for_frozen_erasure(mut self) -> Self {
        self.frozen_erasure = true;
        self
    }

    pub fn table_id(&self) -> &TableIdent {
        &self.table_id
    }

    async fn attempt(&self, manifest: &ExportManifest) -> Result<bool> {
        // Rebuild both sessions on every bounded attempt, proactively acquiring
        // fresh OAuth/workload tokens before hourly work (no 3600s token cache).
        let catalog = self
            .config
            .load()
            .await
            .map_err(|_| anyhow::anyhow!("export catalog session failed"))?;
        if !catalog
            .namespace_exists(&self.table_id.namespace)
            .await
            .map_err(|_| anyhow::anyhow!("export namespace lookup failed"))?
        {
            // A competing creator is harmless; recheck on the next attempt.
            if catalog
                .create_namespace(&self.table_id.namespace, HashMap::new())
                .await
                .is_err()
            {
                return Ok(false);
            }
        }
        if !catalog
            .table_exists(&self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("export table lookup failed"))?
        {
            ensure!(!self.frozen_erasure, "frozen maintenance table unavailable");
            let creation = TableCreation::builder()
                .name(self.table_id.name.clone())
                .location(self.table.location.clone())
                .schema(self.table.contract.schema.clone())
                .properties(self.table.contract.properties(&self.table.tenant_id))
                .build();
            if catalog
                .create_table(&self.table_id.namespace, creation)
                .await
                .is_err()
            {
                return Ok(false);
            }
        }
        let table = catalog
            .load_table(&self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("export table load failed"))?;
        if self.frozen_erasure {
            ensure!(
                table.metadata().properties().get(schema::FROZEN).map(String::as_str) == Some("true"),
                "frozen maintenance requires a frozen table"
            );
            self.table.contract.validate_identity(
                &table, &self.table.tenant_id, &self.table.location,
            )?;
        } else {
            self.table.contract.validate_table(
                &table, &self.table.tenant_id, &self.table.location,
            )?;
        }
        if checkpoint(&table, manifest)? {
            return Ok(true);
        }
        let (schema, mut requirements, mut updates) = if self.frozen_erasure {
            (table.metadata().current_schema().as_ref().clone(), Vec::new(), Vec::new())
        } else {
            self.table.contract.evolution(&table)?
        };
        let files = self
            .target
            .prepare(manifest, &schema)
            .await
            .map_err(|_| anyhow::anyhow!("export target preparation failed"))?;
        validate_prepared(
            manifest,
            &files,
            &self.table.data_prefix,
            self.table.max_files,
        )?;
        let (snapshot, snapshot_requirements) = prepare_snapshot_inner(
            &table,
            manifest,
            files,
            &schema,
            &self.table.data_prefix,
            self.table.max_files,
            self.frozen_erasure,
        )
        .await
        .map_err(|_| anyhow::anyhow!("export snapshot preparation failed"))?;
        requirements.extend(snapshot_requirements);
        let snapshot_id = snapshot.snapshot_id();
        updates.extend([
            TableUpdate::AddSnapshot { snapshot },
            TableUpdate::SetSnapshotRef {
                ref_name: MAIN_BRANCH.to_string(),
                reference: SnapshotReference::new(
                    snapshot_id,
                    SnapshotRetention::branch(None, None, None),
                ),
            },
            TableUpdate::SetProperties {
                updates: HashMap::from([
                    (CHECKPOINT.to_string(), manifest.planned_at_ms.to_string()),
                    (DIGEST.to_string(), manifest_digest(manifest)?),
                ]),
            },
        ]);
        let client = RestTableCommitClient::new(&self.config, &self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("export REST session failed"))?;
        match client.commit(requirements, updates).await {
            Ok(CommitOutcome::Committed(response)) => {
                ensure!(
                    response.metadata.properties().get(DIGEST) == Some(&manifest_digest(manifest)?)
                        && response.metadata.properties().get(CHECKPOINT)
                            == Some(&manifest.planned_at_ms.to_string())
                        && response.metadata.current_snapshot_id() == Some(snapshot_id)
                        && response.metadata.current_schema_id() == schema.schema_id()
                        && response.metadata.uuid() == table.metadata().uuid(),
                    "export commit response omitted checkpoint"
                );
                Ok(true)
            }
            // Transport errors include ambiguous successes. Reload/check the
            // catalog checkpoint on retry, never blindly append the same files.
            Ok(CommitOutcome::Conflict) | Err(_) => Ok(false),
        }
    }
}

#[async_trait::async_trait]
impl IcebergCommitter for RestIcebergCommitter {
    async fn commit(&self, manifest: &ExportManifest) -> Result<()> {
        validate_manifest(manifest, &self.table.tenant_id, self.table.max_files)?;
        for attempt in 0..ATTEMPTS {
            match tokio::time::timeout(ATTEMPT_TIMEOUT, self.attempt(manifest)).await {
                Ok(Ok(true)) => return Ok(()),
                Ok(Err(error)) => return Err(error),
                Ok(Ok(false)) | Err(_) => {}
            }
            if attempt + 1 < ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(250 * (1 << attempt))).await;
            }
        }
        bail!("export commit exhausted bounded retries; keep pending manifest")
    }
}

pub fn manifest_digest(manifest: &ExportManifest) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(b"nano:lean-iceberg-export:v1\0");
    digest.update(serde_json::to_vec(manifest)?);
    Ok(hex::encode(digest.finalize()))
}

/// A checkpoint survives snapshot expiry. The predecessor prevents skipping a
/// failed delta. An older replay is harmless once the ordered chain passed it.
fn checkpoint(table: &Table, manifest: &ExportManifest) -> Result<bool> {
    let properties = table.metadata().properties();
    let previous = properties
        .get(CHECKPOINT)
        .map(|v| v.parse::<i64>())
        .transpose()?;
    if let Some(previous) = previous {
        if manifest.planned_at_ms < previous {
            return Ok(true);
        }
        if manifest.planned_at_ms == previous {
            ensure!(
                properties.get(DIGEST) == Some(&manifest_digest(manifest)?),
                "export checkpoint collision"
            );
            return Ok(true);
        }
    }
    ensure!(
        previous == manifest.previous_plan_ms,
        "export predecessor missing; replay pending manifests in order"
    );
    Ok(false)
}

fn validate_manifest(manifest: &ExportManifest, tenant: &str, max_files: usize) -> Result<()> {
    ensure!(manifest.tenant_id == tenant, "cross-tenant export refused");
    ensure!(
        manifest.planned_at_ms > 0
            && manifest
                .previous_plan_ms
                .is_none_or(|p| p > 0 && p < manifest.planned_at_ms),
        "invalid export ordering"
    );
    ensure!(
        manifest.add.len() <= max_files
            && manifest.remove_parts.len() <= max_files
            && manifest.hours.len() <= max_files,
        "export manifest exceeds bound"
    );
    let mut parts = BTreeSet::new();
    let mut count = 0usize;
    for part in &manifest.add {
        validate_part_id(&part.part_id)?;
        ensure!(
            parts.insert(&part.part_id)
                && !part.keys.is_empty()
                && part.min_time_us <= part.max_time_us,
            "invalid export part"
        );
        count = count
            .checked_add(part.keys.len())
            .ok_or_else(|| anyhow::anyhow!("export file count overflow"))?;
        ensure!(count <= max_files, "export file count exceeds bound");
        for (index, key) in part.keys.iter().enumerate() {
            ensure!(
                key.len() <= 4096
                    && key.starts_with(&format!("{PARTS_ROOT}/tenant={tenant}/parts/"))
                    && key.ends_with(&format!("/{}/data-{index:05}.parquet", part.part_id)),
                "invalid export source key"
            );
            ensure!(
                key.split('/')
                    .all(|segment| !matches!(segment, "" | "." | ".."))
                    && !key.chars().any(char::is_control),
                "invalid export source path"
            );
        }
    }
    let mut removed = BTreeSet::new();
    for id in &manifest.remove_parts {
        validate_part_id(id)?;
        ensure!(
            removed.insert(id) && !parts.contains(id),
            "invalid export replacement"
        );
    }
    let mut hours = BTreeSet::new();
    for hour in &manifest.hours {
        ensure!(hours.insert(hour.event_hour), "duplicate export hour");
        for id in &hour.parts {
            validate_part_id(id)?;
        }
    }
    Ok(())
}

fn validate_part_id(id: &str) -> Result<()> {
    ensure!(id.is_ascii(), "invalid export part ID");
    PartId::parse(id)?;
    Ok(())
}

fn validate_object_uri(uri: &str) -> Result<()> {
    let parsed =
        reqwest::Url::parse(uri).map_err(|_| anyhow::anyhow!("invalid export object URI"))?;
    ensure!(
        parsed.scheme() == "s3"
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "invalid export object URI"
    );
    ensure!(
        uri.is_ascii()
            && !uri.contains('\\')
            && uri.len() <= 4096
            && !uri.chars().any(char::is_control)
            && !uri.contains('%')
            && uri.split('/').skip(3).all(|s| !matches!(s, "." | "..")),
        "invalid export object path"
    );
    Ok(())
}

fn part_id_from_path<'a>(path: &'a str, prefix: &str) -> Result<&'a str> {
    validate_object_uri(path)?;
    ensure!(
        path.starts_with(prefix),
        "export data file outside tenant prefix"
    );
    let (dir, name) = path
        .rsplit_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid export data file"))?;
    ensure!(
        name.len() == 18
            && name.starts_with("data-")
            && name.ends_with(".parquet")
            && name.as_bytes()[5..10].iter().all(|b| b.is_ascii_digit()),
        "invalid export data filename"
    );
    let part_id = dir.rsplit('/').next().unwrap_or_default();
    validate_part_id(part_id)?;
    Ok(part_id)
}

fn validate_prepared(
    manifest: &ExportManifest,
    prepared: &BTreeMap<String, Vec<DataFile>>,
    prefix: &str,
    max_files: usize,
) -> Result<()> {
    ensure!(
        prepared.len() == manifest.add.len(),
        "prepared export part set mismatch"
    );
    let mut paths = BTreeSet::new();
    for part in &manifest.add {
        let files = prepared
            .get(&part.part_id)
            .ok_or_else(|| anyhow::anyhow!("missing prepared export part"))?;
        ensure!(
            files.len() == part.keys.len(),
            "prepared export file set mismatch"
        );
        let mut rows = 0u64;
        let mut bytes = 0u64;
        for (index, file) in files.iter().enumerate() {
            ensure!(
                file.file_path()
                    .ends_with(&format!("/{}/data-{index:05}.parquet", part.part_id)),
                "prepared export filename mismatch"
            );
            ensure!(
                paths.insert(file.file_path())
                    && paths.len() <= max_files
                    && part_id_from_path(file.file_path(), prefix)? == part.part_id,
                "invalid prepared export identity"
            );
            ensure!(
                file.content_type() == DataContentType::Data
                    && file.file_format() == DataFileFormat::Parquet
                    && file.partition().fields().is_empty(),
                "invalid prepared export data file"
            );
            rows = rows
                .checked_add(file.record_count())
                .ok_or_else(|| anyhow::anyhow!("export row count overflow"))?;
            bytes = bytes
                .checked_add(file.file_size_in_bytes())
                .ok_or_else(|| anyhow::anyhow!("export byte count overflow"))?;
        }
        ensure!(
            rows == part.rows && bytes == part.bytes,
            "prepared export aggregate mismatch"
        );
    }
    Ok(())
}

#[cfg(test)]
async fn prepare_snapshot(
    table: &Table,
    manifest: &ExportManifest,
    added: BTreeMap<String, Vec<DataFile>>,
    schema: &iceberg::spec::Schema,
    prefix: &str,
    max_files: usize,
) -> Result<(Snapshot, Vec<TableRequirement>)> {
    prepare_snapshot_inner(table, manifest, added, schema, prefix, max_files, false).await
}

/// Standard v2 append/overwrite/delete snapshot. Rewrites live entries without
/// their historical tombstones; old snapshots retain their own manifests.
async fn prepare_snapshot_inner(
    table: &Table,
    manifest: &ExportManifest,
    added: BTreeMap<String, Vec<DataFile>>,
    schema: &iceberg::spec::Schema,
    prefix: &str,
    max_files: usize,
    frozen_erasure: bool,
) -> Result<(Snapshot, Vec<TableRequirement>)> {
    let parent = table.metadata().current_snapshot().map(|s| s.snapshot_id());
    let mut live = BTreeMap::new();
    if let Some(snapshot) = table.metadata().current_snapshot() {
        let list = table.manifest_list_reader(snapshot).load().await?;
        ensure!(
            list.entries().len() <= max_files,
            "export manifest list exceeds bound"
        );
        let mut inspected = 0usize;
        for descriptor in list.entries().to_vec() {
            ensure!(
                descriptor.content == ManifestContentType::Data
                    && descriptor.partition_spec_id == 0,
                "unsupported export manifest content"
            );
            let loaded = descriptor.load_manifest(table.file_io()).await?;
            inspected = inspected
                .checked_add(loaded.entries().len())
                .ok_or_else(|| anyhow::anyhow!("export entry count overflow"))?;
            ensure!(inspected <= max_files, "export table exceeds file bound");
            for entry in loaded.entries().iter().filter(|e| e.is_alive()) {
                part_id_from_path(entry.file_path(), prefix)?;
                ensure!(
                    live.insert(entry.file_path().to_string(), entry.as_ref().clone())
                        .is_none(),
                    "duplicate live export file"
                );
            }
        }
    }
    let remove = manifest
        .remove_parts
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if frozen_erasure {
        let mut found = BTreeSet::new();
        let mut old_rows = 0u64;
        for entry in live.values() {
            let id = part_id_from_path(entry.file_path(), prefix)?;
            if remove.contains(id) {
                found.insert(id);
                old_rows = old_rows.checked_add(entry.data_file().record_count())
                    .ok_or_else(|| anyhow::anyhow!("frozen input row overflow"))?;
            }
        }
        ensure!(found == remove, "frozen erasure must replace current parts");
        let new_rows = added.values().flatten().try_fold(0u64, |sum, file| {
            sum.checked_add(file.record_count())
                .ok_or_else(|| anyhow::anyhow!("frozen output row overflow"))
        })?;
        ensure!(new_rows <= old_rows, "frozen erasure cannot increase current row count");
    }
    let digest = manifest_digest(manifest)?;
    // Unique immutable metadata paths even when two workers race on the same base.
    let nonce = uuid::Uuid::new_v4();
    let snapshot_id = (u64::from_be_bytes(
        Sha256::digest(format!("{digest}:{parent:?}")).as_slice()[..8].try_into()?,
    ) & i64::MAX as u64) as i64;
    ensure!(
        snapshot_id > 0 && table.metadata().snapshot_by_id(snapshot_id).is_none(),
        "export snapshot identity collision"
    );
    let mut writer = ManifestWriterBuilder::new(
        table.file_io().new_output(format!(
            "{}/metadata/export-{nonce}.avro",
            table.metadata().location().trim_end_matches('/')
        ))?,
        Some(snapshot_id),
        Arc::new(schema.clone()),
        table.metadata().default_partition_spec().as_ref().clone(),
    )
    .build_v2_data();
    let mut deleted = 0usize;
    let mut total_files = 0usize;
    let mut total_rows = 0u64;
    let mut total_bytes = 0u64;
    for entry in live.values() {
        let sequence = entry
            .sequence_number()
            .ok_or_else(|| anyhow::anyhow!("export file sequence missing"))?;
        if remove.contains(part_id_from_path(entry.file_path(), prefix)?) {
            writer.add_delete_file(
                entry.data_file().clone(),
                sequence,
                entry.file_sequence_number,
            )?;
            deleted += 1;
        } else {
            writer.add_existing_file(
                entry.data_file().clone(),
                entry
                    .snapshot_id()
                    .ok_or_else(|| anyhow::anyhow!("export file snapshot missing"))?,
                sequence,
                entry.file_sequence_number,
            )?;
            total_files += 1;
            total_rows = total_rows
                .checked_add(entry.data_file().record_count())
                .ok_or_else(|| anyhow::anyhow!("export row count overflow"))?;
            total_bytes = total_bytes
                .checked_add(entry.data_file().file_size_in_bytes())
                .ok_or_else(|| anyhow::anyhow!("export byte count overflow"))?;
        }
    }
    let mut appended = 0usize;
    for file in added.into_values().flatten() {
        if let Some(existing) = live.get(file.file_path()) {
            ensure!(
                existing.data_file() == &file,
                "immutable export file changed"
            );
            continue; // A shared day file is already present for another hour.
        }
        total_files += 1;
        appended += 1;
        ensure!(
            total_files + deleted <= max_files,
            "export table exceeds file bound"
        );
        total_rows = total_rows
            .checked_add(file.record_count())
            .ok_or_else(|| anyhow::anyhow!("export row count overflow"))?;
        total_bytes = total_bytes
            .checked_add(file.file_size_in_bytes())
            .ok_or_else(|| anyhow::anyhow!("export byte count overflow"))?;
        writer.add_file(file, table.metadata().next_sequence_number())?;
    }
    let descriptor = writer.write_manifest_file().await?;
    let list_path = format!(
        "{}/metadata/export-{nonce}-list.avro",
        table.metadata().location().trim_end_matches('/')
    );
    let mut list = ManifestListWriter::v2(
        table.file_io().new_output(&list_path)?.writer().await?,
        snapshot_id,
        parent,
        table.metadata().next_sequence_number(),
    );
    list.add_manifests([descriptor].into_iter())?;
    list.close().await?;
    let operation = if deleted == 0 {
        Operation::Append
    } else if appended == 0 {
        Operation::Delete
    } else {
        Operation::Overwrite
    };
    let snapshot = Snapshot::builder()
        .with_snapshot_id(snapshot_id)
        .with_parent_snapshot_id(parent)
        .with_sequence_number(table.metadata().next_sequence_number())
        .with_timestamp_ms(chrono::Utc::now().timestamp_millis())
        .with_manifest_list(list_path)
        .with_schema_id(schema.schema_id())
        .with_summary(Summary {
            operation,
            additional_properties: HashMap::from([
                (DIGEST.to_string(), digest),
                ("total-data-files".to_string(), total_files.to_string()),
                ("total-records".to_string(), total_rows.to_string()),
                ("total-files-size".to_string(), total_bytes.to_string()),
                ("added-data-files".to_string(), appended.to_string()),
                ("deleted-data-files".to_string(), deleted.to_string()),
            ]),
        })
        .build();
    Ok((
        snapshot,
        vec![
            TableRequirement::UuidMatch {
                uuid: table.metadata().uuid(),
            },
            TableRequirement::RefSnapshotIdMatch {
                r#ref: MAIN_BRANCH.to_string(),
                snapshot_id: parent,
            },
            TableRequirement::DefaultSpecIdMatch { default_spec_id: 0 },
        ],
    ))
}

#[cfg(test)]
mod tests;
