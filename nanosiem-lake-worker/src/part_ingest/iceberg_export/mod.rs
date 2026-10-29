// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared exporter and the agent lane's catalog lifecycle boundary.
//! Targets authenticate signed parts and either copy them or resolve their URIs.
//! Only this committer mutates the public contract table.

pub mod schema;
pub mod customer;
pub mod egress;
pub mod runner;
pub mod hosted;
pub mod lifecycle;
pub mod activation;
pub(crate) mod control_retry;
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
    ManifestWriterBuilder, NestedFieldRef, Operation, Schema, Snapshot, SnapshotReference, SnapshotRetention, Summary, Type,
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
/// The catalog round trips of one attempt (session, load, commit).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(120);
/// NAN-4614: plus target preparation, which verifies every added byte (a
/// full read for hosted references): budgeted at this floor rate, so a
/// bounded batch is never cut off by a timeout sized for metadata alone.
pub(crate) const ATTEMPT_PREPARE_BYTES_PER_SEC: u64 = 8 * 1024 * 1024;
const ATTEMPT_TIMEOUT_MAX: Duration = Duration::from_secs(600);
const ATTEMPTS: usize = 3;
const STAGE_SESSION: usize = 0;
const STAGE_PREPARE: usize = 1;
const STAGE_SNAPSHOT: usize = 2;
const STAGE_COMMIT: usize = 3;
const TIMED_OUT_IN: [&str; 4] = [
    "attempt_timeout_catalog_session",
    "attempt_timeout_target_prepare",
    "attempt_timeout_snapshot_write",
    "attempt_timeout_commit",
];

/// The bound on one commit attempt of `manifest`. This is NOT the caller's
/// sync budget: the lifecycle sync bounds how many batches it starts, each
/// commit bounds only its own attempts.
pub(crate) fn attempt_timeout(manifest: &ExportManifest) -> Duration {
    let bytes = manifest.add.iter().fold(0u64, |sum, part| sum.saturating_add(part.bytes));
    (ATTEMPT_TIMEOUT + Duration::from_secs(bytes / ATTEMPT_PREPARE_BYTES_PER_SEC)).min(ATTEMPT_TIMEOUT_MAX)
}

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
    lifecycle: bool,
    platform_auth: Option<(
        Arc<super::platform_tls::PlatformCatalogClient>,
        String,
        Arc<dyn iceberg::io::StorageFactory>,
    )>,
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
            lifecycle: false,
            platform_auth: None,
        })
    }

    #[cfg_attr(not(feature = "enterprise"), allow(dead_code))]
    pub(super) fn for_frozen_erasure(mut self) -> Self {
        self.frozen_erasure = true;
        self
    }

    pub(super) fn for_lifecycle(mut self) -> Self {
        self.lifecycle = true;
        self
    }

    pub(super) fn with_platform_auth(
        mut self,
        client: Arc<super::platform_tls::PlatformCatalogClient>,
        token: String,
        storage: Arc<dyn iceberg::io::StorageFactory>,
    ) -> Self {
        self.platform_auth = Some((client, token, storage));
        self
    }

    async fn load_catalog(&self) -> Result<iceberg_catalog_rest::RestCatalog> {
        let (token, client, storage) = if let Some((client, token, storage)) = &self.platform_auth {
            (
                Some(token.as_str()),
                Some(client.iceberg_client()?),
                Some(storage.clone()),
            )
        } else {
            (None, None, None)
        };
        self.config.load_with_bearer(token, client, storage).await
    }

    async fn commit_client(&self) -> Result<RestTableCommitClient> {
        let (token, client) = self
            .platform_auth
            .as_ref()
            .map_or((None, None), |(client, token, _storage)| {
                (Some(token.as_str()), Some(client.client()))
            });
        RestTableCommitClient::new_with_bearer(&self.config, &self.table_id, token, client).await
    }

    pub fn table_id(&self) -> &TableIdent {
        &self.table_id
    }

    /// NAN-4782: this table's current snapshot as reusable catalog entries
    /// (metadata reads only: the manifest list and its manifests).
    pub(crate) async fn live_entries(&self) -> Result<LiveEntries> {
        let catalog = self
            .load_catalog()
            .await
            .map_err(|_| anyhow::anyhow!("catalog live-entry session unavailable"))?;
        if !catalog
            .table_exists(&self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog live-entry lookup unavailable"))?
        {
            return Ok(LiveEntries::default());
        }
        let table = catalog
            .load_table(&self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("catalog live-entry table unavailable"))?;
        self.table
            .contract
            .validate_table(&table, &self.table.tenant_id, &self.table.location)?;
        live_entries_of(&table, &self.table.data_prefix, self.table.max_files).await
    }

    /// NAN-4782: make this table hold exactly `entries` (the master's live
    /// data files, with the master's checkpoint and digest) in ONE metadata
    /// commit. No part file is read: every entry was verified (signed
    /// provenance, bytes, footer) when the master committed it. Idempotent:
    /// a table already holding exactly `entries` at that checkpoint is a no-op.
    pub(crate) async fn seed(&self, entries: &LiveEntries) -> Result<()> {
        for attempt in 0..ATTEMPTS {
            let stage = match tokio::time::timeout(ATTEMPT_TIMEOUT, self.seed_attempt(entries)).await {
                Ok(Ok(Ok(()))) => return Ok(()),
                Ok(Err(error)) => return Err(error),
                Ok(Ok(Err(stage))) => stage,
                Err(_) => "attempt_timeout_seed",
            };
            tracing::warn!(attempt = attempt + 1, stage, "serving epoch seed attempt did not land");
            if attempt + 1 < ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(250 * (1 << attempt))).await;
            }
        }
        bail!("serving epoch seed exhausted bounded retries")
    }

    async fn seed_attempt(&self, entries: &LiveEntries) -> Result<std::result::Result<(), &'static str>> {
        ensure!(!self.frozen_erasure, "a frozen table is never seeded");
        let creation_schema = seed_creation_schema(entries, &self.table.contract)?;
        let catalog = self
            .load_catalog()
            .await
            .map_err(|_| anyhow::anyhow!("seed catalog session failed"))?;
        if !catalog
            .namespace_exists(&self.table_id.namespace)
            .await
            .map_err(|_| anyhow::anyhow!("seed namespace lookup failed"))?
            && catalog
                .create_namespace(&self.table_id.namespace, HashMap::new())
                .await
                .is_err()
        {
            return Ok(Err("create_namespace"));
        }
        if !catalog
            .table_exists(&self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("seed table lookup failed"))?
        {
            let creation = TableCreation::builder()
                .name(self.table_id.name.clone())
                .location(self.table.location.clone())
                .schema(creation_schema)
                .properties(self.table.contract.properties(&self.table.tenant_id))
                .build();
            if catalog.create_table(&self.table_id.namespace, creation).await.is_err() {
                return Ok(Err("create_table"));
            }
        }
        let table = catalog
            .load_table(&self.table_id)
            .await
            .map_err(|_| anyhow::anyhow!("seed table load failed"))?;
        self.table
            .contract
            .validate_table(&table, &self.table.tenant_id, &self.table.location)?;
        let Some(prepared) = prepare_seed(&table, entries, &self.table.contract, &self.table.data_prefix, self.table.max_files).await? else {
            return Ok(Ok(()));
        };
        let (snapshot_id, schema_id, requirements, updates) = prepared;
        let client = self
            .commit_client()
            .await
            .map_err(|_| anyhow::anyhow!("seed REST session failed"))?;
        match client.commit(requirements, updates).await {
            Ok(CommitOutcome::Committed(response)) => {
                ensure!(
                    response.metadata.properties().get(DIGEST) == entries.digest.as_ref()
                        && response.metadata.properties().get(CHECKPOINT)
                            == entries.checkpoint.map(|c| c.to_string()).as_ref()
                        && response.metadata.current_snapshot_id() == Some(snapshot_id)
                        && response.metadata.current_schema_id() == schema_id
                        && entries.schema.as_deref().is_some_and(|source|
                            response.metadata.current_schema().as_struct() == source.as_struct())
                        && response.metadata.uuid() == table.metadata().uuid(),
                    "seed commit response omitted checkpoint or source schema"
                );
                tracing::info!(files = entries.files.len(), parts = entries.parts.len(),
                    "serving epoch seeded from the master's catalog entries; no part file read");
                Ok(Ok(()))
            }
            Ok(CommitOutcome::Conflict) => Ok(Err("commit_conflict")),
            Err(_) => Ok(Err("commit_transport")),
        }
    }

    /// `Ok(Ok(()))`: the manifest is in the catalog. `Ok(Err(stage))`: this
    /// bounded attempt did not land and may be retried; `stage` is value-free.
    async fn attempt(
        &self,
        manifest: &ExportManifest,
        reached: &std::sync::atomic::AtomicUsize,
    ) -> Result<std::result::Result<(), &'static str>> {
        use std::sync::atomic::Ordering::Relaxed;
        // NAN-4614: name the slow stage. Value-free: counts and timings only.
        let started = std::time::Instant::now();
        reached.store(STAGE_SESSION, Relaxed);
        // Rebuild both sessions on every bounded attempt, proactively acquiring
        // fresh OAuth/workload tokens before hourly work (no 3600s token cache).
        let catalog = self
            .load_catalog()
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
                return Ok(Err("create_namespace"));
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
                return Ok(Err("create_table"));
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
            tracing::debug!(load_ms = started.elapsed().as_millis() as u64, "export batch already at the catalog checkpoint");
            return Ok(Ok(()));
        }
        let loaded_ms = started.elapsed().as_millis() as u64;
        reached.store(STAGE_PREPARE, Relaxed);
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
        let prepared_ms = started.elapsed().as_millis() as u64;
        reached.store(STAGE_SNAPSHOT, Relaxed);
        let (snapshot, snapshot_requirements) = prepare_snapshot_with_removals(
            &table,
            manifest,
            files,
            &schema,
            &self.table.data_prefix,
            self.table.max_files,
            self.frozen_erasure,
            self.lifecycle,
        )
        .await
        .map_err(|_| anyhow::anyhow!("export snapshot preparation failed"))?;
        let snapshot_ms = started.elapsed().as_millis() as u64;
        reached.store(STAGE_COMMIT, Relaxed);
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
        let client = self
            .commit_client()
            .await
            .map_err(|_| anyhow::anyhow!("export REST session failed"))?;
        let outcome = client.commit(requirements, updates).await;
        tracing::info!(
            parts = manifest.add.len(),
            removed = manifest.remove_parts.len(),
            bytes = manifest.add.iter().fold(0u64, |sum, part| sum.saturating_add(part.bytes)),
            load_ms = loaded_ms,
            prepare_ms = prepared_ms - loaded_ms,
            snapshot_ms = snapshot_ms - prepared_ms,
            commit_ms = started.elapsed().as_millis() as u64 - snapshot_ms,
            committed = matches!(outcome, Ok(CommitOutcome::Committed(_))),
            "export commit attempt stages"
        );
        match outcome {
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
                Ok(Ok(()))
            }
            // Transport errors include ambiguous successes. Reload/check the
            // catalog checkpoint on retry, never blindly append the same files.
            Ok(CommitOutcome::Conflict) => Ok(Err("commit_conflict")),
            Err(_) => Ok(Err("commit_transport")),
        }
    }
}

#[async_trait::async_trait]
impl IcebergCommitter for RestIcebergCommitter {
    async fn commit(&self, manifest: &ExportManifest) -> Result<()> {
        validate_manifest(manifest, &self.table.tenant_id, self.table.max_files)?;
        for attempt in 0..ATTEMPTS {
            // NAN-4612: a retryable miss used to vanish into the final
            // "exhausted" error; name the stage (value-free) per attempt.
            // NAN-4614: a timeout also names the stage it cut off.
            let reached = std::sync::atomic::AtomicUsize::new(STAGE_SESSION);
            let stage = match tokio::time::timeout(attempt_timeout(manifest), self.attempt(manifest, &reached)).await {
                Ok(Ok(Ok(()))) => return Ok(()),
                Ok(Err(error)) => return Err(error),
                Ok(Ok(Err(stage))) => stage,
                Err(_) => TIMED_OUT_IN[reached.load(std::sync::atomic::Ordering::Relaxed)],
            };
            if attempt + 1 < ATTEMPTS {
                tracing::warn!(attempt = attempt + 1, stage, "export commit attempt did not land; retrying within bound");
            } else {
                tracing::warn!(attempt = attempt + 1, stage, "export commit attempt did not land; bound exhausted");
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
    checkpoint_decision(previous, properties.get(DIGEST).map(String::as_str), manifest)
}

/// The catalog-side ordering rule, shared with test catalogs so a fixture
/// enforces exactly the predecessor chain the REST committer does.
pub(crate) fn checkpoint_decision(
    previous: Option<i64>,
    digest: Option<&str>,
    manifest: &ExportManifest,
) -> Result<bool> {
    if let Some(previous) = previous {
        if manifest.planned_at_ms < previous {
            return Ok(true);
        }
        if manifest.planned_at_ms == previous {
            ensure!(
                digest == Some(manifest_digest(manifest)?.as_str()),
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

/// NAN-4627: the remote export chain head. After a cell roll wipes the
/// writer's `export/state.json`, this (not a guess) is what the writer
/// rebuilds its predecessor and per-hour export state from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportHead {
    /// The table's `nano.export.planned_at_ms`; `None` for a table that has
    /// never committed an export (or does not exist yet).
    pub checkpoint: Option<i64>,
    /// Part id -> event hour (from its data-file key) of every live file in
    /// the current snapshot. Empty unless requested.
    pub parts: BTreeMap<String, i32>,
}

/// The remote export state cannot be trusted as a predecessor. Fails closed;
/// `reason` is a stable, value-free alert label.
#[derive(Debug, thiserror::Error)]
#[error("catalog export state cannot be rebuilt: {reason}")]
pub struct ExportStateUnrecoverable {
    pub reason: &'static str,
}

impl ExportStateUnrecoverable {
    pub const CODE: &'static str = "export_state_unrecoverable";
}

/// Read the export chain head from one loaded table version.
pub(crate) async fn export_head_of(
    table: &Table,
    prefix: &str,
    max_files: usize,
    with_parts: bool,
) -> Result<ExportHead> {
    let checkpoint = match table.metadata().properties().get(CHECKPOINT) {
        None => None,
        Some(value) => match value.parse::<i64>() {
            Ok(at) if at > 0 => Some(at),
            _ => {
                return Err(ExportStateUnrecoverable {
                    reason: "remote export checkpoint is malformed",
                }
                .into())
            }
        },
    };
    let Some(snapshot) = table.metadata().current_snapshot() else {
        return Ok(ExportHead { checkpoint, parts: BTreeMap::new() });
    };
    if checkpoint.is_none() {
        return Err(ExportStateUnrecoverable {
            reason: "remote catalog holds a snapshot without an export checkpoint",
        }
        .into());
    }
    let mut parts = BTreeMap::new();
    if !with_parts {
        return Ok(ExportHead { checkpoint, parts });
    }
    let list = table.manifest_list_reader(snapshot).load().await?;
    ensure!(list.entries().len() <= max_files, "export manifest list exceeds bound");
    let mut inspected = 0usize;
    for descriptor in list.entries() {
        ensure!(
            descriptor.content == ManifestContentType::Data && descriptor.partition_spec_id == 0,
            "unsupported export manifest content"
        );
        let loaded = descriptor.load_manifest(table.file_io()).await?;
        inspected = inspected
            .checked_add(loaded.entries().len())
            .ok_or_else(|| anyhow::anyhow!("export entry count overflow"))?;
        ensure!(inspected <= max_files, "export table exceeds file bound");
        for entry in loaded.entries().iter().filter(|e| e.is_alive()) {
            let part = part_id_from_path(entry.file_path(), prefix)?;
            let hour = event_hour_of_path(entry.file_path())?;
            ensure!(
                *parts.entry(part.to_string()).or_insert(hour) == hour,
                "export part spans two key hours"
            );
        }
    }
    Ok(ExportHead { checkpoint, parts })
}

/// NAN-4782: one table's current snapshot as catalog entries a fresh serving
/// epoch can reuse verbatim: the live data files (path, size, record count,
/// partition, any column stats) plus the export checkpoint and digest. Only
/// LIVE entries are carried. A lifecycle table never writes removal
/// tombstones (bounds-bearing entries of erased parts), so these are all of
/// its current snapshot; `all_parts` counts every entry anyway, so a caller
/// can refuse a source whose metadata still names anything else.
#[derive(Debug, Clone, Default)]
pub(crate) struct LiveEntries {
    pub checkpoint: Option<i64>,
    pub digest: Option<String>,
    /// File field IDs belong to this schema, including after additive growth.
    pub schema: Option<Arc<Schema>>,
    pub files: Vec<DataFile>,
    /// Part ids of the live files.
    pub parts: BTreeSet<String>,
    /// Part ids of EVERY entry of the current snapshot (live or not).
    pub all_parts: BTreeSet<String>,
}

/// Bound on entries per manifest a seed writes (one snapshot, several
/// manifests when the live set is large).
const SEED_MANIFEST_ENTRIES: usize = 8_192;

pub(crate) async fn live_entries_of(table: &Table, prefix: &str, max_files: usize) -> Result<LiveEntries> {
    let properties = table.metadata().properties();
    let checkpoint = match properties.get(CHECKPOINT) {
        None => None,
        Some(value) => Some(value.parse::<i64>().ok().filter(|at| *at > 0).ok_or(ExportStateUnrecoverable {
            reason: "remote export checkpoint is malformed",
        })?),
    };
    let digest = properties.get(DIGEST).cloned();
    let Some(snapshot) = table.metadata().current_snapshot() else {
        return Ok(LiveEntries { checkpoint, digest, schema: Some(table.metadata().current_schema().clone()), ..LiveEntries::default() });
    };
    ensure!(checkpoint.is_some() && digest.is_some(), ExportStateUnrecoverable {
        reason: "remote catalog holds a snapshot without an export checkpoint",
    });
    let list = table.manifest_list_reader(snapshot).load().await?;
    ensure!(list.entries().len() <= max_files, "export manifest list exceeds bound");
    let mut entries = LiveEntries { checkpoint, digest, schema: Some(table.metadata().current_schema().clone()), ..LiveEntries::default() };
    let mut paths = BTreeSet::new();
    let mut inspected = 0usize;
    for descriptor in list.entries() {
        ensure!(
            descriptor.content == ManifestContentType::Data && descriptor.partition_spec_id == 0,
            "unsupported export manifest content"
        );
        let loaded = descriptor.load_manifest(table.file_io()).await?;
        inspected = inspected
            .checked_add(loaded.entries().len())
            .ok_or_else(|| anyhow::anyhow!("export entry count overflow"))?;
        ensure!(inspected <= max_files, "export table exceeds file bound");
        for entry in loaded.entries() {
            let part = part_id_from_path(entry.file_path(), prefix)?.to_string();
            entries.all_parts.insert(part.clone());
            if entry.is_alive() {
                ensure!(paths.insert(entry.file_path().to_string()), "duplicate live export file");
                entries.parts.insert(part);
                entries.files.push(entry.data_file().clone());
            }
        }
    }
    Ok(entries)
}

/// The live file paths of `table`'s current snapshot.
async fn live_paths_of(table: &Table, max_files: usize) -> Result<BTreeSet<String>> {
    let mut paths = BTreeSet::new();
    let Some(snapshot) = table.metadata().current_snapshot() else {
        return Ok(paths);
    };
    let list = table.manifest_list_reader(snapshot).load().await?;
    ensure!(list.entries().len() <= max_files, "export manifest list exceeds bound");
    for descriptor in list.entries() {
        let loaded = descriptor.load_manifest(table.file_io()).await?;
        for entry in loaded.entries().iter().filter(|e| e.is_alive()) {
            paths.insert(entry.file_path().to_string());
            ensure!(paths.len() <= max_files, "export table exceeds file bound");
        }
    }
    Ok(paths)
}

pub(crate) type SeedCommit = (i64, i32, Vec<TableRequirement>, Vec<TableUpdate>);

#[derive(Debug, thiserror::Error)]
#[error("serving epoch field IDs differ from the master; a fresh name is required")]
pub(crate) struct SeedSchemaMismatch;

/// The public metadata builder applies the same ID assignment as catalog
/// creation, while preserving defaults and types that an Arrow round trip
/// could change. This constructs no files or catalog table.
fn canonical_seed_schema(source: &Schema) -> Result<Schema> {
    let metadata = iceberg::spec::TableMetadataBuilder::from_table_creation(
        TableCreation::builder().name("seed_schema".to_string())
            .location("s3://seed-schema/table".to_string()).schema(source.clone()).build(),
    )?.build()?.metadata;
    Ok(metadata.current_schema().as_ref().clone())
}

/// Catalog creation reassigns IDs breadth-first. Start from the canonical
/// prefix of the master's schema, then add its remaining optional fields in
/// the seed commit with their original IDs. Creating from the full evolved
/// schema would renumber old nested fields when a later top-level field exists.
fn seed_creation_schema(entries: &LiveEntries, contract: &SchemaContract) -> Result<Schema> {
    let Some(source) = entries.schema.as_deref() else {
        ensure!(entries.checkpoint.is_none(), "seed source has no schema");
        return Ok(contract.schema.clone());
    };
    let mut prefix = source.clone();
    loop {
        let canonical = canonical_seed_schema(&prefix)?;
        let mut fields = prefix.as_struct().fields().iter().zip(canonical.as_struct().fields()).collect::<Vec<_>>();
        let mut cutoff = None;
        while let Some((old, fresh)) = fields.pop() {
            if fresh.id < old.id {
                cutoff = Some(cutoff.map_or(old.id, |at: i32| at.min(old.id)));
            }
            match (old.field_type.as_ref(), fresh.field_type.as_ref()) {
                (Type::Struct(a), Type::Struct(b)) => fields.extend(a.fields().iter().zip(b.fields())),
                (Type::List(a), Type::List(b)) => fields.push((&a.element_field, &b.element_field)),
                (Type::Map(a), Type::Map(b)) => {
                    fields.push((&a.key_field, &b.key_field));
                    fields.push((&a.value_field, &b.value_field));
                }
                _ => {}
            }
        }
        let cutoff = match cutoff {
            Some(cutoff) => cutoff,
            None => {
                ensure!(prefix.as_struct() == canonical.as_struct(),
                    "seed schema prefix does not preserve master field IDs");
                if seed_fields_extend(prefix.as_struct().fields(), source.as_struct().fields()) {
                    return Ok(prefix);
                }
                // A new optional parent may contain required children. If
                // projection split that group, remove more of the addition
                // until the whole parent can be added atomically instead.
                let cutoff = prefix.highest_field_id();
                ensure!(cutoff > 0, "seed schema has no additive creation prefix");
                cutoff
            }
        };
        let next = Schema::builder()
            .with_fields(source.as_struct().fields().iter().filter_map(|field| seed_prefix_field(field, cutoff)))
            .with_identifier_field_ids(source.identifier_field_ids())
            .build()?;
        ensure!(next.highest_field_id() < cutoff && cutoff <= prefix.highest_field_id(),
            "seed schema prefix did not shrink");
        // Removing a later field can reveal an earlier reassignment that its
        // position had masked. Recompute until creation preserves every ID.
        prefix = next;
    }
}

/// Project an ID prefix while keeping map keys whole. Unlike a query-column
/// projection this must never pull in a map's values just because its key was
/// selected, or panic when a projected map value is an empty struct.
fn seed_prefix_field(field: &NestedFieldRef, cutoff: i32) -> Option<NestedFieldRef> {
    if field.id >= cutoff { return None; }
    let mut projected = field.as_ref().clone();
    projected.field_type = Box::new(match field.field_type.as_ref() {
        Type::Primitive(value) => Type::Primitive(value.clone()),
        Type::Struct(value) => Type::Struct(iceberg::spec::StructType::new(value.fields().iter()
            .filter_map(|child| seed_prefix_field(child, cutoff)).collect())),
        Type::List(value) => Type::List(iceberg::spec::ListType::new(seed_prefix_field(&value.element_field, cutoff)?)),
        Type::Map(value) => {
            let key = seed_prefix_field(&value.key_field, cutoff)?;
            if key != value.key_field { return None; }
            Type::Map(iceberg::spec::MapType::new(key, seed_prefix_field(&value.value_field, cutoff)?))
        }
    });
    Some(Arc::new(projected))
}

fn seed_fields_extend(old: &[NestedFieldRef], source: &[NestedFieldRef]) -> bool {
    old.iter().all(|field| source.iter().find(|next| next.id == field.id)
        .is_some_and(|next| seed_field_extends(field, next)))
        && source.iter().all(|field| old.iter().any(|old| old.id == field.id) || !field.required)
}

fn seed_field_extends(old: &NestedFieldRef, source: &NestedFieldRef) -> bool {
    let mut comparable = source.as_ref().clone();
    comparable.field_type = old.field_type.clone();
    if &comparable != old.as_ref() { return false; }
    match (old.field_type.as_ref(), source.field_type.as_ref()) {
        (Type::Struct(a), Type::Struct(b)) => seed_fields_extend(a.fields(), b.fields()),
        (Type::List(a), Type::List(b)) => seed_field_extends(&a.element_field, &b.element_field),
        (Type::Map(a), Type::Map(b)) => a.key_field == b.key_field && seed_field_extends(&a.value_field, &b.value_field),
        (a, b) => a == b,
    }
}

/// Preserve the master's IDs rather than running the epoch's independent ID
/// allocator. This is an additive schema update accepted by the platform; it
/// accompanies the snapshot in the same atomic commit.
fn seed_schema_updates(table: &Table, entries: &LiveEntries, contract: &SchemaContract) -> Result<(Schema, Vec<TableRequirement>, Vec<TableUpdate>)> {
    let source = entries.schema.as_deref().ok_or_else(|| anyhow::anyhow!("seed source has no schema"))?;
    let current = table.metadata().current_schema();
    ensure!(seed_fields_extend(current.as_struct().fields(), source.as_struct().fields())
        && current.identifier_field_ids().collect::<BTreeSet<_>>() == source.identifier_field_ids().collect::<BTreeSet<_>>()
        && source.field_id_to_fields().keys().all(|id| current.field_by_id(*id).is_some() || *id > table.metadata().last_column_id()),
        SeedSchemaMismatch);
    let mut requirements = vec![TableRequirement::CurrentSchemaIdMatch { current_schema_id: current.schema_id() }];
    let mut updates = vec![];
    let schema = if current.as_struct() == source.as_struct() {
        current.as_ref().clone()
    } else {
        let id = table.metadata().schemas_iter().map(|schema| schema.schema_id()).max().unwrap_or(0)
            .checked_add(1).ok_or_else(|| anyhow::anyhow!("seed schema ID exhausted"))?;
        let schema = source.clone().into_builder().with_schema_id(id).build()?;
        requirements.push(TableRequirement::LastAssignedFieldIdMatch { last_assigned_field_id: table.metadata().last_column_id() });
        updates.extend([TableUpdate::AddSchema { schema: schema.clone() }, TableUpdate::SetCurrentSchema { schema_id: id }]);
        schema
    };
    updates.push(TableUpdate::SetProperties { updates: HashMap::from([
        (schema::OCSF_VERSION.to_string(), contract.ocsf_version.clone()),
        (iceberg::spec::DEFAULT_SCHEMA_NAME_MAPPING.to_string(), serde_json::to_string(&schema::name_mapping(&schema))?),
    ]) });
    Ok((schema, requirements, updates))
}

/// NAN-4782: the one metadata-only commit that makes `table` hold exactly
/// `entries`. `None`: it already does (same checkpoint, digest and live
/// files), so a retried seed whose response was lost commits nothing. The
/// new snapshot lists ONLY `entries` (whatever an earlier, unpublished
/// attempt left is dropped from the current snapshot and expired by the
/// caller's inspection before any publish). Its checkpoint and digest are the
/// source's, so the master's next delta continues this table's chain.
pub(crate) async fn prepare_seed(
    table: &Table,
    entries: &LiveEntries,
    contract: &SchemaContract,
    prefix: &str,
    max_files: usize,
) -> Result<Option<SeedCommit>> {
    let properties = table.metadata().properties();
    let current = properties.get(CHECKPOINT).map(|v| v.parse::<i64>()).transpose()?;
    let wanted = entries.files.iter().map(|f| f.file_path().to_string()).collect::<BTreeSet<_>>();
    ensure!(wanted.len() == entries.files.len(), "duplicate seed file");
    ensure!(wanted.len() <= max_files, "seed exceeds file bound");
    for path in &wanted {
        part_id_from_path(path, prefix)?;
    }
    let Some(checkpoint) = entries.checkpoint else {
        // The source never committed: an empty table is already its equal.
        ensure!(
            table.metadata().current_snapshot().is_none() && current.is_none(),
            "seed source has no checkpoint but the epoch holds a snapshot"
        );
        return Ok(None);
    };
    let digest = entries.digest.clone().ok_or_else(|| anyhow::anyhow!("seed source has no digest"))?;
    ensure!(current.is_none_or(|at| at <= checkpoint), "serving epoch is ahead of the master");
    let (schema, mut requirements, mut updates) = seed_schema_updates(table, entries, contract)?;
    let present = live_paths_of(table, max_files).await?;
    if current == Some(checkpoint) && properties.get(DIGEST) == Some(&digest) && present == wanted
        && table.metadata().current_schema().as_struct() == schema.as_struct() {
        return Ok(None);
    }
    let parent = table.metadata().current_snapshot().map(|s| s.snapshot_id());
    let sequence = table.metadata().next_sequence_number();
    let snapshot_id = (u64::from_be_bytes(
        Sha256::digest(format!("seed:{digest}:{checkpoint}:{parent:?}")).as_slice()[..8].try_into()?,
    ) & i64::MAX as u64) as i64;
    ensure!(
        snapshot_id > 0 && table.metadata().snapshot_by_id(snapshot_id).is_none(),
        "seed snapshot identity collision"
    );
    // The platform's metadata PUT constructor accepts exactly
    // `export-<uuid>.avro` / `export-<uuid>-list.avro` (one UUID each).
    let location = table.metadata().location().trim_end_matches('/').to_string();
    let mut descriptors = Vec::new();
    let (mut rows, mut bytes) = (0u64, 0u64);
    for chunk in entries.files.chunks(SEED_MANIFEST_ENTRIES) {
        let mut writer = ManifestWriterBuilder::new(
            table.file_io().new_output(format!("{location}/metadata/export-{}.avro", uuid::Uuid::new_v4()))?,
            Some(snapshot_id),
            Arc::new(schema.clone()),
            table.metadata().default_partition_spec().as_ref().clone(),
        )
        .build_v2_data();
        for file in chunk {
            ensure!(
                file.content_type() == DataContentType::Data
                    && file.file_format() == DataFileFormat::Parquet
                    && file.partition().fields().is_empty(),
                "invalid seed data file"
            );
            rows = rows.checked_add(file.record_count()).ok_or_else(|| anyhow::anyhow!("seed row count overflow"))?;
            bytes = bytes.checked_add(file.file_size_in_bytes()).ok_or_else(|| anyhow::anyhow!("seed byte count overflow"))?;
            writer.add_file(file.clone(), sequence)?;
        }
        descriptors.push(writer.write_manifest_file().await?);
    }
    let list_path = format!("{location}/metadata/export-{}-list.avro", uuid::Uuid::new_v4());
    let mut list = ManifestListWriter::v2(
        table.file_io().new_output(&list_path)?.writer().await?,
        snapshot_id,
        parent,
        sequence,
    );
    list.add_manifests(descriptors.into_iter())?;
    list.close().await?;
    let snapshot = Snapshot::builder()
        .with_snapshot_id(snapshot_id)
        .with_parent_snapshot_id(parent)
        .with_sequence_number(sequence)
        .with_timestamp_ms(chrono::Utc::now().timestamp_millis())
        .with_manifest_list(list_path)
        .with_schema_id(schema.schema_id())
        .with_summary(Summary {
            operation: if present.is_empty() { Operation::Append } else { Operation::Overwrite },
            additional_properties: HashMap::from([
                (DIGEST.to_string(), digest.clone()),
                ("total-data-files".to_string(), wanted.len().to_string()),
                ("total-records".to_string(), rows.to_string()),
                ("total-files-size".to_string(), bytes.to_string()),
                ("added-data-files".to_string(), wanted.len().to_string()),
                ("deleted-data-files".to_string(), present.len().to_string()),
            ]),
        })
        .build();
    requirements.extend([
        TableRequirement::UuidMatch { uuid: table.metadata().uuid() },
        TableRequirement::RefSnapshotIdMatch { r#ref: MAIN_BRANCH.to_string(), snapshot_id: parent },
        TableRequirement::DefaultSpecIdMatch { default_spec_id: 0 },
    ]);
    updates.extend([
        TableUpdate::AddSnapshot { snapshot },
        TableUpdate::SetSnapshotRef {
            ref_name: MAIN_BRANCH.to_string(),
            reference: SnapshotReference::new(snapshot_id, SnapshotRetention::branch(None, None, None)),
        },
        TableUpdate::SetProperties {
            updates: HashMap::from([
                (CHECKPOINT.to_string(), checkpoint.to_string()),
                (DIGEST.to_string(), digest),
            ]),
        },
    ]);
    Ok(Some((snapshot_id, schema.schema_id(), requirements, updates)))
}

/// The event hour encoded in a part data file's key (a day part's first hour).
pub(crate) fn event_hour_of_path(path: &str) -> Result<i32> {
    let parsed =
        reqwest::Url::parse(path).map_err(|_| anyhow::anyhow!("invalid export object URI"))?;
    let key = crate::lake_part_gc::parse_part_file_key(parsed.path().trim_start_matches('/'))
        .ok_or_else(|| anyhow::anyhow!("export data file key has no event hour"))?;
    i32::try_from(key.path_hour.timestamp().div_euclid(3_600))
        .map_err(|_| anyhow::anyhow!("export data file hour out of range"))
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

/// Customer v2 append/overwrite/delete snapshot, retaining removal tombstones.
#[cfg(test)]
pub(super) async fn prepare_snapshot_inner(
    table: &Table,
    manifest: &ExportManifest,
    added: BTreeMap<String, Vec<DataFile>>,
    schema: &iceberg::spec::Schema,
    prefix: &str,
    max_files: usize,
    frozen_erasure: bool,
) -> Result<(Snapshot, Vec<TableRequirement>)> {
    prepare_snapshot_with_removals(table, manifest, added, schema, prefix, max_files, frozen_erasure, false).await
}

#[cfg(test)]
pub(super) async fn prepare_lifecycle_snapshot(
    table: &Table,
    manifest: &ExportManifest,
    added: BTreeMap<String, Vec<DataFile>>,
    schema: &iceberg::spec::Schema,
    prefix: &str,
    max_files: usize,
) -> Result<(Snapshot, Vec<TableRequirement>)> {
    prepare_snapshot_with_removals(table, manifest, added, schema, prefix, max_files, false, true).await
}

async fn prepare_snapshot_with_removals(
    table: &Table,
    manifest: &ExportManifest,
    added: BTreeMap<String, Vec<DataFile>>,
    schema: &iceberg::spec::Schema,
    prefix: &str,
    max_files: usize,
    frozen_erasure: bool,
    lifecycle: bool,
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
            // Only lifecycle custody omits bounds-bearing removal entries.
            // Preserve the existing customer export tombstone behavior.
            if !lifecycle {
                writer.add_delete_file(entry.data_file().clone(), sequence, entry.file_sequence_number)?;
            }
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
