// SPDX-License-Identifier: AGPL-3.0-or-later
//! Inventory the exact archived config using the executor's verification plan.
//! Unsupported external read graphs fail explicitly, never produce a descriptor.

use super::*;
use crate::config::WorkerConfigFile;
use crate::generation::{verify_hot_tail_manifest, ObjectStampManifest};
use crate::verify::VerifyJob;

pub struct Inventory {
    pub descriptor: Descriptor,
    pub sources: BTreeMap<String, PathBuf>,
}

/// Caller holds the existing generation admission guard plus tail cache lease.
/// `tail_sources` maps signed source URIs to the exact hydrated local objects.
/// It is deliberately not a callback that can fetch a current/latest manifest.
#[allow(clippy::too_many_arguments)]
pub async fn capture(
    tenant_id: Uuid,
    logical_tenant_id: &str,
    assignment_revision: u64,
    executor_abi: &str,
    pin: DurableLakeGenerationPin,
    config_path: &Path,
    tail_path: Option<&Path>,
    tail_sources: &BTreeMap<String, PathBuf>,
) -> Result<Inventory> {
    pin.validate()?;
    let config_bytes = std::fs::read(config_path)?;
    let config: WorkerConfigFile = serde_json::from_slice(&config_bytes)?;
    if crate::config::event_config_sha256(&config_bytes)? != pin.event_config_sha256
        || config.assigned_tenant_id != logical_tenant_id
        || config.tenant.tenant_id != logical_tenant_id
        || config.compiler.sha256 != pin.compiler_sha256
        || config.native_library.sha256 != pin.native_artifact_sha256
    {
        bail!("archived configuration differs from admission identity");
    }
    if config.risk_snapshot.is_some() || config.ioc_snapshot.is_some() {
        bail!("admission completeness gap: mutable state remains in event archive");
    }
    let cache = config.snapshot_cache.as_ref().context(
        "admission completeness gap: remote Iceberg read graph without exact snapshot cache",
    )?;
    let plan = config.verification_plan(false);
    let jobs = plan.jobs().to_vec();
    plan.run(crate::verify::verify_workers())?;
    let mut inventory = Inventory {
        descriptor: Descriptor {
            contract: CONTRACT,
            tenant_id,
            logical_tenant_id: logical_tenant_id.into(),
            assignment_revision,
            executor_abi: executor_abi.into(),
            pin,
            dependencies: Vec::new(),
            secrets: vec![SecretReference {
                purpose: "entity-tail-hmac".into(),
                sha256: config.entity_sidecar.hmac_key.sha256.clone(),
            }],
        },
        sources: BTreeMap::new(),
    };
    inventory.file(
        "worker-config",
        config_path,
        Some(&digest(&config_bytes)),
        false,
    )?;
    inventory.file(
        "compiler",
        &config.compiler.path,
        Some(&config.compiler.sha256),
        true,
    )?;
    inventory.file(
        "native-library",
        &config.native_library.path,
        Some(&config.native_library.sha256),
        false,
    )?;
    for job in jobs {
        match job {
            VerifyJob::File {
                path,
                expected_sha256,
            } => {
                if path == config.entity_sidecar.hmac_key.path || path == config.compiler.path {
                    continue;
                }
                inventory.file(
                    &format!("file:{}", path.display()),
                    &path,
                    Some(&expected_sha256),
                    false,
                )?;
            }
            VerifyJob::Tree {
                directory,
                expected_sha256,
                label,
            } => {
                let mut members =
                    std::fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
                members.sort_by_key(std::fs::DirEntry::file_name);
                for member in members {
                    if member.file_name().to_string_lossy().ends_with(".lock") {
                        continue;
                    }
                    let path = member.path();
                    inventory.file(&format!("file:{}", path.display()), &path, None, false)?;
                }
                // Recheck the tree after inventory to detect a changed member set.
                if crate::config::index_directory_sha256(&directory, &label)?.0 != expected_sha256 {
                    bail!("admission dependency tree changed during inventory");
                }
            }
        }
    }
    for snapshot in config.prevalence_snapshots.values() {
        if snapshot.object_store_url != "file:///" {
            bail!("admission completeness gap: unsupported prevalence object store");
        }
        inventory
            .checkpoint(&snapshot.database_path, snapshot.checkpoint_id)
            .await?;
    }
    let stamps: ObjectStampManifest =
        serde_json::from_slice(&std::fs::read(&cache.object_stamp_manifest.path)?)?;
    if stamps.snapshot_id != inventory.descriptor.pin.snapshot_id
        || inventory
            .descriptor
            .pin
            .iceberg_metadata_location
            .as_ref()
            .is_some_and(|p| p != &stamps.metadata_location)
    {
        bail!("snapshot cache differs from accepted snapshot/metadata pin");
    }
    for stamp in stamps.objects {
        let relative = Path::new(&stamp.relative_path);
        if relative.is_absolute()
            || !relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            bail!("unsafe snapshot dependency path");
        }
        let path = cache.data_directory.join(relative);
        let locator = format!("file:{}", path.display());
        inventory.file(&locator, &path, Some(&stamp.sha256), false)?;
        if inventory
            .descriptor
            .dependencies
            .iter()
            .find(|d| d.locator == locator)
            .unwrap()
            .bytes
            != stamp.size_bytes
        {
            bail!("snapshot object differs from exact size pin");
        }
    }
    match (
        &inventory.descriptor.pin.hot_tail_manifest_sha256.clone(),
        tail_path,
    ) {
        (Some(expected), Some(path)) => {
            let bytes = std::fs::read(path)?;
            if digest(&bytes) != *expected {
                bail!("tail differs from admission pin");
            }
            let key = std::fs::read(&config.entity_sidecar.hmac_key.path)?;
            let manifest = verify_hot_tail_manifest(&bytes, &key)?;
            if manifest.tenant_id != logical_tenant_id
                || manifest.base_snapshot_id != inventory.descriptor.pin.snapshot_id
                || Some(manifest.head_snapshot_id) != inventory.descriptor.pin.hot_tail_snapshot_id
                || manifest.tail_id != inventory.descriptor.pin.hot_tail_id
            {
                bail!("signed tail differs from accepted pin");
            }
            inventory.file("hot-tail-manifest", path, Some(expected), false)?;
            for object in manifest.objects {
                let sha = object
                    .sha256
                    .context("admission completeness gap: tail object has no content digest")?;
                let source = tail_sources
                    .get(&object.source_uri)
                    .context("admission completeness gap: exact tail object not hydrated")?;
                let locator = format!("tail:{}#{}", object.source_uri, object.version_id);
                inventory.file(&locator, source, Some(&sha), false)?;
                if inventory
                    .descriptor
                    .dependencies
                    .iter()
                    .find(|d| d.locator == locator)
                    .unwrap()
                    .bytes
                    != object.size_bytes
                {
                    bail!("tail object differs from exact size pin");
                }
            }
        }
        (None, None) => {}
        _ => bail!("admission completeness gap: missing or unpinned tail manifest"),
    }
    inventory
        .descriptor
        .dependencies
        .sort_by(|a, b| a.locator.cmp(&b.locator));
    inventory.descriptor.validate()?;
    // Secret bytes must not enter the object namespace under an alias.
    if inventory
        .descriptor
        .dependencies
        .iter()
        .any(|d| d.sha256 == config.entity_sidecar.hmac_key.sha256)
    {
        bail!("archive dependency aliases a secret");
    }
    Ok(inventory)
}

impl Inventory {
    /// The same checkpoint selection and PathResolver as DbReader. Checkpoint
    /// mode never replays WAL (vendor/slatedb/src/db_reader.rs); it reads the
    /// exact manifest's L0/compacted SSTs, including segmented and cloned SSTs.
    /// The discovery manifest is itself archived so the pinned UUID remains
    /// discoverable after the original database root disappears.
    pub(super) async fn checkpoint(
        &mut self,
        database_path: &str,
        checkpoint_id: Uuid,
    ) -> Result<()> {
        use slatedb::admin::AdminBuilder;
        use slatedb::object_store::local::LocalFileSystem;
        use std::sync::Arc;
        let relative = Path::new(database_path);
        if relative.is_absolute()
            || relative.components().count() < 2
            || !relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
        {
            bail!("unsafe prevalence checkpoint root");
        }
        let admin = AdminBuilder::new(
            database_path,
            Arc::new(LocalFileSystem::new_with_prefix("/")?),
        )
        .build();
        // This is discovery of an already-pinned checkpoint, not generation
        // fallback. Any discovery/read error aborts inventory immediately.
        let discovery = admin
            .read_manifest(None)
            .await?
            .context("checkpoint discovery manifest missing")?;
        let checkpoint = discovery
            .checkpoints()
            .iter()
            .find(|c| c.id == checkpoint_id)
            .context("admission completeness gap: pinned prevalence checkpoint is absent")?;
        let exact = admin
            .read_manifest(Some(checkpoint.manifest_id))
            .await?
            .context("admission completeness gap: pinned prevalence manifest is absent")?;
        if exact.wal_object_store_uri().is_some() {
            bail!("admission completeness gap: external prevalence WAL store");
        }
        let manifests = Path::new("/").join(database_path).join("manifest");
        for id in BTreeSet::from([discovery.id(), checkpoint.manifest_id]) {
            let mut matches = Vec::new();
            for entry in std::fs::read_dir(&manifests)? {
                let path = entry?.path();
                if path.extension().and_then(|x| x.to_str()) == Some("manifest")
                    && path
                        .file_stem()
                        .and_then(|x| x.to_str())
                        .and_then(|x| x.parse::<u64>().ok())
                        == Some(id)
                {
                    matches.push(path);
                }
            }
            if matches.len() != 1 {
                bail!("admission completeness gap: checkpoint manifest file missing or ambiguous");
            }
            let path = &matches[0];
            self.file(&format!("file:{}", path.display()), path, None, false)?;
        }
        let resolver = slatedb::PathResolver::new(database_path, &exact);
        let mut paths = BTreeSet::new();
        for view in exact.l0().iter().chain(
            exact
                .compacted()
                .iter()
                .flat_map(|run| run.sst_views.iter()),
        ) {
            paths.insert(resolver.sst_path(&view.sst.id).to_string());
        }
        for segment in exact.segments() {
            for view in segment.l0().iter().chain(
                segment
                    .compacted()
                    .iter()
                    .flat_map(|run| run.sst_views.iter()),
            ) {
                paths.insert(resolver.sst_path(&view.sst.id).to_string());
            }
        }
        for path in paths {
            let relative = Path::new(&path);
            if relative.is_absolute()
                || !relative
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                bail!("unsafe prevalence SST path");
            }
            let path = Path::new("/").join(relative);
            self.file(&format!("file:{}", path.display()), &path, None, false)?;
        }
        Ok(())
    }

    fn file(
        &mut self,
        locator: &str,
        path: &Path,
        expected: Option<&str>,
        executable: bool,
    ) -> Result<()> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            bail!("admission dependency is not a regular file");
        }
        let mut reader = std::fs::File::open(path)?;
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            let size = reader.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            hash.update(&buffer[..size]);
        }
        let sha256 = hex::encode(hash.finalize());
        if expected.is_some_and(|e| e != sha256) {
            bail!("admission dependency digest changed");
        }
        let dependency = Dependency {
            locator: locator.into(),
            sha256,
            bytes: metadata.len(),
            executable,
        };
        if let Some(existing) = self
            .descriptor
            .dependencies
            .iter()
            .find(|d| d.locator == locator)
        {
            if *existing != dependency {
                bail!("conflicting dependency locator");
            }
        } else {
            if self.descriptor.dependencies.len() >= MAX_DEPENDENCIES {
                bail!("admission dependency count exceeds bound");
            }
            self.descriptor.dependencies.push(dependency);
            self.sources.insert(locator.into(), path.into());
        }
        Ok(())
    }
}
