// SPDX-License-Identifier: AGPL-3.0-or-later

//! Serialized publication of immutable tenant enrichment snapshots.
//!
//! One lock covers read/merge, content-addressed Parquet publication, candidate
//! validation, and atomic worker-config activation. Replacing one feed can
//! therefore never erase another feed that published concurrently.

use crate::config::{refresh_derivative_generation_id, WorkerConfigFile};
use crate::enrichment::{write_ioc_snapshot, IocSnapshot, IocSnapshotInput};
use crate::ioc_snapshot_prune::{prune_ioc_snapshots, IocSnapshotPruneInputs};
use crate::native::file_sha256;
use crate::orphan_temp::{sweep_ioc_orphan_temporaries, DEFAULT_ORPHAN_TEMP_GRACE};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Superseded snapshots survive at least one day by default so a draining
/// worker generation or an operator rollback can still read them, mirroring
/// `--sidecar-prune-grace-seconds` in `lake_risk_publish`.
pub const DEFAULT_SNAPSHOT_PRUNE_GRACE: Duration = Duration::from_secs(86_400);

#[derive(Debug)]
pub enum IocSourceUpdate {
    FullReplace(Vec<IocSnapshotInput>),
    Replace {
        source_id: String,
        rows: Vec<IocSnapshotInput>,
    },
    Delete {
        source_id: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct IocPublicationResult {
    pub status: &'static str,
    pub tenant_id: String,
    pub snapshot_id: String,
    pub snapshot_sha256: String,
    pub snapshot_path: PathBuf,
    pub rows: usize,
    pub bytes: u64,
    pub generation_id: String,
    pub source_operation: &'static str,
}

pub struct PreparedIocPublication {
    result: IocPublicationResult,
}

impl PreparedIocPublication {
    pub fn result(&self) -> &IocPublicationResult {
        &self.result
    }

    pub fn durable_assignment(&self) -> (&str, &Path, &str) {
        (
            &self.result.snapshot_id,
            &self.result.snapshot_path,
            &self.result.snapshot_sha256,
        )
    }
}

pub struct IocPublisher {
    output_directory: PathBuf,
    worker_config: PathBuf,
    tenant_id: String,
    snapshot_id: String,
    snapshot_prune_grace: Duration,
    snapshot_prune_disabled: bool,
    archived_config_root: Option<PathBuf>,
}

impl IocPublisher {
    pub fn new(
        output_directory: PathBuf,
        worker_config: PathBuf,
        tenant_id: String,
        snapshot_id: String,
    ) -> Result<Self> {
        if !output_directory.is_absolute() || !worker_config.is_absolute() {
            bail!("IOC publication paths must be absolute");
        }
        validate_identity("tenant", &tenant_id)?;
        validate_identity("snapshot", &snapshot_id)?;
        Ok(Self {
            output_directory,
            worker_config,
            tenant_id,
            snapshot_id,
            snapshot_prune_grace: DEFAULT_SNAPSHOT_PRUNE_GRACE,
            snapshot_prune_disabled: false,
            archived_config_root: None,
        })
    }

    /// Operator knobs for the superseded-snapshot prune (NAN-2361 leak fix),
    /// mirroring `--sidecar-prune-grace-seconds` / `--sidecar-prune-disabled`
    /// / `--generation-config-root` in `lake_risk_publish`. Callers that never
    /// touch this keep the defaults: enabled, one-day grace, no archive scan.
    pub fn with_snapshot_prune(
        mut self,
        grace: Duration,
        disabled: bool,
        archived_config_root: Option<PathBuf>,
    ) -> Self {
        self.snapshot_prune_grace = grace;
        self.snapshot_prune_disabled = disabled;
        self.archived_config_root = archived_config_root;
        self
    }

    pub fn publish(&self, update: IocSourceUpdate) -> Result<IocPublicationResult> {
        self.activate(self.prepare(update)?)
    }

    pub fn prepare(&self, update: IocSourceUpdate) -> Result<PreparedIocPublication> {
        std::fs::create_dir_all(&self.output_directory)?;
        let lock_path = self.worker_config.with_extension("ioc.lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(lock_path)?;
        fs2::FileExt::lock_exclusive(&lock)?;
        let worker_value: Value = serde_json::from_slice(&std::fs::read(&self.worker_config)?)?;
        if worker_value["assigned_tenant_id"].as_str() != Some(self.tenant_id.as_str()) {
            bail!("IOC snapshot tenant differs from the worker assignment");
        }
        let (rows, source_operation) = publication_rows(&worker_value, update)?;
        let temporary = self
            .output_directory
            .join(format!(".ioc-{}.parquet", uuid::Uuid::now_v7()));
        let digest = match write_ioc_snapshot(&temporary, &rows) {
            Ok(digest) => digest,
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error);
            }
        };
        let immutable = self.output_directory.join(format!("{digest}.parquet"));
        match std::fs::hard_link(&temporary, &immutable) {
            Ok(()) => {
                std::fs::remove_file(&temporary)?;
                sync_directory(&self.output_directory)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&temporary);
                if file_sha256(&immutable)? != digest {
                    bail!("existing content-addressed IOC object has conflicting bytes");
                }
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        let bytes = std::fs::metadata(&immutable)?.len();
        let mut candidate_value = worker_value;
        set_ioc_assignment(
            &mut candidate_value,
            Some((&self.snapshot_id, &immutable, &digest)),
        )?;
        let generation_id = candidate_value["generation_id"]
            .as_str()
            .context("candidate IOC generation identity is absent")?
            .to_string();
        Ok(PreparedIocPublication {
            result: IocPublicationResult {
                status: "published",
                tenant_id: self.tenant_id.clone(),
                snapshot_id: self.snapshot_id.clone(),
                snapshot_sha256: digest,
                snapshot_path: immutable,
                rows: rows.len(),
                bytes,
                generation_id,
                source_operation,
            },
        })
    }

    pub fn activate(&self, mut prepared: PreparedIocPublication) -> Result<IocPublicationResult> {
        let (_generation_lock, _ioc_lock) = acquire_ioc_config_locks(&self.worker_config)?;
        match sweep_ioc_orphan_temporaries(
            &self.output_directory,
            std::time::SystemTime::now(),
            DEFAULT_ORPHAN_TEMP_GRACE,
        ) {
            Ok(report) if report.matched_candidates > 0 => {
                tracing::info!(
                    report = ?report,
                    "bounded IOC temporary sweep completed under the IOC lock"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "IOC temporary sweep skipped; retaining every uncertain candidate"
                );
            }
        }
        let mut value: Value = serde_json::from_slice(&std::fs::read(&self.worker_config)?)?;
        prepared.result.generation_id = persist_ioc_assignment(
            &self.worker_config,
            &self.tenant_id,
            &mut value,
            Some((
                &prepared.result.snapshot_id,
                &prepared.result.snapshot_path,
                &prepared.result.snapshot_sha256,
            )),
        )?;
        // The PostgreSQL pointer already committed before coordinator callers
        // reach activation. Pruning is therefore safe and never makes durable
        // publication depend on local garbage collection.
        self.prune_superseded_snapshots();
        Ok(prepared.result)
    }

    pub fn assignment(&self) -> Result<Option<(String, PathBuf, String)>> {
        let value: Value = serde_json::from_slice(&std::fs::read(&self.worker_config)?)?;
        let Some(snapshot) = value.get("ioc_snapshot").filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        let snapshot_id = snapshot
            .get("snapshot_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .context("assigned IOC snapshot has no identity")?
            .to_string();
        let path = PathBuf::from(
            snapshot
                .pointer("/data/path")
                .and_then(Value::as_str)
                .context("assigned IOC snapshot has no trusted path")?,
        );
        let digest = snapshot
            .pointer("/data/sha256")
            .and_then(Value::as_str)
            .context("assigned IOC snapshot has no trusted digest")?
            .to_string();
        if path.parent() != Some(self.output_directory.as_path())
            || path.file_name().and_then(|value| value.to_str())
                != Some(&format!("{digest}.parquet"))
            || file_sha256(&path)? != digest
        {
            bail!("assigned IOC snapshot differs from its durable local cache");
        }
        Ok(Some((snapshot_id, path, digest)))
    }

    /// Delete superseded content-addressed IOC snapshots (NAN-2361 leak fix).
    ///
    /// Every publication writes a new whole-set Parquet and nothing removed
    /// the superseded ones, which filled the shared local runtime volume that
    /// also hosts serving generations. The safe-deletion rules and the
    /// protected set live in `crate::ioc_snapshot_prune`; this wrapper
    /// throttles via a stamp file (mirroring `prune_hot_tail_archives` and
    /// `lake_risk_publish::prune_superseded_sidecars`), relies on the
    /// publisher's exclusive `ioc.lock` already held by `publish`, and never
    /// fails the publication.
    fn prune_superseded_snapshots(&self) {
        if self.snapshot_prune_disabled {
            return;
        }
        let result = (|| -> Result<Option<Value>> {
            let now = std::time::SystemTime::now();
            let marker = self.output_directory.join(format!(
                ".ioc-snapshot-prune-{}.stamp",
                &hex::encode(Sha256::digest(self.tenant_id.as_bytes()))[..16]
            ));
            let prune_interval = self
                .snapshot_prune_grace
                .min(Duration::from_secs(3_600))
                .max(Duration::from_secs(300));
            if marker
                .metadata()
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|elapsed| elapsed < prune_interval)
            {
                return Ok(None);
            }
            let report = prune_ioc_snapshots(
                &IocSnapshotPruneInputs {
                    snapshot_dir: self.output_directory.clone(),
                    worker_config: self.worker_config.clone(),
                    archived_config_root: self.archived_config_root.clone(),
                    grace: self.snapshot_prune_grace,
                },
                now,
            )?;
            std::fs::write(marker, chrono::Utc::now().timestamp().to_string())?;
            Ok(Some(json!({
                "scanned": report.scanned,
                "deleted": report.deleted,
                "deleted_bytes": report.deleted_bytes,
                "retained_referenced": report.retained_referenced,
                "retained_rollback": report.retained_rollback,
                "retained_grace": report.retained_grace,
            })))
        })();
        match result {
            Ok(Some(report)) => {
                tracing::info!(report = %report, "superseded IOC snapshot prune completed");
            }
            Ok(None) => {}
            Err(error) => {
                // Retaining garbage is always safe; deletion never proceeds
                // after an error, so the publisher keeps running.
                tracing::warn!(error = %error, "IOC snapshot prune skipped; retaining all snapshots");
            }
        }
    }
}

/// Restore the exact object-store-backed IOC assignment before the
/// coordinator serves reads or accepts a new merge. `None` is an authoritative
/// empty state, not permission to retain an uncommitted local assignment.
pub fn recover_ioc_assignment(
    worker_config: &Path,
    tenant_id: &str,
    assignment: Option<(&str, &Path, &str)>,
) -> Result<String> {
    let (_generation_lock, _ioc_lock) = acquire_ioc_config_locks(worker_config)?;
    let mut value: Value = serde_json::from_slice(&std::fs::read(worker_config)?)?;
    persist_ioc_assignment(worker_config, tenant_id, &mut value, assignment)
}

/// Every whole-file worker-config writer takes generation.lock first. IOC
/// publication then takes its narrower lock, so concurrent generation and IOC
/// activation cannot deadlock or overwrite a value read before the other
/// writer committed.
fn acquire_ioc_config_locks(worker_config: &Path) -> Result<(File, File)> {
    let generation_lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(worker_config.with_extension("generation.lock"))?;
    fs2::FileExt::lock_exclusive(&generation_lock)?;
    let ioc_lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(worker_config.with_extension("ioc.lock"))?;
    fs2::FileExt::lock_exclusive(&ioc_lock)?;
    Ok((generation_lock, ioc_lock))
}

fn persist_ioc_assignment(
    worker_config: &Path,
    tenant_id: &str,
    value: &mut Value,
    assignment: Option<(&str, &Path, &str)>,
) -> Result<String> {
    if value["assigned_tenant_id"].as_str() != Some(tenant_id) {
        bail!("IOC snapshot tenant differs from the worker assignment");
    }
    set_ioc_assignment(value, assignment)?;
    persist_ioc_value(worker_config, tenant_id, value)?;
    value["generation_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .context("candidate IOC generation identity is absent")
}

fn set_ioc_assignment(value: &mut Value, assignment: Option<(&str, &Path, &str)>) -> Result<()> {
    value["ioc_snapshot"] = match assignment {
        Some((snapshot_id, immutable, digest)) => json!({
            "snapshot_id": snapshot_id,
            "data": {"path": immutable, "sha256": digest},
        }),
        None => Value::Null,
    };
    refresh_derivative_generation_id(value)?;
    Ok(())
}

fn persist_ioc_value(worker_config: &Path, tenant_id: &str, value: &Value) -> Result<()> {
    let parent = worker_config
        .parent()
        .context("worker config has no parent directory")?;
    let mut candidate = tempfile::Builder::new()
        .prefix(".lake-ioc-")
        .suffix(".json")
        .tempfile_in(parent)?;
    serde_json::to_writer_pretty(candidate.as_file_mut(), &value)?;
    candidate.as_file_mut().write_all(b"\n")?;
    candidate.as_file().sync_all()?;
    let candidate_bytes = std::fs::read(candidate.path())?;
    WorkerConfigFile::load_risk_only(
        &candidate_bytes,
        tenant_id,
        value["tenant"]["max_query_bytes"]
            .as_u64()
            .context("worker query byte budget is missing")?,
    )
    .context("candidate IOC state configuration failed validation")?;
    candidate.persist(worker_config)?;
    sync_directory(parent)?;
    Ok(())
}

fn publication_rows(
    worker_value: &Value,
    update: IocSourceUpdate,
) -> Result<(Vec<IocSnapshotInput>, &'static str)> {
    match update {
        IocSourceUpdate::FullReplace(rows) => Ok((rows, "full_replace")),
        IocSourceUpdate::Replace { source_id, rows } => {
            validate_identity("source", &source_id)?;
            if rows.is_empty() || rows.iter().any(|row| row.source_id != source_id) {
                bail!("source replacement input must contain only the selected source identity");
            }
            let mut merged = current_publication_rows(worker_value)?;
            merged.retain(|row| row.source_id != source_id);
            merged.extend(rows);
            Ok((merged, "replace_source"))
        }
        IocSourceUpdate::Delete { source_id } => {
            validate_identity("source", &source_id)?;
            let mut rows = current_publication_rows(worker_value)?;
            rows.retain(|row| row.source_id != source_id);
            Ok((rows, "delete_source"))
        }
    }
}

fn current_publication_rows(worker_value: &Value) -> Result<Vec<IocSnapshotInput>> {
    let Some(snapshot) = worker_value
        .get("ioc_snapshot")
        .filter(|value| !value.is_null())
    else {
        return Ok(Vec::new());
    };
    let path = snapshot
        .pointer("/data/path")
        .and_then(Value::as_str)
        .context("assigned IOC snapshot has no trusted path")?;
    let digest = snapshot
        .pointer("/data/sha256")
        .and_then(Value::as_str)
        .context("assigned IOC snapshot has no trusted digest")?;
    Ok(IocSnapshot::open(path, digest)?.publication_rows())
}

fn validate_identity(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        bail!("{name} identity is invalid");
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::event_config_sha256;
    use std::sync::Arc;

    fn state_config() -> Value {
        let artifact = || json!({"path": "/not-loaded", "sha256": "0".repeat(64)});
        json!({
            "schema_version": 1,
            "generation_id": "lake-v1",
            "assigned_tenant_id": "tenant-a",
            "compiler": artifact(),
            "native_library": artifact(),
            "tenant": {
                "tenant_id": "tenant-a",
                "source": "s3://bucket/events",
                "iceberg_metadata_file_path": "metadata/v1.json",
                "source_manifest": artifact(),
                "max_query_bytes": 268435456,
                "max_memory_bytes": 4294967296_u64,
                "max_execution_seconds": 30,
                "threads": 4,
                "event_contract": "ocsf-1.9",
                "allow_broad_npl": true,
                "iceberg_default_credentials": true
            },
            "entity_sidecar": {
                "manifest": artifact(),
                "hmac_key": artifact(),
                "index_files": [artifact()]
            },
            "keyword_sidecar": {
                "manifest": artifact(),
                "index_directory": "/not-loaded/keyword",
                "index_tree_sha256": "0".repeat(64),
                "fragment_manifest": artifact(),
                "fragment_index_directory": "/not-loaded/fragment",
                "fragment_index_tree_sha256": "0".repeat(64)
            }
        })
    }

    fn row(source: &str, value: &str) -> IocSnapshotInput {
        IocSnapshotInput {
            ioc_value: value.to_string(),
            ioc_type: "domain".to_string(),
            source_id: source.to_string(),
            enrichment_name: source.to_string(),
            confidence_level: 90,
            ..IocSnapshotInput::default()
        }
    }

    #[test]
    fn source_replace_and_delete_are_atomic_state_only_updates() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("worker.json");
        std::fs::write(&config, serde_json::to_vec_pretty(&state_config()).unwrap()).unwrap();
        let original_event = event_config_sha256(&std::fs::read(&config).unwrap()).unwrap();
        let publisher = IocPublisher::new(
            root.path().join("snapshots"),
            config.clone(),
            "tenant-a".to_string(),
            "ioc-current".to_string(),
        )
        .unwrap();
        publisher
            .publish(IocSourceUpdate::FullReplace(vec![
                row("feed-a", "a.example"),
                row("feed-b", "b.example"),
            ]))
            .unwrap();
        publisher
            .publish(IocSourceUpdate::Replace {
                source_id: "feed-a".to_string(),
                rows: vec![row("feed-a", "new-a.example")],
            })
            .unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        let rows = current_publication_rows(&value).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| row.ioc_value == "new-a.example"));
        assert!(rows.iter().any(|row| row.ioc_value == "b.example"));
        assert_eq!(
            event_config_sha256(&std::fs::read(&config).unwrap()).unwrap(),
            original_event
        );

        publisher
            .publish(IocSourceUpdate::Delete {
                source_id: "feed-a".to_string(),
            })
            .unwrap();
        publisher
            .publish(IocSourceUpdate::Delete {
                source_id: "feed-b".to_string(),
            })
            .unwrap();
        let value: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        assert!(current_publication_rows(&value).unwrap().is_empty());
    }

    #[test]
    fn prepare_keeps_local_assignment_unchanged_until_activation() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("worker.json");
        std::fs::write(&config, serde_json::to_vec_pretty(&state_config()).unwrap()).unwrap();
        let publisher = IocPublisher::new(
            root.path().join("snapshots"),
            config,
            "tenant-a".to_string(),
            "ioc-current".to_string(),
        )
        .unwrap();

        let prepared = publisher
            .prepare(IocSourceUpdate::FullReplace(vec![row(
                "feed-a",
                "a.example",
            )]))
            .unwrap();
        let (_, candidate, _) = prepared.durable_assignment();
        assert!(candidate.is_file());
        assert!(publisher.assignment().unwrap().is_none());

        publisher.activate(prepared).unwrap();
        assert!(publisher.assignment().unwrap().is_some());
    }

    fn advance_event_generation(config: &Path) {
        let mut value: Value = serde_json::from_slice(&std::fs::read(config).unwrap()).unwrap();
        value["tenant"]["iceberg_metadata_file_path"] = json!("metadata/v2.json");
        refresh_derivative_generation_id(&mut value).unwrap();
        std::fs::write(config, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    #[test]
    fn activation_rebases_on_a_concurrent_generation_commit() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("worker.json");
        std::fs::write(&config, serde_json::to_vec_pretty(&state_config()).unwrap()).unwrap();
        let publisher = Arc::new(
            IocPublisher::new(
                root.path().join("snapshots"),
                config.clone(),
                "tenant-a".to_string(),
                "ioc-current".to_string(),
            )
            .unwrap(),
        );
        let prepared = publisher
            .prepare(IocSourceUpdate::FullReplace(vec![row(
                "feed-a",
                "a.example",
            )]))
            .unwrap();
        let generation_lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(config.with_extension("generation.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&generation_lock).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let thread_barrier = barrier.clone();
        let thread_publisher = publisher.clone();
        let activation = std::thread::spawn(move || {
            thread_barrier.wait();
            thread_publisher.activate(prepared)
        });
        barrier.wait();
        advance_event_generation(&config);
        drop(generation_lock);
        activation.join().unwrap().unwrap();

        let active: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        assert_eq!(
            active["tenant"]["iceberg_metadata_file_path"],
            "metadata/v2.json"
        );
        assert!(active.get("ioc_snapshot").is_some_and(Value::is_object));
    }

    #[test]
    fn recovery_waits_for_and_preserves_a_concurrent_generation_commit() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("worker.json");
        std::fs::write(&config, serde_json::to_vec_pretty(&state_config()).unwrap()).unwrap();
        let snapshot = root.path().join("ioc.parquet");
        let digest = write_ioc_snapshot(&snapshot, &[row("feed-a", "a.example")]).unwrap();
        let generation_lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(config.with_extension("generation.lock"))
            .unwrap();
        fs2::FileExt::lock_exclusive(&generation_lock).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let thread_barrier = barrier.clone();
        let thread_config = config.clone();
        let recovery = std::thread::spawn(move || {
            thread_barrier.wait();
            recover_ioc_assignment(
                &thread_config,
                "tenant-a",
                Some(("ioc-current", &snapshot, &digest)),
            )
        });
        barrier.wait();
        advance_event_generation(&config);
        drop(generation_lock);
        recovery.join().unwrap().unwrap();

        let active: Value = serde_json::from_slice(&std::fs::read(&config).unwrap()).unwrap();
        assert_eq!(
            active["tenant"]["iceberg_metadata_file_path"],
            "metadata/v2.json"
        );
        assert!(active.get("ioc_snapshot").is_some_and(Value::is_object));
    }
}
