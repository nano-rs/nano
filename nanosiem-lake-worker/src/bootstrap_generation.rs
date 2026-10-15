// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2361 wave 8: the zero-snapshot **bootstrap generation**.
//!
//! A brand-new hosted-shared tenant has an Iceberg table with NO current
//! snapshot: nothing has been compacted yet, every event it has lives in the
//! signed staged hot tail. Before this module the generation manager refused
//! to reconcile such a table (`Iceberg event table has no current snapshot`),
//! the query worker never left its `bootstrap-pending` wait loop, and every
//! search timed out at the identity probe. A tenant could not search until
//! its first compaction committed.
//!
//! The bootstrap generation is a real, fenced `worker.json` whose Iceberg
//! side is provably empty:
//!
//! * `generation_id` is `lake-0-<24 hex>` — the same deployment-path
//!   normalized digest the activator computes for a real generation. The
//!   digest covers the object-stamp artifact, which binds the table UUID and
//!   the current metadata location, so the identity is derived from
//!   (table uuid, snapshot 0) exactly like `lake-<snapshot>-<digest>` is
//!   derived from (snapshot, artifacts).
//! * `snapshot_cache.object_stamp_manifest` names an object-stamp manifest
//!   with `snapshot_id: 0`, `objects: []`, and `table_uuid` set. This is the
//!   ONLY form in which a zero snapshot is ever admitted; a manifest with
//!   snapshot 0 and objects, or without the table UUID, is invalid.
//! * `snapshot_cache.max_bytes` is 0, `ancestor_snapshot_ids` is empty, the
//!   data directory exists and is empty, and the catalog read schema is
//!   pinned so the worker can materialize an empty base with the exact
//!   catalog column shape.
//! * The entity, keyword, fragment, count-rollup, identity, and prevalence
//!   derivatives are ABSENT (the seed's placeholder shape). The derivative
//!   bundle for an empty generation is empty, not missing:
//!   `--generation-bundle-required` is satisfied because there is no object
//!   whose derivative could be required.
//!
//! Installing it never downgrades: only a `bootstrap-pending` seed or an
//! existing bootstrap generation for the same table may be (re)rendered. The
//! first real snapshot is promoted through the ordinary activation path,
//! which treats the bootstrap exactly like the seed (no prior generation to
//! reuse, no prepared tail to wait for).

use crate::config::{deployment_path_normalized_sha256, WorkerConfigFile};
use crate::generation::ObjectStampManifest;
use crate::native::file_sha256;
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde_json::{json, Value};
use sha2::Digest as _;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Generation identity prefix of the zero-snapshot bootstrap form.
pub const BOOTSTRAP_GENERATION_PREFIX: &str = "lake-0-";
/// The non-runnable seed the config bootstrapper writes before any
/// generation exists. The query container's entrypoint waits on this literal.
pub const BOOTSTRAP_PENDING_GENERATION_ID: &str = "bootstrap-pending";
/// The snapshot identity of the bootstrap generation. Iceberg snapshot IDs
/// are always positive, so zero can never collide with a real snapshot.
pub const BOOTSTRAP_SNAPSHOT_ID: i64 = 0;
/// Directory name under the generations root that holds the bootstrap
/// snapshot tree. Distinct from `snapshot-<id>-<digest>` so the local
/// generation ledger never confuses it with a promotable generation.
pub const BOOTSTRAP_GENERATION_DIRECTORY_PREFIX: &str = "bootstrap-";

const GENERATION_DIGEST_CHARS: usize = 24;

/// True for `lake-0-<24 lowercase hex>` and nothing else.
pub fn is_bootstrap_generation_id(generation_id: &str) -> bool {
    generation_id
        .strip_prefix(BOOTSTRAP_GENERATION_PREFIX)
        .is_some_and(|digest| {
            digest.len() == GENERATION_DIGEST_CHARS
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// True when a worker generation identity is one the worker must NOT start
/// from: the seed. The bootstrap generation is deliberately not in this set.
pub fn is_bootstrap_pending(generation_id: &str) -> bool {
    generation_id == BOOTSTRAP_PENDING_GENERATION_ID
}

/// True ONLY for the exact empty-table form: snapshot 0, no objects, and the
/// table UUID bound. Every other zero or negative snapshot stays invalid.
pub fn is_bootstrap_stamps(stamps: &ObjectStampManifest) -> bool {
    stamps.snapshot_id == BOOTSTRAP_SNAPSHOT_ID
        && stamps.objects.is_empty()
        && stamps
            .table_uuid
            .as_deref()
            .is_some_and(|value| uuid::Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil()))
}

/// The object-stamp manifest of an empty table.
pub fn empty_object_stamp_manifest(
    table: &str,
    metadata_location: &str,
    table_uuid: uuid::Uuid,
) -> Result<ObjectStampManifest> {
    if table.is_empty() || table_uuid.is_nil() {
        bail!("bootstrap object-stamp manifest requires a table and its UUID");
    }
    validate_metadata_location(metadata_location)?;
    Ok(ObjectStampManifest {
        metadata_location: metadata_location.to_string(),
        snapshot_id: BOOTSTRAP_SNAPSHOT_ID,
        table: table.to_string(),
        objects: Vec::new(),
        table_uuid: Some(table_uuid.hyphenated().to_string()),
    })
}

fn validate_metadata_location(metadata_location: &str) -> Result<()> {
    if !metadata_location.starts_with("s3://")
        || !metadata_location.ends_with(".metadata.json")
        || !metadata_location.contains("/metadata/")
        || metadata_location.contains("..")
        || metadata_location.len() > 2_048
        || metadata_location.chars().any(char::is_control)
    {
        bail!("bootstrap metadata location is outside an Iceberg table");
    }
    Ok(())
}

/// Everything the bootstrap installer needs. All paths are absolute.
pub struct BootstrapGenerationInput<'a> {
    pub worker_config: &'a Path,
    pub generations_root: &'a Path,
    pub tenant_id: &'a str,
    pub table: &'a str,
    pub table_location_prefix: &'a str,
    pub metadata_location: &'a str,
    pub table_uuid: uuid::Uuid,
    /// ClickHouse column structure of the catalog's current schema
    /// (`iceberg::table_read_contract`).
    pub read_schema: &'a str,
    /// NAN-3366: leaf path -> type of the catalog's current schema
    /// (`iceberg::table_field_types`), recorded in the source manifest as
    /// `bootstrap_field_types`. The worker exposes exactly these paths on its
    /// typed empty base and serves them as the generation's field inventory,
    /// so readers that fetch the schema at boot get the real (empty-table)
    /// contract instead of an empty inventory.
    pub field_types: &'a std::collections::BTreeMap<String, String>,
    pub worker_source: &'a str,
    pub max_memory_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapGenerationOutcome {
    /// The bootstrap generation was rendered and atomically installed.
    Installed {
        generation_id: String,
        snapshot_root: PathBuf,
    },
    /// The installed bootstrap generation already has this exact identity.
    Unchanged { generation_id: String },
}

impl BootstrapGenerationOutcome {
    pub fn generation_id(&self) -> &str {
        match self {
            Self::Installed { generation_id, .. } | Self::Unchanged { generation_id } => {
                generation_id
            }
        }
    }
}

/// Where the bootstrap snapshot tree lives for one (table, metadata) pair.
/// Keyed by the metadata location too so a schema evolution before the first
/// snapshot renders a NEW immutable tree instead of rewriting the one the
/// installed config still digests; the worker and the tail signer keep
/// verifying the old tree until the new config is atomically installed.
pub fn bootstrap_generation_root(
    generations_root: &Path,
    table_uuid: uuid::Uuid,
    metadata_location: &str,
) -> PathBuf {
    let digest = hex::encode(sha2::Sha256::digest(metadata_location.as_bytes()));
    generations_root.join(format!(
        "{BOOTSTRAP_GENERATION_DIRECTORY_PREFIX}{}-{}",
        table_uuid.simple(),
        &digest[..16]
    ))
}

/// A rendered (not yet installed) bootstrap generation: the exact worker.json
/// value, its identity, and the snapshot tree it points at.
pub struct RenderedBootstrapGeneration {
    pub value: Value,
    pub generation_id: String,
    pub snapshot_root: PathBuf,
    /// The generation the worker.json carried before this render.
    pub current_generation_id: String,
}

/// Render and install the bootstrap generation under the activator's
/// generation lock. Idempotent: rendering the same inputs twice yields
/// `Unchanged`. Refuses to touch any worker.json that is neither the seed nor
/// a bootstrap generation, so an activated generation can never be replaced
/// by the empty form.
pub fn install_bootstrap_generation(
    input: &BootstrapGenerationInput<'_>,
) -> Result<BootstrapGenerationOutcome> {
    // Same lock the activator holds while it swaps a real generation, so a
    // bootstrap render can never interleave with a first activation.
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(input.worker_config.with_extension("generation.lock"))
        .context("open worker generation lock")?;
    lock.lock_exclusive()
        .context("acquire worker generation lock for bootstrap install")?;
    let rendered = render_bootstrap_generation(input)?;
    if rendered.current_generation_id == rendered.generation_id {
        return Ok(BootstrapGenerationOutcome::Unchanged {
            generation_id: rendered.generation_id,
        });
    }
    let parent = input
        .worker_config
        .parent()
        .context("worker config has no parent directory")?;
    let mut candidate = tempfile::Builder::new()
        .prefix(".lake-bootstrap-generation-")
        .suffix(".json")
        .tempfile_in(parent)?;
    serde_json::to_writer_pretty(candidate.as_file_mut(), &rendered.value)?;
    candidate.as_file_mut().write_all(b"\n")?;
    candidate.as_file().sync_all()?;
    let loaded = WorkerConfigFile::load(candidate.path())
        .context("bootstrap generation candidate validation failed")?;
    if !loaded.bootstrap || loaded.generation_id != rendered.generation_id {
        bail!("bootstrap generation candidate did not load as the bootstrap form");
    }
    candidate.persist(input.worker_config)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(BootstrapGenerationOutcome::Installed {
        generation_id: rendered.generation_id,
        snapshot_root: rendered.snapshot_root,
    })
}

/// Materialize the empty snapshot tree and render the bootstrap worker.json
/// value without installing it. `install_bootstrap_generation` is this plus
/// the lock, the full config-load fence, and the atomic swap; the split lets
/// the exact rendered format be verified without a native runtime.
pub fn render_bootstrap_generation(
    input: &BootstrapGenerationInput<'_>,
) -> Result<RenderedBootstrapGeneration> {
    let prefix = input.table_location_prefix.trim_end_matches('/');
    let metadata_prefix = format!("{prefix}/metadata/");
    if input.tenant_id.is_empty()
        || input.tenant_id.len() > 256
        || input.tenant_id.chars().any(char::is_control)
        || input.worker_source.is_empty()
        || input.read_schema.is_empty()
        || input.read_schema.len() > 1_048_576
        || input.read_schema.chars().any(char::is_control)
        || input.field_types.is_empty()
        || input.field_types.len() > 100_000
        || !prefix.starts_with("s3://")
        || !input.metadata_location.starts_with(&metadata_prefix)
        || !input.worker_config.is_absolute()
        || !input.generations_root.is_absolute()
    {
        bail!("bootstrap generation input is invalid");
    }
    let stamps = empty_object_stamp_manifest(input.table, input.metadata_location, input.table_uuid)?;
    let relative_metadata = input
        .metadata_location
        .strip_prefix(&metadata_prefix)
        .map(|relative| format!("metadata/{relative}"))
        .context("metadata is outside the assigned table")?;
    if relative_metadata.contains("..") || relative_metadata.contains("//") {
        bail!("relative Iceberg metadata path is invalid");
    }

    let current_bytes =
        std::fs::read(input.worker_config).context("read current worker configuration")?;
    let current = WorkerConfigFile::read(input.worker_config)?;
    if current.assigned_tenant_id != input.tenant_id || current.tenant.tenant_id != input.tenant_id
    {
        bail!("bootstrap generation tenant differs from the worker assignment");
    }
    // Only the seed or an existing bootstrap (by SHAPE: a state publisher may
    // have rotated its identity to `lakecfg-…`) may be re-rendered; an
    // activated generation is never replaced by the empty form.
    if !is_bootstrap_pending(&current.generation_id) && !current.is_bootstrap_generation() {
        bail!(
            "refusing to replace activated generation {} with the empty bootstrap form",
            current.generation_id
        );
    }
    let mut value: Value =
        serde_json::from_slice(&current_bytes).context("decode current worker configuration")?;

    // Materialize the empty snapshot tree.
    let root =
        bootstrap_generation_root(input.generations_root, input.table_uuid, input.metadata_location);
    let snapshot_root = root.join("snapshot");
    let data_directory = snapshot_root.join("data");
    std::fs::create_dir_all(&data_directory).context("create bootstrap data directory")?;
    if std::fs::read_dir(&data_directory)?.next().is_some() {
        bail!("bootstrap snapshot data directory is not empty");
    }
    let stamp_path = snapshot_root.join("object-stamps.json");
    let mut stamp_bytes = serde_json::to_vec_pretty(&stamps)?;
    stamp_bytes.push(b'\n');
    write_if_changed(&stamp_path, &stamp_bytes)?;
    let read_schema_path = snapshot_root.join("clickhouse-read-schema.sql");
    write_if_changed(&read_schema_path, input.read_schema.as_bytes())?;
    let source_manifest_path = snapshot_root.join("source-manifest.json");
    let mut source_manifest_bytes = serde_json::to_vec_pretty(&json!({
        "schema_version": 1,
        "generation": "bootstrap",
        "tenant_id": input.tenant_id,
        "table": input.table,
        "table_uuid": input.table_uuid.hyphenated().to_string(),
        "snapshot_id": BOOTSTRAP_SNAPSHOT_ID,
        "object_stamp_manifest": stamp_path,
        "objects": [],
        "bootstrap_field_types": input.field_types,
    }))?;
    source_manifest_bytes.push(b'\n');
    write_if_changed(&source_manifest_path, &source_manifest_bytes)?;

    // Bind the same runtime this image ships, exactly as the activator does
    // for a real generation: an image upgrade must not leave the bootstrap
    // pinned to a previous release's digests.
    for artifact in ["compiler", "native_library"] {
        if let Some(path) = value
            .get(artifact)
            .and_then(|artifact| artifact.get("path"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .filter(|path| path.is_file())
        {
            value[artifact]["sha256"] = json!(file_sha256(&path)?);
        }
    }
    let source_manifest_sha = file_sha256(&source_manifest_path)?;
    value["tenant"]["iceberg_metadata_file_path"] = json!(relative_metadata);
    value["tenant"]["source"] = json!(input.worker_source);
    value["tenant"]["source_manifest"] = artifact(&source_manifest_path, &source_manifest_sha);
    value["tenant"]["max_memory_bytes"] = json!(input.max_memory_bytes);
    value["snapshot_cache"] = json!({
        "object_stamp_manifest": artifact(&stamp_path, &file_sha256(&stamp_path)?),
        "data_directory": data_directory,
        "max_bytes": 0,
        "read_schema": artifact(&read_schema_path, &file_sha256(&read_schema_path)?),
        "ancestor_snapshot_ids": [],
    });
    // The entity manifest of a real generation IS the source manifest. Point
    // the empty sidecar at the same artifact so the worker's source binding
    // reads one verified file; the index set is empty.
    value["entity_sidecar"]["manifest"] = artifact(&source_manifest_path, &source_manifest_sha);
    value["entity_sidecar"]["index_files"] = json!([]);
    if let Some(object) = value.as_object_mut() {
        // No derivative may exist for zero objects; a stale key from an
        // earlier render must not survive.
        object.remove("count_rollup");
        object.remove("identity_snapshot");
        object.remove("prevalence_snapshots");
    }
    value["generation_id"] = json!("pending");
    let digest = deployment_path_normalized_sha256(&value)?;
    let generation_id = format!(
        "{BOOTSTRAP_GENERATION_PREFIX}{}",
        &digest[..GENERATION_DIGEST_CHARS]
    );
    value["generation_id"] = json!(generation_id);
    Ok(RenderedBootstrapGeneration {
        value,
        generation_id,
        snapshot_root,
        current_generation_id: current.generation_id,
    })
}

fn artifact(path: &Path, sha256: &str) -> Value {
    json!({ "path": path, "sha256": sha256 })
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<()> {
    if std::fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    let parent = path.parent().context("bootstrap artifact has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_generation_identity_is_exactly_the_zero_prefixed_digest_form() {
        assert!(is_bootstrap_generation_id(&format!(
            "lake-0-{}",
            "0123456789abcdef01234567"
        )));
        assert!(!is_bootstrap_generation_id("lake-0-0123456789ABCDEF01234567"));
        assert!(!is_bootstrap_generation_id("lake-0-0123"));
        assert!(!is_bootstrap_generation_id("lake-42-0123456789abcdef01234567"));
        assert!(!is_bootstrap_generation_id("lakecfg-0123456789abcdef01234567"));
        assert!(!is_bootstrap_generation_id("bootstrap-pending"));
        assert!(is_bootstrap_pending("bootstrap-pending"));
    }

    #[test]
    fn only_the_empty_uuid_bound_zero_snapshot_is_a_bootstrap_manifest() {
        let uuid = uuid::Uuid::new_v4();
        let stamps = empty_object_stamp_manifest(
            "tenant1.events",
            "s3://lake/tenant1/events/metadata/00000-abc.metadata.json",
            uuid,
        )
        .unwrap();
        assert!(is_bootstrap_stamps(&stamps));
        assert_eq!(stamps.snapshot_id, 0);
        assert!(stamps.objects.is_empty());

        let mut without_uuid = stamps.clone();
        without_uuid.table_uuid = None;
        assert!(!is_bootstrap_stamps(&without_uuid));

        let mut nil_uuid = stamps.clone();
        nil_uuid.table_uuid = Some(uuid::Uuid::nil().to_string());
        assert!(!is_bootstrap_stamps(&nil_uuid));

        let mut with_object = stamps.clone();
        with_object.objects.push(crate::generation::ObjectStamp {
            relative_path: "a.parquet".to_string(),
            source_uri: "s3://lake/tenant1/events/data/a.parquet".to_string(),
            version_id: "v1".to_string(),
            size_bytes: 1,
            sha256: "0".repeat(64),
        });
        assert!(!is_bootstrap_stamps(&with_object));

        let mut real = stamps;
        real.snapshot_id = 7;
        assert!(!is_bootstrap_stamps(&real));

        assert!(empty_object_stamp_manifest("tenant1.events", "file:///x", uuid).is_err());
        assert!(empty_object_stamp_manifest("tenant1.events", "s3://lake/t/metadata/v1.metadata.json", uuid::Uuid::nil()).is_err());
    }

    #[test]
    fn empty_manifest_round_trips_through_serde_with_its_table_uuid() {
        let uuid = uuid::Uuid::new_v4();
        let stamps = empty_object_stamp_manifest(
            "tenant1.events",
            "s3://lake/tenant1/events/metadata/00000-abc.metadata.json",
            uuid,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&stamps).unwrap();
        let decoded: ObjectStampManifest = serde_json::from_slice(&bytes).unwrap();
        assert!(is_bootstrap_stamps(&decoded));
        assert_eq!(decoded.table_uuid.as_deref(), Some(uuid.hyphenated().to_string().as_str()));
        // A real manifest without the key still decodes (the key is optional)
        // and is never mistaken for the bootstrap form.
        let legacy: ObjectStampManifest = serde_json::from_str(
            r#"{"metadata_location":"s3://lake/t/metadata/v2.metadata.json","snapshot_id":9,"table":"t.events","objects":[]}"#,
        )
        .unwrap();
        assert!(legacy.table_uuid.is_none());
        assert!(!is_bootstrap_stamps(&legacy));
        // Serializing a manifest without the UUID keeps the legacy byte shape
        // (no `table_uuid` key), so existing digests are unchanged.
        assert!(!serde_json::to_string(&legacy).unwrap().contains("table_uuid"));
    }

    #[test]
    fn install_refuses_to_downgrade_an_activated_generation() {
        let root = tempfile::tempdir().unwrap();
        let worker_config = root.path().join("worker.json");
        std::fs::write(
            &worker_config,
            serde_json::to_vec(&json!({
                "schema_version": 1,
                "generation_id": "lake-42-0123456789abcdef01234567",
                "assigned_tenant_id": "tenant-a",
                "compiler": {"path": "/nonexistent/compiler", "sha256": "0".repeat(64)},
                "native_library": {"path": "/nonexistent/libchdb.so", "sha256": "0".repeat(64)},
                "tenant": {
                    "tenant_id": "tenant-a",
                    "source": "s3://lake/tenant-a/events",
                    "iceberg_metadata_file_path": "metadata/v1.metadata.json",
                    "source_manifest": {"path": "/nonexistent/manifest.json", "sha256": "0".repeat(64)},
                    "max_query_bytes": 1,
                    "max_execution_seconds": 1,
                    "threads": 1,
                    "event_contract": "ocsf-1.9",
                    "allow_broad_npl": true
                },
                "entity_sidecar": {
                    "manifest": {"path": "/nonexistent/entity.json", "sha256": "0".repeat(64)},
                    "hmac_key": {"path": "/nonexistent/hmac", "sha256": "0".repeat(64)},
                    "index_files": []
                },
                "keyword_sidecar": {
                    "manifest": {"path": "/nonexistent/keyword.json", "sha256": "0".repeat(64)},
                    "index_directory": "/nonexistent/keyword",
                    "index_tree_sha256": "0".repeat(64),
                    "fragment_manifest": {"path": "/nonexistent/fragment.json", "sha256": "0".repeat(64)},
                    "fragment_index_directory": "/nonexistent/fragment",
                    "fragment_index_tree_sha256": "0".repeat(64)
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let generations = root.path().join("generations");
        std::fs::create_dir_all(&generations).unwrap();
        let error = install_bootstrap_generation(&BootstrapGenerationInput {
            worker_config: &worker_config,
            generations_root: &generations,
            tenant_id: "tenant-a",
            table: "tenant_a.events",
            table_location_prefix: "s3://lake/tenant-a/events",
            metadata_location: "s3://lake/tenant-a/events/metadata/00000-abc.metadata.json",
            table_uuid: uuid::Uuid::new_v4(),
            read_schema: "time Nullable(DateTime64(6))",
            field_types: &std::collections::BTreeMap::from([("time".to_string(), "timestamp".to_string())]),
            worker_source: "s3://lake/tenant-a/events",
            max_memory_bytes: 64 * 1024 * 1024,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("refusing to replace activated generation"),
            "{error:#}"
        );
        // The activated config is untouched.
        let after = WorkerConfigFile::read(&worker_config).unwrap();
        assert_eq!(after.generation_id, "lake-42-0123456789abcdef01234567");
    }
}
