// SPDX-License-Identifier: AGPL-3.0-or-later

//! Strict worker configuration. Credentials are resolved only from named
//! process environment variables and never accepted in request bodies.

use crate::generation::ObjectStampManifest;
use crate::native::{file_sha256, NativeChdb, NativeChdbError};
use crate::planner::{
    validate_tenant, ObjectStoreCredentials, SnapshotCache, SnapshotCacheObject, TenantQueryConfig,
    DEFAULT_QUERY_MEMORY_BYTES,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read worker config: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to decode worker config: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("worker config is invalid: {0}")]
    Invalid(String),
    #[error("worker artifact verification failed: {0}")]
    Artifact(#[from] NativeChdbError),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerConfigFile {
    #[serde(default)]
    pub generation_proof: Option<crate::generation_proof::Reference>,
    pub schema_version: u64,
    pub generation_id: String,
    pub assigned_tenant_id: String,
    pub compiler: VerifiedArtifact,
    pub native_library: VerifiedArtifact,
    pub tenant: TenantConfigFile,
    #[serde(default)]
    pub snapshot_cache: Option<SnapshotCacheConfigFile>,
    pub entity_sidecar: EntitySidecarConfigFile,
    pub keyword_sidecar: KeywordSidecarConfigFile,
    #[serde(default)]
    pub count_rollup: Option<CountRollupConfigFile>,
    #[serde(default)]
    pub identity_snapshot: Option<IdentitySnapshotConfigFile>,
    #[serde(default)]
    pub ioc_snapshot: Option<IocSnapshotConfigFile>,
    #[serde(default)]
    pub prevalence_snapshots: BTreeMap<String, PrevalenceSnapshotConfigFile>,
    #[serde(default)]
    pub risk_snapshot: Option<RiskSnapshotConfigFile>,
    /// NAN-2361: the deployment's derived sizing profile. Optional so
    /// existing worker.json files and the bootstrap seed keep loading;
    /// when present it deserializes through the profile's validating wire
    /// twin, so a worker.json carrying bounds that violate a cross-layer
    /// inequality refuses to load AT ALL rather than starting a process
    /// that cannot work. Excluded from `event_config_sha256` below —
    /// sizing is runner capacity, not event-serving identity.
    #[serde(default)]
    pub bounds_profile: Option<crate::bounds::LakeBoundsProfile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedArtifact {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfigFile {
    pub tenant_id: String,
    pub source: String,
    pub iceberg_metadata_file_path: String,
    pub source_manifest: VerifiedArtifact,
    pub max_query_bytes: u64,
    /// Per-native-query memory ceiling. Deployment memory must also cover one
    /// ceiling per executor connection plus the worker's resident indexes.
    #[serde(default = "default_query_memory_bytes")]
    pub max_memory_bytes: u64,
    pub max_execution_seconds: u64,
    pub threads: u64,
    /// Optional long-running analytics class. Omitted values inherit the
    /// interactive limit, so existing/open-core deployments never reserve or
    /// advertise capacity they did not explicitly provision.
    #[serde(default)]
    pub analytics_max_memory_bytes: Option<u64>,
    #[serde(default)]
    pub analytics_max_execution_seconds: Option<u64>,
    #[serde(default)]
    pub analytics_threads: Option<u64>,
    pub event_contract: String,
    pub allow_broad_npl: bool,
    #[serde(default)]
    pub iceberg_default_credentials: bool,
    #[serde(default)]
    pub iceberg_access_key_env: Option<String>,
    #[serde(default)]
    pub iceberg_secret_key_env: Option<String>,
    #[serde(default)]
    pub iceberg_session_token_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitySidecarConfigFile {
    pub manifest: VerifiedArtifact,
    pub hmac_key: VerifiedArtifact,
    pub index_files: Vec<VerifiedArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeywordSidecarConfigFile {
    pub manifest: VerifiedArtifact,
    pub index_directory: PathBuf,
    pub index_tree_sha256: String,
    pub fragment_manifest: VerifiedArtifact,
    pub fragment_index_directory: PathBuf,
    pub fragment_index_tree_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountRollupConfigFile {
    pub manifest: VerifiedArtifact,
    pub data_directory: PathBuf,
    pub data_tree_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCacheConfigFile {
    pub object_stamp_manifest: VerifiedArtifact,
    pub data_directory: PathBuf,
    pub max_bytes: u64,
    #[serde(default)]
    pub read_schema: Option<VerifiedArtifact>,
    /// Complete Iceberg ancestry of the serving snapshot, newest first. The
    /// bounded-tail signer uses this immutable assignment to avoid re-serving
    /// compacted inputs during or after a generation cutover.
    #[serde(default)]
    pub ancestor_snapshot_ids: Vec<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySnapshotConfigFile {
    pub snapshot_id: String,
    pub by_ip: VerifiedArtifact,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IocSnapshotConfigFile {
    pub snapshot_id: String,
    pub data: VerifiedArtifact,
}

/// On-disk shape of a Bronze publisher's projected prevalence hand-off
/// assignment (see `WorkerConfigFile::load_prevalence_handoff`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceHandoffConfigFile {
    pub schema_version: u64,
    pub generation_id: String,
    pub assigned_tenant_id: String,
    pub snapshot_id: i64,
    pub bundle_identity_sha256: String,
    pub handoff_manifest_sha256: String,
    pub tenant: PrevalenceHandoffTenantConfigFile,
    pub entity_sidecar: PrevalenceHandoffEntitySidecarConfigFile,
    #[serde(default)]
    pub prevalence_snapshots: BTreeMap<String, PrevalenceSnapshotConfigFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceHandoffTenantConfigFile {
    pub tenant_id: String,
    pub max_query_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceHandoffEntitySidecarConfigFile {
    pub hmac_key: VerifiedArtifact,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceSnapshotConfigFile {
    pub window: String,
    pub object_store_url: String,
    pub database_path: String,
    pub checkpoint_id: uuid::Uuid,
    pub scan_files: Vec<VerifiedArtifact>,
    /// Immutable cross-source projection used by the default explorer path.
    /// Older generations omit it and retain the exact scoped-scan fallback.
    #[serde(default)]
    pub explorer: Option<VerifiedArtifact>,
    #[serde(default)]
    pub daily_history: Option<PrevalenceDailyHistoryConfigFile>,
    pub source_types: Vec<String>,
    #[serde(default = "default_rarity_threshold")]
    pub rarity_threshold: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrevalenceDailyHistoryConfigFile {
    pub scan_file: VerifiedArtifact,
    pub daily_start: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskSnapshotConfigFile {
    pub manifest: VerifiedArtifact,
}

#[derive(Debug, Deserialize)]
struct RiskSnapshotManifest {
    schema_version: u64,
    tenant_id: String,
    snapshot_id: String,
    snapshot_version: String,
    objects: Vec<RiskSnapshotObject>,
    #[serde(default)]
    clear_snapshot: Option<RiskClearSnapshotManifest>,
    // mirror-gate: wire
    #[serde(default, rename = "enterprise_shared")]
    shared_binding: Option<SharedRiskManifestBinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedRiskManifestBinding {
    security_tenant_id: uuid::Uuid,
    logical_tenant_id: String,
    assignment_revision: i64,
    publisher_worker_identity: String,
    publisher_worker_actor_id: uuid::Uuid,
    lake_worker_identity: String,
    lake_worker_revision: i64,
    publisher_config_revision: i64,
    publisher_image_digest: String,
    provider_credential_revision: i64,
    event_generation_id: String,
    event_snapshot_id: i64,
    source_object_stamp_sha256: String,
    worker_config_sha256: String,
}

#[derive(Debug, Deserialize)]
struct RiskSnapshotObject {
    source_uri: PathBuf,
    size_bytes: u64,
    version_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskClearSnapshotManifest {
    source_uri: PathBuf,
    size_bytes: u64,
    version_id: String,
    row_count: u64,
    published_revision: i64,
    global_clear_us: i64,
}

fn default_rarity_threshold() -> u64 {
    3
}

fn default_query_memory_bytes() -> u64 {
    DEFAULT_QUERY_MEMORY_BYTES
}

/// Hash the immutable event-serving binding while excluding state publishers
/// and runner-capacity knobs. Risk refreshes must not invalidate queued log
/// jobs, and the same event generation must be runnable in different isolated
/// memory classes.
pub fn event_config_sha256(bytes: &[u8]) -> Result<String> {
    let mut config: Value = serde_json::from_slice(bytes)?;
    let object = config
        .as_object_mut()
        .context("worker configuration is not an object")?;
    object.remove("generation_id");
    object.remove("risk_snapshot");
    object.remove("ioc_snapshot");
    // NAN-2361: the sizing profile is runner capacity, exactly the category
    // this digest already excludes (see the tenant capacity fields below).
    // Covering it would give the SAME event data a new generation identity on
    // every sizing retune, needlessly re-archiving configs; excluding it is a
    // no-op remove on files that predate the profile, so existing digests are
    // unchanged. The profile is NOT unfenced by this: it validates its own
    // 14 cross-layer inequalities on every deserialize (bounds.rs wire twin).
    object.remove("bounds_profile");
    if let Some(tenant) = object.get_mut("tenant").and_then(Value::as_object_mut) {
        for field in [
            "max_memory_bytes",
            "max_execution_seconds",
            "threads",
            "analytics_max_memory_bytes",
            "analytics_max_execution_seconds",
            "analytics_threads",
        ] {
            tenant.remove(field);
        }
    }
    normalize_local_paths(&mut config);
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&config)?)))
}

fn normalize_local_paths(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (name, value) in object {
                if matches!(
                    name.as_str(),
                    "path"
                        | "data_directory"
                        | "index_directory"
                        | "fragment_index_directory"
                        | "database_path"
                ) && value.is_string()
                {
                    *value = Value::String("<deployment-path>".to_string());
                } else {
                    normalize_local_paths(value);
                }
            }
        }
        Value::Array(values) => values.iter_mut().for_each(normalize_local_paths),
        _ => {}
    }
}

/// Hash a complete worker-generation candidate after replacing only
/// deployment-local filesystem paths. Unlike [`event_config_sha256`], this
/// retains state publishers and capacity fields because they participate in
/// the local worker generation handshake. The normalization makes the same
/// signed derivative bundle produce the same generation ID on a different
/// Pod root.
pub fn deployment_path_normalized_sha256(value: &Value) -> Result<String> {
    let mut normalized = value.clone();
    normalize_local_paths(&mut normalized);
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(
        &normalized,
    )?)))
}

/// `event-<snapshot>-<digest16>`. Snapshot 0 is the bootstrap generation
/// (NAN-2361 wave 8): an empty Iceberg side under the same config digest
/// contract, so the identity stays comparable across the first activation.
pub fn event_generation_id(snapshot_id: i64, event_config_sha256: &str) -> Result<String> {
    if snapshot_id < 0
        || event_config_sha256.len() != 64
        || !event_config_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("event generation identity is invalid");
    }
    Ok(format!(
        "event-{snapshot_id}-{}",
        &event_config_sha256[..16]
    ))
}

/// Advance the mutable derivative-state identity without breaking the first
/// event-generation handshake.
///
/// Risk and IOC snapshots may legitimately appear before the first Iceberg
/// event generation. During that window `bootstrap-pending` is a protocol
/// marker: generation activation uses it to install the first complete
/// configuration without waiting for a query worker that cannot start from
/// the placeholder manifest. Preserve that marker while still allowing the
/// derivative assignment itself to be written. Once an event generation is
/// active, state-only changes receive their normal content-derived identity.
pub fn refresh_derivative_generation_id(value: &mut Value) -> Result<String> {
    let current = value
        .get("generation_id")
        .and_then(Value::as_str)
        .context("worker generation identity is missing")?;
    if current == "bootstrap-pending" {
        return Ok(current.to_string());
    }
    value["generation_id"] = Value::String("pending".to_string());
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&value)?));
    let generation_id = format!("lakecfg-{}", &digest[..24]);
    value["generation_id"] = Value::String(generation_id.clone());
    Ok(generation_id)
}

/// NAN-2361: read ONLY the optional `bounds_profile` key out of a
/// worker.json, tolerating every other present or future field.
///
/// Maintenance processes that do not (and must not) validate the full
/// generation config — the tail packer and compactor — still need the
/// deployment's sizing profile. This projection read survives rolling
/// additions to unrelated config sections, and still runs the profile's full
/// inequality validation on the way in (the profile deserializes through its
/// validating wire twin), so a worker.json carrying bounds that cannot work
/// is an ERROR here, never a silent start.
pub fn load_bounds_profile(
    worker_config: &Path,
) -> Result<Option<crate::bounds::LakeBoundsProfile>> {
    let bytes = std::fs::read(worker_config)
        .with_context(|| format!("read worker config {}", worker_config.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("decode worker config {}", worker_config.display()))?;
    match value.get("bounds_profile") {
        None | Some(Value::Null) => Ok(None),
        Some(profile) => Ok(Some(serde_json::from_value(profile.clone()).with_context(
            || {
                format!(
                    "lake bounds profile in {} is invalid; refusing to start with \
                     bounds that violate a cross-layer inequality",
                    worker_config.display()
                )
            },
        )?)),
    }
}

#[derive(Debug, Clone)]
pub struct ArchivedEventConfig {
    pub path: PathBuf,
    pub event_config_sha256: String,
    pub generation_id: String,
}

/// Publish a content-addressed configuration for durable isolated jobs. The
/// active worker file is mutable because state publishers advance risk data;
/// this archive deliberately removes that state and pins executable artifacts
/// by digest so a queued job survives deployments and process restarts.
pub fn archive_event_config(
    worker_config: &Path,
    archive_root: &Path,
    snapshot_id: i64,
) -> Result<ArchivedEventConfig> {
    if !archive_root.is_absolute() {
        anyhow::bail!("event-config archive root must be absolute");
    }
    let original = std::fs::read(worker_config).context("read active worker configuration")?;
    let event_sha256 = event_config_sha256(&original)?;
    let generation_id = event_generation_id(snapshot_id, &event_sha256)?;
    let mut value: Value = serde_json::from_slice(&original)?;
    let object = value
        .as_object_mut()
        .context("worker configuration is not an object")?;
    object.insert(
        "generation_id".to_string(),
        Value::String(generation_id.clone()),
    );
    object.remove("risk_snapshot");
    object.remove("ioc_snapshot");

    let artifacts = archive_root.join("artifacts");
    std::fs::create_dir_all(&artifacts)?;
    for field in ["compiler", "native_library"] {
        let artifact = object
            .get_mut(field)
            .and_then(Value::as_object_mut)
            .with_context(|| format!("worker configuration omitted {field}"))?;
        let source = artifact
            .get("path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .with_context(|| format!("{field} omitted its path"))?;
        let expected = artifact
            .get("sha256")
            .and_then(Value::as_str)
            .with_context(|| format!("{field} omitted its SHA-256"))?;
        let extension = source
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .filter(|value| value.len() <= 16)
            .unwrap_or("bin");
        let destination = artifacts.join(format!("{expected}.{extension}"));
        archive_verified_file(&source, expected, &destination)?;
        artifact.insert(
            "path".to_string(),
            Value::String(destination.to_string_lossy().into_owned()),
        );
    }
    if let Some(tenant) = object.get_mut("tenant").and_then(Value::as_object_mut) {
        tenant.insert(
            "max_memory_bytes".to_string(),
            Value::from(4_294_967_296_u64),
        );
        tenant.insert("max_execution_seconds".to_string(), Value::from(120_u64));
        tenant.insert("threads".to_string(), Value::from(4_u64));
        for field in [
            "analytics_max_memory_bytes",
            "analytics_max_execution_seconds",
            "analytics_threads",
        ] {
            tenant.remove(field);
        }
    }

    let mut encoded = serde_json::to_vec_pretty(&value)?;
    encoded.push(b'\n');
    if event_config_sha256(&encoded)? != event_sha256 {
        anyhow::bail!("archived configuration changed its event-generation identity");
    }
    let configs = archive_root.join("configs");
    std::fs::create_dir_all(&configs)?;
    let path = configs.join(format!("{event_sha256}.json"));
    write_content_addressed(&path, &encoded, Some(&event_sha256))?;
    Ok(ArchivedEventConfig {
        path,
        event_config_sha256: event_sha256,
        generation_id,
    })
}

fn archive_verified_file(source: &Path, expected_sha256: &str, destination: &Path) -> Result<()> {
    if file_sha256(source)? != expected_sha256 {
        anyhow::bail!("source executable failed its configured SHA-256 fence");
    }
    let source_permissions = std::fs::metadata(source)?.permissions();
    if destination.exists() {
        if file_sha256(destination)? != expected_sha256 {
            anyhow::bail!("existing archived executable failed its SHA-256 fence");
        }
        std::fs::set_permissions(destination, source_permissions)?;
        return Ok(());
    }
    let temp = destination.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
    let result = (|| -> Result<()> {
        let mut input = std::fs::File::open(source)?;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        if file_sha256(&temp)? != expected_sha256 {
            anyhow::bail!("copied executable failed its SHA-256 fence");
        }
        match std::fs::hard_link(&temp, destination) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if file_sha256(destination)? == expected_sha256 {
                    Ok(())
                } else {
                    Err(error.into())
                }
            }
            Err(error) => Err(error.into()),
        }
    })();
    let _ = std::fs::remove_file(&temp);
    result?;
    std::fs::set_permissions(destination, source_permissions)?;
    Ok(())
}

fn write_content_addressed(path: &Path, bytes: &[u8], event_sha256: Option<&str>) -> Result<()> {
    fn verify_existing(path: &Path, bytes: &[u8], event_sha256: Option<&str>) -> Result<()> {
        let existing = std::fs::read(path)?;
        let matching_event = event_sha256.is_some_and(|expected| {
            event_config_sha256(&existing)
                .map(|actual| actual == expected)
                .unwrap_or(false)
        });
        if existing == bytes || matching_event {
            Ok(())
        } else {
            anyhow::bail!("event-config archive path contains conflicting bytes")
        }
    }

    if path.exists() {
        return verify_existing(path, bytes, event_sha256);
    }
    let parent = path
        .parent()
        .context("content-addressed archive path has no parent")?;
    let mut candidate = tempfile::NamedTempFile::new_in(parent)?;
    candidate.write_all(bytes)?;
    candidate.as_file().sync_all()?;
    match candidate.persist_noclobber(path) {
        Ok(_) => std::fs::File::open(parent)?
            .sync_all()
            .context("sync content-addressed archive directory"),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            verify_existing(path, bytes, event_sha256)
        }
        Err(error) => Err(error.error.into()),
    }
}

pub struct LoadedWorkerConfig {
    pub admission_proof: Option<crate::generation_proof::Body>,
    pub generation_id: String,
    /// NAN-2361 wave 8: true for the zero-snapshot bootstrap generation
    /// (`crate::bootstrap_generation`). The Iceberg side is provably empty:
    /// `snapshot_cache` carries the empty object-stamp manifest, the entity
    /// index set is empty, and no keyword, fragment, count-rollup, identity,
    /// or prevalence derivative exists. The worker serves the signed hot tail
    /// alone until the first real generation activates.
    pub bootstrap: bool,
    pub assigned_tenant_id: String,
    pub compiler: PathBuf,
    pub source_manifest: PathBuf,
    pub tenant: TenantQueryConfig,
    pub analytics_tenant: TenantQueryConfig,
    pub runtime: NativeChdb,
    pub entity_sidecar: LoadedEntitySidecarConfig,
    pub keyword_sidecar: LoadedKeywordSidecarConfig,
    pub count_rollup: Option<LoadedCountRollupConfig>,
    pub identity_snapshot: Option<LoadedIdentitySnapshotConfig>,
    pub ioc_snapshot: Option<LoadedIocSnapshotConfig>,
    pub prevalence_snapshots: BTreeMap<String, LoadedPrevalenceSnapshotConfig>,
    pub risk_snapshot: Option<LoadedRiskSnapshotConfig>,
}

pub struct LoadedEntitySidecarConfig {
    pub manifest: PathBuf,
    pub hmac_key: PathBuf,
    pub index_files: Vec<PathBuf>,
}

pub struct LoadedKeywordSidecarConfig {
    pub manifest: PathBuf,
    pub index_directory: PathBuf,
    pub fragment_manifest: PathBuf,
    pub fragment_index_directory: PathBuf,
}

pub struct LoadedCountRollupConfig {
    pub manifest: PathBuf,
    pub data_directory: PathBuf,
}

pub struct LoadedIdentitySnapshotConfig {
    pub snapshot_id: String,
    pub by_ip: PathBuf,
    pub by_ip_sha256: String,
    pub by_ip_bytes: u64,
    pub by_ip_modified: std::time::SystemTime,
}

pub struct LoadedIocSnapshotConfig {
    pub snapshot_id: String,
    pub data: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

/// Everything ingest-time prevalence stamping needs from the worker config.
pub struct LoadedPrevalenceAssignment {
    pub snapshots: BTreeMap<String, LoadedPrevalenceSnapshotConfig>,
    pub hmac_key: PathBuf,
    /// Exact configuration whose artifact bytes were verified before this
    /// assignment was admitted. Reusing this fence is safe only while every
    /// checkpoint, path, digest, and serving option remains byte-for-byte the
    /// same.
    pub verified: BTreeMap<String, PrevalenceSnapshotConfigFile>,
}

pub struct LoadedPrevalenceSnapshotConfig {
    pub snapshot_id: String,
    pub window: String,
    pub object_store_url: String,
    pub database_path: String,
    pub checkpoint_id: uuid::Uuid,
    pub scan_files: Vec<LoadedImmutableFile>,
    pub explorer: Option<LoadedImmutableFile>,
    pub daily_history: Option<LoadedPrevalenceDailyHistory>,
    pub source_types: Vec<String>,
    pub rarity_threshold: u64,
}

pub struct LoadedPrevalenceDailyHistory {
    pub scan_file: LoadedImmutableFile,
    pub daily_start: chrono::NaiveDate,
}

#[derive(Clone)]
pub struct LoadedImmutableFile {
    pub path: PathBuf,
    pub bytes: u64,
    pub modified: std::time::SystemTime,
}

pub struct LoadedRiskSnapshotConfig {
    pub snapshot_id: String,
    pub snapshot_version: String,
    pub source: PathBuf,
    pub bytes: u64,
    pub modified: std::time::SystemTime,
    pub clear_snapshot_version: Option<String>,
    pub clear_source: Option<PathBuf>,
    pub clear_bytes: u64,
    pub clear_modified: Option<std::time::SystemTime>,
    pub clear_published_revision: i64,
    pub global_clear_us: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadedWorkerCapacityConfig {
    pub max_memory_bytes: u64,
    pub max_execution_seconds: u64,
    pub threads: u64,
}

/// The seed writes this digest for every artifact that does not exist yet;
/// the bootstrap generation keeps it for the derivatives an empty table has
/// no objects to build.
const BOOTSTRAP_PLACEHOLDER_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

impl WorkerConfigFile {
    /// NAN-2361 wave 8: is this the zero-snapshot bootstrap generation?
    ///
    /// Decided by SHAPE -- the snapshot cache names the exact empty
    /// bootstrap object-stamp manifest -- not by the identity string alone.
    /// A risk or IOC state publication rotates `generation_id` from
    /// `lake-0-…` to `lakecfg-…` without touching the event side (exactly as
    /// it does for a real generation), and the worker must still recognize
    /// and load the bootstrap after such a rotation. `resolve` then requires
    /// the identity to be one of those two forms, and `load_snapshot_cache`
    /// re-reads the manifest through the digest fence before admitting it.
    pub fn is_bootstrap_generation(&self) -> bool {
        self.snapshot_cache
            .as_ref()
            .and_then(|cache| std::fs::read(&cache.object_stamp_manifest.path).ok())
            .and_then(|bytes| serde_json::from_slice::<ObjectStampManifest>(&bytes).ok())
            .is_some_and(|stamps| crate::bootstrap_generation::is_bootstrap_stamps(&stamps))
    }

    pub fn admission_proof(&self) -> Result<crate::generation_proof::Body> {
        let reference = self.generation_proof.as_ref().context("generation has no admission proof")?;
        verify_artifact(&self.entity_sidecar.hmac_key)?;
        let key = crate::generation_proof::key(&self.entity_sidecar.hmac_key.path)?;
        if reference.identity.tenant_id != self.assigned_tenant_id { anyhow::bail!("proof tenant mismatch"); }
        if let Ok(revision) = std::env::var("NANO_LAKE_WORKER_ASSIGNMENT_REVISION") {
            if revision.parse::<i64>()? != reference.identity.assignment_revision { anyhow::bail!("proof assignment revision mismatch"); }
        }
        if let Ok(table_uuid) = std::env::var("NANO_LAKE_HANDOVER_TABLE_UUID") {
            if table_uuid != reference.identity.table_uuid { anyhow::bail!("proof table UUID differs from current assignment"); }
        }
        let proof = crate::generation_proof::Body::load(reference, &key)?;
        let cache = self.snapshot_cache.as_ref().context("proven generation has no snapshot cache")?;
        if proof.file_digest(&cache.object_stamp_manifest.path) != Some(cache.object_stamp_manifest.sha256.as_str()) {
            anyhow::bail!("proof transformed source manifest mismatch");
        }
        let stamps: ObjectStampManifest = serde_json::from_slice(&std::fs::read(&cache.object_stamp_manifest.path)?)?;
        if stamps.snapshot_id != proof.identity.snapshot_id
            || stamps.table_uuid.as_ref().is_some_and(|uuid| uuid != &proof.identity.table_uuid)
            || crate::generation_bundle::object_stamp_manifest_sha256(&crate::generation_bundle::GenerationBundleObjectStampManifest::from(&stamps))? != proof.identity.source_stamp_sha256 {
            anyhow::bail!("proof snapshot identity mismatch");
        }
        Ok(proof)
    }

    pub fn read(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(ConfigError::Read)?;
        serde_json::from_slice(&bytes).map_err(ConfigError::Decode)
    }

    /// Load only the tenant-pinned IOC assignment used by ingest publication.
    /// This deliberately avoids opening unrelated risk/prevalence state every
    /// time the Bronze publisher checks for a feed generation change.
    pub fn load_ioc_only(
        bytes: &[u8],
        assigned_tenant_id: &str,
        max_query_bytes: u64,
    ) -> Result<Option<LoadedIocSnapshotConfig>, ConfigError> {
        let configured: Self = serde_json::from_slice(bytes).map_err(ConfigError::Decode)?;
        validate_partial_state_assignment(&configured, assigned_tenant_id, "IOC")?;
        load_ioc_snapshot_config(configured.ioc_snapshot, max_query_bytes)
    }

    /// Load only the prevalence assignments and HMAC key that ingest-time
    /// prevalence stamping needs. Mirrors `load_ioc_only`: Bronze re-reads the
    /// worker config at each poll boundary to notice a generation rotation, and
    /// must not pay for risk state, the native library, or Iceberg credentials
    /// to do it.
    ///
    /// The HMAC key is the SAME key the entity sidecar and the query worker use;
    /// prevalence keys are HMACs of (kind, scope, entity), so a different key
    /// would silently produce misses that are indistinguishable from "brand new
    /// artifact" and would stamp every row as rare.
    ///
    /// `verified` carries the exact prevalence assignment the caller already
    /// holds active. An exact match skips only the content re-hash; any changed
    /// checkpoint, path, digest, or serving option is verified in full before
    /// adoption. Pass an empty map to verify everything.
    pub fn load_prevalence_only(
        bytes: &[u8],
        assigned_tenant_id: &str,
        max_query_bytes: u64,
        verified: &BTreeMap<String, PrevalenceSnapshotConfigFile>,
    ) -> Result<Option<LoadedPrevalenceAssignment>, ConfigError> {
        let configured: Self = serde_json::from_slice(bytes).map_err(ConfigError::Decode)?;
        validate_partial_state_assignment(&configured, assigned_tenant_id, "prevalence")?;
        let prevalence_config = configured.prevalence_snapshots;
        if prevalence_config.is_empty() {
            return Ok(None);
        }
        // The HMAC key selects every SlateDB lookup key. The full worker load
        // verifies it, but this lightweight Bronze reload previously trusted
        // only its path. A mixed or tampered config could therefore stamp one
        // tenant's events through another tenant's derived key namespace.
        verify_artifact(&configured.entity_sidecar.hmac_key)?;
        let hmac_key = configured.entity_sidecar.hmac_key.path;
        let snapshots =
            load_prevalence_snapshot_configs(prevalence_config.clone(), max_query_bytes, verified)?;
        Ok(Some(LoadedPrevalenceAssignment {
            snapshots,
            hmac_key,
            verified: prevalence_config,
        }))
    }

    /// NAN-2361: load the ingest prevalence assignment a Bronze publisher
    /// projected from a signed prevalence hand-off. The file is not a
    /// worker.json (a publisher has no compiler, sidecars, or source manifest);
    /// it carries exactly the identity, HMAC key, and prevalence snapshot
    /// entries that `load_prevalence_only` would read out of one, validated by
    /// the same snapshot loader so both paths admit the same assignments.
    pub fn load_prevalence_handoff(
        bytes: &[u8],
        assigned_tenant_id: &str,
        verified: &BTreeMap<String, PrevalenceSnapshotConfigFile>,
    ) -> Result<Option<LoadedPrevalenceAssignment>, ConfigError> {
        let configured: PrevalenceHandoffConfigFile =
            serde_json::from_slice(bytes).map_err(ConfigError::Decode)?;
        if configured.schema_version != 1
            || configured.generation_id.is_empty()
            || configured.generation_id.len() > 256
            || configured.generation_id.chars().any(char::is_control)
            || configured.assigned_tenant_id != assigned_tenant_id
            || configured.tenant.tenant_id != assigned_tenant_id
            || configured.snapshot_id <= 0
            || configured.tenant.max_query_bytes == 0
        {
            return Err(ConfigError::Invalid(
                "prevalence hand-off configuration changed the generation or tenant boundary"
                    .to_string(),
            ));
        }
        validate_sha256(&configured.bundle_identity_sha256)?;
        validate_sha256(&configured.handoff_manifest_sha256)?;
        if configured.prevalence_snapshots.is_empty() {
            return Ok(None);
        }
        verify_artifact(&configured.entity_sidecar.hmac_key)?;
        let hmac_key = configured.entity_sidecar.hmac_key.path;
        let snapshots = load_prevalence_snapshot_configs(
            configured.prevalence_snapshots.clone(),
            configured.tenant.max_query_bytes,
            verified,
        )?;
        Ok(Some(LoadedPrevalenceAssignment {
            snapshots,
            hmac_key,
            verified: configured.prevalence_snapshots,
        }))
    }

    pub fn load(path: &Path) -> Result<LoadedWorkerConfig, ConfigError> {
        Self::read(path)?.resolve(false)
    }

    /// Load a worker configuration for a process that serves count-rollup
    /// parts through a derivative tier (NAN-2361). Identical to [`Self::load`]
    /// except for ONE deliberate relaxation: the count-rollup data directory
    /// is a bounded local cache over content-addressed object storage, so a
    /// part that is absent locally is "tiered", not corrupt, and the
    /// whole-tree digest (`data_tree_sha256`) can no longer be required to
    /// match. Integrity is not weakened: the manifest itself remains a
    /// sha-pinned [`VerifiedArtifact`], and `CountRollup::load_tiered`
    /// re-fences every part that IS present (byte length plus sha256 against
    /// that manifest) while parts that are absent are only ever read back
    /// through the same digest fence at hydration or by an exact
    /// content-addressed object read.
    ///
    /// With `tiered_count_rollup = false` this is byte-for-byte `load`.
    pub fn load_with_derivative_tiering(
        path: &Path,
        tiered_count_rollup: bool,
    ) -> Result<LoadedWorkerConfig, ConfigError> {
        Self::read(path)?.resolve(tiered_count_rollup)
    }

    pub fn load_risk_only(
        bytes: &[u8],
        assigned_tenant_id: &str,
        max_query_bytes: u64,
    ) -> Result<
        (
            String,
            Option<LoadedRiskSnapshotConfig>,
            Option<LoadedIocSnapshotConfig>,
            LoadedWorkerCapacityConfig,
        ),
        ConfigError,
    > {
        let configured: Self = serde_json::from_slice(bytes).map_err(ConfigError::Decode)?;
        if configured.schema_version != 1
            || configured.assigned_tenant_id != assigned_tenant_id
            || configured.tenant.tenant_id != assigned_tenant_id
            || configured.generation_id.is_empty()
            || configured.generation_id.len() > 256
            || configured.generation_id.chars().any(char::is_control)
        {
            return Err(ConfigError::Invalid(
                "risk-only reload changed the worker generation or tenant boundary".to_string(),
            ));
        }
        let risk = load_risk_snapshot_config(
            configured.risk_snapshot,
            assigned_tenant_id,
            max_query_bytes,
        )?;
        let ioc = load_ioc_snapshot_config(configured.ioc_snapshot, max_query_bytes)?;
        Ok((
            configured.generation_id,
            risk,
            ioc,
            LoadedWorkerCapacityConfig {
                max_memory_bytes: configured.tenant.max_memory_bytes,
                max_execution_seconds: configured.tenant.max_execution_seconds,
                threads: configured.tenant.threads,
            },
        ))
    }

    /// Every digest-pinned file and tree `resolve` fences, as one batch for
    /// the bounded-parallel verifier (NAN-2361 cold start).
    ///
    /// Deliberately NOT in the plan:
    /// * `native_library` -- `NativeChdb::load_verified` hashes it itself
    ///   immediately before `dlopen`, and that coupling (hash the exact bytes
    ///   you are about to execute) is worth one serial file.
    /// * snapshot-cache event objects -- `load_snapshot_cache` decides per
    ///   object whether the hydrator's stat-corroborated ledger already
    ///   vouches for it, and runs its own parallel batch over the remainder.
    /// * risk snapshot Parquet -- its digest lives inside the risk manifest,
    ///   which must be parsed first; it is one bounded file.
    pub(crate) fn verification_plan(&self, tiered_count_rollup: bool) -> crate::verify::VerificationPlan {
        let mut plan = crate::verify::VerificationPlan::new();
        plan.file(&self.compiler);
        plan.file(&self.tenant.source_manifest);
        if let Some(cache) = &self.snapshot_cache {
            plan.file(&cache.object_stamp_manifest);
            if let Some(schema) = &cache.read_schema {
                plan.file(schema);
            }
        }
        plan.file(&self.entity_sidecar.manifest);
        plan.file(&self.entity_sidecar.hmac_key);
        for file in &self.entity_sidecar.index_files {
            plan.file(file);
        }
        // The bootstrap generation has no keyword or fragment tree (its
        // placeholders are the seed's zero digests and absent directories);
        // `resolve` proves the placeholder shape instead of hashing it.
        if !self.is_bootstrap_generation() {
            plan.file(&self.keyword_sidecar.manifest);
            plan.file(&self.keyword_sidecar.fragment_manifest);
            plan.tree(
                &self.keyword_sidecar.index_directory,
                &self.keyword_sidecar.index_tree_sha256,
                "keyword",
            );
            plan.tree(
                &self.keyword_sidecar.fragment_index_directory,
                &self.keyword_sidecar.fragment_index_tree_sha256,
                "fragment",
            );
        }
        if let Some(rollup) = &self.count_rollup {
            plan.file(&rollup.manifest);
            if !tiered_count_rollup {
                plan.tree(&rollup.data_directory, &rollup.data_tree_sha256, "count-rollup");
            }
        }
        if let Some(identity) = &self.identity_snapshot {
            plan.file(&identity.by_ip);
        }
        if let Some(ioc) = &self.ioc_snapshot {
            plan.file(&ioc.data);
        }
        for snapshot in self.prevalence_snapshots.values() {
            for file in &snapshot.scan_files {
                plan.file(file);
            }
            if let Some(explorer) = &snapshot.explorer {
                plan.file(explorer);
            }
            if let Some(history) = &snapshot.daily_history {
                plan.file(&history.scan_file);
            }
        }
        if let Some(risk) = &self.risk_snapshot {
            plan.file(&risk.manifest);
        }
        plan
    }

    fn resolve(self, tiered_count_rollup: bool) -> Result<LoadedWorkerConfig, ConfigError> {
        if let Some(root) = self.snapshot_cache.as_ref().and_then(|cache| cache.data_directory.parent()).and_then(Path::parent) {
            crate::generation_proof::ensure_not_retired(root).map_err(|error| ConfigError::Invalid(error.to_string()))?;
        }
        if let Some(reference) = &self.generation_proof {
            // Full hashing cannot repair a known assignment mismatch.
            if std::env::var("NANO_LAKE_HANDOVER_TABLE_UUID").ok().is_some_and(|uuid| uuid != reference.identity.table_uuid)
                || std::env::var("NANO_LAKE_WORKER_ASSIGNMENT_REVISION").ok().is_some_and(|revision| revision.parse::<i64>().ok() != Some(reference.identity.assignment_revision)) {
                return Err(ConfigError::Invalid("generation proof belongs to a different current assignment".to_string()));
            }
        }

        if self.schema_version != 1
            || self.generation_id.is_empty()
            || self.generation_id.len() > 256
            || self.generation_id.chars().any(char::is_control)
            || self.assigned_tenant_id.is_empty()
            || self.tenant.tenant_id != self.assigned_tenant_id
            || self.tenant.event_contract != "ocsf-1.9"
            || !self.tenant.allow_broad_npl
        {
            return Err(ConfigError::Invalid(
                "worker requires one assigned OCSF 1.9 tenant with broad nPL enabled".to_string(),
            ));
        }
        // NAN-2361 cold start: every digest-pinned artifact and tree below is
        // hashed ONCE, concurrently, under a bounded pool (see verify.rs),
        // and each site then consults that proof where it used to hash
        // serially. A site the plan missed still hashes in full at its own
        // call, so the fence can only get faster here, never weaker.
        let workers = crate::verify::verify_workers();
        let proof = match self.admission_proof() {
            Ok(proof) => Some(proof),
            Err(error) => {
                // NAN-2532: name the REAL reason. The fallback re-derives both
                // tree identities from disk (see
                // `index_directory_digests_cancellable`), so a content-store
                // generation still verifies here -- but if it then fails, the
                // operator must see that the proof was missing first, not a
                // bare "index directory digest mismatch" that reads like
                // corrupted data.
                tracing::error!(
                    %error,
                    proof_path = ?self.generation_proof.as_ref().map(|reference| reference.path.clone()),
                    "generation admission proof could not be authenticated; every pinned artifact and tree will be re-hashed from disk (slower boot, not data loss)"
                );
                None
            }
        };
        let verified = self.verification_plan(tiered_count_rollup).run_proven(workers, proof.as_ref(),
            &[self.compiler.path.clone(), self.native_library.path.clone(), self.entity_sidecar.hmac_key.path.clone()])?;
        tracing::info!(
            files = verified.report.files,
            trees = verified.report.trees,
            bytes = verified.report.bytes,
            workers = verified.report.workers,
            seconds = verified.report.elapsed.as_secs_f64(),
            "verified generation artifacts"
        );
        verified.verify_artifact(&self.compiler)?;
        verified.verify_artifact(&self.tenant.source_manifest)?;
        let bootstrap = self.is_bootstrap_generation();
        let snapshot_cache = self
            .snapshot_cache
            .map(|configured| load_snapshot_cache(configured, &verified, workers, bootstrap))
            .transpose()?;
        verified.verify_artifact(&self.entity_sidecar.manifest)?;
        verified.verify_artifact(&self.entity_sidecar.hmac_key)?;
        if bootstrap {
            // The zero-snapshot form is admitted ONLY as the complete empty
            // shape: an empty snapshot cache that proved snapshot 0 with the
            // table UUID bound, no entity index, the seed's keyword/fragment
            // placeholders, and no derivative of any kind. A bootstrap
            // identity over a real artifact set, or a real identity over an
            // empty one, is refused: neither can be an honest generation.
            let bootstrap_identity =
                crate::bootstrap_generation::is_bootstrap_generation_id(&self.generation_id)
                    || self.generation_id.starts_with("lakecfg-");
            if !bootstrap_identity
                || snapshot_cache
                    .as_ref()
                    .is_none_or(|cache| !cache.bootstrap)
                || !self.entity_sidecar.index_files.is_empty()
                || self.keyword_sidecar.index_tree_sha256 != BOOTSTRAP_PLACEHOLDER_SHA256
                || self.keyword_sidecar.fragment_index_tree_sha256 != BOOTSTRAP_PLACEHOLDER_SHA256
                || self.keyword_sidecar.manifest.sha256 != BOOTSTRAP_PLACEHOLDER_SHA256
                || self.keyword_sidecar.fragment_manifest.sha256 != BOOTSTRAP_PLACEHOLDER_SHA256
                || self.keyword_sidecar.index_directory.exists()
                || self.keyword_sidecar.fragment_index_directory.exists()
                || self.count_rollup.is_some()
                || self.identity_snapshot.is_some()
                || !self.prevalence_snapshots.is_empty()
            {
                return Err(ConfigError::Invalid(
                    "bootstrap generation must be exactly the empty zero-snapshot form"
                        .to_string(),
                ));
            }
        } else {
            if snapshot_cache.as_ref().is_some_and(|cache| cache.bootstrap) {
                return Err(ConfigError::Invalid(
                    "an empty zero-snapshot cache is only valid under a bootstrap generation identity"
                        .to_string(),
                ));
            }
            if self.entity_sidecar.index_files.is_empty() {
                return Err(ConfigError::Invalid(
                    "entity sidecar requires immutable index files".to_string(),
                ));
            }
            for file in &self.entity_sidecar.index_files {
                verified.verify_artifact(file)?;
            }
            verified.verify_artifact(&self.keyword_sidecar.manifest)?;
            verified.verify_artifact(&self.keyword_sidecar.fragment_manifest)?;
            verified.verify_index_directory(
                &self.keyword_sidecar.index_directory,
                &self.keyword_sidecar.index_tree_sha256,
                "keyword",
            )?;
        }
        let count_rollup = self
            .count_rollup
            .map(|configured| {
                verified.verify_artifact(&configured.manifest)?;
                if !tiered_count_rollup {
                    verified.verify_index_directory(
                        &configured.data_directory,
                        &configured.data_tree_sha256,
                        "count-rollup",
                    )?;
                }
                // Tiered: the directory is a partial local cache, so the
                // whole-tree digest cannot hold. Every part that is present
                // is still individually re-fenced against the sha-pinned
                // manifest in CountRollup::load_tiered, and absent parts are
                // resolved by content address only.
                Ok::<_, ConfigError>(LoadedCountRollupConfig {
                    manifest: configured.manifest.path,
                    data_directory: configured.data_directory,
                })
            })
            .transpose()?;
        if !bootstrap {
            verified.verify_index_directory(
                &self.keyword_sidecar.fragment_index_directory,
                &self.keyword_sidecar.fragment_index_tree_sha256,
                "fragment",
            )?;
        }
        let identity_snapshot = self
            .identity_snapshot
            .map(|snapshot| {
                if snapshot.snapshot_id.is_empty()
                    || snapshot.snapshot_id.len() > 256
                    || snapshot.snapshot_id.chars().any(char::is_control)
                {
                    return Err(ConfigError::Invalid(
                        "identity snapshot ID is invalid".to_string(),
                    ));
                }
                verified.verify_artifact(&snapshot.by_ip)?;
                let metadata =
                    std::fs::metadata(&snapshot.by_ip.path).map_err(ConfigError::Read)?;
                let by_ip_bytes = metadata.len();
                let by_ip_modified = metadata.modified().map_err(ConfigError::Read)?;
                if by_ip_bytes == 0 || by_ip_bytes > self.tenant.max_query_bytes {
                    return Err(ConfigError::Invalid(
                        "identity by-IP snapshot is empty or exceeds the tenant query budget"
                            .to_string(),
                    ));
                }
                Ok(LoadedIdentitySnapshotConfig {
                    snapshot_id: snapshot.snapshot_id,
                    by_ip: snapshot.by_ip.path,
                    by_ip_sha256: snapshot.by_ip.sha256,
                    by_ip_bytes,
                    by_ip_modified,
                })
            })
            .transpose()?;
        let ioc_snapshot = load_ioc_snapshot_config_verified(
            self.ioc_snapshot,
            self.tenant.max_query_bytes,
            &verified,
        )?;
        // Every prevalence artifact was hashed by the plan above, which is
        // exactly the proof the NAN-2380 `verified` map encodes (an artifact
        // set whose digests this process has already checked); any artifact
        // the plan did not cover is hashed inside the loader as before.
        let prevalence_verified = self
            .prevalence_snapshots
            .iter()
            .filter(|(_, snapshot)| {
                snapshot
                    .scan_files
                    .iter()
                    .chain(snapshot.explorer.iter())
                    .chain(snapshot.daily_history.iter().map(|history| &history.scan_file))
                    .all(|artifact| verified.covers_file(artifact))
            })
            .map(|(snapshot_id, snapshot)| (snapshot_id.clone(), snapshot.clone()))
            .collect::<BTreeMap<_, _>>();
        let prevalence_snapshots = load_prevalence_snapshot_configs(
            self.prevalence_snapshots,
            self.tenant.max_query_bytes,
            &prevalence_verified,
        )?;
        let risk_snapshot = load_risk_snapshot_config(
            self.risk_snapshot,
            &self.assigned_tenant_id,
            self.tenant.max_query_bytes,
        )?;
        let runtime =
            NativeChdb::load_verified(&self.native_library.path, &self.native_library.sha256)?;
        let credentials = if self.tenant.iceberg_default_credentials {
            if self.tenant.iceberg_access_key_env.is_some()
                || self.tenant.iceberg_secret_key_env.is_some()
                || self.tenant.iceberg_session_token_env.is_some()
            {
                return Err(ConfigError::Invalid(
                    "default Iceberg credentials cannot be combined with static credential environments"
                        .to_string(),
                ));
            }
            ObjectStoreCredentials::DefaultChain
        } else {
            let access_env = self
                .tenant
                .iceberg_access_key_env
                .as_deref()
                .ok_or_else(|| {
                    ConfigError::Invalid(
                        "static Iceberg mode requires an access-key environment".to_string(),
                    )
                })?;
            let secret_env = self
                .tenant
                .iceberg_secret_key_env
                .as_deref()
                .ok_or_else(|| {
                    ConfigError::Invalid(
                        "static Iceberg mode requires a secret-key environment".to_string(),
                    )
                })?;
            ObjectStoreCredentials::Static {
                access_key: required_secret_env(access_env)?,
                secret_key: required_secret_env(secret_env)?,
                session_token: self
                    .tenant
                    .iceberg_session_token_env
                    .as_deref()
                    .map(required_secret_env)
                    .transpose()?,
            }
        };
        let tenant = TenantQueryConfig {
            tenant_id: self.tenant.tenant_id,
            source: self.tenant.source,
            iceberg_metadata_file_path: self.tenant.iceberg_metadata_file_path,
            max_query_bytes: self.tenant.max_query_bytes,
            max_memory_bytes: self.tenant.max_memory_bytes,
            max_execution_seconds: self.tenant.max_execution_seconds,
            threads: self.tenant.threads,
            credentials,
            snapshot_cache,
        };
        validate_tenant(&tenant).map_err(|error| ConfigError::Invalid(error.to_string()))?;
        let mut analytics_tenant = tenant.clone();
        analytics_tenant.max_memory_bytes = self
            .tenant
            .analytics_max_memory_bytes
            .unwrap_or(tenant.max_memory_bytes);
        analytics_tenant.max_execution_seconds = self
            .tenant
            .analytics_max_execution_seconds
            .unwrap_or(tenant.max_execution_seconds);
        analytics_tenant.threads = self.tenant.analytics_threads.unwrap_or(tenant.threads);
        validate_tenant(&analytics_tenant)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        if analytics_tenant.max_memory_bytes < tenant.max_memory_bytes
            || analytics_tenant.max_execution_seconds < tenant.max_execution_seconds
        {
            return Err(ConfigError::Invalid(
                "analytics query limits must not be lower than interactive limits".to_string(),
            ));
        }
        Ok(LoadedWorkerConfig {
            admission_proof: proof,
            generation_id: self.generation_id,
            bootstrap,
            assigned_tenant_id: self.assigned_tenant_id,
            compiler: self.compiler.path,
            source_manifest: self.tenant.source_manifest.path,
            tenant,
            analytics_tenant,
            runtime,
            entity_sidecar: LoadedEntitySidecarConfig {
                manifest: self.entity_sidecar.manifest.path,
                hmac_key: self.entity_sidecar.hmac_key.path,
                index_files: self
                    .entity_sidecar
                    .index_files
                    .into_iter()
                    .map(|artifact| artifact.path)
                    .collect(),
            },
            keyword_sidecar: LoadedKeywordSidecarConfig {
                manifest: self.keyword_sidecar.manifest.path,
                index_directory: self.keyword_sidecar.index_directory,
                fragment_manifest: self.keyword_sidecar.fragment_manifest.path,
                fragment_index_directory: self.keyword_sidecar.fragment_index_directory,
            },
            count_rollup,
            identity_snapshot,
            ioc_snapshot,
            prevalence_snapshots,
            risk_snapshot,
        })
    }
}

/// Validate the tenant identity shared by every lightweight derived-state
/// reload before any artifact path is opened. These loaders deliberately skip
/// unrelated worker state, but they must retain the full load's schema,
/// generation, and exact inner/outer tenant binding.
fn validate_partial_state_assignment(
    configured: &WorkerConfigFile,
    assigned_tenant_id: &str,
    state: &str,
) -> Result<(), ConfigError> {
    if configured.schema_version != 1
        || configured.generation_id.is_empty()
        || configured.generation_id.len() > 256
        || configured.generation_id.chars().any(char::is_control)
        || configured.assigned_tenant_id != assigned_tenant_id
        || configured.tenant.tenant_id != assigned_tenant_id
    {
        return Err(ConfigError::Invalid(format!(
            "{state} state configuration changed the worker generation or tenant boundary"
        )));
    }
    Ok(())
}

/// Validate and load the tenant's prevalence snapshot assignments.
///
/// Extracted from `load()` so the Bronze publisher can resolve the same
/// assignments for ingest-time prevalence stamping without opening unrelated
/// risk/IOC/native state. One validator, two callers: an assignment Bronze
/// would accept is exactly one the query worker would accept.
fn load_prevalence_snapshot_configs(
    configured: BTreeMap<String, PrevalenceSnapshotConfigFile>,
    max_query_bytes: u64,
    verified: &BTreeMap<String, PrevalenceSnapshotConfigFile>,
) -> Result<BTreeMap<String, LoadedPrevalenceSnapshotConfig>, ConfigError> {
    if configured.len() > 16 {
        return Err(ConfigError::Invalid(
            "worker accepts at most 16 prevalence snapshots".to_string(),
        ));
    }
    let mut prevalence_snapshots = BTreeMap::new();
    for (snapshot_id, snapshot) in configured {
        if snapshot_id.is_empty()
            || snapshot_id.len() > 256
            || !snapshot_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
            || !matches!(snapshot.window.as_str(), "1h" | "24h" | "7d" | "30d")
            || snapshot.object_store_url != "file:///"
            || snapshot.database_path.is_empty()
            || std::path::Path::new(&snapshot.database_path).is_absolute()
            || std::path::Path::new(&snapshot.database_path)
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || snapshot.source_types.is_empty()
            || snapshot.source_types.len() > 1_024
            || snapshot.scan_files.is_empty()
            || snapshot.scan_files.len() > 64
            || snapshot.rarity_threshold == 0
            || snapshot.rarity_threshold > 10_000
        {
            return Err(ConfigError::Invalid(
                "prevalence snapshot violates its identity, window, store, scope, or threshold contract"
                    .to_string(),
            ));
        }
        let already_verified = verified.get(&snapshot_id) == Some(&snapshot);
        let source_types = snapshot
            .source_types
            .into_iter()
            .map(|source| source.trim().to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        if source_types.iter().any(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        }) {
            return Err(ConfigError::Invalid(
                "prevalence snapshot source type is invalid".to_string(),
            ));
        }
        // NAN-2380: an exact snapshot assignment the caller already holds
        // active was digest-verified when it was adopted, and its artifacts
        // are immutable by contract. Re-hashing it on every poll made the
        // Bronze publisher re-read 653 MB of prevalence Parquet per cycle --
        // 3.4 s of software SHA-256 on a COMPLETELY IDLE publisher, pinning a
        // core forever. The exact comparison is important: a changed path or
        // digest behind the same checkpoint must still be verified in full.
        let mut scan_files = Vec::with_capacity(snapshot.scan_files.len());
        let mut scan_bytes = 0_u64;
        for artifact in &snapshot.scan_files {
            verify_prevalence_artifact(artifact, already_verified)?;
            if artifact.path.extension().and_then(|value| value.to_str()) != Some("parquet") {
                return Err(ConfigError::Invalid(
                    "prevalence scan artifacts must be Parquet files".to_string(),
                ));
            }
            let metadata = std::fs::metadata(&artifact.path).map_err(ConfigError::Read)?;
            scan_bytes = scan_bytes.checked_add(metadata.len()).ok_or_else(|| {
                ConfigError::Invalid("prevalence scan byte budget overflow".to_string())
            })?;
            scan_files.push(LoadedImmutableFile {
                path: artifact.path.clone(),
                bytes: metadata.len(),
                modified: metadata.modified().map_err(ConfigError::Read)?,
            });
        }
        if scan_bytes == 0 || scan_bytes > max_query_bytes {
            return Err(ConfigError::Invalid(
                "prevalence scan artifacts are empty or exceed the tenant query budget".to_string(),
            ));
        }
        let explorer = snapshot
            .explorer
            .map(|artifact| {
                verify_prevalence_artifact(&artifact, already_verified)?;
                if artifact.path.extension().and_then(|value| value.to_str()) != Some("parquet") {
                    return Err(ConfigError::Invalid(
                        "prevalence explorer artifact must be Parquet".to_string(),
                    ));
                }
                let metadata = std::fs::metadata(&artifact.path).map_err(ConfigError::Read)?;
                if metadata.len() == 0 || metadata.len() > max_query_bytes {
                    return Err(ConfigError::Invalid(
                        "prevalence explorer artifact exceeds the tenant query budget".to_string(),
                    ));
                }
                Ok::<_, ConfigError>(LoadedImmutableFile {
                    path: artifact.path,
                    bytes: metadata.len(),
                    modified: metadata.modified().map_err(ConfigError::Read)?,
                })
            })
            .transpose()?;
        let daily_history = snapshot
            .daily_history
            .map(|history| {
                verify_prevalence_artifact(&history.scan_file, already_verified)?;
                if history
                    .scan_file
                    .path
                    .extension()
                    .and_then(|value| value.to_str())
                    != Some("parquet")
                {
                    return Err(ConfigError::Invalid(
                        "prevalence daily-history artifact must be Parquet".to_string(),
                    ));
                }
                let metadata =
                    std::fs::metadata(&history.scan_file.path).map_err(ConfigError::Read)?;
                if metadata.len() == 0 || metadata.len() > max_query_bytes {
                    return Err(ConfigError::Invalid(
                        "prevalence daily-history artifact exceeds the tenant query budget"
                            .to_string(),
                    ));
                }
                let daily_start =
                    chrono::NaiveDate::parse_from_str(&history.daily_start, "%Y-%m-%d").map_err(
                        |_| {
                            ConfigError::Invalid(
                                "prevalence daily-history start must be an ISO date".to_string(),
                            )
                        },
                    )?;
                Ok::<_, ConfigError>(LoadedPrevalenceDailyHistory {
                    scan_file: LoadedImmutableFile {
                        path: history.scan_file.path,
                        bytes: metadata.len(),
                        modified: metadata.modified().map_err(ConfigError::Read)?,
                    },
                    daily_start,
                })
            })
            .transpose()?;
        prevalence_snapshots.insert(
            snapshot_id.clone(),
            LoadedPrevalenceSnapshotConfig {
                snapshot_id,
                window: snapshot.window,
                object_store_url: snapshot.object_store_url,
                database_path: snapshot.database_path,
                checkpoint_id: snapshot.checkpoint_id,
                scan_files,
                explorer,
                daily_history,
                source_types: source_types.into_iter().collect(),
                rarity_threshold: snapshot.rarity_threshold,
            },
        );
    }
    Ok(prevalence_snapshots)
}

fn load_ioc_snapshot_config(
    configured: Option<IocSnapshotConfigFile>,
    max_query_bytes: u64,
) -> Result<Option<LoadedIocSnapshotConfig>, ConfigError> {
    load_ioc_snapshot_config_verified(
        configured,
        max_query_bytes,
        &crate::verify::VerifiedArtifacts::none(),
    )
}

/// `load_ioc_snapshot_config` that accepts a proof from the parallel
/// verifier; an artifact the proof does not cover is hashed here.
fn load_ioc_snapshot_config_verified(
    configured: Option<IocSnapshotConfigFile>,
    max_query_bytes: u64,
    verified: &crate::verify::VerifiedArtifacts,
) -> Result<Option<LoadedIocSnapshotConfig>, ConfigError> {
    configured
        .map(|snapshot| {
            if snapshot.snapshot_id.is_empty()
                || snapshot.snapshot_id.len() > 256
                || snapshot.snapshot_id.chars().any(char::is_control)
            {
                return Err(ConfigError::Invalid(
                    "IOC snapshot ID is invalid".to_string(),
                ));
            }
            verified.verify_artifact(&snapshot.data)?;
            let metadata = std::fs::metadata(&snapshot.data.path).map_err(ConfigError::Read)?;
            if metadata.len() == 0
                || metadata.len() > max_query_bytes
                || snapshot
                    .data
                    .path
                    .extension()
                    .and_then(|value| value.to_str())
                    != Some("parquet")
            {
                return Err(ConfigError::Invalid(
                    "IOC snapshot must be one bounded immutable Parquet file".to_string(),
                ));
            }
            Ok(LoadedIocSnapshotConfig {
                snapshot_id: snapshot.snapshot_id,
                data: snapshot.data.path,
                sha256: snapshot.data.sha256,
                bytes: metadata.len(),
            })
        })
        .transpose()
}

pub fn load_risk_snapshot_config(
    configured: Option<RiskSnapshotConfigFile>,
    assigned_tenant_id: &str,
    max_query_bytes: u64,
) -> Result<Option<LoadedRiskSnapshotConfig>, ConfigError> {
    configured
        .map(|configured| {
            verify_artifact(&configured.manifest)?;
            let bytes = std::fs::read(&configured.manifest.path).map_err(ConfigError::Read)?;
            let manifest: RiskSnapshotManifest =
                serde_json::from_slice(&bytes).map_err(ConfigError::Decode)?;
            if !matches!(manifest.schema_version, 1 | 2 | 3)
                || manifest.tenant_id != assigned_tenant_id
                || manifest.snapshot_id.is_empty()
                || manifest.snapshot_id.len() > 256
                || manifest.objects.len() != 1
                || (manifest.schema_version == 1 && manifest.clear_snapshot.is_some())
                || (manifest.schema_version == 2 && manifest.clear_snapshot.is_none())
                || (manifest.schema_version < 3 && manifest.shared_binding.is_some())
                || (manifest.schema_version == 3
                    && (manifest.clear_snapshot.is_none() || manifest.shared_binding.is_none()))
            {
                return Err(ConfigError::Invalid(
                    "risk snapshot manifest violates its tenant, identity, or object contract"
                        .to_string(),
                ));
            }
            if let Some(shared) = manifest.shared_binding.as_ref() {
                let valid_identity = |value: &str| {
                    !value.is_empty()
                        && value.len() <= 128
                        && value.bytes().enumerate().all(|(index, byte)| {
                            byte.is_ascii_alphanumeric()
                                || (index > 0 && matches!(byte, b'-' | b'_' | b'.' | b':'))
                        })
                };
                if shared.security_tenant_id.is_nil()
                    || shared.publisher_worker_actor_id.is_nil()
                    || shared.logical_tenant_id != assigned_tenant_id
                    || !valid_identity(&shared.logical_tenant_id)
                    || !valid_identity(&shared.publisher_worker_identity)
                    || !valid_identity(&shared.lake_worker_identity)
                    || shared.assignment_revision <= 0
                    || shared.lake_worker_revision <= 0
                    || shared.publisher_config_revision <= 0
                    || shared.provider_credential_revision <= 0
                    || shared.event_generation_id.is_empty()
                    || shared.event_generation_id.len() > 256
                    || shared.event_generation_id.chars().any(char::is_control)
                    || shared.event_snapshot_id <= 0
                    || !shared
                        .publisher_image_digest
                        .strip_prefix("sha256:")
                        .is_some_and(|digest| validate_sha256(digest).is_ok())
                    || validate_sha256(&shared.source_object_stamp_sha256).is_err()
                    || validate_sha256(&shared.worker_config_sha256).is_err()
                {
                    return Err(ConfigError::Invalid(
                        "enterprise_shared risk snapshot provenance is invalid".to_string(),
                    ));
                }
            }
            let expected_digest = manifest
                .snapshot_version
                .strip_prefix("sha256:")
                .ok_or_else(|| {
                    ConfigError::Invalid(
                        "risk snapshot version must be a SHA-256 digest".to_string(),
                    )
                })?;
            validate_sha256(expected_digest)?;
            let object = manifest.objects.into_iter().next().expect("length checked");
            if object.version_id != manifest.snapshot_version
                || !object.source_uri.is_absolute()
                || object
                    .source_uri
                    .extension()
                    .and_then(|value| value.to_str())
                    != Some("parquet")
            {
                return Err(ConfigError::Invalid(
                    "risk snapshot object lacks an exact local Parquet version".to_string(),
                ));
            }
            let metadata = std::fs::metadata(&object.source_uri).map_err(ConfigError::Read)?;
            if object.size_bytes == 0
                || metadata.len() != object.size_bytes
                || object.size_bytes > max_query_bytes
                || file_sha256(&object.source_uri)? != expected_digest
            {
                return Err(ConfigError::Invalid(
                    "risk snapshot object failed its immutable byte fence".to_string(),
                ));
            }
            let (
                clear_snapshot_version,
                clear_source,
                clear_bytes,
                clear_modified,
                clear_published_revision,
                global_clear_us,
            ) = if let Some(clear) = manifest.clear_snapshot {
                let expected_clear_digest =
                    clear.version_id.strip_prefix("sha256:").ok_or_else(|| {
                        ConfigError::Invalid(
                            "risk clear snapshot version must be a SHA-256 digest".to_string(),
                        )
                    })?;
                validate_sha256(expected_clear_digest)?;
                let clear_metadata =
                    std::fs::metadata(&clear.source_uri).map_err(ConfigError::Read)?;
                if !clear.source_uri.is_absolute()
                    || clear
                        .source_uri
                        .extension()
                        .and_then(|value| value.to_str())
                        != Some("parquet")
                    || clear.size_bytes == 0
                    || clear_metadata.len() != clear.size_bytes
                    || clear.size_bytes > max_query_bytes
                    || object.size_bytes.saturating_add(clear.size_bytes) > max_query_bytes
                    || clear.row_count > 100_000_000
                    || clear.published_revision < 0
                    || clear.global_clear_us < 0
                    || file_sha256(&clear.source_uri)? != expected_clear_digest
                {
                    return Err(ConfigError::Invalid(
                        "risk clear snapshot failed its immutable byte or revision fence"
                            .to_string(),
                    ));
                }
                (
                    Some(clear.version_id),
                    Some(clear.source_uri),
                    clear.size_bytes,
                    Some(clear_metadata.modified().map_err(ConfigError::Read)?),
                    clear.published_revision,
                    clear.global_clear_us,
                )
            } else {
                (None, None, 0, None, 0, 0)
            };
            Ok(LoadedRiskSnapshotConfig {
                snapshot_id: manifest.snapshot_id,
                snapshot_version: manifest.snapshot_version,
                source: object.source_uri,
                bytes: object.size_bytes,
                modified: metadata.modified().map_err(ConfigError::Read)?,
                clear_snapshot_version,
                clear_source,
                clear_bytes,
                clear_modified,
                clear_published_revision,
                global_clear_us,
            })
        })
        .transpose()
}

fn load_snapshot_cache(
    configured: SnapshotCacheConfigFile,
    verified: &crate::verify::VerifiedArtifacts,
    workers: usize,
    bootstrap: bool,
) -> Result<SnapshotCache, ConfigError> {
    verified.verify_artifact(&configured.object_stamp_manifest)?;
    if let Some(schema) = configured.read_schema.as_ref() {
        verified.verify_artifact(schema)?;
    }
    let stamps: ObjectStampManifest = serde_json::from_slice(
        &std::fs::read(&configured.object_stamp_manifest.path).map_err(ConfigError::Read)?,
    )
    .map_err(ConfigError::Decode)?;
    if bootstrap {
        return load_bootstrap_snapshot_cache(configured, &stamps);
    }
    if !configured.data_directory.is_absolute()
        || configured.max_bytes == 0
        || configured.max_bytes > (1_u64 << 60)
    {
        return Err(ConfigError::Invalid(
            "snapshot cache requires an absolute directory and a bounded positive capacity"
                .to_string(),
        ));
    }
    if stamps.snapshot_id <= 0 || stamps.objects.is_empty() {
        return Err(ConfigError::Invalid(
            "snapshot cache object-stamp ledger is empty or invalid".to_string(),
        ));
    }
    if !configured.ancestor_snapshot_ids.is_empty()
        && (configured.ancestor_snapshot_ids.len() > 100_000
            || configured.ancestor_snapshot_ids.first().copied() != Some(stamps.snapshot_id)
            || configured
                .ancestor_snapshot_ids
                .iter()
                .any(|snapshot_id| *snapshot_id <= 0)
            || configured
                .ancestor_snapshot_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != configured.ancestor_snapshot_ids.len())
    {
        return Err(ConfigError::Invalid(
            "snapshot cache ancestry is invalid or does not start at the serving snapshot"
                .to_string(),
        ));
    }
    let mut objects = BTreeMap::new();
    let data_directory = configured
        .data_directory
        .to_str()
        .ok_or_else(|| ConfigError::Invalid("snapshot cache directory is not UTF-8".to_string()))?;
    if data_directory
        .chars()
        .any(|character| matches!(character, '{' | '}' | ',') || character.is_control())
    {
        return Err(ConfigError::Invalid(
            "snapshot cache directory contains an unsupported character".to_string(),
        ));
    }
    // Only authenticated admission evidence can skip source-byte verification.
    // Legacy unsigned stat ledgers are not evidence at this trust boundary.
    let mut trusted_from_ledger = 0_usize;
    let mut fully_hashed = 0_usize;
    let mut to_hash = crate::verify::VerificationPlan::new();

    let mut paths = Vec::with_capacity(stamps.objects.len());
    let mut bytes = 0_u64;
    for stamp in stamps.objects {
        let relative = Path::new(&stamp.relative_path);
        if stamp.source_uri.is_empty()
            || stamp.version_id.is_empty()
            || stamp.size_bytes == 0
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(ConfigError::Invalid(
                "snapshot cache ledger contains an unsafe object".to_string(),
            ));
        }
        validate_sha256(&stamp.sha256)?;
        let path = configured.data_directory.join(relative);
        let path_string = path
            .to_str()
            .ok_or_else(|| ConfigError::Invalid("snapshot cache path is not UTF-8".to_string()))?;
        if path_string
            .chars()
            .any(|character| matches!(character, '{' | '}' | ',') || character.is_control())
        {
            return Err(ConfigError::Invalid(
                "snapshot cache path contains an unsupported character".to_string(),
            ));
        }
        let metadata = std::fs::metadata(&path).map_err(ConfigError::Read)?;
        if !metadata.is_file() || metadata.len() != stamp.size_bytes {
            return Err(ConfigError::Invalid(
                "snapshot cache object failed its immutable size or digest fence".to_string(),
            ));
        }
        let trusted = verified.covers_file(&VerifiedArtifact { path: path.clone(), sha256: stamp.sha256.clone() });
        if trusted {
            trusted_from_ledger += 1;
        } else {
            // Deferred to one bounded-parallel batch after the loop: on a
            // pod whose snapshot arrived WITHOUT the hydrator's ledger this
            // is the whole table (~19 GB on the shared lake), and it was one
            // serial stream.
            fully_hashed += 1;
            to_hash.file(&VerifiedArtifact {
                path: path.clone(),
                sha256: stamp.sha256.clone(),
            });
        }
        bytes = bytes.checked_add(stamp.size_bytes).ok_or_else(|| {
            ConfigError::Invalid("snapshot cache byte total overflowed".to_string())
        })?;
        if bytes > configured.max_bytes
            || objects
                .insert(
                    stamp.source_uri,
                    SnapshotCacheObject {
                        version_id: stamp.version_id,
                        bytes: stamp.size_bytes,
                        path: path.clone(),
                    },
                )
                .is_some()
        {
            return Err(ConfigError::Invalid(
                "snapshot cache exceeds its capacity or duplicates an object".to_string(),
            ));
        }
        let relative_string = relative.to_str().ok_or_else(|| {
            ConfigError::Invalid("snapshot cache relative path is not UTF-8".to_string())
        })?;
        paths.push(relative_string.to_string());
    }
    if !to_hash.is_empty() {
        // Same all-or-nothing contract and the same message the serial loop
        // produced; only the wall-clock serialization is gone.
        to_hash.run(workers).map_err(|error| match error {
            ConfigError::Invalid(_) => ConfigError::Invalid(
                "snapshot cache object failed its immutable size or digest fence".to_string(),
            ),
            other => other,
        })?;
    }
    paths.sort();
    let source_spec = if paths.len() == 1 {
        configured
            .data_directory
            .join(paths.remove(0))
            .to_string_lossy()
            .into_owned()
    } else {
        format!("{data_directory}/{{{}}}", paths.join(","))
    };
    let read_schema = configured
        .read_schema
        .map(|artifact| {
            let bytes = std::fs::read(artifact.path).map_err(ConfigError::Read)?;
            if bytes.is_empty() || bytes.len() > 1_048_576 || bytes.contains(&0) {
                return Err(ConfigError::Invalid(
                    "snapshot cache read schema is empty or exceeds its bound".to_string(),
                ));
            }
            let schema = std::str::from_utf8(&bytes)
                .map_err(|_| {
                    ConfigError::Invalid(
                        "snapshot cache read schema is not valid UTF-8".to_string(),
                    )
                })?
                .trim()
                .to_string();
            if schema.is_empty() || schema.chars().any(char::is_control) {
                return Err(ConfigError::Invalid(
                    "snapshot cache read schema contains an unsupported character".to_string(),
                ));
            }
            Ok(schema)
        })
        .transpose()?;
    tracing::info!(
        trusted_from_ledger,
        fully_hashed,
        objects = trusted_from_ledger + fully_hashed,
        "verified snapshot cache"
    );
    Ok(SnapshotCache {
        source_spec,
        objects,
        bytes,
        read_schema,
        bootstrap: false,
    })
}

/// NAN-2361 wave 8: the ONLY shape in which a zero snapshot is admitted. The
/// ledger must be the exact empty bootstrap manifest (snapshot 0, no objects,
/// table UUID bound), the cache capacity must be zero, the ancestry empty,
/// the data directory absolute and empty, and the catalog read schema
/// present so the worker can materialize an empty base with the exact
/// catalog column shape. Anything else fails closed.
fn load_bootstrap_snapshot_cache(
    configured: SnapshotCacheConfigFile,
    stamps: &ObjectStampManifest,
) -> Result<SnapshotCache, ConfigError> {
    if !crate::bootstrap_generation::is_bootstrap_stamps(stamps)
        || configured.max_bytes != 0
        || !configured.ancestor_snapshot_ids.is_empty()
        || !configured.data_directory.is_absolute()
    {
        return Err(ConfigError::Invalid(
            "bootstrap snapshot cache must bind the empty zero-snapshot ledger with no capacity or ancestry"
                .to_string(),
        ));
    }
    let mut entries = std::fs::read_dir(&configured.data_directory).map_err(ConfigError::Read)?;
    if entries.next().is_some() {
        return Err(ConfigError::Invalid(
            "bootstrap snapshot cache data directory is not empty".to_string(),
        ));
    }
    let read_schema = configured.read_schema.ok_or_else(|| {
        ConfigError::Invalid("bootstrap snapshot cache requires the catalog read schema".to_string())
    })?;
    let bytes = std::fs::read(read_schema.path).map_err(ConfigError::Read)?;
    if bytes.is_empty() || bytes.len() > 1_048_576 || bytes.contains(&0) {
        return Err(ConfigError::Invalid(
            "snapshot cache read schema is empty or exceeds its bound".to_string(),
        ));
    }
    let schema = std::str::from_utf8(&bytes)
        .map_err(|_| ConfigError::Invalid("snapshot cache read schema is not valid UTF-8".to_string()))?
        .trim()
        .to_string();
    if schema.is_empty() || schema.chars().any(char::is_control) {
        return Err(ConfigError::Invalid(
            "snapshot cache read schema contains an unsupported character".to_string(),
        ));
    }
    Ok(SnapshotCache {
        source_spec: String::new(),
        objects: BTreeMap::new(),
        bytes: 0,
        read_schema: Some(schema),
        bootstrap: true,
    })
}

pub fn index_directory_sha256(
    directory: &Path,
    label: &str,
) -> Result<(String, usize), ConfigError> {
    index_directory_sha256_cancellable(directory, label, None)
        .map(|value| value.map(|(digest, files, _)| (digest, files)))
        .transpose()
        .expect("an uncancellable tree digest always completes")
}

/// `index_directory_sha256` that can be abandoned mid-tree when `stop` is
/// raised (a sibling verification failed), returning `None`. Also reports the
/// bytes hashed. The digest itself is unchanged: one running SHA-256 over
/// (name length, name, size, bytes) of every member in name order.
pub(crate) fn index_directory_sha256_cancellable(
    directory: &Path,
    label: &str,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Option<(String, usize, u64)>, ConfigError> {
    Ok(index_directory_digests_cancellable(directory, label, stop)?
        .map(|digests| (digests.payload_sha256, digests.files, digests.bytes)))
}

/// Both tree identities a generation can carry, computed in ONE pass over the
/// directory.
///
/// NAN-2532: a generation admitted through the incremental-inventory path has
/// every index member as a symlink into the per-root content store, and its
/// authenticated tree digest is the v2 *inventory* digest (names, sizes and
/// content digests), not the v1 concatenated-payload digest. Recomputing only
/// v1 -- and rejecting symlinks outright -- made the "generation proof
/// unavailable; falling back to full artifact verification" path in `resolve`
/// a guaranteed boot failure for those generations, reported as if the tree
/// were corrupt. Deriving both here keeps the fallback a slower path rather
/// than an outage.
pub(crate) struct IndexDirectoryDigests {
    /// v1: SHA-256 over (name length, name, size, bytes) of every member.
    pub payload_sha256: String,
    /// v2: `generation_proof::inventory_tree_sha256` over the same members.
    pub inventory_sha256: String,
    pub files: usize,
    pub bytes: u64,
}

pub(crate) fn index_directory_digests_cancellable(
    directory: &Path,
    label: &str,
    stop: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Option<IndexDirectoryDigests>, ConfigError> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(ConfigError::Read)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(ConfigError::Read)?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut hasher = Sha256::new();
    let mut members: Vec<(String, u64, String)> = Vec::new();
    let mut files = 0_usize;
    let mut bytes = 0_u64;
    for entry in entries {
        let kind = entry.file_type().map_err(ConfigError::Read)?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| ConfigError::Invalid(format!("{label} index filename is invalid")))?
            .to_string();
        if (kind.is_file() || kind.is_symlink()) && name.ends_with(".lock") {
            continue;
        }
        // `DirEntry::file_type` does NOT follow symlinks; a content-store link
        // is a regular file for every reader that opens it, so resolve it.
        let resolved = std::fs::metadata(entry.path()).map_err(ConfigError::Read)?;
        if !resolved.is_file() {
            return Err(ConfigError::Invalid(format!(
                "{label} index directory contains an unsupported entry"
            )));
        }
        let mut file = std::fs::File::open(entry.path()).map_err(ConfigError::Read)?;
        let size = file.metadata().map_err(ConfigError::Read)?.len();
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update(size.to_be_bytes());
        let mut member = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            if stop.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed)) {
                return Ok(None);
            }
            let count = file.read(&mut buffer).map_err(ConfigError::Read)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            member.update(&buffer[..count]);
            bytes += count as u64;
        }
        members.push((name, size, hex::encode(member.finalize())));
        files += 1;
    }
    let inventory: Vec<(&str, u64, &str)> = members
        .iter()
        .map(|(name, size, digest)| (name.as_str(), *size, digest.as_str()))
        .collect();
    let inventory_sha256 = crate::generation_proof::inventory_tree_sha256(&inventory)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    Ok(Some(IndexDirectoryDigests {
        payload_sha256: hex::encode(hasher.finalize()),
        inventory_sha256,
        files,
        bytes,
    }))
}

/// `verify_artifact` for an artifact whose owning prevalence checkpoint is
/// already active.
///
/// The declared digest is still validated for shape, and the artifact is still
/// stat-ed by the caller, but the file contents are not re-hashed: that work
/// was already done when this exact checkpoint was adopted. Every other
/// validation the snapshot contract imposes is unchanged.
fn verify_prevalence_artifact(
    artifact: &VerifiedArtifact,
    already_verified: bool,
) -> Result<(), ConfigError> {
    if already_verified {
        return validate_sha256(&artifact.sha256);
    }
    verify_artifact(artifact)
}

fn verify_artifact(artifact: &VerifiedArtifact) -> Result<(), ConfigError> {
    validate_sha256(&artifact.sha256)?;
    let actual = file_sha256(&artifact.path)?;
    if actual != artifact.sha256 {
        return Err(ConfigError::Invalid(format!(
            "artifact digest mismatch for {}",
            artifact.path.display()
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), ConfigError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ConfigError::Invalid(
            "artifact SHA-256 must be lowercase hexadecimal".to_string(),
        ));
    }
    Ok(())
}

fn required_secret_env(name: &str) -> Result<String, ConfigError> {
    if name.is_empty()
        || !name.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_alphabetic() || byte == b'_'
            } else {
                byte.is_ascii_alphanumeric() || byte == b'_'
            }
        })
    {
        return Err(ConfigError::Invalid(
            "credential environment variable name is invalid".to_string(),
        ));
    }
    let value = std::env::var(name).map_err(|_| {
        ConfigError::Invalid(format!("required credential environment {name} is unset"))
    })?;
    if value.is_empty() {
        return Err(ConfigError::Invalid(format!(
            "required credential environment {name} is empty"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::{ObjectStamp, ObjectStampManifest};

    /// NAN-2532 blocker 1. The suite simulated a "restart" by deleting
    /// `verified-generation.json` inside one process, which never reaches
    /// `WorkerConfigFile::read` -> `resolve` -> `verification_plan().run_proven`
    /// -- the path a query pod actually boots through, and the path that could
    /// not verify a content-store generation at all:
    ///
    ///  * `DirEntry::file_type()` does not follow symlinks, so
    ///    `index_directory_sha256_cancellable` rejected every symlinked index
    ///    member as "an unsupported entry"; and
    ///  * the authenticated tree digest of such a generation is the v2
    ///    INVENTORY digest (`Body::inventory_trees`), while the recompute
    ///    produced the v1 payload digest, so it mismatched even once symlinks
    ///    were handled.
    ///
    /// Together that made `resolve`'s deliberate "proof unavailable, fall back
    /// to full verification" degradation a hard boot failure reported as if
    /// the generation were corrupt. This runs the real path in a REAL separate
    /// process.
    fn content_store_generation_fixture(root: &Path) -> (PathBuf, String) {
        let objects = root.join("objects");
        std::fs::create_dir_all(&objects).unwrap();
        let index = root.join("snapshot-1/derivatives/keyword-sidecar/index");
        std::fs::create_dir_all(&index).unwrap();
        let mut members = Vec::new();
        for ordinal in 0..4_u32 {
            let payload = format!("keyword index member {ordinal}").into_bytes();
            let digest = hex::encode(sha2::Sha256::digest(&payload));
            let object = objects.join(&digest);
            std::fs::write(&object, &payload).unwrap();
            let name = format!("{ordinal}.idx");
            // Exactly the layout `hydrate_generation_bundle_inner` installs:
            // an absolute link from the generation tree into the content store.
            std::os::unix::fs::symlink(&object, index.join(&name)).unwrap();
            members.push((name, payload.len() as u64, digest));
        }
        let inventory: Vec<(&str, u64, &str)> = members
            .iter()
            .map(|(name, bytes, digest)| (name.as_str(), *bytes, digest.as_str()))
            .collect();
        let tree_sha256 = crate::generation_proof::inventory_tree_sha256(&inventory).unwrap();
        (index, tree_sha256)
    }

    fn restart_worker_config(root: &Path, index: &Path, index_tree_sha256: &str) -> PathBuf {
        let artifact = |name: &str| {
            let path = root.join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            serde_json::json!({"path": path, "sha256": hex::encode(sha2::Sha256::digest(name.as_bytes()))})
        };
        let fragment = root.join("snapshot-1/derivatives/fragment-sidecar/index");
        std::fs::create_dir_all(&fragment).unwrap();
        std::fs::write(fragment.join("0.idx"), b"fragment member").unwrap();
        let (fragment_sha256, _) = index_directory_sha256(&fragment, "fragment-sidecar").unwrap();
        let config = serde_json::json!({
            "schema_version": 1,
            "generation_id": "lake-42-restart",
            "assigned_tenant_id": "tenant-a",
            "compiler": artifact("compiler"),
            "native_library": artifact("libchdb.so"),
            "tenant": {
                "tenant_id": "tenant-a",
                "source": "s3://bucket/warehouse/tenant-a/events",
                "iceberg_metadata_file_path": "metadata/v1.json",
                "event_contract": "ocsf-1.9",
                "allow_broad_npl": true,
                "max_query_bytes": 1_000_000,
                "max_memory_bytes": 1_000_000,
                "max_execution_seconds": 10,
                "threads": 1,
                "source_manifest": artifact("source.json"),
                "iceberg_default_credentials": true,
            },
            "entity_sidecar": {
                "manifest": artifact("entity.json"),
                "hmac_key": artifact("hmac.key"),
                "index_files": [],
            },
            "keyword_sidecar": {
                "manifest": artifact("keyword.json"),
                "index_directory": index,
                "index_tree_sha256": index_tree_sha256,
                "fragment_manifest": artifact("fragment.json"),
                "fragment_index_directory": fragment,
                "fragment_index_tree_sha256": fragment_sha256,
            },
        });
        let path = root.join("worker.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        path
    }

    /// The child half: a genuinely fresh process, reading worker.json from
    /// disk with no in-process state and no admission proof.
    #[test]
    #[ignore = "child half of a_restarted_process_verifies_a_content_store_generation"]
    fn restart_child_verifies_worker_config() {
        let path = std::env::var("NANO_TEST_WORKER_CONFIG").expect("child needs a worker.json");
        let config = WorkerConfigFile::read(Path::new(&path)).expect("worker.json parses");
        assert!(config.generation_proof.is_none(), "this child must take the proofless path");
        // Exactly what `resolve` runs at config.rs when `admission_proof()` fails.
        let verified = config
            .verification_plan(false)
            .run_proven(crate::verify::verify_workers(), None, &[])
            .expect("a content-store generation must verify without its proof");
        assert_eq!(verified.report.trees, 2);
    }

    #[test]
    fn a_restarted_process_verifies_a_content_store_generation_without_its_proof() {
        let root = tempfile::tempdir().expect("temporary directory");
        let (index, tree_sha256) = content_store_generation_fixture(root.path());
        let config = restart_worker_config(root.path(), &index, &tree_sha256);

        let child = |config: &Path| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "config::tests::restart_child_verifies_worker_config",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("NANO_TEST_WORKER_CONFIG", config)
                .output()
                .expect("spawn the restarted worker")
        };

        let restarted = child(&config);
        assert!(
            restarted.status.success(),
            "restart must verify the content-store generation:\n{}\n{}",
            String::from_utf8_lossy(&restarted.stdout),
            String::from_utf8_lossy(&restarted.stderr),
        );

        // And it is still a real fence: repoint one member at other content.
        let other = root.path().join("objects/decoy");
        std::fs::write(&other, b"not the signed member").unwrap();
        std::fs::remove_file(index.join("0.idx")).unwrap();
        std::os::unix::fs::symlink(&other, index.join("0.idx")).unwrap();
        let tampered = child(&config);
        assert!(!tampered.status.success(), "a repointed object link must fail the tree fence");
        let output = String::from_utf8_lossy(&tampered.stdout).into_owned()
            + &String::from_utf8_lossy(&tampered.stderr);
        assert!(output.contains("index directory digest mismatch"), "{output}");
    }

    /// A legacy (non-symlinked) tree must keep verifying against its v1
    /// payload digest, unchanged.
    #[test]
    fn a_legacy_index_tree_still_verifies_against_its_payload_digest() {
        let root = tempfile::tempdir().expect("temporary directory");
        let directory = root.path().join("index");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("0.idx"), b"legacy member").unwrap();
        let (payload, files) = index_directory_sha256(&directory, "keyword-sidecar").unwrap();
        assert_eq!(files, 1);
        let mut plan = crate::verify::VerificationPlan::new();
        plan.tree(&directory, &payload, "keyword-sidecar");
        plan.run(1).expect("v1 digest still verifies");
        let digests = index_directory_digests_cancellable(&directory, "keyword-sidecar", None)
            .unwrap()
            .unwrap();
        assert_ne!(digests.payload_sha256, digests.inventory_sha256);
    }

    #[test]
    fn content_addressed_archive_publishes_exact_bytes_and_rejects_conflicts() {
        let root = tempfile::tempdir().expect("temporary archive root");
        let destination = root.path().join("event-config.json");

        write_content_addressed(&destination, b"first", None).expect("publish archive");
        write_content_addressed(&destination, b"first", None).expect("idempotent replay");
        assert_eq!(std::fs::read(&destination).unwrap(), b"first");
        assert!(write_content_addressed(&destination, b"second", None).is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"first");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
    }

    // NAN-2380: the Bronze publisher re-hashed every prevalence artifact on
    // every poll -- 653 MB of software SHA-256 per cycle, ~3.4 s of CPU, paid
    // forever on a COMPLETELY IDLE publisher, because the cheap
    // (snapshot_id, checkpoint_id) rotation check ran only AFTER the load.
    // These pin both halves of the fix: an already-active checkpoint must skip
    // the re-hash, and ANY other case must still verify in full.

    fn prevalence_fixture(
        contents: &[u8],
    ) -> (
        tempfile::TempDir,
        uuid::Uuid,
        impl Fn() -> BTreeMap<String, PrevalenceSnapshotConfigFile>,
    ) {
        let root = tempfile::tempdir().expect("temporary directory");
        let scan = root.path().join("snapshot.parquet");
        std::fs::write(&scan, contents).expect("write scan artifact");
        let digest = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(contents))
        };
        let checkpoint_id = uuid::Uuid::from_u128(0x2380);
        let build = move || {
            BTreeMap::from([(
                "prevalence-tenant-a-30d".to_string(),
                PrevalenceSnapshotConfigFile {
                    window: "30d".to_string(),
                    object_store_url: "file:///".to_string(),
                    database_path: "prevalence/db".to_string(),
                    checkpoint_id,
                    scan_files: vec![VerifiedArtifact {
                        path: scan.clone(),
                        sha256: digest.clone(),
                    }],
                    explorer: None,
                    daily_history: None,
                    source_types: vec!["vector".to_string()],
                    rarity_threshold: 10,
                },
            )])
        };
        (root, checkpoint_id, build)
    }

    #[test]
    fn prevalence_artifacts_are_fully_verified_when_nothing_is_active() {
        let (_root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        load_prevalence_snapshot_configs(build(), 1 << 20, &BTreeMap::new())
            .expect("a matching digest must load");
    }

    #[test]
    fn materialized_prevalence_explorer_is_verified_and_loaded() {
        let (root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        let explorer = root.path().join("explorer.parquet");
        let contents = b"materialized-explorer";
        std::fs::write(&explorer, contents).expect("write explorer artifact");
        let mut configured = build();
        let snapshot = configured
            .get_mut("prevalence-tenant-a-30d")
            .expect("fixture snapshot");
        snapshot.explorer = Some(VerifiedArtifact {
            path: explorer.clone(),
            sha256: hex::encode(sha2::Sha256::digest(contents)),
        });

        let loaded = load_prevalence_snapshot_configs(configured, 1 << 20, &BTreeMap::new())
            .expect("verified explorer must load");
        assert_eq!(
            loaded["prevalence-tenant-a-30d"]
                .explorer
                .as_ref()
                .expect("materialized explorer")
                .path,
            explorer
        );
    }

    #[test]
    fn a_tampered_artifact_is_rejected_when_no_checkpoint_is_active() {
        let (root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        std::fs::write(root.path().join("snapshot.parquet"), b"tampered").expect("rewrite");
        let Err(error) = load_prevalence_snapshot_configs(build(), 1 << 20, &BTreeMap::new())
        else {
            panic!("a digest mismatch must fail closed");
        };
        assert!(
            format!("{error:?}").contains("artifact digest mismatch"),
            "expected a digest mismatch, got {error:?}"
        );
    }

    #[test]
    fn an_already_active_checkpoint_skips_the_content_rehash() {
        // The whole point of the fix: this artifact no longer matches its
        // declared digest, but its checkpoint is already active and was
        // verified at adoption, so it must NOT be re-read.
        let (root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        std::fs::write(root.path().join("snapshot.parquet"), b"changed").expect("rewrite");
        let verified = build();
        load_prevalence_snapshot_configs(build(), 1 << 20, &verified)
            .expect("an already-active checkpoint must not be re-hashed");
    }

    #[test]
    fn a_rotated_checkpoint_is_still_verified_in_full() {
        // The safety half. A DIFFERENT checkpoint id for the same snapshot is a
        // rotation, so the new artifact must be hashed before it is adopted --
        // skipping this would let a bad artifact in behind a version bump.
        let (root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        std::fs::write(root.path().join("snapshot.parquet"), b"tampered").expect("rewrite");
        let mut stale = build();
        stale
            .get_mut("prevalence-tenant-a-30d")
            .expect("fixture snapshot")
            .checkpoint_id = uuid::Uuid::from_u128(0xdead);
        let Err(error) = load_prevalence_snapshot_configs(build(), 1 << 20, &stale) else {
            panic!("a rotated checkpoint must be verified in full");
        };
        assert!(
            format!("{error:?}").contains("artifact digest mismatch"),
            "expected a digest mismatch, got {error:?}"
        );
    }

    #[test]
    fn an_unrelated_active_snapshot_does_not_waive_verification() {
        // A match must be on THIS snapshot id, not merely "something is active".
        let (root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        std::fs::write(root.path().join("snapshot.parquet"), b"tampered").expect("rewrite");
        let mut other = build();
        let snapshot = other
            .remove("prevalence-tenant-a-30d")
            .expect("fixture snapshot");
        other.insert("prevalence-tenant-a-7d".to_string(), snapshot);
        let Err(error) = load_prevalence_snapshot_configs(build(), 1 << 20, &other) else {
            panic!("another snapshot's checkpoint must not waive verification");
        };
        assert!(
            format!("{error:?}").contains("artifact digest mismatch"),
            "expected a digest mismatch, got {error:?}"
        );
    }

    #[test]
    fn a_malformed_digest_is_rejected_even_on_the_skip_path() {
        // The skip drops the file read, not the contract on the declared digest.
        let (_root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        let mut verified = build();
        verified
            .get_mut("prevalence-tenant-a-30d")
            .expect("fixture snapshot")
            .scan_files[0]
            .sha256 = "NOT-HEX".to_string();
        assert!(
            load_prevalence_snapshot_configs(verified.clone(), 1 << 20, &verified).is_err(),
            "a malformed digest must still be rejected"
        );
    }

    #[test]
    fn a_changed_path_behind_an_active_checkpoint_is_verified_in_full() {
        let (root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        let verified = build();
        let changed_path = root.path().join("replacement.parquet");
        std::fs::write(&changed_path, b"tampered").expect("write replacement");
        let mut configured = build();
        configured
            .get_mut("prevalence-tenant-a-30d")
            .expect("fixture snapshot")
            .scan_files[0]
            .path = changed_path;
        let Err(error) = load_prevalence_snapshot_configs(configured, 1 << 20, &verified) else {
            panic!("a changed artifact path must be verified in full");
        };
        assert!(
            format!("{error:?}").contains("artifact digest mismatch"),
            "expected a digest mismatch, got {error:?}"
        );
    }

    #[test]
    fn a_changed_digest_behind_an_active_checkpoint_is_verified_in_full() {
        let (_root, _checkpoint, build) = prevalence_fixture(b"prevalence-parquet");
        let verified = build();
        let mut configured = build();
        configured
            .get_mut("prevalence-tenant-a-30d")
            .expect("fixture snapshot")
            .scan_files[0]
            .sha256 = "0".repeat(64);
        let Err(error) = load_prevalence_snapshot_configs(configured, 1 << 20, &verified) else {
            panic!("a changed artifact digest must be verified in full");
        };
        assert!(
            format!("{error:?}").contains("artifact digest mismatch"),
            "expected a digest mismatch, got {error:?}"
        );
    }

    #[test]
    fn derivative_state_preserves_first_generation_handshake() {
        let mut value = serde_json::json!({
            "generation_id": "bootstrap-pending",
            "risk_snapshot": {"manifest": {"sha256": "a".repeat(64)}}
        });

        let generation_id =
            refresh_derivative_generation_id(&mut value).expect("preserve bootstrap identity");

        assert_eq!(generation_id, "bootstrap-pending");
        assert_eq!(value["generation_id"], "bootstrap-pending");
        assert!(value.get("risk_snapshot").is_some());
    }

    #[test]
    fn derivative_state_rotates_an_active_generation_identity() {
        let mut value = serde_json::json!({
            "generation_id": "lake-42-existing",
            "risk_snapshot": {"manifest": {"sha256": "b".repeat(64)}}
        });

        let generation_id =
            refresh_derivative_generation_id(&mut value).expect("rotate active identity");

        assert!(generation_id.starts_with("lakecfg-"));
        assert_eq!(generation_id.len(), "lakecfg-".len() + 24);
        assert_eq!(value["generation_id"], generation_id);
    }

    #[test]
    fn deployment_path_normalized_digest_is_pod_path_independent() {
        let first = serde_json::json!({
            "generation_id": "pending",
            "tenant": {"source_manifest": {"path": "/pod-a/generation/source.json", "sha256": "a".repeat(64)}},
            "keyword_sidecar": {"index_directory": "/pod-a/generation/keyword"},
            "prevalence_snapshots": {"p": {"database_path": "/pod-a/generation/slatedb"}},
        });
        let second = serde_json::json!({
            "generation_id": "pending",
            "tenant": {"source_manifest": {"path": "/pod-b/cache/source.json", "sha256": "a".repeat(64)}},
            "keyword_sidecar": {"index_directory": "/pod-b/cache/keyword"},
            "prevalence_snapshots": {"p": {"database_path": "/pod-b/cache/slatedb"}},
        });
        assert_eq!(
            deployment_path_normalized_sha256(&first).unwrap(),
            deployment_path_normalized_sha256(&second).unwrap()
        );

        let mut changed = second;
        changed["tenant"]["source_manifest"]["sha256"] = Value::String("b".repeat(64));
        assert_ne!(
            deployment_path_normalized_sha256(&first).unwrap(),
            deployment_path_normalized_sha256(&changed).unwrap()
        );
    }

    fn tenant_config_json() -> serde_json::Value {
        serde_json::json!({
            "tenant_id": "tenant-a",
            "source": "s3://bucket/table",
            "iceberg_metadata_file_path": "metadata/v1.json",
            "source_manifest": {"path": "/tmp/source.json", "sha256": "0".repeat(64)},
            "max_query_bytes": 268435456,
            "max_execution_seconds": 30,
            "threads": 4,
            "event_contract": "ocsf-1.9",
            "allow_broad_npl": false
        })
    }

    fn partial_state_config_json() -> serde_json::Value {
        let artifact = || {
            serde_json::json!({
                "path": "/must-not-be-opened",
                "sha256": "0".repeat(64)
            })
        };
        serde_json::json!({
            "schema_version": 1,
            "generation_id": "lake-partial-state-v1",
            "assigned_tenant_id": "tenant-a",
            "compiler": artifact(),
            "native_library": artifact(),
            "tenant": tenant_config_json(),
            "entity_sidecar": {
                "manifest": artifact(),
                "hmac_key": artifact(),
                "index_files": [artifact()]
            },
            "keyword_sidecar": {
                "manifest": artifact(),
                "index_directory": "/must-not-be-opened/keyword",
                "index_tree_sha256": "0".repeat(64),
                "fragment_manifest": artifact(),
                "fragment_index_directory": "/must-not-be-opened/fragment",
                "fragment_index_tree_sha256": "0".repeat(64)
            }
        })
    }

    #[test]
    fn partial_derived_state_loaders_reject_a_foreign_inner_tenant_before_io() {
        let mut config = partial_state_config_json();
        config["tenant"]["tenant_id"] = serde_json::json!("tenant-b");
        let bytes = serde_json::to_vec(&config).unwrap();

        let prevalence =
            WorkerConfigFile::load_prevalence_only(&bytes, "tenant-a", 1 << 20, &BTreeMap::new());
        assert!(
            matches!(prevalence, Err(ConfigError::Invalid(message)) if message.contains("tenant boundary")),
            "prevalence reload must reject a mixed tenant config before opening its paths"
        );

        let ioc = WorkerConfigFile::load_ioc_only(&bytes, "tenant-a", 1 << 20);
        assert!(
            matches!(ioc, Err(ConfigError::Invalid(message)) if message.contains("tenant boundary")),
            "IOC reload must reject a mixed tenant config before opening its paths"
        );
    }

    #[test]
    fn partial_prevalence_reload_verifies_the_exact_hmac_artifact() {
        let (root, checkpoint_id, build) = prevalence_fixture(b"prevalence-parquet");
        let snapshot = build()
            .remove("prevalence-tenant-a-30d")
            .expect("fixture snapshot");
        let hmac_key = root.path().join("prevalence.hmac");
        let admitted_key = b"0123456789abcdef0123456789abcdef";
        std::fs::write(&hmac_key, admitted_key).expect("write admitted HMAC key");
        let hmac_sha256 = hex::encode(sha2::Sha256::digest(admitted_key));

        let mut config = partial_state_config_json();
        config["entity_sidecar"]["hmac_key"] = serde_json::json!({
            "path": hmac_key,
            "sha256": hmac_sha256
        });
        config["prevalence_snapshots"] = serde_json::json!({
            "prevalence-tenant-a-30d": {
                "window": snapshot.window,
                "object_store_url": snapshot.object_store_url,
                "database_path": snapshot.database_path,
                "checkpoint_id": checkpoint_id,
                "scan_files": [{
                    "path": snapshot.scan_files[0].path,
                    "sha256": snapshot.scan_files[0].sha256
                }],
                "source_types": snapshot.source_types,
                "rarity_threshold": snapshot.rarity_threshold
            }
        });

        std::fs::write(&hmac_key, b"fedcba9876543210fedcba9876543210")
            .expect("tamper HMAC key in place");
        let Err(error) = WorkerConfigFile::load_prevalence_only(
            &serde_json::to_vec(&config).unwrap(),
            "tenant-a",
            1 << 20,
            &BTreeMap::new(),
        ) else {
            panic!("a changed prevalence HMAC key must fail closed");
        };
        assert!(
            format!("{error:?}").contains("artifact digest mismatch"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn shared_risk_manifest_provenance_is_strictly_decoded() {
        let manifest = serde_json::json!({
            "schema_version": 3,
            "tenant_id": "tenant_a",
            "snapshot_id": "risk-a",
            "snapshot_version": format!("sha256:{}", "11".repeat(32)),
            "objects": [{
                "source_uri": "/risk/risk-a.parquet",
                "size_bytes": 1,
                "version_id": format!("sha256:{}", "11".repeat(32))
            }],
            "clear_snapshot": {
                "source_uri": "/risk/clear-a.parquet",
                "size_bytes": 1,
                "version_id": format!("sha256:{}", "12".repeat(32)),
                "row_count": 0,
                "published_revision": 0,
                "global_clear_us": 0
            },
            "enterprise_shared": {
                "security_tenant_id": "0198f2d2-c43b-7a32-8f6b-696d1878368f",
                "logical_tenant_id": "tenant_a",
                "assignment_revision": 1,
                "publisher_worker_identity": "risk-publisher-a",
                "publisher_worker_actor_id": "0198f2d2-c43b-7a32-8f6b-696d18783690",
                "lake_worker_identity": "lake-worker-a",
                "lake_worker_revision": 2,
                "publisher_config_revision": 3,
                "publisher_image_digest": format!("sha256:{}", "13".repeat(32)),
                "provider_credential_revision": 4,
                "event_generation_id": "event-generation-a",
                "event_snapshot_id": 5,
                "source_object_stamp_sha256": "14".repeat(32),
                "worker_config_sha256": "15".repeat(32)
            }
        });
        assert!(serde_json::from_value::<RiskSnapshotManifest>(manifest.clone()).is_ok());
        let mut unknown = manifest.clone();
        unknown["enterprise_shared"]["browser_token"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<RiskSnapshotManifest>(unknown).is_err());
        let mut missing = manifest;
        missing
            .as_object_mut()
            .expect("manifest object")
            .remove("enterprise_shared");
        let decoded: RiskSnapshotManifest = serde_json::from_value(missing).unwrap();
        assert_eq!(decoded.schema_version, 3);
        assert!(decoded.shared_binding.is_none());
    }

    #[test]
    fn tenant_memory_ceiling_defaults_and_accepts_an_explicit_override() {
        let defaulted: TenantConfigFile =
            serde_json::from_value(tenant_config_json()).expect("decode default tenant config");
        assert_eq!(defaulted.max_memory_bytes, DEFAULT_QUERY_MEMORY_BYTES);

        let mut explicit = tenant_config_json();
        explicit["max_memory_bytes"] = serde_json::json!(536_870_912_u64);
        let explicit: TenantConfigFile =
            serde_json::from_value(explicit).expect("decode explicit tenant config");
        assert_eq!(explicit.max_memory_bytes, 536_870_912);
    }

    #[test]
    fn analytics_limits_are_optional_but_strictly_typed() {
        let inherited: TenantConfigFile =
            serde_json::from_value(tenant_config_json()).expect("decode inherited limits");
        assert_eq!(inherited.analytics_max_memory_bytes, None);
        assert_eq!(inherited.analytics_max_execution_seconds, None);
        assert_eq!(inherited.analytics_threads, None);

        let mut explicit = tenant_config_json();
        explicit["analytics_max_memory_bytes"] = serde_json::json!(17_179_869_184_u64);
        explicit["analytics_max_execution_seconds"] = serde_json::json!(3_600_u64);
        explicit["analytics_threads"] = serde_json::json!(8_u64);
        let explicit: TenantConfigFile =
            serde_json::from_value(explicit).expect("decode explicit analytics limits");
        assert_eq!(explicit.analytics_max_memory_bytes, Some(17_179_869_184));
        assert_eq!(explicit.analytics_max_execution_seconds, Some(3_600));
        assert_eq!(explicit.analytics_threads, Some(8));
    }

    #[test]
    fn state_only_loader_returns_interactive_capacity_without_loading_event_artifacts() {
        let artifact = || serde_json::json!({"path": "/not-loaded", "sha256": "0".repeat(64)});
        let config = serde_json::json!({
            "schema_version": 1,
            "generation_id": "lake-capacity-v1",
            "assigned_tenant_id": "tenant-a",
            "compiler": artifact(),
            "native_library": artifact(),
            "tenant": {
                "tenant_id": "tenant-a",
                "source": "s3://bucket/table",
                "iceberg_metadata_file_path": "metadata/v1.json",
                "source_manifest": artifact(),
                "max_query_bytes": 268435456,
                "max_memory_bytes": 2147483648_u64,
                "max_execution_seconds": 90,
                "threads": 6,
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
        });
        let (generation, risk, ioc, capacity) = WorkerConfigFile::load_risk_only(
            &serde_json::to_vec(&config).unwrap(),
            "tenant-a",
            268435456,
        )
        .expect("load state-only configuration");
        assert_eq!(generation, "lake-capacity-v1");
        assert!(risk.is_none());
        assert!(ioc.is_none());
        assert_eq!(capacity.max_memory_bytes, 2147483648);
        assert_eq!(capacity.max_execution_seconds, 90);
        assert_eq!(capacity.threads, 6);
    }

    #[test]
    fn event_archive_ignores_state_capacity_and_local_paths_but_pins_artifacts() {
        let root = tempfile::tempdir().expect("temporary directory");
        let compiler = root.path().join("compiler");
        let native = root.path().join("libchdb.so");
        std::fs::write(&compiler, b"compiler-v1").expect("write compiler");
        std::fs::write(&native, b"native-v1").expect("write native");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&compiler, std::fs::Permissions::from_mode(0o755))
                .expect("make compiler executable");
        }
        let compiler_sha = file_sha256(&compiler).expect("hash compiler");
        let native_sha = file_sha256(&native).expect("hash native");
        let config_path = root.path().join("worker.json");
        let config = serde_json::json!({
            "schema_version": 1,
            "generation_id": "mutable-risk-generation",
            "assigned_tenant_id": "tenant-a",
            "compiler": {"path": compiler, "sha256": compiler_sha},
            "native_library": {"path": native, "sha256": native_sha},
            "tenant": {
                "source": "s3://bucket/events",
                "iceberg_metadata_file_path": "metadata/v1.json",
                "max_memory_bytes": 123456789,
                "max_execution_seconds": 30,
                "threads": 2
            },
            "entity_sidecar": {
                "manifest": {"path": "/old/a.json", "sha256": "d".repeat(64)},
                "index_files": [],
                "hmac_key": {"path": "/old/key", "sha256": "e".repeat(64)}
            },
            "keyword_sidecar": {
                "index_directory": "/old/index",
                "index_tree_sha256": "f".repeat(64)
            },
            "risk_snapshot": {"manifest": {"path": "/risk/v1", "sha256": "1".repeat(64)}}
        });
        std::fs::write(
            &config_path,
            serde_json::to_vec_pretty(&config).expect("encode config"),
        )
        .expect("write config");
        let original_digest =
            event_config_sha256(&std::fs::read(&config_path).unwrap()).expect("event digest");
        let archived = archive_event_config(&config_path, &root.path().join("archive"), 42)
            .expect("archive event config");
        assert_eq!(archived.event_config_sha256, original_digest);
        assert_eq!(
            archived.generation_id,
            event_generation_id(42, &original_digest).unwrap()
        );
        let archived_json: Value =
            serde_json::from_slice(&std::fs::read(&archived.path).unwrap()).unwrap();
        assert!(archived_json.get("risk_snapshot").is_none());
        assert!(archived_json.get("ioc_snapshot").is_none());
        assert_eq!(
            archived_json["tenant"]["max_memory_bytes"],
            4_294_967_296_u64
        );
        for field in ["compiler", "native_library"] {
            let path = PathBuf::from(archived_json[field]["path"].as_str().unwrap());
            assert!(path.starts_with(root.path().join("archive/artifacts")));
            assert!(path.is_file());
            #[cfg(unix)]
            if field == "compiler" {
                use std::os::unix::fs::PermissionsExt;
                assert_ne!(
                    std::fs::metadata(path).unwrap().permissions().mode() & 0o111,
                    0
                );
            }
        }

        let mut state_and_capacity_only = config;
        state_and_capacity_only["generation_id"] = Value::String("risk-v2".to_string());
        state_and_capacity_only["risk_snapshot"] =
            serde_json::json!({"manifest": {"path": "/risk/v2", "sha256": "2".repeat(64)}});
        state_and_capacity_only["ioc_snapshot"] = serde_json::json!({
            "snapshot_id": "ioc-v2",
            "data": {"path": "/ioc/v2.parquet", "sha256": "3".repeat(64)}
        });
        state_and_capacity_only["tenant"]["max_memory_bytes"] = Value::from(64_u64 << 30);
        state_and_capacity_only["compiler"]["path"] =
            Value::String("/another/deployment/compiler".to_string());
        assert_eq!(
            event_config_sha256(&serde_json::to_vec(&state_and_capacity_only).unwrap()).unwrap(),
            original_digest
        );

        state_and_capacity_only["tenant"]["iceberg_metadata_file_path"] =
            Value::String("metadata/v2.json".to_string());
        assert_ne!(
            event_config_sha256(&serde_json::to_vec(&state_and_capacity_only).unwrap()).unwrap(),
            original_digest
        );
    }

    #[test]
    fn bounds_profile_never_changes_the_event_generation_identity() {
        // NAN-2361: sizing is runner capacity. Adding, changing, or removing
        // the profile must leave event_config_sha256 untouched, or every
        // sizing retune would orphan queued durable jobs and re-identify the
        // same event data. This is the digest-fence contract the delivery
        // mechanism depends on (see lake_job_runner.rs::prepare_attempt_config).
        let base = serde_json::json!({
            "schema_version": 1,
            "generation_id": "lake-bounds-v1",
            "assigned_tenant_id": "tenant-a",
            "tenant": {"max_memory_bytes": 1, "iceberg_metadata_file_path": "metadata/v1.json"},
        });
        let without = event_config_sha256(&serde_json::to_vec(&base).unwrap()).unwrap();

        let profile = crate::bounds::SizeClass::Edge5GbDay
            .derive()
            .expect("edge profile derives");
        let mut with_profile = base.clone();
        with_profile["bounds_profile"] = serde_json::to_value(&profile).unwrap();
        assert_eq!(
            event_config_sha256(&serde_json::to_vec(&with_profile).unwrap()).unwrap(),
            without,
            "adding a bounds profile must not change the event identity"
        );

        let team = crate::bounds::SizeClass::Team100GbDay
            .derive()
            .expect("team profile derives");
        with_profile["bounds_profile"] = serde_json::to_value(&team).unwrap();
        assert_eq!(
            event_config_sha256(&serde_json::to_vec(&with_profile).unwrap()).unwrap(),
            without,
            "retuning the bounds profile must not change the event identity"
        );
    }

    #[test]
    fn load_bounds_profile_is_tolerant_absent_and_strict_when_present() {
        let root = tempfile::tempdir().expect("temporary directory");
        let path = root.path().join("worker.json");

        // Absent key (every pre-NAN-2361 worker.json): None, no error.
        std::fs::write(
            &path,
            br#"{"schema_version": 1, "unrelated_future_field": true}"#,
        )
        .unwrap();
        assert!(load_bounds_profile(&path)
            .expect("absent profile loads")
            .is_none());

        // Present and valid: loads and revalidates.
        let profile = crate::bounds::SizeClass::Edge5GbDay.derive().unwrap();
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "bounds_profile": serde_json::to_value(&profile).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
        let loaded = load_bounds_profile(&path)
            .expect("valid profile loads")
            .expect("profile present");
        assert_eq!(loaded, profile);

        // Present but violating the NAN-2361 outage inequality: refuses,
        // naming the inequality — never a silent start.
        let mut tampered = serde_json::to_value(&profile).unwrap();
        tampered["max_pack_rows"] = serde_json::json!(1_000);
        std::fs::write(
            &path,
            serde_json::to_vec(
                &serde_json::json!({"schema_version": 1, "bounds_profile": tampered}),
            )
            .unwrap(),
        )
        .unwrap();
        let error = format!(
            "{:#}",
            load_bounds_profile(&path).expect_err("tampered profile")
        );
        assert!(
            error.contains("pack registration deadlock"),
            "rejection must name the violated inequality, got: {error}"
        );
    }

    #[test]
    fn index_tree_digest_covers_names_sizes_and_contents_but_not_lock_files() {
        let root = tempfile::tempdir().expect("temporary directory");
        std::fs::write(root.path().join("meta.json"), b"metadata").expect("write metadata");
        std::fs::write(root.path().join("segment.idx"), b"postings").expect("write postings");
        std::fs::write(root.path().join(".tantivy-meta.lock"), b"").expect("write lock file");
        let (digest, files) = index_directory_sha256(root.path(), "test").expect("hash index tree");
        assert_eq!(files, 2);
        crate::verify::VerifiedArtifacts::none().verify_index_directory(root.path(), &digest, "test").expect("verify exact tree");

        std::fs::write(root.path().join("segment.idx"), b"changed").expect("mutate postings");
        assert!(crate::verify::VerifiedArtifacts::none().verify_index_directory(root.path(), &digest, "test").is_err());
    }

    /// Build a snapshot root with a data dir, an object-stamp manifest and a
    /// matching hydration verification ledger, exactly as the hydrator writes.
    fn snapshot_cache_fixture(
        contents: &[u8],
    ) -> (
        tempfile::TempDir,
        impl Fn() -> SnapshotCacheConfigFile,
        std::path::PathBuf,
    ) {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().expect("temporary directory");
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).expect("create data directory");
        let object = data.join("part-a.parquet");
        std::fs::write(&object, contents).expect("write object");
        let sha = hex::encode(sha2::Sha256::digest(contents));
        let manifest = serde_json::json!({
            "table": "tenant_a.events",
            "snapshot_id": 42,
            "metadata_location": "s3://bucket/warehouse/tenant-a/events/metadata/v1.json",
            "objects": [{
                "relative_path": "part-a.parquet",
                "source_uri": "s3://bucket/warehouse/tenant-a/events/data/part-a.parquet",
                "version_id": "v1",
                "size_bytes": contents.len() as u64,
                "sha256": sha,
            }],
        });
        let manifest_path = root.path().join("object-stamps.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let meta = std::fs::metadata(&object).expect("stat object");
        let ledger = serde_json::json!({
            "schema_version": 1,
            "table": "tenant_a.events",
            "objects": { "part-a.parquet": {
                "sha256": sha,
                "size_bytes": contents.len() as u64,
                "dev": meta.dev(),
                "inode": meta.ino(),
                "mtime_seconds": meta.mtime(),
                "mtime_nanoseconds": meta.mtime_nsec(),
            }},
        });
        std::fs::write(
            root.path().join("local-verification.json"),
            serde_json::to_vec(&ledger).unwrap(),
        )
        .unwrap();
        let digest = hex::encode(sha2::Sha256::digest(std::fs::read(&manifest_path).unwrap()));
        let make = move || SnapshotCacheConfigFile {
            object_stamp_manifest: VerifiedArtifact {
                path: manifest_path.clone(),
                sha256: digest.clone(),
            },
            read_schema: None,
            data_directory: data.clone(),
            max_bytes: 1 << 30,
            ancestor_snapshot_ids: Vec::new(),
        };
        (root, make, object)
    }

    #[test]
    fn a_tampered_cached_object_is_still_rejected_despite_a_matching_ledger() {
        // NAN-2361: config load stopped full-hashing every object per
        // activation. The fence must NOT become vacuous -- tamper the bytes
        // while leaving a ledger that still claims the original digest, and
        // the load must fail. This is the test that proves the optimisation
        // did not delete the check.
        let (_root, make, object) = snapshot_cache_fixture(b"immutable parquet bytes");
        load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false).expect("clean cache loads");

        // Same length so the cheap size check cannot catch it.
        std::fs::write(&object, b"immutable parquet byteX").expect("tamper");
        let error = load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false)
            .expect_err("a tampered object must fail the digest fence");
        assert!(
            format!("{error:?}").contains("digest fence"),
            "must fail on the digest fence, got: {error:?}"
        );
    }

    #[test]
    fn a_ledger_claiming_the_wrong_digest_cannot_widen_trust() {
        // The ledger lives on the same disk as the artifacts it vouches for,
        // so it must never be authoritative. Its digest has to AGREE with the
        // object-stamp manifest; a ledger asserting anything else is ignored
        // and the object is fully hashed.
        use std::os::unix::fs::MetadataExt;
        let (root, make, object) = snapshot_cache_fixture(b"immutable parquet bytes");
        // Every stat field is CORRECT -- only the digest disagrees with the
        // authoritative manifest. A forged ledger with plausible stat data is
        // the realistic attack; if the digest-agreement check were dropped,
        // this ledger would grant trust to bytes nobody verified.
        let meta = std::fs::metadata(&object).expect("stat object");
        let forged = serde_json::json!({
            "schema_version": 1,
            "table": "tenant_a.events",
            "objects": { "part-a.parquet": {
                "sha256": "f".repeat(64),
                "size_bytes": meta.len(),
                "dev": meta.dev(), "inode": meta.ino(),
                "mtime_seconds": meta.mtime(), "mtime_nanoseconds": meta.mtime_nsec(),
            }},
        });
        std::fs::write(
            root.path().join("local-verification.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        // Still loads: the forged stamp is not trusted, so the object is
        // hashed and passes on its own merits.
        load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false).expect("forged ledger falls back to hashing");

        // And the fallback is a REAL hash, not a skipped check: corrupt the
        // bytes to the length the forged ledger claims and it must now fail.
        // Without this the test would pass even if the object were never read.
        std::fs::write(&object, b"immutable parquet byteX").expect("tamper");
        assert!(
            load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false).is_err(),
            "a forged ledger must not let tampered bytes through"
        );
    }

    #[test]
    fn a_ledger_vouching_for_different_content_than_the_manifest_is_not_trusted() {
        // The precise attack the digest-agreement check exists for, and the
        // one my first attempt at this test MISSED: a ledger whose stat fields
        // all match the file on disk, and whose recorded digest matches THOSE
        // BYTES -- but not the digest the authoritative manifest requires.
        //
        // Without `stamp.sha256 == authoritative_sha256` the stats match, the
        // object is trusted, no hash is taken, and swapped content is served
        // as if verified. Tampering AFTER writing the ledger cannot catch this
        // (it moves mtime, which the stat check already rejects) -- the bytes
        // must already be wrong when the ledger is written.
        use std::os::unix::fs::MetadataExt;
        let (root, make, object) = snapshot_cache_fixture(b"immutable parquet bytes");

        // Swap in different content of the SAME length, so the manifest's
        // size fence still passes and only digests can discriminate.
        let swapped = b"SWAPPED parquet bytes!!";
        assert_eq!(swapped.len(), b"immutable parquet bytes".len());
        std::fs::write(&object, swapped).expect("swap content");

        // A ledger that honestly describes the file NOW on disk.
        let meta = std::fs::metadata(&object).expect("stat object");
        let ledger = serde_json::json!({
            "schema_version": 1,
            "table": "tenant_a.events",
            "objects": { "part-a.parquet": {
                "sha256": hex::encode(sha2::Sha256::digest(swapped)),
                "size_bytes": meta.len(),
                "dev": meta.dev(), "inode": meta.ino(),
                "mtime_seconds": meta.mtime(), "mtime_nanoseconds": meta.mtime_nsec(),
            }},
        });
        std::fs::write(
            root.path().join("local-verification.json"),
            serde_json::to_vec(&ledger).unwrap(),
        )
        .unwrap();

        let error = load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false).expect_err(
            "a ledger vouching for content the manifest does not expect must never be trusted",
        );
        assert!(
            format!("{error:?}").contains("digest fence"),
            "must fail the manifest digest fence, got: {error:?}"
        );
    }

    #[test]
    fn an_absent_ledger_falls_back_to_the_pre_change_behaviour() {
        let (root, make, object) = snapshot_cache_fixture(b"immutable parquet bytes");
        std::fs::remove_file(root.path().join("local-verification.json")).unwrap();
        load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false).expect("no ledger still loads");
        std::fs::write(&object, b"immutable parquet byteX").expect("tamper");
        assert!(
            load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), 4, false).is_err(),
            "without a ledger every object is hashed, so tampering must fail"
        );
    }

    #[test]
    fn multi_file_snapshot_cache_uses_one_common_root_brace_spec() {
        let root = tempfile::tempdir().expect("temporary directory");
        let data = root.path().join("data");
        std::fs::create_dir_all(data.join("day=2026-08-12")).expect("create data directory");
        let files = [
            ("day=2026-08-12/part-b.parquet", b"part-b".as_slice()),
            ("day=2026-08-12/part-a.parquet", b"part-a".as_slice()),
        ];
        let mut objects = Vec::new();
        for (index, (relative, contents)) in files.iter().enumerate() {
            let path = data.join(relative);
            std::fs::write(&path, contents).expect("write cached object");
            objects.push(ObjectStamp {
                relative_path: (*relative).to_string(),
                source_uri: format!("s3://bucket/table/{relative}"),
                version_id: format!("version-{index}"),
                size_bytes: contents.len() as u64,
                sha256: file_sha256(&path).expect("hash cached object"),
            });
        }
        let stamp_path = root.path().join("object-stamps.json");
        std::fs::write(
            &stamp_path,
            serde_json::to_vec(&ObjectStampManifest {
                metadata_location: "s3://bucket/table/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "events".to_string(),
                objects,
                table_uuid: None,
            })
            .expect("encode stamp ledger"),
        )
        .expect("write stamp ledger");
        let read_schema_path = root.path().join("clickhouse-read-schema.sql");
        std::fs::write(
            &read_schema_path,
            b"`time` DateTime64(6, 'UTC'), `src_endpoint` Tuple(`ip` Nullable(String))",
        )
        .expect("write read schema");
        let cache = load_snapshot_cache(SnapshotCacheConfigFile {
            object_stamp_manifest: VerifiedArtifact {
                sha256: file_sha256(&stamp_path).expect("hash stamp ledger"),
                path: stamp_path,
            },
            data_directory: data.clone(),
            max_bytes: 1_024,
            read_schema: Some(VerifiedArtifact {
                sha256: file_sha256(&read_schema_path).expect("hash read schema"),
                path: read_schema_path.clone(),
            }),
            ancestor_snapshot_ids: vec![1],
        }, &crate::verify::VerifiedArtifacts::none(), 4, false)
        .expect("load snapshot cache");

        assert_eq!(
            cache.source_spec,
            format!(
                "{}/{{day=2026-08-12/part-a.parquet,day=2026-08-12/part-b.parquet}}",
                data.display()
            )
        );
        assert_eq!(
            cache.read_schema.as_deref(),
            Some("`time` DateTime64(6, 'UTC'), `src_endpoint` Tuple(`ip` Nullable(String))")
        );

        std::fs::write(&read_schema_path, b"tampered").expect("tamper read schema");
        assert!(verify_artifact(&VerifiedArtifact {
            sha256: "0".repeat(64),
            path: read_schema_path,
        })
        .is_err());
    }

    /// NAN-2361: with NO derivative tier, `load` and `load_with_derivative_tiering(_, false)`
    /// are the same code path and a count-rollup part missing from local disk
    /// is a hard fault (today's behaviour, byte for byte). With tiering, that
    /// same absence is tolerated at the config layer — the load proceeds past
    /// count-rollup verification and fails much later, at the native-library
    /// digest fence this fixture cannot satisfy.
    #[test]
    fn tiered_count_rollup_load_tolerates_a_locally_absent_part() {
        use sha2::Digest as _;
        let directory = tempfile::TempDir::new().unwrap();
        let sha = |bytes: &[u8]| hex::encode(sha2::Sha256::digest(bytes));
        let file = |name: &str, content: &[u8]| {
            let path = directory.path().join(name);
            std::fs::write(&path, content).unwrap();
            serde_json::json!({"path": path, "sha256": sha(content)})
        };
        // Keyword/fragment index directories with correct tree digests.
        let index_dir = directory.path().join("keyword-index");
        std::fs::create_dir(&index_dir).unwrap();
        std::fs::write(index_dir.join("segment"), b"segment-bytes").unwrap();
        let (index_tree_sha256, _) = index_directory_sha256(&index_dir, "keyword").unwrap();
        // Count-rollup directory whose recorded tree digest names TWO parts,
        // one of which is absent locally (tiered away).
        let rollup_dir = directory.path().join("count-rollup");
        std::fs::create_dir(&rollup_dir).unwrap();
        std::fs::write(rollup_dir.join("object-0000.parquet"), b"part-zero").unwrap();
        std::fs::write(rollup_dir.join("object-0001.parquet"), b"part-one").unwrap();
        let (rollup_tree_sha256, _) = index_directory_sha256(&rollup_dir, "count-rollup").unwrap();
        let manifest = file("rollup-manifest.json", b"{}");
        std::fs::remove_file(rollup_dir.join("object-0001.parquet")).unwrap();

        let config_path = directory.path().join("worker.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "generation_id": "lake-test",
                "assigned_tenant_id": "tenant-a",
                "compiler": file("compiler", b"compiler"),
                "native_library": file("libchdb.so", b"not-a-real-native-library"),
                "tenant": {
                    "tenant_id": "tenant-a",
                    "source": "s3://bucket/table",
                    "iceberg_metadata_file_path": "metadata/v1.json",
                    "source_manifest": file("source-manifest.json", b"{}"),
                    "max_query_bytes": 268435456,
                    "max_execution_seconds": 30,
                    "threads": 4,
                    "event_contract": "ocsf-1.9",
                    "allow_broad_npl": true,
                    "iceberg_default_credentials": true
                },
                "entity_sidecar": {
                    "manifest": file("entity-manifest.json", b"{}"),
                    "hmac_key": file("entity-hmac.key", b"0123456789abcdef0123456789abcdef"),
                    "index_files": [file("entity-index", b"entity-index")]
                },
                "keyword_sidecar": {
                    "manifest": file("keyword-manifest.json", b"{}"),
                    "index_directory": index_dir,
                    "index_tree_sha256": index_tree_sha256,
                    "fragment_manifest": file("fragment-manifest.json", b"{}"),
                    "fragment_index_directory": index_dir,
                    "fragment_index_tree_sha256": index_tree_sha256
                },
                "count_rollup": {
                    "manifest": manifest,
                    "data_directory": rollup_dir,
                    "data_tree_sha256": rollup_tree_sha256
                }
            }))
            .unwrap(),
        )
        .unwrap();

        // Untiered (both spellings): the absent part IS the failure.
        let untiered = WorkerConfigFile::load(&config_path)
            .err()
            .expect("untiered load must fail on the absent part");
        assert!(untiered
            .to_string()
            .contains("count-rollup index directory digest mismatch"));
        let untiered_explicit = WorkerConfigFile::load_with_derivative_tiering(&config_path, false)
            .err()
            .expect("explicit untiered load must fail identically");
        assert_eq!(untiered.to_string(), untiered_explicit.to_string());

        // Tiered: count-rollup verification tolerates the absence; the load
        // proceeds and fails at the native-library fence instead.
        let tiered = WorkerConfigFile::load_with_derivative_tiering(&config_path, true)
            .err()
            .expect("fixture cannot pass the native-library fence");
        assert!(
            !tiered.to_string().contains("count-rollup"),
            "tiered load must not fault on the locally absent count-rollup part: {tiered}"
        );
    }


    /// A snapshot root the way a REPLACEMENT pod sees it: N objects and the
    /// object-stamp manifest, but no hydration ledger, so every object must
    /// be fully hashed. Returns the config builder and the object paths.
    fn fresh_snapshot_cache_fixture(
        objects: usize,
    ) -> (
        tempfile::TempDir,
        impl Fn() -> SnapshotCacheConfigFile,
        Vec<std::path::PathBuf>,
    ) {
        let root = tempfile::tempdir().expect("temporary directory");
        let data = root.path().join("data");
        std::fs::create_dir_all(&data).expect("create data directory");
        let mut paths = Vec::new();
        let mut stamps = Vec::new();
        for index in 0..objects {
            let contents = vec![index as u8; 1_000 + index * 37];
            let path = data.join(format!("hour={index}/part-{index:03}.parquet"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &contents).expect("write object");
            stamps.push(serde_json::json!({
                "relative_path": format!("hour={index}/part-{index:03}.parquet"),
                "source_uri": format!(
                    "s3://bucket/warehouse/tenant-a/events/data/hour={index}/part-{index:03}.parquet"
                ),
                "version_id": format!("v{index}"),
                "size_bytes": contents.len() as u64,
                "sha256": hex::encode(sha2::Sha256::digest(&contents)),
            }));
            paths.push(path);
        }
        let manifest = serde_json::json!({
            "table": "tenant_a.events",
            "snapshot_id": 42,
            "metadata_location": "s3://bucket/warehouse/tenant-a/events/metadata/v1.json",
            "objects": stamps,
        });
        let manifest_path = root.path().join("object-stamps.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let digest = hex::encode(sha2::Sha256::digest(std::fs::read(&manifest_path).unwrap()));
        let make = move || SnapshotCacheConfigFile {
            object_stamp_manifest: VerifiedArtifact {
                path: manifest_path.clone(),
                sha256: digest.clone(),
            },
            read_schema: None,
            data_directory: data.clone(),
            max_bytes: 1 << 30,
            ancestor_snapshot_ids: Vec::new(),
        };
        (root, make, paths)
    }

    #[test]
    fn a_ledgerless_snapshot_cache_is_fully_hashed_in_parallel_and_one_bad_object_fails_it() {
        // NAN-2361 cold start: with no hydration ledger every object goes
        // through the bounded-parallel batch. Clean bytes load under any
        // worker count; a single same-length corruption fails the whole
        // cache with the serial fence's message.
        let (_root, make, paths) = fresh_snapshot_cache_fixture(65);
        for workers in [1, 4, 64] {
            let cache =
                load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), workers, false)
                    .unwrap_or_else(|error| panic!("{workers} workers: {error}"));
            assert_eq!(cache.objects.len(), 65);
        }
        let victim = &paths[41];
        let mut bytes = std::fs::read(victim).unwrap();
        let third = bytes.len() / 3;
        bytes[third] ^= 0x10;
        std::fs::write(victim, &bytes).unwrap();
        for workers in [1, 8] {
            let error =
                load_snapshot_cache(make(), &crate::verify::VerifiedArtifacts::none(), workers, false)
                    .expect_err("a corrupt object must fail the digest fence");
            assert_eq!(
                error.to_string(),
                "worker config is invalid: snapshot cache object failed its immutable size or digest fence",
                "{workers} workers"
            );
        }
    }

    #[test]
    fn the_verification_plan_covers_every_pinned_artifact_and_tree_in_worker_json() {
        // The plan is the only place the parallel fence learns what to hash.
        // Build a config from every optional section and check the plan
        // registers each digest-pinned file and each tree exactly once; a
        // section left out of the plan is hashed serially at its own site,
        // which is safe but silently slow -- this pins the fast path.
        let root = tempfile::tempdir().expect("temporary directory");
        let artifact = |name: &str| {
            let path = root.path().join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            VerifiedArtifact {
                path,
                sha256: hex::encode(sha2::Sha256::digest(name.as_bytes())),
            }
        };
        let tree = |name: &str| {
            let directory = root.path().join(name);
            std::fs::create_dir(&directory).unwrap();
            std::fs::write(directory.join("0.idx"), name.as_bytes()).unwrap();
            let (digest, _) = index_directory_sha256(&directory, name).unwrap();
            (directory, digest)
        };
        let (keyword_dir, keyword_sha) = tree("keyword");
        let (fragment_dir, fragment_sha) = tree("fragment");
        let (rollup_dir, rollup_sha) = tree("rollup");
        let shared_key = artifact("hmac.key");
        let source_manifest = artifact("source.json");
        let config = WorkerConfigFile {
            generation_proof: None,
            schema_version: 1,
            generation_id: "gen".to_string(),
            assigned_tenant_id: "tenant-a".to_string(),
            compiler: artifact("compiler"),
            native_library: artifact("libchdb.so"),
            tenant: serde_json::from_value(serde_json::json!({
                "tenant_id": "tenant-a",
                "source": "s3://bucket/warehouse/tenant-a/events",
                "iceberg_metadata_file_path": "metadata/v1.json",
                "event_contract": "ocsf-1.9",
                "allow_broad_npl": true,
                "max_query_bytes": 1_000_000,
                "max_memory_bytes": 1_000_000,
                "max_execution_seconds": 10,
                "threads": 1,
                "source_manifest": {
                    "path": source_manifest.path,
                    "sha256": source_manifest.sha256,
                },
                "iceberg_default_credentials": true,
            }))
            .expect("tenant config"),
            snapshot_cache: Some(SnapshotCacheConfigFile {
                object_stamp_manifest: artifact("object-stamps.json"),
                data_directory: root.path().join("data"),
                max_bytes: 1 << 30,
                read_schema: Some(artifact("read-schema.txt")),
                ancestor_snapshot_ids: Vec::new(),
            }),
            entity_sidecar: EntitySidecarConfigFile {
                manifest: artifact("entity.json"),
                hmac_key: shared_key.clone(),
                index_files: vec![artifact("entity-0.idx"), artifact("entity-1.idx")],
            },
            keyword_sidecar: KeywordSidecarConfigFile {
                manifest: artifact("keyword.json"),
                index_directory: keyword_dir.clone(),
                index_tree_sha256: keyword_sha.clone(),
                fragment_manifest: artifact("fragment.json"),
                fragment_index_directory: fragment_dir.clone(),
                fragment_index_tree_sha256: fragment_sha.clone(),
            },
            count_rollup: Some(CountRollupConfigFile {
                manifest: artifact("rollup.json"),
                data_directory: rollup_dir.clone(),
                data_tree_sha256: rollup_sha.clone(),
            }),
            identity_snapshot: Some(IdentitySnapshotConfigFile {
                snapshot_id: "identity".to_string(),
                by_ip: artifact("by-ip.parquet"),
            }),
            ioc_snapshot: Some(IocSnapshotConfigFile {
                snapshot_id: "ioc".to_string(),
                data: artifact("ioc.parquet"),
            }),
            prevalence_snapshots: BTreeMap::from([(
                "prev".to_string(),
                PrevalenceSnapshotConfigFile {
                    window: "30d".to_string(),
                    object_store_url: "file:///".to_string(),
                    database_path: "prevalence/db".to_string(),
                    checkpoint_id: uuid::Uuid::from_u128(1),
                    scan_files: vec![artifact("prev-scan.parquet")],
                    explorer: Some(artifact("prev-explorer.parquet")),
                    daily_history: Some(PrevalenceDailyHistoryConfigFile {
                        scan_file: artifact("prev-daily.parquet"),
                        daily_start: "2026-01-01".to_string(),
                    }),
                    source_types: vec!["vector".to_string()],
                    rarity_threshold: 10,
                },
            )]),
            risk_snapshot: Some(RiskSnapshotConfigFile {
                manifest: artifact("risk.json"),
            }),
            bounds_profile: None,
        };
        // Untiered: 17 files + 3 trees. Tiered: the count-rollup tree is a
        // partial cache and must NOT be in the plan.
        let untiered = config.verification_plan(false);
        assert_eq!(untiered.len(), 17 + 3, "{untiered:?}");
        let tiered = config.verification_plan(true);
        assert_eq!(tiered.len(), 17 + 2, "{tiered:?}");
        // The plan verifies; the proof covers each registered site, and the
        // native library is deliberately NOT covered (hashed at dlopen).
        let verified = untiered.run(4).expect("plan verifies");
        assert!(verified.covers_file(&shared_key));
        assert!(verified.covers_file(&config.ioc_snapshot.as_ref().unwrap().data));
        assert!(!verified.covers_file(&config.native_library));
        verified
            .verify_index_directory(&rollup_dir, &rollup_sha, "count-rollup")
            .expect("rollup tree covered");
        assert_eq!(verified.report.files, 17);
        assert_eq!(verified.report.trees, 3);
    }
}
