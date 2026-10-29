// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact-version local cache for the signed serving hot tail.
//!
//! A schema-v4 hot-tail manifest binds every S3 object version to its byte
//! length and SHA-256. The worker hydrates and verifies the complete object set
//! before activating it, then hard-links those immutable bytes into a
//! per-manifest lease directory. Query plans read stable canonical paths through
//! one parameterized `file()` source instead of emitting one `s3()` plus
//! `UNION ALL` branch per object. The SQL/AST shape is therefore constant even
//! at the 4,096-object serving ceiling.
//!
//! The canonical cache is bounded. Lease hard links make eviction safe across
//! server and durable-job processes: eviction preserves canonical names while
//! their inode has a live lease. A locked lease file identifies a
//! live process; crashed-process directories are reclaimed on the next
//! hydration.

use crate::bounds::HOT_TAIL_OBJECT_FORMAT_CEILING;
use crate::generation::{
    validate_shared_r2_hot_tail_manifest, HotTailManifest, HotTailObject,
};
use crate::tenant_object_cache::{
    CacheEncryptionProvider, TenantObjectCacheAuthority, TenantObjectCacheIdentity,
    TenantObjectCacheNamespace,
};
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use futures::{StreamExt, TryStreamExt};
use opendal::{services::S3, Operator};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HYDRATE_CONCURRENCY: usize = 16;

const DOWNLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct HotTailCacheSettings {
    pub directory: PathBuf,
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HotTailCacheRuntimeBinding<'a> {
    pub assigned_tenant_id: &'a str,
    pub source: &'a str,
    pub assignment_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct HotTailCacheGenerationBinding<'a> {
    pub runtime_generation: &'a str,
    pub schema_generation: &'a str,
}

impl HotTailCacheSettings {
    /// The cache is an explicit deployment contract. Older schema-v1/v2/v3
    /// tails keep working without it; accepting a schema-v4 tail without it
    /// fails closed at activation.
    pub fn from_env() -> Result<Option<Self>> {
        let directory = non_empty_env("NANO_LAKE_HOT_TAIL_CACHE_DIR");
        let max_bytes = non_empty_env("NANO_LAKE_HOT_TAIL_CACHE_BYTES");
        match (directory, max_bytes) {
            (None, None)
                if non_empty_env("DEPLOYMENT_MODE").as_deref() == Some("enterprise_shared") =>
            {
                bail!(
                    "enterprise_shared requires NANO_LAKE_HOT_TAIL_CACHE_DIR and NANO_LAKE_HOT_TAIL_CACHE_BYTES"
                )
            }
            (None, None) => Ok(None),
            (Some(directory), Some(max_bytes)) => {
                let max_bytes = max_bytes
                    .parse::<u64>()
                    .ok()
                    .context("NANO_LAKE_HOT_TAIL_CACHE_BYTES must be an integer")?;
                let capacity = crate::cgroup_memory::process_capacity();
                let volume = nanosiem_lake_cell::disk_ceiling::containing_volume_bytes(Path::new(&directory))
                    .context("hot-tail cache volume capacity")?;
                let max_bytes = if max_bytes == 0 {
                    if non_empty_env("DEPLOYMENT_MODE").as_deref() == Some("enterprise_shared") {
                        bail!("enterprise_shared requires an explicit positive hot-tail cache budget");
                    }
                    // On self-hosted installs, leave RAM for native work and
                    // disk for parts, reader cache and durable job results.
                    (capacity.memory_bytes / 4).min(volume / 100).max(1)
                } else {
                    nanosiem_lake_cell::budget::cache_disk_budget(max_bytes, volume)
                };
                Ok(Some(Self {
                    directory: PathBuf::from(directory),
                    max_bytes,
                }))
            }
            _ => bail!(
                "NANO_LAKE_HOT_TAIL_CACHE_DIR and NANO_LAKE_HOT_TAIL_CACHE_BYTES must be set together"
            ),
        }
    }

    pub fn open(&self) -> Result<Arc<HotTailCache>> {
        HotTailCache::open(&self.directory, self.max_bytes)
    }

    /// Open the historical cache for dedicated/open-core/enterprise workers,
    /// or the stricter tenant namespace for hosted-shared. Shared mode is
    /// admitted only after the signed worker config supplied the UUID tenant
    /// and exact source bucket; no request field participates.
    pub fn open_for_runtime(
        &self,
        binding: HotTailCacheRuntimeBinding<'_>,
    ) -> Result<Arc<HotTailCache>> {
        match non_empty_env("DEPLOYMENT_MODE").as_deref() {
            Some("enterprise_shared") => {
                let tenant_id = uuid::Uuid::parse_str(binding.assigned_tenant_id)
                    .context("enterprise_shared cache tenant must be an immutable UUID")?;
                let bucket = required_env("NANO_LAKE_SHARED_R2_READ_BUCKET")?;
                let endpoint = required_env("NANO_LAKE_SHARED_R2_READ_ENDPOINT")?;
                let (source_bucket, _) = parse_assigned_table_source(binding.source, &endpoint)
                    .context("enterprise_shared cache source must be the assigned R2 table")?;
                if bucket != source_bucket {
                    bail!("enterprise_shared R2 cache bucket differs from the worker source");
                }
                let credential_bucket = required_env("NANO_LAKE_SHARED_R2_READ_CREDENTIAL_BUCKET")?;
                let credential_is_read_only =
                    required_env("NANO_LAKE_SHARED_R2_READ_CREDENTIAL_MODE")? == "read-only";
                // The access-key ID is the independently revocable credential
                // identity. Its hash, never the value, is persisted in the
                // cache authority marker; the secret is never retained.
                let credential_id = required_env("NANO_LAKE_SHARED_R2_READ_ACCESS_KEY_ID")?;
                // Parse the complete dedicated secret surface at startup so a
                // shared worker cannot serve old local hits after being
                // launched without its current remote-read authority.
                let _ = shared_r2_operator(&bucket, &credential_id)?;
                let assignment_revision = binding
                    .assignment_revision
                    .context("enterprise_shared R2 cache requires a worker assignment revision")?;
                let purge_epoch = positive_env_u64("NANO_LAKE_SHARED_R2_CACHE_PURGE_EPOCH")?;
                let encryption_provider = CacheEncryptionProvider::parse(&required_env(
                    "NANO_LAKE_SHARED_CACHE_ENCRYPTION_PROVIDER",
                )?)?;
                let encryption_key_id = required_env("NANO_LAKE_SHARED_CACHE_ENCRYPTION_KEY_ID")?;
                let encryption_key_revision =
                    positive_env_u64("NANO_LAKE_SHARED_CACHE_ENCRYPTION_KEY_REVISION")?;
                let cell_max_bytes = positive_env_u64("NANO_LAKE_SHARED_CACHE_CELL_BYTES")?;
                let authority = TenantObjectCacheAuthority::new(
                    tenant_id,
                    bucket,
                    credential_id,
                    &credential_bucket,
                    credential_is_read_only,
                    assignment_revision,
                    purge_epoch,
                    encryption_provider,
                    encryption_key_id,
                    encryption_key_revision,
                    self.max_bytes,
                    cell_max_bytes,
                )?;
                HotTailCache::open_shared_namespace(&self.directory, authority)
            }
            // This is intentionally an additive hosted-shared contract.
            // Every existing deployment mode retains the historical layout
            // and configuration surface exactly.
            _ => self.open(),
        }
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_env(name: &str) -> Result<String> {
    non_empty_env(name).with_context(|| format!("{name} is required"))
}

fn positive_env_u64(name: &str) -> Result<u64> {
    required_env(name)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .with_context(|| format!("{name} must be a positive integer"))
}

/// Build an R2 reader from the tenant's dedicated read-only secret rather
/// than inheriting the process/job S3 credential chain. Cloudflare enforces
/// the actual bucket policy; the server-owned authority additionally binds
/// the access-key identity and bucket before any object can be selected.
pub(crate) fn shared_r2_operator(bucket: &str, expected_access_key_id: &str) -> Result<Operator> {
    let region = required_env("NANO_LAKE_SHARED_R2_READ_REGION")?;
    let endpoint = required_env("NANO_LAKE_SHARED_R2_READ_ENDPOINT")?;
    if !endpoint.starts_with("https://")
        || endpoint.chars().any(char::is_control)
        || endpoint.contains('@')
    {
        bail!("enterprise_shared R2 read endpoint must be an HTTPS service endpoint");
    }
    let access_key_id = required_env("NANO_LAKE_SHARED_R2_READ_ACCESS_KEY_ID")?;
    if access_key_id != expected_access_key_id {
        bail!("enterprise_shared R2 read credential identity changed after cache admission");
    }
    let secret_access_key = required_env("NANO_LAKE_SHARED_R2_READ_SECRET_ACCESS_KEY")?;
    let mut builder = S3::default()
        .bucket(bucket)
        .region(&region)
        .endpoint(&endpoint)
        .access_key_id(&access_key_id)
        .secret_access_key(&secret_access_key)
        .disable_config_load()
        .disable_ec2_metadata();
    match non_empty_env("NANO_LAKE_SHARED_R2_READ_VIRTUAL_HOST_STYLE").as_deref() {
        None | Some("false") => {}
        Some("true") => builder = builder.enable_virtual_host_style(),
        Some(_) => {
            bail!("NANO_LAKE_SHARED_R2_READ_VIRTUAL_HOST_STYLE must be true or false when set")
        }
    }
    if let Some(token) = non_empty_env("NANO_LAKE_SHARED_R2_READ_SESSION_TOKEN") {
        builder = builder.session_token(&token);
    }
    Ok(Operator::new(builder)?.layer(crate::r2_ops::layer()).finish())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    inode: u64,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

impl FileStamp {
    fn read(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("stat hot-tail cache object {}", path.display()))?;
        if !metadata.is_file() {
            bail!("hot-tail cache object is not a regular file");
        }
        Ok(Self {
            dev: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
        })
    }
}

#[derive(Debug)]
pub struct HotTailCache {
    root: PathBuf,
    objects: PathBuf,
    pins: PathBuf,
    global_lock: PathBuf,
    max_bytes: u64,
    shared_namespace: Option<TenantObjectCacheNamespace>,
    /// Digest verification is expensive by design. Cache it only while the
    /// exact inode/size/mtime stamp is unchanged, so a 13-GB active tail is not
    /// re-hashed on every 500-ms manifest poll.
    verified: Mutex<BTreeMap<String, FileStamp>>,
    /// An enterprise-shared generation changes the canonical cache key even
    /// when an exact R2 object survives the snapshot cutover. Keep a
    /// tenant-local content index so the candidate key can hard-link the
    /// already verified inode instead of requiring two physical tails during
    /// the atomic handoff. The signed object and local digest are still checked
    /// before this index is consulted.
    shared_content: Mutex<BTreeMap<(String, u64), String>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HotTailCacheTrim {
    pub files: usize,
    pub bytes: u64,
}

/// NAN-2651: share of the deployment bound a newest-first PARTIAL tail may
/// occupy.
///
/// The prior serving lease stays pinned while the next revision hydrates, so
/// two successive partial tails must fit together. A partial tail of at most
/// half the bound guarantees `prior ∪ next <= bound` in steady state; the
/// transition from a full tail first shrinks the served tail to the same
/// budget (see [`HotTailCache::plan_coverage_within`]).
pub const PARTIAL_TAIL_BUDGET_DIVISOR: u64 = 2;

/// What a newest-first partial tail leaves out (NAN-2651).
///
/// Objects are ordered by `(max_time_ms, min_time_ms, manifest index)`
/// descending and admitted as a STRICT prefix: selection stops at the first
/// object whose new bytes do not fit. Every served object therefore has a
/// `max_time_ms` at or after every omitted object's, so every event newer than
/// `uncovered_through_ms` is served and only events in
/// `[uncovered_from_ms, uncovered_through_ms]` may be missing. A bound of
/// `None` means an omitted object carried no event-time bound, so that side of
/// the range is unknown.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct HotTailPartialCoverage {
    pub total_objects: usize,
    pub served_objects: usize,
    /// Unique cache bytes of the complete signed tail.
    pub total_bytes: u64,
    /// Unique cache bytes actually hydrated and served.
    pub served_bytes: u64,
    pub budget_bytes: u64,
    pub cache_max_bytes: u64,
    pub uncovered_from_ms: Option<i64>,
    pub uncovered_through_ms: Option<i64>,
    /// NAN-2694: why coverage is partial when the slow path (disk tier + R2
    /// read-through) is configured: `slow_path_over_budget`,
    /// `slow_path_r2_unavailable` or `slow_path_busy`. Absent for the
    /// RAM-only NAN-2651 selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Coverage decision for one signed schema-v4 tail against the cache bound.
#[derive(Debug)]
pub enum HotTailCoveragePlan {
    /// The complete tail fits: hydrate the signed manifest unchanged.
    Full,
    /// The complete tail does not fit: hydrate `manifest`, the newest-first
    /// subset of the signed objects (in their signed order), and report
    /// `coverage` on every read.
    Partial {
        manifest: HotTailManifest,
        coverage: HotTailPartialCoverage,
    },
}

/// Typed "the objects still pinned by live leases leave no room" failure.
/// Pins release as in-flight queries finish, so callers retry instead of
/// rejecting the signed manifest until the publisher changes it.
#[derive(Debug)]
pub struct HotTailCachePinnedPressure {
    pub additional: u64,
    pub used: u64,
    pub max_bytes: u64,
}

impl std::fmt::Display for HotTailCachePinnedPressure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "hot-tail cache requires {} bytes with {} bytes already pinned, above its {} byte deployment bound",
            self.additional, self.used, self.max_bytes
        )
    }
}

impl std::error::Error for HotTailCachePinnedPressure {}

pub fn cache_pinned_pressure(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<HotTailCachePinnedPressure>().is_some())
}

impl HotTailCache {
    pub fn open(root: &Path, max_bytes: u64) -> Result<Arc<Self>> {
        if !root.is_absolute() || max_bytes == 0 {
            bail!("hot-tail cache path or byte bound is invalid");
        }
        let objects = root.join("objects");
        let pins = root.join("pins");
        std::fs::create_dir_all(&objects)
            .with_context(|| format!("create {}", objects.display()))?;
        std::fs::create_dir_all(&pins).with_context(|| format!("create {}", pins.display()))?;
        let cache = Arc::new(Self {
            root: root.to_path_buf(),
            objects,
            pins,
            global_lock: root.join(".cache.lock"),
            max_bytes,
            shared_namespace: None,
            verified: Mutex::new(BTreeMap::new()),
            shared_content: Mutex::new(BTreeMap::new()),
        });
        cache.with_global_lock(|| {
            cache.reclaim_stale_pin_directories()?;
            cache.evict_until_fits(0, &BTreeSet::new())
        })?;
        Ok(cache)
    }

    pub fn open_shared_namespace(
        root: &Path,
        authority: TenantObjectCacheAuthority,
    ) -> Result<Arc<Self>> {
        let namespace = TenantObjectCacheNamespace::open(root, authority)?;
        let cache = Arc::new(Self {
            root: namespace.root().to_path_buf(),
            objects: namespace.objects().to_path_buf(),
            pins: namespace.pins().to_path_buf(),
            global_lock: namespace.global_lock_path().to_path_buf(),
            max_bytes: namespace.tenant_max_bytes(),
            shared_namespace: Some(namespace),
            verified: Mutex::new(BTreeMap::new()),
            shared_content: Mutex::new(BTreeMap::new()),
        });
        cache.with_global_lock(|| {
            cache.reclaim_stale_pin_directories()?;
            cache.evict_until_fits(0, &BTreeSet::new())
        })?;
        Ok(cache)
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Drop only canonical cache objects that have no live manifest lease.
    ///
    /// A lease is a hard link, so `nlink == 1` proves that removing the
    /// canonical name also releases the object's physical tmpfs bytes. Live
    /// queries and the active hot tail keep `nlink > 1` and are never touched.
    /// This gives the query-worker memory guard a safe reclamation step before
    /// it recycles native connections or exits under cgroup pressure.
    pub fn trim_unpinned(&self) -> Result<HotTailCacheTrim> {
        self.with_global_lock(|| {
            self.reclaim_stale_pin_directories()?;
            let pinned_inodes = parquet_inodes(&self.pins)?;
            let bytes_before = physical_parquet_bytes(&self.root)?;
            let mut trimmed = HotTailCacheTrim::default();
            for entry in std::fs::read_dir(&self.objects)? {
                let entry = entry?;
                if entry.file_type()?.is_symlink() {
                    bail!("hot-tail cache contains a symbolic link");
                }
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                let Some(cache_key) = name.strip_suffix(".parquet") else {
                    continue;
                };
                let metadata = std::fs::metadata(&path)?;
                if !metadata.is_file() || pinned_inodes.contains(&(metadata.dev(), metadata.ino()))
                {
                    continue;
                }
                std::fs::remove_file(&path)?;
                self.forget_cache_key(cache_key);
                trimmed.files = trimmed.files.saturating_add(1);
            }
            trimmed.bytes = bytes_before.saturating_sub(physical_parquet_bytes(&self.root)?);
            Ok(trimmed)
        })
    }

    /// Hydrate every exact object and return a lease whose paths stay valid
    /// until the last query holding the verified tail releases it.
    pub async fn hydrate(
        self: &Arc<Self>,
        manifest: &HotTailManifest,
    ) -> Result<HotTailCacheLease> {
        if self.shared_namespace.is_some() {
            bail!("enterprise_shared cache hydration requires exact generation identity");
        }
        self.hydrate_inner(manifest, None).await
    }

    pub async fn hydrate_for_generation(
        self: &Arc<Self>,
        manifest: &HotTailManifest,
        generation: HotTailCacheGenerationBinding<'_>,
    ) -> Result<HotTailCacheLease> {
        self.hydrate_inner(manifest, Some(generation)).await
    }

    /// NAN-2651: decide whether a signed schema-v4 tail fits this cache, and
    /// if not, which newest-first subset the worker may serve instead of
    /// retaining its prior tail forever. Byte accounting uses the same cache
    /// identities hydration uses, so a `Partial` plan always passes the
    /// hydration bound check.
    pub fn plan_coverage(
        &self,
        manifest: &HotTailManifest,
        generation: Option<HotTailCacheGenerationBinding<'_>>,
    ) -> Result<HotTailCoveragePlan> {
        self.plan(manifest, generation, None)
    }

    /// Like [`Self::plan_coverage`] but forces the partial budget: a tail
    /// larger than `max_bytes / PARTIAL_TAIL_BUDGET_DIVISOR` becomes partial
    /// even though it fits the full bound. Used to shrink the tail currently
    /// served (all bytes already cached, so no download) before the next
    /// partial revision is hydrated next to it.
    pub fn plan_coverage_within_partial_budget(
        &self,
        manifest: &HotTailManifest,
        generation: Option<HotTailCacheGenerationBinding<'_>>,
    ) -> Result<HotTailCoveragePlan> {
        self.plan(
            manifest,
            generation,
            Some(self.max_bytes / PARTIAL_TAIL_BUDGET_DIVISOR),
        )
    }

    fn plan(
        &self,
        manifest: &HotTailManifest,
        generation: Option<HotTailCacheGenerationBinding<'_>>,
        budget: Option<u64>,
    ) -> Result<HotTailCoveragePlan> {
        if manifest.schema_version != 4 {
            bail!("only a schema-v4 hot tail has a cache coverage plan");
        }
        let mut unhydrated = manifest.clone();
        unhydrated.local_paths.clear();
        let cache_keys = self.cache_keys(&unhydrated, generation)?;
        plan_newest_fitting(&unhydrated, &cache_keys, self.max_bytes, budget)
    }

    async fn hydrate_inner(
        self: &Arc<Self>,
        manifest: &HotTailManifest,
        generation: Option<HotTailCacheGenerationBinding<'_>>,
    ) -> Result<HotTailCacheLease> {
        if manifest.schema_version != 4 || !manifest.local_paths.is_empty() {
            bail!("only an unhydrated schema-v4 hot tail can enter the local cache");
        }
        if self.shared_namespace.is_some() {
            validate_shared_r2_hot_tail_manifest(manifest)?;
        }
        validate_hydration_sources(manifest)?;
        let started = std::time::Instant::now();
        let tail_objects = manifest.objects.len();
        let tail_bytes: u64 = manifest.objects.iter().map(|object| object.size_bytes).sum();
        let objects = manifest.objects.clone();
        let cache_keys = self.cache_keys(manifest, generation)?;
        let cache = self.clone();
        let result = tokio::task::spawn_blocking(move || cache.hydrate_blocking(&objects, &cache_keys))
            .await
            .context("join hot-tail cache hydration")?;
        tracing::debug!(
            tail_id = ?manifest.tail_id, tail_objects, tail_bytes,
            tail_hydrate_ms = started.elapsed().as_secs_f64() * 1000.0,
            concurrency = HYDRATE_CONCURRENCY, success = result.is_ok(),
            "prepared hot-tail cache revision off the query path"
        );
        result
    }

    fn hydrate_blocking(
        self: &Arc<Self>,
        objects: &[HotTailObject],
        cache_keys: &[String],
    ) -> Result<HotTailCacheLease> {
        let protected = validate_cache_entries(objects, cache_keys, self.max_bytes)?;
        self.with_global_lock(|| {
            self.reclaim_stale_pin_directories()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build exact hot-tail hydration runtime")?;
            // One cross-process lock covers reservations, downloads and leases.
            // Deduplicate canonical keys before starting concurrent writers.
            let mut seen = BTreeSet::new();
            let entries: Vec<_> = objects
                .iter()
                .zip(cache_keys)
                .filter(|(_, key)| seen.insert((*key).clone()))
                .collect();
            let reserved = Cell::new(0_u64);
            self.retry_cache_pressure(&protected, || {
                runtime.block_on(async {
                    hydrate_ordered(entries.iter().map(|(object, key)| {
                        self.ensure_object(object, key, &protected, &reserved)
                    }))
                    .await?;
                    Ok(())
                })
            })?;
            self.create_lease(objects, cache_keys)
        })
    }

    fn retry_cache_pressure<T>(
        &self,
        protected: &BTreeSet<String>,
        mut operation: impl FnMut() -> Result<T>,
    ) -> Result<T> {
        for attempt in 0..=64 {
            match operation() {
                Err(error) if cache_storage_full(&error) && attempt < 64 => {
                    if !self.evict_oldest_unpinned(protected)? {
                        return Err(error);
                    }
                }
                result => return result,
            }
        }
        unreachable!()
    }

    fn evict_oldest_unpinned(&self, protected: &BTreeSet<String>) -> Result<bool> {
        let pinned = parquet_inodes(&self.pins)?;
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(&self.objects)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name();
            let Some(key) = name.to_str().and_then(|name| name.strip_suffix(".parquet")) else {
                continue;
            };
            let metadata = entry.metadata()?;
            if protected.contains(key) || pinned.contains(&(metadata.dev(), metadata.ino())) {
                continue;
            }
            candidates.push((metadata.modified()?, entry.path(), key.to_string()));
        }
        candidates.sort();
        let Some((_, path, key)) = candidates.first() else {
            return Ok(false);
        };
        std::fs::remove_file(path)?;
        self.forget_cache_key(key);
        tracing::warn!(
            cache_key = key,
            "evicted oldest unpinned hot-tail cache object after ENOSPC"
        );
        Ok(true)
    }

    fn cache_keys(
        &self,
        manifest: &HotTailManifest,
        generation: Option<HotTailCacheGenerationBinding<'_>>,
    ) -> Result<Vec<String>> {
        let Some(namespace) = self.shared_namespace.as_ref() else {
            return manifest
                .objects
                .iter()
                .map(|object| {
                    object
                        .sha256
                        .clone()
                        .context("schema-v4 hot-tail object omitted sha256")
                })
                .collect();
        };
        let generation = generation.context(
            "enterprise_shared cache hydration requires query/schema/runtime generation",
        )?;
        let tenant_id = uuid::Uuid::parse_str(&manifest.tenant_id)
            .context("enterprise_shared hot-tail tenant is not a UUID")?;
        if tenant_id != namespace.tenant_id() {
            bail!("enterprise_shared hot-tail cache changed the assigned tenant");
        }
        // Tail membership belongs to the lease, not the immutable object
        // identity. Re-keying every unchanged object for each signed tail
        // revision temporarily requires two complete tails while the prior
        // lease is pinned, which can reject a valid append at the configured
        // one-tail bound. Keep snapshot/runtime/schema rotations isolated,
        // while allowing an exact R2 key + ETag + length + SHA-256 to be
        // reused by successive tails over the same catalog generation.
        let query_generation = format!(
            "base={};head={}",
            manifest.base_snapshot_id, manifest.head_snapshot_id
        );
        manifest
            .objects
            .iter()
            .map(|object| {
                let (bucket, object_key) = parse_s3_uri(&object.source_uri)?;
                namespace.cache_key(&TenantObjectCacheIdentity {
                    tenant_id,
                    dataset: &manifest.table,
                    bucket,
                    object_key,
                    // R2 has no S3 object-version API. The compatibility
                    // `version_id` remains signed in the manifest/ledger, but
                    // shared cache identity and remote admission depend on the
                    // authoritative ETag returned by the conditional writer.
                    version_id: None,
                    etag: Some(
                        object
                            .etag
                            .as_deref()
                            .context("enterprise_shared schema-v4 object omitted ETag")?,
                    ),
                    content_sha256: object
                        .sha256
                        .as_deref()
                        .context("schema-v4 hot-tail object omitted sha256")?,
                    size_bytes: object.size_bytes,
                    query_generation: &query_generation,
                    schema_generation: generation.schema_generation,
                    runtime_generation: generation.runtime_generation,
                })
            })
            .collect()
    }

    async fn ensure_object(
        &self,
        object: &HotTailObject,
        cache_key: &str,
        protected: &BTreeSet<String>,
        reserved: &Cell<u64>,
    ) -> Result<()> {
        let digest = object
            .sha256
            .as_deref()
            .context("schema-v4 hot-tail object omitted sha256")?;
        let (bucket, key) = parse_s3_uri(&object.source_uri)?;
        // The authenticated manifest binds ETag, size and SHA-256. Cache hits
        // verify those immutable bytes locally; misses use conditional GETs.
        let shared_operator = match self.shared_namespace.as_ref() {
            Some(namespace) => Some(shared_r2_operator(bucket, namespace.credential_id())?),
            None => None,
        };
        let path = self.object_path(cache_key);
        if path.exists() {
            let stamp = FileStamp::read(&path)?;
            // Shared product bytes are a cross-tenant security boundary: hash
            // every local admission so a forged inode/mtime stamp cannot turn
            // local tampering into a trusted hit. Preserve the historical
            // stamp memoization only for dedicated/open deployments.
            let already_verified = self.shared_namespace.is_none()
                && stamp.bytes == object.size_bytes
                && self
                    .verified
                    .lock()
                    .expect("hot-tail cache verification lock")
                    .get(cache_key)
                    .is_some_and(|prior| prior == &stamp);
            if already_verified || cached_object_matches(&path, object.size_bytes, digest) {
                self.remember_verified_object(cache_key, digest, stamp);
                return Ok(());
            }
            // A live query uses this canonical name. Never replace it under
            // a live lease after a failed integrity check.
            if parquet_inodes(&self.pins)?.contains(&(stamp.dev, stamp.inode)) {
                bail!("live hot-tail cache object failed its integrity fence");
            }
            self.forget_cache_key(cache_key);
            std::fs::remove_file(&path)
                .with_context(|| format!("remove invalid cache object {}", path.display()))?;
        }

        // Cache keys deliberately include snapshot/runtime/schema generations,
        // but immutable Parquet bytes do not. During a generation cutover the
        // active lease is still pinned while the worker must prepare the
        // candidate tail. Reuse an exact tenant-local inode only after the
        // caller verified the signed object identity above. This
        // preserves generation-isolated names and rollback leases without
        // doubling physical tmpfs at the one-tail deployment bound.
        if self.try_link_verified_shared_content(cache_key, digest, object.size_bytes)? {
            return Ok(());
        }

        let reservation = DownloadReservation::new(reserved, object.size_bytes)?;
        self.evict_until_fits(reserved.get(), protected)?;
        let operator = match shared_operator {
            Some(operator) => operator,
            None => crate::job::result_s3_operator(bucket)
                .with_context(|| format!("open exact hot-tail store for bucket {bucket}"))?,
        };
        let temporary = download_exact_object(
            &operator,
            key,
            object,
            &self.objects,
            self.shared_namespace.is_some(),
        )
        .await?;
        temporary
            .as_file()
            .sync_all()
            .context("sync hot-tail cache temporary")?;
        match temporary.persist_noclobber(&path) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                if FileStamp::read(&path)?.bytes != object.size_bytes
                    || crate::native::file_sha256(&path)? != digest
                {
                    bail!("concurrent hot-tail cache admission produced conflicting bytes");
                }
            }
            Err(error) => return Err(error.error.into()),
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))?;
        let stamp = FileStamp::read(&path)?;
        self.remember_verified_object(cache_key, digest, stamp);
        drop(reservation);
        Ok(())
    }

    fn remember_verified_object(&self, cache_key: &str, digest: &str, stamp: FileStamp) {
        let bytes = stamp.bytes;
        self.verified
            .lock()
            .expect("hot-tail cache verification lock")
            .insert(cache_key.to_string(), stamp);
        if self.shared_namespace.is_some() {
            self.shared_content
                .lock()
                .expect("hot-tail shared-content lock")
                .insert((digest.to_string(), bytes), cache_key.to_string());
        }
    }

    fn forget_cache_key(&self, cache_key: &str) {
        self.verified
            .lock()
            .expect("hot-tail cache verification lock")
            .remove(cache_key);
        self.shared_content
            .lock()
            .expect("hot-tail shared-content lock")
            .retain(|_, indexed_key| indexed_key != cache_key);
    }

    fn try_link_verified_shared_content(
        &self,
        cache_key: &str,
        digest: &str,
        bytes: u64,
    ) -> Result<bool> {
        if self.shared_namespace.is_none() {
            return Ok(false);
        }
        let indexed_key = self
            .shared_content
            .lock()
            .expect("hot-tail shared-content lock")
            .get(&(digest.to_string(), bytes))
            .cloned();
        let Some(indexed_key) = indexed_key else {
            return Ok(false);
        };
        if indexed_key == cache_key {
            return Ok(false);
        }
        let source = self.object_path(&indexed_key);
        if !cached_object_matches(&source, bytes, digest) {
            self.forget_cache_key(&indexed_key);
            return Ok(false);
        }
        let destination = self.object_path(cache_key);
        std::fs::hard_link(&source, &destination).with_context(|| {
            format!(
                "reuse verified hot-tail content {} as generation key {}",
                source.display(),
                destination.display()
            )
        })?;
        if !cached_object_matches(&destination, bytes, digest) {
            let _ = std::fs::remove_file(&destination);
            bail!("generation-linked hot-tail object failed its exact content fence");
        }
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o444))?;
        self.remember_verified_object(cache_key, digest, FileStamp::read(&destination)?);
        Ok(true)
    }

    fn create_lease(
        self: &Arc<Self>,
        objects: &[HotTailObject],
        cache_keys: &[String],
    ) -> Result<HotTailCacheLease> {
        let lease_id = uuid::Uuid::now_v7().to_string();
        let directory = self.pins.join(&lease_id);
        std::fs::create_dir(&directory)
            .with_context(|| format!("create hot-tail lease {}", directory.display()))?;
        let lease_path = directory.join(".lease");
        let lease = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&lease_path)?;
        lease.lock_exclusive()?;
        let result = (|| {
            let mut local_paths = Vec::with_capacity(objects.len());
            let mut seen = BTreeSet::new();
            for (index, (_object, cache_key)) in objects.iter().zip(cache_keys).enumerate() {
                let source = self.object_path(cache_key);
                let destination = directory.join(format!("{index:04}.parquet"));
                std::fs::hard_link(&source, &destination).with_context(|| {
                    format!(
                        "pin hot-tail object {} into {}",
                        source.display(),
                        destination.display()
                    )
                })?;
                // chDB's Parquet metadata cache keys by pathname. A random
                // lease path invalidated every unchanged footer on each append.
                // Keep duplicate content as separate reads, as before.
                local_paths.push(if seen.insert(cache_key) { source } else { destination });
            }
            Ok::<_, anyhow::Error>(local_paths)
        })();
        match result {
            Ok(local_paths) => Ok(HotTailCacheLease {
                cache: self.clone(),
                directory,
                lease,
                local_paths,
            }),
            Err(error) => {
                let _ = FileExt::unlock(&lease);
                let _ = std::fs::remove_dir_all(&directory);
                Err(error)
            }
        }
    }

    fn object_path(&self, cache_key: &str) -> PathBuf {
        self.objects.join(format!("{cache_key}.parquet"))
    }

    fn with_global_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.global_lock)
            .with_context(|| format!("open hot-tail cache lock {}", self.global_lock.display()))?;
        lock.lock_exclusive()?;
        let result = operation();
        let unlock = FileExt::unlock(&lock);
        result.and_then(|value| {
            unlock?;
            Ok(value)
        })
    }

    fn reclaim_stale_pin_directories(&self) -> Result<()> {
        for entry in std::fs::read_dir(&self.pins)? {
            let path = entry?.path();
            if !path.is_dir() {
                let _ = std::fs::remove_file(path);
                continue;
            }
            let lease_path = path.join(".lease");
            let lease = match OpenOptions::new().read(true).write(true).open(&lease_path) {
                Ok(lease) => lease,
                Err(_) => {
                    std::fs::remove_dir_all(&path)?;
                    continue;
                }
            };
            match lease.try_lock_exclusive() {
                Ok(()) => {
                    FileExt::unlock(&lease)?;
                    std::fs::remove_dir_all(&path)?;
                }
                Err(error) if error.kind() == fs2::lock_contended_error().kind() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn evict_until_fits(&self, additional: u64, protected: &BTreeSet<String>) -> Result<()> {
        let mut used = physical_parquet_bytes(&self.root)?;
        let cell_fits = self
            .shared_namespace
            .as_ref()
            .is_none_or(|namespace| namespace.ensure_cell_fits(additional).is_ok());
        if used.saturating_add(additional) <= self.max_bytes && cell_fits {
            return Ok(());
        }
        let pinned = parquet_inodes(&self.pins)?;
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(&self.objects)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(digest) = name.strip_suffix(".parquet").map(ToOwned::to_owned) else {
                continue;
            };
            if protected.contains(&digest) {
                continue;
            }
            let metadata = std::fs::metadata(&path)?;
            if pinned.contains(&(metadata.dev(), metadata.ino())) {
                continue;
            }
            candidates.push((metadata.modified().ok(), path, digest));
        }
        candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        for (_, path, digest) in candidates {
            std::fs::remove_file(&path)?;
            self.forget_cache_key(&digest);
            used = physical_parquet_bytes(&self.root)?;
            let cell_fits = self
                .shared_namespace
                .as_ref()
                .is_none_or(|namespace| namespace.ensure_cell_fits(additional).is_ok());
            if used.saturating_add(additional) <= self.max_bytes && cell_fits {
                return Ok(());
            }
        }
        Err(anyhow::Error::new(HotTailCachePinnedPressure {
            additional,
            used,
            max_bytes: self.max_bytes,
        }))
    }
}

/// Choose between the complete tail and a newest-first partial one.
///
/// `budget` is `None` for the normal decision (complete when it fits, else
/// partial at `max_bytes / PARTIAL_TAIL_BUDGET_DIVISOR`); `Some(budget)`
/// forces a partial selection whenever the tail exceeds `budget`, which the
/// worker uses to shrink its currently served tail before the next partial
/// revision hydrates beside it.
fn plan_newest_fitting(
    manifest: &HotTailManifest,
    cache_keys: &[String],
    max_bytes: u64,
    budget: Option<u64>,
) -> Result<HotTailCoveragePlan> {
    if manifest.objects.is_empty() || cache_keys.len() != manifest.objects.len() {
        bail!("hot-tail coverage plan needs one cache identity per signed object");
    }
    let mut unique = BTreeMap::<&str, u64>::new();
    for (object, key) in manifest.objects.iter().zip(cache_keys) {
        unique.entry(key.as_str()).or_insert(object.size_bytes);
    }
    let total_bytes = unique.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .context("hot-tail cache byte total overflow")
    })?;
    let limit = budget.unwrap_or(max_bytes);
    if total_bytes <= limit {
        return Ok(HotTailCoveragePlan::Full);
    }
    let budget_bytes = budget.unwrap_or(max_bytes / PARTIAL_TAIL_BUDGET_DIVISOR);
    let mut order: Vec<usize> = (0..manifest.objects.len()).collect();
    let rank = |index: usize| {
        let object = &manifest.objects[index];
        (
            object.max_time_ms.unwrap_or(i64::MIN),
            object.min_time_ms.unwrap_or(i64::MIN),
            index,
        )
    };
    order.sort_by_key(|index| std::cmp::Reverse(rank(*index)));
    let mut admitted = BTreeSet::<&str>::new();
    let mut served_bytes = 0_u64;
    let mut kept = Vec::new();
    for index in order {
        let key = cache_keys[index].as_str();
        if !admitted.contains(key) {
            let bytes = manifest.objects[index].size_bytes;
            match served_bytes.checked_add(bytes) {
                Some(next) if next <= budget_bytes => served_bytes = next,
                // Strict prefix: never skip ahead to a smaller, older object,
                // or the "complete after uncovered_through_ms" claim breaks.
                _ => break,
            }
            admitted.insert(key);
        }
        kept.push(index);
    }
    if kept.is_empty() {
        bail!(
            "schema-v4 hot tail needs {total_bytes} cache bytes above its {max_bytes} byte deployment bound, \
             and its newest object does not fit the {budget_bytes} byte partial budget"
        );
    }
    kept.sort_unstable();
    let kept_set: BTreeSet<usize> = kept.iter().copied().collect();
    let omitted: Vec<&HotTailObject> = manifest
        .objects
        .iter()
        .enumerate()
        .filter(|(index, _)| !kept_set.contains(index))
        .map(|(_, object)| object)
        .collect();
    let uncovered_from_ms = omitted
        .iter()
        .map(|object| object.min_time_ms)
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().min());
    let uncovered_through_ms = omitted
        .iter()
        .map(|object| object.max_time_ms)
        .collect::<Option<Vec<_>>>()
        .and_then(|times| times.into_iter().max());
    let mut partial = manifest.clone();
    partial.objects = kept
        .iter()
        .map(|index| manifest.objects[*index].clone())
        .collect();
    partial.local_paths.clear();
    Ok(HotTailCoveragePlan::Partial {
        coverage: HotTailPartialCoverage {
            total_objects: manifest.objects.len(),
            served_objects: partial.objects.len(),
            total_bytes,
            served_bytes,
            budget_bytes,
            cache_max_bytes: max_bytes,
            uncovered_from_ms,
            uncovered_through_ms,
            reason: None,
        },
        manifest: partial,
    })
}

async fn hydrate_ordered<T>(
    reads: impl IntoIterator<Item = impl std::future::Future<Output = Result<T>>>,
) -> Result<Vec<T>> {
    futures::stream::iter(reads)
        .buffered(HYDRATE_CONCURRENCY)
        .try_collect()
        .await
}

/// Open the exact signed object: an ETag-bound conditional GET for
/// hosted-shared R2 (no object versions), else the exact S3 version.
async fn open_exact_object_stream(
    operator: &Operator,
    key: &str,
    object: &HotTailObject,
    etag_bound: bool,
) -> Result<opendal::FuturesBytesStream> {
    let reader = match etag_bound {
        true => {
            let etag = object
                .etag
                .as_deref()
                .context("enterprise_shared schema-v4 object omitted ETag")?;
            operator
                .reader_with(key)
                .if_match(etag)
                .chunk(DOWNLOAD_CHUNK_BYTES)
                .await
                .with_context(|| {
                    format!(
                        "open ETag-bound enterprise_shared R2 object {}",
                        object.source_uri
                    )
                })?
        }
        false => operator
            .reader_with(key)
            .version(&object.version_id)
            .chunk(DOWNLOAD_CHUNK_BYTES)
            .await
            .with_context(|| {
                format!(
                    "open exact hot-tail object {} version {}",
                    object.source_uri, object.version_id
                )
            })?,
    };
    // A bounded range avoids OpenDAL's implicit HEAD to resolve EOF.
    reader
        .into_bytes_stream(0..object.size_bytes)
        .await
        .context("stream exact hot-tail object")
}

async fn download_exact_object(
    operator: &Operator,
    key: &str,
    object: &HotTailObject,
    directory: &Path,
    etag_bound: bool,
) -> Result<tempfile::NamedTempFile> {
    let digest = object
        .sha256
        .as_deref()
        .context("hot-tail object omitted sha256")?;
    let mut stream = open_exact_object_stream(operator, key, object, etag_bound).await?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(directory).context("create hot-tail cache temporary")?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    while let Some(chunk) = stream
        .try_next()
        .await
        .context("read exact hot-tail object")?
    {
        bytes = bytes
            .checked_add(chunk.len() as u64)
            .context("hot-tail cache byte count overflow")?;
        if bytes > object.size_bytes {
            bail!("exact hot-tail object exceeded its signed byte length");
        }
        hasher.update(&chunk);
        temporary
            .write_all(&chunk)
            .context("write hot-tail cache temporary")?;
    }
    if bytes != object.size_bytes || hex::encode(hasher.finalize()) != digest {
        bail!("exact hot-tail object failed its signed length or SHA-256 fence");
    }
    Ok(temporary)
}

/// NAN-2694: the RAM cache's object authority, handed to the slow path.
///
/// It reads exactly what hydration reads (same bucket fence, credential and
/// ETag/version binding) and exposes the RAM-tier file of an object so the
/// disk tier can seal a demoted object without downloading it again.
/// [`crate::hot_tail_slow_path::fetch_verified`] applies the SHA-256 fence.
pub struct HotTailCacheSource {
    cache: Arc<HotTailCache>,
    /// The signed tail's identity with its object list cleared; one object
    /// is spliced in to derive a cache key.
    template: HotTailManifest,
    runtime_generation: String,
    schema_generation: String,
}

impl HotTailCacheSource {
    pub fn new(
        cache: Arc<HotTailCache>,
        manifest: &HotTailManifest,
        generation: Option<HotTailCacheGenerationBinding<'_>>,
    ) -> Result<Self> {
        // The same fences hydration applies before any remote read.
        if cache.shared_namespace.is_some() {
            validate_shared_r2_hot_tail_manifest(manifest)?;
        }
        validate_hydration_sources(manifest)?;
        let mut template = manifest.clone();
        template.objects.clear();
        template.local_paths.clear();
        let (runtime_generation, schema_generation) = generation
            .map(|binding| {
                (
                    binding.runtime_generation.to_string(),
                    binding.schema_generation.to_string(),
                )
            })
            .unwrap_or_default();
        Ok(Self {
            cache,
            template,
            runtime_generation,
            schema_generation,
        })
    }

    fn binding(&self) -> Option<HotTailCacheGenerationBinding<'_>> {
        (!self.runtime_generation.is_empty()).then_some(HotTailCacheGenerationBinding {
            runtime_generation: &self.runtime_generation,
            schema_generation: &self.schema_generation,
        })
    }
}

#[async_trait::async_trait]
impl crate::hot_tail_slow_path::HotTailObjectSource for HotTailCacheSource {
    async fn stream_object(
        &self,
        object: &HotTailObject,
        sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> Result<()> + Send),
    ) -> Result<()> {
        let mut single = self.template.clone();
        single.objects = vec![object.clone()];
        validate_hydration_sources(&single)?;
        let (bucket, key) = parse_s3_uri(&object.source_uri)?;
        let operator = match self.cache.shared_namespace.as_ref() {
            Some(namespace) => shared_r2_operator(bucket, namespace.credential_id())?,
            None => crate::job::result_s3_operator(bucket)
                .with_context(|| format!("open exact hot-tail store for bucket {bucket}"))?,
        };
        let mut stream = open_exact_object_stream(
            &operator,
            key,
            object,
            self.cache.shared_namespace.is_some(),
        )
        .await?;
        while let Some(chunk) = stream
            .try_next()
            .await
            .context("read exact hot-tail object")?
        {
            sink(&chunk)?;
        }
        Ok(())
    }

    fn local_copy(&self, object: &HotTailObject) -> Option<PathBuf> {
        let mut single = self.template.clone();
        single.objects = vec![object.clone()];
        let key = self.cache.cache_keys(&single, self.binding()).ok()?.pop()?;
        let path = self.cache.object_path(&key);
        path.is_file().then_some(path)
    }
}

// Includes temporary downloads, which physical_parquet_bytes cannot yet see.
// Dropping a failed/cancelled future releases its reservation and temporary.
struct DownloadReservation<'a> {
    total: &'a Cell<u64>,
    bytes: u64,
}

impl<'a> DownloadReservation<'a> {
    fn new(total: &'a Cell<u64>, bytes: u64) -> Result<Self> {
        total.set(
            total
                .get()
                .checked_add(bytes)
                .context("tail reservation overflow")?,
        );
        Ok(Self { total, bytes })
    }
}

impl Drop for DownloadReservation<'_> {
    fn drop(&mut self) {
        self.total.set(self.total.get() - self.bytes);
    }
}

pub fn cache_storage_full(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::StorageFull)
    })
}

fn cached_object_matches(path: &Path, expected_bytes: u64, expected_sha256: &str) -> bool {
    FileStamp::read(path).is_ok_and(|stamp| stamp.bytes == expected_bytes)
        && crate::native::file_sha256(path).is_ok_and(|value| value == expected_sha256)
}

fn validate_cache_entries(
    objects: &[HotTailObject],
    cache_keys: &[String],
    max_bytes: u64,
) -> Result<BTreeSet<String>> {
    // Preserve every schema-v4 count/content validation from the historical
    // digest-only layout before applying the stricter shared cache identity.
    let _ = validate_object_set(objects, max_bytes)?;
    if objects.len() != cache_keys.len() {
        bail!("hot-tail cache identity cardinality differs from its object set");
    }
    let mut entries = BTreeMap::<String, u64>::new();
    for (object, cache_key) in objects.iter().zip(cache_keys) {
        if !valid_sha256(cache_key)
            || object.size_bytes == 0
            || entries
                .insert(cache_key.clone(), object.size_bytes)
                .is_some_and(|prior| prior != object.size_bytes)
        {
            bail!("schema-v4 hot-tail cache identities conflict");
        }
    }
    let bytes = entries.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .context("hot-tail cache byte total overflow")
    })?;
    if bytes > max_bytes {
        bail!(
            "schema-v4 hot tail needs {bytes} cache bytes above its {max_bytes} byte deployment bound"
        );
    }
    Ok(entries.into_keys().collect())
}

/// Apply the table/tenant prefix fence before opening any remote reader. The
/// planner repeats this check when it builds SQL, but hydration happens first
/// and must not turn a malformed (even correctly signed) manifest into an
/// object-store read outside the assigned table.
/// Validate that every physical object in a signed tail remains inside the
/// exact tenant table encoded by its metadata location. Query-worker health
/// reuses this lightweight fence before treating a newer signed assignment as
/// bounded hydration lag; no object download is required.
pub fn validate_hydration_sources(manifest: &HotTailManifest) -> Result<()> {
    let metadata_prefix = manifest
        .head_metadata_location
        .strip_suffix(&manifest.iceberg_metadata_file_path)
        .filter(|prefix| prefix.starts_with("s3://") && prefix.ends_with('/'))
        .context("schema-v4 hot-tail metadata path is outside its table")?;
    let data_prefix = format!("{metadata_prefix}data/");
    let tail_prefix = format!("{data_prefix}tail/");
    let staged_prefix = format!(
        "{tail_prefix}tenant_sha256={}/",
        hex::encode(Sha256::digest(manifest.tenant_id.as_bytes()))
    );
    if manifest.objects.iter().any(|object| {
        !object.source_uri.starts_with(&data_prefix)
            || (object.source_uri.starts_with(&tail_prefix)
                && !object.source_uri.starts_with(&staged_prefix))
            || !object.source_uri.ends_with(".parquet")
            || parse_s3_uri(&object.source_uri).is_err()
    }) {
        bail!("schema-v4 hot-tail object is outside its tenant table prefix");
    }
    Ok(())
}

fn validate_object_set(objects: &[HotTailObject], max_bytes: u64) -> Result<BTreeSet<String>> {
    if objects.is_empty() || objects.len() > HOT_TAIL_OBJECT_FORMAT_CEILING as usize {
        bail!("schema-v4 hot-tail object count violates its serving bound");
    }
    let mut digests = BTreeMap::<String, u64>::new();
    for object in objects {
        let digest = object
            .sha256
            .as_deref()
            .filter(|value| valid_sha256(value))
            .context("schema-v4 hot-tail object has an invalid SHA-256")?;
        if object.size_bytes == 0
            || digests
                .insert(digest.to_string(), object.size_bytes)
                .is_some_and(|prior| prior != object.size_bytes)
        {
            bail!("schema-v4 hot-tail content identities conflict");
        }
    }
    let bytes = digests.values().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(*bytes)
            .context("hot-tail cache byte total overflow")
    })?;
    if bytes > max_bytes {
        bail!(
            "schema-v4 hot tail needs {bytes} cache bytes above its {max_bytes} byte deployment bound"
        );
    }
    Ok(digests.into_keys().collect())
}

pub(crate) fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn parse_s3_uri(value: &str) -> Result<(&str, &str)> {
    let remainder = value
        .strip_prefix("s3://")
        .context("hot-tail object is not an s3:// URI")?;
    let (bucket, key) = remainder
        .split_once('/')
        .context("hot-tail object URI has no key")?;
    if bucket.is_empty()
        || key.is_empty()
        || [bucket, key]
            .iter()
            .any(|part| part.chars().any(char::is_control))
    {
        bail!("hot-tail S3 URI is invalid");
    }
    Ok((bucket, key))
}

/// The generation stores the engine-facing table source, which is either the
/// canonical `s3://bucket/key` identity or the exact configured path-style R2
/// endpoint. Do not accept an arbitrary HTTPS host merely because its suffix
/// resembles the assigned bucket/key.
fn parse_assigned_table_source<'a>(value: &'a str, endpoint: &str) -> Result<(&'a str, &'a str)> {
    if value.starts_with("s3://") {
        return parse_s3_uri(value);
    }
    let endpoint = endpoint.trim_end_matches('/');
    if !endpoint.starts_with("https://")
        || endpoint.contains(['?', '#', '@'])
        || endpoint.chars().any(char::is_control)
    {
        bail!("enterprise_shared R2 endpoint is invalid");
    }
    let remainder = value
        .strip_prefix(endpoint)
        .and_then(|value| value.strip_prefix('/'))
        .context("worker source is outside the configured R2 endpoint")?;
    let (bucket, key) = remainder
        .split_once('/')
        .context("worker source has no assigned table key")?;
    if bucket.is_empty()
        || key.is_empty()
        || value.contains(['?', '#', '@'])
        || [bucket, key]
            .iter()
            .any(|part| part.chars().any(char::is_control))
    {
        bail!("enterprise_shared R2 worker source is invalid");
    }
    Ok((bucket, key))
}

fn physical_parquet_bytes(root: &Path) -> Result<u64> {
    fn visit(
        path: &Path,
        depth: usize,
        inodes: &mut BTreeSet<(u64, u64)>,
        bytes: &mut u64,
    ) -> Result<()> {
        if depth > 3 {
            bail!("hot-tail cache directory exceeded its expected depth");
        }
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_symlink() {
                bail!("hot-tail cache contains a symbolic link");
            }
            if file_type.is_dir() {
                visit(&path, depth + 1, inodes, bytes)?;
            } else if path.extension().and_then(|value| value.to_str()) == Some("parquet") {
                let metadata = entry.metadata()?;
                if inodes.insert((metadata.dev(), metadata.ino())) {
                    *bytes = bytes
                        .checked_add(metadata.len())
                        .context("hot-tail cache physical byte count overflow")?;
                }
            }
        }
        Ok(())
    }

    let mut inodes = BTreeSet::new();
    let mut bytes = 0_u64;
    visit(root, 0, &mut inodes, &mut bytes)?;
    Ok(bytes)
}

fn parquet_inodes(root: &Path) -> Result<BTreeSet<(u64, u64)>> {
    fn visit(path: &Path, depth: usize, inodes: &mut BTreeSet<(u64, u64)>) -> Result<()> {
        if depth > 3 {
            bail!("hot-tail cache directory exceeded its expected depth");
        }
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_symlink() {
                bail!("hot-tail cache contains a symbolic link");
            }
            if file_type.is_dir() {
                visit(&path, depth + 1, inodes)?;
            } else if path.extension().and_then(|value| value.to_str()) == Some("parquet") {
                let metadata = entry.metadata()?;
                inodes.insert((metadata.dev(), metadata.ino()));
            }
        }
        Ok(())
    }

    let mut inodes = BTreeSet::new();
    visit(root, 0, &mut inodes)?;
    Ok(inodes)
}

/// Cross-process pin for one fully hydrated manifest.
pub struct HotTailCacheLease {
    cache: Arc<HotTailCache>,
    directory: PathBuf,
    lease: File,
    local_paths: Vec<PathBuf>,
}

impl HotTailCacheLease {
    pub fn local_paths(&self) -> &[PathBuf] {
        &self.local_paths
    }
}

impl std::fmt::Debug for HotTailCacheLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HotTailCacheLease")
            .field("directory", &self.directory)
            .field("objects", &self.local_paths.len())
            .finish()
    }
}

impl Drop for HotTailCacheLease {
    fn drop(&mut self) {
        // Serialize lease removal with cache trim/eviction. The prior drop
        // unlocked and recursively removed this directory outside the global
        // cache fence, so `trim_unpinned()` could walk a pin tree that vanished
        // between `read_dir`, `file_type`, and `metadata`, returning ENOENT and
        // skipping the pressure-recovery step. While the lease is live it must
        // stay visible and locked; once this fence is held, removing it makes
        // every formerly pinned inode atomically eligible for the next trim.
        let _ = self.cache.with_global_lock(|| {
            FileExt::unlock(&self.lease)?;
            match std::fs::remove_dir_all(&self.directory) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared_authority(
        tenant: uuid::Uuid,
        bucket: &str,
        tenant_max_bytes: u64,
        cell_max_bytes: u64,
    ) -> TenantObjectCacheAuthority {
        TenantObjectCacheAuthority::new(
            tenant,
            bucket.to_string(),
            format!("read-credential-{tenant}"),
            bucket,
            true,
            1,
            1,
            CacheEncryptionProvider::CsiEncrypted,
            format!("cache-key-{tenant}"),
            1,
            tenant_max_bytes,
            cell_max_bytes,
        )
        .unwrap()
    }

    fn object(digest: &str, bytes: u64) -> HotTailObject {
        HotTailObject {
            source_uri: "s3://bucket/table/data/tail/object.parquet".to_string(),
            version_id: "version".to_string(),
            etag: None,
            size_bytes: bytes,
            rows: 1,
            sha256: Some(digest.to_string()),
            min_time_ms: Some(1),
            max_time_ms: Some(1),
            committed: false,
        }
    }

    fn manifest(source_uri: String) -> HotTailManifest {
        HotTailManifest {
            schema_version: 4,
            tenant_id: "tenant-a".to_string(),
            table: "nano.events".to_string(),
            base_snapshot_id: 1,
            head_snapshot_id: 1,
            tail_id: Some("c".repeat(64)),
            head_metadata_location: "s3://bucket/table/metadata/v1.json".to_string(),
            iceberg_metadata_file_path: "metadata/v1.json".to_string(),
            read_schema: Some("event Tuple(time String)".to_string()),
            available_paths: vec!["time".to_string()],
            objects: vec![HotTailObject {
                source_uri,
                ..object(&"a".repeat(64), 5)
            }],
            local_paths: Vec::new(),
        }
    }

    fn shared_manifest(tenant: uuid::Uuid, bucket: &str) -> HotTailManifest {
        let tenant_id = tenant.to_string();
        let tenant_hash = hex::encode(Sha256::digest(tenant_id.as_bytes()));
        let table_root = format!("s3://{bucket}/warehouse/nano/events");
        HotTailManifest {
            schema_version: 4,
            tenant_id,
            table: "nano.events".to_string(),
            base_snapshot_id: 41,
            head_snapshot_id: 42,
            tail_id: Some("c".repeat(64)),
            head_metadata_location: format!("{table_root}/metadata/v42.json"),
            iceberg_metadata_file_path: "metadata/v42.json".to_string(),
            read_schema: Some("event Tuple(time String)".to_string()),
            available_paths: vec!["time".to_string()],
            objects: vec![HotTailObject {
                source_uri: format!(
                    "{table_root}/data/tail/tenant_sha256={tenant_hash}/hour=1/object.parquet"
                ),
                etag: Some("\"r2-etag-a\"".to_string()),
                ..object(&"a".repeat(64), 5)
            }],
            local_paths: Vec::new(),
        }
    }

    #[test]
    fn enospc_retries_after_evicting_oldest_without_touching_pins_or_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 100).unwrap();
        let oldest = cache.objects.join("oldest.parquet");
        let pinned = cache.objects.join("pinned.parquet");
        let candidate = cache.objects.join("candidate.parquet");
        for path in [&oldest, &pinned, &candidate] {
            std::fs::write(path, b"test").unwrap();
        }
        let lease = cache.pins.join("live");
        std::fs::create_dir(&lease).unwrap();
        std::fs::hard_link(&pinned, lease.join("pinned.parquet")).unwrap();
        let mut calls = 0;
        cache
            .retry_cache_pressure(&BTreeSet::from(["candidate".to_string()]), || {
                calls += 1;
                if oldest.exists() {
                    return Err(std::io::Error::from_raw_os_error(28))
                        .context("write hot-tail cache temporary");
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(calls, 2);
        assert!(pinned.exists());
        assert!(candidate.exists());
        let error = cache
            .retry_cache_pressure(
                &BTreeSet::from(["candidate".to_string()]),
                || -> Result<()> {
                    Err(std::io::Error::from_raw_os_error(28))
                        .context("write hot-tail cache temporary")
                },
            )
            .unwrap_err();
        assert!(cache_storage_full(&error));
    }

    #[test]
    fn remote_hydration_is_fenced_to_the_signed_tenant_table() {
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        let valid = format!(
            "s3://bucket/table/data/tail/tenant_sha256={tenant_hash}/hour=1/object.parquet"
        );
        assert!(validate_hydration_sources(&manifest(valid)).is_ok());
        let mut catalog_committed =
            manifest("s3://bucket/table/data/event_hour=1/catalog-object.parquet".to_string());
        catalog_committed.objects[0].committed = true;
        assert!(validate_hydration_sources(&catalog_committed).is_ok());
        assert!(validate_hydration_sources(&manifest(
            "s3://bucket/other/data/tail/object.parquet".to_string()
        ))
        .is_err());
        assert!(validate_hydration_sources(&manifest(
            "s3://bucket/table/data/tail/tenant_sha256=other/object.parquet".to_string()
        ))
        .is_err());
        let mut cross_tenant_committed =
            manifest("s3://bucket/table/data/tail/tenant_sha256=other/object.parquet".to_string());
        cross_tenant_committed.objects[0].committed = true;
        assert!(validate_hydration_sources(&cross_tenant_committed).is_err());
    }

    #[test]
    fn manifest_cache_budget_is_total_unique_content_not_object_count() {
        let digest = "a".repeat(64);
        let objects = vec![object(&digest, 200), object(&digest, 200)];
        assert_eq!(validate_object_set(&objects, 200).unwrap().len(), 1);
        assert!(validate_object_set(&objects, 199).is_err());
    }

    #[test]
    fn conflicting_size_for_one_digest_fails_closed() {
        let digest = "b".repeat(64);
        assert!(validate_object_set(&[object(&digest, 1), object(&digest, 2)], 10).is_err());
    }

    #[test]
    fn poisoned_or_tampered_cache_bytes_never_pass_the_content_fence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("object.parquet");
        let digest = hex::encode(Sha256::digest(b"good"));
        std::fs::write(&path, b"evil").unwrap();
        assert!(!cached_object_matches(&path, 4, &digest));
        std::fs::write(&path, b"good").unwrap();
        assert!(cached_object_matches(&path, 4, &digest));
        std::fs::write(&path, b"goof").unwrap();
        assert!(!cached_object_matches(&path, 4, &digest));
    }

    #[test]
    fn assigned_table_source_accepts_only_canonical_or_exact_r2_endpoint() {
        let endpoint = "https://account.r2.cloudflarestorage.com";
        assert_eq!(
            parse_assigned_table_source("s3://tenant-bucket/table/events", endpoint).unwrap(),
            ("tenant-bucket", "table/events")
        );
        assert_eq!(
            parse_assigned_table_source(
                "https://account.r2.cloudflarestorage.com/tenant-bucket/table/events",
                endpoint,
            )
            .unwrap(),
            ("tenant-bucket", "table/events")
        );
        for source in [
            "https://attacker.invalid/tenant-bucket/table/events",
            "https://account.r2.cloudflarestorage.com.attacker.invalid/tenant-bucket/table/events",
            "https://account.r2.cloudflarestorage.com/tenant-bucket/table/events?version=old",
            "https://account.r2.cloudflarestorage.com/tenant-bucket",
        ] {
            assert!(parse_assigned_table_source(source, endpoint).is_err());
        }
    }

    #[tokio::test]
    async fn isolated_cache_reuses_verified_inodes_and_assembles_manifest_order() {
        let directory = tempfile::tempdir().unwrap();
        let writer = HotTailCache::open(directory.path(), 100).unwrap();
        let mut manifest = manifest("s3://bucket/table/data/committed.parquet".to_string());
        manifest.objects.clear();
        for index in (0..20).rev() {
            let bytes = format!("{index:04}");
            let digest = hex::encode(Sha256::digest(bytes.as_bytes()));
            std::fs::write(writer.object_path(&digest), bytes).unwrap();
            manifest.objects.push(HotTailObject {
                source_uri: format!("s3://bucket/table/data/{index}.parquet"),
                committed: true,
                ..object(&digest, 4)
            });
        }
        // A fresh process has no memoized digest stamps. Every hit is rehashed,
        // and admission pins the same inode without modifying its bytes.
        let reader = HotTailCache::open(directory.path(), 100).unwrap();
        let lease = reader.hydrate(&manifest).await.unwrap();
        for (index, path) in lease.local_paths.iter().enumerate() {
            assert_eq!(std::fs::read(path).unwrap(), format!("{:04}", 19-index).as_bytes());
            let canonical = writer.object_path(manifest.objects[index].sha256.as_ref().unwrap());
            assert_eq!(FileStamp::read(Path::new(path)).unwrap().inode,
                FileStamp::read(&canonical).unwrap().inode);
        }
        assert_eq!(physical_parquet_bytes(directory.path()).unwrap(), 80);
    }

    #[tokio::test]
    async fn stable_paths_preserve_duplicate_object_multiplicity() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 4).unwrap();
        let digest = hex::encode(Sha256::digest(b"same"));
        std::fs::write(cache.object_path(&digest), b"same").unwrap();
        let mut tail = manifest("s3://bucket/table/data/first.parquet".into());
        tail.objects = vec![object(&digest, 4), object(&digest, 4)];
        tail.objects[0].source_uri = "s3://bucket/table/data/first.parquet".into();
        tail.objects[1].source_uri = "s3://bucket/table/data/second.parquet".into();
        let lease = cache.hydrate(&tail).await.unwrap();
        assert_eq!(lease.local_paths.len(), 2);
        assert_ne!(lease.local_paths[0], lease.local_paths[1]);
        assert_eq!(physical_parquet_bytes(directory.path()).unwrap(), 4);
    }

    #[tokio::test]
    async fn live_canonical_path_is_not_replaced_after_integrity_failure() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 4).unwrap();
        let digest = hex::encode(Sha256::digest(b"good"));
        let path = cache.object_path(&digest);
        std::fs::write(&path, b"good").unwrap();
        let mut tail = manifest("s3://bucket/table/data/first.parquet".into());
        tail.objects[0].sha256 = Some(digest);
        tail.objects[0].size_bytes = 4;
        let lease = cache.hydrate(&tail).await.unwrap();
        // Simulate storage corruption; a different size defeats any mtime
        // granularity assumptions made by the dedicated cache stamp.
        std::fs::write(&path, b"corrupt").unwrap();
        let error = cache.hydrate(&tail).await.unwrap_err();
        assert!(error.to_string().contains("integrity fence"));
        assert_eq!(lease.local_paths[0], path);
        assert!(path.exists(), "failed admission must not unlink a live name");
    }

    #[tokio::test]
    async fn incremental_append_and_replacement_preserve_live_leases_and_bounds() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 12).unwrap();
        let mut manifest = manifest("s3://bucket/table/data/first.parquet".to_string());
        manifest.objects.clear();
        for (index, bytes) in [b"one!", b"two!", b"pack"].iter().enumerate() {
            let digest = hex::encode(Sha256::digest(bytes));
            std::fs::write(cache.object_path(&digest), bytes).unwrap();
            manifest.objects.push(HotTailObject {
                source_uri: format!("s3://bucket/table/data/{index}.parquet"),
                committed: true,
                ..object(&digest, 4)
            });
        }
        let all = manifest.objects.clone();
        manifest.objects = all[..1].to_vec();
        let first = cache.hydrate(&manifest).await.unwrap();
        manifest.objects = all[..2].to_vec();
        let appended = cache.hydrate(&manifest).await.unwrap();
        assert_eq!(first.local_paths[0], appended.local_paths[0]);
        assert_eq!(
            FileStamp::read(Path::new(&first.local_paths[0]))
                .unwrap()
                .inode,
            FileStamp::read(Path::new(&appended.local_paths[0]))
                .unwrap()
                .inode
        );
        manifest.objects = all[2..].to_vec();
        let packed = cache.hydrate(&manifest).await.unwrap();
        assert_eq!(packed.local_paths.len(), 1);
        assert_eq!(std::fs::read(&packed.local_paths[0]).unwrap(), b"pack");
        assert_eq!(std::fs::read(&appended.local_paths[1]).unwrap(), b"two!");
        assert_eq!(physical_parquet_bytes(directory.path()).unwrap(), 12);
        // A different process cannot unlink names used by either revision.
        let other = HotTailCache::open(directory.path(), 12).unwrap();
        assert!(other.evict_until_fits(1, &BTreeSet::new()).is_err());
        assert_eq!(std::fs::read(&first.local_paths[0]).unwrap(), b"one!");
        assert_eq!(std::fs::read(&appended.local_paths[1]).unwrap(), b"two!");
        drop(first);
        drop(appended);
        cache.trim_unpinned().unwrap();
        assert_eq!(physical_parquet_bytes(directory.path()).unwrap(), 4);
    }

    #[test]
    fn physical_accounting_counts_hard_links_once() {
        let directory = tempfile::tempdir().unwrap();
        let objects = directory.path().join("objects");
        let pins = directory.path().join("pins/lease");
        std::fs::create_dir_all(&objects).unwrap();
        std::fs::create_dir_all(&pins).unwrap();
        let canonical = objects.join("a.parquet");
        std::fs::write(&canonical, b"bytes").unwrap();
        std::fs::hard_link(&canonical, pins.join("0000.parquet")).unwrap();
        assert_eq!(physical_parquet_bytes(directory.path()).unwrap(), 5);
    }

    #[test]
    fn pressure_trim_removes_only_unpinned_cache_objects() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 100).unwrap();
        let pinned = cache.objects.join("pinned.parquet");
        let stale = cache.objects.join("stale.parquet");
        let lease = cache.pins.join("active");
        std::fs::create_dir_all(&lease).unwrap();
        let lease_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(lease.join(".lease"))
            .unwrap();
        lease_file.lock_exclusive().unwrap();
        std::fs::write(&pinned, b"pinned").unwrap();
        std::fs::write(&stale, b"stale").unwrap();
        std::fs::hard_link(&pinned, lease.join("0000.parquet")).unwrap();

        assert_eq!(
            cache.trim_unpinned().unwrap(),
            HotTailCacheTrim { files: 1, bytes: 5 }
        );
        assert!(pinned.exists());
        assert!(!stale.exists());

        std::fs::remove_file(lease.join("0000.parquet")).unwrap();
        FileExt::unlock(&lease_file).unwrap();
        assert_eq!(
            cache.trim_unpinned().unwrap(),
            HotTailCacheTrim { files: 1, bytes: 6 }
        );
        assert!(!pinned.exists());
    }

    #[test]
    fn pressure_trim_understands_generation_aliases() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 100).unwrap();
        let first = cache.objects.join(format!("{}.parquet", "a".repeat(64)));
        let second = cache.objects.join(format!("{}.parquet", "b".repeat(64)));
        let lease = cache.pins.join("active");
        std::fs::create_dir_all(&lease).unwrap();
        let lease_file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(lease.join(".lease"))
            .unwrap();
        lease_file.lock_exclusive().unwrap();
        std::fs::write(&first, b"bytes").unwrap();
        std::fs::hard_link(&first, &second).unwrap();
        std::fs::hard_link(&first, lease.join("0000.parquet")).unwrap();

        assert_eq!(cache.trim_unpinned().unwrap(), HotTailCacheTrim::default());
        std::fs::remove_file(lease.join("0000.parquet")).unwrap();
        FileExt::unlock(&lease_file).unwrap();
        assert_eq!(
            cache.trim_unpinned().unwrap(),
            HotTailCacheTrim { files: 2, bytes: 5 }
        );
        assert!(!first.exists());
        assert!(!second.exists());
    }

    #[test]
    fn dedicated_cache_keeps_the_historical_digest_layout() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 100).unwrap();
        let digest = "a".repeat(64);
        let manifest = manifest("s3://bucket/table/data/event_hour=1/object.parquet".to_string());
        assert_eq!(
            cache.cache_keys(&manifest, None).unwrap(),
            vec![digest.clone()]
        );
        assert_eq!(
            cache.object_path(&digest),
            directory
                .path()
                .join("objects")
                .join(format!("{digest}.parquet"))
        );
    }

    #[test]
    fn shared_adapter_requires_generation_and_namespaces_equal_content() {
        let directory = tempfile::tempdir().unwrap();
        let tenant_a = uuid::Uuid::from_u128(1);
        let tenant_b = uuid::Uuid::from_u128(2);
        let cache_a = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant_a, "nano-tenant-a", 100, 1_000),
        )
        .unwrap();
        let cache_b = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant_b, "nano-tenant-b", 100, 1_000),
        )
        .unwrap();
        let manifest_a = shared_manifest(tenant_a, "nano-tenant-a");
        let manifest_b = shared_manifest(tenant_b, "nano-tenant-b");
        assert!(cache_a.cache_keys(&manifest_a, None).is_err());
        let generation = HotTailCacheGenerationBinding {
            runtime_generation: "runtime-1",
            schema_generation: "schema-1",
        };
        let key_a = cache_a.cache_keys(&manifest_a, Some(generation)).unwrap()[0].clone();
        let key_b = cache_b.cache_keys(&manifest_b, Some(generation)).unwrap()[0].clone();
        assert_ne!(key_a, key_b);
        assert_ne!(cache_a.object_path(&key_a), cache_b.object_path(&key_b));

        std::fs::write(cache_a.object_path(&key_a), b"poison").unwrap();
        assert!(!cache_b.object_path(&key_b).exists());

        let rotated = cache_a
            .cache_keys(
                &manifest_a,
                Some(HotTailCacheGenerationBinding {
                    runtime_generation: "runtime-2",
                    schema_generation: "schema-1",
                }),
            )
            .unwrap();
        assert_ne!(key_a, rotated[0]);
    }

    #[test]
    fn shared_adapter_reuses_exact_objects_across_tail_membership_revisions() {
        let directory = tempfile::tempdir().unwrap();
        let tenant = uuid::Uuid::from_u128(1);
        let cache = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant, "nano-tenant-a", 100, 1_000),
        )
        .unwrap();
        let generation = HotTailCacheGenerationBinding {
            runtime_generation: "runtime-1",
            schema_generation: "schema-1",
        };
        let manifest = shared_manifest(tenant, "nano-tenant-a");
        let key = cache.cache_keys(&manifest, Some(generation)).unwrap()[0].clone();

        let mut next_tail = manifest.clone();
        next_tail.tail_id = Some("d".repeat(64));
        assert_eq!(
            key,
            cache.cache_keys(&next_tail, Some(generation)).unwrap()[0]
        );

        let mut next_snapshot = next_tail;
        next_snapshot.base_snapshot_id += 1;
        next_snapshot.head_snapshot_id += 1;
        assert_ne!(
            key,
            cache.cache_keys(&next_snapshot, Some(generation)).unwrap()[0]
        );
    }

    #[test]
    fn shared_generation_handoff_reuses_verified_physical_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let tenant_a = uuid::Uuid::from_u128(1);
        let tenant_b = uuid::Uuid::from_u128(2);
        let cache_a = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant_a, "nano-tenant-a", 5, 10),
        )
        .unwrap();
        let cache_b = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant_b, "nano-tenant-b", 5, 10),
        )
        .unwrap();
        let first_key = "a".repeat(64);
        let next_key = "b".repeat(64);
        let digest = hex::encode(Sha256::digest(b"bytes"));
        let first = cache_a.object_path(&first_key);
        std::fs::write(&first, b"bytes").unwrap();
        cache_a.remember_verified_object(&first_key, &digest, FileStamp::read(&first).unwrap());

        assert!(cache_a
            .try_link_verified_shared_content(&next_key, &digest, 5)
            .unwrap());
        let next = cache_a.object_path(&next_key);
        assert_eq!(
            FileStamp::read(&first).unwrap().inode,
            FileStamp::read(&next).unwrap().inode
        );
        assert_eq!(physical_parquet_bytes(cache_a.root.as_path()).unwrap(), 5);
        assert!(!cache_b
            .try_link_verified_shared_content(&next_key, &digest, 5)
            .unwrap());
        assert!(!cache_b.object_path(&next_key).exists());
    }

    #[test]
    fn shared_eviction_is_tenant_local_and_cell_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let tenant_a = uuid::Uuid::from_u128(1);
        let tenant_b = uuid::Uuid::from_u128(2);
        let cache_a = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant_a, "nano-tenant-a", 10, 100),
        )
        .unwrap();
        let cache_b = HotTailCache::open_shared_namespace(
            directory.path(),
            shared_authority(tenant_b, "nano-tenant-b", 100, 100),
        )
        .unwrap();
        let key_a = "a".repeat(64);
        let key_b = "b".repeat(64);
        std::fs::write(cache_a.object_path(&key_a), vec![0_u8; 6]).unwrap();
        std::fs::write(cache_b.object_path(&key_b), vec![0_u8; 90]).unwrap();

        cache_a
            .evict_until_fits(5, &BTreeSet::new())
            .expect("tenant A may evict only its own unpinned bytes");
        assert!(!cache_a.object_path(&key_a).exists());
        assert!(cache_b.object_path(&key_b).exists());
        assert!(cache_a.evict_until_fits(11, &BTreeSet::new()).is_err());
        assert!(cache_b.object_path(&key_b).exists());
    }

    /// NAN-2651 fixture: `sizes[i]` bytes of distinct content, event time
    /// `[i*1000, i*1000+999]`, seeded into the cache so hydration never
    /// downloads. Signed (manifest) order is deliberately NOT time order.
    fn seeded_tail(cache: &HotTailCache, sizes: &[usize]) -> HotTailManifest {
        let mut tail = manifest("s3://bucket/table/data/unused.parquet".to_string());
        tail.objects.clear();
        for (index, size) in sizes.iter().enumerate() {
            let bytes = vec![b'a' + index as u8; *size];
            let digest = hex::encode(Sha256::digest(&bytes));
            std::fs::write(cache.object_path(&digest), &bytes).unwrap();
            tail.objects.push(HotTailObject {
                source_uri: format!("s3://bucket/table/data/{:02}.parquet", sizes.len() - index),
                min_time_ms: Some(index as i64 * 1_000),
                max_time_ms: Some(index as i64 * 1_000 + 999),
                ..object(&digest, *size as u64)
            });
        }
        tail
    }

    #[test]
    fn under_bound_tail_plans_full_coverage() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        let tail = seeded_tail(&cache, &[10, 10, 10, 10]);
        assert!(matches!(
            cache.plan_coverage(&tail, None).unwrap(),
            HotTailCoveragePlan::Full
        ));
    }

    #[test]
    fn over_bound_tail_plans_newest_first_prefix_with_explicit_uncovered_range() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        // 50 bytes against a 40-byte bound: the partial budget is 20 bytes.
        let tail = seeded_tail(&cache, &[10, 10, 10, 10, 10]);
        let HotTailCoveragePlan::Partial { manifest, coverage } =
            cache.plan_coverage(&tail, None).unwrap()
        else {
            panic!("an over-bound tail must degrade to a partial plan");
        };
        // The two newest objects (indices 3 and 4), still in signed order.
        assert_eq!(
            manifest
                .objects
                .iter()
                .map(|object| object.min_time_ms.unwrap())
                .collect::<Vec<_>>(),
            vec![3_000, 4_000]
        );
        assert_eq!(
            coverage,
            HotTailPartialCoverage {
                total_objects: 5,
                served_objects: 2,
                total_bytes: 50,
                served_bytes: 20,
                budget_bytes: 20,
                cache_max_bytes: 40,
                uncovered_from_ms: Some(0),
                uncovered_through_ms: Some(2_999),
                reason: None,
            }
        );
        // The completeness claim: every event after the uncovered range lies
        // in a served object.
        for object in &tail.objects {
            if object.max_time_ms.unwrap() > coverage.uncovered_through_ms.unwrap() {
                assert!(manifest
                    .objects
                    .iter()
                    .any(|served| served.source_uri == object.source_uri));
            }
        }
        // Signed identity fields are untouched; only membership shrinks.
        assert_eq!(manifest.tail_id, tail.tail_id);
        assert_eq!(manifest.base_snapshot_id, tail.base_snapshot_id);
    }

    #[test]
    fn partial_selection_is_a_strict_prefix_never_skipping_to_older_objects() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        // Newest 8 fits the 20-byte budget; the next (15) does not; the oldest
        // (2) would fit but must not be admitted past the gap.
        let tail = seeded_tail(&cache, &[2, 30, 15, 8]);
        let HotTailCoveragePlan::Partial { manifest, coverage } =
            cache.plan_coverage(&tail, None).unwrap()
        else {
            panic!("over bound");
        };
        assert_eq!(manifest.objects.len(), 1);
        assert_eq!(manifest.objects[0].min_time_ms, Some(3_000));
        assert_eq!(coverage.uncovered_from_ms, Some(0));
        assert_eq!(coverage.uncovered_through_ms, Some(2_999));
    }

    #[test]
    fn omitted_objects_without_time_bounds_make_the_range_unknown() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        let mut tail = seeded_tail(&cache, &[10, 10, 10, 10, 10]);
        tail.objects[0].min_time_ms = None;
        tail.objects[0].max_time_ms = None;
        let HotTailCoveragePlan::Partial { coverage, .. } =
            cache.plan_coverage(&tail, None).unwrap()
        else {
            panic!("over bound");
        };
        assert_eq!(coverage.uncovered_from_ms, None);
        assert_eq!(coverage.uncovered_through_ms, None);
    }

    #[test]
    fn newest_object_larger_than_the_partial_budget_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        let tail = seeded_tail(&cache, &[30, 30]);
        let error = cache.plan_coverage(&tail, None).unwrap_err().to_string();
        assert!(error.contains("partial budget"), "{error}");
    }

    #[tokio::test]
    async fn over_bound_tail_hydrates_its_partial_plan_instead_of_freezing() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        let tail = seeded_tail(&cache, &[10, 10, 10, 10, 10]);
        // The incident: the complete tail is refused outright.
        let refused = cache.hydrate(&tail).await.unwrap_err().to_string();
        assert!(refused.contains("above its 40 byte deployment bound"), "{refused}");
        let HotTailCoveragePlan::Partial { manifest, .. } =
            cache.plan_coverage(&tail, None).unwrap()
        else {
            panic!("over bound");
        };
        let lease = cache.hydrate(&manifest).await.unwrap();
        assert_eq!(lease.local_paths().len(), 2);
        assert_eq!(std::fs::read(&lease.local_paths()[0]).unwrap(), vec![b'd'; 10]);
        assert_eq!(std::fs::read(&lease.local_paths()[1]).unwrap(), vec![b'e'; 10]);
    }

    #[tokio::test]
    async fn served_full_tail_shrinks_to_the_partial_budget_without_downloads() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 40).unwrap();
        let tail = seeded_tail(&cache, &[10, 10, 10]);
        assert!(matches!(
            cache.plan_coverage(&tail, None).unwrap(),
            HotTailCoveragePlan::Full
        ));
        let HotTailCoveragePlan::Partial { manifest, coverage } =
            cache.plan_coverage_within_partial_budget(&tail, None).unwrap()
        else {
            panic!("30 bytes exceed the 20-byte partial budget");
        };
        assert_eq!(coverage.served_bytes, 20);
        assert_eq!(coverage.uncovered_through_ms, Some(999));
        // Every byte is already cached: the shrunk lease needs no object store.
        assert_eq!(cache.hydrate(&manifest).await.unwrap().local_paths().len(), 2);
    }

    #[test]
    fn pinned_pressure_is_a_typed_retryable_condition() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 4).unwrap();
        let pinned = cache.objects.join("pinned.parquet");
        std::fs::write(&pinned, b"four").unwrap();
        let lease = cache.pins.join("lease");
        std::fs::create_dir_all(&lease).unwrap();
        std::fs::hard_link(&pinned, lease.join("0000.parquet")).unwrap();
        let error = cache.evict_until_fits(1, &BTreeSet::new()).unwrap_err();
        assert!(cache_pinned_pressure(&error), "{error}");
        assert!(error.to_string().contains("already pinned"));
        assert!(!cache_pinned_pressure(&anyhow::anyhow!("other")));
    }
}

#[cfg(test)]
mod error_chain_tests {
    #[test]
    fn cache_admission_error_preserves_storage_cause() {
        let error = anyhow::anyhow!("S3 HEAD returned 403 Forbidden; request_id=fixture")
            .context("HEAD enterprise_shared R2 object before cache admission")
            .context("hot-tail cache admission failed");
        assert_eq!(
            crate::error_log::error_chain(&error),
            "hot-tail cache admission failed: HEAD enterprise_shared R2 object before cache admission: S3 HEAD returned 403 Forbidden; request_id=fixture"
        );
    }
}

#[cfg(test)]
mod concurrent_read_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn hydration_is_ordered_and_bounded_and_one_failure_fails_the_set() {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let values = hydrate_ordered((0..48).map(|index| {
            let active = &active;
            let peak = &peak;
            async move {
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(count, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(if index % 2 == 0 { 10 } else { 1 }))
                    .await;
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(index)
            }
        }))
        .await
        .unwrap();
        assert_eq!(values, (0..48).collect::<Vec<_>>());
        assert_eq!(peak.load(Ordering::SeqCst), HYDRATE_CONCURRENCY);
        let reserved = Cell::new(0);
        let failed = hydrate_ordered((0..48).map(|index| {
            let reserved = &reserved;
            async move {
                let _reservation = DownloadReservation::new(reserved, 4)?;
                if index == 7 {
                    bail!("injected object failure");
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
                Ok(index)
            }
        }))
        .await;
        assert!(failed.is_err());
        assert_eq!(
            reserved.get(),
            0,
            "cancelled downloads release reservations"
        );
    }

    #[tokio::test]
    async fn signed_etag_and_size_use_conditional_get_without_head() {
        use axum::{
            body::Body,
            http::{Request, Response, StatusCode},
            routing::any,
            Router,
        };
        let heads = Arc::new(AtomicUsize::new(0));
        let gets = Arc::new(AtomicUsize::new(0));
        let app = Router::new().fallback(any({
            let heads = heads.clone();
            let gets = gets.clone();
            move |request: Request<Body>| {
                let heads = heads.clone();
                let gets = gets.clone();
                async move {
                    if request.method() == "HEAD" {
                        heads.fetch_add(1, Ordering::SeqCst);
                        return Response::builder()
                            .status(StatusCode::METHOD_NOT_ALLOWED)
                            .body(Body::empty())
                            .unwrap();
                    }
                    gets.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(request.headers()["if-match"], "\"signed-etag\"");
                    assert_eq!(request.headers()["range"], "bytes=0-3");
                    Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .header("content-length", "4")
                        .header("content-range", "bytes 0-3/4")
                        .header("etag", "\"signed-etag\"")
                        .body(Body::from("good"))
                        .unwrap()
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let operator = Operator::new(
            S3::default()
                .bucket("bucket")
                .region("test")
                .endpoint(&endpoint)
                .access_key_id("test")
                .secret_access_key("test")
                .disable_config_load()
                .disable_ec2_metadata(),
        )
        .unwrap()
        .finish();
        let directory = tempfile::tempdir().unwrap();
        let mut object = HotTailObject {
            source_uri: "s3://bucket/object".to_string(),
            version_id: "compat".to_string(),
            etag: Some("\"signed-etag\"".to_string()),
            size_bytes: 4,
            rows: 1,
            sha256: Some(hex::encode(Sha256::digest(b"good"))),
            min_time_ms: Some(1),
            max_time_ms: Some(1),
            committed: true,
        };
        let downloaded =
            download_exact_object(&operator, "object", &object, directory.path(), true)
                .await
                .unwrap();
        assert_eq!(std::fs::read(downloaded.path()).unwrap(), b"good");
        object.sha256 = Some("a".repeat(64));
        assert!(
            download_exact_object(&operator, "object", &object, directory.path(), true)
                .await
                .is_err()
        );
        assert_eq!(heads.load(Ordering::SeqCst), 0);
        assert_eq!(gets.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[test]
    fn reservations_include_all_temporary_bytes_in_the_existing_limit() {
        let directory = tempfile::tempdir().unwrap();
        let cache = HotTailCache::open(directory.path(), 10).unwrap();
        let reserved = Cell::new(0);
        let first = DownloadReservation::new(&reserved, 6).unwrap();
        let second = DownloadReservation::new(&reserved, 5).unwrap();
        assert!(cache
            .evict_until_fits(reserved.get(), &BTreeSet::new())
            .is_err());
        drop(second);
        assert!(cache
            .evict_until_fits(reserved.get(), &BTreeSet::new())
            .is_ok());
        drop(first);
        assert_eq!(reserved.get(), 0);
    }
}
