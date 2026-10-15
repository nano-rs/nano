// SPDX-License-Identifier: AGPL-3.0-or-later

//! Object-storage tiering for per-object derivative artifacts.
//!
//! Local disk is a bounded cache over content-addressed, immutable artifacts
//! whose durable home is object storage — the same shape ClickHouse gives a
//! part whose skip indexes travel with it to S3. Three invariants:
//!
//! 1. **A cache miss never blocks a reader and never fails a query.** The
//!    planner emits a direct object-storage read for the missing artifact and
//!    hydration proceeds asynchronously in the background. Cold requests
//!    continue against S3 while hydration is in flight.
//! 2. **Admission is digest-fenced.** An artifact enters the local cache only
//!    after its bytes hash to the sha256 recorded in the derivative's
//!    digest-fenced manifest — the same fence a generation-local file must
//!    pass at load. A remote fetch that fails the fence is discarded, never
//!    served from disk, and never admitted.
//! 3. **Eviction cannot race an in-flight query.** A planner that resolves an
//!    artifact to its cached path takes a [`PinnedArtifact`] guard that lives
//!    inside the emitted plan; eviction skips any entry with a live pin, so
//!    the file cannot be unlinked between planning and engine open.
//!
//! Artifacts are addressed by content (`<kind>/<version>/sha256/<sha>.parquet`),
//! not by the stable-u32 object id: the id is a stable identity only within
//! one generation lineage and is not tamper-evident, while the sha256 is bound
//! to the id by the digest-fenced manifest and names immutable bytes globally.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Upper bound on concurrently hydrating artifacts; further misses stay
/// served directly from object storage until a slot frees.
const MAX_IN_FLIGHT_HYDRATIONS: usize = 4;
/// Hard bound on a single artifact admitted to the cache. Derivative parts
/// are per-object parquet files (measured p99 well under 64 MiB); anything
/// larger is a manifest fault, not a cacheable artifact.
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

/// Blocking byte fetch from the derivative tier's object-storage root.
/// Implementations run only on dedicated hydration threads, never on a
/// query path.
pub trait RemoteArtifactStore: Send + Sync + 'static {
    fn get(&self, key: &str) -> Result<Vec<u8>>;
}

/// Identity of one tierable artifact: the content address plus the fenced
/// expectations admission must verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRef {
    /// Remote key relative to the tier root, e.g.
    /// `count-rollup/nano-ocsf-5m-count-v5/sha256/<sha>.parquet`.
    pub key: String,
    /// Expected sha256 (lowercase hex) from the digest-fenced manifest.
    pub sha256: String,
    /// Expected byte length from the digest-fenced manifest.
    pub bytes: u64,
}

impl ArtifactRef {
    pub fn new(kind: &str, version: &str, sha256: &str, bytes: u64) -> Result<Self> {
        if kind.is_empty()
            || version.is_empty()
            || bytes == 0
            || bytes > MAX_ARTIFACT_BYTES
            || sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || ![kind, version]
                .iter()
                .all(|part| part.bytes().all(is_key_safe_byte))
        {
            bail!("derivative artifact reference violates its content-address contract");
        }
        Ok(Self {
            key: format!("{kind}/{version}/sha256/{sha256}.parquet"),
            sha256: sha256.to_string(),
            bytes,
        })
    }
}

fn is_key_safe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._".contains(&byte)
}

struct CacheEntry {
    bytes: u64,
    pins: usize,
}

#[derive(Default)]
struct TierState {
    entries: BTreeMap<String, CacheEntry>,
    lru: VecDeque<String>,
    bytes: u64,
    hydrating: BTreeSet<String>,
}

/// A live reference to a cached artifact. While any pin exists the entry
/// cannot be evicted and its file cannot be unlinked. Plans hold their pins
/// until the engine has finished reading.
pub struct PinnedArtifact {
    tier: Arc<DerivativeTier>,
    sha256: String,
    path: PathBuf,
}

impl PinnedArtifact {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for PinnedArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PinnedArtifact")
            .field("sha256", &self.sha256)
            .field("path", &self.path)
            .finish()
    }
}

impl Drop for PinnedArtifact {
    fn drop(&mut self) {
        let mut state = self.tier.state.lock().expect("derivative tier lock");
        if let Some(entry) = state.entries.get_mut(&self.sha256) {
            entry.pins = entry.pins.saturating_sub(1);
        }
    }
}

/// Bounded local cache over a remote derivative-artifact root.
pub struct DerivativeTier {
    /// Object-storage root the QUERY ENGINE reads on a miss, e.g.
    /// `http://lake-object-store:9000/nano-lake/derivatives/tenant-a`.
    /// Joined with an [`ArtifactRef::key`] it names the exact immutable
    /// object; the engine-side URL and the hydration key are the same address.
    remote_root: String,
    cache_directory: PathBuf,
    max_cache_bytes: u64,
    store: Arc<dyn RemoteArtifactStore>,
    state: Mutex<TierState>,
    /// Hydration outcomes, for observability and tests.
    admitted: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for DerivativeTier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DerivativeTier")
            .field("remote_root", &self.remote_root)
            .field("cache_directory", &self.cache_directory)
            .field("max_cache_bytes", &self.max_cache_bytes)
            .finish_non_exhaustive()
    }
}

impl DerivativeTier {
    pub fn new(
        remote_root: &str,
        cache_directory: &Path,
        max_cache_bytes: u64,
        store: Arc<dyn RemoteArtifactStore>,
    ) -> Result<Arc<Self>> {
        let remote_root = remote_root.trim_end_matches('/');
        if !(remote_root.starts_with("http://")
            || remote_root.starts_with("https://")
            || remote_root.starts_with("s3://"))
            || remote_root.len() > 2_048
            || remote_root
                .chars()
                .any(|character| character.is_control() || matches!(character, '{' | '}' | ','))
            || max_cache_bytes == 0
        {
            bail!("derivative tier root or cache bound is invalid");
        }
        std::fs::create_dir_all(cache_directory)
            .with_context(|| format!("create {}", cache_directory.display()))?;
        let tier = Arc::new(Self {
            remote_root: remote_root.to_string(),
            cache_directory: cache_directory.to_path_buf(),
            max_cache_bytes,
            store,
            state: Mutex::new(TierState::default()),
            admitted: std::sync::atomic::AtomicU64::new(0),
            rejected: std::sync::atomic::AtomicU64::new(0),
        });
        tier.recover_existing_entries()?;
        Ok(tier)
    }

    /// Re-admit artifacts that survived a restart. Each is re-verified
    /// against its own content address (the filename IS the digest), so a
    /// torn or tampered file is deleted instead of served.
    fn recover_existing_entries(self: &Arc<Self>) -> Result<()> {
        for entry in std::fs::read_dir(&self.cache_directory)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(sha256) = name.strip_suffix(".parquet") else {
                let _ = std::fs::remove_file(&path);
                continue;
            };
            let verified = std::fs::read(&path)
                .ok()
                .is_some_and(|bytes| hex::encode(Sha256::digest(&bytes)) == sha256);
            if !verified {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let bytes = std::fs::metadata(&path)?.len();
            let mut state = self.state.lock().expect("derivative tier lock");
            state.bytes = state.bytes.saturating_add(bytes);
            state.lru.push_back(sha256.to_string());
            state
                .entries
                .insert(sha256.to_string(), CacheEntry { bytes, pins: 0 });
        }
        self.evict_unpinned_over_budget();
        Ok(())
    }

    /// The engine-facing URL for a direct object-storage read of `artifact`.
    pub fn remote_url(&self, artifact: &ArtifactRef) -> String {
        format!("{}/{}", self.remote_root, artifact.key)
    }

    fn entry_path(&self, sha256: &str) -> PathBuf {
        self.cache_directory.join(format!("{sha256}.parquet"))
    }

    /// Resolve `artifact` to its cached local file, pinning it against
    /// eviction for the life of the returned guard. `None` is a cache miss.
    pub fn pin(self: &Arc<Self>, artifact: &ArtifactRef) -> Option<PinnedArtifact> {
        let mut state = self.state.lock().expect("derivative tier lock");
        let entry = state.entries.get_mut(&artifact.sha256)?;
        entry.pins += 1;
        if let Some(position) = state
            .lru
            .iter()
            .position(|candidate| candidate == &artifact.sha256)
        {
            state.lru.remove(position);
            state.lru.push_back(artifact.sha256.clone());
        }
        Some(PinnedArtifact {
            tier: self.clone(),
            sha256: artifact.sha256.clone(),
            path: self.entry_path(&artifact.sha256),
        })
    }

    /// Start asynchronous hydration of `artifact` unless it is cached, already
    /// hydrating, or the in-flight bound is reached. Never blocks the caller;
    /// the caller keeps reading from object storage in the meantime.
    pub fn begin_hydration(self: &Arc<Self>, artifact: ArtifactRef) {
        {
            let mut state = self.state.lock().expect("derivative tier lock");
            if state.entries.contains_key(&artifact.sha256)
                || state.hydrating.contains(&artifact.sha256)
                || state.hydrating.len() >= MAX_IN_FLIGHT_HYDRATIONS
            {
                return;
            }
            state.hydrating.insert(artifact.sha256.clone());
        }
        let tier = self.clone();
        let sha256 = artifact.sha256.clone();
        std::thread::Builder::new()
            .name("derivative-hydrate".to_string())
            .spawn(move || {
                let outcome = tier.hydrate_blocking(&artifact);
                let mut state = tier.state.lock().expect("derivative tier lock");
                state.hydrating.remove(&artifact.sha256);
                drop(state);
                if let Err(error) = outcome {
                    tier.rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(
                        key = artifact.key,
                        error = %error,
                        "derivative hydration was rejected; queries continue against object storage"
                    );
                }
            })
            .map(drop)
            .unwrap_or_else(|_| {
                let mut state = self.state.lock().expect("derivative tier lock");
                state.hydrating.remove(&sha256);
            });
    }

    /// Synchronous hydration used by the background thread (and tests): fetch,
    /// verify the digest fence, admit atomically, evict over-budget entries.
    pub fn hydrate_blocking(self: &Arc<Self>, artifact: &ArtifactRef) -> Result<()> {
        let data = self.store.get(&artifact.key)?;
        // The digest fence: identical standard to a generation-local part
        // (byte length plus sha256 against the digest-fenced manifest).
        if data.len() as u64 != artifact.bytes {
            bail!(
                "remote derivative artifact length {} differs from its fenced manifest length {}",
                data.len(),
                artifact.bytes
            );
        }
        let observed = hex::encode(Sha256::digest(&data));
        if observed != artifact.sha256 {
            bail!("remote derivative artifact failed its immutable digest fence");
        }
        let final_path = self.entry_path(&artifact.sha256);
        let mut temporary = tempfile::NamedTempFile::new_in(&self.cache_directory)
            .context("create derivative cache temporary")?;
        std::io::Write::write_all(&mut temporary, &data)
            .context("write derivative cache temporary")?;
        temporary
            .as_file()
            .sync_all()
            .context("sync derivative cache temporary")?;
        temporary
            .persist(&final_path)
            .context("admit derivative cache entry")?;
        let mut state = self.state.lock().expect("derivative tier lock");
        if state.entries.contains_key(&artifact.sha256) {
            return Ok(());
        }
        state.bytes = state.bytes.saturating_add(artifact.bytes);
        state.lru.push_back(artifact.sha256.clone());
        state.entries.insert(
            artifact.sha256.clone(),
            CacheEntry {
                bytes: artifact.bytes,
                pins: 0,
            },
        );
        drop(state);
        self.admitted
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.evict_unpinned_over_budget();
        Ok(())
    }

    /// Evict least-recently-used entries until the cache fits its budget.
    /// Entries with live pins are NEVER evicted — an in-flight plan resolved
    /// them to local paths and the engine may not have opened them yet.
    fn evict_unpinned_over_budget(self: &Arc<Self>) {
        let mut unlink = Vec::new();
        {
            let mut state = self.state.lock().expect("derivative tier lock");
            while state.bytes > self.max_cache_bytes {
                let Some(victim) = state
                    .lru
                    .iter()
                    .position(|sha256| {
                        state
                            .entries
                            .get(sha256)
                            .is_some_and(|entry| entry.pins == 0)
                    })
                    .and_then(|position| state.lru.remove(position))
                else {
                    // Everything left is pinned by in-flight queries; stay
                    // over budget rather than race a reader.
                    break;
                };
                if let Some(entry) = state.entries.remove(&victim) {
                    state.bytes = state.bytes.saturating_sub(entry.bytes);
                }
                unlink.push(self.entry_path(&victim));
            }
        }
        for path in unlink {
            let _ = std::fs::remove_file(path);
        }
    }

    pub fn cached_bytes(&self) -> u64 {
        self.state.lock().expect("derivative tier lock").bytes
    }

    pub fn admitted_count(&self) -> u64 {
        self.admitted.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// True while `artifact` is being hydrated in the background.
    pub fn is_hydrating(&self, artifact: &ArtifactRef) -> bool {
        self.state
            .lock()
            .expect("derivative tier lock")
            .hydrating
            .contains(&artifact.sha256)
    }
}

/// Production adapter over an opendal S3 operator. Runs only on hydration
/// threads, which own no async runtime, so a scoped blocking bridge is safe.
pub struct OpendalArtifactStore {
    operator: opendal::Operator,
    /// Key prefix inside the bucket (the tier root's path component). An
    /// [`ArtifactRef::key`] is relative to the tier root, while the operator
    /// is rooted at the bucket.
    prefix: String,
}

impl OpendalArtifactStore {
    pub fn new(operator: opendal::Operator) -> Self {
        Self::with_prefix(operator, "")
    }

    pub fn with_prefix(operator: opendal::Operator, prefix: &str) -> Self {
        Self {
            operator,
            prefix: prefix.trim_matches('/').to_string(),
        }
    }

    fn object_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{key}", self.prefix)
        }
    }
}

impl RemoteArtifactStore for OpendalArtifactStore {
    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let key = self.object_key(key);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build derivative hydration runtime")?;
        let buffer = runtime
            .block_on(self.operator.read(&key))
            .with_context(|| format!("fetch derivative artifact {key}"))?;
        Ok(buffer.to_vec())
    }
}

// ---------------------------------------------------------------------------
// Deployment wiring (NAN-2361)
// ---------------------------------------------------------------------------

/// Floor of the derived cache budget: below this the cache thrashes on a
/// single day of derivative output and hydration churn costs more than it
/// saves.
const MIN_CACHE_BUDGET_BYTES: u64 = 256 * 1024 * 1024;
/// Ceiling of the derived cache budget: the point of tiering is that local
/// derivative disk is O(cache-window), not O(retention).
const MAX_CACHE_BUDGET_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// Fallback budget when the deployment has no event snapshot cache to derive
/// from (documented default; see [`derive_cache_budget_bytes`]).
const DEFAULT_CACHE_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// Derive the derivative-cache budget instead of shipping a literal.
///
/// Precedence:
/// 1. An explicit operator override (`NANO_LAKE_DERIVATIVE_CACHE_BYTES`).
/// 2. A quarter of the deployment's event snapshot cache
///    (`snapshot_cache.max_bytes` in worker.json), clamped to
///    [256 MiB, 64 GiB]. The snapshot cache is already sized per deployment
///    from ingest and retention, and the tierable per-object derivatives are
///    a small fraction of the event bytes they summarize — measured on the
///    live NAN-2361 soak: the full count-rollup set is 270 MB against a
///    5.2 GB snapshot cache (~5%), so a 25% budget holds the complete hot
///    derivative working set with room for the entity/prevalence kinds that
///    follow count-rollup onto this tier.
/// 3. 1 GiB when the deployment has no snapshot cache configured.
pub fn derive_cache_budget_bytes(
    snapshot_cache_max_bytes: Option<u64>,
    override_bytes: Option<u64>,
) -> u64 {
    if let Some(bytes) = override_bytes {
        return bytes;
    }
    match snapshot_cache_max_bytes {
        Some(bytes) => (bytes / 4).clamp(MIN_CACHE_BUDGET_BYTES, MAX_CACHE_BUDGET_BYTES),
        None => DEFAULT_CACHE_BUDGET_BYTES,
    }
}

/// Deployment settings for the derivative tier, read from environment
/// variables so that a rolling deploy is safe in BOTH directions: an older
/// worker binary given these variables ignores them (unlike an unknown CLI
/// flag, which would refuse to start), and a newer binary without them runs
/// byte-for-byte today's untiered path.
///
/// - `NANO_LAKE_DERIVATIVE_TIER_STORE` — `s3://bucket/prefix` root the
///   uploader mirrors into and hydration reads from. Presence of this
///   variable (non-empty) is THE tiering switch.
/// - `NANO_LAKE_DERIVATIVE_CACHE_DIR` — local bounded cache directory.
///   Required together with the store.
/// - `NANO_LAKE_DERIVATIVE_TIER_URL` — engine-facing root for direct object
///   reads on a cache miss. Optional: derived from
///   `NANO_LAKE_RESULT_S3_ENDPOINT` (path-style `endpoint/bucket/prefix`) or,
///   absent an endpoint, AWS virtual-host form using
///   `NANO_LAKE_RESULT_S3_REGION`.
/// - `NANO_LAKE_DERIVATIVE_CACHE_BYTES` — optional budget override; the
///   default is derived (see [`derive_cache_budget_bytes`]).
///
/// Credentials for hydration reuse the existing `NANO_LAKE_RESULT_S3_*`
/// contract — the tier lives in the same object store as query results, so a
/// second credential surface would be pure drift.
#[derive(Clone, Debug)]
pub struct DerivativeTierSettings {
    pub store_root: String,
    pub cache_directory: PathBuf,
    pub engine_url: Option<String>,
    pub cache_bytes_override: Option<u64>,
}

impl DerivativeTierSettings {
    pub fn from_env() -> Result<Option<Self>> {
        let Some(store_root) = non_empty_env("NANO_LAKE_DERIVATIVE_TIER_STORE") else {
            return Ok(None);
        };
        let cache_directory = non_empty_env("NANO_LAKE_DERIVATIVE_CACHE_DIR").context(
            "NANO_LAKE_DERIVATIVE_CACHE_DIR is required when NANO_LAKE_DERIVATIVE_TIER_STORE is set",
        )?;
        let cache_bytes_override = non_empty_env("NANO_LAKE_DERIVATIVE_CACHE_BYTES")
            .map(|value| {
                value
                    .parse::<u64>()
                    .ok()
                    .filter(|bytes| *bytes > 0)
                    .context("NANO_LAKE_DERIVATIVE_CACHE_BYTES must be a positive byte count")
            })
            .transpose()?;
        Ok(Some(Self {
            store_root,
            cache_directory: PathBuf::from(cache_directory),
            engine_url: non_empty_env("NANO_LAKE_DERIVATIVE_TIER_URL"),
            cache_bytes_override,
        }))
    }

    /// Open the tier: hydration store from the `NANO_LAKE_RESULT_S3_*`
    /// credential contract, engine root explicit or derived, budget derived.
    pub fn open(&self, snapshot_cache_max_bytes: Option<u64>) -> Result<Arc<DerivativeTier>> {
        let (bucket, prefix) = crate::job::parse_s3_root(&self.store_root)
            .context("NANO_LAKE_DERIVATIVE_TIER_STORE is not a valid s3://bucket/prefix root")?;
        let operator = crate::job::result_s3_operator(bucket)
            .context("build derivative tier object-store operator")?;
        let store = Arc::new(OpendalArtifactStore::with_prefix(operator, prefix));
        let engine_root = match &self.engine_url {
            Some(url) => url.clone(),
            None => default_engine_root(bucket, prefix)?,
        };
        let budget = derive_cache_budget_bytes(snapshot_cache_max_bytes, self.cache_bytes_override);
        let tier = DerivativeTier::new(&engine_root, &self.cache_directory, budget, store)?;
        tracing::info!(
            store_root = %self.store_root,
            engine_root = %engine_root,
            cache_directory = %self.cache_directory.display(),
            cache_budget_bytes = budget,
            recovered_bytes = tier.cached_bytes(),
            "derivative tier is active; local disk serves as a bounded cache"
        );
        Ok(tier)
    }
}

/// Engine-facing default root for direct s3() reads, mirroring how the
/// result store is addressed: path-style against an explicit endpoint
/// (RustFS/MinIO), AWS virtual-host form otherwise.
fn default_engine_root(bucket: &str, prefix: &str) -> Result<String> {
    let joined = |base: &str| {
        if prefix.is_empty() {
            base.to_string()
        } else {
            format!("{base}/{prefix}")
        }
    };
    if let Some(endpoint) = non_empty_env("NANO_LAKE_RESULT_S3_ENDPOINT") {
        let endpoint = endpoint.trim_end_matches('/');
        return Ok(joined(&format!("{endpoint}/{bucket}")));
    }
    let region = non_empty_env("NANO_LAKE_RESULT_S3_REGION").context(
        "derivative tier engine URL requires NANO_LAKE_DERIVATIVE_TIER_URL, \
         NANO_LAKE_RESULT_S3_ENDPOINT, or NANO_LAKE_RESULT_S3_REGION",
    )?;
    Ok(joined(&format!(
        "https://{bucket}.s3.{region}.amazonaws.com"
    )))
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Open the tier's remote store for the UPLOAD side (the mirror binary).
/// Same address scheme, same credential contract as hydration.
pub fn open_upload_store(store_root: &str) -> Result<(opendal::Operator, String)> {
    crate::shared_mode::require_serialized_writer_authority("retained_generation")?;
    let (bucket, prefix) = crate::job::parse_s3_root(store_root)
        .context("derivative store root is not a valid s3://bucket/prefix root")?;
    let operator = crate::job::result_s3_operator(bucket)
        .context("build derivative mirror object-store operator")?;
    Ok((operator, prefix.to_string()))
}

// ---------------------------------------------------------------------------
// Upload side: mirror built derivative parts to their content addresses
// ---------------------------------------------------------------------------

/// Where the mirror writes. Content-addressed keys make every upload
/// idempotent: re-uploading an existing key rewrites identical bytes.
pub trait ArtifactSink {
    fn exists(&self, key: &str) -> Result<bool>;
    fn put(&self, key: &str, bytes: &[u8]) -> Result<()>;
}

/// Blocking opendal sink for the mirror process (which owns no async
/// runtime); one shared runtime, not one per call.
pub struct OpendalArtifactSink {
    operator: opendal::Operator,
    prefix: String,
    runtime: tokio::runtime::Runtime,
}

impl OpendalArtifactSink {
    pub fn new(operator: opendal::Operator, prefix: &str) -> Result<Self> {
        Ok(Self {
            operator,
            prefix: prefix.trim_matches('/').to_string(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build derivative mirror runtime")?,
        })
    }

    fn object_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}/{key}", self.prefix)
        }
    }
}

impl ArtifactSink for OpendalArtifactSink {
    fn exists(&self, key: &str) -> Result<bool> {
        let key = self.object_key(key);
        self.runtime
            .block_on(self.operator.exists(&key))
            .with_context(|| format!("probe derivative artifact {key}"))
    }

    fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
        crate::shared_mode::require_serialized_writer_authority("retained_generation")?;
        let key = self.object_key(key);
        self.runtime
            .block_on(self.operator.write(&key, bytes.to_vec()))
            .with_context(|| format!("upload derivative artifact {key}"))?;
        Ok(())
    }
}

/// Outcome of one mirror pass. `failed > 0` is NOT an error: a part that
/// failed to upload is simply "not tiered yet" and the next pass retries it.
#[derive(Debug, serde::Serialize)]
pub struct MirrorSummary {
    pub rollup_version: String,
    pub manifest_sha256: String,
    pub uploaded: usize,
    pub skipped: usize,
    pub failed: usize,
}

impl MirrorSummary {
    pub fn complete(&self) -> bool {
        self.failed == 0
    }
}

/// Mirror every count-rollup part named by the worker's ACTIVE generation to
/// its content address under the tier root.
///
/// Trust chain: the manifest bytes must hash to the sha recorded for them in
/// `worker.json` (which the generation activator wrote), and each part's
/// bytes must hash to the sha the manifest records before they are uploaded —
/// the mirror never puts bytes it has not verified against the fenced
/// address it is putting them AT.
///
/// Failure model: a broken trust chain or unreadable configuration is an
/// error (`Err`); an individual part that cannot be probed, read, verified,
/// or written is counted in `failed` and the pass continues. `Ok(None)`
/// means the generation carries no count rollup.
pub fn mirror_count_rollup(
    worker_config: &Path,
    expected_tenant_id: &str,
    sink: &dyn ArtifactSink,
) -> Result<Option<MirrorSummary>> {
    let configured = crate::config::WorkerConfigFile::read(worker_config)
        .with_context(|| format!("read {}", worker_config.display()))?;
    if configured.assigned_tenant_id != expected_tenant_id {
        bail!(
            "worker configuration is assigned to tenant {}, not {expected_tenant_id}",
            configured.assigned_tenant_id
        );
    }
    let Some(rollup) = configured.count_rollup else {
        return Ok(None);
    };
    let manifest_bytes = std::fs::read(&rollup.manifest.path)
        .with_context(|| format!("read {}", rollup.manifest.path.display()))?;
    let manifest_sha256 = hex::encode(Sha256::digest(&manifest_bytes));
    if manifest_sha256 != rollup.manifest.sha256 {
        bail!("count rollup manifest differs from the sha pinned in worker.json");
    }
    let manifest: crate::rollup::CountRollupManifest =
        serde_json::from_slice(&manifest_bytes).context("decode count rollup manifest")?;
    if manifest.tenant_id != expected_tenant_id {
        bail!("count rollup manifest names a different tenant");
    }
    let mut summary = MirrorSummary {
        rollup_version: manifest.rollup_version.clone(),
        manifest_sha256,
        uploaded: 0,
        skipped: 0,
        failed: 0,
    };
    for object in &manifest.objects {
        let outcome = mirror_one_part(
            &rollup.data_directory,
            &manifest.rollup_version,
            object,
            sink,
        );
        match outcome {
            Ok(true) => summary.uploaded += 1,
            Ok(false) => summary.skipped += 1,
            Err(error) => {
                summary.failed += 1;
                tracing::warn!(
                    part = object.relative_path,
                    error = format!("{error:#}"),
                    "count rollup part was not mirrored; it stays local-only until a later pass"
                );
            }
        }
    }
    Ok(Some(summary))
}

fn mirror_one_part(
    data_directory: &Path,
    rollup_version: &str,
    object: &crate::rollup::CountRollupObject,
    sink: &dyn ArtifactSink,
) -> Result<bool> {
    if object.relative_path.is_empty()
        || object.relative_path.contains('/')
        || object.relative_path.contains("..")
    {
        bail!("count rollup manifest names an invalid part path");
    }
    let artifact = ArtifactRef::new("count-rollup", rollup_version, &object.sha256, object.bytes)?;
    if sink.exists(&artifact.key)? {
        return Ok(false);
    }
    let path = data_directory.join(&object.relative_path);
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    // The digest fence, upload side: never put bytes at a content address
    // they do not hash to.
    if bytes.len() as u64 != object.bytes || hex::encode(Sha256::digest(&bytes)) != object.sha256 {
        bail!(
            "local count rollup part {} failed its manifest fence; refusing to mirror it",
            object.relative_path
        );
    }
    sink.put(&artifact.key, &bytes)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rollup::{
        CountRollupManifest, CountRollupManifestField, CountRollupObject, COUNT_ROLLUP_BUCKET_US,
        COUNT_ROLLUP_FIELDS, COUNT_ROLLUP_VERSION,
    };
    use std::sync::Mutex;

    // -- cache budget derivation --------------------------------------------

    #[test]
    fn cache_budget_is_derived_from_snapshot_cache_sizing_not_a_literal() {
        // Live-soak shape: 5.17 GB snapshot cache -> ~1.29 GB derivative cache.
        assert_eq!(
            derive_cache_budget_bytes(Some(5_174_850_373), None),
            5_174_850_373 / 4
        );
        // Clamped at both ends.
        assert_eq!(derive_cache_budget_bytes(Some(1), None), 256 * 1024 * 1024);
        assert_eq!(
            derive_cache_budget_bytes(Some(u64::MAX), None),
            64 * 1024 * 1024 * 1024
        );
        // No snapshot cache: documented 1 GiB default.
        assert_eq!(derive_cache_budget_bytes(None, None), 1024 * 1024 * 1024);
        // An explicit operator override always wins.
        assert_eq!(derive_cache_budget_bytes(Some(1 << 40), Some(42)), 42);
    }

    // -- mirror ---------------------------------------------------------------

    #[derive(Default)]
    struct MemorySink {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        fail_puts: bool,
        puts: std::sync::atomic::AtomicUsize,
    }

    impl ArtifactSink for MemorySink {
        fn exists(&self, key: &str) -> Result<bool> {
            Ok(self.objects.lock().unwrap().contains_key(key))
        }

        fn put(&self, key: &str, bytes: &[u8]) -> Result<()> {
            self.puts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.fail_puts {
                bail!("object store is unavailable");
            }
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_string(), bytes.to_vec());
            Ok(())
        }
    }

    struct MirrorFixture {
        _directory: tempfile::TempDir,
        worker_config: PathBuf,
        part_paths: Vec<PathBuf>,
        part_shas: Vec<String>,
    }

    /// A minimal worker.json + manifest + parts tree, shaped exactly like the
    /// activator writes it (manifest sha pinned in worker.json).
    fn mirror_fixture(parts: &[&[u8]]) -> MirrorFixture {
        let directory = tempfile::TempDir::new().unwrap();
        let data_directory = directory.path().join("count-rollup");
        std::fs::create_dir(&data_directory).unwrap();
        let sha = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let mut objects = Vec::new();
        let mut part_paths = Vec::new();
        let mut part_shas = Vec::new();
        for (id, bytes) in parts.iter().enumerate() {
            let relative_path = format!("object-{id:04}.parquet");
            let path = data_directory.join(&relative_path);
            std::fs::write(&path, bytes).unwrap();
            part_shas.push(sha(bytes));
            part_paths.push(path);
            objects.push(CountRollupObject {
                object_id: id as u32,
                event_object_key: format!("s3://bucket/table/data/{id}.parquet"),
                event_object_version: "v1".to_string(),
                event_object_bytes: 10,
                relative_path,
                min_bucket_start_us: 0,
                max_bucket_start_us: COUNT_ROLLUP_BUCKET_US,
                rows: 1,
                bytes: bytes.len() as u64,
                sha256: sha(bytes),
            });
        }
        let manifest = CountRollupManifest {
            schema_version: 1,
            rollup_version: COUNT_ROLLUP_VERSION.to_string(),
            tenant_id: "tenant-a".to_string(),
            event_snapshot_id: 7,
            object_stamp_sha256: sha(b"stamp"),
            bucket_width_us: COUNT_ROLLUP_BUCKET_US,
            fields: COUNT_ROLLUP_FIELDS
                .iter()
                .map(|field| CountRollupManifestField {
                    field_id: field.field_id,
                    source_path: field.source_path.to_string(),
                    multi_value: field.multi_value,
                })
                .collect(),
            objects,
            rows: parts.len() as u64,
            bytes: parts.iter().map(|bytes| bytes.len() as u64).sum(),
            build_seconds: 0.0,
            reused_objects: 0,
            built_objects: parts.len(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_path = data_directory.join("manifest.json");
        std::fs::write(&manifest_path, &manifest_bytes).unwrap();
        let artifact =
            |path: &Path, content: &[u8]| serde_json::json!({"path": path, "sha256": sha(content)});
        let dummy = directory.path().join("dummy");
        std::fs::write(&dummy, b"x").unwrap();
        let worker_config = directory.path().join("worker.json");
        std::fs::write(
            &worker_config,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "generation_id": "lake-test",
                "assigned_tenant_id": "tenant-a",
                "compiler": artifact(&dummy, b"x"),
                "native_library": artifact(&dummy, b"x"),
                "tenant": {
                    "tenant_id": "tenant-a",
                    "source": "s3://bucket/table",
                    "iceberg_metadata_file_path": "metadata/v1.json",
                    "source_manifest": artifact(&dummy, b"x"),
                    "max_query_bytes": 268435456,
                    "max_execution_seconds": 30,
                    "threads": 4,
                    "event_contract": "ocsf-1.9",
                    "allow_broad_npl": true
                },
                "entity_sidecar": {
                    "manifest": artifact(&dummy, b"x"),
                    "hmac_key": artifact(&dummy, b"x"),
                    "index_files": [artifact(&dummy, b"x")]
                },
                "keyword_sidecar": {
                    "manifest": artifact(&dummy, b"x"),
                    "index_directory": data_directory,
                    "index_tree_sha256": "0".repeat(64),
                    "fragment_manifest": artifact(&dummy, b"x"),
                    "fragment_index_directory": data_directory,
                    "fragment_index_tree_sha256": "0".repeat(64)
                },
                "count_rollup": {
                    "manifest": artifact(&manifest_path, &manifest_bytes),
                    "data_directory": data_directory,
                    "data_tree_sha256": "0".repeat(64)
                }
            }))
            .unwrap(),
        )
        .unwrap();
        MirrorFixture {
            worker_config,
            part_paths,
            part_shas,
            _directory: directory,
        }
    }

    #[test]
    fn mirror_uploads_every_part_once_and_skips_content_addresses_that_exist() {
        let fixture = mirror_fixture(&[b"part-zero", b"part-one"]);
        let sink = MemorySink::default();
        let first = mirror_count_rollup(&fixture.worker_config, "tenant-a", &sink)
            .unwrap()
            .unwrap();
        assert_eq!((first.uploaded, first.skipped, first.failed), (2, 0, 0));
        assert!(first.complete());
        for (index, sha) in fixture.part_shas.iter().enumerate() {
            let key = format!("count-rollup/{COUNT_ROLLUP_VERSION}/sha256/{sha}.parquet");
            assert_eq!(
                sink.objects.lock().unwrap().get(&key).map(Vec::as_slice),
                Some(
                    std::fs::read(&fixture.part_paths[index])
                        .unwrap()
                        .as_slice()
                ),
                "uploaded bytes must live at their content address"
            );
        }
        // Idempotence: a second pass re-uploads nothing.
        let second = mirror_count_rollup(&fixture.worker_config, "tenant-a", &sink)
            .unwrap()
            .unwrap();
        assert_eq!((second.uploaded, second.skipped, second.failed), (0, 2, 0));
        assert_eq!(sink.puts.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// The tiering contract's upload half: a failed upload means "not tiered
    /// yet", never a failed pass — the mirror reports it and carries on, and
    /// (structurally) it runs in its own process so it cannot fail a
    /// generation build at all.
    #[test]
    fn an_upload_failure_is_counted_not_propagated() {
        let fixture = mirror_fixture(&[b"part-zero", b"part-one"]);
        let sink = MemorySink {
            fail_puts: true,
            ..MemorySink::default()
        };
        let summary = mirror_count_rollup(&fixture.worker_config, "tenant-a", &sink)
            .expect("a pass with failed uploads is still an Ok pass")
            .unwrap();
        assert_eq!(
            (summary.uploaded, summary.skipped, summary.failed),
            (0, 0, 2)
        );
        assert!(!summary.complete());
    }

    #[test]
    fn a_tampered_local_part_is_never_uploaded() {
        let fixture = mirror_fixture(&[b"part-zero", b"part-one"]);
        std::fs::write(&fixture.part_paths[1], b"part-onE").unwrap();
        let sink = MemorySink::default();
        let summary = mirror_count_rollup(&fixture.worker_config, "tenant-a", &sink)
            .unwrap()
            .unwrap();
        assert_eq!(
            (summary.uploaded, summary.skipped, summary.failed),
            (1, 0, 1)
        );
        // Only the intact part reached the store; nothing lives at the
        // tampered part's content address.
        assert_eq!(sink.objects.lock().unwrap().len(), 1);
        let tampered_key = format!(
            "count-rollup/{COUNT_ROLLUP_VERSION}/sha256/{}.parquet",
            fixture.part_shas[1]
        );
        assert!(!sink.objects.lock().unwrap().contains_key(&tampered_key));
    }

    #[test]
    fn a_manifest_that_breaks_its_worker_json_pin_is_a_hard_error() {
        let fixture = mirror_fixture(&[b"part-zero"]);
        let manifest_path = fixture.part_paths[0]
            .parent()
            .unwrap()
            .join("manifest.json");
        let mut bytes = std::fs::read(&manifest_path).unwrap();
        bytes.push(b' ');
        std::fs::write(&manifest_path, bytes).unwrap();
        let sink = MemorySink::default();
        let error = mirror_count_rollup(&fixture.worker_config, "tenant-a", &sink).unwrap_err();
        assert!(error.to_string().contains("sha pinned in worker.json"));
        assert!(sink.objects.lock().unwrap().is_empty());
    }

    #[test]
    fn absent_tier_environment_disables_tiering_entirely() {
        // Deliberately does NOT set the variables (tests run in one process:
        // never SET env here, only assert on its absence in CI/dev shells).
        if std::env::var("NANO_LAKE_DERIVATIVE_TIER_STORE").is_ok() {
            return;
        }
        assert!(DerivativeTierSettings::from_env().unwrap().is_none());
    }
}
