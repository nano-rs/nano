// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pluggable schema abstraction (`SchemaProfile`) — OCSF Phase 1 (NAN-1244).
//!
//! Today the entire stack hard-codes "schema == the UDM constants": a build-time
//! `UdmField` enum plus six const arrays in `query::clickhouse_sql_gen`. This
//! module lifts that implicit single schema into an explicit [`SchemaProfile`]
//! trait that the SQL generator, field-stats, detection engine, and frontend
//! will (in later phases) consult by `Arc<dyn SchemaProfile>`.
//!
//! Phase 1 is a **pure addition**: it defines the trait and the [`UdmProfile`]
//! implementation, which *references* the existing canonical data for
//! byte-for-byte parity, but re-points no existing call site. See
//! `OCSF_SCHEMA_SUPPORT_SCOPING.md` §2.2.

mod boot_validation;
mod field_universe;
mod lake_prevalence;
mod metrics;
mod ocsf;
mod profile;
mod risk;
pub mod runtime_profile;
mod spans;
mod stored_enrichment;
mod types;
mod udm;

/// NAN-3451: the aligned `enrichments[]` arrays an open-core lake row's
/// prevalence stamp is read from (row-side: `prevalence::stamped`).
pub(crate) use lake_prevalence::STAMP_ARRAYS as LAKE_PREVALENCE_STAMP_ARRAYS;
pub use boot_validation::{validate_active_schema_table, SchemaValidationError};
pub use field_universe::{
    schema_fields_response, shared_tenant_lake_schema_fields, tenant_lake_schema_fields,
    SchemaFieldInfo, SchemaFieldsResponse,
};
pub(crate) use metrics::canonicalize_metric_field;
pub use metrics::MetricsProfile;
pub use ocsf::{OcsfProfile, OCSF_BOOKKEEPING_COLUMNS};
pub use profile::SchemaProfile;
pub use risk::RiskProfile;
pub use runtime_profile::{
    log_query_backend, log_query_backend_is_lake, runtime_profile_from_env, LogQueryBackend,
    RuntimeProfile,
};
pub(crate) use spans::canonicalize_span_field;
pub use spans::SpansProfile;
pub mod tenant_lake_schema;
pub mod worker_schema;

pub use types::{
    EnrichmentKind, EnrichmentMode, EntityRole, EntityType, EnumIntMapping, FieldCategory,
    FieldDef, FieldResolution, FieldType, SchemaId,
};
pub use udm::UdmProfile;

use std::collections::BTreeMap;
use std::sync::Arc;

/// The environment variable that selects the active schema profile at boot
/// (scoping §2.4). Unset or `ocsf`; resolved only by [`runtime_profile`].
pub const SCHEMA_PROFILE_ENV: &str = "NANO_SCHEMA_PROFILE";
pub const LOG_QUERY_BACKEND_ENV: &str = "NANO_LOG_QUERY_BACKEND";
/// Local, coordinator-published immutable event manifest used for schema
/// discovery by Rust product services. Query authorization remains enforced by
/// the tenant-pinned worker and its independently verified manifest.
pub const LAKE_SCHEMA_MANIFEST_ENV: &str = "NANO_LAKE_SCHEMA_MANIFEST";
/// Stable coordinator-owned worker configuration. Unlike a generation's
/// immutable schema manifest path, this path does not change when a new
/// snapshot is promoted; the config atomically points at the active manifest.
pub const LAKE_WORKER_CONFIG_ENV: &str = "NANO_LAKE_WORKER_CONFIG";

fn snapshot_field_types_from_manifest(raw: &str) -> Result<BTreeMap<String, FieldType>, String> {
    let manifest: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| format!("invalid lake schema manifest JSON: {error}"))?;
    let objects = manifest
        .get("objects")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "lake schema manifest must contain an objects array".to_string())?;
    let mut merged = BTreeMap::new();
    for object in objects {
        let field_types = object
            .get("field_types")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| "lake schema manifest object lacks field_types".to_string())?;
        for (name, raw_type) in field_types {
            let field_type: FieldType =
                serde_json::from_value(raw_type.clone()).map_err(|error| {
                    format!("lake schema manifest has invalid type for {name}: {error}")
                })?;
            if let Some(prior) = merged.insert(name.clone(), field_type) {
                if prior != field_type {
                    return Err(format!(
                        "lake schema manifest has conflicting types for {name}"
                    ));
                }
            }
        }
    }
    Ok(merged)
}

/// Resolve which manifest file the active generation is, without reading its
/// body. Split out of the profile build so the (cheap) path resolution and its
/// fail-closed cross-checks run on every call while the (expensive) parse can be
/// memoized on the resolved path plus its content digest.
/// Resolve the manifest path AND the second candidate that must agree with it.
///
/// The worker config is resolved even when an explicit manifest is set, so a
/// contradictory pair cannot pass silently: a deployment that set both resolved
/// OCSF fields from one generation while its assigned worker served another --
/// observed live as a 387-field inventory against a worker serving 223 different
/// fields, which makes every schema-dependent validation meaningless.
///
/// The agreement check itself is NOT run here. It hashes both manifests (12 MB
/// each on this corpus), and this function is on the per-call path that
/// `lake_ocsf_profile_from_snapshot_env` memoizes precisely to avoid that cost.
/// The caller runs it once per genuine (re)build instead -- which is when the
/// bytes are read anyway, and the only moment a contradiction can newly matter.
fn resolve_lake_schema_manifest_candidates() -> Result<(String, Option<String>), String> {
    let explicit = std::env::var(LAKE_SCHEMA_MANIFEST_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty());
    let active = active_schema_manifest_from_worker_config()?;
    let contender = match (explicit.as_deref(), active.as_deref()) {
        (Some(_), Some(active)) => Some(active.to_string()),
        _ => None,
    };
    require_lake_schema_manifest_path(explicit, active).map(|path| (path, contender))
}

/// Fail closed when both schema inputs are configured but describe different
/// generations.
///
/// Compared by content digest, not path: the same generation is legitimately
/// reachable under two paths (a coordinator-published copy and the worker
/// config's own pointer), and that case must keep working. Different BYTES mean
/// one of the two is not the generation the assigned worker is serving, and there
/// is no safe way to choose between them.
///
/// The chosen manifest's digest is already computed by the caller, so only the
/// contender is read here -- this runs once per genuine profile (re)build, never
/// on the memoized fast path.
fn require_agreeing_bytes(
    chosen_path: &str,
    chosen_digest: &str,
    contender_path: &str,
) -> Result<(), String> {
    if chosen_path == contender_path {
        return Ok(());
    }
    let contender_digest = manifest_digest(contender_path)?;
    if contender_digest == chosen_digest {
        return Ok(());
    }
    Err(format!(
        "{LAKE_SCHEMA_MANIFEST_ENV}={chosen_path:?} (sha256 {}) and the active manifest from \
         {LAKE_WORKER_CONFIG_ENV}={contender_path:?} (sha256 {}) are different generations; unset \
         one or refresh the stale copy",
        &chosen_digest[..16],
        &contender_digest[..16],
    ))
}

fn manifest_digest(path: &str) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|error| format!("failed to read lake schema manifest {path:?}: {error}"))?;
    Ok(manifest_digest_of(&bytes))
}

/// The single hashing path for manifest identity. `manifest_digest` reads a path
/// and delegates here; the profile cache hashes bytes it has already read, so a
/// cache probe costs one read of the manifest instead of two.
fn manifest_digest_of(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn require_lake_schema_manifest_path(
    explicit: Option<String>,
    active: Option<String>,
) -> Result<String, String> {
    explicit.or(active).ok_or_else(|| {
        format!(
            "canonical lake OCSF requires either {LAKE_SCHEMA_MANIFEST_ENV} or {LAKE_WORKER_CONFIG_ENV}"
        )
    })
}

fn active_schema_manifest_from_worker_config() -> Result<Option<String>, String> {
    let Some(config_path) = std::env::var(LAKE_WORKER_CONFIG_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
    else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&config_path).map_err(|error| {
        format!("failed to read {LAKE_WORKER_CONFIG_ENV}={config_path:?}: {error}")
    })?;
    schema_manifest_path_from_worker_config(&raw)
        .map(Some)
        .map_err(|error| format!("invalid {LAKE_WORKER_CONFIG_ENV}={config_path:?}: {error}"))
}

/// The coordinator-published worker assignment, parsed.
///
/// The coordinator already publishes every generation-scoped identity a product
/// service needs (source manifest, prevalence/identity/IOC/risk snapshots, count
/// rollup, sidecars) and rewrites this file atomically on promotion. Services
/// should DERIVE those from here rather than receive a hand-maintained copy in
/// their environment: an env value is written once at exec, cannot be re-read
/// after a promotion, and silently disables a feature when it goes missing.
pub fn active_worker_config() -> Result<Option<serde_json::Value>, String> {
    let Some(config_path) = std::env::var(LAKE_WORKER_CONFIG_ENV)
        .ok()
        .filter(|path| !path.trim().is_empty())
    else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&config_path).map_err(|error| {
        format!("failed to read {LAKE_WORKER_CONFIG_ENV}={config_path:?}: {error}")
    })?;
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|error| format!("invalid {LAKE_WORKER_CONFIG_ENV}={config_path:?}: {error}"))
}

fn schema_manifest_path_from_worker_config(raw: &str) -> Result<String, String> {
    let config: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| format!("worker config is not valid JSON: {error}"))?;
    config
        .pointer("/tenant/source_manifest/path")
        .and_then(serde_json::Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| "worker config has no active tenant source manifest".to_string())
}

/// How many built lake profiles stay resident. Keyed by content digest, the map
/// would otherwise gain an entry per promoted generation and never lose one —
/// a slow leak of a multi-MB field inventory in a process that lives for weeks.
/// A handful is enough: promotions are rare, and only the generation the worker
/// config points at is asked for once a promotion settles. The extra slots exist
/// so in-flight requests holding the previous generation still hit the cache
/// while a promotion rolls through.
const LAKE_PROFILE_CACHE_CAPACITY: usize = 4;

/// Most-recently-built first; short enough that a linear scan beats hashing.
type LakeProfileCache = std::sync::RwLock<Vec<LakeProfileEntry>>;
/// (resolved manifest path, sha256 of its bytes). The digest is what makes this
/// safe: a promoted generation written to the SAME path has different bytes and
/// therefore misses, so no caller is ever served a stale field inventory. The
/// path is part of the key because two generations can legitimately be resident
/// at once (and because the crate's own tests swap manifests via env vars).
type LakeProfileKey = (String, String);
/// (byte length, mtime) of the file that was hashed into an entry's digest.
type ManifestStamp = (u64, std::time::SystemTime);

struct LakeProfileEntry {
    key: LakeProfileKey,
    /// Cheap identity check so the hot path can skip re-reading and re-hashing
    /// 12 MB on every call: `stat` alone decides the common case. The digest
    /// stays the key of record — a file whose length or mtime differs from the
    /// stamp is read and hashed again before anything is served.
    stamp: ManifestStamp,
    profile: Arc<dyn SchemaProfile>,
}

static LAKE_PROFILE_CACHE: std::sync::OnceLock<LakeProfileCache> = std::sync::OnceLock::new();

/// Successful expensive builds, for tests and for answering "is this actually
/// memoized in production?" without attaching a profiler.
static LAKE_PROFILE_BUILDS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn lake_profile_cache() -> &'static LakeProfileCache {
    LAKE_PROFILE_CACHE.get_or_init(LakeProfileCache::default)
}

/// Number of times the lake profile was actually parsed and built in this
/// process. Repeated calls with unchanged manifest bytes must not advance it.
pub fn lake_profile_build_count() -> usize {
    LAKE_PROFILE_BUILDS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Hot path: the file on disk is byte-for-byte the one we already hashed, as far
/// as `stat` can tell. Only a manifest whose length AND mtime are unchanged
/// qualifies; a promotion writes new bytes and necessarily moves the mtime.
fn cached_lake_profile_by_stamp(
    path: &str,
    stamp: ManifestStamp,
) -> Option<Arc<dyn SchemaProfile>> {
    let cache = lake_profile_cache().read().unwrap_or_else(std::sync::PoisonError::into_inner);
    cache
        .iter()
        .find(|entry| entry.key.0 == path && entry.stamp == stamp)
        .map(|entry| Arc::clone(&entry.profile))
}

fn manifest_stamp(path: &str) -> Option<ManifestStamp> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()?))
}

/// Build the canonical lake profile plus the immutable snapshot's physical
/// field inventory. API-owned services use this after `ApiConfig` has already
/// resolved the backend, while the Search process reaches it through
/// [`active_profile_from_env`]. Keeping one constructor prevents the two
/// processes from drifting when a later OCSF minor release adds fields.
///
/// Memoized on (resolved manifest path, content digest) because the build reads
/// and serde-parses the generation's ~12 MB OCSF source manifest — measured
/// 333-394 ms per call in a debug build — and ~20 core call sites on request and
/// detection paths reach it per request/batch, not once at boot. A `stat`
/// fingerprint (length + mtime) short-circuits the read and hash in the steady
/// state; whenever it does not match, the content digest decides.
///
/// Only successes are cached: every failure re-runs the full fail-closed
/// resolution, so a missing, unreadable, non-UTF-8 or invalid manifest can never
/// be latched as a success or as a silently empty field inventory.
/// A schema installed from the query worker's `/v1/schema/manifest`, which
/// takes precedence over any manifest file.
///
/// An external `nanosiem-search` -- a host process in local development, a
/// separate pod in a split deployment -- cannot read the generation volume, so
/// historically its schema had to be COPIED out of the volume. Nothing published
/// a fresh copy when generations rotated, so a copy taken at setup froze, and
/// every field promoted afterwards read as "Unknown canonical OCSF field" no
/// matter what the lake actually held. That failure is silent and points at the
/// query rather than at the schema, which is what makes it expensive.
///
/// The worker is the authority for what the active generation exposes, so the
/// schema is fetched from it instead. Stored as (digest, profile) so a refresh
/// that returns the same field set costs nothing.
static INSTALLED_LAKE_SCHEMA: std::sync::OnceLock<
    std::sync::RwLock<Option<(String, Arc<dyn SchemaProfile>)>>,
> = std::sync::OnceLock::new();

fn installed_lake_schema() -> &'static std::sync::RwLock<Option<(String, Arc<dyn SchemaProfile>)>> {
    INSTALLED_LAKE_SCHEMA.get_or_init(|| std::sync::RwLock::new(None))
}

/// Install the field inventory served by the worker.
///
/// Returns `true` when the schema actually changed. `digest` is the worker's
/// content digest over the field map, so an unchanged field set short-circuits
/// before the profile is rebuilt -- generations rotate far more often than the
/// field set changes.
pub fn install_lake_schema_field_types(
    digest: &str,
    field_types: BTreeMap<String, FieldType>,
) -> Result<bool, String> {
    // NAN-2718: a shared process serves many tenants, so a process-global
    // inventory is by construction some ONE tenant's fields shown to all of
    // them. Shared processes resolve schemas per tenant
    // (`tenant_lake_schema`) and must never install a global one.
    if tenant_lake_schema::shared_tenancy_process() {
        return Err(
            "refusing to install a process-global lake schema in enterprise_shared mode; \
             schemas are resolved per tenant"
                .to_string(),
        );
    }
    if field_types.is_empty() {
        // Fail closed: an empty inventory would make every field unknown, which
        // is indistinguishable from a working schema that happens to reject the
        // query in front of it.
        return Err("worker served an empty lake field inventory".to_string());
    }
    {
        let current = installed_lake_schema()
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if current.as_ref().is_some_and(|(have, _)| have == digest) {
            return Ok(false);
        }
    }
    let profile: Arc<dyn SchemaProfile> = Arc::new(
        OcsfProfile::try_lake_1_9_with_snapshot_field_types(field_types)?,
    );
    let mut slot = installed_lake_schema()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some((digest.to_string(), profile));
    LAKE_PROFILE_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(true)
}

/// The profile last installed from the worker-served schema, if any.
///
/// NAN-3492: a dedicated process builds its long-lived services from the
/// profile it resolves at boot. [`install_lake_schema_field_types`] swaps this
/// slot when the worker's field set changes, so those services compare their
/// pinned profile against it (`Arc::ptr_eq`) and re-pin when it moved.
/// Otherwise every field first stored after boot (a new log source, the lean
/// `prevalence_*` stamp columns) reads as "Unknown canonical OCSF field" until
/// a restart.
pub fn installed_lake_profile() -> Option<Arc<dyn SchemaProfile>> {
    installed_lake_schema()
        .read()
        .ok()?
        .as_ref()
        .map(|(_, profile)| Arc::clone(profile))
}

/// Marker `lake_worker_config_bootstrap` writes into the seed worker config,
/// before any generation has been promoted. It is a documented protocol value,
/// not an inference — see `nanosiem-lake-worker/src/config.rs`: "During that
/// window `bootstrap-pending` is a protocol marker: generation activation uses
/// it to install the first complete configuration without waiting for a query
/// worker that cannot start from the placeholder manifest."
const LAKE_BOOTSTRAP_PENDING_GENERATION: &str = "bootstrap-pending";

/// True only for the seed configuration written before generation 1 exists.
///
/// NAN-2361: a fresh lake install is otherwise circular. The API refuses to boot
/// without a source manifest; the manifest is written by generation promotion;
/// promotion needs the Iceberg events table; the table is created from the first
/// published batch — which needs the Bronze sink the API itself deploys. Nothing
/// broke that loop, so no fresh lake install could ever complete.
///
/// The seed config names this state explicitly, so the one window where an empty
/// field inventory is CORRECT can be recognised precisely, rather than inferred
/// from a missing file. A missing or unreadable manifest at any other time stays
/// a hard failure: that is a real fault (wrong mount, wrong path, torn write) and
/// serving an empty inventory would silently answer every query with nothing.
fn worker_config_is_bootstrap_seed() -> bool {
    // An explicit operator-supplied manifest always wins; if one is configured,
    // this is not the untouched seed state and the normal path must run.
    if std::env::var(LAKE_SCHEMA_MANIFEST_ENV)
        .ok()
        .is_some_and(|path| !path.trim().is_empty())
    {
        return false;
    }
    // A config that cannot be read or parsed is a fault, not a seed.
    matches!(
        active_worker_config(),
        Ok(Some(ref config))
            if config
                .get("generation_id")
                .and_then(serde_json::Value::as_str)
                == Some(LAKE_BOOTSTRAP_PENDING_GENERATION)
    )
}

pub fn lake_ocsf_profile_from_snapshot_env() -> Result<Arc<dyn SchemaProfile>, String> {
    // NAN-2718: in a shared process the process-wide profile is the canonical
    // OCSF 1.9 contract with NO snapshot inventory. Any installed schema,
    // manifest file or worker config would be one tenant's field set served
    // to every tenant. Tenant surfaces use
    // `tenant_lake_schema::profile_for_tenant`.
    if tenant_lake_schema::shared_tenancy_process() {
        return Ok(tenant_lake_schema::canonical_shared_lake_profile());
    }
    // The worker-served schema wins: it is the active generation's own answer,
    // and it cannot silently lag the way a copied manifest does.
    if let Some(profile) = installed_lake_profile() {
        return Ok(profile);
    }
    // Pre-first-generation: serve the canonical OCSF 1.9 writer contract with an
    // empty snapshot inventory. Deliberately NOT cached — there are no manifest
    // bytes to key on, and the underlying field universe is a `OnceLock` static,
    // so rebuilding is cheap. The moment generation 1 activates, the worker
    // config points at a real manifest and every caller re-resolves to it
    // without a restart (see `SharedSchemaProfile`'s refresh loop).
    if worker_config_is_bootstrap_seed() {
        return Ok(Arc::new(
            OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::new())?,
        ));
    }
    let (path, contender) = resolve_lake_schema_manifest_candidates()?;
    // `stat` first. Re-reading and re-hashing 12 MB per call still cost ~84 ms
    // in a debug build, which ~20 call sites per request cannot absorb; an
    // unchanged (len, mtime) means we already hold the profile for these bytes.
    let stamp = manifest_stamp(&path);
    if let Some(stamp) = stamp {
        if let Some(profile) = cached_lake_profile_by_stamp(&path, stamp) {
            return Ok(profile);
        }
    }
    // The stamp moved (or could not be read): the bytes are the authority again.
    // They are both the identity of the generation and the parse input, so this
    // path costs one read plus a hash rather than a 12 MB serde parse, and a
    // promoted generation is detected by its content rather than by its path.
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("failed to read {LAKE_SCHEMA_MANIFEST_ENV}={path:?}: {error}"))?;
    // Stamp what we actually read, so a manifest replaced between the `stat` and
    // the read is fingerprinted by the state the digest describes, not a newer one.
    let stamp = manifest_stamp(&path).or(stamp);
    let key: LakeProfileKey = (path.clone(), manifest_digest_of(&bytes));
    if let Some(profile) = refresh_cached_lake_profile(&key, stamp) {
        return Ok(profile);
    }
    // A genuine (re)build is the only moment a contradictory pair can newly
    // matter, and the chosen manifest's bytes are already in hand, so the second
    // candidate is the only file that still needs hashing.
    if let Some(contender) = contender.as_deref() {
        require_agreeing_bytes(&path, key.1.as_str(), contender)?;
    }
    let raw = String::from_utf8(bytes)
        .map_err(|error| format!("failed to read {LAKE_SCHEMA_MANIFEST_ENV}={path:?}: {error}"))?;
    let field_types = snapshot_field_types_from_manifest(&raw)?;
    let profile: Arc<dyn SchemaProfile> = Arc::new(
        OcsfProfile::try_lake_1_9_with_snapshot_field_types(field_types)?,
    );
    LAKE_PROFILE_BUILDS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // The parse happened outside every lock; the write lock is held only for the
    // vector splice. Double-check under it so a concurrent builder's entry wins
    // and all callers converge on one Arc instead of two equivalent copies.
    // No stamp (the file vanished under us) means no entry: the caller gets this
    // profile, and the next call rebuilds rather than memoizing bytes we cannot
    // recognize again.
    if let (Ok(mut cache), Some(stamp)) = (lake_profile_cache().write(), stamp) {
        if let Some(existing) = cache.iter().find(|entry| entry.key == key) {
            return Ok(Arc::clone(&existing.profile));
        }
        cache.insert(
            0,
            LakeProfileEntry {
                key,
                stamp,
                profile: Arc::clone(&profile),
            },
        );
        cache.truncate(LAKE_PROFILE_CACHE_CAPACITY);
    }
    Ok(profile)
}

/// Digest hit: the bytes match an entry we built earlier even though `stat` said
/// otherwise (a rewritten-identical manifest, or a fresh copy of the same
/// generation). Re-stamp the entry so subsequent calls take the `stat`-only path.
fn refresh_cached_lake_profile(
    key: &LakeProfileKey,
    stamp: Option<ManifestStamp>,
) -> Option<Arc<dyn SchemaProfile>> {
    let mut cache = lake_profile_cache().write().unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = cache.iter_mut().find(|entry| &entry.key == key)?;
    if let Some(stamp) = stamp {
        entry.stamp = stamp;
    }
    Some(Arc::clone(&entry.profile))
}

/// Construct the boxed [`SchemaProfile`] for a [`SchemaId`].
///
/// The single place that maps the selected schema id to its concrete profile
/// implementation, so callers (app boot) never name `UdmProfile`/`OcsfProfile`
/// directly and stay decoupled from the profile set.
pub fn profile_for_id(id: SchemaId) -> Arc<dyn SchemaProfile> {
    match id {
        SchemaId::Udm => Arc::new(UdmProfile::new()),
        SchemaId::Ocsf => Arc::new(OcsfProfile::new()),
        // NAN-1555: per-QUERY dataset profiles, injected by the SQL generator's
        // `with_dataset(...)` — never selected as a tenant log schema.
        SchemaId::Spans => Arc::new(SpansProfile::new()),
        SchemaId::Metrics => Arc::new(MetricsProfile::new()),
        // NAN-1798 P2: the derived accumulated-risk dataset, likewise per-query.
        SchemaId::Risk => Arc::new(RiskProfile::new()),
    }
}

/// Resolve the active tenant log profile from the environment.
///
/// NAN-3491: the runtime profile is resolved by [`runtime_profile`] — unset or
/// `ocsf`/`lake` select canonical OCSF on the object lake, and a legacy value
/// (`udm`, `clickhouse`, `shadow`) is an error rather than a silent fallback.
/// The object-lake product contract is canonical OCSF 1.9, built from the
/// coordinator-published snapshot manifest, so Search, scheduled detections,
/// field validation, and every product service share the exact same
/// field/time/source semantics.
///
/// This reads the process environment and is intended to be called **once** at
/// app boot (in `nanosiem-api` config/state); the resolved `Arc` is then stored
/// and threaded down to the search path. Core code must not scatter env reads.
pub fn active_profile_from_env() -> Result<Arc<dyn SchemaProfile>, String> {
    runtime_profile_from_env()?;
    lake_ocsf_profile_from_snapshot_env()
}

/// The active *ingested-events* table name for the env-configured schema profile.
/// Returns `"ocsf_logs"` under OCSF, `"logs"` under UDM (and on any resolution
/// error, so a malformed env never breaks an admin query). For the handful of
/// direct ClickHouse reads of ingested events that live OUTSIDE the SearchService
/// seam — feed health, retention stats, rule coverage — which have no profile
/// threaded. UDM byte-identical (returns `"logs"`, exactly as before). NAN-1241.
pub fn active_logs_table() -> &'static str {
    active_profile_from_env()
        .map(|p| logs_table_for(p.id()))
        .unwrap_or("logs")
}

/// Stable discriminator written into the profile-aware per-source telemetry
/// rollup. The rollup deliberately stores both UDM and OCSF lanes because an
/// OCSF Vector deployment writes both raw tables during the transition; every
/// reader must select exactly the active lane or those events are counted
/// twice.
pub fn log_telemetry_profile_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf",
        // Spans, metrics, and risk are per-query datasets rather than tenant log
        // schemas. Keep this mapping total and aligned with `logs_table_for`.
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => "udm",
    }
}

/// Env-resolving wrapper for [`log_telemetry_profile_for`].
pub fn active_log_telemetry_profile() -> &'static str {
    active_profile_from_env()
        .map(|p| log_telemetry_profile_for(p.id()))
        .unwrap_or("udm")
}

/// The ingested-events table name for a given schema id. Pure (env-free) so it
/// is unit-testable; `active_logs_table` is the env-resolving wrapper. NAN-1241.
/// This is the READ table — search/detection/maintenance all target it.
pub fn logs_table_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf_logs",
        SchemaId::Udm => "logs",
        // NAN-1555: spans/metrics are per-query datasets, never the tenant log
        // table; these arms are unreachable in practice (no
        // `NANO_SCHEMA_PROFILE=spans|metrics`) but keep the dispatch total.
        SchemaId::Spans => "otel_spans",
        SchemaId::Metrics => "otel_metrics",
        // NAN-1798 P2: the risk dataset is DERIVED from the findings stream in
        // the logs table; unreachable as a tenant schema, kept for totality.
        SchemaId::Risk => "logs",
    }
}

/// The table OCSF/UDM events are INSERTED into — distinct from the read table
/// under OCSF. NAN-1443: OCSF writes land in `ocsf_logs_raw` (ENGINE = Null);
/// the `ocsf_logs_raw_mv` materialized view derives the stored row into
/// `ocsf_logs` (so the full `event` blob is never stored). UDM has no such
/// split — writes and reads are both `logs` (byte-identical).
pub fn ingest_table_for(id: SchemaId) -> &'static str {
    match id {
        SchemaId::Ocsf => "ocsf_logs_raw",
        SchemaId::Udm => "logs",
        // NAN-1555: unreachable as a tenant schema; spans/metrics ingest via their
        // own `otel_*_raw` Null+MV lanes (migrations 138/140), kept for totality.
        SchemaId::Spans => "otel_spans_raw",
        SchemaId::Metrics => "otel_metrics_raw",
        // NAN-1798 P2: risk is derived (no ingest lane of its own); findings
        // ingest through the logs lane. Unreachable as a tenant schema.
        SchemaId::Risk => "logs",
    }
}

/// Env-resolving wrapper for [`ingest_table_for`] (mirrors `active_logs_table`).
pub fn active_ingest_table() -> &'static str {
    active_profile_from_env()
        .map(|p| ingest_table_for(p.id()))
        .unwrap_or("logs")
}

/// The log-source-repository subtree to sync for a given schema id. Parser and
/// rule definitions live in parallel trees in the same git repo: the UDM tree
/// (`parsers/`, `rules/`) and a sibling OCSF tree (`parsers-ocsf/`,
/// `rules-ocsf/`). Under OCSF the sync walks the `<base>-ocsf/` sibling so the
/// imported parsers/rules emit the active schema; under UDM the stored path is
/// returned unchanged (byte-identical default). Idempotent — a path already
/// ending in `-ocsf` is returned as-is. Pure (env-free) so it is unit-testable;
/// `active_repo_path` is the env-resolving wrapper. NAN-1266.
pub fn repo_path_for(id: SchemaId, stored: &str) -> String {
    match id {
        // NAN-1555: spans/metrics have no parser/rule repo tree; passthrough like
        // UDM (and NAN-1798 P2: likewise the derived risk dataset).
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => stored.to_string(),
        SchemaId::Ocsf => {
            let base = stored.trim_end_matches('/');
            // NAN-2361: an EMPTY base has no directory to append `-ocsf` to.
            // This produced the literal path `-ocsf/`, which cannot exist, so
            // the tree walk matched nothing and sync reported SUCCESS with zero
            // rules — the nano-rs/rules layout keeps its tactic trees at the
            // repo root and stores `rules_path` as "".
            //
            // The sibling convention applies per top-level folder in that
            // layout (`execution` → `execution-ocsf`), exactly as
            // `selected_repo_path_for` already documents for selected paths;
            // it is not a property of the base. Returning the base unchanged
            // lets the walk see the root, where that per-folder preference is
            // applied.
            if base.is_empty() {
                return stored.to_string();
            }
            if base.ends_with("-ocsf") {
                stored.to_string()
            } else {
                format!("{base}-ocsf/")
            }
        }
    }
}

/// Pick the OCSF variant of each top-level folder in a ROOT-layout repository.
///
/// Returns `(kept_paths, untranslated_paths)`. For every top-level folder that
/// has an `-ocsf` sibling in the tree, only the sibling's files are kept. A
/// folder with no sibling falls back to its UDM files, reported separately so
/// the caller can flag them `untranslated` rather than importing them as ready
/// (NAN-1387) — a rule written against UDM columns will never fire on OCSF.
///
/// NAN-2361: without this, fixing the empty-base remap alone would import BOTH
/// trees, so every rule would arrive twice — once in the wrong schema.
pub fn select_ocsf_root_layout(
    paths: &[String],
) -> (Vec<String>, std::collections::HashSet<String>) {
    let top = |path: &str| path.split('/').next().unwrap_or("").to_string();

    let ocsf_folders: std::collections::HashSet<String> = paths
        .iter()
        .map(|p| top(p))
        .filter(|folder| folder.ends_with("-ocsf"))
        .collect();

    let mut kept = Vec::new();
    let mut untranslated = std::collections::HashSet::new();
    for path in paths {
        let folder = top(path);
        if folder.ends_with("-ocsf") {
            kept.push(path.clone());
        } else if !ocsf_folders.contains(&format!("{folder}-ocsf")) {
            untranslated.insert(path.clone());
            kept.push(path.clone());
        }
        // else: a sibling exists and already supplied this rule.
    }
    (kept, untranslated)
}

/// The branch the first-party content repositories are followed on.
///
/// `nano-rs/parsers` and `nano-rs/rules` carry the OCSF 1.9 content on `main`
/// (NAN-3897). The pre-1.9 UDM / OCSF 1.8 content for the frozen ClickHouse
/// edition lives on `legacy/clickhouse`, which this app never defaults to.
pub const FIRST_PARTY_CONTENT_BRANCH: &str = "main";

/// The retired OCSF 1.9 content branch. NAN-3758 defaulted the first-party
/// repositories to it; NAN-3897 folded it into `main`. The upstream branch is
/// kept for open-core v1.0.0 installs, but this app follows `main`.
pub const RETIRED_OCSF_CONTENT_BRANCH: &str = "ocsf-1.9";

/// The content branch a first-party repository sync should actually fetch.
///
/// A stored `ocsf-1.9` (the NAN-3758 default) resolves to `main`, so rows the
/// NAN-3897 migration has not rewritten yet and open-core v1.0.0 installs
/// follow `main`. Every other stored branch (`main`, a fork or an operator
/// pin) is kept.
///
/// Callers apply it only to the first-party content repositories; a
/// third-party source's branch is never rewritten.
pub fn content_branch_for(stored: &str) -> String {
    if stored.trim() == RETIRED_OCSF_CONTENT_BRANCH {
        FIRST_PARTY_CONTENT_BRANCH.to_string()
    } else {
        stored.to_string()
    }
}

/// True only for the two first-party, versioned content repositories.
pub fn is_first_party_content_url(raw: &str) -> bool {
    let absolute = if raw.starts_with("github.com/") || raw.starts_with("www.github.com/") {
        format!("https://{raw}")
    } else {
        raw.to_owned()
    };
    let Ok(url) = url::Url::parse(&absolute) else { return false };
    if !matches!(url.scheme(), "http" | "https")
        || !matches!(url.host_str(), Some("github.com" | "www.github.com"))
        || !url.username().is_empty() || url.password().is_some()
        || url.port().is_some() || url.query().is_some() || url.fragment().is_some()
    {
        return false;
    }
    let path = url.path().trim_end_matches('/').to_ascii_lowercase();
    matches!(path.trim_end_matches(".git"), "/nano-rs/parsers" | "/nano-rs/rules")
}

/// Creation default, preserving explicit pins and third-party branches.
///
/// First-party repositories default to `main`; an explicit `ocsf-1.9` request
/// (older clients) is stored as `main` so the row shows what is synced.
pub fn default_content_branch_for(url: &str, requested: Option<&str>) -> String {
    match requested {
        Some(branch) if is_first_party_content_url(url) => content_branch_for(branch),
        Some(branch) => branch.to_owned(),
        None => FIRST_PARTY_CONTENT_BRANCH.to_owned(),
    }
}

/// Branch to store for a new repository row. Resolves without the lake
/// manifest or the schema profile: repository creation and first-boot
/// migrations precede manifest availability.
pub fn default_content_branch(url: &str, requested: Option<&str>) -> String {
    default_content_branch_for(url, requested)
}

/// Branch a first-party repository sync fetches; see [`content_branch_for`].
pub fn active_content_branch(stored: &str) -> String {
    content_branch_for(stored)
}

/// The log-source-repository subtree for the env-configured schema profile.
/// Env-resolving wrapper over [`repo_path_for`]; on any resolution error the
/// stored path is returned unchanged so a malformed env never breaks sync.
/// NAN-1266.
pub fn active_repo_path(stored: &str) -> String {
    // NAN-3758: the validated runtime lane, not the lake manifest: a sync
    // that runs before the manifest resolves must still walk the OCSF tree.
    runtime_profile_from_env()
        .map(|p| repo_path_for(p.schema, stored))
        .unwrap_or_else(|_| stored.to_string())
}

/// Remap a folder-picker selected path to its `-ocsf` sibling for a given
/// schema id. Folder-picker paths are built as `<rules_path>/<folder>`, so the
/// sibling lives at `<rules_path>-ocsf/<folder>` when the repository has a
/// non-empty configured base ("rules/credential_access" →
/// "rules-ocsf/credential_access"). When the base is empty (trees at the repo
/// root — the nano-rs/rules layout) or the selected path lies outside the
/// base, the sibling convention applies to the path's first segment instead
/// ("demo" → "demo-ocsf"). Idempotent — a segment already ending in `-ocsf`
/// is returned as-is — and byte-identical under UDM. Pure (env-free) so it is
/// unit-testable; `active_selected_repo_path` is the env-resolving wrapper.
/// NAN-1387.
pub fn selected_repo_path_for(id: SchemaId, stored_base: &str, selected: &str) -> String {
    match id {
        // NAN-1555: spans/metrics have no repo tree; passthrough like UDM
        // (and NAN-1798 P2: likewise the derived risk dataset).
        SchemaId::Udm | SchemaId::Spans | SchemaId::Metrics | SchemaId::Risk => {
            selected.to_string()
        }
        SchemaId::Ocsf => {
            let base = stored_base.trim_start_matches('/').trim_end_matches('/');
            let sel = selected.trim_start_matches('/').trim_end_matches('/');
            if !base.is_empty() {
                let remapped_base = repo_path_for(SchemaId::Ocsf, base);
                let remapped_base = remapped_base.trim_end_matches('/');
                if sel == base {
                    return remapped_base.to_string();
                }
                if let Some(rest) = sel.strip_prefix(&format!("{base}/")) {
                    return format!("{remapped_base}/{rest}");
                }
            }
            // Empty base (repo-root trees) or a path outside the configured
            // base: remap the first segment to its `-ocsf` sibling.
            let (first, rest) = match sel.split_once('/') {
                Some((first, rest)) => (first, Some(rest)),
                None => (sel, None),
            };
            if first.is_empty() || first.ends_with("-ocsf") {
                return selected.to_string();
            }
            match rest {
                Some(rest) => format!("{first}-ocsf/{rest}"),
                None => format!("{first}-ocsf"),
            }
        }
    }
}

/// The `-ocsf` sibling of a folder-picker selected path for the
/// env-configured schema profile. Env-resolving wrapper over
/// [`selected_repo_path_for`]; on any resolution error the selected path is
/// returned unchanged so a malformed env never breaks sync. NAN-1387.
pub fn active_selected_repo_path(stored_base: &str, selected: &str) -> String {
    runtime_profile_from_env()
        .map(|p| selected_repo_path_for(p.schema, stored_base, selected))
        .unwrap_or_else(|_| selected.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::{
        normalize_field_name, EXPLICIT_COLUMNS, LOWERCASE_NORMALIZED_FIELDS, MATERIALIZED_COLUMNS,
        NUMERIC_UDM_FIELDS, PREWHERE_FIELDS, UUID_FIELDS,
    };
    use crate::udm::fields::UdmField;

    /// Two configured schema inputs that name DIFFERENT generations must fail
    /// closed. Silently preferring one made the product resolve OCSF fields
    /// against a generation its assigned worker was not serving. This exercises
    /// the live path (`require_agreeing_bytes`), which is called once per genuine
    /// profile (re)build with the chosen manifest's digest already in hand.
    #[test]
    fn disagreeing_schema_manifests_fail_closed_but_a_second_path_to_the_same_bytes_is_fine() {
        let directory = tempfile::tempdir().expect("temp dir");
        let chosen = directory.path().join("active.json");
        let copy = directory.path().join("published-copy.json");
        let divergent = directory.path().join("stale.json");
        std::fs::write(&chosen, br#"{"objects":[]}"#).expect("write chosen");
        // A coordinator-published copy of the SAME generation under another path.
        std::fs::write(&copy, br#"{"objects":[]}"#).expect("write copy");
        std::fs::write(&divergent, br#"{"objects":[{"field_types":{}}]}"#).expect("write stale");

        let chosen = chosen.to_str().expect("utf8");
        let chosen_digest = manifest_digest(chosen).expect("digest");

        require_agreeing_bytes(chosen, &chosen_digest, chosen).expect("identical path agrees");
        require_agreeing_bytes(chosen, &chosen_digest, copy.to_str().expect("utf8"))
            .expect("same bytes under a different path agrees");

        let error =
            require_agreeing_bytes(chosen, &chosen_digest, divergent.to_str().expect("utf8"))
                .expect_err("different generations must not resolve");
        assert!(
            error.contains("different generations"),
            "error must name the divergence: {error}"
        );
    }

    // NAN-1241: the ingested-events table name dispatch used by the direct-CH
    // surfaces outside the SearchService seam (feed health, retention, coverage).
    #[test]
    fn logs_table_for_dispatches_by_profile() {
        assert_eq!(logs_table_for(SchemaId::Udm), "logs");
        assert_eq!(logs_table_for(SchemaId::Ocsf), "ocsf_logs");
    }

    #[test]
    fn log_telemetry_profile_dispatches_by_tenant_schema() {
        assert_eq!(log_telemetry_profile_for(SchemaId::Udm), "udm");
        assert_eq!(log_telemetry_profile_for(SchemaId::Ocsf), "ocsf");
    }

    // NAN-3897: first-party content follows `main`; the retired `ocsf-1.9`
    // default resolves to it and every other branch is kept.
    #[test]
    fn content_branch_follows_main_and_retires_ocsf19() {
        assert_eq!(content_branch_for("ocsf-1.9"), "main");
        assert_eq!(content_branch_for(" ocsf-1.9 "), "main");
        assert_eq!(content_branch_for("main"), "main");
        assert_eq!(content_branch_for("my-fork"), "my-fork");
        assert_eq!(content_branch_for("legacy/clickhouse"), "legacy/clickhouse");
        assert_eq!(active_content_branch("ocsf-1.9"), "main");
    }

    #[test]
    fn content_branch_creation_defaults_to_main() {
        for url in ["https://github.com/nano-rs/parsers", "github.com/nano-rs/rules.git"] {
            assert_eq!(default_content_branch_for(url, None), "main");
            assert_eq!(default_content_branch_for(url, Some("ocsf-1.9")), "main");
            assert_eq!(default_content_branch_for(url, Some("my-fork")), "my-fork");
        }
        // A third-party repository's explicit branch is never rewritten.
        assert_eq!(default_content_branch_for("https://github.com/acme/rules", Some("ocsf-1.9")), "ocsf-1.9");
        assert_eq!(default_content_branch_for("https://github.com/SigmaHQ/sigma", None), "main");
    }

    // NAN-1266: log-source-repository subtree dispatch. UDM returns the stored
    // path unchanged (byte-identical); OCSF walks the sibling `<base>-ocsf/`.
    #[test]
    fn repo_path_for_dispatches_by_profile() {
        // UDM: unchanged
        assert_eq!(repo_path_for(SchemaId::Udm, "parsers/"), "parsers/");
        assert_eq!(repo_path_for(SchemaId::Udm, "rules/"), "rules/");
        // OCSF: sibling tree, with or without a trailing slash on input
        assert_eq!(repo_path_for(SchemaId::Ocsf, "parsers/"), "parsers-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules/"), "rules-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "parsers"), "parsers-ocsf/");
        // OCSF: idempotent — an already-OCSF path is left as-is
        assert_eq!(
            repo_path_for(SchemaId::Ocsf, "parsers-ocsf/"),
            "parsers-ocsf/"
        );
    }

    // NAN-1387: folder-picker selected-path dispatch. UDM returns the selected
    // path unchanged (byte-identical); OCSF walks the `-ocsf` sibling tree.
    #[test]
    fn selected_repo_path_for_dispatches_by_profile() {
        // UDM: unchanged, regardless of base
        assert_eq!(
            selected_repo_path_for(SchemaId::Udm, "rules/", "rules/credential_access"),
            "rules/credential_access"
        );
        assert_eq!(selected_repo_path_for(SchemaId::Udm, "", "demo"), "demo");

        // OCSF + non-empty base: sibling of the configured base
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules/", "rules/credential_access"),
            "rules-ocsf/credential_access"
        );
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules", "rules/demo/sub"),
            "rules-ocsf/demo/sub"
        );
        // Selecting the base itself
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules/", "rules"),
            "rules-ocsf"
        );
        // Nested base swaps the whole base, not its first segment
        assert_eq!(
            selected_repo_path_for(
                SchemaId::Ocsf,
                "detections/rules/",
                "detections/rules/impact"
            ),
            "detections/rules-ocsf/impact"
        );

        // OCSF + empty base (repo-root trees, the nano-rs/rules layout):
        // first-segment sibling
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "", "demo"),
            "demo-ocsf"
        );
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "", "credential_access/sub"),
            "credential_access-ocsf/sub"
        );
        // Path outside the configured base falls back to first-segment sibling
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules/", "demo"),
            "demo-ocsf"
        );

        // OCSF: idempotent — an already-OCSF selection is left as-is
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "", "demo-ocsf"),
            "demo-ocsf"
        );
        assert_eq!(
            selected_repo_path_for(SchemaId::Ocsf, "rules-ocsf/", "rules-ocsf/impact"),
            "rules-ocsf/impact"
        );
    }

    // --- Anti-drift gate: UdmProfile must reproduce every const array exactly ---
    //
    // These assert the profile *references* (not copies) the canonical arrays, so
    // when Phase 2 re-points call sites at the profile, a divergence is impossible
    // to introduce silently.

    #[test]
    fn prewhere_fields_match_const() {
        assert_eq!(UdmProfile::new().prewhere_fields(), PREWHERE_FIELDS);
    }

    #[test]
    fn materialized_columns_match_const() {
        assert_eq!(
            UdmProfile::new().materialized_columns(),
            MATERIALIZED_COLUMNS
        );
    }

    #[test]
    fn explicit_columns_match_const() {
        // resolve() returns ExplicitColumn for exactly the EXPLICIT_COLUMNS set.
        let p = UdmProfile::new();
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.resolve(col),
                FieldResolution::ExplicitColumn((*col).to_string()),
                "explicit column {col} did not resolve to ExplicitColumn",
            );
        }
    }

    #[test]
    fn lowercase_normalized_fields_match_const() {
        let p = UdmProfile::new();
        // Every const member is lowercased-at-ingest per the profile...
        for f in LOWERCASE_NORMALIZED_FIELDS {
            assert!(
                p.is_lowercased_at_ingest(f),
                "{f} should be lowercased-at-ingest",
            );
        }
        // ...and nothing outside the const set is.
        let set: std::collections::HashSet<&str> =
            LOWERCASE_NORMALIZED_FIELDS.iter().copied().collect();
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.is_lowercased_at_ingest(col),
                set.contains(col),
                "is_lowercased_at_ingest disagreed with const for {col}",
            );
        }
    }

    #[test]
    fn numeric_fields_match_const() {
        let p = UdmProfile::new();
        let set: std::collections::HashSet<&str> = NUMERIC_UDM_FIELDS.iter().copied().collect();
        for f in NUMERIC_UDM_FIELDS {
            assert!(p.is_numeric_field(f), "{f} should be numeric");
        }
        // No explicit column outside the const should be flagged numeric.
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.is_numeric_field(col),
                set.contains(col),
                "is_numeric_field disagreed with const for {col}",
            );
        }
    }

    #[test]
    fn uuid_fields_match_const() {
        let p = UdmProfile::new();
        let set: std::collections::HashSet<&str> = UUID_FIELDS.iter().copied().collect();
        for f in UUID_FIELDS {
            assert!(p.is_uuid_field(f), "{f} should be a UUID field");
        }
        for col in EXPLICIT_COLUMNS {
            assert_eq!(
                p.is_uuid_field(col),
                set.contains(col),
                "is_uuid_field disagreed with const for {col}",
            );
        }
    }

    // --- resolve() ≡ is_explicit_column() across the whole field universe ---

    #[test]
    fn resolve_matches_is_explicit_column_for_all_explicit_columns() {
        let p = UdmProfile::new();
        for col in EXPLICIT_COLUMNS {
            // EXPLICIT_COLUMNS are exactly the names crate::query::is_explicit_column
            // returns true for; resolve() must return ExplicitColumn for each.
            assert!(matches!(p.resolve(col), FieldResolution::ExplicitColumn(_)));
        }
    }

    #[test]
    fn resolve_matches_is_explicit_column_across_all_udm_fields() {
        let p = UdmProfile::new();
        let explicit: std::collections::HashSet<&str> = EXPLICIT_COLUMNS.iter().copied().collect();
        // For every field in the generated UDM universe, resolve()'s ExplicitColumn
        // vs Unknown decision must agree with EXPLICIT_COLUMNS membership.
        for f in UdmField::all() {
            let name = f.column_name();
            let resolved_explicit = matches!(p.resolve(name), FieldResolution::ExplicitColumn(_));
            assert_eq!(
                resolved_explicit,
                explicit.contains(name),
                "resolve() disagreed with EXPLICIT_COLUMNS membership for {name}",
            );
        }
    }

    #[test]
    fn resolve_unknown_for_non_field() {
        assert_eq!(
            UdmProfile::new().resolve("definitely_not_a_field_xyz"),
            FieldResolution::Unknown,
        );
    }

    // --- fields() universe parity with the generated enum ---

    #[test]
    fn fields_cover_all_udm_fields() {
        let p = UdmProfile::new();
        let names: std::collections::HashSet<&str> = p.fields().iter().map(|f| f.name).collect();
        assert_eq!(p.fields().len(), UdmField::all().len());
        for f in UdmField::all() {
            assert!(
                names.contains(f.column_name()),
                "fields() missing {}",
                f.column_name(),
            );
        }
    }

    #[test]
    fn canonicalize_matches_normalize_field_name() {
        let p = UdmProfile::new();
        // Aliases must rewrite identically to the canonical free fn...
        for f in ["sourcetype", "hostname", "_time", "event_id"] {
            assert_eq!(
                p.canonicalize(f).as_ref(),
                normalize_field_name(f),
                "canonicalize disagreed with normalize_field_name for alias {f}",
            );
        }
        // ...and non-aliased fields pass through unchanged (Borrowed).
        for f in ["src_ip", "user", "definitely_not_a_field_xyz"] {
            let c = p.canonicalize(f);
            assert_eq!(c.as_ref(), normalize_field_name(f));
            assert!(
                matches!(c, std::borrow::Cow::Borrowed(_)),
                "non-aliased field {f} should canonicalize to Borrowed",
            );
        }
    }

    #[test]
    fn is_known_field_accepts_explicit_and_csv_fields() {
        let p = UdmProfile::new();
        assert!(p.is_known_field("src_ip"));
        assert!(p.is_known_field("user"));
        assert!(!p.is_known_field("definitely_not_a_field_xyz"));
    }

    // --- NAN-1425: gated alias authority (mirrors NAN-1422 on the OCSF side) ---

    /// Every `normalize_field_name` alias whose target is an explicit `logs`
    /// column, alias-by-alias. `source_ip` is deliberately absent — pinned typo
    /// case, gate precedence (see `udm_pinned_typo_alias_not_claimed`).
    /// `service_name` is also absent here: its RAW spelling is a generated
    /// `UdmField`, so the profile never re-aliases it (see
    /// `udm_known_raw_spelling_never_realiased`).
    const UDM_ACCEPTED_ALIASES: &[(&str, &str)] = &[
        ("_time", "timestamp"),
        ("sourcetype", "source_type"),
        ("dest_hostname", "dest_host"),
        ("src_hostname", "src_host"),
        ("username", "user"),
        ("destination_ip", "dest_ip"),
        ("src_address", "src_ip"),
        ("dest_address", "dest_ip"),
        ("source_port", "src_port"),
        ("destination_port", "dest_port"),
        ("source_mac", "src_mac"),
        ("destination_mac", "dest_mac"),
        ("process", "command_line"),
        ("parent_process", "parent_command_line"),
        ("uri", "url"),
        ("referer", "http_referrer"),
        ("referrer", "http_referrer"),
        ("useragent", "http_user_agent"),
        ("filename", "file_name"),
        ("filepath", "file_path"),
        ("outcome", "status"),
        ("response_code", "http_status_code"),
        ("http_status", "http_status_code"),
        ("http_response_code", "http_status_code"),
        ("resp_code", "http_status_code"),
        ("request_method", "http_method"),
        ("method", "http_method"),
        ("dns_query", "query"),
        ("dns_response", "answer"),
        ("dns_answer", "answer"),
        ("cloud.provider", "cloud_provider"),
        ("cloud.account.id", "cloud_account_id"),
        ("cloud.account.name", "cloud_account_name"),
        ("cloud.region", "cloud_region"),
        ("cloud.service.name", "cloud_service"),
        ("event_id", "signature_id"),
        ("eventid", "signature_id"),
    ];

    #[test]
    fn udm_accepted_aliases_are_known_and_resolve_to_canonical_column() {
        let p = UdmProfile::new();
        for (alias, target) in UDM_ACCEPTED_ALIASES {
            assert!(
                p.is_known_field(alias),
                "alias {alias} must be a known field (NAN-1425)"
            );
            assert_eq!(
                p.resolve(alias),
                FieldResolution::ExplicitColumn((*target).to_string()),
                "alias {alias} must resolve to its canonical column {target}",
            );
            // …and identically to the canonical spelling, so codegen seams
            // that pass the RAW name (IN-list) land on the same column.
            assert_eq!(
                p.resolve(alias),
                p.resolve(target),
                "alias {alias} and canonical {target} must resolve identically",
            );
        }
    }

    #[test]
    fn udm_pinned_typo_alias_not_claimed() {
        // COLLISION (recorded on NAN-1425): normalize_field_name maps
        // `source_ip` → `src_ip`, but the NAN-1380 G5 typo gate pins
        // `source_ip` as a rejected near-miss ("did you mean src_ip") and that
        // takes precedence — the profile must not claim it as known, and it
        // must keep resolving Unknown.
        let p = UdmProfile::new();
        assert!(!p.is_known_field("source_ip"));
        assert_eq!(p.resolve("source_ip"), FieldResolution::Unknown);
    }

    #[test]
    fn udm_alias_without_explicit_target_does_not_rewrite() {
        // `hostname` → `host` and `destination` → `dest`: targets are not
        // explicit `logs` columns, so the gated alias authority refuses the
        // rewrite (mirrors NAN-1422's `hostname` pin on OCSF) — these names
        // stay exactly as unknown as before and spill to ext raw.
        let p = UdmProfile::new();
        for alias in ["hostname", "destination"] {
            assert!(!p.is_known_field(alias), "{alias} must stay unknown");
            assert_eq!(p.resolve(alias), FieldResolution::Unknown);
        }
    }

    #[test]
    fn udm_known_raw_spelling_never_realiased() {
        // `service_name` is a generated UdmField whose spelling the codegen
        // map rewrites to `cloud_service` — but a real field never re-aliases
        // through the profile: it stays known via its RAW spelling and keeps
        // resolving Unknown (ext spill), exactly the pre-NAN-1425 behavior the
        // anti-drift gates above pin.
        let p = UdmProfile::new();
        assert!(p.is_known_field("service_name"));
        assert_eq!(p.resolve("service_name"), FieldResolution::Unknown);
    }

    #[test]
    fn udm_alias_type_predicates_judge_canonical_target() {
        // The IN-list seam consults is_numeric_field/is_uuid_field with the
        // RAW name; an accepted alias must type like its target or
        // `response_code IN ("200")` would emit `lower(<UInt16 col>)` (CH type
        // error) while the canonical form takes the numeric branch.
        let p = UdmProfile::new();
        for alias in [
            "response_code",
            "http_status",
            "source_port",
            "destination_port",
        ] {
            assert!(
                p.is_numeric_field(alias),
                "{alias} must inherit its numeric target type"
            );
        }
        // String-targeted aliases stay non-numeric…
        assert!(!p.is_numeric_field("sourcetype"));
        // …pinned/refused aliases keep raw-spelling lookups only.
        assert!(!p.is_numeric_field("source_ip"));
        // No alias targets a UUID column today; the predicate must agree.
        for (alias, _) in UDM_ACCEPTED_ALIASES {
            assert!(!p.is_uuid_field(alias));
        }
    }

    #[test]
    fn udm_alias_sql_is_byte_identical_to_canonical() {
        // End-to-end codegen: the alias form and the canonical form must
        // generate byte-identical SQL under UDM — Eq, IN-list (the seam that
        // passes RAW names to the profile), stats and table positions.
        use crate::query::{parse_query, ClickHouseSqlGenerator, TimeRange};
        let time_range = TimeRange {
            start: "2024-01-01T00:00:00Z".parse().unwrap(),
            end: "2024-01-02T00:00:00Z".parse().unwrap(),
        };
        let generator = ClickHouseSqlGenerator::new();
        let sql_for = |q: &str| -> String {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            generator
                .generate(&query, &time_range)
                .unwrap_or_else(|e| panic!("generate {q}: {e}"))
        };
        for (alias, target) in UDM_ACCEPTED_ALIASES {
            // NAN-4286: a comparison against the time column must carry a
            // time literal, so the time alias is exercised with RFC3339 values.
            let (x, y) = if *target == "timestamp" {
                ("2024-01-01T06:00:00Z", "2024-01-01T07:00:00Z")
            } else {
                ("x", "y")
            };
            for (alias_q, canonical_q) in [
                (format!(r#"{alias}="{x}""#), format!(r#"{target}="{x}""#)),
                (
                    format!(r#"{alias} IN ("{x}", "{y}")"#),
                    format!(r#"{target} IN ("{x}", "{y}")"#),
                ),
                (
                    format!("* | stats count() by {alias}"),
                    format!("* | stats count() by {target}"),
                ),
            ] {
                let alias_sql = sql_for(&alias_q);
                let canonical_sql = sql_for(&canonical_q);
                assert_eq!(
                    alias_sql, canonical_sql,
                    "alias {alias} must generate byte-identical SQL to {target} ({alias_q})",
                );
            }
        }
        // The alias is refused exactly like its canonical column: a non-time
        // literal on `_time` gets the same NAN-4286 error as on `timestamp`.
        let refusal = |q: &str| -> String {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            generator
                .generate(&query, &time_range)
                .expect_err("a non-time literal on the time column must be refused")
                .to_string()
        };
        assert_eq!(
            refusal(r#"_time="x""#).replace("_time", "timestamp"),
            refusal(r#"timestamp="x""#),
        );
    }

    #[test]
    fn storage_binding_is_udm() {
        let p = UdmProfile::new();
        assert_eq!(p.id(), SchemaId::Udm);
        assert_eq!(p.table_name(), "nanosiem.logs");
        assert_eq!(p.timestamp_expr(), "timestamp");
        assert_eq!(p.enrichment_mode(), EnrichmentMode::Materialized);
    }

    // --- Default-view renames: the projection-fix contract (Phase 3a) ---

    #[test]
    fn udm_default_view_renames_is_action_event_type() {
        // Exactly today's `* EXCEPT (action), action AS event_type` rewrite.
        assert_eq!(
            UdmProfile::new().default_view_renames(),
            &[("action", "event_type")]
        );
    }

    #[test]
    fn ocsf_default_view_renames_is_empty() {
        // OCSF has no `action` column → no rewrite (bare `*`), so a default-view
        // search does not reference a nonexistent UDM column.
        assert!(OcsfProfile::new().default_view_renames().is_empty());
    }

    // --- Canonical entity-extraction order (single source of truth) ---
    //
    // Phase 5 (NAN-1241) unified three drifted hardcoded entity lists (the risk
    // scorer, the event grouper, and the rule risk-entity auto-detector) onto
    // ONE order — `entity_extraction_order()`. This is now the single source of
    // truth for which fields risk attaches to, so pin it: an accidental edit
    // that re-introduces drift / changes risk attribution must be deliberate.

    #[test]
    fn udm_entity_order_is_canonical_and_priority_tiered() {
        let p = UdmProfile::new();
        let order = p.entity_extraction_order();
        let fields: Vec<&str> = order.iter().map(|(_, f)| *f).collect();

        // Priority tiers: IP before host before user before hash (the contract
        // the detection priority tests rely on).
        let pos = |f: &str| fields.iter().position(|x| *x == f).expect(f);
        assert!(pos("src_ip") < pos("src_host"), "IP must outrank host");
        assert!(pos("src_host") < pos("user"), "host must outrank user");
        assert!(pos("user") < pos("file_hash"), "user must outrank hash");

        // The formerly-divergent fields the grouper/auto-detector had dropped are
        // present (the drift the unification fixed).
        for f in ["src_nt_domain", "dest_nt_domain", "metadata.src_ip"] {
            assert!(fields.contains(&f), "canonical order must include {f}");
        }
        // src_ip is the top-priority entity.
        assert_eq!(fields.first(), Some(&"src_ip"));
    }

    // --- Boot-time profile selection (env → SchemaId → profile) ---

    #[test]
    fn schema_id_from_env_str_defaults_and_parses() {
        assert_eq!(SchemaId::from_env_str("").unwrap(), SchemaId::Udm);
        assert_eq!(SchemaId::from_env_str("udm").unwrap(), SchemaId::Udm);
        assert_eq!(SchemaId::from_env_str("UDM").unwrap(), SchemaId::Udm);
        assert_eq!(SchemaId::from_env_str(" ocsf ").unwrap(), SchemaId::Ocsf);
        assert_eq!(SchemaId::from_env_str("OCSF").unwrap(), SchemaId::Ocsf);
    }

    #[test]
    fn schema_id_from_env_str_rejects_unknown() {
        // Fail-fast, not a silent UDM fallback (NAN-800).
        let err = SchemaId::from_env_str("splunk").unwrap_err();
        assert!(err.contains("invalid NANO_SCHEMA_PROFILE"), "{err}");
    }

    #[test]
    fn profile_for_id_maps_to_concrete_profile() {
        assert_eq!(profile_for_id(SchemaId::Udm).id(), SchemaId::Udm);
        assert_eq!(profile_for_id(SchemaId::Ocsf).id(), SchemaId::Ocsf);
        // And resolves to the right storage table.
        assert_eq!(profile_for_id(SchemaId::Udm).table_name(), "nanosiem.logs");
        assert_eq!(
            profile_for_id(SchemaId::Ocsf).table_name(),
            "nanosiem.ocsf_logs"
        );
    }

    #[test]
    fn immutable_manifest_field_inventory_supports_minor_ocsf_evolution() {
        let fields = snapshot_field_types_from_manifest(
            r#"{
                "objects": [
                    {"field_types": {"metadata.uid": "string", "ai_operation.name": "string"}},
                    {"field_types": {"ai_operation.name": "string", "ai_operation.tools": "array"}}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(fields.get("ai_operation.name"), Some(&FieldType::String));
        assert_eq!(fields.get("ai_operation.tools"), Some(&FieldType::Array));
        let profile = OcsfProfile::try_lake_1_9_with_snapshot_field_types(fields).unwrap();
        assert!(profile.is_known_field("ai_operation.name"));
    }

    #[test]
    fn stable_worker_config_resolves_the_active_schema_manifest() {
        let path = schema_manifest_path_from_worker_config(
            r#"{
                "tenant": {
                    "source_manifest": {
                        "path": "/var/lib/nano-lake/generations/current/entity-sidecar/manifest.json",
                        "sha256": "unused-by-product-profile"
                    }
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            path,
            "/var/lib/nano-lake/generations/current/entity-sidecar/manifest.json"
        );
        assert!(schema_manifest_path_from_worker_config(r#"{"tenant": {}}"#).is_err());
    }

    #[test]
    fn canonical_lake_profile_rejects_a_missing_manifest_source() {
        let error = require_lake_schema_manifest_path(None, None).unwrap_err();
        assert!(error.contains(LAKE_SCHEMA_MANIFEST_ENV), "{error}");
        assert!(error.contains(LAKE_WORKER_CONFIG_ENV), "{error}");
    }

    /// These tests swap the process-wide manifest env vars, so they must not run
    /// concurrently with each other. Nothing else in the crate builds a lake
    /// profile, and the vars are only read by the lake branch.
    fn manifest_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        &LOCK
    }

    /// Sets the explicit manifest var and clears the worker-config var so the
    /// ambient shell cannot influence the result; restores both on drop.
    struct ManifestEnv;

    impl ManifestEnv {
        fn pointing_at(path: &std::path::Path) -> Self {
            std::env::set_var(LAKE_SCHEMA_MANIFEST_ENV, path);
            std::env::remove_var(LAKE_WORKER_CONFIG_ENV);
            Self
        }
    }

    impl Drop for ManifestEnv {
        fn drop(&mut self) {
            std::env::remove_var(LAKE_SCHEMA_MANIFEST_ENV);
        }
    }

    const MANIFEST_A: &str = r#"{"objects":[{"field_types":{"metadata.uid":"string"}}]}"#;
    // Same shape, different BYTES and a different field — a promoted generation.
    const MANIFEST_B: &str =
        r#"{"objects":[{"field_types":{"metadata.uid":"string","ai_operation.name":"string"}}]}"#;

    /// The build reads and serde-parses a ~12 MB source manifest (333-394 ms in a
    /// debug build) and ~20 core call sites reach it per request/batch, so repeated
    /// calls over unchanged bytes must hit the memo, not the parser.
    #[test]
    fn repeated_calls_over_unchanged_manifest_bytes_build_the_profile_once() {
        let _guard = manifest_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let directory = tempfile::tempdir().expect("temp dir");
        let manifest = directory.path().join("manifest.json");
        std::fs::write(&manifest, MANIFEST_A).expect("write manifest");
        let _env = ManifestEnv::pointing_at(&manifest);

        let before = lake_profile_build_count();
        let first = lake_ocsf_profile_from_snapshot_env().expect("first build");
        assert_eq!(lake_profile_build_count(), before + 1);
        let second = lake_ocsf_profile_from_snapshot_env().expect("cached build");
        assert_eq!(
            lake_profile_build_count(),
            before + 1,
            "the second call re-parsed the manifest"
        );
        assert!(
            Arc::ptr_eq(&first, &second),
            "callers must share one profile instance"
        );
    }

    /// A promotion rewrites the manifest in place, so keying on the path alone
    /// would serve the OLD field inventory for the process lifetime.
    #[test]
    fn new_manifest_bytes_at_the_same_path_are_not_served_from_the_cache() {
        let _guard = manifest_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let directory = tempfile::tempdir().expect("temp dir");
        let manifest = directory.path().join("manifest.json");
        std::fs::write(&manifest, MANIFEST_A).expect("write generation A");
        let _env = ManifestEnv::pointing_at(&manifest);

        let generation_a = lake_ocsf_profile_from_snapshot_env().expect("build A");
        assert!(!generation_a.is_known_field("ai_operation.name"));

        std::fs::write(&manifest, MANIFEST_B).expect("promote generation B");
        let before = lake_profile_build_count();
        let generation_b = lake_ocsf_profile_from_snapshot_env().expect("build B");
        assert_eq!(
            lake_profile_build_count(),
            before + 1,
            "the promoted generation was served from a stale cache entry"
        );
        assert!(!Arc::ptr_eq(&generation_a, &generation_b));
        assert!(generation_b.is_known_field("ai_operation.name"));

        // The prior generation is still resident (in-flight requests hold it) and
        // is still served from the memo rather than rebuilt.
        std::fs::write(&manifest, MANIFEST_A).expect("restore generation A");
        let before = lake_profile_build_count();
        let again = lake_ocsf_profile_from_snapshot_env().expect("cached A");
        assert_eq!(lake_profile_build_count(), before);
        assert!(Arc::ptr_eq(&generation_a, &again));
    }

    /// Fail-closed path: a broken manifest must error on EVERY call. Caching a
    /// failure (or an empty inventory) would make the whole process resolve fields
    /// against nothing until it restarted.
    #[test]
    fn unreadable_or_invalid_manifests_keep_erroring_and_are_never_cached() {
        let _guard = manifest_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let directory = tempfile::tempdir().expect("temp dir");
        let manifest = directory.path().join("missing.json");
        let _env = ManifestEnv::pointing_at(&manifest);

        let before = lake_profile_build_count();
        for _ in 0..2 {
            let Err(error) = lake_ocsf_profile_from_snapshot_env() else {
                panic!("a missing manifest must not resolve");
            };
            assert!(error.contains(LAKE_SCHEMA_MANIFEST_ENV), "{error}");
        }
        // Present but not a manifest: still an error, still not cached.
        std::fs::write(&manifest, b"{not json").expect("write garbage");
        for _ in 0..2 {
            let Err(error) = lake_ocsf_profile_from_snapshot_env() else {
                panic!("an invalid manifest must not resolve");
            };
            assert!(
                error.contains("invalid lake schema manifest JSON"),
                "{error}"
            );
        }
        assert_eq!(
            lake_profile_build_count(),
            before,
            "a failure must not count as a build"
        );

        // Once the real manifest lands, the same path resolves normally.
        std::fs::write(&manifest, MANIFEST_A).expect("write manifest");
        assert!(lake_ocsf_profile_from_snapshot_env().is_ok());
    }

    /// The cache is keyed by content digest, so an unbounded map would gain an
    /// entry per promotion and never release the multi-MB inventory behind it.
    #[test]
    fn the_profile_cache_is_bounded_to_its_capacity() {
        let _guard = manifest_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let directory = tempfile::tempdir().expect("temp dir");
        let manifest = directory.path().join("manifest.json");
        let _env = ManifestEnv::pointing_at(&manifest);

        for generation in 0..(LAKE_PROFILE_CACHE_CAPACITY + 3) {
            let field = format!("ai_operation.tool_{generation}");
            std::fs::write(
                &manifest,
                format!(r#"{{"objects":[{{"field_types":{{"{field}":"string"}}}}]}}"#),
            )
            .expect("promote generation");
            lake_ocsf_profile_from_snapshot_env().expect("build generation");
        }
        let resident = lake_profile_cache().read().expect("cache lock").len();
        assert!(
            resident <= LAKE_PROFILE_CACHE_CAPACITY,
            "cache grew to {resident} entries"
        );
    }

    /// Same-length promotion: the `stat` fingerprint includes mtime precisely so
    /// a rewrite that keeps the byte count is not mistaken for the same bytes.
    #[test]
    fn a_same_length_promotion_still_builds_a_new_profile() {
        let _guard = manifest_env_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let directory = tempfile::tempdir().expect("temp dir");
        let manifest = directory.path().join("manifest.json");
        let generation = |field: &str| {
            format!(r#"{{"objects":[{{"field_types":{{"ai_operation.{field}":"string"}}}}]}}"#)
        };
        std::fs::write(&manifest, generation("aaaa")).expect("write generation A");
        let a_modified = std::fs::metadata(&manifest)
            .and_then(|m| m.modified())
            .expect("stat A");
        let _env = ManifestEnv::pointing_at(&manifest);
        let first = lake_ocsf_profile_from_snapshot_env().expect("build A");

        let promoted = generation("bbbb");
        assert_eq!(promoted.len(), generation("aaaa").len());
        std::fs::write(&manifest, &promoted).expect("promote");
        // Linux stamps mtime from the coarse kernel clock, so two writes inside
        // one tick share an mtime and are indistinguishable by (len, mtime); a
        // real promotion lands a generation later. Pin B's mtime strictly after
        // A's so the case under test (same length, new bytes, new mtime) is
        // deterministic on a fast or a loaded runner.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&manifest)
            .and_then(|f| f.set_modified(a_modified + std::time::Duration::from_secs(1)))
            .expect("advance B's mtime past A's");
        let before = lake_profile_build_count();
        let second = lake_ocsf_profile_from_snapshot_env().expect("build B");
        assert_eq!(lake_profile_build_count(), before + 1);
        assert!(!Arc::ptr_eq(&first, &second));
        assert!(second.is_known_field("ai_operation.bbbb"));
        assert!(!second.is_known_field("ai_operation.aaaa"));
    }

    #[test]
    fn immutable_manifest_field_inventory_rejects_type_conflicts() {
        let error = snapshot_field_types_from_manifest(
            r#"{
                "objects": [
                    {"field_types": {"ai_operation.name": "string"}},
                    {"field_types": {"ai_operation.name": "long"}}
                ]
            }"#,
        )
        .unwrap_err();
        assert!(error.contains("conflicting types"), "{error}");
    }
}

#[cfg(test)]
mod root_layout_repo_tests {
    use super::*;

    /// NAN-2361: `rules_path=""` produced the literal path `-ocsf/`.
    ///
    /// Nothing in any repository can match that, so the tree walk returned no
    /// files and sync reported SUCCESS with zero rules — silently, for every
    /// root-layout repository (nano-rs/rules keeps its tactic trees at the
    /// repo root). Verified against the live tenant: rule_count 0,
    /// last_sync_status "success".
    #[test]
    fn an_empty_base_is_not_remapped_to_a_path_that_cannot_exist() {
        assert_eq!(repo_path_for(SchemaId::Ocsf, ""), "");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "/"), "/");
        // A real base still gets its sibling.
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules/"), "rules-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules"), "rules-ocsf/");
        // Idempotent, and untouched under UDM.
        assert_eq!(repo_path_for(SchemaId::Ocsf, "rules-ocsf/"), "rules-ocsf/");
        assert_eq!(repo_path_for(SchemaId::Udm, ""), "");
        assert_eq!(repo_path_for(SchemaId::Udm, "rules/"), "rules/");
    }

    #[test]
    fn root_layout_prefers_the_ocsf_sibling_folder() {
        let paths: Vec<String> = [
            "execution/mshta.yml",
            "execution-ocsf/mshta.yml",
            "persistence/run_key.yml",
            "persistence-ocsf/run_key.yml",
            // No sibling: UDM-only tactic.
            "exfiltration/dns_tunnel.yml",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let (kept, untranslated) = select_ocsf_root_layout(&paths);

        assert!(kept.contains(&"execution-ocsf/mshta.yml".to_string()));
        assert!(kept.contains(&"persistence-ocsf/run_key.yml".to_string()));
        // The UDM twins must NOT come along, or every rule imports twice.
        assert!(!kept.contains(&"execution/mshta.yml".to_string()));
        assert!(!kept.contains(&"persistence/run_key.yml".to_string()));

        // A tactic with no OCSF sibling is still imported, but flagged, so it
        // surfaces as untranslated rather than as a rule that will never fire.
        assert!(kept.contains(&"exfiltration/dns_tunnel.yml".to_string()));
        assert!(untranslated.contains("exfiltration/dns_tunnel.yml"));
        assert_eq!(untranslated.len(), 1);
    }

    #[test]
    fn root_layout_with_no_ocsf_folders_keeps_everything_flagged() {
        // The `main` branch shape: no `-ocsf` siblings at all.
        let paths: Vec<String> = ["execution/a.yml", "discovery/b.yml"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (kept, untranslated) = select_ocsf_root_layout(&paths);
        assert_eq!(kept.len(), 2, "nothing should be dropped");
        assert_eq!(untranslated.len(), 2, "all are schema-mismatched");
    }
}
