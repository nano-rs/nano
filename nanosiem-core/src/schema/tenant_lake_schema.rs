// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant lake field inventory for enterprise-shared processes (NAN-2718).
//!
//! A hosted-shared api/search/jobs process serves many tenants. It used to
//! fetch ONE field inventory from a process-global `NANO_LAKE_QUERY_URL`
//! (in production: tenant1's query worker) and install it as the schema for
//! every tenant. Other tenants then saw tenant1's field names (including its
//! producer-owned `unmapped.*` leaves) in field lists and suggestions, and
//! their own fields were rejected as unknown.
//!
//! This module replaces that global with a cache keyed by tenant UUID. Each
//! tenant's inventory is fetched from THAT tenant's query worker, resolved
//! through the server-owned shared worker registry (the same assignment Search
//! uses to route the tenant's queries), with the tenant's own credential, and
//! the response must carry the assignment identity/revision the registry
//! expects. A tenant with no verified inventory gets the canonical OCSF 1.9
//! profile with an EMPTY snapshot inventory: it may reject that tenant's
//! `unmapped.*` fields until its schema loads, but it never exposes another
//! tenant's fields.
//!
//! Lean-lake cell tenants (NAN-2997) have no gen1 worker: their inventory is
//! the part schema their cell's `query[T]` serves at `/v1/schema/manifest`,
//! reached through the tenant's own [`LakeCellRoute`]. It is fetched lazily,
//! when that tenant makes a request ([`ensure_tenant_profile`]), never by the
//! background loop: pooled query[T] processes idle out, and a fleet-wide poll
//! would keep every one of them awake. An entry is bound to the exact route
//! (cell origin + assignment generation) it was fetched through.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::{FieldType, OcsfProfile, SchemaProfile};
use crate::search::{LakeCellRoute, SharedLakeWorkerAssignment, SharedLakeWorkerRegistry};

/// How often a tenant's inventory is re-fetched. The worker answers with a
/// content digest, so an unchanged field set costs one small GET and no rebuild.
pub const TENANT_SCHEMA_TTL: Duration = Duration::from_secs(60);
/// A verified inventory older than this is dropped, not served. Transient
/// worker faults keep the tenant's own last-good schema; a worker that has
/// been unreachable for this long no longer vouches for it.
pub const TENANT_SCHEMA_MAX_AGE: Duration = Duration::from_secs(15 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request with NO inventory for its cell tenant waits for the
/// first fetch. The fetch keeps running (and installs) past this; the
/// request meanwhile validates against the canonical profile.
const CELL_FIRST_FETCH_WAIT: Duration = Duration::from_secs(8);
/// After a failed cell fetch, requests do not retry it for this long.
const CELL_RETRY_BACKOFF: Duration = Duration::from_secs(15);
/// NAN-3666: a gen1 refresh that keeps failing for the same tenant is
/// reported at warn once per failure streak, then again at most this often.
/// Every other failure in the streak logs at debug. A tenant whose worker is
/// gone (a deleted tenant still in a stale registry) used to warn every
/// [`TENANT_SCHEMA_TTL`] for ever.
pub const REFRESH_FAILURE_REMINDER: Duration = Duration::from_secs(60 * 60);
/// Sanity bound on one tenant's inventory.
const MAX_INVENTORY_FIELDS: usize = 50_000;
const SCHEMA_ROUTE: &str = "/v1/schema/manifest";
const WORKER_ASSIGNMENT_ID_HEADER: &str = "x-nano-worker-assignment-id";
const WORKER_ASSIGNMENT_REVISION_HEADER: &str = "x-nano-worker-assignment-revision";

/// True when this process runs in the hosted shared-tenancy deployment mode.
/// Ungated on purpose: binaries built without `enterprise` must still refuse
/// a process-global schema in that mode, exactly as enterprise builds do.
pub fn shared_tenancy_process() -> bool {
    std::env::var("DEPLOYMENT_MODE").is_ok_and(|mode| mode.trim() == "enterprise_shared")
}

/// Enterprise name for [`shared_tenancy_process`].
#[cfg(feature = "enterprise")]
pub fn enterprise_shared_process() -> bool {
    shared_tenancy_process()
}

/// The canonical OCSF 1.9 lake profile with no snapshot inventory: the only
/// schema a shared process may hold that is not bound to one tenant.
pub fn canonical_shared_lake_profile() -> Arc<dyn SchemaProfile> {
    static CANONICAL: OnceLock<Arc<dyn SchemaProfile>> = OnceLock::new();
    Arc::clone(CANONICAL.get_or_init(|| {
        Arc::new(
            OcsfProfile::try_lake_1_9_with_snapshot_field_types(BTreeMap::new())
                .expect("the empty snapshot inventory is always valid"),
        )
    }))
}

#[derive(serde::Deserialize)]
struct SchemaManifestResponse {
    schema_digest: String,
    field_types: BTreeMap<String, FieldType>,
}

/// Where an entry's inventory came from.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EntrySource {
    /// The tenant's gen1 worker (registry assignment).
    Gen1,
    /// The tenant's query[T], through exactly this cell route.
    Cell {
        query_base_url: String,
        assignment_generation: u64,
    },
}

impl EntrySource {
    fn cell(route: &LakeCellRoute) -> Self {
        Self::Cell {
            query_base_url: route.query_base_url.clone(),
            assignment_generation: route.assignment_generation,
        }
    }
}

struct Entry {
    digest: String,
    profile: Arc<dyn SchemaProfile>,
    verified_at: Instant,
    source: EntrySource,
}

/// NAN-3666: per-tenant gen1 refresh failure streaks, keyed by tenant UUID.
/// The value is when the streak was last reported at warn.
#[derive(Debug, Default)]
struct RefreshFailureLog {
    warned_at: std::sync::Mutex<HashMap<Uuid, Instant>>,
}

/// What [`RefreshFailureLog`] decides for one refresh outcome.
#[derive(Debug, PartialEq, Eq)]
enum FailureReport {
    /// First failure of a streak, or the reminder interval has passed.
    Warn,
    /// A repeat inside the reminder interval.
    Quiet,
}

impl RefreshFailureLog {
    fn failed(&self, tenant_id: Uuid, now: Instant, reminder: Duration) -> FailureReport {
        let mut warned = self
            .warned_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match warned.get(&tenant_id) {
            Some(at) if now.saturating_duration_since(*at) < reminder => FailureReport::Quiet,
            _ => {
                warned.insert(tenant_id, now);
                FailureReport::Warn
            }
        }
    }

    /// Ends the tenant's streak. `true` when there was one (worth one info line).
    fn succeeded(&self, tenant_id: Uuid) -> bool {
        self.warned_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&tenant_id)
            .is_some()
    }

    /// Forget tenants that are no longer refreshed.
    fn retain(&self, keep: impl Fn(&Uuid) -> bool) {
        self.warned_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|tenant_id, _| keep(tenant_id));
    }
}

/// Per-tenant single flight for cell fetches; holds the last failure time.
type CellFetchSlot = Arc<tokio::sync::Mutex<Option<Instant>>>;

/// Tenant-keyed lake schema cache. No entry is ever shared between tenants:
/// the map key is the tenant UUID and every entry is built only from a
/// response the tenant's own assigned worker produced.
pub struct TenantLakeSchemaCache {
    entries: RwLock<HashMap<Uuid, Entry>>,
    http: reqwest::Client,
    max_age: Duration,
    /// The registry [`Self::start`] runs against: resolves a tenant's cell
    /// route for [`ensure_tenant_profile`].
    registry: OnceLock<Arc<SharedLakeWorkerRegistry>>,
    cell_fetches: std::sync::Mutex<HashMap<Uuid, CellFetchSlot>>,
    refresh_failures: RefreshFailureLog,
}

impl std::fmt::Debug for TenantLakeSchemaCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tenants = self.entries.read().unwrap_or_else(std::sync::PoisonError::into_inner).len();
        formatter
            .debug_struct("TenantLakeSchemaCache")
            .field("tenants", &tenants)
            .finish_non_exhaustive()
    }
}

impl TenantLakeSchemaCache {
    pub fn new() -> Result<Self, String> {
        Self::with_max_age(TENANT_SCHEMA_MAX_AGE)
    }

    pub fn with_max_age(max_age: Duration) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(FETCH_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| format!("failed to build tenant schema HTTP client: {error}"))?;
        Ok(Self {
            entries: RwLock::new(HashMap::new()),
            http,
            max_age,
            registry: OnceLock::new(),
            cell_fetches: std::sync::Mutex::new(HashMap::new()),
            refresh_failures: RefreshFailureLog::default(),
        })
    }

    /// The cache identity for a tenant's schema. Exposed so tests (and any
    /// future shared-store backing) can prove it is tenant-scoped.
    pub fn cache_key(tenant_id: Uuid) -> String {
        crate::security_tenant_scope::SecurityTenantScope::EnterpriseShared(tenant_id)
            .cache_key("lake-schema")
    }

    /// The tenant's verified profile, or `None` when it has none (never
    /// fetched, or older than the max age).
    pub fn cached_profile(&self, tenant_id: Uuid) -> Option<Arc<dyn SchemaProfile>> {
        let entries = self.entries.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.get(&tenant_id)?;
        (entry.verified_at.elapsed() <= self.max_age).then(|| Arc::clone(&entry.profile))
    }

    /// The profile to use for `tenant_id`: its own verified inventory, or the
    /// canonical empty-inventory profile. Never another tenant's.
    pub fn profile_or_canonical(&self, tenant_id: Uuid) -> Arc<dyn SchemaProfile> {
        self.cached_profile(tenant_id)
            .unwrap_or_else(canonical_shared_lake_profile)
    }

    /// Tenants that currently hold a verified entry.
    pub fn cached_tenants(&self) -> Vec<Uuid> {
        self.entries
            .read()
            .map(|entries| entries.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Install an inventory for one tenant. `Ok(true)` when the field set
    /// changed. The digest short-circuit is per tenant: two tenants with the
    /// same digest still get their own entries.
    pub fn install(
        &self,
        tenant_id: Uuid,
        digest: &str,
        field_types: BTreeMap<String, FieldType>,
    ) -> Result<bool, String> {
        self.install_from(tenant_id, EntrySource::Gen1, digest, field_types)
    }

    fn install_from(
        &self,
        tenant_id: Uuid,
        source: EntrySource,
        digest: &str,
        field_types: BTreeMap<String, FieldType>,
    ) -> Result<bool, String> {
        if tenant_id.is_nil() {
            return Err("tenant schema requires a tenant identity".to_string());
        }
        if field_types.is_empty() {
            return Err("tenant worker served an empty lake field inventory".to_string());
        }
        {
            let mut entries = self
                .entries
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = entries.get_mut(&tenant_id) {
                if entry.digest == digest && entry.source == source {
                    entry.verified_at = Instant::now();
                    return Ok(false);
                }
            }
        }
        let profile: Arc<dyn SchemaProfile> = Arc::new(
            OcsfProfile::try_lake_1_9_with_snapshot_field_types(field_types)?,
        );
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entries.insert(
            tenant_id,
            Entry {
                digest: digest.to_string(),
                profile,
                verified_at: Instant::now(),
                source,
            },
        );
        Ok(true)
    }

    /// Drop every tenant that is no longer in the registry.
    fn retain_tenants(&self, registry: &SharedLakeWorkerRegistry) {
        {
            let mut entries = self.entries.write().unwrap_or_else(std::sync::PoisonError::into_inner);
            // NAN-2891: a lean-lake cell tenant never keeps a gen1 inventory.
            // NAN-2997: its cell inventory lives exactly as long as the route
            // it was fetched through (a tenant moved to another cell, or
            // re-assigned, refetches from its current query[T]).
            entries.retain(|tenant_id, entry| match &entry.source {
                EntrySource::Gen1 => {
                    registry.assignment(*tenant_id).is_some()
                        && !registry.is_cell_tenant(*tenant_id)
                }
                EntrySource::Cell { .. } => registry
                    .cell_route(*tenant_id)
                    .is_some_and(|route| entry.source == EntrySource::cell(&route)),
            });
        }
    }

    /// Fetch and install one tenant's inventory from its own assigned worker.
    pub async fn refresh_tenant(
        &self,
        assignment: &SharedLakeWorkerAssignment,
    ) -> Result<bool, String> {
        let body = self.fetch(assignment).await?;
        self.install(assignment.tenant_id, &body.schema_digest, body.field_types)
    }

    /// Refresh every registered tenant. Failures are per tenant: one broken
    /// worker keeps its tenant on its own last-good (or canonical) schema and
    /// never affects another tenant.
    pub async fn refresh_all(&self, registry: &SharedLakeWorkerRegistry) {
        self.retain_tenants(registry);
        let refreshed = |tenant_id: Uuid| {
            registry.assignment(tenant_id).is_some() && !registry.is_cell_tenant(tenant_id)
        };
        // A tenant dropped from the registry (or moved to a cell) ends its
        // streak silently; it is no longer refreshed at all.
        self.refresh_failures.retain(|tenant_id| refreshed(*tenant_id));
        let refreshes = registry
            .assignments()
            .filter(|assignment| refreshed(assignment.tenant_id))
            .map(|assignment| async move {
                let outcome = self.refresh_tenant(assignment).await;
                self.report_refresh(assignment.tenant_id, outcome, Instant::now());
            });
        futures::future::join_all(refreshes).await;
    }

    /// Log one gen1 refresh outcome (NAN-3666: one warn per failure streak,
    /// an hourly reminder, one info on recovery).
    fn report_refresh(&self, tenant_id: Uuid, outcome: Result<bool, String>, now: Instant) {
        match outcome {
            Ok(changed) => {
                if self.refresh_failures.succeeded(tenant_id) {
                    tracing::info!(%tenant_id, "tenant lake schema refresh recovered");
                }
                if changed {
                    tracing::info!(%tenant_id, "tenant lake schema installed");
                }
            }
            Err(error) => match self.refresh_failures.failed(tenant_id, now, REFRESH_FAILURE_REMINDER) {
                FailureReport::Warn => tracing::warn!(
                    %tenant_id,
                    %error,
                    reminder_secs = REFRESH_FAILURE_REMINDER.as_secs(),
                    "tenant lake schema refresh failed; keeping that tenant's own last-good schema \
                     (repeats log at debug until it recovers or the reminder interval passes)"
                ),
                FailureReport::Quiet => tracing::debug!(
                    %tenant_id,
                    %error,
                    "tenant lake schema refresh still failing"
                ),
            },
        }
    }

    async fn fetch(
        &self,
        assignment: &SharedLakeWorkerAssignment,
    ) -> Result<SchemaManifestResponse, String> {
        let url = url::Url::parse(&assignment.internal_endpoint)
            .and_then(|base| base.join(SCHEMA_ROUTE))
            .map_err(|error| format!("invalid tenant worker endpoint: {error}"))?;
        // The registry admitted this canonical, private, per-tenant file; it is
        // read per fetch so a rotated credential is picked up. Errors never
        // carry the credential bytes.
        let bearer = std::fs::read_to_string(&assignment.credential_file)
            .map_err(|_| "tenant worker credential reference is unavailable".to_string())?;
        let bearer = bearer.trim();
        if bearer.len() < 32 {
            return Err("tenant worker credential must contain at least 32 characters".to_string());
        }
        let response = self
            .http
            .get(url)
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|error| format!("tenant schema fetch failed: {}", error.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("tenant schema fetch returned HTTP {}", response.status()));
        }
        // The worker stamps every authenticated response with its assignment.
        // A response from any other worker (a mis-routed Service, a replaced
        // pod) is not this tenant's inventory.
        let identity = response
            .headers()
            .get(WORKER_ASSIGNMENT_ID_HEADER)
            .and_then(|value| value.to_str().ok());
        let revision = response
            .headers()
            .get(WORKER_ASSIGNMENT_REVISION_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if identity != Some(assignment.expected_worker_identity.as_str())
            || revision != Some(assignment.expected_worker_revision)
        {
            return Err(
                "tenant schema response assignment identity/revision mismatch".to_string(),
            );
        }
        response
            .json()
            .await
            .map_err(|error| format!("invalid tenant schema response: {error}"))
    }

    /// The cell tenant's verified profile if it was fetched through exactly
    /// `route`, and whether it is still within [`TENANT_SCHEMA_TTL`].
    fn cell_profile(&self, route: &LakeCellRoute) -> Option<(Arc<dyn SchemaProfile>, bool)> {
        let entries = self.entries.read().unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = entries.get(&route.tenant_id)?;
        let age = entry.verified_at.elapsed();
        (entry.source == EntrySource::cell(route) && age <= self.max_age)
            .then(|| (Arc::clone(&entry.profile), age <= TENANT_SCHEMA_TTL))
    }

    /// Fetch and install one cell tenant's inventory from its query[T],
    /// through its own route. `Ok(true)` when the field set changed.
    pub async fn refresh_cell_tenant(&self, route: &LakeCellRoute) -> Result<bool, String> {
        let (digest, field_types) = route.fetch_schema_manifest(FETCH_TIMEOUT).await?;
        self.install_from(
            route.tenant_id,
            EntrySource::cell(route),
            &digest,
            cell_inventory_field_types(field_types)?,
        )
    }

    fn cell_fetch_slot(&self, tenant_id: Uuid) -> CellFetchSlot {
        let mut slots = self
            .cell_fetches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(slots.entry(tenant_id).or_default())
    }

    /// Refresh under the tenant's single-flight slot, honouring the failure
    /// backoff. A concurrent request that waited on the slot finds the
    /// fresh entry and returns without fetching again.
    async fn refresh_cell_tenant_once(
        &self,
        route: &LakeCellRoute,
        mut slot: tokio::sync::OwnedMutexGuard<Option<Instant>>,
    ) {
        if self.cell_profile(route).is_some_and(|(_, fresh)| fresh) {
            return;
        }
        if slot.is_some_and(|failed_at| failed_at.elapsed() < CELL_RETRY_BACKOFF) {
            return;
        }
        match self.refresh_cell_tenant(route).await {
            Ok(changed) => {
                *slot = None;
                if changed {
                    tracing::info!(tenant_id = %route.tenant_id, "lean-lake tenant field inventory installed");
                }
            }
            Err(error) => {
                *slot = Some(Instant::now());
                tracing::warn!(
                    tenant_id = %route.tenant_id,
                    %error,
                    "lean-lake tenant field inventory refresh failed; keeping that tenant's own last-good (or the canonical) schema"
                );
            }
        }
    }

    /// NAN-2997: the profile for a cell tenant's request. A fresh entry is
    /// served as is; a stale one is served while a background refresh runs;
    /// with none, the request waits (bounded) for the first fetch. Never
    /// another tenant's inventory: the entry is keyed by `route.tenant_id`
    /// and bound to this exact route.
    pub async fn ensure_cell_tenant(self: &Arc<Self>, route: &LakeCellRoute) -> Arc<dyn SchemaProfile> {
        match self.cell_profile(route) {
            Some((profile, true)) => profile,
            Some((profile, false)) => {
                if let Ok(slot) = self.cell_fetch_slot(route.tenant_id).try_lock_owned() {
                    let cache = Arc::clone(self);
                    let route = route.clone();
                    tokio::spawn(async move { cache.refresh_cell_tenant_once(&route, slot).await });
                }
                profile
            }
            None => {
                let cache = Arc::clone(self);
                let owned_route = route.clone();
                let slot = self.cell_fetch_slot(route.tenant_id);
                // Spawned so a slow first fetch still installs after this
                // request stops waiting for it.
                let fetch = tokio::spawn(async move {
                    let guard = slot.lock_owned().await;
                    cache.refresh_cell_tenant_once(&owned_route, guard).await;
                });
                let _ = tokio::time::timeout(CELL_FIRST_FETCH_WAIT, fetch).await;
                self.cell_profile(route)
                    .map(|(profile, _)| profile)
                    .unwrap_or_else(canonical_shared_lake_profile)
            }
        }
    }

    /// The profile to validate a request for `tenant_id` with: for a cell
    /// tenant, [`Self::ensure_cell_tenant`] through its current route; for any
    /// other tenant, its verified gen1 inventory or the canonical profile.
    pub async fn ensure_tenant(self: &Arc<Self>, tenant_id: Uuid) -> Arc<dyn SchemaProfile> {
        let route = self
            .registry
            .get()
            .and_then(|registry| registry.cell_route(tenant_id));
        match route {
            Some(route) if route.tenant_id == tenant_id => self.ensure_cell_tenant(&route).await,
            _ => self.profile_or_canonical(tenant_id),
        }
    }

    /// Initial refresh (bounded) plus a background loop at [`TENANT_SCHEMA_TTL`].
    pub async fn start(self: Arc<Self>, registry: Arc<SharedLakeWorkerRegistry>) {
        let _ = self.registry.set(Arc::clone(&registry));
        if tokio::time::timeout(Duration::from_secs(20), self.refresh_all(&registry))
            .await
            .is_err()
        {
            tracing::warn!("initial tenant lake schema load timed out; tenants use the canonical schema until their worker answers");
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(TENANT_SCHEMA_TTL);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                self.refresh_all(&registry).await;
            }
        });
    }
}

static PROCESS_CACHE: OnceLock<Arc<TenantLakeSchemaCache>> = OnceLock::new();

/// Install the process's tenant schema cache (shared mode boot, once).
pub fn install_process_cache(cache: Arc<TenantLakeSchemaCache>) -> Result<(), String> {
    PROCESS_CACHE
        .set(cache)
        .map_err(|_| "tenant lake schema cache is already installed".to_string())
}

pub fn process_cache() -> Option<Arc<TenantLakeSchemaCache>> {
    PROCESS_CACHE.get().cloned()
}

/// The schema profile for one tenant in a shared process: that tenant's own
/// verified inventory, or the canonical empty-inventory profile. This is the
/// ONLY schema lookup shared-mode tenant surfaces may use.
pub fn profile_for_tenant(tenant_id: Uuid) -> Arc<dyn SchemaProfile> {
    match process_cache() {
        Some(cache) => cache.profile_or_canonical(tenant_id),
        None => canonical_shared_lake_profile(),
    }
}

/// NAN-2997: make sure a lean-lake cell tenant's own field inventory is
/// loaded (bounded wait on its first request), then return the tenant's
/// profile. Shared-mode request paths await this before any synchronous
/// [`profile_for_tenant`] lookup; for a gen1 tenant it is that lookup.
pub async fn ensure_tenant_profile(tenant_id: Uuid) -> Arc<dyn SchemaProfile> {
    match process_cache() {
        Some(cache) => cache.ensure_tenant(tenant_id).await,
        None => canonical_shared_lake_profile(),
    }
}

/// Convert query[T]'s part-schema types into profile types, dropping leaves
/// the strict profile cannot address (a producer key such as
/// `unmapped.Event-ID` is not a query identifier) rather than refusing the
/// whole inventory.
pub(crate) fn cell_inventory_field_types(
    field_types: BTreeMap<String, String>,
) -> Result<BTreeMap<String, FieldType>, String> {
    if field_types.len() > MAX_INVENTORY_FIELDS {
        return Err(format!(
            "tenant field inventory has {} leaves (limit {MAX_INVENTORY_FIELDS})",
            field_types.len()
        ));
    }
    Ok(field_types
        .into_iter()
        .filter(|(path, _)| OcsfProfile::is_admissible_snapshot_field_path(path))
        .map(|(path, type_name)| {
            let field_type = serde_json::from_value(serde_json::Value::String(type_name))
                .unwrap_or(FieldType::String);
            (path, field_type)
        })
        .collect())
}

/// Boot helper for api/search/jobs in hosted shared mode: load the
/// server-owned registry, install the process cache and start its refresh
/// loop. A missing registry leaves every tenant on the canonical profile
/// (fail closed: no tenant inventory at all, never a borrowed one).
pub async fn start_for_shared_process() -> Option<Arc<TenantLakeSchemaCache>> {
    let registry = match SharedLakeWorkerRegistry::from_env() {
        Ok(registry) => Arc::new(registry),
        Err(error) => {
            tracing::error!(%error, "shared worker registry unavailable; every tenant uses the canonical lake schema");
            return None;
        }
    };
    let cache = match TenantLakeSchemaCache::new() {
        Ok(cache) => Arc::new(cache),
        Err(error) => {
            tracing::error!(%error, "tenant lake schema cache unavailable");
            return None;
        }
    };
    if let Err(error) = install_process_cache(Arc::clone(&cache)) {
        tracing::warn!(%error, "tenant lake schema cache already installed");
        return process_cache();
    }
    Arc::clone(&cache).start(registry).await;
    Some(cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::schema_fields_response;
    use std::io::Write as _;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TENANT_A: Uuid = Uuid::from_u128(0xa000_0000_0000_4000_8000_0000_0000_000a);
    const TENANT_B: Uuid = Uuid::from_u128(0xb000_0000_0000_4000_8000_0000_0000_000b);

    fn inventory(fields: &[&str]) -> BTreeMap<String, FieldType> {
        let mut map: BTreeMap<String, FieldType> = fields
            .iter()
            .map(|name| ((*name).to_string(), FieldType::String))
            .collect();
        map.insert("src_endpoint.ip".to_string(), FieldType::String);
        map
    }

    fn field_names(profile: &dyn SchemaProfile) -> Vec<String> {
        schema_fields_response(profile)
            .fields
            .into_iter()
            .map(|field| field.name)
            .collect()
    }

    #[test]
    fn tenant_b_never_sees_tenant_a_fields_in_its_field_list() {
        let cache = TenantLakeSchemaCache::new().unwrap();
        cache
            .install(TENANT_A, "digest-a", inventory(&["a_only_ns.secret_leaf", "unmapped.a_only_source_key"]))
            .unwrap();
        cache
            .install(TENANT_B, "digest-b", inventory(&["b_only_ns.leaf"]))
            .unwrap();

        let a = field_names(cache.profile_or_canonical(TENANT_A).as_ref());
        let b = field_names(cache.profile_or_canonical(TENANT_B).as_ref());
        assert!(a.iter().any(|name| name == "a_only_ns.secret_leaf"), "A sees its own field");
        assert!(b.iter().any(|name| name == "b_only_ns.leaf"), "B sees its own field");
        assert!(
            !b.iter().any(|name| name == "a_only_ns.secret_leaf"),
            "tenant A's field leaked into tenant B's field list"
        );
        assert!(!a.iter().any(|name| name == "b_only_ns.leaf"));
        // Producer-owned `unmapped.*` leaves are the most sensitive part of an
        // inventory (they are source keys): never listed for another tenant.
        assert!(a.iter().any(|name| name == "unmapped.a_only_source_key"));
        assert!(!b.iter().any(|name| name.starts_with("unmapped.")), "{b:?}");
    }

    #[test]
    fn a_field_only_tenant_a_has_is_unknown_for_tenant_b() {
        let cache = TenantLakeSchemaCache::new().unwrap();
        cache
            .install(TENANT_A, "digest-a", inventory(&["a_only_ns.secret_leaf"]))
            .unwrap();
        cache
            .install(TENANT_B, "digest-b", inventory(&["b_only_ns.leaf"]))
            .unwrap();
        let a = cache.profile_or_canonical(TENANT_A);
        let b = cache.profile_or_canonical(TENANT_B);
        assert!(a.is_known_field("a_only_ns.secret_leaf"));
        assert!(!b.is_known_field("a_only_ns.secret_leaf"));

        // The nPL validator (Search pre-validation, rule validation) rejects
        // it as unknown for B and does not suggest A's field.
        let query = crate::parse_query("a_only_ns.secret_leaf=\"x\"").expect("parse");
        let errors_b = crate::query::validation::validate_query_fields_with_profile(&query, Some(b.as_ref()));
        assert!(!errors_b.is_empty(), "B must reject a field only A has");
        for error in &errors_b {
            assert!(
                !error.suggestions.iter().any(|s| s.contains("a_only_secret_key")),
                "B was offered A's field as a suggestion: {:?}",
                error.suggestions
            );
        }
        let errors_a = crate::query::validation::validate_query_fields_with_profile(&query, Some(a.as_ref()));
        assert!(errors_a.is_empty(), "A accepts its own field: {errors_a:?}");
    }

    #[test]
    fn a_tenant_without_a_verified_schema_gets_the_canonical_profile_not_a_neighbour() {
        let cache = TenantLakeSchemaCache::new().unwrap();
        cache
            .install(TENANT_A, "digest-a", inventory(&["a_only_ns.secret_leaf"]))
            .unwrap();
        let b = cache.profile_or_canonical(TENANT_B);
        assert!(Arc::ptr_eq(&b, &canonical_shared_lake_profile()));
        assert!(!b.is_known_field("a_only_ns.secret_leaf"));
    }

    #[test]
    fn identical_digests_still_produce_per_tenant_entries() {
        let cache = TenantLakeSchemaCache::new().unwrap();
        cache.install(TENANT_A, "same", inventory(&["a_only_ns.leaf"])).unwrap();
        assert!(cache.install(TENANT_B, "same", inventory(&["b_only_ns.leaf2"])).unwrap());
        assert!(!cache.profile_or_canonical(TENANT_B).is_known_field("a_only_ns.leaf"));
        // Same tenant, same digest: short-circuits.
        assert!(!cache.install(TENANT_A, "same", inventory(&["a_only_ns.leaf"])).unwrap());
    }

    #[test]
    fn schema_cache_keys_are_tenant_scoped() {
        let a = TenantLakeSchemaCache::cache_key(TENANT_A);
        let b = TenantLakeSchemaCache::cache_key(TENANT_B);
        assert_ne!(a, b);
        assert!(a.contains(&TENANT_A.to_string()));
        assert!(b.contains(&TENANT_B.to_string()));
        assert!(!a.contains(&TENANT_B.to_string()));
    }

    #[test]
    fn expired_entries_are_not_served() {
        let cache = TenantLakeSchemaCache::with_max_age(Duration::ZERO).unwrap();
        cache.install(TENANT_A, "d", inventory(&["a_only_ns.leaf"])).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(cache.cached_profile(TENANT_A).is_none());
        assert!(!cache.profile_or_canonical(TENANT_A).is_known_field("a_only_ns.leaf"));
    }

    #[test]
    fn nil_tenant_and_empty_inventory_are_refused() {
        let cache = TenantLakeSchemaCache::new().unwrap();
        assert!(cache.install(Uuid::nil(), "d", inventory(&[])).is_err());
        assert!(cache.install(TENANT_A, "d", BTreeMap::new()).is_err());
    }

    fn assignment_for(
        dir: &tempfile::TempDir,
        tenant_id: Uuid,
        endpoint: &str,
        token: &str,
    ) -> SharedLakeWorkerAssignment {
        let credential = dir.path().join(format!("{tenant_id}.token"));
        let mut file = std::fs::File::create(&credential).unwrap();
        writeln!(file, "{token}").unwrap();
        SharedLakeWorkerAssignment {
            tenant_id,
            internal_endpoint: endpoint.to_string(),
            credential_file: credential,
            expected_worker_identity: format!("worker-{tenant_id}"),
            expected_worker_revision: 7,
            timeout_secs: 30,
            prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots {
                one_hour: "p1h".into(),
                twenty_four_hours: "p24h".into(),
                seven_days: "p7d".into(),
                thirty_days: "p30d".into(),
            },
            prevalence_rarity_threshold: 3,
            prevalence_timeout_secs: 30,
            enrichment_coordinator: None,
            otel_ingest: None,
            erasure_executor: None,
        }
    }

    fn worker_response(tenant_id: Uuid, field: &str) -> ResponseTemplate {
        ResponseTemplate::new(200)
            .insert_header(WORKER_ASSIGNMENT_ID_HEADER, format!("worker-{tenant_id}").as_str())
            .insert_header(WORKER_ASSIGNMENT_REVISION_HEADER, "7")
            .set_body_json(serde_json::json!({
                "schema_version": 1,
                "generation_id": "g",
                "schema_digest": format!("digest-{tenant_id}"),
                "field_types": { "src_endpoint.ip": "string", field: "string" },
            }))
    }

    /// Each tenant's schema comes from ITS worker with ITS credential.
    #[tokio::test]
    async fn each_tenant_is_fetched_from_its_own_worker_with_its_own_credential() {
        let worker_a = MockServer::start().await;
        let worker_b = MockServer::start().await;
        let token_a = "tenant-a-token-0123456789abcdef0123456789";
        let token_b = "tenant-b-token-0123456789abcdef0123456789";
        Mock::given(method("GET"))
            .and(path(SCHEMA_ROUTE))
            .and(header("authorization", format!("Bearer {token_a}").as_str()))
            .respond_with(worker_response(TENANT_A, "a_only_ns.secret_leaf"))
            .expect(1)
            .mount(&worker_a)
            .await;
        Mock::given(method("GET"))
            .and(path(SCHEMA_ROUTE))
            .and(header("authorization", format!("Bearer {token_b}").as_str()))
            .respond_with(worker_response(TENANT_B, "b_only_ns.leaf"))
            .expect(1)
            .mount(&worker_b)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let cache = TenantLakeSchemaCache::new().unwrap();
        cache
            .refresh_tenant(&assignment_for(&dir, TENANT_A, &worker_a.uri(), token_a))
            .await
            .unwrap();
        cache
            .refresh_tenant(&assignment_for(&dir, TENANT_B, &worker_b.uri(), token_b))
            .await
            .unwrap();
        assert!(cache.profile_or_canonical(TENANT_A).is_known_field("a_only_ns.secret_leaf"));
        assert!(!cache.profile_or_canonical(TENANT_B).is_known_field("a_only_ns.secret_leaf"));
        assert!(cache.profile_or_canonical(TENANT_B).is_known_field("b_only_ns.leaf"));
    }

    const ROUTER_TOKEN: &str = "cell-router-token-0123456789abcdef0123456789";

    fn cell_route(dir: &tempfile::TempDir, tenant_id: Uuid, origin: &str) -> LakeCellRoute {
        let token = dir.path().join("router.token");
        std::fs::write(&token, ROUTER_TOKEN).unwrap();
        LakeCellRoute::for_test(tenant_id, origin, token)
    }

    fn cell_manifest_path(tenant_id: Uuid) -> String {
        format!("/v1/tenants/{}/query/v1/schema/manifest", tenant_id.as_hyphenated())
    }

    /// query[T]'s `/v1/schema/manifest` body (NAN-2997), as `tenant_id`.
    fn cell_manifest(tenant_id: Uuid, digest_byte: char, fields: &[(&str, &str)]) -> ResponseTemplate {
        let field_types: serde_json::Map<String, serde_json::Value> = fields
            .iter()
            .map(|(path, kind)| ((*path).to_string(), serde_json::json!(kind)))
            .collect();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "schema_version": 1,
            "tenant_id": tenant_id.as_hyphenated().to_string(),
            "source_mode": "parts",
            "log_head": {"seq": 42, "sha256": "a".repeat(64)},
            "schema_fingerprint": "f",
            "schema_digest": digest_byte.to_string().repeat(64),
            "field_types": field_types,
        }))
    }

    const LEAN_PART_FIELDS: &[(&str, &str)] = &[
        ("time", "timestamp"),
        ("class_uid", "long"),
        ("dst_endpoint.ip", "string"),
        ("prevalence_dest_ip", "integer"),
        ("prevalence_min", "integer"),
        ("enrichments.data.host_count", "array"),
        ("unmapped.vendor.event_id", "string"),
        // Not a query identifier: dropped, the rest of the inventory kept.
        ("unmapped.Event-ID", "string"),
    ];

    fn front_door_accepts(profile: &dyn SchemaProfile, query: &str) -> bool {
        let query = crate::parse_query(query).expect("parse");
        crate::search::service::validate_query_field_names(&query, profile).is_ok()
    }

    /// NAN-2997: a cell tenant's inventory comes from its own query[T]
    /// through its route, and the Search front door then accepts the
    /// inventory-only leaves (the 22nd k6 corpus query) and lists them.
    #[tokio::test]
    async fn cell_tenant_inventory_feeds_the_front_door_and_the_fields_panel() {
        let router = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(cell_manifest_path(TENANT_A)))
            .and(header("authorization", format!("Bearer {ROUTER_TOKEN}").as_str()))
            .respond_with(cell_manifest(TENANT_A, 'a', LEAN_PART_FIELDS))
            // Cached: the second request inside the TTL does not refetch.
            .expect(1)
            .mount(&router)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let route = cell_route(&dir, TENANT_A, &router.uri());
        let cache = Arc::new(TenantLakeSchemaCache::new().unwrap());

        let canonical = canonical_shared_lake_profile();
        assert!(
            !front_door_accepts(canonical.as_ref(), "prevalence_dest_ip<50 | stats count"),
            "precondition: the inventory-less profile rejects the stamp column"
        );

        let profile = cache.ensure_cell_tenant(&route).await;
        assert!(!Arc::ptr_eq(&profile, &canonical), "cell inventory installed");
        for query in [
            "prevalence_dest_ip<50 | stats count",
            "prevalence_dest_ip=1",
            "enrichments.data.host_count>2",
            "unmapped.vendor.event_id=\"4624\"",
            // Contract leaves stay accepted (NAN-2994).
            "metadata.event_code=\"4624\"",
        ] {
            assert!(front_door_accepts(profile.as_ref(), query), "{query}");
        }
        // Inventory types win over the contract.
        assert_eq!(profile.field_type("prevalence_dest_ip"), Some(FieldType::Integer));

        // Fields panel / field stats universe: the stored leaves are listed.
        let names = field_names(cache.profile_or_canonical(TENANT_A).as_ref());
        for stored in ["prevalence_dest_ip", "enrichments.data.host_count", "unmapped.vendor.event_id"] {
            assert!(names.iter().any(|name| name == stored), "{stored} missing from {names:?}");
        }
        assert!(!names.iter().any(|name| name == "unmapped.Event-ID"));

        let again = cache.ensure_cell_tenant(&route).await;
        assert!(Arc::ptr_eq(&profile, &again));
    }

    /// NAN-2997: tenant A's cell inventory is never served for tenant B,
    /// whether B has no entry, or B's route (wrongly) reaches A's query[T].
    #[tokio::test]
    async fn a_cell_tenants_inventory_is_never_served_for_another_tenant() {
        let router = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(cell_manifest_path(TENANT_A)))
            .respond_with(cell_manifest(TENANT_A, 'a', &[("prevalence_dest_ip", "integer"), ("enrichments.data.a_only_key", "string")]))
            .mount(&router)
            .await;
        // Tenant B's path answered by A's process (a mis-wired router).
        Mock::given(method("GET"))
            .and(path(cell_manifest_path(TENANT_B)))
            .respond_with(cell_manifest(TENANT_A, 'a', &[("enrichments.data.a_only_key", "string")]))
            .mount(&router)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(TenantLakeSchemaCache::new().unwrap());
        let a = cache.ensure_cell_tenant(&cell_route(&dir, TENANT_A, &router.uri())).await;
        assert!(a.is_known_field("enrichments.data.a_only_key"));

        let b = cache.ensure_cell_tenant(&cell_route(&dir, TENANT_B, &router.uri())).await;
        assert!(Arc::ptr_eq(&b, &canonical_shared_lake_profile()), "B stays canonical");
        assert!(cache.cached_profile(TENANT_B).is_none());
        assert!(!field_names(cache.profile_or_canonical(TENANT_B).as_ref())
            .iter()
            .any(|name| name == "enrichments.data.a_only_key"));
        let error = cache
            .refresh_cell_tenant(&cell_route(&dir, TENANT_B, &router.uri()))
            .await
            .expect_err("another tenant's inventory must be refused");
        assert!(error.contains("not this tenant"), "{error}");
    }

    /// NAN-2997: a cell entry is bound to the route it was fetched through;
    /// a tenant moved to another cell (or re-assigned) refetches.
    #[tokio::test]
    async fn a_cell_inventory_is_bound_to_its_route() {
        let old_cell = MockServer::start().await;
        let new_cell = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(cell_manifest_path(TENANT_A)))
            .respond_with(cell_manifest(TENANT_A, 'a', &[("enrichments.data.old_key", "array")]))
            .mount(&old_cell)
            .await;
        Mock::given(method("GET"))
            .and(path(cell_manifest_path(TENANT_A)))
            .respond_with(cell_manifest(TENANT_A, 'b', &[("enrichments.data.new_key", "array")]))
            .expect(1)
            .mount(&new_cell)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(TenantLakeSchemaCache::new().unwrap());
        let old_route = cell_route(&dir, TENANT_A, &old_cell.uri());
        assert!(cache.ensure_cell_tenant(&old_route).await.is_known_field("enrichments.data.old_key"));
        let moved = cache.ensure_cell_tenant(&cell_route(&dir, TENANT_A, &new_cell.uri())).await;
        assert!(moved.is_known_field("enrichments.data.new_key"));
        assert!(!moved.is_known_field("enrichments.data.old_key"));
        assert!(cache.cell_profile(&old_route).is_none());
    }

    /// A cell tenant whose query[T] has no manifest route yet (older cell
    /// image) or is down stays on the canonical profile; the failure backs
    /// off instead of costing every request a fetch.
    #[tokio::test]
    async fn a_failed_cell_fetch_falls_back_to_canonical_and_backs_off() {
        let router = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(cell_manifest_path(TENANT_A)))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&router)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let cache = Arc::new(TenantLakeSchemaCache::new().unwrap());
        let route = cell_route(&dir, TENANT_A, &router.uri());
        for _ in 0..3 {
            let profile = cache.ensure_cell_tenant(&route).await;
            assert!(Arc::ptr_eq(&profile, &canonical_shared_lake_profile()));
        }
    }

    /// A worker that answers as another tenant's assignment is refused: its
    /// inventory is never installed under the requesting tenant.
    #[tokio::test]
    async fn a_response_from_another_tenants_worker_is_refused() {
        let worker = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(SCHEMA_ROUTE))
            .respond_with(worker_response(TENANT_A, "a_only_ns.secret_leaf"))
            .mount(&worker)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let cache = TenantLakeSchemaCache::new().unwrap();
        // Tenant B's registry entry routed (wrongly) to tenant A's worker.
        let error = cache
            .refresh_tenant(&assignment_for(
                &dir,
                TENANT_B,
                &worker.uri(),
                "tenant-b-token-0123456789abcdef0123456789",
            ))
            .await
            .expect_err("mismatched assignment must be refused");
        assert!(error.contains("mismatch"), "{error}");
        assert!(cache.cached_profile(TENANT_B).is_none());
        assert!(!cache.profile_or_canonical(TENANT_B).is_known_field("a_only_ns.secret_leaf"));
    }

    /// NAN-3666: a tenant whose worker is gone warns once per streak, not
    /// every refresh; the reminder re-arms it; a recovery ends the streak.
    #[test]
    fn a_failing_tenant_warns_once_per_streak() {
        let log = RefreshFailureLog::default();
        let reminder = Duration::from_secs(3600);
        let t0 = Instant::now();
        assert_eq!(log.failed(TENANT_A, t0, reminder), FailureReport::Warn);
        for minute in 1..60 {
            let now = t0 + Duration::from_secs(60 * minute);
            assert_eq!(log.failed(TENANT_A, now, reminder), FailureReport::Quiet, "minute {minute}");
        }
        // Another tenant's streak is its own.
        assert_eq!(log.failed(TENANT_B, t0 + Duration::from_secs(60), reminder), FailureReport::Warn);
        // The hourly reminder.
        assert_eq!(log.failed(TENANT_A, t0 + reminder, reminder), FailureReport::Warn);
        assert_eq!(log.failed(TENANT_A, t0 + reminder + Duration::from_secs(60), reminder), FailureReport::Quiet);
        // Recovery ends the streak; the next failure is news again.
        assert!(log.succeeded(TENANT_A));
        assert!(!log.succeeded(TENANT_A));
        assert_eq!(log.failed(TENANT_A, t0 + reminder + Duration::from_secs(120), reminder), FailureReport::Warn);
    }

    /// NAN-3666: once the writer prunes a deleted tenant, the reader neither
    /// fetches it nor keeps its schema or failure streak; the surviving
    /// tenant keeps refreshing from its own worker.
    #[tokio::test]
    async fn a_tenant_pruned_from_the_registry_is_not_refreshed_and_live_tenants_are() {
        let live = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(SCHEMA_ROUTE))
            .respond_with(worker_response(TENANT_A, "a_only_ns.leaf"))
            .expect(2)
            .mount(&live)
            .await;
        let gone = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(SCHEMA_ROUTE))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&gone)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let cache = TenantLakeSchemaCache::new().unwrap();
        let token = "tenant-token-0123456789abcdef0123456789";
        let before = SharedLakeWorkerRegistry::from_assignments_for_test(vec![
            assignment_for(&dir, TENANT_A, &live.uri(), token),
            assignment_for(&dir, TENANT_B, &gone.uri(), token),
        ]);
        cache.refresh_all(&before).await;
        assert!(cache.cached_profile(TENANT_A).is_some());
        assert!(cache.cached_profile(TENANT_B).is_none());
        assert!(cache.refresh_failures.warned_at.lock().unwrap().contains_key(&TENANT_B));

        // The pruned revision: tenant B is gone, tenant A is untouched.
        let after = SharedLakeWorkerRegistry::from_assignments_for_test(vec![assignment_for(
            &dir,
            TENANT_A,
            &live.uri(),
            token,
        )]);
        cache.refresh_all(&after).await;
        assert!(cache.profile_or_canonical(TENANT_A).is_known_field("a_only_ns.leaf"));
        assert!(!cache.refresh_failures.warned_at.lock().unwrap().contains_key(&TENANT_B));
        // `expect` on the mocks: A fetched on both passes, B only before the prune.
    }
}
