// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake cell routes (NAN-2865 / NAN-2891).
//!
//! A lean-lake tenant has no gen1 lake reader. Its per-tenant `query[T]`
//! process runs inside a pooled "cell" and is reached through the cell's
//! router at `{cell}/v1/tenants/{T}/query/{rest}`. The platform publishes two
//! server-owned inputs into the api, jobs and search namespaces:
//!
//! * the `lake-cell-routes` ConfigMap (key `routes.json`), mounted as a
//!   DIRECTORY (no subPath) so kubelet's atomic `..data` symlink swap lands:
//!   a flat JSON object mapping each placed tenant UUID to its route. Two
//!   value forms are accepted, and a map may mix them:
//!   - the assignment route (NAN-2921), an object carrying exactly
//!     `{cell_origin, assignment_generation, part_log_writer_epoch,
//!     worker_revision}` from the control head's committed assignment;
//!     missing, non-positive or unknown fields refuse the entry;
//!   - DEPRECATED: a plain origin string,
//!     `{"<uuid>": "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790"}`,
//!     which the platform's renderer still emits until the control head that
//!     serves `read_lean_assignment` (9003480) is live. It carries no
//!     assignment fence: the route gets the fixed revision
//!     [`LAKE_CELL_ASSIGNMENT_REVISION`] for generation, writer epoch and
//!     worker revision, exactly as before NAN-2921, and is marked
//!     [`LakeCellRoute::assignment_fenced`] = false. A one-time warning is
//!     logged per tenant;
//! * the router bearer (`router.token`), a 0400 file. It is one value for
//!   every cell of the cluster, and the router strips it before forwarding,
//!   so a tenant process never sees it. Rotation is a pod roll, but the file
//!   is still re-read on every call (cheap) and never through a resolved
//!   symlink target.
//!
//! The deployment names the files in `NANO_LAKE_CELL_ROUTES_FILE` and
//! `NANO_LAKE_CELL_ROUTER_TOKEN_FILE`. **With neither set, no tenant is a
//! cell tenant and every lake path is exactly the gen1 path** (dark by
//! default).
//!
//! Failure isolation: nothing about cells may fail the process's boot, which
//! would take every gen1 tenant down with it. One variable without the other,
//! an unreadable token, an unparseable routes file or a malformed entry is
//! logged loudly and affects only cell routing: a bad entry is dropped alone;
//! a bad file keeps the last good map (empty at boot).
//!
//! Placement changes are picked up without a restart: the routes file is
//! re-read (by its configured path, following the `..data` swap) at most
//! every [`ROUTES_RELOAD_INTERVAL`], and callers that cache per-tenant views
//! compare the route they cached against the current one.
//!
//! Isolation: a route is looked up only by the authenticated tenant UUID
//! (see [`LakeCellRoutes::route`]). The tenant path segment is rendered from
//! that UUID, never from request input, and the router rejects any other
//! shape. The request body also carries the tenant, which query[T] checks
//! against its own process tenant, and the client checks the response
//! envelope's tenant.
//!
//! Per-tenant bearers (NAN-3289, completes NAN-2904): when
//! `NANO_LAKE_CELL_ROUTER_TENANT_KEY_FILE` names the router's tenant
//! derivation key (64 hex, from the full router token; the platform mounts it
//! only for cell images reporting `router_tenant_tokens_v1`), every cell
//! call presents a bearer derived for exactly its route's tenant, cell and
//! scope (`query` or `detect`, from the route path), which the router
//! checks against the `/v1/tenants/{t}` segment ([`router_bearer`]).
//! Without it, the cluster-wide router token above is presented (its reach
//! is the router's `router_accept_cluster_query_token` legacy mode).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use url::Url;
use uuid::Uuid;

/// Environment variable naming the mounted `routes.json`.
pub const LAKE_CELL_ROUTES_FILE_ENV: &str = "NANO_LAKE_CELL_ROUTES_FILE";
/// Environment variable naming the mounted router-token file.
pub const LAKE_CELL_ROUTER_TOKEN_FILE_ENV: &str = "NANO_LAKE_CELL_ROUTER_TOKEN_FILE";
/// NAN-3492: explicit trusted-local (single-tenant open core) opt-in for the
/// api, search and jobs processes. `nanosiem-lake-cell trusted-local init`
/// renders it into `lake-cell.env`; nothing else sets it. See
/// [`trusted_local_from_env`].
pub const TRUSTED_LOCAL_ENV: &str = "NANO_TRUSTED_LOCAL";
/// NAN-3289: environment variable naming the router's per-tenant derivation
/// key (64 hex). Optional; see [`router_bearer`].
pub const LAKE_CELL_ROUTER_TENANT_KEY_FILE_ENV: &str = "NANO_LAKE_CELL_ROUTER_TENANT_KEY_FILE";
/// Prefix of a per-tenant router token (nanosiem-lake-cell `tenant_token`).
pub const LAKE_CELL_TENANT_TOKEN_PREFIX: &str = "nct1.";

/// Worker "revision" used to key the Search job store and runtime cache of a
/// cell tenant. It only has to be non-zero and stable.
pub const LAKE_CELL_ASSIGNMENT_REVISION: u64 = 1;

/// Prevalence rarity threshold for a cell tenant (the value the platform renders
/// for every tenant).
pub const LAKE_CELL_PREVALENCE_RARITY_THRESHOLD: u64 = 3;

/// How often the routes file is re-read for placement changes.
pub const ROUTES_RELOAD_INTERVAL: Duration = Duration::from_secs(10);

/// Bound on the routes map. The platform caps a pooled cell at 20 tenants; this is
/// a sanity bound on the whole cluster's map, not a placement rule.
const MAX_CELL_ROUTES: usize = 4_096;
const MAX_ROUTES_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 64 * 1024;

/// How long a cell client keeps an idle keep-alive connection. A cell router
/// never closes an idle connection except when its pod is rolled away, and
/// then only after the drain window (`zero_downtime_roll.drain_secs`, 15 s
/// by default, counted from SIGTERM after the writers are released); every
/// connection used during the drain is retired by `Connection: close`. A
/// pool idle timeout below that window means an idle connection this pool
/// could still pick is never one the cell is closing.
pub const LAKE_CELL_POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// The HTTP client builder for every lean-lake cell client (search, IOC,
/// prevalence, risk): the caller's request timeout and
/// [`LAKE_CELL_POOL_IDLE_TIMEOUT`].
pub fn lake_cell_http_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(timeout)
        .pool_idle_timeout(LAKE_CELL_POOL_IDLE_TIMEOUT)
}

/// One tenant's resolved cell route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LakeCellRoute {
    pub tenant_id: Uuid,
    /// Generation from the control head that published this route.
    pub assignment_generation: u64,
    /// Committed tenant part-log writer epoch from the same assignment row.
    pub part_log_writer_epoch: u64,
    /// Tenant worker revision committed in the same assignment.
    pub worker_revision: u64,
    /// True when the three values above came from a committed assignment (the
    /// object route form). False for a deprecated plain-string route: the
    /// values are then the fixed [`LAKE_CELL_ASSIGNMENT_REVISION`] and are NOT
    /// a fence, so nothing may treat them as proof of a current assignment.
    pub assignment_fenced: bool,
    /// The cell router origin, for example
    /// `http://nano-cell-cell-us-1.nano-lake-cells.svc:8790`.
    pub cell_origin: String,
    /// `{cell_origin}/v1/tenants/{tenant_id}/query`: the base that query[T]'s
    /// own routes (`/v1/query`, `/v1/status`, ...) are appended to.
    pub query_base_url: String,
    /// The CONFIGURED router-token path (never a resolved symlink target).
    /// Read on every call.
    pub router_token_file: PathBuf,
}

impl LakeCellRoute {
    pub fn validate_origin(value: &str) -> Result<(), String> {
        validate_cell_origin(value)
    }
    /// The same authenticated tenant and cell, routed to its isolated
    /// scheduled-detection child instead of the interactive query child.
    pub fn for_detection(&self) -> Result<Self, String> {
        self.validate_query_base()?;
        let mut route = self.clone();
        route.query_base_url = format!(
            "{}/v1/tenants/{}/detect",
            route.cell_origin,
            route.tenant_id.as_hyphenated()
        );
        Ok(route)
    }

    /// Build a route from an already-validated origin. The tenant path segment
    /// comes only from the UUID.
    fn new(tenant_id: Uuid, cell_origin: &str, router_token_file: PathBuf) -> Self {
        let origin = cell_origin.trim_end_matches('/').to_string();
        let query_base_url = format!("{origin}/v1/tenants/{}/query", tenant_id.as_hyphenated());
        Self {
            tenant_id,
            assignment_generation: LAKE_CELL_ASSIGNMENT_REVISION,
            part_log_writer_epoch: LAKE_CELL_ASSIGNMENT_REVISION,
            worker_revision: LAKE_CELL_ASSIGNMENT_REVISION,
            assignment_fenced: false,
            cell_origin: origin,
            query_base_url,
            router_token_file,
        }
    }

    /// Test-only constructor that skips origin admission (loopback mock
    /// servers are not private cluster addresses).
    #[cfg(test)]
    pub(crate) fn for_test(tenant_id: Uuid, cell_origin: &str, router_token_file: PathBuf) -> Self {
        Self::new(tenant_id, cell_origin, router_token_file)
    }

    /// The router bearer for this route now: its tenant's derived bearer
    /// when the derivation key is configured, else the router token file
    /// (at least 32 characters, trimmed). See [`router_bearer`].
    pub fn read_router_token(&self) -> Result<String, String> {
        router_bearer(&self.router_token_file, &self.query_base_url)
    }

    /// The cell id of this route's origin (`nano-cell-<cell>.…`), the id
    /// per-tenant router tokens are bound to.
    pub fn cell_id(&self) -> Option<String> {
        cell_id_from_origin(&self.cell_origin)
    }

    /// Read a router bearer from a configured token path.
    pub fn read_token_file(path: &Path) -> Result<String, String> {
        read_router_token(path)
    }

    /// NAN-2997: this tenant's stored field inventory from its query[T]
    /// (`GET /v1/schema/manifest` through the router, via the lean-lake
    /// client, so the tenant path and the response tenant are both checked).
    /// Returns `(schema_digest, leaf path -> part-schema type name)`.
    pub async fn fetch_schema_manifest(
        &self,
        timeout: Duration,
    ) -> Result<(String, std::collections::BTreeMap<String, String>), String> {
        let client = super::lake::LakeQueryClient::new_lake_cell(self, timeout)?;
        let manifest = client
            .lake_cell_schema_manifest()
            .await
            .map_err(|error| error.to_string())?;
        Ok((manifest.schema_digest, manifest.field_types))
    }

    /// Validate that `url` is exactly this tenant's router prefix. Every cell
    /// client constructor calls this, so a tampered route can never point a
    /// tenant at another tenant's path.
    pub fn validate_query_base(&self) -> Result<(), String> {
        let query = format!("/v1/tenants/{}/query", self.tenant_id.as_hyphenated());
        let detect = format!("/v1/tenants/{}/detect", self.tenant_id.as_hyphenated());
        let parsed = Url::parse(&self.query_base_url)
            .map_err(|error| format!("invalid lake cell query URL: {error}"))?;
        let origin = Url::parse(&self.cell_origin)
            .map_err(|error| format!("invalid lake cell origin: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || parsed.origin() != origin.origin()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != query && parsed.path() != detect
        {
            return Err("lake cell query URL must be the tenant's own router prefix".to_string());
        }
        Ok(())
    }
}

/// A snapshot of the cluster's lake-cell route registry: tenant UUID → route.
#[derive(Clone, Debug, Default)]
pub struct LakeCellRoutes {
    routes: HashMap<Uuid, Arc<LakeCellRoute>>,
}

impl LakeCellRoutes {
    /// Parse `routes.json`. A structurally invalid file is an error (the
    /// caller keeps its previous map); a malformed ENTRY is dropped alone and
    /// reported in the second value.
    pub fn parse(bytes: &[u8], router_token_file: &Path) -> Result<(Self, Vec<String>), String> {
        Self::parse_with(bytes, router_token_file, validate_cell_origin)
    }

    /// [`Self::parse`] with an explicit origin admission rule (the
    /// trusted-local single-tenant mode admits compose service names).
    fn parse_with(
        bytes: &[u8],
        router_token_file: &Path,
        validate_origin: fn(&str) -> Result<(), String>,
    ) -> Result<(Self, Vec<String>), String> {
        // `serde_json::Map` would silently keep the last of two duplicate keys;
        // read the raw entries so a duplicated tenant is refused.
        let raw = parse_flat_object(bytes)?;
        if raw.len() > MAX_CELL_ROUTES {
            return Err("lake cell routes map exceeds its tenant bound".to_string());
        }
        let mut rejected = Vec::new();
        let mut counts: HashMap<String, usize> = HashMap::new();
        for (key, _) in &raw {
            *counts.entry(key.clone()).or_default() += 1;
        }
        let mut routes = HashMap::with_capacity(raw.len());
        for (key, value) in raw {
            if counts.get(&key).copied().unwrap_or(0) > 1 {
                // Ambiguous: never pick one of two placements.
                rejected.push(format!("tenant {key:?} is listed more than once"));
                continue;
            }
            let Some(tenant_id) = Uuid::parse_str(&key)
                .ok()
                .filter(|tenant| !tenant.is_nil() && tenant.as_hyphenated().to_string() == key)
            else {
                rejected.push(format!(
                    "key {key:?} is not a lowercase hyphenated tenant UUID"
                ));
                continue;
            };
            let (origin, fence) =
                if let Some(object) = value.as_object() {
                    let Some(origin) = object.get("cell_origin").and_then(|v| v.as_str()) else {
                        rejected.push(format!("route for {tenant_id} has no cell_origin"));
                        continue;
                    };
                    let Some(generation) = object
                        .get("assignment_generation")
                        .and_then(|v| v.as_u64())
                        .filter(|g| *g > 0)
                    else {
                        rejected.push(format!(
                            "route for {tenant_id} has no positive assignment_generation"
                        ));
                        continue;
                    };
                    let Some(worker_revision) = object
                        .get("worker_revision")
                        .and_then(|v| v.as_u64())
                        .filter(|g| *g > 0)
                    else {
                        rejected.push(format!(
                            "route for {tenant_id} has no positive worker_revision"
                        ));
                        continue;
                    };
                    let Some(writer_epoch) = object
                        .get("part_log_writer_epoch")
                        .and_then(|v| v.as_u64())
                        .filter(|g| *g > 0)
                    else {
                        rejected.push(format!(
                            "route for {tenant_id} has no positive part_log_writer_epoch"
                        ));
                        continue;
                    };
                    if object.len() != 4 {
                        rejected.push(format!("route for {tenant_id} has unexpected fields"));
                        continue;
                    }
                    (origin, Some((generation, writer_epoch, worker_revision)))
                } else if let Some(origin) = value.as_str() {
                    // Deprecated plain-origin form: no assignment fence.
                    (origin, None)
                } else {
                    rejected.push(format!(
                        "route for {tenant_id} is neither an assignment route nor an origin string"
                    ));
                    continue;
                };
            if let Err(error) = validate_origin(origin) {
                rejected.push(format!("route for {tenant_id} is invalid: {error}"));
                continue;
            }
            let mut route = LakeCellRoute::new(tenant_id, origin, router_token_file.to_path_buf());
            if let Some((generation, writer_epoch, worker_revision)) = fence {
                route.assignment_generation = generation;
                route.part_log_writer_epoch = writer_epoch;
                route.worker_revision = worker_revision;
                route.assignment_fenced = true;
            }
            routes.insert(tenant_id, Arc::new(route));
        }
        Ok((Self { routes }, rejected))
    }

    /// The route of exactly this authenticated tenant, or `None`.
    pub fn route(&self, tenant_id: Uuid) -> Option<&Arc<LakeCellRoute>> {
        self.routes.get(&tenant_id)
    }

    pub fn routes(&self) -> impl Iterator<Item = &Arc<LakeCellRoute>> {
        self.routes.values()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_routes_for_test(routes: impl IntoIterator<Item = LakeCellRoute>) -> Self {
        Self {
            routes: routes
                .into_iter()
                .map(|route| (route.tenant_id, Arc::new(route)))
                .collect(),
        }
    }
}

/// NAN-3867: the sibling key of `routes.json` in the `lake-cell-routes`
/// ConfigMap that declares, per tenant, the lean erasure executor its cell
/// runs: `{"<tenant uuid>": {"executor_node": "lean-cell:<cell id>"}}`.
/// the platform renders an entry only for a cell image reporting
/// `lean_erasure_v1`. Optional by design, so neither repo must roll first:
/// an older reader ignores the key, and without it nothing is declared.
pub const LAKE_CELL_ERASURE_EXECUTORS_FILE: &str = "erasure-executors.json";

/// Parsed `erasure-executors.json`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LakeCellErasureExecutors {
    executors: HashMap<Uuid, String>,
}

impl LakeCellErasureExecutors {
    /// Fixed declarations (tests and hand-built registries).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (Uuid, String)>) -> Self {
        Self { executors: pairs.into_iter().collect() }
    }

    /// Parse the file. A structurally invalid file is an error; a malformed
    /// entry is dropped alone and reported.
    pub fn parse(bytes: &[u8]) -> Result<(Self, Vec<String>), String> {
        let raw = parse_flat_object(bytes)?;
        if raw.len() > MAX_CELL_ROUTES {
            return Err("erasure executor map exceeds its tenant bound".to_string());
        }
        let mut counts: HashMap<String, usize> = HashMap::new();
        for (key, _) in &raw {
            *counts.entry(key.clone()).or_default() += 1;
        }
        let (mut executors, mut rejected) = (HashMap::new(), Vec::new());
        for (key, value) in raw {
            if counts.get(&key).copied().unwrap_or(0) > 1 {
                rejected.push(format!("tenant {key:?} is declared more than once"));
                continue;
            }
            let Some(tenant_id) = Uuid::parse_str(&key)
                .ok()
                .filter(|tenant| !tenant.is_nil() && tenant.as_hyphenated().to_string() == key)
            else {
                rejected.push(format!("key {key:?} is not a lowercase hyphenated tenant UUID"));
                continue;
            };
            let node = value.as_object().filter(|object| object.len() == 1)
                .and_then(|object| object.get("executor_node")).and_then(|node| node.as_str());
            match node {
                Some(node) if valid_executor_node(node) => {
                    executors.insert(tenant_id, node.to_string());
                }
                _ => rejected.push(format!("erasure executor for {tenant_id} is not exactly {{\"executor_node\": <node>}}")),
            }
        }
        Ok((Self { executors }, rejected))
    }

    pub fn executor(&self, tenant_id: Uuid) -> Option<&str> {
        self.executors.get(&tenant_id).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.executors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.executors.is_empty()
    }
}

/// `lake_erasure_work_orders.executor_node` is 1..=128 chars; the platform
/// renders `lean-cell:<cell id>`.
fn valid_executor_node(node: &str) -> bool {
    node.strip_prefix("lean-cell:").is_some_and(|cell| {
        !cell.is_empty()
            && node.len() <= 128
            && cell.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

/// Where the current [`LakeCellRoutes`] come from.
#[derive(Debug)]
enum Origin {
    /// Fixed map (tests, and callers that build a registry by hand).
    Static,
    /// The mounted ConfigMap file, re-read by its configured path.
    File {
        routes_file: PathBuf,
        /// Last bytes parsed (successfully or not), so an unchanged file is
        /// not re-parsed or re-logged.
        last_bytes: Mutex<Option<Vec<u8>>>,
        last_check: Mutex<Instant>,
        /// NAN-3867: last `erasure-executors.json` bytes seen (`Some(None)`:
        /// the file was absent), so an unchanged file is not re-parsed.
        executors_last: Mutex<Option<Option<Vec<u8>>>>,
    },
}

/// The live route registry. Cheap to query; reloads the routes file at most
/// every [`ROUTES_RELOAD_INTERVAL`].
#[derive(Debug)]
pub struct LakeCellRouteSource {
    origin: Origin,
    router_token_file: PathBuf,
    current: RwLock<Arc<LakeCellRoutes>>,
    /// Tenants already warned about a deprecated plain-string route.
    string_route_warned: Mutex<HashSet<Uuid>>,
    /// NAN-3867: tenants whose cell runs the lean erasure executor
    /// (`erasure-executors.json`, a sibling of `routes.json`).
    erasure_executors: RwLock<Arc<LakeCellErasureExecutors>>,
    /// NAN-4149: true once a routes map has been ACCEPTED (parsed) at least
    /// once in this process (always true for a fixed map). Until then an empty
    /// route map means "not loaded yet", not "no tenant is placed".
    loaded: std::sync::atomic::AtomicBool,
}

impl LakeCellRouteSource {
    /// Load from the environment. `None` when neither variable is set, or
    /// when the configuration is unusable (logged; cells stay dark, gen1 is
    /// unaffected).
    pub fn from_env() -> Option<Arc<Self>> {
        let routes = env_path(LAKE_CELL_ROUTES_FILE_ENV);
        let token = env_path(LAKE_CELL_ROUTER_TOKEN_FILE_ENV);
        match (routes, token) {
            (None, None) => None,
            (Some(routes), Some(token)) => Some(Arc::new(Self::from_files(&routes, &token))),
            _ => {
                tracing::error!(
                    metric = "lean_lake_cell_routes_misconfigured",
                    "{LAKE_CELL_ROUTES_FILE_ENV} and {LAKE_CELL_ROUTER_TOKEN_FILE_ENV} must be set together; lean-lake cell routing is OFF (gen1 tenants unaffected)"
                );
                None
            }
        }
    }

    /// Build from the mounted files. Never fails: problems are logged and
    /// leave cell routing empty until the files are fixed.
    pub fn from_files(routes_file: &Path, router_token_file: &Path) -> Self {
        if let Err(error) = admit_router_token_file(router_token_file) {
            tracing::error!(
                metric = "lean_lake_cell_router_token_invalid",
                error = %error,
                "lean-lake cell router token is not usable; every cell tenant's lake calls will fail until it is fixed"
            );
        }
        let source = Self {
            origin: Origin::File {
                routes_file: routes_file.to_path_buf(),
                last_bytes: Mutex::new(None),
                last_check: Mutex::new(Instant::now()),
                executors_last: Mutex::new(None),
            },
            router_token_file: router_token_file.to_path_buf(),
            current: RwLock::new(Arc::new(LakeCellRoutes::default())),
            string_route_warned: Mutex::new(HashSet::new()),
            erasure_executors: RwLock::new(Arc::new(LakeCellErasureExecutors::default())),
            loaded: std::sync::atomic::AtomicBool::new(false),
        };
        source.reload();
        source
    }

    /// A fixed route map (no file, no reload).
    pub fn fixed(routes: LakeCellRoutes) -> Self {
        let router_token_file = routes
            .routes()
            .next()
            .map(|route| route.router_token_file.clone())
            .unwrap_or_default();
        Self {
            origin: Origin::Static,
            router_token_file,
            current: RwLock::new(Arc::new(routes)),
            string_route_warned: Mutex::new(HashSet::new()),
            erasure_executors: RwLock::new(Arc::new(LakeCellErasureExecutors::default())),
            loaded: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// NAN-4149: whether a routes map has been accepted at least once (a
    /// fixed map always has). Re-checks a due reload first, so a map that
    /// arrives after boot is seen without waiting for another caller.
    pub fn has_loaded(&self) -> bool {
        if !self.loaded.load(std::sync::atomic::Ordering::Acquire) {
            let _ = self.current();
        }
        self.loaded.load(std::sync::atomic::Ordering::Acquire)
    }

    /// A fixed route map plus fixed erasure-executor declarations (tests).
    pub fn fixed_with_erasure_executors(routes: LakeCellRoutes, executors: LakeCellErasureExecutors) -> Self {
        let source = Self::fixed(routes);
        *source.erasure_executors.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(executors);
        source
    }

    /// NAN-3867: the erasure executor node declared for this tenant's cell,
    /// only while the tenant has a FENCED (committed-assignment) route. A
    /// declaration for an unrouted tenant, or one on the deprecated string
    /// form, declares nothing.
    pub fn erasure_executor(&self, tenant_id: Uuid) -> Option<String> {
        let route = self.route(tenant_id)?;
        if !route.assignment_fenced {
            return None;
        }
        self.erasure_executors
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .executor(tenant_id)
            .map(str::to_owned)
    }

    /// The current routes, reloading first when the interval has passed.
    pub fn current(&self) -> Arc<LakeCellRoutes> {
        if let Origin::File { last_check, .. } = &self.origin {
            // NAN-3080: never poison-stuck (a poisoned lock used to stop
            // route reloads for the life of the process).
            let due = {
                let mut last = last_check.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                if last.elapsed() >= ROUTES_RELOAD_INTERVAL {
                    *last = Instant::now();
                    true
                } else {
                    false
                }
            };
            if due {
                self.reload();
            }
        }
        self.snapshot()
    }

    fn snapshot(&self) -> Arc<LakeCellRoutes> {
        // NAN-3080: a poisoned lock used to return EMPTY routes (every tenant
        // unroutable) forever; the Arc swap is atomic, so the value is sound.
        Arc::clone(&self.current.read().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// The route of exactly this authenticated tenant, if placed.
    pub fn route(&self, tenant_id: Uuid) -> Option<Arc<LakeCellRoute>> {
        self.current().route(tenant_id).cloned()
    }

    /// Re-read the routes file now (by its configured path).
    pub fn reload(&self) {
        let Origin::File {
            routes_file,
            last_bytes,
            executors_last,
            ..
        } = &self.origin
        else {
            return;
        };
        self.reload_erasure_executors(routes_file, executors_last);
        let bytes = match read_bounded(routes_file, MAX_ROUTES_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(
                    metric = "lean_lake_cell_routes_unreadable",
                    path = %routes_file.display(),
                    error = %error,
                    "lean-lake cell routes file is unreadable; keeping the last good routes"
                );
                return;
            }
        };
        if last_bytes.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_deref()
            == Some(bytes.as_slice())
        {
            return;
        }
        match LakeCellRoutes::parse(&bytes, &self.router_token_file) {
            Ok((routes, rejected)) => {
                for reason in &rejected {
                    tracing::error!(
                        metric = "lean_lake_cell_route_rejected",
                        reason = %reason,
                        "lean-lake cell route entry rejected; that tenant is not routed to a cell"
                    );
                }
                self.warn_string_routes_once(&routes);
                tracing::info!(
                    routes = routes.len(),
                    rejected = rejected.len(),
                    "lean-lake cell routes loaded"
                );
                *self.current.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
                    Arc::new(routes);
                self.loaded.store(true, std::sync::atomic::Ordering::Release);
            }
            Err(error) => {
                tracing::error!(
                    metric = "lean_lake_cell_routes_invalid",
                    path = %routes_file.display(),
                    error = %error,
                    "lean-lake cell routes file is invalid; keeping the last good routes"
                );
            }
        }
        *last_bytes.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(bytes);
    }
}

impl LakeCellRouteSource {
    /// NAN-3867: re-read the optional `erasure-executors.json` beside
    /// `routes.json`. Absent = no tenant declares an executor (every older
    /// the platform render); invalid = keep the last good declarations.
    fn reload_erasure_executors(&self, routes_file: &Path, executors_last: &Mutex<Option<Option<Vec<u8>>>>) {
        let path = routes_file.with_file_name(LAKE_CELL_ERASURE_EXECUTORS_FILE);
        let bytes = if path.exists() {
            match read_bounded(&path, MAX_ROUTES_FILE_BYTES) {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    tracing::error!(metric = "lean_lake_cell_erasure_executors_unreadable", path = %path.display(), error = %error,
                        "lean-lake erasure executor declarations are unreadable; keeping the last good set");
                    return;
                }
            }
        } else {
            None
        };
        let mut last = executors_last.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if last.as_ref() == Some(&bytes) {
            return;
        }
        let parsed = match &bytes {
            None => Ok((LakeCellErasureExecutors::default(), Vec::new())),
            Some(bytes) => LakeCellErasureExecutors::parse(bytes),
        };
        match parsed {
            Ok((executors, rejected)) => {
                for reason in &rejected {
                    tracing::error!(metric = "lean_lake_cell_erasure_executor_rejected", reason = %reason,
                        "lean-lake erasure executor declaration rejected; that tenant's erasure requests stay deferred");
                }
                tracing::info!(declared = executors.len(), rejected = rejected.len(), "lean-lake erasure executor declarations loaded");
                *self.erasure_executors.write().unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(executors);
            }
            Err(error) => {
                tracing::error!(metric = "lean_lake_cell_erasure_executors_invalid", path = %path.display(), error = %error,
                    "lean-lake erasure executor declarations are invalid; keeping the last good set");
            }
        }
        *last = Some(bytes);
    }

    /// Log the deprecation of each plain-string route once per tenant for the
    /// life of the process. Returns the tenants warned about now.
    fn warn_string_routes_once(&self, routes: &LakeCellRoutes) -> Vec<Uuid> {
        let mut warned =
            self.string_route_warned.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut newly = Vec::new();
        for route in routes.routes().filter(|route| !route.assignment_fenced) {
            if warned.insert(route.tenant_id) {
                tracing::warn!(
                    metric = "lean_lake_cell_string_route_deprecated",
                    tenant_id = %route.tenant_id,
                    "lean-lake cell route is a plain origin string (deprecated): it carries no assignment generation or part-log writer epoch fence; the control plane must render the assignment object form"
                );
                newly.push(route.tenant_id);
            }
        }
        newly
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > max {
        return Err("file exceeds its size bound".to_string());
    }
    Ok(bytes)
}

/// Parse `{"k": <v>, ...}` into ordered pairs (duplicates preserved).
fn parse_flat_object(bytes: &[u8]) -> Result<Vec<(String, serde_json::Value)>, String> {
    struct Pairs(Vec<(String, serde_json::Value)>);
    impl<'de> serde::Deserialize<'de> for Pairs {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Visitor;
            impl<'de> serde::de::Visitor<'de> for Visitor {
                type Value = Pairs;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an object mapping tenant UUIDs to cell origins")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<Pairs, A::Error> {
                    let mut out = Vec::new();
                    while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                        out.push((key, value));
                    }
                    Ok(Pairs(out))
                }
            }
            deserializer.deserialize_map(Visitor)
        }
    }
    serde_json::from_slice::<Pairs>(bytes)
        .map(|pairs| pairs.0)
        .map_err(|error| format!("invalid lake cell routes JSON: {error}"))
}

/// A cell origin is an HTTP(S) origin with an explicit port on private IP
/// space or Kubernetes service DNS, like a gen1 worker endpoint. A path,
/// query, fragment or userinfo is refused: the tenant path is added here.
fn validate_cell_origin(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value).map_err(|error| format!("not a URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err("must be an HTTP(S) origin with an explicit port and no path".to_string());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "must have a host".to_string())?;
    let private_ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| match address {
            std::net::IpAddr::V4(address) => address.is_private() || address.is_link_local(),
            std::net::IpAddr::V6(address) => {
                address.is_unique_local() || address.is_unicast_link_local()
            }
        });
    let cluster_dns = host.ends_with(".svc") || host.ends_with(".svc.cluster.local");
    if !private_ip && !cluster_dns {
        return Err("must use private IP space or Kubernetes service DNS".to_string());
    }
    Ok(())
}

/// Client timeout for dedicated-cell prevalence reads (the cell search
/// budget, `search::lake::DEFAULT_LAKE_CELL_TIMEOUT_SECS`).
pub const DEDICATED_CELL_TIMEOUT_SECS: u64 = 130;

/// Trusted-local single-tenant mode (NAN-3492, open core on lean).
///
/// A self-hosted install runs ONE tenant in one dedicated cell and has no
/// gen1 query worker. `nanosiem-lake-cell trusted-local init` renders the
/// same `routes.json` + query-only router token the hosted control plane
/// mounts, and the api, search and jobs processes route that tenant's
/// search, prevalence, IOC and schema reads to its `query[T]`.
///
/// Opt-in and dark by default: it applies only when
/// - the process is NOT the hosted shared deployment mode (shared mode
///   keeps its per-request registry), and
/// - both [`LAKE_CELL_ROUTES_FILE_ENV`] and
///   [`LAKE_CELL_ROUTER_TOKEN_FILE_ENV`] are set.
///
/// Then `NANO_LAKE_TENANT_ID` must be a lowercase UUID with a route in the
/// file, and `NANO_LAKE_QUERY_URL` must be unset (one backend, never two).
/// Any misconfiguration is an error, never a silent fall back to gen1.
/// Route origins may be compose service names (`http://lake-cell:8790`)
/// or loopback, besides the private addresses the hosted form accepts.
pub fn dedicated_route_from_env() -> Result<Option<Arc<LakeCellRoute>>, String> {
    dedicated_route_from_lookup(&|name| std::env::var(name).ok())
}

/// Whether this process runs as the trusted-local single-tenant install
/// (NAN-3492): [`TRUSTED_LOCAL_ENV`] is exactly `1` or `true` and the process
/// is not the hosted shared deployment mode. Absent (every hosted
/// deployment) is false. It gates what only a trusted-local install may do:
/// admit tenantless durable result references, treat the installation's own
/// job store as the cell job runner, and stamp lake findings with the lake
/// tenant as their security tenant. Routing to a dedicated cell
/// ([`dedicated_route_from_env`]) does not imply it.
pub fn trusted_local_from_env() -> bool {
    trusted_local_from_lookup(&|name| std::env::var(name).ok())
}

pub(crate) fn trusted_local_from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> bool {
    if lookup("DEPLOYMENT_MODE").is_some_and(|mode| mode.trim() == "enterprise_shared") {
        return false;
    }
    lookup(TRUSTED_LOCAL_ENV).is_some_and(|value| matches!(value.trim(), "1" | "true"))
}

/// Register the trusted-local install's lake tenant in `tenants` (NAN-3492).
///
/// A trusted-local install stamps lake findings, late replays and event
/// publications with its own lake tenant as `security_tenant_id`. The
/// enterprise overlay (migration 9000084) foreign-keys that column to
/// `tenants(id)`, and nothing else on a single-tenant install creates that
/// row, so every enterprise finding insert failed the FK and no finding,
/// risk or alert signal reached the lake. The open schema has no FK, but the
/// row is harmless there and keeps one tenant model across editions.
///
/// Idempotent and run at every API / jobs boot. Returns the tenant it
/// ensured, `None` outside trusted-local. Fails boot when the row cannot be
/// made active: a suspended or deleted local tenant is an operator decision
/// this must not silently undo.
pub async fn ensure_trusted_local_tenant(pool: &sqlx::PgPool) -> Result<Option<Uuid>, String> {
    let lookup = |name: &str| std::env::var(name).ok();
    if !trusted_local_from_lookup(&lookup) {
        return Ok(None);
    }
    let tenant = trusted_local_tenant_from_lookup(&lookup)?;
    sqlx::query(
        "INSERT INTO tenants (id, slug, display_name, status) \
         VALUES ($1, $2, 'Local', 'active') ON CONFLICT DO NOTHING",
    )
    .bind(tenant)
    .bind(trusted_local_tenant_slug(tenant))
    .execute(pool)
    .await
    .map_err(|error| format!("register the trusted-local tenant: {error}"))?;
    let status: Option<String> = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
        .bind(tenant)
        .fetch_optional(pool)
        .await
        .map_err(|error| format!("read the trusted-local tenant: {error}"))?;
    match status.as_deref() {
        Some("active") => Ok(Some(tenant)),
        Some(other) => Err(format!("the trusted-local tenant {tenant} is {other}, not active")),
        None => Err(format!(
            "the trusted-local tenant {tenant} could not be registered (its slug is taken by another tenant)"
        )),
    }
}

fn trusted_local_tenant_from_lookup(lookup: &dyn Fn(&str) -> Option<String>) -> Result<Uuid, String> {
    lookup("NANO_LAKE_TENANT_ID")
        .and_then(|value| Uuid::parse_str(value.trim()).ok())
        .filter(|tenant| !tenant.is_nil())
        .ok_or_else(|| "a trusted-local install needs a non-nil UUID NANO_LAKE_TENANT_ID".to_string())
}

/// `local-<first 8 hex>`: fits `tenants_slug_shape` and cannot collide with
/// the compatibility tenant's `default` slug.
fn trusted_local_tenant_slug(tenant: Uuid) -> String {
    format!("local-{}", &tenant.simple().to_string()[..8])
}

pub(crate) fn dedicated_route_from_lookup(
    lookup: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Arc<LakeCellRoute>>, String> {
    let set = |name: &str| lookup(name).filter(|value| !value.trim().is_empty());
    if set("DEPLOYMENT_MODE").is_some_and(|mode| mode.trim() == "enterprise_shared") {
        return Ok(None);
    }
    let (routes_file, token_file) = match (
        set(LAKE_CELL_ROUTES_FILE_ENV),
        set(LAKE_CELL_ROUTER_TOKEN_FILE_ENV),
    ) {
        (None, None) => return Ok(None),
        (Some(routes), Some(token)) => (PathBuf::from(routes), PathBuf::from(token)),
        _ => {
            return Err(format!(
                "{LAKE_CELL_ROUTES_FILE_ENV} and {LAKE_CELL_ROUTER_TOKEN_FILE_ENV} must be set together"
            ))
        }
    };
    if set("NANO_LAKE_QUERY_URL").is_some() {
        return Err(format!(
            "NANO_LAKE_QUERY_URL and {LAKE_CELL_ROUTES_FILE_ENV} are both set; a dedicated deployment \
             uses exactly one lake backend (unset NANO_LAKE_QUERY_URL for the lean cell)"
        ));
    }
    let tenant = set("NANO_LAKE_TENANT_ID")
        .ok_or_else(|| "NANO_LAKE_TENANT_ID is required for the dedicated lake cell".to_string())?;
    let tenant_id = Uuid::parse_str(tenant.trim())
        .ok()
        .filter(|id| !id.is_nil() && id.as_hyphenated().to_string() == tenant.trim())
        .ok_or_else(|| {
            "NANO_LAKE_TENANT_ID must be a lowercase hyphenated UUID for the lean cell \
             (trusted-local init mints one)"
                .to_string()
        })?;
    admit_router_token_file(&token_file)?;
    let bytes = read_bounded(&routes_file, MAX_ROUTES_FILE_BYTES)?;
    let (routes, rejected) =
        LakeCellRoutes::parse_with(&bytes, &token_file, validate_trusted_local_origin)?;
    let route = routes.route(tenant_id).cloned().ok_or_else(|| {
        let why = rejected.join("; ");
        format!("{} has no usable route for tenant {tenant_id}{}", routes_file.display(),
            if why.is_empty() { String::new() } else { format!(" ({why})") })
    })?;
    if routes.len() != 1 {
        return Err(format!("{} must hold exactly one tenant in dedicated mode", routes_file.display()));
    }
    route.validate_query_base()?;
    Ok(Some(route))
}

/// The hosted origin rule plus single-label service names (Docker compose
/// DNS) and loopback, for the trusted-local single-tenant mode only.
fn validate_trusted_local_origin(value: &str) -> Result<(), String> {
    if validate_cell_origin(value).is_ok() {
        return Ok(());
    }
    let parsed = Url::parse(value).map_err(|error| format!("not a URL: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err("must be an HTTP(S) origin with an explicit port and no path".to_string());
    }
    let host = parsed.host_str().ok_or_else(|| "must have a host".to_string())?;
    let loopback = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback());
    let service_name = !host.is_empty()
        && host.len() <= 63
        && host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !host.starts_with('-');
    if loopback || service_name || host == "localhost" {
        Ok(())
    } else {
        Err("must use a private address, a compose service name or loopback".to_string())
    }
}

/// Admit the router-token reference like a gen1 worker credential: absolute,
/// a regular file (following the mount's symlinks), private (no group/other
/// bits), at least 32 characters. The configured path is what is kept.
fn admit_router_token_file(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "{LAKE_CELL_ROUTER_TOKEN_FILE_ENV} must be an absolute path"
        ));
    }
    let metadata =
        std::fs::metadata(path).map_err(|_| "lake cell router token is unavailable".to_string())?;
    if !metadata.is_file() {
        return Err("lake cell router token is unavailable".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "lake cell router token is not private (mount it with mode 0400)".to_string(),
            );
        }
    }
    read_router_token(path).map(|_| ())
}

/// NAN-3289: the cell id in the platform cell origin. The platform renders every
/// origin as `http(s)://nano-cell-<cell id>.<namespace>.svc[.cluster.local]:<port>`
/// (`lakeCellUrl`); anything else has no derivable cell id.
pub fn cell_id_from_origin(origin: &str) -> Option<String> {
    let host = Url::parse(origin).ok()?.host_str()?.to_string();
    let (first, rest) = host.split_once('.')?;
    let cell = first.strip_prefix("nano-cell-")?;
    let valid = !cell.is_empty()
        && cell.len() <= 63
        && cell.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && (rest.ends_with(".svc") || rest.ends_with(".svc.cluster.local"));
    valid.then(|| cell.to_string())
}

/// `(tenant, cell id, scope)` of a cell router URL
/// (`{origin}/v1/tenants/{tenant}/{query|detect}[/…]`).
fn bearer_target(url: &str) -> Option<(String, String, &'static str)> {
    let parsed = Url::parse(url).ok()?;
    let origin = parsed.origin().ascii_serialization();
    let cell = cell_id_from_origin(&origin)?;
    let mut segments = parsed.path_segments()?;
    if segments.next()? != "v1" || segments.next()? != "tenants" {
        return None;
    }
    let tenant = segments.next()?.to_string();
    let scope = match segments.next()? {
        "query" => "query",
        "detect" => "detect",
        _ => return None,
    };
    (!tenant.is_empty()).then_some((tenant, cell, scope))
}

/// The per-tenant router bearer: `"nct1." ‖ hex(HMAC-SHA256(key,
/// "v1" ‖ 0 ‖ tenant ‖ 0 ‖ cell ‖ 0 ‖ scope))`, byte-identical to
/// nanosiem-lake-cell `tenant_token::TenantKey::token`.
pub fn derive_tenant_router_token(tenant_key: &[u8; 32], tenant: &str, cell_id: &str, scope: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(tenant_key).expect("HMAC takes any key length");
    mac.update(b"v1");
    for part in [tenant.as_bytes(), cell_id.as_bytes(), scope.as_bytes()] {
        mac.update(&[0]);
        mac.update(part);
    }
    format!("{LAKE_CELL_TENANT_TOKEN_PREFIX}{}", hex::encode(mac.finalize().into_bytes()))
}

fn read_tenant_key(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let bytes = zeroize::Zeroizing::new(
        read_bounded(path, 256).map_err(|_| "lake cell router tenant key is unavailable".to_string())?,
    );
    let text = std::str::from_utf8(&bytes).map_err(|_| "lake cell router tenant key is not UTF-8".to_string())?;
    let raw = zeroize::Zeroizing::new(
        hex::decode(text.trim()).map_err(|_| "lake cell router tenant key is not hex".to_string())?,
    );
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    if raw.len() != key.len() {
        return Err("lake cell router tenant key must be 32 bytes (64 hex)".to_string());
    }
    key.copy_from_slice(&raw);
    Ok(key)
}

/// NAN-3289: the bearer for a call to `url` (a cell router URL under one
/// tenant's `query` or `detect` prefix). With
/// [`LAKE_CELL_ROUTER_TENANT_KEY_FILE_ENV`] set, the bearer is derived for
/// exactly that tenant, cell and scope (the router refuses it anywhere
/// else); an unusable key file is an error, never a silent fallback to the
/// cluster token. A URL without a derivable target (an origin the platform did
/// not render) and the unset variable present `token_file` as before.
pub fn router_bearer(token_file: &Path, url: &str) -> Result<String, String> {
    router_bearer_with(token_file, url, env_path(LAKE_CELL_ROUTER_TENANT_KEY_FILE_ENV).as_deref())
}

fn router_bearer_with(token_file: &Path, url: &str, tenant_key_file: Option<&Path>) -> Result<String, String> {
    if let Some(key_file) = tenant_key_file {
        if let Some((tenant, cell, scope)) = bearer_target(url) {
            let key = read_tenant_key(key_file)?;
            return Ok(derive_tenant_router_token(&key, &tenant, &cell, scope));
        }
    }
    read_router_token(token_file)
}

fn read_router_token(path: &Path) -> Result<String, String> {
    let bytes = read_bounded(path, MAX_TOKEN_FILE_BYTES)
        .map_err(|_| "lake cell router token is unavailable".to_string())?;
    let token =
        String::from_utf8(bytes).map_err(|_| "lake cell router token is not UTF-8".to_string())?;
    let token = token.trim();
    if token.len() < 32 {
        return Err("lake cell router token must contain at least 32 characters".to_string());
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn trusted_local_tenant_needs_a_non_nil_uuid_and_gets_a_local_slug() {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let ok = |name: &str| (name == "NANO_LAKE_TENANT_ID").then(|| tenant.to_string());
        let parsed = super::trusted_local_tenant_from_lookup(&ok).unwrap();
        assert_eq!(parsed, Uuid::parse_str(tenant).unwrap());
        assert_eq!(super::trusted_local_tenant_slug(parsed), "local-6f1c1e2a");
        for bad in ["", "acme-gen1", "00000000-0000-0000-0000-000000000000"] {
            let lookup = |name: &str| (name == "NANO_LAKE_TENANT_ID").then(|| bad.to_string());
            assert!(super::trusted_local_tenant_from_lookup(&lookup).is_err(), "{bad:?}");
        }
        assert!(super::trusted_local_tenant_from_lookup(&|_: &str| None).is_err());
    }

    use super::*;

    fn private_token(dir: &tempfile::TempDir) -> PathBuf {
        let path = dir.path().join("router.token");
        std::fs::write(&path, "r".repeat(43)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        path
    }

    fn routes_file(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("routes.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    const TENANT_A: &str = "0b7a2f9e-1c4d-4e8f-9a0b-1c2d3e4f5a6b";
    const TENANT_B: &str = "7c1e3d5f-2a4b-4c6d-8e0f-a1b2c3d4e5f6";
    const CELL_1: &str = "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790";
    const CELL_2: &str = "http://nano-cell-cell-us-2.nano-lake-cells.svc:8790";

    fn entry(tenant: &str, cell: &str) -> String {
        format!("\"{tenant}\":{{\"cell_origin\":\"{cell}\",\"assignment_generation\":1,\"part_log_writer_epoch\":1,\"worker_revision\":1}}")
    }

    fn dedicated_env<'a>(
        vars: &'a [(&'static str, String)],
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| v.clone())
    }

    /// NAN-3867: `erasure-executors.json` beside `routes.json` declares the
    /// lean erasure executor per tenant: optional, strict per entry, only for
    /// a fenced route, and never leaking to another tenant.
    #[test]
    fn erasure_executor_declarations_are_optional_strict_and_tenant_scoped() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let routes = routes_file(&dir, &format!("{{{},\"{TENANT_B}\":\"{CELL_2}\"}}", entry(TENANT_A, CELL_1)));
        let source = LakeCellRouteSource::from_files(&routes, &token);
        let a = Uuid::parse_str(TENANT_A).unwrap();
        let b = Uuid::parse_str(TENANT_B).unwrap();
        // No file: nothing declared (every older platform render).
        assert_eq!(source.erasure_executor(a), None);
        let executors = dir.path().join(LAKE_CELL_ERASURE_EXECUTORS_FILE);
        std::fs::write(&executors, format!(
            "{{\"{TENANT_A}\":{{\"executor_node\":\"lean-cell:cell-us-1\"}},\"{TENANT_B}\":{{\"executor_node\":\"lean-cell:cell-us-2\"}}}}"
        )).unwrap();
        source.reload();
        assert_eq!(source.erasure_executor(a).as_deref(), Some("lean-cell:cell-us-1"));
        // TENANT_B is on the deprecated (unfenced) string route: not declared.
        assert_eq!(source.erasure_executor(b), None);
        // An unrouted tenant declares nothing either.
        assert_eq!(source.erasure_executor(Uuid::from_u128(7)), None);
        // An invalid file keeps the last good declarations.
        std::fs::write(&executors, "not json").unwrap();
        source.reload();
        assert_eq!(source.erasure_executor(a).as_deref(), Some("lean-cell:cell-us-1"));
        // Removing the file withdraws every declaration.
        std::fs::remove_file(&executors).unwrap();
        source.reload();
        assert_eq!(source.erasure_executor(a), None);

        let parse = |body: &str| LakeCellErasureExecutors::parse(body.as_bytes()).unwrap();
        for bad in [
            format!("{{\"{TENANT_A}\":{{\"executor_node\":\"cell-us-1\"}}}}"),
            format!("{{\"{TENANT_A}\":{{\"executor_node\":\"lean-cell:Cell_1\"}}}}"),
            format!("{{\"{TENANT_A}\":{{\"executor_node\":\"lean-cell:c\",\"extra\":1}}}}"),
            format!("{{\"{TENANT_A}\":\"lean-cell:c\"}}"),
            format!("{{\"{}\":{{\"executor_node\":\"lean-cell:c\"}}}}", TENANT_A.to_uppercase()),
            format!("{{\"{TENANT_A}\":{{\"executor_node\":\"lean-cell:c\"}},\"{TENANT_A}\":{{\"executor_node\":\"lean-cell:d\"}}}}"),
        ] {
            let (parsed, rejected) = parse(&bad);
            assert!(parsed.is_empty() && !rejected.is_empty(), "{bad}");
        }
    }

    #[test]
    fn dedicated_route_is_dark_without_env_and_off_in_shared_mode() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let routes = routes_file(&dir, &format!("{{{}}}", entry(TENANT_A, "http://lake-cell:8790")));
        assert!(dedicated_route_from_lookup(&dedicated_env(&[])).unwrap().is_none());
        let shared = [
            ("DEPLOYMENT_MODE", "enterprise_shared".to_string()),
            (LAKE_CELL_ROUTES_FILE_ENV, routes.display().to_string()),
            (LAKE_CELL_ROUTER_TOKEN_FILE_ENV, token.display().to_string()),
            ("NANO_LAKE_TENANT_ID", TENANT_A.to_string()),
        ];
        assert!(dedicated_route_from_lookup(&dedicated_env(&shared)).unwrap().is_none());
    }

    #[test]
    fn dedicated_route_resolves_the_install_tenant_on_a_compose_origin() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let routes = routes_file(&dir, &format!("{{{}}}", entry(TENANT_A, "http://lake-cell:8790")));
        let vars = [
            (LAKE_CELL_ROUTES_FILE_ENV, routes.display().to_string()),
            (LAKE_CELL_ROUTER_TOKEN_FILE_ENV, token.display().to_string()),
            ("NANO_LAKE_TENANT_ID", TENANT_A.to_string()),
        ];
        let route = dedicated_route_from_lookup(&dedicated_env(&vars)).unwrap().unwrap();
        assert_eq!(route.tenant_id.to_string(), TENANT_A);
        assert_eq!(route.query_base_url, format!("http://lake-cell:8790/v1/tenants/{TENANT_A}/query"));
        assert!(route.assignment_fenced);
        // The hosted parser still refuses the compose origin.
        let (hosted, rejected) = LakeCellRoutes::parse(&std::fs::read(&routes).unwrap(), &token).unwrap();
        assert!(hosted.is_empty() && rejected.len() == 1);
    }

    #[test]
    fn dedicated_route_misconfiguration_is_an_error_not_gen1() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let routes = routes_file(&dir, &format!("{{{}}}", entry(TENANT_A, "http://lake-cell:8790")));
        let base = |extra: &[(&'static str, String)]| {
            let mut vars = vec![
                (LAKE_CELL_ROUTES_FILE_ENV, routes.display().to_string()),
                (LAKE_CELL_ROUTER_TOKEN_FILE_ENV, token.display().to_string()),
                ("NANO_LAKE_TENANT_ID", TENANT_A.to_string()),
            ];
            for (k, v) in extra {
                vars.retain(|(key, _)| key != k);
                vars.push((k, v.clone()));
            }
            vars
        };
        for (why, vars) in [
            ("gen1 url beside the cell", base(&[("NANO_LAKE_QUERY_URL", "http://lake-query-worker:3015".into())])),
            ("legacy default tenant", base(&[("NANO_LAKE_TENANT_ID", "default".into())])),
            ("tenant without a route", base(&[("NANO_LAKE_TENANT_ID", TENANT_B.into())])),
            ("public origin", {
                let other = dir.path().join("public.json");
                std::fs::write(&other, format!("{{{}}}", entry(TENANT_A, "http://example.com:8790"))).unwrap();
                base(&[(LAKE_CELL_ROUTES_FILE_ENV, other.display().to_string())])
            }),
            ("two tenants", {
                let other = dir.path().join("two.json");
                std::fs::write(&other, format!("{{{},{}}}", entry(TENANT_A, "http://lake-cell:8790"), entry(TENANT_B, "http://lake-cell:8790"))).unwrap();
                base(&[(LAKE_CELL_ROUTES_FILE_ENV, other.display().to_string())])
            }),
        ] {
            assert!(dedicated_route_from_lookup(&dedicated_env(&vars)).is_err(), "{why}");
        }
        let half = [(LAKE_CELL_ROUTES_FILE_ENV, routes.display().to_string())];
        assert!(dedicated_route_from_lookup(&dedicated_env(&half)).is_err(), "one variable without the other");
        // A group-readable token is refused.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(dedicated_route_from_lookup(&dedicated_env(&base(&[]))).is_err());
        }
    }

    #[test]
    fn trusted_local_needs_the_explicit_flag() {
        let with = |pairs: &'static [(&'static str, &'static str)]| {
            trusted_local_from_lookup(&move |name| {
                pairs.iter().find(|(key, _)| *key == name).map(|(_, value)| value.to_string())
            })
        };
        // Absent (hosted default), off, or anything but an explicit yes: false.
        assert!(!with(&[]));
        assert!(!with(&[(TRUSTED_LOCAL_ENV, "")]));
        assert!(!with(&[(TRUSTED_LOCAL_ENV, "0")]));
        assert!(!with(&[(TRUSTED_LOCAL_ENV, "false")]));
        assert!(!with(&[(TRUSTED_LOCAL_ENV, "yes")]));
        // The routes alone (a dedicated cell route) do not make a process trusted-local.
        assert!(!with(&[(LAKE_CELL_ROUTES_FILE_ENV, "/r.json"), (LAKE_CELL_ROUTER_TOKEN_FILE_ENV, "/t")]));
        assert!(with(&[(TRUSTED_LOCAL_ENV, "1")]));
        assert!(with(&[(TRUSTED_LOCAL_ENV, "true")]));
        // Never in the hosted shared process, whatever the env says.
        assert!(!with(&[(TRUSTED_LOCAL_ENV, "1"), ("DEPLOYMENT_MODE", "enterprise_shared")]));
    }

    #[test]
    fn trusted_local_origin_rule() {
        for ok in ["http://lake-cell:8790", "http://127.0.0.1:8790", "http://localhost:8790", "http://10.0.0.5:8790",
            "http://nano-cell-a.ns.svc:8790"] {
            assert!(validate_trusted_local_origin(ok).is_ok(), "{ok}");
        }
        for bad in ["http://lake-cell", "http://lake-cell:8790/x", "http://a.example.com:8790", "ftp://lake-cell:8790",
            "http://u:p@lake-cell:8790"] {
            assert!(validate_trusted_local_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_nano_main_routes_map_into_tenant_scoped_query_bases() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let body = format!(
            "{{{}, {}}}",
            entry(TENANT_A, CELL_1),
            entry(TENANT_B, CELL_2)
        );
        let source = LakeCellRouteSource::from_files(&routes_file(&dir, &body), &token);
        let routes = source.current();
        assert_eq!(routes.len(), 2);
        let a = routes.route(Uuid::parse_str(TENANT_A).unwrap()).unwrap();
        assert_eq!(
            a.query_base_url,
            format!("{CELL_1}/v1/tenants/{TENANT_A}/query")
        );
        a.validate_query_base().unwrap();
        let detect = a.for_detection().unwrap();
        assert_eq!(detect.query_base_url, format!("{CELL_1}/v1/tenants/{TENANT_A}/detect"));
        detect.validate_query_base().unwrap();
        assert_eq!(a.query_base_url, format!("{CELL_1}/v1/tenants/{TENANT_A}/query"));
        let b = routes.route(Uuid::parse_str(TENANT_B).unwrap()).unwrap();
        assert_eq!(b.cell_origin, CELL_2);
        assert_eq!(a.read_router_token().unwrap(), "r".repeat(43));
        // The configured path is kept, never a resolved target.
        assert_eq!(a.router_token_file, token);
    }

    #[test]
    fn tenant_a_never_resolves_to_tenant_b_cell() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let body = format!(
            "{{{}, {}}}",
            entry(TENANT_A, CELL_1),
            entry(TENANT_B, CELL_2)
        );
        let source = LakeCellRouteSource::from_files(&routes_file(&dir, &body), &token);
        let a = Uuid::parse_str(TENANT_A).unwrap();
        let b = Uuid::parse_str(TENANT_B).unwrap();
        let route_a = source.route(a).unwrap();
        assert_eq!(route_a.tenant_id, a);
        assert!(!route_a.query_base_url.contains(TENANT_B));
        assert!(!route_a.cell_origin.contains("cell-us-2"));
        // An unplaced tenant resolves to nothing (it stays on gen1), never to
        // some other tenant's cell.
        assert!(source.route(Uuid::from_u128(0xc)).is_none());
        assert!(source.route(Uuid::nil()).is_none());
        assert_ne!(
            source.route(b).unwrap().query_base_url,
            route_a.query_base_url
        );
        // A route whose base names another tenant's prefix is refused.
        let mut forged = (*route_a).clone();
        forged.query_base_url = format!("{CELL_2}/v1/tenants/{TENANT_B}/query");
        assert!(forged.validate_query_base().is_err());
        forged.query_base_url = format!("{CELL_2}/v1/tenants/{TENANT_A}/detect");
        assert!(forged.validate_query_base().is_err());
    }

    #[test]
    fn a_malformed_entry_is_dropped_alone() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        for bad in [
            // not a UUID / not canonical / nil
            format!("\"tenant-a\": \"{CELL_2}\""),
            format!("\"{}\": \"{CELL_2}\"", TENANT_B.to_uppercase()),
            format!("\"00000000-0000-0000-0000-000000000000\": \"{CELL_2}\""),
            // origin carries a path (could redirect to another tenant's prefix)
            format!("\"{TENANT_B}\": \"{CELL_2}/v1/tenants/{TENANT_A}/query\""),
            // public host, missing port, credentials, query, scheme
            format!("\"{TENANT_B}\": \"http://example.com:8790\""),
            format!("\"{TENANT_B}\": \"http://nano-cell-cell-us-2.nano-lake-cells.svc\""),
            format!("\"{TENANT_B}\": \"http://u:p@nano-cell-cell-us-2.nano-lake-cells.svc:8790\""),
            format!("\"{TENANT_B}\": \"{CELL_2}?t={TENANT_A}\""),
            format!("\"{TENANT_B}\": \"file:///etc/passwd\""),
            // an object that is not an assignment route
            format!("\"{TENANT_B}\": {{\"url\": \"{CELL_2}\"}}"),
        ] {
            let body = format!("{{{}, {bad}}}", entry(TENANT_A, CELL_1));
            let source = LakeCellRouteSource::from_files(&routes_file(&dir, &body), &token);
            let routes = source.current();
            assert_eq!(routes.len(), 1, "bad entry must be dropped alone: {bad}");
            assert!(routes.route(Uuid::parse_str(TENANT_A).unwrap()).is_some());
            assert!(routes.route(Uuid::parse_str(TENANT_B).unwrap()).is_none());
        }
        // A duplicated tenant is ambiguous: neither placement is used.
        let body = format!(
            "{{{}, {}}}",
            entry(TENANT_A, CELL_1),
            entry(TENANT_A, CELL_2)
        );
        let source = LakeCellRouteSource::from_files(&routes_file(&dir, &body), &token);
        assert!(source.current().is_empty());
    }

    #[test]
    fn generation_route_requires_complete_positive_revision() {
        let tenant = Uuid::parse_str(TENANT_A).unwrap();
        let token = Path::new("/tmp/router.token");
        let body = format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"{CELL_1}\",\"assignment_generation\":2,\"part_log_writer_epoch\":7,\"worker_revision\":9}}}}");
        let (routes, rejected) = LakeCellRoutes::parse(body.as_bytes(), token).unwrap();
        assert!(rejected.is_empty());
        let route = routes.route(tenant).unwrap();
        assert_eq!(route.assignment_generation, 2);
        assert_eq!(route.part_log_writer_epoch, 7);
        assert_eq!(route.worker_revision, 9);
        assert!(route.assignment_fenced);

        let body = format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"{CELL_1}\",\"assignment_generation\":0,\"part_log_writer_epoch\":7,\"worker_revision\":9}}}}");
        let (routes, rejected) = LakeCellRoutes::parse(body.as_bytes(), token).unwrap();
        assert!(routes.is_empty());
        assert_eq!(rejected.len(), 1);
        for bad in [
            format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"{CELL_1}\",\"assignment_generation\":2,\"worker_revision\":9}}}}"),
            format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"{CELL_1}\",\"assignment_generation\":2,\"part_log_writer_epoch\":0,\"worker_revision\":9}}}}"),
            // Unknown field alongside a complete assignment.
            format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"{CELL_1}\",\"assignment_generation\":2,\"part_log_writer_epoch\":7,\"worker_revision\":9,\"extra\":1}}}}"),
            // Missing cell_origin, non-string origin, non-integer generation.
            format!("{{\"{TENANT_A}\":{{\"assignment_generation\":2,\"part_log_writer_epoch\":7,\"worker_revision\":9,\"origin\":\"{CELL_1}\"}}}}"),
            format!("{{\"{TENANT_A}\":{{\"cell_origin\":7,\"assignment_generation\":2,\"part_log_writer_epoch\":7,\"worker_revision\":9}}}}"),
            format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"{CELL_1}\",\"assignment_generation\":\"2\",\"part_log_writer_epoch\":7,\"worker_revision\":9}}}}"),
            // An object route's origin gets the same admission as a string's.
            format!("{{\"{TENANT_A}\":{{\"cell_origin\":\"http://example.com:8790\",\"assignment_generation\":2,\"part_log_writer_epoch\":7,\"worker_revision\":9}}}}"),
            // Neither form.
            format!("{{\"{TENANT_A}\":7}}"),
            format!("{{\"{TENANT_A}\":[\"{CELL_1}\"]}}"),
        ] {
            let (routes, rejected) = LakeCellRoutes::parse(bad.as_bytes(), token).unwrap();
            assert!(routes.is_empty());
            assert_eq!(rejected.len(), 1);
        }
    }

    /// the platform's live renderer emits `"<tenant>": "<origin>"`. Such a route
    /// must work exactly as before NAN-2921: fixed revision 1 for generation,
    /// writer epoch and worker revision, and explicitly unfenced.
    #[test]
    fn a_plain_string_route_works_unfenced() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let body = format!("{{\"{TENANT_A}\": \"{CELL_1}\"}}");
        let source = LakeCellRouteSource::from_files(&routes_file(&dir, &body), &token);
        let route = source.route(Uuid::parse_str(TENANT_A).unwrap()).unwrap();
        assert_eq!(route.cell_origin, CELL_1);
        assert_eq!(route.query_base_url, format!("{CELL_1}/v1/tenants/{TENANT_A}/query"));
        route.validate_query_base().unwrap();
        assert_eq!(
            (route.assignment_generation, route.part_log_writer_epoch, route.worker_revision),
            (LAKE_CELL_ASSIGNMENT_REVISION, LAKE_CELL_ASSIGNMENT_REVISION, LAKE_CELL_ASSIGNMENT_REVISION)
        );
        assert!(!route.assignment_fenced);
        // A trailing slash is normalised as it always was.
        let body = format!("{{\"{TENANT_A}\": \"{CELL_1}/\"}}");
        let (routes, rejected) = LakeCellRoutes::parse(body.as_bytes(), &token).unwrap();
        assert!(rejected.is_empty());
        assert_eq!(routes.route(Uuid::parse_str(TENANT_A).unwrap()).unwrap().cell_origin, CELL_1);
    }

    #[test]
    fn an_object_route_works_fenced() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let body = format!("{{{}}}", entry(TENANT_B, CELL_2));
        let source = LakeCellRouteSource::from_files(&routes_file(&dir, &body), &token);
        let route = source.route(Uuid::parse_str(TENANT_B).unwrap()).unwrap();
        assert_eq!(route.query_base_url, format!("{CELL_2}/v1/tenants/{TENANT_B}/query"));
        assert!(route.assignment_fenced);
    }

    #[test]
    fn a_mixed_map_routes_both_forms() {
        let token = Path::new("/tmp/router.token");
        let body = format!(
            "{{\"{TENANT_A}\": \"{CELL_1}\", \"{TENANT_B}\":{{\"cell_origin\":\"{CELL_2}\",\"assignment_generation\":4,\"part_log_writer_epoch\":5,\"worker_revision\":6}}}}"
        );
        let (routes, rejected) = LakeCellRoutes::parse(body.as_bytes(), token).unwrap();
        assert!(rejected.is_empty(), "{rejected:?}");
        assert_eq!(routes.len(), 2);
        let a = routes.route(Uuid::parse_str(TENANT_A).unwrap()).unwrap();
        assert_eq!((a.cell_origin.as_str(), a.assignment_fenced, a.worker_revision), (CELL_1, false, 1));
        let b = routes.route(Uuid::parse_str(TENANT_B).unwrap()).unwrap();
        assert_eq!(
            (b.cell_origin.as_str(), b.assignment_fenced, b.assignment_generation, b.part_log_writer_epoch, b.worker_revision),
            (CELL_2, true, 4, 5, 6)
        );
        // A tenant listed once as a string and once as an object is still
        // ambiguous: neither placement is used, the other tenant is kept.
        let body = format!(
            "{{\"{TENANT_A}\": \"{CELL_1}\", {}, {}}}",
            entry(TENANT_A, CELL_2),
            entry(TENANT_B, CELL_2)
        );
        let (routes, rejected) = LakeCellRoutes::parse(body.as_bytes(), token).unwrap();
        assert_eq!(rejected.len(), 2);
        assert!(routes.route(Uuid::parse_str(TENANT_A).unwrap()).is_none());
        assert!(routes.route(Uuid::parse_str(TENANT_B).unwrap()).is_some());
    }

    #[test]
    fn string_route_deprecation_is_warned_once_per_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let a = Uuid::parse_str(TENANT_A).unwrap();
        let b = Uuid::parse_str(TENANT_B).unwrap();
        let path = routes_file(&dir, &format!("{{\"{TENANT_A}\": \"{CELL_1}\"}}"));
        let source = LakeCellRouteSource::from_files(&path, &token);
        // Boot already warned for A; a changed file with A still a string and
        // B newly a string warns for B only; an object route never warns.
        assert_eq!(source.warn_string_routes_once(&source.current()), Vec::<Uuid>::new());
        std::fs::write(&path, format!("{{\"{TENANT_A}\": \"{CELL_2}\", \"{TENANT_B}\": \"{CELL_1}\"}}")).unwrap();
        source.reload();
        assert_eq!(source.string_route_warned.lock().unwrap().len(), 2);
        assert!(source.string_route_warned.lock().unwrap().contains(&b));
        assert_eq!(source.warn_string_routes_once(&source.current()), Vec::<Uuid>::new());
        let (objects, _) = LakeCellRoutes::parse(
            format!("{{{}}}", entry(TENANT_A, CELL_1)).as_bytes(),
            &token,
        )
        .unwrap();
        let fresh = LakeCellRouteSource::fixed(LakeCellRoutes::default());
        assert!(fresh.warn_string_routes_once(&objects).is_empty());
        assert!(!fresh.string_route_warned.lock().unwrap().contains(&a));
    }

    #[test]
    fn an_invalid_file_never_fails_boot_and_keeps_the_last_good_map() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        for body in ["[1,2]", "not json", ""] {
            let source = LakeCellRouteSource::from_files(&routes_file(&dir, body), &token);
            assert!(source.current().is_empty());
        }
        // Missing routes file and missing token: still constructs (dark).
        let source = LakeCellRouteSource::from_files(
            &dir.path().join("absent.json"),
            &dir.path().join("absent.token"),
        );
        assert!(source.current().is_empty());
        // Good, then broken: the good map is kept.
        let path = routes_file(&dir, &format!("{{{}}}", entry(TENANT_A, CELL_1)));
        let source = LakeCellRouteSource::from_files(&path, &token);
        assert_eq!(source.current().len(), 1);
        std::fs::write(&path, "{broken").unwrap();
        source.reload();
        assert_eq!(source.current().len(), 1);
        // An empty map is valid (no tenant placed yet).
        std::fs::write(&path, "{}").unwrap();
        source.reload();
        assert!(source.current().is_empty());
    }

    /// kubelet updates a ConfigMap directory mount by writing a new
    /// timestamped directory and atomically swapping the `..data` symlink.
    /// The reload must follow the swap by re-opening the configured path.
    #[cfg(unix)]
    #[test]
    fn reload_follows_the_configmap_symlink_swap() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let mount = dir.path().join("lake-cell-routes");
        std::fs::create_dir(&mount).unwrap();
        let v1 = mount.join("..2026_09_25_01");
        std::fs::create_dir(&v1).unwrap();
        std::fs::write(
            v1.join("routes.json"),
            format!("{{{}}}", entry(TENANT_A, CELL_1)),
        )
        .unwrap();
        std::os::unix::fs::symlink("..2026_09_25_01", mount.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/routes.json", mount.join("routes.json")).unwrap();
        let source = LakeCellRouteSource::from_files(&mount.join("routes.json"), &token);
        let a = Uuid::parse_str(TENANT_A).unwrap();
        assert!(source.route(a).unwrap().cell_origin.contains("cell-us-1"));

        // Swap: tenant A moves to cell 2, tenant B is placed.
        let v2 = mount.join("..2026_09_25_02");
        std::fs::create_dir(&v2).unwrap();
        std::fs::write(
            v2.join("routes.json"),
            format!(
                "{{{}, {}}}",
                entry(TENANT_A, CELL_2),
                entry(TENANT_B, CELL_1)
            ),
        )
        .unwrap();
        std::os::unix::fs::symlink("..2026_09_25_02", mount.join("..data_tmp")).unwrap();
        std::fs::rename(mount.join("..data_tmp"), mount.join("..data")).unwrap();
        std::fs::remove_dir_all(&v1).unwrap();
        source.reload();
        assert!(source.route(a).unwrap().cell_origin.contains("cell-us-2"));
        assert!(source.route(Uuid::parse_str(TENANT_B).unwrap()).is_some());
    }

    /// The token is re-read by its configured path on every call, so a
    /// rotated Secret (atomic dir swap) is used without a restart.
    #[cfg(unix)]
    #[test]
    fn router_token_is_reread_through_the_mount_path() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let mount = dir.path().join("lake-cell-router");
        std::fs::create_dir(&mount).unwrap();
        let write_version = |name: &str, token: &str| {
            let version = mount.join(name);
            std::fs::create_dir(&version).unwrap();
            let file = version.join("router.token");
            std::fs::write(&file, token).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
        };
        write_version("..v1", &"a".repeat(40));
        std::os::unix::fs::symlink("..v1", mount.join("..data")).unwrap();
        std::os::unix::fs::symlink("..data/router.token", mount.join("router.token")).unwrap();
        let routes = routes_file(&dir, &format!("{{{}}}", entry(TENANT_A, CELL_1)));
        let source = LakeCellRouteSource::from_files(&routes, &mount.join("router.token"));
        let route = source.route(Uuid::parse_str(TENANT_A).unwrap()).unwrap();
        assert_eq!(route.router_token_file, mount.join("router.token"));
        assert_eq!(route.read_router_token().unwrap(), "a".repeat(40));
        write_version("..v2", &"b".repeat(40));
        std::os::unix::fs::symlink("..v2", mount.join("..data_tmp")).unwrap();
        std::fs::rename(mount.join("..data_tmp"), mount.join("..data")).unwrap();
        std::fs::remove_dir_all(mount.join("..v1")).unwrap();
        assert_eq!(route.read_router_token().unwrap(), "b".repeat(40));
    }

    #[test]
    fn router_token_admission_rules() {
        let dir = tempfile::tempdir().unwrap();
        let short = dir.path().join("short.token");
        std::fs::write(&short, "short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o400)).unwrap();
            let open = dir.path().join("open.token");
            std::fs::write(&open, "o".repeat(43)).unwrap();
            std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(admit_router_token_file(&open).is_err());
        }
        assert!(admit_router_token_file(&short).is_err());
        assert!(admit_router_token_file(Path::new("relative.token")).is_err());
        assert!(admit_router_token_file(&dir.path().join("missing")).is_err());
        assert!(admit_router_token_file(&private_token(&dir)).is_ok());
    }

    /// NAN-3289: the golden vector shared with nanosiem-lake-cell
    /// (`tenant_token`) and the platform (`lake-cell-tenant-token.ts`).
    #[test]
    fn tenant_router_token_golden_vector() {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(b"full-router-token-0123456789abcdef0123456789").unwrap();
        mac.update(b"nano-cell-router-tenant-key/v1");
        let key: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(hex::encode(key), "8d4f3dc8d00c88091476a987ccb55bb1560f391439e73604e1dbec7c6575769c");
        assert_eq!(
            derive_tenant_router_token(&key, "0b7a2f9e-1c4d-4e8f-9a0b-1c2d3e4f5a6b", "cell-us-d-0a1b2c3d", "query"),
            "nct1.b268f7857708456bf5ed364d2429f318a9724795eb424a4329990dc55c6afb45"
        );
        assert_eq!(
            derive_tenant_router_token(&key, "0b7a2f9e-1c4d-4e8f-9a0b-1c2d3e4f5a6b", "cell-us-d-0a1b2c3d", "detect"),
            "nct1.6403019ba23c3a5992e509cc3f43a1237ed58e59fa26f0c57f71cc90e0b11d25"
        );
    }

    #[test]
    fn cell_id_and_bearer_target_come_from_the_rendered_route() {
        assert_eq!(cell_id_from_origin("http://nano-cell-cell-us-d-0a1b2c3d.nano-lake-cells.svc:8790").as_deref(),
            Some("cell-us-d-0a1b2c3d"));
        assert_eq!(cell_id_from_origin("https://nano-cell-c1.ns.svc.cluster.local:8790").as_deref(), Some("c1"));
        for bad in ["http://10.0.0.1:8790", "http://cell-1.nano-lake-cells.svc:8790", "http://nano-cell-.ns.svc:8790",
            "http://nano-cell-c1.example.com:8790", "http://nano-cell-c_1.ns.svc:8790", "http://nano-cell-c1.svc:8790"] {
            assert_eq!(cell_id_from_origin(bad), None, "{bad}");
        }
        let base = format!("http://nano-cell-c1.nano-lake-cells.svc:8790/v1/tenants/{TENANT_A}");
        assert_eq!(bearer_target(&format!("{base}/query")), Some((TENANT_A.to_string(), "c1".to_string(), "query")));
        assert_eq!(bearer_target(&format!("{base}/detect/v1/query")), Some((TENANT_A.to_string(), "c1".to_string(), "detect")));
        assert_eq!(bearer_target(&format!("{base}/wake")), None);
        assert_eq!(bearer_target("http://nano-cell-c1.nano-lake-cells.svc:8790/v1/status"), None);
    }

    #[test]
    fn router_bearer_derives_per_tenant_tokens_when_the_key_is_configured() {
        let dir = tempfile::tempdir().unwrap();
        let token = private_token(&dir);
        let query_base = format!("http://nano-cell-c1.nano-lake-cells.svc:8790/v1/tenants/{TENANT_A}/query");
        let detect_base = format!("http://nano-cell-c1.nano-lake-cells.svc:8790/v1/tenants/{TENANT_A}/detect");
        assert_eq!(router_bearer_with(&token, &query_base, None).unwrap(), "r".repeat(43), "no key: the cluster token");
        let key_file = dir.path().join("tenant.key");
        let key = [7u8; 32];
        std::fs::write(&key_file, hex::encode(key)).unwrap();
        let with_key = |url: &str| router_bearer_with(&token, url, Some(&key_file));
        assert_eq!(with_key(&query_base).unwrap(), derive_tenant_router_token(&key, TENANT_A, "c1", "query"));
        assert_eq!(with_key(&format!("{detect_base}/v1/detections/plan")).unwrap(),
            derive_tenant_router_token(&key, TENANT_A, "c1", "detect"));
        // An origin without a cell id keeps the cluster token.
        assert_eq!(with_key(&format!("http://10.0.0.1:8790/v1/tenants/{TENANT_A}/query")).unwrap(), "r".repeat(43));
        // A broken key file fails closed (never the cluster token).
        std::fs::write(&key_file, "not-hex").unwrap();
        assert!(with_key(&query_base).is_err());
    }
}
