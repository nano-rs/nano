// SPDX-License-Identifier: AGPL-3.0-or-later

//! Internal client for tenant-pinned chDB lake-query workers.
//!
//! The public search request never carries object-store coordinates or
//! credentials. Nano resolves one authenticated deployment/tenant assignment
//! from process configuration and sends only nPL plus bounded query controls to
//! the internal worker.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::lake_http::LakeRequestBuilderExt;
use crate::schema::SchemaId;

use super::{
    DurableLakeGenerationPin, EventCompleteness, FieldStatistics, QueryWarningOutput, SearchError,
    SearchJobResultPage, SearchJobResultRef, SearchRequest, SearchResponse, TimeRangeInput,
};

const DEFAULT_TIMEOUT_SECS: u64 = 130;
/// Query timeout for a lean-lake cell tenant view (NAN-2891); the same
/// budget as a gen1 worker.
pub(crate) const DEFAULT_LAKE_CELL_TIMEOUT_SECS: u64 = DEFAULT_TIMEOUT_SECS;
/// query[T]'s detection plan is advisory: one short attempt (NAN-2891).
const LAKE_CELL_DETECTION_PLAN_TIMEOUT: Duration = Duration::from_secs(3);
/// A detection-gate commit is bounded and runs detached from the executor.
const LAKE_CELL_DETECTION_COMMIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Identity/health probe budget. NAN-2361 wave 8: 2 s was too tight for a
/// chDB worker that is verifying a generation or serving a heavy interactive
/// lane; the probe is a small authenticated GET, so 5 s bounds a genuinely
/// unresponsive worker without turning ordinary load into a search outage.
/// The query timeout itself stays with the registry (`DEFAULT_TIMEOUT_SECS`).
const HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
/// NAN-3644: one cold-progress poll; progress is best effort.
const COLD_PROGRESS_TIMEOUT: Duration = Duration::from_secs(2);

/// NAN-3644: query[T]'s `GET /v1/query/progress` answer.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct LakeColdProgress {
    #[serde(default)]
    pub cold_bytes_read: u64,
    #[serde(default)]
    pub cold_bytes_total: u64,
    #[serde(default)]
    pub queued: bool,
}
const DEFAULT_RESULT_LIMIT: usize = 100;
const MAX_RESULT_LIMIT: usize = 1_000_000;
const TRANSACTION_EVENT_PREVIEW_LIMIT: usize = 50;
const WORKER_ASSIGNMENT_ID_HEADER: &str = "x-nano-worker-assignment-id";
const WORKER_ASSIGNMENT_REVISION_HEADER: &str = "x-nano-worker-assignment-revision";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LakeQueryMode {
    Disabled,
    Primary,
}

/// `NANO_LAKE_QUERY_TIMEOUT_SECS` (1..=3600, default 130).
fn lake_query_timeout_secs() -> Result<u64, String> {
    let timeout_secs = std::env::var("NANO_LAKE_QUERY_TIMEOUT_SECS")
        .ok()
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|_| "NANO_LAKE_QUERY_TIMEOUT_SECS must be an integer".to_string())
        })
        .transpose()?
        .unwrap_or(DEFAULT_TIMEOUT_SECS);
    if timeout_secs == 0 || timeout_secs > 3_600 {
        return Err("NANO_LAKE_QUERY_TIMEOUT_SECS must be between 1 and 3600".to_string());
    }
    Ok(timeout_secs)
}

#[derive(Clone)]
pub(crate) struct LakeQueryRuntime {
    pub mode: LakeQueryMode,
    pub client: Option<LakeQueryClient>,
}

impl LakeQueryRuntime {
    /// Clone a tenant-pinned cell reader onto its detect leaf. Gen1 readers
    /// retain their original route.
    pub(crate) fn detection_lane(&self) -> Result<Self, String> {
        let mut lane = self.clone();
        if let Some(client) = lane.client.as_mut().filter(|c| c.lake_cell) {
            let prefix = client.base_url.strip_suffix("/query")
                .ok_or_else(|| "cell reader route has no query suffix".to_string())?;
            client.base_url = format!("{prefix}/detect");
        }
        Ok(lane)
    }

    pub(crate) fn detection_prevalence_parts(&self) -> Option<(&str, &str, &Path)> {
        let client = self.client.as_ref().filter(|c| c.lake_cell)?;
        Some((&client.base_url, &client.tenant_id, client.router_token_file.as_deref()?))
    }

    pub(crate) fn assigned_tenant_id(&self) -> Option<&str> {
        self.client.as_ref().map(|client| client.tenant_id.as_str())
    }

    pub fn from_env(profile: SchemaId) -> Result<Self, String> {
        // NAN-3491: the lake is the only log backend. Unset selects it, and a
        // legacy `clickhouse`/`shadow` value is refused rather than converted.
        let backend_raw = std::env::var(crate::schema::LOG_QUERY_BACKEND_ENV).ok();
        crate::schema::runtime_profile::log_query_backend_from_value(backend_raw.as_deref())?;
        let mode = LakeQueryMode::Primary;

        if profile != SchemaId::Ocsf {
            // Boot only ever resolves OCSF (`runtime_profile` refuses `udm`),
            // so a non-OCSF profile comes from the legacy UDM-default
            // `SearchService` constructors that tests (and code the NAN-3491
            // series is still removing) build directly. With the backend left
            // unset those keep the ClickHouse executor they were written for;
            // an explicit `lake` with a non-OCSF profile stays a hard error.
            if backend_raw.as_deref().is_none_or(|raw| raw.trim().is_empty()) {
                return Ok(Self {
                    mode: LakeQueryMode::Disabled,
                    client: None,
                });
            }
            return Err(
                "lake query mode requires NANO_SCHEMA_PROFILE=ocsf; refusing a UDM/OCSF mismatch"
                    .to_string(),
            );
        }

        // Shared mode resolves the worker only after authentication, from the
        // server-owned UUID registry below. Reading the dedicated global
        // NANO_LAKE_TENANT_ID here would silently bind every tenant to one
        // worker before a request had been authenticated.
        if std::env::var("DEPLOYMENT_MODE").is_ok_and(|mode| mode == "enterprise_shared") {
            return Ok(Self { mode, client: None });
        }

        // NAN-3492: trusted-local single-tenant installs route to their
        // dedicated lean cell instead of a gen1 worker (opt-in by env).
        if let Some(route) = super::lake_cell::dedicated_route_from_env()? {
            let timeout_secs = lake_query_timeout_secs()?;
            let trusted_local = super::lake_cell::trusted_local_from_env();
            tracing::info!(tenant_id = %route.tenant_id, cell = %route.cell_origin, trusted_local,
                "lake search routes to the dedicated lean cell");
            return Self::from_lake_cell_route(&route, Duration::from_secs(timeout_secs))
                .map(|runtime| Self {
                    mode,
                    client: runtime.client.map(|client| client.with_trusted_local(trusted_local)),
                });
        }

        let base_url = required_env("NANO_LAKE_QUERY_URL")?;
        let tenant_id = required_env("NANO_LAKE_TENANT_ID")?;
        let token_file = PathBuf::from(required_env("NANO_LAKE_QUERY_TOKEN_FILE")?);
        let bearer_token = std::fs::read_to_string(&token_file)
            .map_err(|error| {
                format!(
                    "failed to read NANO_LAKE_QUERY_TOKEN_FILE {}: {error}",
                    token_file.display()
                )
            })?
            .trim()
            .to_string();
        if bearer_token.len() < 32 {
            return Err("lake query bearer token must contain at least 32 characters".to_string());
        }
        let timeout_secs = lake_query_timeout_secs()?;

        Ok(Self {
            mode,
            client: Some(LakeQueryClient::new(
                &base_url,
                tenant_id,
                bearer_token,
                Duration::from_secs(timeout_secs),
            )?),
        })
    }

    #[cfg(feature = "enterprise")]
    pub(crate) fn from_enterprise_shared_assignment(
        assignment: &SharedLakeWorkerAssignment,
    ) -> Result<Self, String> {
        let bearer_token =
            std::fs::read_to_string(&assignment.credential_file).map_err(|error| {
                format!(
                    "failed to read shared lake worker credential reference {}: {error}",
                    assignment.credential_file.display()
                )
            })?;
        let bearer_token = bearer_token.trim().to_string();
        if bearer_token.len() < 32 {
            return Err("shared lake worker credential must contain at least 32 characters".into());
        }
        Ok(Self {
            mode: LakeQueryMode::Primary,
            client: Some(LakeQueryClient::new_with_assignment(
                &assignment.internal_endpoint,
                assignment.tenant_id.to_string(),
                bearer_token,
                Duration::from_secs(assignment.timeout_secs),
                assignment.expected_worker_identity.clone(),
                assignment.expected_worker_revision,
            )?),
        })
    }

    /// A primary-lake runtime bound to one tenant's lean-lake `query[T]`
    /// (NAN-2891). The client is tenant-pinned by the route itself.
    pub(crate) fn from_lake_cell_route(
        route: &super::lake_cell::LakeCellRoute,
        timeout: Duration,
    ) -> Result<Self, String> {
        Ok(Self {
            mode: LakeQueryMode::Primary,
            client: Some(LakeQueryClient::new_lake_cell(route, timeout)?),
        })
    }
}

/// The lake backend serving one authenticated tenant (NAN-2891).
///
/// Resolved only from the tenant UUID of an authenticated request, via
/// [`SharedLakeWorkerRegistry::backend`]. A tenant listed in the cell routes
/// map is a cell tenant whether or not it also has a (legacy) gen1 registry
/// entry: the routes map is the explicit lean-lake opt-in, and nothing about a
/// cell tenant is derived from a gen1 entry.
#[derive(Debug, Clone)]
pub enum LakeBackend<'a> {
    Gen1(&'a SharedLakeWorkerAssignment),
    Cell(std::sync::Arc<super::lake_cell::LakeCellRoute>),
}

impl LakeBackend<'_> {
    /// The worker revision the tenant's Search job store and runtime cache
    /// are keyed by: the gen1 assignment's, or the fixed cell revision.
    pub fn worker_revision(&self) -> u64 {
        match self {
            Self::Gen1(assignment) => assignment.expected_worker_revision,
            Self::Cell(route) => route.worker_revision,
        }
    }

    pub fn is_cell(&self) -> bool {
        matches!(self, Self::Cell(_))
    }

    pub fn tenant_id(&self) -> Uuid {
        match self {
            Self::Gen1(assignment) => assignment.tenant_id,
            Self::Cell(route) => route.tenant_id,
        }
    }

    /// The cell route, when this is a cell backend.
    pub fn cell_route(&self) -> Option<&super::lake_cell::LakeCellRoute> {
        match self {
            Self::Gen1(_) => None,
            Self::Cell(route) => Some(route),
        }
    }

    /// The gen1 assignment, when this is a gen1 backend.
    pub fn gen1(&self) -> Option<&SharedLakeWorkerAssignment> {
        match self {
            Self::Gen1(assignment) => Some(assignment),
            Self::Cell(_) => None,
        }
    }

    /// The tenant's prevalence client: its cell's `query[T]` or the gen1
    /// reader's immutable snapshots.
    pub fn prevalence_client(&self) -> Result<crate::prevalence::LakePrevalenceClient, String> {
        match self {
            Self::Gen1(assignment) => assignment.prevalence_client(),
            Self::Cell(route) => crate::prevalence::LakePrevalenceClient::from_lake_cell_route(
                route,
                super::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD,
                Duration::from_secs(DEFAULT_LAKE_CELL_TIMEOUT_SECS),
            ),
        }
    }

    /// NAN-3881: the tenant's IOC snapshot reader on the same backend (the
    /// gen1 assignment's worker or the cell's query[T]), pinned to that
    /// tenant and its `ioc-<tenant>-current` pointer.
    pub fn ioc_client(&self) -> Result<crate::enrichment::ioc::LakeIocClient, String> {
        match self {
            Self::Gen1(assignment) => crate::enrichment::ioc::LakeIocClient::from_shared_assignment(assignment),
            Self::Cell(route) => crate::enrichment::ioc::LakeIocClient::from_lake_cell_route(route),
        }
        .map_err(|error| error.to_string())
    }

    /// An owned copy, detached from the registry borrow.
    pub fn to_owned_backend(&self) -> OwnedLakeBackend {
        match self {
            Self::Gen1(assignment) => OwnedLakeBackend::Gen1((*assignment).clone()),
            Self::Cell(route) => OwnedLakeBackend::Cell(std::sync::Arc::clone(route)),
        }
    }
}

/// [`LakeBackend`] without the registry borrow, for verified runtimes that
/// outlive one lookup.
#[derive(Debug, Clone)]
pub enum OwnedLakeBackend {
    Gen1(SharedLakeWorkerAssignment),
    Cell(std::sync::Arc<super::lake_cell::LakeCellRoute>),
}

impl OwnedLakeBackend {
    pub fn as_backend(&self) -> LakeBackend<'_> {
        match self {
            Self::Gen1(assignment) => LakeBackend::Gen1(assignment),
            Self::Cell(route) => LakeBackend::Cell(std::sync::Arc::clone(route)),
        }
    }
}

/// query[T]'s detection-gate verdict for one rule window (NAN-2891; the
/// `part_query::detections::Plan` wire shape).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LakeDetectionPlan {
    pub run: bool,
    pub reason: String,
    pub log_seq: u64,
    #[serde(default)]
    pub rerun_windows: Vec<LakeDetectionRerunWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct LakeDetectionRerunWindow {
    pub start_us: i64,
    pub end_us: i64,
}

/// One immutable, server-owned enterprise-shared worker assignment. The
/// credential field is a runtime file reference only; raw credentials are
/// neither deserialized from the registry nor retained here.
#[derive(Debug, Clone)]
pub struct SharedLakeWorkerAssignment {
    pub tenant_id: Uuid,
    pub internal_endpoint: String,
    pub credential_file: PathBuf,
    pub expected_worker_identity: String,
    pub expected_worker_revision: u64,
    pub timeout_secs: u64,
    pub prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots,
    pub prevalence_rarity_threshold: u64,
    pub prevalence_timeout_secs: u64,
    /// NAN-2361 wave 5: the tenant cell's enrichment coordinator (the
    /// mutation boundary for custom-enrichment IOC snapshots), when the
    /// platform has provisioned one for this tenant. `None` means custom
    /// enrichment runs can validate and execute but have nowhere to publish.
    pub enrichment_coordinator: Option<SharedLakeEnrichmentCoordinatorAssignment>,
    /// NAN-2361 wave 6: the tenant's `lake_otel_ingest` drain/query service
    /// (traces, span detail, metrics, services, infra, RUM). `None` means the
    /// platform has not provisioned an OTLP drain for this tenant: the Search
    /// OTLP routes answer a typed 503 and `/api/log-sources/ingest-endpoint`
    /// reports `otlp_telemetry_ingested: false`.
    pub otel_ingest: Option<SharedLakeOtelIngestAssignment>,
    /// NAN-2361 wave 6: the tenant cell's `lake_erasure_execute` runner
    /// (the publish-principal sidecar that rewrites, purges and expires
    /// on behalf of the platform erasure runner). `None` means the cell
    /// render does not run one yet: erasure requests are deferred
    /// `erasure_executor_unassigned` instead of being handed a work order
    /// nothing will claim. No endpoint: the executor is driven through the
    /// `lake_erasure_work_orders` ledger, so the entry only names the render.
    pub erasure_executor: Option<SharedLakeErasureExecutorAssignment>,
}

impl SharedLakeWorkerAssignment {
    /// The gen1 reader's immutable-snapshot prevalence client. Callers that
    /// may serve a lean-lake tenant use [`LakeBackend::prevalence_client`].
    pub fn prevalence_client(&self) -> Result<crate::prevalence::LakePrevalenceClient, String> {
        crate::prevalence::LakePrevalenceClient::from_shared_assignment(
            &self.internal_endpoint,
            self.tenant_id,
            &self.credential_file,
            &self.prevalence_snapshots,
            self.prevalence_rarity_threshold,
            Duration::from_secs(self.prevalence_timeout_secs),
            self.expected_worker_identity.clone(),
            self.expected_worker_revision,
        )
    }
}

/// Tenant-pinned `lake_otel_ingest` reference (NAN-2361 wave 6). Same
/// admission rules as the enrichment coordinator: HTTP(S) origin, absolute and
/// private credential file (the service's QUERY token), unique across tenants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedLakeOtelIngestAssignment {
    pub internal_endpoint: String,
    pub credential_file: PathBuf,
    pub timeout_secs: u64,
}

/// Tenant-pinned `lake_erasure_execute` render facts (NAN-2361 wave 6).
/// `executor_node` is the node name the render passes as `--executor-node`
/// (the work order's `executor_node` column), `render_revision` the cell
/// render that carries the binary and its retention-authority credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedLakeErasureExecutorAssignment {
    pub executor_node: String,
    pub render_revision: u64,
}

/// Tenant-pinned `lake_enrichment_coordinator` reference (NAN-2361 wave 5).
/// Same admission rules as the query worker: HTTP(S) origin, absolute and
/// private credential file, unique across tenants.
#[derive(Clone, Debug)]
pub struct SharedLakeEnrichmentCoordinatorAssignment {
    pub internal_endpoint: String,
    pub credential_file: PathBuf,
    pub timeout_secs: u64,
}

#[derive(Clone)]
pub struct SharedLakeWorkerRegistry {
    assignments: HashMap<Uuid, SharedLakeWorkerAssignment>,
    /// NAN-2891: lean-lake cell routes (live-reloaded). `None` unless the
    /// deployment mounts the platform's `lake-cell-routes` map and router token.
    cells: Option<std::sync::Arc<super::lake_cell::LakeCellRouteSource>>,
    /// Last fleet readiness verdict and when it was computed. The public
    /// search `/health` and `/ready` probes fan out an authenticated identity
    /// read to EVERY tenant worker; caching the verdict for a few seconds
    /// bounds that fan-out to one round per `READINESS_CACHE_TTL` no matter
    /// how often the probes (or an unauthenticated caller) hit them.
    readiness: std::sync::Arc<tokio::sync::Mutex<Option<(std::time::Instant, bool)>>>,
}

/// How long a fleet readiness verdict is reused before the workers are
/// probed again.
const READINESS_CACHE_TTL: Duration = Duration::from_secs(3);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedLakeWorkerRegistryFile {
    version: u32,
    assignments: Vec<SharedLakeWorkerAssignmentFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedLakeWorkerAssignmentFile {
    tenant_id: Uuid,
    expected_worker_tenant_id: Uuid,
    internal_endpoint: String,
    credential_file: PathBuf,
    expected_worker_identity: String,
    expected_worker_revision: u64,
    #[serde(default = "default_shared_worker_timeout_secs")]
    timeout_secs: u64,
    prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots,
    #[serde(default = "default_prevalence_rarity_threshold")]
    prevalence_rarity_threshold: u64,
    #[serde(default = "default_prevalence_timeout_secs")]
    prevalence_timeout_secs: u64,
    #[serde(default)]
    enrichment_coordinator: Option<SharedLakeEnrichmentCoordinatorFile>,
    #[serde(default)]
    otel_ingest: Option<SharedLakeOtelIngestFile>,
    #[serde(default)]
    erasure_executor: Option<SharedLakeErasureExecutorFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedLakeOtelIngestFile {
    internal_endpoint: String,
    credential_file: PathBuf,
    #[serde(default = "default_otel_ingest_timeout_secs")]
    timeout_secs: u64,
}

const fn default_otel_ingest_timeout_secs() -> u64 {
    130
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedLakeErasureExecutorFile {
    executor_node: String,
    render_revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SharedLakeEnrichmentCoordinatorFile {
    internal_endpoint: String,
    credential_file: PathBuf,
    #[serde(default = "default_enrichment_coordinator_timeout_secs")]
    timeout_secs: u64,
}

const fn default_enrichment_coordinator_timeout_secs() -> u64 {
    600
}

const fn default_shared_worker_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

const fn default_prevalence_rarity_threshold() -> u64 {
    3
}

const fn default_prevalence_timeout_secs() -> u64 {
    30
}

impl SharedLakeWorkerRegistry {
    pub fn from_env() -> Result<Self, String> {
        // Never fails on a cell problem (logged; cells stay dark).
        let Some(cells) = super::lake_cell::LakeCellRouteSource::from_env() else {
            let path = required_env("NANO_LAKE_SHARED_WORKER_REGISTRY_FILE")?;
            return Self::from_file_for_process(
                Path::new(&path),
                crate::schema::tenant_lake_schema::shared_tenancy_process(),
            );
        };
        // With cells configured, the gen1 registry may be absent or empty (a
        // cluster whose only tenants are lean-lake ones, or whose routes map
        // is still empty). A gen1 file that IS configured keeps its own
        // validation: a broken gen1 registry is a gen1 outage, as before.
        let gen1 = match optional_env("NANO_LAKE_SHARED_WORKER_REGISTRY_FILE") {
            Some(path) => Self::from_file_inner(Path::new(&path), true)?,
            None => Self::empty(),
        };
        Ok(gen1.with_cell_source(cells))
    }

    pub fn from_file(path: &Path) -> Result<Self, String> {
        Self::from_file_inner(path, false)
    }

    /// A new hosted region has no admitted tenants before its first release.
    /// Its explicit version-1 empty registry authorizes nobody, even before
    /// cell routes exist. Open-core/gen1 file loading remains strict; malformed
    /// files and every nonempty assignment retain the same admission checks.
    fn from_file_for_process(path: &Path, shared_tenancy: bool) -> Result<Self, String> {
        Self::from_file_inner(path, shared_tenancy)
    }

    fn empty() -> Self {
        Self {
            assignments: HashMap::new(),
            cells: None,
            readiness: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Test-only: a registry over already-admitted assignments (mock workers
    /// listen on loopback, which the file admission rightly refuses).
    #[cfg(test)]
    pub(crate) fn from_assignments_for_test(assignments: Vec<SharedLakeWorkerAssignment>) -> Self {
        let mut registry = Self::empty();
        registry.assignments = assignments
            .into_iter()
            .map(|assignment| (assignment.tenant_id, assignment))
            .collect();
        registry
    }

    /// A registry with no gen1 assignments, serving lean-lake cell tenants
    /// only (what `from_env` builds when no gen1 registry file is mounted).
    pub fn empty_for_cells(cells: std::sync::Arc<super::lake_cell::LakeCellRouteSource>) -> Self {
        Self::empty().with_cell_source(cells)
    }

    /// Attach a live lean-lake cell route source (NAN-2891).
    pub fn with_cell_source(mut self, cells: std::sync::Arc<super::lake_cell::LakeCellRouteSource>) -> Self {
        self.cells = Some(cells);
        self
    }

    /// Attach a fixed lean-lake cell route map (no reload).
    pub fn with_cell_routes(self, cells: super::lake_cell::LakeCellRoutes) -> Self {
        self.with_cell_source(std::sync::Arc::new(super::lake_cell::LakeCellRouteSource::fixed(cells)))
    }

    fn from_file_inner(path: &Path, allow_empty: bool) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|error| {
            format!(
                "failed to read NANO_LAKE_SHARED_WORKER_REGISTRY_FILE {}: {error}",
                path.display()
            )
        })?;
        let file: SharedLakeWorkerRegistryFile = serde_json::from_slice(&bytes)
            .map_err(|error| format!("invalid shared lake worker registry JSON: {error}"))?;
        if file.version != 1 {
            return Err("shared lake worker registry version must be 1".to_string());
        }
        if file.assignments.is_empty() && !allow_empty {
            return Err("shared lake worker registry must contain assignments".to_string());
        }
        let mut assignments = HashMap::new();
        let mut endpoints = HashSet::new();
        let mut identities = HashSet::new();
        let mut credential_files = HashSet::new();
        for raw in file.assignments {
            if raw.expected_worker_tenant_id != raw.tenant_id {
                return Err(format!(
                    "shared lake worker assignment for {} expects a foreign tenant",
                    raw.tenant_id
                ));
            }
            validate_internal_worker_endpoint(&raw.internal_endpoint)?;
            if !raw.credential_file.is_absolute() {
                return Err(format!(
                    "shared lake worker credential reference for {} must be absolute",
                    raw.tenant_id
                ));
            }
            let credential_metadata = std::fs::metadata(&raw.credential_file).map_err(|_| {
                format!(
                    "shared lake worker credential reference for {} is unavailable",
                    raw.tenant_id
                )
            })?;
            if !credential_metadata.is_file() {
                return Err(format!(
                    "shared lake worker credential reference for {} is unavailable",
                    raw.tenant_id
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if credential_metadata.permissions().mode() & 0o077 != 0 {
                    return Err(format!(
                        "shared lake worker credential reference for {} is not private",
                        raw.tenant_id
                    ));
                }
            }
            // Each tenant must have an independently revocable worker secret.
            // Compare canonical references so lexical aliases and Kubernetes-
            // style symlinks cannot disguise one credential file as two tenant
            // assignments. The credential bytes are neither read nor logged.
            let canonical_credential_file =
                std::fs::canonicalize(&raw.credential_file).map_err(|_| {
                    format!(
                        "shared lake worker credential reference for {} is unavailable",
                        raw.tenant_id
                    )
                })?;
            if !credential_files.insert(canonical_credential_file.clone()) {
                return Err(
                    "shared lake worker registry reuses a credential reference across tenants"
                        .to_string(),
                );
            }
            if raw.expected_worker_identity.is_empty()
                || raw.expected_worker_identity.len() > 128
                || !raw.expected_worker_identity.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
            {
                return Err(format!(
                    "shared lake worker identity for {} is invalid",
                    raw.tenant_id
                ));
            }
            if raw.expected_worker_revision == 0 {
                return Err(format!(
                    "shared lake worker revision for {} must be positive",
                    raw.tenant_id
                ));
            }
            if raw.timeout_secs == 0 || raw.timeout_secs > 3_600 {
                return Err(format!(
                    "shared lake worker timeout for {} must be between 1 and 3600 seconds",
                    raw.tenant_id
                ));
            }
            if raw.prevalence_timeout_secs == 0 || raw.prevalence_timeout_secs > 300 {
                return Err(format!(
                    "shared lake prevalence timeout for {} must be between 1 and 300 seconds",
                    raw.tenant_id
                ));
            }
            if raw.prevalence_rarity_threshold == 0 {
                return Err(format!(
                    "shared lake prevalence rarity threshold for {} must be positive",
                    raw.tenant_id
                ));
            }
            raw.prevalence_snapshots.validate().map_err(|error| {
                format!(
                    "shared lake prevalence assignment for {} is invalid: {error}",
                    raw.tenant_id
                )
            })?;
            if !endpoints.insert(raw.internal_endpoint.clone()) {
                return Err("shared lake worker registry contains a duplicate endpoint".to_string());
            }
            if !identities.insert((
                raw.expected_worker_identity.clone(),
                raw.expected_worker_revision,
            )) {
                return Err(
                    "shared lake worker registry contains a duplicate worker identity/revision"
                        .to_string(),
                );
            }
            let enrichment_coordinator = match raw.enrichment_coordinator {
                None => None,
                Some(coordinator) => {
                    validate_internal_worker_endpoint(&coordinator.internal_endpoint)?;
                    if !endpoints.insert(coordinator.internal_endpoint.clone()) {
                        return Err(
                            "shared lake worker registry reuses an endpoint for an enrichment coordinator"
                                .to_string(),
                        );
                    }
                    let canonical = admit_private_credential_file(
                        &coordinator.credential_file,
                        &raw.tenant_id,
                        "enrichment coordinator",
                    )?;
                    if !credential_files.insert(canonical.clone()) {
                        return Err(
                            "shared lake worker registry reuses a credential reference for an enrichment coordinator"
                                .to_string(),
                        );
                    }
                    if coordinator.timeout_secs == 0 || coordinator.timeout_secs > 3_600 {
                        return Err(format!(
                            "shared lake enrichment coordinator timeout for {} must be between 1 and 3600 seconds",
                            raw.tenant_id
                        ));
                    }
                    Some(SharedLakeEnrichmentCoordinatorAssignment {
                        internal_endpoint: coordinator.internal_endpoint,
                        credential_file: canonical,
                        timeout_secs: coordinator.timeout_secs,
                    })
                }
            };
            let otel_ingest = match raw.otel_ingest {
                None => None,
                Some(otel) => {
                    validate_internal_worker_endpoint(&otel.internal_endpoint)?;
                    if !endpoints.insert(otel.internal_endpoint.clone()) {
                        return Err(
                            "shared lake worker registry reuses an endpoint for an OTLP ingest service"
                                .to_string(),
                        );
                    }
                    let canonical = admit_private_credential_file(
                        &otel.credential_file,
                        &raw.tenant_id,
                        "OTLP ingest service",
                    )?;
                    if !credential_files.insert(canonical.clone()) {
                        return Err(
                            "shared lake worker registry reuses a credential reference for an OTLP ingest service"
                                .to_string(),
                        );
                    }
                    if otel.timeout_secs == 0 || otel.timeout_secs > 3_600 {
                        return Err(format!(
                            "shared lake OTLP ingest timeout for {} must be between 1 and 3600 seconds",
                            raw.tenant_id
                        ));
                    }
                    Some(SharedLakeOtelIngestAssignment {
                        internal_endpoint: otel.internal_endpoint,
                        credential_file: canonical,
                        timeout_secs: otel.timeout_secs,
                    })
                }
            };
            let erasure_executor = match raw.erasure_executor {
                None => None,
                Some(executor) => {
                    let node = executor.executor_node.trim();
                    if node.is_empty()
                        || node.len() > 128
                        || node.chars().any(|c| c.is_control() || c.is_whitespace())
                        || executor.render_revision == 0
                    {
                        return Err(format!(
                            "shared lake erasure executor for {} must name one bounded node and a positive render revision",
                            raw.tenant_id
                        ));
                    }
                    Some(SharedLakeErasureExecutorAssignment {
                        executor_node: node.to_string(),
                        render_revision: executor.render_revision,
                    })
                }
            };
            let assignment = SharedLakeWorkerAssignment {
                tenant_id: raw.tenant_id,
                internal_endpoint: raw.internal_endpoint,
                // Keep the exact path whose identity was admitted. Reading the
                // original symlink later would reopen a validation/use race in
                // which it could be retargeted to another tenant's secret.
                credential_file: canonical_credential_file,
                expected_worker_identity: raw.expected_worker_identity,
                expected_worker_revision: raw.expected_worker_revision,
                timeout_secs: raw.timeout_secs,
                prevalence_snapshots: raw.prevalence_snapshots,
                prevalence_rarity_threshold: raw.prevalence_rarity_threshold,
                prevalence_timeout_secs: raw.prevalence_timeout_secs,
                enrichment_coordinator,
                otel_ingest,
                erasure_executor,
            };
            if assignments
                .insert(assignment.tenant_id, assignment)
                .is_some()
            {
                return Err("shared lake worker registry contains a duplicate tenant".to_string());
            }
        }
        Ok(Self {
            assignments,
            cells: None,
            readiness: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    /// The lake backend of exactly this authenticated tenant (NAN-2891).
    /// `None` when the tenant has neither a cell route nor a gen1 assignment.
    /// Callers pass the tenant UUID of the authenticated scope, never a value
    /// taken from the request.
    pub fn backend(&self, tenant_id: Uuid) -> Option<LakeBackend<'_>> {
        match self.cell_route(tenant_id) {
            Some(route) => Some(LakeBackend::Cell(route)),
            None => self.assignments.get(&tenant_id).map(LakeBackend::Gen1),
        }
    }

    /// The backend of this authenticated tenant, admitted against the
    /// signed PostgreSQL search authority (worker identity / revision) that
    /// authorised the call. A gen1 backend must name exactly that worker; a
    /// cell backend is admitted by its own route (a lean tenant never needs a
    /// gen1 registry entry). `None` for an unknown tenant or a mismatch.
    pub fn authorized_backend(
        &self,
        tenant_id: Uuid,
        authority_worker_identity: &str,
        authority_worker_revision: i64,
    ) -> Option<LakeBackend<'_>> {
        let backend = self.backend(tenant_id)?;
        let allowed = match &backend {
            LakeBackend::Gen1(assignment) => {
                assignment.tenant_id == tenant_id
                    && assignment.expected_worker_identity == authority_worker_identity
                    && i64::try_from(assignment.expected_worker_revision).ok()
                        == Some(authority_worker_revision)
            }
            LakeBackend::Cell(route) => route.tenant_id == tenant_id,
        };
        allowed.then_some(backend)
    }

    /// This tenant's lean-lake cell route, if it is placed on a cell now.
    pub fn cell_route(&self, tenant_id: Uuid) -> Option<std::sync::Arc<super::lake_cell::LakeCellRoute>> {
        self.cells.as_ref().and_then(|cells| cells.route(tenant_id))
    }

    /// Number of lean-lake cell routes (0 when the feature is dark).
    pub fn cell_route_count(&self) -> usize {
        self.cells.as_ref().map_or(0, |cells| cells.current().len())
    }

    /// The live cell route source (`None` when cells are dark).
    pub fn cell_source(&self) -> Option<std::sync::Arc<super::lake_cell::LakeCellRouteSource>> {
        self.cells.clone()
    }

    /// NAN-4149: whether this registry's tenant set is authoritative yet:
    /// true for a gen1-only registry, and for a cell registry once its routes
    /// map has been loaded at least once in this process.
    pub fn routes_loaded(&self) -> bool {
        self.cells.as_ref().is_none_or(|cells| cells.has_loaded())
    }

    /// Whether this tenant is currently placed on a lean-lake cell.
    pub fn is_cell_tenant(&self, tenant_id: Uuid) -> bool {
        self.cell_route(tenant_id).is_some()
    }

    pub fn assignment(&self, tenant_id: Uuid) -> Option<&SharedLakeWorkerAssignment> {
        self.assignments.get(&tenant_id)
    }

    /// Every server-owned tenant assignment (NAN-2718: the per-tenant schema
    /// cache refreshes each tenant from its own worker).
    pub fn assignments(&self) -> impl Iterator<Item = &SharedLakeWorkerAssignment> {
        self.assignments.values()
    }

    /// Every tenant that carries an `otel_ingest` service (NAN-2361 wave 6).
    pub fn otel_ingest_assignments(
        &self,
    ) -> impl Iterator<Item = (Uuid, &SharedLakeOtelIngestAssignment)> {
        self.assignments
            .iter()
            .filter_map(|(tenant_id, assignment)| {
                assignment.otel_ingest.as_ref().map(|otel| (*tenant_id, otel))
            })
    }

    /// Whether the tenant has an erasure executor: a gen1 assignment whose
    /// render runs `lake_erasure_execute` (NAN-2361 wave 6), or (NAN-3867) a
    /// lean cell tenant whose cell declares one
    /// ([`Self::cell_erasure_executor`]). Unknown tenants are `false`.
    pub fn erasure_executor_assigned(&self, tenant_id: Uuid) -> bool {
        self.assignments
            .get(&tenant_id)
            .is_some_and(|assignment| assignment.erasure_executor.is_some())
            || self.cell_erasure_executor(tenant_id).is_some()
    }

    /// NAN-3867: the lean erasure executor node declared for this cell
    /// tenant (`erasure-executors.json`), only on a fenced route.
    pub fn cell_erasure_executor(&self, tenant_id: Uuid) -> Option<String> {
        self.cells.as_ref()?.erasure_executor(tenant_id)
    }

    pub fn len(&self) -> usize {
        self.assignments.len()
    }

    /// Deep readiness for every server-owned tenant assignment.
    ///
    /// Enterprise-shared mode deliberately has no process-global lake tenant,
    /// so probing the singleton SearchService would always report unavailable.
    /// Verify the actual registry instead, including each worker's response
    /// tenant and assignment identity. Run the checks concurrently and bound
    /// the aggregate probe so one broken worker cannot hang a Kubernetes
    /// readiness request beyond its own timeout.
    pub async fn all_workers_ready(&self) -> bool {
        // Hold the slot across the probe so concurrent probes coalesce into
        // one fan-out instead of each racing the workers.
        let mut cached = self.readiness.lock().await;
        if let Some((at, ready)) = *cached {
            if at.elapsed() < READINESS_CACHE_TTL {
                return ready;
            }
        }
        let ready = self.probe_all_workers().await;
        *cached = Some((std::time::Instant::now(), ready));
        ready
    }

    async fn probe_all_workers(&self) -> bool {
        // NAN-2891: cell tenants are not part of the fleet verdict. Probing
        // query[T] would wake every pooled tenant each readiness period, and a
        // cell outage must not take gen1 tenants' Search out of rotation; a
        // cell tenant's queries answer 503 on their own instead.
        let checks = self
            .assignments
            .values()
            .filter(|assignment| !self.is_cell_tenant(assignment.tenant_id))
            .map(|assignment| async move {
            let tenant = assignment.tenant_id.clone();
            let result: Result<(), String> = async {
                #[cfg(feature = "enterprise")]
                let config = LakeQueryRuntime::from_enterprise_shared_assignment(assignment)?;
                #[cfg(not(feature = "enterprise"))]
                let config = Err::<LakeQueryRuntime, String>(
                    "shared lake worker assignments require the enterprise build".to_string(),
                )?;
                let client = config
                    .client
                    .as_ref()
                    .ok_or_else(|| "shared worker assignment produced no query client".to_string())?;
                client.health().await.map_err(|error| error.to_string())
            }
            .await;
            if let Err(error) = &result {
                // Readiness verdicts are aggregate; name the tenant and the
                // reason so a single unready worker is attributable without
                // reproducing the probe by hand.
                tracing::warn!(tenant = %tenant, error = %error, "shared lake worker readiness probe failed");
            }
            result
        });
        let result = tokio::time::timeout(
            Duration::from_millis(1_500),
            futures::future::join_all(checks),
        )
        .await;
        match result {
            Ok(results) => results.iter().all(Result::is_ok),
            Err(_) => false,
        }
    }
}

/// Admit a credential reference the way the query-worker file is admitted:
/// absolute, a regular file, private (no group/other bits), and canonical
/// so symlink aliases cannot disguise one secret as two.
pub(crate) fn admit_private_credential_file(path: &Path, tenant_id: &Uuid, what: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("shared lake {what} credential reference for {tenant_id} must be absolute"));
    }
    let metadata = std::fs::metadata(path)
        .map_err(|_| format!("shared lake {what} credential reference for {tenant_id} is unavailable"))?;
    if !metadata.is_file() {
        return Err(format!("shared lake {what} credential reference for {tenant_id} is unavailable"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!("shared lake {what} credential reference for {tenant_id} is not private"));
        }
    }
    std::fs::canonicalize(path)
        .map_err(|_| format!("shared lake {what} credential reference for {tenant_id} is unavailable"))
}

pub(crate) fn validate_internal_worker_endpoint(value: &str) -> Result<(), String> {
    let parsed = Url::parse(value)
        .map_err(|error| format!("invalid shared lake internal endpoint: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        return Err(
            "shared lake internal endpoint must be an HTTP(S) origin with an explicit port"
                .to_string(),
        );
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "shared lake internal endpoint must have a host".to_string())?;
    let private_ip = host.parse::<IpAddr>().is_ok_and(|address| match address {
        IpAddr::V4(address) => address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => address.is_unique_local() || address.is_unicast_link_local(),
    });
    let cluster_dns = host.ends_with(".svc") || host.ends_with(".svc.cluster.local");
    if !private_ip && !cluster_dns {
        return Err(
            "shared lake worker endpoint must use private IP space or Kubernetes service DNS"
                .to_string(),
        );
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    let value = std::env::var(name).unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        Err(format!(
            "{name} is required when lake query mode is enabled"
        ))
    } else {
        Ok(value.to_string())
    }
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Classify the worker's fail-closed event-publication gate as the transient
/// dependency outage it is.
///
/// When the signed hot-tail publisher is frozen or carries an old unpublished
/// backlog, the worker refuses to serve an incomplete event view and answers
/// HTTP 503 / `DEPENDENCY_UNAVAILABLE`. Folding that into a validation error
/// would surface a backend outage as a malformed query: HTTP 400 renders in the
/// UI as a query syntax failure and is never retried by a client retry policy.
/// The same condition already drives the worker's `/ready` 503, so the product
/// surfaces must agree with it.
fn lake_dependency_unavailable(
    status: reqwest::StatusCode,
    error_code: Option<&str>,
) -> Option<SearchError> {
    if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        || error_code == Some("DEPENDENCY_UNAVAILABLE")
    {
        return Some(SearchError::ServiceUnavailable(
            "lake event publication is temporarily unavailable; retry the request".to_string(),
        ));
    }
    None
}

/// NAN-2707: decide whether a worker 5xx is an outage or a query error.
///
/// The worker answers 500 with `error_code = QUERY_EXECUTION_FAILED` when the
/// embedded engine rejects the SQL for the analyst's query (for example, a type
/// error). That result is deterministic: retrying cannot help, and the worker
/// already sanitizes the diagnostic so it can be shown. Turning it into
/// "temporarily unavailable; retry shortly" hid a query bug behind a fake
/// outage. Only that coded rejection falls through to the query-error path;
/// every other 5xx, including one with no parseable envelope, is still an
/// outage.
fn lake_server_error_unavailable(
    status: reqwest::StatusCode,
    envelope: Option<&LakeQueryEnvelope>,
) -> Option<SearchError> {
    if !status.is_server_error() {
        return None;
    }
    let engine_rejection = status == reqwest::StatusCode::INTERNAL_SERVER_ERROR
        && envelope.is_some_and(|envelope| {
            !envelope.ok && envelope.error_code.as_deref() == Some(LAKE_QUERY_EXECUTION_FAILED)
        });
    if engine_rejection {
        return None;
    }
    Some(SearchError::ServiceUnavailable(format!(
        "lake query worker returned {status}"
    )))
}

/// Worker `error_code` for a query its embedded engine refused (see
/// `ServiceError::Execution` in nanosiem-lake-worker).
const LAKE_QUERY_EXECUTION_FAILED: &str = "QUERY_EXECUTION_FAILED";

fn validate_identity_snapshot_binding(
    expected: Option<&str>,
    actual: Option<&str>,
) -> Result<(), SearchError> {
    let actual = actual.filter(|value| {
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    });
    let Some(actual) = actual else {
        return Err(SearchError::SqlValidationError(
            "lake identity worker omitted its active immutable snapshot".to_string(),
        ));
    };
    if expected.is_some_and(|expected| expected != actual) {
        return Err(SearchError::SqlValidationError(
            "lake identity worker substituted the explicitly pinned snapshot".to_string(),
        ));
    }
    Ok(())
}

/// NAN-3245: does this `logs` request return full raw events (non-table-view,
/// filter/order/limit stages only)? Those rows are a `SELECT *` over the OCSF
/// union schema and are pruned to their populated fields; table-view list
/// rows, projections and aggregates keep their shape.
fn full_event_rows_requested(request: &SearchRequest) -> bool {
    !request.table_view && crate::search::sparse_event::query_returns_full_events(&request.query)
}

fn limit_transaction_event_previews(rows: &mut [serde_json::Value]) -> bool {
    let mut truncated_any = false;
    for row in rows {
        let Some(fields) = row.as_object_mut() else {
            continue;
        };
        let Some(events) = fields
            .get_mut("_raw_events")
            .and_then(serde_json::Value::as_array_mut)
        else {
            continue;
        };
        let materialized = events.len();
        if materialized <= TRANSACTION_EVENT_PREVIEW_LIMIT {
            continue;
        }
        events.truncate(TRANSACTION_EVENT_PREVIEW_LIMIT);
        fields.insert(
            "_raw_events_returned".to_string(),
            serde_json::Value::from(TRANSACTION_EVENT_PREVIEW_LIMIT),
        );
        fields.insert(
            "_raw_events_materialized".to_string(),
            serde_json::Value::from(materialized),
        );
        fields.insert(
            "_raw_events_truncated".to_string(),
            serde_json::Value::Bool(true),
        );
        truncated_any = true;
    }
    truncated_any
}

#[derive(Clone)]
pub(crate) struct LakeQueryClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    bearer_token: String,
    timeout: Duration,
    expected_worker_identity: Option<String>,
    expected_worker_revision: Option<u64>,
    /// NAN-2891: `base_url` is a lean-lake cell's per-tenant query[T] prefix
    /// (`{cell}/v1/tenants/{T}/query`), not a gen1 reader. query[T] has no
    /// gen1 generation/identity surface; see the `lake_cell` branches.
    lake_cell: bool,
    /// NAN-2891: cell clients re-read the router bearer from this CONFIGURED
    /// path on every call (never a resolved symlink target), so a rotated
    /// token is picked up without rebuilding the client. `bearer_token` is
    /// unused on a cell client.
    router_token_file: Option<std::path::PathBuf>,
    /// NAN-3492: set only for the trusted-local single-tenant install's
    /// dedicated cell client (explicit `NANO_TRUSTED_LOCAL`, see
    /// [`super::lake_cell::trusted_local_from_env`]). It alone admits the
    /// tenantless durable result references that install's job store writes.
    trusted_local: bool,
}

/// query[T]'s `GET /v1/schema/manifest` (NAN-2997).
#[derive(Debug, Deserialize)]
pub(crate) struct LakeCellSchemaManifest {
    ok: bool,
    tenant_id: String,
    #[serde(default)]
    source_mode: Option<String>,
    pub(crate) schema_digest: String,
    /// Leaf path -> part-schema type name (`string`, `long`, `array`, ...).
    pub(crate) field_types: std::collections::BTreeMap<String, String>,
}

/// query[T]'s `GET /v1/status` (NAN-2891).
#[derive(Debug, Deserialize)]
struct LakeCellQueryStatus {
    ok: bool,
    tenant_id: String,
    #[serde(default)]
    source_mode: Option<String>,
    #[serde(default)]
    durable_jobs_ready: bool,
    #[serde(default)]
    generation_id: Option<String>,
    #[serde(default)]
    generation_snapshot_id: Option<i64>,
    #[serde(default)]
    event_config_sha256: Option<String>,
    #[serde(default)]
    compiler_sha256: Option<String>,
    #[serde(default)]
    native_artifact_sha256: Option<String>,
    #[serde(default)]
    log_head: Option<LakeCellLogHead>,
    /// NAN-3020: totals over the live part set (absent on older query[T]).
    #[serde(default)]
    live_parts: Option<LakeCellLiveParts>,
}

/// query[T]'s `live_parts` status block (NAN-3020): what the tenant's
/// verified part log holds right now (data files only).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub struct LakeCellLiveParts {
    pub parts: u64,
    pub rows: u64,
    pub data_bytes: u64,
    pub data_files: u64,
    #[serde(default)]
    pub min_time_us: Option<i64>,
    #[serde(default)]
    pub max_time_us: Option<i64>,
    #[serde(default)]
    pub last_added_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct LakeCellLogHead {
    seq: u64,
    sha256: String,
}

impl LakeCellQueryStatus {
    fn durable_pin(&self) -> Result<DurableLakeGenerationPin, SearchError> {
        if !self.ok || self.source_mode.as_deref() != Some("parts") || !self.durable_jobs_ready {
            return Err(SearchError::ServiceUnavailable("lean-lake cell is not ready for durable work".into()));
        }
        let pin = DurableLakeGenerationPin {
            generation_id: self.generation_id.clone().ok_or_else(|| SearchError::ServiceUnavailable("cell generation ID is missing".into()))?,
            snapshot_id: self.generation_snapshot_id.ok_or_else(|| SearchError::ServiceUnavailable("cell snapshot ID is missing".into()))?,
            event_config_sha256: self.event_config_sha256.clone().ok_or_else(|| SearchError::ServiceUnavailable("cell event config digest is missing".into()))?,
            compiler_sha256: self.compiler_sha256.clone().ok_or_else(|| SearchError::ServiceUnavailable("cell compiler digest is missing".into()))?,
            native_artifact_sha256: self.native_artifact_sha256.clone().ok_or_else(|| SearchError::ServiceUnavailable("cell native artifact digest is missing".into()))?,
            iceberg_metadata_location: None,
            hot_tail_manifest_sha256: None,
            hot_tail_snapshot_id: None,
            hot_tail_id: None,
        };
        pin.validate().map_err(|error| SearchError::ServiceUnavailable(error.to_string()))?;
        Ok(pin)
    }
}

/// Parse the three physical scan fences emitted by query[T], including
/// archived cells. Never infer a byte estimate from native time/memory errors.
fn cell_scan_budget_bytes(message: &str) -> Option<(u64, u64)> {
    for (prefix, middle) in [
        ("query scan budget rejected ", " bytes above "),
        ("interactive query scan estimate ", " exceeds budget "),
        ("query needs ", " cold bytes, over the per-query reader cache budget of "),
    ] {
        if let Some((_, rest)) = message.split_once(prefix) {
            let (estimated, rest) = rest.split_once(middle)?;
            let budget = rest.split(|c: char| !c.is_ascii_digit()).next()?;
            return Some((estimated.parse().ok()?, budget.parse().ok()?));
        }
    }
    None
}

/// NAN-3644: the bytes of a reader-ceiling refusal whose type a cell erased
/// to text (`query needs N uncached bytes in one pass, over the C bytes …`).
fn cell_cold_ceiling_bytes(message: &str) -> Option<(u64, u64)> {
    let (_, rest) = message.split_once("query needs ")?;
    let (needed, rest) = rest.split_once(" uncached bytes in one pass, over the ")?;
    let ceiling = rest.split(|c: char| !c.is_ascii_digit()).next()?;
    Some((needed.parse().ok()?, ceiling.parse().ok()?))
}

/// query[T]'s error body (`{"ok": false, "error", "reason"}`) and the cell
/// router's (`{"error"}`), read only on cell clients.
#[derive(Debug, Default, Deserialize)]
struct LakeCellErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    estimated_bytes: Option<u64>,
    #[serde(default)]
    needed_bytes: Option<u64>,
    #[serde(default)]
    budget_bytes: Option<u64>,
    /// NAN-3644: a `cold_scan_too_large` refusal's reader ceilings.
    #[serde(default)]
    ceiling_bytes: Option<u64>,
    #[serde(default)]
    background_ceiling_bytes: Option<u64>,
    /// `role_spawn_blocked`: the tenant role the cell cannot start and the
    /// control plane's refusal code (e.g. `detect_drain_disabled`).
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    refusal: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LakeWorkerGenerationHealth {
    status: String,
    tenant_id: String,
    event_generation_id: String,
    generation_snapshot_id: i64,
    #[serde(default)]
    iceberg_metadata_location: Option<String>,
    event_config_sha256: String,
    compiler_sha256: String,
    native_artifact_sha256: String,
    hot_tail_manifest_sha256: Option<String>,
    hot_tail_snapshot_id: Option<i64>,
    hot_tail_id: Option<String>,
    #[serde(default)]
    worker_assignment_identity: Option<String>,
    #[serde(default)]
    worker_assignment_revision: Option<u64>,
    /// Executor health reported separately from the rolled-up `status`, so a
    /// publication-only degradation can be told apart from executor pressure.
    #[serde(default)]
    executor_status: Option<String>,
    /// Publication liveness, reported independently of executor pressure.
    #[serde(default)]
    hot_tail_publication: Option<LakeWorkerPublicationHealth>,
}

impl LakeWorkerGenerationHealth {
    fn interactive_ready(&self) -> bool {
        self.status == "ok"
            && self
                .executor_status
                .as_deref()
                .is_none_or(|status| status == "ok")
            && self
                .hot_tail_publication
                .as_ref()
                .is_some_and(|publication| {
                    publication.status == "ok" && publication.verdict.as_deref() == Some("healthy")
                })
    }

    /// Whether a `degraded` worker is still fit for INTERACTIVE traffic:
    /// the executor is healthy and the only degradation is a `stale`
    /// hot-tail publication verdict (NAN-2361) — a correct, immutable event
    /// view that is merely missing recent events, which the worker serves
    /// with a loud completeness envelope. Older workers report no
    /// `executor_status`/`verdict`, so they never qualify and keep today's
    /// fail-closed behavior. `unservable` never qualifies.
    /// Interactive admission (NAN-2401): the executor is healthy and the
    /// hot-tail verdict is `healthy` or `stale`, regardless of whether the
    /// roll-up status is `ok` or `degraded`. Under a publication backlog
    /// (`publication_consumer_lag`) the worker reports `ok` + `stale`: a
    /// correct immutable view missing only the newest events, served with
    /// the completeness envelope. `unservable` never qualifies, and the
    /// durable pin path keeps its own stricter gate.
    fn interactive_servable(&self) -> bool {
        self.interactive_ready() || self.degraded_but_interactive_servable() || (
            self.status == "ok"
                && self.executor_status.as_deref().is_none_or(|status| status == "ok")
                && self
                    .hot_tail_publication
                    .as_ref()
                    .and_then(|publication| publication.verdict.as_deref())
                    == Some("stale")
        )
    }

    fn degraded_but_interactive_servable(&self) -> bool {
        self.status == "degraded"
            && self.executor_status.as_deref() == Some("ok")
            && self
                .hot_tail_publication
                .as_ref()
                .and_then(|publication| publication.verdict.as_deref())
                == Some("stale")
    }
}

#[derive(Debug, Deserialize)]
struct LakeWorkerPublicationHealth {
    /// "ok" or "degraded"; `degraded` means the signed hot-tail publisher is
    /// frozen, backlogged, or bound-exhausted.
    #[serde(default)]
    status: String,
    #[serde(default)]
    reason: Option<String>,
    /// Tri-state serving verdict ("healthy" / "stale" / "unservable"), added
    /// by NAN-2361 workers. `status` above intentionally keeps the ok/degraded
    /// contract so older cores stay fail-closed across version skew.
    #[serde(default)]
    verdict: Option<String>,
}

fn generation_pin_from_health(
    health: LakeWorkerGenerationHealth,
    expected_tenant_id: &str,
) -> Result<DurableLakeGenerationPin, SearchError> {
    generation_pin_from_health_with(health, expected_tenant_id, false)
}

/// `tolerate_stale_publication` is the interactive lane's stance: a `stale`
/// (never `unservable`) hot tail is served with a completeness envelope, so
/// the pin is still taken; the durable lane keeps refusing it.
fn generation_pin_from_health_with(
    health: LakeWorkerGenerationHealth,
    expected_tenant_id: &str,
    tolerate_stale_publication: bool,
) -> Result<DurableLakeGenerationPin, SearchError> {
    // A resource-exhausted interactive query can temporarily mark the serving
    // executor degraded while it recycles idle chDB connections. Durable work
    // runs in an isolated worker, so admission still needs the immutable event
    // generation identity during that recovery window. Reject only an invalid
    // status or tenant substitution here; `health()` remains the stricter
    // readiness gate for interactive traffic.
    if !matches!(health.status.as_str(), "ok" | "degraded")
        || health.tenant_id != expected_tenant_id
    {
        return Err(SearchError::SqlValidationError(
            "lake query worker health did not match the assigned tenant".to_string(),
        ));
    }
    // A durable pin is captured at SUBMISSION and reused by every retry, but it
    // records no ledger revision or coverage watermark. If publication is frozen
    // now, the tail this pin names is already missing events, and the job-mode
    // liveness gate at execution time cannot detect that -- by then the publisher
    // may be healthy again and the job would complete "successfully" over an
    // incomplete view. Executor `degraded` is still tolerated above (durable work
    // runs in an isolated worker); publication `degraded` is not.
    if let Some(publication) = health.hot_tail_publication.as_ref() {
        // Refuse on the legacy ok/degraded status AND, defense-in-depth, on
        // any non-healthy tri-state verdict a newer worker reports. `stale`
        // is interactive-servable but NEVER durable-pinnable: the pin records
        // no coverage watermark, so a job pinned now would later complete
        // "successfully" over an incomplete view.
        let stale_tolerated = tolerate_stale_publication
            && publication.verdict.as_deref() == Some("stale");
        if !stale_tolerated
            && (publication.status == "degraded"
                || publication
                    .verdict
                    .as_deref()
                    .is_some_and(|verdict| verdict != "healthy"))
        {
            return Err(SearchError::TenantLakePublicationDegraded(format!(
                "lake event publication is temporarily unavailable ({}); a durable query \
                 submitted now would be pinned to an incomplete event view -- retry the request",
                publication.reason.as_deref().unwrap_or("degraded")
            )));
        }
    }
    // NAN-2361 wave 8: the zero-snapshot bootstrap generation of an empty
    // Iceberg table is admitted as a durable pin (`event-0-…`, hot tail at 0),
    // so an empty tenant's search runs and returns zero rows. The pin's own
    // validation refuses any other zero snapshot.
    let pin = DurableLakeGenerationPin {
        generation_id: health.event_generation_id,
        event_config_sha256: health.event_config_sha256,
        snapshot_id: health.generation_snapshot_id,
        iceberg_metadata_location: health.iceberg_metadata_location,
        compiler_sha256: health.compiler_sha256,
        native_artifact_sha256: health.native_artifact_sha256,
        hot_tail_manifest_sha256: health.hot_tail_manifest_sha256,
        hot_tail_snapshot_id: health.hot_tail_snapshot_id,
        hot_tail_id: health.hot_tail_id,
    };
    pin.validate().map_err(|error| {
        SearchError::SqlValidationError(format!(
            "lake query worker health returned an invalid durable generation pin: {error}"
        ))
    })?;
    Ok(pin)
}

#[derive(Serialize)]
struct LakeResultPageRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    job_id: &'a str,
    manifest_uri: &'a str,
    manifest_sha256: &'a str,
    rows: u64,
    parts: usize,
    has_more: bool,
    page_rows: usize,
    page: usize,
}

#[derive(Deserialize)]
struct LakeResultPageEnvelope {
    ok: bool,
    request_id: Option<String>,
    tenant_id: Option<String>,
    route: Option<String>,
    error: Option<String>,
    error_code: Option<String>,
    result: Option<SearchJobResultPage>,
}

impl LakeQueryClient {
    fn verify_worker_assignment(
        &self,
        health: &LakeWorkerGenerationHealth,
    ) -> Result<(), SearchError> {
        if self.expected_worker_identity.as_deref() != health.worker_assignment_identity.as_deref()
            || self.expected_worker_revision != health.worker_assignment_revision
        {
            if self.expected_worker_identity.is_some() || self.expected_worker_revision.is_some() {
                return Err(SearchError::ServiceUnavailable(
                    "lake query worker assignment identity/revision mismatch".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Validate the immutable startup assignment on the response itself. A
    /// health check alone is insufficient because service discovery may route
    /// the following query/result read to a different worker. Dedicated
    /// clients retain their historical header-agnostic behavior.
    fn verify_response_assignment(
        &self,
        headers: &reqwest::header::HeaderMap,
    ) -> Result<(), SearchError> {
        let Some(expected_identity) = self.expected_worker_identity.as_deref() else {
            return Ok(());
        };
        let Some(expected_revision) = self.expected_worker_revision else {
            return Err(SearchError::ServiceUnavailable(
                "lake query worker assignment expectation is incomplete".to_string(),
            ));
        };
        let actual_identity = headers
            .get(WORKER_ASSIGNMENT_ID_HEADER)
            .and_then(|value| value.to_str().ok());
        let actual_revision = headers
            .get(WORKER_ASSIGNMENT_REVISION_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if actual_identity != Some(expected_identity) || actual_revision != Some(expected_revision)
        {
            return Err(SearchError::ServiceUnavailable(
                "lake query response assignment identity/revision mismatch".to_string(),
            ));
        }
        Ok(())
    }

    fn new(
        base_url: &str,
        tenant_id: String,
        bearer_token: String,
        timeout: Duration,
    ) -> Result<Self, String> {
        Self::new_inner(base_url, tenant_id, bearer_token, timeout, None, None)
    }

    fn new_with_assignment(
        base_url: &str,
        tenant_id: String,
        bearer_token: String,
        timeout: Duration,
        expected_worker_identity: String,
        expected_worker_revision: u64,
    ) -> Result<Self, String> {
        Self::new_inner(
            base_url,
            tenant_id,
            bearer_token,
            timeout,
            Some(expected_worker_identity),
            Some(expected_worker_revision),
        )
    }

    fn new_inner(
        base_url: &str,
        tenant_id: String,
        bearer_token: String,
        timeout: Duration,
        expected_worker_identity: Option<String>,
        expected_worker_revision: Option<u64>,
    ) -> Result<Self, String> {
        if tenant_id.trim().is_empty() {
            return Err("lake query tenant ID must not be empty".to_string());
        }
        let parsed = Url::parse(base_url)
            .map_err(|error| format!("invalid NANO_LAKE_QUERY_URL: {error}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("NANO_LAKE_QUERY_URL must use http or https".to_string());
        }
        if parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(
                "NANO_LAKE_QUERY_URL must be an origin without credentials, query, fragment, or path"
                    .to_string(),
            );
        }
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| format!("failed to build lake query HTTP client: {error}"))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token,
            timeout,
            expected_worker_identity,
            expected_worker_revision,
            lake_cell: false,
            router_token_file: None,
            trusted_local: false,
        })
    }

    /// A client for one tenant's lean-lake query[T] behind its cell router
    /// (NAN-2891). The base URL carries the tenant path the route rendered
    /// from the tenant UUID; the gen1 origin-only rule does not apply to it.
    pub(crate) fn new_lake_cell(
        route: &super::lake_cell::LakeCellRoute,
        timeout: Duration,
    ) -> Result<Self, String> {
        let tenant_id = route.tenant_id.as_hyphenated().to_string();
        route.validate_query_base()?;
        let http = super::lake_cell::lake_cell_http_client_builder(timeout)
            .build()
            .map_err(|error| format!("failed to build lake cell HTTP client: {error}"))?;
        Ok(Self {
            http,
            base_url: route.query_base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token: String::new(),
            timeout,
            expected_worker_identity: None,
            expected_worker_revision: None,
            lake_cell: true,
            router_token_file: Some(route.router_token_file.clone()),
            trusted_local: false,
        })
    }

    /// The bearer for the next request: the gen1 worker credential, or the
    /// cell router token re-read from its configured path.
    fn bearer(&self) -> Result<std::borrow::Cow<'_, str>, SearchError> {
        match &self.router_token_file {
            None => Ok(std::borrow::Cow::Borrowed(self.bearer_token.as_str())),
            Some(path) => super::lake_cell::router_bearer(path, &self.base_url)
                .map(std::borrow::Cow::Owned)
                .map_err(|error| {
                    SearchError::ServiceUnavailable(format!(
                        "lean-lake cell router token is unavailable: {error}"
                    ))
                }),
        }
    }

    /// The deadline an idempotent read's retries stay within: a cell
    /// client's request timeout (the retry covers a cell pod rolling away
    /// under a pooled connection); gen1 keeps its recovery window.
    fn read_deadline(&self) -> Option<Duration> {
        self.lake_cell.then_some(self.timeout)
    }

    /// The tenant query[T] prefix a cell client talks to.
    pub(crate) fn lake_cell_query_base(&self) -> Option<&str> {
        self.lake_cell.then_some(self.base_url.as_str())
    }

    /// Whether this client talks to a lean-lake cell's query[T].
    pub(crate) fn is_lake_cell(&self) -> bool {
        self.lake_cell
    }

    /// Whether this is the trusted-local install's dedicated cell client
    /// (NAN-3492). Never true for a hosted client.
    pub(crate) fn is_trusted_local(&self) -> bool {
        self.lake_cell && self.trusted_local
    }

    /// Mark a dedicated cell client trusted-local (NAN-3492). Only the
    /// explicit env opt-in calls this with `true`.
    pub(crate) fn with_trusted_local(mut self, trusted_local: bool) -> Self {
        self.trusted_local = trusted_local;
        self
    }

    fn lake_cell_unsupported(&self, what: &str) -> SearchError {
        SearchError::ServiceUnavailable(format!(
            "{what} is not served for lean-lake tenants yet (no wired query[T] interface)"
        ))
    }

    /// Classify a cell router / query[T] failure (NAN-2891). The router's
    /// 401/404/502/503 and query[T]'s 503 are outages, query[T]'s 413 is a
    /// scan-budget refusal, and its 400 is a query error. Only called on cell
    /// clients for a non-success status.
    fn lake_cell_failure(&self, status: reqwest::StatusCode, body: &[u8]) -> SearchError {
        let parsed: LakeCellErrorBody = serde_json::from_slice(body).unwrap_or_default();
        let message = parsed
            .error
            .unwrap_or_else(|| format!("lake cell returned HTTP {status}"));
        // Recognize archived cells that erased the cache type to internal/503.
        // The diagnostic is an exact known fence, never an arbitrary outage.
        // NAN-3644: `cold_scan_too_large` is the reader's ceiling (an OOM
        // safety net); a cell from before NAN-3644 still answers its old
        // per-query `cold_budget_exceeded` refusal during a roll, mapped to
        // the same error with that budget as the ceiling.
        let cold = match parsed.reason.as_deref() {
            Some("cold_scan_too_large") => parsed.needed_bytes.zip(parsed.ceiling_bytes)
                .map(|(needed, ceiling)| (needed, ceiling, parsed.background_ceiling_bytes)),
            Some("cold_budget_exceeded") => parsed.needed_bytes.zip(parsed.budget_bytes).map(|(needed, budget)| (needed, budget, None)),
            _ => None,
        }
            .or_else(|| cell_cold_ceiling_bytes(&message).map(|(needed, ceiling)| (needed, ceiling, None)))
            .or_else(|| message.contains(" cold bytes, over the per-query reader cache budget of ").then(|| cell_scan_budget_bytes(&message)).flatten()
                .map(|(needed, budget)| (needed, budget, None)));
        if let Some((needed_bytes, ceiling_bytes, background_ceiling_bytes)) = cold {
            return SearchError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_ceiling_bytes };
        }
        match (status.as_u16(), parsed.reason.as_deref()) {
            (401, _) => SearchError::ServiceUnavailable(
                "lean-lake cell router rejected the router token (HTTP 401): the mounted token does not match the cell's; check the nano-cell-router-token rollout".to_string(),
            ),
            // query[T]'s memory (503) or admission (429) budget refused this
            // one request (NAN-3046). Retryable; the search handler escalates
            // it to a durable job, detections retry it.
            (status, Some("query_budget_exhausted")) => SearchError::ResourceExhausted(
                if status == 429 { "concurrency" } else { "memory" }.to_string(),
            ),
            (413, _) | (_, Some("scan_budget_exhausted")) => {
                // Older cells carried exact estimates only in the diagnostic.
                // Preserve those rather than reducing every 413 to "scan".
                let bytes = parsed.estimated_bytes.zip(parsed.budget_bytes).or_else(|| cell_scan_budget_bytes(&message));
                SearchError::ResourceExhausted(bytes.map_or_else(
                    || "scan".to_string(),
                    |(estimated, budget)| format!("scan; estimated_bytes={estimated}; budget_bytes={budget}"),
                ))
            }
            // NAN-4593: a cancelled job (409 `job_cancelled`) or a statement
            // chDB cancelled (`QUERY_WAS_CANCELLED`, sent as a 422 query
            // failure) is a cancel, never "rejected query" or "retry".
            (409, Some("job_cancelled")) => SearchError::Cancelled,
            (_, Some("query_execution_failed")) if message.contains("QUERY_WAS_CANCELLED") => SearchError::Cancelled,
            (400, Some("invalid_request")) | (422, _) | (_, Some("query_execution_failed")) => {
                SearchError::SqlValidationError(format!("lake query rejected: {message}"))
            }
            (_, Some("role_spawn_blocked")) => SearchError::ServiceUnavailable(format!(
                "lean-lake cell cannot start the tenant's {} process: the control plane refused it ({}); the cell retries with backoff",
                parsed.role.as_deref().unwrap_or("unknown"),
                parsed.refusal.as_deref().unwrap_or("unknown"),
            )),
            _ => SearchError::ServiceUnavailable(format!(
                "lean-lake query service returned HTTP {status}; retry the request"
            )),
        }
    }

    /// query[T] readiness (NAN-2891): an authenticated `GET /v1/status`
    /// through the router, which must answer for exactly this tenant.
    async fn lake_cell_status(&self) -> Result<(), SearchError> {
        self.lake_cell_status_report().await.map(|_| ())
    }

    /// Tenant-bound committed head used by a live SSE follow. A changed digest
    /// at the same sequence is treated as a new snapshot, never as a cursor.
    pub(crate) async fn lake_cell_part_log_head(&self) -> Result<Option<(u64, String)>, SearchError> {
        if !self.lake_cell {
            return Err(self.lake_cell_unsupported("part-log follow"));
        }
        Ok(self.lake_cell_status_report().await?.log_head.map(|head| (head.seq, head.sha256)))
    }

    /// NAN-3020: the live part totals query[T] reports on `/v1/status`;
    /// `None` when the image predates the field.
    pub(crate) async fn lake_cell_live_parts(&self) -> Result<Option<LakeCellLiveParts>, SearchError> {
        if !self.lake_cell {
            return Err(self.lake_cell_unsupported("live part totals"));
        }
        Ok(self.lake_cell_status_report().await?.live_parts)
    }

    /// NAN-3644: the cold-read progress query[T] reports for the in-flight
    /// requests of `request_id` (`{request_id}` and `{request_id}-…`).
    /// `Ok(None)` when none is in flight or the cell predates the route.
    /// One short attempt, never retried: a missed poll is just a skipped tick.
    pub(crate) async fn lake_cell_cold_progress(&self, request_id: &str) -> Result<Option<LakeColdProgress>, SearchError> {
        if !self.lake_cell {
            return Ok(None);
        }
        let response = tokio::time::timeout(
            COLD_PROGRESS_TIMEOUT,
            self.http
                .get(format!("{}/v1/query/progress", self.base_url))
                .query(&[("request_id", request_id)])
                .bearer_auth(self.bearer()?)
                .send(),
        )
        .await
        .map_err(|_| SearchError::ServiceUnavailable("lake cold-progress poll timed out".to_string()))?
        .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(SearchError::ServiceUnavailable(format!("lake cold-progress poll returned HTTP {status}")));
        }
        let progress: LakeColdProgress = response.json().await.map_err(|error| self.map_transport_error(error))?;
        Ok(Some(progress))
    }

    /// NAN-3662: query[T]'s `POST /v1/ingest/refusals` answer for
    /// `[start_ms, end_ms)` (rows refused at admission per source lane), or
    /// `Ok(None)` from a cell that predates the route (404/405).
    pub(crate) async fn lake_cell_refusals(&self, start_ms: i64, end_ms: i64) -> Result<Option<serde_json::Value>, SearchError> {
        if !self.lake_cell {
            return Err(self.lake_cell_unsupported("per-source admission refusals"));
        }
        let response = tokio::time::timeout(
            self.timeout,
            self.http
                .post(format!("{}/v1/ingest/refusals", self.base_url))
                .bearer_auth(self.bearer()?)
                .json(&serde_json::json!({"start_ms": start_ms, "end_ms": end_ms}))
                .send(),
        )
        .await
        .map_err(|_| SearchError::ServiceUnavailable("lean-lake refusal read timed out".to_string()))?
        .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(SearchError::ServiceUnavailable(format!("lean-lake refusal read returned HTTP {status}")));
        }
        let body: serde_json::Value = response.json().await.map_err(|error| self.map_transport_error(error))?;
        Ok(Some(body))
    }

    async fn lake_cell_status_report(&self) -> Result<LakeCellQueryStatus, SearchError> {
        let response = tokio::time::timeout(
            HEALTH_TIMEOUT,
            self.http
                .get(format!("{}/v1/status", self.base_url))
                .bearer_auth(self.bearer()?)
                .send_idempotent_with_recovery_within(self.read_deadline()),
        )
        .await
        .map_err(|_| lake_worker_not_ready(&self.tenant_id, HEALTH_TIMEOUT))?
        .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| self.map_transport_error(error))?;
        if !status.is_success() {
            return Err(SearchError::ServiceUnavailable(format!(
                "lean-lake query service status returned HTTP {status}"
            )));
        }
        let report: LakeCellQueryStatus = serde_json::from_slice(&body).map_err(|_| {
            SearchError::ServiceUnavailable(
                "lean-lake query service returned an invalid status report".to_string(),
            )
        })?;
        if !report.ok
            || report.tenant_id != self.tenant_id
            || report.source_mode.as_deref().is_some_and(|mode| mode != "parts")
        {
            return Err(SearchError::ServiceUnavailable(
                "lean-lake query service is not ready for this tenant".to_string(),
            ));
        }
        if let Some(head) = &report.log_head {
            if head.sha256.len() != 64 || !head.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(SearchError::ServiceUnavailable(
                    "lean-lake query service returned an invalid part-log head".to_string(),
                ));
            }
        }
        Ok(report)
    }

    /// query[T]'s stored field inventory (NAN-2997): an authenticated
    /// `GET /v1/schema/manifest` through the router, which must answer for
    /// exactly this tenant with a content digest.
    pub(crate) async fn lake_cell_schema_manifest(&self) -> Result<LakeCellSchemaManifest, SearchError> {
        if !self.lake_cell {
            return Err(self.lake_cell_unsupported("the part-schema field inventory"));
        }
        let response = self
            .http
            .get(format!("{}/v1/schema/manifest", self.base_url))
            .bearer_auth(self.bearer()?)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| self.map_transport_error(error))?;
        if !status.is_success() {
            return Err(SearchError::ServiceUnavailable(format!(
                "lean-lake field inventory returned HTTP {status}"
            )));
        }
        let manifest: LakeCellSchemaManifest = serde_json::from_slice(&body).map_err(|_| {
            SearchError::ServiceUnavailable(
                "lean-lake query service returned an invalid field inventory".to_string(),
            )
        })?;
        if !manifest.ok
            || manifest.tenant_id != self.tenant_id
            || manifest.source_mode.as_deref().is_some_and(|mode| mode != "parts")
            || manifest.schema_digest.len() != 64
            || !manifest.schema_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SearchError::ServiceUnavailable(
                "lean-lake field inventory is not this tenant's".to_string(),
            ));
        }
        Ok(manifest)
    }

    /// query[T] `POST /v1/detections/plan` (NAN-2891). `Ok(None)` on a gen1
    /// client: gen1 readers have no detection gate.
    pub(crate) async fn detection_plan(
        &self,
        rule_id: &str,
        window_start_us: i64,
        window_end_us: i64,
        grid_us: Option<i64>,
    ) -> Result<Option<LakeDetectionPlan>, SearchError> {
        if !self.lake_cell {
            return Ok(None);
        }
        let mut payload = serde_json::json!({
            "rule_id": rule_id,
            "window_start_us": window_start_us,
            "window_end_us": window_end_us,
        });
        if let Some(grid_us) = grid_us {
            payload["grid_us"] = serde_json::Value::from(grid_us);
        }
        // Advisory: one short attempt, no retry. A slow or failed plan only
        // means the window runs without a late-window report.
        let response = self
            .http
            .post(format!("{}/v1/detections/plan", self.base_url))
            .bearer_auth(self.bearer()?)
            .timeout(LAKE_CELL_DETECTION_PLAN_TIMEOUT)
            .json(&payload)
            .send()
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| self.map_transport_error(error))?;
        if !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let plan: LakeDetectionPlan = serde_json::from_slice(&body).map_err(|_| {
            SearchError::ServiceUnavailable(
                "lean-lake detection gate returned an invalid plan".to_string(),
            )
        })?;
        Ok(Some(plan))
    }

    /// query[T] `POST /v1/detections/commit` (NAN-2891): record a completed
    /// rule window at the log seq its plan named. `Ok(false)` on gen1.
    pub(crate) async fn detection_commit(
        &self,
        rule_id: &str,
        log_seq: u64,
        evaluated_through_us: i64,
    ) -> Result<bool, SearchError> {
        if !self.lake_cell {
            return Ok(false);
        }
        let response = self
            .http
            .post(format!("{}/v1/detections/commit", self.base_url))
            .bearer_auth(self.bearer()?)
            .timeout(LAKE_CELL_DETECTION_COMMIT_TIMEOUT)
            .json(&serde_json::json!({
                "rule_id": rule_id,
                "log_seq": log_seq,
                "evaluated_through_us": evaluated_through_us,
            }))
            .send()
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| self.map_transport_error(error))?;
        if !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        Ok(true)
    }

    pub(crate) async fn health(&self) -> Result<(), SearchError> {
        if self.lake_cell {
            return self.lake_cell_status().await;
        }
        let health = self.worker_generation_health().await?;
        // A `stale` publication verdict with a healthy executor stays
        // interactive-servable (the worker attaches a completeness envelope to
        // every degraded response); refusing here would convert a maintenance
        // backlog into a total interactive outage. Anything else non-ok —
        // executor pressure, `unservable`, or an older worker that reports
        // neither field — refuses exactly as before.
        let servable = health.status == "ok" || health.degraded_but_interactive_servable();
        if !servable || health.tenant_id != self.tenant_id {
            return Err(SearchError::ServiceUnavailable(
                "lake query worker is not ready for interactive traffic".to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn generation_pin(&self) -> Result<DurableLakeGenerationPin, SearchError> {
        if self.lake_cell {
            // No gen1 generation exists over parts. Callers that only use the
            // pin as a cache identity treat this as "not cacheable".
            return Err(self.lake_cell_unsupported("a durable lake generation pin"));
        }
        let health = self.worker_generation_health().await?;
        generation_pin_from_health(health, &self.tenant_id)
    }

    pub(crate) async fn admission_generation(
        &self,
    ) -> Result<(DurableLakeGenerationPin, bool), SearchError> {
        if self.lake_cell {
            return Ok((self.lake_cell_status_report().await?.durable_pin()?, true));
        }
        let health = self.worker_generation_health().await?;
        let interactive = health.interactive_servable();
        Ok((
            generation_pin_from_health_with(health, &self.tenant_id, interactive)?,
            interactive,
        ))
    }

    /// Read the worker's identity/health report. NAN-2361 moved every
    /// identifying field off the unauthenticated `/health` probe onto the
    /// bearer-authenticated `/v1/identity` route, so this is an authenticated
    /// read like every other worker call.
    async fn worker_generation_health(&self) -> Result<LakeWorkerGenerationHealth, SearchError> {
    crate::request_timing::timed(crate::request_timing::Phase::Upstream, async {

        let response = tokio::time::timeout(
            HEALTH_TIMEOUT,
            self.http
                .get(format!("{}/v1/identity", self.base_url))
                .bearer_auth(self.bearer()?)
                .send_idempotent_with_recovery_within(self.read_deadline()),
        )
        .await
        .map_err(|_| lake_worker_not_ready(&self.tenant_id, HEALTH_TIMEOUT))?
        .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        let body = response.bytes().await.map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake query worker health response read failed: {error}"
            ))
        })?;
        let health: LakeWorkerGenerationHealth =
            serde_json::from_slice(&body).map_err(|error| {
                SearchError::SqlValidationError(format!(
                    "lake query worker returned invalid health JSON ({status}): {error}"
                ))
            })?;
        if !status.is_success() {
            return Err(SearchError::SqlValidationError(format!(
                "lake query worker health returned HTTP {status}"
            )));
        }
        self.verify_worker_assignment(&health)?;
        Ok(health)

    }).await
}

    /// NAN-3809: ask the tenant's cell whether a finished durable search job
    /// may be re-served. The cell reads the reuse marker it wrote next to the
    /// job's result pages and answers `true` only when the window is settled
    /// and its current data identity (overlapping parts, read schema, query
    /// artifacts, enrichment read authority) equals the one the job read.
    /// Anything else, including a cell without the route, is a miss.
    pub(crate) async fn settled_job_reuse_check(
        &self,
        job_id: &str,
        reference: &SearchJobResultRef,
    ) -> Result<bool, SearchError> {
        if !self.lake_cell
            || reference.tenant_id.is_none_or(|tenant| tenant.to_string() != self.tenant_id)
        {
            return Ok(false);
        }
        let response = self.http
            .post(format!("{}/v1/jobs/reuse-check", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&serde_json::json!({
                "tenant_id": self.tenant_id,
                "job_id": job_id,
                "manifest_sha256": reference.manifest_sha256,
            }))
            .send_idempotent_with_recovery_within(self.read_deadline()).await
            .map_err(|error| self.map_transport_error(error))?;
        if !response.status().is_success() {
            return Ok(false);
        }
        let body: serde_json::Value = response.json().await.map_err(|error| {
            SearchError::SqlValidationError(format!("cell returned an invalid reuse answer: {error}"))
        })?;
        Ok(body.get("tenant_id").and_then(serde_json::Value::as_str) == Some(self.tenant_id.as_str())
            && body.get("job_id").and_then(serde_json::Value::as_str) == Some(job_id)
            && body.get("reusable").and_then(serde_json::Value::as_bool) == Some(true))
    }

    pub(crate) async fn result_page(
        &self,
        scope: super::tenant::SearchTenantScope,
        job_id: &str,
        reference: &SearchJobResultRef,
        page: usize,
    ) -> Result<SearchJobResultPage, SearchError> {
    crate::request_timing::timed(crate::request_timing::Phase::Upstream, async {

        if page >= reference.parts {
            return Err(SearchError::SqlValidationError(
                "durable result page is out of range".to_string(),
            ));
        }
        if self.lake_cell {
            if self.trusted_local {
                // NAN-3492: the explicit trusted-local client. The admission
                // scope decides whether a reference may be tenantless: only
                // `Dedicated` admits one (`verify_stored_tenant`), every shared
                // scope still requires its own tenant. A stamped reference must
                // then name this cell.
                scope.verify_stored_tenant(reference.tenant_id).map_err(|error| {
                    SearchError::SqlValidationError(format!(
                        "cell result reference does not match the tenant scope: {error}"
                    ))
                })?;
                if reference.tenant_id.is_some_and(|tenant| tenant.to_string() != self.tenant_id) {
                    return Err(SearchError::SqlValidationError(
                        "cell result reference belongs to another tenant".to_string(),
                    ));
                }
            } else if reference.tenant_id.is_none_or(|tenant| tenant.to_string() != self.tenant_id) {
                // Every other cell client (hosted): the reference must carry
                // exactly this cell's tenant, whatever the scope.
                return Err(SearchError::SqlValidationError(
                    "cell result reference belongs to another tenant".to_string(),
                ));
            }
            let tenant_hash = hex::encode(Sha256::digest(self.tenant_id.as_bytes()));
            let r2_prefix = format!(
                "s3://nano-shared-r2-{0}/{0}/durable-query-result/v1/tenant-{tenant_hash}/job-{job_id}/attempt-",
                self.tenant_id,
            );
            if !reference.manifest_uri.starts_with("file://")
                && !(reference.manifest_uri.starts_with(&r2_prefix)
                    && reference.manifest_uri.ends_with("/manifest.json"))
            {
                return Err(SearchError::SqlValidationError(
                    "cell result reference is outside the tenant job prefix".to_string(),
                ));
            }
            let response = self.http
                .post(format!("{}/v1/jobs/result-page", self.base_url))
                .bearer_auth(self.bearer()?)
                .json(&serde_json::json!({
                    "tenant_id": self.tenant_id,
                    "job_id": job_id,
                    "reference": {
                        "manifest_uri": reference.manifest_uri,
                        "manifest_sha256": reference.manifest_sha256,
                        "rows": reference.rows,
                        "parts": reference.parts,
                        "has_more": reference.has_more,
                        "page_rows": reference.page_rows,
                    },
                    "page": page,
                }))
                .send_idempotent_with_recovery_within(self.read_deadline()).await
                .map_err(|error| self.map_transport_error(error))?;
            let status = response.status();
            let body = crate::search::view_memory::read_body(response, |error| self.map_transport_error(error))
                .await?;
            if !status.is_success() {
                return Err(self.lake_cell_failure(status, &body));
            }
            let mut result: SearchJobResultPage = serde_json::from_slice(&body).map_err(|error| {
                SearchError::SqlValidationError(format!("cell returned invalid result page: {error}"))
            })?;
            if result.page != page || result.pages != reference.parts
                || result.total_rows != reference.rows
                || result.row_offset != u64::try_from(page.saturating_mul(reference.page_rows)).unwrap_or(u64::MAX)
            {
                return Err(SearchError::SqlValidationError(
                    "cell result page substituted its artifact binding".to_string(),
                ));
            }
            limit_transaction_event_previews(&mut result.rows);
            return Ok(result);
        }
        let request_id = format!("job-page-{}", uuid::Uuid::now_v7());
        let response = self
            .http
            .post(format!("{}/v1/jobs/result-page", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&LakeResultPageRequest {
                request_id: &request_id,
                tenant_id: &self.tenant_id,
                job_id,
                manifest_uri: &reference.manifest_uri,
                manifest_sha256: &reference.manifest_sha256,
                rows: reference.rows,
                parts: reference.parts,
                has_more: reference.has_more,
                page_rows: reference.page_rows,
                page,
            })
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        let body = crate::search::view_memory::read_body(response, |error| {
            SearchError::SqlValidationError(format!(
                "lake result-page response read failed: {error}"
            ))
        }).await?;
        let envelope: LakeResultPageEnvelope = serde_json::from_slice(&body).map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake worker returned invalid result-page JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                || envelope.error_code.as_deref() == Some("DEPENDENCY_UNAVAILABLE")
            {
                return Err(SearchError::ServiceUnavailable(
                    "durable result storage is temporarily unavailable".to_string(),
                ));
            }
            return Err(SearchError::SqlValidationError(
                envelope
                    .error
                    .unwrap_or_else(|| "durable result page read failed".to_string()),
            ));
        }
        if envelope.request_id.as_deref() != Some(&request_id)
            || envelope.tenant_id.as_deref() != Some(&self.tenant_id)
            || envelope.route.as_deref() != Some("result_page")
        {
            return Err(SearchError::SqlValidationError(
                "lake result-page worker substituted its request binding".to_string(),
            ));
        }
        let mut result = envelope.result.ok_or_else(|| {
            SearchError::SqlValidationError("lake result-page response omitted rows".to_string())
        })?;
        if result.page != page
            || result.pages != reference.parts
            || result.total_rows != reference.rows
            || result.row_offset
                != u64::try_from(page.saturating_mul(reference.page_rows)).unwrap_or(u64::MAX)
        {
            return Err(SearchError::SqlValidationError(
                "lake result-page response substituted its artifact binding".to_string(),
            ));
        }
        limit_transaction_event_previews(&mut result.rows);
        Ok(result)

    }).await
}

    pub async fn search(
        &self,
        request: &SearchRequest,
        query_id: &str,
        risk_config: Option<&crate::risk::clickhouse_sql::RiskQueryConfig>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<SearchResponse, SearchError> {
        self.search_with_product_cursor(request, query_id, risk_config, deny_source_types, None)
            .await
    }

    pub(crate) async fn search_product_page(
        &self,
        request: &SearchRequest,
        query_id: &str,
        deny_source_types: &BTreeSet<String>,
        cursor: &crate::search::ProductViewCursor,
    ) -> Result<SearchResponse, SearchError> {
        self.search_with_product_cursor(request, query_id, None, deny_source_types, Some(cursor))
            .await
    }

    #[tracing::instrument(name = "db.lake.execute", skip_all, fields(db.response.rows = tracing::field::Empty))]
    async fn search_with_product_cursor(
        &self,
        request: &SearchRequest,
        query_id: &str,
        risk_config: Option<&crate::risk::clickhouse_sql::RiskQueryConfig>,
        deny_source_types: &BTreeSet<String>,
        cursor: Option<&crate::search::ProductViewCursor>,
    ) -> Result<SearchResponse, SearchError> {
        self.search_cursor_page(request, query_id, risk_config, deny_source_types, cursor)
            .await
            .map(|(response, _)| {
                tracing::Span::current().record("db.response.rows", response.results.len() as u64);
                response
            })
    }

    /// One `broad_npl` page, plus whether query[T] declared its rows raw
    /// events newest first (cursor-continuable).
    async fn search_cursor_page(
        &self,
        request: &SearchRequest,
        query_id: &str,
        risk_config: Option<&crate::risk::clickhouse_sql::RiskQueryConfig>,
        deny_source_types: &BTreeSet<String>,
        cursor: Option<&crate::search::ProductViewCursor>,
    ) -> Result<(SearchResponse, bool), SearchError> {
    crate::request_timing::timed(crate::request_timing::Phase::Upstream, async {

        let limit = request.limit.unwrap_or(DEFAULT_RESULT_LIMIT);
        if limit == 0 || limit > MAX_RESULT_LIMIT {
            return Err(SearchError::SqlValidationError(format!(
                "lake result limit must be between 1 and {MAX_RESULT_LIMIT}"
            )));
        }
        let offset = request.offset.unwrap_or(0);
        if offset > MAX_RESULT_LIMIT || offset.saturating_add(limit) > MAX_RESULT_LIMIT {
            return Err(SearchError::SqlValidationError(format!(
                "lake offset plus limit must not exceed {MAX_RESULT_LIMIT}"
            )));
        }
        let dataset = match crate::query::Dataset::from_selector(
            request.dataset.as_deref().unwrap_or("logs"),
        ) {
            crate::query::Dataset::Risk => "risk",
            _ => "logs",
        };
        let product_cursor = cursor.map(|cursor| {
            (cursor.time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true), cursor.event_uid.as_str())
        });
        let mut envelope = self
            .broad_npl_envelope(request, query_id, risk_config, deny_source_types, dataset, limit, offset,
                product_cursor.as_ref().map(|(time, uid)| (time.as_str(), *uid)))
            .await?;
        // NAN-3270: a newest-first page query[T] cut at its result byte
        // budget comes back with the rows that fit and the (time, uid) cursor
        // of the last one. Fill the requested page from that cursor instead
        // of failing or escalating it: the browser pages by offset, so a
        // short page would skip rows. Past a few hops (a page far wider than
        // one cell answer) it goes durable as before.
        let (mut hops, mut fill_wall_seconds) = (0_usize, 0.0_f64);
        loop {
            let Some(result) = envelope.result.as_mut() else { break };
            let Some(next) = result.continuation.take() else { break };
            let wanted = limit.saturating_sub(result.rows.len());
            if wanted == 0 {
                // Every requested row is in; more exist past the cut.
                result.page_has_more = Some(true);
                break;
            }
            if hops >= MAX_BYTE_CUT_FILL_HOPS {
                return Err(SearchError::ResourceExhausted("memory".to_string()));
            }
            hops += 1;
            let more = self
                .broad_npl_envelope(request, query_id, risk_config, deny_source_types, dataset, wanted, 0,
                    Some((next.cursor_time.as_str(), next.cursor_event_uid.as_str())))
                .await?;
            let more = more.result.ok_or_else(|| {
                SearchError::SqlValidationError("lake query worker response omitted result".to_string())
            })?;
            result.rows.extend(more.rows);
            result.result_rows = Some(result.rows.len());
            result.page_has_more = more.page_has_more;
            result.continuation = more.continuation;
            result.query_result_cache_hit &= more.query_result_cache_hit;
            fill_wall_seconds += more.wall_seconds.unwrap_or_default();
            if let Some(wall) = result.wall_seconds.as_mut() {
                *wall += more.wall_seconds.unwrap_or_default();
            }
        }
        if let Some(wall) = envelope.wall_seconds.as_mut() {
            *wall += fill_wall_seconds;
        }
        if hops > 0 {
            tracing::info!(query_id, hops, limit, "filled a byte-cut lake page from its continuation");
        }
        let newest_first = envelope
            .result
            .as_ref()
            .and_then(|result| result.newest_first_event_rows)
            .unwrap_or(false);
        if dataset == "logs" && full_event_rows_requested(request) {
            if let Some(result) = envelope.result.as_mut() {
                crate::search::sparse_event::sparse_full_event_rows(&mut result.rows);
            }
        }
        envelope.into_search_response(limit, offset).map(|response| (response, newest_first))

    }).await
}

    /// One `broad_npl` request to query[T], answered and bound-checked
    /// (NAN-3270: split out so a byte-cut page can be continued).
    #[allow(clippy::too_many_arguments)]
    async fn broad_npl_envelope(
        &self,
        request: &SearchRequest,
        query_id: &str,
        risk_config: Option<&crate::risk::clickhouse_sql::RiskQueryConfig>,
        deny_source_types: &BTreeSet<String>,
        dataset: &'static str,
        limit: usize,
        offset: usize,
        cursor: Option<(&str, &str)>,
    ) -> Result<LakeQueryEnvelope, SearchError> {
        let clear_boundaries: std::collections::BTreeMap<String, i64> = risk_config
            .map(|config| {
                let cleared = config.lake_cleared.as_ref().unwrap_or(&config.cleared);
                cleared
                    .entities()
                    .iter()
                    .zip(cleared.boundaries_micros())
                    .filter(|(entity, _)| !entity.is_empty())
                    .map(|(entity, boundary)| (entity.clone(), *boundary))
                    .collect()
            })
            .unwrap_or_default();
        let payload = LakeQueryRequest {
            request_id: query_id,
            tenant_id: &self.tenant_id,
            route: "broad_npl",
            dataset,
            query: &request.query,
            start: request.time_range.start.to_rfc3339(),
            end: request.time_range.end.to_rfc3339(),
            limit,
            offset,
            table_view: request.table_view,
            use_cache: request.use_cache,
            cursor_time: cursor.map(|(time, _)| time.to_string()),
            cursor_event_uid: cursor.map(|(_, event_uid)| event_uid),
            anchor_us: risk_config.map(|config| config.now.timestamp_micros()),
            decay: risk_config.map(|config| &config.decay),
            clear_boundaries,
            minimum_clear_revision: risk_config
                .and_then(|config| config.lake_minimum_clear_revision),
            watch_weights: risk_config
                .map(|config| config.cleared.watch().lake_map())
                .unwrap_or_default(),
            deny_source_types,
        };
        let sent = std::time::Instant::now();
        let bearer = self.bearer()?;
        crate::search::lake_debug::phase("broad_npl_auth", sent.elapsed());
        let encoding = std::time::Instant::now();
        let outgoing = self.http.post(format!("{}/v1/query", self.base_url))
            .bearer_auth(bearer).json(&payload);
        // NAN-3077 debug header; NAN-3406 per-request switch overrides.
        let outgoing = crate::search::lake_debug::lake_call_headers(outgoing, true);
        crate::search::lake_debug::phase("broad_npl_request_encode", encoding.elapsed());
        let waiting = std::time::Instant::now();
        let http_response = outgoing
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        crate::search::lake_debug::phase("broad_npl_headers_wait", waiting.elapsed());
        let status = http_response.status();
        self.verify_response_assignment(http_response.headers())?;
        let receiving = std::time::Instant::now();
        // NAN-3282: charged to the product view (if any) before decode.
        let body = crate::search::view_memory::read_body(http_response, |error| self.map_transport_error(error)).await?;
        crate::search::lake_debug::phase("broad_npl_response_read", receiving.elapsed());
        crate::search::lake_debug::record_response("broad_npl", query_id, sent, status.as_u16(), &body);
        if self.lake_cell && !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let decoding = std::time::Instant::now();
        let parsed = serde_json::from_slice::<LakeQueryEnvelope>(&body);
        crate::search::lake_debug::phase("broad_npl_response_decode", decoding.elapsed());
        if let Some(unavailable) = lake_server_error_unavailable(status, parsed.as_ref().ok()) {
            return Err(unavailable);
        }
        let envelope: LakeQueryEnvelope = parsed.map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake query worker returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            if let Some(unavailable) =
                lake_dependency_unavailable(status, envelope.error_code.as_deref())
            {
                return Err(unavailable);
            }
            if envelope.error_code.as_deref() == Some("RESOURCE_EXHAUSTED") {
                let kind = envelope
                    .error
                    .as_deref()
                    .and_then(|message| {
                        ["memory", "time", "scan"]
                            .into_iter()
                            .find(|kind| message.contains(kind))
                    })
                    .unwrap_or("resource");
                let detail = match (kind, envelope.estimated_bytes, envelope.budget_bytes) {
                    (_, Some(estimated), Some(budget)) => {
                        format!("{kind}; estimated_bytes={estimated}; budget_bytes={budget}")
                    }
                    _ => kind.to_string(),
                };
                return Err(SearchError::ResourceExhausted(detail));
            }
            let message = envelope
                .error
                .unwrap_or_else(|| format!("lake query worker returned HTTP {status}"));
            if message.to_ascii_lowercase().contains("cancelled") {
                return Err(SearchError::Cancelled);
            }
            return Err(SearchError::SqlValidationError(format!(
                "lake query rejected: {message}"
            )));
        }
        self.validate_envelope_binding(&envelope, query_id, "broad_npl")?;
        Ok(envelope)
    }

    /// NAN-3046: a raw-event lake search delivered in bounded pages, newest
    /// first, each continuing from the previous page's last (time,
    /// metadata.uid). Neither query[T] nor this process ever holds more than
    /// one page, whatever the requested limit. `on_page` receives each page's
    /// rows and returns false to stop (client gone).
    ///
    /// Returns `Ok(None)` without calling `on_page` when the query is not
    /// cursor-continuable (aggregates, sorts, projections without the cursor
    /// fields, older workers): the caller then runs the ordinary search.
    /// A page refused by query[T]'s memory budget is retried at half size.
    pub async fn search_paged<F, Fut>(
        &self,
        request: &SearchRequest,
        query_id: &str,
        deny_source_types: &BTreeSet<String>,
        page_rows: usize,
        mut on_page: F,
    ) -> Result<Option<PagedSearch>, SearchError>
    where
        F: FnMut(Vec<serde_json::Value>) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        const MIN_PAGE_ROWS: usize = 64;
        let total = request.limit.unwrap_or(DEFAULT_RESULT_LIMIT).min(MAX_RESULT_LIMIT);
        if request.offset.unwrap_or(0) != 0 || total == 0 || page_rows == 0 {
            return Ok(None);
        }
        // NAN-3060: one execution, streamed in pages, where the cell can.
        if self.lake_cell {
            match self
                .search_streamed(request, query_id, deny_source_types, page_rows.max(MIN_PAGE_ROWS), total, &mut on_page)
                .await?
            {
                StreamedRead::Done(paged) => return Ok(Some(paged)),
                StreamedRead::NotContinuable => return Ok(None),
                StreamedRead::Fallback => {}
            }
        }
        let mut page_rows = page_rows.max(MIN_PAGE_ROWS);
        let mut cursor: Option<crate::search::ProductViewCursor> = None;
        let mut paged = PagedSearch::default();
        let mut index = 0_u32;
        loop {
            let want = page_rows.min(total - paged.delivered);
            let mut page_request = request.clone();
            // One row past the page tells whether another page exists.
            page_request.limit = Some(want + 1);
            page_request.offset = Some(0);
            let page_id = format!("{query_id}-p{index}");
            let (mut response, newest_first) = match self
                .search_cursor_page(&page_request, &page_id, None, deny_source_types, cursor.as_ref())
                .await
            {
                Ok(page) => page,
                Err(SearchError::ResourceExhausted(kind))
                    if (kind == "memory" || kind == "concurrency") && page_rows > MIN_PAGE_ROWS =>
                {
                    page_rows = (page_rows / 2).max(MIN_PAGE_ROWS);
                    continue;
                }
                Err(error) => return Err(error),
            };
            index += 1;
            let has_more = response.results.len() > want;
            response.results.truncate(want);
            let next = if has_more {
                match response.results.last().map(crate::search::service::lake_product_cursor_for_row) {
                    Some(Ok(next)) => Some(next),
                    // No cursor fields: only a first page can still fall back.
                    _ if paged.delivered == 0 => return Ok(None),
                    Some(Err(error)) => return Err(error),
                    None => None,
                }
            } else {
                None
            };
            if paged.delivered == 0 {
                if !newest_first {
                    return Ok(None);
                }
                paged.first = Some(SearchResponse { results: Vec::new(), ..response.clone() });
            }
            let rows = std::mem::take(&mut response.results);
            paged.delivered += rows.len();
            paged.pages += 1;
            if !on_page(rows).await {
                paged.stopped = true;
                return Ok(Some(paged));
            }
            match next {
                Some(next) if paged.delivered < total => cursor = Some(next),
                _ => {
                    paged.truncated = has_more;
                    return Ok(Some(paged));
                }
            }
        }
    }

    /// NAN-3060: the whole paged read as ONE query[T] execution
    /// (`POST /v1/query/pages`), its rows streamed back as NDJSON pages. The
    /// cursor protocol below re-ran the full statement for every page.
    ///
    /// `Fallback` (then the cursor protocol runs) when the cell predates the
    /// route (404) or its chDB cannot stream (501), or when the single
    /// statement is over query[T]'s memory budget before its first page
    /// (smaller cursor pages may still fit). A concurrency refusal (429) is
    /// returned as is: the handler escalates it to a durable job.
    #[tracing::instrument(name = "db.lake.stream", skip_all)]
    async fn search_streamed<F, Fut>(
        &self,
        request: &SearchRequest,
        query_id: &str,
        deny_source_types: &BTreeSet<String>,
        page_rows: usize,
        total: usize,
        on_page: &mut F,
    ) -> Result<StreamedRead, SearchError>
    where
        F: FnMut(Vec<serde_json::Value>) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let payload = LakeQueryRequest {
            request_id: query_id,
            tenant_id: &self.tenant_id,
            route: "broad_npl",
            dataset: "logs",
            query: &request.query,
            start: request.time_range.start.to_rfc3339(),
            end: request.time_range.end.to_rfc3339(),
            limit: total,
            offset: 0,
            table_view: request.table_view,
            use_cache: false,
            cursor_time: None,
            cursor_event_uid: None,
            anchor_us: None,
            decay: None,
            clear_boundaries: std::collections::BTreeMap::new(),
            minimum_clear_revision: None,
            watch_weights: std::collections::BTreeMap::new(),
            deny_source_types,
        };
        let response = self
            .http
            .post(format!("{}/v1/query/pages?page_rows={page_rows}", self.base_url))
            .bearer_auth(self.bearer()?)
            .timeout(STREAMED_READ_TIMEOUT.max(self.timeout))
            .json(&payload);
        let response = crate::search::lake_debug::lake_call_headers(response, false)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        if !status.is_success() {
            let body = response.bytes().await.map_err(|error| self.map_transport_error(error))?;
            if matches!(status.as_u16(), 404 | 501) {
                return Ok(StreamedRead::Fallback);
            }
            return match self.lake_cell_failure(status, &body) {
                SearchError::ResourceExhausted(kind) if kind == "memory" => Ok(StreamedRead::Fallback),
                error => Err(error),
            };
        }
        let mut body = StreamedBody { response, lines: NdjsonLines::default(), idle: self.timeout };
        let mut paged = PagedSearch::default();
        let Some(first) = body.next_line(self).await? else {
            return Err(SearchError::ServiceUnavailable("lake query worker ended a streamed read before its first page".to_string()));
        };
        let mut envelope: LakeQueryEnvelope = serde_json::from_slice(&first).map_err(|error| {
            SearchError::SqlValidationError(format!("lake query worker returned an invalid streamed envelope: {error}"))
        })?;
        if !envelope.ok {
            return Err(SearchError::ServiceUnavailable("lake query worker refused the streamed read".to_string()));
        }
        self.validate_envelope_binding(&envelope, query_id, "broad_npl")?;
        let newest_first = envelope.result.as_ref().and_then(|result| result.newest_first_event_rows).unwrap_or(false);
        if !newest_first {
            return Ok(StreamedRead::NotContinuable);
        }
        // NAN-3245: the streamed route is `logs` only (see the payload).
        let full_events = full_event_rows_requested(request);
        if full_events {
            if let Some(result) = envelope.result.as_mut() {
                crate::search::sparse_event::sparse_full_event_rows(&mut result.rows);
            }
        }
        let mut first_page = envelope.into_search_response(total, 0)?;
        let rows = std::mem::take(&mut first_page.results);
        paged.first = Some(first_page);
        let mut deliver = |rows: Vec<serde_json::Value>, paged: &mut PagedSearch| {
            paged.delivered += rows.len();
            paged.pages += 1;
            on_page(rows)
        };
        if !deliver(rows, &mut paged).await {
            // Dropping the response closes the stream; query[T] cancels.
            paged.stopped = true;
            return Ok(StreamedRead::Done(paged));
        }
        loop {
            let Some(line) = body.next_line(self).await? else {
                return Err(SearchError::ServiceUnavailable(
                    "lake query worker ended a streamed read without its completion line".to_string(),
                ));
            };
            let message: StreamedLine = serde_json::from_slice(&line).map_err(|error| {
                SearchError::SqlValidationError(format!("lake query worker returned an invalid streamed page: {error}"))
            })?;
            match message {
                StreamedLine::Page { mut rows } => {
                    limit_transaction_event_previews(&mut rows);
                    if full_events {
                        crate::search::sparse_event::sparse_full_event_rows(&mut rows);
                    }
                    if !deliver(rows, &mut paged).await {
                        paged.stopped = true;
                        return Ok(StreamedRead::Done(paged));
                    }
                }
                StreamedLine::Done { has_more, delivered, .. } => {
                    if delivered != paged.delivered {
                        return Err(SearchError::ServiceUnavailable(format!(
                            "lake query worker streamed {} rows but reported {delivered}", paged.delivered
                        )));
                    }
                    paged.truncated = has_more;
                    return Ok(StreamedRead::Done(paged));
                }
                StreamedLine::Failed { status, error, reason, needed_bytes, budget_bytes, ceiling_bytes, background_ceiling_bytes } => {
                    let body = serde_json::json!({"ok": false, "error": error, "reason": reason, "needed_bytes": needed_bytes, "budget_bytes": budget_bytes,
                        "ceiling_bytes": ceiling_bytes, "background_ceiling_bytes": background_ceiling_bytes});
                    let status = reqwest::StatusCode::from_u16(status).unwrap_or(reqwest::StatusCode::SERVICE_UNAVAILABLE);
                    return Err(self.lake_cell_failure(status, body.to_string().as_bytes()));
                }
            }
        }
    }

    pub(crate) async fn explain(
        &self,
        request: &SearchRequest,
        request_id: &str,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<String, SearchError> {
        let limit = request.limit.unwrap_or(DEFAULT_RESULT_LIMIT);
        if limit == 0 || limit > MAX_RESULT_LIMIT {
            return Err(SearchError::SqlValidationError(format!(
                "lake result limit must be between 1 and {MAX_RESULT_LIMIT}"
            )));
        }
        let offset = request.offset.unwrap_or(0);
        if offset > MAX_RESULT_LIMIT || offset.saturating_add(limit) > MAX_RESULT_LIMIT {
            return Err(SearchError::SqlValidationError(format!(
                "lake offset plus limit must not exceed {MAX_RESULT_LIMIT}"
            )));
        }
        let dataset = match crate::query::Dataset::from_selector(
            request.dataset.as_deref().unwrap_or("logs"),
        ) {
            crate::query::Dataset::Risk => "risk",
            _ => "logs",
        };
        let payload = LakeQueryRequest {
            request_id,
            tenant_id: &self.tenant_id,
            route: "explain_npl",
            dataset,
            query: &request.query,
            start: request.time_range.start.to_rfc3339(),
            end: request.time_range.end.to_rfc3339(),
            limit,
            offset,
            table_view: request.table_view,
            use_cache: false,
            cursor_time: None,
            cursor_event_uid: None,
            anchor_us: None,
            decay: None,
            clear_boundaries: std::collections::BTreeMap::new(),
            minimum_clear_revision: None,
            watch_weights: std::collections::BTreeMap::new(),
            deny_source_types,
        };
        let response = self
            .http
            .post(format!("{}/v1/query", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&payload)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        let body = response.bytes().await.map_err(|error| {
            SearchError::SqlValidationError(format!("lake explain response read failed: {error}"))
        })?;
        if self.lake_cell && !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let envelope: LakeExplainEnvelope = serde_json::from_slice(&body).map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake worker returned invalid explain JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            // The explain envelope carries no error_code, but the transport status
            // alone identifies the fail-closed publication gate.
            if let Some(unavailable) = lake_dependency_unavailable(status, None) {
                return Err(unavailable);
            }
            return Err(SearchError::SqlValidationError(format!(
                "lake explain rejected: {}",
                envelope
                    .error
                    .unwrap_or_else(|| format!("worker returned HTTP {status}"))
            )));
        }
        if envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || envelope.request_id.as_deref() != Some(request_id)
            || envelope.route.as_deref() != Some("explain_npl")
        {
            return Err(SearchError::SqlValidationError(
                "lake explain worker substituted the tenant, request, or route binding".to_string(),
            ));
        }
        let result = envelope.result.ok_or_else(|| {
            SearchError::SqlValidationError("lake explain response omitted its plan".to_string())
        })?;
        let expected_placeholder = if dataset == "risk" {
            "__nano_risk_source__"
        } else {
            "__nano_lake_source__"
        };
        if result.sql.is_empty()
            || result.source_placeholder != expected_placeholder
            || !result.sql.contains(expected_placeholder)
        {
            return Err(SearchError::SqlValidationError(
                "lake explain response omitted its tenant-bound source placeholder".to_string(),
            ));
        }
        Ok(result.sql)
    }

    pub(crate) async fn count_aggregate(
        &self,
        request_id: &str,
        group_field: &str,
        group_results: bool,
        predicate: Option<&LakeCountPredicate>,
        bucket_span_us: Option<i64>,
        count_alias: &str,
        time_range: &TimeRangeInput,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
        max_groups: usize,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        self.count_aggregate_grouped(
            request_id,
            group_field,
            group_results,
            false,
            predicate,
            bucket_span_us,
            count_alias,
            time_range,
            source_filter,
            deny_source_types,
            max_groups,
        )
        .await
    }

    /// [`Self::count_aggregate`] that can group the rows matching `predicate`
    /// on `group_field` by their `metadata.log_source` (NAN-3153; rows then
    /// carry `metadata.log_source`). Excludes `group_results`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn count_aggregate_grouped(
        &self,
        request_id: &str,
        group_field: &str,
        group_results: bool,
        group_by_source: bool,
        predicate: Option<&LakeCountPredicate>,
        bucket_span_us: Option<i64>,
        count_alias: &str,
        time_range: &TimeRangeInput,
        source_filter: Option<&str>,
        deny_source_types: &BTreeSet<String>,
        max_groups: usize,
    ) -> Result<Vec<serde_json::Value>, SearchError> {
        let payload = LakeCountAggregateRequest {
            request_id,
            tenant_id: &self.tenant_id,
            group_field,
            group_results,
            group_by_source,
            predicate,
            bucket_span_us,
            count_alias,
            start: time_range.start.to_rfc3339(),
            // NAN-4280: search windows are half-open `[start, end)`; this
            // route's `end` is inclusive on the wire (the worker adds 1 µs),
            // so it gets the last covered microsecond. Converting here keeps
            // the wire contract (and so any worker/search roll order)
            // unchanged while rollup and scan agree about the end instant.
            end: (time_range.end - chrono::Duration::microseconds(1)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            source_filter,
            deny_source_types,
            max_groups,
        };
        let sent = std::time::Instant::now();
        let http_response = self
            .http
            .post(format!("{}/v1/aggregate/count", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&payload);
        let http_response = crate::search::lake_debug::lake_call_headers(http_response, false)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = http_response.status();
        self.verify_response_assignment(http_response.headers())?;
        let body = crate::search::view_memory::read_body(http_response, |error| {
            SearchError::SqlValidationError(format!(
                "lake count-rollup response read failed: {error}"
            ))
        }).await?;
        crate::search::lake_debug::record_response("count_aggregate", request_id, sent, status.as_u16(), &body);
        if self.lake_cell && !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let envelope: LakeQueryEnvelope = serde_json::from_slice(&body).map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake count-rollup worker returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            if let Some(unavailable) =
                lake_dependency_unavailable(status, envelope.error_code.as_deref())
            {
                return Err(unavailable);
            }
            let message = envelope
                .error
                .unwrap_or_else(|| format!("lake count-rollup worker returned HTTP {status}"));
            return Err(SearchError::SqlValidationError(format!(
                "lake count rollup rejected: {message}"
            )));
        }
        self.validate_envelope_binding(&envelope, request_id, "count_aggregate")?;
        // query[T] reads the verified part log, not a gen1 Iceberg generation:
        // its immutable binding is the log head the answer was computed at.
        if self.lake_cell {
            let rows = envelope.result.as_ref().map_or(0, |result| result.rows.len());
            if !valid_lake_cell_log_head(envelope.log_head.as_ref(), rows) {
                return Err(SearchError::SqlValidationError(
                    "lean-lake count rollup omitted its part-log head binding".to_string(),
                ));
            }
        } else if envelope
            .generation_id
            .as_deref()
            .is_none_or(|generation| generation.is_empty() || generation.len() > 256)
            || envelope
                .snapshot_id
                .as_deref()
                .is_none_or(|snapshot| snapshot.parse::<i64>().is_err())
        {
            return Err(SearchError::SqlValidationError(
                "lake count rollup omitted its immutable generation binding".to_string(),
            ));
        }
        let result = envelope.result.ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake count-rollup worker response omitted result".to_string(),
            )
        })?;
        if result.rows.len() > max_groups {
            return Err(SearchError::SqlValidationError(
                "lake count-rollup worker exceeded the requested group bound".to_string(),
            ));
        }
        Ok(result.rows)
    }

    /// NAN-3094: first/last event time and event count per value of one
    /// identity path, from query[T]'s entity-range partials (`/v1/entity/ranges`).
    /// Parts wholly inside the window answer from their partial; only the
    /// parts straddling a window edge read rows. There is no source-scope
    /// filter on this route, so callers must use it for unrestricted scopes
    /// only.
    pub(crate) async fn entity_ranges(
        &self,
        path: &str,
        values: &[String],
        time_range: &TimeRangeInput,
    ) -> Result<Vec<LakeEntityRange>, SearchError> {
        if !self.lake_cell {
            return Err(SearchError::ServiceUnavailable(
                "entity ranges are served by the lean-lake cell only".to_string(),
            ));
        }
        if values.is_empty() || values.len() > 1_000 {
            return Err(SearchError::SqlValidationError(
                "entity range request must name between 1 and 1000 values".to_string(),
            ));
        }
        let request_id = format!("asset-range-{}", uuid::Uuid::now_v7());
        let payload = LakeEntityRangesRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            path,
            values,
            start: time_range.start.to_rfc3339(),
            end: time_range.end.to_rfc3339(),
            case_insensitive: true,
        };
        let sent = std::time::Instant::now();
        let http_response = self
            .http
            .post(format!("{}/v1/entity/ranges", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&payload);
        let http_response = crate::search::lake_debug::lake_call_headers(http_response, false)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = http_response.status();
        self.verify_response_assignment(http_response.headers())?;
        let body = crate::search::view_memory::read_body(http_response, |error| {
            SearchError::SqlValidationError(format!(
                "lake entity-range response read failed: {error}"
            ))
        }).await?;
        crate::search::lake_debug::record_response(
            "entity_ranges",
            &request_id,
            sent,
            status.as_u16(),
            &body,
        );
        if !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let envelope: LakeEntityRangesEnvelope =
            serde_json::from_slice(&body).map_err(|error| {
                SearchError::SqlValidationError(format!(
                    "lake entity-range worker returned invalid JSON ({status}): {error}"
                ))
            })?;
        if !envelope.ok
            || envelope.request_id != request_id
            || envelope.tenant_id != self.tenant_id
            || envelope.route != "entity_ranges"
        {
            return Err(SearchError::SqlValidationError(
                "lake entity-range response is not bound to this request".to_string(),
            ));
        }
        let rows = envelope
            .result
            .map(|result| result.rows)
            .unwrap_or_default();
        if rows.len() > values.len() {
            return Err(SearchError::SqlValidationError(
                "lake entity-range worker returned more rows than requested values".to_string(),
            ));
        }
        Ok(rows)
    }

    pub(crate) async fn unmapped_field_names(&self) -> Result<Vec<String>, SearchError> {
        let request_id = uuid::Uuid::now_v7().to_string();
        let payload = LakeFieldNamesRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            route: "field_names",
        };
        let http_response = self
            .http
            .post(format!("{}/v1/query", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&payload)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = http_response.status();
        self.verify_response_assignment(http_response.headers())?;
        let body = http_response.bytes().await.map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake field-name response read failed: {error}"
            ))
        })?;
        if self.lake_cell && !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let envelope: LakeQueryEnvelope = serde_json::from_slice(&body).map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake field-name worker returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            if let Some(unavailable) =
                lake_dependency_unavailable(status, envelope.error_code.as_deref())
            {
                return Err(unavailable);
            }
            let message = envelope
                .error
                .clone()
                .unwrap_or_else(|| format!("lake field-name worker returned HTTP {status}"));
            return Err(SearchError::SqlValidationError(format!(
                "lake field-name discovery rejected: {message}"
            )));
        }
        self.validate_envelope_binding(&envelope, &request_id, "field_names")?;
        let result = envelope.result.ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake field-name worker response omitted result".to_string(),
            )
        })?;
        if result.rows.len() > 10_000 {
            return Err(SearchError::SqlValidationError(
                "lake field-name worker exceeded its response bound".to_string(),
            ));
        }
        let mut fields = BTreeSet::new();
        for row in result.rows {
            let field = row
                .get("field")
                .and_then(|value| value.as_str())
                .ok_or_else(|| {
                    SearchError::SqlValidationError(
                        "lake field-name worker returned an invalid row".to_string(),
                    )
                })?;
            if !field.starts_with("unmapped.") || field.len() > 1_024 {
                return Err(SearchError::SqlValidationError(
                    "lake field-name worker returned a non-canonical spill path".to_string(),
                ));
            }
            fields.insert(field.to_string());
        }
        Ok(fields.into_iter().collect())
    }

    pub async fn fetch_log_by_id(
        &self,
        id: &str,
        time_range: Option<&TimeRangeInput>,
        source_type: Option<&str>,
        deny_source_types: &BTreeSet<String>,
    ) -> Result<Option<serde_json::Value>, SearchError> {
        let request_id = uuid::Uuid::now_v7().to_string();
        let payload = LakeFetchLogRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            route: "fetch_log",
            id,
            start: time_range.map(|range| range.start.to_rfc3339()),
            end: time_range.map(|range| range.end.to_rfc3339()),
            log_source: source_type,
            deny_source_types,
        };
        let sent = std::time::Instant::now();
        let http_response = self
            .http
            .post(format!("{}/v1/query", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(&payload)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = http_response.status();
        self.verify_response_assignment(http_response.headers())?;
        let body = crate::search::view_memory::read_body(http_response, |error| {
            SearchError::SqlValidationError(format!("lake fetch-log response read failed: {error}"))
        }).await?;
        crate::search::lake_debug::record_response("fetch_log", &request_id, sent, status.as_u16(), &body);
        if self.lake_cell && !status.is_success() {
            return Err(self.lake_cell_failure(status, &body));
        }
        let envelope: LakeQueryEnvelope = serde_json::from_slice(&body).map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake fetch-log worker returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            if let Some(unavailable) =
                lake_dependency_unavailable(status, envelope.error_code.as_deref())
            {
                return Err(unavailable);
            }
            let message = envelope
                .error
                .unwrap_or_else(|| format!("lake fetch-log worker returned HTTP {status}"));
            return Err(SearchError::SqlValidationError(format!(
                "lake fetch-log rejected: {message}"
            )));
        }
        self.validate_envelope_binding(&envelope, &request_id, "fetch_log")?;
        let result = envelope.result.ok_or_else(|| {
            SearchError::SqlValidationError(
                "lake fetch-log worker response omitted result".to_string(),
            )
        })?;
        // NAN-3245: fetch-by-id is always a full event (a `SELECT *` over the
        // tenant's OCSF union schema): return its populated fields only.
        Ok(result.rows.into_iter().next().map(|mut row| {
            crate::search::sparse_event::sparse_full_event(&mut row);
            row
        }))
    }

    /// POST one identity request and return its rows plus whether the answer
    /// covered the whole lookback window.
    ///
    /// gen1 workers answer from their immutable snapshot (always complete).
    /// Lean cells (NAN-3058) answer from query[T]'s identity observation
    /// index; its `identity_index.state` is `complete` or `backfilling`.
    async fn identity_request<P: Serialize>(
        &self,
        path: &str,
        route: &str,
        request_id: &str,
        snapshot_id: Option<&str>,
        payload: &P,
    ) -> Result<(Vec<serde_json::Value>, bool), SearchError> {
        let sent = std::time::Instant::now();
        let http_response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(self.bearer()?)
            .json(payload);
        let http_response = crate::search::lake_debug::lake_call_headers(http_response, false)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = http_response.status();
        self.verify_response_assignment(http_response.headers())?;
        let body = crate::search::view_memory::read_body(http_response, |error| {
            SearchError::SqlValidationError(format!("lake {route} response read failed: {error}"))
        }).await?;
        crate::search::lake_debug::record_response(route, request_id, sent, status.as_u16(), &body);
        if self.lake_cell && !status.is_success() {
            // A cell image that predates the identity index answers its
            // gen1-only routes 503 `identity_snapshot_unavailable`: nothing is
            // indexed yet, so the caller takes the event-scan fallback.
            let parsed: LakeCellErrorBody = serde_json::from_slice(&body).unwrap_or_default();
            if status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                && parsed.reason.as_deref() == Some("identity_snapshot_unavailable")
            {
                return Ok((Vec::new(), false));
            }
            return Err(self.lake_cell_failure(status, &body));
        }
        let envelope: LakeQueryEnvelope = serde_json::from_slice(&body).map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake {route} worker returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !envelope.ok {
            let message = envelope
                .error
                .clone()
                .unwrap_or_else(|| format!("lake {route} worker returned HTTP {status}"));
            return Err(SearchError::SqlValidationError(format!(
                "lake {route} rejected: {message}"
            )));
        }
        self.validate_envelope_binding(&envelope, request_id, route)?;
        let complete = if self.lake_cell {
            let state = envelope
                .identity_index
                .as_ref()
                .and_then(|index| index.get("state"))
                .and_then(serde_json::Value::as_str);
            match state {
                Some("complete") => true,
                Some("backfilling") => false,
                _ => {
                    return Err(SearchError::SqlValidationError(
                        "lean identity index response omitted its coverage state".to_string(),
                    ))
                }
            }
        } else {
            validate_identity_snapshot_binding(snapshot_id, envelope.snapshot_id.as_deref())?;
            true
        };
        let result = envelope.result.ok_or_else(|| {
            SearchError::SqlValidationError(format!("lake {route} worker response omitted result"))
        })?;
        Ok((result.rows, complete))
    }

    /// Point-in-time IP identities for ≤ 500 items (see [`Self::identity_request`]).
    pub(crate) async fn resolve_identity_batch(
        &self,
        items: &[LakeIdentityBatchItem],
        deny_source_types: &BTreeSet<String>,
    ) -> Result<LakeIdentityAnswer<LakeIdentityBatchObservation>, SearchError> {
        if items.is_empty() || items.len() > 500 {
            return Err(SearchError::SqlValidationError(
                "lake identity batch must contain between 1 and 500 items".to_string(),
            ));
        }
        let snapshot_id = (!self.lake_cell).then(|| optional_env("NANO_LAKE_IDENTITY_SNAPSHOT")).flatten();
        let request_id = uuid::Uuid::now_v7().to_string();
        let payload = LakeIdentityBatchRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            snapshot_id: snapshot_id.as_deref(),
            items,
            deny_source_types,
        };
        let (rows, complete) = self
            .identity_request("/v1/identity/resolve-batch", "identity_batch", &request_id, snapshot_id.as_deref(), &payload)
            .await?;
        Ok(LakeIdentityAnswer { rows: decode_identity_rows(rows, "identity batch")?, complete })
    }

    /// Point-in-time identities keyed by IP, host, or user for ≤ 500 items.
    pub(crate) async fn resolve_identity_entity_batch(
        &self,
        entity_type: &str,
        items: &[LakeIdentityEntityBatchItem],
        deny_source_types: &BTreeSet<String>,
    ) -> Result<LakeIdentityAnswer<LakeIdentityEntityBatchObservation>, SearchError> {
        if !matches!(entity_type, "ip" | "host" | "user") {
            return Err(SearchError::SqlValidationError(
                "lake identity entity type must be ip, host, or user".to_string(),
            ));
        }
        if items.is_empty() || items.len() > 500 {
            return Err(SearchError::SqlValidationError(
                "lake identity entity batch must contain between 1 and 500 items".to_string(),
            ));
        }
        let snapshot_id = (!self.lake_cell).then(|| optional_env("NANO_LAKE_IDENTITY_SNAPSHOT")).flatten();
        let request_id = uuid::Uuid::now_v7().to_string();
        let payload = LakeIdentityEntityBatchRequest {
            request_id: &request_id,
            tenant_id: &self.tenant_id,
            snapshot_id: snapshot_id.as_deref(),
            entity_type,
            items,
            deny_source_types,
        };
        let (rows, complete) = self
            .identity_request(
                "/v1/identity/resolve-entity-batch",
                "identity_entity_batch",
                &request_id,
                snapshot_id.as_deref(),
                &payload,
            )
            .await?;
        Ok(LakeIdentityAnswer { rows: decode_identity_rows(rows, "identity entity batch")?, complete })
    }

    pub async fn cancel(&self, request_id: &str) -> Result<bool, SearchError> {
        if self.lake_cell {
            // query[T] has no cancel route; a routed request ends when its
            // connection closes.
            return Ok(false);
        }
        let response = self
            .http
            .delete(format!(
                "{}/v1/query/{}",
                self.base_url,
                urlencoding::encode(request_id)
            ))
            .bearer_auth(self.bearer()?)
            .send_idempotent_with_recovery_within(self.read_deadline())
            .await
            .map_err(|error| self.map_transport_error(error))?;
        let status = response.status();
        self.verify_response_assignment(response.headers())?;
        let payload: LakeCancelResponse = response.json().await.map_err(|error| {
            SearchError::SqlValidationError(format!(
                "lake cancellation returned invalid JSON ({status}): {error}"
            ))
        })?;
        if !status.is_success() || !payload.ok {
            return Err(SearchError::SqlValidationError(format!(
                "lake cancellation failed with HTTP {status}"
            )));
        }
        Ok(payload.cancelled)
    }

    fn map_transport_error(&self, error: reqwest::Error) -> SearchError {
        if error.is_timeout() {
            SearchError::Timeout(self.timeout.as_millis() as u64)
        } else {
            SearchError::ServiceUnavailable(format!(
                "lake query worker is temporarily unavailable: {error}"
            ))
        }
    }

    fn validate_envelope_binding(
        &self,
        envelope: &LakeQueryEnvelope,
        request_id: &str,
        route: &str,
    ) -> Result<(), SearchError> {
        if envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || envelope.request_id.as_deref() != Some(request_id)
            || envelope.route.as_deref() != Some(route)
        {
            return Err(SearchError::SqlValidationError(
                "lake query worker substituted the tenant, request, or route binding".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct LakeQueryRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    route: &'static str,
    dataset: &'static str,
    query: &'a str,
    start: String,
    end: String,
    limit: usize,
    offset: usize,
    table_view: bool,
    use_cache: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor_event_uid: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_us: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decay: Option<&'a crate::risk::RiskDecayConfig>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    clear_boundaries: std::collections::BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    minimum_clear_revision: Option<i64>,
    /// Watchlist weights (NAN-3228) for `dataset=risk`: normalized entity
    /// value -> weight. Omitted when empty so a worker that predates the field
    /// (`deny_unknown_fields`) keeps serving tenants without watchlists.
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    watch_weights: std::collections::BTreeMap<String, f64>,
    deny_source_types: &'a BTreeSet<String>,
}

#[derive(Serialize)]
struct LakeFetchLogRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    route: &'static str,
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_source: Option<&'a str>,
    deny_source_types: &'a BTreeSet<String>,
}

#[derive(Serialize)]
struct LakeEntityRangesRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    path: &'a str,
    values: &'a [String],
    start: String,
    end: String,
    case_insensitive: bool,
}

#[derive(Deserialize)]
struct LakeEntityRangesEnvelope {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    request_id: String,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    route: String,
    #[serde(default)]
    result: Option<LakeEntityRangesResult>,
}

#[derive(Deserialize)]
struct LakeEntityRangesResult {
    #[serde(default)]
    rows: Vec<LakeEntityRange>,
}

/// One value's activity range from `/v1/entity/ranges` (NAN-3094).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub(crate) struct LakeEntityRange {
    /// The matched value, lowercased (the route matches case-insensitively).
    pub entity: String,
    /// First event time, µs since the epoch.
    #[serde(deserialize_with = "lenient_i64")]
    pub first_us: i64,
    /// Last event time, µs since the epoch.
    #[serde(deserialize_with = "lenient_i64")]
    pub last_us: i64,
    #[serde(deserialize_with = "lenient_i64")]
    pub events: i64,
}

/// chDB may render 64-bit integers as JSON strings; accept both.
fn lenient_i64<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    match serde_json::Value::deserialize(deserializer)? {
        serde_json::Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
            .ok_or_else(|| serde::de::Error::custom("integer out of range")),
        serde_json::Value::String(text) => text.parse().map_err(serde::de::Error::custom),
        _ => Err(serde::de::Error::custom("expected an integer")),
    }
}

#[derive(Serialize)]
struct LakeCountAggregateRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    group_field: &'a str,
    group_results: bool,
    /// Sent only when set, so older workers see an unchanged request.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    group_by_source: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    predicate: Option<&'a LakeCountPredicate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bucket_span_us: Option<i64>,
    count_alias: &'a str,
    start: String,
    end: String,
    source_filter: Option<&'a str>,
    deny_source_types: &'a BTreeSet<String>,
    max_groups: usize,
}


/// The fields the lake's exact count rollups cover, and whether each is
/// multi-valued: a mirror of `nanosiem-lake-worker`'s
/// `rollup::COUNT_ROLLUP_FIELDS` contract (the worker's tests pin it
/// exactly). Search plans a rollup read only for these, so a request the
/// worker would refuse or scan is never chosen as a rollup route (NAN-3093).
pub const LAKE_COUNT_ROLLUP_FIELDS: &[(&str, bool)] = &[
    ("metadata.log_source", false),
    ("process.name", false),
    ("process.cmd_line", false),
    ("actor.process.name", false),
    ("actor.process.cmd_line", false),
    ("device.hostname", false),
    ("src_endpoint.hostname", false),
    ("dst_endpoint.hostname", false),
    ("src_endpoint.ip", false),
    ("dst_endpoint.ip", false),
    ("user.name", false),
    ("actor.user.name", false),
    ("file.name", false),
    ("file.path", false),
    ("module.file.name", false),
    ("module.file.path", false),
    ("http_request.url.hostname", false),
    ("http_request.url.url_string", false),
    ("severity", false),
    ("class_name", false),
    ("category_name", false),
    ("activity_name", false),
    ("src_endpoint.mac", false),
    ("dst_endpoint.mac", false),
    ("user.uid", false),
    ("actor.user.uid", false),
    ("process.uid", false),
    ("actor.process.uid", false),
    ("url.hostname", false),
    ("url.url_string", false),
    ("query.hostname", false),
    ("email.from", false),
    ("email.to", false),
    ("vulnerabilities.cve.uid", false),
    ("file.hashes.value", true),
    ("process.file.hashes.value", true),
    ("actor.process.file.hashes.value", true),
    ("answers.rdata", true),
    ("resources.ip", true),
    ("resources.hostname", true),
    ("resources.device.hostname", true),
    ("resources.user.name", true),
    ("resources.user.uid", true),
    ("resources.uid", true),
    ("evidences.query.hostname", true),
    ("evidences.url.url_string", true),
    ("__nano.dashboard_breakdown", false),
    ("class_uid", false),
    ("category_uid", false),
    ("activity_id", false),
    ("type_uid", false),
    ("severity_id", false),
    ("status", false),
    ("status_id", false),
    ("src_endpoint.port", false),
    ("dst_endpoint.port", false),
    ("src_endpoint.location.country", false),
    ("dst_endpoint.location.country", false),
    ("api.service.name", false),
    ("metadata.product.name", false),
    ("metadata.product.vendor_name", false),
    ("cloud.provider", false),
    ("cloud.region", false),
    ("cloud.account.uid", false),
    ("finding_info.analytic.name", false),
    ("finding_info.title", false),
    ("unmapped.error_code", false),
    ("unmapped.threat_tier", false),
    ("unmapped.threat_blocked", false),
    ("enrichments.name", true),
    ("enrichments.value", true),
    ("enrichments.type", true),
    ("enrichments.provider", true),
    ("enrichments.short_desc", true),
];

/// `Some(multi_value)` for a count-rollup field, `None` otherwise.
pub fn lake_count_rollup_field_multi_value(field: &str) -> Option<bool> {
    LAKE_COUNT_ROLLUP_FIELDS
        .iter()
        .find(|(path, _)| *path == field)
        .map(|(_, multi_value)| *multi_value)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct LakeCountPredicate {
    pub kind: &'static str,
    pub values: Vec<String>,
}

#[derive(Serialize)]
struct LakeFieldNamesRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    route: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LakeIdentityBatchItem {
    pub ip: String,
    pub reference_time: String,
}

#[derive(Serialize)]
struct LakeIdentityBatchRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<&'a str>,
    items: &'a [LakeIdentityBatchItem],
    deny_source_types: &'a BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LakeIdentityEntityBatchItem {
    pub value: String,
    pub reference_time: String,
}

#[derive(Serialize)]
struct LakeIdentityEntityBatchRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<&'a str>,
    entity_type: &'a str,
    items: &'a [LakeIdentityEntityBatchItem],
    deny_source_types: &'a BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LakeIdentityObservation {
    pub hostname: String,
    pub user: String,
    pub mac: String,
    /// The observing log source. When the answer came from the bounded
    /// event scan instead of the identity index it is prefixed
    /// [`EVENT_SCAN_SOURCE_PREFIX`] (NAN-3058).
    pub source: String,
    pub observed_at: String,
    /// The full host name (the index keeps `hostname` short for `.corp.`
    /// FQDNs, like ClickHouse's `identity_observations`).
    #[serde(default)]
    pub fqdn: String,
    /// The IP saw 3+ distinct hostnames in one hour of the 7 days before the
    /// reference time (`nat_candidates_view`); index answers only.
    #[serde(default)]
    pub nat_candidate: bool,
    #[serde(default)]
    pub resolved_via: LakeIdentityResolution,
}

/// How a lean identity answer was produced (NAN-3058).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LakeIdentityResolution {
    /// The tenant's identity observation index (or a gen1 snapshot).
    #[default]
    Index,
    /// The bounded scan over the tenant's events (NAN-3057), used while the
    /// index is still backfilling.
    EventScan,
}

/// `source` prefix of an event-scan answer.
pub const EVENT_SCAN_SOURCE_PREFIX: &str = "event_scan:";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LakeIdentityBatchObservation {
    pub ordinal: usize,
    pub ip: String,
    pub hostname: String,
    pub user: String,
    pub mac: String,
    pub source: String,
    pub observed_at: String,
    /// Lean index only (NAN-3058): the full host name, and whether the IP
    /// saw 3+ hostnames in one hour of the last 7 days (NAT/VPN).
    #[serde(default)]
    pub fqdn: String,
    #[serde(default)]
    pub nat_candidate: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct LakeIdentityEntityBatchObservation {
    pub ordinal: usize,
    pub value: String,
    pub ip: String,
    pub hostname: String,
    pub user: String,
    pub mac: String,
    pub source: String,
    pub observed_at: String,
    #[serde(default)]
    pub fqdn: String,
    #[serde(default)]
    pub nat_candidate: bool,
}

#[derive(Debug, Deserialize)]
struct LakeQueryEnvelope {
    ok: bool,
    #[serde(default)]
    estimated_bytes: Option<u64>,
    #[serde(default)]
    budget_bytes: Option<u64>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    generation_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    wall_seconds: Option<f64>,
    #[serde(default)]
    result: Option<LakeQueryResult>,
    /// Event-completeness envelope stamped by the worker when it served this
    /// response over a STALE hot-tail publication (NAN-2361 per-consumer
    /// policy). Absent on a complete view and from older workers.
    #[serde(default)]
    completeness: Option<EventCompleteness>,
    /// query[T] (NAN-2891): the verified part-log head the answer was
    /// computed at. Absent from gen1 readers.
    /// `None` when the key is absent; `Some(Value::Null)` when query[T]
    /// answered over an empty part log (no head yet).
    #[serde(default, deserialize_with = "deserialize_present")]
    log_head: Option<serde_json::Value>,
    /// query[T]'s identity routes (NAN-3058): the observation index coverage
    /// of the lookback window, `{"state": "complete"|"backfilling", ...}`.
    #[serde(default)]
    identity_index: Option<serde_json::Value>,
}

fn decode_identity_rows<T: serde::de::DeserializeOwned>(
    rows: Vec<serde_json::Value>,
    what: &str,
) -> Result<Vec<T>, SearchError> {
    rows.into_iter()
        .map(|row| {
            serde_json::from_value(row).map_err(|error| {
                SearchError::SqlValidationError(format!(
                    "lake {what} worker returned an invalid row: {error}"
                ))
            })
        })
        .collect()
}

/// Identity rows plus whether they cover the whole lookback window.
#[derive(Debug, Clone)]
pub(crate) struct LakeIdentityAnswer<T> {
    pub rows: Vec<T>,
    /// False while a lean cell is still backfilling its identity index: the
    /// rows are exact over the indexed parts only.
    pub complete: bool,
}

fn deserialize_present<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

/// A query[T] part-log head binding is `{"seq": u64, "sha256": 64 hex}`, or
/// `null` only for an answer with no rows (a tenant whose log is still empty).
fn valid_lake_cell_log_head(head: Option<&serde_json::Value>, rows: usize) -> bool {
    match head {
        Some(serde_json::Value::Null) => rows == 0,
        Some(serde_json::Value::Object(head)) => {
            head.get("seq").is_some_and(serde_json::Value::is_u64)
                && head
                    .get("sha256")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        _ => false,
    }
}

#[derive(Debug, Deserialize)]
struct LakeExplainEnvelope {
    ok: bool,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    route: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    result: Option<LakeExplainResult>,
}

#[derive(Debug, Deserialize)]
struct LakeExplainResult {
    sql: String,
    source_placeholder: String,
}

impl LakeQueryEnvelope {
    fn into_search_response(
        self,
        requested_limit: usize,
        offset: usize,
    ) -> Result<SearchResponse, SearchError> {
        let mut result = self.result.ok_or_else(|| {
            SearchError::SqlValidationError("lake query worker response omitted result".to_string())
        })?;
        if result.query_result_cache_hit {
            crate::request_timing::record_lake_result_cache_hit();
        }
        let transaction_preview_truncated = limit_transaction_event_previews(&mut result.rows);
        let mut statistics = FieldStatistics::new();
        for row in &result.rows {
            statistics.process_row(row);
        }
        let returned = result.rows.len() as u64;
        let elapsed_seconds = self
            .wall_seconds
            .or(result.wall_seconds)
            .unwrap_or_default();
        // NAN-2550: a lake page cannot cheaply prove a search-wide total (chdb
        // over a set of tail objects), so "more may exist" is a PROPERTY of this
        // result, not a warning. It rides on `total_count_exact`; nothing is
        // pushed onto `warnings` for it, because a correct bounded page is not a
        // condition the analyst has to act on.
        let count_is_page_bound = result.page_has_more.unwrap_or(false)
            || result.result_rows.unwrap_or(result.rows.len()) >= requested_limit;
        // NAN-2550: and it is reported AS a lower bound. The old
        // `offset + returned + (page_has_more as u64)` dressed the bound up as an
        // exact `51` for a 50-row page -- a number no row in the result set
        // supports. `offset + returned` is the largest count this page proves.
        let total_count = result.group_total.unwrap_or(offset as u64 + returned);
        let mut warnings = Vec::new();
        if transaction_preview_truncated {
            warnings.push(QueryWarningOutput {
                severity: "info".to_string(),
                code: "TRANSACTION_EVENT_PREVIEW".to_string(),
                message: format!(
                    "Transaction cards show at most {TRANSACTION_EVENT_PREVIEW_LIMIT} embedded event samples per row."
                ),
                suggestion: Some(
                    "Narrow the transaction or drill into its entity and time range to inspect every member event."
                        .to_string(),
                ),
                impact: Some(
                    "Transaction counts, duration, grouping, and sorting remain exact. Only the inline HTTP/UI event preview is bounded; durable job artifacts are not rewritten."
                        .to_string(),
                ),
            });
        }
        if let Some(completeness) = self
            .completeness
            .as_ref()
            .filter(|completeness| completeness.generation.as_deref() == Some("bootstrap"))
        {
            // NAN-2361 wave 8: the tenant has no compacted Iceberg snapshot
            // yet. The result is exact over everything published (the signed
            // hot tail); say so, quietly, so an empty first search is not
            // mistaken for a broken one.
            warnings.push(QueryWarningOutput {
                severity: "info".to_string(),
                code: "LAKE_GENERATION_BOOTSTRAP".to_string(),
                message: "This tenant's lake has not compacted its first snapshot yet; results come from the live hot tail only.".to_string(),
                suggestion: None,
                impact: Some(
                    "Entity, keyword, and count-rollup acceleration start with the first compacted generation; results are exact over every published event."
                        .to_string(),
                ),
            });
        }
        if let Some(partial) = self
            .completeness
            .as_ref()
            .and_then(|completeness| completeness.hot_tail_partial.as_ref())
        {
            // NAN-2651: the signed hot tail exceeded the reader's cache bound
            // and only its newest objects were searched. This is a HOLE in
            // the middle of the timeline, not "the newest events are late",
            // so it gets its own code and is listed first (the UI shows the
            // first `warning`-severity entry).
            warnings.push(hot_tail_partial_warning(partial));
        }
        if let Some(slow_path) = self
            .completeness
            .as_ref()
            .and_then(|completeness| completeness.hot_tail_slow_path.as_ref())
        {
            // NAN-2694: complete, but part of the tail came from the disk
            // tier or R2. Informational: the analyst sees why it was slower
            // and which range was read through.
            warnings.push(hot_tail_slow_path_warning(slow_path));
        }
        if let Some(completeness) = self
            .completeness
            .as_ref()
            .filter(|completeness| {
                completeness.status != "ok"
                    && completeness.status != "partial"
                    && !(completeness.status == "stale"
                        && completeness.reason.as_deref() == Some("publication_consumer_lag")
                        && completeness.freshness_notice_required == Some(false))
            })
        {
            // The worker's display threshold suppresses only routine consumer
            // lag. Always preserve the structured watermark in the response.
            let complete_through = completeness
                .events_complete_through_ms
                .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_else(|| "an unknown time".to_string());
            warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "LAKE_EVENTS_INCOMPLETE".to_string(),
                message: format!(
                    "Recent events are not yet searchable: results are complete through {complete_through} ({reason}).",
                    reason = completeness.reason.as_deref().unwrap_or("publication degraded"),
                ),
                suggestion: Some(
                    "Re-run the search once event publication recovers to include the newest events."
                        .to_string(),
                ),
                impact: Some(format!(
                    "{revisions} staged revision(s) are not yet visible; hot-tail pressure {bytes}% bytes / {objects}% objects.",
                    revisions = completeness.unpublished_revisions,
                    bytes = completeness.byte_pressure_percent,
                    objects = completeness.object_pressure_percent,
                )),
            });
        }
        let warnings = (!warnings.is_empty()).then_some(warnings);
        Ok(SearchResponse {
            server_wall_ms: None,
            results: result.rows,
            total_count,
            execution_time_ms: (elapsed_seconds.max(0.0) * 1_000.0).round() as u64,
            fields: statistics.get_field_info(100),
            generated_sql: None,
            histogram: None,
            warnings,
            cost_score: None,
            display_type: None,
            column_order: None,
            completeness: self.completeness,
            total_count_exact: result.group_total.is_some() || !count_is_page_bound,
        })
    }
}

/// NAN-2694: HOT_TAIL_SLOW_PATH, with the range served beyond the RAM tier.
fn hot_tail_slow_path_warning(slow_path: &super::HotTailSlowPathCoverage) -> QueryWarningOutput {
    let format_ms = |value: Option<i64>| {
        value
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    };
    let range = |from: Option<i64>, through: Option<i64>| match (format_ms(from), format_ms(through)) {
        (Some(from), Some(through)) => format!("{from} to {through}"),
        (None, Some(through)) => format!("up to {through}"),
        (Some(from), None) => format!("from {from}"),
        (None, None) => "an unknown range".to_string(),
    };
    let message = if slow_path.r2_objects > 0 {
        format!(
            "Results are complete. Events from {} were read through from object storage because the live hot tail exceeds the search cache, so this search was slower.",
            range(slow_path.r2_from_ms, slow_path.r2_through_ms)
        )
    } else {
        format!(
            "Results are complete. Events from {} were served from the encrypted disk cache because the live hot tail exceeds the in-memory search cache.",
            range(slow_path.from_ms, slow_path.through_ms)
        )
    };
    QueryWarningOutput {
        severity: "info".to_string(),
        code: "HOT_TAIL_SLOW_PATH".to_string(),
        message,
        suggestion: Some(
            "Searches after this range stay fast; the slow path ends once the next lake generation publishes and the tail drains."
                .to_string(),
        ),
        impact: Some(format!(
            "{objects} hot-tail objects ({mib} MiB) beyond the RAM tier: {disk} from the disk cache, {r2} ({r2_mib} MiB) from object storage, staged in {ms} ms.",
            objects = slow_path.objects,
            mib = slow_path.bytes / 1_048_576,
            disk = slow_path.disk_objects,
            r2 = slow_path.r2_objects,
            r2_mib = slow_path.r2_bytes / 1_048_576,
            ms = slow_path.staging_ms,
        )),
    }
}

/// NAN-2651: HOT_TAIL_PARTIAL, with the uncovered event-time range.
fn hot_tail_partial_warning(partial: &super::HotTailPartialCoverage) -> QueryWarningOutput {
    let format_ms = |value: Option<i64>| {
        value
            .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
            .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    };
    let message = match (
        format_ms(partial.uncovered_from_ms),
        format_ms(partial.uncovered_through_ms),
    ) {
        (Some(from), Some(through)) => format!(
            "Results are partial: events between {from} and {through} may be missing because the live hot tail exceeds the search cache. Events after {through} are complete."
        ),
        (None, Some(through)) => format!(
            "Results are partial: events up to {through} may be missing because the live hot tail exceeds the search cache. Events after {through} are complete."
        ),
        _ => "Results are partial: the live hot tail exceeds the search cache and older uncompacted events may be missing; the uncovered time range is unknown.".to_string(),
    };
    QueryWarningOutput {
        severity: "warning".to_string(),
        code: "HOT_TAIL_PARTIAL".to_string(),
        message,
        suggestion: Some(
            "Narrow the search to after the uncovered range, or re-run it once the next lake generation publishes and the tail drains."
                .to_string(),
        ),
        impact: Some(format!(
            "{served} of {total} hot-tail objects ({served_mib} of {total_mib} MiB) were searched against a {bound_mib} MiB cache bound.{why}",
            served = partial.served_objects,
            total = partial.total_objects,
            served_mib = partial.served_bytes / 1_048_576,
            total_mib = partial.total_bytes / 1_048_576,
            bound_mib = partial.cache_max_bytes / 1_048_576,
            // NAN-2694: with the disk tier + R2 read-through, partial is the
            // last resort; say which resource ran out.
            why = match partial.reason.as_deref() {
                Some("slow_path_r2_unavailable") => " Object storage was unreachable for the older range.",
                Some("slow_path_over_budget") => " The older range exceeded the per-search read-through budget; narrow the time range.",
                Some("slow_path_busy") => " Too many searches were reading through at once; retry shortly.",
                _ => "",
            },
        )),
    }
}

/// NAN-2361 wave 8: the identity probe did not answer within its budget. A
/// tenant whose query worker is still starting (bootstrap), rolling a
/// generation, or saturated must surface as a retryable, typed 503 -- not
/// as "Query timeout after 2000ms", which the search service rendered as a
/// 500 and which no client retry policy honored.
fn lake_worker_not_ready(tenant_id: &str, budget: Duration) -> SearchError {
    SearchError::LakeWorkerNotReady(format!(
        "tenant {tenant_id} lake query worker did not answer its identity probe within {} ms",
        budget.as_millis()
    ))
}

#[derive(Debug, Deserialize)]
struct LakeQueryResult {
    /// Exact output-group count supplied by the compiled cell page.
    #[serde(default)]
    group_total: Option<u64>,
    rows: Vec<serde_json::Value>,
    #[serde(default)]
    result_rows: Option<usize>,
    #[serde(default)]
    page_has_more: Option<bool>,
    #[serde(default)]
    wall_seconds: Option<f64>,
    /// query[T] served this page from its exact part-set result cache.
    #[serde(default)]
    query_result_cache_hit: bool,
    /// query[T] (NAN-3046): the rows are raw events newest first, so the
    /// (time, metadata.uid) cursor of the last row continues the result.
    #[serde(default)]
    newest_first_event_rows: Option<bool>,
    /// query[T] (NAN-3270): the page stopped at its result byte budget;
    /// the rows still wanted continue from this cursor (offset 0).
    #[serde(default)]
    continuation: Option<LakeContinuation>,
}

/// NAN-3270: where a byte-cut `broad_npl` page continues.
#[derive(Debug, Deserialize)]
struct LakeContinuation {
    cursor_time: String,
    cursor_event_uid: String,
}

/// NAN-3270: continuation requests one interactive page may make before it
/// is treated as too wide for an interactive answer (durable job). At
/// ~12 MiB of decoded rows per cell answer this fills ~200 MB of page.
const MAX_BYTE_CUT_FILL_HOPS: usize = 16;

/// A streamed read never takes longer than this end to end; each block
/// must also arrive within the client's request timeout.
const STREAMED_READ_TIMEOUT: Duration = Duration::from_secs(30 * 60);

enum StreamedRead {
    Done(PagedSearch),
    NotContinuable,
    Fallback,
}

/// A line after the envelope of a `/v1/query/pages` response.
#[derive(Deserialize)]
#[serde(untagged)]
enum StreamedLine {
    Page { rows: Vec<serde_json::Value> },
    Done {
        #[allow(dead_code)]
        done: bool,
        has_more: bool,
        delivered: usize,
    },
    Failed {
        status: u16, error: String, reason: String,
        #[serde(default)] needed_bytes: Option<u64>, #[serde(default)] budget_bytes: Option<u64>,
        #[serde(default)] ceiling_bytes: Option<u64>, #[serde(default)] background_ceiling_bytes: Option<u64>,
    },
}

/// Splits a streamed body into NDJSON lines, holding at most one partial
/// line (a page) between chunks.
#[derive(Default)]
struct NdjsonLines {
    buffer: Vec<u8>,
    scanned: usize,
}

/// A streamed response body read line by line, each block within `idle`.
struct StreamedBody {
    response: reqwest::Response,
    lines: NdjsonLines,
    idle: Duration,
}

impl StreamedBody {
    async fn next_line(&mut self, client: &LakeQueryClient) -> Result<Option<Vec<u8>>, SearchError> {
        loop {
            if let Some(line) = self.lines.next_line() {
                return Ok(Some(line));
            }
            match tokio::time::timeout(self.idle, self.response.chunk()).await {
                Ok(Ok(Some(bytes))) => {
                    // NAN-3282: a streamed page counts against the view too.
                    crate::search::view_memory::charge_wire_bytes(bytes.len() as u64).await?;
                    self.lines.push(&bytes)?
                }
                Ok(Ok(None)) => return self.lines.finish(),
                Ok(Err(error)) => return Err(client.map_transport_error(error)),
                Err(_) => return Err(SearchError::Timeout(self.idle.as_millis() as u64)),
            }
        }
    }
}

/// A single streamed line (one page of rows) may not exceed this.
const MAX_STREAMED_LINE_BYTES: usize = 512 * 1024 * 1024;

impl NdjsonLines {
    fn push(&mut self, bytes: &[u8]) -> Result<(), SearchError> {
        self.buffer.extend_from_slice(bytes);
        if self.buffer.len() > MAX_STREAMED_LINE_BYTES {
            return Err(SearchError::ResourceExhausted("memory".to_string()));
        }
        Ok(())
    }

    fn next_line(&mut self) -> Option<Vec<u8>> {
        loop {
            let Some(offset) = self.buffer[self.scanned..].iter().position(|byte| *byte == b'\n') else {
                // Never rescan what was already searched.
                self.scanned = self.buffer.len();
                return None;
            };
            let at = self.scanned + offset;
            let mut line: Vec<u8> = self.buffer.drain(..=at).collect();
            self.scanned = 0;
            line.pop();
            if !line.iter().all(u8::is_ascii_whitespace) {
                return Some(line);
            }
        }
    }

    fn finish(&mut self) -> Result<Option<Vec<u8>>, SearchError> {
        let rest = std::mem::take(&mut self.buffer);
        Ok((!rest.iter().all(u8::is_ascii_whitespace)).then_some(rest))
    }
}

/// The outcome of [`LakeQueryClient::search_paged`].
#[derive(Debug, Default)]
pub struct PagedSearch {
    /// The first page's response without its rows (fields, completeness...).
    pub first: Option<SearchResponse>,
    pub delivered: usize,
    pub pages: u32,
    /// Stopped at the requested limit with more rows remaining.
    pub truncated: bool,
    /// The consumer stopped the stream.
    pub stopped: bool,
}

#[derive(Deserialize)]
struct LakeCancelResponse {
    ok: bool,
    #[serde(default)]
    cancelled: bool,
}

#[cfg(test)]
mod tests {
    #[test]
    fn physical_scan_estimates_survive_archived_cell_errors() {
        for message in [
            "query scan budget rejected 720 bytes above 100",
            "interactive query scan estimate 720 exceeds budget 100",
            "query needs 720 cold bytes, over the per-query reader cache budget of 100 bytes",
        ] {
            assert_eq!(super::cell_scan_budget_bytes(message), Some((720, 100)));
        }
        assert_eq!(super::cell_scan_budget_bytes("Code: 241 memory limit exceeded"), None);
    }

    use super::*;

    fn write_private_credential(path: &Path, value: &str) {
        std::fs::write(path, value).expect("write runtime secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("make runtime secret owner-only");
        }
    }

    fn write_shared_registry(
        directory: &tempfile::TempDir,
        assignments: serde_json::Value,
    ) -> (PathBuf, PathBuf) {
        let credential = directory.path().join("worker-token");
        write_private_credential(&credential, &"a".repeat(64));
        let registry = directory.path().join("workers.json");
        std::fs::write(
            &registry,
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "assignments": assignments,
            }))
            .unwrap(),
        )
        .expect("write registry");
        (registry, credential)
    }

    #[test]
    fn cell_group_pages_report_exact_totals_including_empty_offset_pages() {
        for (rows, offset) in [(serde_json::json!([{"count": 10}]), 0),
                               (serde_json::json!([]), 200_000)] {
            let envelope: LakeQueryEnvelope = serde_json::from_value(serde_json::json!({
                "ok":true, "result":{"rows":rows,"group_total":193567,"page_has_more":true}
            })).unwrap();
            let response = envelope.into_search_response(100, offset).unwrap();
            assert_eq!(response.total_count, 193567);
            assert!(response.total_count_exact);
        }
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn shared_worker_registry_routes_equal_work_to_disjoint_exact_assignments() {
        let directory = tempfile::tempdir().unwrap();
        let credential_a = directory.path().join("worker-token-a");
        let credential_b = directory.path().join("worker-token-b");
        write_private_credential(&credential_a, &"a".repeat(64));
        write_private_credential(&credential_b, &"b".repeat(64));
        let tenant_a = Uuid::from_u128(0xa);
        let tenant_b = Uuid::from_u128(0xb);
        let assignment = |tenant: Uuid, service: &str, identity: &str, credential: &Path| {
            serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": tenant,
                "internal_endpoint": format!("http://{service}.nano.svc:8080"),
                "credential_file": credential,
                "expected_worker_identity": identity,
                "expected_worker_revision": 7,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                }
            })
        };
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([
                assignment(tenant_a, "query-a", "worker-a", &credential_a),
                assignment(tenant_b, "query-b", "worker-b", &credential_b)
            ]),
        );
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        assert_eq!(registry.len(), 2);
        assert_eq!(
            registry.assignment(tenant_a).unwrap().internal_endpoint,
            "http://query-a.nano.svc:8080"
        );
        assert_eq!(
            registry.assignment(tenant_b).unwrap().internal_endpoint,
            "http://query-b.nano.svc:8080"
        );
        let runtime_a = LakeQueryRuntime::from_enterprise_shared_assignment(
            registry.assignment(tenant_a).unwrap(),
        )
        .unwrap();
        let runtime_b = LakeQueryRuntime::from_enterprise_shared_assignment(
            registry.assignment(tenant_b).unwrap(),
        )
        .unwrap();
        let tenant_a = tenant_a.to_string();
        let tenant_b = tenant_b.to_string();
        assert_eq!(runtime_a.assigned_tenant_id(), Some(tenant_a.as_str()));
        assert_eq!(runtime_b.assigned_tenant_id(), Some(tenant_b.as_str()));
    }

    #[cfg(feature = "enterprise")]
    /// NAN-2903 (tenant offboarding). Offboarding a tenant publishes the next
    /// immutable registry revision WITHOUT its assignment and keys. Every
    /// surviving tenant's entry and credential file carry over byte for byte,
    /// so pods on the old revision and pods on the new one authenticate the
    /// surviving tenants identically; that is the dual-accept window, and no
    /// surviving token changes. After the rollover the dropped tenant's
    /// leftover producer config is `Offboarded`: skipped, never attested. A
    /// survivor whose config disagrees on the worker revision still fails
    /// closed.
    #[cfg(unix)]
    #[test]
    fn offboarding_revision_drops_one_tenant_and_leaves_survivors_routed() {
        use crate::search::job_coordinator_config::{
            HostedCoordinatorDeployment, HostedProducerRouting,
        };
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let credential_a = directory.path().join("query-token-a");
        let credential_b = directory.path().join("query-token-b");
        write_private_credential(&credential_a, &"a".repeat(64));
        write_private_credential(&credential_b, &"b".repeat(64));
        let (survivor, offboarded) = (Uuid::from_u128(0xa), Uuid::from_u128(0xb));
        let assignment = |tenant: Uuid, service: &str, identity: &str, credential: &Path| {
            serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": tenant,
                "internal_endpoint": format!("http://{service}.nano.svc:8080"),
                "credential_file": credential,
                "expected_worker_identity": identity,
                "expected_worker_revision": 7,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                }
            })
        };
        let survivor_entry = assignment(survivor, "query-a", "worker-a", &credential_a);
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([
                survivor_entry.clone(),
                assignment(offboarded, "query-b", "worker-b", &credential_b)
            ]),
        );
        let before = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        let (path, _) = write_shared_registry(&directory, serde_json::json!([survivor_entry]));
        let after = SharedLakeWorkerRegistry::from_file(&path).unwrap();

        assert_eq!(after.len(), 1);
        assert!(after.assignment(offboarded).is_none());
        let (old, new) = (
            before.assignment(survivor).unwrap(),
            after.assignment(survivor).unwrap(),
        );
        assert_eq!(old.internal_endpoint, new.internal_endpoint);
        assert_eq!(old.credential_file, new.credential_file);
        assert_eq!(old.expected_worker_identity, new.expected_worker_identity);
        assert_eq!(old.expected_worker_revision, new.expected_worker_revision);

        let producer = |tenant: Uuid, revision: u64| {
            let path = directory.path().join(format!("producer-{tenant}-{revision}.json"));
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({"schema_version":1,
                    "deployment_kind":"isolated_test","tenant_id":tenant,
                    "worker_assignment_revision":revision,
                    "endpoint":"https://coordinator.invalid/v1/coordinate","epoch":"epoch1",
                    "policy":{"max_execution_failures":2,"max_lease_recoveries":3},
                    "authority":{"entitlement_revision":1,"retention_revision":1,
                        "retention_days":90,"irreversible_event_time_floor_micros":0},
                    "token_file":"/private/token"}))
                .unwrap(),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            HostedCoordinatorDeployment::from_file(&path).unwrap()
        };
        let (survivor_config, leftover) = (producer(survivor, 7), producer(offboarded, 7));
        // Old revision: both tenants are live.
        assert_eq!(
            survivor_config.routing_under(&before).unwrap(),
            HostedProducerRouting::Routed
        );
        assert_eq!(
            leftover.routing_under(&before).unwrap(),
            HostedProducerRouting::Routed
        );
        // New revision: the survivor is untouched and the leftover is skipped.
        assert_eq!(
            survivor_config.routing_under(&after).unwrap(),
            HostedProducerRouting::Routed
        );
        assert_eq!(
            leftover.routing_under(&after).unwrap(),
            HostedProducerRouting::Offboarded
        );
        // A routed tenant at the wrong worker revision is not "offboarded".
        assert!(producer(survivor, 8).routing_under(&after).is_err());
        assert!(producer(offboarded, 8).routing_under(&before).is_err());
    }

    /// NAN-3666: the contract the platform's registry prune relies on. An EMPTY
    /// gen1 registry loads when the process also has lean-lake cell routes
    /// (what `from_env` passes as `allow_empty`), and is refused without them.
    #[test]
    fn an_empty_shared_registry_loads_only_alongside_cell_routes() {
        let directory = tempfile::tempdir().unwrap();
        let (path, _) = write_shared_registry(&directory, serde_json::json!([]));
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        let registry = SharedLakeWorkerRegistry::from_file_inner(&path, true).unwrap();
        assert_eq!(registry.assignments().count(), 0);
        assert!(registry.assignment(Uuid::from_u128(0xa)).is_none());
    }

    #[test]
    fn first_shared_region_can_start_empty_without_authorizing_any_tenant() {
        let directory = tempfile::tempdir().unwrap();
        let (path, _) = write_shared_registry(&directory, serde_json::json!([]));
        let registry = SharedLakeWorkerRegistry::from_file_for_process(&path, true).unwrap();
        assert_eq!(registry.assignments().count(), 0);
        assert!(super::super::job_coordinator_config::hosted_producer_config_paths("[]", &registry).unwrap().is_empty());
        for tenant in [Uuid::from_u128(0xa), Uuid::from_u128(0xb)] {
            assert!(registry.assignment(tenant).is_none());
            assert!(registry.cell_route(tenant).is_none());
        }
        assert!(SharedLakeWorkerRegistry::from_file_for_process(&path, false).is_err());
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
    }

    #[cfg(feature = "enterprise")]
    #[test]
    fn populated_gen1_registry_still_requires_hosted_producer_configs() {
        let directory = tempfile::tempdir().unwrap();
        let credential = directory.path().join("worker-token");
        let tenant = Uuid::from_u128(0xa);
        let (path, _) = write_shared_registry(&directory, serde_json::json!([{
            "tenant_id": tenant, "expected_worker_tenant_id": tenant,
            "internal_endpoint": "http://query-a.nano.svc:8080",
            "credential_file": credential,
            "expected_worker_identity": "worker-a", "expected_worker_revision": 7,
            "prevalence_snapshots": {"one_hour": "prev-1h", "twenty_four_hours": "prev-24h",
                "seven_days": "prev-7d", "thirty_days": "prev-30d"}
        }]));
        let registry = SharedLakeWorkerRegistry::from_file_for_process(&path, true).unwrap();
        assert_eq!(registry.assignments().count(), 1);
        assert_eq!(registry.cell_route_count(), 0);
        assert!(super::super::job_coordinator_config::hosted_producer_config_paths("[]", &registry).is_err());
        assert!(super::super::job_coordinator_config::hosted_producer_config_paths("not JSON", &registry).is_err());
    }

    #[test]
    fn shared_region_empty_startup_still_refuses_broken_registry_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("worker-registry.json");
        assert!(SharedLakeWorkerRegistry::from_file_for_process(&path, true).is_err());
        for body in [
            r#"{"version":2,"assignments":[]}"#,
            r#"{"version":1}"#,
            r#"{"version":1,"assignments":[{}]}"#,
            "not JSON",
        ] {
            std::fs::write(&path, body).unwrap();
            assert!(SharedLakeWorkerRegistry::from_file_for_process(&path, true).is_err());
        }
    }

    #[test]
    fn shared_worker_registry_admits_an_optional_erasure_executor() {
        let directory = tempfile::tempdir().unwrap();
        let worker_credential = directory.path().join("worker-token");
        write_private_credential(&worker_credential, &"a".repeat(64));
        let tenant = Uuid::from_u128(0xd);
        let base = |executor: serde_json::Value| {
            let mut assignment = serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": tenant,
                "internal_endpoint": "http://query-d.nano.svc:8080",
                "credential_file": worker_credential,
                "expected_worker_identity": "worker-d",
                "expected_worker_revision": 7,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                }
            });
            if !executor.is_null() {
                assignment["erasure_executor"] = executor;
            }
            assignment
        };
        // absent: allowed, `None`, and the runner treats the tenant as unassigned
        let (path, _) = write_shared_registry(&directory, serde_json::json!([base(serde_json::Value::Null)]));
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        assert!(registry.assignment(tenant).unwrap().erasure_executor.is_none());
        assert!(!registry.erasure_executor_assigned(tenant));
        assert!(!registry.erasure_executor_assigned(Uuid::from_u128(0xe)));
        // present: node + render revision
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "executor_node": "cell-d-erasure-0",
                "render_revision": 3
            }))]),
        );
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        let executor = registry.assignment(tenant).unwrap().erasure_executor.clone().unwrap();
        assert_eq!(executor.executor_node, "cell-d-erasure-0");
        assert_eq!(executor.render_revision, 3);
        assert!(registry.erasure_executor_assigned(tenant));
        // bounded node name and positive revision
        for broken in [
            serde_json::json!({"executor_node": "", "render_revision": 1}),
            serde_json::json!({"executor_node": "cell d", "render_revision": 1}),
            serde_json::json!({"executor_node": "cell-d", "render_revision": 0}),
            serde_json::json!({"executor_node": "cell-d", "render_revision": 1, "endpoint": "x"}),
        ] {
            let (path, _) = write_shared_registry(&directory, serde_json::json!([base(broken)]));
            assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        }
    }

    #[test]
    fn shared_worker_registry_admits_an_optional_enrichment_coordinator() {
        let directory = tempfile::tempdir().unwrap();
        let worker_credential = directory.path().join("worker-token");
        let coordinator_credential = directory.path().join("coordinator-token");
        write_private_credential(&worker_credential, &"a".repeat(64));
        write_private_credential(&coordinator_credential, &"c".repeat(64));
        let tenant = Uuid::from_u128(0xc);
        let base = |coordinator: serde_json::Value| {
            let mut assignment = serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": tenant,
                "internal_endpoint": "http://query-c.nano.svc:8080",
                "credential_file": worker_credential,
                "expected_worker_identity": "worker-c",
                "expected_worker_revision": 7,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                }
            });
            if !coordinator.is_null() {
                assignment["enrichment_coordinator"] = coordinator;
            }
            assignment
        };
        // absent: allowed, `None`
        let (path, _) = write_shared_registry(&directory, serde_json::json!([base(serde_json::Value::Null)]));
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        assert!(registry.assignment(tenant).unwrap().enrichment_coordinator.is_none());
        // present: endpoint + private credential admitted, default timeout
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://enrich-c.nano.svc:3016",
                "credential_file": coordinator_credential,
            }))]),
        );
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        let coordinator = registry.assignment(tenant).unwrap().enrichment_coordinator.clone().unwrap();
        assert_eq!(coordinator.internal_endpoint, "http://enrich-c.nano.svc:3016");
        assert_eq!(coordinator.timeout_secs, 600);
        // the coordinator may not reuse the query worker's endpoint or secret
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://query-c.nano.svc:8080",
                "credential_file": coordinator_credential,
            }))]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://enrich-c.nano.svc:3016",
                "credential_file": worker_credential,
            }))]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        // a world-readable coordinator secret is refused
        let public = directory.path().join("public-token");
        std::fs::write(&public, "p".repeat(64)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
            let (path, _) = write_shared_registry(
                &directory,
                serde_json::json!([base(serde_json::json!({
                    "internal_endpoint": "http://enrich-c.nano.svc:3016",
                    "credential_file": public,
                }))]),
            );
            assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        }
    }

    #[test]
    fn shared_worker_registry_admits_an_optional_otel_ingest_service() {
        let directory = tempfile::tempdir().unwrap();
        let worker_credential = directory.path().join("worker-token");
        let coordinator_credential = directory.path().join("coordinator-token");
        let otel_credential = directory.path().join("otel-token");
        write_private_credential(&worker_credential, &"a".repeat(64));
        write_private_credential(&coordinator_credential, &"c".repeat(64));
        write_private_credential(&otel_credential, &"o".repeat(64));
        let tenant = Uuid::from_u128(0xd);
        let base = |otel: serde_json::Value| {
            let mut assignment = serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": tenant,
                "internal_endpoint": "http://query-d.nano.svc:8080",
                "credential_file": worker_credential,
                "expected_worker_identity": "worker-d",
                "expected_worker_revision": 7,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                },
                "enrichment_coordinator": {
                    "internal_endpoint": "http://enrich-d.nano.svc:3016",
                    "credential_file": coordinator_credential,
                }
            });
            if !otel.is_null() {
                assignment["otel_ingest"] = otel;
            }
            assignment
        };
        // absent: allowed, `None` (no drain provisioned for the tenant)
        let (path, _) = write_shared_registry(&directory, serde_json::json!([base(serde_json::Value::Null)]));
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        assert!(registry.assignment(tenant).unwrap().otel_ingest.is_none());
        // present: endpoint + private credential admitted, default timeout
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://otel-d.nano.svc:3014",
                "credential_file": otel_credential,
            }))]),
        );
        let registry = SharedLakeWorkerRegistry::from_file(&path).unwrap();
        let otel = registry.assignment(tenant).unwrap().otel_ingest.clone().unwrap();
        assert_eq!(otel.internal_endpoint, "http://otel-d.nano.svc:3014");
        assert_eq!(otel.timeout_secs, 130);
        // an explicit timeout is honored and bounded
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://otel-d.nano.svc:3014",
                "credential_file": otel_credential,
                "timeout_secs": 30
            }))]),
        );
        assert_eq!(SharedLakeWorkerRegistry::from_file(&path).unwrap().assignment(tenant).unwrap().otel_ingest.as_ref().unwrap().timeout_secs, 30);
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://otel-d.nano.svc:3014",
                "credential_file": otel_credential,
                "timeout_secs": 0
            }))]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        // the OTLP service may reuse neither the query worker's nor the
        // coordinator's endpoint or secret
        for (endpoint, credential) in [
            ("http://query-d.nano.svc:8080", &otel_credential),
            ("http://enrich-d.nano.svc:3016", &otel_credential),
            ("http://otel-d.nano.svc:3014", &worker_credential),
            ("http://otel-d.nano.svc:3014", &coordinator_credential),
        ] {
            let (path, _) = write_shared_registry(
                &directory,
                serde_json::json!([base(serde_json::json!({
                    "internal_endpoint": endpoint,
                    "credential_file": credential,
                }))]),
            );
            assert!(SharedLakeWorkerRegistry::from_file(&path).is_err(), "{endpoint}");
        }
        // a public (non-internal) origin is refused
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "https://otel.example.com:443",
                "credential_file": otel_credential,
            }))]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
        // unknown keys inside the block are refused
        let (path, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(serde_json::json!({
                "internal_endpoint": "http://otel-d.nano.svc:3014",
                "credential_file": otel_credential,
                "ingest_token_file": "/nope"
            }))]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&path).is_err());
    }

    #[test]
    fn shared_worker_registry_rejects_foreign_duplicate_and_public_assignments() {
        let directory = tempfile::tempdir().unwrap();
        let credential = directory.path().join("worker-token");
        let tenant_a = Uuid::from_u128(0xa);
        let tenant_b = Uuid::from_u128(0xb);
        let base = |tenant: Uuid, expected: Uuid, endpoint: &str| {
            serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": expected,
                "internal_endpoint": endpoint,
                "credential_file": credential,
                "expected_worker_identity": format!("worker-{tenant}"),
                "expected_worker_revision": 1,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                }
            })
        };
        let (foreign, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(tenant_a, tenant_b, "http://query-a.nano.svc:8080")]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&foreign).is_err());

        let (duplicate, _) = write_shared_registry(
            &directory,
            serde_json::json!([
                base(tenant_a, tenant_a, "http://query-a.nano.svc:8080"),
                base(tenant_a, tenant_a, "http://query-b.nano.svc:8080")
            ]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&duplicate).is_err());

        let (public, _) = write_shared_registry(
            &directory,
            serde_json::json!([base(tenant_a, tenant_a, "https://example.com:443")]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&public).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (non_private, _) = write_shared_registry(
                &directory,
                serde_json::json!([base(tenant_a, tenant_a, "http://query-a.nano.svc:8080")]),
            );
            std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o640))
                .expect("make negative credential group-readable");
            assert!(SharedLakeWorkerRegistry::from_file(&non_private).is_err());
            write_private_credential(&credential, &"a".repeat(64));
        }

        let credential_assignment = |tenant: Uuid, endpoint: &str, credential_file: &Path| {
            serde_json::json!({
                "tenant_id": tenant,
                "expected_worker_tenant_id": tenant,
                "internal_endpoint": endpoint,
                "credential_file": credential_file,
                "expected_worker_identity": format!("worker-{tenant}"),
                "expected_worker_revision": 1,
                "prevalence_snapshots": {
                    "one_hour": "prev-1h",
                    "twenty_four_hours": "prev-24h",
                    "seven_days": "prev-7d",
                    "thirty_days": "prev-30d"
                }
            })
        };
        let (credential_duplicate, _) = write_shared_registry(
            &directory,
            serde_json::json!([
                credential_assignment(tenant_a, "http://query-a.nano.svc:8080", &credential,),
                credential_assignment(tenant_b, "http://query-b.nano.svc:8080", &credential,)
            ]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&credential_duplicate).is_err());

        let credential_alias = directory.path().join("worker-token-alias");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&credential, &credential_alias)
            .expect("create credential reference alias");
        #[cfg(not(unix))]
        let credential_alias = directory.path().join(".").join("worker-token");
        let (credential_reuse, _) = write_shared_registry(
            &directory,
            serde_json::json!([
                credential_assignment(tenant_a, "http://query-a.nano.svc:8080", &credential,),
                credential_assignment(tenant_b, "http://query-b.nano.svc:8080", &credential_alias,)
            ]),
        );
        assert!(SharedLakeWorkerRegistry::from_file(&credential_reuse).is_err());
    }

    /// The worker refuses to serve an incomplete event view while the signed
    /// hot-tail publisher is frozen. That must reach the analyst as a retryable
    /// 503, never as a 400 that renders like a query syntax error.
    /// A durable pin is captured at submission and reused by every retry, so a pin
    /// taken while the publisher is frozen names an already-incomplete tail. The
    /// execution-time liveness gate cannot detect that (the publisher may be
    /// healthy again by then), so admission must refuse. Executor `degraded` is a
    /// DIFFERENT condition -- durable work runs in an isolated worker -- and must
    /// still admit, which is why the check reads the publication half specifically.
    #[test]
    fn a_pin_is_refused_over_a_degraded_publisher_but_not_a_degraded_executor() {
        let mut health = generation_health("degraded", "tenant-a");
        health.hot_tail_publication = Some(LakeWorkerPublicationHealth {
            status: "ok".to_string(),
            reason: None,
            verdict: Some("healthy".to_string()),
        });
        generation_pin_from_health(health, "tenant-a")
            .expect("executor pressure must not block durable admission");

        let mut health = generation_health("degraded", "tenant-a");
        health.hot_tail_publication = Some(LakeWorkerPublicationHealth {
            status: "degraded".to_string(),
            reason: Some("reconciliation_stale".to_string()),
            verdict: None,
        });
        let error = generation_pin_from_health(health, "tenant-a")
            .expect_err("a pin over a frozen publisher must be refused");
        assert!(
            matches!(error, SearchError::TenantLakePublicationDegraded(ref message)
                if message.contains("reconciliation_stale")),
            "must be retryable and name the reason: {error:?}"
        );
    }

    #[test]
    fn a_frozen_event_publication_maps_to_a_retryable_service_error() {
        assert!(matches!(
            lake_dependency_unavailable(reqwest::StatusCode::SERVICE_UNAVAILABLE, None),
            Some(SearchError::ServiceUnavailable(_))
        ));
        assert!(matches!(
            lake_dependency_unavailable(
                reqwest::StatusCode::BAD_REQUEST,
                Some("DEPENDENCY_UNAVAILABLE")
            ),
            Some(SearchError::ServiceUnavailable(_))
        ));
        // A genuinely malformed query must stay a validation error.
        assert!(
            lake_dependency_unavailable(reqwest::StatusCode::BAD_REQUEST, Some("QUERY_ERROR"))
                .is_none()
        );
        assert!(lake_dependency_unavailable(reqwest::StatusCode::BAD_REQUEST, None).is_none());
    }

    /// NAN-2707: the live worker body for `prevalence_dest_ip=*` before the
    /// codegen fix. A deterministic engine rejection must reach the analyst as
    /// a query error that carries the diagnostic, not as a retryable outage.
    #[test]
    fn a_worker_engine_rejection_is_a_query_error_not_an_outage() {
        let rejected: LakeQueryEnvelope = serde_json::from_value(serde_json::json!({
            "ok": false,
            "error": "lake engine rejected the query: chDB query failed: Code: 32. DB::Exception: Attempt to read after eof: while converting '' to UInt16. (ATTEMPT_TO_READ_AFTER_EOF)",
            "error_code": "QUERY_EXECUTION_FAILED",
        }))
        .expect("worker 500 envelope parses");
        assert!(
            lake_server_error_unavailable(
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                Some(&rejected)
            )
            .is_none(),
            "engine rejection must fall through to the query-error path"
        );
        // Every other 5xx is still an outage: an opaque internal failure, an
        // unparseable body, a gateway error, and the 503 publication gate.
        let internal: LakeQueryEnvelope = serde_json::from_value(serde_json::json!({
            "ok": false, "error": "worker execution failed", "error_code": null,
        }))
        .unwrap();
        for (status, envelope) in [
            (reqwest::StatusCode::INTERNAL_SERVER_ERROR, Some(&internal)),
            (reqwest::StatusCode::INTERNAL_SERVER_ERROR, None),
            (reqwest::StatusCode::BAD_GATEWAY, Some(&rejected)),
            (reqwest::StatusCode::SERVICE_UNAVAILABLE, Some(&rejected)),
        ] {
            assert!(
                matches!(
                    lake_server_error_unavailable(status, envelope),
                    Some(SearchError::ServiceUnavailable(_))
                ),
                "{status} must stay an outage"
            );
        }
        assert!(lake_server_error_unavailable(reqwest::StatusCode::BAD_REQUEST, None).is_none());
    }

    #[test]
    fn interactive_admission_requires_healthy_publication_and_executor() {
        let publication = |verdict: Option<&str>, status: &str| LakeWorkerPublicationHealth {
            status: status.to_string(),
            reason: None,
            verdict: verdict.map(str::to_string),
        };
        let mut health = generation_health("ok", "tenant-a");
        assert!(!health.interactive_ready());
        health.hot_tail_publication = Some(publication(Some("healthy"), "ok"));
        assert!(health.interactive_ready());
        health.status = "degraded".into();
        assert!(!health.interactive_ready());
        assert!(generation_pin_from_health(health, "tenant-a").is_ok());
        let mut stale = generation_health("ok", "tenant-a");
        stale.hot_tail_publication = Some(publication(Some("stale"), "degraded"));
        assert!(!stale.interactive_ready());
        // NAN-2401: a stale tail is interactive-servable (completeness envelope)
        // and the interactive lane takes the pin; the durable lane still refuses.
        assert!(stale.interactive_servable());
        assert!(generation_pin_from_health(stale, "tenant-a").is_err());
        let mut stale = generation_health("ok", "tenant-a");
        stale.hot_tail_publication = Some(publication(Some("stale"), "degraded"));
        assert!(generation_pin_from_health_with(stale, "tenant-a", true).is_ok());
        let mut unservable = generation_health("ok", "tenant-a");
        unservable.hot_tail_publication = Some(publication(Some("unservable"), "degraded"));
        assert!(!unservable.interactive_servable());
        assert!(generation_pin_from_health_with(unservable, "tenant-a", true).is_err());
    }

    fn generation_health(status: &str, tenant_id: &str) -> LakeWorkerGenerationHealth {
        LakeWorkerGenerationHealth {
            status: status.to_string(),
            tenant_id: tenant_id.to_string(),
            event_generation_id: "event-42-deadbeef".to_string(),
            generation_snapshot_id: 42,
            iceberg_metadata_location: Some(
                "s3://lake/warehouse/tenant-a/events/metadata/00042.metadata.json".to_string(),
            ),
            event_config_sha256: "1".repeat(64),
            compiler_sha256: "2".repeat(64),
            native_artifact_sha256: "3".repeat(64),
            hot_tail_manifest_sha256: Some("4".repeat(64)),
            executor_status: None,
            hot_tail_publication: None,
            hot_tail_snapshot_id: Some(43),
            hot_tail_id: Some("5".repeat(64)),
            worker_assignment_identity: None,
            worker_assignment_revision: None,
        }
    }

    #[test]
    fn shared_client_rejects_foreign_or_stale_worker_assignment() {
        let client = LakeQueryClient::new_with_assignment(
            "http://query-a.nano.svc:8080",
            Uuid::from_u128(0xa).to_string(),
            "x".repeat(32),
            Duration::from_secs(1),
            "worker-a".to_string(),
            7,
        )
        .unwrap();
        let mut health = generation_health("ok", &Uuid::from_u128(0xa).to_string());
        health.worker_assignment_identity = Some("worker-a".to_string());
        health.worker_assignment_revision = Some(7);
        assert!(client.verify_worker_assignment(&health).is_ok());
        health.worker_assignment_identity = Some("worker-b".to_string());
        assert!(client.verify_worker_assignment(&health).is_err());
        health.worker_assignment_identity = Some("worker-a".to_string());
        health.worker_assignment_revision = Some(8);
        assert!(client.verify_worker_assignment(&health).is_err());

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            WORKER_ASSIGNMENT_ID_HEADER,
            reqwest::header::HeaderValue::from_static("worker-a"),
        );
        headers.insert(
            WORKER_ASSIGNMENT_REVISION_HEADER,
            reqwest::header::HeaderValue::from_static("7"),
        );
        assert!(client.verify_response_assignment(&headers).is_ok());
        headers.insert(
            WORKER_ASSIGNMENT_REVISION_HEADER,
            reqwest::header::HeaderValue::from_static("8"),
        );
        assert!(client.verify_response_assignment(&headers).is_err());
        headers.remove(WORKER_ASSIGNMENT_ID_HEADER);
        assert!(client.verify_response_assignment(&headers).is_err());

        let dedicated = LakeQueryClient::new(
            "http://query-a.nano.svc:8080",
            "dedicated".to_string(),
            "x".repeat(32),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(dedicated
            .verify_response_assignment(&reqwest::header::HeaderMap::new())
            .is_ok());
    }

    #[test]
    fn client_rejects_credentialed_or_path_urls() {
        let token = "x".repeat(32);
        assert!(LakeQueryClient::new(
            "http://user:pass@localhost:3010",
            "tenant-a".to_string(),
            token.clone(),
            Duration::from_secs(1),
        )
        .is_err());
        assert!(LakeQueryClient::new(
            "http://localhost:3010/not-an-origin",
            "tenant-a".to_string(),
            token,
            Duration::from_secs(1),
        )
        .is_err());
    }

    #[test]
    fn durable_pin_accepts_degraded_executor_but_not_tenant_substitution() {
        let pin = generation_pin_from_health(generation_health("degraded", "tenant-a"), "tenant-a")
            .expect("degraded serving capacity must not block isolated durable admission");
        assert_eq!(pin.snapshot_id, 42);
        assert_eq!(pin.generation_id, "event-42-deadbeef");

        assert!(
            generation_pin_from_health(generation_health("degraded", "tenant-b"), "tenant-a")
                .is_err()
        );
        assert!(
            generation_pin_from_health(generation_health("failed", "tenant-a"), "tenant-a")
                .is_err()
        );
    }

    #[tokio::test]
    async fn resource_rejection_retains_structured_bytes_over_http() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for kind in ["scan", "memory"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut buffer = [0; 4096];
                let read = socket.read(&mut buffer).await.unwrap();
                assert!(read > 0);
                request.extend_from_slice(&buffer[..read]);
                if let Some(header_end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= header_end + 4 + length {
                        break;
                    }
                }
            }
            let body = serde_json::json!({
                "ok": false, "error_code": "RESOURCE_EXHAUSTED",
                "error": format!("interactive query exhausted its {kind} budget"),
                "estimated_bytes": 720_000_000, "budget_bytes": 100_000_000,
                "tail_objects_considered": 7
            })
            .to_string();
            socket.write_all(format!("HTTP/1.1 422 Unprocessable Entity\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
        });
        let client = LakeQueryClient::new(
            &endpoint,
            "tenant-a".into(),
            "x".repeat(32),
            Duration::from_secs(5),
        )
        .unwrap();
        let request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "* | stats count", "time_range": { "start": "2026-09-19T00:00:00Z", "end": "2026-09-20T00:00:00Z" }
        })).unwrap();
        let error = client
            .search(&request, "scan-test", None, &BTreeSet::new())
            .await
            .unwrap_err();
        server.await.unwrap();
        assert!(matches!(error, SearchError::ResourceExhausted(ref detail)
            if detail == &format!("{kind}; estimated_bytes=720000000; budget_bytes=100000000")));
        }
    }

    #[test]
    fn envelope_maps_rows_and_page_bound_count() {
        let response = LakeQueryEnvelope {
            identity_index: None,
            log_head: None,
            estimated_bytes: None,
            budget_bytes: None,
            ok: true,
            request_id: Some("request-a".to_string()),
            tenant_id: Some("tenant-a".to_string()),
            route: Some("broad_npl".to_string()),
            generation_id: None,
            snapshot_id: None,
            error: None,
            error_code: None,
            wall_seconds: Some(0.125),
            completeness: None,
            result: Some(LakeQueryResult {
                group_total: None,
                rows: vec![serde_json::json!({"src_endpoint.ip": "10.0.0.1"})],
                result_rows: Some(1),
                page_has_more: Some(true),
                wall_seconds: None,
                query_result_cache_hit: false,
                newest_first_event_rows: None,
                continuation: None,
            }),
        }
        .into_search_response(1, 0)
        .expect("valid worker envelope");

        assert_eq!(response.results.len(), 1);
        // NAN-2550: one row came back and more exist. The count is that one row,
        // flagged as a lower bound -- not the old fabricated `2`.
        assert_eq!(response.total_count, 1);
        assert!(!response.total_count_exact);
        assert_eq!(response.execution_time_ms, 125);
        assert_eq!(response.fields[0].field_type, "ip");
        // The bound is a property of the result, so nothing lands in `warnings`
        // for the UI to render as a banner.
        assert!(response.warnings.is_none());
    }

    /// NAN-2550: the offset is still carried into the bound, and a page that
    /// proves the end of the result set reports an exact count.
    #[test]
    fn envelope_reports_a_complete_page_as_an_exact_count() {
        let response = LakeQueryEnvelope {
            identity_index: None,
            log_head: None,
            estimated_bytes: None,
            budget_bytes: None,
            ok: true,
            request_id: Some("request-a".to_string()),
            tenant_id: Some("tenant-a".to_string()),
            route: Some("broad_npl".to_string()),
            generation_id: None,
            snapshot_id: None,
            error: None,
            error_code: None,
            wall_seconds: Some(0.125),
            completeness: None,
            result: Some(LakeQueryResult {
                group_total: None,
                rows: vec![serde_json::json!({"src_endpoint.ip": "10.0.0.1"})],
                result_rows: Some(1),
                page_has_more: Some(false),
                wall_seconds: None,
                query_result_cache_hit: false,
                newest_first_event_rows: None,
                continuation: None,
            }),
        }
        .into_search_response(50, 100)
        .expect("valid worker envelope");

        assert_eq!(response.total_count, 101);
        assert!(response.total_count_exact);
        assert!(response.warnings.is_none());
    }

    /// NAN-2550 wire compatibility: a response from a peer that predates the
    /// field must decode as "not exact", never as a trusted total.
    #[test]
    fn a_search_response_without_the_field_decodes_as_not_exact() {
        let decoded: SearchResponse = serde_json::from_value(serde_json::json!({
            "results": [],
            "total_count": 50,
            "execution_time_ms": 1,
            "fields": [],
            "generated_sql": null,
        }))
        .expect("legacy search response");
        assert!(!decoded.total_count_exact);
    }

    #[test]
    fn transaction_event_preview_is_bounded_without_changing_exact_count() {
        let events = (0..75)
            .map(|index| serde_json::Value::String(format!("event-{index}")))
            .collect::<Vec<_>>();
        let response = LakeQueryEnvelope {
            identity_index: None,
            log_head: None,
            estimated_bytes: None,
            budget_bytes: None,
            ok: true,
            request_id: Some("request-a".to_string()),
            tenant_id: Some("tenant-a".to_string()),
            route: Some("broad_npl".to_string()),
            generation_id: None,
            snapshot_id: None,
            error: None,
            error_code: None,
            wall_seconds: Some(0.1),
            completeness: None,
            result: Some(LakeQueryResult {
                group_total: None,
                rows: vec![serde_json::json!({
                    "device.hostname": "server-a",
                    "eventcount": 500,
                    "_raw_events": events,
                })],
                result_rows: Some(1),
                page_has_more: Some(false),
                wall_seconds: None,
                query_result_cache_hit: false,
                newest_first_event_rows: None,
                continuation: None,
            }),
        }
        .into_search_response(50, 0)
        .expect("transaction response");

        let row = response.results[0].as_object().expect("object row");
        assert_eq!(row["eventcount"], 500);
        assert_eq!(
            row["_raw_events"].as_array().expect("preview").len(),
            TRANSACTION_EVENT_PREVIEW_LIMIT
        );
        assert_eq!(row["_raw_events_materialized"], 75);
        assert_eq!(row["_raw_events_truncated"], true);
        assert!(response.warnings.as_ref().is_some_and(|warnings| warnings
            .iter()
            .any(|warning| warning.code == "TRANSACTION_EVENT_PREVIEW")));
    }

    #[test]
    fn envelope_binding_rejects_tenant_request_or_route_substitution() {
        let client = LakeQueryClient::new(
            "http://localhost:3010",
            "tenant-a".to_string(),
            "x".repeat(32),
            Duration::from_secs(1),
        )
        .unwrap();
        let mut envelope = LakeQueryEnvelope {
            identity_index: None,
            log_head: None,
            estimated_bytes: None,
            budget_bytes: None,
            ok: true,
            request_id: Some("request-a".to_string()),
            tenant_id: Some("tenant-a".to_string()),
            route: Some("identity".to_string()),
            generation_id: None,
            snapshot_id: Some("identity-day-v2".to_string()),
            error: None,
            error_code: None,
            wall_seconds: None,
            completeness: None,
            result: None,
        };
        assert!(client
            .validate_envelope_binding(&envelope, "request-a", "identity")
            .is_ok());
        envelope.tenant_id = Some("tenant-b".to_string());
        assert!(client
            .validate_envelope_binding(&envelope, "request-a", "identity")
            .is_err());
    }

    #[test]
    fn identity_snapshot_allows_active_rotation_but_honors_an_explicit_pin() {
        assert!(validate_identity_snapshot_binding(None, Some("identity-42-deadbeef")).is_ok());
        assert!(validate_identity_snapshot_binding(
            Some("identity-42-deadbeef"),
            Some("identity-42-deadbeef"),
        )
        .is_ok());
        assert!(validate_identity_snapshot_binding(
            Some("identity-41-old"),
            Some("identity-42-deadbeef"),
        )
        .is_err());
        assert!(validate_identity_snapshot_binding(None, None).is_err());
        assert!(validate_identity_snapshot_binding(None, Some("bad\nidentity")).is_err());
    }
}

/// NAN-2361 follow-up: the completeness envelope and the per-consumer health
/// policy on the core side. One test per policy branch, each stating the
/// mutation it exists to catch.
#[cfg(test)]
mod completeness_policy_tests {
    use super::*;

    fn worker_health(status: &str) -> LakeWorkerGenerationHealth {
        LakeWorkerGenerationHealth {
            status: status.to_string(),
            tenant_id: "tenant-a".to_string(),
            event_generation_id: "event-42-deadbeef".to_string(),
            generation_snapshot_id: 42,
            iceberg_metadata_location: Some(
                "s3://lake/warehouse/tenant-a/events/metadata/00042.metadata.json".to_string(),
            ),
            event_config_sha256: "1".repeat(64),
            compiler_sha256: "2".repeat(64),
            native_artifact_sha256: "3".repeat(64),
            hot_tail_manifest_sha256: Some("4".repeat(64)),
            executor_status: None,
            hot_tail_publication: None,
            hot_tail_snapshot_id: Some(43),
            hot_tail_id: Some("5".repeat(64)),
            worker_assignment_identity: None,
            worker_assignment_revision: None,
        }
    }

    fn publication(verdict: Option<&str>, status: &str) -> LakeWorkerPublicationHealth {
        LakeWorkerPublicationHealth {
            status: status.to_string(),
            reason: Some("publication_backlog_stale".to_string()),
            verdict: verdict.map(str::to_string),
        }
    }

    /// The worker's degraded response must reach the caller as a structured
    /// envelope AND a loud warning, with the worker's real numbers. Mutation
    /// caught: dropping the completeness field on the way through
    /// `into_search_response`, or building the warning from defaults.
    #[test]
    fn a_degraded_worker_response_carries_the_completeness_envelope_and_a_warning() {
        let body = serde_json::json!({
            "ok": true,
            "request_id": "request-a",
            "tenant_id": "tenant-a",
            "route": "broad_npl",
            "wall_seconds": 0.125,
            "completeness": {
                "status": "stale",
                "reason": "publication_attempts_failing",
                // Only consumer lag may opt out of the warning.
                "freshness_notice_required": false,
                "events_complete_through_ms": 1_755_000_000_000_i64,
                "unpublished_revisions": 7,
                "oldest_unpublished_age_ms": 240_000,
                "byte_pressure_percent": 100,
                "object_pressure_percent": 12,
            },
            "result": {
                "rows": [{"src_endpoint.ip": "10.0.0.1"}],
                "result_rows": 1,
                "page_has_more": false,
            },
        });
        let envelope: LakeQueryEnvelope =
            serde_json::from_value(body).expect("worker envelope must deserialize");
        let response = envelope
            .into_search_response(50, 0)
            .expect("degraded response must still map");
        let completeness = response
            .completeness
            .as_ref()
            .expect("completeness must survive into SearchResponse");
        assert_eq!(completeness.status, "stale");
        assert_eq!(
            completeness.reason.as_deref(),
            Some("publication_attempts_failing")
        );
        assert_eq!(
            completeness.events_complete_through_ms,
            Some(1_755_000_000_000)
        );
        assert_eq!(completeness.unpublished_revisions, 7);
        assert_eq!(completeness.byte_pressure_percent, 100);
        let warning = response
            .warnings
            .as_ref()
            .and_then(|warnings| {
                warnings
                    .iter()
                    .find(|warning| warning.code == "LAKE_EVENTS_INCOMPLETE")
            })
            .expect("degradation must be a loud warning, never silent");
        assert_eq!(warning.severity, "warning");
        assert!(warning.message.contains("publication_attempts_failing"));
        assert!(warning
            .impact
            .as_deref()
            .is_some_and(|impact| impact.contains("7 staged revision")));
    }

    #[test]
    fn consumer_lag_display_decision_preserves_watermark_in_api_response() {
        for notice in [Some(false), Some(true), None] {
            let mut body = serde_json::json!({
                "ok": true, "request_id": "request-a", "tenant_id": "tenant-a",
                "route": "broad_npl",
                "completeness": {
                    "status": "stale", "reason": "publication_consumer_lag",
                    "events_complete_through_ms": 1_755_000_000_000_i64,
                },
                "result": {"rows": [], "result_rows": 0, "page_has_more": false},
            });
            if let Some(notice) = notice {
                body["completeness"]["freshness_notice_required"] = notice.into();
            }
            let envelope: LakeQueryEnvelope = serde_json::from_value(body).unwrap();
            let response = envelope.into_search_response(50, 0).unwrap();
            let json = serde_json::to_value(&response).unwrap();
            assert_eq!(
                json["completeness"]["events_complete_through_ms"],
                1_755_000_000_000_i64,
            );
            assert_eq!(json["completeness"]["reason"], "publication_consumer_lag");
            assert_eq!(
                response.completeness.as_ref().unwrap().freshness_notice_required,
                notice,
            );
            let warning = response.warnings.as_ref().and_then(|warnings| {
                warnings.iter().find(|warning| warning.code == "LAKE_EVENTS_INCOMPLETE")
            });
            assert_eq!(warning.is_some(), notice != Some(false));
            if let Some(warning) = warning {
                assert_eq!(warning.message, "Recent events are not yet searchable: results are complete through 2025-08-12T12:00:00Z (publication_consumer_lag).");
                assert_eq!(warning.suggestion.as_deref(), Some("Re-run the search once event publication recovers to include the newest events."));
            }
        }
    }

    /// A complete response must carry NO envelope and no incompleteness
    /// warning. Mutation caught: stamping every response as degraded.
    #[test]
    fn a_complete_response_has_no_completeness_envelope() {
        let body = serde_json::json!({
            "ok": true,
            "request_id": "request-a",
            "tenant_id": "tenant-a",
            "route": "broad_npl",
            "result": {"rows": [], "result_rows": 0, "page_has_more": false},
        });
        let envelope: LakeQueryEnvelope = serde_json::from_value(body).expect("envelope");
        let response = envelope.into_search_response(50, 0).expect("response");
        assert!(response.completeness.is_none());
        assert!(response.warnings.as_ref().is_none_or(|warnings| warnings
            .iter()
            .all(|warning| warning.code != "LAKE_EVENTS_INCOMPLETE")));
    }

    /// Interactive health tolerates EXACTLY one degraded shape: executor ok +
    /// publication verdict "stale". An old worker reports neither field and
    /// keeps failing closed; "unservable" and executor pressure keep failing
    /// closed. Mutation caught: widening the tolerance to any degraded status
    /// (which would re-admit executor-pressure and identity faults), or to
    /// workers that cannot attach a completeness envelope.
    #[test]
    fn interactive_health_tolerates_only_an_executor_ok_stale_publication() {
        let mut stale_only = worker_health("degraded");
        stale_only.executor_status = Some("ok".to_string());
        stale_only.hot_tail_publication = Some(publication(Some("stale"), "degraded"));
        assert!(stale_only.degraded_but_interactive_servable());

        // Old worker: degraded with no tri-state fields — fail closed as today.
        let mut old_worker = worker_health("degraded");
        old_worker.hot_tail_publication = Some(publication(None, "degraded"));
        assert!(!old_worker.degraded_but_interactive_servable());

        // Unservable never qualifies.
        let mut unservable = worker_health("degraded");
        unservable.executor_status = Some("ok".to_string());
        unservable.hot_tail_publication = Some(publication(Some("unservable"), "degraded"));
        assert!(!unservable.degraded_but_interactive_servable());

        // Executor pressure never qualifies, whatever the publication says.
        let mut executor_pressure = worker_health("degraded");
        executor_pressure.executor_status = Some("degraded".to_string());
        executor_pressure.hot_tail_publication = Some(publication(Some("stale"), "degraded"));
        assert!(!executor_pressure.degraded_but_interactive_servable());
    }

    /// Durable pins keep failing closed on a stale publication — a pin records
    /// no coverage watermark, so admitting it would later complete a job
    /// "successfully" over an incomplete view. Mutation caught: extending the
    /// interactive stale-tolerance to the pin path, and (defense-in-depth)
    /// trusting the legacy ok/degraded status alone when a newer worker
    /// reports a non-healthy verdict.
    #[test]
    fn a_durable_pin_is_refused_on_a_stale_verdict_even_if_legacy_status_says_ok() {
        let mut stale = worker_health("ok");
        stale.hot_tail_publication = Some(publication(Some("stale"), "ok"));
        let error = generation_pin_from_health(stale, "tenant-a")
            .expect_err("a stale publication must refuse durable admission");
        assert!(matches!(error, SearchError::TenantLakePublicationDegraded(_)));

        let mut healthy = worker_health("ok");
        healthy.hot_tail_publication = Some(publication(Some("healthy"), "ok"));
        generation_pin_from_health(healthy, "tenant-a")
            .expect("a healthy publication must admit durable work");
    }

    /// NAN-2651: a response served over a newest-first partial hot tail
    /// reaches the analyst as HOT_TAIL_PARTIAL with the uncovered range, never
    /// as a silent 200. Mutation caught: dropping `hot_tail_partial` on the
    /// way through, or mislabeling the hole as routine "recent events" lag.
    #[test]
    fn a_partial_hot_tail_response_carries_hot_tail_partial_with_the_uncovered_range() {
        let body = serde_json::json!({
            "ok": true,
            "request_id": "request-a",
            "tenant_id": "tenant-a",
            "route": "broad_npl",
            "wall_seconds": 0.1,
            "completeness": {
                "status": "partial",
                "reason": "hot_tail_over_cache_bound",
                "unpublished_revisions": 0,
                "byte_pressure_percent": 0,
                "object_pressure_percent": 0,
                "hot_tail_partial": {
                    "total_objects": 900,
                    "served_objects": 400,
                    "total_bytes": 3_282_334_630_u64,
                    "served_bytes": 1_610_612_736_u64,
                    "budget_bytes": 1_610_612_736_u64,
                    "cache_max_bytes": 3_221_225_472_u64,
                    "uncovered_from_ms": 1_790_103_900_000_i64,
                    "uncovered_through_ms": 1_790_175_600_000_i64,
                },
            },
            "result": {"rows": [], "result_rows": 0, "page_has_more": false},
        });
        let envelope: LakeQueryEnvelope = serde_json::from_value(body).unwrap();
        let response = envelope.into_search_response(50, 0).unwrap();
        let warnings = response.warnings.expect("a partial tail is never silent");
        assert_eq!(warnings[0].code, "HOT_TAIL_PARTIAL");
        assert_eq!(warnings[0].severity, "warning");
        assert!(
            warnings[0].message.contains("2026-09-22T19:05:00Z")
                && warnings[0].message.contains("2026-09-23T15:00:00Z"),
            "{}",
            warnings[0].message
        );
        assert!(warnings[0]
            .impact
            .as_deref()
            .is_some_and(|impact| impact.contains("400 of 900")));
        assert!(
            warnings.iter().all(|warning| warning.code != "LAKE_EVENTS_INCOMPLETE"),
            "a healthy publication over a partial tail is not 'recent events are late'"
        );
        let partial = response
            .completeness
            .and_then(|completeness| completeness.hot_tail_partial)
            .expect("the structured range survives into SearchResponse");
        assert_eq!(partial.uncovered_through_ms, Some(1_790_175_600_000));
    }

    /// NAN-2694: an over-RAM tail served through the disk tier / R2 is
    /// COMPLETE: it reaches the analyst as the informational
    /// HOT_TAIL_SLOW_PATH with the R2 range, never as HOT_TAIL_PARTIAL or
    /// LAKE_EVENTS_INCOMPLETE.
    #[test]
    fn a_slow_path_response_is_complete_and_names_the_range_read_from_r2() {
        let body = serde_json::json!({
            "ok": true,
            "completeness": {
                "status": "ok",
                "reason": "hot_tail_slow_path",
                "unpublished_revisions": 0,
                "byte_pressure_percent": 0,
                "object_pressure_percent": 0,
                "hot_tail_slow_path": {
                    "objects": 500, "bytes": 1_671_721_894_u64,
                    "disk_objects": 420, "disk_bytes": 1_400_000_000_u64,
                    "r2_objects": 80, "r2_bytes": 271_721_894_u64,
                    "from_ms": 1_790_103_900_000_i64, "through_ms": 1_790_175_600_000_i64,
                    "r2_from_ms": 1_790_103_900_000_i64, "r2_through_ms": 1_790_110_000_000_i64,
                    "query_budget_bytes": 2_147_483_648_u64, "staging_ms": 4_200,
                },
            },
            "result": {"rows": [], "result_rows": 0, "page_has_more": false},
        });
        let envelope: LakeQueryEnvelope = serde_json::from_value(body).unwrap();
        let response = envelope.into_search_response(50, 0).unwrap();
        let warnings = response.warnings.expect("the slow path is explained");
        let codes: Vec<&str> = warnings.iter().map(|warning| warning.code.as_str()).collect();
        assert_eq!(codes, vec!["HOT_TAIL_SLOW_PATH"]);
        assert_eq!(warnings[0].severity, "info");
        assert!(warnings[0].message.starts_with("Results are complete"), "{}", warnings[0].message);
        assert!(warnings[0].message.contains("2026-09-22T19:05:00Z"), "{}", warnings[0].message);
        assert!(warnings[0].impact.as_deref().is_some_and(|impact| impact.contains("80 (259 MiB) from object storage")));
        let completeness = response.completeness.expect("envelope survives");
        assert!(completeness.hot_tail_partial.is_none());
        assert_eq!(completeness.hot_tail_slow_path.unwrap().r2_objects, 80);
    }

    /// NAN-2694: the last-resort partial names why the slow path failed.
    #[test]
    fn a_last_resort_partial_keeps_its_reason() {
        let body = serde_json::json!({
            "ok": true,
            "completeness": {
                "status": "partial",
                "reason": "hot_tail_over_cache_bound",
                "hot_tail_partial": {
                    "uncovered_through_ms": 1_790_103_900_000_i64,
                    "reason": "slow_path_r2_unavailable",
                },
            },
            "result": {"rows": [], "result_rows": 0, "page_has_more": false},
        });
        let envelope: LakeQueryEnvelope = serde_json::from_value(body).unwrap();
        let response = envelope.into_search_response(50, 0).unwrap();
        assert_eq!(response.warnings.unwrap()[0].code, "HOT_TAIL_PARTIAL");
        assert_eq!(
            response.completeness.unwrap().hot_tail_partial.unwrap().reason.as_deref(),
            Some("slow_path_r2_unavailable")
        );
    }

    /// A partial tail whose publication is ALSO stale keeps both warnings,
    /// the hole first.
    #[test]
    fn a_stale_and_partial_tail_reports_both_the_hole_and_the_lag() {
        let body = serde_json::json!({
            "ok": true,
            "completeness": {
                "status": "stale",
                "reason": "publication_attempts_failing",
                "events_complete_through_ms": 1_790_175_600_000_i64,
                "unpublished_revisions": 2,
                "byte_pressure_percent": 90,
                "object_pressure_percent": 10,
                "hot_tail_partial": {"uncovered_through_ms": 1_790_103_900_000_i64},
            },
            "result": {"rows": [], "result_rows": 0, "page_has_more": false},
        });
        let envelope: LakeQueryEnvelope = serde_json::from_value(body).unwrap();
        let warnings = envelope.into_search_response(50, 0).unwrap().warnings.unwrap();
        let codes: Vec<&str> = warnings.iter().map(|warning| warning.code.as_str()).collect();
        assert_eq!(codes, vec!["HOT_TAIL_PARTIAL", "LAKE_EVENTS_INCOMPLETE"]);
        assert!(warnings[0].message.contains("up to 2026-09-22T19:05:00Z"), "{}", warnings[0].message);
    }
}

#[cfg(test)]
mod lake_cell_routing_tests {
    //! NAN-2891: lean-lake cell routing. Backend resolution, tenant isolation,
    //! and the query[T] wire through a mock cell router.
    use super::super::lake_cell::{LakeCellRoute, LakeCellRoutes};
    use super::*;
    use super::super::tenant::SearchTenantScope;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "router-token-router-token-router-token-xyz";

    fn private_file(dir: &tempfile::TempDir, name: &str, value: &str) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, value).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn gen1_registry(dir: &tempfile::TempDir, tenants: &[Uuid]) -> SharedLakeWorkerRegistry {
        let assignments: Vec<_> = tenants
            .iter()
            .enumerate()
            .map(|(index, tenant)| {
                let credential = private_file(dir, &format!("gen1-{index}"), &"g".repeat(64));
                serde_json::json!({
                    "tenant_id": tenant,
                    "expected_worker_tenant_id": tenant,
                    "internal_endpoint": format!("http://reader-{index}.nano.svc:8080"),
                    "credential_file": credential,
                    "expected_worker_identity": format!("reader-{index}"),
                    "expected_worker_revision": 7,
                    "prevalence_snapshots": {
                        "one_hour": "prev-1h", "twenty_four_hours": "prev-24h",
                        "seven_days": "prev-7d", "thirty_days": "prev-30d"
                    }
                })
            })
            .collect();
        let path = dir.path().join("workers.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({"version": 1, "assignments": assignments})).unwrap(),
        )
        .unwrap();
        SharedLakeWorkerRegistry::from_file(&path).unwrap()
    }

    fn cell_route(dir: &tempfile::TempDir, tenant: Uuid, origin: &str) -> LakeCellRoute {
        let token = private_file(dir, "router.token", TOKEN);
        LakeCellRoute::for_test(tenant, origin, token)
    }

    fn search_request() -> SearchRequest {
        serde_json::from_value(serde_json::json!({
            "query": "* | head 5",
            "time_range": {"start": "2026-09-25T00:00:00Z", "end": "2026-09-25T01:00:00Z"}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn cell_durable_admission_uses_tenant_status_pin() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x42);
        let route = cell_route(&dir, tenant, &server.uri());
        let client = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5))
            .unwrap().client.unwrap();
        let config = "a".repeat(64);
        Mock::given(method("GET"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/status")))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "tenant_id": tenant.to_string(), "source_mode": "parts",
                "durable_jobs_ready": true,
                "generation_id": format!("event-0-{}", &config[..16]),
                "generation_snapshot_id": 0,
                "event_config_sha256": config,
                "compiler_sha256": "b".repeat(64),
                "native_artifact_sha256": "c".repeat(64),
            })))
            .expect(1).mount(&server).await;
        let (pin, ready) = client.admission_generation().await.unwrap();
        assert!(ready);
        assert!(pin.is_bootstrap());
        assert_eq!(pin.snapshot_id, 0);
        let unconfigured: LakeCellQueryStatus = serde_json::from_value(serde_json::json!({
            "ok": true, "tenant_id": tenant.to_string(), "source_mode": "parts",
            "generation_id": pin.generation_id,
            "generation_snapshot_id": pin.snapshot_id,
            "event_config_sha256": pin.event_config_sha256,
            "compiler_sha256": pin.compiler_sha256,
            "native_artifact_sha256": pin.native_artifact_sha256,
        })).unwrap();
        assert!(unconfigured.durable_pin().is_err(), "unprovisioned result storage cannot admit jobs");
    }

    #[tokio::test]
    async fn cell_result_pages_preserve_tenant_and_artifact_binding() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x42);
        let route = cell_route(&dir, tenant, &server.uri());
        let client = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5))
            .unwrap().client.unwrap();
        let reference = SearchJobResultRef {
            tenant_id: Some(tenant),
            manifest_uri: "file:///state/results/tenant-a/job-job1/attempt-1/manifest.json".into(),
            manifest_sha256: "a".repeat(64),
            rows: 3,
            parts: 2,
            has_more: false,
            page_rows: 2,
            retention_proof: None,
        };
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/jobs/result-page")))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .and(body_partial_json(serde_json::json!({
                "tenant_id": tenant.to_string(), "job_id": "job1", "page": 1,
                "reference": {"manifest_uri": reference.manifest_uri,
                    "manifest_sha256": reference.manifest_sha256, "rows": 3, "parts": 2,
                    "page_rows": 2}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "page": 1, "pages": 2, "total_rows": 3, "row_offset": 2,
                "rows": [{"event_uid": "last"}]
            })))
            .expect(1).mount(&server).await;
        let page = client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 1).await.unwrap();
        assert_eq!(page.rows[0]["event_uid"], "last");
        assert!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 2).await.is_err());
        let mut foreign = reference.clone();
        foreign.tenant_id = Some(Uuid::from_u128(0x43));
        assert!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &foreign, 1).await.is_err());
        let mut remote = reference.clone();
        remote.manifest_uri = "s3://other-bucket/result.json".into();
        assert!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &remote, 1).await.is_err());

        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/jobs/result-page")))
            .and(body_partial_json(serde_json::json!({"page": 0})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "page": 0, "pages": 2, "total_rows": 4, "row_offset": 0,
                "rows": [{"event_uid": "substituted"}]
            })))
            .expect(1).mount(&server).await;
        assert!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 0).await.is_err());
    }

    /// NAN-3282: inside a product-view scope, a lake answer is charged to the
    /// view's ledger as it is read, and one over the view's budget is refused
    /// with the typed `ViewTooLarge` before it is decoded.
    #[tokio::test]
    async fn view_scoped_lake_reads_are_charged_and_refused_over_budget() {
        use crate::search::view_memory::{self, ViewMemoryBudget, ViewMemoryConfig, MIB};
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x42);
        let route = cell_route(&dir, tenant, &server.uri());
        let client = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5))
            .unwrap().client.unwrap();
        let reference = SearchJobResultRef {
            tenant_id: Some(tenant),
            manifest_uri: "file:///state/results/tenant-a/job-job1/attempt-1/manifest.json".into(),
            manifest_sha256: "a".repeat(64),
            rows: 2,
            parts: 1,
            has_more: false,
            page_rows: 2,
            retention_proof: None,
        };
        // ~6 MiB on the wire: 18 MiB charged once amplified for decode.
        let wide = "x".repeat(3 * MIB as usize);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/jobs/result-page")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "page": 0, "pages": 1, "total_rows": 2, "row_offset": 0,
                "rows": [{"event_uid": "a", "raw": wide}, {"event_uid": "b", "raw": wide}]
            })))
            .mount(&server).await;

        // Unscoped (ordinary search / job paths): not budgeted.
        assert_eq!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 0).await.unwrap().rows.len(), 2);

        // A view with room: read, and the bytes land on its ledger.
        let roomy = ViewMemoryBudget::new(ViewMemoryConfig::derive(None, Some(64), Some(64), Some(50)));
        let ledger = roomy.ledger("asset-events");
        let page = view_memory::scope(ledger.clone(), client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 0))
            .await
            .unwrap();
        assert_eq!(page.rows.len(), 2);
        assert!(ledger.charged_bytes() >= 18 * MIB, "charged {}", ledger.charged_bytes());

        // A view over its per-request budget: typed refusal, nothing decoded.
        let tight = ViewMemoryBudget::new(ViewMemoryConfig::derive(None, Some(64), Some(16), Some(50)));
        let error = view_memory::scope(tight.ledger("asset-dossier"), client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 0))
            .await
            .expect_err("over the per-request view budget");
        assert!(
            matches!(&error, SearchError::ViewTooLarge { view, budget_bytes, .. }
                if view == "asset-dossier" && *budget_bytes == 16 * MIB),
            "got {error:?}"
        );
        assert_eq!(tight.available_mib(), 64, "a refused view releases its reservation");
    }

    #[tokio::test]
    async fn cell_result_page_uses_tenant_r2_reference_after_route_move() {
        let moved_cell = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x42);
        let route = cell_route(&dir, tenant, &moved_cell.uri());
        let client = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5))
            .unwrap().client.unwrap();
        let tenant_hash = hex::encode(Sha256::digest(tenant.to_string().as_bytes()));
        let reference = SearchJobResultRef {
            tenant_id: Some(tenant),
            manifest_uri: format!(
                "s3://nano-shared-r2-{tenant}/{tenant}/durable-query-result/v1/tenant-{tenant_hash}/job-job1/attempt-a/manifest.json"
            ),
            manifest_sha256: "a".repeat(64),
            rows: 1,
            parts: 1,
            has_more: false,
            page_rows: 10_000,
            retention_proof: None,
        };
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/jobs/result-page")))
            .and(header("authorization", format!("Bearer {TOKEN}")))
            .and(body_partial_json(serde_json::json!({
                "tenant_id": tenant.to_string(), "job_id": "job1", "page": 0,
                "reference": {"manifest_uri": reference.manifest_uri}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "page": 0, "pages": 1, "total_rows": 1, "row_offset": 0,
                "rows": [{"event_uid": "retained"}]
            })))
            .expect(1).mount(&moved_cell).await;
        assert_eq!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &reference, 0).await.unwrap().rows[0]["event_uid"], "retained");
        let mut foreign = reference.clone();
        foreign.manifest_uri = foreign.manifest_uri.replace("job-job1", "job-job2");
        assert!(client.result_page(SearchTenantScope::EnterpriseShared(tenant), "job1", &foreign, 0).await.is_err());
    }

    /// NAN-3492: a dedicated (trusted-local) durable job stores a tenantless
    /// reference; under the `Dedicated` scope the explicitly trusted-local
    /// cell client reads it under its own tenant. The same tenantless
    /// reference is refused under every shared (hosted) scope before any
    /// request leaves, an explicitly foreign tenant is refused under any
    /// scope, and a cell client without the explicit flag (hosted, the
    /// default) refuses it under every scope, `Dedicated` included.
    #[tokio::test]
    async fn cell_result_page_admits_tenantless_reference_only_under_dedicated_scope() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x42);
        let route = cell_route(&dir, tenant, &server.uri());
        let hosted = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5))
            .unwrap().client.unwrap();
        assert!(!hosted.is_trusted_local(), "a route alone is never trusted-local");
        let client = hosted.clone().with_trusted_local(true);
        assert!(client.is_trusted_local());
        let reference = SearchJobResultRef {
            tenant_id: None,
            manifest_uri: "file:///state/results/tenant-a/job-job1/attempt-1/manifest.json".into(),
            manifest_sha256: "a".repeat(64),
            rows: 1,
            parts: 1,
            has_more: false,
            page_rows: 10_000,
            retention_proof: None,
        };
        // Exactly one request: the dedicated read. Every refusal below must
        // happen before the client calls the cell.
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/jobs/result-page")))
            .and(body_partial_json(serde_json::json!({"tenant_id": tenant.to_string(), "job_id": "job1"})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "page": 0, "pages": 1, "total_rows": 1, "row_offset": 0,
                "rows": [{"event_uid": "dedicated"}]
            })))
            .expect(1).mount(&server).await;
        let page = client.result_page(SearchTenantScope::Dedicated, "job1", &reference, 0).await.unwrap();
        assert_eq!(page.rows[0]["event_uid"], "dedicated");

        // Hosted shared scopes: a tenantless reference is refused.
        let shared_scopes = [
            SearchTenantScope::EnterpriseShared(tenant),
            SearchTenantScope::EnterpriseSharedRetained {
                tenant_id: tenant,
                retention_revision: 1,
                retention_days: 30,
                irreversible_event_time_floor_micros: 0,
            },
        ];
        for scope in shared_scopes {
            let error = client.result_page(scope, "job1", &reference, 0).await
                .expect_err("shared scope must refuse a tenantless reference");
            assert!(error.to_string().contains("does not match the tenant scope"), "{scope:?}: {error:?}");
        }

        // A foreign tenant stamp is refused under the dedicated and shared scopes.
        let mut foreign = reference.clone();
        foreign.tenant_id = Some(Uuid::from_u128(0x43));
        for scope in [SearchTenantScope::Dedicated, SearchTenantScope::EnterpriseShared(tenant)] {
            assert!(client.result_page(scope, "job1", &foreign, 0).await.is_err(), "{scope:?}");
        }
        // A stamped reference is not admitted under the dedicated scope.
        let mut stamped = reference.clone();
        stamped.tenant_id = Some(tenant);
        assert!(client.result_page(SearchTenantScope::Dedicated, "job1", &stamped, 0).await.is_err());

        // Without the explicit flag the tenantless reference is refused under
        // every scope, before any request leaves (the mock expects one call).
        for scope in [SearchTenantScope::Dedicated, SearchTenantScope::EnterpriseShared(tenant)] {
            let error = hosted.result_page(scope, "job1", &reference, 0).await
                .expect_err("a non-trusted-local cell client must refuse a tenantless reference");
            assert!(error.to_string().contains("belongs to another tenant"), "{scope:?}: {error:?}");
            assert!(hosted.result_page(scope, "job1", &foreign, 0).await.is_err(), "{scope:?}");
        }
    }

    #[test]
    fn dark_registry_resolves_every_tenant_to_gen1_exactly_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let tenant1 = Uuid::from_u128(0x1);
        let registry = gen1_registry(&dir, &[tenant1]);
        assert_eq!(registry.cell_route_count(), 0);
        let backend = registry.backend(tenant1).unwrap();
        assert!(matches!(backend, LakeBackend::Gen1(a) if a.tenant_id == tenant1));
        assert_eq!(backend.worker_revision(), 7);
        assert!(!registry.is_cell_tenant(tenant1));
        // An empty cell map changes nothing either.
        let registry = registry.with_cell_routes(LakeCellRoutes::default());
        assert!(matches!(registry.backend(tenant1), Some(LakeBackend::Gen1(_))));
        assert!(registry.backend(Uuid::from_u128(0x2)).is_none());
        #[cfg(feature = "enterprise")]
        {
            let runtime =
                LakeQueryRuntime::from_enterprise_shared_assignment(registry.assignment(tenant1).unwrap())
                    .unwrap();
            assert!(!runtime.client.as_ref().unwrap().is_lake_cell());
        }
    }

    #[test]
    fn cell_route_wins_and_gen1_tenants_are_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let tenant1 = Uuid::from_u128(0x1); // gen1 only (tenant1)
        let dual = Uuid::from_u128(0x2); // gen1 assignment + cell placement
        let fresh = Uuid::from_u128(0x3); // cell only (fresh lean-lake tenant)
        let routes = LakeCellRoutes::from_routes_for_test([
            cell_route(&dir, dual, "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790"),
            cell_route(&dir, fresh, "http://nano-cell-cell-us-2.nano-lake-cells.svc:8790"),
        ]);
        let registry = gen1_registry(&dir, &[tenant1, dual]).with_cell_routes(routes);

        assert!(matches!(registry.backend(tenant1), Some(LakeBackend::Gen1(_))));
        assert!(!registry.is_cell_tenant(tenant1));
        // The gen1 tenant's authorised backend still needs its exact worker.
        assert!(registry.authorized_backend(tenant1, "reader-0", 7).is_some());
        assert!(registry.authorized_backend(tenant1, "reader-1", 7).is_none());
        assert!(registry.authorized_backend(tenant1, "reader-0", 8).is_none());

        let Some(LakeBackend::Cell(route)) = registry.backend(dual) else {
            panic!("dual tenant must resolve to its cell");
        };
        assert_eq!(route.tenant_id, dual);
        // Nothing about a cell tenant comes from its legacy gen1 entry.
        assert_eq!(
            registry.backend(dual).unwrap().worker_revision(),
            super::super::lake_cell::LAKE_CELL_ASSIGNMENT_REVISION
        );
        // The legacy gen1 entry's worker is irrelevant to a cell tenant.
        assert!(matches!(registry.authorized_backend(dual, "anything", 99), Some(LakeBackend::Cell(_))));

        let Some(LakeBackend::Cell(route)) = registry.backend(fresh) else {
            panic!("fresh tenant must resolve to its cell");
        };
        assert_eq!(route.tenant_id, fresh);
        assert_eq!(
            registry.backend(fresh).unwrap().worker_revision(),
            super::super::lake_cell::LAKE_CELL_ASSIGNMENT_REVISION
        );
        assert!(registry.assignment(fresh).is_none());
        assert!(matches!(registry.authorized_backend(fresh, "lean-query", 1), Some(LakeBackend::Cell(_))));
        // Unknown tenant: nothing.
        assert!(registry.authorized_backend(Uuid::from_u128(0x9), "reader-0", 7).is_none());

        // The dual tenant's Search runtime talks to its cell, pinned to it.
        let Some(LakeBackend::Cell(route)) = registry.backend(dual) else { unreachable!() };
        let runtime = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5)).unwrap();
        let client = runtime.client.as_ref().unwrap();
        assert!(client.is_lake_cell());
        assert_eq!(client.tenant_id, dual.to_string());
        assert_eq!(
            client.base_url,
            format!("http://nano-cell-cell-us-1.nano-lake-cells.svc:8790/v1/tenants/{dual}/query")
        );
    }

    #[test]
    fn tenant_a_is_never_routed_to_tenant_b_cell() {
        let dir = tempfile::tempdir().unwrap();
        let a = Uuid::from_u128(0xa);
        let b = Uuid::from_u128(0xb);
        let routes = LakeCellRoutes::from_routes_for_test([
            cell_route(&dir, a, "http://nano-cell-cell-us-1.nano-lake-cells.svc:8790"),
            cell_route(&dir, b, "http://nano-cell-cell-us-2.nano-lake-cells.svc:8790"),
        ]);
        let registry = gen1_registry(&dir, &[a]).with_cell_routes(routes);
        for (tenant, other) in [(a, b), (b, a)] {
            let Some(LakeBackend::Cell(route)) = registry.backend(tenant) else {
                panic!("placed tenant must resolve to a cell");
            };
            assert_eq!(route.tenant_id, tenant);
            assert!(!route.query_base_url.contains(&other.to_string()));
            let runtime = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5)).unwrap();
            let detection = runtime.detection_lane().unwrap();
            let detect_client = detection.client.as_ref().unwrap();
            assert!(detect_client.base_url.ends_with(&format!("/v1/tenants/{tenant}/detect")));
            assert!(detection.detection_lane().is_err(), "a second runtime lane conversion must fail");
            assert!(!detect_client.base_url.contains(&other.to_string()));
            assert_eq!(runtime.client.as_ref().unwrap().base_url, route.query_base_url);
            let client = runtime.client.unwrap();
            assert_eq!(client.tenant_id, tenant.to_string());
            assert!(!client.base_url.contains(&other.to_string()));
        }
        // A tampered route (another tenant's prefix under this tenant's UUID)
        // is refused by the client constructor.
        let mut forged = cell_route(&dir, a, "http://nano-cell-cell-us-2.nano-lake-cells.svc:8790");
        forged.query_base_url =
            format!("http://nano-cell-cell-us-2.nano-lake-cells.svc:8790/v1/tenants/{b}/query");
        assert!(LakeQueryRuntime::from_lake_cell_route(&forged, Duration::from_secs(5)).is_err());
        // A cell route bound to B can never be attached to A's assignment.
        let registry = gen1_registry(&dir, &[a]).with_cell_routes(LakeCellRoutes::from_routes_for_test([
            cell_route(&dir, b, "http://nano-cell-cell-us-2.nano-lake-cells.svc:8790"),
        ]));
        assert!(!registry.is_cell_tenant(a));
        assert!(matches!(registry.backend(a), Some(LakeBackend::Gen1(_))));
    }

    async fn cell_client(server: &MockServer, dir: &tempfile::TempDir, tenant: Uuid) -> LakeQueryClient {
        let route = cell_route(dir, tenant, &server.uri());
        LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_secs(5))
            .unwrap()
            .client
            .unwrap()
    }

    /// A fake query[T] over `total` events newest first: honors limit and the
    /// (time, metadata.uid) cursor, echoes the binding, and refuses any page
    /// over `max_page` rows as its memory budget would (503).
    struct PagedCell {
        tenant: String,
        total: usize,
        max_page: usize,
        newest_first: bool,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl wiremock::Respond for PagedCell {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            self.requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let limit = body["limit"].as_u64().unwrap() as usize;
            if limit > self.max_page {
                // The worker marks its own budget refusal with the reason
                // header (NAN-3270), so the client answers it at once. Without
                // it the 503 reads as a worker recycle and each refusal was
                // replayed until the request deadline (NAN-4304).
                return ResponseTemplate::new(503)
                    .insert_header(crate::lake_http::LAKE_REASON_HEADER, crate::lake_http::QUERY_BUDGET_EXHAUSTED_REASON)
                    .set_body_json(serde_json::json!({
                        "ok": false, "reason": "query_budget_exhausted", "error": "query memory budget exceeded"}));
            }
            // Event i has time base - i seconds and uid e{i:06}.
            let base = chrono::DateTime::parse_from_rfc3339("2026-09-25T01:00:00Z").unwrap().with_timezone(&chrono::Utc);
            let start = match body["cursor_event_uid"].as_str() {
                Some(uid) => uid.trim_start_matches('e').parse::<usize>().unwrap() + 1,
                None => 0,
            };
            let rows = (start..self.total.min(start + limit))
                .map(|i| serde_json::json!({
                    "time": (base - chrono::Duration::seconds(i as i64)).to_rfc3339(),
                    "metadata": {"uid": format!("e{i:06}")}, "message": "x"}))
                .collect::<Vec<_>>();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": self.tenant,
                "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
                "result": {"result_rows": rows.len(), "rows": rows, "page_offset": 0, "page_limit": limit,
                           "page_has_more": false, "newest_first_event_rows": self.newest_first}}))
        }
    }

    #[tokio::test]
    async fn paged_search_streams_every_row_in_bounded_pages() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xb);
        let requests = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // An older cell: no `/v1/query/pages` (404), so the cursor protocol runs.
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(PagedCell { tenant: tenant.to_string(), total: 5_000, max_page: 700,
                newest_first: true, requests: requests.clone() })
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let mut request = search_request();
        request.query = "*".into();
        request.limit = Some(20_000);
        let mut seen = Vec::new();
        let mut largest = 0;
        let paged = client
            .search_paged(&request, "q-1", &BTreeSet::new(), 2_000, |rows| {
                largest = largest.max(rows.len());
                seen.extend(rows.into_iter().map(|row| row["metadata"]["uid"].as_str().unwrap().to_string()));
                async { true }
            })
            .await
            .unwrap()
            .expect("newest-first rows page");
        // Every event exactly once, newest first, in pages the fake cell's
        // budget admits (2000 -> 1000 -> 500 after two refusals).
        assert_eq!(paged.delivered, 5_000);
        assert_eq!(seen.len(), 5_000);
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(largest <= 700);
        assert!(!paged.truncated);

        // A limit below the total stops there and reports truncation.
        request.limit = Some(1_234);
        let mut count = 0;
        let paged = client
            .search_paged(&request, "q-2", &BTreeSet::new(), 500, |rows| { count += rows.len(); async { true } })
            .await.unwrap().unwrap();
        assert_eq!((count, paged.delivered, paged.truncated), (1_234, 1_234, true));

        // A consumer that goes away stops the paging.
        let before = requests.load(std::sync::atomic::Ordering::SeqCst);
        let paged = client
            .search_paged(&request, "q-3", &BTreeSet::new(), 500, |_| async { false })
            .await.unwrap().unwrap();
        assert!(paged.stopped);
        assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst) - before, 1);
    }

    /// A fake query[T] `/v1/query/pages`: ONE request answers the whole
    /// read as NDJSON (envelope with the first page, then pages, then the
    /// completion line), as the real route does from one execution.
    struct StreamingCell {
        tenant: String,
        total: usize,
        newest_first: bool,
        fail_after_first: bool,
        requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl wiremock::Respond for StreamingCell {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            self.requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert!(body.get("cursor_time").is_none() && body["offset"] == 0);
            let limit = body["limit"].as_u64().unwrap() as usize;
            let page_rows: usize = request.url.query_pairs().find(|(k, _)| k == "page_rows").unwrap().1.parse().unwrap();
            let base = chrono::DateTime::parse_from_rfc3339("2026-09-25T01:00:00Z").unwrap().with_timezone(&chrono::Utc);
            let rows = (0..self.total.min(limit))
                .map(|i| serde_json::json!({
                    "time": (base - chrono::Duration::seconds(i as i64)).to_rfc3339(),
                    "metadata": {"uid": format!("e{i:06}")}, "message": "x"}))
                .collect::<Vec<_>>();
            let mut pages = rows.chunks(page_rows).map(<[serde_json::Value]>::to_vec).collect::<Vec<_>>();
            if pages.is_empty() || !self.newest_first {
                pages = vec![Vec::new()];
            }
            let mut out = String::new();
            let first = pages.remove(0);
            out.push_str(&serde_json::json!({
                "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": self.tenant,
                "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01, "stream": {"page_rows": page_rows},
                "result": {"result_rows": first.len(), "rows": first, "page_offset": 0, "page_limit": limit,
                           "page_has_more": false, "newest_first_event_rows": self.newest_first}}).to_string());
            out.push('\n');
            if self.fail_after_first {
                out.push_str(r#"{"ok":false,"error":"query memory budget exceeded","reason":"query_budget_exhausted","status":503}"#);
                out.push('\n');
                return ResponseTemplate::new(200).set_body_raw(out, "application/x-ndjson");
            }
            for page in &pages {
                out.push_str(&serde_json::json!({"rows": page}).to_string());
                out.push('\n');
            }
            out.push_str(&serde_json::json!({"done": true, "delivered": rows.len(), "pages": pages.len() + 1,
                "has_more": self.total > limit, "result_statements": 1}).to_string());
            out.push('\n');
            ResponseTemplate::new(200).set_body_raw(out, "application/x-ndjson")
        }
    }

    /// NAN-3060: a cell that serves `/v1/query/pages` answers the whole
    /// paged read from ONE request (one execution), every row exactly once,
    /// newest first, in page-sized deliveries; the cursor route is never
    /// called.
    #[tokio::test]
    async fn paged_search_reads_the_whole_result_from_one_streamed_execution() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xd);
        let streamed = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cursor_pages = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query/pages")))
            .respond_with(StreamingCell { tenant: tenant.to_string(), total: 5_000, newest_first: true,
                fail_after_first: false, requests: streamed.clone() })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(PagedCell { tenant: tenant.to_string(), total: 5_000, max_page: 100_000,
                newest_first: true, requests: cursor_pages.clone() })
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let mut request = search_request();
        request.query = "*".into();
        request.limit = Some(20_000);
        let mut seen = Vec::new();
        let mut largest = 0;
        let paged = client
            .search_paged(&request, "q-1", &BTreeSet::new(), 700, |rows| {
                largest = largest.max(rows.len());
                seen.extend(rows.into_iter().map(|row| row["metadata"]["uid"].as_str().unwrap().to_string()));
                async { true }
            })
            .await
            .unwrap()
            .expect("newest-first rows page");
        assert_eq!((paged.delivered, seen.len(), paged.pages), (5_000, 5_000, 8));
        assert!(seen.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(largest <= 700 && !paged.truncated && paged.first.is_some());
        assert_eq!(streamed.load(std::sync::atomic::Ordering::SeqCst), 1, "one execution for eight pages");
        assert_eq!(cursor_pages.load(std::sync::atomic::Ordering::SeqCst), 0, "the per-page cursor route is never used");

        // A limit below the total: truncated at the limit, still one request.
        request.limit = Some(1_234);
        let mut count = 0;
        let paged = client
            .search_paged(&request, "q-2", &BTreeSet::new(), 500, |rows| { count += rows.len(); async { true } })
            .await.unwrap().unwrap();
        assert_eq!((count, paged.delivered, paged.truncated), (1_234, 1_234, true));
        assert_eq!(streamed.load(std::sync::atomic::Ordering::SeqCst), 2);

        // A consumer that goes away stops after the first page.
        let paged = client
            .search_paged(&request, "q-3", &BTreeSet::new(), 500, |_| async { false })
            .await.unwrap().unwrap();
        assert!(paged.stopped && paged.pages == 1);
        assert_eq!(cursor_pages.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// A failure after the first page arrives as an error line and keeps
    /// its budget classification (503 query_budget_exhausted -> memory).
    #[tokio::test]
    async fn streamed_read_failure_after_the_first_page_is_classified() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xe);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query/pages")))
            .respond_with(StreamingCell { tenant: tenant.to_string(), total: 5_000, newest_first: true,
                fail_after_first: true, requests: Default::default() })
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let mut request = search_request();
        request.limit = Some(5_000);
        let error = client
            .search_paged(&request, "q-1", &BTreeSet::new(), 1_000, |_| async { true })
            .await
            .unwrap_err();
        assert!(matches!(error, SearchError::ResourceExhausted(ref kind) if kind == "memory"), "{error:?}");
    }

    /// A streamed read's refusal before any row keeps the escalation
    /// contract: 429 is a concurrency refusal for the caller to escalate.
    #[tokio::test]
    async fn streamed_read_concurrency_refusal_is_returned_to_the_caller() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xf);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query/pages")))
            .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
                "ok": false, "reason": "query_budget_exhausted", "error": "all 2 query slots stayed busy"})))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let mut request = search_request();
        request.limit = Some(5_000);
        let error = client
            .search_paged(&request, "q-1", &BTreeSet::new(), 1_000, |_| async { true })
            .await
            .unwrap_err();
        assert!(matches!(error, SearchError::ResourceExhausted(ref kind) if kind == "concurrency"), "{error:?}");
    }

    #[test]
    fn ndjson_lines_split_across_chunks_without_rescanning() {
        let mut lines = NdjsonLines::default();
        lines.push(b"{\"a\":").unwrap();
        assert!(lines.next_line().is_none());
        lines.push(b"1}\n\n{\"b\"").unwrap();
        assert_eq!(lines.next_line().unwrap(), b"{\"a\":1}");
        assert!(lines.next_line().is_none());
        lines.push(b":2}").unwrap();
        assert!(lines.next_line().is_none());
        assert_eq!(lines.finish().unwrap().unwrap(), b"{\"b\":2}");
    }

    #[tokio::test]
    async fn paged_search_declines_rows_that_are_not_newest_first_events() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xc);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(PagedCell { tenant: tenant.to_string(), total: 5_000, max_page: 10_000,
                newest_first: false, requests: Default::default() })
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let mut request = search_request();
        request.limit = Some(5_000);
        let mut called = false;
        let paged = client
            .search_paged(&request, "q-1", &BTreeSet::new(), 1_000, |_| { called = true; async { true } })
            .await
            .unwrap();
        assert!(paged.is_none() && !called);
    }

    #[tokio::test]
    async fn cell_search_posts_broad_npl_to_the_tenant_prefix_with_the_router_bearer() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        let tenant_s = tenant.to_string();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant_s}/query/v1/query")))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_partial_json(serde_json::json!({
                "route": "broad_npl", "tenant_id": tenant_s, "request_id": "q-1", "dataset": "logs"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "schema_version": 1, "request_id": "q-1", "tenant_id": tenant_s,
                "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
                "result": {"result_rows": 1, "rows": [{"metadata.uid": "e1"}],
                           "page_offset": 0, "page_limit": 100, "page_has_more": false}
            })))
            .expect(2)
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let response = client
            .search(&search_request(), "q-1", None, &BTreeSet::new())
            .await
            .unwrap();
        assert_eq!(response.results.len(), 1);
        assert!(response.total_count_exact);
        let (debug_response, _) = crate::search::lake_debug::collect(
            client.search(&search_request(), "q-1", None, &BTreeSet::new())
        ).await;
        assert_eq!(debug_response.unwrap().results.len(), response.results.len());
        let requests = server.received_requests().await.unwrap();
        let queries: Vec<_> = requests.iter().filter(|request| request.url.path().ends_with("/v1/query")).collect();
        assert_eq!(queries.len(), 2);
        assert!(queries[0].headers.get("x-nano-search-debug").is_none());
        assert_eq!(queries[1].headers.get("x-nano-search-debug").unwrap(), "1");
    }

    /// NAN-4593: query[T]'s wire answer for one broad nPL search.
    fn broad_npl_ok(tenant: &str, rows: serde_json::Value) -> serde_json::Value {
        let count = rows.as_array().map_or(0, Vec::len);
        serde_json::json!({
            "ok": true, "schema_version": 1, "request_id": "q-1", "tenant_id": tenant,
            "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
            "result": {"result_rows": count, "rows": rows,
                       "page_offset": 0, "page_limit": 100, "page_has_more": false}
        })
    }

    /// NAN-4593: a search that query[T] cancels, times out or gives up on
    /// must reach the caller as an explicit error, never as `Ok` with no
    /// rows (an analyst reads that as "no activity"). Each body is the one
    /// query[T]'s `ApiError` funnel writes; the client is the production
    /// cell client.
    #[tokio::test]
    async fn cell_cancel_deadline_and_cache_give_up_are_errors_never_empty_results() {
        let tenant = Uuid::from_u128(0x4593);
        let cases: Vec<(&str, u16, serde_json::Value, fn(&SearchError) -> bool)> = vec![
            // Deadline: chDB's max_execution_time (55 s) fired.
            ("deadline", 413, serde_json::json!({"ok": false, "reason": "scan_budget_exhausted",
                "error": "native chDB query failed: Code: 159. DB::Exception: Timeout exceeded: elapsed 55.0 seconds. (TIMEOUT_EXCEEDED)"}),
                |error| matches!(error, SearchError::ResourceExhausted(_))),
            // Client / admin cancel of the job the read belongs to.
            ("job cancel", 409, serde_json::json!({"ok": false, "reason": "job_cancelled", "error": "search job was cancelled"}),
                |error| matches!(error, SearchError::Cancelled)),
            // The statement itself was cancelled inside chDB.
            ("chdb cancel", 422, serde_json::json!({"ok": false, "reason": "query_execution_failed",
                "error": "native chDB query failed: Code: 394. DB::Exception: Query was cancelled. (QUERY_WAS_CANCELLED)"}),
                |error| matches!(error, SearchError::Cancelled)),
            // Reader cache saturated: the read gave up waiting for room.
            ("cache saturated", 503, serde_json::json!({"ok": false, "reason": "part_data_unavailable",
                "error": "reader cache is saturated by leased or protected objects; 268435456 bytes could not be admitted"}),
                |error| matches!(error, SearchError::ServiceUnavailable(_))),
            // A cold fetch outlived its deadline.
            ("cold fetch timeout", 503, serde_json::json!({"ok": false, "reason": "cold_fetch_timeout",
                "error": "reader cache fetch timed out"}),
                |error| matches!(error, SearchError::ServiceUnavailable(_))),
            // The lane stayed busy past its wait.
            ("lane wait", 503, serde_json::json!({"ok": false, "reason": "lane_wait_timeout",
                "error": "native chDB lane wait timed out; retry the request"}),
                |error| matches!(error, SearchError::ServiceUnavailable(_))),
        ];
        for (name, status, body, expected) in cases {
            let server = MockServer::start().await;
            let dir = tempfile::tempdir().unwrap();
            Mock::given(method("POST"))
                .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
                .respond_with(ResponseTemplate::new(status).set_body_json(body))
                .mount(&server)
                .await;
            let client = cell_client(&server, &dir, tenant).await;
            let result = client.search(&search_request(), "q-1", None, &BTreeSet::new()).await;
            let error = match result {
                Ok(response) => panic!("{name}: answered Ok with {} rows instead of an error", response.results.len()),
                Err(error) => error,
            };
            assert!(expected(&error), "{name}: wrong error {error:?}");
        }
    }

    /// NAN-4593: the search service's own deadline on the cell call (the
    /// client timeout) is an explicit `Timeout`, never an empty answer.
    #[tokio::test]
    async fn cell_call_past_the_client_deadline_is_a_timeout_not_an_empty_result() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x4594);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(ResponseTemplate::new(200)
                .set_body_json(broad_npl_ok(&tenant.to_string(), serde_json::json!([{"metadata.uid": "late"}])))
                .set_delay(Duration::from_secs(3)))
            .mount(&server)
            .await;
        let route = cell_route(&dir, tenant, &server.uri());
        let client = LakeQueryRuntime::from_lake_cell_route(&route, Duration::from_millis(300))
            .unwrap().client.unwrap();
        let error = client.search(&search_request(), "q-1", None, &BTreeSet::new()).await.unwrap_err();
        assert!(matches!(error, SearchError::Timeout(_) | SearchError::ServiceUnavailable(_)), "{error:?}");
    }

    /// NAN-4593: a search with genuinely no matches is still a successful,
    /// exact, empty answer.
    #[tokio::test]
    async fn cell_search_with_no_matches_is_an_exact_empty_success() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x4595);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(ResponseTemplate::new(200).set_body_json(broad_npl_ok(&tenant.to_string(), serde_json::json!([]))))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let response = client.search(&search_request(), "q-1", None, &BTreeSet::new()).await.unwrap();
        assert!(response.results.is_empty());
        assert_eq!(response.total_count, 0);
        assert!(response.total_count_exact);
    }

    /// NAN-3245: a fake query[T] that answers every `/v1/query` route with
    /// one OCSF union-schema row (mostly null leaves), echoing the binding.
    struct UnionSchemaCell {
        tenant: String,
    }

    fn union_schema_row() -> serde_json::Value {
        serde_json::json!({
            "time": "2026-09-25T00:30:00.000000Z",
            "severity_id": 0,
            "is_alert": false,
            "message": null,
            "metadata": {"uid": "f1541890", "log_source": "apache_access", "labels": [], "original_time": ""},
            "actor": {"process": {"file": {"name": null, "path": null}}},
            "finding_info": {"analytic": {"name": null, "uid": null}},
            "http_response": {"code": 200, "length": 0, "message": null},
            "raw_data": "203.0.113.7 - - \"GET / HTTP/1.1\" 200 0",
            "enrichments": [{"name": "geo", "value": null}],
            // NAN-3458: the lean Parquet `unmapped` struct is the union of
            // every key the tenant stored, null except this event's own.
            "unmapped": {"_timestamp": null, "winlog": {"event_data": {"Image": null}}, "user": "alice", "status": "200"},
        })
    }

    impl wiremock::Respond for UnionSchemaCell {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": self.tenant,
                "route": body["route"], "source_mode": "parts", "wall_seconds": 0.01,
                "result": {"result_rows": 1, "rows": [union_schema_row()], "page_offset": 0, "page_limit": 100,
                           "page_has_more": false, "newest_first_event_rows": true}}))
        }
    }

    fn sparse_union_schema_row() -> serde_json::Value {
        serde_json::json!({
            "time": "2026-09-25T00:30:00.000000Z",
            "severity_id": 0,
            "is_alert": false,
            "metadata": {"uid": "f1541890", "log_source": "apache_access"},
            "http_response": {"code": 200, "length": 0},
            "raw_data": "203.0.113.7 - - \"GET / HTTP/1.1\" 200 0",
            "enrichments": [{"name": "geo"}],
            "unmapped": {"user": "alice", "status": "200"},
        })
    }

    #[tokio::test]
    async fn lean_full_event_fetch_and_rows_are_sparse_list_and_projection_rows_are_not() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0x3245);
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(UnionSchemaCell { tenant: tenant.to_string() })
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;

        // Fetch-by-id (hover prefetch / inspector): populated fields only;
        // 0/false kept; raw_data verbatim; union-padded `unmapped` and
        // `enrichments` members dropped (NAN-3458).
        let event = client
            .fetch_log_by_id("f1541890", None, Some("apache_access"), &BTreeSet::new())
            .await
            .unwrap()
            .expect("one event");
        assert_eq!(event, sparse_union_schema_row());

        // A non-table-view raw-event search returns the same sparse rows.
        let mut request = search_request();
        request.table_view = false;
        let response = client.search(&request, "q-full", None, &BTreeSet::new()).await.unwrap();
        assert_eq!(response.results, vec![sparse_union_schema_row()]);

        // Table-view list rows keep their shape.
        request.table_view = true;
        let response = client.search(&request, "q-table", None, &BTreeSet::new()).await.unwrap();
        assert_eq!(response.results, vec![union_schema_row()]);

        // A projection's nulls are real column values: untouched.
        request.table_view = false;
        request.query = "* | table time, message".into();
        let response = client.search(&request, "q-proj", None, &BTreeSet::new()).await.unwrap();
        assert_eq!(response.results, vec![union_schema_row()]);
    }

    /// B2: the router token is re-read by path on every call (a rotated
    /// Secret is used without rebuilding the client), and a router 401 is
    /// reported as a token mismatch.
    #[tokio::test]
    async fn cell_client_rereads_the_router_token_and_names_a_401() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        let tenant_s = tenant.to_string();
        let rotated = "rotated-router-token-rotated-router-token";
        Mock::given(method("GET"))
            .and(path(format!("/v1/tenants/{tenant_s}/query/v1/status")))
            .and(header("authorization", format!("Bearer {rotated}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "tenant_id": tenant_s, "source_mode": "parts"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({"error": "unauthorized"})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({"error": "unauthorized"})))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        // Old token: the router refuses; the error names the token.
        let error = client
            .search(&search_request(), "q-1", None, &BTreeSet::new())
            .await
            .unwrap_err();
        assert!(matches!(error, SearchError::ServiceUnavailable(ref m) if m.contains("401") && m.contains("router token")), "{error:?}");
        assert!(client.health().await.is_err());
        // Rotate the token file in place: the SAME client now authenticates.
        private_file(&dir, "router.token", rotated);
        client.health().await.unwrap();
    }

    #[tokio::test]
    async fn cell_search_refuses_a_response_for_another_tenant() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "request_id": "q-1", "tenant_id": Uuid::from_u128(0xb).to_string(),
                "route": "broad_npl", "result": {"rows": [{"secret": "b"}]}
            })))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let error = client
            .search(&search_request(), "q-1", None, &BTreeSet::new())
            .await
            .unwrap_err();
        assert!(matches!(error, SearchError::SqlValidationError(ref m) if m.contains("substituted")));
    }

    #[tokio::test]
    async fn cell_failures_map_to_outage_budget_or_query_error() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        for (status, body, expect) in [
            (404, serde_json::json!({"error": "tenant not placed on this cell"}), "unavailable"),
            (401, serde_json::json!({"error": "unauthorized"}), "unavailable"),
            (503, serde_json::json!({"ok": false, "error": "parts", "reason": "part_data_unavailable"}), "unavailable"),
            (413, serde_json::json!({"ok": false, "error": "too big", "reason": "scan_budget_exhausted"}), "budget"),
            (503, serde_json::json!({"ok": false, "error": "query memory budget exceeded", "reason": "query_budget_exhausted"}), "memory"),
            (429, serde_json::json!({"ok": false, "error": "query concurrency budget exceeded", "reason": "query_budget_exhausted"}), "concurrency"),
            (400, serde_json::json!({"ok": false, "error": "bad nPL", "reason": "invalid_request"}), "query"),
            (422, serde_json::json!({"ok": false, "error": "bad nPL: type", "reason": "query_execution_failed"}), "query"),
            (500, serde_json::json!({"ok": false, "error": "invariant", "reason": "internal"}), "unavailable"),
        ] {
            let server = MockServer::start().await;
            // The worker echoes every error reason in a header (NAN-3270).
            let mut template = ResponseTemplate::new(status);
            if let Some(reason) = body["reason"].as_str() {
                template = template.insert_header(crate::lake_http::LAKE_REASON_HEADER, reason);
            }
            Mock::given(method("POST"))
                .respond_with(template.set_body_json(body))
                .mount(&server)
                .await;
            let client = cell_client(&server, &dir, tenant).await;
            let error = client
                .search(&search_request(), "q-1", None, &BTreeSet::new())
                .await
                .unwrap_err();
            match expect {
                "unavailable" => assert!(matches!(error, SearchError::ServiceUnavailable(_)), "{status}: {error:?}"),
                "budget" => assert!(matches!(error, SearchError::ResourceExhausted(_)), "{status}: {error:?}"),
                "memory" | "concurrency" => assert!(matches!(error, SearchError::ResourceExhausted(ref kind) if kind == expect), "{status}: {error:?}"),
                _ => assert!(matches!(error, SearchError::SqlValidationError(ref m) if m.contains("bad nPL")), "{status}: {error:?}"),
            }
        }
    }

    /// A role the cell cannot start (the control plane refused its token)
    /// surfaces the role and the refusal code, not a bare "HTTP 503".
    #[tokio::test]
    async fn cell_role_spawn_blocked_names_the_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "error": "detect spawn blocked", "reason": "role_spawn_blocked", "role": "detect",
                "refusal": "detect_drain_disabled", "refusal_status": 403, "retry_after_secs": 60
            })))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let error = client
            .search(&search_request(), "q-1", None, &BTreeSet::new())
            .await
            .unwrap_err();
        assert!(matches!(error, SearchError::ServiceUnavailable(ref m)
            if m.contains("tenant's detect process") && m.contains("(detect_drain_disabled)")), "{error:?}");
    }

    #[tokio::test]
    async fn cell_readiness_is_query_status_not_gen1_generation_health() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        let tenant_s = tenant.to_string();
        Mock::given(method("GET"))
            .and(path(format!("/v1/tenants/{tenant_s}/query/v1/status")))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "tenant_id": tenant_s, "source_mode": "parts",
                "log_head": {"seq": 3, "sha256": "ab".repeat(32)}, "inflight": 0
            })))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        client.health().await.unwrap();
        // No gen1 generation exists: durable pins/admission refuse cleanly.
        assert!(matches!(client.generation_pin().await, Err(SearchError::ServiceUnavailable(_))));
        assert!(matches!(client.admission_generation().await, Err(SearchError::ServiceUnavailable(_))));
        assert!(!client.cancel("q-1").await.unwrap());

        // A status answered for another tenant is not readiness.
        let other = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "tenant_id": Uuid::from_u128(0xb).to_string(), "source_mode": "parts"
            })))
            .mount(&other)
            .await;
        let client = cell_client(&other, &dir, tenant).await;
        assert!(matches!(client.health().await, Err(SearchError::ServiceUnavailable(_))));
    }

    /// NAN-3094: entity ranges are the partial-backed first/last-seen read.
    #[tokio::test]
    async fn cell_entity_ranges_echo_their_binding_and_accept_quoted_integers() {
        struct EchoRanges(String);
        impl wiremock::Respond for EchoRanges {
            fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
                let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["path"], "device.hostname");
                assert_eq!(body["case_insensitive"], true);
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": self.0,
                    "route": "entity_ranges", "source_mode": "parts", "path": "device.hostname",
                    "result": {"result_rows": 1, "rows": [
                        {"entity": "srv-db02.corp.local", "first_us": "1790700000000000", "last_us": 1790770000000000_i64, "events": "42"}
                    ]}
                }))
            }
        }
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xb);
        let tenant_s = tenant.to_string();
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/tenants/{tenant_s}/query/v1/entity/ranges"
            )))
            .respond_with(EchoRanges(tenant_s.clone()))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let range: TimeRangeInput = serde_json::from_value(serde_json::json!({
            "start": "2026-09-01T00:00:00Z", "end": "2026-09-30T00:00:00Z"
        }))
        .unwrap();
        let rows = client
            .entity_ranges(
                "device.hostname",
                &["SRV-DB02.corp.local".to_string()],
                &range,
            )
            .await
            .unwrap();
        assert_eq!(
            rows,
            vec![LakeEntityRange {
                entity: "srv-db02.corp.local".to_string(),
                first_us: 1_790_700_000_000_000,
                last_us: 1_790_770_000_000_000,
                events: 42,
            }]
        );

        // A response bound to another request is refused.
        let foreign = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "request_id": "someone-else", "tenant_id": tenant_s,
                "route": "entity_ranges", "result": {"rows": []}
            })))
            .mount(&foreign)
            .await;
        let client = cell_client(&foreign, &dir, tenant).await;
        assert!(client
            .entity_ranges("device.hostname", &["h".to_string()], &range)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cell_count_rollup_binds_to_the_part_log_head_not_a_gen1_generation() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        let tenant_s = tenant.to_string();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant_s}/query/v1/aggregate/count")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "request_id": "c-1", "tenant_id": tenant_s, "route": "count_aggregate",
                "source_mode": "parts", "log_head": {"seq": 4, "sha256": "ab".repeat(32)},
                "result": {"rows": [{"count": 3}]}
            })))
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let range: TimeRangeInput = serde_json::from_value(serde_json::json!({
            "start": "2026-09-25T00:00:00Z", "end": "2026-09-25T01:00:00Z"
        }))
        .unwrap();
        let rows = client
            .count_aggregate("c-1", "metadata.log_source", false, None, None, "count", &range, None, &BTreeSet::new(), 10)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);

        // An empty part log answers `log_head: null` with no rows: accepted.
        let empty = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "request_id": "c-3", "tenant_id": tenant_s, "route": "count_aggregate",
                "log_head": null, "result": {"rows": []}
            })))
            .mount(&empty)
            .await;
        let client_empty = cell_client(&empty, &dir, tenant).await;
        assert!(client_empty
            .count_aggregate("c-3", "metadata.log_source", false, None, None, "count", &range, None, &BTreeSet::new(), 10)
            .await
            .unwrap()
            .is_empty());

        // Without the part-log head binding the rollup is refused.
        let unbound = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "request_id": "c-2", "tenant_id": tenant_s, "route": "count_aggregate",
                "result": {"rows": [{"count": 3}]}
            })))
            .mount(&unbound)
            .await;
        let client = cell_client(&unbound, &dir, tenant).await;
        assert!(client
            .count_aggregate("c-2", "metadata.log_source", false, None, None, "count", &range, None, &BTreeSet::new(), 10)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cell_detection_gate_plan_and_commit_wire() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = Uuid::from_u128(0xa);
        let tenant_s = tenant.to_string();
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant_s}/query/v1/detections/plan")))
            .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
            .and(body_partial_json(serde_json::json!({
                "rule_id": "rule-1", "window_start_us": 10, "window_end_us": 20
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "run": false, "reason": "no_new_data", "log_seq": 9, "rerun_windows": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant_s}/query/v1/detections/commit")))
            .and(body_partial_json(serde_json::json!({
                "rule_id": "rule-1", "log_seq": 9, "evaluated_through_us": 20
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
        let client = cell_client(&server, &dir, tenant).await;
        let plan = client.detection_plan("rule-1", 10, 20, None).await.unwrap().unwrap();
        assert!(!plan.run);
        assert_eq!(plan.log_seq, 9);
        assert!(client.detection_commit("rule-1", 9, 20).await.unwrap());
    }

    #[tokio::test]
    async fn gen1_clients_never_call_the_detection_gate() {
        let client = LakeQueryClient::new(
            "http://127.0.0.1:9",
            "tenant-a".into(),
            "x".repeat(32),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(client.detection_plan("r", 0, 1, None).await.unwrap().is_none());
        assert!(!client.detection_commit("r", 1, 1).await.unwrap());
        // And the gen1 constructor still refuses a base URL with a path.
        assert!(LakeQueryClient::new(
            "http://reader.nano.svc:8080/v1/tenants/x/query",
            "tenant-a".into(),
            "x".repeat(32),
            Duration::from_secs(1),
        )
        .is_err());
    }
}

#[cfg(test)]
mod cold_budget_tests {
    use super::*;

    /// NAN-3644: the reader's ceiling refusal maps to `ColdScanTooLarge`,
    /// typed or erased to text; a pre-NAN-3644 cell's `cold_budget_exceeded`
    /// (still possible mid-roll) maps to the same error.
    #[test]
    fn cold_ceiling_cell_classification_preserves_typed_archived_and_legacy_errors() {
        let dir = tempfile::tempdir().unwrap();
        let route = super::super::lake_cell::LakeCellRoute::for_test(uuid::Uuid::from_u128(42), "http://127.0.0.1:8790", dir.path().join("token"));
        let client = LakeQueryClient::new_lake_cell(&route, Duration::from_secs(1)).unwrap();
        for (status, body, background) in [
            (422, serde_json::json!({"error": "too large", "reason": "cold_scan_too_large", "needed_bytes": 14_800_000_000_u64,
                "ceiling_bytes": 9_600_000_000_u64, "background_ceiling_bytes": 9_600_000_000_u64}), Some(9_600_000_000)),
            (503, serde_json::json!({"error": "query needs 14800000000 uncached bytes in one pass, over the 9600000000 bytes this reader can stage at once", "reason": "internal"}), None),
            (422, serde_json::json!({"error": "narrow the time range", "reason": "cold_budget_exceeded", "needed_bytes": 14_800_000_000_u64, "budget_bytes": 9_600_000_000_u64}), None),
            (503, serde_json::json!({"error": "query needs 14800000000 cold bytes, over the per-query reader cache budget of 9600000000; narrow the time range", "reason": "internal"}), None),
        ] {
            let mapped = client.lake_cell_failure(reqwest::StatusCode::from_u16(status).unwrap(), &serde_json::to_vec(&body).unwrap());
            assert!(matches!(mapped, SearchError::ColdScanTooLarge { needed_bytes: 14_800_000_000, ceiling_bytes: 9_600_000_000, background_ceiling_bytes }
                if background_ceiling_bytes == background), "{mapped:?}");
        }
        let line: StreamedLine = serde_json::from_value(serde_json::json!({"ok": false, "status": 422, "error": "too large", "reason": "cold_scan_too_large",
            "needed_bytes": 14_800_000_000_u64, "ceiling_bytes": 9_600_000_000_u64, "background_ceiling_bytes": 9_600_000_000_u64})).unwrap();
        assert!(matches!(line, StreamedLine::Failed { needed_bytes: Some(14_800_000_000), ceiling_bytes: Some(9_600_000_000), .. }));
    }

    #[test]
    fn cold_ceiling_message_offers_a_background_run_only_when_it_fits() {
        let fits = SearchError::ColdScanTooLarge { needed_bytes: 6_000_000_000, ceiling_bytes: 4_800_000_000, background_ceiling_bytes: Some(9_600_000_000) };
        let text = fits.to_string();
        assert!(text.contains("~6.0 GB") && text.contains("~4.8 GB") && text.contains("too large to run interactively"), "{text}");
        assert!(text.contains("background search (async)") && text.contains("~9.6 GB"), "{text}");
        for background in [None, Some(5_000_000_000)] {
            let text = SearchError::ColdScanTooLarge { needed_bytes: 6_000_000_000, ceiling_bytes: 4_800_000_000, background_ceiling_bytes: background }.to_string();
            assert!(!text.contains("background"), "{text}");
            assert!(text.contains("Narrow the time range"), "{text}");
        }
    }
}

#[cfg(test)]
mod cold_budget_transport_tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    #[tokio::test]
    async fn cold_ceiling_422_is_one_cell_request_without_transient_retry() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "cold-budget-test-token-0000000000000000").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let route = super::super::lake_cell::LakeCellRoute::for_test(uuid::Uuid::from_u128(42), &server.uri(), token);
        let client = LakeQueryClient::new_lake_cell(&route, Duration::from_secs(5)).unwrap();
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
            "ok": false, "reason": "cold_scan_too_large", "error": "too large", "needed_bytes": 14_800_000_000_u64,
            "ceiling_bytes": 9_600_000_000_u64, "background_ceiling_bytes": 9_600_000_000_u64,
        }))).expect(1).mount(&server).await;
        let request = serde_json::from_value(serde_json::json!({"query": "* | head 5", "time_range": {"start": "2026-09-25T00:00:00Z", "end": "2026-09-25T01:00:00Z"}})).unwrap();
        let error = client.search(&request, "q-1", None, &BTreeSet::new()).await.unwrap_err();
        assert!(matches!(error, SearchError::ColdScanTooLarge { .. }), "{error:?}");
    }
    fn cell_client(server: &MockServer, dir: &tempfile::TempDir) -> LakeQueryClient {
        let token = dir.path().join("token");
        std::fs::write(&token, "byte-cut-test-token-00000000000000000000").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let route = super::super::lake_cell::LakeCellRoute::for_test(uuid::Uuid::from_u128(42), &server.uri(), token);
        LakeQueryClient::new_lake_cell(&route, Duration::from_secs(5)).unwrap()
    }

    /// NAN-3270: a fake query[T] whose answers hold at most `per_answer`
    /// rows (its result byte budget): a longer page comes back cut, with the
    /// `(time, uid)` continuation of its last row. Event i is newest-first
    /// `e{i:06}`; a cursor continues strictly after its uid.
    struct ByteCutCell {
        total: usize,
        per_answer: usize,
        bodies: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    }

    impl wiremock::Respond for ByteCutCell {
        fn respond(&self, request: &wiremock::Request) -> ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            self.bodies.lock().unwrap().push(body.clone());
            let (limit, offset) = (body["limit"].as_u64().unwrap() as usize, body["offset"].as_u64().unwrap() as usize);
            let first = match body["cursor_event_uid"].as_str() {
                Some(uid) => uid.trim_start_matches('e').parse::<usize>().unwrap() + 1,
                None => 0,
            } + offset;
            let base = chrono::DateTime::parse_from_rfc3339("2026-09-25T00:59:00Z").unwrap().with_timezone(&chrono::Utc);
            let time = |i: usize| (base - chrono::Duration::milliseconds(i as i64)).to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
            let end = self.total.min(first + limit);
            let cut = end - first.min(end) > self.per_answer;
            let end = if cut { first + self.per_answer } else { end };
            let rows = (first..end)
                .map(|i| serde_json::json!({"time": time(i), "metadata": {"uid": format!("e{i:06}")}, "message": "x"}))
                .collect::<Vec<_>>();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "schema_version": 1, "request_id": body["request_id"], "tenant_id": uuid::Uuid::from_u128(42).to_string(),
                "route": "broad_npl", "source_mode": "parts", "wall_seconds": 0.01,
                "result": {"result_rows": rows.len(), "rows": rows, "page_offset": offset, "page_limit": limit,
                    "page_has_more": cut || self.total > first + limit, "newest_first_event_rows": true,
                    "page_byte_cut": cut,
                    "continuation": cut.then(|| serde_json::json!({"cursor_time": time(end - 1), "cursor_event_uid": format!("e{:06}", end - 1)}))}}))
        }
    }

    /// NAN-3270: a byte-cut page is filled from its continuation (no error,
    /// so nothing escalates to a durable job): every requested row, in
    /// order, from offset 0 continuation requests for the rows still wanted.
    #[tokio::test]
    async fn byte_cut_page_is_filled_from_its_continuation() {
        for (offset, limit, total) in [(0_usize, 2_000_usize, 2_500_usize), (300, 2_000, 2_500), (0, 2_000, 1_900), (100, 1_400, 1_500)] {
            let server = MockServer::start().await;
            let dir = tempfile::tempdir().unwrap();
            let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            Mock::given(method("POST")).respond_with(ByteCutCell { total, per_answer: 700, bodies: bodies.clone() }).mount(&server).await;
            let client = cell_client(&server, &dir);
            let mut request: SearchRequest = serde_json::from_value(serde_json::json!({
                "query": "metadata.log_source=apache_access", "time_range": {"start": "2026-09-25T00:00:00Z", "end": "2026-09-25T01:00:00Z"}})).unwrap();
            request.limit = Some(limit);
            request.offset = Some(offset);
            let response = client.search(&request, "q-fill", None, &BTreeSet::new()).await
                .unwrap_or_else(|error| panic!("offset {offset} limit {limit}: {error:?}"));
            let uids = response.results.iter().map(|row| row["metadata"]["uid"].as_str().unwrap().to_string()).collect::<Vec<_>>();
            let expected = (offset..total.min(offset + limit)).map(|i| format!("e{i:06}")).collect::<Vec<_>>();
            assert_eq!(uids, expected, "offset {offset} limit {limit} total {total}");
            assert_eq!(!response.total_count_exact, total > offset + limit || uids.len() >= limit, "offset {offset} limit {limit} total {total}");
            let bodies = bodies.lock().unwrap();
            assert_eq!(bodies.len(), (total.min(offset + limit) - offset).div_ceil(700), "offset {offset} limit {limit} total {total}");
            assert_eq!((bodies[0]["offset"].as_u64(), bodies[0]["limit"].as_u64()), (Some(offset as u64), Some(limit as u64)));
            assert!(bodies[0].get("cursor_event_uid").is_none());
            for (hop, body) in bodies.iter().enumerate().skip(1) {
                let delivered = 700 * hop;
                assert_eq!(body["offset"], 0, "continuations carry no offset");
                assert_eq!(body["limit"].as_u64(), Some((limit - delivered) as u64), "only the rows still wanted");
                assert_eq!(body["cursor_event_uid"], format!("e{:06}", offset + delivered - 1));
                assert!(body["cursor_time"].as_str().unwrap().ends_with('Z'));
            }
        }
    }

    /// NAN-3270: a 503 the cell marks as its own budget refusal answers at
    /// once (one request, classified for durable escalation), instead of
    /// being replayed for the transport's recovery window.
    #[tokio::test]
    async fn budget_refusal_is_one_cell_request() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let client = cell_client(&server, &dir);
        Mock::given(method("POST")).respond_with(ResponseTemplate::new(503)
            .insert_header(crate::lake_http::LAKE_REASON_HEADER, crate::lake_http::QUERY_BUDGET_EXHAUSTED_REASON)
            .set_body_json(serde_json::json!({"ok": false, "reason": "query_budget_exhausted",
                "error": "query memory budget exceeded: query result of 20000000 bytes exceeds the 16777216-byte result memory budget"})))
            .expect(1).mount(&server).await;
        let request = serde_json::from_value(serde_json::json!({"query": "* | head 5", "time_range": {"start": "2026-09-25T00:00:00Z", "end": "2026-09-25T01:00:00Z"}})).unwrap();
        let error = client.search(&request, "q-1", None, &BTreeSet::new()).await.unwrap_err();
        assert!(matches!(&error, SearchError::ResourceExhausted(kind) if kind == "memory"), "{error:?}");
    }

    /// Past the fill bound a page is too wide for an interactive answer: it
    /// is refused as a memory budget (the handler makes it a durable job).
    #[tokio::test]
    async fn a_page_wider_than_the_fill_bound_goes_durable() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        Mock::given(method("POST")).respond_with(ByteCutCell { total: 100_000, per_answer: 10, bodies: bodies.clone() }).mount(&server).await;
        let client = cell_client(&server, &dir);
        let mut request: SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "*", "time_range": {"start": "2026-09-25T00:00:00Z", "end": "2026-09-25T01:00:00Z"}})).unwrap();
        request.limit = Some(5_000);
        let error = client.search(&request, "q-wide", None, &BTreeSet::new()).await.unwrap_err();
        assert!(matches!(&error, SearchError::ResourceExhausted(kind) if kind == "memory"), "{error:?}");
        assert_eq!(bodies.lock().unwrap().len(), 1 + MAX_BYTE_CUT_FILL_HOPS);
    }
}
